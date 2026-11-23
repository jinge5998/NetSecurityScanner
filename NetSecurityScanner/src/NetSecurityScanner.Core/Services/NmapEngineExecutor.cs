using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using NetSecurityScanner.Core.Models;
using NetSecurityScanner.Models;

namespace NetSecurityScanner.Core.Services
{
  /// <summary>
  /// 真正的 nmap 执行引擎。
  ///
  /// 此前 <see cref="NmapCommandBuilder"/> 只把界面配置翻译成 nmap 命令字符串，
  /// 程序自身从不执行 nmap；本类补齐这条缺失链路：
  ///   1. 定位本机的 nmap.exe（PATH / Program Files / 应用目录 / tools/ 等常见位置）；
  ///   2. 用 <see cref="NmapCommandBuilder"/> 生成的参数 + 强制 <c>-oX -</c> 拼出可执行命令行；
  ///   3. 启动 nmap 子进程，流式读取 stdout 上的 XML；
  ///   4. 用 <see cref="NmapXmlParser"/> 反序列化为 <see cref="PortScanResult"/> 返回。
  ///
  /// 边界：本类不强绑 nmap 二进制。找不到 nmap 时 <see cref="TryLocateNmap"/> 返回 false，
  /// 由调用方（UI）决定回退到 Rust / 内置 C# 引擎，本类不抛异常、不假扫。
  /// </summary>
  public sealed class NmapEngineExecutor : IDisposable
  {
    private readonly string? _nmapPath;

    // Windows 上程序自身不消费 stderr，nmap 的正常进度/状态提示走 stdout 的注释行。
    public bool IsAvailable => _nmapPath != null;
    public string? NmapPath => _nmapPath;

    public NmapEngineExecutor()
    {
      _nmapPath = LocateNmap();
    }

    public NmapEngineExecutor(string nmapPath)
    {
      _nmapPath = ResolveExistingExecutable(nmapPath);
    }

    /// <summary>
    /// 校验调用方传入的路径：只有真实存在的文件才视为可用引擎。
    /// 传相对路径（如 "tools\nmap\nmap.exe"）时按当前工作目录展开为绝对路径，
    /// 避免 <see cref="IsAvailable"/> 报 true 而启动子进程时才抛 Win32Exception。
    /// </summary>
    private static string? ResolveExistingExecutable(string? nmapPath)
    {
      if (string.IsNullOrWhiteSpace(nmapPath)) return null;
      try
      {
        var full = Path.GetFullPath(nmapPath);
        return File.Exists(full) ? full : null;
      }
      catch
      {
        return null;
      }
    }

    /// <summary>
    /// 探测 nmap 可执行文件的存放位置。找不到返回 null。
    /// </summary>
    public static string? LocateNmap()
    {
      var candidates = new List<string>();

      // 1) 执行文件所在目录（自包含发布的 tools/ 子目录优先）
      var baseDir = AppContext.BaseDirectory;
      AddIfExists(candidates, Path.Combine(baseDir, "tools", "nmap", "nmap.exe"));
      AddIfExists(candidates, Path.Combine(baseDir, "tools", "nmap.exe"));
      AddIfExists(candidates, Path.Combine(baseDir, "nmap.exe"));

      // 2) 常见安装路径
      AddIfExists(candidates, @"C:\Program Files (x86)\Nmap\nmap.exe");
      AddIfExists(candidates, @"C:\Program Files\Nmap\nmap.exe");

      // 3) PATH 环境变量
      candidates.AddRange(FindOnPath("nmap.exe"));

      return candidates.FirstOrDefault();
    }

    private static void AddIfExists(List<string> list, string path)
    {
      if (!string.IsNullOrWhiteSpace(path) && File.Exists(path)) list.Add(path);
    }

    private static IEnumerable<string> FindOnPath(string fileName)
    {
      var pathVar = Environment.GetEnvironmentVariable("PATH");
      if (string.IsNullOrWhiteSpace(pathVar)) yield break;
      foreach (var dir in pathVar.Split(Path.PathSeparator, StringSplitOptions.RemoveEmptyEntries))
      {
        var full = Path.Combine(dir.Trim(), fileName);
        if (File.Exists(full)) yield return full;
      }
    }

    /// <summary>
    /// 读取 nmap 版本号，用于「自检」界面展示。无 nmap 或解析失败时返回空串。
    /// </summary>
    public async Task<string> GetVersionAsync(CancellationToken ct = default)
    {
      if (_nmapPath == null) return "";

      var psi = new ProcessStartInfo
      {
        FileName = _nmapPath,
        Arguments = "--version",
        UseShellExecute = false,
        CreateNoWindow = true,
        RedirectStandardOutput = true,
        RedirectStandardError = true,
        StandardOutputEncoding = Encoding.UTF8
      };
      try
      {
        using var proc = Process.Start(psi);
        if (proc == null) return "";

        var stdout = await proc.StandardOutput.ReadToEndAsync().ConfigureAwait(false);
        await proc.WaitForExitAsync(ct).ConfigureAwait(false);

        // 形如: Nmap version 7.95 ( https://nmap.org )
        var line = stdout.Split('\n').FirstOrDefault(l => l.Contains("Nmap version", StringComparison.OrdinalIgnoreCase));
        return line?.Trim() ?? "";
      }
      catch (Exception ex) when (ex is not OperationCanceledException)
      {
        // 版本探测属于「自检」展示信息，任何启动失败（文件被删除/无执行权限/非可执行文件）
        // 都只应表现为「版本未知」，不能把异常抛给 UI 导致页面崩溃。
        return "";
      }
    }

    /// <summary>
    /// 用 nmap 实际扫描目标的一组端口。
    /// </summary>
    /// <param name="target">目标 IP / 主机名（本例只处理单目标）。</param>
    /// <param name="ports">要扫描的端口号列表；为空时直接返回空结果，不启动 nmap。</param>
    /// <param name="config">专家模式界面配置，用于构建扫描参数。</param>
    /// <param name="progress">进度回调（每完成一个目标内部固定为端口批量完成时回调）。</param>
    /// <param name="onProgress">
    /// 实时进度回调：(本次扫描内的整体完成百分比 0-100, 人类可读进度文本)。
    /// nmap 用 <c>--stats-every</c> 把统计写到 stderr，这些行在扫描过程中就会产出；
    /// 各扫描阶段（SYN/UDP/服务识别/OS/NSE）的百分比会被映射到统一的 0-100% 区间，
    /// 因此调用方可以直接把它喂给进度条。不传则丢弃（保持既有调用方行为不变）。
    /// </param>
    public async Task<List<PortScanResult>> ScanAsync(
        string target,
        List<int> ports,
        ExpertScanConfiguration config,
        IProgress<int>? progress = null,
        CancellationToken ct = default,
        Action<double, string>? onProgress = null)
    {
      var result = new List<PortScanResult>();
      if (_nmapPath == null) return result;

      // 端口列表为空时不启动 nmap。实测（nmap 7.993）：缺少 -p 参数时 nmap 会退化为
      // 默认 top-1000 扫描，等于替调用方扫了 1000 个它根本没要求的端口，
      // 并返回 5 条与本次请求无关的结果。内置 C# 引擎对空列表直接返回空，
      // 这里保持一致，避免两个引擎在同一输入下行为分叉。
      if (ports == null || ports.Count == 0) return result;

      // 用 NmapCommandBuilder 生成完整命令参数，再追加 XML-stdout 输出与目标。
      // 注意 Builder 的输出以 "nmap " 为前缀且末尾是目标，这里会剥掉前缀、重组参数，
      // 保证 -oX - 与目标顺序正确。
      var baseCmd = NmapCommandBuilder.Build(config, timestamp: "scan_live");
      // 与 --host-timeout 同口径的主机预算（供下方 C# 侧进程级保险丝复用：
      // nmap 自身的超时只在进程内部正常执行时生效，进程级挂死需要 C# 侧兜底）。
      long hostBudgetMs = EstimateHostBudgetMs(ports, config);
      var tokens = SplitCommand(baseCmd).ToList();
      tokens.Remove("nmap"); // 本类自行指定 FileName

      // ===== 关键修复：Builder 的输出是"给用户复制到终端看的命令"，不能直接当执行参数 =====
      // 实测缺陷（Nmap 7.993）：
      //   1) 末尾含字面占位符 "<target>"（当 config.TargetValue 为空时），
      //      传给 nmap 会报 "Failed to resolve <target>" 并使整次扫描返回 0 条；
      //   2) 含展示用输出参数 -oJ/-oX/-oN/-oG/-oA 及文件名（如 -oJ "scan_scan_live.json"），
      //      与这里强制的 stdout XML (-oX -) 冲突，导致 XML 混入文件而非 stdout；
      //   3) 含 --top-ports 1000 / -p 等端口参数（展示用默认），
      //      与实际下发的 ports 列表不一致，会扫错端口。
      // 因此按白名单思路剥离这些 token，只保留扫描行为类参数，再追加真实端口/XML/目标。
      var cleaned = new List<string>();
      var skipNext = false;
      string[] outputFlags = { "-oX", "-oJ", "-oN", "-oG", "-oA", "-oB" };
      string[] valueFlags = { "--top-ports", "-p", "--exclude-ports", "--exclude-hosts", "--max-retries", "--min-rate", "--max-rate", "--host-timeout" };
      for (var i = 0; i < tokens.Count; i++)
      {
        var t = tokens[i];
        if (skipNext) { skipNext = false; continue; }
        if (t == "<target>") continue;                              // 展示用目标占位符
        if (t == "--randomize-ports") continue;                      // nmap 不存在的非法参数（旧版 Builder 生成）
        if (!string.IsNullOrEmpty(config.TargetValue) && t == config.TargetValue.Trim()) continue; // 展示用目标
        if (outputFlags.Contains(t)) { skipNext = true; continue; }  // 输出格式 + 文件名
        if (valueFlags.Contains(t)) { skipNext = true; continue; }   // 端口/排除/速率 + 值
        if (t.StartsWith("-p-", StringComparison.Ordinal)) continue; // 全端口展示参数
        if (t == "--open") continue;                                 // 只显示开放端口：结果解析需要全状态
        cleaned.Add(t);
      }
      tokens = cleaned;

      // 以真实端口列表、stdout XML、真实目标重组执行参数
      // （端口列表已在方法入口校验非空，这里无需再判空）
      {
        // Windows CreateProcess 对单行命令行有 ~32767 字符限制；
        // 65535 个端口逐个拼成 "1,2,3,..." 会超限导致进程启动失败
        // （实测取消测试报"文件名或扩展名太长"）。改用连续区间压缩：
        // 1,2,3,...,1024 → "1-1024"，命令行长度恒定且 nmap 完全支持。
        tokens.Add("-p");
        tokens.Add(CompressPortRanges(ports));
      }

      // host-timeout 兜底：必须按「真实端口规模」重算，不能沿用 Builder 的展示值。
      //
      // 实测假阴性（nmap 7.993，本机 127.0.0.1）：
      //   Builder 按 TcpTimeout*3 生成 --host-timeout 9000ms，而全端口 TCP+UDP+服务识别
      //   根本不可能 9 秒完成，nmap 在第 9 秒放弃主机并输出
      //   <host timedout="true"> 且 <ports> 为空 —— 明明 40+ 个端口开放，
      //   却返回 0 条结果，界面显示「无开放端口」并跳过漏洞扫描。
      // 因此改为：端口数 × 每端口预算 × 协议数，并夹在 5 分钟 ~ 2 小时之间。
      // 该值只作「防止永久卡死」的安全网，必须远大于实际预期耗时，宁大勿小。
      //
      // ⚠️ 无条件生成，不设 TcpTimeout>=2000 门槛：默认配置（TcpTimeout=500）
      // 下若省去 host-timeout，当目标 SYN 被防火墙静默丢弃时，nmap 对每个端口
      // 都要等满 max-rtt-timeout 才放弃，全端口扫描可能无限徘徊、界面零反馈
      // （这正是「nmap 卡死」的典型可见形态）。真实端口数已知时预算永远合理，
      // 只有上限过高（2h）没有收紧风险，故始终注入。
      {
        var hostTimeout = Math.Clamp(hostBudgetMs, 300_000L, 7_200_000L);
        tokens.Add("--host-timeout");
        tokens.Add($"{hostTimeout}ms");
      }

      // NSE 脚本超时兜底（独立于 Builder）：即使生成参数时漏掉 --script-timeout，
      // 只要启用了脚本扫描，执行端也必须保证单个脚本有超时上限。
      // 实测教训（nmap 7.993）：smb-vuln-ms10-061 在无 SMB 凭据时对默认认证组合
      // 无限重试，ETC 一路涨到 9 小时；--script-timeout 180s 让同样扫描 45s 收尾。
      // 注意 Builder 的记录命令用 --script-timeout 180s 单串、这里用两个 token，
      // 因此先检查 tokens 中是否已出现该参数，避免重复添加。
      if (config.ScriptScan && !tokens.Contains("--script-timeout", StringComparer.Ordinal))
      {
        tokens.Add("--script-timeout");
        tokens.Add("180s");
      }
      tokens.Add("-oX");
      tokens.Add("-");
      tokens.Add(target);

      var psi = new ProcessStartInfo
      {
        FileName = _nmapPath,
        UseShellExecute = false,
        CreateNoWindow = true,
        RedirectStandardOutput = true,
        RedirectStandardError = true,
        StandardOutputEncoding = Encoding.UTF8,
      };
      foreach (var t in tokens) psi.ArgumentList.Add(t);

      // 诊断日志：记录实际执行的完整 nmap 命令行。
      // 界面预览命令与本方法最终下发的参数并不一致（本方法会剥离展示用 token 再重组），
      // 排查"手动执行能扫到、引擎扫不到"类问题时必须看到这份真实参数。
      try
      {
        System.IO.File.AppendAllText(
          System.IO.Path.Combine(System.IO.Path.GetTempPath(), "nmap_engine_debug.log"),
          $"[{DateTime.Now:HH:mm:ss}] CMD: \"{_nmapPath}\" {string.Join(" ", tokens)}\r\n");
      }
      catch { /* 诊断日志失败不影响扫描 */ }

      using var proc = StartNmapProcess(psi);
      if (proc == null) return result;

      // ===== C# 侧进程级保险丝 =====
      // nmap 自身的超时（--host-timeout / --script-timeout）只在进程内部正常执行时生效，
      // 只靠它们是「相信子进程会自杀」。若 nmap 因系统级原因挂死——Windows 进程无响应、
      // 杀软挂钩、DNS 解析黑洞、网络栈异常导致进程不输出也不退出——那么 stdout 的
      // ReadAsync 会无限阻塞，传入的 ct 也只能在读取返回后才能生效，「停止/取消」彻底失效。
      // 这里创建一条与用户取消链接的内部超时：预算按 host-timeout 同口径再加 15 分钟余量，
      // 到期即强制 Kill 并抛出可读异常，彻底断绝「无限等待」的最后一条路径。
      // 15 分钟余量远大于任何正常扫描的波动（host-timeout 预算本身已显著宽松），
      // 只拦截真实挂死，不会误杀正常扫描。
      using var fuseCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
      fuseCts.CancelAfter(TimeSpan.FromMilliseconds(hostBudgetMs + 15 * 60 * 1000L));

      try
      {
        // stderr 必须与 stdout 并行消费：nmap 会把参数错误、权限不足（如 -O 需要管理员）、
        // NSE 脚本缺失等提示写到 stderr。若只读 stdout，stderr 缓冲区写满会让子进程阻塞，
        // 表现为扫描「卡住」；而且失败原因会完全丢失，调用方只能看到 0 条结果。
        //
        // 这里改为逐行流式读取而非 ReadToEndAsync：nmap 的 --stats-every 会把
        // "Stats: ... / Timing: About 12.3% done; ETC: ..." 实时写到 stderr，
        // 一次性读完等于把整段扫描期间的进度全部丢弃。实测全端口 UDP 扫描可长达
        // 数分钟且 stdout（XML）在此期间恒为空，UI 进度因此长期停在 0，
        // 用户会误判为「引擎根本没开始扫描」。流式读取后即可边扫边回报。
        // nmap 的进度行是「分阶段」的：SYN 扫描、UDP 扫描、服务识别、OS 识别、NSE、
        // Traceroute 各自从 0% 重新计数，直接透传会让进度条反复归零。
        // 这里按 nmap 的实际执行顺序把各阶段映射到统一的 0-100% 区间。
        var phaseProgress = new NmapPhaseProgress(config.TcpScan, config.UdpScan);

        var stderrBuilder = new StringBuilder();
        var stderrTask = Task.Run(async () =>
        {
          try
          {
            using var reader = proc.StandardError;
            string? line;
            // net6.0 的 StreamReader 没有 ReadLineAsync(CancellationToken) 重载
            // （该重载 .NET 7 才引入）；无需担心保险丝触发时此处阻塞——
            // 保险丝超时路径会先 Kill 子进程，管道关闭后 ReadLineAsync 返回 null 自行结束。
            while ((line = await reader.ReadLineAsync().ConfigureAwait(false)) != null)
            {
              stderrBuilder.AppendLine(line);

              if (onProgress == null) continue;

              // 只挑进度类行回报，其余（警告、乱码本地化片段）留在 stderr 里供失败时解析
              var sample = TryParseNmapProgress(line);
              if (sample == null) continue;

              onProgress(phaseProgress.Accept(sample.Value.Phase, sample.Value.PercentInPhase), sample.Value.Text);
            }
          }
          catch (Exception)
          {
            // stderr 读取失败不应影响扫描本身：nmap 的退出码与 stdout XML 仍是有效信息
          }
        });

        // 流式读取 stdout，同时增量解析进度。
        //
        // 关键实测结论（nmap 7.993）：一旦指定 -oX -（XML 输出到 stdout），nmap 就不再
        // 往 stderr 写 "XXX Scan Timing: About N% done" 这类进度行，而是把进度作为
        // <taskprogress task="SYN Stealth Scan" time="..." percent="0.03"/> 元素嵌进
        // stdout 的 XML 流里（实测 stderr 全文为空，stdout 有 2 条 taskprogress）。
        // 因此只解析 stderr 的旧实现永远收不到进度，进度条会一直停在 0。
        // 这里改为边读 stdout 边按完整行提取 taskprogress，与 stderr 解析互为补充
        // （未用 -oX - 时进度仍在 stderr，两条通道都保留）。
        var sb = new StringBuilder();
        var buf = new char[8192];
        var parsedChars = 0;
        int read;
        // net6.0 的 StreamReader 只有 ReadAsync(Memory<char>, CancellationToken)
        // 支持取消；stdout 是唯一可能长期阻塞的通道（nmap 挂死不产出时卡住），
        // 必须绑定保险丝 token，否则保险丝形同虚设。
        while ((read = await proc.StandardOutput.ReadAsync(buf.AsMemory(), fuseCts.Token).ConfigureAwait(false)) > 0)
        {
          ct.ThrowIfCancellationRequested();
          sb.Append(buf, 0, read);
          progress?.Report(sb.Length);

          if (onProgress == null) continue;

          // 只处理已读到的完整行，避免把被截断的半个元素当成进度
          var pending = sb.ToString(parsedChars, sb.Length - parsedChars);
          var lastNewline = pending.LastIndexOf('\n');
          if (lastNewline < 0) continue;

          foreach (var line in pending.Substring(0, lastNewline).Split('\n'))
          {
            var sample = TryParseNmapTaskProgress(line);
            if (sample == null) continue;
            onProgress(phaseProgress.Accept(sample.Value.Phase, sample.Value.PercentInPhase), sample.Value.Text);
          }
          parsedChars += lastNewline + 1;
        }

        await proc.WaitForExitAsync(fuseCts.Token).ConfigureAwait(false);
        await stderrTask.ConfigureAwait(false);
        var stderr = stderrBuilder.ToString();
        result = NmapXmlParser.Parse(sb.ToString());
        // 诊断：stderr 里的权限/参数/Npcap 警告是"0 开放"假阴性的主要线索，同样落盘。
        try
        {
          System.IO.File.AppendAllText(
            System.IO.Path.Combine(System.IO.Path.GetTempPath(), "nmap_engine_debug.log"),
            $"[{DateTime.Now:HH:mm:ss}] EXIT={proc.ExitCode} PORTS={result.Count} STDERR: {stderr}\r\n");
        }
        catch { /* 诊断日志失败不影响扫描 */ }

        // 退出码兜底：nmap 因参数非法 / 权限不足 / 脚本加载失败而退出时，
        // stdout 里不会有任何 <port> 元素，若直接返回空列表，UI 会把「执行失败」
        // 误判成「目标没有开放端口」（假阴性）。
        //
        // 实测（nmap 7.993）还有一类更隐蔽的假阴性：目标无法解析时
        // （如 "999.999.999.999"），nmap 的退出码是 **0**，只在 stderr 写
        // "Failed to resolve ..." 与 "WARNING: No targets were specified"。
        // 若只判断退出码，这种情况会被静默当成「目标无开放端口」，
        // 而内置 C# 引擎对同一目标同样返回 0 条 —— 两个引擎一起「安静地失败」，
        // 用户完全无法区分「目标不可达」与「端口全关」。
        if (result.Count == 0)
        {
          var targetUnresolvable =
              stderr.Contains("Failed to resolve", StringComparison.OrdinalIgnoreCase) ||
              stderr.Contains("No targets were specified", StringComparison.OrdinalIgnoreCase);
          if (targetUnresolvable)
          {
            // 目标解析失败给出明确中文提示，而不是把 nmap 的原始 stderr 直接抛出去。
            // 原因：nmap 会把 Windows 本地化的错误详情写成一行无法还原的乱码
            // （实测字节为 "N鍂S愘?h剉;N:g0"，既不是合法 GBK 也不是可读 UTF-8），
            // 直接把 stderr 拼进异常消息会让用户看到一串乱码，反而读不懂到底哪里错了。
            throw new InvalidOperationException(
                $"无法解析目标地址 \"{target}\"，请检查 IP / 主机名格式或网络 DNS 是否可用。");
          }
          if (proc.ExitCode != 0)
          {
            throw new InvalidOperationException(
                $"nmap 执行失败（退出码 {proc.ExitCode}）: {ExtractNmapError(stderr)}");
          }
        }
      }
      catch (OperationCanceledException)
      {
        // 无论用户取消还是保险丝超时，都必须先杀掉子进程。
        // Windows 上 Kill(true) 会连同子进程树一起终止，避免 nmap 的 NSE
        // 派生子进程（如 smbclient）残留并继续持有端口/句柄。
        try { proc.Kill(true); } catch { /* 已退出 */ }

        if (fuseCts.IsCancellationRequested && !ct.IsCancellationRequested)
        {
          // 保险丝先触发：nmap 进程挂死而非用户点「停止」。
          // 用 TimeoutException 而非 OperationCanceledException，
          // 让 UI 能把它渲染成「扫描超时」而不是「已取消」。
          throw new TimeoutException(
              $"nmap 扫描超过最长时限（约 {TimeSpan.FromMilliseconds(hostBudgetMs).TotalMinutes:F0} 分钟 + 15 分钟余量）未完成，已强制终止。" +
              "目标可能对探测无响应（防火墙静默丢包/主机离线），请检查目标可达性或缩小扫描范围。");
        }
        throw; // 用户主动取消，原样透传 OperationCanceledException
      }

      return result;
    }

    /// <summary>
    /// 启动 nmap 子进程。文件在构造后被删除/被占用/无执行权限时，
    /// <see cref="Process.Start(ProcessStartInfo)"/> 抛的是 <see cref="Win32Exception"/>（如 ERROR_FILE_NOT_FOUND=2），
    /// 直接透出会让调用方看到一串无上下文的系统错误码；这里统一转成可读的业务异常。
    /// </summary>
    private Process? StartNmapProcess(ProcessStartInfo psi)
    {
      try
      {
        return Process.Start(psi);
      }
      catch (Exception ex) when (ex is Win32Exception || ex is FileNotFoundException)
      {
        throw new InvalidOperationException(
            $"无法启动 nmap（路径: {_nmapPath ?? "<未指定>"}）: {ex.Message}", ex);
      }
    }

    /// <summary>
    /// 从 nmap stderr 中提取可读的错误摘要（去掉大量空白与重复换行）。
    /// nmap 的错误通常是 "nmap: unrecognized option ..." 或 "Failed to resolve ..." 一类单行信息。
    /// </summary>
    private static string ExtractNmapError(string stderr)
    {
      if (string.IsNullOrWhiteSpace(stderr)) return "nmap 未返回错误信息";

      var lines = stderr
          .Split('\n')
          .Select(l => l.Trim())
          .Where(l => l.Length > 0)
          .ToList();

      if (lines.Count == 0) return "nmap 未返回错误信息";

      // nmap 的 stderr 会把「无害提示」和「真正的失败原因」混在一起，且无害提示通常排在前面。
      // 实测无效目标时前两行是 raw socket 警告（"You have specified some options that require
      // raw socket access."），真正的 "Error resolving ..." 排在后面。
      // 若机械取前 3 行，用户看到的全是警告，读不到任何失败原因，等于没报错。
      // 因此优先挑选含失败关键字的行，只有一行关键字都没有时才回退到前 3 行。
      var keyLines = lines.Where(IsFailureLine).ToList();
      var picked = (keyLines.Count > 0 ? keyLines : lines).ToList();

      // 再优先保留纯 ASCII 行：nmap 自身的英文提示（Error resolving / QUITTING / illegal ...）
      // 一定不含非 ASCII 字符；而 Windows 本地化的错误详情在中文系统上会变成无法还原的乱码
      // （实测字节 "N鍂S愘?h剉;N:g0"，GBK 与 UTF-8 解码都读不通）。
      // 丢弃非 ASCII 行既能保证用户读到可理解的原因，也不会丢信息 —— 关键原因都在英文行里。
      var asciiLines = picked.Where(IsAsciiLine).ToList();
      if (asciiLines.Count > 0) picked = asciiLines;

      var summary = string.Join(" | ", picked.Take(3));
      return summary.Length > 500 ? summary.Substring(0, 500) + "..." : summary;
    }

    /// <summary>
    /// nmap 的一条进度采样：所属阶段名、该阶段内的完成百分比，以及中文提示文本。
    /// </summary>
    internal readonly struct NmapProgressSample
    {
      public NmapProgressSample(string phase, double percentInPhase, string text)
      {
        Phase = phase;
        PercentInPhase = percentInPhase;
        Text = text;
      }

      /// <summary>阶段名，如 "SYN Stealth Scan" / "UDP Scan" / "Service scan"。</summary>
      public string Phase { get; }

      /// <summary>该阶段内的完成百分比（0-100）。nmap 每个阶段都从 0 重新计数。</summary>
      public double PercentInPhase { get; }

      /// <summary>给用户看的中文进度提示。</summary>
      public string Text { get; }
    }

    /// <summary>
    /// 把 nmap 的 <c>--stats-every</c> 统计行解析成一条进度采样；非进度行返回 null。
    /// nmap 的原始格式（实测 7.993）：
    /// <code>
    /// Stats: 0:00:15 elapsed; 0 hosts completed (1 up), 1 undergoing UDP Scan
    /// UDP Scan Timing: About 12.30% done; ETC: 18:15 (0:07:10 remaining)
    /// </code>
    /// 只取 "Timing" 行（含百分比与 ETC），因为它才能给用户「还要等多久」的预期；
    /// "Stats:" 行只是已用时长，重复回报会造成日志刷屏。
    /// </summary>
    internal static NmapProgressSample? TryParseNmapProgress(string line)
    {
      if (string.IsNullOrWhiteSpace(line)) return null;
      if (!line.Contains("Timing:", StringComparison.OrdinalIgnoreCase)) return null;

      // 形如 "UDP Scan Timing: About 12.30% done; ETC: 18:15 (0:07:10 remaining)"
      var percentIdx = line.IndexOf("About ", StringComparison.OrdinalIgnoreCase);
      var percentEnd = line.IndexOf('%', percentIdx < 0 ? 0 : percentIdx);
      var percentText = percentIdx >= 0 && percentEnd > percentIdx
          ? line.Substring(percentIdx + "About ".Length, percentEnd - percentIdx - "About ".Length).Trim()
          : "";

      // 阶段名：Timing 之前的部分（"UDP Scan" / "SYN Stealth Scan" / "Service scan" 等）
      var timingIdx = line.IndexOf("Timing:", StringComparison.OrdinalIgnoreCase);
      var phase = timingIdx > 0 ? line.Substring(0, timingIdx).Trim().TrimEnd(':') : "";

      // 剩余时间：括号内的 "0:07:10 remaining"
      var remainIdx = line.IndexOf("remaining", StringComparison.OrdinalIgnoreCase);
      var remain = "";
      if (remainIdx > 0)
      {
        var open = line.LastIndexOf('(', remainIdx);
        var close = line.IndexOf(')', remainIdx);
        if (open >= 0 && close > open)
        {
          remain = line.Substring(open + 1, close - open - 1).Replace("remaining", "", StringComparison.OrdinalIgnoreCase).Trim();
        }
      }

      if (percentText.Length == 0 && remain.Length == 0) return null;

      // 百分比解析失败时按 0 处理：进度条不前进，但日志里的提示仍然有效
      double percent = 0;
      if (percentText.Length > 0)
        double.TryParse(percentText, NumberStyles.Float, CultureInfo.InvariantCulture, out percent);

      var phaseText = string.IsNullOrEmpty(phase) ? "扫描" : phase;
      var percentPart = percentText.Length == 0 ? "" : $" {percentText}% 完成";
      var remainPart = remain.Length == 0 ? "" : $"，剩余约 {remain}";
      return new NmapProgressSample(phase, percent, $"⏳ nmap {phaseText}{percentPart}{remainPart}");
    }

    /// <summary>
    /// 解析 XML 输出模式下的进度元素；非进度行返回 null。
    /// 实测格式（nmap 7.993，-oX - 时写在 stdout）：
    /// <code>
    /// &lt;taskprogress task="SYN Stealth Scan" time="1795000597" percent="0.03"/&gt;
    /// </code>
    /// <c>percent</c> 是百分比数值（0.03 表示 0.03%），可直接作为阶段内完成度使用。
    /// </summary>
    internal static NmapProgressSample? TryParseNmapTaskProgress(string line)
    {
      if (string.IsNullOrWhiteSpace(line)) return null;
      if (!line.Contains("<taskprogress", StringComparison.Ordinal)) return null;

      var task = ReadXmlAttribute(line, "task");
      var percentText = ReadXmlAttribute(line, "percent");
      if (task.Length == 0 && percentText.Length == 0) return null;

      // 百分比解析失败时按 0 处理：进度不前进，但日志提示仍然有效
      double percent = 0;
      if (percentText.Length > 0)
        double.TryParse(percentText, NumberStyles.Float, CultureInfo.InvariantCulture, out percent);

      var remain = ReadXmlAttribute(line, "remaining");
      var phaseText = task.Length == 0 ? "扫描" : task;
      var percentPart = percentText.Length == 0 ? "" : $" {percentText}% 完成";
      var remainPart = remain.Length == 0 ? "" : $"，剩余约 {remain}";
      return new NmapProgressSample(task, percent, $"⏳ nmap {phaseText}{percentPart}{remainPart}");
    }

    /// <summary>
    /// 从单行 XML 片段中读取属性值（仅用于解析 nmap 的扁平 &lt;taskprogress/&gt; 元素，
    /// 不引入完整 XML 解析器：该元素可能在流式读取时跨缓冲区，用轻量字符串匹配更稳妥）。
    /// </summary>
    private static string ReadXmlAttribute(string line, string name)
    {
      var key = name + "=\"";
      var idx = line.IndexOf(key, StringComparison.Ordinal);
      if (idx < 0) return "";
      idx += key.Length;
      var end = line.IndexOf('"', idx);
      return end > idx ? line.Substring(idx, end - idx) : "";
    }

    /// <summary>
    /// 把 nmap 各扫描阶段内的百分比折算成整次扫描的 0-100% 进度。
    /// nmap 每个阶段（SYN 扫描 / UDP 扫描 / 服务识别 / OS 识别 / NSE / Traceroute）都从 0%
    /// 重新计数，直接透传会让进度条在阶段切换时回退。这里按 nmap 的实际执行顺序给每个
    /// 阶段分配固定区间：端口扫描占大头（TCP+UDP 时各 40%），其余阶段依次占用剩余区间。
    /// 同时做单调递增保护，避免 nmap 输出抖动导致进度条倒退。
    /// </summary>
    internal sealed class NmapPhaseProgress
    {
      /// <summary>端口扫描阶段的第一个子阶段（TCP 扫描）区间上界。</summary>
      private readonly double _tcpPortSpan;

      /// <summary>UDP 端口扫描阶段区间起点（= TCP 阶段上界；仅 UDP 时为 0）。</summary>
      private readonly double _udpPortBase;

      /// <summary>UDP 端口扫描阶段区间跨度。</summary>
      private readonly double _udpPortSpan;

      private double _reported = -1;

      /// <summary>
      /// 串行化访问保护：stderr 解析在独立线程上跑，stdout 解析在主线程上跑，
      /// 两条通道都会调用 <see cref="Accept"/>。若不加锁，单调递增保护会被并发写破坏，
      /// 表现为进度条偶发回退。
      /// </summary>
      private readonly object _syncRoot = new();

      public NmapPhaseProgress(bool tcpEnabled, bool udpEnabled)
      {
        if (tcpEnabled && udpEnabled)
        {
          _tcpPortSpan = 40;
          _udpPortBase = 40;
          _udpPortSpan = 40;
        }
        else if (udpEnabled)
        {
          _tcpPortSpan = 0;
          _udpPortBase = 0;
          _udpPortSpan = 80;
        }
        else
        {
          _tcpPortSpan = 80;
          _udpPortBase = 80;
          _udpPortSpan = 0;
        }
      }

      /// <summary>最近一次回报的整体百分比（未回报过时为 -1）。</summary>
      public double ReportedPercent => _reported;

      /// <summary>
      /// 接收一条阶段内采样，返回折算后的整体百分比（0-100，单调不减）。
      /// </summary>
      public double Accept(string phase, double percentInPhase)
      {
        lock (_syncRoot)
        {
          return AcceptCore(phase, percentInPhase);
        }
      }

      private double AcceptCore(string phase, double percentInPhase)
      {
        var name = phase ?? "";
        double baseOf;
        double span;

        if (IsUdpScanPhase(name))
        {
          baseOf = _udpPortBase;
          span = _udpPortSpan;
        }
        else if (name.IndexOf("Service scan", StringComparison.OrdinalIgnoreCase) >= 0)
        {
          baseOf = 80;
          span = 13;
        }
        else if (name.IndexOf("OS detection", StringComparison.OrdinalIgnoreCase) >= 0)
        {
          baseOf = 93;
          span = 4;
        }
        else if (name.IndexOf("NSE", StringComparison.OrdinalIgnoreCase) >= 0
              || name.IndexOf("Script", StringComparison.OrdinalIgnoreCase) >= 0)
        {
          baseOf = 97;
          span = 2;
        }
        else if (name.IndexOf("Traceroute", StringComparison.OrdinalIgnoreCase) >= 0)
        {
          baseOf = 99;
          span = 1;
        }
        else if (IsPortScanPhase(name))
        {
          baseOf = 0;
          span = _tcpPortSpan;
        }
        else
        {
          // 未知阶段：保持当前进度不动，避免进度条乱跳
          return _reported < 0 ? 0 : _reported;
        }

        var clamped = percentInPhase < 0 ? 0 : (percentInPhase > 100 ? 100 : percentInPhase);
        var overall = baseOf + clamped / 100.0 * span;
        if (overall < _reported) overall = _reported;
        _reported = overall;
        return overall;
      }

      private static bool IsUdpScanPhase(string phase) =>
        phase.IndexOf("UDP Scan", StringComparison.OrdinalIgnoreCase) >= 0
        || phase.IndexOf("UDP", StringComparison.OrdinalIgnoreCase) >= 0;

      private static bool IsPortScanPhase(string phase) =>
        phase.IndexOf("SYN", StringComparison.OrdinalIgnoreCase) >= 0
        || phase.IndexOf("Connect Scan", StringComparison.OrdinalIgnoreCase) >= 0
        || phase.IndexOf("Scan", StringComparison.OrdinalIgnoreCase) >= 0;
    }

    /// <summary>
    /// 判断一行是否全为可打印 ASCII 字符（0x20-0x7E）。
    /// nmap 自身的英文提示满足该条件，本地化乱码不满足。
    /// </summary>
    private static bool IsAsciiLine(string line)
    {
      foreach (var ch in line)
      {
        if (ch < 0x20 || ch > 0x7E) return false;
      }
      return line.Length > 0;
    }

    /// <summary>
    /// 判断一行 stderr 是否包含失败原因关键字（错误 / 解析失败 / 权限不足 / 参数非法等）。
    /// 用于把真正的失败原因从 nmap 的冗长警告流里挑出来。
    /// </summary>
    private static bool IsFailureLine(string line)
    {
      return line.Contains("error", StringComparison.OrdinalIgnoreCase)
          || line.Contains("failed", StringComparison.OrdinalIgnoreCase)
          || line.Contains("resolve", StringComparison.OrdinalIgnoreCase)
          || line.Contains("quit", StringComparison.OrdinalIgnoreCase)
          || line.Contains("permission", StringComparison.OrdinalIgnoreCase)
          || line.Contains("denied", StringComparison.OrdinalIgnoreCase)
          || line.Contains("no targets", StringComparison.OrdinalIgnoreCase)
          || line.Contains("illegal", StringComparison.OrdinalIgnoreCase)
          || line.Contains("invalid", StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>
    /// 把端口列表压缩为 nmap 的 -p 参数格式：连续段用 start-end，其余逗号分隔。
    /// 例：[1,2,3,5,80,443,444] → "1-3,5,80,443-444"。
    /// 避免大端口集（如全端口 65535 个）超出 Windows 命令行长度限制。
    /// </summary>
    internal static string CompressPortRanges(List<int> ports)
    {
      if (ports == null || ports.Count == 0) return "";
      var sorted = ports.Where(p => p > 0 && p <= 65535).Distinct().OrderBy(p => p).ToList();
      if (sorted.Count == 0) return "";

      var parts = new List<string>();
      int start = sorted[0], prev = sorted[0];
      for (var i = 1; i < sorted.Count; i++)
      {
        var p = sorted[i];
        if (p == prev + 1) { prev = p; continue; }
        parts.Add(start == prev ? start.ToString() : $"{start}-{prev}");
        start = prev = p;
      }
      parts.Add(start == prev ? start.ToString() : $"{start}-{prev}");
      return string.Join(",", parts);
    }

    /// <summary>
    /// 按真实端口规模估算主机的总扫描预算（毫秒），同时作为
    /// <c>--host-timeout</c> 与 C# 侧进程级保险丝的统一口径。
    ///
    /// 口径：端口数 × 每端口预算 × 协议数，夹在 5 分钟 ~ 2 小时之间。
    /// 每端口预算：TCP 60ms（等待握手超时量级）、UDP 120ms（无握手，只能靠
    /// 等待回包判定，单端口预算必须显著高于 TCP）。
    ///
    /// 注意这个值只作「防止永久卡死」的安全网，必须远大于实际预期耗时（宁大勿小）：
    /// 实测假阴性（nmap 7.993，本机 127.0.0.1）——Builder 按 TcpTimeout*3 生成
    /// <c>--host-timeout 9000ms</c>，而全端口 TCP+UDP+服务识别根本不可能 9 秒完成，
    /// nmap 在第 9 秒放弃主机并输出 <c>&lt;host timedout="true"&gt;</c> 且 &lt;ports&gt; 为空，
    /// 明明 40+ 个端口开放却返回 0 条结果。故这里宁大勿小、只设上限不设下限。
    /// </summary>
    public static long EstimateHostBudgetMs(List<int> ports, ExpertScanConfiguration config)
    {
      var protocolCount = (config.TcpScan ? 1 : 0) + (config.UdpScan ? 1 : 0);
      if (protocolCount == 0) protocolCount = 1;
      var count = ports?.Count ?? 0;
      var perPortMs = config.UdpScan ? 120L : 60L;
      var budget = (long)count * perPortMs * protocolCount;
      return Math.Clamp(budget, 300_000L, 7_200_000L);
    }

    /// <summary>
    /// 把所有结果状态统一补到 2 值：本引擎只回传 hit 状态（开放/开放或过滤），
    /// 关闭端口由调用方决定是否补齐。这里保留原样。
    /// </summary>
    private static IEnumerable<string> SplitCommand(string command)
    {
      var parts = new List<string>();
      var current = new StringBuilder();
      bool inQuote = false;
      foreach (var ch in command)
      {
        if (ch == '"') { inQuote = !inQuote; continue; }
        if (ch == ' ' && !inQuote)
        {
          if (current.Length > 0) { parts.Add(current.ToString()); current.Clear(); }
          continue;
        }
        current.Append(ch);
      }
      if (current.Length > 0) parts.Add(current.ToString());
      return parts.Where(p => !string.IsNullOrWhiteSpace(p));
    }

    public void Dispose() { }
  }
}