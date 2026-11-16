using System;
using System.Collections.Generic;
using System.Diagnostics;
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
      _nmapPath = string.IsNullOrWhiteSpace(nmapPath) ? null : nmapPath;
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
      using var proc = Process.Start(psi);
      if (proc == null) return "";

      var stdout = await proc.StandardOutput.ReadToEndAsync().ConfigureAwait(false);
      await proc.WaitForExitAsync(ct).ConfigureAwait(false);

      // 形如: Nmap version 7.95 ( https://nmap.org )
      var line = stdout.Split('\n').FirstOrDefault(l => l.Contains("Nmap version", StringComparison.OrdinalIgnoreCase));
      return line?.Trim() ?? "";
    }

    /// <summary>
    /// 用 nmap 实际扫描目标的一组端口。
    /// </summary>
    /// <param name="target">目标 IP / 主机名（本例只处理单目标）。</param>
    /// <param name="ports">要扫描的端口号列表；为空时交给 nmap 默认（top-ports 1000）。</param>
    /// <param name="config">专家模式界面配置，用于构建扫描参数。</param>
    /// <param name="progress">进度回调（每完成一个目标内部固定为端口批量完成时回调）。</param>
    public async Task<List<PortScanResult>> ScanAsync(
        string target,
        List<int> ports,
        ExpertScanConfiguration config,
        IProgress<int>? progress = null,
        CancellationToken ct = default)
    {
      var result = new List<PortScanResult>();
      if (_nmapPath == null) return result;

      // 用 NmapCommandBuilder 生成完整命令参数，再追加 XML-stdout 输出与目标。
      // 注意 Builder 的输出以 "nmap " 为前缀且末尾是目标，这里会剥掉前缀、重组参数，
      // 保证 -oX - 与目标顺序正确。
      var baseCmd = NmapCommandBuilder.Build(config, timestamp: "scan_live");
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
      string[] valueFlags = { "--top-ports", "-p", "--exclude-ports", "--exclude-hosts", "--max-retries", "--min-rate", "--max-rate" };
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
      if (ports != null && ports.Count > 0)
      {
        // Windows CreateProcess 对单行命令行有 ~32767 字符限制；
        // 65535 个端口逐个拼成 "1,2,3,..." 会超限导致进程启动失败
        // （实测取消测试报"文件名或扩展名太长"）。改用连续区间压缩：
        // 1,2,3,...,1024 → "1-1024"，命令行长度恒定且 nmap 完全支持。
        tokens.Add("-p");
        tokens.Add(CompressPortRanges(ports));
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

      using var proc = Process.Start(psi);
      if (proc == null) return result;

      try
      {
        // 流式读取 stdout（nmap 的进度注释行以 "# " 开头，可忽略）
        var sb = new StringBuilder();
        var buf = new char[8192];
        int read;
        while ((read = await proc.StandardOutput.ReadAsync(buf, 0, buf.Length).ConfigureAwait(false)) > 0)
        {
          ct.ThrowIfCancellationRequested();
          sb.Append(buf, 0, read);
          progress?.Report(sb.Length);
        }

        await proc.WaitForExitAsync(ct).ConfigureAwait(false);
        result = NmapXmlParser.Parse(sb.ToString());
      }
      catch (OperationCanceledException)
      {
        try { proc.Kill(true); } catch { /* 已退出 */ }
        throw;
      }

      return result;
    }

    /// <summary>
    /// 把端口列表压缩为 nmap 的 -p 参数格式：连续段用 start-end，其余逗号分隔。
    /// 例：[1,2,3,5,80,443,444] → "1-3,5,80,443-444"。
    /// 避免大端口集（如全端口 65535 个）超出 Windows 命令行长度限制。
    /// </summary>
    private static string CompressPortRanges(List<int> ports)
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