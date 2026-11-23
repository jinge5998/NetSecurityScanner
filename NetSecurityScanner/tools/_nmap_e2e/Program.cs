using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using NetSecurityScanner.Core.Models;
using NetSecurityScanner.Core.Services;
using NetSecurityScanner.Models;
using NetSecurityScanner.Services;

internal static class Program
{
  private static async Task<int> Main(string[] args)
  {
    if (args.Length < 3)
    {
      Console.WriteLine("usage: nmap_e2e <nmap.exe path> <target> <rust-scanner-service.exe path>");
      return 2;
    }

    var nmapPath = ResolveExistingPath(args[0]);
    var target = args[1];
    var rustExe = ResolveExistingPath(args[2]);
    if (nmapPath == null || rustExe == null)
    {
      Console.WriteLine("nmap.exe 或 rust-scanner-service.exe 路径不存在，请传入绝对路径后重试");
      return 2;
    }

    Console.WriteLine("=== 1. 执行器可用性与版本 ===");
    using var executor = new NmapEngineExecutor(nmapPath);
    Console.WriteLine($"IsAvailable={executor.IsAvailable}");
    Console.WriteLine($"NmapPath={executor.NmapPath}");
    Console.WriteLine($"Version={await executor.GetVersionAsync()}");
    Console.WriteLine($"LocateNmap()(当前工作目录无关)={NmapEngineExecutor.LocateNmap() ?? "<not found>"}");

    // 配置模拟「专家模式」默认：TCP 连接扫描 + 服务识别 + 默认 Common 端口模式。
    // PortMode=Common 会让 NmapCommandBuilder 产出 --top-ports 1000 展示参数，
    // 正是执行器必须剥离的干扰项，用它验证参数清洗是否生效。
    var config = new ExpertScanConfiguration
    {
      TargetValue = target,
      TcpScan = true,
      ServiceDetection = true,
      Verbosity = 0,
      SaveOutput = false
    };

    Console.WriteLine();
    Console.WriteLine("=== 2. 精确端口扫描 (21,23,80,443,3389) ===");
    var portsA = new List<int> { 21, 23, 80, 443, 3389 };
    var swA = Stopwatch.StartNew();
    var resultsA = await executor.ScanAsync(target, portsA, config, null, CancellationToken.None);
    swA.Stop();
    Console.WriteLine($"耗时={swA.Elapsed.TotalSeconds:F1}s 结果条数={resultsA.Count}");
    foreach (var r in resultsA.OrderBy(r => r.PortNumber))
    {
      Console.WriteLine($"  {r.PortNumber,-5} {r.Status,-6} svc={r.Service,-22} ver={r.ServiceVersion,-8} conf={r.Confidence}");
    }

    Console.WriteLine();
    Console.WriteLine("=== 3. 大端口集扫描 (1-200，验证端口区间压缩) ===");
    var portsB = Enumerable.Range(1, 200).ToList();
    var swB = Stopwatch.StartNew();
    var resultsB = await executor.ScanAsync(target, portsB, config, null, CancellationToken.None);
    swB.Stop();
    var openB = resultsB.Where(r => r.Status == "开放").ToList();
    Console.WriteLine($"耗时={swB.Elapsed.TotalSeconds:F1}s 结果条数={resultsB.Count} 开放={openB.Count}");
    foreach (var r in openB.OrderBy(r => r.PortNumber))
    {
      Console.WriteLine($"  {r.PortNumber,-5} {r.Status,-6} svc={r.Service,-22} ver={r.ServiceVersion,-8}");
    }

    Console.WriteLine();
    Console.WriteLine("=== 4. 漏洞扫描链路（nmap 结果 → VulnerabilityScanner）===");
    var openForVuln = resultsA.Where(r => r.Status == "开放").ToList();
    var vulnScanner = new VulnerabilityScanner();
    var swC = Stopwatch.StartNew();
    var vulns = await vulnScanner.ScanVulnerabilitiesAsync(target, openForVuln, CancellationToken.None);
    swC.Stop();
    Console.WriteLine($"耗时={swC.Elapsed.TotalSeconds:F1}s 漏洞条数={vulns.Count}");
    foreach (var v in vulns.OrderByDescending(v => v.RiskLevel).Take(15))
    {
      Console.WriteLine($"  [{v.RiskLevel}] {v.CveId,-16} port={v.Port,-5} {v.Name}");
    }

    Console.WriteLine();
    Console.WriteLine("=== 4.5 错误路径验证（非法 NSE 脚本应抛出可读异常）===");
    var badConfig = new ExpertScanConfiguration
    {
      TargetValue = target,
      TcpScan = true,
      ServiceDetection = true,
      ScriptScan = true,
      NseScriptArgs = "definitely-not-an-existing-script",
      Verbosity = 0,
      SaveOutput = false
    };
    try
    {
      var badResults = await executor.ScanAsync(target, new List<int> { 80 }, badConfig, null, CancellationToken.None);
      Console.WriteLine($"未抛出异常，结果条数={badResults.Count}（预期抛出异常）");
    }
    catch (Exception ex)
    {
      Console.WriteLine($"捕获异常类型={ex.GetType().Name}");
      Console.WriteLine($"异常信息={ex.Message}");
    }

    Console.WriteLine();
    Console.WriteLine("=== 5.5 内置 C# 引擎（对应专家模式「内置C#引擎」单选）===");
    var nativeOk = false;
    try
    {
      using var nativeScanner = new PortScanner();
      var swN = Stopwatch.StartNew();
      var nativeResults = await nativeScanner.ScanPortsAsync(target, portsA, null, CancellationToken.None);
      swN.Stop();
      var nativeOpen = nativeResults.Where(r => r.Status == "开放").ToList();
      Console.WriteLine($"耗时={swN.Elapsed.TotalSeconds:F1}s 结果条数={nativeResults.Count} 开放={nativeOpen.Count}");
      foreach (var r in nativeResults.OrderBy(r => r.PortNumber).Take(10))
        Console.WriteLine($"  {r.PortNumber,-5} {r.Status,-6} svc={r.Service}");
      nativeOk = nativeOpen.Any(r => r.PortNumber == 3389);
    }
    catch (Exception ex)
    {
      Console.WriteLine($"内置引擎异常: {ex.GetType().Name}: {ex.Message}");
    }

    Console.WriteLine();
    Console.WriteLine("=== 6. RustScan 引擎（按 ExpertModeWindow 真实调用顺序）===");
    var rustOk = false;
    var rustUdpOk = false;
    RustScannerClient? rustClient = null;
    try
    {
      rustClient = new RustScannerClient();
      rustClient.OnLog += (_, msg) => Console.WriteLine($"  [Rust] {msg}");
      var started = await rustClient.StartServiceAsync(rustExe, 1000, 200, 500);
      Console.WriteLine($"StartServiceAsync={started} IsConnected={rustClient.IsConnected}");
      if (started)
      {
        var profile = ScanConfigMapper.ToScanProfileConfig(config);
        var swR = Stopwatch.StartNew();
        var rustTcp = await rustClient.ScanPortsAsync(
            new List<string> { target }, portsA, "tcp",
            1000, 200, 500, true, true, CancellationToken.None, profile);
        swR.Stop();
        Console.WriteLine($"耗时={swR.Elapsed.TotalSeconds:F1}s 原始结果数={rustTcp.Count}");
        foreach (var r in rustTcp.OrderBy(r => r.Port).Take(10))
        {
          var st = (r.Status ?? "").Trim().ToLowerInvariant();
          var isOpen = st == "open" || st == "opened" || st == "true" || st == "开放";
          Console.WriteLine($"  {r.Port,-5} raw=[{r.Status}] isOpen={isOpen} svc={r.Service,-20} ver={r.Version}");
          if (isOpen) rustOk = true;
        }

        // 第二阶段：在同一连接上追加 UDP 请求，复现专家模式「TCP 阶段 → UDP 阶段」复用连接
        // 旧版 Rust 服务每条连接只处理一个请求，第二次请求会打到已关闭的连接上并静默回退到内置扫描器
        var swU = Stopwatch.StartNew();
        var rustUdp = await rustClient.ScanPortsAsync(
            new List<string> { target }, new List<int> { 53, 123, 161, 500 }, "udp",
            1000, 200, 500, false, true, CancellationToken.None, profile);
        swU.Stop();
        Console.WriteLine($"UDP 阶段耗时={swU.Elapsed.TotalSeconds:F1}s 结果数={rustUdp.Count} IsConnected={rustClient.IsConnected}");
        foreach (var r in rustUdp.OrderBy(r => r.Port))
          Console.WriteLine($"  [UDP] {r.Port,-5} raw=[{r.Status}] svc={r.Service}");
        rustUdpOk = rustUdp.Count > 0 && rustClient.IsConnected;
      }
    }
    catch (Exception ex)
    {
      Console.WriteLine($"Rust 引擎异常: {ex.GetType().Name}: {ex.Message}");
    }
    finally
    {
      try { rustClient?.StopService(); } catch { }
      try { rustClient?.Dispose(); } catch { }
    }

    Console.WriteLine();
    Console.WriteLine("=== 6.5 专家模式超时接线验证（本次修复项）===");
    // 复现专家模式界面配置：UDP 扫描 + 服务识别，分别用「未调整滑块」与「调大两个超时滑块」
    var udpDefaultCfg = new ExpertScanConfiguration
    {
      TargetValue = target,
      TcpScan = true,
      UdpScan = true,
      ServiceDetection = true,
      UdpTimeout = 1000,
      ServiceDetectTimeout = 2000,
      Verbosity = 0,
      SaveOutput = false
    };
    var udpRaisedCfg = new ExpertScanConfiguration
    {
      TargetValue = target,
      TcpScan = true,
      UdpScan = true,
      ServiceDetection = true,
      UdpTimeout = 5000,
      ServiceDetectTimeout = 5000,
      Verbosity = 0,
      SaveOutput = false
    };
    var cmdDefault = NmapCommandBuilder.Build(udpDefaultCfg, ttl: 64, timestamp: "t");
    var cmdRaised = NmapCommandBuilder.Build(udpRaisedCfg, ttl: 64, timestamp: "t");
    Console.WriteLine($"默认滑块命令: {cmdDefault}");
    Console.WriteLine($"调大滑块命令: {cmdRaised}");
    var wiringOk = !cmdDefault.Contains("--max-rtt-timeout 5000ms")
                   && cmdRaised.Contains("--max-rtt-timeout 5000ms");
    Console.WriteLine($"命令层接线生效(UdpTimeout/ServiceDetectTimeout 进入 nmap 参数): {wiringOk}");
    // 修复后 host-timeout 无条件生成（防 SYN 被静默丢弃时全端口扫描无限徘徊），
    // 且按端口规模预算而非滑块值计算，因此调大超时不收紧 host-timeout（避免假阴性）。
    var hostDefault = ExtractHostTimeoutMs(cmdDefault);
    var hostRaised = ExtractHostTimeoutMs(cmdRaised);
    Console.WriteLine($"host-timeout 无条件存在(防卡死): {hostDefault.HasValue && Math.Abs((hostRaised ?? 0) - (hostDefault ?? 0)) <= 1}");
    Console.WriteLine($"调大超时不应收紧 host-timeout(避免假阴性): {hostDefault.HasValue && !hostRaised.HasValue == false && (hostRaised ?? long.MaxValue) >= (hostDefault ?? 0)}");

    Console.WriteLine();
    Console.WriteLine("--- 真实扫描对比：500/udp（IKE 探针 bind 重试场景）---");
    var swUdpDefault = Stopwatch.StartNew();
    var udpResDefault = await executor.ScanAsync(target, new List<int> { 500 }, udpDefaultCfg, null, CancellationToken.None);
    swUdpDefault.Stop();
    Console.WriteLine($"默认滑块: 耗时={swUdpDefault.Elapsed.TotalSeconds:F1}s 结果={udpResDefault.Count}");

    var swUdpRaised = Stopwatch.StartNew();
    var udpResRaised = await executor.ScanAsync(target, new List<int> { 500 }, udpRaisedCfg, null, CancellationToken.None);
    swUdpRaised.Stop();
    Console.WriteLine($"调大滑块: 耗时={swUdpRaised.Elapsed.TotalSeconds:F1}s 结果={udpResRaised.Count}");
    // 关键判定：调大超时后结果条数不得减少（否则就是「调大反而扫不到」的假阴性回归）
    var timeoutGuardOk = udpResRaised.Count >= udpResDefault.Count;
    Console.WriteLine($"调大超时无假阴性(结果数不减少): {timeoutGuardOk}");

    Console.WriteLine();
    Console.WriteLine("=== 8. 全端口 1-65535 三引擎对比（基准=裸 nmap）===");
    // 基准刻意绕过本项目的解析器与命令构建器，直接用 nmap 取真值，
    // 避免「用被测代码验证被测代码」导致的循环论证。
    var truthPorts = await RunRawNmapOpenPortsAsync(nmapPath, target);
    Console.WriteLine($"基准开放端口数={truthPorts.Count}: {string.Join(" ", truthPorts.OrderBy(p => p))}");

    var allPorts = Enumerable.Range(1, 65535).ToList();
    // 内置引擎在「低并发 + 每端口失败后重试一次」的组合下吞吐有限，
    // 全端口实测会跑到小时级，故用 1-5000 抽样量出单端口成本再外推。
    var nativeSamplePorts = Enumerable.Range(1, 5000).ToList();

    // 8.1 内置 C# 引擎：复刻用户报障时的参数（TCP 并发 20 / 超时 3000ms / 限速 500 端口每秒）
    var userPolicy = new ScanPolicy
    {
      Name = "用户报障参数复刻",
      NetworkScanConfig = new NetworkScanConfig
      {
        EnableTcpScan = true,
        EnableUdpScan = false,
        PortTimeout = 3000,
        SmallPortRangeThreshold = 20
      },
      RateLimitConfig = new RateLimitConfig
      {
        MaxConcurrentConnections = 20,
        UdpMaxConcurrentConnections = 10,
        EnableRateLimit = true,
        PortScanRate = 500
      },
      TimeoutConfig = new TimeoutConfig
      {
        TcpTimeout = 3000,
        UdpTimeout = 1000,
        SmallPortRangeTimeout = 3000
      },
      ServiceDetectionConfig = ServiceDetectionConfig.FromIntensity(true, 1, 3000)
    };

    var nativeFullOk = false;
    try
    {
      using var nativeFull = new PortScanner();
      var swNf = Stopwatch.StartNew();
      var nativeFullResults = await nativeFull.ScanTcpPortsAsync(target, nativeSamplePorts, null, CancellationToken.None, userPolicy);
      swNf.Stop();
      var nativeOpenPorts = nativeFullResults
          .Where(r => r.Status == "开放")
          .Select(r => r.PortNumber)
          .Distinct()
          .ToList();
      var perPortMs = swNf.Elapsed.TotalMilliseconds / nativeSamplePorts.Count;
      Console.WriteLine($"内置引擎 抽样 1-5000 耗时={swNf.Elapsed.TotalSeconds:F1}s 单端口={perPortMs:F1}ms 结果条数={nativeFullResults.Count} 开放={nativeOpenPorts.Count}");
      Console.WriteLine($"内置引擎 外推全端口 1-65535 预计耗时≈{perPortMs * 65535 / 60000:F1} 分钟");
      Console.WriteLine($"内置引擎 抽样开放端口: {string.Join(" ", nativeOpenPorts.OrderBy(p => p))}");
      var truthInSample = truthPorts.Where(p => p <= 5000).ToList();
      Console.WriteLine($"内置引擎 抽样命中率={HitRate(truthInSample, nativeOpenPorts):P1} 漏报={string.Join(" ", truthInSample.Except(nativeOpenPorts).OrderBy(p => p))}");
      nativeFullOk = nativeOpenPorts.Count > 0;
    }
    catch (Exception ex)
    {
      Console.WriteLine($"内置引擎 全端口异常: {ex.GetType().Name}: {ex.Message}");
    }

    // 8.2 RustScan 引擎：同一端口全集、同一目标
    var rustFullOk = false;
    try
    {
      using var rustFullClient = new RustScannerClient();
      rustFullClient.OnLog += (_, msg) => Console.WriteLine($"  [Rust-Full] {msg}");
      if (await rustFullClient.StartServiceAsync(rustExe, 1000, 200, 500))
      {
        var profile = ScanConfigMapper.ToScanProfileConfig(config);
        var swRf = Stopwatch.StartNew();
        var rustFullResults = await rustFullClient.ScanPortsAsync(
            new List<string> { target }, allPorts, "tcp",
            1000, 200, 500, true, true, CancellationToken.None, profile);
        swRf.Stop();
        var rustOpenPorts = rustFullResults
            .Where(r => IsOpenStatus(r.Status))
            .Select(r => (int)r.Port)
            .Distinct()
            .ToList();
        Console.WriteLine($"Rust 全端口 耗时={swRf.Elapsed.TotalSeconds:F1}s 结果条数={rustFullResults.Count} 开放={rustOpenPorts.Count}");
        Console.WriteLine($"Rust 开放端口: {string.Join(" ", rustOpenPorts.OrderBy(p => p))}");
        Console.WriteLine($"Rust 命中率={HitRate(truthPorts, rustOpenPorts):P1} 漏报={string.Join(" ", truthPorts.Except(rustOpenPorts).OrderBy(p => p))}");
        rustFullOk = rustOpenPorts.Count > 0;
      }
    }
    catch (Exception ex)
    {
      Console.WriteLine($"Rust 全端口异常: {ex.GetType().Name}: {ex.Message}");
    }

    // 8.3 漏洞扫描：喂入基准真值端口，验证「有端口时能否产出漏洞」
    var vulnFullCount = 0;
    try
    {
      var truthAsResults = truthPorts.Select(p => new PortScanResult
      {
        TargetIp = target,
        PortNumber = p,
        Status = "开放",
        Service = ""
      }).ToList();
      var swVf = Stopwatch.StartNew();
      var vulnsFull = await vulnScanner.ScanVulnerabilitiesAsync(target, truthAsResults, CancellationToken.None);
      swVf.Stop();
      vulnFullCount = vulnsFull.Count;
      Console.WriteLine($"全端口漏洞扫描 耗时={swVf.Elapsed.TotalSeconds:F1}s 漏洞条数={vulnsFull.Count}");
      foreach (var v in vulnsFull.OrderByDescending(v => v.RiskLevel).Take(10))
        Console.WriteLine($"  [{v.RiskLevel}] {v.CveId,-16} port={v.Port,-5} {v.Name}");
    }
    catch (Exception ex)
    {
      Console.WriteLine($"全端口漏洞扫描异常: {ex.GetType().Name}: {ex.Message}");
    }

    Console.WriteLine();
    Console.WriteLine("=== 7. 判定 ===");
    var okA = resultsA.Any(r => r.Status == "开放");
    var okB = openB.Count > 0;
    Console.WriteLine($"精确端口扫描命中开放端口: {okA}");
    Console.WriteLine($"大端口集扫描命中开放端口: {okB}");
    Console.WriteLine($"服务识别有效(非空 Service): {resultsA.Any(r => !string.IsNullOrWhiteSpace(r.Service))}");
    Console.WriteLine($"漏洞扫描产出结果: {vulns.Count > 0}");
    Console.WriteLine($"内置 C# 引擎命中开放端口: {nativeOk}");
    Console.WriteLine($"RustScan 引擎命中开放端口: {rustOk}");
    Console.WriteLine($"RustScan 引擎 UDP 复用同一连接: {rustUdpOk}");
    Console.WriteLine($"专家模式超时接线生效: {wiringOk}");
    Console.WriteLine($"专家模式调大超时无假阴性: {timeoutGuardOk}");
    Console.WriteLine($"内置 C# 引擎 全端口命中开放端口: {nativeFullOk}");
    Console.WriteLine($"RustScan 引擎 全端口命中开放端口: {rustFullOk}");
    Console.WriteLine($"全端口漏洞扫描产出结果: {vulnFullCount > 0}");
    return okA && okB && nativeOk && rustOk && rustUdpOk && wiringOk && timeoutGuardOk
           && nativeFullOk && rustFullOk && vulnFullCount > 0 ? 0 : 1;
  }

  /// <summary>
  /// 用裸 nmap 拿「开放端口真值」，不经过本项目的 NmapCommandBuilder / NmapXmlParser，
  /// 这样三引擎的命中率才有独立基准可对照。
  /// </summary>
  /// <summary>从 nmap 命令串里提取 --host-timeout 的毫秒值，不存在时返回 null。</summary>
  private static long? ExtractHostTimeoutMs(string cmd)
  {
    var idx = cmd.IndexOf("--host-timeout", StringComparison.Ordinal);
    if (idx < 0) return null;
    var rest = cmd.Substring(idx + "--host-timeout".Length).TrimStart();
    var numEnd = 0;
    while (numEnd < rest.Length && char.IsDigit(rest[numEnd])) numEnd++;
    if (numEnd == 0) return null;
    if (!long.TryParse(rest.Substring(0, numEnd), out var ms)) return null;
    if (numEnd < rest.Length && rest[numEnd] == 's') ms *= 1000; // "180s" 风格
    return ms;
  }

  private static async Task<List<int>> RunRawNmapOpenPortsAsync(string nmapPath, string target)
  {
    var psi = new ProcessStartInfo(nmapPath)
    {
      RedirectStandardOutput = true,
      RedirectStandardError = true,
      UseShellExecute = false,
      CreateNoWindow = true
    };
    foreach (var a in new[] { "-sT", "-n", "-Pn", "-p1-65535", "--min-rate", "2000", "-oX", "-", target })
      psi.ArgumentList.Add(a);

    using var p = Process.Start(psi)!;
    var stdoutTask = p.StandardOutput.ReadToEndAsync();
    _ = p.StandardError.ReadToEndAsync();
    await p.WaitForExitAsync();
    var xml = await stdoutTask;
    return ParseOpenPortsFromXml(xml);
  }

  private static List<int> ParseOpenPortsFromXml(string xml)
  {
    var ports = new List<int>();
    if (string.IsNullOrWhiteSpace(xml)) return ports;
    try
    {
      var doc = System.Xml.Linq.XDocument.Parse(xml);
      foreach (var port in doc.Descendants("port"))
      {
        var state = port.Element("state")?.Attribute("state")?.Value;
        var idText = port.Attribute("portid")?.Value;
        if (state == "open" && int.TryParse(idText, out var id)) ports.Add(id);
      }
    }
    catch (Exception ex)
    {
      Console.WriteLine($"基准 XML 解析失败: {ex.GetType().Name}: {ex.Message}");
    }
    return ports;
  }

  private static bool IsOpenStatus(string? status)
  {
    var st = (status ?? "").Trim().ToLowerInvariant();
    return st == "open" || st == "opened" || st == "true" || st == "开放";
  }

  private static double HitRate(List<int> truth, List<int> found)
  {
    if (truth.Count == 0) return 0;
    var hit = truth.Intersect(found).Count();
    return (double)hit / truth.Count;
  }

  private static string? ResolveExistingPath(string raw)
  {
    if (string.IsNullOrWhiteSpace(raw)) return null;
    try
    {
      var full = Path.GetFullPath(raw);
      return File.Exists(full) ? full : null;
    }
    catch
    {
      return null;
    }
  }
}