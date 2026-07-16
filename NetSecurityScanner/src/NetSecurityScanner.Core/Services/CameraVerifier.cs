using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Net.Sockets;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using NetSecurityScanner.Models;

namespace NetSecurityScanner.Core
{
  /// <summary>
  /// 摄像头精准判定器（v5-T2/T3/T4）。
  /// 多级验证：反例黑名单 → 端口启发 → 厂商关键字 → HTTP 指纹 → RTSP 响应 → ONVIF 协议。
  /// </summary>
  public class CameraVerifier : IDisposable
  {
    private readonly HttpClient _httpClient;
    private readonly List<CameraFingerprintRule> _rules;
    private bool _disposed;

    /// <summary>反例黑名单（路由器/打印机/NAS/PC 等响应中的关键词）</summary>
    public static readonly string[] AntiCameraKeywords = new[]
    {
      "D-Link", "TP-LINK Router", "TP-Link Router", "MiWiFi", "Redmi Router",
      "Xiaomi Router", "Huawei Router", "Honor Router", "H3C Router", "Ruijie",
      "iStoreOS", "OpenWrt", "iKuai", "ikuaiOS", "MikroTik", "RouterOS",
      "Synology", "DiskStation", "QNAP", "NAS",
      "HP Printer", "Brother Printer", "Canon Printer", "Epson Printer", "Lexmark",
      "Windows Server", "IIS", "Microsoft-HTTPAPI",
      "WPS Office", "Apache Tomcat", "nginx default",
      "Apple", "AirPort", "Time Capsule"
    };

    /// <summary>摄像头厂商默认端口表</summary>
    public static readonly Dictionary<string, int[]> VendorPorts = new(StringComparer.OrdinalIgnoreCase)
    {
      ["Hikvision"]    = new[] { 80, 443, 554, 8000, 8080, 8200, 8899 },
      ["Dahua"]        = new[] { 80, 443, 554, 37777, 8080, 34567, 34599 },
      ["Uniview"]      = new[] { 80, 443, 554, 34567, 8080, 9999 },
      ["Tiandy"]       = new[] { 80, 443, 554, 6036, 8080, 8899 },
      ["TP-Link"]      = new[] { 80, 443, 554, 2020, 8080, 9999 },
      ["EZVIZ"]        = new[] { 80, 443, 554, 8000, 8001, 8002 },
      ["Axis"]         = new[] { 80, 443, 554, 8080, 9090 },
      ["Bosch"]        = new[] { 80, 443, 554, 8080, 8443 },
      ["Hanwha"]       = new[] { 80, 443, 554, 8080, 8888 },
      ["Onvif"]        = new[] { 80, 443, 554, 8080, 8899 },
      ["Xiongmai"]     = new[] { 80, 34567, 34599, 8080, 8899 },
      ["Anji"]         = new[] { 80, 8080, 8899, 9999 },
      ["Tvt"]          = new[] { 80, 8080, 8899 },
    };

    /// <summary>综合所有厂商的端口去重列表（用于默认扫描）</summary>
    public static readonly int[] DefaultScanPorts = VendorPorts
        .SelectMany(kv => kv.Value)
        .Distinct()
        .OrderBy(p => p)
        .ToArray();

    public CameraVerifier()
    {
      _httpClient = new HttpClient { Timeout = TimeSpan.FromSeconds(4) };
      _httpClient.DefaultRequestHeaders.UserAgent.ParseAdd("CameraScanner/2.0");
      _rules = LoadFingerprintRules();
    }

    private List<CameraFingerprintRule> LoadFingerprintRules()
    {
      try
      {
        var assemblyLocation = typeof(CameraVerifier).Assembly.Location;
        var assemblyDir = Path.GetDirectoryName(assemblyLocation) ?? string.Empty;
        var jsonPath = Path.Combine(assemblyDir, "Data", "CameraFingerprintDB.json");
        if (!File.Exists(jsonPath))
        {
          var altPath = Path.Combine(Directory.GetCurrentDirectory(), "Data", "CameraFingerprintDB.json");
          if (File.Exists(altPath)) jsonPath = altPath;
          else return new List<CameraFingerprintRule>();
        }
        var json = File.ReadAllText(jsonPath, Encoding.UTF8);
        return JsonSerializer.Deserialize<List<CameraFingerprintRule>>(json) ?? new List<CameraFingerprintRule>();
      }
      catch (Exception ex)
      {
        System.Diagnostics.Debug.WriteLine($"[CameraVerifier] 加载指纹数据库失败: {ex.Message}");
        return new List<CameraFingerprintRule>();
      }
    }

    /// <summary>
    /// 对单个 IP 进行多级摄像头判定。
    /// </summary>
    public async Task<VerificationResult> VerifyAsync(string ip, int[]? portsToProbe = null, CancellationToken ct = default)
    {
      var result = new VerificationResult { Ip = ip, Method = "未知" };
      portsToProbe ??= DefaultScanPorts;

      // T3: 反例过滤（先看 HTTP 响应）
      var (openPorts, httpBanner, serverHeader) = await ProbeTcpAndHttpAsync(ip, portsToProbe, ct);
      result.OpenPorts = openPorts;
      result.HttpBanner = httpBanner;
      result.ServerHeader = serverHeader;

      if (IsLikelyNotCamera(httpBanner, serverHeader))
      {
        result.IsCamera = false;
        result.Confidence = 0.0;
        result.Vendor = "非摄像头（反例匹配）";
        result.Method = "反例黑名单";
        result.Evidence = $"命中反例关键词: {MatchAntiKeyword(httpBanner, serverHeader)}";
        return result;
      }

      // T2: 多级验证
      // 第一级：端口启发 - 海康 8000 / 大华 37777 / 萤石 8000/8001 等
      var vendorByPort = MatchVendorByPort(openPorts);
      if (vendorByPort != null)
      {
        result.IsCamera = true;
        result.Confidence = 0.6;
        result.Vendor = vendorByPort;
        result.Method = "端口启发";
        result.Evidence = $"开放端口包含 {vendorByPort} 默认端口";
        // 继续后续验证提高置信度
      }

      // 第二级：HTTP 指纹
      if (!string.IsNullOrEmpty(httpBanner))
      {
        var (vendorFromHttp, confidenceFromHttp, evidence) = MatchVendorFromHttp(httpBanner, serverHeader);
        if (vendorFromHttp != null)
        {
          if (result.Confidence < confidenceFromHttp)
          {
            result.Vendor = vendorFromHttp;
            result.Confidence = confidenceFromHttp;
            result.Method = "HTTP指纹";
            result.Evidence = evidence;
          }
          else
          {
            result.Confidence = Math.Min(1.0, result.Confidence + 0.15);
          }
          result.IsCamera = true;
        }
      }

      // 第三级：RTSP 响应（554 端口开放时）
      if (openPorts.Contains(554))
      {
        var vendorFromRtsp = await ProbeRtspAsync(ip, 554, ct);
        if (vendorFromRtsp != null)
        {
          if (result.Confidence < 0.75)
          {
            result.Vendor = vendorFromRtsp;
            result.Confidence = 0.75;
            result.Method = "RTSP响应";
            result.Evidence = $"554 RTSP 服务器标识匹配 {vendorFromRtsp}";
          }
          else
          {
            result.Confidence = Math.Min(1.0, result.Confidence + 0.1);
          }
          result.IsCamera = true;
        }
        else if (!result.IsCamera)
        {
          // 554 开放但 RTSP 无响应，置信度 +0.2
          result.IsCamera = true;
          result.Confidence = Math.Max(result.Confidence, 0.4);
          if (string.IsNullOrEmpty(result.Vendor)) result.Vendor = "未知（仅554开放）";
          result.Method = result.Method == "未知" ? "RTSP端口" : result.Method;
          result.Evidence = "554 RTSP 端口开放，等待握手响应";
        }
      }

      // 第四级：ONVIF 协议
      if (openPorts.Any(p => p == 80 || p == 8080 || p == 8899 || p == 8000))
      {
        var vendorFromOnvif = await ProbeOnvifAsync(ip, openPorts.First(p => p == 80 || p == 8080 || p == 8899 || p == 8000), ct);
        if (vendorFromOnvif != null)
        {
          result.IsCamera = true;
          if (result.Confidence < 0.9)
          {
            result.Vendor = vendorFromOnvif;
            result.Confidence = 0.9;
            result.Method = "ONVIF协议";
            result.Evidence = "ONVIF GetDeviceInformation 响应";
          }
          else
          {
            result.Confidence = Math.Min(1.0, result.Confidence + 0.05);
          }
        }
      }

      if (!result.IsCamera)
      {
        result.Vendor = "未识别";
        result.Method = "未识别";
        result.Evidence = $"开放端口: {(openPorts.Count > 0 ? string.Join(",", openPorts) : "无")}；无 HTTP 响应";
      }

      return result;
    }

    /// <summary>
    /// 探测 TCP 开放端口 + HTTP 响应（取第一个有响应的 HTTP 端口）。
    /// </summary>
    private async Task<(List<int> OpenPorts, string HttpBanner, string ServerHeader)> ProbeTcpAndHttpAsync(
        string ip, int[] ports, CancellationToken ct)
    {
      var open = new List<int>();
      string banner = string.Empty;
      string server = string.Empty;

      // 限制并发
      using var sem = new SemaphoreSlim(20, 20);
      var tasks = new List<Task<(int port, bool open, string? httpBody, string? serverHdr)>>();

      foreach (var port in ports)
      {
        tasks.Add(ProbeOneAsync(ip, port, sem, ct));
      }

      var results = await Task.WhenAll(tasks);
      foreach (var (port, openOk, body, srv) in results)
      {
        if (openOk) open.Add(port);
        if (openOk && string.IsNullOrEmpty(banner) && !string.IsNullOrEmpty(body))
        {
          banner = body;
          server = srv ?? string.Empty;
        }
      }

      return (open.OrderBy(p => p).ToList(), banner, server);
    }

    private async Task<(int port, bool open, string? httpBody, string? serverHdr)> ProbeOneAsync(
        string ip, int port, SemaphoreSlim sem, CancellationToken ct)
    {
      await sem.WaitAsync(ct);
      try
      {
        using var tcp = new TcpClient();
        var connectTask = tcp.ConnectAsync(ip, port);
        if (await Task.WhenAny(connectTask, Task.Delay(1500, ct)) != connectTask)
          return (port, false, null, null);
        await connectTask;

        // 端口开放，尝试 HTTP 探测
        if (port == 80 || port == 8080 || port == 8000 || port == 443 || port == 8443)
        {
          try
          {
            var scheme = port == 443 || port == 8443 ? "https" : "http";
            var url = $"{scheme}://{ip}:{port}/";
            using var request = new HttpRequestMessage(HttpMethod.Get, url);
            using var response = await _httpClient.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, ct);
            if (response.IsSuccessStatusCode || (int)response.StatusCode < 500)
            {
              var body = await response.Content.ReadAsStringAsync();
              var serverHdr = response.Headers.Server?.ToString() ?? string.Empty;
              return (port, true, body, serverHdr);
            }
            return (port, true, null, null);
          }
          catch
          {
            return (port, true, null, null);
          }
        }

        return (port, true, null, null);
      }
      catch
      {
        return (port, false, null, null);
      }
      finally
      {
        sem.Release();
      }
    }

    /// <summary>
    /// T3: 反例过滤 - 检测响应是否来自路由器/打印机/NAS/PC。
    /// </summary>
    public static bool IsLikelyNotCamera(string httpBody, string serverHeader)
    {
      if (string.IsNullOrEmpty(httpBody) && string.IsNullOrEmpty(serverHeader))
        return false;
      return MatchAntiKeyword(httpBody, serverHeader) != null;
    }

    private static string? MatchAntiKeyword(string httpBody, string serverHeader)
    {
      var combined = $"{(httpBody ?? string.Empty)}\n{(serverHeader ?? string.Empty)}";
      foreach (var kw in AntiCameraKeywords)
      {
        if (combined.Contains(kw, StringComparison.OrdinalIgnoreCase))
          return kw;
      }
      return null;
    }

    /// <summary>
    /// T4: 端口启发 - 根据开放端口判断可能厂商。
    /// </summary>
    private static string? MatchVendorByPort(List<int> openPorts)
    {
      int bestScore = 0;
      string? bestVendor = null;
      foreach (var kv in VendorPorts)
      {
        int score = kv.Value.Count(p => openPorts.Contains(p));
        if (score > bestScore)
        {
          bestScore = score;
          bestVendor = kv.Key;
        }
      }
      return bestScore >= 2 ? bestVendor : (bestScore >= 1 ? bestVendor : null);
    }

    /// <summary>
    /// HTTP 响应匹配厂商。
    /// </summary>
    private (string? vendor, double confidence, string evidence) MatchVendorFromHttp(string body, string server)
    {
      var combined = $"{(body ?? string.Empty)}\n{(server ?? string.Empty)}";
      string? matchedVendor = null;
      int matchCount = 0;
      int totalChecks = 0;

      foreach (var rule in _rules)
      {
        if (string.IsNullOrEmpty(rule.Vendor)) continue;
        int ruleScore = 0;
        if (rule.HttpPatterns?.Any() == true)
        {
          totalChecks++;
          if (rule.HttpPatterns.Any(p => combined.Contains(p, StringComparison.OrdinalIgnoreCase)))
            ruleScore++;
        }
        if (rule.HttpServer?.Any() == true)
        {
          totalChecks++;
          if (rule.HttpServer.Any(s => combined.Contains(s, StringComparison.OrdinalIgnoreCase)))
            ruleScore++;
        }
        if (ruleScore > 0 && ruleScore > matchCount)
        {
          matchCount = ruleScore;
          matchedVendor = rule.Vendor;
        }
      }

      if (matchedVendor == null) return (null, 0, string.Empty);
      double confidence = 0.5 + 0.2 * matchCount;
      if (confidence > 0.95) confidence = 0.95;
      return (matchedVendor, confidence, $"HTTP 响应匹配 {matchedVendor}（{matchCount} 项关键字）");
    }

    /// <summary>
    /// RTSP 服务器响应匹配。
    /// </summary>
    private async Task<string?> ProbeRtspAsync(string ip, int port, CancellationToken ct)
    {
      try
      {
        using var tcp = new TcpClient();
        var connectTask = tcp.ConnectAsync(ip, port);
        if (await Task.WhenAny(connectTask, Task.Delay(2000, ct)) != connectTask)
          return null;
        await connectTask;
        using var stream = tcp.GetStream();

        var req = $"OPTIONS rtsp://{ip}:{port}/ RTSP/1.0\r\nCSeq: 1\r\nUser-Agent: CameraScanner\r\n\r\n";
        var bytes = Encoding.ASCII.GetBytes(req);
        await stream.WriteAsync(bytes, ct);
        await stream.FlushAsync(ct);

        var buf = new byte[2048];
        var read = await stream.ReadAsync(buf, ct);
        if (read <= 0) return null;
        var response = Encoding.ASCII.GetString(buf, 0, read);

        // T6: Server 头厂商识别（基于 RTSP Server 字段）—— 在规则匹配前先做高优先级识别
        var serverMatch = Regex.Match(response, @"Server:\s*([^\r\n]+)", RegexOptions.IgnoreCase);
        if (serverMatch.Success)
        {
          var server = serverMatch.Groups[1].Value.Trim();
          // 天地伟业 Tiandy - H264DVR 是其特征 Server 标识
          if (server.Contains("H264DVR", StringComparison.OrdinalIgnoreCase))
          {
            System.Diagnostics.Debug.WriteLine($"[CameraVerifier] Tiandy 识别（Server={server}）");
            return "Tiandy";
          }
          // 海康威视
          if (server.Contains("Hikvision", StringComparison.OrdinalIgnoreCase) ||
              server.Contains("HikVison", StringComparison.OrdinalIgnoreCase))
            return "Hikvision";
          // 大华
          if (server.Contains("Dahua", StringComparison.OrdinalIgnoreCase))
            return "Dahua";
          // Axis
          if (server.Contains("AXIS", StringComparison.OrdinalIgnoreCase))
            return "Axis";
          // 宇视 Uniview
          if (server.Contains("Uniview", StringComparison.OrdinalIgnoreCase))
            return "Uniview";
        }

        foreach (var rule in _rules)
        {
          if (!string.IsNullOrEmpty(rule.Vendor) && response.Contains(rule.Vendor, StringComparison.OrdinalIgnoreCase))
            return rule.Vendor;
        }
        // 通用 RTSP 响应 → 可能是摄像头
        if (response.StartsWith("RTSP/", StringComparison.OrdinalIgnoreCase) || response.Contains("RTSP/1.0"))
          return "RTSP设备";
        return null;
      }
      catch
      {
        return null;
      }
    }

    /// <summary>
    /// ONVIF GetDeviceInformation 探测。
    /// </summary>
    private async Task<string?> ProbeOnvifAsync(string ip, int port, CancellationToken ct)
    {
      try
      {
        var url = $"http://{ip}:{port}/onvif/device_service";
        var soap = "<?xml version=\"1.0\" encoding=\"utf-8\"?>" +
                   "<s:Envelope xmlns:s=\"http://www.w3.org/2003/05/soap-envelope\">" +
                   "<s:Body><GetDeviceInformation xmlns=\"http://www.onvif.org/ver10/device/wsdl\"/></s:Body></s:Envelope>";

        using var request = new HttpRequestMessage(HttpMethod.Post, url);
        request.Content = new StringContent(soap, Encoding.UTF8, "application/soap+xml");

        using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        cts.CancelAfter(3000);
        using var response = await _httpClient.SendAsync(request, cts.Token);
        if (!response.IsSuccessStatusCode) return null;

        var content = await response.Content.ReadAsStringAsync();
        if (string.IsNullOrEmpty(content) || !content.Contains("Manufacturer")) return null;

        var mfrMatch = Regex.Match(content, @"<tdc:Manufacturer>([^<]+)</tdc:Manufacturer>");
        if (mfrMatch.Success) return mfrMatch.Groups[1].Value.Trim();
        return "ONVIF设备";
      }
      catch
      {
        return null;
      }
    }

    public void Dispose()
    {
      if (_disposed) return;
      _disposed = true;
      try { _httpClient.Dispose(); } catch { }
    }
  }

  public class VerificationResult
  {
    public string Ip { get; set; } = string.Empty;
    public bool IsCamera { get; set; }
    public double Confidence { get; set; }
    public string Vendor { get; set; } = string.Empty;
    public string Method { get; set; } = string.Empty;
    public string Evidence { get; set; } = string.Empty;
    public List<int> OpenPorts { get; set; } = new();
    public string HttpBanner { get; set; } = string.Empty;
    public string ServerHeader { get; set; } = string.Empty;
  }
}
