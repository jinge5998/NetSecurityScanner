using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Net.Sockets;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using NetSecurityScanner.Models;

namespace NetSecurityScanner.Core
{
  public class CameraScannerService : IDisposable
  {
    private readonly CameraFingerprintService _fingerprintService;
    private readonly CameraWeakPasswordService _weakPasswordService;
    private readonly List<CameraVulnerabilityEntry> _vulnerabilityDb;
    private readonly HttpClient _httpClient;
    // v3-T5: 黑名单过滤器（共享单例，懒加载）
    private static readonly Lazy<CameraListService> _listService = new(() => new CameraListService());
    private bool _disposed;

    private static readonly int[] DefaultCameraPorts =
    {
            80, 443, 554, 1935, 8000, 8080, 8443, 8899, 9000, 9010,
            37777, 37778, 34567, 3000, 35000, 2020, 88, 8866,
            21, 22, 23, 161, 1900, 3702, 5353,
            // 海康/萤石云 EZVIZ P2P 端口
            23000, 23001, 23560, 25000
        };

    public CameraScannerService()
    {
      _fingerprintService = new CameraFingerprintService();
      _weakPasswordService = new CameraWeakPasswordService();
      _httpClient = new HttpClient { Timeout = TimeSpan.FromSeconds(5) };
      _vulnerabilityDb = LoadVulnerabilityDb();
    }

    public List<CameraVulnerabilityEntry> GetVulnerabilityDb() => _vulnerabilityDb;

    /// <summary>
    /// 对单个目标做漏洞检测诊断，返回每一步执行情况。
    /// </summary>
    public async Task<CameraScanDiagnosis> DiagnoseAsync(
        CameraScanResult camera, CancellationToken ct)
    {
      var diag = new CameraScanDiagnosis
      {
        Ip = camera.Ip,
        Vendor = camera.Vendor ?? "",
        FirmwareVersion = camera.FirmwareVersion ?? "",
        OpenPorts = camera.OpenPorts.Select(p => $"{p.Port}/{p.Service}").ToList(),
        VulnDbCount = _vulnerabilityDb.Count,
        HttpAvailable = camera.OpenPorts.Any(p =>
            p.Port == 80 || p.Port == 8080 || p.Port == 8000 || p.Port == 443 || p.Port == 8443),
        Steps = new List<string>()
      };

      diag.Steps.Add($"[1] 漏洞数据库加载: {diag.VulnDbCount} 条记录");
      diag.Steps.Add($"[2] 目标厂商: '{(string.IsNullOrEmpty(camera.Vendor) ? "未识别" : camera.Vendor)}'");
      diag.Steps.Add($"[3] 固件版本: '{(string.IsNullOrEmpty(camera.FirmwareVersion) ? "未知" : camera.FirmwareVersion)}'");
      diag.Steps.Add($"[4] 开放端口: {(diag.OpenPorts.Count == 0 ? "无" : string.Join(", ", diag.OpenPorts))}");
      diag.Steps.Add($"[5] HTTP服务可用: {(diag.HttpAvailable ? "是" : "否")}");

      // 按厂商过滤
      var vendorVulns = _vulnerabilityDb.Where(v =>
          string.IsNullOrEmpty(v.AffectedVendor) ||
          v.AffectedVendor.Equals(camera.Vendor, StringComparison.OrdinalIgnoreCase) ||
          v.AffectedVendor == "多厂商"
      ).ToList();
      diag.Steps.Add($"[6] 匹配厂商的漏洞: {vendorVulns.Count} 条 (共 {_vulnerabilityDb.Count} 条)");

      // 按方法分类
      var byMethod = vendorVulns.GroupBy(v => v.DetectionMethod)
          .Select(g => $"{g.Key}: {g.Count()}")
          .ToList();
      diag.Steps.Add($"[7] 检测方法分布: {(byMethod.Any() ? string.Join(" | ", byMethod) : "无")}");

      // 跑真实漏洞检测
      diag.DetectedVulnerabilities = await DetectVulnerabilitiesAsync(camera, ct);
      diag.Steps.Add($"[8] 实际检出漏洞: {diag.DetectedVulnerabilities.Count} 个");

      if (diag.DetectedVulnerabilities.Count == 0)
      {
        if (string.IsNullOrEmpty(camera.Vendor))
          diag.Suggestions.Add("厂商未识别 - 启用'指纹识别'并确保 80/8080 端口可访问");
        if (string.IsNullOrEmpty(camera.FirmwareVersion) || camera.FirmwareVersion == "未知")
          diag.Suggestions.Add("固件版本未知 - 多数 VersionCheck 类型漏洞无法命中");
        if (!diag.HttpAvailable)
          diag.Suggestions.Add("HTTP 服务未开放 - AuthBypass/PathTraversal 探测无法执行");
        if (!diag.Steps.Any(s => s.Contains("检测方法分布: ") && !s.EndsWith(": 0")))
          diag.Suggestions.Add("漏洞数据库无匹配 - 厂商/型号可能不在数据库中");
      }
      else
      {
        diag.Suggestions.Add($"成功检测到 {diag.DetectedVulnerabilities.Count} 个漏洞！");
      }

      return diag;
    }

    private List<CameraVulnerabilityEntry> LoadVulnerabilityDb()
    {
      try
      {
        var assemblyLocation = typeof(CameraScannerService).Assembly.Location;
        var assemblyDir = Path.GetDirectoryName(assemblyLocation) ?? string.Empty;
        var jsonPath = Path.Combine(assemblyDir, "Data", "CameraVulnerabilityDB.json");
        if (!File.Exists(jsonPath))
        {
          var altPath = Path.Combine(Directory.GetCurrentDirectory(), "Data", "CameraVulnerabilityDB.json");
          jsonPath = File.Exists(altPath) ? altPath : jsonPath;
        }
        if (!File.Exists(jsonPath)) return new List<CameraVulnerabilityEntry>();
        var json = File.ReadAllText(jsonPath, Encoding.UTF8);
        return JsonSerializer.Deserialize<List<CameraVulnerabilityEntry>>(json) ?? new List<CameraVulnerabilityEntry>();
      }
      catch (Exception ex)
      {
        System.Diagnostics.Debug.WriteLine($"加载漏洞数据库失败: {ex.Message}");
        return new List<CameraVulnerabilityEntry>();
      }
    }

    /// <summary>
    /// 导出扫描结果为 JSON 报告
    /// </summary>
    public string ExportToJson(List<CameraScanResult> results)
    {
      var report = new
      {
        GenerateTime = DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss"),
        TotalCount = results.Count,
        OnlineCount = results.Count(r => r.IsOnline),
        VulnerableCount = results.Count(r => r.Vulnerabilities.Count > 0),
        HighRiskCount = results.Count(r =>
            r.Vulnerabilities.Any(v => v.Severity == "Critical" || v.Severity == "High")),
        Cameras = results.Select(r => new
        {
          r.Ip,
          r.IsOnline,
          Vendor = string.IsNullOrEmpty(r.Vendor) ? "未识别" : r.Vendor,
          r.Model,
          r.FirmwareVersion,
          r.Mac,
          r.SerialNumber,
          r.ResponseTimeMs,
          OpenPorts = r.OpenPorts.Select(p => new
          {
            p.Port,
            p.Protocol,
            p.Service,
            p.Status,
            p.RiskLevel
          }),
          Vulnerabilities = r.Vulnerabilities.Select(v => new
          {
            v.CveId,
            v.Name,
            v.Severity,
            CvssScore = Math.Round(v.CvssScore, 1),
            v.Description,
            v.AffectedVendor,
            v.AffectedVersions,
            v.FixedVersion,
            v.Solution,
            v.Reference,
            v.IsVerified,
            v.VerificationMethod,
            v.VulnerabilityType
          }),
          WeakPasswords = r.WeakPasswords.Select(w => new
          {
            w.Username,
            w.Password,
            w.ServiceType,
            w.Port,
            w.RiskLevel
          }),
          r.RiskAssessment
        })
      };
      return JsonSerializer.Serialize(report, new JsonSerializerOptions
      {
        WriteIndented = true,
        Encoder = System.Text.Encodings.Web.JavaScriptEncoder.UnsafeRelaxedJsonEscaping
      });
    }

    /// <summary>
    /// 导出扫描结果为 CSV 报告（UTF-8 BOM 兼容 Excel 中文）
    /// </summary>
    public string ExportToCsv(List<CameraScanResult> results)
    {
      var sb = new StringBuilder();
      // UTF-8 BOM 让 Excel 正确显示中文
      sb.Append('\uFEFF');
      // 表头
      sb.AppendLine("IP,厂商,型号,固件,在线,开放端口,风险等级,漏洞数,严重,高危,中危,低危,具体漏洞,弱口令数,CVE列表");
      foreach (var r in results)
      {
        var ports = string.Join(";", r.OpenPorts.Select(p => $"{p.Port}/{p.Service}"));
        var vulns = string.Join(" | ", r.Vulnerabilities.Select(v => $"{v.CveId}({v.Severity})"));
        var cveList = string.Join(";", r.Vulnerabilities.Select(v => v.CveId));
        var sb2 = new StringBuilder();
        sb2.Append(EscapeCsv(r.Ip)).Append(',');
        sb2.Append(EscapeCsv(r.Vendor ?? "未识别")).Append(',');
        sb2.Append(EscapeCsv(r.Model ?? "未知")).Append(',');
        sb2.Append(EscapeCsv(r.FirmwareVersion ?? "未知")).Append(',');
        sb2.Append(r.IsOnline ? "是" : "否").Append(',');
        sb2.Append(EscapeCsv(ports)).Append(',');
        sb2.Append(EscapeCsv(r.RiskAssessment?.RiskLevel ?? "")).Append(',');
        sb2.Append(r.Vulnerabilities.Count).Append(',');
        sb2.Append(r.Vulnerabilities.Count(v => v.Severity == "Critical")).Append(',');
        sb2.Append(r.Vulnerabilities.Count(v => v.Severity == "High")).Append(',');
        sb2.Append(r.Vulnerabilities.Count(v => v.Severity == "Medium")).Append(',');
        sb2.Append(r.Vulnerabilities.Count(v => v.Severity == "Low")).Append(',');
        sb2.Append(EscapeCsv(vulns)).Append(',');
        sb2.Append(r.WeakPasswords.Count).Append(',');
        sb2.Append(EscapeCsv(cveList));
        sb.AppendLine(sb2.ToString());
      }
      return sb.ToString();
    }

    private static string EscapeCsv(string s)
    {
      if (string.IsNullOrEmpty(s)) return "";
      if (s.Contains(',') || s.Contains('"') || s.Contains('\n') || s.Contains('\r'))
        return "\"" + s.Replace("\"", "\"\"") + "\"";
      return s;
    }

    public async Task<List<CameraScanResult>> ScanCamerasAsync(
        CameraScanOptions options,
        IProgress<CameraScanProgress> progress,
        CancellationToken cancellationToken)
    {
      var results = new ConcurrentBag<CameraScanResult>();
      var ips = ParseIpRange(options);
      // v3-T5: 在扫描入口过滤黑名单
      ips = _listService.Value.FilterBlackList(ips);
      var totalIps = ips.Count;
      var processedCount = 0;
      var lockObj = new object();

      progress.Report(new CameraScanProgress
      {
        Phase = "IP扫描",
        TotalCount = totalIps,
        CompletedCount = 0,
        Message = $"正在扫描 {totalIps} 个IP地址..."
      });

      var semaphore = new SemaphoreSlim(options.MaxConcurrency);
      var tasks = ips.Select(async ip =>
      {
        await semaphore.WaitAsync(cancellationToken);
        try
        {
          var result = await ScanSingleCameraAsync(ip, options, cancellationToken);
          results.Add(result);

          var completed = Interlocked.Increment(ref processedCount);
          progress.Report(new CameraScanProgress
          {
            Phase = "IP扫描",
            TotalCount = totalIps,
            CompletedCount = completed,
            Message = $"已完成 {completed}/{totalIps} - {ip} {(result.IsOnline ? "✓" : "✗")}"
          });
        }
        catch (OperationCanceledException) { }
        catch (Exception ex)
        {
          var completed = Interlocked.Increment(ref processedCount);
          progress.Report(new CameraScanProgress
          {
            Phase = "IP扫描",
            TotalCount = totalIps,
            CompletedCount = completed,
            Message = $"扫描 {ip} 时出错: {ex.Message}"
          });
        }
        finally
        {
          semaphore.Release();
        }
      });

      await Task.WhenAll(tasks);

      var onlineCameras = results.Where(r => r.IsOnline).ToList();
      var cameraIndex = 0;

      foreach (var camera in onlineCameras)
      {
        if (cancellationToken.IsCancellationRequested) break;
        cameraIndex++;

        if (options.EnableFingerprint)
        {
          progress.Report(new CameraScanProgress
          {
            Phase = "指纹识别",
            TotalCount = onlineCameras.Count,
            CompletedCount = cameraIndex,
            Message = $"正在识别 {camera.Ip} 设备指纹..."
          });

          var httpPort = camera.OpenPorts.FirstOrDefault(p => p.Port == 80 || p.Port == 8080 || p.Port == 443);
          if (httpPort != null)
          {
            var fingerprint = await _fingerprintService.IdentifyCameraAsync(camera.Ip, httpPort.Port, cancellationToken);
            if (fingerprint != null)
            {
              camera.Vendor = fingerprint.Vendor;
              camera.Model = fingerprint.Model;
              camera.FirmwareVersion = fingerprint.FirmwareVersion;
              camera.SerialNumber = string.IsNullOrEmpty(camera.SerialNumber) ? fingerprint.SerialNumber : camera.SerialNumber;
              camera.Mac = string.IsNullOrEmpty(camera.Mac) ? fingerprint.MacAddress : camera.Mac;
            }
          }

          // 尝试ONVIF指纹识别
          var onvifPort = camera.OpenPorts.FirstOrDefault(p => p.Port == 8899);
          if (onvifPort != null)
          {
            var onvifFingerprint = await _fingerprintService.IdentifyByOnvifAsync(camera.Ip, 8899, cancellationToken);
            if (onvifFingerprint != null)
            {
              camera.Vendor = string.IsNullOrEmpty(camera.Vendor) ? onvifFingerprint.Vendor : camera.Vendor;
              camera.Model = string.IsNullOrEmpty(camera.Model) ? onvifFingerprint.Model : camera.Model;
              camera.FirmwareVersion = string.IsNullOrEmpty(camera.FirmwareVersion) ? onvifFingerprint.FirmwareVersion : camera.FirmwareVersion;
              camera.SerialNumber = string.IsNullOrEmpty(camera.SerialNumber) ? onvifFingerprint.SerialNumber : camera.SerialNumber;
              camera.Mac = string.IsNullOrEmpty(camera.Mac) ? onvifFingerprint.MacAddress : camera.Mac;
            }
          }

          // 尝试RTSP指纹识别
          var rtspPort = camera.OpenPorts.FirstOrDefault(p => p.Port == 554);
          if (rtspPort != null)
          {
            var rtspFingerprint = await _fingerprintService.IdentifyByRtspAsync(camera.Ip, 554, cancellationToken);
            if (rtspFingerprint != null)
            {
              // RTSP 指纹覆盖逻辑：
              // 1) 高置信度(>=0.7)且非泛化标签时，总是覆盖（即使有具体厂商名）
              // 2) 泛化标签场景：RTSP设备/未知/未识别/空
              if (rtspFingerprint.Confidence >= 0.7 &&
                  !string.IsNullOrEmpty(rtspFingerprint.Vendor) &&
                  rtspFingerprint.Vendor != "RTSP设备" &&
                  rtspFingerprint.Vendor != "未知")
              {
                if (camera.Vendor != rtspFingerprint.Vendor)
                {
                  System.Diagnostics.Debug.WriteLine($"[CameraScanner] RTSP 指纹覆盖厂商: {camera.Vendor} -> {rtspFingerprint.Vendor} ({rtspFingerprint.Confidence:P0})");
                  camera.Vendor = rtspFingerprint.Vendor;
                }
              }
              else if (string.IsNullOrEmpty(camera.Vendor))
              {
                camera.Vendor = rtspFingerprint.Vendor;
              }
            }
          }

          // 尝试UPnP指纹识别
          var upnpPort = camera.OpenPorts.FirstOrDefault(p => p.Port == 1900);
          if (upnpPort != null)
          {
            var upnpFingerprint = await _fingerprintService.IdentifyByUpnpAsync(camera.Ip, 1900, cancellationToken);
            if (upnpFingerprint != null)
            {
              camera.Vendor = string.IsNullOrEmpty(camera.Vendor) ? upnpFingerprint.Vendor : camera.Vendor;
            }
          }
        }

        if (options.EnableVulnerabilityScan)
        {
          progress.Report(new CameraScanProgress
          {
            Phase = "漏洞检测",
            TotalCount = onlineCameras.Count,
            CompletedCount = cameraIndex,
            Message = $"正在检测 {camera.Ip} 漏洞..."
          });
          camera.Vulnerabilities = await DetectVulnerabilitiesAsync(camera, cancellationToken);
        }

        if (options.EnableWeakPasswordScan)
        {
          progress.Report(new CameraScanProgress
          {
            Phase = "弱口令检测",
            TotalCount = onlineCameras.Count,
            CompletedCount = cameraIndex,
            Message = $"正在检测 {camera.Ip} 弱口令..."
          });
          var wsProgress = new Progress<string>(msg =>
              progress.Report(new CameraScanProgress
              {
                Phase = "弱口令检测",
                TotalCount = onlineCameras.Count,
                CompletedCount = cameraIndex,
                Message = msg
              }));
          camera.WeakPasswords = await _weakPasswordService.CheckWeakPasswordsAsync(
              camera.Ip, camera.Vendor, camera.OpenPorts, cancellationToken, wsProgress);
        }

        // v5-T2: CameraVerifier 精准判定（端口启发 → 厂商关键字 → HTTP 指纹 → RTSP → ONVIF）
        try
        {
          var verifier = new CameraVerifier();
          using (verifier)
          {
            var ports = camera.OpenPorts.Select(p => p.Port).ToArray();
            var verResult = await verifier.VerifyAsync(camera.Ip, ports, cancellationToken);
            camera.VerificationMethod = verResult.Method;
            camera.VerificationConfidence = verResult.Confidence;
            camera.VerificationEvidence = verResult.Evidence;

            // 当 verifier 判定为非摄像头（反例命中）时，仍保留在结果中但 vendor 标记为非摄像头
            if (!verResult.IsCamera && verResult.Method == "反例黑名单")
            {
              camera.Vendor = string.IsNullOrEmpty(camera.Vendor) ? verResult.Vendor : camera.Vendor;
              // 弱口令扫描可能已经在此设备上跑过，保持原状不强制清除
            }
            // 当 verifier 置信度比当前 Vendor 更高时，覆盖 Vendor
            else if (verResult.IsCamera && verResult.Confidence > 0.7 && !string.IsNullOrEmpty(verResult.Vendor))
            {
              camera.Vendor = verResult.Vendor;
            }
          }
        }
        catch (Exception ex)
        {
          System.Diagnostics.Debug.WriteLine($"[CameraVerifier] 校验 {camera.Ip} 失败: {ex.Message}");
        }

        camera.RiskAssessment = AssessRisk(camera);
      }

      return results.ToList();
    }

    private async Task<CameraScanResult> ScanSingleCameraAsync(
        string ip, CameraScanOptions options, CancellationToken ct)
    {
      var result = new CameraScanResult
      {
        Ip = ip,
        IpType = IPAddress.TryParse(ip, out var parsedIp) && parsedIp.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6
            ? "IPv6" : "IPv4"
      };
      var scanStart = DateTime.Now;

      try
      {
        var portsToScan = options.UseDefaultPorts
            ? DefaultCameraPorts.ToList()
            : options.CustomPorts;

        if (options.CustomPorts.Any())
        {
          portsToScan = portsToScan.Union(options.CustomPorts).Distinct().ToList();
        }

        var scanOptions = new ScanOptions
        {
          Timeout = options.TimeoutMs,
          MaxConcurrency = 10,
          ScanType = "TCP",
          EnableServiceDetection = false
        };

        var scanProgress = new Progress<ScanProgressInfo>();
        var portScanner = new PortScannerService();
        // 修复：必须把 ct 传给 PortScannerService，否则停止扫描无效，内部会跑完整个超时
        var portResults = await portScanner.ScanPortsAsync(ip, portsToScan, scanOptions, scanProgress, ct);

        foreach (var pr in portResults.Where(p => p.Status == "开放"))
        {
          var banner = pr.ServiceDetails ?? string.Empty;
          var service = IdentifyService(pr.PortNumber, banner);
          result.OpenPorts.Add(new CameraPortInfo
          {
            Port = pr.PortNumber,
            Protocol = "TCP",
            Service = service,
            Status = "Open",
            Banner = banner,
            IsDefaultPort = DefaultCameraPorts.Contains(pr.PortNumber),
            RiskLevel = GetPortRiskLevel(pr.PortNumber, service)
          });
        }

        result.IsOnline = result.OpenPorts.Count > 0;
        result.HasTelnet = result.OpenPorts.Any(p => p.Port == 23);
        result.ResponseTimeMs = (int)(DateTime.Now - scanStart).TotalMilliseconds;
        result.ScanTime = DateTime.Now;
      }
      catch (Exception ex)
      {
        System.Diagnostics.Debug.WriteLine($"扫描 {ip} 失败: {ex.GetType().Name}: {ex.Message}");
        result.IsOnline = false;
        result.ScanTime = DateTime.Now;
      }

      return result;
    }

    private static string IdentifyService(int port, string banner)
    {
      if (port == 554) return "RTSP";
      if (port == 1935) return "RTMP";
      if (port == 23) return "Telnet";
      if (port == 22) return "SSH";
      if (port == 21) return "FTP";
      if (port == 443 || port == 8443) return "HTTPS";
      if (port == 80 || port == 8080 || port == 8000 || port == 8899 || port == 9000 || port == 9010)
        return "HTTP";
      if (port == 37777 || port == 37778) return "Dahua-私有协议";
      if (port == 34567) return "Tiandy-私有协议";
      if (port == 35000) return "FLIR-私有协议";
      if (port == 2020) return "TP-Link-ONVIF";
      if (port == 8866) return "GV-私有协议";
      if (port == 88) return "HTTP-Alt";
      if (port == 3000) return "HTTP/Tiandy";
      if (port == 8899) return "ONVIF";
      if (port == 3702) return "WS-Discovery";
      if (port == 1900) return "UPnP/SSDP";
      if (port == 5353) return "mDNS";
      if (port == 161) return "SNMP";
      if (banner.Contains("RTSP", StringComparison.OrdinalIgnoreCase)) return "RTSP";
      if (banner.Contains("ONVIF", StringComparison.OrdinalIgnoreCase)) return "ONVIF";
      if (banner.Contains("HTTP", StringComparison.OrdinalIgnoreCase)) return "HTTP";
      return "未知";
    }

    private static string GetPortRiskLevel(int port, string service)
    {
      if (port == 23) return "高危";
      if (port == 21) return "高危";
      if (port == 22) return "高危";
      if (service == "SSH") return "高危";
      if (service == "Telnet") return "高危";
      if (service == "FTP") return "高危";
      if (service == "RTSP" && port == 554) return "中危";
      if (service == "ONVIF" && port == 8899) return "中危";
      if (service == "SNMP") return "中危";
      if (service == "HTTP" && port != 443) return "低危";
      if (port == 37777 || port == 37778 || port == 34567) return "低危";
      if (port == 3702 || port == 1900 || port == 5353) return "信息";
      return "信息";
    }

    private async Task<List<CameraVulnerability>> DetectVulnerabilitiesAsync(
        CameraScanResult camera, CancellationToken ct)
    {
      var vulnerabilities = new List<CameraVulnerability>();

      var vendorVulns = _vulnerabilityDb.Where(v =>
          string.IsNullOrEmpty(v.AffectedVendor) ||
          v.AffectedVendor.Equals(camera.Vendor, StringComparison.OrdinalIgnoreCase) ||
          v.AffectedVendor == "多厂商")
          .ToList();

      // 缓存默认凭证检查结果 - 一个目标只检测一次
      bool? httpDefaultCredsChecked = null;
      (bool isVuln, string evidence) httpDefaultCredsResult = (false, "");

      foreach (var v in vendorVulns)
      {
        if (ct.IsCancellationRequested) break;

        var isVulnerable = false;
        string detectionEvidence = v.DetectionMethod;

        switch (v.DetectionMethod)
        {
          case "VersionCheck":
            if (camera.FirmwareVersion != "未知" && !string.IsNullOrEmpty(v.AffectedVersions))
            {
              isVulnerable = IsVersionVulnerable(camera.FirmwareVersion, v.AffectedVersions);
            }
            break;

          case "RTSPProbe":
            var rtspPort = camera.OpenPorts.FirstOrDefault(p => p.Port == 554);
            if (rtspPort != null)
            {
              // 先尝试匿名访问
              isVulnerable = await CheckRtspUnauthorizedAsync(camera.Ip, ct);
              if (isVulnerable)
              {
                detectionEvidence = "RTSP 匿名 DESCRIBE 返回 200 OK";
              }
              else
              {
                // 匿名失败则尝试默认凭证
                var rtspCreds = await CheckRtspDigestCredsAsync(camera.Ip, ct);
                isVulnerable = rtspCreds.isVuln;
                if (isVulnerable) detectionEvidence = rtspCreds.evidence;
              }
            }
            break;

          case "ONVIFProbe":
            var onvifPort = camera.OpenPorts.FirstOrDefault(p =>
                p.Port == 80 || p.Port == 8080 || p.Port == 8899);
            if (onvifPort != null)
            {
              isVulnerable = await CheckOnvifUnauthorizedAsync(camera.Ip, onvifPort.Port, ct);
            }
            break;

          case "AuthBypass":
            isVulnerable = await CheckAuthBypassAsync(camera.Ip, camera.Vendor, ct);
            break;

          case "PathTraversal":
          case "PathCheck":
          case "InfoLeak":
            isVulnerable = await CheckSensitivePathAsync(camera.Ip, ct);
            if (isVulnerable) detectionEvidence = "敏感路径返回 200 OK 含敏感数据";
            break;

          case "PortCheck":
            isVulnerable = v.CveId switch
            {
              "TELNET-OPEN-001" => camera.OpenPorts.Any(p => p.Port == 23),
              "HTTP-PLAIN-001" => camera.OpenPorts.Any(p => p.Port == 80) &&
                                  !camera.OpenPorts.Any(pp => pp.Port == 443 || pp.Port == 8443),
              "SSH-OPEN-001" => camera.OpenPorts.Any(p => p.Port == 22),
              "FTP-OPEN-001" => camera.OpenPorts.Any(p => p.Port == 21),
              _ => false
            };
            if (isVulnerable) detectionEvidence = v.CveId switch
            {
              "TELNET-OPEN-001" => "端口 23 开放",
              "HTTP-PLAIN-001" => "HTTP 80 开放但 HTTPS 443/8443 未启用",
              "SSH-OPEN-001" => "端口 22 开放",
              "FTP-OPEN-001" => "端口 21 开放",
              _ => v.DetectionMethod
            };
            break;
        }

        if (isVulnerable)
        {
          vulnerabilities.Add(new CameraVulnerability
          {
            CveId = v.CveId,
            Name = v.Name,
            Description = v.Description,
            Severity = v.Severity,
            CvssScore = v.CvssScore,
            AffectedVendor = v.AffectedVendor,
            AffectedVersions = v.AffectedVersions,
            FixedVersion = v.FixedVersion,
            Solution = v.Solution,
            Reference = v.Reference,
            IsVerified = v.DetectionMethod != "VersionCheck",
            VerificationMethod = detectionEvidence
          });
        }
      }

      // 额外：检查 HTTP 默认凭证 - 通用漏洞 (CVE-2017-7921, CVE-2018-9995 等)
      if (camera.OpenPorts.Any(p => p.Port == 80 || p.Port == 8080 || p.Port == 8899))
      {
        try
        {
          if (!httpDefaultCredsChecked.HasValue)
          {
            httpDefaultCredsResult = await CheckHttpDefaultCredsAsync(camera.Ip, ct);
            httpDefaultCredsChecked = true;
          }
          if (httpDefaultCredsResult.isVuln)
          {
            // 避免重复添加相同漏洞
            if (!vulnerabilities.Any(x => x.CveId == "CRED-DEFAULT-001"))
            {
              vulnerabilities.Add(new CameraVulnerability
              {
                CveId = "CRED-DEFAULT-001",
                Name = "HTTP 默认凭证泄露",
                Description = $"摄像头 HTTP 管理界面使用默认凭证 ({httpDefaultCredsResult.evidence})，攻击者可直接登录获取设备控制权。",
                Severity = "Critical",
                CvssScore = 9.8,
                AffectedVendor = "多厂商",
                AffectedVersions = "所有版本",
                FixedVersion = "无",
                Solution = "立即修改默认口令为 12 位以上强密码（大小写+数字+特殊字符）。若设备无此功能，应联系厂商升级固件。",
                Reference = "https://www.cvedetails.com/vulnerability-list/vendor_id-10000/product_id-20978/",
                IsVerified = true,
                VerificationMethod = httpDefaultCredsResult.evidence
              });
            }
          }
        }
        catch (Exception ex)
        {
          System.Diagnostics.Debug.WriteLine($"HTTP 默认凭证检测异常: {ex.Message}");
        }
      }

      return vulnerabilities;
    }

    private static bool IsVersionVulnerable(string currentVersion, string affectedVersions)
    {
      if (string.IsNullOrEmpty(currentVersion) || string.IsNullOrEmpty(affectedVersions))
        return false;

      if (affectedVersions.Contains("<"))
      {
        var threshold = affectedVersions.Replace("<", "").Replace("=", "").Trim();
        if (threshold.StartsWith("V", StringComparison.OrdinalIgnoreCase))
          threshold = threshold.Substring(1);

        if (Version.TryParse(currentVersion, out var current) &&
            Version.TryParse(threshold, out var target))
        {
          return current < target;
        }
      }

      if (affectedVersions.Contains("多个版本") || affectedVersions.Contains("所有"))
        return true;

      return false;
    }

    private async Task<bool> CheckRtspUnauthorizedAsync(string ip, CancellationToken ct)
    {
      try
      {
        using var tcpClient = new TcpClient();
        var connectTask = tcpClient.ConnectAsync(ip, 554);
        if (await Task.WhenAny(connectTask, Task.Delay(3000, ct)) != connectTask)
          return false;
        await connectTask;
        using var stream = tcpClient.GetStream();
        var describeRequest = "DESCRIBE rtsp://0.0.0.0:554/ RTSP/1.0\r\nCSeq: 1\r\nUser-Agent: Scanner\r\n\r\n";
        var requestBytes = Encoding.ASCII.GetBytes(describeRequest);
        await stream.WriteAsync(requestBytes, ct);
        await stream.FlushAsync(ct);

        var buffer = new byte[2048];
        var bytesRead = await stream.ReadAsync(buffer, ct);
        var response = Encoding.ASCII.GetString(buffer, 0, bytesRead);

        return response.Contains("200 OK") && !response.Contains("Unauthorized");
      }
      catch
      {
        return false;
      }
    }

    private async Task<bool> CheckOnvifUnauthorizedAsync(string ip, int port, CancellationToken ct)
    {
      try
      {
        var url = port == 443 ? $"https://{FormatIpForUrl(ip)}:{port}/onvif/device_service" : $"http://{FormatIpForUrl(ip)}:{port}/onvif/device_service";
        using var request = new HttpRequestMessage(HttpMethod.Get, url);
        using var response = await _httpClient.SendAsync(request, ct);
        return response.StatusCode == System.Net.HttpStatusCode.OK;
      }
      catch
      {
        return false;
      }
    }

    private async Task<bool> CheckAuthBypassAsync(string ip, string vendor, CancellationToken ct)
    {
      var testPaths = new List<string>();
      if (vendor == "Hikvision")
      {
        testPaths.AddRange(new[] { "/System/configurationFile", "/onvif-http/snapshot", "/ISAPI/System/deviceInfo" });
      }
      else if (vendor == "Dahua")
      {
        testPaths.AddRange(new[] { "/current_config/passwd", "/cgi-bin/snapshot.cgi", "/RPC2_Login" });
      }
      else if (vendor == "Tiandy" || string.Equals(vendor, "Tiandy", StringComparison.OrdinalIgnoreCase))
      {
        // 天地伟业 - 配置和 PTZ 控制未授权路径
        testPaths.AddRange(new[] { "/TIANDY.config", "/config/tiandy.conf", "/cgi-bin/ptctrl.cgi", "/cgi-bin/snapshot.cgi", "/config/account.xml" });
      }
      else if (vendor == "Uniview")
      {
        testPaths.AddRange(new[] { "/api/v1/system/info", "/LAPI/V1.0/System/DeviceInfo" });
      }
      else if (vendor == "TP-Link")
      {
        testPaths.AddRange(new[] { "/config.json", "/api/v1/users" });
      }

      testPaths.AddRange(new[] { "/.env", "/config/", "/cgi-bin/", "/web/config", "/backup/", "/admin/" });

      foreach (var path in testPaths.Take(8))
      {
        if (ct.IsCancellationRequested) return false;
        try
        {
          var url = $"http://{FormatIpForUrl(ip)}:80{path}";
          using var request = new HttpRequestMessage(HttpMethod.Get, url);
          // 模拟常见 User-Agent
          request.Headers.UserAgent.ParseAdd("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36");
          using var response = await _httpClient.SendAsync(request, ct);
          // 必须严格验证：响应是真正的敏感内容，而不是通用 404 页面
          if (response.IsSuccessStatusCode)
          {
            var body = await response.Content.ReadAsStringAsync();
            if (ContainsRealSensitiveContent(body))
            {
              System.Diagnostics.Debug.WriteLine($"[AuthBypass] {path} 真敏感内容 ({body.Length} bytes)");
              return true;
            }
            else
            {
              System.Diagnostics.Debug.WriteLine($"[AuthBypass] {path} 200 OK 但是通用页面 ({body.Length} bytes)，忽略");
            }
          }
          // 401/403/302 路径存在但需认证 - 算存在但不算未授权访问
          // 注：这些状态码不再作为弱口令/未授权访问的证据
        }
        catch (Exception ex)
        {
          System.Diagnostics.Debug.WriteLine($"[AuthBypass] {path} 异常: {ex.GetType().Name}: {ex.Message}");
        }
      }
      return false;
    }

    /// <summary>
    /// 判断响应内容是否真的包含敏感数据（而非通用 404 页面或登录页）
    /// </summary>
    private static bool ContainsRealSensitiveContent(string body)
    {
      if (string.IsNullOrEmpty(body) || body.Length < 100) return false;

      // 排除通用错误页/登录页
      var lowerBody = body.ToLower();
      if (lowerBody.Contains("404") && (lowerBody.Contains("file not found") || lowerBody.Contains("not found on this server")))
        return false;  // Tiandy 通用 404 页面
      if (lowerBody.Contains("<title>404") || lowerBody.Contains("not found</title>"))
        return false;
      if (lowerBody.Contains("login") || lowerBody.Contains("signin") || lowerBody.Contains("sign in"))
        return false;  // 登录页面
      if (lowerBody.Contains("<html") && body.Length < 300)
        return false;  // 短 HTML 页面（通用 404 模板）

      // 必须包含真实敏感数据特征（任一）
      // XML/JSON 配置文件
      bool looksLikeConfig = body.TrimStart().StartsWith("{") ||
                              body.Contains("<configuration", StringComparison.OrdinalIgnoreCase) ||
                              body.Contains("<settings", StringComparison.OrdinalIgnoreCase) ||
                              body.Contains("<config", StringComparison.OrdinalIgnoreCase) ||
                              body.Contains("<account", StringComparison.OrdinalIgnoreCase) ||
                              body.Contains("<user", StringComparison.OrdinalIgnoreCase) ||
                              body.Contains("<password", StringComparison.OrdinalIgnoreCase);
      // 敏感字段
      bool hasSensitiveField = body.Contains("password", StringComparison.OrdinalIgnoreCase) ||
                                body.Contains("passwd", StringComparison.OrdinalIgnoreCase) ||
                                body.Contains("admin", StringComparison.OrdinalIgnoreCase) ||
                                body.Contains("username", StringComparison.OrdinalIgnoreCase) ||
                                body.Contains("userlist", StringComparison.OrdinalIgnoreCase) ||
                                body.Contains("devinfo", StringComparison.OrdinalIgnoreCase) ||
                                body.Contains("devicepasswd", StringComparison.OrdinalIgnoreCase);

      // 必须同时看起来像配置文件且有敏感字段 OR 是大段敏感数据
      if (looksLikeConfig && hasSensitiveField) return true;
      // 或者大段（>2KB）含敏感字段（避免误报但允许长响应）
      if (body.Length > 2048 && hasSensitiveField) return true;
      return false;
    }

    private async Task<bool> CheckSensitivePathAsync(string ip, CancellationToken ct)
    {
      // 扩展到 20+ 路径，覆盖海康/大华/天地伟业/宇视/TP-Link/Bosch 等主流厂商
      var sensitivePaths = new[]
      {
                // 海康威视
                "/System/configurationFile",
                "/Security/users?auth=YWRtaW46MTEK",
                "/onvif-http/snapshot",
                "/ISAPI/System/deviceInfo",
                "/ISAPI/Security/users",
                "/doc/script.html",
                // 大华
                "/current_config/passwd",
                "/current_config/Account1",
                "/cgi-bin/snapshot.cgi",
                "/cgi-bin/magicBox.cgi",
                "/RPC2_Login",
                // 天地伟业 Tiandy
                "/TIANDY.config",
                "/config/tiandy.conf",
                "/cgi-bin/ptctrl.cgi",
                // 宇视 Uniview
                "/api/v1/system/info",
                "/LAPI/V1.0/System/DeviceInfo",
                // TP-Link / 通用
                "/config/",
                "/backup/",
                "/.env",
                "/.git/config",
                "/cgi-bin/",
                "/web/config",
                "/dvr.ini",
                "/system.ini",
                "/user.xml",
                "/device.xml",
                "/cgi-bin/user.cgi",
                "/api/v1/users",
                "/doc/page/login.asp"
            };

      int foundCount = 0;
      foreach (var path in sensitivePaths)
      {
        if (ct.IsCancellationRequested) return foundCount > 0;
        try
        {
          var url = $"http://{FormatIpForUrl(ip)}:80{path}";
          using var request = new HttpRequestMessage(HttpMethod.Get, url);
          using var response = await _httpClient.SendAsync(request, ct);
          // 成功 (200) 必须严格验证内容；不能只看状态码
          if (response.IsSuccessStatusCode)
          {
            var body = await response.Content.ReadAsStringAsync();
            // 必须包含真实敏感内容（排除通用 404/登录页面）
            if (ContainsRealSensitiveContent(body))
            {
              System.Diagnostics.Debug.WriteLine($"敏感路径泄露: {path} ({body.Length} bytes) - 真敏感数据");
              foundCount++;
              if (foundCount >= 1) return true;
            }
            else
            {
              System.Diagnostics.Debug.WriteLine($"敏感路径检查 {path} ({body.Length} bytes) - 通用页面，跳过");
            }
          }
        }
        catch (Exception ex)
        {
          System.Diagnostics.Debug.WriteLine($"敏感路径检查失败 ({path}): {ex.Message}");
        }
      }
      return false;
    }

    /// <summary>
    /// 摄像头常见默认凭证字典（厂商 + 默认账号）
    /// </summary>
    private static readonly (string User, string Pass)[] DefaultCreds =
    {
      ("admin", "admin"),
      ("admin", "12345"),
      ("admin", "123456"),
      ("admin", "password"),
      ("admin", ""),
      ("admin", "1111111"),
      ("admin", "888888"),
      ("admin", "1234"),
      ("admin", "4321"),
      ("admin", "9999"),
      ("root", "root"),
      ("root", "pass"),
      ("root", "12345"),
      ("user", "user"),
      ("user", "12345"),
      ("666666", "666666"),
      ("888888", "888888"),
      // 海康威视后门 CVE-2017-7921
      ("admin", "tlJwpbo6"),
      // 大华
      ("admin", "7ujMko0admin"),
      // 天地伟业
      ("admin", "admin123"),
      // 安联锐视
      ("admin", "default"),
    };

    /// <summary>
    /// HTTP/HTTPS 默认凭证检测 - 覆盖 admin/admin 等常见默认密码
    /// </summary>
    private async Task<(bool isVuln, string evidence)> CheckHttpDefaultCredsAsync(
        string ip, CancellationToken ct)
    {
      foreach (var port in new[] { 80, 8080, 8899, 8000 })
      {
        // 先确认端口开放
        if (!await IsPortOpenAsync(ip, port, 1500)) continue;

        foreach (var (user, pass) in DefaultCreds)
        {
          try
          {
            using var authClient = new HttpClient { Timeout = TimeSpan.FromSeconds(2) };
            var auth = "Basic " + Convert.ToBase64String(
                Encoding.ASCII.GetBytes($"{user}:{pass}"));

            var urls = new[] {
              $"http://{FormatIpForUrl(ip)}:{port}/",
              $"http://{FormatIpForUrl(ip)}:{port}/index.html",
              $"http://{FormatIpForUrl(ip)}:{port}/doc/page/login.asp",
            };

            foreach (var url in urls)
            {
              try
              {
                // 1) 先无凭证探测：必须 401 才是"启用了认证"
                bool requiresAuth = false;
                using (var noAuthResp = await authClient.GetAsync(url, ct))
                {
                  if (noAuthResp.StatusCode == System.Net.HttpStatusCode.Unauthorized)
                    requiresAuth = true;
                  else
                    break;  // 公开访问，不算弱口令
                }
                if (!requiresAuth) continue;

                // 2) 启用了认证 → 带凭证请求
                using var credReq = new HttpRequestMessage(HttpMethod.Get, url);
                credReq.Headers.TryAddWithoutValidation("Authorization", auth);
                using var resp = await authClient.SendAsync(credReq, ct);
                if (resp.StatusCode == System.Net.HttpStatusCode.OK)
                {
                  return (true, $"HTTP:{port} {user}:{pass} 登录成功 (凭证使 401 变 200)");
                }
              }
              catch { }
            }
          }
          catch (Exception ex)
          {
            System.Diagnostics.Debug.WriteLine($"HTTP 默认凭证检查失败 ({user}:{pass}): {ex.Message}");
          }
        }
      }
      return (false, "未发现默认凭证");
    }

    /// <summary>
    /// RTSP Digest/Basic 凭证检测 - 处理 401 挑战后再认证
    /// </summary>
    private async Task<(bool isVuln, string evidence)> CheckRtspDigestCredsAsync(
        string ip, CancellationToken ct)
    {
      try
      {
        using var tcp = new TcpClient();
        var connect = tcp.ConnectAsync(ip, 554);
        if (await Task.WhenAny(connect, Task.Delay(2000, ct)) != connect)
          return (false, "连接超时");
        await connect;
        using var stream = tcp.GetStream();

        foreach (var (user, pass) in DefaultCreds)
        {
          try
          {
            string respStr;
            // 第一次请求：探测是否需要认证（不带凭证）
            var req1 = $"DESCRIBE rtsp://{FormatIpForUrl(ip)}:554/ RTSP/1.0\r\nCSeq: 1\r\nUser-Agent: scanner\r\n\r\n";
            await stream.WriteAsync(Encoding.ASCII.GetBytes(req1), ct);
            await stream.FlushAsync(ct);

            var buf1 = new byte[2048];
            using var cts1 = new CancellationTokenSource(2000);
            int read1;
            try { read1 = await stream.ReadAsync(buf1, cts1.Token); }
            catch { read1 = 0; }
            respStr = Encoding.ASCII.GetString(buf1, 0, read1);

            // 如果直接 200 OK 则说明不需要凭证（其他方法已检测，这里不重复）
            if (respStr.Contains("200 OK") && !respStr.Contains("401"))
              continue;

            // 如果是 401 Unauthorized，尝试 Basic 认证
            if (respStr.Contains("401"))
            {
              // Basic 认证
              var basic = Convert.ToBase64String(Encoding.ASCII.GetBytes($"{user}:{pass}"));
              var authReq = $"DESCRIBE rtsp://{FormatIpForUrl(ip)}:554/ RTSP/1.0\r\nCSeq: 2\r\nAuthorization: Basic {basic}\r\nUser-Agent: scanner\r\n\r\n";
              await stream.WriteAsync(Encoding.ASCII.GetBytes(authReq), ct);
              await stream.FlushAsync(ct);

              var buf2 = new byte[2048];
              using var cts2 = new CancellationTokenSource(2000);
              int read2;
              try { read2 = await stream.ReadAsync(buf2, cts2.Token); }
              catch { read2 = 0; }
              var resp2 = Encoding.ASCII.GetString(buf2, 0, read2);

              if (resp2.Contains("200 OK"))
                return (true, $"RTSP Basic 认证成功 {user}:{pass}");

              // Digest 认证（提取 realm 和 nonce）
              var realmMatch = System.Text.RegularExpressions.Regex.Match(respStr, @"realm=""([^""]+)""");
              var nonceMatch = System.Text.RegularExpressions.Regex.Match(respStr, @"nonce=""([^""]+)""");
              if (realmMatch.Success && nonceMatch.Success)
              {
                var realm = realmMatch.Groups[1].Value;
                var nonce = nonceMatch.Groups[1].Value;
                // Digest: response = MD5(MD5(user:realm:pass) : nonce : MD5(method:uri))
                var ha1 = ComputeMd5($"{user}:{realm}:{pass}");
                var ha2 = ComputeMd5($"DESCRIBE:rtsp://{FormatIpForUrl(ip)}:554/");
                var responseDigest = ComputeMd5($"{ha1}:{nonce}:{ha2}");

                var digestReq = $"DESCRIBE rtsp://{FormatIpForUrl(ip)}:554/ RTSP/1.0\r\nCSeq: 3\r\nAuthorization: Digest username=\"{user}\", realm=\"{realm}\", nonce=\"{nonce}\", uri=\"rtsp://{FormatIpForUrl(ip)}:554/\", response=\"{responseDigest}\"\r\nUser-Agent: scanner\r\n\r\n";
                await stream.WriteAsync(Encoding.ASCII.GetBytes(digestReq), ct);
                await stream.FlushAsync(ct);

                var buf3 = new byte[2048];
                using var cts3 = new CancellationTokenSource(2000);
                int read3;
                try { read3 = await stream.ReadAsync(buf3, cts3.Token); }
                catch { read3 = 0; }
                var resp3 = Encoding.ASCII.GetString(buf3, 0, read3);

                if (resp3.Contains("200 OK"))
                  return (true, $"RTSP Digest 认证成功 {user}:{pass} (realm={realm})");
              }
            }
          }
          catch (Exception ex)
          {
            System.Diagnostics.Debug.WriteLine($"RTSP 凭证检查异常 ({user}:{pass}): {ex.Message}");
          }
        }
      }
      catch (Exception ex)
      {
        System.Diagnostics.Debug.WriteLine($"RTSP 凭证检查失败: {ex.Message}");
      }
      return (false, "未发现 RTSP 默认凭证");
    }

    private static string ComputeMd5(string input)
    {
      using var md5 = System.Security.Cryptography.MD5.Create();
      var hash = md5.ComputeHash(Encoding.ASCII.GetBytes(input));
      return BitConverter.ToString(hash).Replace("-", "").ToLowerInvariant();
    }

    private static async Task<bool> IsPortOpenAsync(string ip, int port, int timeoutMs)
    {
      try
      {
        using var tcp = new TcpClient();
        var connect = tcp.ConnectAsync(ip, port);
        if (await Task.WhenAny(connect, Task.Delay(timeoutMs)) != connect) return false;
        await connect;
        return true;
      }
      catch { return false; }
    }

    public CameraRiskAssessment AssessRisk(CameraScanResult camera)
    {
      var assessment = new CameraRiskAssessment();
      var score = 0.0;

      assessment.VulnerabilityCount = camera.Vulnerabilities.Count;
      assessment.CriticalCount = camera.Vulnerabilities.Count(v => v.Severity == "Critical");
      assessment.HighCount = camera.Vulnerabilities.Count(v => v.Severity == "High");
      assessment.MediumCount = camera.Vulnerabilities.Count(v => v.Severity == "Medium");
      assessment.WeakPasswordCount = camera.WeakPasswords.Count;
      assessment.DangerousPortCount = camera.OpenPorts.Count(p => p.RiskLevel == "高危" || p.RiskLevel == "严重");

      foreach (var vuln in camera.Vulnerabilities)
      {
        score += vuln.CvssScore * 5;
      }

      foreach (var wp in camera.WeakPasswords)
      {
        score += wp.RiskLevel == "严重" ? 15 : 10;
      }

      score += camera.OpenPorts.Count(p => p.RiskLevel == "严重") * 8;
      score += camera.OpenPorts.Count(p => p.RiskLevel == "高危") * 5;
      score += camera.OpenPorts.Count(p => p.RiskLevel == "中危") * 2;
      score += camera.OpenPorts.Count(p => p.RiskLevel == "低危") * 1;

      if (camera.OpenPorts.Any(p => p.Port == 22))
        score += 3;
      if (camera.OpenPorts.Any(p => p.Port == 21))
        score += 3;
      if (camera.OpenPorts.Any(p => p.Port == 23))
        score += 5;
      if (camera.OpenPorts.Any(p => p.Port == 161))
        score += 2;
      if (camera.OpenPorts.Any(p => p.Port == 8899) && camera.WeakPasswords.Any(w => w.ServiceType == "ONVIF"))
        score += 5;

      if (camera.WeakPasswords.Any(w => w.ServiceType == "SSH"))
        score += 8;
      if (camera.WeakPasswords.Any(w => w.ServiceType == "FTP"))
        score += 8;
      if (camera.WeakPasswords.Any(w => w.ServiceType == "ONVIF"))
        score += 10;

      assessment.TotalScore = Math.Min(score, 100);
      assessment.RiskLevel = assessment.TotalScore switch
      {
        >= 80 => "严重",
        >= 60 => "高危",
        >= 30 => "中危",
        >= 10 => "低危",
        _ => "信息"
      };

      var remediations = new List<string>();
      if (assessment.CriticalCount > 0)
        remediations.Add($"立即修复 {assessment.CriticalCount} 个严重漏洞，升级固件至最新版本");
      if (assessment.WeakPasswordCount > 0)
        remediations.Add($"修改 {assessment.WeakPasswordCount} 处弱口令为强密码（至少12位，含大小写字母+数字+特殊字符）");
      if (assessment.DangerousPortCount > 0)
        remediations.Add($"关闭或限制访问 {assessment.DangerousPortCount} 个高危端口（Telnet/SSH/FTP等）");
      if (camera.OpenPorts.Any(p => p.Port == 80 && !camera.OpenPorts.Any(pp => pp.Port == 443)))
        remediations.Add("启用HTTPS加密管理界面，配置TLS 1.2+证书");
      if (camera.Vulnerabilities.Any(v => v.CveId == "RTSP-ANON-001"))
        remediations.Add("启用RTSP认证，防止视频流被未授权访问");
      if (camera.OpenPorts.Any(p => p.Port == 23))
        remediations.Add("立即关闭Telnet服务（明文传输），改用SSH密钥认证或完全禁用远程终端");
      if (camera.OpenPorts.Any(p => p.Port == 22))
        remediations.Add("SSH端口对外开放风险较高，建议配置密钥认证并限制访问来源IP");
      if (camera.OpenPorts.Any(p => p.Port == 21))
        remediations.Add("FTP明文传输密码存在泄露风险，建议关闭或改用SFTP/FTPS");
      if (camera.OpenPorts.Any(p => p.Port == 161))
        remediations.Add("SNMP服务可能泄露设备信息，建议关闭或配置SNMPv3加密认证");
      if (camera.OpenPorts.Any(p => p.Port == 8899))
        remediations.Add("ONVIF接口对外开放，建议启用认证并限制访问来源");
      if (camera.OpenPorts.Any(p => p.Port == 1900) || camera.OpenPorts.Any(p => p.Port == 3702))
        remediations.Add("UPnP/SSDP发现服务对外开放，建议在内网中禁用此类服务");
      if (camera.HasTelnet)
        remediations.Add("Telnet明文传输，建议关闭并改用SSH密钥认证");

      if (remediations.Count == 0)
        remediations.Add("当前未发现明显风险，建议定期进行安全扫描并保持固件更新");

      assessment.TopRemediations = remediations.Take(5).ToList();
      assessment.AssessmentTime = DateTime.Now;

      return assessment;
    }

    /// <summary>
    /// 估算目标IP数量（用于智能推荐）
    /// </summary>
    public static int EstimateIpCount(CameraScanOptions options)
    {
      try
      {
        return ParseIpRange(options).Count;
      }
      catch
      {
        return 0;
      }
    }

    /// <summary>
    /// 解析扫描选项中的所有目标 IP（含单 IP / CIDR / 段 / IPv6）。
    /// 不会真正发起扫描，调用方应在 UI 线程外使用以避免阻塞。
    /// </summary>
    public static List<string> GetAllTargetIps(CameraScanOptions options)
    {
      try
      {
        if (options == null) return new List<string>();
        var ips = ParseIpRange(options);
        // ParseIpRange 失败时会回退到 "127.0.0.1"，这里剔除该回退值
        if (ips.Count == 1 && ips[0] == "127.0.0.1" &&
            string.IsNullOrEmpty(options.TargetIp) &&
            string.IsNullOrEmpty(options.IpRange) &&
            string.IsNullOrEmpty(options.CidrNotation) &&
            string.IsNullOrEmpty(options.Ipv6Cidr))
        {
          return new List<string>();
        }
        ips.RemoveAll(ip => ip == "127.0.0.1");
        return ips;
      }
      catch
      {
        return new List<string>();
      }
    }

    private static List<string> ParseIpRange(CameraScanOptions options)
    {
      var ips = new HashSet<string>();

      if (!string.IsNullOrEmpty(options.TargetIp))
      {
        ips.Add(options.TargetIp.Trim());
      }

      if (!string.IsNullOrEmpty(options.CidrNotation))
      {
        try
        {
          var parts = options.CidrNotation.Trim().Split('/');
          if (parts.Length == 2 && int.TryParse(parts[1], out var cidr))
          {
            var baseIp = IPAddress.Parse(parts[0]);
            var baseBytes = baseIp.GetAddressBytes();
            if (baseBytes.Length == 4 && cidr >= 16 && cidr <= 32)
            {
              var mask = ~((1u << (32 - cidr)) - 1);
              var baseUint = (uint)baseBytes[0] << 24 | (uint)baseBytes[1] << 16 |
                             (uint)baseBytes[2] << 8 | baseBytes[3];
              var start = baseUint & mask;
              var count = (~mask) + 1;

              for (uint i = 1; i < count - 1; i++)
              {
                var ip = start + i;
                ips.Add($"{(ip >> 24) & 0xFF}.{(ip >> 16) & 0xFF}.{(ip >> 8) & 0xFF}.{ip & 0xFF}");
              }
            }
          }
        }
        catch (Exception ex)
        {
          System.Diagnostics.Debug.WriteLine($"CIDR解析失败 ({options.CidrNotation}): {ex.Message}");
        }
      }

      if (!string.IsNullOrEmpty(options.IpRange))
      {
        try
        {
          var range = options.IpRange.Trim();
          if (range.Contains('-'))
          {
            var parts = range.Split('-');
            if (parts.Length >= 2)
            {
              var startStr = parts[0].Trim();
              var endStr = parts[1].Trim();

              // 形式1: 192.168.3.1-192.168.3.254 (完整 IP 范围) 或 跨子网 192.168.3.1-192.168.5.254
              // 形式2: 192.168.3.1-254 (仅末尾八位字节)
              if (IPAddress.TryParse(startStr, out var startIp) && startIp.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork)
              {
                uint startUint = IpToUint(startIp);
                uint endUint = 0;
                bool parsed = false;

                if (IPAddress.TryParse(endStr, out var endIp) && endIp.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork)
                {
                  // 完整 IP 范围（含跨子网）
                  endUint = IpToUint(endIp);
                  parsed = true;
                }
                else if (int.TryParse(endStr, out var lastOctet) && lastOctet >= 0 && lastOctet <= 255)
                {
                  // 仅末尾八位字节：192.168.3.1-254
                  var startBytes = startIp.GetAddressBytes();
                  endUint = ((uint)startBytes[0] << 24) | ((uint)startBytes[1] << 16) |
                            ((uint)startBytes[2] << 8) | (uint)lastOctet;
                  parsed = true;
                }

                if (!parsed)
                {
                  System.Diagnostics.Debug.WriteLine($"IP范围解析失败: 无法解析结束值 '{endStr}' (in '{range}')");
                }
                else if (endUint < startUint)
                {
                  System.Diagnostics.Debug.WriteLine($"IP范围解析失败: 结束 IP 小于起始 IP (in '{range}')");
                }
                else
                {
                  // 保护：单次扫描 IP 数量上限 (避免 10.0.0.0-255.255.255.255 把 UI 拉死)
                  const uint MaxIps = 65536;
                  uint count = endUint - startUint + 1;
                  if (count > MaxIps)
                  {
                    System.Diagnostics.Debug.WriteLine($"IP范围过大 ({count}), 截断为 {MaxIps}");
                    count = MaxIps;
                  }
                  for (uint i = 0; i < count; i++)
                  {
                    var u = startUint + i;
                    ips.Add(UintToIp(u));
                  }
                }
              }
            }
          }
        }
        catch (Exception ex)
        {
          System.Diagnostics.Debug.WriteLine($"IP范围解析失败 ({options.IpRange}): {ex.Message}");
        }
      }

      if (!string.IsNullOrEmpty(options.Ipv6Cidr))
      {
        ParseIpv6Input(options.Ipv6Cidr.Trim(), ips);
      }

      if (ips.Count == 0)
        ips.Add("127.0.0.1");

      return ips.ToList();
    }

    private static uint IpToUint(IPAddress ip)
    {
      var b = ip.GetAddressBytes();
      return ((uint)b[0] << 24) | ((uint)b[1] << 16) | ((uint)b[2] << 8) | b[3];
    }

    private static string UintToIp(uint u) =>
      $"{(u >> 24) & 0xFF}.{(u >> 16) & 0xFF}.{(u >> 8) & 0xFF}.{u & 0xFF}";

    private static void ParseIpv6Input(string input, HashSet<string> ips)
    {
      try
      {
        if (input.Contains('/'))
        {
          var parts = input.Split('/');
          if (parts.Length == 2 && IPAddress.TryParse(parts[0], out var baseIp6) &&
              baseIp6.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6 &&
              int.TryParse(parts[1], out var cidr) && cidr >= 112 && cidr <= 128)
          {
            var baseBytes = baseIp6.GetAddressBytes();
            var hostBits = 128 - cidr;
            var maxHosts = 1UL << hostBits;
            if (maxHosts > 65536)
            {
              System.Diagnostics.Debug.WriteLine($"IPv6 CIDR范围过大 ({input}), 限制为前65536个地址");
              maxHosts = 65536;
            }

            var baseAddr = new System.Numerics.BigInteger(baseBytes, isUnsigned: true, isBigEndian: true);
            var mask = ~((System.Numerics.BigInteger.One << hostBits) - 1);
            var networkAddr = baseAddr & mask;

            for (var i = 0UL; i < maxHosts; i++)
            {
              var addr = networkAddr + i;
              var addrBytes = addr.ToByteArray(isUnsigned: true, isBigEndian: true);
              if (addrBytes.Length < 16)
              {
                var padded = new byte[16];
                Array.Copy(addrBytes, 0, padded, 16 - addrBytes.Length, addrBytes.Length);
                addrBytes = padded;
              }
              else if (addrBytes.Length > 16)
              {
                addrBytes = addrBytes[^16..];
              }
              var ip6 = new IPAddress(addrBytes);
              ips.Add(ip6.ToString());
            }
          }
        }
        else
        {
          if (IPAddress.TryParse(input, out var ip6) &&
              ip6.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6)
          {
            ips.Add(ip6.ToString());
          }
        }
      }
      catch (Exception ex)
      {
        System.Diagnostics.Debug.WriteLine($"IPv6解析失败 ({input}): {ex.Message}");
      }
    }

    private static string FormatIpForUrl(string ip)
    {
      if (IPAddress.TryParse(ip, out var addr) && addr.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6)
        return $"[{ip}]";
      return ip;
    }

    public void Dispose()
    {
      if (_disposed) return;
      _disposed = true;
      _fingerprintService?.Dispose();
      _weakPasswordService?.Dispose();
      _httpClient?.Dispose();
    }
  }

  public class CameraScanProgress
  {
    public string Phase { get; set; } = string.Empty;
    public int TotalCount { get; set; }
    public int CompletedCount { get; set; }
    public string Message { get; set; } = string.Empty;
  }

  public class CameraVulnerabilityEntry
  {
    public string CveId { get; set; } = string.Empty;
    public string Name { get; set; } = string.Empty;
    public string Description { get; set; } = string.Empty;
    public string Severity { get; set; } = string.Empty;
    public double CvssScore { get; set; }
    public string AffectedVendor { get; set; } = string.Empty;
    public string AffectedVersions { get; set; } = string.Empty;
    public string FixedVersion { get; set; } = string.Empty;
    public string Solution { get; set; } = string.Empty;
    public string Reference { get; set; } = string.Empty;
    public string DetectionMethod { get; set; } = string.Empty;
  }
}