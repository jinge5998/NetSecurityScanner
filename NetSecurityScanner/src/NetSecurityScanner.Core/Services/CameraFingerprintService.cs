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
  public class CameraFingerprintService : IDisposable
  {
    private readonly List<CameraFingerprintRule> _rules;
    private readonly HttpClient _httpClient;
    private bool _disposed;

    public CameraFingerprintService()
    {
      _httpClient = new HttpClient { Timeout = TimeSpan.FromSeconds(5) };
      _rules = LoadFingerprintRules();
    }

    private List<CameraFingerprintRule> LoadFingerprintRules()
    {
      try
      {
        var assemblyLocation = typeof(CameraFingerprintService).Assembly.Location;
        var assemblyDir = Path.GetDirectoryName(assemblyLocation) ?? string.Empty;
        var jsonPath = Path.Combine(assemblyDir, "Data", "CameraFingerprintDB.json");
        if (!File.Exists(jsonPath))
        {
          var altPath = Path.Combine(Directory.GetCurrentDirectory(), "Data", "CameraFingerprintDB.json");
          if (File.Exists(altPath))
            jsonPath = altPath;
          else
            return new List<CameraFingerprintRule>();
        }
        var json = File.ReadAllText(jsonPath, Encoding.UTF8);
        return JsonSerializer.Deserialize<List<CameraFingerprintRule>>(json) ?? new List<CameraFingerprintRule>();
      }
      catch (Exception ex)
      {
        System.Diagnostics.Debug.WriteLine($"加载指纹数据库失败: {ex.Message}");
        return new List<CameraFingerprintRule>();
      }
    }

    public async Task<CameraFingerprint?> IdentifyCameraAsync(string ip, int httpPort, CancellationToken ct)
    {
      try
      {
        var httpUrl = httpPort == 443 ? $"https://{FormatIpForUrl(ip)}" : $"http://{FormatIpForUrl(ip)}:{httpPort}";
        using var request = new HttpRequestMessage(HttpMethod.Get, httpUrl);
        using var response = await _httpClient.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, ct);
        if (!response.IsSuccessStatusCode) return null;

        var responseBody = await response.Content.ReadAsStringAsync();
        var serverHeader = response.Headers.Server?.ToString() ?? string.Empty;

        foreach (var rule in _rules)
        {
          var confidence = 0.0;
          var matchCount = 0;
          var totalChecks = 1;

          if (rule.HttpPatterns?.Any() == true)
          {
            totalChecks++;
            if (rule.HttpPatterns.Any(p => responseBody.Contains(p, StringComparison.OrdinalIgnoreCase)))
            {
              matchCount++;
              confidence += 0.4;
            }
          }

          if (rule.HttpServer?.Any() == true)
          {
            totalChecks++;
            if (rule.HttpServer.Any(s => serverHeader.Contains(s, StringComparison.OrdinalIgnoreCase)))
            {
              matchCount++;
              confidence += 0.3;
            }
          }

          if (matchCount > 0)
          {
            confidence = Math.Min(confidence, 1.0);
            return new CameraFingerprint
            {
              Vendor = rule.Vendor,
              Model = ExtractModel(responseBody),
              FirmwareVersion = ExtractFirmware(responseBody),
              HttpServer = serverHeader,
              Confidence = confidence
            };
          }
        }

        return new CameraFingerprint { Vendor = "未知", Confidence = 0.0 };
      }
      catch (Exception ex)
      {
        System.Diagnostics.Debug.WriteLine($"HTTP指纹识别失败 ({ip}): {ex.Message}");
        return null;
      }
    }

    public async Task<CameraFingerprint?> IdentifyByRtspAsync(string ip, int rtspPort, CancellationToken ct)
    {
      try
      {
        using var tcpClient = new TcpClient();
        var connectTask = tcpClient.ConnectAsync(ip, rtspPort);
        if (await Task.WhenAny(connectTask, Task.Delay(3000, ct)) != connectTask)
          return null;
        await connectTask;
        using var stream = tcpClient.GetStream();

        var describeRequest = $"DESCRIBE rtsp://{FormatIpForUrl(ip)}:{rtspPort}/ RTSP/1.0\r\nCSeq: 1\r\nUser-Agent: CameraScanner\r\n\r\n";
        var requestBytes = Encoding.ASCII.GetBytes(describeRequest);
        await stream.WriteAsync(requestBytes, ct);
        await stream.FlushAsync(ct);

        var buffer = new byte[4096];
        var bytesRead = await stream.ReadAsync(buffer, ct);
        var response = Encoding.ASCII.GetString(buffer, 0, bytesRead);

        var fingerprint = new CameraFingerprint();

        // 提取 Server 头（即使 401 也会有）
        var serverMatch = System.Text.RegularExpressions.Regex.Match(response,
            @"Server:\s*([^\r\n]+)", System.Text.RegularExpressions.RegexOptions.IgnoreCase);
        if (serverMatch.Success)
        {
          var server = serverMatch.Groups[1].Value.Trim();
          // 基于 Server 头识别厂商
          if (server.Contains("H264DVR", StringComparison.OrdinalIgnoreCase))
          {
            fingerprint.Vendor = "Tiandy";
            fingerprint.Model = server;
            fingerprint.Confidence = 0.95;
            System.Diagnostics.Debug.WriteLine($"[Tiandy 识别] {ip}: Server={server}");
          }
          else if (server.Contains("Hikvision", StringComparison.OrdinalIgnoreCase) ||
                   server.Contains("HikVison", StringComparison.OrdinalIgnoreCase))
          {
            fingerprint.Vendor = "Hikvision";
            fingerprint.Confidence = 0.95;
          }
          else if (server.Contains("Dahua", StringComparison.OrdinalIgnoreCase) ||
                   server.Contains("DHS", StringComparison.OrdinalIgnoreCase))
          {
            fingerprint.Vendor = "Dahua";
            fingerprint.Confidence = 0.95;
          }
          else if (server.Contains("DVR", StringComparison.OrdinalIgnoreCase) ||
                   server.Contains("NetSurveillance", StringComparison.OrdinalIgnoreCase))
          {
            // 常见国内 DVR/NVR 通用签名
            fingerprint.Vendor = "GenericDVR";
            fingerprint.Confidence = 0.5;
          }
        }

        // 兼容旧的关键词匹配
        foreach (var rule in _rules)
        {
          if (response.Contains(rule.Vendor, StringComparison.OrdinalIgnoreCase))
          {
            if (string.IsNullOrEmpty(fingerprint.Vendor))
            {
              fingerprint.Vendor = rule.Vendor;
              fingerprint.Confidence = 0.6;
            }
            break;
          }
        }

        if (string.IsNullOrEmpty(fingerprint.Vendor))
          return null;
        return fingerprint;
      }
      catch (Exception ex)
      {
        System.Diagnostics.Debug.WriteLine($"RTSP指纹识别失败 ({ip}): {ex.Message}");
        return null;
      }
    }

    private static string ExtractModel(string html)
    {
      var modelPatterns = new[]
      {
                @"model[=:]\s*['""]?([\w-]+)['""]?",
                @"Model[=:]\s*['""]?([\w-]+)['""]?",
                @"DS-[\w]+",
                @"DH-[\w]+",
                @"IPC-[\w]+",
                @"WV-[\w]+",
                @"SNC-[\w]+"
            };
      foreach (var pattern in modelPatterns)
      {
        var match = Regex.Match(html, pattern, RegexOptions.IgnoreCase);
        if (match.Success)
          return match.Groups[1].Value;
      }
      return "未知";
    }

    private static string ExtractFirmware(string html)
    {
      var versionPatterns = new[]
      {
                @"firmwareVersion[=:]\s*['""]?([\d.]+)['""]?",
                @"Firmware[=:]\s*['""]?([\d.]+)['""]?",
                @"V(\d+\.\d+\.\d+)",
                @"version[=:]\s*['""]?([\d.]+)['""]?"
            };
      foreach (var pattern in versionPatterns)
      {
        var match = Regex.Match(html, pattern, RegexOptions.IgnoreCase);
        if (match.Success)
          return match.Groups[1].Value;
      }
      return "未知";
    }

    public void Dispose()
    {
      if (_disposed) return;
      _disposed = true;
      _httpClient?.Dispose();
    }

    private static string FormatIpForUrl(string ip)
    {
      if (IPAddress.TryParse(ip, out var addr) && addr.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6)
        return $"[{ip}]";
      return ip;
    }

    /// <summary>
    /// 通过ONVIF协议识别摄像头指纹
    /// </summary>
    public async Task<CameraFingerprint?> IdentifyByOnvifAsync(string ip, int onvifPort, CancellationToken ct)
    {
      try
      {
        var scheme = onvifPort == 443 ? "https" : "http";
        var baseUrl = $"{scheme}://{FormatIpForUrl(ip)}:{onvifPort}/onvif/device_service";
        var soapBody = "<?xml version=\"1.0\" encoding=\"utf-8\"?>" +
            "<s:Envelope xmlns:s=\"http://www.w3.org/2003/05/soap-envelope\">" +
            "<s:Body><GetDeviceInformation xmlns=\"http://www.onvif.org/ver10/device/wsdl\"/>" +
            "</s:Body></s:Envelope>";

        using var request = new HttpRequestMessage(HttpMethod.Post, baseUrl);
        request.Content = new StringContent(soapBody, Encoding.UTF8, "application/soap+xml");

        using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        cts.CancelAfter(5000);
        using var response = await _httpClient.SendAsync(request, cts.Token);
        if (!response.IsSuccessStatusCode) return null;

        var content = await response.Content.ReadAsStringAsync();
        if (string.IsNullOrEmpty(content)) return null;

        var fingerprint = new CameraFingerprint();

        foreach (var rule in _rules)
        {
          if (content.Contains(rule.Vendor, StringComparison.OrdinalIgnoreCase))
          {
            fingerprint.Vendor = rule.Vendor;
            fingerprint.Confidence = 0.7;
            break;
          }
        }

        var mfrMatch = System.Text.RegularExpressions.Regex.Match(content,
            @"<tdc:Manufacturer>([^<]+)</tdc:Manufacturer>");
        if (mfrMatch.Success)
        {
          fingerprint.Vendor = mfrMatch.Groups[1].Value;
          fingerprint.Confidence = Math.Max(fingerprint.Confidence, 0.6);
        }

        var modelMatch = System.Text.RegularExpressions.Regex.Match(content,
            @"<tdc:Model>([^<]+)</tdc:Model>");
        if (modelMatch.Success)
          fingerprint.Model = modelMatch.Groups[1].Value;

        var fwMatch = System.Text.RegularExpressions.Regex.Match(content,
            @"<tdc:FirmwareVersion>([^<]+)</tdc:FirmwareVersion>");
        if (fwMatch.Success)
          fingerprint.FirmwareVersion = fwMatch.Groups[1].Value;

        var snMatch = System.Text.RegularExpressions.Regex.Match(content,
            @"<tdc:SerialNumber>([^<]+)</tdc:SerialNumber>");
        if (snMatch.Success)
          fingerprint.SerialNumber = snMatch.Groups[1].Value;

        return fingerprint.Vendor != null ? fingerprint : null;
      }
      catch (Exception ex)
      {
        System.Diagnostics.Debug.WriteLine($"RTSP指纹识别失败 ({ip}): {ex.Message}");
        return null;
      }
    }

    /// <summary>
    /// 通过UPnP/SSDP发现识别摄像头
    /// </summary>
    public async Task<CameraFingerprint?> IdentifyByUpnpAsync(string ip, int upnpPort, CancellationToken ct)
    {
      try
      {
        using var udpClient = new System.Net.Sockets.UdpClient();
        udpClient.Client.ReceiveTimeout = 3000;

        var searchRequest = "M-SEARCH * HTTP/1.1\r\n" +
            "HOST: 239.255.255.250:1900\r\n" +
            "MAN: \"ssdp:discover\"\r\n" +
            "MX: 2\r\n" +
            "ST: upnp:rootdevice\r\n" +
            "\r\n";
        var requestBytes = Encoding.ASCII.GetBytes(searchRequest);

        await udpClient.SendAsync(requestBytes, requestBytes.Length,
            new System.Net.IPEndPoint(System.Net.IPAddress.Parse(ip), upnpPort));

        var receiveTask = udpClient.ReceiveAsync();
        if (await Task.WhenAny(receiveTask, Task.Delay(3000, ct)) != receiveTask)
          return null;
        var result = await receiveTask;
        var response = Encoding.ASCII.GetString(result.Buffer);

        var fingerprint = new CameraFingerprint();

        foreach (var rule in _rules)
        {
          if (response.Contains(rule.Vendor, StringComparison.OrdinalIgnoreCase))
          {
            fingerprint.Vendor = rule.Vendor;
            fingerprint.Confidence = 0.5;
            break;
          }
        }

        var serverMatch = System.Text.RegularExpressions.Regex.Match(response,
            @"SERVER:\s*([^\r\n]+)");
        if (serverMatch.Success)
          fingerprint.HttpServer = serverMatch.Groups[1].Value.Trim();

        var locationMatch = System.Text.RegularExpressions.Regex.Match(response,
            @"LOCATION:\s*([^\r\n]+)");
        if (locationMatch.Success)
          fingerprint.LocationUrl = locationMatch.Groups[1].Value.Trim();

        return fingerprint.Vendor != null || fingerprint.HttpServer != null
            ? fingerprint : null;
      }
      catch (Exception ex)
      {
        System.Diagnostics.Debug.WriteLine($"UPnP指纹识别失败 ({ip}): {ex.Message}");
        return null;
      }
    }
  }

  public class CameraFingerprintRule
  {
    public string Vendor { get; set; } = string.Empty;
    public List<string>? HttpPatterns { get; set; }
    public List<string>? HttpServer { get; set; }
    public List<string>? MacOui { get; set; }
    public List<int>? DefaultPorts { get; set; }
  }
}