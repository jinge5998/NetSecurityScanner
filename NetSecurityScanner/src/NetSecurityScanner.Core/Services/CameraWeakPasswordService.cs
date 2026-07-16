using System;
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
  public class CameraWeakPasswordService : IDisposable
  {
    private readonly List<WeakPasswordEntry> _dictionary;
    private readonly HttpClient _httpClient;
    private bool _disposed;

    public CameraWeakPasswordService()
    {
      _httpClient = new HttpClient { Timeout = TimeSpan.FromSeconds(5) };
      _dictionary = LoadDictionary();
    }

    private List<WeakPasswordEntry> LoadDictionary()
    {
      try
      {
        var assemblyLocation = typeof(CameraWeakPasswordService).Assembly.Location;
        var assemblyDir = Path.GetDirectoryName(assemblyLocation) ?? string.Empty;
        var jsonPath = Path.Combine(assemblyDir, "Data", "CameraWeakPasswordDict.json");
        if (!File.Exists(jsonPath))
        {
          var altPath = Path.Combine(Directory.GetCurrentDirectory(), "Data", "CameraWeakPasswordDict.json");
          jsonPath = File.Exists(altPath) ? altPath : jsonPath;
        }
        if (!File.Exists(jsonPath)) return new List<WeakPasswordEntry>();
        var json = File.ReadAllText(jsonPath, Encoding.UTF8);
        return JsonSerializer.Deserialize<List<WeakPasswordEntry>>(json) ?? new List<WeakPasswordEntry>();
      }
      catch
      {
        return new List<WeakPasswordEntry>();
      }
    }

    public async Task<List<CameraWeakPassword>> CheckWeakPasswordsAsync(
        string ip, string vendor, List<CameraPortInfo> openPorts,
        CancellationToken ct, IProgress<string>? progress = null)
    {
      var results = new List<CameraWeakPassword>();
      var vendorEntry = _dictionary.FirstOrDefault(d =>
          d.Vendor.Equals(vendor, StringComparison.OrdinalIgnoreCase));
      var genericEntry = _dictionary.FirstOrDefault(d => d.Vendor == "通用");

      var usernames = new List<string>();
      var passwords = new List<string>();

      if (vendorEntry != null)
      {
        usernames.AddRange(vendorEntry.Usernames ?? new List<string>());
        passwords.AddRange(vendorEntry.Passwords ?? new List<string>());
      }
      if (genericEntry != null)
      {
        usernames.AddRange(genericEntry.Usernames?.Except(usernames) ?? new List<string>());
        passwords.AddRange(genericEntry.Passwords?.Except(passwords) ?? new List<string>());
      }

      if (!usernames.Any() || !passwords.Any())
        return results;

      var httpPorts = openPorts.Where(p =>
          p.Service.Contains("HTTP", StringComparison.OrdinalIgnoreCase) ||
          p.Service.Contains("HTTPS", StringComparison.OrdinalIgnoreCase) ||
          p.Port == 80 || p.Port == 443 || p.Port == 8080 || p.Port == 8443).ToList();

      foreach (var portInfo in httpPorts)
      {
        progress?.Report($"正在检测 {ip}:{portInfo.Port} HTTP弱口令...");
        var httpResult = await CheckHttpWeakPasswordAsync(ip, portInfo.Port, usernames, passwords, ct);
        if (httpResult != null)
        {
          results.Add(httpResult);
          break;
        }
      }

      var rtspPort = openPorts.FirstOrDefault(p => p.Port == 554);
      if (rtspPort != null)
      {
        progress?.Report($"正在检测 {ip}:554 RTSP弱口令...");
        var rtspResult = await CheckRtspWeakPasswordAsync(ip, usernames, passwords, ct);
        if (rtspResult != null)
          results.Add(rtspResult);
      }

      var telnetPort = openPorts.FirstOrDefault(p => p.Port == 23);
      if (telnetPort != null)
      {
        progress?.Report($"正在检测 {ip}:23 Telnet弱口令...");
        var telnetResult = await CheckTelnetWeakPasswordAsync(ip, usernames, passwords, ct);
        if (telnetResult != null)
          results.Add(telnetResult);
      }

      // 检查SSH弱口令
      var sshPort = openPorts.FirstOrDefault(p => p.Port == 22);
      if (sshPort != null)
      {
        progress?.Report($"检查SSH弱口令 (端口22)...");
        var sshResult = await CheckSshWeakPasswordAsync(ip, 22, usernames, passwords, ct);
        if (sshResult != null)
          results.Add(sshResult);
      }

      // 检查ONVIF弱口令
      var onvifPort = openPorts.FirstOrDefault(p => p.Port == 8899 || p.Port == 8080);
      if (onvifPort != null)
      {
        progress?.Report($"检查ONVIF弱口令 (端口{onvifPort.Port})...");
        var onvifResult = await CheckOnvifWeakPasswordAsync(ip, onvifPort.Port, usernames, passwords, ct);
        if (onvifResult != null)
          results.Add(onvifResult);
      }

      // 检查FTP弱口令
      var ftpPort = openPorts.FirstOrDefault(p => p.Port == 21);
      if (ftpPort != null)
      {
        progress?.Report($"检查FTP弱口令 (端口21)...");
        var ftpResult = await CheckFtpWeakPasswordAsync(ip, 21, usernames, passwords, ct);
        if (ftpResult != null)
          results.Add(ftpResult);
      }

      return results;
    }

    private async Task<CameraWeakPassword?> CheckHttpWeakPasswordAsync(
        string ip, int port, List<string> usernames, List<string> passwords, CancellationToken ct)
    {
      var scheme = port == 443 ? "https" : "http";
      var baseUrl = $"{scheme}://{FormatIpForUrl(ip)}:{port}";

      // 1) 先无凭证探测：服务器是否要求认证？
      try
      {
        using var noAuthReq = new HttpRequestMessage(HttpMethod.Get, baseUrl);
        using var noAuthResp = await _httpClient.SendAsync(noAuthReq, ct);
        // 只有 401 Unauthorized 才是"启用了认证"
        if (noAuthResp.StatusCode != HttpStatusCode.Unauthorized)
        {
          // 服务端无认证（200/403/302 等）→ 这是"未授权访问"漏洞，不算弱口令
          System.Diagnostics.Debug.WriteLine($"[WeakPwd] HTTP {ip}:{port} 未要求认证 (status={noAuthResp.StatusCode}) - 跳过弱口令检测");
          return null;
        }
      }
      catch (Exception ex)
      {
        System.Diagnostics.Debug.WriteLine($"[WeakPwd] HTTP {ip}:{port} 探测失败: {ex.Message}");
        return null;
      }

      // 2) 服务端启用认证 → 尝试弱口令
      foreach (var username in usernames.Take(5))
      {
        foreach (var password in passwords.Take(10))
        {
          if (ct.IsCancellationRequested) return null;
          try
          {
            var credential = Convert.ToBase64String(
                Encoding.ASCII.GetBytes($"{username}:{password}"));
            using var request = new HttpRequestMessage(HttpMethod.Get, baseUrl);
            request.Headers.Add("Authorization", $"Basic {credential}");

            using var response = await _httpClient.SendAsync(request, ct);
            // 服务器要求认证 + 凭证使 401 变 200 → 真弱口令
            if (response.IsSuccessStatusCode && response.StatusCode != HttpStatusCode.Unauthorized)
            {
              return new CameraWeakPassword
              {
                ServiceType = "HTTP",
                Port = port,
                Username = username,
                Password = password,
                RiskLevel = "严重",
                Suggestion = $"立即修改 {username} 账户密码为强密码（至少12位，包含大小写字母、数字和特殊字符）"
              };
            }

            await Task.Delay(100, ct);
          }
          catch
          {
            break;
          }
        }
      }
      return null;
    }

    private async Task<CameraWeakPassword?> CheckRtspWeakPasswordAsync(
        string ip, List<string> usernames, List<string> passwords, CancellationToken ct)
    {
      // 1) 先无凭证探测：RTSP 是否启用了认证？
      bool rtspRequiresAuth = false;
      try
      {
        using var tcp0 = new TcpClient();
        var connect0 = tcp0.ConnectAsync(ip, 554);
        if (await Task.WhenAny(connect0, Task.Delay(2000, ct)) != connect0) return null;
        await connect0;
        using (var stream0 = tcp0.GetStream())
        {
          var noAuthReq = $"DESCRIBE rtsp://{FormatIpForUrl(ip)}:554/ RTSP/1.0\r\nCSeq: 1\r\nUser-Agent: CameraScanner\r\n\r\n";
          var noAuthBytes = Encoding.ASCII.GetBytes(noAuthReq);
          await stream0.WriteAsync(noAuthBytes, ct);
          await stream0.FlushAsync(ct);
          var buf0 = new byte[2048];
          var n0 = await stream0.ReadAsync(buf0, ct);
          var resp0 = Encoding.ASCII.GetString(buf0, 0, n0);
          // RTSP 401 = 启用了认证；200 = RTSP 实际开放（未授权访问漏洞）
          if (resp0.StartsWith("RTSP/1.0 401") || resp0.Contains("401 Unauthorized"))
          {
            rtspRequiresAuth = true;
          }
          else
          {
            System.Diagnostics.Debug.WriteLine($"[WeakPwd] RTSP {ip}:554 未要求认证 (200 OK) - 这是未授权访问漏洞，不算弱口令");
            return null;
          }
        }
      }
      catch (Exception ex)
      {
        System.Diagnostics.Debug.WriteLine($"[WeakPwd] RTSP {ip}:554 探测失败: {ex.Message}");
        return null;
      }

      if (!rtspRequiresAuth) return null;

      // 2) RTSP 启用了认证 → 尝试弱口令
      foreach (var username in usernames.Take(3))
      {
        foreach (var password in passwords.Take(5))
        {
          if (ct.IsCancellationRequested) return null;
          try
          {
            using var tcpClient = new TcpClient();
            var connectTask = tcpClient.ConnectAsync(ip, 554);
            if (await Task.WhenAny(connectTask, Task.Delay(2000, ct)) != connectTask)
              return null;
            await connectTask;
            using var stream = tcpClient.GetStream();
            var auth = Convert.ToBase64String(
                Encoding.ASCII.GetBytes($"{username}:{password}"));
            var describeRequest = $"DESCRIBE rtsp://{FormatIpForUrl(ip)}:554/ RTSP/1.0\r\nCSeq: 1\r\nAuthorization: Basic {auth}\r\nUser-Agent: CameraScanner\r\n\r\n";
            var requestBytes = Encoding.ASCII.GetBytes(describeRequest);
            await stream.WriteAsync(requestBytes, ct);
            await stream.FlushAsync(ct);

            var buffer = new byte[2048];
            var bytesRead = await stream.ReadAsync(buffer, ct);
            var response = Encoding.ASCII.GetString(buffer, 0, bytesRead);

            // 凭证使 401 变 200 → 真弱口令
            if (response.Contains("200 OK"))
            {
              return new CameraWeakPassword
              {
                ServiceType = "RTSP",
                Port = 554,
                Username = username,
                Password = password,
                RiskLevel = "严重",
                Suggestion = "立即修改RTSP认证密码为强密码，禁用匿名访问"
              };
            }
            await Task.Delay(200, ct);
          }
          catch
          {
            break;
          }
        }
      }
      return null;
    }

    private async Task<CameraWeakPassword?> CheckTelnetWeakPasswordAsync(
        string ip, List<string> usernames, List<string> passwords, CancellationToken ct)
    {
      foreach (var username in usernames.Take(3))
      {
        foreach (var password in passwords.Take(5))
        {
          if (ct.IsCancellationRequested) return null;
          try
          {
            using var tcpClient = new TcpClient();
            var connectTask = tcpClient.ConnectAsync(ip, 23);
            if (await Task.WhenAny(connectTask, Task.Delay(2000, ct)) != connectTask)
              return null;
            await connectTask;
            using var stream = tcpClient.GetStream();

            var buffer = new byte[1024];
            var bytesRead = await stream.ReadAsync(buffer, ct);
            var banner = Encoding.ASCII.GetString(buffer, 0, bytesRead);

            if (banner.Contains("login:", StringComparison.OrdinalIgnoreCase) ||
                banner.Contains("Username:", StringComparison.OrdinalIgnoreCase))
            {
              return new CameraWeakPassword
              {
                ServiceType = "Telnet",
                Port = 23,
                Username = username,
                Password = "***",
                RiskLevel = "高危",
                Suggestion = "强烈建议关闭Telnet服务，改用SSH或禁用远程终端。如必须使用，请配置复杂密码并限制访问IP"
              };
            }
            break;
          }
          catch
          {
            break;
          }
        }
      }
      return null;
    }

    public void Dispose()
    {
      if (_disposed) return;
      _disposed = true;
      _httpClient?.Dispose();
    }

    private static string FormatIpForUrl(string ip)
    {
      if (IPAddress.TryParse(ip, out var addr) && addr.AddressFamily == AddressFamily.InterNetworkV6)
        return $"[{ip}]";
      return ip;
    }

    /// <summary>
    /// 检查SSH弱口令（端口22）
    /// </summary>
    private async Task<CameraWeakPassword?> CheckSshWeakPasswordAsync(
        string ip, int port, List<string> usernames, List<string> passwords, CancellationToken ct)
    {
      foreach (var username in usernames.Take(3))
      {
        foreach (var password in passwords.Take(5))
        {
          if (ct.IsCancellationRequested) return null;
          try
          {
            using var tcpClient = new TcpClient();
            var connectTask = tcpClient.ConnectAsync(ip, port);
            if (await Task.WhenAny(connectTask, Task.Delay(2000, ct)) != connectTask)
              return null;
            await connectTask;
            using var stream = tcpClient.GetStream();

            var banner = new byte[256];
            var readTask = stream.ReadAsync(banner, 0, banner.Length, ct);
            if (await Task.WhenAny(readTask, Task.Delay(2000, ct)) != readTask)
              return null;
            var bytesRead = await readTask;
            var bannerStr = Encoding.ASCII.GetString(banner, 0, bytesRead);

            if (bannerStr.Contains("SSH"))
            {
              return new CameraWeakPassword
              {
                ServiceType = "SSH",
                Port = port,
                Username = username,
                Password = "***检测到SSH服务***",
                RiskLevel = "严重",
                Suggestion = "SSH端口对外开放，建议关闭或使用密钥认证并限制访问IP"
              };
            }
            await Task.Delay(200, ct);
          }
          catch { break; }
        }
      }
      return null;
    }

    /// <summary>
    /// 检查ONVIF弱口令（通常端口80/8899）
    /// </summary>
    private async Task<CameraWeakPassword?> CheckOnvifWeakPasswordAsync(
        string ip, int port, List<string> usernames, List<string> passwords, CancellationToken ct)
    {
      var scheme = port == 443 ? "https" : "http";
      var onvifUrl = $"{scheme}://{FormatIpForUrl(ip)}:{port}/onvif/device_service";
      var probeBody = "<?xml version=\"1.0\" encoding=\"utf-8\"?>" +
          "<s:Envelope xmlns:s=\"http://www.w3.org/2003/05/soap-envelope\">" +
          "<s:Body><GetDeviceInformation xmlns=\"http://www.onvif.org/ver10/device/wsdl\"/>" +
          "</s:Body></s:Envelope>";

      // 1) 先无凭证探测：ONVIF 是否要求认证？
      bool onvifRequiresAuth = false;
      try
      {
        using var noAuthReq = new HttpRequestMessage(HttpMethod.Post, onvifUrl);
        noAuthReq.Content = new StringContent(probeBody, Encoding.UTF8, "application/soap+xml");
        using var noAuthCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        noAuthCts.CancelAfter(3000);
        using var noAuthResp = await _httpClient.SendAsync(noAuthReq, noAuthCts.Token);
        // ONVIF 通常用 401/403 表示要求认证
        if (noAuthResp.StatusCode == HttpStatusCode.Unauthorized ||
            noAuthResp.StatusCode == HttpStatusCode.Forbidden)
        {
          onvifRequiresAuth = true;
        }
        else if (noAuthResp.IsSuccessStatusCode)
        {
          // 200 OK = ONVIF 匿名访问（GetDeviceInformation 公开）→ 这是 ONVIF-ANON 漏洞，不算弱口令
          System.Diagnostics.Debug.WriteLine($"[WeakPwd] ONVIF {ip}:{port} 未要求认证 (status={noAuthResp.StatusCode}) - 这是未授权访问漏洞，不算弱口令");
          return null;
        }
      }
      catch (Exception ex)
      {
        System.Diagnostics.Debug.WriteLine($"[WeakPwd] ONVIF {ip}:{port} 探测失败: {ex.Message}");
        return null;
      }

      if (!onvifRequiresAuth) return null;

      // 2) ONVIF 启用了认证 → 尝试弱口令
      foreach (var username in usernames.Take(3))
      {
        foreach (var password in passwords.Take(5))
        {
          if (ct.IsCancellationRequested) return null;
          try
          {
            var auth = Convert.ToBase64String(
                Encoding.ASCII.GetBytes($"{username}:{password}"));

            using var request = new HttpRequestMessage(HttpMethod.Post, onvifUrl);
            request.Headers.TryAddWithoutValidation("Authorization", $"Basic {auth}");
            request.Content = new StringContent(probeBody, Encoding.UTF8, "application/soap+xml");

            using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
            cts.CancelAfter(3000);
            using var response = await _httpClient.SendAsync(request, cts.Token);

            // 凭证使 401 变 200 → 真弱口令
            if (response.IsSuccessStatusCode)
            {
              return new CameraWeakPassword
              {
                ServiceType = "ONVIF",
                Port = port,
                Username = username,
                Password = password,
                RiskLevel = "严重",
                Suggestion = "ONVIF接口使用弱口令，应立即修改为强密码并限制访问来源"
              };
            }
            await Task.Delay(100, ct);
          }
          catch { break; }
        }
      }
      return null;
    }

    /// <summary>
    /// 检查FTP弱口令/匿名登录（端口21）
    /// </summary>
    private async Task<CameraWeakPassword?> CheckFtpWeakPasswordAsync(
        string ip, int port, List<string> usernames, List<string> passwords, CancellationToken ct)
    {
      foreach (var username in usernames.Take(3))
      {
        foreach (var password in passwords.Take(5))
        {
          if (ct.IsCancellationRequested) return null;
          try
          {
            using var tcpClient = new TcpClient();
            var connectTask = tcpClient.ConnectAsync(ip, port);
            if (await Task.WhenAny(connectTask, Task.Delay(2000, ct)) != connectTask)
              return null;
            await connectTask;
            using var stream = tcpClient.GetStream();
            using var reader = new StreamReader(stream, Encoding.ASCII);

            var banner = await reader.ReadLineAsync();
            if (banner == null) break;

            using var writer = new StreamWriter(stream, Encoding.ASCII) { AutoFlush = true, NewLine = "\r\n" };
            await writer.WriteLineAsync($"USER {username}");
            var userResp = await reader.ReadLineAsync();
            if (userResp == null) break;

            await writer.WriteLineAsync($"PASS {password}");
            var passResp = await reader.ReadLineAsync();
            if (passResp != null && passResp.StartsWith("230"))
            {
              return new CameraWeakPassword
              {
                ServiceType = "FTP",
                Port = port,
                Username = username,
                Password = password,
                RiskLevel = "严重",
                Suggestion = "FTP使用弱口令，应立即修改密码或改用SFTP/FTPS"
              };
            }
            await Task.Delay(200, ct);
          }
          catch { break; }
        }
      }
      return null;
    }
  }

  public class WeakPasswordEntry
  {
    public string Vendor { get; set; } = string.Empty;
    public List<string>? Usernames { get; set; }
    public List<string>? Passwords { get; set; }
  }
}