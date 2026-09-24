using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Net.NetworkInformation;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using NetSecurityScanner.Core.Models;

namespace NetSecurityScanner.Core.Services
{
    public class CameraSecurityScanner : IDisposable
    {
        private readonly HttpClient _httpClient;
        private readonly ILogger<CameraSecurityScanner> _logger;
        private readonly List<CameraVulnerability> _vulnerabilities = new();
        private readonly List<CameraFingerprint> _fingerprints = new();
        private readonly List<CameraWeakPasswordEntry> _weakPasswords = new();
        private readonly HikvisionPoC _hikvisionPoC;
        private readonly DahuaPoC _dahuaPoC;
        private static readonly int[] CommonPorts = { 80, 443, 554, 8000, 8200, 37777, 81, 8080, 8443, 9000, 23, 21, 22, 3702 };
        private const int MaxBruteForceAttempts = 200;

        public CameraSecurityScanner(ILogger<CameraSecurityScanner> logger)
        {
            _logger = logger ?? throw new ArgumentNullException(nameof(logger));
            var handler = new SocketsHttpHandler
            {
                ConnectTimeout = TimeSpan.FromSeconds(5),
                PooledConnectionLifetime = TimeSpan.FromMinutes(2),
                SslOptions = new SslClientAuthenticationOptions
                {
                    RemoteCertificateValidationCallback = delegate { return true; },
                    EnabledSslProtocols = SslProtocols.Tls12 | SslProtocols.Tls13
                }
            };
            _httpClient = new HttpClient(handler)
            {
                Timeout = TimeSpan.FromSeconds(15)
            };
            _httpClient.DefaultRequestHeaders.Add("User-Agent", "Mozilla/5.0 NetSecurityScanner/1.0");
            _hikvisionPoC = new HikvisionPoC(_httpClient, logger);
            _dahuaPoC = new DahuaPoC(_httpClient, logger);
            LoadDatabases();
        }

        private void LoadDatabases()
        {
            try
            {
                var dataDir = Path.Combine(AppContext.BaseDirectory, "Data");
                if (!Directory.Exists(dataDir))
                {
                    foreach (var dir in Directory.GetDirectories(AppContext.BaseDirectory, "Data", SearchOption.AllDirectories))
                    {
                        dataDir = dir;
                        break;
                    }
                }

                var vulnFile = Path.Combine(dataDir, "CameraVulnerabilityDB.json");
                if (File.Exists(vulnFile))
                {
                    var json = File.ReadAllText(vulnFile);
                    var opts = new JsonSerializerOptions { PropertyNameCaseInsensitive = true };
                    _vulnerabilities.AddRange(JsonSerializer.Deserialize<List<CameraVulnerability>>(json, opts) ?? new());
                    _logger.LogInformation("Loaded {Count} camera vulnerabilities", _vulnerabilities.Count);
                }

                var fpFile = Path.Combine(dataDir, "CameraFingerprintDB.json");
                if (File.Exists(fpFile))
                {
                    var json = File.ReadAllText(fpFile);
                    var opts = new JsonSerializerOptions { PropertyNameCaseInsensitive = true };
                    var loaded = JsonSerializer.Deserialize<List<CameraFingerprint>>(json, opts) ?? new();
                    _fingerprints.AddRange(loaded);
                    _logger.LogInformation("Loaded {Count} camera fingerprints", _fingerprints.Count);
                }

                var wpFile = Path.Combine(dataDir, "CameraWeakPasswordDict.json");
                if (File.Exists(wpFile))
                {
                    var json = File.ReadAllText(wpFile);
                    var opts = new JsonSerializerOptions { PropertyNameCaseInsensitive = true };
                    _weakPasswords.AddRange(JsonSerializer.Deserialize<List<CameraWeakPasswordEntry>>(json, opts) ?? new());
                    _logger.LogInformation("Loaded {Count} weak password entries", _weakPasswords.Count);
                }
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Failed to load camera databases");
            }
        }

        public async Task<CameraScanResult> ScanAsync(
            string ipAddress,
            CancellationToken cancellationToken = default,
            IProgress<string>? progress = null)
        {
            if (string.IsNullOrWhiteSpace(ipAddress))
                throw new ArgumentException("IP地址不能为空", nameof(ipAddress));

            var target = new CameraScanTarget { IpAddress = ipAddress };
            var result = new CameraScanResult { Target = target };

            progress?.Report($"[*] 开始扫描 {ipAddress} ...");

            target.IsReachable = await PingAsync(ipAddress, cancellationToken);
            if (!target.IsReachable)
            {
                progress?.Report($"[!] {ipAddress} 不可达，但继续尝试端口扫描...");
            }

            progress?.Report("[*] 阶段1/7: 端口扫描...");
            await PortScanAsync(target, cancellationToken);
            if (!target.OpenPorts.Any())
            {
                progress?.Report("[!] 未发现开放端口，扫描终止");
                return result;
            }
            progress?.Report($"[+] 发现 {target.OpenPorts.Count} 个开放端口: {string.Join(", ", target.OpenPorts)}");

            progress?.Report("[*] 阶段2/7: ONVIF 发现探测...");
            await OnvifDiscoveryAsync(target, result.Findings, cancellationToken, progress);

            progress?.Report("[*] 阶段3/7: HTTP 指纹识别...");
            await HttpFingerprintAsync(target, cancellationToken);
            progress?.Report($"[+] 识别设备品牌: {(string.IsNullOrEmpty(target.DetectedVendor) ? "未知" : target.DetectedVendor)}");

            progress?.Report("[*] 阶段4/7: 固件信息探测...");
            await FirmwareProbeAsync(target, cancellationToken);

            progress?.Report("[*] 阶段5/7: 漏洞 PoC 检测...");
            await VulnDetectionAsync(target, result.Findings, cancellationToken, progress);
            progress?.Report($"[+] 发现 {result.Findings.Count} 个漏洞");

            progress?.Report("[*] 阶段6/7: RTSP 认证检测...");
            await RtspAuthCheckAsync(target, result.Findings, cancellationToken, progress);

            progress?.Report("[*] 阶段7/7: 弱口令检测...");
            if (target.OpenPorts.Contains(80) || target.OpenPorts.Contains(8000) || target.OpenPorts.Contains(37777) || target.OpenPorts.Contains(443))
            {
                await WeakPasswordScanAsync(target, result.Findings, cancellationToken, progress);
            }

            ApplyPortBasedFindings(target, result.Findings);

            progress?.Report($"[✓] 扫描完成！风险等级: {result.OverallRiskLevel}, 风险评分: {result.RiskScore}/100");
            return result;
        }

        private void ApplyPortBasedFindings(CameraScanTarget target, List<CameraVulnFinding> findings)
        {
            if (target.OpenPorts.Contains(23) && !findings.Any(f => f.CveId == "TELNET-OPEN-001"))
            {
                findings.Add(new CameraVulnFinding
                {
                    CveId = "TELNET-OPEN-001",
                    Name = "Telnet 服务开放",
                    Severity = "Medium",
                    CvssScore = 5.0,
                    Vendor = target.DetectedVendor,
                    Confirmed = true,
                    DetectionMethod = "PortCheck",
                    Evidence = "端口 23 开放",
                    Remedy = "关闭 Telnet 服务，使用 SSH 替代"
                });
            }
            if (target.OpenPorts.Contains(21) && !findings.Any(f => f.CveId == "FTP-OPEN-001"))
            {
                findings.Add(new CameraVulnFinding
                {
                    CveId = "FTP-OPEN-001",
                    Name = "FTP 服务开放",
                    Severity = "High",
                    CvssScore = 7.0,
                    Vendor = target.DetectedVendor,
                    Confirmed = true,
                    DetectionMethod = "PortCheck",
                    Evidence = "端口 21 开放",
                    Remedy = "关闭 FTP 服务，改用 SFTP 或 FTPS"
                });
            }
            if (target.OpenPorts.Contains(80) && !target.OpenPorts.Contains(443) && !findings.Any(f => f.CveId == "HTTP-PLAIN-001"))
            {
                findings.Add(new CameraVulnFinding
                {
                    CveId = "HTTP-PLAIN-001",
                    Name = "未加密 HTTP 管理",
                    Severity = "Medium",
                    CvssScore = 5.0,
                    Vendor = target.DetectedVendor,
                    Confirmed = true,
                    DetectionMethod = "PortCheck",
                    Evidence = "仅 HTTP(80) 开放，无 HTTPS(443)",
                    Remedy = "启用 HTTPS，配置 TLS 1.2+，禁用 HTTP 或重定向至 HTTPS"
                });
            }
        }

        private static async Task<bool> PingAsync(string ip, CancellationToken ct)
        {
            try
            {
                using var ping = new Ping();
                var reply = await ping.SendPingAsync(ip, 3000);
                return reply.Status == IPStatus.Success;
            }
            catch
            {
                return false;
            }
        }

        private async Task PortScanAsync(CameraScanTarget target, CancellationToken ct)
        {
            var bag = new ConcurrentBag<(int port, string service)>();
            using var sem = new SemaphoreSlim(50);

            await Task.WhenAll(CommonPorts.Select(async port =>
            {
                await sem.WaitAsync(ct);
                try
                {
                    using var tcp = new TcpClient();
                    using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
                    cts.CancelAfter(3000);
                    try
                    {
                        await tcp.ConnectAsync(target.IpAddress, port).WaitAsync(cts.Token);
                        if (tcp.Connected)
                        {
                            bag.Add((port, PortToService(port)));
                        }
                    }
                    catch { }
                }
                catch { }
                finally
                {
                    sem.Release();
                }
            }));

            foreach (var (port, svc) in bag.OrderBy(x => x.port))
            {
                target.OpenPorts.Add(port);
                target.PortServices[port] = svc;
            }
        }

        private static string PortToService(int port) => port switch
        {
            21 => "FTP",
            22 => "SSH",
            23 => "Telnet",
            80 => "HTTP",
            443 => "HTTPS",
            554 => "RTSP",
            3702 => "ONVIF-Discovery",
            8000 => "Hikvision SDK",
            8200 => "Hikvision",
            37777 => "Dahua SDK",
            81 => "HTTP-Alt",
            8080 => "HTTP-Proxy",
            8443 => "HTTPS-Alt",
            9000 => "RTSP-Alt",
            _ => "Unknown"
        };

        private async Task OnvifDiscoveryAsync(
            CameraScanTarget target,
            List<CameraVulnFinding> findings,
            CancellationToken ct,
            IProgress<string>? progress)
        {
            if (!target.OpenPorts.Contains(3702)) return;

            try
            {
                using var udp = new UdpClient();
                udp.Client.ReceiveTimeout = 5000;
                var endpoint = new IPEndPoint(IPAddress.Parse(target.IpAddress), 3702);

                var probe = @"<?xml version=""1.0"" encoding=""UTF-8""?>
<s:Envelope xmlns:s=""http://www.w3.org/2003/05/soap-envelope"" xmlns:a=""http://schemas.xmlsoap.org/ws/2004/08/addressing"">
<s:Header><a:Action>http://schemas.xmlsoap.org/ws/2005/04/discovery/Probe</a:Action>
<a:MessageID>urn:uuid:" + Guid.NewGuid() + @"</a:MessageID>
<a:To>urn:schemas-xmlsoap-org:ws:2005:04:discovery</a:To></s:Header>
<s:Body><Probe xmlns=""http://schemas.xmlsoap.org/ws/2005/04/discovery"">
<d:Types xmlns:d=""http://schemas.xmlsoap.org/ws/2005/04/discovery"">dn:NetworkVideoTransmitter</d:Types>
</Probe></s:Body></s:Envelope>";

                var bytes = Encoding.UTF8.GetBytes(probe);
                await udp.SendAsync(bytes, bytes.Length, endpoint);

                var receiveTask = udp.ReceiveAsync();
                using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
                cts.CancelAfter(5000);
                var result = await receiveTask.WaitAsync(cts.Token);
                var response = Encoding.UTF8.GetString(result.Buffer);

                if (response.Contains("ProbeMatches") || response.Contains("NetworkVideoTransmitter"))
                {
                    progress?.Report("  [+] ONVIF 设备发现成功");

                    var mfgMatch = Regex.Match(response, @"Manufacturer[^>]*>([^<]+)<");
                    if (mfgMatch.Success && string.IsNullOrEmpty(target.DetectedVendor))
                    {
                        target.DetectedVendor = mfgMatch.Groups[1].Value.Trim();
                    }

                    var modelMatch = Regex.Match(response, @"Model[^>]*>([^<]+)<");
                    if (modelMatch.Success)
                    {
                        target.HardwareVersion = modelMatch.Groups[1].Value.Trim();
                    }
                }
            }
            catch (OperationCanceledException) { }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "ONVIF discovery failed for {Ip}", target.IpAddress);
            }
        }

        private async Task HttpFingerprintAsync(CameraScanTarget target, CancellationToken ct)
        {
            var httpPorts = target.OpenPorts.Where(p => p is 80 or 443 or 81 or 8080 or 8443 or 8000 or 8200).ToList();
            if (!httpPorts.Any()) return;

            foreach (var port in httpPorts)
            {
                var scheme = port == 443 || port == 8443 ? "https" : "http";
                var url = $"{scheme}://{target.IpAddress}:{port}/";
                try
                {
                    using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
                    cts.CancelAfter(5000);
                    var resp = await _httpClient.GetAsync(url, cts.Token);
                    target.Port = port;
                    target.Protocol = scheme;
                    target.HttpServerHeader = resp.Headers.Server?.ToString() ?? string.Empty;

                    if (resp.Content.Headers.ContentType?.MediaType?.Contains("text/html") == true)
                    {
                        using var stream = await resp.Content.ReadAsStreamAsync(ct);
                        using var reader = new StreamReader(stream);
                        target.HttpBanner = (await reader.ReadToEndAsync()) ?? string.Empty;
                    }
                    else
                    {
                        target.HttpBanner = await resp.Content.ReadAsStringAsync(ct);
                    }

                    foreach (var fp in _fingerprints)
                    {
                        var hay = $"{target.HttpServerHeader} {target.HttpBanner}";
                        if (fp.HttpPatterns.Any(p => hay.Contains(p, StringComparison.OrdinalIgnoreCase))
                            || fp.HttpServer.Any(s => target.HttpServerHeader.Contains(s, StringComparison.OrdinalIgnoreCase)))
                        {
                            target.DetectedVendor = fp.Vendor;
                            _logger.LogInformation("Fingerprint matched: {Vendor}", fp.Vendor);
                            return;
                        }
                    }

                    if (!string.IsNullOrEmpty(target.DetectedVendor)) return;

                    var lowerBanner = target.HttpBanner.ToLowerInvariant();
                    if (lowerBanner.Contains("hikvision") || lowerBanner.Contains("hik-vision") || target.HttpServerHeader.Contains("App-webs"))
                        target.DetectedVendor = "Hikvision";
                    else if (lowerBanner.Contains("dahua") || lowerBanner.Contains("lechange") || lowerBanner.Contains("smartpss"))
                        target.DetectedVendor = "Dahua";
                    else if (lowerBanner.Contains("axis"))
                        target.DetectedVendor = "Axis";
                    else if (lowerBanner.Contains("uniview") || lowerBanner.Contains("宇视"))
                        target.DetectedVendor = "Uniview";
                    else if (lowerBanner.Contains("tp-link"))
                        target.DetectedVendor = "TP-Link";
                    else if (lowerBanner.Contains("ezviz") || lowerBanner.Contains("萤石"))
                        target.DetectedVendor = "EZVIZ";
                    else if (lowerBanner.Contains("xiongmai") || lowerBanner.Contains("xmtech"))
                        target.DetectedVendor = "Xiongmai";
                    else if (lowerBanner.Contains("vivotek"))
                        target.DetectedVendor = "Vivotek";
                    else if (lowerBanner.Contains("bosch"))
                        target.DetectedVendor = "Bosch";
                    else if (lowerBanner.Contains("hanwha") || lowerBanner.Contains("wisenet"))
                        target.DetectedVendor = "Hanwha";

                    if (!string.IsNullOrEmpty(target.DetectedVendor)) return;
                }
                catch (Exception ex) when (ex is not OperationCanceledException)
                {
                    _logger.LogDebug(ex, "HTTP probe failed on port {Port}", port);
                }
            }
        }

        private async Task FirmwareProbeAsync(CameraScanTarget target, CancellationToken ct)
        {
            if (string.IsNullOrEmpty(target.DetectedVendor) || target.Port == 0) return;

            var probes = new List<string>();
            if (target.DetectedVendor == "Hikvision")
            {
                probes.Add($"{target.Protocol}://{target.IpAddress}:{target.Port}/ISAPI/System/deviceInfo");
                probes.Add($"{target.Protocol}://{target.IpAddress}:{target.Port}/doc/page/login.asp");
                probes.Add($"{target.Protocol}://{target.IpAddress}:{target.Port}/");
            }
            else if (target.DetectedVendor == "Dahua")
            {
                probes.Add($"{target.Protocol}://{target.IpAddress}:{target.Port}/RPC2_Login");
                probes.Add($"{target.Protocol}://{target.IpAddress}:{target.Port}/");
            }
            else if (target.DetectedVendor == "Axis")
            {
                probes.Add($"{target.Protocol}://{target.IpAddress}:{target.Port}/axis-cgi/param.cgi?action=list&group=Properties");
            }
            else if (target.DetectedVendor == "Uniview")
            {
                probes.Add($"{target.Protocol}://{target.IpAddress}:{target.Port}/ISAPI/System/deviceInfo");
            }
            else
            {
                probes.Add($"{target.Protocol}://{target.IpAddress}:{target.Port}/");
            }

            foreach (var url in probes)
            {
                try
                {
                    using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
                    cts.CancelAfter(4000);
                    var resp = await _httpClient.GetAsync(url, cts.Token);
                    if (!resp.IsSuccessStatusCode && resp.StatusCode != HttpStatusCode.Unauthorized) continue;

                    var body = await resp.Content.ReadAsStringAsync(ct);
                    var versionMatch = Regex.Match(body, @"version[\""\s:=]+([\""\']?)([\d\.]+)");
                    if (versionMatch.Success)
                    {
                        target.FirmwareVersion = versionMatch.Groups[2].Value;
                    }

                    var hwMatch = Regex.Match(body, @"model[\""\s:=]+([\""\']?)([\w\-]+)");
                    if (hwMatch.Success)
                    {
                        target.HardwareVersion = hwMatch.Groups[2].Value;
                    }
                }
                catch { }
            }
        }

        private async Task VulnDetectionAsync(
            CameraScanTarget target,
            List<CameraVulnFinding> findings,
            CancellationToken ct,
            IProgress<string>? progress)
        {
            var vendor = target.DetectedVendor;

            if (vendor == "Hikvision")
            {
                progress?.Report("  → 执行海康 CVE PoC (CVE-2021-36260, CVE-2017-7921, CVE-2021-36261, CVE-2020-25078)...");
                var hikFindings = await _hikvisionPoC.RunAllAsync(target, ct);
                findings.AddRange(hikFindings);
            }
            else if (vendor == "Dahua")
            {
                progress?.Report("  → 执行大华 CVE PoC (CVE-2021-33044, CVE-2021-33045, CVE-2022-30563)...");
                var dahuaFindings = await _dahuaPoC.RunAllAsync(target, ct);
                findings.AddRange(dahuaFindings);
            }

            foreach (var vuln in _vulnerabilities.Where(v =>
                         string.Equals(v.AffectedVendor, vendor, StringComparison.OrdinalIgnoreCase) ||
                         v.AffectedVendor == "通用" || v.AffectedVendor == "多厂商"))
            {
                if (findings.Any(f => f.CveId == vuln.CveId)) continue;

                progress?.Report($"  → 匹配漏洞库: {vuln.Name} ({vuln.CveId})...");

                var confirmed = await GenericPoCAsync(target, vuln, ct);
                if (confirmed)
                {
                    findings.Add(new CameraVulnFinding
                    {
                        CveId = vuln.CveId,
                        Name = vuln.Name,
                        Description = vuln.Description,
                        Severity = vuln.Severity,
                        CvssScore = vuln.CvssScore,
                        Vendor = vuln.AffectedVendor,
                        Confirmed = true,
                        DetectionMethod = "GenericPoC",
                        Evidence = $"PoC verification succeeded for {vuln.CveId}",
                        Remedy = vuln.Solution
                    });
                    progress?.Report($"  [!] 确认漏洞: {vuln.CveId}");
                }
            }
        }

        private async Task<bool> GenericPoCAsync(CameraScanTarget target, CameraVulnerability vuln, CancellationToken ct)
        {
            if (target.Port == 0) return false;
            if (!vuln.PoCEndpoints.Any() || string.IsNullOrEmpty(vuln.VerificationPattern)) return false;

            foreach (var endpoint in vuln.PoCEndpoints)
            {
                var url = $"{target.Protocol}://{target.IpAddress}:{target.Port}{endpoint}";
                try
                {
                    using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
                    cts.CancelAfter(5000);

                    HttpResponseMessage resp;
                    if (vuln.PoCMethod.Equals("POST", StringComparison.OrdinalIgnoreCase) && !string.IsNullOrEmpty(vuln.PoCPayload))
                    {
                        var content = new StringContent(vuln.PoCPayload, Encoding.UTF8, "application/xml");
                        resp = await _httpClient.PostAsync(url, content, cts.Token);
                    }
                    else
                    {
                        resp = await _httpClient.GetAsync(url, cts.Token);
                    }

                    if (!resp.IsSuccessStatusCode && resp.StatusCode != HttpStatusCode.Unauthorized && resp.StatusCode != HttpStatusCode.Forbidden)
                        continue;

                    var body = await resp.Content.ReadAsStringAsync(ct);
                    if (body.Contains(vuln.VerificationPattern, StringComparison.OrdinalIgnoreCase))
                        return true;
                }
                catch { }
            }
            return false;
        }

        private async Task RtspAuthCheckAsync(
            CameraScanTarget target,
            List<CameraVulnFinding> findings,
            CancellationToken ct,
            IProgress<string>? progress)
        {
            if (!target.OpenPorts.Contains(554)) return;

            progress?.Report("  → 检测 RTSP 认证状态...");
            try
            {
                using var tcp = new TcpClient();
                using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
                cts.CancelAfter(5000);
                await tcp.ConnectAsync(target.IpAddress, 554).WaitAsync(cts.Token);

                using var stream = tcp.GetStream();
                var probeUri = $"rtsp://{target.IpAddress}:554/stream1";
                var request = $"DESCRIBE {probeUri} RTSP/1.0\r\nCSeq: 1\r\nAccept: application/sdp\r\n\r\n";
                var data = Encoding.ASCII.GetBytes(request);
                await stream.WriteAsync(data, ct);

                var buffer = new byte[4096];
                var read = await stream.ReadAsync(buffer, ct);
                var response = Encoding.ASCII.GetString(buffer, 0, read);

                if (response.Contains("200 OK") || (response.Contains("454") == false && response.Contains("401") == false && response.StartsWith("RTSP/1.0")))
                {
                    findings.Add(new CameraVulnFinding
                    {
                        CveId = "RTSP-ANON-001",
                        Name = "RTSP 未授权访问",
                        Severity = "High",
                        CvssScore = 7.5,
                        Vendor = target.DetectedVendor,
                        Confirmed = true,
                        Evidence = $"RTSP DESCRIBE 返回 200 OK，无需认证即可获取视频流: {probeUri}",
                        DetectionMethod = "RTSPProbe",
                        Remedy = "启用 RTSP 认证，设置强密码；如需公网访问请使用 VPN"
                    });
                    progress?.Report("  [!] RTSP 未授权访问确认");
                }
                else if (response.Contains("401"))
                {
                    progress?.Report("  [+] RTSP 已启用认证 (401)");
                }
            }
            catch (OperationCanceledException) { }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "RTSP auth check failed for {Ip}", target.IpAddress);
            }
        }

        private async Task WeakPasswordScanAsync(
            CameraScanTarget target,
            List<CameraVulnFinding> findings,
            CancellationToken ct,
            IProgress<string>? progress)
        {
            var entries = _weakPasswords.Where(w =>
                string.Equals(w.Vendor, target.DetectedVendor, StringComparison.OrdinalIgnoreCase) ||
                w.Vendor == "通用").ToList();

            if (!entries.Any()) return;

            progress?.Report($"  → 弱口令爆破（{entries.Count} 组字典）...");
            int attempts = 0, confirmed = 0;

            foreach (var entry in entries)
            {
                foreach (var user in entry.Usernames)
                {
                    foreach (var pwd in entry.Passwords)
                    {
                        if (ct.IsCancellationRequested) return;
                        attempts++;
                        if (attempts > MaxBruteForceAttempts)
                        {
                            progress?.Report($"  [!] 超过最大尝试次数 {MaxBruteForceAttempts}，停止爆破");
                            goto DONE;
                        }

                        try
                        {
                            var success = false;
                            string evidence = string.Empty;

                            if (target.DetectedVendor == "Hikvision")
                            {
                                (success, evidence) = await TryHikvisionLoginAsync(target, user, pwd, ct);
                            }
                            else if (target.DetectedVendor == "Dahua")
                            {
                                (success, evidence) = await TryDahuaLoginAsync(target, user, pwd, ct);
                            }
                            else
                            {
                                (success, evidence) = await TryGenericHttpAuthAsync(target, user, pwd, ct);
                            }

                            if (success)
                            {
                                confirmed++;
                                findings.Add(new CameraVulnFinding
                                {
                                    CveId = $"WP-{confirmed}",
                                    Name = "弱口令",
                                    Severity = "Critical",
                                    CvssScore = 9.8,
                                    Vendor = target.DetectedVendor,
                                    Confirmed = true,
                                    Evidence = evidence,
                                    DetectionMethod = "BruteForce",
                                    Remedy = "立即修改默认口令为 12 位以上强密码（大小写+数字+特殊字符）"
                                });
                                progress?.Report($"  [!] 发现弱口令: {user}/{pwd}");
                            }
                        }
                        catch (OperationCanceledException) { throw; }
                        catch { }
                    }
                }
            }
        DONE:
            progress?.Report($"  → 弱口令尝试: {attempts} 次, 发现: {confirmed} 个");
        }

        private async Task<(bool success, string evidence)> TryHikvisionLoginAsync(
            CameraScanTarget target, string user, string pwd, CancellationToken ct)
        {
            var loginUrl = $"{target.Protocol}://{target.IpAddress}:{target.Port}/ISAPI/Security/users/login";
            using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
            cts.CancelAfter(3000);

            var auth = Convert.ToBase64String(Encoding.UTF8.GetBytes($"{user}:{pwd}"));
            using var request = new HttpRequestMessage(HttpMethod.Get, loginUrl);
            request.Headers.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Basic", auth);

            var resp = await _httpClient.SendAsync(request, cts.Token);
            if (resp.IsSuccessStatusCode)
            {
                return (true, $"Hikvision Basic 认证成功 - 用户名: {user}, 密码: {pwd}");
            }
            return (false, string.Empty);
        }

        private async Task<(bool success, string evidence)> TryDahuaLoginAsync(
            CameraScanTarget target, string user, string pwd, CancellationToken ct)
        {
            var loginUrl = $"{target.Protocol}://{target.IpAddress}:{target.Port}/RPC2_Login";
            using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
            cts.CancelAfter(3000);

            var payload = $"{{\"method\":\"global.login\",\"params\":{{\"authorityType\":0,\"passwordType\":\"Plain\",\"userName\":\"{user}\",\"password\":\"{pwd}\"}},\"id\":1}}";
            var content = new StringContent(payload, Encoding.UTF8, "application/json");
            var resp = await _httpClient.PostAsync(loginUrl, content, cts.Token);
            var body = await resp.Content.ReadAsStringAsync(ct);

            if (body.Contains("\"result\":0") || body.Contains("session"))
            {
                return (true, $"Dahua RPC2 登录成功 - 用户名: {user}, 密码: {pwd}");
            }
            return (false, string.Empty);
        }

        private async Task<(bool success, string evidence)> TryGenericHttpAuthAsync(
            CameraScanTarget target, string user, string pwd, CancellationToken ct)
        {
            var loginUrl = $"{target.Protocol}://{target.IpAddress}:{target.Port}/";
            using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
            cts.CancelAfter(3000);

            var auth = Convert.ToBase64String(Encoding.UTF8.GetBytes($"{user}:{pwd}"));
            using var request = new HttpRequestMessage(HttpMethod.Get, loginUrl);
            request.Headers.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Basic", auth);

            var resp = await _httpClient.SendAsync(request, cts.Token);
            if (resp.IsSuccessStatusCode)
            {
                var body = await resp.Content.ReadAsStringAsync(ct);
                if (body.Contains("login", StringComparison.OrdinalIgnoreCase) == false &&
                    body.Length > 200)
                {
                    return (true, $"HTTP Basic 认证成功 - 用户名: {user}, 密码: {pwd}");
                }
            }
            return (false, string.Empty);
        }

        public void Dispose()
        {
            _httpClient.Dispose();
        }
    }
}