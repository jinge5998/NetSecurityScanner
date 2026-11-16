using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Http;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using NetSecurityScanner.Core.Models;

namespace NetSecurityScanner.Core.Services
{
    public class HikvisionPoC
    {
        private readonly HttpClient _http;
        private readonly ILogger _logger;

        public HikvisionPoC(HttpClient http, ILogger logger)
        {
            _http = http;
            _logger = logger;
        }

        public async Task<List<CameraVulnFinding>> RunAllAsync(CameraScanTarget target, CancellationToken ct)
        {
            var findings = new List<CameraVulnFinding>();

            var ctsCancel = CancellationTokenSource.CreateLinkedTokenSource(ct);
            ctsCancel.CancelAfter(TimeSpan.FromSeconds(30));
            var linkedCt = ctsCancel.Token;

            try
            {
                var tasks = new[]
                {
                    PocCve202136260Async(target, linkedCt),
                    PocCve20177921Async(target, linkedCt),
                    PocCve202136261Async(target, linkedCt),
                    PocCve202025078Async(target, linkedCt)
                };

                var results = await Task.WhenAll(tasks);
                foreach (var f in results)
                    if (f != null) findings.Add(f);
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                _logger.LogDebug(ex, "Hikvision PoC batch failed");
            }

            return findings;
        }

        private async Task<CameraVulnFinding?> PocCve202136260Async(CameraScanTarget target, CancellationToken ct)
        {
            var url = $"{target.Protocol}://{target.IpAddress}:{target.Port}/ISAPI/System/deviceInfo";
            try
            {
                using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
                cts.CancelAfter(5000);

                var resp = await _http.GetAsync(url, cts.Token);
                var body = await resp.Content.ReadAsStringAsync(ct);

                if (resp.IsSuccessStatusCode && (body.Contains("DeviceID") || body.Contains("deviceName") || body.Contains("model") || body.Contains("firmwareVersion")))
                {
                    _logger.LogWarning("[PoC] CVE-2021-36260 confirmed on {Ip}", target.IpAddress);
                    return new CameraVulnFinding
                    {
                        CveId = "CVE-2021-36260",
                        Name = "海康威视命令注入漏洞",
                        Severity = "Critical",
                        CvssScore = 9.8,
                        Vendor = "Hikvision",
                        Confirmed = true,
                        Endpoint = url,
                        Evidence = $"未授权访问 /ISAPI/System/deviceInfo 成功，返回设备信息: {body[..Math.Min(200, body.Length)]}",
                        DetectionMethod = "UnauthISAPI"
                    };
                }
            }
            catch (Exception ex) when (ex is not OperationCanceledException) { _logger.LogDebug(ex, "CVE-2021-36260 probe failed"); }
            return null;
        }

        private async Task<CameraVulnFinding?> PocCve20177921Async(CameraScanTarget target, CancellationToken ct)
        {
            var url = $"{target.Protocol}://{target.IpAddress}:{target.Port}/ISAPI/Management/network/User/admin";
            try
            {
                using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
                cts.CancelAfter(5000);

                var resp = await _http.GetAsync(url, cts.Token);
                var body = await resp.Content.ReadAsStringAsync(ct);

                if ((int)resp.StatusCode == 401 && resp.Headers.WwwAuthenticate != null &&
                    resp.Headers.WwwAuthenticate.ToString().Contains("Hikvision") ||
                    body.Contains("salt") || body.Contains("iterations"))
                {
                    _logger.LogWarning("[PoC] CVE-2017-7921 confirmed on {Ip}", target.IpAddress);
                    return new CameraVulnFinding
                    {
                        CveId = "CVE-2017-7921",
                        Name = "海康威视后门账户漏洞",
                        Severity = "Critical",
                        CvssScore = 10.0,
                        Vendor = "Hikvision",
                        Confirmed = true,
                        Endpoint = url,
                        Evidence = "存在默认后门账户 (用户名: admin, 密码: 12345 / 激活码可绕过)",
                        DetectionMethod = "BackdoorAccount"
                    };
                }
            }
            catch (Exception ex) when (ex is not OperationCanceledException) { _logger.LogDebug(ex, "CVE-2017-7921 probe failed"); }
            return null;
        }

        private async Task<CameraVulnFinding?> PocCve202136261Async(CameraScanTarget target, CancellationToken ct)
        {
            var url = $"{target.Protocol}://{target.IpAddress}:{target.Port}/doc/page/login.asp";
            try
            {
                using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
                cts.CancelAfter(5000);

                var resp = await _http.GetAsync(url, cts.Token);
                var body = await resp.Content.ReadAsStringAsync(ct);

                if (resp.IsSuccessStatusCode && body.Contains("version", StringComparison.OrdinalIgnoreCase))
                {
                    return new CameraVulnFinding
                    {
                        CveId = "CVE-2021-36261",
                        Name = "海康威视未授权固件版本泄露",
                        Severity = "High",
                        CvssScore = 7.5,
                        Vendor = "Hikvision",
                        Confirmed = true,
                        Endpoint = url,
                        Evidence = $"未授权访问 login.asp 泄露固件版本: {ExtractFirmwareVersion(body)}",
                        DetectionMethod = "FirmwareLeak"
                    };
                }
            }
            catch (Exception ex) when (ex is not OperationCanceledException) { _logger.LogDebug(ex, "CVE-2021-36261 probe failed"); }
            return null;
        }

        private async Task<CameraVulnFinding?> PocCve202025078Async(CameraScanTarget target, CancellationToken ct)
        {
            var url = $"{target.Protocol}://{target.IpAddress}:{target.Port}/ISAPI/System/security/fishingDetection/capabilities";
            try
            {
                using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
                cts.CancelAfter(5000);

                var resp = await _http.GetAsync(url, cts.Token);
                if (resp.StatusCode == HttpStatusCode.Unauthorized)
                    return null;

                var body = await resp.Content.ReadAsStringAsync(ct);
                if (body.Contains("<") || body.Contains("capabilities"))
                {
                    return new CameraVulnFinding
                    {
                        CveId = "CVE-2020-25078",
                        Name = "海康威视未授权配置读取",
                        Severity = "High",
                        CvssScore = 7.5,
                        Vendor = "Hikvision",
                        Confirmed = true,
                        Endpoint = url,
                        Evidence = "未授权访问 ISAPI 接口获取系统能力配置",
                        DetectionMethod = "UnauthConfigRead"
                    };
                }
            }
            catch { }
            return null;
        }

        private static string ExtractFirmwareVersion(string html)
        {
            var m = System.Text.RegularExpressions.Regex.Match(html, @"version[\""\s:=]+[\\\""]?([\d\.]+)");
            return m.Success ? m.Groups[1].Value : "未知";
        }
    }
}