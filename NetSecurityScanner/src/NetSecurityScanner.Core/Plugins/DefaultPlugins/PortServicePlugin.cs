using NetSecurityScanner.Models;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Sockets;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace NetSecurityScanner.Plugins.DefaultPlugins
{
    /// <summary>
    /// 端口服务识别插件
    /// </summary>
    [PluginMetadata(
        PluginId = "builtin.portservice",
        Name = "端口服务识别",
        Version = "1.0.0",
        Description = "智能识别开放端口上运行的服务类型和版本信息",
        Author = "NetSecurityScanner",
        SupportedScanTypes = new[] { "HTTP", "HTTPS", "SMTP", "DNS", "SNMP" }
    )]
    public class PortServicePlugin : IVulnerabilityScannerPlugin
    {
        public string PluginId => "builtin.portservice";
        public string Name => "端口服务识别";
        public string Version => "1.0.0";
        public string Description => "智能识别开放端口上运行的服务类型和版本信息";
        public string Author => "NetSecurityScanner";
        public List<string> SupportedScanTypes => new List<string> { "HTTP", "HTTPS", "SMTP", "DNS", "SNMP" };

        public List<PluginConfigParameter> ConfigParameters => new List<PluginConfigParameter>
        {
            new PluginConfigParameter
            {
                Name = "Timeout",
                DisplayName = "超时时间(ms)",
                Description = "连接超时时间",
                Type = PluginConfigType.Integer,
                DefaultValue = 5000,
                IsRequired = false
            },
            new PluginConfigParameter
            {
                Name = "EnableBannerGrab",
                DisplayName = "启用Banner抓取",
                Description = "是否抓取服务Banner信息",
                Type = PluginConfigType.Boolean,
                DefaultValue = true,
                IsRequired = false
            },
            new PluginConfigParameter
            {
                Name = "MaxRetries",
                DisplayName = "最大重试次数",
                Description = "服务识别失败后的最大重试次数",
                Type = PluginConfigType.Integer,
                DefaultValue = 2,
                IsRequired = false
            }
        };

        private int _timeout = 5000;
        private bool _enableBannerGrab = true;
        private int _maxRetries = 2;
        private bool _isInitialized = false;
        private bool _isRunning = false;
        private int _scanCount = 0;
        private int _vulnerabilityFound = 0;
        private DateTime? _lastScanTime = null;

        public Task<bool> InitializeAsync(Dictionary<string, object> config)
        {
            if (config.TryGetValue("Timeout", out var timeout))
            {
                _timeout = Convert.ToInt32(timeout);
            }
            if (config.TryGetValue("EnableBannerGrab", out var enableBannerGrab))
            {
                _enableBannerGrab = Convert.ToBoolean(enableBannerGrab);
            }
            if (config.TryGetValue("MaxRetries", out var maxRetries))
            {
                _maxRetries = Convert.ToInt32(maxRetries);
            }

            _isInitialized = true;
            return Task.FromResult(true);
        }

        public async Task<bool> CanScanAsync(string target, int port)
        {
            var supportedPorts = new[] { 21, 22, 23, 25, 53, 80, 110, 143, 161, 443, 993, 995, 3306, 5432, 6379, 8080, 8443, 9090 };
            await Task.CompletedTask;
            return Array.Exists(supportedPorts, p => p == port);
        }

        public async Task<List<VulnerabilityResult>> ScanAsync(ScanContext context, CancellationToken cancellationToken = default)
        {
            var results = new List<VulnerabilityResult>();

            if (!_isInitialized)
            {
                return results;
            }

            _isRunning = true;
            try
            {
                using var client = new TcpClient();
                var connectTask = client.ConnectAsync(context.Target, context.Port);
                var timeoutTask = Task.Delay(context.Timeout);

                if (await Task.WhenAny(connectTask, timeoutTask) == timeoutTask)
                {
                    return results;
                }

                using var stream = client.GetStream();
                stream.ReadTimeout = 5000;
                stream.WriteTimeout = 5000;

                string banner = "";
                if (context.Port == 80 || context.Port == 8080 || context.Port == 443)
                {
                    var request = Encoding.ASCII.GetBytes($"HEAD / HTTP/1.1\r\nHost: {context.Target}\r\nConnection: close\r\n\r\n");
                    await stream.WriteAsync(request, 0, request.Length, cancellationToken);
                }

                var buffer = new byte[4096];
                var readTask = stream.ReadAsync(buffer, 0, buffer.Length, cancellationToken);
                var readTimeout = Task.Delay(5000);

                if (await Task.WhenAny(readTask, readTimeout) == readTimeout)
                {
                    return results;
                }

                int bytesRead = await readTask;
                banner = Encoding.ASCII.GetString(buffer, 0, bytesRead);

                if (!string.IsNullOrEmpty(banner))
                {
                    string serviceInfo = ExtractServiceInfo(banner);
                    results.Add(new VulnerabilityResult
                    {
                        Name = $"端口 {context.Port} 服务识别",
                        Description = $"检测到服务信息：{serviceInfo}\nBanner: {banner.Substring(0, Math.Min(banner.Length, 200))}",
                        RiskLevel = "信息",
                        Port = context.Port,
                        PluginId = PluginId,
                        PluginName = Name
                    });

                    if (banner.Contains("Apache/") && banner.Contains("2.4."))
                    {
                        results.Add(new VulnerabilityResult
                        {
                            Name = "Apache 版本信息泄露",
                            Description = $"Apache 服务器版本信息在 Banner 中暴露：{serviceInfo}",
                            RiskLevel = "低",
                            Port = context.Port,
                            PluginId = PluginId,
                            PluginName = Name
                        });
                    }

                    if (banner.Contains("Server: "))
                    {
                        var serverLine = banner.Split('\n').FirstOrDefault(l => l.StartsWith("Server:"));
                        if (serverLine != null && serverLine.Contains("Microsoft-IIS"))
                        {
                            results.Add(new VulnerabilityResult
                            {
                                Name = "IIS 版本信息泄露",
                                Description = $"IIS 服务器版本信息暴露：{serverLine.Trim()}",
                                RiskLevel = "低",
                                Port = context.Port,
                                PluginId = PluginId,
                                PluginName = Name
                            });
                        }
                    }
                }
            }
            catch { }
            finally
            {
                _scanCount++;
                _vulnerabilityFound += results.Count;
                _lastScanTime = DateTime.Now;
                _isRunning = false;
            }

            return results;
        }

        private string ExtractServiceInfo(string banner)
        {
            var lines = banner.Split('\n');
            foreach (var line in lines)
            {
                if (line.StartsWith("Server:", StringComparison.OrdinalIgnoreCase))
                    return line.Trim();
            }
            if (banner.StartsWith("SSH-"))
                return banner.Split('\n')[0].Trim();
            if (banner.StartsWith("220 ") || banner.StartsWith("230 "))
                return "FTP Service";
            if (banner.StartsWith("+OK"))
                return "POP3 Service";
            if (banner.StartsWith("220") && banner.Contains("SMTP"))
                return "SMTP Service";
            return banner.Split('\n')[0].Trim();
        }

        public PluginRuntimeStatus GetStatus()
        {
            return new PluginRuntimeStatus
            {
                IsInitialized = _isInitialized,
                IsRunning = _isRunning,
                ScanCount = _scanCount,
                VulnerabilityFound = _vulnerabilityFound,
                LastScanTime = _lastScanTime,
                Message = _isInitialized ? "已初始化" : "未初始化"
            };
        }

        public Task UnloadAsync()
        {
            _isInitialized = false;
            return Task.CompletedTask;
        }
    }
}
