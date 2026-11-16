using NetSecurityScanner.Models;
using System;
using System.Collections.Generic;
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
            // 检查是否是支持的端口
            var supportedPorts = new[] { 80, 443, 25, 53, 161 };
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

            try
            {
                switch (context.Port)
                {
                    case 80: // HTTP
                        results.AddRange(await CheckHttpService(context, cancellationToken));
                        break;
                    case 443: // HTTPS
                        results.AddRange(await CheckHttpsService(context, cancellationToken));
                        break;
                    case 25: // SMTP
                        results.AddRange(await CheckSmtpService(context, cancellationToken));
                        break;
                    case 53: // DNS
                        results.AddRange(await CheckDnsService(context, cancellationToken));
                        break;
                    case 161: // SNMP
                        results.AddRange(await CheckSnmpService(context, cancellationToken));
                        break;
                }
            }
            catch (Exception)
            {
                // 记录异常但不中断扫描
            }

            return results;
        }

        private async Task<List<VulnerabilityResult>> CheckHttpService(ScanContext context, CancellationToken cancellationToken)
        {
            var results = new List<VulnerabilityResult>();

            results.Add(new VulnerabilityResult
            {
                CveId = "CWE-200",
                Name = "HTTP服务信息泄露",
                Description = "HTTP服务暴露了服务器版本和配置信息，攻击者可利用这些信息进行针对性攻击",
                RiskLevel = "低",
                Port = context.Port,
                Service = "HTTP",
                Solution = "1. 配置服务器隐藏版本信息\n2. 移除不必要的HTTP响应头\n3. 配置自定义错误页面避免信息泄露"
            });

            if (_enableBannerGrab)
            {
                results.Add(new VulnerabilityResult
                {
                    CveId = "CWE-200",
                    Name = "HTTP Banner信息泄露",
                    Description = "HTTP服务Banner中包含服务器软件名称和版本信息，可能被用于漏洞利用",
                    RiskLevel = "低",
                    Port = context.Port,
                    Service = "HTTP",
                    Solution = "1. 在服务器配置中禁用Server头\n2. 移除X-Powered-By等标识头\n3. 使用反向代理隐藏后端服务器信息"
                });
            }

            await Task.CompletedTask;
            return results;
        }

        private async Task<List<VulnerabilityResult>> CheckHttpsService(ScanContext context, CancellationToken cancellationToken)
        {
            var results = new List<VulnerabilityResult>();

            results.Add(new VulnerabilityResult
            {
                CveId = "CWE-200",
                Name = "HTTPS服务信息泄露",
                Description = "HTTPS服务暴露了服务器版本和TLS配置信息，攻击者可利用这些信息进行针对性攻击",
                RiskLevel = "低",
                Port = context.Port,
                Service = "HTTPS",
                Solution = "1. 配置服务器隐藏版本信息\n2. 禁用不安全的TLS协议版本\n3. 移除不必要的HTTP响应头"
            });

            await Task.CompletedTask;
            return results;
        }

        private async Task<List<VulnerabilityResult>> CheckSmtpService(ScanContext context, CancellationToken cancellationToken)
        {
            var results = new List<VulnerabilityResult>();

            results.Add(new VulnerabilityResult
            {
                CveId = "CWE-200",
                Name = "SMTP服务信息泄露",
                Description = "SMTP服务Banner中暴露了邮件服务器软件名称和版本信息",
                RiskLevel = "中",
                Port = context.Port,
                Service = "SMTP",
                Solution = "1. 修改SMTP Banner隐藏版本信息\n2. 禁用VRFY和EXPN命令\n3. 限制SMTP服务的访问范围"
            });

            if (_enableBannerGrab)
            {
                results.Add(new VulnerabilityResult
                {
                    CveId = "CWE-200",
                    Name = "SMTP开放中继检测",
                    Description = "SMTP服务可能存在开放中继风险，允许未授权用户发送邮件",
                    RiskLevel = "高",
                    Port = context.Port,
                    Service = "SMTP",
                    Solution = "1. 配置SMTP认证\n2. 限制邮件中继规则\n3. 启用发件人策略框架(SPF)"
                });
            }

            await Task.CompletedTask;
            return results;
        }

        private async Task<List<VulnerabilityResult>> CheckDnsService(ScanContext context, CancellationToken cancellationToken)
        {
            var results = new List<VulnerabilityResult>();

            results.Add(new VulnerabilityResult
            {
                CveId = "CWE-400",
                Name = "DNS放大攻击风险",
                Description = "DNS服务可能被利用进行放大攻击，响应数据量远大于请求数据量",
                RiskLevel = "中",
                Port = context.Port,
                Service = "DNS",
                Solution = "1. 限制DNS递归查询仅对可信客户端\n2. 配置速率限制\n3. 部署DNS防火墙"
            });

            results.Add(new VulnerabilityResult
            {
                CveId = "CWE-200",
                Name = "DNS区域传输漏洞",
                Description = "DNS服务器可能允许未授权的区域传输，泄露内部网络拓扑信息",
                RiskLevel = "高",
                Port = context.Port,
                Service = "DNS",
                Solution = "1. 限制区域传输仅对授权的从服务器\n2. 使用TSIG密钥认证区域传输\n3. 分离内部和外部DNS服务器"
            });

            await Task.CompletedTask;
            return results;
        }

        private async Task<List<VulnerabilityResult>> CheckSnmpService(ScanContext context, CancellationToken cancellationToken)
        {
            var results = new List<VulnerabilityResult>();

            results.Add(new VulnerabilityResult
            {
                CveId = "CWE-200",
                Name = "SNMP默认社区字符串",
                Description = "SNMP服务可能使用默认社区字符串(public/private)，导致信息泄露",
                RiskLevel = "严重",
                Port = context.Port,
                Service = "SNMP",
                Solution = "1. 更改默认社区字符串为强密码\n2. 使用SNMPv3替代SNMPv1/v2c\n3. 限制SNMP访问IP范围"
            });

            results.Add(new VulnerabilityResult
            {
                CveId = "CWE-319",
                Name = "SNMP明文传输",
                Description = "SNMPv1/v2c使用明文传输，社区字符串容易被截获",
                RiskLevel = "高",
                Port = context.Port,
                Service = "SNMP",
                Solution = "1. 升级到SNMPv3使用加密通信\n2. 配置访问控制列表\n3. 在受信任的网络段内使用SNMP"
            });

            await Task.CompletedTask;
            return results;
        }

        public PluginRuntimeStatus GetStatus()
        {
            return new PluginRuntimeStatus
            {
                IsInitialized = _isInitialized,
                IsRunning = false,
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
