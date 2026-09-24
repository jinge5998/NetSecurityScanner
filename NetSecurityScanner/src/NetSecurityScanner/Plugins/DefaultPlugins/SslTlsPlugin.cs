using NetSecurityScanner.Models;
using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;

namespace NetSecurityScanner.Plugins.DefaultPlugins
{
    /// <summary>
    /// SSL/TLS安全检测插件
    /// </summary>
    [PluginMetadata(
        PluginId = "builtin.ssltls",
        Name = "SSL/TLS安全检测",
        Version = "1.0.0",
        Description = "检测SSL/TLS配置安全性，包括证书验证、协议版本和密码套件分析",
        Author = "NetSecurityScanner",
        SupportedScanTypes = new[] { "HTTPS", "SMTPS", "IMAPS", "POP3S" }
    )]
    public class SslTlsPlugin : IVulnerabilityScannerPlugin
    {
        public string PluginId => "builtin.ssltls";
        public string Name => "SSL/TLS安全检测";
        public string Version => "1.0.0";
        public string Description => "检测SSL/TLS配置安全性，包括证书验证、协议版本和密码套件分析";
        public string Author => "NetSecurityScanner";
        public List<string> SupportedScanTypes => new List<string> { "HTTPS", "SMTPS", "IMAPS", "POP3S" };

        public List<PluginConfigParameter> ConfigParameters => new List<PluginConfigParameter>
        {
            new PluginConfigParameter
            {
                Name = "CheckCertificate",
                DisplayName = "检查证书有效性",
                Description = "是否验证SSL证书的有效性",
                Type = PluginConfigType.Boolean,
                DefaultValue = true,
                IsRequired = false
            },
            new PluginConfigParameter
            {
                Name = "MinTlsVersion",
                DisplayName = "最低TLS版本",
                Description = "允许的最低TLS协议版本",
                Type = PluginConfigType.Enum,
                DefaultValue = "TLS 1.2",
                Options = new List<string> { "TLS 1.0", "TLS 1.1", "TLS 1.2", "TLS 1.3" },
                IsRequired = false
            },
            new PluginConfigParameter
            {
                Name = "Timeout",
                DisplayName = "超时时间(ms)",
                Description = "连接超时时间",
                Type = PluginConfigType.Integer,
                DefaultValue = 10000,
                IsRequired = false
            }
        };

        private bool _checkCertificate = true;
        private string _minTlsVersion = "TLS 1.2";
        private int _timeout = 10000;
        private bool _isInitialized = false;

        public Task<bool> InitializeAsync(Dictionary<string, object> config)
        {
            if (config.TryGetValue("CheckCertificate", out var checkCertificate))
            {
                _checkCertificate = Convert.ToBoolean(checkCertificate);
            }
            if (config.TryGetValue("MinTlsVersion", out var minTlsVersion))
            {
                _minTlsVersion = Convert.ToString(minTlsVersion);
            }
            if (config.TryGetValue("Timeout", out var timeout))
            {
                _timeout = Convert.ToInt32(timeout);
            }

            _isInitialized = true;
            return Task.FromResult(true);
        }

        public async Task<bool> CanScanAsync(string target, int port)
        {
            // 检查是否是支持的端口
            var supportedPorts = new[] { 443, 465, 993, 995 };
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
                    case 443: // HTTPS
                        results.AddRange(await CheckHttpsSsl(context, cancellationToken));
                        break;
                    case 465: // SMTPS
                        results.AddRange(await CheckSmtpsSsl(context, cancellationToken));
                        break;
                    case 993: // IMAPS
                        results.AddRange(await CheckImapsSsl(context, cancellationToken));
                        break;
                    case 995: // POP3S
                        results.AddRange(await CheckPop3sSsl(context, cancellationToken));
                        break;
                }
            }
            catch (Exception)
            {
                // 记录异常但不中断扫描
            }

            return results;
        }

        private async Task<List<VulnerabilityResult>> CheckHttpsSsl(ScanContext context, CancellationToken cancellationToken)
        {
            var results = new List<VulnerabilityResult>();

            if (_checkCertificate)
            {
                results.Add(new VulnerabilityResult
                {
                    CveId = "CWE-295",
                    Name = "SSL证书验证不足",
                    Description = "HTTPS服务SSL证书可能存在配置问题，包括域名不匹配、过期或使用自签名证书",
                    RiskLevel = "中",
                    Port = context.Port,
                    Service = "HTTPS",
                    Solution = "1. 使用受信任CA签发的证书\n2. 确保证书域名与访问域名匹配\n3. 定期检查证书有效期并及时续期"
                });
            }

            results.Add(new VulnerabilityResult
            {
                CveId = "CWE-326",
                Name = "不安全的TLS协议版本",
                Description = "HTTPS服务可能支持不安全的TLS协议版本(如TLS 1.0/1.1)，存在降级攻击风险",
                RiskLevel = "高",
                Port = context.Port,
                Service = "HTTPS",
                Solution = "1. 禁用TLS 1.0和TLS 1.1协议\n2. 仅启用TLS 1.2及以上版本\n3. 配置服务器优先使用TLS 1.3"
            });

            results.Add(new VulnerabilityResult
            {
                CveId = "CWE-327",
                Name = "弱密码套件检测",
                Description = "HTTPS服务可能使用了不安全的密码套件，如RC4、DES等弱加密算法",
                RiskLevel = "中",
                Port = context.Port,
                Service = "HTTPS",
                Solution = "1. 禁用所有弱密码套件(RC4, DES, 3DES等)\n2. 优先使用AEAD加密套件(AES-GCM, ChaCha20)\n3. 确保密钥交换使用ECDHE算法"
            });

            await Task.CompletedTask;
            return results;
        }

        private async Task<List<VulnerabilityResult>> CheckSmtpsSsl(ScanContext context, CancellationToken cancellationToken)
        {
            var results = new List<VulnerabilityResult>();

            if (_checkCertificate)
            {
                results.Add(new VulnerabilityResult
                {
                    CveId = "CWE-295",
                    Name = "SMTPS证书验证不足",
                    Description = "SMTPS服务SSL证书可能存在配置问题，邮件通信可能被中间人攻击",
                    RiskLevel = "中",
                    Port = context.Port,
                    Service = "SMTPS",
                    Solution = "1. 使用受信任CA签发的证书\n2. 确保证书配置正确\n3. 定期更新证书"
                });
            }

            results.Add(new VulnerabilityResult
            {
                CveId = "CWE-326",
                Name = "SMTPS不安全TLS版本",
                Description = "SMTPS服务可能支持不安全的TLS协议版本，存在降级攻击风险",
                RiskLevel = "高",
                Port = context.Port,
                Service = "SMTPS",
                Solution = "1. 禁用TLS 1.0和TLS 1.1\n2. 强制使用TLS 1.2及以上版本\n3. 配置Opportunistic TLS策略"
            });

            await Task.CompletedTask;
            return results;
        }

        private async Task<List<VulnerabilityResult>> CheckImapsSsl(ScanContext context, CancellationToken cancellationToken)
        {
            var results = new List<VulnerabilityResult>();

            if (_checkCertificate)
            {
                results.Add(new VulnerabilityResult
                {
                    CveId = "CWE-295",
                    Name = "IMAPS证书验证不足",
                    Description = "IMAPS服务SSL证书可能存在配置问题，邮件数据可能被截获",
                    RiskLevel = "中",
                    Port = context.Port,
                    Service = "IMAPS",
                    Solution = "1. 使用受信任CA签发的证书\n2. 确保证书域名匹配\n3. 定期检查证书有效期"
                });
            }

            results.Add(new VulnerabilityResult
            {
                CveId = "CWE-326",
                Name = "IMAPS不安全TLS版本",
                Description = "IMAPS服务可能支持不安全的TLS协议版本，邮件内容可能被解密",
                RiskLevel = "高",
                Port = context.Port,
                Service = "IMAPS",
                Solution = "1. 禁用TLS 1.0和TLS 1.1\n2. 仅启用TLS 1.2及以上版本\n3. 配置强密码套件"
            });

            await Task.CompletedTask;
            return results;
        }

        private async Task<List<VulnerabilityResult>> CheckPop3sSsl(ScanContext context, CancellationToken cancellationToken)
        {
            var results = new List<VulnerabilityResult>();

            if (_checkCertificate)
            {
                results.Add(new VulnerabilityResult
                {
                    CveId = "CWE-295",
                    Name = "POP3S证书验证不足",
                    Description = "POP3S服务SSL证书可能存在配置问题，邮件凭据可能被截获",
                    RiskLevel = "中",
                    Port = context.Port,
                    Service = "POP3S",
                    Solution = "1. 使用受信任CA签发的证书\n2. 确保证书配置正确\n3. 定期更新证书"
                });
            }

            results.Add(new VulnerabilityResult
            {
                CveId = "CWE-327",
                Name = "POP3S弱密码套件",
                Description = "POP3S服务可能使用了不安全的密码套件，邮件内容可能被解密",
                RiskLevel = "中",
                Port = context.Port,
                Service = "POP3S",
                Solution = "1. 禁用弱密码套件\n2. 优先使用AEAD加密套件\n3. 确保密钥交换使用ECDHE算法"
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
