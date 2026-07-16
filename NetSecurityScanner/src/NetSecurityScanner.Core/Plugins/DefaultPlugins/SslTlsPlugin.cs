using NetSecurityScanner.Models;
using System;
using System.Collections.Generic;
using System.Net.Sockets;
using System.Net.Security;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;
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
        private bool _isRunning = false;
        private int _scanCount = 0;
        private int _vulnerabilityFound = 0;
        private DateTime? _lastScanTime = null;

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
            var supportedPorts = new[] { 443, 465, 636, 853, 993, 995, 8443 };
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
                    return results;

                using var stream = client.GetStream();
                using var sslStream = new SslStream(stream, false, (sender, certificate, chain, sslPolicyErrors) => true);

                await sslStream.AuthenticateAsClientAsync(context.Target, null, SslProtocols.None, false);

                var protocol = sslStream.SslProtocol;
                var cipherAlgorithm = sslStream.CipherAlgorithm;
                var cipherStrength = sslStream.CipherStrength;
                var hashAlgorithm = sslStream.HashAlgorithm;
                var hashStrength = sslStream.HashStrength;
                var keyExchangeAlgorithm = sslStream.KeyExchangeAlgorithm;
                var keyExchangeStrength = sslStream.KeyExchangeStrength;

                results.Add(new VulnerabilityResult
                {
                    Name = $"SSL/TLS 协议检测 - 端口 {context.Port}",
                    Description = $"协议版本：{protocol}\n密码套件：{cipherAlgorithm} ({cipherStrength}bit)\n哈希算法：{hashAlgorithm} ({hashStrength}bit)\n密钥交换：{keyExchangeAlgorithm} ({keyExchangeStrength}bit)",
                    RiskLevel = "信息",
                    Port = context.Port,
                    PluginId = PluginId,
                    PluginName = Name
                });

                if (protocol == SslProtocols.Ssl2 ||
                    protocol == SslProtocols.Ssl3 ||
                    protocol == SslProtocols.Tls)
                {
                    results.Add(new VulnerabilityResult
                    {
                        Name = "不安全的 TLS 协议版本",
                        Description = $"检测到使用不安全的协议版本：{protocol}。建议升级到 TLS 1.2 或更高版本。",
                        RiskLevel = "高",
                        Port = context.Port,
                        PluginId = PluginId,
                        PluginName = Name
                    });
                }

                var cert = sslStream.RemoteCertificate;
                if (cert != null)
                {
                    var x509 = new X509Certificate2(cert);
                    var expiryDate = x509.NotAfter;
                    var daysUntilExpiry = (expiryDate - DateTime.Now).TotalDays;

                    if (daysUntilExpiry < 0)
                    {
                        results.Add(new VulnerabilityResult
                        {
                            Name = "SSL 证书已过期",
                            Description = $"证书已于 {expiryDate:yyyy-MM-dd} 过期。\n主题：{x509.Subject}\n颁发者：{x509.Issuer}",
                            RiskLevel = "高",
                            Port = context.Port,
                            PluginId = PluginId,
                            PluginName = Name
                        });
                    }
                    else if (daysUntilExpiry < 30)
                    {
                        results.Add(new VulnerabilityResult
                        {
                            Name = "SSL 证书即将过期",
                            Description = $"证书将在 {daysUntilExpiry:F0} 天后过期（{expiryDate:yyyy-MM-dd}）。\n主题：{x509.Subject}\n颁发者：{x509.Issuer}",
                            RiskLevel = "中",
                            Port = context.Port,
                            PluginId = PluginId,
                            PluginName = Name
                        });
                    }

                    if (x509.Issuer.Contains("Fake") || x509.Subject == x509.Issuer)
                    {
                        results.Add(new VulnerabilityResult
                        {
                            Name = "自签名 SSL 证书",
                            Description = $"检测到自签名证书，可能存在中间人攻击风险。\n主题：{x509.Subject}\n颁发者：{x509.Issuer}",
                            RiskLevel = "中",
                            Port = context.Port,
                            PluginId = PluginId,
                            PluginName = Name
                        });
                    }
                }
            }
            catch (AuthenticationException) { }
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
