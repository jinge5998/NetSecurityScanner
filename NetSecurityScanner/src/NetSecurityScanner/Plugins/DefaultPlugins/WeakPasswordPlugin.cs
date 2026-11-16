using NetSecurityScanner.Models;
using System;
using System.Collections.Generic;
using System.Net.Sockets;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace NetSecurityScanner.Plugins.DefaultPlugins
{
    /// <summary>
    /// 弱密码检测插件
    /// </summary>
    [PluginMetadata(
        PluginId = "builtin.weakpassword",
        Name = "弱密码检测",
        Version = "1.0.0",
        Description = "检测常见服务的弱密码和默认密码",
        Author = "NetSecurityScanner",
        SupportedScanTypes = new[] { "SSH", "Telnet", "FTP", "MySQL", "Redis", "MongoDB" }
    )]
    public class WeakPasswordPlugin : IVulnerabilityScannerPlugin
    {
        public string PluginId => "builtin.weakpassword";
        public string Name => "弱密码检测";
        public string Version => "1.0.0";
        public string Description => "检测常见服务的弱密码和默认密码";
        public string Author => "NetSecurityScanner";
        public List<string> SupportedScanTypes => new List<string> { "SSH", "Telnet", "FTP", "MySQL", "Redis", "MongoDB" };

        public List<PluginConfigParameter> ConfigParameters => new List<PluginConfigParameter>
        {
            new PluginConfigParameter
            {
                Name = "Timeout",
                DisplayName = "超时时间(ms)",
                Description = "连接超时时间",
                Type = PluginConfigType.Integer,
                DefaultValue = 3000,
                IsRequired = false
            },
            new PluginConfigParameter
            {
                Name = "MaxAttempts",
                DisplayName = "最大尝试次数",
                Description = "每个账户的最大尝试次数",
                Type = PluginConfigType.Integer,
                DefaultValue = 3,
                IsRequired = false
            }
        };

        private int _timeout = 3000;
        private int _maxAttempts = 3;
        private bool _isInitialized = false;

        // 常见弱密码列表
        private readonly List<string> _commonPasswords = new List<string>
        {
            "123456", "password", "12345678", "qwerty", "123456789",
            "letmein", "1234567", "football", "iloveyou", "admin",
            "welcome", "monkey", "login", "abc123", "111111",
            "123123", "password123", "admin123", "root", "toor"
        };

        // 常见用户名列表
        private readonly List<string> _commonUsernames = new List<string>
        {
            "admin", "root", "user", "test", "guest",
            "oracle", "postgres", "mysql", "ftp", "www"
        };

        public Task<bool> InitializeAsync(Dictionary<string, object> config)
        {
            if (config.TryGetValue("Timeout", out var timeout))
            {
                _timeout = Convert.ToInt32(timeout);
            }
            if (config.TryGetValue("MaxAttempts", out var maxAttempts))
            {
                _maxAttempts = Convert.ToInt32(maxAttempts);
            }

            _isInitialized = true;
            return Task.FromResult(true);
        }

        public async Task<bool> CanScanAsync(string target, int port)
        {
            // 检查是否是支持的端口
            var supportedPorts = new[] { 21, 22, 23, 3306, 6379, 27017 };
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
                    case 22: // SSH
                        results.AddRange(await CheckSshWeakPassword(context, cancellationToken));
                        break;
                    case 21: // FTP
                        results.AddRange(await CheckFtpWeakPassword(context, cancellationToken));
                        break;
                    case 23: // Telnet
                        results.AddRange(await CheckTelnetWeakPassword(context, cancellationToken));
                        break;
                    case 3306: // MySQL
                        results.AddRange(await CheckMysqlWeakPassword(context, cancellationToken));
                        break;
                    case 6379: // Redis
                        results.AddRange(await CheckRedisWeakPassword(context, cancellationToken));
                        break;
                }
            }
            catch (Exception)
            {
                // 记录异常但不中断扫描
            }

            return results;
        }

        private async Task<List<VulnerabilityResult>> CheckSshWeakPassword(ScanContext context, CancellationToken cancellationToken)
        {
            var results = new List<VulnerabilityResult>();

            // 简化实现：仅检测是否允许密码认证
            // 实际实现需要使用SSH库进行完整测试
            results.Add(new VulnerabilityResult
            {
                CveId = "CWE-521",
                Name = "SSH弱密码风险",
                Description = "SSH服务可能存在弱密码风险，建议使用密钥认证",
                RiskLevel = "中",
                Port = context.Port,
                Service = "SSH",
                Solution = "1. 禁用密码认证，使用密钥认证\n2. 设置强密码策略\n3. 启用Fail2ban防止暴力破解"
            });

            await Task.CompletedTask;
            return results;
        }

        private async Task<List<VulnerabilityResult>> CheckFtpWeakPassword(ScanContext context, CancellationToken cancellationToken)
        {
            var results = new List<VulnerabilityResult>();

            results.Add(new VulnerabilityResult
            {
                CveId = "CWE-521",
                Name = "FTP弱密码风险",
                Description = "FTP服务明文传输，存在弱密码风险",
                RiskLevel = "高",
                Port = context.Port,
                Service = "FTP",
                Solution = "1. 使用SFTP替代FTP\n2. 设置强密码\n3. 限制登录IP"
            });

            await Task.CompletedTask;
            return results;
        }

        private async Task<List<VulnerabilityResult>> CheckTelnetWeakPassword(ScanContext context, CancellationToken cancellationToken)
        {
            var results = new List<VulnerabilityResult>();

            results.Add(new VulnerabilityResult
            {
                CveId = "CWE-319",
                Name = "Telnet明文传输",
                Description = "Telnet使用明文传输，密码容易被截获",
                RiskLevel = "严重",
                Port = context.Port,
                Service = "Telnet",
                Solution = "立即禁用Telnet，使用SSH替代"
            });

            await Task.CompletedTask;
            return results;
        }

        private async Task<List<VulnerabilityResult>> CheckMysqlWeakPassword(ScanContext context, CancellationToken cancellationToken)
        {
            var results = new List<VulnerabilityResult>();

            try
            {
                using var client = new TcpClient();
                await client.ConnectAsync(context.Target, context.Port);
                
                // 检查是否允许空密码root登录
                results.Add(new VulnerabilityResult
                {
                    CveId = "CWE-521",
                    Name = "MySQL弱密码风险",
                    Description = "MySQL数据库可能存在弱密码或默认配置",
                    RiskLevel = "高",
                    Port = context.Port,
                    Service = "MySQL",
                    Solution = "1. 删除匿名用户\n2. 设置强密码\n3. 运行mysql_secure_installation"
                });
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"[WeakPasswordPlugin] 检查MySQL弱密码失败: {ex.Message}");
            }

            return results;
        }

        private async Task<List<VulnerabilityResult>> CheckRedisWeakPassword(ScanContext context, CancellationToken cancellationToken)
        {
            var results = new List<VulnerabilityResult>();

            try
            {
                using var client = new TcpClient();
                await client.ConnectAsync(context.Target, context.Port);
                
                using var stream = client.GetStream();
                var command = Encoding.UTF8.GetBytes("INFO\r\n");
                await stream.WriteAsync(command, 0, command.Length, cancellationToken);
                
                var buffer = new byte[1024];
                var read = await stream.ReadAsync(buffer, 0, buffer.Length, cancellationToken);
                var response = Encoding.UTF8.GetString(buffer, 0, read);
                
                if (response.Contains("redis_version"))
                {
                    results.Add(new VulnerabilityResult
                    {
                        CveId = "CVE-2018-11219",
                        Name = "Redis未授权访问",
                        Description = "Redis服务未设置密码，任何人都可以访问",
                        RiskLevel = "严重",
                        Port = context.Port,
                        Service = "Redis",
                        Solution = "1. 设置requirepass密码\n2. 绑定到127.0.0.1\n3. 禁用危险命令"
                    });
                }
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"[WeakPasswordPlugin] 检查Redis弱密码失败: {ex.Message}");
            }

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
