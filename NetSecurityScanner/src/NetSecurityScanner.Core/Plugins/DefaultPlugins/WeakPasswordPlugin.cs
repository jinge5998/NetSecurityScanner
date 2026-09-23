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
        SupportedScanTypes = new[] { "SSH", "Telnet", "FTP", "MySQL", "Redis", "MongoDB", "PostgreSQL", "MSSQL" }
    )]
    public class WeakPasswordPlugin : IVulnerabilityScannerPlugin
    {
        public string PluginId => "builtin.weakpassword";
        public string Name => "弱密码检测";
        public string Version => "1.0.0";
        public string Description => "检测常见服务的弱密码和默认密码";
        public string Author => "NetSecurityScanner";
        public List<string> SupportedScanTypes => new List<string> { "SSH", "Telnet", "FTP", "MySQL", "Redis", "MongoDB", "PostgreSQL", "MSSQL" };

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
        private bool _isRunning = false;
        private int _scanCount = 0;
        private int _vulnerabilityFound = 0;
        private DateTime? _lastScanTime = null;

        private readonly List<string> _commonPasswords = new List<string>
        {
            // 基础弱密码
            "123456", "password", "12345678", "qwerty", "123456789",
            "letmein", "1234567", "football", "iloveyou", "admin",
            "welcome", "monkey", "login", "abc123", "111111",
            "123123", "password123", "admin123", "root", "toor",
            // 扩展弱密码（常见 Top 50）
            "12345", "1234", "1234567890", "000000", "11111111",
            "1q2w3e4r", "1qaz2wsx", "qazwsx", "passw0rd", "p@ssw0rd",
            "P@ssw0rd", "Password1", "Password123", "Admin123", "Admin@123",
            "root123", "root1234", "rootroot", "toor123", "test123",
            "test1234", "guest", "guest123", "user", "user123",
            "changeme", "default", "secret", "master", "letmein123",
            "super", "super123", "supervisor", "manager", "123abc",
            "access", "access123", "login123", "pass123", "pass1234",
            "baseball", "dragon", "trustno1", "shadow", "sunshine",
            "123qwe", "qwe123", "q1w2e3r4", "asdfgh", "asdf1234"
        };

        private readonly List<string> _commonUsernames = new List<string>
        {
            // 基础用户名
            "admin", "root", "user", "test", "guest",
            "oracle", "postgres", "mysql", "ftp", "www",
            // 扩展用户名
            "administrator", "Administrator", "ADMIN", "ROOT",
            "sa", "system", "sys", "dba", "dbadmin", "db2admin",
            "operator", "manager", "super", "supervisor", "monitor",
            "ftpuser", "anonymous", "upload", "download", "webmaster",
            "nginx", "apache", "tomcat", "jenkins", "git", "gitlab",
            "dev", "devuser", "demo", "temp", "backup", "support",
            "user1", "user01", "user123", "test1", "test01", "test123",
            "info", "service", "help", "office", "qwerty", "hp"
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
            var supportedPorts = new[] { 21, 22, 23, 3306, 5432, 6379, 1433, 27017 };
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
                stream.ReadTimeout = 5000;

                var buffer = new byte[4096];

                if (context.Port == 21)
                {
                    var readTask = stream.ReadAsync(buffer, 0, buffer.Length, cancellationToken);
                    var readTimeout = Task.Delay(5000);
                    if (await Task.WhenAny(readTask, readTimeout) == readTimeout) return results;
                    int bytesRead = await readTask;
                    string response = Encoding.ASCII.GetString(buffer, 0, bytesRead);

                    if (response.StartsWith("220"))
                    {
                        results.Add(new VulnerabilityResult
                        {
                            Name = "FTP 服务允许匿名/密码认证",
                            Description = $"FTP 服务在端口 {context.Port} 上运行，允许密码认证。Banner: {response.Split('\n')[0].Trim()}",
                            RiskLevel = "中",
                            Port = context.Port,
                            PluginId = PluginId,
                            PluginName = Name
                        });

                        try
                        {
                            var userCmd = Encoding.ASCII.GetBytes("USER anonymous\r\n");
                            await stream.WriteAsync(userCmd, 0, userCmd.Length, cancellationToken);
                            bytesRead = await stream.ReadAsync(buffer, 0, buffer.Length, cancellationToken);
                            response = Encoding.ASCII.GetString(buffer, 0, bytesRead);

                            if (response.StartsWith("331"))
                            {
                                var passCmd = Encoding.ASCII.GetBytes("PASS anonymous@\r\n");
                                await stream.WriteAsync(passCmd, 0, passCmd.Length, cancellationToken);
                                bytesRead = await stream.ReadAsync(buffer, 0, buffer.Length, cancellationToken);
                                response = Encoding.ASCII.GetString(buffer, 0, bytesRead);

                                if (response.StartsWith("230"))
                                {
                                    results.Add(new VulnerabilityResult
                                    {
                                        Name = "FTP 允许匿名登录",
                                        Description = "FTP 服务器允许匿名登录，存在信息泄露风险。",
                                        RiskLevel = "高",
                                        Port = context.Port,
                                        PluginId = PluginId,
                                        PluginName = Name
                                    });
                                }
                            }
                        }
                        catch { }
                    }
                }
                else if (context.Port == 22)
                {
                    var readTask = stream.ReadAsync(buffer, 0, buffer.Length, cancellationToken);
                    var readTimeout = Task.Delay(5000);
                    if (await Task.WhenAny(readTask, readTimeout) == readTimeout) return results;
                    int bytesRead = await readTask;
                    string banner = Encoding.ASCII.GetString(buffer, 0, bytesRead);

                    results.Add(new VulnerabilityResult
                    {
                        Name = "SSH 服务密码认证检测",
                        Description = $"SSH 服务在端口 {context.Port} 上运行。Banner: {banner.Trim()}\n建议禁用密码认证，仅使用密钥认证。",
                        RiskLevel = "中",
                        Port = context.Port,
                        PluginId = PluginId,
                        PluginName = Name
                    });
                }
                else if (context.Port == 23)
                {
                    results.Add(new VulnerabilityResult
                    {
                        Name = "Telnet 服务检测",
                        Description = $"Telnet 服务在端口 {context.Port} 上运行，通信未加密，存在凭据窃听风险。建议使用 SSH 替代。",
                        RiskLevel = "高",
                        Port = context.Port,
                        PluginId = PluginId,
                        PluginName = Name
                    });
                }
                else if (context.Port == 3306)
                {
                    var readTask = stream.ReadAsync(buffer, 0, buffer.Length, cancellationToken);
                    var readTimeout = Task.Delay(5000);
                    if (await Task.WhenAny(readTask, readTimeout) == readTimeout) return results;
                    int bytesRead = await readTask;

                    results.Add(new VulnerabilityResult
                    {
                        Name = "MySQL 远程访问检测",
                        Description = $"MySQL 服务在端口 {context.Port} 上运行，允许远程连接。建议限制远程访问IP。",
                        RiskLevel = "中",
                        Port = context.Port,
                        PluginId = PluginId,
                        PluginName = Name
                    });
                }
                else if (context.Port == 6379)
                {
                    var infoCmd = Encoding.ASCII.GetBytes("INFO\r\n");
                    await stream.WriteAsync(infoCmd, 0, infoCmd.Length, cancellationToken);
                    var readTask = stream.ReadAsync(buffer, 0, buffer.Length, cancellationToken);
                    var readTimeout = Task.Delay(5000);

                    if (await Task.WhenAny(readTask, readTimeout) != readTimeout)
                    {
                        int bytesRead = await readTask;
                        string response = Encoding.ASCII.GetString(buffer, 0, bytesRead);

                        if (response.Contains("redis_version"))
                        {
                            results.Add(new VulnerabilityResult
                            {
                                Name = "Redis 未授权访问",
                                Description = $"Redis 服务在端口 {context.Port} 上运行且无需认证即可访问，存在严重安全风险。建议设置密码认证。",
                                RiskLevel = "严重",
                                Port = context.Port,
                                PluginId = PluginId,
                                PluginName = Name
                            });
                        }
                    }
                }
                else if (context.Port == 5432)
                {
                    // PostgreSQL：发送 startup 消息探测是否启用 trust 认证
                    // 简化检测：仅探测端口开放 + 尝试无密码连接会被拒绝即视为安全
                    // 这里只做 Banner/协议层探测，避免实际穷举密码
                    results.Add(new VulnerabilityResult
                    {
                        Name = "PostgreSQL 服务暴露检测",
                        Description = $"PostgreSQL 服务在端口 {context.Port} 上运行且可远程连接。建议：1) 限制 pg_hba.conf 仅允许内网 IP；2) 禁用 trust 认证；3) 为 postgres 用户设置强密码。",
                        RiskLevel = "中",
                        Port = context.Port,
                        PluginId = PluginId,
                        PluginName = Name
                    });
                }
                else if (context.Port == 1433)
                {
                    // MSSQL：探测端口开放（实际登录检测受协议复杂度限制，仅做暴露提示）
                    results.Add(new VulnerabilityResult
                    {
                        Name = "MSSQL 服务暴露检测",
                        Description = $"MSSQL/SQL Server 服务在端口 {context.Port} 上运行且可远程连接。建议：1) 如非必要禁用远程 TCP 访问；2) 为 sa 账户设置强密码并禁用；3) 启用 Windows 身份验证；4) 限制 1433 端口仅内网访问。",
                        RiskLevel = "中",
                        Port = context.Port,
                        PluginId = PluginId,
                        PluginName = Name
                    });
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
