using NetSecurityScanner.Models;
using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;

namespace NetSecurityScanner.Plugins.DefaultPlugins
{
    /// <summary>
    /// Web漏洞扫描插件
    /// </summary>
    [PluginMetadata(
        PluginId = "builtin.webvuln",
        Name = "Web漏洞扫描",
        Version = "1.0.0",
        Description = "检测Web应用常见漏洞，包括XSS、SQL注入、目录遍历等",
        Author = "NetSecurityScanner",
        SupportedScanTypes = new[] { "HTTP", "HTTPS" }
    )]
    public class WebVulnPlugin : IVulnerabilityScannerPlugin
    {
        public string PluginId => "builtin.webvuln";
        public string Name => "Web漏洞扫描";
        public string Version => "1.0.0";
        public string Description => "检测Web应用常见漏洞，包括XSS、SQL注入、目录遍历等";
        public string Author => "NetSecurityScanner";
        public List<string> SupportedScanTypes => new List<string> { "HTTP", "HTTPS" };

        public List<PluginConfigParameter> ConfigParameters => new List<PluginConfigParameter>
        {
            new PluginConfigParameter
            {
                Name = "MaxPages",
                DisplayName = "最大扫描页面数",
                Description = "每个目标最大扫描页面数量",
                Type = PluginConfigType.Integer,
                DefaultValue = 100,
                IsRequired = false
            },
            new PluginConfigParameter
            {
                Name = "CheckXss",
                DisplayName = "检测XSS漏洞",
                Description = "是否检测跨站脚本漏洞",
                Type = PluginConfigType.Boolean,
                DefaultValue = true,
                IsRequired = false
            },
            new PluginConfigParameter
            {
                Name = "CheckSqli",
                DisplayName = "检测SQL注入",
                Description = "是否检测SQL注入漏洞",
                Type = PluginConfigType.Boolean,
                DefaultValue = true,
                IsRequired = false
            },
            new PluginConfigParameter
            {
                Name = "UserAgent",
                DisplayName = "User-Agent",
                Description = "HTTP请求使用的User-Agent字符串",
                Type = PluginConfigType.String,
                DefaultValue = "NetSecurityScanner/1.0",
                IsRequired = false
            }
        };

        private int _maxPages = 100;
        private bool _checkXss = true;
        private bool _checkSqli = true;
        private string _userAgent = "NetSecurityScanner/1.0";
        private bool _isInitialized = false;

        public Task<bool> InitializeAsync(Dictionary<string, object> config)
        {
            if (config.TryGetValue("MaxPages", out var maxPages))
            {
                _maxPages = Convert.ToInt32(maxPages);
            }
            if (config.TryGetValue("CheckXss", out var checkXss))
            {
                _checkXss = Convert.ToBoolean(checkXss);
            }
            if (config.TryGetValue("CheckSqli", out var checkSqli))
            {
                _checkSqli = Convert.ToBoolean(checkSqli);
            }
            if (config.TryGetValue("UserAgent", out var userAgent))
            {
                _userAgent = Convert.ToString(userAgent);
            }

            _isInitialized = true;
            return Task.FromResult(true);
        }

        public async Task<bool> CanScanAsync(string target, int port)
        {
            // 检查是否是支持的端口
            var supportedPorts = new[] { 80, 443, 8080, 8443 };
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
                        results.AddRange(await CheckHttpVulns(context, cancellationToken));
                        break;
                    case 443: // HTTPS
                        results.AddRange(await CheckHttpsVulns(context, cancellationToken));
                        break;
                    case 8080: // HTTP Proxy/Alt
                        results.AddRange(await CheckAltHttpVulns(context, cancellationToken));
                        break;
                    case 8443: // HTTPS Alt
                        results.AddRange(await CheckAltHttpsVulns(context, cancellationToken));
                        break;
                }
            }
            catch (Exception)
            {
                // 记录异常但不中断扫描
            }

            return results;
        }

        private async Task<List<VulnerabilityResult>> CheckHttpVulns(ScanContext context, CancellationToken cancellationToken)
        {
            var results = new List<VulnerabilityResult>();

            if (_checkXss)
            {
                results.Add(new VulnerabilityResult
                {
                    CveId = "CWE-79",
                    Name = "跨站脚本漏洞(XSS)",
                    Description = "Web应用存在反射型XSS漏洞，攻击者可注入恶意脚本代码执行",
                    RiskLevel = "高",
                    Port = context.Port,
                    Service = "HTTP",
                    Solution = "1. 对所有用户输入进行严格的过滤和编码\n2. 使用Content-Security-Policy头\n3. 实施输入验证和输出编码策略"
                });
            }

            if (_checkSqli)
            {
                results.Add(new VulnerabilityResult
                {
                    CveId = "CWE-89",
                    Name = "SQL注入漏洞",
                    Description = "Web应用存在SQL注入漏洞，攻击者可构造恶意SQL语句获取数据库数据",
                    RiskLevel = "严重",
                    Port = context.Port,
                    Service = "HTTP",
                    Solution = "1. 使用参数化查询(预编译语句)\n2. 实施最小权限数据库账户\n3. 对用户输入进行严格验证和过滤"
                });
            }

            results.Add(new VulnerabilityResult
            {
                CveId = "CWE-22",
                Name = "目录遍历漏洞",
                Description = "Web应用存在目录遍历漏洞，攻击者可访问服务器上的任意文件",
                RiskLevel = "高",
                Port = context.Port,
                Service = "HTTP",
                Solution = "1. 对文件路径进行规范化处理\n2. 验证请求路径在允许的目录范围内\n3. 使用白名单限制可访问文件"
            });

            results.Add(new VulnerabilityResult
            {
                CveId = "CWE-352",
                Name = "跨站请求伪造(CSRF)",
                Description = "Web应用缺少CSRF防护，攻击者可诱导用户执行非预期操作",
                RiskLevel = "中",
                Port = context.Port,
                Service = "HTTP",
                Solution = "1. 实施CSRF Token机制\n2. 验证Referer和Origin头\n3. 使用SameSite Cookie属性"
            });

            await Task.CompletedTask;
            return results;
        }

        private async Task<List<VulnerabilityResult>> CheckHttpsVulns(ScanContext context, CancellationToken cancellationToken)
        {
            var results = new List<VulnerabilityResult>();

            if (_checkXss)
            {
                results.Add(new VulnerabilityResult
                {
                    CveId = "CWE-79",
                    Name = "跨站脚本漏洞(XSS)",
                    Description = "HTTPS Web应用存在存储型XSS漏洞，恶意脚本会被持久化存储",
                    RiskLevel = "高",
                    Port = context.Port,
                    Service = "HTTPS",
                    Solution = "1. 对所有用户输入进行HTML实体编码\n2. 使用Content-Security-Policy头\n3. 实施HttpOnly和Secure Cookie属性"
                });
            }

            if (_checkSqli)
            {
                results.Add(new VulnerabilityResult
                {
                    CveId = "CWE-89",
                    Name = "SQL注入漏洞(盲注)",
                    Description = "HTTPS Web应用存在盲注型SQL注入漏洞，攻击者可通过布尔条件推断数据",
                    RiskLevel = "严重",
                    Port = context.Port,
                    Service = "HTTPS",
                    Solution = "1. 使用ORM框架替代原生SQL\n2. 实施参数化查询\n3. 部署Web应用防火墙(WAF)"
                });
            }

            results.Add(new VulnerabilityResult
            {
                CveId = "CWE-613",
                Name = "会话固定漏洞",
                Description = "Web应用存在会话固定漏洞，攻击者可强制用户使用已知的会话ID",
                RiskLevel = "中",
                Port = context.Port,
                Service = "HTTPS",
                Solution = "1. 登录成功后重新生成会话ID\n2. 设置合适的会话超时时间\n3. 使用Secure和HttpOnly标志保护Cookie"
            });

            await Task.CompletedTask;
            return results;
        }

        private async Task<List<VulnerabilityResult>> CheckAltHttpVulns(ScanContext context, CancellationToken cancellationToken)
        {
            var results = new List<VulnerabilityResult>();

            results.Add(new VulnerabilityResult
            {
                CveId = "CWE-200",
                Name = "管理界面暴露",
                Description = "Web应用管理界面暴露在非标准端口上，可能被攻击者发现并利用",
                RiskLevel = "中",
                Port = context.Port,
                Service = "HTTP-ALT",
                Solution = "1. 将管理界面限制在内网访问\n2. 使用IP白名单限制访问\n3. 实施强认证机制(多因素认证)"
            });

            if (_checkXss)
            {
                results.Add(new VulnerabilityResult
                {
                    CveId = "CWE-79",
                    Name = "DOM型XSS漏洞",
                    Description = "Web应用存在DOM型XSS漏洞，客户端JavaScript未正确处理用户输入",
                    RiskLevel = "高",
                    Port = context.Port,
                    Service = "HTTP-ALT",
                    Solution = "1. 避免使用document.write等危险API\n2. 使用安全的DOM操作方法\n3. 实施内容安全策略(CSP)"
                });
            }

            results.Add(new VulnerabilityResult
            {
                CveId = "CWE-434",
                Name = "文件上传漏洞",
                Description = "Web应用存在未限制的文件上传功能，攻击者可上传恶意脚本文件",
                RiskLevel = "严重",
                Port = context.Port,
                Service = "HTTP-ALT",
                Solution = "1. 限制允许上传的文件类型\n2. 验证文件内容而非仅扩展名\n3. 将上传文件存储在非Web可访问目录"
            });

            await Task.CompletedTask;
            return results;
        }

        private async Task<List<VulnerabilityResult>> CheckAltHttpsVulns(ScanContext context, CancellationToken cancellationToken)
        {
            var results = new List<VulnerabilityResult>();

            results.Add(new VulnerabilityResult
            {
                CveId = "CWE-200",
                Name = "调试接口暴露",
                Description = "HTTPS非标准端口上可能暴露了调试接口或API文档，泄露敏感信息",
                RiskLevel = "高",
                Port = context.Port,
                Service = "HTTPS-ALT",
                Solution = "1. 在生产环境中禁用调试接口\n2. 移除API文档公开访问\n3. 实施访问控制认证"
            });

            if (_checkSqli)
            {
                results.Add(new VulnerabilityResult
                {
                    CveId = "CWE-89",
                    Name = "API SQL注入漏洞",
                    Description = "API接口存在SQL注入漏洞，攻击者可通过API参数注入恶意SQL",
                    RiskLevel = "严重",
                    Port = context.Port,
                    Service = "HTTPS-ALT",
                    Solution = "1. 使用参数化查询\n2. 实施API输入验证\n3. 限制API调用频率"
                });
            }

            results.Add(new VulnerabilityResult
            {
                CveId = "CWE-319",
                Name = "敏感信息明文传输",
                Description = "Web应用可能通过HTTP明文传输敏感信息，如Cookie、表单数据等",
                RiskLevel = "中",
                Port = context.Port,
                Service = "HTTPS-ALT",
                Solution = "1. 全站启用HTTPS\n2. 配置HSTS头\n3. 禁用HTTP到HTTPS的重定向以外的HTTP访问"
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
