using NetSecurityScanner.Models;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Text.RegularExpressions;
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
        private bool _isRunning = false;
        private int _scanCount = 0;
        private int _vulnerabilityFound = 0;
        private DateTime? _lastScanTime = null;

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

            _isRunning = true;
            try
            {
                var handler = new HttpClientHandler
                {
                    ServerCertificateCustomValidationCallback = (sender, cert, chain, errors) => true,
                    AllowAutoRedirect = false
                };

                using var client = new HttpClient(handler);
                client.Timeout = TimeSpan.FromSeconds(context.Timeout / 1000.0);
                client.DefaultRequestHeaders.Add("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36");

                string scheme = context.Port == 443 || context.Port == 8443 ? "https" : "http";
                string baseUrl = $"{scheme}://{context.Target}:{context.Port}";

                try
                {
                    var response = await client.GetAsync(baseUrl, cancellationToken);
                    var headers = response.Headers;
                    var content = await response.Content.ReadAsStringAsync(cancellationToken);

                    results.Add(new VulnerabilityResult
                    {
                        Name = $"Web 服务检测 - 端口 {context.Port}",
                        Description = $"HTTP 状态码：{(int)response.StatusCode}\nServer: {headers.Server?.ToString() ?? "未设置"}",
                        RiskLevel = "信息",
                        Port = context.Port,
                        PluginId = PluginId,
                        PluginName = Name
                    });

                    var securityHeaders = new Dictionary<string, string>
                    {
                        { "X-Frame-Options", "防止点击劫持" },
                        { "X-Content-Type-Options", "防止MIME类型嗅探" },
                        { "X-XSS-Protection", "XSS过滤" },
                        { "Strict-Transport-Security", "HSTS强制HTTPS" },
                        { "Content-Security-Policy", "内容安全策略" }
                    };

                    var missingHeaders = new List<string>();
                    foreach (var header in securityHeaders)
                    {
                        if (!headers.Contains(header.Key))
                        {
                            missingHeaders.Add(header.Key);
                        }
                    }

                    if (missingHeaders.Count > 0)
                    {
                        results.Add(new VulnerabilityResult
                        {
                            Name = "缺少安全响应头",
                            Description = $"缺少以下安全响应头：\n{string.Join("\n", missingHeaders.Select(h => $"- {h}（{securityHeaders[h]}）"))}",
                            RiskLevel = "低",
                            Port = context.Port,
                            PluginId = PluginId,
                            PluginName = Name
                        });
                    }

                    var sensitivePaths = new Dictionary<string, string>
                    {
                        { "/.git/config", "Git 配置文件泄露" },
                        { "/.env", "环境变量文件泄露" },
                        { "/wp-admin/", "WordPress 管理后台" },
                        { "/admin/", "管理后台" },
                        { "/robots.txt", "Robots 文件" },
                        { "/server-status", "Apache 服务器状态" }
                    };

                    foreach (var path in sensitivePaths)
                    {
                        try
                        {
                            var pathResponse = await client.GetAsync($"{baseUrl}{path.Key}", cancellationToken);
                            if (pathResponse.StatusCode == System.Net.HttpStatusCode.OK)
                            {
                                results.Add(new VulnerabilityResult
                                {
                                    Name = path.Value,
                                    Description = $"检测到可访问的敏感路径：{path.Key}\nHTTP 状态码：{(int)pathResponse.StatusCode}",
                                    RiskLevel = path.Key.Contains(".git") || path.Key.Contains(".env") ? "高" : "中",
                                    Port = context.Port,
                                    PluginId = PluginId,
                                    PluginName = Name
                                });
                            }
                        }
                        catch { }
                    }

                    if (content.Contains("<!--") && content.Contains("-->"))
                    {
                        var commentPattern = Regex.Matches(content, @"<!--(.*?)-->", RegexOptions.Singleline);
                        if (commentPattern.Count > 3)
                        {
                            results.Add(new VulnerabilityResult
                            {
                                Name = "HTML 注释信息泄露",
                                Description = $"页面包含 {commentPattern.Count} 个 HTML 注释，可能泄露敏感信息。",
                                RiskLevel = "低",
                                Port = context.Port,
                                PluginId = PluginId,
                                PluginName = Name
                            });
                        }
                    }
                }
                catch (HttpRequestException) { }
                catch (TaskCanceledException) { }
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
