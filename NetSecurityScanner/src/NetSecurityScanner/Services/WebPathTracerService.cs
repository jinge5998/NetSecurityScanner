using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Reflection;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using HtmlAgilityPack;
using Microsoft.Win32;
using OpenQA.Selenium;
using OpenQA.Selenium.Chrome;
using OpenQA.Selenium.Support.UI;

namespace NetSecurityScanner.Services
{
    public enum TraceMode
    {
        Quick,
        Standard,
        Deep
    }

    public class RedirectStep
    {
        public string Url { get; set; } = "";
        public int StatusCode { get; set; }
        public string? LocationHeader { get; set; }
    }

    public class DiscoveredPath
    {
        public string Url { get; set; } = "";
        public string Source { get; set; } = "";
        public int StatusCode { get; set; }
        public string PathType { get; set; } = "";
        public int Confidence { get; set; } = 100;
        public long ContentLength { get; set; }
        public string? Title { get; set; }
    }

    public class DirectoryBruteResult
    {
        public int TotalTested { get; set; }
        public List<DiscoveredPath> FoundPaths { get; set; } = new();
        public Dictionary<int, List<DiscoveredPath>> ByStatusCode { get; set; } = new();
        public long BaselineContentLength { get; set; }
        public bool HasCustom404 { get; set; }
    }

    public class DeepCrawlResult
    {
        public int TotalCrawled { get; set; }
        public int MaxDepth { get; set; }
        public List<DiscoveredPath> FoundPaths { get; set; } = new();
        public List<string> CrawledUrls { get; set; } = new();
    }

    public class TraceChainStep
    {
        public int Layer { get; set; }
        public string Method { get; set; } = "";
        public string FromUrl { get; set; } = "";
        public string ToUrl { get; set; } = "";
        public string Description { get; set; } = "";
    }

    public class WebPathTraceResult
    {
        public string OriginalUrl { get; set; } = "";
        public string? FinalUrl { get; set; }
        public TraceMode Mode { get; set; }
        public List<RedirectStep> RedirectChain { get; set; } = new();
        public List<TraceChainStep> TraceChain { get; set; } = new();
        public Layer1Result? Layer1Results { get; set; }
        public Layer2Result? Layer2Results { get; set; }
        public Layer3Result? Layer3Results { get; set; }
        public Layer4Result? Layer4Results { get; set; }
        public DirectoryBruteResult? BruteResults { get; set; }
        public DeepCrawlResult? CrawlResults { get; set; }
        public SuffixProbeResult? SuffixProbeResults { get; set; }
        public List<DiscoveredPath> AllDiscoveredPaths { get; set; } = new();
        public bool FoundPath => FinalUrl != null || AllDiscoveredPaths.Count > 0;
    }

    public class SuffixProbeResult
    {
        public string DetectedTech { get; set; } = "";
        public List<string> ProbedSuffixes { get; set; } = new();
        public List<DiscoveredPath> FoundPaths { get; set; } = new();
    }

    public class Layer1Result
    {
        public int StatusCode { get; set; }
        public Dictionary<string, string> Headers { get; set; } = new();
        public string? FoundUrl { get; set; }
        public string? Error { get; set; }
        public List<RedirectStep> RedirectChain { get; set; } = new();
        public string? RefreshUrl { get; set; }
        public string? ContentLocationUrl { get; set; }
        public string? LinkHeaderUrl { get; set; }
        public string? XRedirectUrl { get; set; }
        public List<string> SecurityHeaders { get; set; } = new();
        public List<string> MissingSecurityHeaders { get; set; } = new();
        public TechFingerprint? TechStack { get; set; }
        public List<CookieInfo> SetCookies { get; set; } = new();
        public List<OpenRedirectFinding> OpenRedirects { get; set; } = new();
        public WafDetection? WafInfo { get; set; }
        public List<ApiEndpoint> DiscoveredApis { get; set; } = new();
        public List<string> DiscoveredSubdomains { get; set; } = new();
        public List<string> ParamVulnerabilityHints { get; set; } = new();
    }

    public class WafDetection
    {
        public bool IsBehindWaf { get; set; }
        public string WafName { get; set; } = "";
        public string DetectionMethod { get; set; } = "";
        public List<string> Indicators { get; set; } = new();
    }

    public class TechFingerprint
    {
        public string Server { get; set; } = "";
        public string XPoweredBy { get; set; } = "";
        public List<string> DetectedTechs { get; set; } = new();
        public string BackendLanguage { get; set; } = "";
        public string Framework { get; set; } = "";
        public string Cms { get; set; } = "";
    }

    public class ApiEndpoint
    {
        public string Url { get; set; } = "";
        public string Type { get; set; } = "";
        public string Method { get; set; } = "";
        public List<string> Parameters { get; set; } = new();
        public string? Description { get; set; }
        public bool IsInteractive { get; set; }
    }

    public class CookieInfo
    {
        public string Name { get; set; } = "";
        public string Domain { get; set; } = "";
        public string Path { get; set; } = "";
        public bool Secure { get; set; }
        public bool HttpOnly { get; set; }
        public bool IsSession { get; set; }
    }

    public class OpenRedirectFinding
    {
        public string Parameter { get; set; } = "";
        public string TestUrl { get; set; } = "";
        public string? RedirectedTo { get; set; }
        public bool IsVulnerable { get; set; }
    }

    public class Layer2Result
    {
        public string HtmlSource { get; set; } = "";
        public string? MetaRefreshUrl { get; set; }
        public string? JsRedirectUrl { get; set; }
        public string? LoginLinkUrl { get; set; }
        public List<string> FoundLoginLinks { get; set; } = new();
        public string? FoundUrl { get; set; }
        public string? Error { get; set; }
        public List<string> JsRedirectUrls { get; set; } = new();
        public List<string> SpaRouteUrls { get; set; } = new();
        public List<string> DecodedUrls { get; set; } = new();
        public List<ClassifiedLink> AllLinks { get; set; } = new();
        public List<string> ExternalResources { get; set; } = new();
        public List<string> InlineEventHandlers { get; set; } = new();
    }

    public class ClassifiedLink
    {
        public string Url { get; set; } = "";
        public string Text { get; set; } = "";
        public string Category { get; set; } = "";
        public string Source { get; set; } = "";
    }

    public class Layer3Result
    {
        public List<string> FoundUrls { get; set; } = new();
        public List<string> DisallowPaths { get; set; } = new();
        public List<string> AllowPaths { get; set; } = new();
        public List<string> SitemapUrls { get; set; } = new();
    }

    public class Layer4Result
    {
        public string InitialUrl { get; set; } = "";
        public string? FinalUrl { get; set; }
        public bool UrlChanged { get; set; }
        public List<string> RedirectChain { get; set; } = new();
        public string InitialPageSource { get; set; } = "";
        public string FinalPageSource { get; set; } = "";
        public List<string> FoundForms { get; set; } = new();
        public List<string> FoundIframes { get; set; } = new();
        public List<string> FoundDynamicLinks { get; set; } = new();
        public List<string> FoundAjaxCalls { get; set; } = new();
        public List<string> ConsoleLogs { get; set; } = new();
        public string? ScreenshotPath { get; set; }
        public string? Error { get; set; }
    }

    public class WebPathTracerService
    {
        private static readonly HttpClient _httpClient;
        private const int TIMEOUT_SECONDS = 8;
        private const int MAX_REDIRECTS = 20;
        private const string USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36";

        static WebPathTracerService()
        {
            var handler = new HttpClientHandler
            {
                AllowAutoRedirect = false,
                ServerCertificateCustomValidationCallback = (msg, cert, chain, errors) => true
            };
            _httpClient = new HttpClient(handler)
            {
                Timeout = TimeSpan.FromSeconds(TIMEOUT_SECONDS)
            };
            _httpClient.DefaultRequestHeaders.Add("User-Agent", USER_AGENT);
        }

        public event Action<string>? OnLog;

        public bool EnableSelenium { get; set; } = true;

        public bool EnableBrute { get; set; } = true;

        public bool EnableCrawl { get; set; } = true;

        public TraceMode Mode { get; set; } = TraceMode.Standard;

        public string? ChromeDriverPath { get; set; }

        public int MaxCrawlDepth { get; set; } = 2;

        public bool SameDomainOnly { get; set; } = true;

        public int BruteConcurrency { get; set; } = 10;

        private static readonly string[] _directoryDictionary = new[]
        {
            "admin", "login", "dashboard", "manage", "system", "console", "panel", "control",
            "api", "api/v1", "api/v2", "swagger", "docs", "graphiql",
            "upload", "download", "backup", "config", "test", "debug",
            "user", "users", "register", "signup", "auth", "oauth", "sso", "cas",
            "index.php", "index.asp", "index.jsp", "info.json", "config.xml", "db.bak", "site.old", "archive.zip", "backup.tar.gz",
            "wp-admin", "wp-login", "wp-content", "wp-includes",
            "administrator", "phpmyadmin", "phpinfo", "info.php",
            ".git", ".git/HEAD", ".git/config", ".svn", ".env", ".htaccess",
            "robots.txt", "sitemap.xml", "favicon.ico", "crossdomain.xml",
            "WEB-INF/web.xml", "META-INF",
            "server-status", "server-info", "nginx_status",
            "actuator", "actuator/health", "actuator/env",
            "graphql", "playground",
            "static", "public", "assets", "media", "images", "css", "js",
            "feed", "rss", "atom", "atom.xml",
            "oauth/authorize", "oauth/token",
            "api-docs", "openapi.json", "swagger.json", "swagger-ui",
            "health", "status", "ping", "version", "info",
            "search", "query", "filter",
            "admin/login", "admin/dashboard", "admin/config",
            "user/login", "user/register", "user/profile",
            "portal", "portal/login", "portal/dashboard",
            "app", "mobile", "ios", "android",
            "v1", "v2", "v3", "beta", "alpha", "staging", "production",
            "README.md", "readme.txt", "CHANGELOG.md", "package.json", "composer.json",
            "web.config", ".svn/entries", "DS_Store", ".DS_Store",
            "elmah.axd", "trace.axd", "error.log", "access.log",
            "wp-config.php", "database.sql", "dump.sql",
            "cgi-bin", "bin", "obj", "tmp", "temp",
            "console", "shell", "terminal", "cmd",
            "monitor", "metrics", "prometheus", "grafana",
            "jenkins", "ci", "cd", "deploy", "release",
            "socket.io", "signalr", "websocket",
            "callback", "webhook", "notify",
            "export", "import", "sync", "migrate",
            "cron", "task", "job", "queue", "worker"
        };

        private static readonly string[] _loginKeywords = new[]
        {
            "login", "signin", "admin", "dashboard", "sys", "auth", "sso", "cas", "oauth"
        };

        private static readonly string[] _pathTypeKeywords = new[]
        {
            "login", "admin", "dashboard", "auth", "api", "file", "redirect"
        };

        public async Task<WebPathTraceResult> TraceAsync(string targetUrl, CancellationToken ct = default)
        {
            var result = new WebPathTraceResult
            {
                OriginalUrl = targetUrl,
                Mode = Mode
            };

            OnLog?.Invoke($"\n{new string('=', 60)}");
            OnLog?.Invoke($"开始逐层递进追踪: {targetUrl} (模式: {Mode})");
            OnLog?.Invoke(new string('=', 60));

            var visitedUrls = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            var traceChain = new List<TraceChainStep>();
            string currentUrl = targetUrl;
            string? nextUrl = null;

            // ===== 第一层：HTTP重定向链追踪 =====
            OnLog?.Invoke($"\n{'─',60}");
            OnLog?.Invoke($"▶ 第一层：HTTP重定向链追踪 → {currentUrl}");
            OnLog?.Invoke($"{'─',60}");

            var layer1 = await TraceHttpRedirectChainAsync(currentUrl, ct);
            result.Layer1Results = layer1;

            if (layer1.RedirectChain.Count > 0)
            {
                result.RedirectChain = layer1.RedirectChain;
                foreach (var step in layer1.RedirectChain)
                {
                    traceChain.Add(new TraceChainStep
                    {
                        Layer = 1,
                        Method = $"HTTP {step.StatusCode}",
                        FromUrl = currentUrl,
                        ToUrl = step.Url,
                        Description = $"HTTP {step.StatusCode} → {step.Url}"
                    });
                    visitedUrls.Add(step.Url);
                }
                var lastRedirect = layer1.RedirectChain.Last();
                nextUrl = lastRedirect.Url;
                currentUrl = nextUrl;
                result.FinalUrl = currentUrl;
                OnLog?.Invoke($"✅ 第一层发现重定向链，最终URL: {currentUrl}");
            }
            else if (layer1.FoundUrl != null)
            {
                nextUrl = layer1.FoundUrl;
                traceChain.Add(new TraceChainStep
                {
                    Layer = 1,
                    Method = "HTTP Redirect/Refresh",
                    FromUrl = currentUrl,
                    ToUrl = nextUrl,
                    Description = $"HTTP跳转 → {nextUrl}"
                });
                visitedUrls.Add(nextUrl);
                currentUrl = nextUrl;
                result.FinalUrl = currentUrl;
                OnLog?.Invoke($"✅ 第一层发现跳转，当前URL: {currentUrl}");
            }
            else
            {
                OnLog?.Invoke($"❌ 第一层未发现HTTP重定向");
            }

            // ===== 开放重定向检测 =====
            OnLog?.Invoke($"\n{'─',60}");
            OnLog?.Invoke($"▶ 开放重定向参数检测 → {currentUrl}");
            OnLog?.Invoke($"{'─',60}");

            var openRedirects = await DetectOpenRedirectsAsync(currentUrl, ct);
            if (result.Layer1Results != null)
            {
                result.Layer1Results.OpenRedirects = openRedirects;
            }
            if (openRedirects.Count > 0)
            {
                foreach (var finding in openRedirects)
                {
                    if (finding.IsVulnerable)
                    {
                        OnLog?.Invoke($"⚠️ 开放重定向漏洞: 参数 {finding.Parameter} 可被利用 → {finding.RedirectedTo}");
                    }
                }
            }
            else
            {
                OnLog?.Invoke("[开放重定向] 未发现可利用的重定向参数");
            }

            // ===== 后缀智能探测 =====
            if (Mode == TraceMode.Standard || Mode == TraceMode.Deep)
            {
                OnLog?.Invoke($"\n{'─',60}");
                OnLog?.Invoke($"▶ 后缀智能探测 → {currentUrl}");
                OnLog?.Invoke($"{'─',60}");

                var suffixResult = await ProbeSuffixesAsync(currentUrl, result.Layer1Results?.TechStack, ct);
                result.SuffixProbeResults = suffixResult;
            }

            // ===== 第二层：HTML/JS源码分析（对当前URL） =====
            OnLog?.Invoke($"\n{'─',60}");
            OnLog?.Invoke($"▶ 第二层：HTML/JS源码分析 → {currentUrl}");
            OnLog?.Invoke($"{'─',60}");

            var layer2 = await CheckHtmlRedirectAsync(currentUrl, ct);
            result.Layer2Results = layer2;

            if (!string.IsNullOrEmpty(layer2.HtmlSource))
            {
                var apiEndpoints = DiscoverApiEndpoints(layer2.HtmlSource, currentUrl);
                if (result.Layer1Results != null)
                {
                    result.Layer1Results.DiscoveredApis = apiEndpoints;
                }
                if (apiEndpoints.Count > 0)
                {
                    OnLog?.Invoke($"[第二层] 🔗 发现 {apiEndpoints.Count} 个API端点:");
                    foreach (var api in apiEndpoints.Take(5))
                    {
                        OnLog?.Invoke($"[第二层]   {api.Type}: {api.Url}");
                    }
                }

                var baseDomain = GetDomain(currentUrl);
                if (!string.IsNullOrEmpty(baseDomain))
                {
                    var subdomains = DiscoverSubdomains(layer2.HtmlSource, baseDomain);
                    if (result.Layer1Results != null)
                    {
                        result.Layer1Results.DiscoveredSubdomains = subdomains;
                    }
                    if (subdomains.Count > 0)
                    {
                        OnLog?.Invoke($"[第二层] 🌐 发现 {subdomains.Count} 个子域名:");
                        foreach (var sub in subdomains.Take(5))
                        {
                            OnLog?.Invoke($"[第二层]   → {sub}");
                        }
                    }
                }

                var paramHints = DetectParamVulnerabilities(layer2.HtmlSource, currentUrl);
                if (result.Layer1Results != null)
                {
                    result.Layer1Results.ParamVulnerabilityHints = paramHints;
                }
                if (paramHints.Count > 0)
                {
                    OnLog?.Invoke($"[第二层] ⚠️ 参数漏洞风险提示:");
                    foreach (var hint in paramHints.Take(3))
                    {
                        OnLog?.Invoke($"[第二层]   → {hint}");
                    }
                }
            }

            if (layer2.FoundUrl != null && !visitedUrls.Contains(layer2.FoundUrl))
            {
                nextUrl = layer2.FoundUrl;
                var method = layer2.JsRedirectUrl != null ? "JS跳转"
                    : layer2.MetaRefreshUrl != null ? "Meta Refresh"
                    : layer2.LoginLinkUrl != null ? "登录链接" : "HTML分析";
                traceChain.Add(new TraceChainStep
                {
                    Layer = 2,
                    Method = method,
                    FromUrl = currentUrl,
                    ToUrl = nextUrl,
                    Description = $"{method} → {nextUrl}"
                });
                visitedUrls.Add(nextUrl);
                currentUrl = nextUrl;
                result.FinalUrl = currentUrl;
                OnLog?.Invoke($"✅ 第二层发现{method}，当前URL: {currentUrl}");

                // 对新URL再次执行第一层和第二层（递进追踪）
                int subRound = 1;
                while (subRound <= 5)
                {
                    OnLog?.Invoke($"\n{'─',60}");
                    OnLog?.Invoke($"  🔄 递进追踪第{subRound}轮 → {currentUrl}");
                    OnLog?.Invoke($"{'─',60}");

                    var subL1 = await TraceHttpRedirectChainAsync(currentUrl, ct);
                    if (subL1.FoundUrl != null && !visitedUrls.Contains(subL1.FoundUrl))
                    {
                        visitedUrls.Add(subL1.FoundUrl);
                        traceChain.Add(new TraceChainStep
                        {
                            Layer = 1,
                            Method = $"递进-HTTP重定向",
                            FromUrl = currentUrl,
                            ToUrl = subL1.FoundUrl,
                            Description = $"递进第{subRound}轮 HTTP → {subL1.FoundUrl}"
                        });
                        currentUrl = subL1.FoundUrl;
                        result.FinalUrl = currentUrl;
                        OnLog?.Invoke($"  ✅ 递进发现HTTP跳转 → {currentUrl}");
                        subRound++;
                        continue;
                    }

                    var subL2 = await CheckHtmlRedirectAsync(currentUrl, ct);
                    if (subL2.FoundUrl != null && !visitedUrls.Contains(subL2.FoundUrl))
                    {
                        visitedUrls.Add(subL2.FoundUrl);
                        var subMethod = subL2.JsRedirectUrl != null ? "JS跳转"
                            : subL2.MetaRefreshUrl != null ? "Meta Refresh"
                            : subL2.LoginLinkUrl != null ? "登录链接" : "HTML分析";
                        traceChain.Add(new TraceChainStep
                        {
                            Layer = 2,
                            Method = $"递进-{subMethod}",
                            FromUrl = currentUrl,
                            ToUrl = subL2.FoundUrl,
                            Description = $"递进第{subRound}轮 {subMethod} → {subL2.FoundUrl}"
                        });
                        currentUrl = subL2.FoundUrl;
                        result.FinalUrl = currentUrl;
                        OnLog?.Invoke($"  ✅ 递进发现{subMethod} → {currentUrl}");
                        subRound++;
                        continue;
                    }

                    OnLog?.Invoke($"  ⏹ 递进追踪结束，无新跳转");
                    break;
                }
            }
            else
            {
                if (layer2.FoundUrl != null)
                {
                    OnLog?.Invoke($"⚠️ 第二层发现URL但已访问过: {layer2.FoundUrl}");
                }
                else
                {
                    OnLog?.Invoke($"❌ 第二层未发现HTML/JS跳转");
                }
            }

            // ===== 辅助层（并行执行，对最终URL） =====
            var auxiliaryTasks = new List<Task>();

            if (Mode == TraceMode.Standard || Mode == TraceMode.Deep)
            {
                OnLog?.Invoke($"\n{'─',60}");
                OnLog?.Invoke($"▶ 第三层：敏感文件泄露检测 → {currentUrl}");
                OnLog?.Invoke($"{'─',60}");

                var layer3Task = CheckSensitiveFilesAsync(currentUrl, ct).ContinueWith(t =>
                {
                    if (t.IsCompletedSuccessfully)
                    {
                        result.Layer3Results = t.Result;
                        foreach (var url in t.Result.FoundUrls)
                        {
                            if (!visitedUrls.Contains(url))
                            {
                                traceChain.Add(new TraceChainStep
                                {
                                    Layer = 3,
                                    Method = "敏感文件",
                                    FromUrl = currentUrl,
                                    ToUrl = url,
                                    Description = $"敏感文件 → {url}"
                                });
                            }
                        }
                    }
                }, ct);
                auxiliaryTasks.Add(layer3Task);

                if (EnableBrute)
                {
                    OnLog?.Invoke($"\n{'─',60}");
                    OnLog?.Invoke($"▶ 目录爆破扫描 → {currentUrl} (并发: {BruteConcurrency})");
                    OnLog?.Invoke($"{'─',60}");

                    var suffixPaths = result.SuffixProbeResults?.FoundPaths
                        .Select(p => p.Url.Substring(p.Url.LastIndexOf('/') + 1))
                        .Where(p => !string.IsNullOrEmpty(p))
                        .ToList();

                    var bruteTask = DirectoryBruteAsync(currentUrl, ct, result.Layer1Results?.TechStack, suffixPaths).ContinueWith(t =>
                    {
                        if (t.IsCompletedSuccessfully)
                        {
                            result.BruteResults = t.Result;
                        }
                    }, ct);
                    auxiliaryTasks.Add(bruteTask);
                }
                else
                {
                    OnLog?.Invoke("\n[目录爆破] 已跳过（未启用）");
                }
            }

            if (Mode == TraceMode.Deep)
            {
                if (EnableSelenium)
                {
                    OnLog?.Invoke($"\n{'─',60}");
                    OnLog?.Invoke($"▶ 第四层：Selenium动态检测 → {currentUrl}");
                    OnLog?.Invoke($"{'─',60}");

                    var layer4Task = CheckSeleniumDynamicRedirectAsync(currentUrl, ct, result.Layer1Results?.SetCookies).ContinueWith(t =>
                    {
                        if (t.IsCompletedSuccessfully)
                        {
                            result.Layer4Results = t.Result;
                            if (t.Result.FinalUrl != null && t.Result.FinalUrl != currentUrl && !visitedUrls.Contains(t.Result.FinalUrl))
                            {
                                traceChain.Add(new TraceChainStep
                                {
                                    Layer = 4,
                                    Method = "Selenium动态跳转",
                                    FromUrl = currentUrl,
                                    ToUrl = t.Result.FinalUrl,
                                    Description = $"Selenium → {t.Result.FinalUrl}"
                                });
                                if (result.FinalUrl == currentUrl)
                                {
                                    result.FinalUrl = t.Result.FinalUrl;
                                }
                            }
                        }
                    }, ct);
                    auxiliaryTasks.Add(layer4Task);
                }
                else
                {
                    OnLog?.Invoke("\n[第四层] Selenium动态检测已跳过（未启用）");
                }

                if (EnableCrawl)
                {
                    OnLog?.Invoke($"\n{'─',60}");
                    OnLog?.Invoke($"▶ 深度爬取 → {currentUrl} (深度: {MaxCrawlDepth})");
                    OnLog?.Invoke($"{'─',60}");

                    var layer2Seeds = result.Layer2Results?.AllLinks
                        .Where(l => l.Category == "login" || l.Category == "admin" || l.Category == "api" || l.Category == "form")
                        .Select(l => l.Url)
                        .ToList();
                    var loginLinkSeeds = result.Layer2Results?.FoundLoginLinks ?? new List<string>();
                    var allSeeds = (layer2Seeds ?? new List<string>()).Concat(loginLinkSeeds).Distinct().ToList();

                    var crawlTask = DeepCrawlAsync(currentUrl, ct, allSeeds).ContinueWith(t =>
                    {
                        if (t.IsCompletedSuccessfully)
                        {
                            result.CrawlResults = t.Result;
                        }
                    }, ct);
                    auxiliaryTasks.Add(crawlTask);
                }
                else
                {
                    OnLog?.Invoke("\n[深度爬取] 已跳过（未启用）");
                }
            }

            await Task.WhenAll(auxiliaryTasks);

            result.TraceChain = traceChain;
            CollectAllPaths(result);

            if (result.AllDiscoveredPaths.Count > 0)
            {
                var prioritized = result.AllDiscoveredPaths
                    .OrderByDescending(p => GetPathPriority(p))
                    .ToList();
                result.AllDiscoveredPaths = prioritized;

                if (result.FinalUrl == null)
                {
                    var best = prioritized.FirstOrDefault(p => p.PathType == "redirect")
                        ?? prioritized.FirstOrDefault(p => p.PathType == "login")
                        ?? prioritized.FirstOrDefault();
                    if (best != null)
                    {
                        result.FinalUrl = best.Url;
                    }
                }
            }

            // 输出追踪链摘要
            OnLog?.Invoke($"\n{new string('=', 60)}");
            OnLog?.Invoke("📊 逐层追踪链摘要:");
            OnLog?.Invoke(new string('=', 60));
            OnLog?.Invoke($"  起点: {targetUrl}");
            for (int i = 0; i < traceChain.Count; i++)
            {
                var step = traceChain[i];
                OnLog?.Invoke($"  {i + 1}. [第{step.Layer}层-{step.Method}] {step.FromUrl} → {step.ToUrl}");
            }
            OnLog?.Invoke($"  终点: {result.FinalUrl ?? "未找到"}");
            OnLog?.Invoke($"  共发现 {result.AllDiscoveredPaths.Count} 条路径");

            if (result.FinalUrl == null && result.AllDiscoveredPaths.Count == 0)
            {
                OnLog?.Invoke("\n[!] 所有探测层均未直接找到目标路径。");
            }

            return result;
        }

        private int GetPathPriority(DiscoveredPath path)
        {
            var basePriority = path.PathType switch
            {
                "redirect" => 100,
                "login" => 80,
                "admin" => 70,
                "config" => 65,
                "api" => 50,
                "file" => 30,
                "other" => 10,
                _ => 10
            };
            return basePriority + (path.Confidence >= 70 ? 0 : path.Confidence >= 50 ? -10 : -30);
        }

        private void CollectAllPaths(WebPathTraceResult result)
        {
            var all = new List<DiscoveredPath>();

            if (result.Layer1Results?.FoundUrl != null)
            {
                all.Add(new DiscoveredPath
                {
                    Url = result.Layer1Results.FoundUrl,
                    Source = "Layer1-HTTP",
                    StatusCode = result.Layer1Results.StatusCode,
                    PathType = "redirect"
                });
            }

            if (result.Layer1Results?.OpenRedirects != null)
            {
                foreach (var or in result.Layer1Results.OpenRedirects.Where(o => o.IsVulnerable))
                {
                    all.Add(new DiscoveredPath
                    {
                        Url = or.TestUrl,
                        Source = "Layer1-OpenRedirect",
                        StatusCode = 302,
                        PathType = "redirect",
                        Confidence = 100
                    });
                }
            }

            if (result.Layer1Results?.RedirectChain.Count > 0)
            {
                foreach (var step in result.Layer1Results.RedirectChain)
                {
                    all.Add(new DiscoveredPath
                    {
                        Url = step.Url,
                        Source = "Layer1-Redirect",
                        StatusCode = step.StatusCode,
                        PathType = "redirect"
                    });
                }
            }

            if (result.Layer2Results?.FoundUrl != null)
            {
                all.Add(new DiscoveredPath
                {
                    Url = result.Layer2Results.FoundUrl,
                    Source = "Layer2-HTML",
                    StatusCode = 0,
                    PathType = ClassifyPath(result.Layer2Results.FoundUrl)
                });
            }

            foreach (var link in result.Layer2Results?.FoundLoginLinks ?? Enumerable.Empty<string>())
            {
                all.Add(new DiscoveredPath
                {
                    Url = link,
                    Source = "Layer2-LoginLink",
                    StatusCode = 0,
                    PathType = "login"
                });
            }

            foreach (var url in result.Layer2Results?.JsRedirectUrls ?? Enumerable.Empty<string>())
            {
                all.Add(new DiscoveredPath
                {
                    Url = url,
                    Source = "Layer2-JS",
                    StatusCode = 0,
                    PathType = "redirect"
                });
            }

            foreach (var url in result.Layer2Results?.SpaRouteUrls ?? Enumerable.Empty<string>())
            {
                all.Add(new DiscoveredPath
                {
                    Url = url,
                    Source = "Layer2-SPA",
                    StatusCode = 0,
                    PathType = "redirect"
                });
            }

            foreach (var url in result.Layer2Results?.DecodedUrls ?? Enumerable.Empty<string>())
            {
                all.Add(new DiscoveredPath
                {
                    Url = url,
                    Source = "Layer2-Decoded",
                    StatusCode = 0,
                    PathType = "redirect"
                });
            }

            foreach (var link in result.Layer2Results?.AllLinks ?? Enumerable.Empty<ClassifiedLink>())
            {
                if (link.Category == "login" || link.Category == "admin" || link.Category == "api" || link.Category == "register" || link.Category == "form")
                {
                    all.Add(new DiscoveredPath
                    {
                        Url = link.Url,
                        Source = $"Layer2-{link.Category}",
                        StatusCode = 0,
                        PathType = link.Category
                    });
                }
            }

            if (result.Layer3Results != null)
            {
                foreach (var url in result.Layer3Results.FoundUrls)
                {
                    all.Add(new DiscoveredPath
                    {
                        Url = url,
                        Source = "Layer3-Sensitive",
                        StatusCode = 200,
                        PathType = "file"
                    });
                }
                foreach (var path in result.Layer3Results.DisallowPaths)
                {
                    all.Add(new DiscoveredPath
                    {
                        Url = path,
                        Source = "Layer3-robots",
                        StatusCode = 0,
                        PathType = ClassifyPath(path)
                    });
                }
            }

            if (result.Layer4Results != null)
            {
                if (result.Layer4Results.UrlChanged && result.Layer4Results.FinalUrl != null)
                {
                    all.Add(new DiscoveredPath
                    {
                        Url = result.Layer4Results.FinalUrl,
                        Source = "Layer4-Selenium",
                        StatusCode = 0,
                        PathType = "redirect"
                    });
                }

                foreach (var link in result.Layer4Results.FoundDynamicLinks)
                {
                    all.Add(new DiscoveredPath
                    {
                        Url = link,
                        Source = "Layer4-Dynamic",
                        StatusCode = 0,
                        PathType = "login"
                    });
                }

                foreach (var url in result.Layer4Results.FoundAjaxCalls)
                {
                    all.Add(new DiscoveredPath
                    {
                        Url = url,
                        Source = "Layer4-AJAX",
                        StatusCode = 0,
                        PathType = "api"
                    });
                }

                foreach (var url in result.Layer4Results.FoundIframes)
                {
                    all.Add(new DiscoveredPath
                    {
                        Url = url,
                        Source = "Layer4-Iframe",
                        StatusCode = 0,
                        PathType = "file"
                    });
                }
            }

            if (result.BruteResults != null)
            {
                foreach (var path in result.BruteResults.FoundPaths)
                {
                    all.Add(path);
                }
            }

            if (result.CrawlResults != null)
            {
                foreach (var path in result.CrawlResults.FoundPaths)
                {
                    all.Add(path);
                }
            }

            if (result.SuffixProbeResults != null)
            {
                foreach (var path in result.SuffixProbeResults.FoundPaths)
                {
                    all.Add(path);
                }
            }

            var unique = new Dictionary<string, DiscoveredPath>();
            foreach (var p in all)
            {
                if (!unique.ContainsKey(p.Url))
                {
                    unique[p.Url] = p;
                }
            }

            result.AllDiscoveredPaths = unique.Values.ToList();
        }

        private static List<string> GenerateTechSpecificPaths(TechFingerprint tech)
        {
            var paths = new List<string>();
            var lang = tech.BackendLanguage?.ToLower() ?? "";
            var framework = tech.Framework?.ToLower() ?? "";
            var cms = tech.Cms?.ToLower() ?? "";
            var server = tech.Server?.ToLower() ?? "";

            if (lang == "php" || cms.Length > 0)
            {
                paths.AddRange(new[] { "index.php", "info.php", "phpinfo.php", "test.php",
                    "admin/login.php", "admin/index.php", "admin/config.php",
                    "wp-config.php", "wp-settings.php", "wp-load.php",
                    "config.php", "database.php", "db.php", "connect.php" });
            }
            if (lang == "asp.net")
            {
                paths.AddRange(new[] { "default.aspx", "Global.asax", "Web.config",
                    "admin/default.aspx", "admin/login.aspx", "admin/web.config",
                    "elmah.axd", "trace.axd", "bin/", "App_Data/",
                    "swagger/schemas", "api/values" });
            }
            if (lang == "java")
            {
                paths.AddRange(new[] { "index.jsp", "login.jsp", "WEB-INF/web.xml",
                    "META-INF/MANIFEST.MF", "struts.xml", "spring-configuration.xml",
                    "admin/index.do", "admin/login.do", "admin/index.action" });
            }
            if (lang == "python")
            {
                paths.AddRange(new[] { "admin/login", "admin/", "api/v1/", "api/v2/",
                    "static/", "media/", "manage.py", "settings.py", "wsgi.py",
                    "django_admin/", "graphql", "graphiql" });
            }
            if (lang == "node.js")
            {
                paths.AddRange(new[] { "api/", "api/v1/", "api/v2/", "graphql",
                    ".env", "package.json", "node_modules/", "next.config.js",
                    "nuxt.config.js", "server.js", "app.js" });
            }
            if (lang == "ruby")
            {
                paths.AddRange(new[] { "admin/login", "admin/", "rails/info",
                    "assets/", "Gemfile", "config/routes.rb", "db/schema.rb" });
            }

            if (framework.Contains("spring"))
            {
                paths.AddRange(new[] { "actuator", "actuator/health", "actuator/env",
                    "actuator/metrics", "actuator/beans", "actuator/mappings",
                    "actuator/configprops", "actuator/info", "actuator/loggers",
                    "swagger-ui.html", "v2/api-docs", "v3/api-docs" });
            }
            if (framework.Contains("django"))
            {
                paths.AddRange(new[] { "admin/", "admin/login/", "api/",
                    "django_admin/", "static/admin/", "__debug__/" });
            }
            if (framework.Contains("laravel"))
            {
                paths.AddRange(new[] { "api/", "horizon", "telescope", "_debugbar",
                    "storage/logs/laravel.log", ".env" });
            }
            if (cms == "wordpress")
            {
                paths.AddRange(new[] { "wp-admin/", "wp-login.php", "wp-content/",
                    "wp-includes/", "wp-config.php", "wp-cron.php",
                    "wp-content/debug.log", "wp-content/uploads/",
                    "xmlrpc.php", "wp-json/wp/v2/" });
            }
            if (cms == "drupal")
            {
                paths.AddRange(new[] { "user/login", "admin/", "sites/default/",
                    "sites/default/settings.php", "core/install.php",
                    "update.php", "cron.php", "xmlrpc.php" });
            }
            if (cms == "joomla")
            {
                paths.AddRange(new[] { "administrator/", "administrator/index.php",
                    "configuration.php", "api/", "cli/",
                    "libraries/", "tmp/", "logs/" });
            }
            if (server.Contains("nginx"))
            {
                paths.AddRange(new[] { "nginx_status", "status", "stub_status" });
            }
            if (server.Contains("apache"))
            {
                paths.AddRange(new[] { "server-status", "server-info", ".htaccess",
                    ".htpasswd", "cgi-bin/" });
            }
            if (server.Contains("iis"))
            {
                paths.AddRange(new[] { "aspnet_client/", "iisstart.htm",
                    "web.config", "_vti_bin/", "_vti_inf.html" });
            }

            return paths.Distinct().ToList();
        }

        private string ClassifyPath(string url)
        {
            var lower = url.ToLower();
            if (lower.Contains("login") || lower.Contains("signin") || lower.Contains("auth") || lower.Contains("sso") || lower.Contains("cas") || lower.Contains("oauth"))
                return "login";
            if (lower.Contains("admin") || lower.Contains("dashboard") || lower.Contains("panel") || lower.Contains("manage") || lower.Contains("console") || lower.Contains("system"))
                return "admin";
            if (lower.Contains("api") || lower.Contains("swagger") || lower.Contains("graphql") || lower.Contains("actuator") || lower.Contains("metrics"))
                return "api";
            if (lower.Contains("redirect") || lower.Contains("location") || lower.Contains("callback") || lower.Contains("return") || lower.Contains("next") || lower.Contains("goto"))
                return "redirect";
            if (lower.Contains("upload") || lower.Contains("download") || lower.Contains("file") || lower.Contains("attachment") || lower.Contains("media"))
                return "file";
            if (lower.Contains("config") || lower.Contains("setting") || lower.Contains("env") || lower.Contains("secret") || lower.Contains("key") || lower.Contains("token") || lower.Contains("password") || lower.Contains("private"))
                return "config";
            return "other";
        }

        private async Task<Layer1Result> TraceHttpRedirectChainAsync(string target, CancellationToken ct)
        {
            var result = new Layer1Result();
            OnLog?.Invoke("\n--- 第一层：HTTP重定向链追踪 ---");

            try
            {
                var currentUrl = target;
                var visited = new HashSet<string>();
                int redirectCount = 0;

                while (redirectCount < MAX_REDIRECTS)
                {
                    if (ct.IsCancellationRequested) break;

                    HttpResponseMessage resp;
                    try
                    {
                        resp = await _httpClient.GetAsync(currentUrl, HttpCompletionOption.ResponseHeadersRead, ct);
                    }
                    catch (Exception ex)
                    {
                        OnLog?.Invoke($"[第一层] 请求 {currentUrl} 失败: {ex.Message}");
                        break;
                    }

                    var step = new RedirectStep
                    {
                        Url = currentUrl,
                        StatusCode = (int)resp.StatusCode,
                        LocationHeader = resp.Headers.Location?.ToString()
                    };
                    result.RedirectChain.Add(step);

                    if (result.StatusCode == 0)
                    {
                        result.StatusCode = (int)resp.StatusCode;
                        result.Headers = resp.Headers.ToDictionary(h => h.Key, h => string.Join(", ", h.Value));
                    }

                    if ((int)resp.StatusCode >= 300 && (int)resp.StatusCode < 400)
                    {
                        if (resp.Headers.Location != null)
                        {
                            var nextUrl = MakeAbsoluteUrl(currentUrl, resp.Headers.Location.ToString());
                            OnLog?.Invoke($"[第一层] HTTP {(int)resp.StatusCode} 跳转 → {nextUrl}");

                            if (visited.Contains(nextUrl))
                            {
                                OnLog?.Invoke($"[第一层] 检测到循环重定向: {nextUrl}");
                                break;
                            }

                            visited.Add(currentUrl);
                            currentUrl = nextUrl;
                            redirectCount++;
                            continue;
                        }
                    }

                    if (resp.Headers.TryGetValues("Refresh", out var refreshValues))
                    {
                        var refresh = refreshValues.FirstOrDefault();
                        if (refresh != null)
                        {
                            var match = Regex.Match(refresh, @"url=([^;]+)", RegexOptions.IgnoreCase);
                            if (match.Success)
                            {
                                var fullUrl = MakeAbsoluteUrl(currentUrl, match.Groups[1].Value.Trim());
                                result.RefreshUrl = fullUrl;
                                result.FoundUrl ??= fullUrl;
                                OnLog?.Invoke($"[第一层] HTTP Refresh 头跳转 → {fullUrl}");
                            }
                        }
                    }

                    if (resp.Headers.TryGetValues("Content-Location", out var contentLocationValues))
                    {
                        var contentLocation = contentLocationValues.FirstOrDefault();
                        if (!string.IsNullOrEmpty(contentLocation))
                        {
                            var contentLocationUrl = MakeAbsoluteUrl(currentUrl, contentLocation);
                            result.ContentLocationUrl = contentLocationUrl;
                            result.FoundUrl ??= contentLocationUrl;
                            OnLog?.Invoke($"[第一层] Content-Location 头 → {contentLocationUrl}");
                        }
                    }

                    if (resp.Headers.TryGetValues("Link", out var linkValues))
                    {
                        foreach (var linkVal in linkValues)
                        {
                            var linkMatch = Regex.Match(linkVal, @"<([^>]+)>", RegexOptions.IgnoreCase);
                            if (linkMatch.Success)
                            {
                                var linkUrl = MakeAbsoluteUrl(currentUrl, linkMatch.Groups[1].Value.Trim());
                                result.LinkHeaderUrl = linkUrl;
                                result.FoundUrl ??= linkUrl;
                                OnLog?.Invoke($"[第一层] Link 头 → {linkUrl}");
                            }
                        }
                    }

                    if (resp.Headers.TryGetValues("X-Redirect", out var xRedirectValues))
                    {
                        var xRedirect = xRedirectValues.FirstOrDefault();
                        if (!string.IsNullOrEmpty(xRedirect))
                        {
                            var xRedirectUrl = MakeAbsoluteUrl(currentUrl, xRedirect);
                            result.XRedirectUrl = xRedirectUrl;
                            result.FoundUrl ??= xRedirectUrl;
                            OnLog?.Invoke($"[第一层] X-Redirect 头 → {xRedirectUrl}");
                        }
                    }

                    foreach (var headerName in new[] { "Location", "Refresh", "Content-Location", "Link", "X-Redirect" })
                    {
                        if (resp.Headers.Contains(headerName))
                            result.SecurityHeaders.Add(headerName);
                    }

                    var securityHeaderChecks = new (string name, bool present)[]
                    {
                        ("X-Frame-Options", resp.Headers.Contains("X-Frame-Options")),
                        ("X-Content-Type-Options", resp.Headers.Contains("X-Content-Type-Options")),
                        ("X-XSS-Protection", resp.Headers.Contains("X-XSS-Protection")),
                        ("Strict-Transport-Security", resp.Headers.Contains("Strict-Transport-Security")),
                        ("Content-Security-Policy", resp.Headers.Contains("Content-Security-Policy")),
                        ("Referrer-Policy", resp.Headers.Contains("Referrer-Policy")),
                        ("Permissions-Policy", resp.Headers.Contains("Permissions-Policy")),
                    };
                    foreach (var (name, present) in securityHeaderChecks)
                    {
                        if (present)
                            result.SecurityHeaders.Add(name);
                        else
                            result.MissingSecurityHeaders.Add(name);
                    }

                    if (result.MissingSecurityHeaders.Count > 0)
                    {
                        OnLog?.Invoke($"[第一层] 缺少安全头: {string.Join(", ", result.MissingSecurityHeaders)}");
                    }

                    result.TechStack = FingerprintTech(resp, "");
                    if (result.TechStack != null && result.TechStack.DetectedTechs.Count > 0)
                    {
                        OnLog?.Invoke($"[第一层] 技术栈识别: {string.Join(", ", result.TechStack.DetectedTechs)}");
                    }

                    result.WafInfo = DetectWaf(resp, "");
                    if (result.WafInfo.IsBehindWaf)
                    {
                        OnLog?.Invoke($"[第一层] ⚠️ 检测到WAF: {result.WafInfo.WafName}");
                        OnLog?.Invoke($"[第一层]   检测依据: {result.WafInfo.DetectionMethod}");
                        foreach (var indicator in result.WafInfo.Indicators.Take(3))
                        {
                            OnLog?.Invoke($"[第一层]   → {indicator}");
                        }
                    }
                    else
                    {
                        OnLog?.Invoke($"[第一层] 未检测到WAF/防火墙");
                    }

                    if (resp.Headers.TryGetValues("Set-Cookie", out var cookieValues))
                    {
                        foreach (var cookieStr in cookieValues)
                        {
                            var cookie = ParseCookie(cookieStr);
                            result.SetCookies.Add(cookie);
                            if (cookie.IsSession || cookie.Name.ToLower().Contains("session") || cookie.Name.ToLower().Contains("token"))
                            {
                                OnLog?.Invoke($"[第一层] Set-Cookie: {cookie.Name} (Session={cookie.IsSession}, HttpOnly={cookie.HttpOnly}, Secure={cookie.Secure})");
                            }
                        }
                        if (result.SetCookies.Count > 0)
                        {
                            OnLog?.Invoke($"[第一层] 共检测到 {result.SetCookies.Count} 个Cookie");
                        }
                    }

                    break;
                }

                if (redirectCount >= MAX_REDIRECTS)
                {
                    OnLog?.Invoke($"[第一层] 达到最大重定向次数限制 ({MAX_REDIRECTS})");
                }

                if (result.RedirectChain.Count > 1 || result.RefreshUrl != null || result.ContentLocationUrl != null)
                {
                    OnLog?.Invoke($"[第一层] 重定向链共 {result.RedirectChain.Count} 步");
                    if (result.FoundUrl == null && result.RedirectChain.Count > 0)
                    {
                        var lastStep = result.RedirectChain[result.RedirectChain.Count - 1];
                        if (lastStep.StatusCode >= 200 && lastStep.StatusCode < 300)
                        {
                            result.FoundUrl = lastStep.Url;
                        }
                    }
                }
                else
                {
                    OnLog?.Invoke($"[第一层] 未发现HTTP层跳转 (状态码: {result.StatusCode})");
                }
            }
            catch (Exception ex)
            {
                OnLog?.Invoke($"[第一层] 请求失败: {ex.Message}");
                result.Error = ex.Message;
            }

            return result;
        }

        private async Task<Layer2Result> CheckHtmlRedirectAsync(string target, CancellationToken ct)
        {
            var result = new Layer2Result();
            OnLog?.Invoke("\n--- 第二层：HTML源码深度分析 ---");

            try
            {
                var resp = await _httpClient.GetAsync(target, ct);
                var html = await resp.Content.ReadAsStringAsync(ct);
                result.HtmlSource = html;
                var doc = new HtmlAgilityPack.HtmlDocument();
                doc.LoadHtml(html);

                var metaRefresh = doc.DocumentNode.SelectSingleNode("//meta[translate(@http-equiv,'ABCDEFGHIJKLMNOPQRSTUVWXYZ','abcdefghijklmnopqrstuvwxyz')='refresh']");
                if (metaRefresh != null)
                {
                    var content = metaRefresh.GetAttributeValue("content", "");
                    var match = Regex.Match(content, @"url=([^;]+)", RegexOptions.IgnoreCase);
                    if (match.Success)
                    {
                        var fullUrl = MakeAbsoluteUrl(target, match.Groups[1].Value.Trim());
                        result.FoundUrl = fullUrl;
                        result.MetaRefreshUrl = fullUrl;
                        OnLog?.Invoke($"[第二层] Meta Refresh 跳转 → {fullUrl}");
                    }
                }

                var scripts = doc.DocumentNode.SelectNodes("//script");
                if (scripts != null)
                {
                    var basicPatterns = new (string pattern, string name)[]
                    {
                        (@"window\.location\.href\s*=\s*[""']([^""']+)[""']", "window.location.href"),
                        (@"window\.location\.replace\s*\(\s*[""']([^""']+)[""']\s*\)", "window.location.replace"),
                        (@"location\.href\s*=\s*[""']([^""']+)[""']", "location.href"),
                        (@"self\.location\s*=\s*[""']([^""']+)[""']", "self.location"),
                        (@"window\.location\s*=\s*[""']([^""']+)[""']", "window.location"),
                        (@"window\.location\.assign\s*\(\s*[""']([^""']+)[""']\s*\)", "window.location.assign"),
                        (@"document\.location\.href\s*=\s*[""']([^""']+)[""']", "document.location.href"),
                        (@"document\.location\.replace\s*\(\s*[""']([^""']+)[""']\s*\)", "document.location.replace"),
                        (@"top\.location\s*=\s*[""']([^""']+)[""']", "top.location"),
                        (@"parent\.location\s*=\s*[""']([^""']+)[""']", "parent.location"),
                        (@"window\.open\s*\(\s*[""']([^""']+)[""']", "window.open"),
                        (@"location\.replace\s*\(\s*[""']([^""']+)[""']\s*\)", "location.replace"),
                        (@"location\.assign\s*\(\s*[""']([^""']+)[""']\s*\)", "location.assign"),
                        (@"location\s*=\s*[""']([^""']+)[""']", "location="),
                        (@"window\.navigate\s*\(\s*[""']([^""']+)[""']", "window.navigate"),
                    };

                    var advancedPatterns = new (string pattern, string name)[]
                    {
                        (@"setTimeout\s*\(\s*function\s*\(\s*\)\s*\{[^}]*location[^}]*\}\s*,\s*\d+\s*\)", "setTimeout+location"),
                        (@"setInterval\s*\(\s*function\s*\(\s*\)\s*\{[^}]*location[^}]*\}\s*,\s*\d+\s*\)", "setInterval+location"),
                        (@"eval\s*\(\s*[""']([^""']*location[^""']*)[""']\s*\)", "eval+location"),
                        (@"new\s+Function\s*\(\s*[""']([^""']*location[^""']*)[""']\s*\)", "new Function+location"),
                        (@"document\.write\s*\(\s*[""']<script[^>]*>\s*(?:location|window\.location)[^""]*[""']\s*\)", "document.write+script"),
                        (@"atob\s*\(\s*[""']([A-Za-z0-9+/=]+)[""']\s*\)", "atob(base64)"),
                        (@"router\.(?:push|replace)\s*\(\s*[""']([^""']+)[""']\s*\)", "router.push/replace"),
                        (@"navigate\s*\(\s*[""']([^""']+)[""']\s*\)", "navigate"),
                        (@"redirect\s*\(\s*[""']([^""']+)[""']\s*\)", "redirect"),
                        (@"\$router\.(?:push|replace)\s*\(\s*[""']([^""']+)[""']\s*\)", "$router.push/replace"),
                        (@"React\.Router\.(?:push|replace)\s*\(\s*[""']([^""']+)[""']\s*\)", "React.Router"),
                        (@"window\.location\.href\s*=\s*`([^`]+)`", "template_literal_location"),
                        (@"location\.href\s*=\s*`([^`]+)`", "template_literal_href"),
                        (@"window\.location\s*=\s*`([^`]+)`", "template_literal_window"),
                        (@"fetch\s*\(\s*[""']([^""']+)[""']\s*\)\s*\.then\s*\(\s*\w+\s*=>\s*\w+\.location", "fetch+redirect"),
                        (@"\.replace\s*\(\s*[""']([^""']+)[""']\s*\)", "string.replace_redirect"),
                        (@"history\.(?:pushState|replaceState)\s*\([^,]*,\s*[^,]*,\s*[""']([^""']+)[""']", "history.pushState"),
                        (@"window\.history\.(?:pushState|replaceState)\s*\([^,]*,\s*[^,]*,\s*[""']([^""']+)[""']", "window.history"),
                    };

                    foreach (var script in scripts)
                    {
                        var scriptText = script.InnerText;
                        if (string.IsNullOrEmpty(scriptText)) continue;

                        foreach (var (pattern, name) in basicPatterns)
                        {
                            foreach (Match m in Regex.Matches(scriptText, pattern, RegexOptions.IgnoreCase))
                            {
                                if (m.Groups.Count > 1 && m.Groups[1].Success)
                                {
                                    var fullUrl = MakeAbsoluteUrl(target, m.Groups[1].Value);
                                    result.JsRedirectUrls.Add(fullUrl);
                                    result.FoundUrl ??= fullUrl;
                                    result.JsRedirectUrl ??= fullUrl;
                                    OnLog?.Invoke($"[第二层] JS跳转({name}) → {fullUrl}");
                                }
                            }
                        }

                        foreach (var (pattern, name) in advancedPatterns)
                        {
                            foreach (Match m in Regex.Matches(scriptText, pattern, RegexOptions.IgnoreCase))
                            {
                                if (name == "atob(base64)" && m.Groups.Count > 1 && m.Groups[1].Success)
                                {
                                    try
                                    {
                                        var decoded = Encoding.UTF8.GetString(Convert.FromBase64String(m.Groups[1].Value));
                                        if (decoded.StartsWith("http://") || decoded.StartsWith("https://") || decoded.StartsWith("/"))
                                        {
                                            var fullUrl = MakeAbsoluteUrl(target, decoded);
                                            result.DecodedUrls.Add(fullUrl);
                                            result.FoundUrl ??= fullUrl;
                                            OnLog?.Invoke($"[第二层] Base64解码跳转 → {fullUrl}");
                                        }
                                    }
                                    catch { }
                                }
                                else if ((name == "router.push/replace" || name == "$router.push/replace" || name == "React.Router" || name == "navigate" || name == "redirect") && m.Groups.Count > 1 && m.Groups[1].Success)
                                {
                                    var route = m.Groups[1].Value;
                                    var fullUrl = MakeAbsoluteUrl(target, route);
                                    result.SpaRouteUrls.Add(fullUrl);
                                    result.FoundUrl ??= fullUrl;
                                    OnLog?.Invoke($"[第二层] SPA路由({name}) → {fullUrl}");
                                }
                                else if (name == "setTimeout+location" || name == "setInterval+location")
                                {
                                    var locMatch = Regex.Match(m.Value, @"(?:window\.)?(?:location|self\.location)(?:\.href)?\s*=\s*[""']([^""']+)[""']", RegexOptions.IgnoreCase);
                                    if (locMatch.Success)
                                    {
                                        var fullUrl = MakeAbsoluteUrl(target, locMatch.Groups[1].Value);
                                        result.JsRedirectUrls.Add(fullUrl);
                                        result.FoundUrl ??= fullUrl;
                                        result.JsRedirectUrl ??= fullUrl;
                                        OnLog?.Invoke($"[第二层] 延迟跳转({name}) → {fullUrl}");
                                    }
                                }
                                else if (name == "eval+location" || name == "new Function+location")
                                {
                                    var locMatch = Regex.Match(m.Groups[1].Value, @"(?:window\.)?location(?:\.href)?\s*=\s*[""']([^""']+)[""']", RegexOptions.IgnoreCase);
                                    if (locMatch.Success)
                                    {
                                        var fullUrl = MakeAbsoluteUrl(target, locMatch.Groups[1].Value);
                                        result.JsRedirectUrls.Add(fullUrl);
                                        result.FoundUrl ??= fullUrl;
                                        result.JsRedirectUrl ??= fullUrl;
                                        OnLog?.Invoke($"[第二层] 动态代码跳转({name}) → {fullUrl}");
                                    }
                                }
                                else if (name == "document.write+script")
                                {
                                    var locMatch = Regex.Match(m.Value, @"(?:window\.)?location(?:\.href)?\s*=\s*[""']([^""']+)[""']", RegexOptions.IgnoreCase);
                                    if (locMatch.Success)
                                    {
                                        var fullUrl = MakeAbsoluteUrl(target, locMatch.Groups[1].Value);
                                        result.JsRedirectUrls.Add(fullUrl);
                                        result.FoundUrl ??= fullUrl;
                                        result.JsRedirectUrl ??= fullUrl;
                                        OnLog?.Invoke($"[第二层] document.write跳转 → {fullUrl}");
                                    }
                                }
                            }
                        }

                        var hexPattern = @"(?:""|')((?:\\x[0-9a-fA-F]{2})+)(?:""|')";
                        foreach (Match m in Regex.Matches(scriptText, hexPattern))
                        {
                            try
                            {
                                var decoded = DecodeHexString(m.Groups[1].Value);
                                if (decoded.StartsWith("http://") || decoded.StartsWith("https://"))
                                {
                                    result.DecodedUrls.Add(decoded);
                                    result.FoundUrl ??= decoded;
                                    OnLog?.Invoke($"[第二层] 十六进制解码URL → {decoded}");
                                }
                            }
                            catch { }
                        }

                        var unicodePattern = @"(?:""|')((?:\\u[0-9a-fA-F]{4})+)(?:""|')";
                        foreach (Match m in Regex.Matches(scriptText, unicodePattern))
                        {
                            try
                            {
                                var decoded = DecodeUnicodeString(m.Groups[1].Value);
                                if (decoded.StartsWith("http://") || decoded.StartsWith("https://"))
                                {
                                    result.DecodedUrls.Add(decoded);
                                    result.FoundUrl ??= decoded;
                                    OnLog?.Invoke($"[第二层] Unicode解码URL → {decoded}");
                                }
                            }
                            catch { }
                        }
                    }
                }

                var links = doc.DocumentNode.SelectNodes("//a[@href]");
                if (links != null)
                {
                    foreach (var link in links)
                    {
                        var href = link.GetAttributeValue("href", "");
                        var text = link.InnerText.Trim();
                        if (string.IsNullOrEmpty(href) || href.StartsWith("#") || href.StartsWith("javascript:")) continue;

                        var fullUrl = MakeAbsoluteUrl(target, href);
                        var category = ClassifyLink(href, text);

                        result.AllLinks.Add(new ClassifiedLink
                        {
                            Url = fullUrl,
                            Text = text.Length > 80 ? text.Substring(0, 80) + "..." : text,
                            Category = category,
                            Source = "a[href]"
                        });

                        if (_loginKeywords.Any(kw => href.ToLower().Contains(kw)))
                        {
                            result.FoundLoginLinks.Add(fullUrl);
                            result.FoundUrl ??= fullUrl;
                            result.LoginLinkUrl ??= fullUrl;
                            OnLog?.Invoke($"[第二层] 页面内疑似登录链接 → {fullUrl}");
                        }
                    }
                }

                var forms = doc.DocumentNode.SelectNodes("//form[@action]");
                if (forms != null)
                {
                    foreach (var form in forms)
                    {
                        var action = form.GetAttributeValue("action", "");
                        var method = form.GetAttributeValue("method", "get").ToUpper();
                        if (!string.IsNullOrEmpty(action))
                        {
                            var fullUrl = MakeAbsoluteUrl(target, action);
                            result.AllLinks.Add(new ClassifiedLink
                            {
                                Url = fullUrl,
                                Text = $"Form[{method}]",
                                Category = "form",
                                Source = "form[action]"
                            });
                        }
                    }
                }

                var externalResources = new (string xpath, string attr, string label)[]
                {
                    ("//link[@href]", "href", "stylesheet"),
                    ("//script[@src]", "src", "script"),
                    ("//img[@src]", "src", "image"),
                    ("//iframe[@src]", "src", "iframe"),
                    ("//object[@data]", "data", "object"),
                };
                foreach (var (xpath, attr, label) in externalResources)
                {
                    var nodes = doc.DocumentNode.SelectNodes(xpath);
                    if (nodes == null) continue;
                    foreach (var node in nodes)
                    {
                        var val = node.GetAttributeValue(attr, "");
                        if (!string.IsNullOrEmpty(val) && !val.StartsWith("data:"))
                        {
                            var fullUrl = MakeAbsoluteUrl(target, val);
                            result.ExternalResources.Add($"{label}: {fullUrl}");
                        }
                    }
                }

                var inlineEventNodes = doc.DocumentNode.SelectNodes("//*[//@onclick or //@onload or //@onerror or //@onmouseover]");
                if (inlineEventNodes != null)
                {
                    foreach (var node in inlineEventNodes)
                    {
                        var onclick = node.GetAttributeValue("onclick", "");
                        var onload = node.GetAttributeValue("onload", "");
                        var onerror = node.GetAttributeValue("onerror", "");
                        var handlers = new[] { onclick, onload, onerror }.Where(h => !string.IsNullOrEmpty(h));
                        foreach (var handler in handlers)
                        {
                            result.InlineEventHandlers.Add(handler);
                            var locMatch = Regex.Match(handler, @"(?:window\.)?location(?:\.href)?\s*=\s*[""']([^""']+)[""']", RegexOptions.IgnoreCase);
                            if (locMatch.Success)
                            {
                                var fullUrl = MakeAbsoluteUrl(target, locMatch.Groups[1].Value);
                                result.JsRedirectUrls.Add(fullUrl);
                                result.FoundUrl ??= fullUrl;
                                result.JsRedirectUrl ??= fullUrl;
                                OnLog?.Invoke($"[第二层] 内联事件跳转 → {fullUrl}");
                            }
                        }
                    }
                }

                if (result.AllLinks.Count > 0)
                {
                    var grouped = result.AllLinks.GroupBy(l => l.Category).ToDictionary(g => g.Key, g => g.Count());
                    OnLog?.Invoke($"[第二层] 页面链接统计: {string.Join(", ", grouped.Select(g => $"{g.Key}={g.Value}"))}");
                }

                if (result.FoundUrl == null && result.JsRedirectUrls.Count == 0 && result.FoundLoginLinks.Count == 0)
                {
                    OnLog?.Invoke("[第二层] HTML源码中未发现明显跳转或登录链接");
                }
            }
            catch (Exception ex)
            {
                OnLog?.Invoke($"[第二层] 请求失败: {ex.Message}");
                result.Error = ex.Message;
            }

            return result;
        }

        private string DecodeHexString(string hexStr)
        {
            var bytes = new List<byte>();
            var matches = Regex.Matches(hexStr, @"\\x([0-9a-fA-F]{2})");
            foreach (Match m in matches)
            {
                bytes.Add(Convert.ToByte(m.Groups[1].Value, 16));
            }
            return Encoding.UTF8.GetString(bytes.ToArray());
        }

        private string DecodeUnicodeString(string unicodeStr)
        {
            var sb = new StringBuilder();
            var matches = Regex.Matches(unicodeStr, @"\\u([0-9a-fA-F]{4})");
            foreach (Match m in matches)
            {
                sb.Append((char)Convert.ToInt32(m.Groups[1].Value, 16));
            }
            return sb.ToString();
        }

        private async Task<Layer3Result> CheckSensitiveFilesAsync(string target, CancellationToken ct)
        {
            var result = new Layer3Result();
            OnLog?.Invoke("\n--- 第三层：敏感文件泄露 ---");

            var sensitiveList = new[]
            {
                "robots.txt",
                "sitemap.xml",
                ".git/HEAD",
                ".git/config",
                ".git/index",
                ".git/objects/pack",
                ".svn/entries",
                ".svn/wc.db",
                ".hg/requires",
                ".bzr/branch-lock",
                ".env",
                ".env.local",
                ".env.production",
                ".env.backup",
                ".env~",
                ".env.bak",
                ".aws/credentials",
                ".aws/config",
                ".ssh/id_rsa",
                ".ssh/id_rsa.pub",
                ".ssh/known_hosts",
                ".htaccess",
                ".htpasswd",
                "README.md",
                "readme.txt",
                "readme.html",
                "readme.md",
                "CHANGELOG.md",
                "LICENSE",
                "VERSION",
                "backup.zip",
                "backup.tar.gz",
                "backup.tar",
                "backup.rar",
                "backup.sql",
                "database.sql",
                "dump.sql",
                "data.sql",
                "www.zip",
                "site.zip",
                "console",
                "admin",
                "admin/",
                "login",
                "administrator",
                "web.config",
                "crossdomain.xml",
                "clientaccesspolicy.xml",
                "WEB-INF/web.xml",
                "WEB-INF/classes/",
                "WEB-INF/lib/",
                "META-INF/",
                "package.json",
                "package-lock.json",
                "yarn.lock",
                "composer.json",
                "composer.lock",
                "Gemfile",
                "Gemfile.lock",
                "requirements.txt",
                "Pipfile",
                "Pipfile.lock",
                "go.mod",
                "go.sum",
                "Cargo.toml",
                "Cargo.lock",
                "Dockerfile",
                "docker-compose.yml",
                "docker-compose.yaml",
                "docker-compose.prod.yml",
                ".dockerignore",
                "docker-entrypoint.sh",
                ".dockerenv",
                "Jenkinsfile",
                ".gitlab-ci.yml",
                ".github/workflows/main.yml",
                "kubernetes.yaml",
                "k8s.yaml",
                "helm.yaml",
                "server-status",
                "server-info",
                "nginx_status",
                "nginx_status?all",
                "status",
                "health",
                "actuator",
                "actuator/health",
                "actuator/env",
                "actuator/beans",
                "actuator/mappings",
                "actuator/configprops",
                "actuator/loggers",
                "actuator/heapdump",
                "actuator/gc.log",
                "actuator/threaddump",
                "actuator/scheduledtasks",
                "actuator/httptrace",
                "actuator/caches",
                "swagger-ui.html",
                "swagger-ui/",
                "swagger-ui/index.html",
                "swagger.json",
                "swagger.yaml",
                "v2/api-docs",
                "v3/api-docs",
                "openapi.json",
                "openapi.yaml",
                "api-docs",
                "graphiql",
                "graphql-playground",
                "graphiql/",
                "playground",
                "stoplight",
                ".DS_Store",
                "Thumbs.db",
                "desktop.ini",
                "error.log",
                "error_log",
                "access.log",
                "access_log",
                "debug.log",
                "application.log",
                "server.log",
                "app.log",
                "syslog",
                "php.ini~",
                "php.ini.bak",
                "phpinfo.php",
                "info.php",
                "test.php",
                "debug.php",
                "status.php",
                "info.aspx",
                "trace.axd",
                "elmah.axd",
                "healthcheck",
                ".well-known/security.txt",
                "security.txt",
                "debug",
                "trace",
                "profiler",
                "debug/pprof/heap",
                "debug/pprof/profile",
                "debug/pprof/trace",
                "metrics",
                "prometheus",
                "graphite",
                "monitor",
                "telescope",
                "horizon",
                "_debugbar",
                "_profiler",
                "api/config.yaml",
                "api/config.yml",
                "api/settings.yaml",
                "api/settings.yml",
                "config.yaml",
                "config.yml",
                "application.yaml",
                "application.yml",
                "application.properties",
                "conf/application.conf",
                "wp-config.php~",
                "wp-config.php.bak",
                "wp-config.php.old",
                "wp-login.php",
                "wp-admin/",
                "wp-content/",
                "wp-includes/",
                "xmlrpc.php",
                "wp-json/wp/v2/",
                "wp-content/debug.log",
                "configuration.php~",
                "configuration.php.bak",
                "configuration.php.old",
                "sites/default/settings.php",
                "sites/default/settings.php~",
                "sites/default/settings.php.bak",
                "core/install.php",
                "update.php",
                "cron.php",
                "user/login",
                "django_admin/",
                "static/admin/",
                "__debug__/",
                "rails/info",
                "assets/",
                "config/routes.rb",
                "db/schema.rb",
                "nuxt.config.js",
                "server.js",
                "app.js",
                "routes/",
                "api/",
                "api/users",
                "api/admin",
                "api/v1/",
                "api/v2/",
                "rest/",
                "rest/v1/",
                "graphql",
                "soap",
                "wsdl",
                "soap.wsdl",
                "api/metrics",
                "api/health",
                ".gitignore",
                ".gitattributes",
                ".git/hooks",
                ".git/logs/",
                "tmp/",
                "temp/",
                "uploads/",
                "upload/",
                "files/",
                "images/",
                "media/",
                ".cache",
                ".npm",
                ".yarn",
                "vendor/",
                "venv/",
                "env/",
                ".venv/",
                "__pycache__/",
                "var/log",
                "lib/",
                "libs/",
            };

            var baseUri = target.TrimEnd('/');

            OnLog?.Invoke("[第三层] 正在检测自定义404页面...");
            var (baselineLength, baselineSnippet, hasCustom404) = await ProbeCustom404Async(baseUri, ct);

            foreach (var item in sensitiveList)
            {
                if (ct.IsCancellationRequested) break;

                var testUrl = $"{baseUri}/{item}";
                try
                {
                    var resp = await _httpClient.GetAsync(testUrl, ct);
                    if (resp.IsSuccessStatusCode)
                    {
                        var content = await resp.Content.ReadAsStringAsync(ct);
                        var contentLength = content.Length;
                        var confidence = 100;

                        if (hasCustom404 && IsLikelyCustom404(content, contentLength, baselineLength, baselineSnippet))
                        {
                            confidence = 30;
                            OnLog?.Invoke($"[第三层] ⚠️ 疑似自定义404: {testUrl} (置信度降低)");
                        }

                        if (!ValidateSensitiveContent(item, content))
                        {
                            confidence = Math.Min(confidence, 40);
                            OnLog?.Invoke($"[第三层] ⚠️ 内容格式不匹配: {testUrl} (置信度降低)");
                        }

                        if (confidence >= 50)
                        {
                            OnLog?.Invoke($"[第三层] 发现敏感文件: {testUrl} (置信度:{confidence}%)");
                        }
                        result.FoundUrls.Add(testUrl);

                        if (item == "robots.txt" || item == "sitemap.xml")
                        {
                            var disallowPaths = Regex.Matches(content, @"Disallow:\s*(\S+)", RegexOptions.IgnoreCase);
                            foreach (Match m in disallowPaths)
                            {
                                var fullPath = MakeAbsoluteUrl(target, m.Groups[1].Value);
                                OnLog?.Invoke($"   → Disallow 路径: {fullPath}");
                                result.DisallowPaths.Add(fullPath);
                            }
                            var allowPaths = Regex.Matches(content, @"Allow:\s*(\S+)", RegexOptions.IgnoreCase);
                            foreach (Match m in allowPaths)
                            {
                                var fullPath = MakeAbsoluteUrl(target, m.Groups[1].Value);
                                OnLog?.Invoke($"   → Allow 路径: {fullPath}");
                                result.AllowPaths.Add(fullPath);
                            }
                            var sitemapUrls = Regex.Matches(content, @"Sitemap:\s*(\S+)", RegexOptions.IgnoreCase);
                            foreach (Match m in sitemapUrls)
                            {
                                OnLog?.Invoke($"   → Sitemap: {m.Groups[1].Value}");
                                result.SitemapUrls.Add(m.Groups[1].Value);
                            }
                        }
                    }
                }
                catch { }
            }

            if (result.FoundUrls.Count == 0)
            {
                OnLog?.Invoke("[第三层] 未发现敏感文件");
            }

            return result;
        }

        private static bool ValidateSensitiveContent(string filename, string content)
        {
            if (string.IsNullOrEmpty(content)) return false;

            return filename switch
            {
                ".git/HEAD" => content.StartsWith("ref: refs/") || content.StartsWith("ref: "),
                ".git/config" => content.Contains("[core]") || content.Contains("[remote"),
                "robots.txt" => content.Contains("User-agent") || content.Contains("Disallow") || content.Contains("Allow") || content.Contains("Sitemap"),
                "sitemap.xml" => content.Contains("<urlset") || content.Contains("<sitemap"),
                ".env" => content.Contains("=") && (content.Contains("DB_") || content.Contains("APP_") || content.Contains("SECRET") || content.Contains("KEY") || content.Contains("PASSWORD") || content.Contains("DATABASE")),
                "package.json" => content.Contains("\"name\"") && (content.Contains("\"version\"") || content.Contains("\"dependencies\"")),
                "composer.json" => content.Contains("\"name\"") && (content.Contains("\"require\"") || content.Contains("\"autoload\"")),
                "web.config" => content.Contains("<configuration") || content.Contains("<system.web"),
                "WEB-INF/web.xml" => content.Contains("<web-app") || content.Contains("<servlet"),
                "crossdomain.xml" => content.Contains("<cross-domain-policy"),
                "Dockerfile" => content.Contains("FROM ") || content.Contains("RUN ") || content.Contains("COPY "),
                "docker-compose.yml" => content.Contains("services:") || content.Contains("image:"),
                _ => true
            };
        }

        private async Task<DirectoryBruteResult> DirectoryBruteAsync(string target, CancellationToken ct, TechFingerprint? techStack = null, List<string>? extraPaths = null)
        {
            var result = new DirectoryBruteResult();
            OnLog?.Invoke("\n--- 目录爆破模式 ---");

            var baseUri = target.TrimEnd('/');

            OnLog?.Invoke("[目录爆破] 正在检测自定义404页面...");
            var (baselineLength, baselineSnippet, hasCustom404) = await ProbeCustom404Async(baseUri, ct);
            result.BaselineContentLength = baselineLength;
            result.HasCustom404 = hasCustom404;

            if (hasCustom404)
            {
                OnLog?.Invoke($"[目录爆破] ⚠️ 目标站点使用自定义404页面，将启用内容相似度过滤");
            }

            var dictList = _directoryDictionary.ToList();

            if (techStack != null)
            {
                var techSpecificPaths = GenerateTechSpecificPaths(techStack);
                foreach (var p in techSpecificPaths)
                {
                    if (!dictList.Contains(p))
                    {
                        dictList.Add(p);
                    }
                }
                if (techSpecificPaths.Count > 0)
                {
                    OnLog?.Invoke($"[目录爆破] 🔗 根据技术栈({techStack.BackendLanguage}/{techStack.Framework})新增 {techSpecificPaths.Count} 条针对性路径");
                }
            }

            if (extraPaths != null)
            {
                foreach (var p in extraPaths)
                {
                    if (!dictList.Contains(p))
                    {
                        dictList.Add(p);
                    }
                }
                if (extraPaths.Count > 0)
                {
                    OnLog?.Invoke($"[目录爆破] 🔗 合并后缀探测发现的 {extraPaths.Count} 条路径");
                }
            }

            var semaphore = new SemaphoreSlim(BruteConcurrency);
            var foundPaths = new ConcurrentBag<DiscoveredPath>();
            var testedCount = 0;

            var tasks = dictList.Select(async item =>
            {
                await semaphore.WaitAsync(ct);
                try
                {
                    if (ct.IsCancellationRequested) return;

                    var testUrl = $"{baseUri}/{item}";
                    try
                    {
                        var resp = await _httpClient.GetAsync(testUrl, ct);
                        Interlocked.Increment(ref testedCount);

                        var statusCode = (int)resp.StatusCode;
                        if (statusCode >= 200 && statusCode < 600)
                        {
                            var contentLength = resp.Content.Headers.ContentLength ?? 0;
                            string? title = null;
                            var confidence = 100;

                            if (statusCode >= 200 && statusCode < 400)
                            {
                                if (hasCustom404 && statusCode == 200)
                                {
                                    var body = await resp.Content.ReadAsStringAsync(ct);
                                    contentLength = body.Length;
                                    title = ExtractTitle(body);

                                    if (IsLikelyCustom404(body, contentLength, baselineLength, baselineSnippet))
                                    {
                                        confidence = 30;
                                        OnLog?.Invoke($"[目录爆破] ⚠️ 疑似自定义404: {testUrl} (内容相似, 置信度降低)");
                                    }
                                }
                                else if (statusCode == 200)
                                {
                                    try
                                    {
                                        var body = await resp.Content.ReadAsStringAsync(ct);
                                        contentLength = body.Length;
                                        title = ExtractTitle(body);
                                    }
                                    catch { }
                                }

                                if (statusCode == 403)
                                {
                                    confidence = 70;
                                    OnLog?.Invoke($"[目录爆破] 发现(403禁止): {testUrl}");
                                }

                                var path = new DiscoveredPath
                                {
                                    Url = testUrl,
                                    Source = "BruteForce",
                                    StatusCode = statusCode,
                                    PathType = ClassifyPath(testUrl),
                                    Confidence = confidence,
                                    ContentLength = contentLength,
                                    Title = title
                                };

                                foundPaths.Add(path);
                                if (confidence >= 50)
                                {
                                    OnLog?.Invoke($"[目录爆破] 发现: {testUrl} (HTTP {statusCode}, 置信度:{confidence}%)");
                                }
                            }
                        }
                    }
                    catch
                    {
                        Interlocked.Increment(ref testedCount);
                    }
                }
                finally
                {
                    semaphore.Release();
                }
            }).ToArray();

            await Task.WhenAll(tasks);

            result.TotalTested = testedCount;
            result.FoundPaths = foundPaths.Where(p => p.Confidence >= 30).ToList();

            result.ByStatusCode = result.FoundPaths
                .GroupBy(p => p.StatusCode)
                .ToDictionary(g => g.Key, g => g.ToList());

            var highConf = result.FoundPaths.Count(p => p.Confidence >= 70);
            var medConf = result.FoundPaths.Count(p => p.Confidence >= 50 && p.Confidence < 70);
            var lowConf = result.FoundPaths.Count(p => p.Confidence < 50);
            var status2xx = result.FoundPaths.Count(p => p.StatusCode >= 200 && p.StatusCode < 300);
            var status3xx = result.FoundPaths.Count(p => p.StatusCode >= 300 && p.StatusCode < 400);
            var status4xx = result.FoundPaths.Count(p => p.StatusCode >= 400 && p.StatusCode < 500);
            var status5xx = result.FoundPaths.Count(p => p.StatusCode >= 500);

            OnLog?.Invoke($"[目录爆破] 完成: 测试 {testedCount} 条, 发现 {result.FoundPaths.Count} 条路径");
            OnLog?.Invoke($"[目录爆破] 置信度分布: 高={highConf} 中={medConf} 低(疑似404)={lowConf}");
            OnLog?.Invoke($"[目录爆破] 状态码分布: 2xx={status2xx} 3xx={status3xx} 4xx={status4xx} 5xx={status5xx}");

            return result;
        }

        private async Task<DeepCrawlResult> DeepCrawlAsync(string target, CancellationToken ct, List<string>? seedUrls = null)
        {
            var result = new DeepCrawlResult
            {
                MaxDepth = MaxCrawlDepth
            };
            OnLog?.Invoke("\n--- 深度爬取模式 ---");

            var visited = new HashSet<string>();
            var queue = new Queue<(string Url, int Depth)>();
            var foundPaths = new List<DiscoveredPath>();
            var baseDomain = GetDomain(target);

            queue.Enqueue((target, 0));
            visited.Add(NormalizeUrl(target));

            if (seedUrls != null && seedUrls.Count > 0)
            {
                OnLog?.Invoke($"[深度爬取] 🔗 注入 {seedUrls.Count} 条Layer2发现的链接作为种子");
                foreach (var seed in seedUrls)
                {
                    var normalized = NormalizeUrl(seed);
                    if (!visited.Contains(normalized) && (!SameDomainOnly || GetDomain(seed) == baseDomain))
                    {
                        visited.Add(normalized);
                        queue.Enqueue((seed, 1));
                    }
                }
            }

            var keywordFilter = new[] { "login", "admin", "dashboard", "auth", "api", "signin", "oauth", "sso", "cas", "manage", "panel", "console", "config", "upload", "debug", "register", "signup", "password", "reset", "token", "key", "secret", "private", "user", "profile", "account", "setting", "system", "monitor", "status", "health", "swagger", "graphql", "actuator", "metrics" };

            while (queue.Count > 0 && !ct.IsCancellationRequested)
            {
                var (url, depth) = queue.Dequeue();

                if (depth > MaxCrawlDepth) continue;

                OnLog?.Invoke($"[深度爬取] 爬取第{depth}层: {url}");

                try
                {
                    var resp = await _httpClient.GetAsync(url, ct);
                    var html = await resp.Content.ReadAsStringAsync(ct);

                    result.CrawledUrls.Add(url);
                    result.TotalCrawled++;

                    var doc = new HtmlAgilityPack.HtmlDocument();
                    doc.LoadHtml(html);

                    var linkSelectors = new (string xpath, string attr)[]
                    {
                        ("//a[@href]", "href"),
                        ("//form[@action]", "action"),
                        ("//iframe[@src]", "src"),
                        ("//frame[@src]", "src"),
                        ("//link[@href]", "href"),
                        ("//script[@src]", "src"),
                        ("//area[@href]", "href"),
                        ("//img[@src]", "src"),
                        ("//source[@src]", "src"),
                        ("//embed[@src]", "src"),
                        ("//object[@data]", "data"),
                        ("//video[@src]", "src"),
                        ("//video[@poster]", "poster"),
                        ("//audio[@src]", "src"),
                    };

                    var dataAttrNodes = doc.DocumentNode.SelectNodes("//*[//@data-href or //@data-url or //@data-link or //@data-src]");
                    if (dataAttrNodes != null)
                    {
                        foreach (var node in dataAttrNodes)
                        {
                            var dataUrl = node.GetAttributeValue("data-href", "")
                                ?? node.GetAttributeValue("data-url", "")
                                ?? node.GetAttributeValue("data-link", "")
                                ?? node.GetAttributeValue("data-src", "");
                            if (!string.IsNullOrEmpty(dataUrl) && !dataUrl.StartsWith("#") && !dataUrl.StartsWith("javascript:"))
                            {
                                var fullUrl = MakeAbsoluteUrl(url, dataUrl);
                                var normalizedUrl = NormalizeUrl(fullUrl);
                                if (!visited.Contains(normalizedUrl))
                                {
                                    visited.Add(normalizedUrl);
                                    if (!SameDomainOnly || GetDomain(fullUrl) == baseDomain)
                                    {
                                        var isInteresting = keywordFilter.Any(kw => fullUrl.ToLower().Contains(kw));
                                        if (isInteresting)
                                        {
                                            foundPaths.Add(new DiscoveredPath
                                            {
                                                Url = fullUrl,
                                                Source = $"Crawl-D{depth}-dataAttr",
                                                StatusCode = 0,
                                                PathType = ClassifyPath(fullUrl)
                                            });
                                            OnLog?.Invoke($"[深度爬取] 发现data属性路径 → {fullUrl}");
                                        }
                                        if (depth < MaxCrawlDepth)
                                            queue.Enqueue((fullUrl, depth + 1));
                                    }
                                }
                            }
                        }
                    }

                    foreach (var (xpath, attr) in linkSelectors)
                    {
                        var nodes = doc.DocumentNode.SelectNodes(xpath);
                        if (nodes == null) continue;

                        foreach (var node in nodes)
                        {
                            var value = node.GetAttributeValue(attr, "");
                            if (string.IsNullOrEmpty(value) || value.StartsWith("#") || value.StartsWith("javascript:") || value.StartsWith("mailto:"))
                                continue;

                            var fullUrl = MakeAbsoluteUrl(url, value);
                            var normalizedUrl = NormalizeUrl(fullUrl);

                            if (SameDomainOnly && GetDomain(fullUrl) != baseDomain)
                                continue;

                            if (visited.Contains(normalizedUrl))
                                continue;

                            visited.Add(normalizedUrl);

                            var isInteresting = keywordFilter.Any(kw => fullUrl.ToLower().Contains(kw));
                            var discovered = new DiscoveredPath
                            {
                                Url = fullUrl,
                                Source = $"Crawl-D{depth}",
                                StatusCode = 0,
                                PathType = ClassifyPath(fullUrl)
                            };

                            if (isInteresting)
                            {
                                foundPaths.Add(discovered);
                                OnLog?.Invoke($"[深度爬取] 发现关键路径 → {fullUrl}");
                            }

                            if (depth < MaxCrawlDepth)
                            {
                                queue.Enqueue((fullUrl, depth + 1));
                            }
                        }
                    }
                }
                catch (Exception ex)
                {
                    OnLog?.Invoke($"[深度爬取] 爬取 {url} 失败: {ex.Message}");
                }
            }

            result.FoundPaths = foundPaths;

            var verifyPaths = foundPaths.Take(50).ToList();
            if (verifyPaths.Count > 0)
            {
                OnLog?.Invoke($"[深度爬取] 正在验证 {verifyPaths.Count} 条路径的状态码...");
                var verifySemaphore = new SemaphoreSlim(5);
                var verifiedPaths = new ConcurrentBag<DiscoveredPath>();

                var verifyTasks = verifyPaths.Select(async p =>
                {
                    await verifySemaphore.WaitAsync(ct);
                    try
                    {
                        try
                        {
                            var resp = await _httpClient.GetAsync(p.Url, HttpCompletionOption.ResponseHeadersRead, ct);
                            p.StatusCode = (int)resp.StatusCode;
                            p.ContentLength = resp.Content.Headers.ContentLength ?? 0;
                            if (resp.StatusCode == System.Net.HttpStatusCode.OK)
                            {
                                try
                                {
                                    var body = await resp.Content.ReadAsStringAsync(ct);
                                    p.ContentLength = body.Length;
                                    p.Title = ExtractTitle(body);
                                }
                                catch { }
                            }
                            verifiedPaths.Add(p);
                        }
                        catch
                        {
                            p.StatusCode = -1;
                            verifiedPaths.Add(p);
                        }
                    }
                    finally
                    {
                        verifySemaphore.Release();
                    }
                }).ToArray();
                await Task.WhenAll(verifyTasks);

                foreach (var vp in verifiedPaths)
                {
                    var existing = foundPaths.FirstOrDefault(p => p.Url == vp.Url);
                    if (existing != null)
                    {
                        existing.StatusCode = vp.StatusCode;
                        existing.ContentLength = vp.ContentLength;
                        existing.Title = vp.Title;
                    }
                }
            }

            OnLog?.Invoke($"[深度爬取] 完成: 爬取 {result.TotalCrawled} 页, 发现 {foundPaths.Count} 条关键路径");

            return result;
        }

        private string GetDomain(string url)
        {
            try
            {
                var uri = new Uri(url);
                return uri.Host.ToLower();
            }
            catch
            {
                return "";
            }
        }

        private string NormalizeUrl(string url)
        {
            try
            {
                var uri = new Uri(url);
                var normalized = $"{uri.Scheme}://{uri.Host}{uri.AbsolutePath}";
                if (!normalized.EndsWith("/"))
                    normalized += "/";
                return normalized.ToLower();
            }
            catch
            {
                return url.ToLower();
            }
        }

        private async Task<Layer4Result> CheckSeleniumDynamicRedirectAsync(string target, CancellationToken ct, List<CookieInfo>? cookies = null)
        {
            var result = new Layer4Result();
            OnLog?.Invoke("\n--- 第四层：Selenium动态跳转检测 ---");

            IWebDriver? driver = null;

            try
            {
                OnLog?.Invoke("[第四层] 正在启动Chrome浏览器（无头模式）...");

                var options = new ChromeOptions();
                options.AddArgument("--headless=new");
                options.AddArgument("--disable-gpu");
                options.AddArgument("--no-sandbox");
                options.AddArgument("--disable-dev-shm-usage");
                options.AddArgument("--disable-extensions");
                options.AddArgument("--disable-software-rasterizer");
                options.AddArgument("--ignore-certificate-errors");
                options.AddArgument("--ignore-ssl-errors=yes");
                options.AddArgument($"--user-agent={USER_AGENT}");
                options.AddArgument("--window-size=1920,1080");
                options.AddExcludedArgument("enable-logging");

                ChromeDriverService service;

                if (!string.IsNullOrEmpty(ChromeDriverPath) && File.Exists(ChromeDriverPath))
                {
                    service = ChromeDriverService.CreateDefaultService(
                        Path.GetDirectoryName(ChromeDriverPath),
                        Path.GetFileName(ChromeDriverPath));
                }
                else
                {
                    var autoDriverPath = await TryAutoMatchChromeDriverAsync();
                    if (autoDriverPath != null)
                    {
                        service = ChromeDriverService.CreateDefaultService(
                            Path.GetDirectoryName(autoDriverPath),
                            Path.GetFileName(autoDriverPath));
                    }
                    else
                    {
                        service = ChromeDriverService.CreateDefaultService();
                    }
                }

                service.HideCommandPromptWindow = true;
                service.SuppressInitialDiagnosticInformation = true;

                driver = new ChromeDriver(service, options);
                driver.Manage().Timeouts().PageLoad = TimeSpan.FromSeconds(30);
                driver.Manage().Timeouts().ImplicitWait = TimeSpan.FromSeconds(5);

                OnLog?.Invoke($"[第四层] 正在加载页面: {target}");

                var urlHistory = new List<string> { target };

                driver.Navigate().GoToUrl(target);
                result.InitialPageSource = driver.PageSource;
                result.InitialUrl = driver.Url;

                if (cookies != null && cookies.Count > 0)
                {
                    OnLog?.Invoke($"[第四层] 🔗 注入 {cookies.Count} 个Layer1发现的Cookie");
                    var targetUri = new Uri(target);
                    foreach (var cookie in cookies)
                    {
                        try
                        {
                            var seleniumCookie = new OpenQA.Selenium.Cookie(
                                cookie.Name,
                                cookie.IsSession ? "session" : "value",
                                string.IsNullOrEmpty(cookie.Domain) ? targetUri.Host : cookie.Domain,
                                string.IsNullOrEmpty(cookie.Path) ? "/" : cookie.Path,
                                null);
                            driver.Manage().Cookies.AddCookie(seleniumCookie);
                        }
                        catch (Exception ex)
                        {
                            OnLog?.Invoke($"[第四层] Cookie注入失败({cookie.Name}): {ex.Message}");
                        }
                    }
                    driver.Navigate().Refresh();
                    await Task.Delay(1000, ct);
                }

                await Task.Delay(2000, ct);

                var currentUrl = driver.Url;
                result.FinalUrl = currentUrl;
                urlHistory.Add(currentUrl);

                OnLog?.Invoke($"[第四层] 页面加载完成，当前URL: {currentUrl}");

                if (currentUrl != target)
                {
                    OnLog?.Invoke($"[第四层] ✅ 检测到URL变化!");
                    OnLog?.Invoke($"[第四层]   原始URL: {target}");
                    OnLog?.Invoke($"[第四层]   最终URL: {currentUrl}");
                    result.UrlChanged = true;
                    result.RedirectChain.AddRange(urlHistory);
                }

                var wait = new WebDriverWait(driver, TimeSpan.FromSeconds(10));

                try
                {
                    wait.Until(d =>
                    {
                        var url = d.Url;
                        if (url != currentUrl)
                        {
                            urlHistory.Add(url);
                            OnLog?.Invoke($"[第四层] 检测到延迟跳转 → {url}");
                            return true;
                        }
                        return false;
                    });

                    result.FinalUrl = driver.Url;
                    result.UrlChanged = true;
                    result.RedirectChain.AddRange(urlHistory);
                }
                catch (WebDriverTimeoutException)
                {
                    OnLog?.Invoke("[第四层] 等待期间未检测到延迟跳转");
                }

                try
                {
                    var finalSource = driver.PageSource;
                    result.FinalPageSource = finalSource;

                    var doc = new HtmlDocument();
                    doc.LoadHtml(finalSource);

                    var forms = doc.DocumentNode.SelectNodes("//form");
                    if (forms != null)
                    {
                        foreach (var form in forms)
                        {
                            var action = form.GetAttributeValue("action", "");
                            var method = form.GetAttributeValue("method", "get").ToUpper();
                            var inputs = form.SelectNodes(".//input");
                            var inputInfo = inputs != null
                                ? string.Join(", ", inputs.Select(i => $"{i.GetAttributeValue("name", "?")}({i.GetAttributeValue("type", "text")})"))
                                : "无";

                            var formInfo = $"Form[{method}] action={action} fields=[{inputInfo}]";
                            result.FoundForms.Add(formInfo);
                            OnLog?.Invoke($"[第四层] 发现表单: {formInfo}");
                        }
                    }

                    var iframes = doc.DocumentNode.SelectNodes("//iframe[@src] | //frame[@src]");
                    if (iframes != null)
                    {
                        foreach (var iframe in iframes)
                        {
                            var src = iframe.GetAttributeValue("src", "");
                            if (!string.IsNullOrEmpty(src))
                            {
                                var fullUrl = MakeAbsoluteUrl(currentUrl, src);
                                result.FoundIframes.Add(fullUrl);
                                OnLog?.Invoke($"[第四层] 发现iframe/frame: {fullUrl}");
                            }
                        }
                    }

                    var allLinks = doc.DocumentNode.SelectNodes("//a[@href]");
                    if (allLinks != null)
                    {
                        foreach (var link in allLinks)
                        {
                            var href = link.GetAttributeValue("href", "");
                            var text = link.InnerText.Trim();
                            if (!string.IsNullOrEmpty(href) && _loginKeywords.Any(kw => href.ToLower().Contains(kw) || text.ToLower().Contains(kw)))
                            {
                                var fullUrl = MakeAbsoluteUrl(currentUrl, href);
                                result.FoundDynamicLinks.Add(fullUrl);
                                OnLog?.Invoke($"[第四层] 动态页面登录链接: {fullUrl}");
                            }
                        }
                    }

                    var ajaxPatterns = new[]
                    {
                        @"fetch\s*\(\s*[""']([^""']+)[""']",
                        @"\$\.(?:get|post|ajax)\s*\(\s*[""']([^""']+)[""']",
                        @"XMLHttpRequest.*?open\s*\(\s*[""']GET[""']\s*,\s*[""']([^""']+)[""']",
                        @"axios\.(?:get|post)\s*\(\s*[""']([^""']+)[""']",
                    };

                    var allScripts = doc.DocumentNode.SelectNodes("//script");
                    if (allScripts != null)
                    {
                        foreach (var script in allScripts)
                        {
                            var scriptText = script.InnerText;
                            if (string.IsNullOrEmpty(scriptText)) continue;

                            foreach (var p in ajaxPatterns)
                            {
                                foreach (Match m in Regex.Matches(scriptText, p, RegexOptions.IgnoreCase))
                                {
                                    var ajaxUrl = MakeAbsoluteUrl(currentUrl, m.Groups[1].Value);
                                    result.FoundAjaxCalls.Add(ajaxUrl);
                                    OnLog?.Invoke($"[第四层] 发现AJAX请求: {ajaxUrl}");
                                }
                            }
                        }
                    }
                }
                catch (Exception ex)
                {
                    OnLog?.Invoke($"[第四层] 页面深度分析失败: {ex.Message}");
                }

                try
                {
                    try
                    {
                        var screenshot = ((ITakesScreenshot)driver).GetScreenshot();
                        var screenshotsDir = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "screenshots");
                        Directory.CreateDirectory(screenshotsDir);
                        var safeName = Regex.Replace(new Uri(target).Host, @"[^a-zA-Z0-9]", "_");
                        var timestamp = DateTime.Now.ToString("yyyyMMdd_HHmmss");
                        var screenshotPath = Path.Combine(screenshotsDir, $"{safeName}_{timestamp}.png");
                        screenshot.SaveAsFile(screenshotPath);
                        result.ScreenshotPath = screenshotPath;
                        OnLog?.Invoke($"[第四层] 📷 页面截图已保存: {Path.GetFileName(screenshotPath)}");
                    }
                    catch
                    {
                    }

                    var logs = driver.Manage().Logs.GetLog(LogType.Browser);
                    foreach (var log in logs)
                    {
                        if (log.Level == LogLevel.Severe || log.Message.Contains("redirect") || log.Message.Contains("location"))
                        {
                            result.ConsoleLogs.Add($"[{log.Level}] {log.Message}");
                        }
                    }
                    if (result.ConsoleLogs.Count > 0)
                    {
                        OnLog?.Invoke($"[第四层] 捕获到 {result.ConsoleLogs.Count} 条相关控制台日志");
                    }
                }
                catch { }

                if (!result.UrlChanged && result.FoundForms.Count == 0 && result.FoundIframes.Count == 0 && result.FoundDynamicLinks.Count == 0)
                {
                    OnLog?.Invoke("[第四层] Selenium动态检测未发现跳转或隐藏路径");
                }
            }
            catch (OperationCanceledException)
            {
                OnLog?.Invoke("[第四层] 检测已取消");
                throw;
            }
            catch (Exception ex)
            {
                OnLog?.Invoke($"[第四层] Selenium检测失败: {ex.Message}");
                OnLog?.Invoke("[第四层] 提示: 请确保已安装Chrome浏览器，或尝试关闭Selenium检测");
                result.Error = ex.Message;
            }
            finally
            {
                try
                {
                    driver?.Quit();
                    driver?.Dispose();
                }
                catch { }
            }

            return result;
        }

        private async Task<string?> TryAutoMatchChromeDriverAsync()
        {
            try
            {
                var chromeVersion = GetInstalledChromeVersion();
                if (string.IsNullOrEmpty(chromeVersion))
                {
                    OnLog?.Invoke("[ChromeDriver] 未检测到本地Chrome安装");
                    return null;
                }

                OnLog?.Invoke($"[ChromeDriver] 检测到Chrome版本: {chromeVersion}");

                var parts = chromeVersion.Split('.');
                if (parts.Length < 1) return null;
                var majorVersion = parts[0];

                var currentDriverDir = Path.GetDirectoryName(Assembly.GetExecutingAssembly().Location);
                if (string.IsNullOrEmpty(currentDriverDir)) return null;

                var existingDriver = Path.Combine(currentDriverDir, "chromedriver.exe");
                if (File.Exists(existingDriver))
                {
                    try
                    {
                        var driverVersion = GetChromeDriverVersion(existingDriver);
                        if (!string.IsNullOrEmpty(driverVersion) && driverVersion.Split('.')[0] == majorVersion)
                        {
                            OnLog?.Invoke($"[ChromeDriver] 内置驱动版本匹配: {driverVersion}");
                            return existingDriver;
                        }
                    }
                    catch { }
                }

                OnLog?.Invoke($"[ChromeDriver] 正在自动下载匹配版本 {chromeVersion}...");

                var downloadUrl = $"https://storage.googleapis.com/chrome-for-testing-public/{chromeVersion}/win64/chromedriver-win64.zip";
                var tempDir = Path.Combine(Path.GetTempPath(), $"chromedriver_{Guid.NewGuid():N}");
                Directory.CreateDirectory(tempDir);

                try
                {
                    var zipPath = Path.Combine(tempDir, "chromedriver.zip");
                    using (var handler = new HttpClientHandler
                    {
                        ServerCertificateCustomValidationCallback = (msg, cert, chain, errors) => true
                    })
                    using (var client = new HttpClient(handler) { Timeout = TimeSpan.FromSeconds(60) })
                    {
                        var bytes = await client.GetByteArrayAsync(downloadUrl);
                        await File.WriteAllBytesAsync(zipPath, bytes);
                    }

                    ZipFile.ExtractToDirectory(zipPath, tempDir);

                    var extractedDriver = Directory.GetFiles(tempDir, "chromedriver.exe", SearchOption.AllDirectories).FirstOrDefault();
                    if (extractedDriver != null)
                    {
                        var destDriver = Path.Combine(currentDriverDir, "chromedriver.exe");
                        File.Copy(extractedDriver, destDriver, true);
                        OnLog?.Invoke($"[ChromeDriver] 自动下载完成: {destDriver}");
                        return destDriver;
                    }
                }
                catch (Exception ex)
                {
                    OnLog?.Invoke($"[ChromeDriver] 自动下载失败: {ex.Message}");
                }
                finally
                {
                    try
                    {
                        if (Directory.Exists(tempDir))
                            Directory.Delete(tempDir, true);
                    }
                    catch { }
                }
            }
            catch (Exception ex)
            {
                OnLog?.Invoke($"[ChromeDriver] 自动匹配失败: {ex.Message}");
            }

            return null;
        }

        private string? GetInstalledChromeVersion()
        {
            var paths = new[]
            {
                @"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Google Chrome",
                @"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\Google Chrome",
            };

            foreach (var regPath in paths)
            {
                try
                {
                    using var key = Registry.LocalMachine.OpenSubKey(regPath);
                    if (key?.GetValue("version") is string version)
                        return version;
                }
                catch { }

                try
                {
                    using var key = Registry.CurrentUser.OpenSubKey(regPath);
                    if (key?.GetValue("version") is string version)
                        return version;
                }
                catch { }
            }

            var chromePaths = new[]
            {
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "Google", "Chrome", "Application", "chrome.exe"),
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86), "Google", "Chrome", "Application", "chrome.exe"),
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Google", "Chrome", "Application", "chrome.exe"),
            };

            foreach (var chromePath in chromePaths)
            {
                if (File.Exists(chromePath))
                {
                    try
                    {
                        var versionInfo = System.Diagnostics.FileVersionInfo.GetVersionInfo(chromePath);
                        return versionInfo.FileVersion;
                    }
                    catch { }
                }
            }

            return null;
        }

        private string? GetChromeDriverVersion(string driverPath)
        {
            try
            {
                var psi = new System.Diagnostics.ProcessStartInfo
                {
                    FileName = driverPath,
                    Arguments = "--version",
                    RedirectStandardOutput = true,
                    UseShellExecute = false,
                    CreateNoWindow = true
                };
                using var process = System.Diagnostics.Process.Start(psi);
                if (process == null) return null;
                var output = process.StandardOutput.ReadToEnd();
                process.WaitForExit(5000);
                var match = Regex.Match(output, @"(\d+\.\d+\.\d+\.\d+)");
                return match.Success ? match.Groups[1].Value : null;
            }
            catch
            {
                return null;
            }
        }

        private TechFingerprint FingerprintTech(HttpResponseMessage resp, string html)
        {
            var fp = new TechFingerprint();

            if (resp.Headers.TryGetValues("Server", out var serverValues))
            {
                fp.Server = serverValues.FirstOrDefault() ?? "";
                fp.DetectedTechs.Add($"Server:{fp.Server}");

                var s = fp.Server.ToLower();
                if (s.Contains("nginx")) fp.DetectedTechs.Add("Nginx");
                if (s.Contains("apache")) fp.DetectedTechs.Add("Apache");
                if (s.Contains("iis")) { fp.DetectedTechs.Add("IIS"); fp.BackendLanguage = "ASP.NET"; }
                if (s.Contains("tomcat")) { fp.DetectedTechs.Add("Tomcat"); fp.BackendLanguage = "Java"; }
                if (s.Contains("express")) { fp.DetectedTechs.Add("Express"); fp.BackendLanguage = "Node.js"; fp.Framework = "Express"; }
                if (s.Contains("gunicorn")) { fp.DetectedTechs.Add("Gunicorn"); fp.BackendLanguage = "Python"; }
                if (s.Contains("uvicorn")) { fp.DetectedTechs.Add("Uvicorn"); fp.BackendLanguage = "Python"; }
                if (s.Contains("php")) fp.BackendLanguage = "PHP";
                if (s.Contains("openresty")) fp.DetectedTechs.Add("OpenResty");
                if (s.Contains("caddy")) fp.DetectedTechs.Add("Caddy");
                if (s.Contains("cloudflare")) fp.DetectedTechs.Add("Cloudflare");
                if (s.Contains("akamai")) fp.DetectedTechs.Add("Akamai");
            }

            if (resp.Headers.TryGetValues("X-Powered-By", out var poweredByValues))
            {
                fp.XPoweredBy = poweredByValues.FirstOrDefault() ?? "";
                fp.DetectedTechs.Add($"X-Powered-By:{fp.XPoweredBy}");

                var p = fp.XPoweredBy.ToLower();
                if (p.Contains("asp.net")) { fp.BackendLanguage = "ASP.NET"; fp.Framework = "ASP.NET"; }
                if (p.Contains("express")) { fp.BackendLanguage = "Node.js"; fp.Framework = "Express"; }
                if (p.Contains("php")) fp.BackendLanguage = "PHP";
                if (p.Contains("next")) { fp.Framework = "Next.js"; fp.DetectedTechs.Add("Next.js"); }
                if (p.Contains("nuxt")) { fp.Framework = "Nuxt.js"; fp.DetectedTechs.Add("Nuxt.js"); }
            }

            if (resp.Headers.TryGetValues("X-AspNet-Version", out _))
            {
                fp.BackendLanguage = "ASP.NET";
                fp.DetectedTechs.Add("ASP.NET");
            }

            if (resp.Headers.Contains("X-Request-ID") || resp.Headers.Contains("X-Runtime"))
            {
                fp.DetectedTechs.Add("Rails");
                fp.BackendLanguage = "Ruby";
                fp.Framework = "Ruby on Rails";
            }

            if (!string.IsNullOrEmpty(html))
            {
                var lower = html.ToLower();
                if (lower.Contains("__viewstate")) { fp.BackendLanguage = "ASP.NET"; fp.DetectedTechs.Add("ASP.NET WebForms"); }
                if (lower.Contains("__requestverificationtoken")) { fp.BackendLanguage = "ASP.NET"; fp.DetectedTechs.Add("ASP.NET MVC"); }
                if (lower.Contains("wp-content") || lower.Contains("wp-includes")) { fp.Cms = "WordPress"; fp.DetectedTechs.Add("WordPress"); fp.BackendLanguage = "PHP"; }
                if (lower.Contains("sites/default/files")) { fp.Cms = "Drupal"; fp.DetectedTechs.Add("Drupal"); fp.BackendLanguage = "PHP"; }
                if (lower.Contains("/media/com_")) { fp.Cms = "Joomla"; fp.DetectedTechs.Add("Joomla"); fp.BackendLanguage = "PHP"; }
                if (lower.Contains("next-route-worker")) { fp.Framework = "Next.js"; fp.DetectedTechs.Add("Next.js"); fp.BackendLanguage = "Node.js"; }
                if (lower.Contains("__nuxt")) { fp.Framework = "Nuxt.js"; fp.DetectedTechs.Add("Nuxt.js"); }
                if (lower.Contains("ng-version")) { fp.Framework = "Angular"; fp.DetectedTechs.Add("Angular"); }
                if (lower.Contains("data-reactroot") || lower.Contains("__next")) { fp.DetectedTechs.Add("React"); }
                if (lower.Contains("data-v-")) { fp.DetectedTechs.Add("Vue.js"); }
                if (lower.Contains("django")) { fp.BackendLanguage = "Python"; fp.Framework = "Django"; fp.DetectedTechs.Add("Django"); }
                if (lower.Contains("laravel")) { fp.BackendLanguage = "PHP"; fp.Framework = "Laravel"; fp.DetectedTechs.Add("Laravel"); }
                if (lower.Contains("symfony")) { fp.BackendLanguage = "PHP"; fp.Framework = "Symfony"; fp.DetectedTechs.Add("Symfony"); }
                if (lower.Contains("spring")) { fp.BackendLanguage = "Java"; fp.Framework = "Spring"; fp.DetectedTechs.Add("Spring"); }
                if (lower.Contains("flask")) { fp.BackendLanguage = "Python"; fp.Framework = "Flask"; fp.DetectedTechs.Add("Flask"); }
                if (lower.Contains("fastapi")) { fp.BackendLanguage = "Python"; fp.Framework = "FastAPI"; fp.DetectedTechs.Add("FastAPI"); }
            }

            return fp;
        }

        private static CookieInfo ParseCookie(string cookieStr)
        {
            var parts = cookieStr.Split(';');
            var cookie = new CookieInfo();
            if (parts.Length > 0)
            {
                var nameValue = parts[0].Trim();
                var eqIdx = nameValue.IndexOf('=');
                cookie.Name = eqIdx > 0 ? nameValue.Substring(0, eqIdx).Trim() : nameValue;
                var value = eqIdx > 0 ? nameValue.Substring(eqIdx + 1).Trim() : "";
                cookie.IsSession = string.IsNullOrEmpty(value) || value.ToLower() == "session";
            }
            for (int i = 1; i < parts.Length; i++)
            {
                var part = parts[i].Trim().ToLower();
                if (part.StartsWith("domain=")) cookie.Domain = parts[i].Trim().Substring(7);
                if (part.StartsWith("path=")) cookie.Path = parts[i].Trim().Substring(5);
                if (part == "secure") cookie.Secure = true;
                if (part == "httponly") cookie.HttpOnly = true;
            }
            return cookie;
        }

        private async Task<List<OpenRedirectFinding>> DetectOpenRedirectsAsync(string targetUrl, CancellationToken ct)
        {
            var findings = new List<OpenRedirectFinding>();
            var redirectParams = new[] { "redirect", "url", "next", "return", "returnTo", "goto", "dest",
                "destination", "redir", "redirect_url", "redirect_uri", "continue", "callback",
                "return_url", "forward", "target", "rurl", "referrer", "jump", "jump_url",
                "link", "go", "out", "exit", "ref", "source", "site", "to" };
            var testPayload = "https://evil.example.com/test";

            var uri = new Uri(targetUrl);
            var baseUrl = $"{uri.Scheme}://{uri.Host}{uri.AbsolutePath}";

            foreach (var param in redirectParams)
            {
                if (ct.IsCancellationRequested) break;

                var testUrl = $"{baseUrl}?{param}={Uri.EscapeDataString(testPayload)}";
                try
                {
                    var handler = new HttpClientHandler
                    {
                        AllowAutoRedirect = false,
                        ServerCertificateCustomValidationCallback = (msg, cert, chain, errors) => true
                    };
                    using var client = new HttpClient(handler) { Timeout = TimeSpan.FromSeconds(5) };
                    client.DefaultRequestHeaders.Add("User-Agent", USER_AGENT);

                    var resp = await client.GetAsync(testUrl, ct);
                    if ((int)resp.StatusCode >= 300 && (int)resp.StatusCode < 400)
                    {
                        var location = resp.Headers.Location?.ToString() ?? "";
                        if (location.Contains("evil.example.com"))
                        {
                            findings.Add(new OpenRedirectFinding
                            {
                                Parameter = param,
                                TestUrl = testUrl,
                                RedirectedTo = location,
                                IsVulnerable = true
                            });
                            OnLog?.Invoke($"[开放重定向] ⚠️ 参数 {param} 存在开放重定向漏洞!");
                        }
                    }
                }
                catch { }
            }

            return findings;
        }

        private async Task<SuffixProbeResult> ProbeSuffixesAsync(string target, TechFingerprint? techStack, CancellationToken ct)
        {
            var result = new SuffixProbeResult();
            var baseUri = target.TrimEnd('/');

            var tech = techStack?.BackendLanguage?.ToLower() ?? "";
            var framework = techStack?.Framework?.ToLower() ?? "";
            var server = techStack?.Server?.ToLower() ?? "";
            var cms = techStack?.Cms?.ToLower() ?? "";

            var suffixes = new List<string>();

            if (tech == "php" || cms == "wordpress" || cms == "drupal" || cms == "joomla" || server.Contains("apache"))
            {
                suffixes.AddRange(new[] { ".php", ".php5", ".phtml" });
                result.DetectedTech = "PHP";
            }
            if (tech == "asp.net" || server.Contains("iis"))
            {
                suffixes.AddRange(new[] { ".aspx", ".asmx", ".ashx", ".asp" });
                result.DetectedTech = "ASP.NET";
            }
            if (tech == "java" || framework.Contains("spring") || server.Contains("tomcat"))
            {
                suffixes.AddRange(new[] { ".jsp", ".do", ".action" });
                result.DetectedTech = "Java";
            }
            if (tech == "python" || framework.Contains("django") || framework.Contains("flask") || framework.Contains("fastapi"))
            {
                result.DetectedTech = "Python";
            }
            if (tech == "node.js" || framework.Contains("express") || framework.Contains("next"))
            {
                result.DetectedTech = "Node.js";
            }
            if (tech == "ruby" || framework.Contains("rails"))
            {
                suffixes.AddRange(new[] { ".rb", ".erb" });
                result.DetectedTech = "Ruby";
            }

            if (suffixes.Count == 0)
            {
                suffixes.AddRange(new[] { ".php", ".aspx", ".jsp", ".html", ".json", ".xml" });
                result.DetectedTech = "Unknown(全量探测)";
            }

            var commonPaths = new[] { "admin", "login", "dashboard", "config", "api", "user", "upload", "search", "index", "home" };
            var testPaths = new List<string>();
            foreach (var path in commonPaths)
            {
                foreach (var suffix in suffixes.Distinct())
                {
                    testPaths.Add($"{path}{suffix}");
                }
            }

            result.ProbedSuffixes = testPaths;

            OnLog?.Invoke($"[后缀探测] 技术栈: {result.DetectedTech}, 测试后缀: {string.Join(", ", suffixes.Distinct())}");

            var (baselineLength, baselineSnippet, hasCustom404) = await ProbeCustom404Async(baseUri, ct);

            var semaphore = new SemaphoreSlim(BruteConcurrency);
            var foundPaths = new ConcurrentBag<DiscoveredPath>();

            var tasks = testPaths.Select(async item =>
            {
                await semaphore.WaitAsync(ct);
                try
                {
                    if (ct.IsCancellationRequested) return;
                    var testUrl = $"{baseUri}/{item}";
                    try
                    {
                        var resp = await _httpClient.GetAsync(testUrl, ct);
                        var statusCode = (int)resp.StatusCode;
                        if (statusCode >= 200 && statusCode < 400)
                        {
                            var confidence = 100;
                            string? title = null;
                            var contentLength = 0L;

                            if (statusCode == 200 && hasCustom404)
                            {
                                var body = await resp.Content.ReadAsStringAsync(ct);
                                contentLength = body.Length;
                                title = ExtractTitle(body);
                                if (IsLikelyCustom404(body, contentLength, baselineLength, baselineSnippet))
                                {
                                    confidence = 30;
                                }
                            }
                            else if (statusCode == 200)
                            {
                                try
                                {
                                    var body = await resp.Content.ReadAsStringAsync(ct);
                                    contentLength = body.Length;
                                    title = ExtractTitle(body);
                                }
                                catch { }
                            }

                            if (statusCode == 403) confidence = 70;

                            var path = new DiscoveredPath
                            {
                                Url = testUrl,
                                Source = $"SuffixProbe-{result.DetectedTech}",
                                StatusCode = statusCode,
                                PathType = ClassifyPath(testUrl),
                                Confidence = confidence,
                                ContentLength = contentLength,
                                Title = title
                            };
                            foundPaths.Add(path);
                            if (confidence >= 50)
                            {
                                OnLog?.Invoke($"[后缀探测] 发现: {testUrl} (HTTP {statusCode}, 置信度:{confidence}%)");
                            }
                        }
                    }
                    catch { }
                }
                finally
                {
                    semaphore.Release();
                }
            }).ToArray();

            await Task.WhenAll(tasks);

            result.FoundPaths = foundPaths.Where(p => p.Confidence >= 30).ToList();
            OnLog?.Invoke($"[后缀探测] 完成: 测试 {testPaths.Count} 条, 发现 {result.FoundPaths.Count} 条路径");

            return result;
        }

        private static string ClassifyLink(string href, string text)
        {
            var lower = (href + " " + text).ToLower();
            if (lower.Contains("login") || lower.Contains("sign in") || lower.Contains("登录")) return "login";
            if (lower.Contains("admin") || lower.Contains("manage") || lower.Contains("管理")) return "admin";
            if (lower.Contains("api") || lower.Contains("swagger")) return "api";
            if (lower.Contains("doc") || lower.Contains("help") || lower.Contains("文档")) return "docs";
            if (lower.Contains("download") || lower.Contains("下载")) return "download";
            if (lower.Contains("register") || lower.Contains("signup") || lower.Contains("注册")) return "register";
            if (lower.Contains("contact") || lower.Contains("联系")) return "contact";
            if (lower.Contains("about") || lower.Contains("关于")) return "about";
            if (lower.Contains("search") || lower.Contains("搜索")) return "search";
            return "navigation";
        }

        private static WafDetection DetectWaf(HttpResponseMessage resp, string html)
        {
            var detection = new WafDetection();
            var indicators = new List<string>();

            foreach (var header in resp.Headers.Concat(resp.Content.Headers))
            {
                var hName = header.Key.ToLower();
                var hVal = string.Join(", ", header.Value).ToLower();

                if (hName.Contains("cf-") || hName == "cf-ray" || hName == "cf-cache-status")
                { detection.WafName = "Cloudflare"; indicators.Add($"Header: {header.Key}"); }
                else if (hName.Contains("x-sucuri") || hName.Contains("x-sucuri-id") || hVal.Contains("sucuri"))
                { detection.WafName = "Sucuri"; indicators.Add($"Header: {header.Key}"); }
                else if (hName.Contains("x-akamai") || hName == "akamai-origin-hop")
                { detection.WafName = "Akamai"; indicators.Add($"Header: {header.Key}"); }
                else if (hName.Contains("x-aws") || hName == "x-amz-cf-id")
                { detection.WafName = "AWS CloudFront"; indicators.Add($"Header: {header.Key}"); }
                else if (hName.Contains("x-fastly") || hName == "fastly-debug-digest")
                { detection.WafName = "Fastly"; indicators.Add($"Header: {header.Key}"); }
                else if (hName == "server" && (hVal.Contains("cloudflare") || hVal.Contains("ddos-guard") || hVal.Contains("incapsula") || hVal.Contains("imperva")))
                { detection.WafName = hVal.Contains("cloudflare") ? "Cloudflare" : hVal.Contains("incapsula") ? "Imperva Incapsula" : "DDOS-Guard"; indicators.Add($"Server: {hVal}"); }
                else if (hName.Contains("x-stackpath"))
                { detection.WafName = "StackPath"; indicators.Add($"Header: {header.Key}"); }
                else if (hName.Contains("x-vercel"))
                { detection.WafName = "Vercel"; indicators.Add($"Header: {header.Key}"); }
                else if (hName.Contains("x-nitro") || hName.Contains("x-kinsta"))
                { detection.WafName = "Kinsta CDN"; indicators.Add($"Header: {header.Key}"); }
                else if (hName.Contains("x-fortiwaf") || hName.Contains("forti"))
                { detection.WafName = "FortiWeb"; indicators.Add($"Header: {header.Key}"); }
                else if (hName.Contains("x-citrix") || hName.Contains("x-ctxs"))
                { detection.WafName = "Citrix WAF"; indicators.Add($"Header: {header.Key}"); }
                else if (hName == "x-request-id" && hVal.Contains("-"))
                { }
            }

            if (!detection.IsBehindWaf && !string.IsNullOrEmpty(html))
            {
                var lower = html.ToLower();
                if (lower.Contains("cloudflare") || lower.Contains("challenges.cloudflare") || lower.Contains("ray id"))
                { detection.WafName = "Cloudflare"; indicators.Add("HTML内容包含Cloudflare特征"); }
                else if (lower.Contains("incapsula") || lower.Contains("incapsula incident id"))
                { detection.WafName = "Imperva Incapsula"; indicators.Add("HTML内容包含Incapsula特征"); }
                else if (lower.Contains("attention required") || lower.Contains("ddos protection"))
                { detection.WafName = "CDN/Anti-DDoS"; indicators.Add("检测到DDoS保护页面"); }
                else if (lower.Contains("sucuri") || lower.Contains("sucuri website firewall"))
                { detection.WafName = "Sucuri"; indicators.Add("HTML内容包含Sucuri特征"); }
            }

            detection.IsBehindWaf = !string.IsNullOrEmpty(detection.WafName);
            detection.Indicators = indicators;
            detection.DetectionMethod = indicators.Count > 0 ? $"{indicators.Count}个特征" : "Header分析";
            return detection;
        }

        private static List<ApiEndpoint> DiscoverApiEndpoints(string html, string baseUrl)
        {
            var apis = new List<ApiEndpoint>();
            if (string.IsNullOrEmpty(html)) return apis;

            var doc = new HtmlAgilityPack.HtmlDocument();
            doc.LoadHtml(html);
            var lower = html.ToLower();

            var swaggerLinks = doc.DocumentNode.SelectNodes("//a[@href]");
            if (swaggerLinks != null)
            {
                foreach (var link in swaggerLinks)
                {
                    var href = link.GetAttributeValue("href", "").ToLower();
                    if (href.Contains("swagger") || href.Contains("swagger-ui") || href.Contains("api-docs") || href.Contains("openapi") || href.Contains("redoc") || href.Contains("graphiql") || href.Contains("graphql-playground") || href.Contains("stoplight"))
                    {
                        apis.Add(new ApiEndpoint
                        {
                            Url = href.StartsWith("http") ? href : new Uri(new Uri(baseUrl), href).ToString(),
                            Type = href.Contains("graphql") || href.Contains("graphiql") || href.Contains("playground") ? "GraphQL" : "OpenAPI/Swagger",
                            Description = "API文档/测试界面",
                            IsInteractive = true
                        });
                    }
                }
            }

            if (lower.Contains("\"endpoints\"") || lower.Contains("\"paths\"") || lower.Contains("\"api\""))
            {
                var apiPathPatterns = new[]
                {
                    @"/api/v\d+", @"/api/v\d+/\w+", @"/rest", @"/rest/v\d+",
                    @"/graphql", @"/graphqli", @"/graphql/schema",
                    @"/soap", @"/wsdl", @"/api-docs",
                    @"/actuator", @"/actuator/\w+"
                };
                foreach (var pattern in apiPathPatterns)
                {
                    foreach (Match m in Regex.Matches(html, pattern, RegexOptions.IgnoreCase))
                    {
                        var url = m.Value.StartsWith("/") ? new Uri(new Uri(baseUrl), m.Value).ToString() : m.Value;
                        if (!apis.Any(a => a.Url == url))
                        {
                            apis.Add(new ApiEndpoint
                            {
                                Url = url,
                                Type = pattern.Contains("graphql") || pattern.Contains("graphqli") ? "GraphQL" :
                                       pattern.Contains("soap") || pattern.Contains("wsdl") ? "SOAP" :
                                       pattern.Contains("actuator") ? "Spring Actuator" : "REST API",
                                Description = "API端点"
                            });
                        }
                    }
                }
            }

            if (lower.Contains("json") || lower.Contains("rest") || lower.Contains("api"))
            {
                var scriptSrc = doc.DocumentNode.SelectNodes("//script[@src]");
                if (scriptSrc != null)
                {
                    foreach (var script in scriptSrc)
                    {
                        var src = script.GetAttributeValue("src", "");
                        if (src.Contains("/api/") || src.Contains("_api") || src.Contains("api.js") || src.Contains("api.min.js"))
                        {
                            apis.Add(new ApiEndpoint
                            {
                                Url = src,
                                Type = "API Client",
                                Description = "API客户端脚本"
                            });
                        }
                    }
                }
            }

            return apis;
        }

        private static List<string> DiscoverSubdomains(string html, string baseDomain)
        {
            var subdomains = new HashSet<string>();
            if (string.IsNullOrEmpty(html)) return subdomains.ToList();

            var matches = Regex.Matches(html, @"(?:https?://)?([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+" + Regex.Escape(baseDomain), RegexOptions.IgnoreCase);
            foreach (Match m in matches)
            {
                var subdomain = m.Groups[1].Value.TrimEnd('.');
                if (!string.IsNullOrEmpty(subdomain) && subdomain != "www" && subdomain != baseDomain)
                {
                    subdomains.Add(subdomain + "." + baseDomain);
                }
            }

            var cnames = Regex.Matches(html, @"(?:src|href|action|url)\s*[=:]\s*['""]?(https?://)?([a-zA-Z0-9\-\.]+\." + Regex.Escape(baseDomain) + @")[/'""\s]", RegexOptions.IgnoreCase);
            foreach (Match m in cnames)
            {
                var subdomain = m.Groups[2].Value;
                if (!string.IsNullOrEmpty(subdomain) && subdomain != "www." + baseDomain && subdomain != baseDomain)
                {
                    subdomains.Add(subdomain);
                }
            }

            return subdomains.ToList();
        }

        private static List<string> DetectParamVulnerabilities(string html, string baseUrl)
        {
            var hints = new List<string>();
            if (string.IsNullOrEmpty(html)) return hints;

            var doc = new HtmlAgilityPack.HtmlDocument();
            doc.LoadHtml(html);
            var lower = html.ToLower();

            if (lower.Contains("sql") || lower.Contains("database") || lower.Contains("query"))
                hints.Add("页面包含数据库/SQL相关内容，可能存在SQL注入点");

            if (lower.Contains("search") || lower.Contains("filter") || lower.Contains("sort"))
            {
                var forms = doc.DocumentNode.SelectNodes("//form[@method='get']");
                if (forms != null && forms.Count > 0)
                    hints.Add($"检测到{forms.Count}个GET表单，可能存在参数注入点(SQL/XSS)");
            }

            var searchInputs = doc.DocumentNode.SelectNodes("//input[@type='search'] | //input[contains(@name,'search')] | //input[contains(@name,'query')] | //input[contains(@name,'q')]");
            if (searchInputs != null && searchInputs.Count > 0)
                hints.Add($"检测到{searchInputs.Count}个搜索框，存在搜索注入风险");

            var fileInputs = doc.DocumentNode.SelectNodes("//input[@type='file']");
            if (fileInputs != null && fileInputs.Count > 0)
            {
                hints.Add($"检测到{fileInputs.Count}个文件上传点，存在文件上传漏洞风险");
            }

            var passInputs = doc.DocumentNode.SelectNodes("//input[@type='password']");
            if (passInputs != null && passInputs.Count > 0)
                hints.Add($"检测到{passInputs.Count}个密码输入框，存在认证相关漏洞风险");

            if (lower.Contains("debug") || lower.Contains("?debug=true") || lower.Contains("mode=debug"))
                hints.Add("页面包含调试相关参数，可能暴露敏感信息");

            if (lower.Contains("eval") || lower.Contains("executenonquery") || lower.Contains("executereader"))
                hints.Add("页面代码可能包含不安全的数据库操作");

            return hints;
        }

        private string MakeAbsoluteUrl(string baseUrl, string relativeUrl)
        {
            if (string.IsNullOrEmpty(relativeUrl)) return baseUrl;
            if (relativeUrl.StartsWith("http://") || relativeUrl.StartsWith("https://")) return relativeUrl;

            try
            {
                var baseUri = new Uri(baseUrl);
                return new Uri(baseUri, relativeUrl).ToString();
            }
            catch
            {
                return relativeUrl;
            }
        }

        private async Task<(long contentLength, string contentSnippet, bool isCustom404)> ProbeCustom404Async(string baseUrl, CancellationToken ct)
        {
            var randomPaths = new[]
            {
                $"/this_page_definitely_does_not_exist_{Guid.NewGuid():N}.html",
                $"/nonexistent_{Guid.NewGuid():N}",
                $"/404test_{Guid.NewGuid():N}.asp",
            };

            var contentLengths = new List<long>();
            var contentSnippets = new List<string>();
            var statusCodes = new List<int>();

            foreach (var randomPath in randomPaths)
            {
                try
                {
                    var testUrl = baseUrl.TrimEnd('/') + randomPath;
                    var resp = await _httpClient.GetAsync(testUrl, HttpCompletionOption.ResponseHeadersRead, ct);
                    var body = await resp.Content.ReadAsStringAsync(ct);
                    contentLengths.Add(body.Length);
                    statusCodes.Add((int)resp.StatusCode);
                    contentSnippets.Add(body.Length > 500 ? body.Substring(0, 500) : body);
                }
                catch { }
            }

            if (contentLengths.Count == 0) return (0, "", false);

            var hasCustom404 = statusCodes.Any(s => s == 200);
            var avgLength = contentLengths.Count > 0 ? (long)contentLengths.Average() : 0;
            var snippet = contentSnippets.FirstOrDefault() ?? "";

            if (hasCustom404)
            {
                OnLog?.Invoke($"[假阳性检测] 检测到自定义404页面(随机路径返回200)，平均内容长度: {avgLength}");
            }

            return (avgLength, snippet, hasCustom404);
        }

        private bool IsLikelyCustom404(string content, long contentLength, long baselineLength, string baselineSnippet)
        {
            if (baselineLength <= 0) return false;

            if (contentLength > 0 && baselineLength > 0)
            {
                var ratio = (double)contentLength / baselineLength;
                if (ratio is >= 0.85 and <= 1.15) return true;
            }

            if (!string.IsNullOrEmpty(baselineSnippet) && !string.IsNullOrEmpty(content))
            {
                var baselineWords = ExtractKeyWords(baselineSnippet);
                var contentWords = ExtractKeyWords(content.Length > 500 ? content.Substring(0, 500) : content);
                if (baselineWords.Count > 0 && contentWords.Count > 0)
                {
                    var overlap = baselineWords.Intersect(contentWords).Count();
                    var similarity = (double)overlap / Math.Max(baselineWords.Count, contentWords.Count);
                    if (similarity > 0.7) return true;
                }
            }

            return false;
        }

        private static HashSet<string> ExtractKeyWords(string text)
        {
            var words = Regex.Matches(text.ToLower(), @"[a-z\u4e00-\u9fff]{3,}");
            var stopWords = new HashSet<string> { "the", "and", "for", "are", "but", "not", "you", "all", "can", "had", "her", "was", "one", "our", "out", "has", "have", "this", "that", "with", "from", "they", "been", "said", "each", "which", "their", "will", "other", "about", "many", "then", "them", "these", "some", "would", "make", "like", "into", "time", "very", "when", "come", "could", "more", "over", "such", "after", "also", "than" };
            return words.Select(m => m.Value).Where(w => !stopWords.Contains(w)).Take(50).ToHashSet();
        }

        private static string? ExtractTitle(string html)
        {
            try
            {
                var match = Regex.Match(html, @"<title[^>]*>(.*?)</title>", RegexOptions.IgnoreCase | RegexOptions.Singleline);
                return match.Success ? match.Groups[1].Value.Trim() : null;
            }
            catch { return null; }
        }
    }
}
