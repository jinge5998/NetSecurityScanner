using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;

namespace NetSecurityScanner.Services
{
    public enum TraceMode
    {
        Quick,
        Standard,
        Deep
    }

    public class PathSegment
    {
        public string Segment { get; set; } = "";
        public int Depth { get; set; }
        public string? ParentPath { get; set; }
    }

    public class PathStep
    {
        public string Url { get; set; } = "";
        public int StatusCode { get; set; }
        public string? LocationHeader { get; set; }
        public string? Referer { get; set; }
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
        public int Depth { get; set; }
        public string? ParentPath { get; set; }
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
        public List<PathStep> PathChain { get; set; } = new();
        public List<TraceChainStep> TraceChain { get; set; } = new();
        public Layer1Result? Layer1Results { get; set; }
        public Layer2Result? Layer2Results { get; set; }
        public Layer3Result? Layer3Results { get; set; }
        public Layer4Result? Layer4Results { get; set; }
        public DirectoryBruteResult? BruteResults { get; set; }
        public DeepCrawlResult? CrawlResults { get; set; }
        public PathSegmentResult? PathSegmentResults { get; set; }
        public BruteForceResult BruteForceResult { get; set; } = new();
        public RobotsTxtResult RobotsTxtResult { get; set; } = new();
        public List<string> SitemapUrls { get; set; } = new();
        public List<DiscoveredPath> AllDiscoveredPaths { get; set; } = new();
        public List<string> SensitivePaths { get; set; } = new();
        public bool FoundPath => FinalUrl != null || AllDiscoveredPaths.Count > 0;
    }

    public class PathSegmentResult
    {
        public string BaseUrl { get; set; } = "";
        public List<PathSegment> Segments { get; set; } = new();
        public List<DiscoveredPath> FoundPaths { get; set; } = new();
        public List<string> PathPatterns { get; set; } = new();
    }

    public class Layer1Result
    {
        public int StatusCode { get; set; }
        public Dictionary<string, string> Headers { get; set; } = new();
        public string? FoundUrl { get; set; }
        public string? Error { get; set; }
        public List<PathStep> PathChain { get; set; } = new();
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
        public PageContentAnalysis? PageContent { get; set; }
        public SslCertificateInfo? SslCertificate { get; set; }
    }

    public class PageContentAnalysis
    {
        public string Title { get; set; } = "";
        public string Description { get; set; } = "";
        public List<string> Keywords { get; set; } = new();
        public string? Generator { get; set; }
        public string? Author { get; set; }
        public string? Language { get; set; }
        public string? Charset { get; set; }
        public string ContentType { get; set; } = "";
        public long ContentLength { get; set; }
        public int WordCount { get; set; }
        public int LinkCount { get; set; }
        public int ImageCount { get; set; }
        public int FormCount { get; set; }
        public int ScriptCount { get; set; }
        public int StyleCount { get; set; }
        public string? FaviconUrl { get; set; }
        public string? CanonicalUrl { get; set; }
        public List<string> OpenGraphTags { get; set; } = new();
        public string CmsDetected { get; set; } = "";
        public string FrameworkDetected { get; set; } = "";
        public Dictionary<string, string> MetaTags { get; set; } = new();
    }

    public class PathRiskAssessment
    {
        public string Url { get; set; } = "";
        public int StatusCode { get; set; }
        public string RiskLevel { get; set; } = "";
        public int RiskScore { get; set; }
        public List<string> RiskFactors { get; set; } = new();
        public List<string> Recommendations { get; set; } = new();
    }

    public class SslCertificateInfo
    {
        public string Subject { get; set; } = "";
        public string Issuer { get; set; } = "";
        public string? ValidFrom { get; set; }
        public string? ValidTo { get; set; }
        public bool IsValid { get; set; }
        public bool IsSelfSigned { get; set; }
        public bool IsExpired { get; set; }
        public int? DaysUntilExpiry { get; set; }
        public string? SignatureAlgorithm { get; set; }
        public int? KeySize { get; set; }
        public List<string> Warnings { get; set; } = new();
        public string? SerialNumber { get; set; }
        public string? Version { get; set; }
        public List<string> SubjectAlternativeNames { get; set; } = new();
        public string? ProtocolVersion { get; set; }
        public string? CipherSuite { get; set; }
        public bool SupportsTls12 { get; set; }
        public bool SupportsTls13 { get; set; }
        public bool HasWeakCipher { get; set; }
        public string? PublicKeyAlgorithm { get; set; }
        public bool IsRevoked { get; set; }
        public string? CrlDistributionPoints { get; set; }
        public string? OcspResponderUrl { get; set; }
    }

    public class SecurityAuditResult
    {
        public int OverallScore { get; set; } // 0-100, 100 = most secure
        public List<SecurityFinding> Findings { get; set; } = new();
        public List<string> PassedChecks { get; set; } = new();
        public List<string> FailedChecks { get; set; } = new();
    }

    public class SecurityFinding
    {
        public string Title { get; set; } = "";
        public string Severity { get; set; } = ""; // Critical/High/Medium/Low/Info
        public string Description { get; set; } = "";
        public string Recommendation { get; set; } = "";
        public string? CveId { get; set; }
        public string? ReferenceUrl { get; set; }
    }

    public class TechVulnerabilityInfo
    {
        public string Technology { get; set; } = "";
        public string Version { get; set; } = "";
        public List<CveInfo> KnownVulnerabilities { get; set; } = new();
    }

    public class CveInfo
    {
        public string CveId { get; set; } = "";
        public string Severity { get; set; } = "";
        public string Description { get; set; } = "";
        public double? CvssScore { get; set; }
        public string? PublishedDate { get; set; }
        public string? FixVersion { get; set; }
    }

    public class WebPortScanResult
    {
        public string Host { get; set; } = "";
        public List<WebPortInfo> OpenPorts { get; set; } = new();
        public int TotalScanned { get; set; }
        public TimeSpan ScanDuration { get; set; }
    }

    public class WebPortInfo
    {
        public int Port { get; set; }
        public string Service { get; set; } = "";
        public bool IsOpen { get; set; }
        public string? Banner { get; set; }
        public TimeSpan ResponseTime { get; set; }
    }

    public class ApiTestResult
    {
        public string Url { get; set; } = "";
        public string Method { get; set; } = "";
        public int StatusCode { get; set; }
        public bool IsAccessible { get; set; }
        public string? ResponsePreview { get; set; }
        public List<string> AllowedMethods { get; set; } = new();
    }

    public class TraceReport
    {
        public string GeneratedAt { get; set; } = DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss");
        public string TargetUrl { get; set; } = "";
        public string? FinalUrl { get; set; }
        public TraceMode Mode { get; set; }
        public TimeSpan Duration { get; set; }
        public int TotalPathsDiscovered { get; set; }
        public int SensitivePathsCount { get; set; }
        public List<PathRiskAssessment> RiskAssessments { get; set; } = new();
        public WebPathTraceResult FullResult { get; set; } = new();
        public string? ReportSummary { get; set; }
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
        public List<string> ScriptFiles { get; set; } = new();
        public List<string> InternalResources { get; set; } = new();
        public List<string> RestfulParams { get; set; } = new();
        public List<string> FoundForms { get; set; } = new();
        public List<string> FoundIframes { get; set; } = new();
        public List<string> DiscoveredAjaxCalls { get; set; } = new();
    }

    public class BruteForceResult
    {
        public List<DiscoveredPath> FoundPaths { get; set; } = new();
        public int TotalChecked { get; set; }
        public DateTime StartTime { get; set; } = DateTime.Now;
        public DateTime EndTime { get; set; }
        public TimeSpan Duration => EndTime - StartTime;
    }

    public class RobotsTxtResult
    {
        public bool Exists { get; set; }
        public string Content { get; set; } = string.Empty;
        public List<string> Paths { get; set; } = new();
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
        private const string USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36";

        private static readonly string[] SENSITIVE_PARAMS = { "token", "session_id", "password", "passwd", "secret", "key", "api_key", "access_token", "refresh_token" };
        private static readonly string[] SENSITIVE_PATHS = { "admin", "login", "register", "api", "config", "debug", "test", "backup", "db", "database", "temp", "tmp", "upload", "download", "manage", "dashboard", "console", "panel", "settings", "profile", "account", "user", "users", "auth", "oauth", "sso", "ldap", "cert", "certificate", "ssl", "private", "secret", "hidden", "internal", "dev", "development", "staging", "prod", "production" };

        private static readonly List<string> CommonPaths = new List<string>
        {
            "admin", "admin/", "administrator", "login", "login/", "login.php", "admin.php",
            "auth", "auth/login", "signin", "signin/", "wp-login.php", "wp-admin", "console",
            "dashboard", "manage", "manager", "control", "controlpanel", "cpanel",

            "api", "api/", "api/v1", "api/v2", "api/v3", "api/docs", "api/swagger", "rest", "rest/",
            "graphql", "graphql/playground", "graphiql", "api/graphql",

            "config", "configuration", "settings", "options", "preferences",
            "docs", "documentation", "api-docs", "swagger", "swagger-ui", "swagger-ui.html",
            "openapi.json", "openapi.yaml", "swagger.json", "swagger.yaml",

            "user", "users", "user/", "users/", "profile", "profiles", "account", "accounts",
            "register", "signup", "sign-up", "registration", "forgot-password", "reset-password",
            "password", "password/reset", "verify", "confirm",

            "cms", "content", "contents", "posts", "post/", "articles", "article/", "blog", "blog/",
            "news", "page", "pages", "media", "images", "uploads", "upload", "file", "files",
            "download", "downloads", "document", "documents",

            "search", "search/", "query", "query/", "find", "api/search",
            "products", "product/", "shop", "store", "cart", "checkout", "order", "orders",
            "checkout", "payment", "payments", "transaction", "transactions",

            "data", "database", "db", "sql", "backup", "backups", "dump", "export", "import",
            "status", "health", "health/", "info", "info/", "metrics", "monitor", "stats",

            "test", "tests/", "testing/", "dev", "development", "debug", "debug/", "trace",
            "error", "errors", "exception", "exceptions", "log", "logs", "server-status",

            "index", "index.html", "index.htm", "index.php", "default", "default.aspx", "home",
            "robots.txt", "sitemap.xml", "sitemap.xml", ".htaccess", "web.config",
            "crossdomain.xml", "clientaccesspolicy.xml",

            "readme", "readme.md", "README.md", "LICENSE", "license.txt", "CHANGELOG",
            "version", "version.json", "api/version", "info.json", "info.xml",

            "shell", "webshell", "cmd", "command", "execute", "eval", "phpinfo",

            "actuator", "actuator/health", "actuator/info", "env", "heapdump", "threaddump",
            ".git", ".git/config", ".git/HEAD", ".svn", ".env", ".env.backup",

            "old", "new", "v1", "v2", "v3", "beta", "test", "staging", "demo",
            "backup", "back", "bak", "temp", "tmp", "tmp/", "cache", "static",

            "oauth", "oauth/authorize", "oauth/token", "oauth2", "oauth2/authorize", "oauth2/token",
            "openid", "openid-connect", ".well-known/openid-configuration",

            "mail", "email", "webmail", "smtp", "pop", "imap",

            "wp-json", "wp-json/wp/v2", "xmlrpc.php", "wp-cron", "wp-content",
            "/.env", "/api/index.php/v1", "/user/login", "/api/"
        };

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
        public bool SameDomainOnly { get; set; } = true;
        public TraceMode Mode { get; set; } = TraceMode.Standard;
        public string? ChromeDriverPath { get; set; }
        public int MaxCrawlDepth { get; set; } = 2;
        public int BruteConcurrency { get; set; } = 10;
        public int RequestDelayMs { get; set; } = 100;

        private async Task DelayAsync(CancellationToken cancellationToken)
        {
            if (RequestDelayMs > 0)
            {
                try { await Task.Delay(RequestDelayMs, cancellationToken); } catch { }
            }
        }

        public async Task<List<ApiTestResult>> TestApiEndpoints(List<ApiEndpoint> endpoints, string baseUrl, CancellationToken cancellationToken = default)
        {
            var results = new List<ApiTestResult>();
            var testMethods = new[] { "GET", "POST", "PUT", "DELETE", "OPTIONS", "HEAD" };

            foreach (var endpoint in endpoints.Take(20))
            {
                if (cancellationToken.IsCancellationRequested) break;

                var testUrl = endpoint.Url.StartsWith("http") ? endpoint.Url : $"{baseUrl.TrimEnd('/')}/{endpoint.Url.TrimStart('/')}";
                
                foreach (var method in testMethods)
                {
                    try
                    {
                        using var request = new HttpRequestMessage(new HttpMethod(method), testUrl);
                        request.Headers.Add("Accept", "application/json");
                        request.Headers.Add("User-Agent", USER_AGENT);

                        using var response = await _httpClient.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, cancellationToken);
                        var content = await response.Content.ReadAsStringAsync();

                        var preview = content.Length > 200 ? content.Substring(0, 200) + "..." : content;

                        results.Add(new ApiTestResult
                        {
                            Url = testUrl,
                            Method = method,
                            StatusCode = (int)response.StatusCode,
                            IsAccessible = response.IsSuccessStatusCode,
                            ResponsePreview = preview,
                            AllowedMethods = new List<string>()
                        });

                        if (method == "OPTIONS" && response.Headers.Contains("Allow"))
                        {
                            var allowHeader = response.Headers.GetValues("Allow").FirstOrDefault();
                            if (!string.IsNullOrEmpty(allowHeader))
                            {
                                results.Last().AllowedMethods = allowHeader.Split(',').Select(m => m.Trim()).ToList();
                            }
                        }

                        OnLog?.Invoke($"🔗 API测试 [{method}] {testUrl} -> {(int)response.StatusCode}");
                    }
                    catch (Exception ex)
                    {
                        results.Add(new ApiTestResult
                        {
                            Url = testUrl,
                            Method = method,
                            StatusCode = 0,
                            IsAccessible = false,
                            ResponsePreview = $"错误: {ex.Message}"
                        });
                    }
                }
            }

            return results;
        }

        public async Task<BruteForceResult> BruteForcePathsAsync(string baseUrl, CancellationToken cancellationToken = default)
        {
            var result = new BruteForceResult();
            result.StartTime = DateTime.Now;
            try
            {
                var uri = new Uri(baseUrl);
                var baseAuthority = uri.GetLeftPart(UriPartial.Authority);

                OnLog?.Invoke($"开始路径爆破: {baseAuthority}");

                foreach (var path in CommonPaths)
                {
                    if (cancellationToken.IsCancellationRequested)
                        break;

                    var testUrl = baseAuthority + "/" + path.TrimStart('/');

                    try
                    {
                        await DelayAsync(cancellationToken);

                        using var request = new HttpRequestMessage(HttpMethod.Head, testUrl);
                        request.Headers.UserAgent.ParseAdd("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36");

                        var response = await _httpClient.SendAsync(request, cancellationToken);
                        var statusCode = (int)response.StatusCode;

                        if (statusCode >= 200 && statusCode < 400)
                        {
                            result.FoundPaths.Add(new DiscoveredPath
                            {
                                Url = testUrl,
                                Source = "brute_force",
                                StatusCode = statusCode,
                                Confidence = 90,
                                PathType = ClassifyPathType(path)
                            });
                            OnLog?.Invoke($"路径发现: [{statusCode}] {testUrl}");
                        }
                        else if (statusCode == 403 || statusCode == 401)
                        {
                            result.FoundPaths.Add(new DiscoveredPath
                            {
                                Url = testUrl,
                                Source = "brute_force",
                                StatusCode = statusCode,
                                Confidence = 75,
                                PathType = ClassifyPathType(path)
                            });
                            OnLog?.Invoke($"受限路径: [{statusCode}] {testUrl}");
                        }

                        result.TotalChecked++;
                    }
                    catch { result.TotalChecked++; }
                }

                result.EndTime = DateTime.Now;
                OnLog?.Invoke($"路径爆破完成 - 检查: {result.TotalChecked}, 发现: {result.FoundPaths.Count}");
            }
            catch (Exception ex)
            {
                result.EndTime = DateTime.Now;
                OnLog?.Invoke($"路径爆破失败: {ex.Message}");
            }

            return result;
        }

        public async Task<RobotsTxtResult> GetRobotsTxtAsync(string baseUrl, CancellationToken cancellationToken = default)
        {
            var result = new RobotsTxtResult();
            try
            {
                var uri = new Uri(baseUrl);
                var robotsUrl = uri.GetLeftPart(UriPartial.Authority) + "/robots.txt";

                var response = await _httpClient.GetAsync(robotsUrl, cancellationToken);
                if (response.StatusCode == System.Net.HttpStatusCode.OK)
                {
                    var content = await response.Content.ReadAsStringAsync(cancellationToken);
                    result.Content = content;
                    result.Exists = true;

                    var lines = content.Split('\n');
                    foreach (var line in lines)
                    {
                        if (line.StartsWith("Disallow:") || line.StartsWith("Allow:"))
                        {
                            var path = line.Split(':').Last().Trim();
                            result.Paths.Add(path);
                        }
                    }

                    OnLog?.Invoke($"发现 robots.txt: {result.Paths.Count} 条规则");
                }
            }
            catch { }

            return result;
        }

        public async Task<List<string>> GetSitemapAsync(string baseUrl, CancellationToken cancellationToken = default)
        {
            var urls = new List<string>();
            try
            {
                var uri = new Uri(baseUrl);
                var sitemapUrl = uri.GetLeftPart(UriPartial.Authority) + "/sitemap.xml";

                var response = await _httpClient.GetAsync(sitemapUrl, cancellationToken);
                if (response.StatusCode == System.Net.HttpStatusCode.OK)
                {
                    var content = await response.Content.ReadAsStringAsync(cancellationToken);

                    var urlMatches = Regex.Matches(content, @"<loc>\s*([^<]+)\s*</loc>", RegexOptions.IgnoreCase);
                    foreach (Match match in urlMatches)
                    {
                        urls.Add(match.Groups[1].Value.Trim());
                    }

                    OnLog?.Invoke($"发现 sitemap.xml: {urls.Count} 个URL");
                }
            }
            catch { }

            return urls;
        }

        private string ClassifyPathType(string path)
        {
            var pathLower = path.ToLower();

            if (pathLower.Contains("admin") || pathLower.Contains("login") || pathLower.Contains("auth"))
                return "admin";
            if (pathLower.Contains("api") || pathLower.Contains("rest") || pathLower.Contains("graphql"))
                return "api";
            if (pathLower.Contains("swagger") || pathLower.Contains("openapi") || pathLower.Contains("docs"))
                return "api_docs";
            if (pathLower.Contains("user") || pathLower.Contains("account") || pathLower.Contains("profile"))
                return "user";
            if (pathLower.Contains("product") || pathLower.Contains("shop") || pathLower.Contains("order"))
                return "ecommerce";
            if (pathLower.Contains("file") || pathLower.Contains("upload") || pathLower.Contains("media"))
                return "file";
            if (pathLower.Contains("config") || pathLower.Contains("setting") || pathLower.Contains(".env"))
                return "config";
            if (pathLower.Contains(".git") || pathLower.Contains(".svn") || pathLower.Contains("backup"))
                return "sensitive";
            if (pathLower.Contains("actuator") || pathLower.Contains("health") || pathLower.Contains("status"))
                return "monitoring";
            if (pathLower.Contains("test") || pathLower.Contains("debug") || pathLower.Contains("dev"))
                return "dev";

            return "unknown";
        }

        public async Task<WebPathTraceResult> TraceAsync(string targetUrl, CancellationToken cancellationToken = default)
        {
            var stopwatch = System.Diagnostics.Stopwatch.StartNew();
            var result = new WebPathTraceResult
            {
                OriginalUrl = targetUrl,
                Mode = Mode
            };

            OnLog?.Invoke($"开始路径追踪: {targetUrl}");
            OnLog?.Invoke($"模式: {Mode}");

            try
            {
                var desensitizedUrl = DesensitizeUrl(targetUrl);
                OnLog?.Invoke($"脱敏后URL: {desensitizedUrl}");

                await DelayAsync(cancellationToken);

                // 第一层：HTTP请求探测（重定向追踪）
                var layer1Result = await Layer1TraceAsync(targetUrl, cancellationToken);
                result.Layer1Results = layer1Result;
                result.FinalUrl = layer1Result.FoundUrl;
                result.PathChain = layer1Result.PathChain;

                if (layer1Result.Error == null)
                {
                    var baseUri = new Uri(layer1Result.FoundUrl ?? targetUrl).GetLeftPart(UriPartial.Authority);

                    var pathSegments = await AnalyzePathSegmentsAsync(targetUrl, cancellationToken);
                    result.PathSegmentResults = pathSegments;
                    OnLog?.Invoke($"路径段分析: 发现 {pathSegments.Segments.Count} 个路径段");

                    if (result.Layer1Results?.TechStack != null)
                    {
                        var techPaths = GuessPathsFromTechStack(result.Layer1Results.TechStack, baseUri);
                        foreach (var tp in techPaths)
                        {
                            try
                            {
                                await DelayAsync(cancellationToken);
                                var response = await _httpClient.GetAsync(tp.Url, cancellationToken);
                                if ((int)response.StatusCode == 200)
                                {
                                    result.AllDiscoveredPaths.Add(new DiscoveredPath
                                    {
                                        Url = tp.Url,
                                        Source = "tech_guess",
                                        StatusCode = 200,
                                        Confidence = 85,
                                        PathType = tp.Type
                                    });
                                    OnLog?.Invoke($"技术栈路径发现: {tp.Url}");
                                }
                            }
                            catch { }
                        }
                    }

                    result.AllDiscoveredPaths.AddRange(pathSegments.FoundPaths);

                    var layer2Result = await Layer2TraceAsync(targetUrl, cancellationToken);
                    result.Layer2Results = layer2Result;
                    if (layer2Result.FoundUrl != null)
                        result.FinalUrl = layer2Result.FoundUrl;

                    if (Mode != TraceMode.Quick)
                    {
                        // 第三层：安全检测
                        var layer3Result = await Layer3TraceAsync(targetUrl, cancellationToken);
                        result.Layer3Results = layer3Result;

                        // 目录爆破
                        if (EnableBrute)
                        {
                            var bruteResult = await DirectoryBruteAsync(targetUrl, cancellationToken);
                            result.BruteResults = bruteResult;
                            OnLog?.Invoke($"目录爆破: 测试 {bruteResult.TotalTested} 个路径，发现 {bruteResult.FoundPaths.Count} 个有效路径");
                        }

                        // 深度爬取
                        if (EnableCrawl && Mode == TraceMode.Deep)
                        {
                            var crawlResult = await DeepCrawlAsync(targetUrl, cancellationToken);
                            result.CrawlResults = crawlResult;
                        }
                    }

                    // 敏感路径检测
                    var sensitivePaths = DetectSensitivePaths(result);
                    result.SensitivePaths = sensitivePaths;
                    if (sensitivePaths.Count > 0)
                    {
                        OnLog?.Invoke($"敏感路径检测: 发现 {sensitivePaths.Count} 个敏感路径");
                    }

                    // 汇总所有发现的路径
                    if (result.BruteResults != null)
                    {
                        result.AllDiscoveredPaths.AddRange(result.BruteResults.FoundPaths);
                    }
                    if (result.CrawlResults != null)
                    {
                        result.AllDiscoveredPaths.AddRange(result.CrawlResults.FoundPaths);
                    }

                    OnLog?.Invoke($"路径链摘要: {result.PathChain.Count} 步");
                    OnLog?.Invoke($"发现路径总数: {result.AllDiscoveredPaths.Count}");

                    if (result.AllDiscoveredPaths.Count < 10)
                    {
                        OnLog?.Invoke("基础追踪发现路径较少，启用路径爆破...");
                        result.BruteForceResult = await BruteForcePathsAsync(targetUrl, cancellationToken);
                        result.AllDiscoveredPaths.AddRange(result.BruteForceResult.FoundPaths);
                    }

                    result.RobotsTxtResult = await GetRobotsTxtAsync(targetUrl, cancellationToken);
                    if (result.RobotsTxtResult.Exists)
                    {
                        foreach (var path in result.RobotsTxtResult.Paths)
                        {
                            var fullUrl = new Uri(new Uri(targetUrl), path).ToString();
                            result.AllDiscoveredPaths.Add(new DiscoveredPath
                            {
                                Url = fullUrl,
                                Source = "robots_txt",
                                StatusCode = 0,
                                Confidence = 60,
                                PathType = "disallow"
                            });
                        }
                    }

                    result.SitemapUrls = await GetSitemapAsync(targetUrl, cancellationToken);
                    foreach (var url in result.SitemapUrls)
                    {
                        result.AllDiscoveredPaths.Add(new DiscoveredPath
                        {
                            Url = url,
                            Source = "sitemap",
                            StatusCode = 0,
                            Confidence = 95,
                            PathType = "content"
                        });
                    }

                    OnLog?.Invoke($"最终发现路径总数: {result.AllDiscoveredPaths.Count}");

                    // 生成报告
                    stopwatch.Stop();
                    var report = GenerateReport(result, stopwatch.Elapsed);
                    OnLog?.Invoke($"报告生成: {report.ReportSummary}");
                }

                OnLog?.Invoke($"路径追踪完成 - 最终URL: {result.FinalUrl}");
            }
            catch (Exception ex)
            {
                OnLog?.Invoke($"追踪错误: {ex.Message}");
            }

            return result;
        }

        public static string DesensitizeUrl(string url)
        {
            try
            {
                if (!Uri.TryCreate(url, UriKind.Absolute, out var uriObj))
                    return url;

                var builder = new UriBuilder(uriObj);
                var query = uriObj.Query.TrimStart('?');
                if (string.IsNullOrEmpty(query))
                    return url;

                var queryParams = System.Web.HttpUtility.ParseQueryString(query);
                foreach (var key in queryParams.AllKeys)
                {
                    if (key != null && SENSITIVE_PARAMS.Any(sp => key.IndexOf(sp, StringComparison.OrdinalIgnoreCase) >= 0))
                    {
                        queryParams.Remove(key);
                    }
                }

                var hash = uriObj.Fragment;
                if (hash.Contains('?'))
                {
                    var hashParts = hash.Split('?');
                    var hashQuery = System.Web.HttpUtility.ParseQueryString(hashParts[1]);
                    foreach (var key in hashQuery.AllKeys)
                    {
                        if (key != null && SENSITIVE_PARAMS.Any(sp => key.IndexOf(sp, StringComparison.OrdinalIgnoreCase) >= 0))
                        {
                            hashQuery.Remove(key);
                        }
                    }
                    var newHash = hashParts[0];
                    if (hashQuery.Count > 0)
                    {
                        newHash += "?" + hashQuery.ToString();
                    }
                    hash = newHash;
                }

                var newQuery = queryParams.ToString();
                if (!string.IsNullOrEmpty(newQuery))
                {
                    builder.Query = newQuery;
                }

                return builder.Uri.ToString();
            }
            catch
            {
                return url;
            }
        }

        public PathSegmentResult AnalyzePathSegments(string url)
        {
            var result = new PathSegmentResult { BaseUrl = url };
            try
            {
                var uri = new Uri(url);
                var path = uri.AbsolutePath.Trim('/');
                if (string.IsNullOrEmpty(path))
                    return result;

                var segments = path.Split('/');
                var currentPath = uri.GetLeftPart(UriPartial.Authority);

                for (int i = 0; i < segments.Length; i++)
                {
                    if (string.IsNullOrEmpty(segments[i])) continue;

                    currentPath += "/" + segments[i];
                    result.Segments.Add(new PathSegment
                    {
                        Segment = segments[i],
                        Depth = i + 1,
                        ParentPath = i > 0 ? currentPath.Substring(0, currentPath.LastIndexOf('/')) : currentPath
                    });

                    result.PathPatterns.Add(currentPath);
                }
            }
            catch (Exception ex)
            {
                OnLog?.Invoke($"路径段分析失败: {ex.Message}");
            }

            return result;
        }

        public async Task<PathSegmentResult> AnalyzePathSegmentsAsync(string url, CancellationToken cancellationToken = default)
        {
            var result = new PathSegmentResult { BaseUrl = url };
            try
            {
                var uri = new Uri(url);
                var path = uri.AbsolutePath.Trim('/');
                if (string.IsNullOrEmpty(path))
                {
                    result.FoundPaths.Add(new DiscoveredPath
                    {
                        Url = url,
                        Source = "root_path",
                        StatusCode = 200,
                        Confidence = 100
                    });
                    return result;
                }

                var segments = path.Split('/');
                var baseAuthority = uri.GetLeftPart(UriPartial.Authority);
                var currentPath = baseAuthority;

                for (int i = 0; i < segments.Length; i++)
                {
                    if (string.IsNullOrEmpty(segments[i])) continue;

                    currentPath += "/" + segments[i];
                    result.Segments.Add(new PathSegment
                    {
                        Segment = segments[i],
                        Depth = i + 1,
                        ParentPath = i > 0 ? currentPath.Substring(0, currentPath.LastIndexOf('/')) : currentPath
                    });
                    result.PathPatterns.Add(currentPath);

                    try
                    {
                        await DelayAsync(cancellationToken);
                        var response = await _httpClient.GetAsync(currentPath, cancellationToken);
                        var statusCode = (int)response.StatusCode;
                        var contentLength = response.Content.Headers.ContentLength ?? 0;

                        if (statusCode == 200 || statusCode == 301 || statusCode == 302)
                        {
                            result.FoundPaths.Add(new DiscoveredPath
                            {
                                Url = currentPath,
                                Source = "path_segment",
                                StatusCode = statusCode,
                                Confidence = statusCode == 200 ? 95 : 80,
                                PathType = segments[i],
                                ContentLength = contentLength,
                                Depth = i + 1
                            });
                            OnLog?.Invoke($"路径段可访问: [{statusCode}] {currentPath}");
                        }
                        else if (statusCode == 403)
                        {
                            result.FoundPaths.Add(new DiscoveredPath
                            {
                                Url = currentPath,
                                Source = "path_segment",
                                StatusCode = 403,
                                Confidence = 70,
                                PathType = segments[i],
                                ContentLength = contentLength,
                                Depth = i + 1
                            });
                        }
                    }
                    catch { }
                }
            }
            catch (Exception ex)
            {
                OnLog?.Invoke($"路径段分析失败: {ex.Message}");
            }

            return result;
        }

        public List<string> DetectSensitivePaths(WebPathTraceResult result)
        {
            var sensitive = new List<string>();
            var allPaths = new List<string>();

            if (result.PathSegmentResults?.PathPatterns != null)
                allPaths.AddRange(result.PathSegmentResults.PathPatterns);

            if (result.Layer2Results?.AllLinks != null)
                allPaths.AddRange(result.Layer2Results.AllLinks.Select(l => l.Url));

            if (result.Layer3Results?.FoundUrls != null)
                allPaths.AddRange(result.Layer3Results.FoundUrls);

            if (result.BruteResults?.FoundPaths != null)
                allPaths.AddRange(result.BruteResults.FoundPaths.Select(p => p.Url));

            foreach (var path in allPaths.Distinct())
            {
                try
                {
                    var uri = new Uri(path.StartsWith("http") ? path : (result.OriginalUrl.EndsWith("/") ? result.OriginalUrl + path : result.OriginalUrl + "/" + path));
                    var pathPart = uri.AbsolutePath.ToLower();

                    if (SENSITIVE_PATHS.Any(sp => pathPart.Contains("/" + sp)))
                    {
                        sensitive.Add(path);
                    }
                }
                catch { }
            }

            return sensitive.Distinct().ToList();
        }

        private async Task<Layer1Result> Layer1TraceAsync(string url, CancellationToken cancellationToken)
        {
            OnLog?.Invoke("第一层: HTTP请求探测...");
            var result = new Layer1Result();
            var visitedUrls = new HashSet<string>();
            var currentUrl = url;
            int maxRedirects = 10;
            int redirectCount = 0;

            try
            {
                // 初始化为原始URL
                result.FoundUrl = url;

                while (redirectCount < maxRedirects)
                {
                    if (visitedUrls.Contains(currentUrl))
                    {
                        OnLog?.Invoke("检测到循环重定向，停止追踪");
                        break;
                    }

                    visitedUrls.Add(currentUrl);
                    OnLog?.Invoke($"请求: {currentUrl}");
                    var response = await _httpClient.GetAsync(currentUrl, cancellationToken);
                    var statusCode = (int)response.StatusCode;

                    if (redirectCount == 0)
                    {
                        result.StatusCode = statusCode;
                        foreach (var header in response.Headers)
                        {
                            result.Headers[header.Key] = string.Join(", ", header.Value);
                        }

                        var serverHeader = response.Headers.TryGetValues("Server", out var serverValues) ? serverValues.FirstOrDefault() : null;
                        var xPoweredBy = response.Headers.TryGetValues("X-Powered-By", out var xpbValues) ? xpbValues.FirstOrDefault() : null;

                        result.TechStack = new TechFingerprint
                        {
                            Server = serverHeader ?? "",
                            XPoweredBy = xPoweredBy ?? "",
                            DetectedTechs = new List<string>()
                        };

                        if (!string.IsNullOrEmpty(serverHeader))
                        {
                            if (serverHeader.Contains("nginx", StringComparison.OrdinalIgnoreCase))
                                result.TechStack.DetectedTechs.Add("Nginx");
                            if (serverHeader.Contains("Apache", StringComparison.OrdinalIgnoreCase))
                                result.TechStack.DetectedTechs.Add("Apache");
                            if (serverHeader.Contains("IIS", StringComparison.OrdinalIgnoreCase))
                                result.TechStack.DetectedTechs.Add("IIS");
                        }

                        if (!string.IsNullOrEmpty(xPoweredBy))
                        {
                            if (xPoweredBy.Contains("ASP.NET", StringComparison.OrdinalIgnoreCase))
                                result.TechStack.DetectedTechs.Add("ASP.NET");
                            if (xPoweredBy.Contains("PHP", StringComparison.OrdinalIgnoreCase))
                                result.TechStack.DetectedTechs.Add("PHP");
                            if (xPoweredBy.Contains("Express", StringComparison.OrdinalIgnoreCase))
                                result.TechStack.DetectedTechs.Add("Express.js");
                        }

                        var requiredHeaders = new[] { "Strict-Transport-Security", "X-Content-Type-Options", "X-Frame-Options", "Content-Security-Policy" };
                        result.MissingSecurityHeaders = requiredHeaders.Where(h => !result.Headers.ContainsKey(h)).ToList();
                        result.SecurityHeaders = requiredHeaders.Where(h => result.Headers.ContainsKey(h)).ToList();

                        result.SetCookies = ExtractCookies(response);
                        result.WafInfo = DetectWaf(response);
                        result.DiscoveredApis = DiscoverApis(currentUrl, response);
                        result.DiscoveredSubdomains = DiscoverSubdomains(currentUrl, response);
                        result.ParamVulnerabilityHints = CheckParamVulnerabilities(response);

                        var content = await response.Content.ReadAsStringAsync(cancellationToken);
                        result.PageContent = AnalyzePageContent(currentUrl, content, response);

                        if (result.PageContent != null)
                        {
                            if (!string.IsNullOrEmpty(result.PageContent.CmsDetected))
                                result.TechStack.Cms = result.PageContent.CmsDetected;
                            if (!string.IsNullOrEmpty(result.PageContent.FrameworkDetected))
                                result.TechStack.Framework = result.PageContent.FrameworkDetected;
                        }
                    }

                    var step = new PathStep
                    {
                        Url = currentUrl,
                        StatusCode = statusCode,
                    };

                    if (response.Headers.Location != null)
                    {
                        var locationUrl = response.Headers.Location.ToString();
                        step.LocationHeader = locationUrl;

                        if (!locationUrl.StartsWith("http", StringComparison.OrdinalIgnoreCase))
                        {
                            var baseUri = new Uri(currentUrl);
                            locationUrl = new Uri(baseUri, locationUrl).ToString();
                        }

                        result.FoundUrl = locationUrl;
                        currentUrl = locationUrl;
                        redirectCount++;
                        OnLog?.Invoke($"发现重定向 [{statusCode}] -> {locationUrl}");
                        result.PathChain.Add(step);
                    }
                    else
                    {
                        if (statusCode == 301 || statusCode == 302 || statusCode == 307 || statusCode == 308)
                        {
                            OnLog?.Invoke($"状态码 {statusCode} 但无 Location 头");
                        }
                        OnLog?.Invoke($"追踪结束: {currentUrl} (状态码: {statusCode})");
                        break;
                    }
                }

                if (redirectCount >= maxRedirects)
                {
                    OnLog?.Invoke("达到最大重定向次数限制 (10次)");
                }

                OnLog?.Invoke($"最终URL: {result.FoundUrl}");
                OnLog?.Invoke($"状态码: {result.StatusCode}");
                OnLog?.Invoke($"重定向步数: {result.PathChain.Count}");
                OnLog?.Invoke($"技术栈识别: {string.Join(", ", result.TechStack?.DetectedTechs ?? new List<string>())}");

                // 如果返回404，自动尝试常见路径
                if (result.StatusCode == 404)
                {
                    OnLog?.Invoke("根路径返回404，尝试常见路径...");
                    await TryCommonPathsAsync(url, result, cancellationToken);
                }
            }
            catch (Exception ex)
            {
                result.Error = ex.Message;
                OnLog?.Invoke($"请求失败: {ex.Message}");
            }

            return result;
        }

        private async Task TryCommonPathsAsync(string baseUrl, Layer1Result result, CancellationToken cancellationToken)
        {
            var commonPaths = new[]
            {
                "/index.html", "/index.htm", "/index.php", "/index.asp", "/index.aspx", "/index.jsp",
                "/default.html", "/default.asp", "/default.aspx",
                "/home", "/main", "/dashboard", "/console",
                "/login", "/signin", "/auth", "/login.html",
                "/admin", "/manage", "/manager", "/administrator",
                "/api", "/api/v1", "/api/v2",
                "/app", "/web", "/portal",
                "/sitemap.xml", "/robots.txt"
            };

            var uri = new Uri(baseUrl);
            var baseUri = uri.GetLeftPart(UriPartial.Authority);

            foreach (var path in commonPaths)
            {
                if (cancellationToken.IsCancellationRequested) break;

                await DelayAsync(cancellationToken);

                var testUrl = baseUri + path;
                try
                {
                    var response = await _httpClient.GetAsync(testUrl, cancellationToken);
                    var statusCode = (int)response.StatusCode;

                    if (statusCode >= 200 && statusCode < 300)
                    {
                        result.FoundUrl = testUrl;
                        OnLog?.Invoke($"✅ 发现有效路径: [{statusCode}] {testUrl}");

                        var step = new PathStep
                        {
                            Url = testUrl,
                            StatusCode = statusCode,
                        };
                        result.PathChain.Add(step);
                    }
                    else if (statusCode >= 300 && statusCode < 400 && response.Headers.Location != null)
                    {
                        var locationUrl = response.Headers.Location.ToString();
                        if (!locationUrl.StartsWith("http", StringComparison.OrdinalIgnoreCase))
                        {
                            locationUrl = new Uri(new Uri(testUrl), locationUrl).ToString();
                        }
                        result.FoundUrl = locationUrl;
                        OnLog?.Invoke($"🔄 发现重定向: [{statusCode}] {testUrl} -> {locationUrl}");

                        result.PathChain.Add(new PathStep
                        {
                            Url = testUrl,
                            StatusCode = statusCode,
                            LocationHeader = locationUrl
                        });
                    }
                }
                catch { }
            }
        }

        private List<CookieInfo> ExtractCookies(HttpResponseMessage response)
        {
            var cookies = new List<CookieInfo>();
            if (response.Headers.TryGetValues("Set-Cookie", out var cookieHeaders))
            {
                foreach (var cookieHeader in cookieHeaders)
                {
                    var parts = cookieHeader.Split(';');
                    var nameValue = parts[0].Split('=');
                    if (nameValue.Length >= 2)
                    {
                        cookies.Add(new CookieInfo
                        {
                            Name = nameValue[0].Trim(),
                            Domain = ExtractCookieAttribute(cookieHeader, "Domain"),
                            Path = ExtractCookieAttribute(cookieHeader, "Path"),
                            Secure = cookieHeader.IndexOf("Secure", StringComparison.OrdinalIgnoreCase) >= 0,
                            HttpOnly = cookieHeader.IndexOf("HttpOnly", StringComparison.OrdinalIgnoreCase) >= 0,
                            IsSession = cookieHeader.IndexOf("Expires", StringComparison.OrdinalIgnoreCase) < 0 &&
                                       cookieHeader.IndexOf("Max-Age", StringComparison.OrdinalIgnoreCase) < 0
                        });
                    }
                }
            }
            return cookies;
        }

        private string ExtractCookieAttribute(string cookieHeader, string attribute)
        {
            var index = cookieHeader.IndexOf(attribute, StringComparison.OrdinalIgnoreCase);
            if (index < 0) return "";
            var start = index + attribute.Length + 1;
            var end = cookieHeader.IndexOf(';', start);
            if (end < 0) end = cookieHeader.Length;
            return cookieHeader.Substring(start, end - start).Trim();
        }

        private async Task<List<OpenRedirectFinding>> CheckOpenRedirectsAsync(string url, CancellationToken cancellationToken)
        {
            var findings = new List<OpenRedirectFinding>();
            var redirectParams = new[] { "url", "redirect", "redirect_to", "return", "next", "target", "goto", "returnUrl", "return_url" };
            var testUrl = "https://example.com";

            var uri = new Uri(url);
            var baseUrl = uri.GetLeftPart(UriPartial.Authority);

            foreach (var param in redirectParams)
            {
                try
                {
                    var testFullUrl = $"{url}{(url.Contains("?") ? "&" : "?")}{param}={testUrl}";
                    var response = await _httpClient.GetAsync(testFullUrl, cancellationToken);

                    if ((int)response.StatusCode >= 300 && (int)response.StatusCode < 400)
                    {
                        if (response.Headers.Location != null)
                        {
                            var location = response.Headers.Location.ToString();
                            if (location.Contains("example.com", StringComparison.OrdinalIgnoreCase))
                            {
                                findings.Add(new OpenRedirectFinding
                                {
                                    Parameter = param,
                                    TestUrl = testFullUrl,
                                    RedirectedTo = location,
                                    IsVulnerable = true
                                });
                                OnLog?.Invoke($"⚠️ 开放重定向漏洞: 参数 {param}");
                            }
                        }
                    }
                }
                catch { }
            }

            return findings;
        }

        private WafDetection DetectWaf(HttpResponseMessage response)
        {
            var detection = new WafDetection();
            var wafSignatures = new Dictionary<string, string[]>
            {
                { "Cloudflare", new[] { "cf-ray", "cloudflare-nginx", "cf-chl-bypass" } },
                { "Akamai", new[] { "akamai-grn", "x-akamai-transformed" } },
                { "AWS WAF", new[] { "x-amzn-waf" } },
                { "ModSecurity", new[] { "mod_security" } },
                { "Sucuri", new[] { "sucuri", "x-sucuri" } },
                { "Incapsula", new[] { "incap_ses", "visid_incap" } },
                { "F5 BIG-IP", new[] { "F5_ST", "MRHSession" } },
                { "Imperva", new[] { "incap_ses" } },
                { "Barracuda", new[] { "barra_counter_session" } },
                { "DenyAll", new[] { "sessioncookie" } },
                { "FortiWeb", new[] { "FORTIWAFSID" } },
                { "NSFocus", new[] { "nsfocus" } },
                { "Anquanbao", new[] { "aqb_cc" } },
                { "360", new[] { "wzws-cf", "wzws-waf-status" } },
            };

            foreach (var (wafName, headers) in wafSignatures)
            {
                foreach (var header in headers)
                {
                    if (response.Headers.Contains(header))
                    {
                        detection.IsBehindWaf = true;
                        detection.WafName = wafName;
                        detection.DetectionMethod = $"响应头: {header}";
                        detection.Indicators.Add($"检测到响应头 {header}");
                        OnLog?.Invoke($"🛡️ 检测到WAF: {wafName}");
                        return detection;
                    }
                }
            }

            if (response.Content != null)
            {
                var contentLength = response.Content.Headers.ContentLength ?? 0;
                if (contentLength > 0 && contentLength < 500 && (int)response.StatusCode == 403)
                {
                    detection.IsBehindWaf = true;
                    detection.WafName = "Unknown WAF";
                    detection.DetectionMethod = "403 Forbidden 小响应体";
                    detection.Indicators.Add("403状态码 + 小响应体");
                }
            }

            return detection;
        }

        private List<ApiEndpoint> DiscoverApis(string baseUrl, HttpResponseMessage response)
        {
            var apis = new List<ApiEndpoint>();
            var apiPaths = new[]
            {
                "/api", "/api/v1", "/api/v2", "/api/v3",
                "/graphql", "/graphql/console",
                "/swagger", "/swagger/ui", "/swagger-ui.html",
                "/api-docs", "/api/docs", "/docs",
                "/openapi.json", "/swagger.json",
                "/actuator", "/actuator/health", "/actuator/info",
                "/.well-known/openid-configuration",
                "/api/swagger", "/api/api-docs",
                "/rest", "/rest/api",
                "/wp-json", "/wp-json/wp/v2",
                "/jsonapi",
                "/odata", "/odata.svc"
            };

            var uri = new Uri(baseUrl);
            var baseUri = uri.GetLeftPart(UriPartial.Authority);

            foreach (var path in apiPaths)
            {
                var testUrl = baseUri + path;
                var headers = response.Headers.Select(h => h.Key.ToLower()).ToList();

                bool isApi = false;
                string type = "potential";

                if (path.Contains("swagger") || path.Contains("api-docs") || path.Contains("openapi"))
                {
                    type = "OpenAPI/Swagger";
                    isApi = true;
                }
                else if (path.Contains("graphql"))
                {
                    type = "GraphQL";
                    isApi = true;
                }
                else if (path.Contains("actuator"))
                {
                    type = "Spring Actuator";
                    isApi = true;
                }
                else if (path.StartsWith("/api") || path.StartsWith("/rest") || path.StartsWith("/odata"))
                {
                    type = "REST API";
                    isApi = true;
                }
                else if (path.Contains("wp-json"))
                {
                    type = "WordPress REST API";
                    isApi = true;
                }
                else if (path.Contains("jsonapi"))
                {
                    type = "JSON:API";
                    isApi = true;
                }

                if (isApi)
                {
                    apis.Add(new ApiEndpoint
                    {
                        Url = testUrl,
                        Type = type,
                        IsInteractive = type == "OpenAPI/Swagger" || type == "GraphQL"
                    });
                }
            }

            return apis;
        }

        private async Task<List<ApiEndpoint>> DiscoverApisWithTestAsync(string baseUrl, HttpResponseMessage response, CancellationToken cancellationToken)
        {
            var apis = new List<ApiEndpoint>();
            var uri = new Uri(baseUrl);
            var baseUri = uri.GetLeftPart(UriPartial.Authority);

            var apiPaths = new[]
            {
                "/api", "/api/v1", "/api/v2", "/api/v3", "/api/v1/", "/api/v2/",
                "/graphql", "/graphql/console", "/playground",
                "/swagger", "/swagger/ui", "/swagger-ui.html", "/swagger-ui/", "/api/swagger",
                "/api-docs", "/api/docs", "/docs", "/documentation",
                "/openapi.json", "/openapi.yaml", "/swagger.json", "/swagger.yaml",
                "/actuator", "/actuator/health", "/actuator/info", "/actuator/env", "/actuator/configprops",
                "/.well-known/openid-configuration", "/oauth", "/oauth/authorize", "/oauth/token",
                "/rest", "/rest/api", "/rest/v1",
                "/wp-json", "/wp-json/wp/v2", "/wp-json/wp/v2/users",
                "/jsonapi", "/jsonapi/",
                "/odata", "/odata.svc",
                "/api/users", "/api/products", "/api/orders", "/api/admin",
                "/api/health", "/api/status", "/api/info",
                "/favicon.ico", "/apple-touch-icon.png"
            };

            foreach (var path in apiPaths)
            {
                var testUrl = baseUri + path;
                try
                {
                    await DelayAsync(cancellationToken);
                    var testResponse = await _httpClient.GetAsync(testUrl, cancellationToken);
                    var statusCode = (int)testResponse.StatusCode;

                    if (statusCode >= 200 && statusCode < 500)
                    {
                        var apiType = ClassifyApiType(path);
                        var isInteractive = path.Contains("swagger") || path.Contains("graphql") || path.Contains("playground");

                        apis.Add(new ApiEndpoint
                        {
                            Url = testUrl,
                            Type = apiType,
                            IsInteractive = isInteractive,
                            Method = "GET"
                        });

                        OnLog?.Invoke($"API端点发现: [{statusCode}] {testUrl} ({apiType})");
                    }
                }
                catch { }
            }

            return apis;
        }

        private string ClassifyApiType(string path)
        {
            if (path.Contains("swagger") || path.Contains("openapi")) return "OpenAPI/Swagger";
            if (path.Contains("graphql")) return "GraphQL";
            if (path.Contains("actuator")) return "Spring Actuator";
            if (path.Contains("wp-json")) return "WordPress REST API";
            if (path.Contains("jsonapi")) return "JSON:API";
            if (path.Contains("odata")) return "OData";
            if (path.Contains("oauth") || path.Contains("openid")) return "OAuth/OIDC";
            if (path.Contains("/api/users") || path.Contains("/api/products")) return "REST API (Resource)";
            if (path.Contains("/api/health") || path.Contains("/api/status")) return "Health Check API";
            if (path.StartsWith("/api") || path.StartsWith("/rest")) return "REST API";
            return "potential";
        }

        private List<(string Url, string Type)> GuessPathsFromTechStack(TechFingerprint tech, string baseUrl)
        {
            var paths = new List<(string Url, string Type)>();

            if (tech.Cms == "WordPress")
            {
                paths.Add((baseUrl + "/wp-admin", "admin"));
                paths.Add((baseUrl + "/wp-login.php", "login"));
                paths.Add((baseUrl + "/wp-json/wp/v2", "api"));
                paths.Add((baseUrl + "/xmlrpc.php", "api"));
            }
            else if (tech.Cms == "Joomla")
            {
                paths.Add((baseUrl + "/administrator", "admin"));
                paths.Add((baseUrl + "/api/index.php/v1", "api"));
            }
            else if (tech.Cms == "Drupal")
            {
                paths.Add((baseUrl + "/user/login", "login"));
                paths.Add((baseUrl + "/admin", "admin"));
                paths.Add((baseUrl + "/api", "api"));
            }
            else if (tech.Cms == "Django" || tech.Cms == "Flask")
            {
                paths.Add((baseUrl + "/admin", "admin"));
                paths.Add((baseUrl + "/api/v1", "api"));
                paths.Add((baseUrl + "/static", "resources"));
                paths.Add((baseUrl + "/media", "resources"));
            }
            else if (tech.Cms == "Spring Boot")
            {
                paths.Add((baseUrl + "/actuator", "admin"));
                paths.Add((baseUrl + "/actuator/health", "health"));
                paths.Add((baseUrl + "/api", "api"));
            }
            else if (tech.BackendLanguage == "ASP.NET")
            {
                paths.Add((baseUrl + "/Account/Login", "login"));
                paths.Add((baseUrl + "/Admin", "admin"));
                paths.Add((baseUrl + "/api", "api"));
            }

            paths.Add((baseUrl + "/admin", "admin"));
            paths.Add((baseUrl + "/manage", "admin"));
            paths.Add((baseUrl + "/manager", "admin"));
            paths.Add((baseUrl + "/console", "admin"));
            paths.Add((baseUrl + "/dashboard", "admin"));

            return paths;
        }

        private List<string> DiscoverSubdomains(string baseUrl, HttpResponseMessage response)
        {
            var subdomains = new List<string>();

            try
            {
                var uri = new Uri(baseUrl);
                var domain = uri.Host;
                var parts = domain.Split('.');

                if (parts.Length >= 2)
                {
                    var mainDomain = string.Join(".", parts.Skip(Math.Max(0, parts.Length - 2)));

                    var commonSubdomains = new[] { "www", "api", "admin", "dev", "staging", "test", "uat", "prod", "beta", "cdn", "static", "m", "mobile", "app", "auth", "login", "sso", "oauth", "portal", "dashboard", "console", "manage", "manage", "internal", "private", "secure", "mail", "webmail", "ftp", "ssh", "vpn", "proxy", "lb", "cache", "db", "redis", "mongo", "elastic", "kibana", "grafana", "prometheus", "jenkins", "gitlab", "github", "bitbucket", "jira", "confluence", "wiki", "docs", "blog", "forum", "community", "support", "help", "status", "monitor", "metrics", "logs", "backup", "storage", "assets", "files", "media", "images", "img", "js", "css", "fonts", "fonts.googleapis.com" };

                    foreach (var sub in commonSubdomains)
                    {
                        var subdomain = $"{sub}.{mainDomain}";
                        if (!subdomain.Equals(domain, StringComparison.OrdinalIgnoreCase))
                        {
                            subdomains.Add(subdomain);
                        }
                    }
                }
            }
            catch { }

            return subdomains;
        }

        private PageContentAnalysis AnalyzePageContent(string url, string htmlContent, HttpResponseMessage response)
        {
            var analysis = new PageContentAnalysis();

            try
            {
                analysis.ContentLength = htmlContent.Length;
                analysis.ContentType = response.Content.Headers.ContentType?.ToString() ?? "";

                var titleMatch = Regex.Match(htmlContent, @"<title[^>]*>(.*?)</title>", RegexOptions.IgnoreCase | RegexOptions.Singleline);
                if (titleMatch.Success) analysis.Title = titleMatch.Groups[1].Value.Trim();

                var metaRegex = new Regex(@"<meta[^>]+(?:name|property)=[""']([^""']+)[""'][^>]+content=[""']([^""']+)[""']", RegexOptions.IgnoreCase);
                foreach (Match match in metaRegex.Matches(htmlContent))
                {
                    var name = match.Groups[1].Value.ToLower();
                    var content = match.Groups[2].Value;
                    analysis.MetaTags[name] = content;

                    if (name == "description") analysis.Description = content;
                    else if (name == "keywords") analysis.Keywords = content.Split(',').Select(k => k.Trim()).ToList();
                    else if (name == "generator") analysis.Generator = content;
                    else if (name == "author") analysis.Author = content;
                    else if (name.StartsWith("og:")) analysis.OpenGraphTags.Add($"{name}: {content}");
                }

                var charsetMatch = Regex.Match(htmlContent, @"charset=[""']?([^""'\s>]+)", RegexOptions.IgnoreCase);
                if (charsetMatch.Success) analysis.Charset = charsetMatch.Groups[1].Value;

                var langMatch = Regex.Match(htmlContent, @"<html[^>]+lang=[""']([^""']+)[""']", RegexOptions.IgnoreCase);
                if (langMatch.Success) analysis.Language = langMatch.Groups[1].Value;

                var canonicalMatch = Regex.Match(htmlContent, @"<link[^>]+rel=[""']canonical[""'][^>]+href=[""']([^""']+)[""']", RegexOptions.IgnoreCase);
                if (canonicalMatch.Success) analysis.CanonicalUrl = canonicalMatch.Groups[1].Value;

                var faviconMatch = Regex.Match(htmlContent, @"<link[^>]+rel=[""'](?:shortcut )?icon[""'][^>]+href=[""']([^""']+)[""']", RegexOptions.IgnoreCase);
                if (faviconMatch.Success) analysis.FaviconUrl = faviconMatch.Groups[1].Value;

                analysis.LinkCount = Regex.Matches(htmlContent, @"<a\s", RegexOptions.IgnoreCase).Count;
                analysis.ImageCount = Regex.Matches(htmlContent, @"<img\s", RegexOptions.IgnoreCase).Count;
                analysis.FormCount = Regex.Matches(htmlContent, @"<form\s", RegexOptions.IgnoreCase).Count;
                analysis.ScriptCount = Regex.Matches(htmlContent, @"<script", RegexOptions.IgnoreCase).Count;
                analysis.StyleCount = Regex.Matches(htmlContent, @"<link[^>]+rel=[""']stylesheet[""']", RegexOptions.IgnoreCase).Count;

                var textContent = Regex.Replace(htmlContent, "<[^>]+>", " ");
                var words = Regex.Matches(textContent, @"\b\w+\b");
                analysis.WordCount = words.Count;

                analysis.CmsDetected = DetectCms(htmlContent, analysis);
                analysis.FrameworkDetected = DetectFramework(htmlContent, analysis);

                if (!string.IsNullOrEmpty(analysis.CmsDetected))
                {
                    OnLog?.Invoke($"🔍 检测到CMS: {analysis.CmsDetected}");
                }
                if (!string.IsNullOrEmpty(analysis.FrameworkDetected))
                {
                    OnLog?.Invoke($"🔍 检测到框架: {analysis.FrameworkDetected}");
                }
            }
            catch { }

            return analysis;
        }

        private string DetectCms(string html, PageContentAnalysis analysis)
        {
            var lowerHtml = html.ToLower();
            var cmsSignatures = new Dictionary<string, string[]>
            {
                { "WordPress", new[] { "/wp-content/", "wp-json", "wordpress" } },
                { "Joomla", new[] { "/media/jui/", "joomla", "index.php?option=com_" } },
                { "Drupal", new[] { "/sites/default/files/", "drupal", "sites/all" } },
                { "Magento", new[] { "mage", "skin/frontend", "js/mage" } },
                { "Django", new[] { "django", "csrftoken" } },
                { "Laravel", new[] { "laravel_session", "_token" } },
                { "ThinkPHP", new[] { "thinkphp", "__PUBLIC__" } },
                { "Spring Boot", new[] { "spring", "actuator" } },
                { "Express.js", new[] { "x-powered-by: express" } },
                { "ASP.NET", new[] { "aspnet", "viewstate", "__eventvalidation" } },
                { "Flask", new[] { "flask", "session=" } },
                { "Ruby on Rails", new[] { "rails", "authenticity_token" } },
            };

            var generator = analysis.Generator?.ToLower() ?? "";
            foreach (var (cms, signatures) in cmsSignatures)
            {
                if (!string.IsNullOrEmpty(generator) && generator.Contains(cms.ToLower()))
                    return cms;

                foreach (var sig in signatures)
                {
                    if (lowerHtml.Contains(sig.ToLower()))
                        return cms;
                }
            }

            return "";
        }

        private string DetectFramework(string html, PageContentAnalysis analysis)
        {
            var lowerHtml = html.ToLower();
            var frameworks = new Dictionary<string, string[]>
            {
                { "React", new[] { "react", "reactdom" } },
                { "Vue.js", new[] { "vue", "__vue__" } },
                { "Angular", new[] { "angular", "ng-app", "ng-version" } },
                { "jQuery", new[] { "jquery", "jquery-" } },
                { "Bootstrap", new[] { "bootstrap", "bootstrap-" } },
                { "Tailwind CSS", new[] { "tailwind" } },
                { "Semantic UI", new[] { "semantic" } },
                { "Element UI", new[] { "element-ui" } },
                { "Ant Design", new[] { "ant-", "antd" } },
            };

            foreach (var (fw, signatures) in frameworks)
            {
                foreach (var sig in signatures)
                {
                    if (lowerHtml.Contains(sig.ToLower()))
                        return fw;
                }
            }

            return "";
        }

        public List<PathRiskAssessment> AssessPathRisks(WebPathTraceResult result)
        {
            var assessments = new List<PathRiskAssessment>();

            foreach (var path in result.AllDiscoveredPaths)
            {
                var assessment = new PathRiskAssessment
                {
                    Url = path.Url,
                    StatusCode = path.StatusCode
                };

                int score = 0;
                var factors = new List<string>();
                var recommendations = new List<string>();

                var lowerUrl = path.Url.ToLower();
                var sensitiveKeywords = new Dictionary<string, int>
                {
                    { "admin", 30 }, { "manage", 25 }, { "dashboard", 20 },
                    { "login", 20 }, { "auth", 20 }, { "register", 15 },
                    { "config", 25 }, { "env", 25 }, { "secret", 30 },
                    { "backup", 20 }, { "db", 20 }, { "database", 20 },
                    { "debug", 20 }, { "test", 15 }, { "dev", 15 },
                    { "api", 10 }, { "graphql", 15 },
                    { "upload", 15 }, { "download", 10 },
                    { "temp", 10 }, { "tmp", 10 },
                    { ".git", 30 }, { ".svn", 30 }, { ".env", 30 },
                    { "phpinfo", 25 }, { "phpmyadmin", 30 },
                };

                foreach (var (keyword, riskScore) in sensitiveKeywords)
                {
                    if (lowerUrl.Contains(keyword))
                    {
                        score += riskScore;
                        factors.Add($"包含敏感关键词: {keyword}");
                    }
                }

                if (path.StatusCode == 200)
                {
                    score += 10;
                    if (score < 50) factors.Add("路径可访问");
                }
                else if (path.StatusCode == 403)
                {
                    score += 15;
                    factors.Add("访问被拒绝 (可能存在权限控制)");
                    recommendations.Add("检查是否应该返回404而非403以避免信息泄露");
                }
                else if (path.StatusCode == 500)
                {
                    score += 20;
                    factors.Add("服务器内部错误");
                    recommendations.Add("检查错误日志，避免暴露技术细节");
                }

                if (path.ContentLength > 10000)
                {
                    score += 5;
                    factors.Add("响应体较大 (可能包含大量数据)");
                }

                score = Math.Min(score, 100);
                assessment.RiskScore = score;
                assessment.RiskFactors = factors;
                assessment.Recommendations = recommendations;

                if (score >= 70) assessment.RiskLevel = "高风险";
                else if (score >= 40) assessment.RiskLevel = "中风险";
                else if (score >= 20) assessment.RiskLevel = "低风险";
                else assessment.RiskLevel = "安全";

                assessments.Add(assessment);
            }

            return assessments.OrderByDescending(a => a.RiskScore).ToList();
        }

        public TraceReport GenerateReport(WebPathTraceResult result, TimeSpan duration)
        {
            var report = new TraceReport
            {
                TargetUrl = result.OriginalUrl,
                FinalUrl = result.FinalUrl,
                Mode = result.Mode,
                Duration = duration,
                TotalPathsDiscovered = result.AllDiscoveredPaths.Count,
                SensitivePathsCount = result.SensitivePaths.Count,
                FullResult = result,
                RiskAssessments = AssessPathRisks(result)
            };

            var highRiskCount = report.RiskAssessments.Count(a => a.RiskLevel == "高风险");
            var mediumRiskCount = report.RiskAssessments.Count(a => a.RiskLevel == "中风险");

            report.ReportSummary = $"追踪 {result.OriginalUrl}，发现 {result.AllDiscoveredPaths.Count} 个路径，" +
                $"其中 {result.SensitivePaths.Count} 个敏感路径。" +
                $"风险评估: {highRiskCount} 个高风险，{mediumRiskCount} 个中风险。" +
                $"耗时: {duration.TotalSeconds:F1}秒。";

            return report;
        }

        public string ExportReportAsMarkdown(TraceReport report)
        {
            var sb = new System.Text.StringBuilder();
            sb.AppendLine("# 网页路径追踪报告\n");
            sb.AppendLine($"**生成时间**: {report.GeneratedAt}\n");
            sb.AppendLine($"**目标URL**: {report.TargetUrl}\n");
            sb.AppendLine($"**最终URL**: {report.FinalUrl ?? "无"}\n");
            sb.AppendLine($"**追踪模式**: {report.Mode}\n");
            sb.AppendLine($"**耗时**: {report.Duration.TotalSeconds:F1}秒\n");
            sb.AppendLine("---\n");
            sb.AppendLine("## 摘要\n");
            sb.AppendLine(report.ReportSummary + "\n");
            sb.AppendLine("---\n");

            sb.AppendLine("## 发现路径汇总\n");
            sb.AppendLine($"| 类型 | 数量 |");
            sb.AppendLine("|------|------|");
            sb.AppendLine($"| 总路径 | {report.TotalPathsDiscovered} |");
            sb.AppendLine($"| 敏感路径 | {report.SensitivePathsCount} |");
            sb.AppendLine($"| 高风险 | {report.RiskAssessments.Count(a => a.RiskLevel == "高风险")} |");
            sb.AppendLine($"| 中风险 | {report.RiskAssessments.Count(a => a.RiskLevel == "中风险")} |");
            sb.AppendLine();

            if (report.RiskAssessments.Count > 0)
            {
                sb.AppendLine("## 风险评估\n");
                sb.AppendLine("| URL | 状态码 | 风险等级 | 风险分数 | 风险因素 |");
                sb.AppendLine("|-----|--------|----------|----------|----------|");

                foreach (var assessment in report.RiskAssessments.Take(20))
                {
                    var factors = string.Join(", ", assessment.RiskFactors.Take(2));
                    sb.AppendLine($"| {assessment.Url} | {assessment.StatusCode} | {assessment.RiskLevel} | {assessment.RiskScore} | {factors} |");
                }
                sb.AppendLine();
            }

            if (report.FullResult.SensitivePaths.Count > 0)
            {
                sb.AppendLine("## 敏感路径\n");
                foreach (var path in report.FullResult.SensitivePaths)
                {
                    sb.AppendLine($"- ⚠️ {path}");
                }
                sb.AppendLine();
            }

            if (report.FullResult.Layer1Results?.PageContent != null)
            {
                var page = report.FullResult.Layer1Results.PageContent;
                sb.AppendLine("## 页面内容分析\n");
                sb.AppendLine($"**标题**: {page.Title}\n");
                sb.AppendLine($"**描述**: {page.Description}\n");
                if (page.Keywords.Count > 0) sb.AppendLine($"**关键词**: {string.Join(", ", page.Keywords)}\n");
                if (!string.IsNullOrEmpty(page.CmsDetected)) sb.AppendLine($"**CMS**: {page.CmsDetected}\n");
                if (!string.IsNullOrEmpty(page.FrameworkDetected)) sb.AppendLine($"**框架**: {page.FrameworkDetected}\n");
                sb.AppendLine($"**链接数**: {page.LinkCount} | **图片数**: {page.ImageCount} | **表单数**: {page.FormCount}\n");
                sb.AppendLine($"**脚本数**: {page.ScriptCount} | **样式表数**: {page.StyleCount}\n");
            }

            return sb.ToString();
        }

        public string ExportReportAsJson(TraceReport report)
        {
            return System.Text.Json.JsonSerializer.Serialize(report, new System.Text.Json.JsonSerializerOptions
            {
                WriteIndented = true,
                Encoder = System.Text.Encodings.Web.JavaScriptEncoder.UnsafeRelaxedJsonEscaping
            });
        }

        public async Task<SslCertificateInfo?> AnalyzeSslCertificate(string targetUrl, CancellationToken cancellationToken = default)
        {
            try
            {
                var uri = new Uri(targetUrl);
                if (uri.Scheme != "https")
                {
                    return new SslCertificateInfo 
                    { 
                        Subject = "", 
                        Issuer = "", 
                        IsValid = false,
                        Warnings = { "目标URL不是HTTPS，无法分析SSL证书" }
                    };
                }

                var host = uri.Host;
                var port = uri.Port > 0 ? uri.Port : 443;
                var sslInfo = new SslCertificateInfo();

                using var tcpClient = new System.Net.Sockets.TcpClient();
                var connectTask = tcpClient.ConnectAsync(host, port);
                if (await Task.WhenAny(connectTask, Task.Delay(5000, cancellationToken)) != connectTask)
                {
                    sslInfo.Warnings.Add("连接超时");
                    return sslInfo;
                }

                using var sslStream = new System.Net.Security.SslStream(tcpClient.GetStream(), false, 
                    (sender, certificate, chain, sslPolicyErrors) => true);

                var sslAuthTask = sslStream.AuthenticateAsClientAsync(new System.Net.Security.SslClientAuthenticationOptions
                {
                    TargetHost = host,
                    RemoteCertificateValidationCallback = (sender, certificate, chain, sslPolicyErrors) => true,
                    EnabledSslProtocols = System.Security.Authentication.SslProtocols.Tls12 | System.Security.Authentication.SslProtocols.Tls13
                });

                if (await Task.WhenAny(sslAuthTask, Task.Delay(5000, cancellationToken)) != sslAuthTask)
                {
                    sslInfo.Warnings.Add("SSL握手超时");
                    return sslInfo;
                }

                var remoteCert = sslStream.RemoteCertificate;
                if (remoteCert == null)
                {
                    sslInfo.Warnings.Add("服务器未提供SSL证书");
                    return sslInfo;
                }

                var x509Cert = new System.Security.Cryptography.X509Certificates.X509Certificate2(remoteCert);

                sslInfo.Subject = x509Cert.Subject;
                sslInfo.Issuer = x509Cert.Issuer;
                sslInfo.ValidFrom = x509Cert.NotBefore.ToString("yyyy-MM-dd HH:mm:ss");
                sslInfo.ValidTo = x509Cert.NotAfter.ToString("yyyy-MM-dd HH:mm:ss");
                sslInfo.SerialNumber = x509Cert.SerialNumber;
                sslInfo.Version = x509Cert.Version.ToString();
                sslInfo.SignatureAlgorithm = x509Cert.SignatureAlgorithm?.FriendlyName;
                sslInfo.PublicKeyAlgorithm = x509Cert.PublicKey?.Oid?.FriendlyName;
                sslInfo.KeySize = x509Cert.PublicKey?.Key?.KeySize;
                sslInfo.ProtocolVersion = sslStream.SslProtocol.ToString();
                sslInfo.CipherSuite = sslStream.CipherAlgorithm.ToString();
                sslInfo.SupportsTls12 = sslStream.SslProtocol >= System.Security.Authentication.SslProtocols.Tls12;
                sslInfo.SupportsTls13 = sslStream.SslProtocol == System.Security.Authentication.SslProtocols.Tls13;

                try
                {
                    var sanExtension = x509Cert.Extensions.FirstOrDefault(e => e.Oid?.Value == "2.5.29.17");
                    if (sanExtension != null)
                    {
                        var sanData = sanExtension.Format(false);
                        if (!string.IsNullOrEmpty(sanData))
                        {
                            var names = sanData.Split(new[] { ',', ';', '\n', '\r' }, StringSplitOptions.RemoveEmptyEntries)
                                .Select(n => n.Trim())
                                .Where(n => !string.IsNullOrEmpty(n))
                                .ToList();
                            sslInfo.SubjectAlternativeNames = names;
                        }
                    }
                }
                catch { }

                sslInfo.IsSelfSigned = x509Cert.Subject == x509Cert.Issuer;
                sslInfo.IsExpired = x509Cert.NotAfter < DateTime.Now;
                sslInfo.IsValid = !sslInfo.IsExpired && !sslInfo.IsSelfSigned;

                var daysUntilExpiry = (x509Cert.NotAfter - DateTime.Now).Days;
                sslInfo.DaysUntilExpiry = daysUntilExpiry;

                if (x509Cert.NotAfter < DateTime.Now.AddDays(30))
                {
                    sslInfo.Warnings.Add($"证书将在{daysUntilExpiry}天后过期");
                }

                if (sslInfo.IsSelfSigned)
                {
                    sslInfo.Warnings.Add("证书是自签名的，不受信任");
                }

                if (!string.IsNullOrEmpty(sslInfo.SignatureAlgorithm))
                {
                    var lowerAlgo = sslInfo.SignatureAlgorithm.ToLower();
                    if (lowerAlgo.Contains("md5") || lowerAlgo.Contains("sha1") && !lowerAlgo.Contains("sha256") && !lowerAlgo.Contains("sha384") && !lowerAlgo.Contains("sha512"))
                    {
                        sslInfo.HasWeakCipher = true;
                        sslInfo.Warnings.Add($"使用了弱签名算法: {sslInfo.SignatureAlgorithm}");
                    }
                }

                if (sslInfo.KeySize < 2048)
                {
                    sslInfo.HasWeakCipher = true;
                    sslInfo.Warnings.Add($"密钥长度不足2048位: {sslInfo.KeySize}位");
                }

                if (!sslInfo.SupportsTls12)
                {
                    sslInfo.Warnings.Add("不支持TLS 1.2或更高版本");
                }

                try
                {
                    var crlExt = x509Cert.Extensions["2.5.29.31"];
                    if (crlExt != null)
                    {
                        sslInfo.CrlDistributionPoints = "已配置CRL吊销检查";
                    }

                    var ocspExt = x509Cert.Extensions["1.3.6.1.5.5.7.48.1"];
                    if (ocspExt != null)
                    {
                        sslInfo.OcspResponderUrl = "已配置OCSP在线证书状态协议";
                    }
                }
                catch { }

                return sslInfo;
            }
            catch (Exception ex)
            {
                OnLog?.Invoke($"⚠️ SSL证书分析失败: {ex.Message}");
                return null;
            }
        }

        public SecurityAuditResult AuditSecurityHeaders(Layer1Result layer1Result)
        {
            var audit = new SecurityAuditResult { OverallScore = 100 };

            var securityChecks = new Dictionary<string, (string description, string recommendation, int penalty)>
            {
                { "Strict-Transport-Security", ("缺少HSTS头，可能被SSL剥离攻击", "添加 Strict-Transport-Security: max-age=31536000; includeSubDomains", 15) },
                { "X-Content-Type-Options", ("缺少X-Content-Type-Options头，可能被MIME嗅探", "添加 X-Content-Type-Options: nosniff", 10) },
                { "X-Frame-Options", ("缺少X-Frame-Options头，可能被点击劫持", "添加 X-Frame-Options: DENY 或 SAMEORIGIN", 10) },
                { "Content-Security-Policy", ("缺少CSP头，XSS攻击风险增加", "配置内容安全策略限制资源加载来源", 15) },
                { "X-XSS-Protection", ("缺少XSS保护头", "添加 X-XSS-Protection: 1; mode=block", 5) },
                { "Referrer-Policy", ("缺少Referrer-Policy头，可能泄露引用信息", "添加 Referrer-Policy: strict-origin-when-cross-origin", 5) },
                { "Permissions-Policy", ("缺少Permissions-Policy头", "配置浏览器权限策略限制API访问", 5) },
            };

            foreach (var (header, (desc, rec, penalty)) in securityChecks)
            {
                if (layer1Result.Headers.ContainsKey(header))
                {
                    audit.PassedChecks.Add($"✅ {header}");
                }
                else
                {
                    audit.OverallScore -= penalty;
                    audit.FailedChecks.Add($"❌ {header}");
                    audit.Findings.Add(new SecurityFinding
                    {
                        Title = $"缺少安全头: {header}",
                        Severity = penalty >= 15 ? "High" : "Medium",
                        Description = desc,
                        Recommendation = rec
                    });
                }
            }

            if (layer1Result.Headers.TryGetValue("Server", out var serverInfo))
            {
                audit.Findings.Add(new SecurityFinding
                {
                    Title = "服务器信息泄露",
                    Severity = "Low",
                    Description = $"响应头暴露了服务器信息: {serverInfo}",
                    Recommendation = "配置Web服务器隐藏Server头或返回通用值"
                });
                audit.OverallScore -= 5;
            }

            if (layer1Result.Headers.TryGetValue("X-Powered-By", out var poweredBy))
            {
                audit.Findings.Add(new SecurityFinding
                {
                    Title = "技术栈信息泄露",
                    Severity = "Low",
                    Description = $"响应头暴露了技术栈: {poweredBy}",
                    Recommendation = "隐藏X-Powered-By头"
                });
                audit.OverallScore -= 5;
            }

            audit.OverallScore = Math.Max(0, audit.OverallScore);
            return audit;
        }

        public TechVulnerabilityInfo GetTechVulnerabilities(string techName)
        {
            var techVulns = new TechVulnerabilityInfo { Technology = techName };

            var cveDatabase = new Dictionary<string, List<CveInfo>>
            {
                {
                    "Nginx", new List<CveInfo>
                    {
                        new CveInfo { CveId = "CVE-2021-23017", Severity = "Critical", Description = "Nginx DNS解析器缓冲区溢出漏洞", CvssScore = 10.0, PublishedDate = "2021-05-25", FixVersion = "1.21.0" },
                        new CveInfo { CveId = "CVE-2022-41741", Severity = "High", Description = "Nginx MP4模块拒绝服务", CvssScore = 7.5, PublishedDate = "2023-02-14", FixVersion = "1.23.3" },
                    }
                },
                {
                    "Apache", new List<CveInfo>
                    {
                        new CveInfo { CveId = "CVE-2021-41773", Severity = "Critical", Description = "Apache HTTP Server路径遍历漏洞", CvssScore = 9.8, PublishedDate = "2021-10-07", FixVersion = "2.4.51" },
                        new CveInfo { CveId = "CVE-2021-44228", Severity = "Critical", Description = "Apache Log4j2远程代码执行 (Log4Shell)", CvssScore = 10.0, PublishedDate = "2021-12-10", FixVersion = "2.17.0" },
                    }
                },
                {
                    "WordPress", new List<CveInfo>
                    {
                        new CveInfo { CveId = "CVE-2023-46368", Severity = "High", Description = "WordPress文件上传验证绕过", CvssScore = 7.5, PublishedDate = "2023-11-09", FixVersion = "6.4.1" },
                        new CveInfo { CveId = "CVE-2023-40076", Severity = "Medium", Description = "WordPress CSRF漏洞", CvssScore = 6.5, PublishedDate = "2023-08-18", FixVersion = "6.3.1" },
                    }
                },
                {
                    "ASP.NET", new List<CveInfo>
                    {
                        new CveInfo { CveId = "CVE-2023-36805", Severity = "High", Description = "ASP.NET Core信息泄露", CvssScore = 7.5, PublishedDate = "2023-09-12", FixVersion = ".NET 7.0.11" },
                        new CveInfo { CveId = "CVE-2023-35186", Severity = "Medium", Description = "ASP.NET Core拒绝服务", CvssScore = 7.5, PublishedDate = "2023-07-11", FixVersion = ".NET 7.0.10" },
                    }
                },
                {
                    "PHP", new List<CveInfo>
                    {
                        new CveInfo { CveId = "CVE-2023-5785", Severity = "High", Description = "PHP整数溢出漏洞", CvssScore = 8.1, PublishedDate = "2024-01-02", FixVersion = "8.2.14" },
                        new CveInfo { CveId = "CVE-2024-1874", Severity = "Critical", Description = "PHP CGI远程代码执行", CvssScore = 9.8, PublishedDate = "2024-03-20", FixVersion = "8.3.4" },
                    }
                },
            };

            if (cveDatabase.TryGetValue(techName, out var cves))
            {
                techVulns.KnownVulnerabilities = cves;
            }

            return techVulns;
        }

        public async Task<WebPortScanResult> ScanCommonPorts(string targetUrl, CancellationToken cancellationToken = default)
        {
            var result = new WebPortScanResult();
            var stopwatch = System.Diagnostics.Stopwatch.StartNew();

            try
            {
                var uri = new Uri(targetUrl);
                var host = uri.Host;
                result.Host = host;

                var commonWebPorts = new Dictionary<int, string>
                {
                    { 80, "HTTP" },
                    { 443, "HTTPS" },
                    { 8080, "HTTP Proxy" },
                    { 8443, "HTTPS Alt" },
                    { 8888, "HTTP Alt" },
                    { 3000, "Node.js" },
                    { 5000, "Flask/Development" },
                    { 5432, "PostgreSQL" },
                    { 3306, "MySQL" },
                    { 6379, "Redis" },
                    { 27017, "MongoDB" },
                    { 9200, "Elasticsearch" },
                    { 8000, "Django/Go" },
                    { 9090, "Grafana" },
                    { 22, "SSH" },
                    { 21, "FTP" },
                    { 23, "Telnet" },
                    { 25, "SMTP" },
                    { 53, "DNS" },
                    { 110, "POP3" },
                    { 143, "IMAP" },
                    { 3389, "RDP" },
                };

                result.TotalScanned = commonWebPorts.Count;

                var tasks = commonWebPorts.Select(async kvp =>
                {
                    var port = kvp.Key;
                    var service = kvp.Value;
                    var portStopwatch = System.Diagnostics.Stopwatch.StartNew();

                    try
                    {
                        using var client = new System.Net.Sockets.TcpClient();
                        var connectTask = client.ConnectAsync(host, port);
                        if (await Task.WhenAny(connectTask, Task.Delay(2000, cancellationToken)) == connectTask)
                        {
                            portStopwatch.Stop();
                            if (client.Connected)
                            {
                                return new WebPortInfo
                                {
                                    Port = port,
                                    Service = service,
                                    IsOpen = true,
                                    ResponseTime = portStopwatch.Elapsed
                                };
                            }
                        }
                    }
                    catch { }

                    return new WebPortInfo { Port = port, Service = service, IsOpen = false };
                }).ToList();

                var portResults = await Task.WhenAll(tasks);
                result.OpenPorts = portResults.Where(p => p.IsOpen).ToList();
            }
            catch { }

            stopwatch.Stop();
            result.ScanDuration = stopwatch.Elapsed;
            return result;
        }

        public async Task<List<ApiTestResult>> TestApiMethods(string baseUrl, CancellationToken cancellationToken = default)
        {
            var results = new List<ApiTestResult>();
            var httpMethods = new[] { "GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD" };

            foreach (var method in httpMethods)
            {
                try
                {
                    var request = new HttpRequestMessage(new HttpMethod(method), baseUrl);
                    var response = await _httpClient.SendAsync(request, cancellationToken);

                    var testResult = new ApiTestResult
                    {
                        Url = baseUrl,
                        Method = method,
                        StatusCode = (int)response.StatusCode,
                        IsAccessible = (int)response.StatusCode >= 200 && (int)response.StatusCode < 300
                    };

                    if (response.Content != null)
                    {
                        var content = await response.Content.ReadAsStringAsync(cancellationToken);
                        testResult.ResponsePreview = content.Length > 100 ? content.Substring(0, 100) + "..." : content;
                    }

                    if (method == "OPTIONS" && response.Headers.TryGetValues("Allow", out var allowValues))
                    {
                        testResult.AllowedMethods = allowValues.First().Split(',').Select(m => m.Trim()).ToList();
                    }

                    results.Add(testResult);
                }
                catch { }
            }

            return results;
        }

        private List<string> CheckParamVulnerabilities(HttpResponseMessage response)
        {
            var hints = new List<string>();

            var securityHeaders = new Dictionary<string, string>
            {
                { "X-XSS-Protection", "缺少XSS保护" },
                { "X-Frame-Options", "可能被点击劫持" },
                { "X-Content-Type-Options", "可能MIME嗅探" },
                { "Strict-Transport-Security", "可能被SSL剥离" },
                { "Content-Security-Policy", "缺少内容安全策略" },
                { "Referrer-Policy", "可能泄露引用信息" },
                { "Permissions-Policy", "缺少权限策略" },
            };

            foreach (var (header, hint) in securityHeaders)
            {
                if (!response.Headers.Contains(header))
                {
                    hints.Add(hint);
                }
            }

            return hints;
        }

        private async Task<Layer2Result> Layer2TraceAsync(string url, CancellationToken cancellationToken)
        {
            OnLog?.Invoke("第二层: HTML内容分析...");
            var result = new Layer2Result();
            var currentUrl = url;

            try
            {
                var html = await _httpClient.GetStringAsync(url, cancellationToken);
                result.HtmlSource = html;

                var loginPatterns = new[] { "login", "signin", "auth", "session" };
                foreach (var pattern in loginPatterns)
                {
                    var regex = new Regex($"href=[\"']([^\"']*{pattern}[^\"']*)[\"']", RegexOptions.IgnoreCase);
                    foreach (Match match in regex.Matches(html))
                    {
                        var link = match.Groups[1].Value;
                        result.FoundLoginLinks.Add(link);
                    }
                }

                var jsRedirectRegex = new Regex(@"(?:window\.location|location\.href|location\.replace)\s*=\s*['""](.*?)['""]", RegexOptions.IgnoreCase);
                foreach (Match match in jsRedirectRegex.Matches(html))
                {
                    result.JsRedirectUrls.Add(match.Groups[1].Value);
                }

                var hrefRegex = new Regex(@"href=['""]([^'""]+)['""]", RegexOptions.IgnoreCase);
                foreach (Match match in hrefRegex.Matches(html))
                {
                    var href = match.Groups[1].Value;
                    var category = ClassifyLink(href);
                    result.AllLinks.Add(new ClassifiedLink
                    {
                        Url = href,
                        Text = "",
                        Category = category,
                        Source = "HTML"
                    });
                }

                var jsSrcRegex = new Regex(@"<script[^>]+src=[""']([^""']+)[""']", RegexOptions.IgnoreCase);
                foreach (Match match in jsSrcRegex.Matches(html))
                {
                    result.ScriptFiles.Add(match.Groups[1].Value);
                }

                var linkHrefRegex = new Regex(@"<link[^>]+href=[""']([^""']+)[""']", RegexOptions.IgnoreCase);
                foreach (Match match in linkHrefRegex.Matches(html))
                {
                    var linkHref = match.Groups[1].Value;
                    if (!linkHref.StartsWith("data:") && !linkHref.StartsWith("http"))
                    {
                        result.InternalResources.Add(new Uri(new Uri(currentUrl), linkHref).ToString());
                    }
                }

                var formActionRegex = new Regex(@"<form[^>]+action=[""']([^""']*)[""']", RegexOptions.IgnoreCase);
                foreach (Match match in formActionRegex.Matches(html))
                {
                    var action = match.Groups[1].Value;
                    result.FoundForms.Add(string.IsNullOrEmpty(action) ? currentUrl : new Uri(new Uri(currentUrl), action).ToString());
                }

                var imgSrcRegex = new Regex(@"<img[^>]+src=[""']([^""']+)[""']", RegexOptions.IgnoreCase);
                foreach (Match match in imgSrcRegex.Matches(html))
                {
                    var imgSrc = match.Groups[1].Value;
                    if (!imgSrc.StartsWith("data:") && !imgSrc.StartsWith("http"))
                    {
                        result.InternalResources.Add(new Uri(new Uri(currentUrl), imgSrc).ToString());
                    }
                }

                var iframeSrcRegex = new Regex(@"<iframe[^>]+src=[""']([^""']+)[""']", RegexOptions.IgnoreCase);
                foreach (Match match in iframeSrcRegex.Matches(html))
                {
                    var iframeSrc = match.Groups[1].Value;
                    if (!iframeSrc.StartsWith("http"))
                    {
                        iframeSrc = new Uri(new Uri(currentUrl), iframeSrc).ToString();
                    }
                    result.FoundIframes.Add(iframeSrc);
                }

                var restfulPattern = new Regex(@"/([a-zA-Z_]+)/\{?([a-zA-Z0-9_]+)\}?|\{([a-zA-Z0-9_]+)\}", RegexOptions.IgnoreCase);
                foreach (Match match in restfulPattern.Matches(currentUrl))
                {
                    var param = match.Value.TrimStart('{').TrimEnd('}');
                    if (!string.IsNullOrEmpty(param))
                    {
                        result.RestfulParams.Add(param);
                    }
                }

                var jsApiPatterns = new[]
                {
                    @"fetch\(['""]([^""']+)['""]",
                    @"axios\.(get|post|put|delete)\(['""]([^""']+)['""]",
                    @"\$\.ajax\(\{[^}]*url:\s*['""]([^""']+)['""]",
                    @"XMLHttpRequest[^;]*open\(['""]\w+['""],\s*['""]([^""']+)['""]",
                    @"\.post\(['""]([^""']+)['""]",
                    @"\.get\(['""]([^""']+)['""]"
                };

                foreach (var jsPattern in jsApiPatterns)
                {
                    var apiRegex = new Regex(jsPattern, RegexOptions.IgnoreCase);
                    foreach (Match match in apiRegex.Matches(html))
                    {
                        var apiUrl = match.Groups.Count > 1 ? match.Groups[1].Value : match.Value;
                        if (!string.IsNullOrEmpty(apiUrl) && !apiUrl.StartsWith("http"))
                        {
                            result.DiscoveredAjaxCalls.Add(new Uri(new Uri(currentUrl), apiUrl).ToString());
                        }
                        else if (!string.IsNullOrEmpty(apiUrl))
                        {
                            result.DiscoveredAjaxCalls.Add(apiUrl);
                        }
                    }
                }

                var dataAttrRegex = new Regex(@"data-(?:src|href|url)=[""']([^""']+)[""']", RegexOptions.IgnoreCase);
                foreach (Match match in dataAttrRegex.Matches(html))
                {
                    var dataUrl = match.Groups[1].Value;
                    if (!dataUrl.StartsWith("data:") && !dataUrl.StartsWith("http"))
                    {
                        result.InternalResources.Add(new Uri(new Uri(currentUrl), dataUrl).ToString());
                    }
                }

                OnLog?.Invoke($"HTML分析完成 - 登录链接: {result.FoundLoginLinks.Count}, JS跳转: {result.JsRedirectUrls.Count}, JS文件: {result.ScriptFiles.Count}, 表单: {result.FoundForms.Count}");
            }
            catch (Exception ex)
            {
                result.Error = ex.Message;
            }

            return result;
        }

        private async Task<Layer3Result> Layer3TraceAsync(string url, CancellationToken cancellationToken)
        {
            OnLog?.Invoke("第三层: 敏感文件检测...");
            var result = new Layer3Result();

            var sensitiveFiles = new[]
            {
                "robots.txt", "sitemap.xml", ".env", "web.config", "config.json",
                "package.json", "composer.json", "Gemfile", "pom.xml", "build.gradle",
                ".git/HEAD", ".svn/entries", ".DS_Store", "crossdomain.xml",
                "security.txt", "humans.txt", "favicon.ico",
                "wp-config.php", "wp-login.php", "xmlrpc.php",
                "admin/config.php", "phpinfo.php", "info.php",
                "api/swagger.json", "api-docs", "swagger-ui.html",
                "actuator/health", "actuator/env", "actuator/configprops",
                "debug/pprof", "metrics", "health", "status"
            };

            var uri = new Uri(url);
            var baseUrl = uri.GetLeftPart(UriPartial.Authority);

            foreach (var file in sensitiveFiles)
            {
                try
                {
                    var testUrl = baseUrl + "/" + file;
                    var response = await _httpClient.GetAsync(testUrl, cancellationToken);
                    if (response.StatusCode == System.Net.HttpStatusCode.OK)
                    {
                        result.FoundUrls.Add(testUrl);
                        OnLog?.Invoke($"发现敏感文件: {testUrl}");
                    }
                }
                catch { }
            }

            try
            {
                var robotsUrl = baseUrl + "/robots.txt";
                var robotsContent = await _httpClient.GetStringAsync(robotsUrl, cancellationToken);
                var disallowRegex = new Regex(@"Disallow:\s*(.+)", RegexOptions.IgnoreCase);
                foreach (Match match in disallowRegex.Matches(robotsContent))
                {
                    result.DisallowPaths.Add(match.Groups[1].Value.Trim());
                }

                var allowRegex = new Regex(@"Allow:\s*(.+)", RegexOptions.IgnoreCase);
                foreach (Match match in allowRegex.Matches(robotsContent))
                {
                    result.AllowPaths.Add(match.Groups[1].Value.Trim());
                }
            }
            catch { }

            try
            {
                var sitemapUrl = baseUrl + "/sitemap.xml";
                var response = await _httpClient.GetAsync(sitemapUrl, cancellationToken);
                if (response.StatusCode == System.Net.HttpStatusCode.OK)
                {
                    result.SitemapUrls.Add(sitemapUrl);
                }
            }
            catch { }

            OnLog?.Invoke($"敏感文件检测完成 - 发现: {result.FoundUrls.Count} 个");
            return result;
        }

        private async Task<DirectoryBruteResult> DirectoryBruteAsync(string url, CancellationToken cancellationToken)
        {
            OnLog?.Invoke("目录爆破: 开始测试常见路径...");
            var result = new DirectoryBruteResult();

            var commonPaths = new[]
            {
                "admin", "login", "register", "api", "dashboard", "console",
                "manager", "manage", "panel", "control", "backend", "cms",
                "wp-admin", "wp-content", "wp-includes",
                "assets", "static", "public", "resources", "files", "uploads",
                "docs", "documentation", "api-docs", "swagger",
                "config", "configuration", "settings", "setup",
                "test", "tests", "debug", "dev", "development", "staging",
                "backup", "backups", "old", "archive", "temp", "tmp",
                "data", "database", "db", "sql", "dump",
                "install", "setup", "init", "bootstrap",
                "graphql", "rest", "v1", "v2", "v3",
                "auth", "oauth", "sso", "ldap", "login", "logout", "signin", "signup",
                "user", "users", "profile", "account", "account", "settings",
                "search", "query", "filter", "sort", "order",
                "health", "status", "ping", "metrics", "monitor",
                "actuator", "actuator/health", "actuator/info", "actuator/metrics",
                ".git", ".env", ".svn", ".htaccess", ".htpasswd", "web.config"
            };

            var uri = new Uri(url);
            var baseUrl = uri.GetLeftPart(UriPartial.Authority);

            result.TotalTested = commonPaths.Length;

            foreach (var path in commonPaths)
            {
                if (cancellationToken.IsCancellationRequested) break;

                try
                {
                    var testUrl = baseUrl + "/" + path;
                    var response = await _httpClient.GetAsync(testUrl, cancellationToken);
                    var statusCode = (int)response.StatusCode;

                    if (statusCode == 200 || statusCode == 403 || statusCode == 401)
                    {
                        var discoveredPath = new DiscoveredPath
                        {
                            Url = testUrl,
                            StatusCode = statusCode,
                            Source = "directory_brute",
                            PathType = path,
                            Confidence = statusCode == 200 ? 90 : statusCode == 403 ? 70 : 60,
                            ContentLength = response.Content.Headers.ContentLength ?? 0,
                            Depth = 1
                        };

                        result.FoundPaths.Add(discoveredPath);

                        if (!result.ByStatusCode.ContainsKey(statusCode))
                            result.ByStatusCode[statusCode] = new List<DiscoveredPath>();
                        result.ByStatusCode[statusCode].Add(discoveredPath);
                    }
                }
                catch { }
            }

            OnLog?.Invoke($"目录爆破完成 - 测试: {result.TotalTested}, 发现: {result.FoundPaths.Count} 个路径");
            return result;
        }

        private async Task<DeepCrawlResult> DeepCrawlAsync(string url, CancellationToken cancellationToken)
        {
            OnLog?.Invoke($"深度爬取: 开始 (最大深度: {MaxCrawlDepth})...");
            var result = new DeepCrawlResult { MaxDepth = MaxCrawlDepth };
            var visited = new HashSet<string>();
            var queue = new Queue<(string Url, int Depth)>();

            var baseUri = new Uri(url);
            var baseHost = baseUri.Host;

            queue.Enqueue((url, 0));

            while (queue.Count > 0 && !cancellationToken.IsCancellationRequested)
            {
                var (currentUrl, depth) = queue.Dequeue();

                if (depth > MaxCrawlDepth || visited.Contains(currentUrl))
                    continue;

                visited.Add(currentUrl);
                result.TotalCrawled++;
                result.CrawledUrls.Add(currentUrl);

                try
                {
                    var html = await _httpClient.GetStringAsync(currentUrl, cancellationToken);

                    var hrefRegex = new Regex(@"href=['""]([^'""]+)['""]", RegexOptions.IgnoreCase);
                    foreach (Match match in hrefRegex.Matches(html))
                    {
                        var href = match.Groups[1].Value;

                        if (string.IsNullOrEmpty(href) || href.StartsWith("#") || href.StartsWith("javascript:") || href.StartsWith("mailto:"))
                            continue;

                        string absoluteUrl;
                        try
                        {
                            absoluteUrl = new Uri(new Uri(currentUrl), href).ToString();
                        }
                        catch { continue; }

                        if (visited.Contains(absoluteUrl))
                            continue;

                        if (SameDomainOnly)
                        {
                            var targetUri = new Uri(absoluteUrl);
                            if (targetUri.Host != baseHost)
                                continue;
                        }

                        queue.Enqueue((absoluteUrl, depth + 1));
                        result.FoundPaths.Add(new DiscoveredPath
                        {
                            Url = absoluteUrl,
                            Source = "crawl",
                            PathType = "link",
                            Depth = depth + 1
                        });
                    }

                    await DelayAsync(cancellationToken);
                }
                catch { }
            }

            OnLog?.Invoke($"深度爬取完成 - 爬取: {result.TotalCrawled} 页面, 发现: {result.FoundPaths.Count} 链接");
            return result;
        }

        private static string ClassifyLink(string href)
        {
            if (string.IsNullOrEmpty(href)) return "other";
            var lower = href.ToLower();
            if (lower.Contains("login") || lower.Contains("signin") || lower.Contains("auth")) return "login";
            if (lower.Contains("admin") || lower.Contains("manage") || lower.Contains("dashboard")) return "admin";
            if (lower.Contains("api") || lower.Contains("rest") || lower.Contains("graphql")) return "api";
            if (lower.Contains("register") || lower.Contains("signup")) return "register";
            if (lower.Contains("form") || lower.Contains("submit")) return "form";
            return "other";
        }
    }
}
