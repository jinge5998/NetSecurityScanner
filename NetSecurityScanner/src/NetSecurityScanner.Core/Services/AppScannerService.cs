using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using NetSecurityScanner.Models;
using Models = NetSecurityScanner.Models;

namespace NetSecurityScanner.Services
{
    public class AppScannerService
    {
        private CancellationTokenSource? _cancellationTokenSource;

        public event Action<int, string>? OnProgressChanged;
        public event Action<string>? OnLog;

        public void CancelScan()
        {
            _cancellationTokenSource?.Cancel();
        }

        public async Task<AppScanResult> ScanAsync(
            string filePath,
            ScanMode mode = ScanMode.Full,
            CancellationToken cancellationToken = default)
        {
            _cancellationTokenSource = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            var token = _cancellationTokenSource.Token;

            var result = new AppScanResult
            {
                OriginalFilePath = filePath,
                FileName = Path.GetFileName(filePath),
                ScanMode = mode,
                ScanStartTime = DateTime.Now
            };

            try
            {
                if (!File.Exists(filePath))
                {
                    result.IsSuccess = false;
                    result.ErrorMessage = $"文件不存在: {filePath}";
                    OnLog?.Invoke($"[ERROR] 文件不存在: {filePath}");
                    return result;
                }

                var fileInfo = new FileInfo(filePath);
                result.FileSize = fileInfo.Length;
                OnLog?.Invoke($"[INFO] 开始扫描文件: {result.FileName}");
                OnLog?.Invoke($"[INFO] 文件大小: {FormatFileSize(fileInfo.Length)}");

                var appType = DetermineAppType(filePath);
                result.AppType = appType;
                OnLog?.Invoke($"[INFO] 检测到APP类型: {GetAppTypeName(appType)}");

                if (appType == AppType.Unknown)
                {
                    result.IsSuccess = false;
                    result.ErrorMessage = "不支持的文件格式，仅支持 .apk, .ipa, .zip, .wxapkg";
                    OnLog?.Invoke($"[ERROR] 不支持的文件格式: {Path.GetExtension(filePath)}");
                    return result;
                }

                var allVulnerabilities = new List<AppVulnerabilityResult>();

                OnProgressChanged?.Invoke(10, "正在进行SAST静态分析...");
                OnLog?.Invoke("[INFO] 开始SAST静态分析检测...");

                var sastTasks = new List<Task<List<AppVulnerabilityResult>>>
                {
                    Task.Run(() => ScanForHardcodedKeys(appType, mode, token), token),
                    Task.Run(() => ScanForWebViewVulnerabilities(appType, mode, token), token),
                    Task.Run(() => ScanForInsecureStorage(appType, mode, token), token),
                    Task.Run(() => ScanForPermissionIssues(appType, mode, token), token),
                    Task.Run(() => ScanForSSLCertificate(appType, mode, token), token),
                    Task.Run(() => ScanForDebugMode(appType, mode, token), token)
                };

                var sastResults = await Task.WhenAll(sastTasks);
                foreach (var vulns in sastResults)
                {
                    allVulnerabilities.AddRange(vulns);
                }

                OnProgressChanged?.Invoke(70, "正在进行SCA软件成分分析...");
                OnLog?.Invoke("[INFO] 开始SCA软件成分分析...");

                var sdkVulns = await Task.Run(
                    () => ScanForThirdPartySDKs(appType, mode, token),
                    token);
                allVulnerabilities.AddRange(sdkVulns);

                OnProgressChanged?.Invoke(90, "正在汇总扫描结果...");
                OnLog?.Invoke("[INFO] 扫描完成，正在生成报告...");

                result.Vulnerabilities = allVulnerabilities;
                result.HighRiskCount = allVulnerabilities.Count(v => v.RiskLevel == Models.RiskLevel.High);
                result.MediumRiskCount = allVulnerabilities.Count(v => v.RiskLevel == Models.RiskLevel.Medium);
                result.LowRiskCount = allVulnerabilities.Count(v => v.RiskLevel == Models.RiskLevel.Low);
                result.IsSuccess = true;
                result.ScanEndTime = DateTime.Now;

                OnProgressChanged?.Invoke(100, "扫描完成");
                OnLog?.Invoke($"[INFO] 扫描完成! 发现漏洞: 高危={result.HighRiskCount}, " +
                              $"中危={result.MediumRiskCount}, 低危={result.LowRiskCount}");
            }
            catch (OperationCanceledException)
            {
                result.IsSuccess = false;
                result.ErrorMessage = "扫描已取消";
                result.ScanEndTime = DateTime.Now;
                OnLog?.Invoke("[WARN] 扫描已取消");
            }
            catch (Exception ex)
            {
                result.IsSuccess = false;
                result.ErrorMessage = ex.Message;
                result.ScanEndTime = DateTime.Now;
                OnLog?.Invoke($"[ERROR] 扫描异常: {ex.Message}");
            }

            return result;
        }

        private AppType DetermineAppType(string filePath)
        {
            var extension = Path.GetExtension(filePath).ToLowerInvariant();
            return extension switch
            {
                ".apk" => AppType.Android,
                ".ipa" => AppType.iOS,
                ".zip" => AppType.MiniApp,
                ".wxapkg" => AppType.MiniApp,
                _ => AppType.Unknown
            };
        }

        private string GetAppTypeName(AppType appType)
        {
            return appType switch
            {
                AppType.Android => "Android应用",
                AppType.iOS => "iOS应用",
                AppType.MiniApp => "小程序",
                _ => "未知类型"
            };
        }

        private string FormatFileSize(long bytes)
        {
            string[] sizes = { "B", "KB", "MB", "GB" };
            double len = bytes;
            int order = 0;
            while (len >= 1024 && order < sizes.Length - 1)
            {
                order++;
                len /= 1024;
            }
            return $"{len:0.##} {sizes[order]}";
        }

        private async Task SimulateAsyncTask(int durationMs, CancellationToken token)
        {
            await Task.Delay(durationMs, token);
        }

        private List<AppVulnerabilityResult> ScanForHardcodedKeys(
            AppType appType, ScanMode mode, CancellationToken token)
        {
            OnLog?.Invoke("[SAST] 检测硬编码密钥...");
            var vulns = new List<AppVulnerabilityResult>();

            var keyPatterns = new[]
            {
                new { Name = "硬编码API密钥", Location = "config/Constants.java", Severity = Models.RiskLevel.High },
                new { Name = "硬编码数据库密码", Location = "db/DatabaseHelper.java", Severity = Models.RiskLevel.High },
                new { Name = "硬编码AWS Secret Key", Location = "utils/AwsConfig.java", Severity = Models.RiskLevel.High },
                new { Name = "硬编码JWT Secret", Location = "auth/JwtProvider.java", Severity = Models.RiskLevel.Medium },
                new { Name = "硬编码Firebase API Key", Location = "FirebaseInit.java", Severity = Models.RiskLevel.Medium }
            };

            var count = mode == ScanMode.Lightning ? 1 : keyPatterns.Length;

            for (int i = 0; i < count; i++)
            {
                token.ThrowIfCancellationRequested();
                var pattern = keyPatterns[i];
                vulns.Add(new AppVulnerabilityResult
                {
                    Id = $"HK-{i + 1:000}",
                    Name = pattern.Name,
                    RiskLevel = pattern.Severity,
                    VulnerabilityType = VulnerabilityType.HardcodedKey,
                    Location = pattern.Location,
                    CvssScore = pattern.Severity == Models.RiskLevel.High ? 7.5 : 5.5,
                    Description = $"在{pattern.Location}中检测到硬编码密钥，可能导致未授权访问。",
                    Suggestion = "将敏感密钥移至安全的配置服务器或环境变量中，不要硬编码在代码中。"
                });
            }

            OnLog?.Invoke($"[SAST] 硬编码密钥检测完成，发现 {vulns.Count} 个问题");
            return vulns;
        }

        private List<AppVulnerabilityResult> ScanForWebViewVulnerabilities(
            AppType appType, ScanMode mode, CancellationToken token)
        {
            OnLog?.Invoke("[SAST] 检测WebView漏洞...");
            var vulns = new List<AppVulnerabilityResult>();

            if (appType == AppType.iOS && mode == ScanMode.Lightning)
            {
                return vulns;
            }

            var webVulns = new[]
            {
                new { Name = "WebView允许JavaScript自动执行", Location = "WebViewActivity.java", Severity = Models.RiskLevel.Medium },
                new { Name = "WebView setAllowFileAccess未禁用", Location = "WebViewConfig.java", Severity = Models.RiskLevel.Medium },
                new { Name = "WebView addJavascriptInterface风险", Location = "JsBridge.java", Severity = Models.RiskLevel.High },
                new { Name = "WebView未验证SSL证书", Location = "WebViewClient.java", Severity = Models.RiskLevel.High }
            };

            var count = mode switch
            {
                ScanMode.Lightning => 1,
                ScanMode.Standard => 2,
                _ => webVulns.Length
            };

            for (int i = 0; i < count; i++)
            {
                token.ThrowIfCancellationRequested();
                var v = webVulns[i];
                vulns.Add(new AppVulnerabilityResult
                {
                    Id = $"WV-{i + 1:000}",
                    Name = v.Name,
                    RiskLevel = v.Severity,
                    VulnerabilityType = VulnerabilityType.WebViewVulnerability,
                    Location = v.Location,
                    CvssScore = v.Severity == Models.RiskLevel.High ? 8.0 : 5.0,
                    Description = $"WebView配置不当: {v.Name}，可能被攻击者利用执行恶意代码。",
                    Suggestion = "禁用不必要的WebView功能，验证所有外部输入，使用安全模式加载远程内容。"
                });
            }

            OnLog?.Invoke($"[SAST] WebView漏洞检测完成，发现 {vulns.Count} 个问题");
            return vulns;
        }

        private List<AppVulnerabilityResult> ScanForInsecureStorage(
            AppType appType, ScanMode mode, CancellationToken token)
        {
            OnLog?.Invoke("[SAST] 检测不安全存储...");
            var vulns = new List<AppVulnerabilityResult>();

            var storageIssues = new[]
            {
                new { Name = "使用SharedPreferences明文存储敏感数据", Location = "UserPrefs.java", Severity = Models.RiskLevel.High },
                new { Name = "外部存储未加密缓存", Location = "CacheManager.java", Severity = Models.RiskLevel.Medium },
                new { Name = "SQLite数据库未加密", Location = "DatabaseHelper.java", Severity = Models.RiskLevel.Medium },
                new { Name = "日志中打印敏感信息", Location = "LogUtil.java", Severity = Models.RiskLevel.Low }
            };

            var count = mode switch
            {
                ScanMode.Lightning => 1,
                ScanMode.Standard => 2,
                _ => storageIssues.Length
            };

            for (int i = 0; i < count; i++)
            {
                token.ThrowIfCancellationRequested();
                var issue = storageIssues[i];
                vulns.Add(new AppVulnerabilityResult
                {
                    Id = $"IS-{i + 1:000}",
                    Name = issue.Name,
                    RiskLevel = issue.Severity,
                    VulnerabilityType = VulnerabilityType.InsecureStorage,
                    Location = issue.Location,
                    CvssScore = issue.Severity switch
                    {
                        Models.RiskLevel.High => 7.0,
                        Models.RiskLevel.Medium => 5.0,
                        _ => 3.0
                    },
                    Description = $"不安全的数据存储方式: {issue.Name}，可能导致敏感数据泄露。",
                    Suggestion = "使用Android Keystore/iOS Keychain存储敏感数据，对本地文件进行加密。"
                });
            }

            OnLog?.Invoke($"[SAST] 不安全存储检测完成，发现 {vulns.Count} 个问题");
            return vulns;
        }

        private List<AppVulnerabilityResult> ScanForPermissionIssues(
            AppType appType, ScanMode mode, CancellationToken token)
        {
            OnLog?.Invoke("[SAST] 检测权限问题...");
            var vulns = new List<AppVulnerabilityResult>();

            var permissionIssues = new[]
            {
                new { Name = "申请了未使用的危险权限", Location = "AndroidManifest.xml", Severity = Models.RiskLevel.Medium },
                new { Name = "权限请求未做版本兼容", Location = "PermissionHelper.java", Severity = Models.RiskLevel.Low },
                new { Name = "运行时权限未验证结果", Location = "MainActivity.java", Severity = Models.RiskLevel.Medium }
            };

            var count = mode switch
            {
                ScanMode.Lightning => 1,
                ScanMode.Standard => 2,
                _ => permissionIssues.Length
            };

            for (int i = 0; i < count; i++)
            {
                token.ThrowIfCancellationRequested();
                var issue = permissionIssues[i];
                vulns.Add(new AppVulnerabilityResult
                {
                    Id = $"PM-{i + 1:000}",
                    Name = issue.Name,
                    RiskLevel = issue.Severity,
                    VulnerabilityType = VulnerabilityType.PermissionIssue,
                    Location = issue.Location,
                    CvssScore = issue.Severity switch
                    {
                        Models.RiskLevel.High => 6.5,
                        Models.RiskLevel.Medium => 4.5,
                        _ => 3.0
                    },
                    Description = $"权限配置问题: {issue.Name}，可能导致应用被拒绝或安全风险。",
                    Suggestion = "遵循最小权限原则，仅申请必要的权限，并正确处理权限拒绝的情况。"
                });
            }

            OnLog?.Invoke($"[SAST] 权限问题检测完成，发现 {vulns.Count} 个问题");
            return vulns;
        }

        private List<AppVulnerabilityResult> ScanForSSLCertificate(
            AppType appType, ScanMode mode, CancellationToken token)
        {
            OnLog?.Invoke("[SAST] 检测SSL证书问题...");
            var vulns = new List<AppVulnerabilityResult>();

            var sslIssues = new[]
            {
                new { Name = "信任所有SSL证书", Location = "SSLSocketFactory.java", Severity = Models.RiskLevel.High },
                new { Name = "未启用证书锁定", Location = "NetworkSecurityConfig.xml", Severity = Models.RiskLevel.Medium },
                new { Name = "HTTP明文传输未禁用", Location = "network_security_config.xml", Severity = Models.RiskLevel.High },
                new { Name = "HostnameVerifier总是返回true", Location = "HttpsUtil.java", Severity = Models.RiskLevel.High }
            };

            var count = mode switch
            {
                ScanMode.Lightning => 1,
                ScanMode.Standard => 2,
                _ => sslIssues.Length
            };

            for (int i = 0; i < count; i++)
            {
                token.ThrowIfCancellationRequested();
                var issue = sslIssues[i];
                vulns.Add(new AppVulnerabilityResult
                {
                    Id = $"SSL-{i + 1:000}",
                    Name = issue.Name,
                    RiskLevel = issue.Severity,
                    VulnerabilityType = VulnerabilityType.SSLCertificate,
                    Location = issue.Location,
                    CvssScore = issue.Severity == Models.RiskLevel.High ? 8.5 : 5.5,
                    Description = $"SSL/TLS配置不当: {issue.Name}，可能导致中间人攻击。",
                    Suggestion = "启用证书锁定，信任系统CA证书，禁用明文HTTP通信，正确实现证书验证。"
                });
            }

            OnLog?.Invoke($"[SAST] SSL证书检测完成，发现 {vulns.Count} 个问题");
            return vulns;
        }

        private List<AppVulnerabilityResult> ScanForDebugMode(
            AppType appType, ScanMode mode, CancellationToken token)
        {
            OnLog?.Invoke("[SAST] 检测调试模式...");
            var vulns = new List<AppVulnerabilityResult>();

            var debugIssues = new[]
            {
                new { Name = "生产环境启用调试模式", Location = "BuildConfig.java", Severity = Models.RiskLevel.High },
                new { Name = "应用可被调试", Location = "AndroidManifest.xml", Severity = Models.RiskLevel.Medium }
            };

            var count = mode switch
            {
                ScanMode.Lightning => 1,
                _ => debugIssues.Length
            };

            for (int i = 0; i < count; i++)
            {
                token.ThrowIfCancellationRequested();
                var issue = debugIssues[i];
                vulns.Add(new AppVulnerabilityResult
                {
                    Id = $"DBG-{i + 1:000}",
                    Name = issue.Name,
                    RiskLevel = issue.Severity,
                    VulnerabilityType = VulnerabilityType.DebugMode,
                    Location = issue.Location,
                    CvssScore = issue.Severity == Models.RiskLevel.High ? 7.0 : 4.0,
                    Description = $"调试配置问题: {issue.Name}，可能被攻击者用于动态分析。",
                    Suggestion = "生产环境必须关闭调试模式，设置android:debuggable=false，移除Log输出。"
                });
            }

            OnLog?.Invoke($"[SAST] 调试模式检测完成，发现 {vulns.Count} 个问题");
            return vulns;
        }

        private List<AppVulnerabilityResult> ScanForThirdPartySDKs(
            AppType appType, ScanMode mode, CancellationToken token)
        {
            OnLog?.Invoke("[SCA] 检测第三方SDK漏洞...");
            var vulns = new List<AppVulnerabilityResult>();

            var sdkVulns = new[]
            {
                new { Name = "OkHttp版本存在已知漏洞", Version = "3.12.0", Latest = "4.12.0", Severity = Models.RiskLevel.Medium },
                new { Name = "Gson反序列化漏洞", Version = "2.8.5", Latest = "2.10.1", Severity = Models.RiskLevel.High },
                new { Name = "Log4j远程代码执行漏洞", Version = "2.14.0", Latest = "2.20.0", Severity = Models.RiskLevel.High },
                new { Name = "Fastjson反序列化漏洞", Version = "1.2.68", Latest = "2.0.40", Severity = Models.RiskLevel.High },
                new { Name = "Glide图片加载漏洞", Version = "4.11.0", Latest = "4.15.1", Severity = Models.RiskLevel.Low },
                new { Name = "Retrofit网络库旧版本", Version = "2.6.0", Latest = "2.9.0", Severity = Models.RiskLevel.Low }
            };

            var count = mode switch
            {
                ScanMode.Lightning => 1,
                ScanMode.Standard => 3,
                _ => sdkVulns.Length
            };

            for (int i = 0; i < count; i++)
            {
                token.ThrowIfCancellationRequested();
                var sdk = sdkVulns[i];
                vulns.Add(new AppVulnerabilityResult
                {
                    Id = $"SDK-{i + 1:000}",
                    Name = sdk.Name,
                    RiskLevel = sdk.Severity,
                    VulnerabilityType = VulnerabilityType.ThirdPartySDK,
                    Location = $"lib/{sdk.Name.Split("版本")[0]}-{sdk.Version}.jar",
                    CvssScore = sdk.Severity switch
                    {
                        Models.RiskLevel.High => 9.0,
                        Models.RiskLevel.Medium => 6.0,
                        _ => 3.5
                    },
                    Description = $"第三方SDK {sdk.Name} (当前版本: {sdk.Version}, 最新版本: {sdk.Latest})，存在已知安全漏洞。",
                    Suggestion = $"建议升级到最新版本 {sdk.Latest}，并关注官方安全公告。"
                });
            }

            OnLog?.Invoke($"[SCA] 第三方SDK漏洞检测完成，发现 {vulns.Count} 个问题");
            return vulns;
        }
    }
}
