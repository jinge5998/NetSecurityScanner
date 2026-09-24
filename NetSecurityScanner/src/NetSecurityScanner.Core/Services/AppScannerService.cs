using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Text;
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

            string? extractedPath = null;

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

                OnProgressChanged?.Invoke(5, "正在解压应用包...");
                OnLog?.Invoke("[INFO] 正在解压应用包...");
                extractedPath = await ExtractAppPackageAsync(filePath, appType, token);
                OnLog?.Invoke($"[INFO] 解压完成: {extractedPath}");

                OnProgressChanged?.Invoke(10, "正在进行SAST静态分析...");
                OnLog?.Invoke("[INFO] 开始SAST静态分析检测...");

                var sastTasks = new List<Task<List<AppVulnerabilityResult>>>
                {
                    Task.Run(() => ScanForHardcodedKeys(appType, mode, extractedPath, token), token),
                    Task.Run(() => ScanForWebViewVulnerabilities(appType, mode, extractedPath, token), token),
                    Task.Run(() => ScanForInsecureStorage(appType, mode, extractedPath, token), token),
                    Task.Run(() => ScanForPermissionIssues(appType, mode, extractedPath, token), token),
                    Task.Run(() => ScanForSSLCertificate(appType, mode, extractedPath, token), token),
                    Task.Run(() => ScanForDebugMode(appType, mode, extractedPath, token), token)
                };

                var sastResults = await Task.WhenAll(sastTasks);
                foreach (var vulns in sastResults)
                {
                    allVulnerabilities.AddRange(vulns);
                }

                if (appType == AppType.iOS)
                {
                    OnProgressChanged?.Invoke(40, "正在进行iOS深度安全分析...");
                    OnLog?.Invoke("[INFO] 开始iOS深度安全分析...");

                    var ipaResult = await AnalyzeIpaAsync(extractedPath, token);
                    if (ipaResult != null)
                    {
                        OnLog?.Invoke("[INFO] IPA分析完成，开始运行专项检测器...");

                        var detectorTasks = new List<Task<List<AppVulnerabilityResult>>>
                        {
                            Task.Run(async () =>
                            {
                                var r = await new PrivacyComplianceDetector().DetectAsync(ipaResult, mode, token);
                                return r.Vulnerabilities;
                            }, token),
                            Task.Run(async () =>
                            {
                                var r = await new StorageSecurityDetector().DetectAsync(ipaResult, mode, token);
                                return r.Vulnerabilities;
                            }, token),
                            Task.Run(async () =>
                            {
                                var r = await new DylibInjectionDetector().DetectAsync(ipaResult, mode, token);
                                return r.Vulnerabilities;
                            }, token),
                            Task.Run(async () =>
                            {
                                var r = await new ObfuscationDetector().DetectAsync(ipaResult, mode, token);
                                return r.Vulnerabilities;
                            }, token)
                        };

                        var detectorResults = await Task.WhenAll(detectorTasks);
                        foreach (var vulns in detectorResults)
                        {
                            allVulnerabilities.AddRange(vulns);
                        }
                        OnLog?.Invoke($"[INFO] iOS专项检测完成，发现 {detectorResults.Sum(v => v.Count)} 个问题");
                    }
                }

                OnProgressChanged?.Invoke(70, "正在进行SCA软件成分分析...");
                OnLog?.Invoke("[INFO] 开始SCA软件成分分析...");

                var sdkVulns = await Task.Run(
                    () => ScanForThirdPartySDKs(appType, mode, extractedPath, token),
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
            finally
            {
                if (!string.IsNullOrEmpty(extractedPath))
                {
                    try
                    {
                        if (Directory.Exists(extractedPath))
                        {
                            Directory.Delete(extractedPath, true);
                            OnLog?.Invoke($"[INFO] 已清理临时目录: {extractedPath}");
                        }
                    }
                    catch (Exception cleanupEx)
                    {
                        OnLog?.Invoke($"[WARN] 临时目录清理失败: {cleanupEx.Message}");
                    }
                }
            }

            return result;
        }

        private async Task<string> ExtractAppPackageAsync(string filePath, AppType appType, CancellationToken token)
        {
            var tempDir = Path.Combine(Path.GetTempPath(), $"appscan_{Guid.NewGuid():N}");
            Directory.CreateDirectory(tempDir);

            await Task.Run(() =>
            {
                try
                {
                    if (appType == AppType.iOS)
                    {
                        ZipFile.ExtractToDirectory(filePath, tempDir, true);
                    }
                    else
                    {
                        ZipFile.ExtractToDirectory(filePath, tempDir, true);
                    }
                }
                catch (Exception ex)
                {
                    OnLog?.Invoke($"[WARN] 解压失败，将基于文件名进行模拟分析: {ex.Message}");
                }
            }, token);

            return tempDir;
        }

        private async Task<IpaAnalysisResult?> AnalyzeIpaAsync(string extractedPath, CancellationToken token)
        {
            return await Task.Run(() =>
            {
                try
                {
                    var ipa = new IpaAnalysisResult
                    {
                        AnalyzedAt = DateTime.Now
                    };

                    var payloadDir = Path.Combine(extractedPath, "Payload");
                    if (!Directory.Exists(payloadDir))
                    {
                        OnLog?.Invoke("[WARN] 未找到 Payload 目录");
                        return ipa;
                    }

                    var appDirs = Directory.GetDirectories(payloadDir, "*.app");
                    if (appDirs.Length == 0)
                    {
                        OnLog?.Invoke("[WARN] 未找到 .app 目录");
                        return ipa;
                    }

                    var appDir = appDirs[0];
                    ipa.SizeBytes = Directory.GetFiles(appDir, "*", SearchOption.AllDirectories)
                        .Sum(f => new FileInfo(f).Length);

                    var infoPlistPath = Path.Combine(appDir, "Info.plist");
                    if (File.Exists(infoPlistPath))
                    {
                        ipa.InfoPlistRawText = File.ReadAllText(infoPlistPath);
                        ParseInfoPlist(ipa, ipa.InfoPlistRawText);
                    }

                    var allFiles = Directory.GetFiles(appDir, "*", SearchOption.AllDirectories).ToList();
                    ipa.Frameworks = allFiles
                        .Where(f => f.Contains(".framework"))
                        .Select(f => Path.GetFileName(f))
                        .Distinct()
                        .ToList();
                    ipa.SdkFiles = allFiles
                        .Where(f => f.EndsWith(".dylib") || f.Contains(".framework"))
                        .Select(f => Path.GetRelativePath(appDir, f))
                        .ToList();
                    ipa.NativeLibs = allFiles
                        .Where(f => f.EndsWith(".dylib"))
                        .Select(f => Path.GetFileName(f))
                        .ToList();

                    var exeName = Path.GetFileNameWithoutExtension(appDir);
                    var exePath = Path.Combine(appDir, exeName);
                    if (File.Exists(exePath))
                    {
                        ipa.MainExecutable = exeName;
                        ipa.MachOData = File.ReadAllBytes(exePath);
                        ipa.HasEncryptedBinary = CheckMachOEncryption(ipa.MachOData);
                    }

                    ipa.MachODylibs = ExtractDylibReferences(ipa.MachOData);
                    ipa.MachOSymbols = ExtractSymbols(ipa.MachOData, 500);
                    ipa.MachOFunctions = ExtractSymbols(ipa.MachOData, 200);

                    return ipa;
                }
                catch (Exception ex)
                {
                    OnLog?.Invoke($"[ERROR] IPA分析失败: {ex.Message}");
                    return new IpaAnalysisResult();
                }
            }, token);
        }

        private void ParseInfoPlist(IpaAnalysisResult ipa, string plistText)
        {
            try
            {
                var bundleIdMatch = System.Text.RegularExpressions.Regex.Match(plistText,
                    @"<key>CFBundleIdentifier</key>\s*<string>([^<]+)</string>");
                if (bundleIdMatch.Success) ipa.BundleId = bundleIdMatch.Groups[1].Value;

                var nameMatch = System.Text.RegularExpressions.Regex.Match(plistText,
                    @"<key>CFBundleDisplayName</key>\s*<string>([^<]+)</string>");
                if (nameMatch.Success) ipa.DisplayName = nameMatch.Groups[1].Value;

                var versionMatch = System.Text.RegularExpressions.Regex.Match(plistText,
                    @"<key>CFBundleShortVersionString</key>\s*<string>([^<]+)</string>");
                if (versionMatch.Success) ipa.Version = versionMatch.Groups[1].Value;

                var urlSchemes = System.Text.RegularExpressions.Regex.Matches(plistText,
                    @"<key>CFBundleURLSchemes</key>");
                ipa.UrlSchemes = new List<string>();
                foreach (System.Text.RegularExpressions.Match m in urlSchemes)
                {
                    ipa.UrlSchemes.Add(m.Value);
                }
            }
            catch { }
        }

        private bool CheckMachOEncryption(byte[]? data)
        {
            if (data == null || data.Length < 100) return false;
            try
            {
                int offset = 0;
                uint magic = BitConverter.ToUInt32(data, offset);
                bool is64 = magic == 0xFEEDFACF || magic == 0xCFFAEDFE;
                int headerSize = is64 ? 32 : 28;

                offset = headerSize;
                uint ncmds = BitConverter.ToUInt32(data, offset + 4);
                offset += 8;

                for (int i = 0; i < ncmds && offset < data.Length - 8; i++)
                {
                    uint cmd = BitConverter.ToUInt32(data, offset);
                    uint cmdsize = BitConverter.ToUInt32(data, offset + 4);
                    if (cmd == 0x21)
                    {
                        uint cryptid = BitConverter.ToUInt32(data, offset + 16);
                        return cryptid != 0;
                    }
                    offset += (int)cmdsize;
                }
            }
            catch { }
            return false;
        }

        private List<string> ExtractDylibReferences(byte[]? data)
        {
            var dylibs = new List<string>();
            if (data == null) return dylibs;

            try
            {
                var text = Encoding.ASCII.GetString(data);
                var matches = System.Text.RegularExpressions.Regex.Matches(text, @"/usr/lib/[a-zA-Z0-9_./\-]+\.dylib");
                foreach (System.Text.RegularExpressions.Match m in matches)
                {
                    if (!dylibs.Contains(m.Value))
                        dylibs.Add(m.Value);
                }
            }
            catch { }
            return dylibs;
        }

        private List<string> ExtractSymbols(byte[]? data, int maxCount)
        {
            var symbols = new List<string>();
            if (data == null) return symbols;

            try
            {
                var text = Encoding.ASCII.GetString(data);
                var matches = System.Text.RegularExpressions.Regex.Matches(text, @"[_][a-zA-Z_][a-zA-Z0-9_]{3,}");
                foreach (System.Text.RegularExpressions.Match m in matches)
                {
                    if (!symbols.Contains(m.Value))
                    {
                        symbols.Add(m.Value);
                        if (symbols.Count >= maxCount) break;
                    }
                }
            }
            catch { }
            return symbols;
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
            AppType appType, ScanMode mode, string extractedPath, CancellationToken token)
        {
            OnLog?.Invoke("[SAST] 检测硬编码密钥...");
            var vulns = new List<AppVulnerabilityResult>();

            var keyPatterns = new[]
            {
                new { Pattern = "api[_-]?key", Name = "硬编码API密钥", Severity = Models.RiskLevel.High },
                new { Pattern = "password", Name = "硬编码密码", Severity = Models.RiskLevel.High },
                new { Pattern = "secret[_-]?key", Name = "硬编码Secret Key", Severity = Models.RiskLevel.High },
                new { Pattern = "aws[_-]?secret", Name = "硬编码AWS Secret", Severity = Models.RiskLevel.High },
                new { Pattern = "jwt[_-]?secret", Name = "硬编码JWT Secret", Severity = Models.RiskLevel.Medium },
                new { Pattern = "firebase", Name = "硬编码Firebase Key", Severity = Models.RiskLevel.Medium }
            };

            try
            {
                var files = Directory.GetFiles(extractedPath, "*", SearchOption.AllDirectories)
                    .Where(f =>
                    {
                        var ext = Path.GetExtension(f).ToLower();
                        return ext == ".xml" || ext == ".json" || ext == ".properties" ||
                               ext == ".js" || ext == ".ts" || ext == ".txt" ||
                               ext == ".plist" || ext == ".config";
                    })
                    .Take(mode == ScanMode.Lightning ? 20 : mode == ScanMode.Standard ? 50 : 200)
                    .ToList();

                int vulnIndex = 1;
                foreach (var file in files)
                {
                    token.ThrowIfCancellationRequested();
                    try
                    {
                        var content = File.ReadAllText(file);
                        var relativePath = Path.GetRelativePath(extractedPath, file);

                        foreach (var kp in keyPatterns)
                        {
                            if (content.IndexOf(kp.Pattern, StringComparison.OrdinalIgnoreCase) >= 0)
                            {
                                vulns.Add(new AppVulnerabilityResult
                                {
                                    Id = $"HK-{vulnIndex++:000}",
                                    Name = kp.Name,
                                    RiskLevel = kp.Severity,
                                    VulnerabilityType = VulnerabilityType.HardcodedKey,
                                    Location = relativePath,
                                    CvssScore = kp.Severity == Models.RiskLevel.High ? 7.5 : 5.5,
                                    Description = $"在 {relativePath} 中检测到 {kp.Name}，可能导致未授权访问。",
                                    Suggestion = "将敏感密钥移至安全的配置服务器或环境变量中，不要硬编码在代码中。"
                                });
                            }
                        }
                    }
                    catch { }
                }
            }
            catch (Exception ex)
            {
                OnLog?.Invoke($"[SAST] 硬编码密钥扫描异常: {ex.Message}");
            }

            if (vulns.Count == 0)
            {
                vulns.Add(new AppVulnerabilityResult
                {
                    Id = "HK-000",
                    Name = "未检测到明显硬编码密钥",
                    RiskLevel = Models.RiskLevel.Low,
                    VulnerabilityType = VulnerabilityType.HardcodedKey,
                    Location = "全局扫描",
                    CvssScore = 1.0,
                    Description = "在文本文件中未发现明显的硬编码密钥模式。建议仍进行人工代码审查。",
                    Suggestion = "继续保持良好的密钥管理实践，定期轮换密钥。"
                });
            }

            OnLog?.Invoke($"[SAST] 硬编码密钥检测完成，发现 {vulns.Count} 个问题");
            return vulns;
        }

        private List<AppVulnerabilityResult> ScanForWebViewVulnerabilities(
            AppType appType, ScanMode mode, string extractedPath, CancellationToken token)
        {
            OnLog?.Invoke("[SAST] 检测WebView漏洞...");
            var vulns = new List<AppVulnerabilityResult>();
            var patterns = new[]
            {
                new { Pattern = "addJavascriptInterface", Name = "WebView addJavascriptInterface风险", Severity = Models.RiskLevel.High },
                new { Pattern = "setAllowFileAccess(true)", Name = "WebView setAllowFileAccess未禁用", Severity = Models.RiskLevel.Medium },
                new { Pattern = "setJavaScriptEnabled(true)", Name = "WebView允许JavaScript自动执行", Severity = Models.RiskLevel.Medium },
                new { Pattern = "onReceivedSslError.*proceed", Name = "WebView未验证SSL证书", Severity = Models.RiskLevel.High },
                new { Pattern = "WKWebView", Name = "iOS WKWebView配置检测", Severity = Models.RiskLevel.Low }
            };

            try
            {
                var files = Directory.GetFiles(extractedPath, "*", SearchOption.AllDirectories)
                    .Where(f =>
                    {
                        var ext = Path.GetExtension(f).ToLower();
                        return ext == ".xml" || ext == ".json" || ext == ".js" || ext == ".ts" ||
                               ext == ".plist" || ext == ".m" || ext == ".swift";
                    })
                    .Take(mode == ScanMode.Lightning ? 20 : mode == ScanMode.Standard ? 50 : 200)
                    .ToList();

                int idx = 1;
                foreach (var file in files)
                {
                    token.ThrowIfCancellationRequested();
                    try
                    {
                        var content = File.ReadAllText(file);
                        var relPath = Path.GetRelativePath(extractedPath, file);

                        foreach (var p in patterns)
                        {
                            if (content.IndexOf(p.Pattern, StringComparison.OrdinalIgnoreCase) >= 0)
                            {
                                vulns.Add(new AppVulnerabilityResult
                                {
                                    Id = $"WV-{idx++:000}",
                                    Name = p.Name,
                                    RiskLevel = p.Severity,
                                    VulnerabilityType = VulnerabilityType.WebViewVulnerability,
                                    Location = relPath,
                                    CvssScore = p.Severity == Models.RiskLevel.High ? 8.0 : 5.0,
                                    Description = $"在 {relPath} 中检测到 {p.Name}，可能被攻击者利用执行恶意代码。",
                                    Suggestion = "禁用不必要的WebView功能，验证所有外部输入，使用安全模式加载远程内容。"
                                });
                            }
                        }
                    }
                    catch { }
                }
            }
            catch (Exception ex)
            {
                OnLog?.Invoke($"[SAST] WebView扫描异常: {ex.Message}");
            }

            if (vulns.Count == 0)
            {
                vulns.Add(new AppVulnerabilityResult
                {
                    Id = "WV-000",
                    Name = "未检测到明显WebView漏洞",
                    RiskLevel = Models.RiskLevel.Low,
                    VulnerabilityType = VulnerabilityType.WebViewVulnerability,
                    Location = "全局扫描",
                    CvssScore = 1.0,
                    Description = "未发现明显的WebView安全配置问题。",
                    Suggestion = "继续保持WebView安全配置，定期审查JavaScript接口。"
                });
            }

            OnLog?.Invoke($"[SAST] WebView漏洞检测完成，发现 {vulns.Count} 个问题");
            return vulns;
        }

        private List<AppVulnerabilityResult> ScanForInsecureStorage(
            AppType appType, ScanMode mode, string extractedPath, CancellationToken token)
        {
            OnLog?.Invoke("[SAST] 检测不安全存储...");
            var vulns = new List<AppVulnerabilityResult>();
            var patterns = new[]
            {
                new { Pattern = "SharedPreferences", Name = "SharedPreferences明文存储检测", Severity = Models.RiskLevel.Medium },
                new { Pattern = "getExternalStorage", Name = "外部存储未加密缓存", Severity = Models.RiskLevel.Medium },
                new { Pattern = "SQLiteOpenHelper", Name = "SQLite数据库未加密", Severity = Models.RiskLevel.Medium },
                new { Pattern = "Log\\.d\\(|Log\\.i\\(|print\\(", Name = "日志中打印敏感信息", Severity = Models.RiskLevel.Low },
                new { Pattern = "NSUserDefaults", Name = "iOS NSUserDefaults明文存储", Severity = Models.RiskLevel.Medium }
            };

            try
            {
                var files = Directory.GetFiles(extractedPath, "*", SearchOption.AllDirectories)
                    .Where(f =>
                    {
                        var ext = Path.GetExtension(f).ToLower();
                        return ext == ".xml" || ext == ".json" || ext == ".js" ||
                               ext == ".plist" || ext == ".m" || ext == ".swift";
                    })
                    .Take(mode == ScanMode.Lightning ? 20 : mode == ScanMode.Standard ? 50 : 200)
                    .ToList();

                int idx = 1;
                foreach (var file in files)
                {
                    token.ThrowIfCancellationRequested();
                    try
                    {
                        var content = File.ReadAllText(file);
                        var relPath = Path.GetRelativePath(extractedPath, file);

                        foreach (var p in patterns)
                        {
                            if (System.Text.RegularExpressions.Regex.IsMatch(content, p.Pattern))
                            {
                                vulns.Add(new AppVulnerabilityResult
                                {
                                    Id = $"IS-{idx++:000}",
                                    Name = p.Name,
                                    RiskLevel = p.Severity,
                                    VulnerabilityType = VulnerabilityType.InsecureStorage,
                                    Location = relPath,
                                    CvssScore = p.Severity switch
                                    {
                                        Models.RiskLevel.High => 7.0,
                                        Models.RiskLevel.Medium => 5.0,
                                        _ => 3.0
                                    },
                                    Description = $"在 {relPath} 中检测到 {p.Name}，可能导致敏感数据泄露。",
                                    Suggestion = "使用Android Keystore/iOS Keychain存储敏感数据，对本地文件进行加密。"
                                });
                            }
                        }
                    }
                    catch { }
                }
            }
            catch (Exception ex)
            {
                OnLog?.Invoke($"[SAST] 不安全存储扫描异常: {ex.Message}");
            }

            if (vulns.Count == 0)
            {
                vulns.Add(new AppVulnerabilityResult
                {
                    Id = "IS-000",
                    Name = "未检测到明显不安全存储",
                    RiskLevel = Models.RiskLevel.Low,
                    VulnerabilityType = VulnerabilityType.InsecureStorage,
                    Location = "全局扫描",
                    CvssScore = 1.0,
                    Description = "未发现明显的不安全存储模式。",
                    Suggestion = "继续使用加密存储方案保护用户数据。"
                });
            }

            OnLog?.Invoke($"[SAST] 不安全存储检测完成，发现 {vulns.Count} 个问题");
            return vulns;
        }

        private List<AppVulnerabilityResult> ScanForPermissionIssues(
            AppType appType, ScanMode mode, string extractedPath, CancellationToken token)
        {
            OnLog?.Invoke("[SAST] 检测权限问题...");
            var vulns = new List<AppVulnerabilityResult>();

            try
            {
                var dangerousPermissions = new[]
                {
                    "CAMERA", "RECORD_AUDIO", "READ_CONTACTS", "ACCESS_FINE_LOCATION",
                    "READ_CALL_LOG", "READ_SMS", "SEND_SMS", "READ_PHONE_STATE",
                    "READ_EXTERNAL_STORAGE", "WRITE_EXTERNAL_STORAGE"
                };

                var manifestPath = Directory.GetFiles(extractedPath, "AndroidManifest.xml", SearchOption.AllDirectories)
                    .FirstOrDefault();

                if (manifestPath != null)
                {
                    var content = File.ReadAllText(manifestPath);
                    int idx = 1;
                    foreach (var perm in dangerousPermissions)
                    {
                        if (content.Contains($"android.permission.{perm}"))
                        {
                            vulns.Add(new AppVulnerabilityResult
                            {
                                Id = $"PM-{idx++:000}",
                                Name = $"申请危险权限: {perm}",
                                RiskLevel = Models.RiskLevel.Medium,
                                VulnerabilityType = VulnerabilityType.PermissionIssue,
                                Location = "AndroidManifest.xml",
                                CvssScore = 4.5,
                                Description = $"应用申请了危险权限 {perm}，请确认是否为功能必需。",
                                Suggestion = "遵循最小权限原则，仅申请必要的权限，并在运行时动态申请。"
                            });
                        }
                    }

                    if (content.Contains("android:debuggable=\"true\""))
                    {
                        vulns.Add(new AppVulnerabilityResult
                        {
                            Id = $"PM-DEBUG",
                            Name = "生产环境启用调试模式",
                            RiskLevel = Models.RiskLevel.High,
                            VulnerabilityType = VulnerabilityType.PermissionIssue,
                            Location = "AndroidManifest.xml",
                            CvssScore = 7.0,
                            Description = "AndroidManifest.xml 中设置了 android:debuggable=true，生产环境不应启用。",
                            Suggestion = "生产环境必须设置 android:debuggable=\"false\"。"
                        });
                    }
                }
            }
            catch (Exception ex)
            {
                OnLog?.Invoke($"[SAST] 权限扫描异常: {ex.Message}");
            }

            if (vulns.Count == 0)
            {
                vulns.Add(new AppVulnerabilityResult
                {
                    Id = "PM-000",
                    Name = "未检测到明显权限问题",
                    RiskLevel = Models.RiskLevel.Low,
                    VulnerabilityType = VulnerabilityType.PermissionIssue,
                    Location = "全局扫描",
                    CvssScore = 1.0,
                    Description = "未发现明显的权限配置问题。",
                    Suggestion = "继续遵循最小权限原则，定期审查权限申请。"
                });
            }

            OnLog?.Invoke($"[SAST] 权限问题检测完成，发现 {vulns.Count} 个问题");
            return vulns;
        }

        private List<AppVulnerabilityResult> ScanForSSLCertificate(
            AppType appType, ScanMode mode, string extractedPath, CancellationToken token)
        {
            OnLog?.Invoke("[SAST] 检测SSL证书问题...");
            var vulns = new List<AppVulnerabilityResult>();
            var patterns = new[]
            {
                new { Pattern = "trustAllCerts|TrustAllManager", Name = "信任所有SSL证书", Severity = Models.RiskLevel.High },
                new { Pattern = "HostnameVerifier.*true", Name = "HostnameVerifier总是返回true", Severity = Models.RiskLevel.High },
                new { Pattern = "usesCleartextTraffic=\"true\"", Name = "HTTP明文传输未禁用", Severity = Models.RiskLevel.High },
                new { Pattern = "NSAllowsArbitraryLoads.*true", Name = "iOS ATS未启用", Severity = Models.RiskLevel.High },
                new { Pattern = "onReceivedSslError.*proceed", Name = "WebView忽略SSL错误", Severity = Models.RiskLevel.High }
            };

            try
            {
                var files = Directory.GetFiles(extractedPath, "*", SearchOption.AllDirectories)
                    .Where(f =>
                    {
                        var ext = Path.GetExtension(f).ToLower();
                        return ext == ".xml" || ext == ".json" || ext == ".js" ||
                               ext == ".plist" || ext == ".m" || ext == ".swift" || ext == ".config";
                    })
                    .Take(mode == ScanMode.Lightning ? 20 : mode == ScanMode.Standard ? 50 : 200)
                    .ToList();

                int idx = 1;
                foreach (var file in files)
                {
                    token.ThrowIfCancellationRequested();
                    try
                    {
                        var content = File.ReadAllText(file);
                        var relPath = Path.GetRelativePath(extractedPath, file);

                        foreach (var p in patterns)
                        {
                            if (System.Text.RegularExpressions.Regex.IsMatch(content, p.Pattern))
                            {
                                vulns.Add(new AppVulnerabilityResult
                                {
                                    Id = $"SSL-{idx++:000}",
                                    Name = p.Name,
                                    RiskLevel = p.Severity,
                                    VulnerabilityType = VulnerabilityType.SSLCertificate,
                                    Location = relPath,
                                    CvssScore = p.Severity == Models.RiskLevel.High ? 8.5 : 5.5,
                                    Description = $"在 {relPath} 中检测到 {p.Name}，可能导致中间人攻击。",
                                    Suggestion = "启用证书锁定，信任系统CA证书，禁用明文HTTP通信，正确实现证书验证。"
                                });
                            }
                        }
                    }
                    catch { }
                }
            }
            catch (Exception ex)
            {
                OnLog?.Invoke($"[SAST] SSL证书扫描异常: {ex.Message}");
            }

            if (vulns.Count == 0)
            {
                vulns.Add(new AppVulnerabilityResult
                {
                    Id = "SSL-000",
                    Name = "未检测到明显SSL证书问题",
                    RiskLevel = Models.RiskLevel.Low,
                    VulnerabilityType = VulnerabilityType.SSLCertificate,
                    Location = "全局扫描",
                    CvssScore = 1.0,
                    Description = "未发现明显的SSL/TLS配置问题。",
                    Suggestion = "继续启用证书锁定和HTTPS，定期更新证书。"
                });
            }

            OnLog?.Invoke($"[SAST] SSL证书检测完成，发现 {vulns.Count} 个问题");
            return vulns;
        }

        private List<AppVulnerabilityResult> ScanForDebugMode(
            AppType appType, ScanMode mode, string extractedPath, CancellationToken token)
        {
            OnLog?.Invoke("[SAST] 检测调试模式...");
            var vulns = new List<AppVulnerabilityResult>();

            try
            {
                var files = Directory.GetFiles(extractedPath, "*", SearchOption.AllDirectories)
                    .Where(f =>
                    {
                        var ext = Path.GetExtension(f).ToLower();
                        return ext == ".xml" || ext == ".plist" || ext == ".m" || ext == ".swift";
                    })
                    .Take(mode == ScanMode.Lightning ? 20 : 100)
                    .ToList();

                int idx = 1;
                foreach (var file in files)
                {
                    token.ThrowIfCancellationRequested();
                    try
                    {
                        var content = File.ReadAllText(file);
                        var relPath = Path.GetRelativePath(extractedPath, file);

                        if (content.Contains("android:debuggable=\"true\"") ||
                            content.Contains("DEBUG = true"))
                        {
                            vulns.Add(new AppVulnerabilityResult
                            {
                                Id = $"DBG-{idx++:000}",
                                Name = "生产环境启用调试模式",
                                RiskLevel = Models.RiskLevel.High,
                                VulnerabilityType = VulnerabilityType.DebugMode,
                                Location = relPath,
                                CvssScore = 7.0,
                                Description = $"在 {relPath} 中检测到调试模式启用，可能被攻击者用于动态分析。",
                                Suggestion = "生产环境必须关闭调试模式，移除调试日志输出。"
                            });
                        }

                        if (System.Text.RegularExpressions.Regex.IsMatch(content, @"NSLog\(|println\(|print\("))
                        {
                            vulns.Add(new AppVulnerabilityResult
                            {
                                Id = $"DBG-{idx++:000}",
                                Name = "包含调试日志输出",
                                RiskLevel = Models.RiskLevel.Low,
                                VulnerabilityType = VulnerabilityType.DebugMode,
                                Location = relPath,
                                CvssScore = 3.0,
                                Description = $"在 {relPath} 中检测到调试日志输出，可能泄露敏感信息。",
                                Suggestion = "生产版本中移除调试日志输出。"
                            });
                        }
                    }
                    catch { }
                }
            }
            catch (Exception ex)
            {
                OnLog?.Invoke($"[SAST] 调试模式扫描异常: {ex.Message}");
            }

            if (vulns.Count == 0)
            {
                vulns.Add(new AppVulnerabilityResult
                {
                    Id = "DBG-000",
                    Name = "未检测到调试模式问题",
                    RiskLevel = Models.RiskLevel.Low,
                    VulnerabilityType = VulnerabilityType.DebugMode,
                    Location = "全局扫描",
                    CvssScore = 1.0,
                    Description = "未发现明显的调试配置问题。",
                    Suggestion = "继续保持生产环境禁用调试模式。"
                });
            }

            OnLog?.Invoke($"[SAST] 调试模式检测完成，发现 {vulns.Count} 个问题");
            return vulns;
        }

        private List<AppVulnerabilityResult> ScanForThirdPartySDKs(
            AppType appType, ScanMode mode, string extractedPath, CancellationToken token)
        {
            OnLog?.Invoke("[SCA] 检测第三方SDK漏洞...");
            var vulns = new List<AppVulnerabilityResult>();

            var knownVulnSdks = new Dictionary<string, (string Name, Models.RiskLevel Severity, double Cvss, string Suggestion)>
            {
                ["okhttp"] = ("OkHttp版本存在已知漏洞", Models.RiskLevel.Medium, 6.0, "建议升级到 OkHttp 4.12.0+"),
                ["gson"] = ("Gson反序列化漏洞", Models.RiskLevel.High, 9.0, "建议升级到 Gson 2.10.1+"),
                ["log4j"] = ("Log4j远程代码执行漏洞", Models.RiskLevel.High, 10.0, "建议升级到 Log4j 2.20.0+"),
                ["fastjson"] = ("Fastjson反序列化漏洞", Models.RiskLevel.High, 9.0, "建议升级到 Fastjson 2.0.40+"),
                ["retrofit"] = ("Retrofit网络库旧版本", Models.RiskLevel.Low, 3.5, "建议升级到 Retrofit 2.9.0+"),
                ["glide"] = ("Glide图片加载漏洞", Models.RiskLevel.Low, 3.5, "建议升级到 Glide 4.15.1+")
            };

            try
            {
                var files = Directory.GetFiles(extractedPath, "*", SearchOption.AllDirectories)
                    .Where(f =>
                    {
                        var name = f.ToLower();
                        return name.EndsWith(".jar") || name.EndsWith(".aar") ||
                               name.Contains(".framework") || name.EndsWith(".dylib");
                    })
                    .ToList();

                int idx = 1;
                foreach (var file in files)
                {
                    token.ThrowIfCancellationRequested();
                    var fileName = Path.GetFileName(file).ToLower();
                    var relPath = Path.GetRelativePath(extractedPath, file);

                    foreach (var sdk in knownVulnSdks)
                    {
                        if (fileName.Contains(sdk.Key))
                        {
                            vulns.Add(new AppVulnerabilityResult
                            {
                                Id = $"SDK-{idx++:000}",
                                Name = sdk.Value.Name,
                                RiskLevel = sdk.Value.Severity,
                                VulnerabilityType = VulnerabilityType.ThirdPartySDK,
                                Location = relPath,
                                CvssScore = sdk.Value.Cvss,
                                Description = $"检测到第三方组件 {sdk.Value.Name} (位置: {relPath})，存在已知安全漏洞。",
                                Suggestion = sdk.Value.Suggestion
                            });
                        }
                    }
                }

                if (mode != ScanMode.Lightning && vulns.Count == 0)
                {
                    vulns.Add(new AppVulnerabilityResult
                    {
                        Id = "SDK-000",
                        Name = "未检测到已知漏洞SDK",
                        RiskLevel = Models.RiskLevel.Low,
                        VulnerabilityType = VulnerabilityType.ThirdPartySDK,
                        Location = "全局扫描",
                        CvssScore = 1.0,
                        Description = "在已知漏洞库中未匹配到高危组件。建议仍定期检查所有第三方依赖的CVE公告。",
                        Suggestion = "建立依赖清单，定期扫描所有第三方组件的安全公告。"
                    });
                }
            }
            catch (Exception ex)
            {
                OnLog?.Invoke($"[SCA] 第三方SDK扫描异常: {ex.Message}");
            }

            OnLog?.Invoke($"[SCA] 第三方SDK漏洞检测完成，发现 {vulns.Count} 个问题");
            return vulns;
        }
    }
}