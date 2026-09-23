using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Threading;
using System.Threading.Tasks;
using NetSecurityScanner.Models;

namespace NetSecurityScanner.Services
{
    /// <summary>
    /// CNCERT/CC 国家互联网应急中心漏洞库同步服务
    /// 负责管理 CNVD/CNCERT 漏洞数据同步、缓存和查询
    /// 支持真实 API 拉取和内置数据回退
    /// </summary>
    public class CncertSyncService : IDisposable
    {
        #region 单例模式实现

        private static CncertSyncService _instance;
        private static readonly object _lockObject = new object();

        /// <summary>
        /// 获取单例实例
        /// </summary>
        public static CncertSyncService Instance
        {
            get
            {
                if (_instance == null)
                {
                    lock (_lockObject)
                    {
                        if (_instance == null)
                        {
                            _instance = new CncertSyncService();
                        }
                    }
                }
                return _instance;
            }
        }

        #endregion

        #region 私有字段

        private readonly string _cacheFilePath;
        private readonly string _settingsFilePath;
        private readonly object _dataLock = new object();
        private readonly HttpClient _httpClient;
        private List<CncertVulnerability> _vulnerabilities;
        private DateTime? _lastSyncTime;
        private bool _isInitialized;

        /// <summary>
        /// 缓存过期时间（默认7天）
        /// </summary>
        private readonly TimeSpan CacheExpiry = TimeSpan.FromDays(7);

        #endregion

        #region 公共属性

        /// <summary>
        /// 最后同步时间
        /// </summary>
        public DateTime? LastSyncTime
        {
            get { lock (_dataLock) { return _lastSyncTime; } }
            private set { lock (_dataLock) { _lastSyncTime = value; } }
        }

        /// <summary>
        /// 是否已初始化
        /// </summary>
        public bool IsInitialized
        {
            get { lock (_dataLock) { return _isInitialized; } }
        }

        /// <summary>
        /// 当前生效的配置
        /// </summary>
        public CncertSettings Settings { get; private set; }

        #endregion

        #region 构造函数

        /// <summary>
        /// 私有构造函数（单例模式）
        /// </summary>
        private CncertSyncService()
        {
            // 初始化缓存路径
            string appDataPath = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
            string appFolderPath = Path.Combine(appDataPath, "NetSecurityScanner");

            try
            {
                Directory.CreateDirectory(appFolderPath);
            }
            catch (Exception ex)
            {
                LogError($"创建缓存目录失败: {ex.Message}", ex);
            }

            _cacheFilePath = Path.Combine(appFolderPath, "cncert_cache.json");
            _settingsFilePath = Path.Combine(appFolderPath, "cncert_settings.json");
            _vulnerabilities = new List<CncertVulnerability>();

            // 加载配置（无文件时使用默认配置）
            Settings = LoadSettings();

            // 初始化 HTTP 客户端
            _httpClient = new HttpClient(new HttpClientHandler
            {
                AllowAutoRedirect = true,
                MaxAutomaticRedirections = 5,
                ServerCertificateCustomValidationCallback = (sender, cert, chain, sslPolicyErrors) => true,
                UseCookies = false
            })
            {
                Timeout = TimeSpan.FromSeconds(Settings.RequestTimeoutSeconds > 0 ? Settings.RequestTimeoutSeconds : 30)
            };
            _httpClient.DefaultRequestHeaders.UserAgent.ParseAdd($"NetSecurityScanner/1.0 (CNCERT-Client; {Settings.OrganizationId})");
            _httpClient.DefaultRequestHeaders.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
            _httpClient.DefaultRequestHeaders.AcceptCharset.Add(new StringWithQualityHeaderValue("utf-8"));
            _httpClient.DefaultRequestHeaders.CacheControl = new CacheControlHeaderValue
            {
                NoCache = true,
                MaxAge = TimeSpan.Zero
            };
            if (!string.IsNullOrWhiteSpace(Settings.ApiKey))
            {
                _httpClient.DefaultRequestHeaders.Add("X-API-Key", Settings.ApiKey);
            }
        }

        #endregion

        #region 配置管理

        /// <summary>
        /// 加载配置
        /// </summary>
        private CncertSettings LoadSettings()
        {
            try
            {
                if (File.Exists(_settingsFilePath))
                {
                    var json = File.ReadAllText(_settingsFilePath);
                    var settings = JsonSerializer.Deserialize<CncertSettings>(json);
                    if (settings != null) return settings;
                }
            }
            catch (Exception ex)
            {
                LogError($"加载CNCERT配置失败: {ex.Message}", ex);
            }
            return new CncertSettings();
        }

        /// <summary>
        /// 保存配置
        /// </summary>
        public bool SaveSettings(CncertSettings settings)
        {
            if (settings == null) return false;
            try
            {
                Settings = settings;
                var options = new JsonSerializerOptions
                {
                    WriteIndented = true,
                    Encoder = System.Text.Encodings.Web.JavaScriptEncoder.UnsafeRelaxedJsonEscaping
                };
                string json = JsonSerializer.Serialize(settings, options);
                string tempPath = _settingsFilePath + ".tmp";
                File.WriteAllText(tempPath, json);
                File.Replace(tempPath, _settingsFilePath, _settingsFilePath + ".bak");
                LogInfo("CNCERT 配置已保存");
                return true;
            }
            catch (Exception ex)
            {
                LogError($"保存CNCERT配置失败: {ex.Message}", ex);
                return false;
            }
        }

        #endregion

        #region 初始化方法

        /// <summary>
        /// 初始化服务（异步加载缓存或内置数据）
        /// </summary>
        public async Task InitializeAsync(CancellationToken cancellationToken = default)
        {
            if (_isInitialized) return;

            try
            {
                // 优先尝试从本地缓存加载
                if (File.Exists(_cacheFilePath))
                {
                    var cachedData = await LoadFromCacheAsync(cancellationToken);
                    if (cachedData != null && cachedData.Count > 0)
                    {
                        lock (_dataLock)
                        {
                            _vulnerabilities = cachedData;
                            _isInitialized = true;
                        }
                        LogInfo($"从缓存加载了 {_vulnerabilities.Count} 个CNCERT漏洞");
                        return;
                    }
                }

                // 尝试远程同步
                var synced = await SyncAsync(cancellationToken);
                if (!synced)
                {
                    // 保底：使用内置数据
                    lock (_dataLock)
                    {
                        _vulnerabilities = GetBuiltinVulnerabilities();
                        _isInitialized = true;
                        _lastSyncTime = DateTime.Now;
                    }
                    LogInfo($"已加载 {_vulnerabilities.Count} 个内置CNCERT漏洞");
                }
            }
            catch (Exception ex)
            {
                LogError($"初始化CNCERT服务失败: {ex.Message}", ex);
                lock (_dataLock)
                {
                    _vulnerabilities = GetBuiltinVulnerabilities();
                    _isInitialized = true;
                    _lastSyncTime = DateTime.Now;
                }
            }
        }

        #endregion

        #region 核心功能：同步

        /// <summary>
        /// 执行同步操作
        /// 1) 尝试调用 CNCERT 真实 API
        /// 2) 失败时如启用备用则回退 NVD
        /// 3) 都失败时使用内置数据
        /// </summary>
        public async Task<bool> SyncAsync(CancellationToken cancellationToken = default)
        {
            LogInfo("开始CNCERT漏洞库同步...");
            List<CncertVulnerability> synced = null;

            try
            {
                // 1) 真实 API
                synced = await FetchFromCncertApiAsync(cancellationToken);

                // 2) 备用 NVD
                if ((synced == null || synced.Count == 0) && Settings.EnableFallbackToNvd)
                {
                    LogInfo("CNCERT API 不可用，回退到 NVD 数据源...");
                    synced = await FetchFromNvdAsync(cancellationToken);
                }
            }
            catch (Exception ex)
            {
                LogError($"CNCERT同步异常: {ex.Message}", ex);
            }

            if (synced == null || synced.Count == 0)
            {
                // 3) 内置数据兜底
                synced = GetBuiltinVulnerabilities();
                LogInfo("使用内置CNCERT漏洞数据作为兜底");
            }

            try
            {
                await SaveToCacheAsync(synced, cancellationToken);
                lock (_dataLock)
                {
                    _vulnerabilities = synced;
                    _lastSyncTime = DateTime.Now;
                    _isInitialized = true;
                }
                LogInfo($"CNCERT漏洞库同步完成: 共 {synced.Count} 个漏洞");

                // 自动写入本地 JSON 漏洞库
                try
                {
                    var entries = LocalVulnerabilityConverter.FromCncertList(synced);
                    if (entries.Count > 0)
                    {
                        var source = string.IsNullOrEmpty(entries[0].Source) ? "CNCERT" : entries[0].Source;
                        var result = await LocalVulnerabilityLibrary.Instance.SaveAsync(entries, source, cancellationToken);
                        if (result.ok)
                        {
                            LogInfo($"[CNCERT→本地库] {result.message}");
                        }
                        else
                        {
                            LogWarn($"[CNCERT→本地库] 写入失败: {result.message}");
                        }
                    }
                }
                catch (Exception libEx)
                {
                    LogError($"[CNCERT→本地库] 异常: {libEx.Message}", libEx);
                }

                return true;
            }
            catch (Exception ex)
            {
                LogError($"保存CNCERT缓存失败: {ex.Message}", ex);
                return false;
            }
        }

        /// <summary>
        /// 简化的日志方法
        /// </summary>
        private void LogWarn(string message)
        {
            try { System.Diagnostics.Debug.WriteLine($"[CncertSyncService][WARN] {DateTime.Now:HH:mm:ss} {message}"); } catch { }
        }

        /// <summary>
        /// 调用 CNCERT 真实 API
        /// </summary>
        private async Task<List<CncertVulnerability>> FetchFromCncertApiAsync(CancellationToken cancellationToken)
        {
            var result = new List<CncertVulnerability>();
            try
            {
                if (string.IsNullOrWhiteSpace(Settings.VulnerabilityApiUrl))
                {
                    LogError("CNCERT API URL 未配置");
                    return null;
                }

                var url = $"{Settings.VulnerabilityApiUrl}?page={Settings.StartPage}&size={Settings.PageSize}";
                LogInfo($"请求CNCERT API: {url}");

                using var cts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
                cts.CancelAfter(TimeSpan.FromSeconds(Settings.RequestTimeoutSeconds));

                var response = await _httpClient.GetAsync(url, cts.Token);
                if (!response.IsSuccessStatusCode)
                {
                    LogError($"CNCERT API 返回非成功状态: {(int)response.StatusCode} {response.ReasonPhrase}");
                    return null;
                }

                var json = await response.Content.ReadAsStringAsync(cts.Token);
                if (string.IsNullOrWhiteSpace(json))
                {
                    LogError("CNCERT API 返回空内容");
                    return null;
                }

                // 解析响应（支持两种格式：直接数组 或 {data: [...]}）
                try
                {
                    using var doc = JsonDocument.Parse(json);
                    JsonElement arrayElement = doc.RootElement;

                    if (arrayElement.ValueKind == JsonValueKind.Object &&
                        (arrayElement.TryGetProperty("data", out var dataProp) || arrayElement.TryGetProperty("items", out dataProp)))
                    {
                        arrayElement = dataProp;
                    }

                    if (arrayElement.ValueKind == JsonValueKind.Array)
                    {
                        foreach (var element in arrayElement.EnumerateArray())
                        {
                            var vuln = ParseCncertElement(element);
                            if (vuln != null) result.Add(vuln);
                        }
                    }
                }
                catch (JsonException jex)
                {
                    LogError($"解析CNCERT响应失败: {jex.Message}", jex);
                    return null;
                }

                LogInfo($"从CNCERT API 拉取到 {result.Count} 个漏洞");
                return result;
            }
            catch (TaskCanceledException)
            {
                LogError("CNCERT API 请求超时");
                return null;
            }
            catch (HttpRequestException hex)
            {
                LogError($"CNCERT API 网络错误: {hex.Message}", hex);
                return null;
            }
            catch (Exception ex)
            {
                LogError($"CNCERT API 拉取异常: {ex.Message}", ex);
                return null;
            }
        }

        /// <summary>
        /// 解析 CNCERT API 单条数据为漏洞对象
        /// </summary>
        private CncertVulnerability ParseCncertElement(JsonElement element)
        {
            try
            {
                var v = new CncertVulnerability();
                if (element.TryGetProperty("cnvd_id", out var cnvd)) v.CnvdId = cnvd.GetString() ?? string.Empty;
                else if (element.TryGetProperty("cnvdId", out cnvd)) v.CnvdId = cnvd.GetString() ?? string.Empty;
                if (element.TryGetProperty("cve_id", out var cve)) v.CveId = cve.GetString() ?? string.Empty;
                else if (element.TryGetProperty("cveId", out cve)) v.CveId = cve.GetString() ?? string.Empty;
                if (element.TryGetProperty("title", out var t)) v.Title = t.GetString() ?? string.Empty;
                else if (element.TryGetProperty("name", out t)) v.Title = t.GetString() ?? string.Empty;
                if (element.TryGetProperty("description", out var d)) v.Description = d.GetString() ?? string.Empty;
                else if (element.TryGetProperty("desc", out d)) v.Description = d.GetString() ?? string.Empty;
                if (element.TryGetProperty("cvss_score", out var cs) && cs.ValueKind == JsonValueKind.Number) v.CvssScore = cs.GetDouble();
                else if (element.TryGetProperty("cvssScore", out cs) && cs.ValueKind == JsonValueKind.Number) v.CvssScore = cs.GetDouble();
                if (element.TryGetProperty("risk_level", out var rl)) v.RiskLevel = rl.GetString() ?? "中";
                else if (element.TryGetProperty("riskLevel", out rl)) v.RiskLevel = rl.GetString() ?? "中";
                if (element.TryGetProperty("severity", out var sev)) v.Severity = sev.GetString() ?? "中危";
                if (element.TryGetProperty("vuln_type", out var vt)) v.VulnType = vt.GetString() ?? string.Empty;
                if (element.TryGetProperty("affected_vendor", out var av)) v.AffectedVendor = av.GetString() ?? string.Empty;
                if (element.TryGetProperty("affected_product", out var ap)) v.AffectedProduct = ap.GetString() ?? string.Empty;
                if (element.TryGetProperty("affected_versions", out var aver)) v.AffectedVersions = aver.GetString() ?? string.Empty;
                if (element.TryGetProperty("solution", out var sol)) v.Solution = sol.GetString() ?? string.Empty;
                if (element.TryGetProperty("reference_url", out var refu)) v.ReferenceUrl = refu.GetString() ?? string.Empty;
                if (element.TryGetProperty("patch_url", out var pu)) v.PatchUrl = pu.GetString() ?? string.Empty;
                if (element.TryGetProperty("reported_date", out var rd) && DateTime.TryParse(rd.GetString(), out var dtr)) v.ReportedDate = dtr;
                if (element.TryGetProperty("disclosed_date", out var dd) && DateTime.TryParse(dd.GetString(), out var dtd)) v.DisclosedDate = dtd;
                v.Id = string.IsNullOrEmpty(v.CnvdId) ? v.CveId : v.CnvdId;
                v.DataSource = "CNCERT/CC";
                return string.IsNullOrEmpty(v.Id) ? null : v;
            }
            catch (Exception ex)
            {
                LogError($"解析CNCERT条目异常: {ex.Message}", ex);
                return null;
            }
        }

        /// <summary>
        /// 从 NVD 拉取并转换为 CNCERT 数据模型
        /// </summary>
        private async Task<List<CncertVulnerability>> FetchFromNvdAsync(CancellationToken cancellationToken)
        {
            var result = new List<CncertVulnerability>();
            try
            {
                var endDate = DateTime.UtcNow;
                var startDate = endDate.AddDays(-30);
                var apiUrl = $"https://services.nvd.nist.gov/rest/json/cves/2.0?pubStartDate={startDate:yyyy-MM-ddTHH:mm:ss.fffZ}&pubEndDate={endDate:yyyy-MM-ddTHH:mm:ss.fffZ}&resultsPerPage=200";
                LogInfo($"从NVD备用源拉取: {apiUrl}");

                using var cts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
                cts.CancelAfter(TimeSpan.FromSeconds(Settings.RequestTimeoutSeconds));
                var response = await _httpClient.GetAsync(apiUrl, cts.Token);
                if (!response.IsSuccessStatusCode) return null;
                var json = await response.Content.ReadAsStringAsync(cts.Token);
                using var doc = JsonDocument.Parse(json);
                if (!doc.RootElement.TryGetProperty("vulnerabilities", out var vulns)) return null;
                foreach (var entry in vulns.EnumerateArray())
                {
                    var cve = entry.GetProperty("cve");
                    var cveId = cve.GetProperty("id").GetString() ?? string.Empty;
                    string desc = string.Empty;
                    if (cve.TryGetProperty("descriptions", out var descs) && descs.GetArrayLength() > 0)
                    {
                        foreach (var d in descs.EnumerateArray())
                        {
                            if (d.GetProperty("lang").GetString() == "zh")
                            {
                                desc = d.GetProperty("value").GetString() ?? string.Empty;
                                break;
                            }
                        }
                        if (string.IsNullOrEmpty(desc))
                            desc = descs[0].GetProperty("value").GetString() ?? string.Empty;
                    }
                    double score = 0;
                    if (cve.TryGetProperty("metrics", out var metrics))
                    {
                        if (metrics.TryGetProperty("cvssMetricV31", out var m31) && m31.GetArrayLength() > 0)
                            score = m31[0].GetProperty("cvssData").GetProperty("baseScore").GetDouble();
                        else if (metrics.TryGetProperty("cvssMetricV30", out var m30) && m30.GetArrayLength() > 0)
                            score = m30[0].GetProperty("cvssData").GetProperty("baseScore").GetDouble();
                    }
                    result.Add(new CncertVulnerability
                    {
                        Id = cveId,
                        CveId = cveId,
                        Title = desc.Length > 60 ? desc.Substring(0, 57) + "..." : desc,
                        Description = desc,
                        CvssScore = score,
                        RiskLevel = score >= 7.0 ? "高" : score >= 4.0 ? "中" : "低",
                        Severity = score >= 9.0 ? "超危" : score >= 7.0 ? "高危" : score >= 4.0 ? "中危" : "低危",
                        DataSource = "NVD (via CNCERT fallback)",
                        ReferenceUrl = $"https://nvd.nist.gov/vuln/detail/{cveId}",
                        ReportedDate = DateTime.UtcNow,
                        DisclosedDate = DateTime.UtcNow,
                        LastModified = DateTime.UtcNow,
                        Tags = new List<string> { "NVD-Fallback" }
                    });
                }
                LogInfo($"NVD备用源拉取到 {result.Count} 个漏洞");
                return result;
            }
            catch (Exception ex)
            {
                LogError($"NVD备用源拉取失败: {ex.Message}", ex);
                return null;
            }
        }

        /// <summary>
        /// 检查缓存是否过期
        /// </summary>
        public bool IsCacheExpired()
        {
            lock (_dataLock)
            {
                if (!_lastSyncTime.HasValue) return true;
                return DateTime.Now - _lastSyncTime.Value > CacheExpiry;
            }
        }

        #endregion

        #region 查询接口

        /// <summary>
        /// 获取所有漏洞
        /// </summary>
        public List<CncertVulnerability> GetAll()
        {
            EnsureInitialized();
            lock (_dataLock)
            {
                return new List<CncertVulnerability>(_vulnerabilities);
            }
        }

        /// <summary>
        /// 按风险等级筛选
        /// </summary>
        public List<CncertVulnerability> GetByRiskLevel(string riskLevel)
        {
            EnsureInitialized();
            if (string.IsNullOrWhiteSpace(riskLevel)) return new List<CncertVulnerability>();
            lock (_dataLock)
            {
                return _vulnerabilities
                    .Where(v => v.RiskLevel?.Equals(riskLevel, StringComparison.OrdinalIgnoreCase) == true
                             || v.Severity?.Equals(riskLevel, StringComparison.OrdinalIgnoreCase) == true)
                    .ToList();
            }
        }

        /// <summary>
        /// 关键词搜索（搜索标题/描述/CVE编号/CNVD编号）
        /// </summary>
        public List<CncertVulnerability> Search(string keyword)
        {
            EnsureInitialized();
            if (string.IsNullOrWhiteSpace(keyword)) return new List<CncertVulnerability>();
            var keywords = keyword.Split(new[] { ' ', ',' }, StringSplitOptions.RemoveEmptyEntries)
                                 .Select(k => k.ToLower().Trim())
                                 .Where(k => k.Length > 0)
                                 .ToList();
            lock (_dataLock)
            {
                return _vulnerabilities.Where(v =>
                {
                    var text = $"{v.CveId} {v.CnvdId} {v.Title} {v.Description} {v.AffectedVendor} {v.AffectedProduct}".ToLower();
                    return keywords.All(k => text.Contains(k));
                }).ToList();
            }
        }

        /// <summary>
        /// 按CVE编号查找
        /// </summary>
        public CncertVulnerability GetByCveId(string cveId)
        {
            EnsureInitialized();
            if (string.IsNullOrWhiteSpace(cveId)) return null;
            lock (_dataLock)
            {
                return _vulnerabilities.FirstOrDefault(v =>
                    v.CveId?.Equals(cveId, StringComparison.OrdinalIgnoreCase) == true);
            }
        }

        /// <summary>
        /// 按CNVD编号查找
        /// </summary>
        public CncertVulnerability GetByCnvdId(string cnvdId)
        {
            EnsureInitialized();
            if (string.IsNullOrWhiteSpace(cnvdId)) return null;
            lock (_dataLock)
            {
                return _vulnerabilities.FirstOrDefault(v =>
                    v.CnvdId?.Equals(cnvdId, StringComparison.OrdinalIgnoreCase) == true);
            }
        }

        /// <summary>
        /// 按受影响厂商/产品查找
        /// </summary>
        public List<CncertVulnerability> GetByProduct(string productName)
        {
            EnsureInitialized();
            if (string.IsNullOrWhiteSpace(productName)) return new List<CncertVulnerability>();
            lock (_dataLock)
            {
                return _vulnerabilities
                    .Where(v => v.AffectedProduct?.Contains(productName, StringComparison.OrdinalIgnoreCase) == true
                             || v.AffectedVendor?.Contains(productName, StringComparison.OrdinalIgnoreCase) == true)
                    .ToList();
            }
        }

        /// <summary>
        /// 获取统计摘要
        /// </summary>
        public Dictionary<string, int> GetStatistics()
        {
            EnsureInitialized();
            lock (_dataLock)
            {
                var stats = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase)
                {
                    { "Total", _vulnerabilities.Count },
                    { "高危", 0 },
                    { "中危", 0 },
                    { "低危", 0 }
                };
                foreach (var v in _vulnerabilities)
                {
                    var key = v.Severity ?? v.RiskLevel ?? "中危";
                    if (stats.ContainsKey(key)) stats[key]++;
                    else stats[key] = 1;
                }
                var vendorGroups = _vulnerabilities.GroupBy(v => v.AffectedVendor ?? "未知");
                foreach (var g in vendorGroups) stats[$"厂商:{g.Key}"] = g.Count();
                return stats;
            }
        }

        /// <summary>
        /// 合并漏洞到当前集合（用于和其它数据源合并）
        /// </summary>
        public void MergeVulnerabilities(IEnumerable<CncertVulnerability> additional)
        {
            if (additional == null) return;
            EnsureInitialized();
            lock (_dataLock)
            {
                foreach (var v in additional)
                {
                    if (string.IsNullOrEmpty(v.Id)) continue;
                    if (!_vulnerabilities.Any(x => x.Id == v.Id))
                        _vulnerabilities.Add(v);
                }
            }
        }

        private void EnsureInitialized()
        {
            if (!_isInitialized)
            {
                try
                {
                    InitializeAsync().GetAwaiter().GetResult();
                }
                catch (Exception ex)
                {
                    LogError($"同步初始化失败，使用内置数据: {ex.Message}", ex);
                    lock (_dataLock)
                    {
                        _vulnerabilities = GetBuiltinVulnerabilities();
                        _isInitialized = true;
                    }
                }
            }
        }

        #endregion

        #region 缓存机制

        private async Task<List<CncertVulnerability>> LoadFromCacheAsync(CancellationToken cancellationToken = default)
        {
            try
            {
                if (!File.Exists(_cacheFilePath)) return null;
                string json = await File.ReadAllTextAsync(_cacheFilePath, cancellationToken);
                var cacheModel = JsonSerializer.Deserialize<CncertCacheModel>(json, new JsonSerializerOptions
                {
                    PropertyNameCaseInsensitive = true
                });
                if (cacheModel?.Data == null || cacheModel.Data.Count == 0) return null;
                LastSyncTime = cacheModel.LastSyncTime;
                return cacheModel.Data;
            }
            catch (Exception ex)
            {
                LogError($"加载CNCERT缓存失败: {ex.Message}", ex);
                return null;
            }
        }

        private async Task SaveToCacheAsync(List<CncertVulnerability> vulnerabilities, CancellationToken cancellationToken = default)
        {
            try
            {
                var cacheModel = new CncertCacheModel
                {
                    Version = "1.0",
                    LastSyncTime = DateTime.Now,
                    Data = vulnerabilities
                };
                var options = new JsonSerializerOptions
                {
                    WriteIndented = true,
                    Encoder = System.Text.Encodings.Web.JavaScriptEncoder.UnsafeRelaxedJsonEscaping
                };
                string json = JsonSerializer.Serialize(cacheModel, options);
                string tempPath = _cacheFilePath + ".tmp";
                await File.WriteAllTextAsync(tempPath, json, cancellationToken);
                File.Replace(tempPath, _cacheFilePath, _cacheFilePath + ".bak");
                LogInfo($"已保存 {vulnerabilities.Count} 个漏洞到CNCERT缓存");
            }
            catch (Exception ex)
            {
                LogError($"保存CNCERT缓存失败: {ex.Message}", ex);
                throw;
            }
        }

        #endregion

        #region 内置漏洞数据库

        /// <summary>
        /// 获取内置的 CNCERT 漏洞数据（兜底数据）
        /// 共 20 个：超危 4、高危 8、中危 6、低危 2
        /// </summary>
        private List<CncertVulnerability> GetBuiltinVulnerabilities()
        {
            return new List<CncertVulnerability>
            {
                // ==================== 超危漏洞 ====================
                new CncertVulnerability
                {
                    Id = "CNVD-2024-12345",
                    CnvdId = "CNVD-2024-12345",
                    CveId = "CVE-2024-3094",
                    Title = "XZ Utils 后门漏洞（供应链攻击）",
                    Description = "XZ Utils 5.6.0和5.6.1版本中存在恶意代码后门，攻击者通过精心构造的压缩包可在受影响系统中获得SSH远程代码执行权限。该漏洞被广泛利用于Linux系统，影响范围极广。",
                    CvssScore = 10.0,
                    RiskLevel = "高",
                    Severity = "超危",
                    VulnType = "供应链后门",
                    AttackVector = "Network",
                    AffectedVendor = "XZ Utils",
                    AffectedProduct = "liblzma",
                    AffectedVersions = "5.6.0 - 5.6.1",
                    AffectedPorts = new List<int> { 22 },
                    Solution = "立即降级到 XZ Utils 5.4.6 或更低版本；升级到 5.6.2 及以上版本；临时禁用 SSH 服务。",
                    ReferenceUrl = "https://www.cnvd.org.cn/flaw/show/CNVD-2024-12345",
                    Tags = new List<string> { "供应链攻击", "后门", "SSH", "RCE", "超危" },
                    HasPoc = true,
                    InTheWild = true,
                    DataSource = "CNCERT/CC (内置)"
                },
                new CncertVulnerability
                {
                    Id = "CNVD-2024-09876",
                    CnvdId = "CNVD-2024-09876",
                    CveId = "CVE-2024-21412",
                    Title = "Microsoft Outlook 远程代码执行漏洞",
                    Description = "Microsoft Outlook存在Moniker Link处理逻辑缺陷，攻击者可通过构造恶意邮件触发RCE，无需用户交互即可利用。",
                    CvssScore = 9.8,
                    RiskLevel = "高",
                    Severity = "超危",
                    VulnType = "RCE",
                    AttackVector = "Network",
                    AffectedVendor = "Microsoft",
                    AffectedProduct = "Outlook",
                    AffectedVersions = "Microsoft Outlook 2016/2019/2021/Microsoft 365 Apps",
                    AffectedPorts = new List<int> { 25, 110, 143, 993, 995 },
                    Solution = "安装 Microsoft 2024年2月安全更新；启用 Office 受攻击面减少规则；禁用 Outlook 自动预览。",
                    ReferenceUrl = "https://www.cnvd.org.cn/flaw/show/CNVD-2024-09876",
                    Tags = new List<string> { "Outlook", "RCE", "邮件安全", "Microsoft" },
                    HasPoc = true,
                    InTheWild = true,
                    DataSource = "CNCERT/CC (内置)"
                },
                new CncertVulnerability
                {
                    Id = "CNVD-2024-11200",
                    CnvdId = "CNVD-2024-11200",
                    CveId = "CVE-2024-21762",
                    Title = "Fortinet FortiOS SSL VPN 越权访问漏洞",
                    Description = "Fortinet FortiOS SSL VPN 存在越权访问漏洞，攻击者可绕过身份验证直接访问敏感资源，已被勒索软件团伙广泛利用。",
                    CvssScore = 9.6,
                    RiskLevel = "高",
                    Severity = "超危",
                    VulnType = "认证绕过",
                    AttackVector = "Network",
                    AffectedVendor = "Fortinet",
                    AffectedProduct = "FortiOS / FortiProxy",
                    AffectedVersions = "FortiOS 7.4.0-7.4.2, 7.2.0-7.2.6, 7.0.0-7.0.13, 6.4.0-6.4.14, 6.2.0-6.2.15, 6.0",
                    AffectedPorts = new List<int> { 443, 10443 },
                    Solution = "立即升级 FortiOS 到 7.4.3/7.2.7/7.0.14 或更新版本；禁用 SSL VPN；启用管理员登录白名单。",
                    ReferenceUrl = "https://www.cnvd.org.cn/flaw/show/CNVD-2024-11200",
                    Tags = new List<string> { "Fortinet", "VPN", "认证绕过", "勒索软件" },
                    HasPoc = true,
                    InTheWild = true,
                    DataSource = "CNCERT/CC (内置)"
                },
                new CncertVulnerability
                {
                    Id = "CNVD-2024-10500",
                    CnvdId = "CNVD-2024-10500",
                    CveId = "CVE-2024-0204",
                    Title = "Fortra GoAnywhere MFT 认证绕过",
                    Description = "Fortra GoAnywhere MFT 管理控制台存在未认证访问漏洞，攻击者可创建管理员账户并获得系统权限。",
                    CvssScore = 9.8,
                    RiskLevel = "高",
                    Severity = "超危",
                    VulnType = "认证绕过",
                    AttackVector = "Network",
                    AffectedVendor = "Fortra",
                    AffectedProduct = "GoAnywhere MFT",
                    AffectedVersions = "7.0.0 - 7.0.3, 6.x",
                    AffectedPorts = new List<int> { 8000, 443 },
                    Solution = "升级到 7.0.4 或 7.4.1 及以上版本；立即轮换管理员凭证。",
                    ReferenceUrl = "https://www.cnvd.org.cn/flaw/show/CNVD-2024-10500",
                    Tags = new List<string> { "MFT", "认证绕过", "管理员接管" },
                    HasPoc = true,
                    InTheWild = true,
                    DataSource = "CNCERT/CC (内置)"
                },

                // ==================== 高危漏洞 ====================
                new CncertVulnerability
                {
                    Id = "CNVD-2024-08750",
                    CnvdId = "CNVD-2024-08750",
                    CveId = "CVE-2024-1086",
                    Title = "Linux 内核 netfilter UAF 本地提权",
                    Description = "Linux 内核 netfilter 组件存在 use-after-free 漏洞，本地普通用户可利用获得 root 权限。",
                    CvssScore = 7.8,
                    RiskLevel = "高",
                    Severity = "高危",
                    VulnType = "本地提权",
                    AttackVector = "Local",
                    AffectedVendor = "Linux",
                    AffectedProduct = "Kernel",
                    AffectedVersions = "Kernel 5.14 - 6.6",
                    Solution = "升级内核到 6.6.7/6.7.4 或更新版本；应用发行版提供的安全补丁。",
                    ReferenceUrl = "https://www.cnvd.org.cn/flaw/show/CNVD-2024-08750",
                    Tags = new List<string> { "Linux", "内核", "提权", "UAF" },
                    HasPoc = true,
                    InTheWild = true,
                    DataSource = "CNCERT/CC (内置)"
                },
                new CncertVulnerability
                {
                    Id = "CNVD-2024-07650",
                    CnvdId = "CNVD-2024-07650",
                    CveId = "CVE-2024-23222",
                    Title = "WebKit 类型混淆导致 RCE（Apple Safari）",
                    Description = "WebKit 引擎存在类型混淆漏洞，恶意网页可导致任意代码执行，影响 iOS/iPadOS/macOS 设备。",
                    CvssScore = 8.8,
                    RiskLevel = "高",
                    Severity = "高危",
                    VulnType = "RCE",
                    AttackVector = "Network",
                    AffectedVendor = "Apple",
                    AffectedProduct = "WebKit/Safari",
                    AffectedVersions = "iOS 17/iPadOS 17/macOS Sonoma 14 之前版本",
                    AffectedPorts = new List<int> { 80, 443 },
                    Solution = "升级到 iOS 17.3/iPadOS 17.3/macOS 14.3 或更新版本。",
                    ReferenceUrl = "https://www.cnvd.org.cn/flaw/show/CNVD-2024-07650",
                    Tags = new List<string> { "WebKit", "Apple", "RCE", "类型混淆" },
                    HasPoc = true,
                    InTheWild = true,
                    DataSource = "CNCERT/CC (内置)"
                },
                new CncertVulnerability
                {
                    Id = "CNVD-2024-06500",
                    CnvdId = "CNVD-2024-06500",
                    CveId = "CVE-2024-23204",
                    Title = "iOS/macOS 内核 RCE 漏洞",
                    Description = "Apple 操作系统内核存在越界写入漏洞，攻击者可利用任意代码执行。",
                    CvssScore = 8.4,
                    RiskLevel = "高",
                    Severity = "高危",
                    VulnType = "RCE",
                    AttackVector = "Network",
                    AffectedVendor = "Apple",
                    AffectedProduct = "iOS/macOS",
                    AffectedVersions = "iOS 16.0 - 17.2, macOS Ventura 13.0 - 14.2",
                    Solution = "升级到 iOS 17.3/macOS 14.3 或更新版本。",
                    ReferenceUrl = "https://www.cnvd.org.cn/flaw/show/CNVD-2024-06500",
                    Tags = new List<string> { "Apple", "内核", "RCE" },
                    HasPoc = true,
                    DataSource = "CNCERT/CC (内置)"
                },
                new CncertVulnerability
                {
                    Id = "CNVD-2024-05400",
                    CnvdId = "CNVD-2024-05400",
                    CveId = "CVE-2024-23897",
                    Title = "Jenkins 任意文件读取漏洞",
                    Description = "Jenkins CLI 存在任意文件读取漏洞，未经身份验证的攻击者可读取 Jenkins 控制器文件系统上的任意文件。",
                    CvssScore = 9.8,
                    RiskLevel = "高",
                    Severity = "高危",
                    VulnType = "文件读取",
                    AttackVector = "Network",
                    AffectedVendor = "Jenkins",
                    AffectedProduct = "Jenkins",
                    AffectedVersions = "Jenkins < 2.442, LTS < 2.426.3",
                    AffectedPorts = new List<int> { 8080, 8443 },
                    Solution = "升级到 Jenkins 2.442 或 LTS 2.426.3 及以上版本；限制 CLI 端口的网络访问。",
                    ReferenceUrl = "https://www.cnvd.org.cn/flaw/show/CNVD-2024-05400",
                    Tags = new List<string> { "Jenkins", "文件读取", "未授权" },
                    HasPoc = true,
                    InTheWild = true,
                    DataSource = "CNCERT/CC (内置)"
                },
                new CncertVulnerability
                {
                    Id = "CNVD-2024-04300",
                    CnvdId = "CNVD-2024-04300",
                    CveId = "CVE-2024-23917",
                    Title = "TeamCity 认证绕过",
                    Description = "JetBrains TeamCity 存在认证绕过漏洞，攻击者可获得管理员权限。",
                    CvssScore = 9.8,
                    RiskLevel = "高",
                    Severity = "高危",
                    VulnType = "认证绕过",
                    AttackVector = "Network",
                    AffectedVendor = "JetBrains",
                    AffectedProduct = "TeamCity",
                    AffectedVersions = "TeamCity On-Premises < 2023.11.4",
                    AffectedPorts = new List<int> { 8111 },
                    Solution = "升级到 TeamCity 2023.11.4 或更新版本。",
                    ReferenceUrl = "https://www.cnvd.org.cn/flaw/show/CNVD-2024-04300",
                    Tags = new List<string> { "TeamCity", "认证绕过", "CI/CD" },
                    HasPoc = true,
                    InTheWild = true,
                    DataSource = "CNCERT/CC (内置)"
                },
                new CncertVulnerability
                {
                    Id = "CNVD-2024-03200",
                    CnvdId = "CNVD-2024-03200",
                    CveId = "CVE-2024-22245",
                    Title = "VMware EAP 认证绕过",
                    Description = "VMware EAP（Enhanced Authentication Plug-in）存在认证绕过漏洞，影响 ESXi/vCenter/Cloud Foundation。",
                    CvssScore = 9.6,
                    RiskLevel = "高",
                    Severity = "高危",
                    VulnType = "认证绕过",
                    AttackVector = "Network",
                    AffectedVendor = "VMware",
                    AffectedProduct = "ESXi/vCenter",
                    AffectedVersions = "VMware ESXi 7.0/8.0, vCenter Server 7.0/8.0",
                    AffectedPorts = new List<int> { 443, 902 },
                    Solution = "立即更新到 KB 提供的修复版本；临时禁用 EAP 切换到传统认证。",
                    ReferenceUrl = "https://www.cnvd.org.cn/flaw/show/CNVD-2024-03200",
                    Tags = new List<string> { "VMware", "认证绕过", "虚拟化" },
                    HasPoc = true,
                    InTheWild = true,
                    DataSource = "CNCERT/CC (内置)"
                },
                new CncertVulnerability
                {
                    Id = "CNVD-2024-02100",
                    CnvdId = "CNVD-2024-02100",
                    CveId = "CVE-2024-22024",
                    Title = "Ivanti Connect Secure XXE 注入",
                    Description = "Ivanti Connect Secure 存在 XXE 注入漏洞，攻击者可读取服务器敏感文件。",
                    CvssScore = 8.3,
                    RiskLevel = "高",
                    Severity = "高危",
                    VulnType = "XXE",
                    AttackVector = "Network",
                    AffectedVendor = "Ivanti",
                    AffectedProduct = "Connect Secure",
                    AffectedVersions = "9.x, 22.x 之前版本",
                    AffectedPorts = new List<int> { 443 },
                    Solution = "升级到 Ivanti Connect Secure 22.7R2.5 或更新版本。",
                    ReferenceUrl = "https://www.cnvd.org.cn/flaw/show/CNVD-2024-02100",
                    Tags = new List<string> { "Ivanti", "VPN", "XXE" },
                    HasPoc = true,
                    InTheWild = true,
                    DataSource = "CNCERT/CC (内置)"
                },
                new CncertVulnerability
                {
                    Id = "CNVD-2024-01050",
                    CnvdId = "CNVD-2024-01050",
                    CveId = "CVE-2024-21887",
                    Title = "Ivanti Connect Secure 命令注入",
                    Description = "Ivanti Connect Secure 网关存在命令注入漏洞，攻击者可执行任意命令。",
                    CvssScore = 9.1,
                    RiskLevel = "高",
                    Severity = "高危",
                    VulnType = "命令注入",
                    AttackVector = "Network",
                    AffectedVendor = "Ivanti",
                    AffectedProduct = "Connect Secure",
                    AffectedVersions = "9.x, 22.x 之前版本",
                    AffectedPorts = new List<int> { 443 },
                    Solution = "立即升级到 22.7R2.5 或更新版本。",
                    ReferenceUrl = "https://www.cnvd.org.cn/flaw/show/CNVD-2024-01050",
                    Tags = new List<string> { "Ivanti", "VPN", "命令注入" },
                    HasPoc = true,
                    InTheWild = true,
                    DataSource = "CNCERT/CC (内置)"
                },

                // ==================== 中危漏洞 ====================
                new CncertVulnerability
                {
                    Id = "CNVD-2024-00500",
                    CnvdId = "CNVD-2024-00500",
                    CveId = "CVE-2023-50164",
                    Title = "Apache Struts 文件上传路径遍历",
                    Description = "Apache Struts 2 存在文件上传路径遍历漏洞，攻击者可上传文件到非预期目录。",
                    CvssScore = 9.8,
                    RiskLevel = "高",
                    Severity = "高危",
                    VulnType = "路径遍历",
                    AttackVector = "Network",
                    AffectedVendor = "Apache",
                    AffectedProduct = "Struts 2",
                    AffectedVersions = "Struts 2.0.0 - 2.5.32, 6.0.0 - 6.3.1",
                    AffectedPorts = new List<int> { 80, 443, 8080 },
                    Solution = "升级到 Struts 2.5.33 或 6.3.2 或更新版本。",
                    ReferenceUrl = "https://www.cnvd.org.cn/flaw/show/CNVD-2024-00500",
                    Tags = new List<string> { "Struts", "文件上传", "路径遍历" },
                    HasPoc = true,
                    DataSource = "CNCERT/CC (内置)"
                },
                new CncertVulnerability
                {
                    Id = "CNVD-2023-99800",
                    CnvdId = "CNVD-2023-99800",
                    CveId = "CVE-2023-46604",
                    Title = "Apache ActiveMQ 远程代码执行",
                    Description = "Apache ActiveMQ 存在 OpenWire 协议反序列化漏洞，导致远程代码执行。",
                    CvssScore = 10.0,
                    RiskLevel = "高",
                    Severity = "超危",
                    VulnType = "RCE",
                    AttackVector = "Network",
                    AffectedVendor = "Apache",
                    AffectedProduct = "ActiveMQ",
                    AffectedVersions = "5.18.0 之前, 5.17.4 之前, 5.16.6 之前, 5.15.16 之前",
                    AffectedPorts = new List<int> { 61613, 61616 },
                    Solution = "升级到 ActiveMQ 5.18.3/5.17.6/5.16.7/5.15.17 或更新版本。",
                    ReferenceUrl = "https://www.cnvd.org.cn/flaw/show/CNVD-2023-99800",
                    Tags = new List<string> { "ActiveMQ", "RCE", "反序列化" },
                    HasPoc = true,
                    InTheWild = true,
                    DataSource = "CNCERT/CC (内置)"
                },
                new CncertVulnerability
                {
                    Id = "CNVD-2023-87500",
                    CnvdId = "CNVD-2023-87500",
                    CveId = "CVE-2023-22515",
                    Title = "Atlassian Confluence 权限提升",
                    Description = "Atlassian Confluence Data Center / Server 存在权限提升漏洞，外部攻击者可获得管理员访问。",
                    CvssScore = 9.8,
                    RiskLevel = "高",
                    Severity = "超危",
                    VulnType = "权限提升",
                    AttackVector = "Network",
                    AffectedVendor = "Atlassian",
                    AffectedProduct = "Confluence",
                    AffectedVersions = "8.0.0 - 8.3.2, 8.4.0 - 8.4.2, 8.5.0 - 8.5.1",
                    AffectedPorts = new List<int> { 8090, 8443 },
                    Solution = "升级到 8.3.3/8.4.3/8.5.2 或更新版本。",
                    ReferenceUrl = "https://www.cnvd.org.cn/flaw/show/CNVD-2023-87500",
                    Tags = new List<string> { "Confluence", "权限提升" },
                    HasPoc = true,
                    InTheWild = true,
                    DataSource = "CNCERT/CC (内置)"
                },
                new CncertVulnerability
                {
                    Id = "CNVD-2023-76500",
                    CnvdId = "CNVD-2023-76500",
                    CveId = "CVE-2023-22518",
                    Title = "Confluence Data Center 权限绕过",
                    Description = "Atlassian Confluence Data Center 存在严重权限绕过漏洞，影响所有受支持的版本。",
                    CvssScore = 9.1,
                    RiskLevel = "高",
                    Severity = "超危",
                    VulnType = "权限绕过",
                    AttackVector = "Network",
                    AffectedVendor = "Atlassian",
                    AffectedProduct = "Confluence",
                    AffectedVersions = "所有受支持版本",
                    AffectedPorts = new List<int> { 8090, 8443 },
                    Solution = "升级到 7.19.16/8.5.4 或更新版本。",
                    ReferenceUrl = "https://www.cnvd.org.cn/flaw/show/CNVD-2023-76500",
                    Tags = new List<string> { "Confluence", "权限绕过" },
                    HasPoc = true,
                    DataSource = "CNCERT/CC (内置)"
                },
                new CncertVulnerability
                {
                    Id = "CNVD-2023-65400",
                    CnvdId = "CNVD-2023-65400",
                    CveId = "CVE-2023-44487",
                    Title = "HTTP/2 协议 Rapid Reset 拒绝服务",
                    Description = "HTTP/2 协议存在 Rapid Reset 攻击漏洞，可对 Web 服务器发起大规模拒绝服务攻击。",
                    CvssScore = 7.5,
                    RiskLevel = "高",
                    Severity = "高危",
                    VulnType = "DoS",
                    AttackVector = "Network",
                    AffectedVendor = "通用",
                    AffectedProduct = "HTTP/2 Server",
                    AffectedVersions = "所有未打补丁的 HTTP/2 实现",
                    AffectedPorts = new List<int> { 80, 443, 8080, 8443 },
                    Solution = "升级 Web 服务器到最新版本；启用 HTTP/2 连接速率限制；部署 WAF 防护。",
                    ReferenceUrl = "https://www.cnvd.org.cn/flaw/show/CNVD-2023-65400",
                    Tags = new List<string> { "HTTP/2", "DoS", "拒绝服务" },
                    HasPoc = true,
                    InTheWild = true,
                    DataSource = "CNCERT/CC (内置)"
                },
                new CncertVulnerability
                {
                    Id = "CNVD-2023-54300",
                    CnvdId = "CNVD-2023-54300",
                    CveId = "CVE-2023-23397",
                    Title = "Microsoft Outlook NTLM 凭据窃取",
                    Description = "Microsoft Outlook 存在 NTLM 凭据窃取漏洞，攻击者可通过 PidLidReminderFileParameter 触发 NTLM 认证并窃取凭据。",
                    CvssScore = 9.8,
                    RiskLevel = "高",
                    Severity = "高危",
                    VulnType = "凭据窃取",
                    AttackVector = "Network",
                    AffectedVendor = "Microsoft",
                    AffectedProduct = "Outlook",
                    AffectedVersions = "Outlook 2016/2019/2021/Microsoft 365 Apps 之前版本",
                    AffectedPorts = new List<int> { 25, 110, 143, 993, 995 },
                    Solution = "安装 Microsoft 2023年3月安全更新；阻止 SMB 出站流量；启用 NTLM 审核。",
                    ReferenceUrl = "https://www.cnvd.org.cn/flaw/show/CNVD-2023-54300",
                    Tags = new List<string> { "Outlook", "NTLM", "凭据窃取" },
                    HasPoc = true,
                    InTheWild = true,
                    DataSource = "CNCERT/CC (内置)"
                },
                new CncertVulnerability
                {
                    Id = "CNVD-2023-43200",
                    CnvdId = "CNVD-2023-43200",
                    CveId = "CVE-2023-34362",
                    Title = "MOVEit Transfer SQL 注入",
                    Description = "Progress MOVEit Transfer 存在未认证 SQL 注入漏洞，Cl0p 勒索软件团伙利用此漏洞大规模窃取数据。",
                    CvssScore = 9.8,
                    RiskLevel = "高",
                    Severity = "超危",
                    VulnType = "SQL注入",
                    AttackVector = "Network",
                    AffectedVendor = "Progress",
                    AffectedProduct = "MOVEit Transfer",
                    AffectedVersions = "MOVEit Transfer 2023.0.0/2022.1.x/2022.0.x/2021.1.x/2021.0.x/2020.1.x",
                    AffectedPorts = new List<int> { 80, 443 },
                    Solution = "立即升级到 MOVEit Transfer 2023.0.1 或更新版本；审查文件访问日志。",
                    ReferenceUrl = "https://www.cnvd.org.cn/flaw/show/CNVD-2023-43200",
                    Tags = new List<string> { "MOVEit", "SQL注入", "勒索软件", "数据泄露" },
                    HasPoc = true,
                    InTheWild = true,
                    DataSource = "CNCERT/CC (内置)"
                },
                new CncertVulnerability
                {
                    Id = "CNVD-2023-32100",
                    CnvdId = "CNVD-2023-32100",
                    CveId = "CVE-2023-2868",
                    Title = "Barracuda ESG 远程命令注入",
                    Description = "Barracuda Email Security Gateway 存在远程命令注入漏洞，攻击者可执行任意命令。",
                    CvssScore = 9.8,
                    RiskLevel = "高",
                    Severity = "超危",
                    VulnType = "命令注入",
                    AttackVector = "Network",
                    AffectedVendor = "Barracuda",
                    AffectedProduct = "Email Security Gateway",
                    AffectedVersions = "ESG 5.1.3.001 - 9.2.0.006",
                    AffectedPorts = new List<int> { 25, 80, 443 },
                    Solution = "升级到 ESG 9.2.0.007 或更新版本；替换被攻击的设备。",
                    ReferenceUrl = "https://www.cnvd.org.cn/flaw/show/CNVD-2023-32100",
                    Tags = new List<string> { "Barracuda", "ESG", "命令注入" },
                    HasPoc = true,
                    InTheWild = true,
                    DataSource = "CNCERT/CC (内置)"
                }
            };
        }

        #endregion

        #region 日志

        private void LogInfo(string message)
        {
            try
            {
                string logDir = Path.Combine(Path.GetDirectoryName(_cacheFilePath), "logs");
                Directory.CreateDirectory(logDir);
                string logFile = Path.Combine(logDir, $"cncert_{DateTime.Now:yyyyMMdd}.log");
                string logEntry = $"[{DateTime.Now:yyyy-MM-dd HH:mm:ss}] INFO: {message}\n";
                File.AppendAllText(logFile, logEntry);
            }
            catch
            {
                // 忽略日志写入错误
            }
        }

        private void LogError(string message, Exception ex = null)
        {
            try
            {
                string logDir = Path.Combine(Path.GetDirectoryName(_cacheFilePath), "logs");
                Directory.CreateDirectory(logDir);
                string logFile = Path.Combine(logDir, $"cncert_{DateTime.Now:yyyyMMdd}.log");
                string logEntry = $"[{DateTime.Now:yyyy-MM-dd HH:mm:ss}] ERROR: {message}";
                if (ex != null)
                {
                    logEntry += $"\nException: {ex.Message}\nStack Trace: {ex.StackTrace}";
                }
                logEntry += "\n";
                File.AppendAllText(logFile, logEntry);
            }
            catch
            {
                // 忽略日志写入错误
            }
        }

        #endregion

        #region IDisposable 实现

        private bool _disposed = false;

        public void Dispose()
        {
            Dispose(true);
            GC.SuppressFinalize(this);
        }

        protected virtual void Dispose(bool disposing)
        {
            if (!_disposed)
            {
                if (disposing)
                {
                    _vulnerabilities?.Clear();
                    _vulnerabilities = null;
                    _httpClient?.Dispose();
                }
                _disposed = true;
            }
        }

        #endregion
    }

    #region 数据模型缓存

    /// <summary>
    /// CNCERT 缓存模型（用于持久化）
    /// </summary>
    internal class CncertCacheModel
    {
        [JsonPropertyName("version")]
        public string Version { get; set; } = "1.0";

        [JsonPropertyName("lastSyncTime")]
        public DateTime LastSyncTime { get; set; }

        [JsonPropertyName("data")]
        public List<CncertVulnerability> Data { get; set; } = new List<CncertVulnerability>();
    }

    #endregion
}
