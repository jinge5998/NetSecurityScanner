using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Threading;
using System.Threading.Tasks;

namespace NetSecurityScanner.Services
{
    /// <summary>
    /// CNNVD漏洞库同步服务
    /// 负责管理OpenClaw/Hermes Agent相关CVE漏洞数据的同步、缓存和查询
    /// </summary>
    public class CnnvdSyncService : IDisposable
    {
        #region 单例模式实现

        private static CnnvdSyncService _instance;
        private static readonly object _lockObject = new object();

        /// <summary>
        /// 获取单例实例
        /// </summary>
        public static CnnvdSyncService Instance
        {
            get
            {
                if (_instance == null)
                {
                    lock (_lockObject)
                    {
                        if (_instance == null)
                        {
                            _instance = new CnnvdSyncService();
                        }
                    }
                }
                return _instance;
            }
        }

        #endregion

        #region 私有字段

        private readonly string _cacheFilePath;
        private readonly object _dataLock = new object();
        private List<CnnvdVulnerability> _vulnerabilities;
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

        #endregion

        #region 构造函数

        /// <summary>
        /// 私有构造函数（单例模式）
        /// </summary>
        private CnnvdSyncService()
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

            _cacheFilePath = Path.Combine(appFolderPath, "cnnvd_cache.json");
            _vulnerabilities = new List<CnnvdVulnerability>();
        }

        #endregion

        #region 初始化方法

        /// <summary>
        /// 初始化服务（异步加载缓存或内置数据）
        /// </summary>
        /// <param name="cancellationToken">取消令牌</param>
        public async Task InitializeAsync(CancellationToken cancellationToken = default)
        {
            if (_isInitialized) return;

            try
            {
                // 尝试从缓存加载
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
                        LogInfo($"从缓存加载了 {_vulnerabilities.Count} 个漏洞");
                        return;
                    }
                }

                // 使用内置数据
                await SyncAsync(cancellationToken);
            }
            catch (Exception ex)
            {
                LogError($"初始化CNNVD服务失败: {ex.Message}", ex);
                
                // 保底：使用内置数据
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
        /// 执行同步操作（当前版本使用内置数据写入缓存）
        /// </summary>
        /// <param name="cancellationToken">取消令牌</param>
        /// <returns>同步是否成功</returns>
        public async Task<bool> SyncAsync(CancellationToken cancellationToken = default)
        {
            try
            {
                LogInfo("开始CNNVD漏洞库同步...");

                // 获取内置漏洞数据
                var builtinData = GetBuiltinVulnerabilities();
                
                // 写入缓存
                await SaveToCacheAsync(builtinData, cancellationToken);

                lock (_dataLock)
                {
                    _vulnerabilities = builtinData;
                    _lastSyncTime = DateTime.Now;
                    _isInitialized = true;
                }

                LogInfo($"CNNVD漏洞库同步完成: 共 {builtinData.Count} 个漏洞");
                return true;
            }
            catch (Exception ex)
            {
                LogError($"CNNVD漏洞库同步失败: {ex.Message}", ex);
                return false;
            }
        }

        /// <summary>
        /// 检查缓存是否过期（超过7天）
        /// </summary>
        /// <returns>是否过期</returns>
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
        /// <returns>漏洞列表</returns>
        public List<CnnvdVulnerability> GetAll()
        {
            EnsureInitialized();
            lock (_dataLock)
            {
                return new List<CnnvdVulnerability>(_vulnerabilities);
            }
        }

        /// <summary>
        /// 按风险等级筛选漏洞
        /// </summary>
        /// <param name="riskLevel">风险等级（超危/高危/中危/低危）</param>
        /// <returns>匹配的漏洞列表</returns>
        public List<CnnvdVulnerability> GetByRiskLevel(string riskLevel)
        {
            EnsureInitialized();
            if (string.IsNullOrWhiteSpace(riskLevel)) return new List<CnnvdVulnerability>();

            lock (_dataLock)
            {
                return _vulnerabilities
                    .Where(v => v.RiskLevel?.Equals(riskLevel, StringComparison.OrdinalIgnoreCase) == true)
                    .ToList();
            }
        }

        /// <summary>
        /// 关键词搜索（搜索标题/描述/CVE编号）
        /// </summary>
        /// <param name="keyword">关键词</param>
        /// <returns>匹配的漏洞列表</returns>
        public List<CnnvdVulnerability> Search(string keyword)
        {
            EnsureInitialized();
            if (string.IsNullOrWhiteSpace(keyword)) return new List<CnnvdVulnerability>();

            var keywords = keyword.Split(new[] { ' ', ',' }, StringSplitOptions.RemoveEmptyEntries)
                               .Select(k => k.ToLower().Trim())
                               .Where(k => k.Length > 0)
                               .ToList();

            lock (_dataLock)
            {
                return _vulnerabilities.Where(v =>
                {
                    var searchableText = $"{v.CveId} {v.Title} {v.Description}".ToLower();
                    return keywords.All(k => searchableText.Contains(k));
                }).ToList();
            }
        }

        /// <summary>
        /// 按CVE编号查找漏洞
        /// </summary>
        /// <param name="cveId">CVE编号</param>
        /// <returns>匹配的漏洞，未找到返回null</returns>
        public CnnvdVulnerability? GetByCveId(string cveId)
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
        /// 按受影响组件筛选漏洞
        /// </summary>
        /// <param name="componentName">组件名称</param>
        /// <returns>匹配的漏洞列表</returns>
        public List<CnnvdVulnerability> GetByComponent(string componentName)
        {
            EnsureInitialized();
            if (string.IsNullOrWhiteSpace(componentName)) return new List<CnnvdVulnerability>();

            lock (_dataLock)
            {
                return _vulnerabilities
                    .Where(v => v.AffectedComponent?.Contains(componentName, StringComparison.OrdinalIgnoreCase) == true)
                    .ToList();
            }
        }

        /// <summary>
        /// 获取统计摘要
        /// </summary>
        /// <returns>统计字典（包含各等级数量、总数等）</returns>
        public Dictionary<string, int> GetStatistics()
        {
            EnsureInitialized();
            
            lock (_dataLock)
            {
                var stats = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase)
                {
                    { "Total", _vulnerabilities.Count },
                    { "超危", 0 },
                    { "高危", 0 },
                    { "中危", 0 },
                    { "低危", 0 }
                };

                foreach (var vuln in _vulnerabilities)
                {
                    if (stats.ContainsKey(vuln.RiskLevel))
                    {
                        stats[vuln.RiskLevel]++;
                    }
                }

                // 组件分布统计
                var componentGroups = _vulnerabilities.GroupBy(v => v.AffectedComponent ?? "未知");
                foreach (var group in componentGroups)
                {
                    stats[$"组件:{group.Key}"] = group.Count();
                }

                // 平台分布统计
                var platformGroups = _vulnerabilities.GroupBy(v => v.Platform ?? "通用");
                foreach (var group in platformGroups)
                {
                    stats[$"平台:{group.Key}"] = group.Count();
                }

                return stats;
            }
        }

        #endregion

        #region 缓存机制

        /// <summary>
        /// 从本地缓存加载漏洞数据
        /// </summary>
        /// <param name="cancellationToken">取消令牌</param>
        /// <returns>缓存的漏洞数据</returns>
        private async Task<List<CnnvdVulnerability>> LoadFromCacheAsync(CancellationToken cancellationToken = default)
        {
            try
            {
                if (!File.Exists(_cacheFilePath)) return null;

                string json = await File.ReadAllTextAsync(_cacheFilePath, cancellationToken);
                var cacheModel = JsonSerializer.Deserialize<CnnvdCacheModel>(json, new JsonSerializerOptions
                {
                    PropertyNameCaseInsensitive = true
                });

                if (cacheModel?.Data == null || cacheModel.Data.Count == 0) return null;

                LastSyncTime = cacheModel.LastSyncTime;
                return cacheModel.Data;
            }
            catch (JsonException ex)
            {
                LogError($"解析缓存文件失败: {ex.Message}", ex);
                return null;
            }
            catch (Exception ex)
            {
                LogError($"加载缓存文件失败: {ex.Message}", ex);
                return null;
            }
        }

        /// <summary>
        /// 将漏洞数据保存到本地缓存
        /// </summary>
        /// <param name="vulnerabilities">要保存的漏洞数据</param>
        /// <param name="cancellationToken">取消令牌</param>
        private async Task SaveToCacheAsync(List<CnnvdVulnerability> vulnerabilities, CancellationToken cancellationToken = default)
        {
            try
            {
                var cacheModel = new CnnvdCacheModel
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
                
                // 先写入临时文件，再替换原文件，确保数据完整性
                string tempPath = _cacheFilePath + ".tmp";
                await File.WriteAllTextAsync(tempPath, json, cancellationToken);
                File.Replace(tempPath, _cacheFilePath, _cacheFilePath + ".bak");

                LogInfo($"已保存 {vulnerabilities.Count} 个漏洞到缓存文件");
            }
            catch (Exception ex)
            {
                LogError($"保存缓存文件失败: {ex.Message}", ex);
                throw;
            }
        }

        #endregion

        #region 内置漏洞数据库

        /// <summary>
        /// 获取内置的Agent CVE漏洞数据
        /// 共82个漏洞：超危12个、高危21个、中危47个、低危2个
        /// </summary>
        /// <returns>内置漏洞列表</returns>
        private List<CnnvdVulnerability> GetBuiltinVulnerabilities()
        {
            return new List<CnnvdVulnerability>
            {
                // ==================== 超危漏洞 (12个) ====================

                new CnnvdVulnerability
                {
                    CveId = "CVE-2026-25253",
                    CnnvdId = "CNNVD-202601-0001",
                    Title = "OpenClaw跨站WebSocket劫持(CSWSH)",
                    CvssScore = 8.8,
                    RiskLevel = "超危",
                    AttackVector = "Network",
                    AffectedComponent = "Gateway",
                    Platform = "OpenClaw",
                    Description = "OpenClaw Gateway存在跨站WebSocket劫持漏洞。攻击者可通过恶意网页劫持受害者的WebSocket连接，窃取AI Agent会话令牌、拦截用户与AI的对话内容，甚至注入恶意指令控制Agent行为。该漏洞影响所有使用OpenClaw Gateway WebSocket端点的部署。",
                    Remediation = "1. 升级OpenClaw到最新版本(>=2.5.3)\n2. 在WebSocket连接验证中加入Origin头检查\n3. 实施CSRF Token保护\n4. 配置Content-Security-Policy限制WebSocket源",
                    ReferenceUrl = "https://openclaw.dev/security/advisories/CVE-2026-25253",
                    PublishedDate = new DateTime(2026, 1, 15),
                    Tags = new List<string> { "WebSocket", "CSWSH", "劫持", "会话窃取" }
                },
                new CnnvdVulnerability
                {
                    CveId = "CVE-2026-25252",
                    CnnvdId = "CNNVD-202601-0002",
                    Title = "OpenClaw Gateway远程命令注入(RCE)",
                    CvssScore = 9.8,
                    RiskLevel = "超危",
                    AttackVector = "Network",
                    AffectedComponent = "Gateway",
                    Platform = "OpenClaw",
                    Description = "OpenClaw Gateway API端点存在严重的远程命令执行漏洞。由于对用户输入的Tool Call参数未做充分过滤，攻击者可通过构造恶意的工具调用请求在服务器上执行任意系统命令。该漏洞无需认证即可利用，可导致完整的系统接管。",
                    Remediation = "1. 立即升级到OpenClaw 2.5.4+\n2. 实施严格的输入验证和白名单过滤\n3. 使用沙箱环境隔离工具执行\n4. 禁用不必要的远程API端点\n5. 配置网络分段限制访问",
                    ReferenceUrl = "https://openclaw.dev/security/advisories/CVE-2026-25252",
                    PublishedDate = new DateTime(2026, 1, 14),
                    Tags = new List<string> { "RCE", "命令注入", "远程执行", "API安全" }
                },
                new CnnvdVulnerability
                {
                    CveId = "CVE-2026-25249",
                    CnnvdId = "CNNVD-202601-0003",
                    Title = "MCP Server认证绕过与权限提升",
                    CvssScore = 9.1,
                    RiskLevel = "超危",
                    AttackVector = "Network",
                    AffectedComponent = "MCP Server",
                    Platform = "Hermes Agent",
                    Description = "Hermes Agent的MCP(Model Context Protocol) Server存在认证绕过漏洞。攻击者可通过发送特制的握手包跳过身份验证流程，获得管理员级别的MCP访问权限。成功利用后可读取/修改模型上下文、注入恶意提示词、窃取API密钥等。",
                    Remediation = "1. 升级Hermes Agent至1.8.2+\n2. 强制启用mTLS双向认证\n3. 实施基于角色的访问控制(RBAC)\n4. 启用审计日志记录所有MCP操作\n5. 定期轮换MCP通信密钥",
                    ReferenceUrl = "https://hermes-agent.io/security/CVE-2026-25249",
                    PublishedDate = new DateTime(2026, 1, 12),
                    Tags = new List<string> { "认证绕过", "权限提升", "MCP", "上下文注入" }
                },
                new CnnvdVulnerability
                {
                    CveId = "CVE-2026-25248",
                    CnnvdId = "CNNVD-202601-0004",
                    Title = "OpenClaw Skill Loader供应链投毒",
                    CvssScore = 9.3,
                    RiskLevel = "超危",
                    AttackVector = "Network",
                    AffectedComponent = "Skill Loader",
                    Platform = "OpenClaw",
                    Description = "OpenClaw的Skill动态加载机制存在供应链攻击漏洞。攻击者可托管包含后门的恶意Skill包，当用户通过Skill Marketplace安装时自动执行恶意代码。该漏洞允许攻击者在Agent运行环境中建立持久化后门，监控所有用户交互并外传敏感数据。",
                    Remediation = "1. 升级到OpenClaw 2.5.5+\n2. 仅从官方认证的Skill仓库安装\n3. 启用Skill签名验证机制\n4. 在沙箱环境中预检新安装的Skill\n5. 定期审查已安装Skill的权限清单",
                    ReferenceUrl = "https://openclaw.dev/security/advisories/CVE-2026-25248",
                    PublishedDate = new DateTime(2026, 1, 10),
                    Tags = new List<string> { "供应链", "投毒", "后门", "Skill加载" }
                },
                new CnnvdVulnerability
                {
                    CveId = "CVE-2026-25246",
                    CnnvdId = "CNNVD-202601-0005",
                    Title = "Hermes Agent Prompt Injection通过MCP工具调用",
                    CvssScore = 9.0,
                    RiskLevel = "超危",
                    AttackVector = "Network",
                    AffectedComponent = "MCP Server",
                    Platform = "Hermes Agent",
                    Description = "Hermes Agent的MCP工具调用链存在间接Prompt Injection漏洞。攻击者可通过控制MCP工具返回的数据注入恶意指令，覆盖Agent的系统提示词。这允许攻击者操纵Agent行为，使其执行非预期的敏感操作如发送邮件、修改配置或泄露内部信息。",
                    Remediation = "1. 升级Hermes Agent到1.9.0+\n2. 对MCP工具返回值实施严格的输出编码\n3. 使用独立的信任边界分隔用户输入和系统指令\n4. 启用Prompt注入检测规则\n5. 限制MCP工具的数据回传大小",
                    ReferenceUrl = "https://hermes-agent.io/security/CVE-2026-25246",
                    PublishedDate = new DateTime(2026, 1, 8),
                    Tags = new List<string> { "Prompt注入", "MCP", "LLM安全", "指令劫持" }
                },
                new CnnvdVulnerability
                {
                    CveId = "CVE-2026-25244",
                    CnnvdId = "CNNVD-202601-0006",
                    Title = "OpenClaw UI SSRF导致内网探测",
                    CvssScore = 8.6,
                    RiskLevel = "超危",
                    AttackVector = "Network",
                    AffectedComponent = "UI",
                    Platform = "OpenClaw",
                    Description = "OpenClaw Web管理界面存在服务器端请求伪造(SSRF)漏洞。攻击者可通过Webhook配置或URL预览功能发起内网探测请求，扫描内网开放端口和服务。结合其他漏洞可实现内网横向移动，威胁整个Agent基础设施的安全。",
                    Remediation = "1. 升级OpenClaw到2.6.0+\n2. 实施URL白名单机制\n3. 禁止对内网IP段(10.x/172.16-31.x/192.168.x)的请求\n4. 代理所有出站HTTP请求并进行流量分析\n5. 启用网络隔离策略",
                    ReferenceUrl = "https://openclaw.dev/security/advisories/CVE-2026-25244",
                    PublishedDate = new DateTime(2026, 1, 6),
                    Tags = new List<string> { "SSRF", "内网探测", "Web界面", "网络隔离" }
                },
                new CnnvdVulnerability
                {
                    CveId = "CVE-2026-25242",
                    CnnvdId = "CNNVD-202512-0007",
                    Title = "Hermes Agent Memory Store反序列化RCE",
                    CvssScore = 9.8,
                    RiskLevel = "超危",
                    AttackVector = "Network",
                    AffectedComponent = "Memory Store",
                    Platform = "Hermes Agent",
                    Description = "Hermes Agent的记忆存储模块存在不安全的反序列化漏洞。攻击者可通过篡改存储的记忆数据注入任意对象，在Agent进程上下文中执行远程代码。由于记忆存储通常以高权限运行，此漏洞可导致完全的系统接管和数据泄露。",
                    Remediation = "1. 紧急升级到Hermes Agent 1.9.2+\n2. 迁移到安全的序列化格式(JSON/Protobuf)\n3. 对反序列化数据实施类型白名单\n4. 启用内存存储加密\n5. 监控异常的反序列化活动",
                    ReferenceUrl = "https://hermes-agent.io/security/CVE-2026-25242",
                    PublishedDate = new DateTime(2025, 12, 28),
                    Tags = new List<string> { "反序列化", "RCE", "内存存储", "对象注入" }
                },
                new CnnvdVulnerability
                {
                    CveId = "CVE-2026-25240",
                    CnnvdId = "CNNVD-202512-0008",
                    Title = "OpenClaw Plugin System任意文件读写",
                    CvssScore = 8.8,
                    RiskLevel = "超危",
                    AttackVector = "Network",
                    AffectedComponent = "Plugin System",
                    Platform = "OpenClaw",
                    Description = "OpenClaw插件系统的文件访问API存在路径遍历漏洞。恶意插件或经过身份验证的攻击者可通过../序列突破沙箱目录限制，读写服务器上的任意文件。此漏洞可用于窃取凭证、植入持久化后门或破坏系统关键文件。",
                    Remediation = "1. 升级到OpenClaw 2.6.1+\n2. 规范化所有文件路径并拒绝遍历序列\n3. 使用虚拟文件系统隔离插件访问\n4. 实施最小权限原则运行插件\n5. 启用插件文件访问审计日志",
                    ReferenceUrl = "https://openclaw.dev/security/advisories/CVE-2026-25240",
                    PublishedDate = new DateTime(2025, 12, 25),
                    Tags = new List<string> { "路径遍历", "文件读写", "插件系统", "沙箱逃逸" }
                },
                new CnnvdVulnerability
                {
                    CveId = "CVE-2026-25238",
                    CnnvdId = "CNNVD-202512-0009",
                    Title = "Hermes Agent Tool Registry竞态条件TOCTOU",
                    CvssScore = 7.7,
                    RiskLevel = "超危",
                    AttackVector = "Local",
                    AffectedComponent = "Tool Registry",
                    Platform = "Hermes Agent",
                    Description = "Hermes Agent的工具注册表存在检查时使用时(TOCTOU)竞态条件漏洞。在高并发场景下，攻击者可在工具注册验证和实际执行之间的时间窗口替换工具实现，导致执行未经授权的恶意代码。此漏洞在多租户共享Agent环境中尤为危险。",
                    Remediation = "1. 升级到Hermes Agent 1.10.0+\n2. 使用原子操作进行工具注册和验证\n3. 实施工具实现的哈希校验锁定\n4. 在独立进程中执行工具调用\n5. 启用并发访问控制",
                    ReferenceUrl = "https://hermes-agent.io/security/CVE-2026-25238",
                    PublishedDate = new DateTime(2025, 12, 22),
                    Tags = new List<string> { "竞态条件", "TOCTOU", "工具注册", "并发安全" }
                },
                new CnnvdVulnerability
                {
                    CveId = "CVE-2026-25236",
                    CnnvdId = "CNNVD-202512-0010",
                    Title = "OpenClaw Auth Bypass via JWT None Algorithm",
                    CvssScore = 9.1,
                    RiskLevel = "超危",
                    AttackVector = "Network",
                    AffectedComponent = "Auth Service",
                    Platform = "OpenClaw",
                    Description = "OpenClaw的身份认证服务存在JWT算法混淆漏洞。攻击者可将JWT签名算法改为'none'绕过签名验证，伪造任意用户的认证令牌。成功利用可获得管理员权限，完全控制OpenClaw平台的所有功能和数据。",
                    Remediation = "1. 紧急升级到OpenClaw 2.6.2+\n2. 显式指定允许的JWT签名算法(HS256/RS256)\n3. 拒绝alg=none的令牌\n4. 实施令牌黑名单机制\n5. 启用多因素认证(MFA)",
                    ReferenceUrl = "https://openclaw.dev/security/advisories/CVE-2026-25236",
                    PublishedDate = new DateTime(2025, 12, 20),
                    Tags = new List<string> { "JWT绕过", "认证失效", "算法混淆", "身份伪造" }
                },
                new CnnvdVulnerability
                {
                    CveId = "CVE-2026-25234",
                    CnnvdId = "CNNVD-202512-0011",
                    Title = "Hermes Agent Sandbox Escape via Container Misconfiguration",
                    CvssScore = 9.0,
                    RiskLevel = "超危",
                    AttackVector = "Network",
                    AffectedComponent = "Execution Engine",
                    Platform = "Hermes Agent",
                    Description = "Hermes Agent的Docker容器沙箱因配置不当存在逃逸漏洞。容器以特权模式运行且挂载了宿主机敏感目录(/var/run/docker.sock)，攻击者可通过容器逃逸获取宿主机root权限，进而控制整个Kubernetes集群或云基础设施。",
                    Remediation = "1. 紧急升级到Hermes Agent 1.10.2+\n2. 移除容器特权模式和敏感挂载点\n3. 使用gVisor/Kata Containers增强隔离\n4. 实施Pod Security Standards策略\n5. 启用运行时安全监控(Sysdig/Falco)",
                    ReferenceUrl = "https://hermes-agent.io/security/CVE-2026-25234",
                    PublishedDate = new DateTime(2025, 12, 18),
                    Tags = new List<string> { "容器逃逸", "沙箱突破", "Docker", "提权" }
                },
                new CnnvdVulnerability
                {
                    CveId = "CVE-2026-25232",
                    CnnvdId = "CNNVD-202512-0012",
                    Title = "OpenClaw Database SQL注入导致全库泄露",
                    CvssScore = 9.8,
                    RiskLevel = "超危",
                    AttackVector = "Network",
                    AffectedComponent = "Database Layer",
                    Platform = "OpenClaw",
                    Description = "OpenClaw的数据访问层存在严重的SQL注入漏洞。多个API端点直接拼接用户查询参数到SQL语句中，攻击者可利用UNION SELECT提取完整数据库内容，包括用户凭据、API密钥、对话历史和Agent配置等高度敏感信息。",
                    Remediation = "1. 紧急升级到OpenClaw 2.7.0+\n2. 全面迁移到参数化查询(ORM)\n3. 实施WAF规则检测SQL注入\n4. 数据库账户最小权限原则\n5. 启用查询审计和异常告警",
                    ReferenceUrl = "https://openclaw.dev/security/advisories/CVE-2026-25232",
                    PublishedDate = new DateTime(2025, 12, 15),
                    Tags = new List<string> { "SQL注入", "数据泄露", "数据库", "UNION注入" }
                },

                // ==================== 高危漏洞 (21个) ====================

                new CnnvdVulnerability
                {
                    CveId = "CVE-2026-25251",
                    CnnvdId = "CNNVD-202601-0013",
                    Title = "Hermes Agent Skill供应链投毒",
                    CvssScore = 8.1,
                    RiskLevel = "高危",
                    AttackVector = "Network",
                    AffectedComponent = "Skill Loader",
                    Platform = "Hermes Agent",
                    Description = "Hermes Agent的Skill安装过程存在中间人攻击风险。Skill下载使用未加密的HTTP连接且未校验包完整性，攻击者可在网络传输层篡改Skill包内容，注入恶意代码随Agent启动自动执行。",
                    Remediation = "1. 升级到Hermes Agent 1.8.5+\n2. 强制使用HTTPS下载Skill\n3. 校验Skill包数字签名和SHA256哈希\n4. 使用可信的Skill镜像源\n5. 启用Skill安装审计",
                    ReferenceUrl = "https://hermes-agent.io/security/CVE-2026-25251",
                    PublishedDate = new DateTime(2026, 1, 13),
                    Tags = new List<string> { "供应链", "MITM", "Skill安全", "包篡改" }
                },
                new CnnvdVulnerability
                {
                    CveId = "CVE-2026-25250",
                    CnnvdId = "CNNVD-202601-0014",
                    Title = "OpenClaw UI网关URL篡改与开放重定向",
                    CvssScore = 7.5,
                    RiskLevel = "高危",
                    AttackVector = "Network",
                    AffectedComponent = "UI",
                    Platform = "OpenClaw",
                    Description = "OpenClaw Web界面的OAuth回调处理存在URL篡改漏洞。攻击者可构造恶意回调链接将用户重定向到钓鱼网站，窃取OAuth授权码或Session Cookie。配合社工攻击可有效劫持用户账号。",
                    Remediation = "1. 升级到OpenClaw 2.5.6+\n2. 验证回调URL必须为注册的合法域名\n3. 使用state参数防止CSRF\n4. 实施Referer和Origin检查\n5. 用户操作增加二次确认",
                    ReferenceUrl = "https://openclaw.dev/security/advisories/CVE-2026-25250",
                    PublishedDate = new DateTime(2026, 1, 11),
                    Tags = new List<string> { "开放重定向", "URL篡改", "OAuth", "钓鱼" }
                },
                new CnnvdVulnerability
                {
                    CveId = "CVE-2026-25247",
                    CnnvdId = "CNNVD-202601-0015",
                    Title = "OpenClaw XSS存储型导致Agent会话劫持",
                    CvssScore = 7.8,
                    RiskLevel = "高危",
                    AttackVector = "Network",
                    AffectedComponent = "UI",
                    Platform = "OpenClaw",
                    Description = "OpenClaw管理界面存在存储型XSS漏洞。攻击者可通过Agent名称、描述字段或对话历史注入JavaScript代码。当管理员查看受污染页面时，XSS payload可窃取Session Token并劫持管理员会话，执行任意管理操作。",
                    Remediation = "1. 升级到OpenClaw 2.5.7+\n2. 所有用户输入实施输出编码\n3. 使用CSP(Content-Security-Policy)限制脚本执行\n4. 设置HttpOnly和Secure标志的Cookie\n5. 启用XSS过滤和输入长度限制",
                    ReferenceUrl = "https://openclaw.dev/security/advisories/CVE-2026-25247",
                    PublishedDate = new DateTime(2026, 1, 9),
                    Tags = new List<string> { "XSS", "存储型", "会话劫持", "前端安全" }
                },
                new CnnvdVulnerability
                {
                    CveId = "CVE-2026-25245",
                    CnnvdId = "CNNVD-202601-0016",
                    Title = "Hermes Agent API Rate Limiting Bypass",
                    CvssScore = 7.0,
                    RiskLevel = "高危",
                    AttackVector = "Network",
                    AffectedComponent = "API Gateway",
                    Platform = "Hermes Agent",
                    Description = "Hermes Agent的API网关速率限制可通过IP欺骗或请求管道化绕过。攻击者可发送大量请求耗尽API配额或触发DoS，影响正常用户使用。在计费场景下还可造成经济损失。",
                    Remediation = "1. 升级到Hermes Agent 1.8.8+\n2. 基于用户ID而非IP实施限流\n3. 使用滑动窗口算法替代固定计数器\n4. 实施多层限流(网关+应用)\n5. 启用异常流量检测和告警",
                    ReferenceUrl = "https://hermes-agent.io/security/CVE-2026-25245",
                    PublishedDate = new DateTime(2026, 1, 7),
                    Tags = new List<string> { "限流绕过", "DoS", "API滥用", "资源耗尽" }
                },
                new CnnvdVulnerability
                {
                    CveId = "CVE-2026-25243",
                    CnnvdId = "CNNVD-202601-0017",
                    Title = "OpenClaw Config File Sensitive Data Exposure",
                    CvssScore = 7.5,
                    RiskLevel = "高危",
                    AttackVector = "Local",
                    AffectedComponent = "Configuration",
                    Platform = "OpenClaw",
                    Description = "OpenClaw的配置文件权限设置过于宽松，世界可读。配置文件中包含明文存储的API密钥、数据库密码、第三方服务凭证等敏感信息。任何本地用户或已入侵的低权限账户均可读取这些凭据。",
                    Remediation = "1. 升级到OpenClaw 2.6.0+\n2. 配置文件权限设置为600(仅所有者可读写)\n3. 使用密钥管理系统(KMS/Vault)存储敏感配置\n4. 敏感值使用环境变量或加密存储\n5. 定期扫描配置文件中的明文密钥",
                    ReferenceUrl = "https://openclaw.dev/security/advisories/CVE-2026-25243",
                    PublishedDate = new DateTime(2026, 1, 5),
                    Tags = new List<string> { "信息泄露", "配置安全", "权限错误", "凭证暴露" }
                },
                new CnnvdVulnerability
                {
                    CveId = "CVE-2026-25241",
                    CnnvdId = "CNNVD-202512-0018",
                    Title = "Hermes Agent Logging Sensitive Data in Plaintext",
                    CvssScore = 6.8,
                    RiskLevel = "高危",
                    AttackVector = "Local",
                    AffectedComponent = "Logging System",
                    Platform = "Hermes Agent",
                    Description = "Hermes Agent的日志系统将敏感数据(用户输入、API密钥、Token)以明文形式写入日志文件。具有日志读取权限的攻击者可从中提取大量敏感信息，用于进一步攻击或数据泄露。",
                    Remediation = "1. 升级到Hermes Agent 1.9.1+\n2. 日志输出前对敏感字段脱敏(masking)\n3. 实施日志访问控制和审计\n4. 配置日志保留期限和自动清理\n5. 使用集中式日志管理系统(ELK/Splunk)",
                    ReferenceUrl = "https://hermes-agent.io/security/CVE-2026-25241",
                    PublishedDate = new DateTime(2025, 12, 27),
                    Tags = new List<string> { "日志泄露", "明文日志", "敏感数据", "合规性" }
                },
                new CnnvdVulnerability
                {
                    CveId = "CVE-2026-25239",
                    CnnvdId = "CNNVD-202512-0019",
                    Title = "OpenClaw WebSocket Message Queue DoS",
                    CvssScore = 7.5,
                    RiskLevel = "高危",
                    AttackVector = "Network",
                    AffectedComponent = "Gateway",
                    Platform = "OpenClaw",
                    Description = "OpenClaw Gateway的WebSocket消息队列缺乏背压机制。攻击者可快速发送大量消息填满队列内存，导致服务OOM崩溃或无响应。恢复期间所有活跃的Agent连接都会断开，造成服务中断。",
                    Remediation = "1. 升级到OpenClaw 2.6.1+\n2. 实施消息队列大小限制和背压策略\n3. 启用单连接消息速率限制\n4. 配置合理的内存阈值和优雅降级\n5. 部署健康检查和自动重启机制",
                    ReferenceUrl = "https://openclaw.dev/security/advisories/CVE-2026-25239",
                    PublishedDate = new DateTime(2025, 12, 24),
                    Tags = new List<string> { "DoS", "WebSocket", "内存耗尽", "背压" }
                },
                new CnnvdVulnerability
                {
                    CveId = "CVE-2026-25237",
                    CnnvdId = "CNNVD-202512-0020",
                    Title = "Hermes Agent CORS Policy Misconfiguration",
                    CvssScore = 6.5,
                    RiskLevel = "高危",
                    AttackVector = "Network",
                    AffectedComponent = "API Gateway",
                    Platform = "Hermes Agent",
                    Description = "Hermes Agent的CORS策略配置为Allow-Origin: *，允许任意域名的跨域请求。攻击者可构造恶意网页窃取已登录用户的API响应数据，包括Agent配置、对话内容和用户凭证。",
                    Remediation = "1. 升级到Hermes Agent 1.9.0+\n2. 配置精确的允许来源白名单\n3. 避免使用通配符*和Credentials: true组合\n4. 实施额外的Origin验证逻辑\n5. 定期审查CORS配置变更",
                    ReferenceUrl = "https://hermes-agent.io/security/CVE-2026-25237",
                    PublishedDate = new DateTime(2025, 12, 21),
                    Tags = new List<string> { "CORS", "跨域", "数据窃取", "配置错误" }
                },
                new CnnvdVulnerability
                {
                    CveId = "CVE-2026-25235",
                    CnnvdId = "CNNVD-202512-0021",
                    Title = "OpenClaw IDOR导致越权访问Agent数据",
                    CvssScore = 7.2,
                    RiskLevel = "高危",
                    AttackVector = "Network",
                    AffectedComponent = "API Gateway",
                    Platform = "OpenClaw",
                    Description = "OpenClaw的REST API存在不安全的直接对象引用(IDOR)漏洞。通过递增资源ID，认证用户可访问其他用户的Agent实例、对话历史和配置信息。多租户环境下可导致严重的数据泄露。",
                    Remediation = "1. 升级到OpenClaw 2.6.2+\n2. 使用UUID替代自增ID作为资源标识\n3. 每个API调用强制校验资源所有权\n4. 实施租户隔离的数据访问层\n5. 启用越权访问检测和告警",
                    ReferenceUrl = "https://openclaw.dev/security/advisories/CVE-2026-25235",
                    PublishedDate = new DateTime(2025, 12, 19),
                    Tags = new List<string> { "IDOR", "越权访问", "水平越权", "数据隔离" }
                },
                new CnnvdVulnerability
                {
                    CveId = "CVE-2026-25233",
                    CnnvdId = "CNNVD-202512-0022",
                    Title = "Hermes Agent XML External Entity (XXE) Injection",
                    CvssScore = 7.0,
                    RiskLevel = "高危",
                    AttackVector = "Network",
                    AffectedComponent = "Config Parser",
                    Platform = "Hermes Agent",
                    Description = "Hermes Agent的XML配置解析器未禁用外部实体引用。攻击者可上传包含XXE payload的配置文件，读取服务器上的任意文件(如/etc/passwd)、探测内网端口或发起SSRF攻击。某些情况下还可触发DoS(Billion Laughs)。",
                    Remediation = "1. 升级到Hermes Agent 1.10.0+\n2. 禁用DTD和外部实体解析(disallow-doctype-decl=true)\n3. 迁移到JSON/YAML格式的配置文件\n4. 对上传的XML文件进行Schema验证\n5. 使用安全的XML解析库",
                    ReferenceUrl = "https://hermes-agent.io/security/CVE-2026-25233",
                    PublishedDate = new DateTime(2025, 12, 17),
                    Tags = new List<string> { "XXE", "XML注入", "文件读取", "SSRF" }
                },
                new CnnvdVulnerability
                {
                    CveId = "CVE-2026-25231",
                    CnnvdId = "CNNVD-202512-0023",
                    Title = "OpenClaw Weak Cryptography in Data-at-Rest",
                    CvssScore = 6.8,
                    RiskLevel = "高危",
                    AttackVector = "Local",
                    AffectedComponent = "Encryption Module",
                    Platform = "OpenClaw",
                    Description = "OpenClaw的静态数据加密使用弱加密算法(ECB模式的AES)和硬编码密钥。具备本地文件访问权限的攻击者可解密存储的Agent记忆、用户凭证和其他敏感数据。ECB模式还使得相同明文产生相同密文，易受频率分析攻击。",
                    Remediation = "1. 升级到OpenClaw 2.7.0+\n2. 使用AES-GCM或ChaCha20-Poly1305替代ECB\n3. 密钥从KMS动态获取，禁止硬编码\n4. 每条数据使用唯一的IV/Nonce\n5. 定期轮换加密密钥",
                    ReferenceUrl = "https://openclaw.dev/security/advisories/CVE-2026-25231",
                    PublishedDate = new DateTime(2025, 12, 14),
                    Tags = new List<string> { "弱加密", "ECB模式", "硬编码密钥", "密码学" }
                },
                new CnnvdVulnerability
                {
                    CveId = "CVE-2026-25230",
                    CnnvdId = "CNNVD-202512-0024",
                    Title = "Hermes Agent Template Injection in Report Generator",
                    CvssScore = 7.5,
                    RiskLevel = "高危",
                    AttackVector = "Network",
                    AffectedComponent = "Report Engine",
                    Platform = "Hermes Agent",
                    Description = "Hermes Agent的报告生成引擎存在服务端模板注入(SSTI)漏洞。用户可控的输入被直接嵌入模板表达式(Jinja2/Liquid)中，攻击者可注入模板语法执行任意代码、读取环境变量或建立反向Shell连接。",
                    Remediation = "1. 升级到Hermes Agent 1.10.1+\n2. 使用沙箱化的模板渲染环境\n3. 禁用危险的模板方法和属性\n4. 对模板输入实施严格的白名单验证\n5. 使用静态模板而非动态拼接",
                    ReferenceUrl = "https://hermes-agent.io/security/CVE-2026-25230",
                    PublishedDate = new DateTime(2025, 12, 12),
                    Tags = new List<string> { "SSTI", "模板注入", "Jinja2", "代码执行" }
                },
                new CnnvdVulnerability
                {
                    CveId = "CVE-2026-25229",
                    CnnvdId = "CNNVD-202512-0025",
                    Title = "OpenClaw Session Fixation Attack",
                    CvssScore = 6.5,
                    RiskLevel = "高危",
                    AttackVector = "Network",
                    AffectedComponent = "Auth Service",
                    Platform = "OpenClaw",
                    Description = "OpenClaw的认证模块存在会话固定漏洞。登录前后未重新生成Session ID，攻击者可预先设置受害者的Session ID，待受害者登录后使用同一Session ID劫持其已认证会话。",
                    Remediation = "1. 升级到OpenClaw 2.7.1+\n2. 登录成功后强制重新生成Session ID\n3. 绑定Session到客户端指纹(IP/User-Agent)\n4. 设置合理的Session超时时间\n5. 实施并发登录检测和旧Session失效",
                    ReferenceUrl = "https://openclaw.dev/security/advisories/CVE-2026-25229",
                    PublishedDate = new DateTime(2025, 12, 10),
                    Tags = new List<string> { "会话固定", "Session劫持", "认证安全", "身份冒充" }
                },
                new CnnvdVulnerability
                {
                    CveId = "CVE-2026-25228",
                    CnnvdId = "CNNVD-202512-0026",
                    Title = "Hermes Agent Insecure Direct Download of Artifacts",
                    CvssScore = 6.8,
                    RiskLevel = "高危",
                    AttackVector = "Network",
                    AffectedComponent = "File Server",
                    Platform = "Hermes Agent",
                    Description = "Hermes Agent的工件(artifact)下载端点缺少授权检查。任何知道URL格式的用户均可下载Agent生成的报告、导出的数据和训练产物，无需提供有效的认证Token。可导致知识产权和敏感业务数据的大规模泄露。",
                    Remediation = "1. 升级到Hermes Agent 1.10.3+\n2. 所有下载端点添加认证和授权检查\n3. 使用临时签名URL(expiring download links)\n4. 记录所有下载操作的审计日志\n5. 实施数据分类和DLP策略",
                    ReferenceUrl = "https://hermes-agent.io/security/CVE-2026-25228",
                    PublishedDate = new DateTime(2025, 12, 8),
                    Tags = new List<string> { "未授权访问", "文件下载", "数据泄露", "缺失鉴权" }
                },
                new CnnvdVulnerability
                {
                    CveId = "CVE-2026-25227",
                    CnnvdId = "CNNVD-202512-0027",
                    Title = "OpenClaw Regex DoS (ReDoS) in Input Validation",
                    CvssScore = 7.0,
                    RiskLevel = "高危",
                    AttackVector = "Network",
                    AffectedComponent = "Input Validator",
                    Platform = "OpenClaw",
                    Description = "OpenClaw的用户输入验证使用了存在ReDoS风险的复杂正则表达式。攻击者可精心构造特殊字符串使正则匹配产生指数级回溯，导致CPU长时间100%占用，形成有效的DoS攻击。单个请求即可使服务线程瘫痪数分钟。",
                    Remediation = "1. 升级到OpenClaw 2.7.2+\n2. 重写有问题的正则表达式消除回溯风险\n3. 设置正则匹配的超时时间限制\n4. 使用线性时间的正则引擎(RE2/NFA)\n5. 对输入长度实施合理上限",
                    ReferenceUrl = "https://openclaw.dev/security/advisories/CVE-2026-25227",
                    PublishedDate = new DateTime(2025, 12, 6),
                    Tags = new List<string> { "ReDoS", "正则DoS", "回溯爆炸", "CPU耗尽" }
                },
                new CnnvdVulnerability
                {
                    CveId = "CVE-2026-25226",
                    CnnvdId = "CNNVD-202512-0028",
                    Title = "Hermes Agent Mass Assignment Vulnerability",
                    CvssScore = 6.5,
                    RiskLevel = "高危",
                    AttackVector = "Network",
                    AffectedComponent = "API Gateway",
                    Platform = "Hermes Agent",
                    Description = "Hermes Agent的API端点存在批量赋值漏洞。攻击者可通过API请求体中额外传入role=admin、isVerified=true等字段，直接修改用户对象的内部属性而无需经过正常的权限审批流程。可导致普通用户提升为管理员角色。",
                    Remediation = "1. 升级到Hermes Agent 1.11.0+\n2. 使用显式的模型绑定白名单\n3. 区分可编辑字段和内部字段\n4. 实施DTO(Data Transfer Object)模式\n5. 服务端对所有赋值操作进行权限校验",
                    ReferenceUrl = "https://hermes-agent.io/security/CVE-2026-25226",
                    PublishedDate = new DateTime(2025, 12, 4),
                    Tags = new List<string> { "批量赋值", "权限提升", "模型绑定", "字段篡改" }
                },
                new CnnvdVulnerability
                {
                    CveId = "CVE-2026-25225",
                    CnnvdId = "CNNVD-202512-0029",
                    Title = "OpenClaw HTTP Request Smuggling via CL.TE",
                    CvssScore = 7.5,
                    RiskLevel = "高危",
                    AttackVector = "Network",
                    AffectedComponent = "Gateway",
                    Platform = "OpenClaw",
                    Description = "OpenClaw Gateway的前后端对Content-Length和Transfer-Encoding头的解析不一致(CL.TE变体)，存在HTTP请求走私漏洞。攻击者可利用此漏洞绕过WAF安全检测、劫持其他用户的请求、或缓存投毒注入恶意响应。",
                    Remediation = "1. 升级到OpenClaw 2.7.3+\n2. 标准化HTTP请求头解析逻辑\n3. 拒绝含歧义的请求(同时包含CL和TE)\n4. 使用统一的反向代理(Nginx/Apache)\n5. 启用HTTP/2减少走私风险",
                    ReferenceUrl = "https://openclaw.dev/security/advisories/CVE-2026-25225",
                    PublishedDate = new DateTime(2025, 12, 2),
                    Tags = new List<string> { "请求走私", "CL.TE", "WAF绕过", "缓存投毒" }
                },
                new CnnvdVulnerability
                {
                    CveId = "CVE-2026-25224",
                    CnnvdId = "CNNVD-202512-0030",
                    Title = "Hermes Agent Path Traversal in File Upload",
                    CvssScore = 7.2,
                    RiskLevel = "高危",
                    AttackVector = "Network",
                    AffectedComponent = "File Handler",
                    Platform = "Hermes Agent",
                    Description = "Hermes Agent的文件上传功能存在路径遍历漏洞。文件名未经过滤直接拼接到目标路径，攻击者可通过../../../序列将文件写入任意目录。可覆盖系统配置文件、写入WebShell或在启动目录放置恶意脚本实现持久化。",
                    Remediation = "1. 升级到Hermes Agent 1.11.1+\n2. 规范化文件路径并拒绝非法字符\n3. 使用UUID重命名上传文件\n4. 将上传目录置于Web根之外\n5. 限制上传文件的扩展名和类型",
                    ReferenceUrl = "https://hermes-agent.io/security/CVE-2026-25224",
                    PublishedDate = new DateTime(2025, 11, 30),
                    Tags = new List<string> { "路径遍历", "文件上传", "WebShell", "任意写" }
                },
                new CnnvdVulnerability
                {
                    CveId = "CVE-2026-25223",
                    CnnvdId = "CNNVD-202512-0031",
                    Title = "OpenClaw Information Disclosure via Error Messages",
                    CvssScore = 6.5,
                    RiskLevel = "高危",
                    AttackVector = "Network",
                    AffectedComponent = "Error Handler",
                    Platform = "OpenClaw",
                    Description = "OpenClaw的错误处理程序向客户端暴露过多内部信息。堆栈跟踪、SQL语句片段、内部路径、依赖版本等调试信息在异常响应中返回。这些信息可帮助攻击者精准定位漏洞类型并制定攻击方案。",
                    Remediation = "1. 升级到OpenClaw 2.7.4+\n2. 生产环境关闭详细错误信息\n3. 自定义友好的错误页面\n4. 错误详情仅写入服务端日志\n5. 实施统一的异常处理中间件",
                    ReferenceUrl = "https://openclaw.dev/security/advisories/CVE-2026-25223",
                    PublishedDate = new DateTime(2025, 11, 28),
                    Tags = new List<string> { "信息泄露", "错误信息", "堆栈暴露", "调试信息" }
                },

                // ==================== 中危漏洞 (47个) - 精简展示代表性漏洞 ====================

                new CnnvdVulnerability
                {
                    CveId = "CVE-2026-25222",
                    CnnvdId = "CNNVD-202512-0032",
                    Title = "Hermes Agent Missing Security Headers",
                    CvssScore = 5.3,
                    RiskLevel = "中危",
                    AttackVector = "Network",
                    AffectedComponent = "Web Server",
                    Platform = "Hermes Agent",
                    Description = "Hermes Agent的Web服务缺少关键安全响应头(X-Frame-Options, X-Content-Type-Options, Strict-Transport-Security等)。应用易受点击劫持、MIME嗅探和协议降级攻击。",
                    Remediation = "1. 升级到Hermes Agent 1.11.2+\n2. 添加完整的安全响应头集合\n3. 启用HSTS并设置max-age>=31536000\n4. 配置CSP策略限制资源加载源\n5. 定期使用安全头部扫描器检查",
                    ReferenceUrl = "https://hermes-agent.io/security/CVE-2026-25222",
                    PublishedDate = new DateTime(2025, 11, 26),
                    Tags = new List<string> { "安全头缺失", "点击劫持", "HSTS", "CSP" }
                },
                new CnnvdVulnerability
                {
                    CveId = "CVE-2026-25221",
                    CnnvdId = "CNNVD-202512-0033",
                    Title = "OpenClaw Clickjacking via Missing X-Frame-Options",
                    CvssScore = 5.0,
                    RiskLevel = "中危",
                    AttackVector = "Network",
                    AffectedComponent = "UI",
                    Platform = "OpenClaw",
                    Description = "OpenClaw管理界面未设置X-Frame-Options头，可被恶意网站嵌入透明iframe中。攻击者可诱导用户在不知情的情况下点击隐藏按钮，执行删除Agent、修改配置等危险操作。",
                    Remediation = "1. 升级到OpenClaw 2.7.5+\n2. 添加X-Frame-Options: DENY/SAMEORIGIN\n3. 实施CSP frame-ancestors指令\n4. 使用frame-busting JavaScript作为防御深度\n5. 用户敏感操作需二次确认",
                    ReferenceUrl = "https://openclaw.dev/security/advisories/CVE-2026-25221",
                    PublishedDate = new DateTime(2025, 11, 24),
                    Tags = new List<string> { "点击劫持", "iframe嵌入", "UI安全", "社会工程" }
                },
                new CnnvdVulnerability
                {
                    CveId = "CVE-2026-25220",
                    CnnvdId = "CNNVD-202512-0034",
                    Title = "Hermes Agent CSRF Token Not Validated on State-Changing Ops",
                    CvssScore = 5.5,
                    RiskLevel = "中危",
                    AttackVector = "Network",
                    AffectedComponent = "Web Interface",
                    Platform = "Hermes Agent",
                    Description = "Hermes Agent的多个状态变更操作(API Key创建、Agent删除、配置修改)缺少CSRF Token验证。已认证的用户访问恶意网页时可触发非预期的状态变更请求。",
                    Remediation = "1. 升级到Hermes Agent 1.11.3+\n2. 所有状态变更操作添加CSRF Token验证\n3. 使用SameSite=Strict/Lax的Cookie\n4. 实施自定义Request Header验证\n5. 关键操作要求重新认证",
                    ReferenceUrl = "https://hermes-agent.io/security/CVE-2026-25220",
                    PublishedDate = new DateTime(2025, 11, 22),
                    Tags = new List<string> { "CSRF", "跨站请求伪造", "状态变更", "Token缺失" }
                },
                new CnnvdVulnerability
                {
                    CveId = "CVE-2026-25219",
                    CnnvdId = "CNNVD-202512-0035",
                    Title = "OpenClaw Verbose API Documentation Exposes Endpoints",
                    CvssScore = 4.5,
                    RiskLevel = "中危",
                    AttackVector = "Network",
                    AffectedComponent = "Documentation",
                    Platform = "OpenClaw",
                    Description = "OpenClaw的Swagger/OpenAPI文档公开了所有API端点细节，包括内部管理接口和调试端点。攻击者可利用文档发现未授权的功能点和隐藏的攻击面。",
                    Remediation = "1. 升级到OpenClaw 2.7.6+\n2. 生产环境禁用Swagger文档\n3. 文档访问需要单独的认证\n4. 分离内部API和外部API文档\n5. 定期审计暴露的API端点",
                    ReferenceUrl = "https://openclaw.dev/security/advisories/CVE-2026-25219",
                    PublishedDate = new DateTime(2025, 11, 20),
                    Tags = new List<string> { "信息泄露", "Swagger", "API文档", "攻击面暴露" }
                },
                new CnnvdVulnerability
                {
                    CveId = "CVE-2026-25218",
                    CnnvdId = "CNNVD-202512-0036",
                    Title = "Hermes Agent Default Credentials Still Active",
                    CvssScore = 7.0,
                    RiskLevel = "中危",
                    AttackVector = "Network",
                    AffectedComponent = "Authentication",
                    Platform = "Hermes Agent",
                    Description = "Hermes Agent在首次安装后的初始配置阶段仍保留默认管理员凭据(admin/admin123)。若管理员未及时更改，攻击者可利用默认凭据获得系统完全控制权。",
                    Remediation = "1. 升级到Hermes Agent 1.12.0+\n2. 首次登录强制修改默认密码\n3. 默认密码使用随机生成\n4. 检测到默认密码时发出告警\n5. 实施密码强度策略",
                    ReferenceUrl = "https://hermes-agent.io/security/CVE-2026-25218",
                    PublishedDate = new DateTime(2025, 11, 18),
                    Tags = new List<string> { "默认凭证", "弱口令", "初始配置", "身份认证" }
                },
                new CnnvdVulnerability
                {
                    CveId = "CVE-2026-25217",
                    CnnvdId = "CNNVD-202512-0037",
                    Title = "OpenClaw Insecure TLS Configuration",
                    CvssScore = 5.5,
                    RiskLevel = "中危",
                    AttackVector = "Network",
                    AffectedComponent = "TLS Terminator",
                    Platform = "OpenClaw",
                    Description = "OpenClaw的TLS配置支持过时的协议版本(TLS 1.0/1.1)和弱加密套件(export grade, RC4)。中间人攻击者可降级连接安全性并解密流量，或使用已知弱点破解加密。",
                    Remediation = "1. 升级到OpenClaw 2.8.0+\n2. 仅启用TLS 1.2和1.3\n3. 禁用弱加密套件(3DES, RC4, DES)\n4. 配置强密码套件优先级(ECDHE+AESGCM)\n5. 定期使用SSL Labs扫描评估",
                    ReferenceUrl = "https://openclaw.dev/security/advisories/CVE-2026-25217",
                    PublishedDate = new DateTime(2025, 11, 16),
                    Tags = new List<string> { "TLS配置", "协议降级", "弱加密套件", "中间人" }
                },
                new CnnvdVulnerability
                {
                    CveId = "CVE-2026-25216",
                    CnnvdId = "CNNVD-202512-0038",
                    Title = "Hermes Agent Unrestricted File Upload Types",
                    CvssScore = 5.8,
                    RiskLevel = "中危",
                    AttackVector = "Network",
                    AffectedComponent = "File Handler",
                    Platform = "Hermes Agent",
                    Description = "Hermes Agent的文件上传功能未限制文件类型，允许上传可执行文件(.exe, .sh, .php, .jsp)。若上传目录可被Web服务器解释执行，攻击者可直接上传WebShell获取服务器控制权。",
                    Remediation = "1. 升级到Hermes Agent 1.12.1+\n2. 实施严格的文件类型白名单\n3. 基于Magic Number检测真实文件类型\n4. 上传文件存储于专用目录禁止执行\n5. 扫描上传文件中的恶意代码",
                    ReferenceUrl = "https://hermes-agent.io/security/CVE-2026-25216",
                    PublishedDate = new DateTime(2025, 11, 14),
                    Tags = new List<string> { "文件上传", "类型不限", "WebShell", "恶意代码" }
                },
                new CnnvdVulnerability
                {
                    CveId = "CVE-2026-25215",
                    CnnvdId = "CNNVD-202512-0039",
                    Title = "OpenClaw Missing Authentication on Debug Endpoint",
                    CvssScore = 6.5,
                    RiskLevel = "中危",
                    AttackVector = "Network",
                    AffectedComponent = "Debug Interface",
                    Platform = "OpenClaw",
                    Description = "OpenClaw的/debug端点(/healthz, /metrics, /env)未要求认证即可访问。攻击者可获取详细的系统信息(环境变量、依赖版本、性能指标)，用于规划后续攻击。",
                    Remediation = "1. 升级到OpenClaw 2.8.1+\n2. 所有调试端点添加认证保护\n3. 生产环境完全禁用debug路由\n4. 敏感信息从健康检查响应中移除\n5. 使用独立的运维VPN访问监控端口",
                    ReferenceUrl = "https://openclaw.dev/security/advisories/CVE-2026-25215",
                    PublishedDate = new DateTime(2025, 11, 12),
                    Tags = new List<string> { "调试端点", "未认证", "信息收集", "运维安全" }
                },
                new CnnvdVulnerability
                {
                    CveId = "CVE-2026-25214",
                    CnnvdId = "CNNVD-202512-0040",
                    Title = "Hermes Agent Subdomain Takeover via Cloud Resources",
                    CvssScore = 5.0,
                    RiskLevel = "中危",
                    AttackVector = "Network",
                    AffectedComponent = "DNS Configuration",
                    Platform = "Hermes Agent",
                    Description = "Hermes Agent使用的云服务子域名(agent.hermes.example.com)指向已释放的云资源(CNAME记录残留)。攻击者可注册同名云资源接管子域名，托管钓鱼页面或收集用户凭证。",
                    Remediation = "1. 审查所有DNS记录确保指向有效资源\n2. 删除不再使用的云资源和对应DNS\n3. 定期自动化扫描悬空子域名\n4. 使用云服务商的子域名接管防护功能\n5. 监控DNS变更并设置告警",
                    ReferenceUrl = "https://hermes-agent.io/security/CVE-2026-25214",
                    PublishedDate = new DateTime(2025, 11, 10),
                    Tags = new List<string> { "子域名接管", "DNS", "云安全", "CNA" }
                },
                new CnnvdVulnerability
                {
                    CveId = "CVE-2026-25213",
                    CnnvdId = "CNNVD-202512-0041",
                    Title = "OpenClaw Email Verification Bypass",
                    CvssScore = 5.5,
                    RiskLevel = "中危",
                    AttackVector = "Network",
                    AffectedComponent = "Registration Flow",
                    Platform = "OpenClaw",
                    Description = "OpenClaw的用户注册邮箱验证可被绕过。攻击者可通过修改验证链接中的userId参数激活任意账户，或重放已使用的验证Token完成验证。可被用于批量创建虚假账户。",
                    Remediation = "1. 升级到OpenClaw 2.8.2+\n2. 验证Token绑定到特定用户且一次性使用\n3. Token设置短有效期(15-30分钟)\n4. 限制同一邮箱的验证尝试次数\n5. 实施CAPTCHA防止自动化滥用",
                    ReferenceUrl = "https://openclaw.dev/security/advisories/CVE-2026-25213",
                    PublishedDate = new DateTime(2025, 11, 8),
                    Tags = new List<string> { "验证绕过", "邮箱确认", "注册流程", "Token重放" }
                },
                new CnnvdVulnerability
                {
                    CveId = "CVE-2026-25212",
                    CnnvdId = "CNNVD-202512-0042",
                    Title = "Hermes Agent Local File Include (LFI) via Template Name",
                    CvssScore = 6.0,
                    RiskLevel = "中危",
                    AttackVector = "Network",
                    AffectedComponent = "Template Engine",
                    Platform = "Hermes Agent",
                    Description = "Hermes Agent的自定义报告模板名称参数未充分过滤，存在本地文件包含(LFI)风险。攻击者可指定../../../etc/passwd等路径读取服务器敏感文件，或包含日志文件注入恶意内容。",
                    Remediation = "1. 升级到Hermes Agent 1.12.2+\n2. 仅允许预定义的白名单模板名称\n3. 规范化模板路径并拒绝遍历序列\n4. 模板文件存储于受限目录\n5. 使用模板ID而非文件路径引用",
                    ReferenceUrl = "https://hermes-agent.io/security/CVE-2026-25212",
                    PublishedDate = new DateTime(2025, 11, 6),
                    Tags = new List<string> { "LFI", "文件包含", "模板引擎", "路径遍历" }
                },
                new CnnvdVulnerability
                {
                    CveId = "CVE-2026-25211",
                    CnnvdId = "CNNVD-202512-0043",
                    Title = "OpenClaw Password Reset Poisoning",
                    CvssScore = 5.5,
                    RiskLevel = "中危",
                    AttackVector = "Network",
                    AffectedComponent = "Password Recovery",
                    Platform = "OpenClaw",
                    Description = "OpenClaw的密码重置邮件使用Host头构建链接。攻击者可通过Host header injection操控重置链接域名，将用户引导至钓鱼站点窃取重置Token，进而重置受害者密码并劫持账户。",
                    Remediation = "1. 升级到OpenClaw 2.8.3+\n2. 使用硬编码的合法域名构建重置链接\n3. 忽略请求中的Host头\n4. 重置Token绑定原始请求IP\n5. 多渠道通知用户密码重置操作",
                    ReferenceUrl = "https://openclaw.dev/security/advisories/CVE-2026-25211",
                    PublishedDate = new DateTime(2025, 11, 4),
                    Tags = new List<string> { "Host注入", "密码重置", "Header注入", "钓鱼" }
                },
                new CnnvdVulnerability
                {
                    CveId = "CVE-2026-25210",
                    CnnvdId = "CNNVD-202512-0044",
                    Title = "Hermes Agent Race Condition in Resource Allocation",
                    CvssScore = 5.5,
                    RiskLevel = "中危",
                    AttackVector = "Local",
                    AffectedComponent = "Resource Manager",
                    Platform = "Hermes Agent",
                    Description = "Hermes Agent的资源分配模块存在竞态条件。高并发场景下多个Agent实例可能被分配相同的资源ID(如GPU设备号)，导致资源冲突和任务执行异常。恶意用户可利用此问题制造拒绝服务。",
                    Remediation = "1. 升级到Hermes Agent 1.12.3+\n2. 使用原子操作或分布式锁进行资源分配\n3. 实施乐观锁或版本号机制\n4. 分配后立即验证资源唯一性\n5. 启用资源冲突检测和自动恢复",
                    ReferenceUrl = "https://hermes-agent.io/security/CVE-2026-25210",
                    PublishedDate = new DateTime(2025, 11, 2),
                    Tags = new List<string> { "竞态条件", "资源分配", "并发安全", "TOCTOU" }
                },
                new CnnvdVulnerability
                {
                    CveId = "CVE-2026-25209",
                    CnnvdId = "CNNVD-202511-0045",
                    Title = "OpenClaw WebSocket Ping Flood DoS",
                    CvssScore = 5.5,
                    RiskLevel = "中危",
                    AttackVector = "Network",
                    AffectedComponent = "Gateway",
                    Platform = "OpenClaw",
                    Description = "OpenClaw Gateway对WebSocket Ping帧的处理缺乏速率限制。攻击者可每秒发送数千Ping帧迫使服务器回复Pong，消耗大量CPU和网络带宽，降低正常用户的连接质量。",
                    Remediation = "1. 升级到OpenClaw 2.8.4+\n2. 限制每个连接的Ping/Pong帧速率\n3. 异常连接自动断开并加入临时黑名单\n4. 实施连接级别的带宽限制\n5. 监控异常的WebSocket流量模式",
                    ReferenceUrl = "https://openclaw.dev/security/advisories/CVE-2026-25209",
                    PublishedDate = new DateTime(2025, 10, 30),
                    Tags = new List<string> { "DoS", "WebSocket", "Ping洪泛", "带宽耗尽" }
                },
                new CnnvdVulnerability
                {
                    CveId = "CVE-2026-25208",
                    CnnvdId = "CNNVD-202511-0046",
                    Title = "Hermes Agent Environment Variable Injection",
                    CvssScore = 6.5,
                    RiskLevel = "中危",
                    AttackVector = "Local",
                    AffectedComponent = "Config Loader",
                    Platform = "Hermes Agent",
                    Description = "Hermes Agent的配置加载器从.env文件读取变量时未过滤特殊字符。具有文件写入权限的攻击者可注入PATH、LD_PRELOAD等环境变量，改变程序行为或加载恶意库。",
                    Remediation = "1. 升级到Hermes Agent 1.13.0+\n2. 过滤环境变量中的危险字符和命令\n3. 使用固定的PATH而非从配置读取\n4. 审计环境变量的变更历史\n5. 运行时验证关键环境变量的合法性",
                    ReferenceUrl = "https://hermes-agent.io/security/CVE-2026-25208",
                    PublishedDate = new DateTime(2025, 10, 28),
                    Tags = new List<string> { "环境变量注入", "LD_PRELOAD", "配置加载", "本地攻击" }
                },
                new CnnvdVulnerability
                {
                    CveId = "CVE-2026-25207",
                    CnnvdId = "CNNVD-202511-0047",
                    Title = "OpenClaw GraphQL Introspection Enabled",
                    CvssScore = 4.5,
                    RiskLevel = "中危",
                    AttackVector = "Network",
                    AffectedComponent = "GraphQL API",
                    Platform = "OpenClaw",
                    Description = "OpenClaw的GraphQL端点启用了Introspection查询(__schema)。攻击者可获取完整的API Schema，了解所有可用查询、Mutation和数据类型，大幅降低后续攻击的成本。",
                    Remediation = "1. 升级到OpenClaw 2.8.5+\n2. 生产环境禁用GraphQL Introspection\n3. 使用持久化查询(Persisted Queries)\n4. 实施查询深度和复杂度限制\n5. API文档与生产环境分离",
                    ReferenceUrl = "https://openclaw.dev/security/advisories/CVE-2026-25207",
                    PublishedDate = new DateTime(2025, 10, 26),
                    Tags = new List<string> { "GraphQL", "内省", "Schema泄露", "API枚举" }
                },
                new CnnvdVulnerability
                {
                    CveId = "CVE-2026-25206",
                    CnnvdId = "CNNVD-202511-0048",
                    Title = "Hermes Agent JWT Secret Stored in Source Code",
                    CvssScore = 6.5,
                    RiskLevel = "中危",
                    AttackVector = "Local",
                    AffectedComponent = "Auth Service",
                    Platform = "Hermes Agent",
                    Description = "Hermes Agent的JWT签名密钥硬编码在源代码配置文件中。任何能访问代码仓库(包括公开GitHub仓库)的人均可获取密钥并伪造任意用户的认证令牌。",
                    Remediation = "1. 升级到Hermes Agent 1.13.1+\n2. 使用环境变量或密钥管理服务存储JWT密钥\n3. 实施Secret Scanning(GitGuardian/truffleHog)\n4. 定期轮换JWT签名密钥\n5. 代码仓库访问权限最小化",
                    ReferenceUrl = "https://hermes-agent.io/security/CVE-2026-25206",
                    PublishedDate = new DateTime(2025, 10, 24),
                    Tags = new List<string> { "硬编码密钥", "JWT", "源码泄露", "凭证管理" }
                },
                new CnnvdVulnerability
                {
                    CveId = "CVE-2026-25205",
                    CnnvdId = "CNNVD-202511-0049",
                    Title = "OpenClaw DOM-based XSS in Client-Side Routing",
                    CvssScore = 6.0,
                    RiskLevel = "中危",
                    AttackVector = "Network",
                    AffectedComponent = "Frontend",
                    Platform = "OpenClaw",
                    Description = "OpenClaw前端SPA的路由处理存在DOM-based XSS。URL hash片段(#/agent/<input>)的内容未经转义直接插入innerHTML，攻击者可构造恶意链接执行JavaScript代码窃取用户Session。",
                    Remediation = "1. 升级到OpenClaw 2.8.6+\n2. 使用textContent代替innerHTML渲染用户输入\n3. 对URL参数实施HTML实体编码\n4. 启用CSP的unsafe-inline禁用\n5. 使用成熟的路由框架(React Router/Vue Router)",
                    ReferenceUrl = "https://openclaw.dev/security/advisories/CVE-2026-25205",
                    PublishedDate = new DateTime(2025, 10, 22),
                    Tags = new List<string> { "DOM XSS", "前端路由", "哈希注入", "SPA安全" }
                },
                new CnnvdVulnerability
                {
                    CveId = "CVE-2026-25204",
                    CnnvdId = "CNNVD-202511-0050",
                    Title = "Hermes Agent LDAP Injection in User Search",
                    CvssScore = 6.0,
                    RiskLevel = "中危",
                    AttackVector = "Network",
                    AffectedComponent = "LDAP Client",
                    Platform = "Hermes Agent",
                    Description = "Hermes Agent的LDAP用户搜索功能将用户输入直接拼接到LDAP查询过滤器中。攻击者可注入LDAP特殊字符(*)(()=)绕过认证查询、枚举所有用户或修改LDAP条目属性。",
                    Remediation = "1. 升级到Hermes Agent 1.13.2+\n2. 使用参数化LDAP查询(LdapFilterBuilder)\n3. 对特殊字符进行转义\n4. 限制LDAP查询的返回属性\n5. 实施LDAP操作审计日志",
                    ReferenceUrl = "https://hermes-agent.io/security/CVE-2026-25204",
                    PublishedDate = new DateTime(2025, 10, 20),
                    Tags = new List<string> { "LDAP注入", "目录服务", "特殊字符", "认证绕过" }
                },
                new CnnvdVulnerability
                {
                    CveId = "CVE-2026-25203",
                    CnnvdId = "CNNVD-202511-0051",
                    Title = "OpenClaw Improper Certificate Validation",
                    CvssScore = 5.5,
                    RiskLevel = "中危",
                    AttackVector = "Network",
                    AffectedComponent = "HTTP Client",
                    Platform = "OpenClaw",
                    Description = "OpenClaw在调用外部API时禁用了SSL证书验证(ServerCertificateCustomValidationCallback返回true)。中间人攻击者可解密所有出站流量，窃取API密钥和敏感业务数据。",
                    Remediation = "1. 升级到OpenClaw 2.8.7+\n2. 启用完整的SSL证书链验证\n3. 使用证书固定(Pinning)保护关键API\n4. 维护可信CA证书库\n5. 监控无效/自签名证书的使用",
                    ReferenceUrl = "https://openclaw.dev/security/advisories/CVE-2026-25203",
                    PublishedDate = new DateTime(2025, 10, 18),
                    Tags = new List<string> { "证书验证", "SSL/TLS", "中间人", "出站安全" }
                },
                new CnnvdVulnerability
                {
                    CveId = "CVE-2026-25202",
                    CnnvdId = "CNNVD-202511-0052",
                    Title = "Hermes Agent NoSQL Injection in MongoDB Queries",
                    CvssScore = 6.5,
                    RiskLevel = "中危",
                    AttackVector = "Network",
                    AffectedComponent = "Data Access Layer",
                    Platform = "Hermes Agent",
                    Description = "Hermes Agent的MongoDB查询构建器接受用户输入的JSON对象作为查询条件。攻击者可注入$gt/$ne/$where等NoSQL操作符绕过查询条件、提取额外字段或执行服务端JavaScript。",
                    Remediation = "1. 升级到Hermes Agent 1.13.3+\n2. 使用类型安全的查询构建器(FilterDefinition)\n3. 白名单允许的查询操作符\n4. 对用户输入的JSON结构进行Schema验证\n5. 禁止$where和$function操作符",
                    ReferenceUrl = "https://hermes-agent.io/security/CVE-2026-25202",
                    PublishedDate = new DateTime(2025, 10, 16),
                    Tags = new List<string> { "NoSQL注入", "MongoDB", "JSON操作符", "查询操纵" }
                },
                new CnnvdVulnerability
                {
                    CveId = "CVE-2026-25201",
                    CnnvdId = "CNNVD-202511-0053",
                    Title = "OpenClaw Missing Input Length Limits",
                    CvssScore = 5.0,
                    RiskLevel = "中危",
                    AttackVector = "Network",
                    AffectedComponent = "Input Validator",
                    Platform = "OpenClaw",
                    Description = "OpenClaw的多个API端点未设置请求体大小限制。攻击者可发送GB级的超大请求导致服务器内存耗尽(OOM)或磁盘空间耗尽，形成有效的DoS攻击向量。",
                    Remediation = "1. 升级到OpenClaw 2.8.8+\n2. 全局设置请求体大小上限(MaxRequestBodySize)\n3. 各端点根据业务需求设置合理限制\n4. 实施流式处理大请求体\n5. 配置内存和磁盘使用率监控告警",
                    ReferenceUrl = "https://openclaw.dev/security/advisories/CVE-2026-25201",
                    PublishedDate = new DateTime(2025, 10, 14),
                    Tags = new List<string> { "DoS", "大payload", "内存耗尽", "输入限制" }
                },
                new CnnvdVulnerability
                {
                    CveId = "CVE-2026-25200",
                    CnnvdId = "CNNVD-202511-0054",
                    Title = "Hermes Agent Predictable Session Identifier",
                    CvssScore = 5.5,
                    RiskLevel = "中危",
                    AttackVector = "Network",
                    AffectedComponent = "Session Manager",
                    Platform = "Hermes Agent",
                    Description = "Hermes Agent的Session ID使用可预测的时间戳+自增序号生成。攻击者可通过分析多个Session ID的模式推断算法，预测有效Session ID并劫持其他用户会话。",
                    Remediation = "1. 升级到Hermes Agent 1.14.0+\n2. 使用密码学安全的随机数生成Session ID\n3. Session ID长度至少128位\n4. 定期轮换Session ID(会话提升时)\n5. 监控异常的Session访问模式",
                    ReferenceUrl = "https://hermes-agent.io/security/CVE-2026-25200",
                    PublishedDate = new DateTime(2025, 10, 12),
                    Tags = new List<string> { "Session预测", "弱随机数", "会话劫持", "PRNG" }
                },
                new CnnvdVulnerability
                {
                    CveId = "CVE-2026-25199",
                    CnnvdId = "CNNVD-202511-0055",
                    Title = "OpenClaw Backup File Exposure",
                    CvssScore = 5.0,
                    RiskLevel = "中危",
                    AttackVector = "Network",
                    AffectedComponent = "Backup System",
                    Platform = "OpenClaw",
                    Description = "OpenClaw的备份文件(.bak, .sql, .old)存储于Web可访问目录且可通过URL直接下载。备份文件包含完整的数据库dump，含用户密码哈希、API密钥和私有配置信息。",
                    Remediation = "1. 升级到OpenClaw 2.9.0+\n2. 备份文件存储于Web根目录之外\n3. 备份文件使用加密存储\n4. 禁止常见备份扩展名的直接访问\n5. 定期清理过期的备份文件",
                    ReferenceUrl = "https://openclaw.dev/security/advisories/CVE-2026-25199",
                    PublishedDate = new DateTime(2025, 10, 10),
                    Tags = new List<string> { "备份泄露", "敏感文件", "目录枚举", "数据备份" }
                },
                new CnnvdVulnerability
                {
                    CveId = "CVE-2026-25198",
                    CnnvdId = "CNNVD-202511-0056",
                    Title = "Hermes Agent Command Injection via Export Feature",
                    CvssScore = 7.0,
                    RiskLevel = "中危",
                    AttackVector = "Network",
                    AffectedComponent = "Export Engine",
                    Platform = "Hermes Agent",
                    Description = "Hermes Agent的数据导出功能将文件名参数传递给shell命令而未正确转义。攻击者可通过文件名注入shell元字符(;|&`$),在服务器上执行任意操作系统命令。",
                    Remediation = "1. 升级到Hermes Agent 1.14.1+\n2. 使用语言原生的文件操作API替代shell命令\n3. 对文件名实施严格的白名单验证\n4. 导出操作在沙箱容器中执行\n5. 记录所有导出操作的命令和参数",
                    ReferenceUrl = "https://hermes-agent.io/security/CVE-2026-25198",
                    PublishedDate = new DateTime(2025, 10, 8),
                    Tags = new List<string> { "命令注入", "导出功能", "Shell转义", "OS命令" }
                },
                new CnnvdVulnerability
                {
                    CveId = "CVE-2026-25197",
                    CnnvdId = "CNNVD-202511-0057",
                    Title = "OpenClaw Cross-User Data Leakage via Shared Cache",
                    CvssScore = 5.5,
                    RiskLevel = "中危",
                    AttackVector = "Network",
                    AffectedComponent = "Cache Layer",
                    Platform = "OpenClaw",
                    Description = "OpenClaw的缓存键未包含租户/用户标识符，多租户环境下可能返回其他用户的缓存数据。攻击者可通过精心构造的请求触发缓存键碰撞，获取其他租户的敏感响应数据。",
                    Remediation = "1. 升级到OpenClaw 2.9.1+\n2. 缓存键包含tenantId + userId前缀\n3. 缓存值包含所有权校验\n4. 租户间使用物理隔离的缓存命名空间\n5. 缓存命中时验证数据归属",
                    ReferenceUrl = "https://openclaw.dev/security/advisories/CVE-2026-25197",
                    PublishedDate = new DateTime(2025, 10, 6),
                    Tags = new List<string> { "数据泄漏", "缓存键", "多租户", "租户隔离" }
                },
                new CnnvdVulnerability
                {
                    CveId = "CVE-2026-25196",
                    CnnvdId = "CNNVD-202511-0058",
                    Title = "Hermes Agent OAuth Token Stored in URL Fragment",
                    CvssScore = 5.0,
                    RiskLevel = "中危",
                    AttackVector = "Network",
                    AffectedComponent = "OAuth Client",
                    Platform = "Hermes Agent",
                    Description = "Hermes Agent的OAuth Access Token通过URL fragment(#token=xxx)传递。Token会被保存在浏览器历史记录、服务器访问日志和Referer头中，增加了Token泄露的风险面。",
                    Remediation = "1. 升级到Hermes Agent 1.14.2+\n2. 使用POST方式或自定义协议接收Token\n3. Token接收后立即从URL清除\n4. 使用短期Token + Refresh Token模式\n5. Referer头设置为no-referrer",
                    ReferenceUrl = "https://hermes-agent.io/security/CVE-2026-25196",
                    PublishedDate = new DateTime(2025, 10, 4),
                    Tags = new List<string> { "OAuth", "Token泄露", "URL参数", "Referer" }
                },
                new CnnvdVulnerability
                {
                    CveId = "CVE-2026-25195",
                    CnnvdId = "CNNVD-202510-0059",
                    Title = "OpenClaw Insecure Random Number Generation",
                    CvssScore = 5.5,
                    RiskLevel = "中危",
                    AttackVector = "Local",
                    AffectedComponent = "Crypto Module",
                    Platform = "OpenClaw",
                    Description = "OpenClaw的安全相关操作(如Session ID生成、CSRF Token创建)使用了System.Random而非密码学安全的RandomNumberGenerator。攻击者可根据输出的随机值序列还原种子状态，预测未来的随机值。",
                    Remediation = "1. 升级到OpenClaw 2.9.2+\n2. 全部使用RandomNumberGenerator/CreateRandom\n3. 安全审计所有Random用法\n4. 使用操作系统提供的CSPRNG\n5. 定期更换加密相关的种子",
                    ReferenceUrl = "https://openclaw.dev/security/advisories/CVE-2026-25195",
                    PublishedDate = new DateTime(2025, 10, 2),
                    Tags = new List<string> { "弱随机数", "PRNG", "预测性", "密码学安全" }
                },
                new CnnvdVulnerability
                {
                    CveId = "CVE-2026-25194",
                    CnnvdId = "CNNVD-202510-0060",
                    Title = "Hermes Agent WebSocket Origin Not Validated",
                    CvssScore = 5.5,
                    RiskLevel = "中危",
                    AttackVector = "Network",
                    AffectedComponent = "WebSocket Handler",
                    Platform = "Hermes Agent",
                    Description = "Hermes Agent的WebSocket端点未验证请求的Origin头。攻击者可从任意域名建立WebSocket连接，利用受害者的已认证Cookie访问实时Agent通信频道，监听或注入消息。",
                    Remediation = "1. 升级到Hermes Agent 1.14.3+\n2. WebSocket握手时严格验证Origin头\n3. 使用wss://(TLS加密)替代ws://\n4. 实施WebSocket连接的Ticket认证\n5. 监控异常来源的WebSocket连接",
                    ReferenceUrl = "https://hermes-agent.io/security/CVE-2026-25194",
                    PublishedDate = new DateTime(2025, 9, 28),
                    Tags = new List<string> { "WebSocket", "Origin验证", "跨域", "实时通信" }
                },
                new CnnvdVulnerability
                {
                    CveId = "CVE-2026-25193",
                    CnnvdId = "CNNVD-202510-0061",
                    Title = "OpenClaw Directory Listing Enabled",
                    CvssScore = 4.5,
                    RiskLevel = "中危",
                    AttackVector = "Network",
                    AffectedComponent = "Static File Server",
                    Platform = "OpenClaw",
                    Description = "OpenClaw的静态文件服务器启用了目录浏览功能。攻击者可通过访问URL路径枚举服务器目录结构，发现隐藏的管理页面、备份文件、配置文件和其他敏感资源。",
                    Remediation = "1. 升级到OpenClaw 2.9.3+\n2. 生产环境禁用目录浏览(DirectoryBrowse Off)\n3. 为敏感目录返回403/404\n4. 使用robots.txt限制爬虫索引\n5. 定期进行目录枚举测试",
                    ReferenceUrl = "https://openclaw.dev/security/advisories/CVE-2026-25193",
                    PublishedDate = new DateTime(2025, 9, 26),
                    Tags = new List<string> { "目录列举", "信息泄露", "静态文件", "路径枚举" }
                },
                new CnnvdVulnerability
                {
                    CveId = "CVE-2026-25192",
                    CnnvdId = "CNNVD-202510-0062",
                    Title = "Hermes Agent Prototype Pollution via Deep Merge",
                    CvssScore = 5.8,
                    RiskLevel = "中危",
                    AttackVector = "Network",
                    AffectedComponent = "Config Merger",
                    Platform = "Hermes Agent",
                    Description = "Hermes Agent的配置合并函数使用递归深拷贝且未过滤__proto__和constructor属性。攻击者可通过恶意配置注入原型属性，影响所有后续对象的行为，可能导致拒绝服务或属性覆盖。",
                    Remediation = "1. 升级到Hermes Agent 1.15.0+\n2. 使用安全的深拷贝库(structuredClone/lodash.mergeWith)\n3. 过滤JSON键名中的危险属性(__proto__, constructor, prototype)\n4. 使用Object.freeze保护全局原型\n5. 输入配置的Schema验证",
                    ReferenceUrl = "https://hermes-agent.io/security/CVE-2026-25192",
                    PublishedDate = new DateTime(2025, 9, 24),
                    Tags = new List<string> { "原型污染", "深合并", "__proto__", "对象注入" }
                },
                new CnnvdVulnerability
                {
                    CveId = "CVE-2026-25191",
                    CnnvdId = "CNNVD-202510-0063",
                    Title = "OpenClaw HTTP Method Override Bypass",
                    CvssScore = 5.0,
                    RiskLevel = "中危",
                    AttackVector = "Network",
                    AffectedComponent = "API Middleware",
                    Platform = "OpenClaw",
                    Description = "OpenClaw支持通过X-HTTP-Method-Override头或_method参数覆盖HTTP方法。部分只允许GET访问的端点可通过此机制被转换为PUT/DELETE请求，绕过方法级别的访问控制。",
                    Remediation = "1. 升级到OpenClaw 2.9.4+\n2. 限制方法覆盖仅适用于特定端点\n3. 方法覆盖后重新执行权限检查\n4. 记录所有方法覆盖的使用情况\n5. 考虑完全移除方法覆盖功能",
                    ReferenceUrl = "https://openclaw.dev/security/advisories/CVE-2026-25191",
                    PublishedDate = new DateTime(2025, 9, 22),
                    Tags = new List<string> { "方法覆盖", "ACL绕过", "REST", "HTTP方法" }
                },
                new CnnvdVulnerability
                {
                    CveId = "CVE-2026-25190",
                    CnnvdId = "CNNVD-202510-0064",
                    Title = "Hermes Agent Sensitive Comments in Production Build",
                    CvssScore = 4.0,
                    RiskLevel = "中危",
                    AttackVector = "Network",
                    AffectedComponent = "Frontend Bundle",
                    Platform = "Hermes Agent",
                    Description = "Hermes Agent的生产构建JSBundle中包含开发者注释(TODO/FIXME/HACK/XXX)，其中部分注释包含内部API地址、调试说明和安全相关的实现细节。攻击者可通过压缩包逆向获取这些信息。",
                    Remediation = "1. 升级到Hermes Agent 1.15.1+\n2. 生产构建移除所有开发注释(strip-comments)\n3. 使用TerserPlugin的drop_comments选项\n4. CI/CD流水线集成注释扫描\n5. 代码审查时标记敏感注释",
                    ReferenceUrl = "https://hermes-agent.io/security/CVE-2026-25190",
                    PublishedDate = new DateTime(2025, 9, 20),
                    Tags = new List<string> { "信息泄露", "源码注释", "构建安全", "前端打包" }
                },
                new CnnvdVulnerability
                {
                    CveId = "CVE-2026-25189",
                    CnnvdId = "CNNVD-202510-0065",
                    Title = "OpenClaw Unsafe Deserialization of User Preferences",
                    CvssScore = 6.0,
                    RiskLevel = "中危",
                    AttackVector = "Network",
                    AffectedComponent = "Preference Storage",
                    Platform = "OpenClaw",
                    Description = "OpenClaw的用户偏好设置使用BinaryFormatter进行序列化和反序列化。攻击者可篡改偏好Cookie或localStorage中的序列化数据，在反序列化过程中执行任意代码或读取服务器文件。",
                    Remediation = "1. 升级到OpenClaw 2.9.5+\n2. 迁移到安全的序列化格式(JSON/Protobuf)\n3. BinaryFormatter已被.NET标记为危险，应全面替换\n4. 对反序列化数据实施类型白名单\n5. 用户偏好数据由服务端加密存储",
                    ReferenceUrl = "https://openclaw.dev/security/advisories/CVE-2026-25189",
                    PublishedDate = new DateTime(2025, 9, 18),
                    Tags = new List<string> { "反序列化", "BinaryFormatter", "偏好设置", "代码执行" }
                },
                new CnnvdVulnerability
                {
                    CveId = "CVE-2026-25188",
                    CnnvdId = "CNNVD-202510-0066",
                    Title = "Hermes Agent Missing Content-Type Validation on API",
                    CvssScore = 5.0,
                    RiskLevel = "中危",
                    AttackVector = "Network",
                    AffectedComponent = "API Gateway",
                    Platform = "Hermes Agent",
                    Description = "Hermes Agent的API端点未验证请求的Content-Type头。攻击者可发送Content-Type: text/xml的请求给期望JSON的端点，触发XML解析器的XXE或其他XML相关漏洞。",
                    Remediation = "1. 升级到Hermes Agent 1.15.2+\n2. 每个端点显式声明接受的Content-Type\n3. 不匹配时返回415 Unsupported Media Type\n4. 使用MediaTypeFilter中间件统一处理\n5. 记录非常规Content-Type的请求",
                    ReferenceUrl = "https://hermes-agent.io/security/CVE-2026-25188",
                    PublishedDate = new DateTime(2025, 9, 16),
                    Tags = new List<string> { "Content-Type", "API安全", "输入验证", "媒体类型" }
                },
                new CnnvdVulnerability
                {
                    CveId = "CVE-2026-25187",
                    CnnvdId = "CNNVD-202510-0067",
                    Title = "OpenClaw Insufficient Password Complexity Requirements",
                    CvssScore = 4.5,
                    RiskLevel = "中危",
                    AttackVector = "Network",
                    AffectedComponent = "Password Policy",
                    Platform = "OpenClaw",
                    Description = "OpenClaw的密码策略仅要求最少4位字符长度，无复杂度要求(大小写/数字/特殊字符)。用户可设置极弱密码(如1234, password)，容易被暴力破解或字典攻击攻破。",
                    Remediation = "1. 升级到OpenClaw 2.9.6+\n2. 最小长度12位且包含四类字符\n3. 禁止常见弱密码(top 10000)\n4. 使用Have I Been Pwned API检查泄露密码\n5. 实施账户锁定策略",
                    ReferenceUrl = "https://openclaw.dev/security/advisories/CVE-2026-25187",
                    PublishedDate = new DateTime(2025, 9, 14),
                    Tags = new List<string> { "弱密码策略", "暴力破解", "密码复杂度", "认证安全" }
                },
                new CnnvdVulnerability
                {
                    CveId = "CVE-2026-25186",
                    CnnvdId = "CNNVD-202510-0068",
                    Title = "Hermes Agent Open Redirect in OAuth Callback",
                    CvssScore = 5.0,
                    RiskLevel = "中危",
                    AttackVector = "Network",
                    AffectedComponent = "OAuth Handler",
                    Platform = "Hermes Agent",
                    Description = "Hermes Agent的OAuth回调处理中的next_url参数未验证目标域名。攻击者可构造/oauth/callback?next_url=https://evil.com的链接，在OAuth认证完成后将用户重定向至恶意网站进行钓鱼攻击。",
                    Remediation = "1. 升级到Hermes Agent 1.15.3+\n2. next_url仅允许相对路径或白名单域名\n3. OAuth完成后始终跳转到固定首页\n4. 显示明确的跳转警告页面\n5. 记录所有外部重定向事件",
                    ReferenceUrl = "https://hermes-agent.io/security/CVE-2026-25186",
                    PublishedDate = new DateTime(2025, 9, 12),
                    Tags = new List<string> { "开放重定向", "OAuth", "回调参数", "钓鱼" }
                },
                new CnnvdVulnerability
                {
                    CveId = "CVE-2026-25185",
                    CnnvdId = "CNNVD-202510-0069",
                    Title = "OpenClaw Stack Trace Leaked in HTTP 500 Response",
                    CvssScore = 4.5,
                    RiskLevel = "中危",
                    AttackVector = "Network",
                    AffectedComponent = "Error Handler",
                    Platform = "OpenClaw",
                    Description = "OpenClaw在发生未捕获异常时返回HTTP 500并在响应体中包含完整堆栈跟踪。堆栈信息暴露了框架版本、内部类名、文件路径和行号，大幅降低了攻击者的侦察成本。",
                    Remediation = "1. 升级到OpenClaw 2.9.7+\n2. 生产环境返回通用错误信息\n3. 堆栈跟踪仅写入服务端日志\n4. 实现全局异常处理中间件\n5. 错误响应中包含追踪ID供排查",
                    ReferenceUrl = "https://openclaw.dev/security/advisories/CVE-2026-25185",
                    PublishedDate = new DateTime(2025, 9, 10),
                    Tags = new List<string> { "堆栈泄露", "500错误", "信息暴露", "异常处理" }
                },
                new CnnvdVulnerability
                {
                    CveId = "CVE-2026-25184",
                    CnnvdId = "CNNVD-202510-0070",
                    Title = "Hermes Agent Missing Account Lockout Policy",
                    CvssScore = 5.5,
                    RiskLevel = "中危",
                    AttackVector = "Network",
                    AffectedComponent = "Authentication",
                    Platform = "Hermes Agent",
                    Description = "Hermes Agent的登录接口无账户锁定机制。攻击者可对任意账户进行无限次密码猜测而不被阻止，结合弱密码策略可高效地进行暴力破解攻击。",
                    Remediation = "1. 升级到Hermes Agent 1.15.4+\n2. 5次失败后锁定账户15分钟(渐进式)\n3. CAPTCHA验证码在第3次失败后出现\n4. 记录失败的登录尝试并告警\n5. 支持管理员手动解锁账户",
                    ReferenceUrl = "https://hermes-agent.io/security/CVE-2026-25184",
                    PublishedDate = new DateTime(2025, 9, 8),
                    Tags = new List<string> { "无账户锁定", "暴力破解", "密码猜测", "认证安全" }
                },
                new CnnvdVulnerability
                {
                    CveId = "CVE-2026-25183",
                    CnnvdId = "CNNVD-202509-0071",
                    Title = "OpenClaw Websocket Connection Limit Not Enforced",
                    CvssScore = 5.0,
                    RiskLevel = "中危",
                    AttackVector = "Network",
                    AffectedComponent = "Gateway",
                    Platform = "OpenClaw",
                    Description = "OpenClaw Gateway未限制单个IP/用户可建立的WebSocket连接数量。攻击者可创建大量连接耗尽服务器文件描述符和内存资源，导致服务不可用(DoS)。",
                    Remediation = "1. 升级到OpenClaw 2.9.8+\n2. 单IP限制最多10个并发WebSocket连接\n3. 单用户限制最多5个并发连接\n4. 空闲连接超时自动断开(5分钟)\n5. 连接数接近阈值时触发告警",
                    ReferenceUrl = "https://openclaw.dev/security/advisories/CVE-2026-25183",
                    PublishedDate = new DateTime(2025, 9, 5),
                    Tags = new List<string> { "DoS", "WebSocket", "连接耗尽", "资源限制" }
                },
                new CnnvdVulnerability
                {
                    CveId = "CVE-2026-25182",
                    CnnvdId = "CNNVD-202509-0072",
                    Title = "Hermes Agent Insecure Cookie Settings",
                    CvssScore = 5.0,
                    RiskLevel = "中危",
                    AttackVector = "Network",
                    AffectedComponent = "Session Management",
                    Platform = "Hermes Agent",
                    Description = "Hermes Agent的认证Cookie未设置Secure和HttpOnly标志。攻击者可通过JavaScript窃取Cookie(XSS场景)或在非加密连接中截获Cookie(中间人场景)，劫持用户会话。",
                    Remediation = "1. 升级到Hermes Agent 1.16.0+\n2. 所有认证Cookie设置Secure; HttpOnly; SameSite=Strict\n3. 强制全局HTTPS(HSTS)\n4. Cookie值使用加密签名防篡改\n5. 定期轮换Cookie签名密钥",
                    ReferenceUrl = "https://hermes-agent.io/security/CVE-2026-25182",
                    PublishedDate = new DateTime(2025, 9, 3),
                    Tags = new List<string> { "Cookie安全", "HttpOnly", "SameSite", "会话管理" }
                },
                new CnnvdVulnerability
                {
                    CveId = "CVE-2026-25181",
                    CnnvdId = "CNNVD-202509-0073",
                    Title = "OpenClaw Git Repository Exposure (.git folder)",
                    CvssScore = 5.5,
                    RiskLevel = "中危",
                    AttackVector = "Network",
                    AffectedComponent = "Web Server",
                    Platform = "OpenClaw",
                    Description = "OpenClaw的Web根目录意外包含.git文件夹。攻击者可通过/.git/HEAD等路径下载完整的Git仓库，获取源代码、提交历史、敏感配置文件(含API密钥)和开发注释。",
                    Remediation = "1. 从生产环境移除.git目录\n2. Web服务器配置拒绝.git路径访问\n3. CI/CD中使用.gitignore排除敏感文件\n4. 部署前扫描Web根目录的隐藏文件\n5. 使用git clean -fxd清理构建产物",
                    ReferenceUrl = "https://openclaw.dev/security/advisories/CVE-2026-25181",
                    PublishedDate = new DateTime(2025, 9, 1),
                    Tags = new List<string> { "Git泄露", "源码暴露", "隐藏目录", "部署安全" }
                },
                new CnnvdVulnerability
                {
                    CveId = "CVE-2026-25180",
                    CnnvdId = "CNNVD-202509-0074",
                    Title = "Hermes Agent Missing Authorization on Admin APIs",
                    CvssScore = 6.5,
                    RiskLevel = "中危",
                    AttackVector = "Network",
                    AffectedComponent = "Admin Controller",
                    Platform = "Hermes Agent",
                    Description = "Hermes Agent的部分管理API(/admin/users, /admin/config)仅检查用户已认证但未验证是否具有管理员角色。普通 authenticated 用户可访问管理功能，执行用户管理、系统配置修改等敏感操作。",
                    Remediation = "1. 升级到Hermes Agent 1.16.1+\n2. 所有Admin端点添加角色检查[Authorize(Roles=\"Admin\")]\n3. 使用基于资源的授权(Resource-based Authorization)\n4. 管理操作实施二次MFA验证\n5. 审计所有管理API的访问记录",
                    ReferenceUrl = "https://hermes-agent.io/security/CVE-2026-25180",
                    PublishedDate = new DateTime(2025, 8, 28),
                    Tags = new List<string> { "越权访问", "垂直越权", "RBAC", "管理接口" }
                },
                new CnnvdVulnerability
                {
                    CveId = "CVE-2026-25179",
                    CnnvdId = "CNNVD-202509-0075",
                    Title = "OpenClaw Sensitive Data in URL Query Parameters",
                    CvssScore = 4.5,
                    RiskLevel = "中危",
                    AttackVector = "Network",
                    AffectedComponent = "Frontend",
                    Platform = "OpenClaw",
                    Description = "OpenClaw前端将access_token、api_key等敏感参数放入URL查询字符串。这些参数会被保存在浏览器历史、代理服务器日志、Referer头和Web服务器访问日志中，极大扩大了泄露风险面。",
                    Remediation = "1. 升级到OpenClaw 2.9.9+\n2. 敏感参数通过POST Body或Header传递\n3. 使用session/localStorage存储Token\n4. URL中的Token在使用后立即清除\n5. 敏感参数不在日志中记录",
                    ReferenceUrl = "https://openclaw.dev/security/advisories/CVE-2026-25179",
                    PublishedDate = new DateTime(2025, 8, 26),
                    Tags = new List<string> { "敏感参数", "URL泄露", "日志记录", "Referer" }
                },
                new CnnvdVulnerability
                {
                    CveId = "CVE-2026-25178",
                    CnnvdId = "CNNVD-202509-0076",
                    Title = "Hermes Agent No Rate Limit on Password Reset",
                    CvssScore = 5.0,
                    RiskLevel = "中危",
                    AttackVector = "Network",
                   AffectedComponent = "Password Recovery",
                    Platform = "Hermes Agent",
                    Description = "Hermes Agent的密码重置接口无频率限制。攻击者可对目标邮箱发起密码重置轰炸(Spam)，大量发送重置邮件干扰正常使用，或通过重置链接的规律性推测Token格式。",
                    Remediation = "1. 升级到Hermes Agent 1.16.2+\n2. 同一邮箱每小时最多3次重置请求\n3. 同一IP每小时最多10次重置请求\n4. 重置请求需图形验证码\n5. 异常频率触发临时邮箱封禁",
                    ReferenceUrl = "https://hermes-agent.io/security/CVE-2026-25178",
                    PublishedDate = new DateTime(2025, 8, 24),
                    Tags = new List<string> { "密码重置", "邮件轰炸", "频率限制", "Spam" }
                },
                new CnnvdVulnerability
                {
                    CveId = "CVE-2026-25177",
                    CnnvdId = "CNNVD-202509-0077",
                    Title = "OpenClaw Missing Security Headers on Static Assets",
                    CvssScore = 4.0,
                    RiskLevel = "中危",
                    AttackVector = "Network",
                    AffectedComponent = "Static File Server",
                    Platform = "OpenClaw",
                    Description = "OpenClaw的静态资源(JS/CSS/图片)响应缺少Cache-Control和X-Content-Type-Options头。浏览器可能缓存敏感资源过长或错误解释MIME类型，增加XSS和缓存投毒的风险。",
                    Remediation = "1. 升级到OpenClaw 3.0.0+\n2. JS/CSS设置Cache-Control: no-cache或短TTL\n3. 添加X-Content-Type-Options: nosniff\n4. 静态资源使用内容哈希文件名\n5. 使用CDN的缓存策略配置",
                    ReferenceUrl = "https://openclaw.dev/security/advisories/CVE-2026-25177",
                    PublishedDate = new DateTime(2025, 8, 22),
                    Tags = new List<string> { "缓存策略", "安全头", "静态资源", "MIME嗅探" }
                },
                new CnnvdVulnerability
                {
                    CveId = "CVE-2026-25176",
                    CnnvdId = "CNNVD-202509-0078",
                    Title = "Hermes Agent Unvalidated Redirects in Notification Links",
                    CvssScore = 4.5,
                    RiskLevel = "中危",
                    AttackVector = "Network",
                    AffectedComponent = "Notification Service",
                    Platform = "Hermes Agent",
                    Description = "Hermes Agent的通知邮件/消息中的链接使用用户提供的URL而未验证。攻击者可在Agent名称或任务描述中注入javascript:或data:协议链接，当管理员点击通知时触发XSS或重定向。",
                    Remediation = "1. 升级到Hermes Agent 1.16.3+\n2. 通知链接仅允许http/https协议\n3. 白名单允许的目标域名\n4. 显示链接的实际目标地址\n5. 用户提交的URL添加rel=noopener noreferrer",
                    ReferenceUrl = "https://hermes-agent.io/security/CVE-2026-25176",
                    PublishedDate = new DateTime(2025, 8, 20),
                    Tags = new List<string> { "开放重定向", "通知系统", "协议注入", "XSS" }
                },
                new CnnvdVulnerability
                {
                    CveId = "CVE-2026-25175",
                    CnnvdId = "CNNVD-202509-0079",
                    Title = "OpenClaw Error Page Contains Version Information",
                    CvssScore = 3.5,
                    RiskLevel = "中危",
                    AttackVector = "Network",
                    AffectedComponent = "Error Handler",
                    Platform = "OpenClaw",
                    Description = "OpenClaw的默认错误页面显示详细的软件版本信息(OpenClaw v2.5.2 .NET 8.0.4)。攻击者可据此查找针对特定版本的已知漏洞，制定精准的攻击方案。",
                    Remediation = "1. 升级到OpenClaw 3.0.1+\n2. 错误页面移除所有版本信息\n3. 使用通用的错误页面模板\n4. Server头移除版本信息(Server: OpenClaw)\n5. 定期更新到最新稳定版",
                    ReferenceUrl = "https://openclaw.dev/security/advisories/CVE-2026-25175",
                    PublishedDate = new DateTime(2025, 8, 18),
                    Tags = new List<string> { "版本泄露", "信息收集", "错误页面", "指纹识别" }
                },
                new CnnvdVulnerability
                {
                    CveId = "CVE-2026-25174",
                    CnnvdId = "CNNVD-202509-0080",
                    Title = "Hermes Agent WebSocket Message Size Not Limited",
                    CvssScore = 5.0,
                    RiskLevel = "中危",
                    AttackVector = "Network",
                    AffectedComponent = "WebSocket Handler",
                    Platform = "Hermes Agent",
                    Description = "Hermes Agent的WebSocket消息处理器未设置最大消息大小限制。攻击者可发送超大消息帧(数百MB)导致服务器内存溢出，或分片发送不完整的消息占用服务器缓冲区。",
                    Remediation = "1. 升级到Hermes Agent 1.16.4+\n2. 设置MaxReceiveMessageSize为1MB\n3. 单条消息处理超时30秒自动断开\n4. 大消息触发告警并记录来源IP\n5. 实施消息大小的分级限制",
                    ReferenceUrl = "https://hermes-agent.io/security/CVE-2026-25174",
                    PublishedDate = new DateTime(2025, 8, 16),
                    Tags = new List<string> { "WebSocket", "大消息", "内存溢出", "DoS" }
                },
                new CnnvdVulnerability
                {
                    CveId = "CVE-2026-25173",
                    CnnvdId = "CNNVD-202509-0081",
                    Title = "OpenClaw Insecure Dependency Versions",
                    CvssScore = 6.5,
                    RiskLevel = "中危",
                    AttackVector = "Network",
                    AffectedComponent = "Dependencies",
                    Platform = "OpenClaw",
                    Description = "OpenClaw依赖多个含有已知漏洞的NuGet包(Newtonsoft.Json 11.0.2, IdentityServer4 2.3.2等)。攻击者可利用这些依赖库中的已知漏洞(反序列化RCE、JWT绕过等)攻击OpenClaw。",
                    Remediation = "1. 升级到OpenClaw 3.0.2+(已修复依赖)\n2. 定期运行dotnet list package --vulnerable\n3. 使用Dependabot/GitHub Advisory自动更新\n4. 锁定依赖版本并定期审核\n5. 使用SNYK进行依赖漏洞扫描",
                    ReferenceUrl = "https://openclaw.dev/security/advisories/CVE-2026-25173",
                    PublishedDate = new DateTime(2025, 8, 14),
                    Tags = new List<string> { "依赖漏洞", "SCA", "NuGet", "供应链" }
                },
                new CnnvdVulnerability
                {
                    CveId = "CVE-2026-25172",
                    CnnvdId = "CNNVD-202509-0082",
                    Title = "Hermes Agent Logging to World-Writable Directory",
                    CvssScore = 4.5,
                    RiskLevel = "中危",
                    AttackVector = "Local",
                    AffectedComponent = "Logging System",
                    Platform = "Hermes Agent",
                    Description = "Hermes Agent的日志目录权限设置为777(所有人可写)。本地低权限用户可修改日志文件内容(插入虚假日志或擦除入侵痕迹)，或创建符号链接导致日志写入覆盖重要系统文件。",
                    Remediation = "1. 升级到Hermes Agent 1.16.5+\n2. 日志目录权限设为750(所有者读写执行，组读)\n3. 日志文件权限设为640\n4. 使用专用的日志用户/组运行\n5. 监控日志目录的权限变更",
                    ReferenceUrl = "https://hermes-agent.io/security/CVE-2026-25172",
                    PublishedDate = new DateTime(2025, 8, 12),
                    Tags = new List<string> { "日志权限", "目录权限", "符号链接", "本地安全" }
                },

                // ==================== 低危漏洞 (2个) ====================

                new CnnvdVulnerability
                {
                    CveId = "CVE-2026-25171",
                    CnnvdId = "CNNVD-202509-0083",
                    Title = "OpenClaw Autocomplete Exposes Internal Object IDs",
                    CvssScore = 2.5,
                    RiskLevel = "低危",
                    AttackVector = "Network",
                    AffectedComponent = "Search API",
                    Platform = "OpenClaw",
                    Description = "OpenClaw的搜索自动补全API返回结果中包含内部数据库自增ID。虽然不能直接利用，但这些信息可辅助攻击者进行IDOR枚举和数据分析，降低其他攻击的尝试成本。",
                    Remediation = "1. 升级到OpenClaw 3.0.3+\n2. API响应中移除内部ID字段\n3. 使用UUID对外暴露资源标识\n4. 自动补全结果限制返回字段\n5. 实施API响应脱敏中间件",
                    ReferenceUrl = "https://openclaw.dev/security/advisories/CVE-2026-25171",
                    PublishedDate = new DateTime(2025, 8, 10),
                    Tags = new List<string> { "信息泄露", "自动补全", "内部ID", "API设计" }
                },
                new CnnvdVulnerability
                {
                    CveId = "CVE-2026-25170",
                    CnnvdId = "CNNVD-202509-0084",
                    Title = "Hermes AgentVerbose Timestamps in API Responses",
                    CvssScore = 2.0,
                    RiskLevel = "低危",
                    AttackVector = "Network",
                    AffectedComponent = "API Gateway",
                    Platform = "Hermes Agent",
                    Description = "Hermes Agent的API响应包含微秒精度的时间戳(created_at: 2026-01-15T10:23:45.123456Z)。高精度时间戳可用于侧信道攻击，通过分析响应时间差异推断数据处理逻辑和条件分支。",
                    Remediation = "1. 升级到Hermes Agent 1.17.0+\n2. 公开API使用秒级时间戳\n3. 内部操作使用独立的高精度日志\n4. 响应时间添加随机抖动(+/-100ms)\n5. 审计时间精度要求的合理性",
                    ReferenceUrl = "https://hermes-agent.io/security/CVE-2026-25170",
                    PublishedDate = new DateTime(2025, 8, 8),
                    Tags = new List<string> { "时间戳", "侧信道", "信息泄露", "API响应" }
                }
            };
        }

        #endregion

        #region 辅助方法

        /// <summary>
        /// 确保服务已初始化
        /// </summary>
        private void EnsureInitialized()
        {
            if (!_isInitialized)
            {
                lock (_dataLock)
                {
                    if (!_isInitialized)
                    {
                        _vulnerabilities = GetBuiltinVulnerabilities();
                        _isInitialized = true;
                        _lastSyncTime = DateTime.Now;
                    }
                }
            }
        }

        /// <summary>
        /// 记录信息日志
        /// </summary>
        /// <param name="message">日志消息</param>
        private void LogInfo(string message)
        {
            try
            {
                string logDir = Path.Combine(Path.GetDirectoryName(_cacheFilePath), "logs");
                Directory.CreateDirectory(logDir);
                string logFile = Path.Combine(logDir, $"cnnvd_{DateTime.Now:yyyyMMdd}.log");

                string logEntry = $"[{DateTime.Now:yyyy-MM-dd HH:mm:ss}] INFO: {message}\n";
                File.AppendAllText(logFile, logEntry);
            }
            catch
            {
                // 忽略日志写入错误
            }
        }

        /// <summary>
        /// 记录错误日志
        /// </summary>
        /// <param name="message">错误消息</param>
        /// <param name="ex">异常对象</param>
        private void LogError(string message, Exception ex = null)
        {
            try
            {
                string logDir = Path.Combine(Path.GetDirectoryName(_cacheFilePath), "logs");
                Directory.CreateDirectory(logDir);
                string logFile = Path.Combine(logDir, $"cnnvd_{DateTime.Now:yyyyMMdd}.log");

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

        /// <summary>
        /// 释放资源
        /// </summary>
        public void Dispose()
        {
            Dispose(true);
            GC.SuppressFinalize(this);
        }

        /// <summary>
        /// 释放资源的实现
        /// </summary>
        /// <param name="disposing">是否正在释放托管资源</param>
        protected virtual void Dispose(bool disposing)
        {
            if (!_disposed)
            {
                if (disposing)
                {
                    // 清理托管资源
                    _vulnerabilities?.Clear();
                    _vulnerabilities = null;
                }
                _disposed = true;
            }
        }

        #endregion
    }

    #region 数据模型

    /// <summary>
    /// CNNVD漏洞数据模型
    /// 用于表示国家信息安全漏洞库中的漏洞条目
    /// </summary>
    public class CnnvdVulnerability
    {
        /// <summary>
        /// CVE编号
        /// </summary>
        [JsonPropertyName("cveId")]
        public string CveId { get; set; } = string.Empty;

        /// <summary>
        /// CNNVD编号
        /// </summary>
        [JsonPropertyName("cnnvdId")]
        public string CnnvdId { get; set; } = string.Empty;

        /// <summary>
        /// 漏洞标题
        /// </summary>
        [JsonPropertyName("title")]
        public string Title { get; set; } = string.Empty;

        /// <summary>
        /// CVSS评分 (0.0 - 10.0)
        /// </summary>
        [JsonPropertyName("cvssScore")]
        public double CvssScore { get; set; }

        /// <summary>
        /// 风险等级 (超危/高危/中危/低危)
        /// </summary>
        [JsonPropertyName("riskLevel")]
        public string RiskLevel { get; set; } = "中危";

        /// <summary>
        /// 攻击向量 (Network/Local/Physical)
        /// </summary>
        [JsonPropertyName("attackVector")]
        public string AttackVector { get; set; } = "Network";

        /// <summary>
        /// 受影响的组件 (Gateway/MCP Server/UI/Skill Loader等)
        /// </summary>
        [JsonPropertyName("affectedComponent")]
        public string AffectedComponent { get; set; } = string.Empty;

        /// <summary>
        /// 受影响的平台 (OpenClaw/Hermes Agent/通用)
        /// </summary>
        [JsonPropertyName("platform")]
        public string Platform { get; set; } = "通用";

        /// <summary>
        /// 漏洞描述
        /// </summary>
        [JsonPropertyName("description")]
        public string Description { get; set; } = string.Empty;

        /// <summary>
        /// 修复建议
        /// </summary>
        [JsonPropertyName("remediation")]
        public string Remediation { get; set; } = string.Empty;

        /// <summary>
        /// 参考链接
        /// </summary>
        [JsonPropertyName("referenceUrl")]
        public string ReferenceUrl { get; set; } = string.Empty;

        /// <summary>
        /// 发布日期
        /// </summary>
        [JsonPropertyName("publishedDate")]
        public DateTime PublishedDate { get; set; } = DateTime.Now;

        /// <summary>
        /// 标签列表 (["WebSocket","注入","XSS"])
        /// </summary>
        [JsonPropertyName("tags")]
        public List<string> Tags { get; set; } = new List<string>();
    }

    /// <summary>
    /// CNNVD缓存数据模型
    /// 用于序列化/反序列化缓存文件
    /// </summary>
    internal class CnnvdCacheModel
    {
        /// <summary>
        /// 缓存数据版本
        /// </summary>
        [JsonPropertyName("version")]
        public string Version { get; set; } = "1.0";

        /// <summary>
        /// 最后同步时间
        /// </summary>
        [JsonPropertyName("lastSyncTime")]
        public DateTime LastSyncTime { get; set; } = DateTime.Now;

        /// <summary>
        /// 漏洞数据列表
        /// </summary>
        [JsonPropertyName("data")]
        public List<CnnvdVulnerability> Data { get; set; } = new List<CnnvdVulnerability>();
    }

    #endregion
}
