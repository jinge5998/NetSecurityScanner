using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.Json;
using System.Threading.Tasks;
using NetSecurityScanner.Models;

namespace NetSecurityScanner.Services
{
    public class AIRiskAssessmentService
    {
        private readonly Dictionary<int, RiskWeightConfigV5> _portWeights;
        private readonly Dictionary<string, VulnerabilitySeverityConfigV5> _severity;
        private readonly PortScanDataService _dataService;
        private readonly JsonSerializerOptions _jsonOpts;

        public AIRiskAssessmentService()
        {
            _portWeights = InitPortWeights();
            _severity = InitSeverity();
            _dataService = new PortScanDataService();
            _jsonOpts = new JsonSerializerOptions { WriteIndented = true, PropertyNameCaseInsensitive = true };
        }

        #region 配置初始化
        private Dictionary<string, VulnerabilitySeverityConfigV5> InitSeverity()
        {
            return new(StringComparer.OrdinalIgnoreCase)
            {
                ["Critical"] = new() { Level = "Critical", BaseCvss = 9.5, ExploitMultiplier = 1.6, ImpactMultiplier = 2.2, ColorHex = "#dc2626" },
                ["High"] = new() { Level = "High", BaseCvss = 7.8, ExploitMultiplier = 1.35, ImpactMultiplier = 1.7, ColorHex = "#ea580c" },
                ["Medium"] = new() { Level = "Medium", BaseCvss = 5.2, ExploitMultiplier = 1.0, ImpactMultiplier = 1.25, ColorHex = "#ca8a04" },
                ["Low"] = new() { Level = "Low", BaseCvss = 2.5, ExploitMultiplier = 0.65, ImpactMultiplier = 0.85, ColorHex = "#16a34a" },
                ["Info"] = new() { Level = "Info", BaseCvss = 0.5, ExploitMultiplier = 0.2, ImpactMultiplier = 0.3, ColorHex = "#475569" }
            };
        }

        private Dictionary<int, RiskWeightConfigV5> InitPortWeights()
        {
            var map = new (int p, string s, double w, RiskLevelV5 l, string d, int cve)[]
            {
                (21,"FTP",8.8,RiskLevelV5.High,"FTP明文传输+弱口令+PROFTPD RCE",234),
                (22,"SSH",7.2,RiskLevelV5.High,"SSH暴力破解+密钥泄露+LibSSH认证绕过",178),
                (23,"Telnet",10.0,RiskLevelV5.Extreme,"Telnet明文传输极易被嗅探劫持",97),
                (25,"SMTP",6.2,RiskLevelV5.Medium,"SMTP开放中继+邮件头注入",189),
                (53,"DNS",5.8,RiskLevelV5.Medium,"DNS劫持+放大DDoS+AXFR传送",323),
                (80,"HTTP",7.0,RiskLevelV5.High,"明文HTTP+WebTop10攻击面极广",1456),
                (110,"POP3",6.2,RiskLevelV5.Medium,"POP3明文密码+邮箱爆破",112),
                (135,"MSRPC",8.8,RiskLevelV5.Critical,"Windows RPC/MS08-067/PrintNightmare",512),
                (139,"NetBIOS",8.8,RiskLevelV5.Critical,"NetBIOS+SMB中继+NTLM Relay",289),
                (143,"IMAP",6.2,RiskLevelV5.Medium,"IMAP爆破+预认证RCE",145),
                (389,"LDAP",7.6,RiskLevelV5.High,"LDAP注入+AD域信息收集",289),
                (443,"HTTPS",4.5,RiskLevelV5.Medium,"HTTPS/TLS配置+Web应用漏洞",1023),
                (445,"SMB",9.9,RiskLevelV5.Extreme,"SMB/永恒之蓝蠕虫级+勒索入口",612),
                (636,"LDAPS",6.5,RiskLevelV5.Medium,"加密LDAP/域信息泄露风险",178),
                (993,"IMAPS",4.5,RiskLevelV5.Medium,"加密IMAP/TLS配置检查",89),
                (995,"POP3S",4.5,RiskLevelV5.Medium,"加密POP3/凭据爆破风险",78),
                (1433,"MSSQL",8.6,RiskLevelV5.Critical,"SQLServer xp_cmdshell+SA爆破",423),
                (1521,"Oracle",8.6,RiskLevelV5.Critical,"Oracle TNS+SYS默认密码+Java RCE",567),
                (3306,"MySQL",7.8,RiskLevelV5.High,"MySQL弱口令+UDF提权+日志写Shell",489),
                (3389,"RDP",8.6,RiskLevelV5.Critical,"RDP BlueKeep/密码喷洒",267),
                (5432,"PostgreSQL",7.2,RiskLevelV5.High,"PostgreSQL COPY RCE+UDF",267),
                (5900,"VNC",8.2,RiskLevelV5.High,"VNC无认证/弱密码+完全接管",156),
                (5985,"WinRM",8.9,RiskLevelV5.Critical,"WinRM CrackMapExec PowerShell",167),
                (5986,"WinRM-HTTPS",7.2,RiskLevelV5.High,"WinRM over HTTPS",134),
                (6379,"Redis",9.9,RiskLevelV5.Extreme,"Redis未授权+写公钥+主从RCE",198),
                (8080,"HTTP-Proxy",7.0,RiskLevelV5.High,"HTTP代理/Tomcat后台+WAR部署",612),
                (8443,"HTTPS-Alt",4.8,RiskLevelV5.Medium,"HTTPS备用/管理后台默认凭据",345),
                (9090,"WebAdmin",6.8,RiskLevelV5.Medium,"Prometheus/metrics泄露",134),
                (9200,"Elasticsearch",7.9,RiskLevelV5.High,"ES Groovy RCE+Log4Shell",389),
                (9300,"ES-Transport",7.2,RiskLevelV5.High,"ES Transport反序列化RCE",245),
                (11211,"Memcached",7.6,RiskLevelV5.High,"Memcached未授权+DDOS放大",98),
                (27017,"MongoDB",8.8,RiskLevelV5.Critical,"MongoDB默认无认证+大规模拖库",323)
            };
            var w = new Dictionary<int, RiskWeightConfigV5>();
            foreach (var m in map) w[m.p] = new RiskWeightConfigV5 { Port = m.p, Service = m.s, BaseWeight = m.w, DefaultLevel = m.l, ThreatDescription = m.d, HistoricalCveCount = m.cve };
            return w;
        }
        #endregion

        #region 公共接口
        public async Task<AIRiskAssessmentReportV5> AutoAssessmentAsync()
        {
            var session = await _dataService.GetLatestPortScanResultsAsync();
            if (session == null) return EmptyReport("未找到端口扫描数据，请先执行扫描");
            var vulns = await LoadVulns(session.TargetIp);
            return await AssessRiskV5Async(session.PortScanResults, vulns, session.TargetIp);
        }

        private AIRiskAssessmentReportV5 EmptyReport(string msg) => new()
        {
            AssessmentTime = DateTime.Now,
            OverallRiskLevel = RiskLevelV5.Safe,
            ExecutiveSummary = msg,
            ConfidenceScore = 0.0,
            PortStatistics = new PortRiskStatisticsV5(),
            DimensionalScores = new DimensionalScoresV5(),
            AttackChainAnalysis = new AttackChainAnalysisV5(),
            CvssBreakdown = new CvssBreakdownV5(),
            ThreatIntel = new ThreatIntelContextV5(),
            Compliance = new ComplianceAnalysisV5(),
            RemediationPlan = new RemediationPlanV5(),
            RiskItems = new List<AIRiskItemV5>()
        };

        private async Task<List<VulnerabilityResult>> LoadVulns(string ip)
        {
            try
            {
                var dir = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
                    "NetSecurityScanner", "Data", "Vulnerabilities");
                if (!Directory.Exists(dir)) return new List<VulnerabilityResult>();
                var pattern = $"vuln_{ip.Replace(".", "_")}_*.json";
                var file = Directory.GetFiles(dir, pattern).OrderByDescending(File.GetLastWriteTime).FirstOrDefault()
                    ?? Directory.GetFiles(dir, "vuln_*.json").OrderByDescending(File.GetLastWriteTime).FirstOrDefault();
                if (file == null) return new List<VulnerabilityResult>();
                var json = await File.ReadAllTextAsync(file);
                return JsonSerializer.Deserialize<List<VulnerabilityResult>>(json, _jsonOpts) ?? new();
            }
            catch { return new List<VulnerabilityResult>(); }
        }
        #endregion
        #region V5核心引擎
        public async Task<AIRiskAssessmentReportV5> AssessRiskV5Async(List<PortScanResult> ports, List<VulnerabilityResult> vulns = null, string ip = null)
        {
            var r = new AIRiskAssessmentReportV5
            {
                AssessmentTime = DateTime.Now,
                TargetIp = ip ?? ports?.FirstOrDefault()?.TargetIp ?? "Unknown",
                ReportVersion = "5.0",
                EngineVersion = "AI Risk Engine v5.0"
            };
            if (ports == null || !ports.Any()) { r.ExecutiveSummary = "无开放端口，攻击面为零"; return r; }
            var open = ports.Where(p => (p.Status ?? "").ToLower().Contains("open") || (p.Status ?? "").Contains("开放")).ToList();
            r.PortStatistics.TotalPortsScanned = ports.Count;
            r.PortStatistics.OpenPortsCount = open.Count;
            r.PortStatistics.FilteredPortsCount = ports.Count(p => (p.Status ?? "").Contains("filter") || (p.Status ?? "").Contains("过滤"));
            r.PortStatistics.ClosedPortsCount = ports.Count - open.Count - r.PortStatistics.FilteredPortsCount;
            r.RiskItems = new List<AIRiskItemV5>();
            var critPorts = 0; var highPorts = 0; var medPorts = 0; var lowPorts = 0;
            foreach (var port in open)
            {
                var item = EvalPort(port);
                r.RiskItems.Add(item);
                if (item.Level >= RiskLevelV5.Critical) critPorts++;
                else if (item.Level == RiskLevelV5.High) highPorts++;
                else if (item.Level == RiskLevelV5.Medium) medPorts++;
                else lowPorts++;
            }
            r.PortStatistics.CriticalPortsCount = critPorts;
            r.PortStatistics.HighRiskPortsCount = highPorts;
            r.PortStatistics.MediumRiskPortsCount = medPorts;
            r.PortStatistics.LowRiskPortsCount = lowPorts;
            r.PortStatistics.ServiceTypeDistribution = ClassifyServices(open);
            r.PortStatistics.RiskPatterns = DetectPatterns(open);
            r.PortStatistics.AttackSurfaceIndex = Math.Round(open.Count * 0.5 + critPorts * 2.0 + highPorts * 0.8, 2);
            r.PortStatistics.ExposureRatio = open.Count == 0 ? 0 : Math.Round((double)(critPorts + highPorts) / open.Count, 3);

            vulns ??= new List<VulnerabilityResult>();
            if (vulns.Any())
            {
                double totalCvss = 0; double maxCvss = 0; int kev = 0; int expl = 0; int crCves = 0, hiCves = 0, mdCves = 0, loCves = 0;
                foreach (var v in vulns)
                {
                    var cfg = _severity.GetValueOrDefault(v.RiskLevel ?? "Medium", _severity["Medium"]);
                    var cvss = cfg.BaseCvss;
                    totalCvss += cvss; maxCvss = Math.Max(maxCvss, cvss);
                    var lvl = DetermineLvl(cvss);
                    var hasExploit = cfg.Level == "Critical" || cfg.Level == "High";
                    var item = new AIRiskItemV5
                    {
                        Category = RiskItemCategoryV5.CveVulnerability,
                        Target = string.IsNullOrEmpty(v.Target) ? "N/A" : v.Target,
                        TargetIp = string.IsNullOrEmpty(v.Target) ? null : v.Target,
                        TargetPort = v.Port,
                        Title = string.IsNullOrEmpty(v.Name) ? $"{v.RiskLevel}漏洞" : v.Name,
                        Description = string.IsNullOrEmpty(v.Description) ? cfg.Description : v.Description,
                        Level = lvl,
                        RiskScore = cvss,
                        CvssScore = Math.Round(cvss, 1),
                        CveId = v.CveId,
                        Service = v.Service,
                        Exploitability = new ExploitabilityMetricsV5 { HasPublicExploit = hasExploit, HasCisaKev = cvss >= 9.5, ExploitAvailabilityScore = cfg.ExploitMultiplier },
                        Impact = new ImpactMetricsV5 { ConfidentialityImpact = cfg.ImpactMultiplier * 0.5, IntegrityImpact = cfg.ImpactMultiplier * 0.5, AvailabilityImpact = cfg.ImpactMultiplier * 0.45 },
                        Metadata = new Dictionary<string, string> { ["CVSS"] = cvss.ToString("F1"), ["严重度"] = v.RiskLevel ?? "Medium", ["修复方案"] = string.IsNullOrEmpty(v.Solution) ? "参考厂商公告" : v.Solution },
                        PriorityScore = cvss * cfg.ExploitMultiplier,
                        RemediationPriority = lvl >= RiskLevelV5.Critical ? RemediationPriorityV5.P0Immediate :
                                          lvl == RiskLevelV5.High ? RemediationPriorityV5.P1Urgent :
                                          lvl == RiskLevelV5.Medium ? RemediationPriorityV5.P2High : RemediationPriorityV5.P3Normal,
                        Confidence = 0.92,
                        DiscoveredAt = DateTime.Now
                    };
                    if (item.Exploitability.HasCisaKev) kev++;
                    if (item.Exploitability.HasPublicExploit) expl++;
                    if (lvl >= RiskLevelV5.Critical) crCves++;
                    else if (lvl == RiskLevelV5.High) hiCves++;
                    else if (lvl == RiskLevelV5.Medium) mdCves++;
                    else loCves++;
                    r.RiskItems.Add(item);
                }
                r.CvssBreakdown = new CvssBreakdownV5
                {
                    AverageCvss = totalCvss / vulns.Count,
                    MaxCvss = maxCvss,
                    TotalCriticalCves = crCves,
                    TotalHighCves = hiCves,
                    TotalMediumCves = mdCves,
                    TotalLowCves = loCves,
                    CvesInKevCatalog = kev,
                    CvesWithKnownExploit = expl
                };
                r.VulnerabilityCount = vulns.Count;
            }
            else r.CvssBreakdown = new CvssBreakdownV5();
            r.RiskItems = r.RiskItems.OrderByDescending(i => i.PriorityScore).ToList();
            r.DimensionalScores = CalcDimensions(r.RiskItems, open, vulns);
            r.AttackChainAnalysis = CalcAttackChain(r.RiskItems, open);
            r.ThreatIntel = CalcIntel(r.RiskItems, open);
            r.Compliance = CalcCompliance(r.RiskItems, open);
            r.OverallRiskScore = Math.Round(CalcFinalScore(r), 2);
            r.OverallRiskLevel = DetermineLvl(r.OverallRiskScore);
            r.ConfidenceScore = Math.Round(0.55 + Math.Min(r.RiskItems.Count, 50) * 0.008 + Math.Min(open.Count, 30) * 0.006, 3);
            r.SecurityPostureScore = Math.Round(100 - r.OverallRiskScore * 8.5, 1);
            r.ReadinessScore = Math.Round(100 - r.DimensionalScores.ConfigurationRisk * 7.8 - r.DimensionalScores.AccessControl * 6.5, 1);
            r.ResilienceScore = Math.Round(100 - r.AttackChainAnalysis.BreachProbability * 70 - r.AttackChainAnalysis.LateralMovementEase * 12, 1);
            r.ExecutiveSummary = GenerateSummary(r);
            r.KeyFindingsSummary = ExtractFindings(r);
            r.RemediationPlan = GenerateFixes(r);
            return r;
        }

        private AIRiskItemV5 EvalPort(PortScanResult p)
        {
            var item = new AIRiskItemV5
            {
                Category = RiskItemCategoryV5.PortExposure,
                Target = $"{p.TargetIp}:{p.PortNumber}",
                TargetIp = p.TargetIp,
                TargetPort = p.PortNumber,
                Service = p.Service,
                ServiceVersion = p.ServiceVersion,
                DiscoveredAt = DateTime.Now,
                Metadata = new Dictionary<string, string> { ["端口"] = p.PortNumber.ToString(), ["服务"] = string.IsNullOrEmpty(p.Service) ? "未识别" : p.Service, ["版本"] = string.IsNullOrEmpty(p.ServiceVersion) ? "未知" : p.ServiceVersion }
            };
            double s = 0; RiskWeightConfigV5 cfg = null;
            if (_portWeights.TryGetValue(p.PortNumber, out cfg))
            {
                s = cfg.BaseWeight;
                item.Title = $"[{cfg.DefaultLevel}] 端口{cfg.Port}/{cfg.Service}";
                item.Description = cfg.ThreatDescription;
                item.CveCountLinked = cfg.HistoricalCveCount;
            }
            else
            {
                s = 3.5;
                item.Title = $"开放端口 {p.PortNumber}/{(string.IsNullOrEmpty(p.Service) ? "未知服务" : p.Service.ToUpper())}";
                item.Description = "非常规端口开放，需人工核查服务内容与暴露必要性";
            }
            if (string.IsNullOrEmpty(p.ServiceVersion) || p.ServiceVersion.Equals("unknown", StringComparison.OrdinalIgnoreCase))
                s += 1.2;
            else s -= 0.4;
            s *= 1.6;
            if (cfg != null) s *= Math.Min(1.45, 1 + Math.Log10(cfg.HistoricalCveCount + 1) * 0.18);
            item.RiskScore = Math.Min(10.0, Math.Max(0, Math.Round(s, 2)));
            item.Level = DetermineLvl(item.RiskScore);
            item.CvssScore = item.RiskScore;
            item.Confidence = 0.75 + (cfg != null ? 0.18 : 0);
            item.Exploitability = new ExploitabilityMetricsV5 { IsWormable = new[] { 445, 139, 135, 3389, 23, 6379 }.Contains(p.PortNumber) };
            item.Impact = new ImpactMetricsV5 { BusinessDisruptionScore = 0.5 + item.RiskScore * 0.05 };
            item.PriorityScore = item.RiskScore * (item.Exploitability.IsWormable ? 1.5 : 1.0);
            item.RemediationPriority = item.Level >= RiskLevelV5.Critical ? RemediationPriorityV5.P0Immediate :
                                     item.Level == RiskLevelV5.High ? RemediationPriorityV5.P1Urgent :
                                     item.Level == RiskLevelV5.Medium ? RemediationPriorityV5.P2High : RemediationPriorityV5.P3Normal;
            return item;
        }
        #endregion

        #region 辅助方法
        private Dictionary<string, int> ClassifyServices(List<PortScanResult> ports)
        {
            var dict = new Dictionary<string, int>();
            foreach (var p in ports)
            {
                var cat = "Other";
                if (new[] { 1433, 1521, 3306, 5432, 6379, 27017, 9200, 11211, 9300 }.Contains(p.PortNumber)) cat = "数据库/缓存";
                else if (new[] { 22, 23, 3389, 5900, 5985, 5986 }.Contains(p.PortNumber)) cat = "远程管理";
                else if (new[] { 80, 443, 8080, 8443, 9090 }.Contains(p.PortNumber)) cat = "Web/HTTP";
                else if (new[] { 25, 110, 143, 993, 995 }.Contains(p.PortNumber)) cat = "邮件服务";
                else if (new[] { 445, 139, 135, 389, 636 }.Contains(p.PortNumber)) cat = "域/共享";
                else if (p.PortNumber == 53) cat = "DNS";
                else if (p.PortNumber == 21) cat = "FTP";
                else if (!string.IsNullOrEmpty(p.Service)) cat = p.Service.ToUpper();
                dict.TryGetValue(cat, out var c); dict[cat] = c + 1;
            }
            return dict;
        }

        private List<string> DetectPatterns(List<PortScanResult> ports)
        {
            var ps = ports.Select(p => p.PortNumber).ToList();
            var patterns = new List<string>();
            if (ps.Contains(445) && ps.Contains(139) && ps.Contains(135)) patterns.Add("⚠️ 完整SMB协议簇暴露，易受勒索软件攻击");
            if (ps.Contains(22) || ps.Contains(3389) || ps.Contains(5900)) patterns.Add("🔓 存在远程管理入口，建议VPN+IP白名单");
            if (ps.Contains(3306) || ps.Contains(1433) || ps.Contains(27017) || ps.Contains(6379)) patterns.Add("💾 数据库端口公网暴露，建议NAT内网部署");
            if (ps.Contains(80) && !ps.Contains(443)) patterns.Add("⚠️ 仅HTTP未启用HTTPS，数据传输存在窃听风险");
            if (ps.Contains(21) || ps.Contains(23)) patterns.Add("❌ 废弃明文协议(FTP/Telnet)，立即迁移至SFTP/SSH");
            if (ports.Any(p => string.IsNullOrEmpty(p.ServiceVersion))) patterns.Add("🔎 部分端口版本指纹识别失败，建议深度服务探测");
            return patterns;
        }

        private DimensionalScoresV5 CalcDimensions(List<AIRiskItemV5> risks, List<PortScanResult> open, List<VulnerabilityResult> vulns)
        {
            var d = new DimensionalScoresV5 { Dimensions = new Dictionary<string, DimensionDetailV5>() };
            var crit = risks.Count(r => r.Level >= RiskLevelV5.Critical);
            var high = risks.Count(r => r.Level == RiskLevelV5.High);
            d.NetworkExposure = Math.Min(10, open.Count * 0.42 + crit * 1.35 + high * 0.72);
            d.ServiceVulnerability = Math.Min(10, open.Select(p => _portWeights.TryGetValue(p.PortNumber, out var w) ? w.BaseWeight * 0.88 : 3).DefaultIfEmpty(0).Average() + vulns.Count * 0.12);
            d.VulnerabilitySeverity = Math.Min(10, risks.Where(r => r.Category == RiskItemCategoryV5.CveVulnerability).Select(r => r.RiskScore).DefaultIfEmpty(0).Average());
            var hiRiskPorts = new[] { 22, 23, 445, 3389, 3306, 1433, 6379, 1521, 27017, 135, 139, 5985, 5986 };
            d.ConfigurationRisk = Math.Min(10, open.Count(p => string.IsNullOrEmpty(p.ServiceVersion)) * 0.65 + open.Count(p => hiRiskPorts.Contains(p.PortNumber)) * 0.85);
            d.AccessControl = Math.Min(10, open.Count(p => new[] { 22, 23, 3389, 5900, 5985, 5986 }.Contains(p.PortNumber)) * 1.55 + open.Count(p => new[] { 21, 110, 143 }.Contains(p.PortNumber)) * 0.85);
            d.DataExposure = Math.Min(10, open.Count(p => new[] { 1433, 1521, 3306, 5432, 27017, 6379, 9200, 11211, 445, 139 }.Contains(p.PortNumber)) * 1.15);
            d.AuthenticationStrength = Math.Min(10, d.AccessControl * 0.7 + d.ConfigurationRisk * 0.3);
            d.EncryptionPosture = Math.Round(10 - Math.Min(10, open.Count(p => new[] { 21, 23, 80, 110, 143 }.Contains(p.PortNumber)) * 1.1), 2);
            d.PatchingCadence = Math.Round(Math.Min(10, d.VulnerabilitySeverity * 0.65 + d.ServiceVulnerability * 0.35), 2);
            d.ComplianceGap = Math.Min(10, d.NetworkExposure * 0.25 + d.DataExposure * 0.35 + d.AccessControl * 0.25 + d.ConfigurationRisk * 0.15);
            d.CompositeIndex = Math.Round(d.NetworkExposure * 0.17 + d.ServiceVulnerability * 0.16 + d.VulnerabilitySeverity * 0.16 + d.ConfigurationRisk * 0.12 + d.AccessControl * 0.13 + d.DataExposure * 0.12 + d.AuthenticationStrength * 0.06 + d.EncryptionPosture * 0.04 + d.PatchingCadence * 0.04, 2);
            d.SecurityPostureScore = Math.Round(100 - d.CompositeIndex * 8.5, 1);
            return d;
        }

        private AttackChainAnalysisV5 CalcAttackChain(List<AIRiskItemV5> risks, List<PortScanResult> open)
        {
            var ps = open.Select(p => p.PortNumber).ToList();
            var a = new AttackChainAnalysisV5 { EntryVectors = new List<AttackVectorChainV5>(), LateralPaths = new List<LateralPathV5>(), KillChain = new List<KillChainPhaseV5>(), TopRiskScenarios = new List<string>() };
            double cumP = 0;
            if (ps.Intersect(new[] { 80, 443, 8080, 8443 }).Any())
            {
                cumP += 0.48;
                a.EntryVectors.Add(new AttackVectorChainV5 { VectorName = "Web应用渗透", Phase = AttackPhaseV5.InitialAccess, Probability = 0.48, CumulativeProbability = cumP, EaseOfExploitation = 0.72, Description = "通过SQL注入/XSS/RCE/WebShell获取主机权限", RelatedTargets = risks.Where(r => r.Level >= RiskLevelV5.High).Select(r => r.Target).Take(5).ToList(), ExploitationSteps = new() { "1. CMS指纹识别+WAF探测", "2. SQLi/文件上传获取WebShell", "3. 提权至system/root", "4. 加载Mimikatz抓取哈希" } });
            }
            if (ps.Intersect(new[] { 445, 135, 139, 3389, 6379, 27017, 9200, 1433, 3306 }).Any())
            {
                cumP += 0.33;
                a.EntryVectors.Add(new AttackVectorChainV5 { VectorName = "高危服务直接RCE", Phase = AttackPhaseV5.InitialAccess, Probability = 0.33, CumulativeProbability = cumP, EaseOfExploitation = 0.88, Description = "SMB/RDP/Redis/数据库直接远程代码执行", ExploitationSteps = new() { "1. 探测高危端口开放", "2. 载入EternalBlue/Redis未授权EXP", "3. 植入Beacon建立C2", "4. 哈希传递横向扩散" } });
            }
            if (ps.Intersect(new[] { 22, 23, 3389, 21, 110, 143, 3306, 5432 }).Any())
            {
                cumP += 0.18;
                a.EntryVectors.Add(new AttackVectorChainV5 { VectorName = "凭据暴力破解", Phase = AttackPhaseV5.InitialAccess, Probability = 0.18, CumulativeProbability = cumP, EaseOfExploitation = 0.62, Description = "SSH/RDP/FTP/数据库密码喷洒攻击", ExploitationSteps = new() { "1. 使用Known_Creds生成字典", "2. Hydra/Medusa并发爆破", "3. 成功后直接登录主机", "4. 安装持久化后门" } });
            }
            a.BreachProbability = Math.Round(Math.Min(0.98, cumP * 0.58 + risks.Count(r => r.Level >= RiskLevelV5.Critical) * 0.09), 3);
            a.MeanTimeToBreachHours = Math.Round(Math.Max(0.5, 72 - a.BreachProbability * 70), 1);
            double cumE = 0;
            if (ps.Contains(445) || ps.Contains(135)) { cumE += 0.9; a.LateralPaths.Add(new LateralPathV5 { PathName = "SMB横向(PsExec/WMI)", EaseScore = 0.9, ProtocolUsed = "SMB/RPC", Description = "445/135端口配合PsExec/Mimikatz哈希传递", Tools = new() { "PsExec", "wmiexec.py", "Mimikatz", "CrackMapExec" } }); }
            if (ps.Contains(5985) || ps.Contains(5986)) { cumE += 0.95; a.LateralPaths.Add(new LateralPathV5 { PathName = "WinRM远程命令", EaseScore = 0.95, ProtocolUsed = "WinRM", Description = "WinRM配合CME/Evil-WinRM执行命令", Tools = new() { "Evil-WinRM", "CrackMapExec" } }); }
            if (ps.Contains(22)) { cumE += 0.8; a.LateralPaths.Add(new LateralPathV5 { PathName = "SSH跳板代理", EaseScore = 0.8, ProtocolUsed = "SSH", Description = "SSH隧道/SOCKS代理穿透内网", Tools = new() { "ssh -D", "Proxychains", "Chisel" } }); }
            if (ps.Contains(3389) || ps.Contains(5900)) { cumE += 0.75; a.LateralPaths.Add(new LateralPathV5 { PathName = "RDP跳转劫持", EaseScore = 0.75, ProtocolUsed = "RDP/VNC", Description = "RDP会话劫持跳转+剪贴板注入", Tools = new() { "mstsc /admin", "SharpRDP", "RDPWrap" } }); }
            a.LateralMovementEase = Math.Round(Math.Min(10, cumE * 6.2 + risks.Count(r => r.Level >= RiskLevelV5.Critical) * 0.25), 2);
            a.DwellTimeEstimateDays = Math.Round(Math.Max(1, 180 - a.BreachProbability * 170 - a.LateralMovementEase * 4), 1);
            a.CriticalAttackPaths = risks.Count(r => r.Level >= RiskLevelV5.Critical) + a.LateralPaths.Count;
            var threats = new List<string>();
            if (a.BreachProbability >= 0.7) threats.Add("🚨 极高突破概率：攻击者大概率在24小时内获得初始立足点");
            if (ps.Contains(445) || ps.Contains(135) || ps.Contains(139)) threats.Add("💀 SMB+RPC暴露：存在勒索软件全网加密的高风险");
            if (a.LateralMovementEase >= 7) threats.Add("⚠️ 横向移动极易：单台沦陷将导致全网渗透");
            if (risks.Any(r => r.Exploitability.IsWormable)) threats.Add("🐛 存在可蠕虫级漏洞：可能无需人工干预自动扩散");
            if (!threats.Any()) threats.Add("✅ 当前配置相对安全，持续监控新增风险");
            a.TopRiskScenarios = threats;
            a.NarrativeThreatDescription = $"基于开放端口评估，该目标突破概率约{a.BreachProbability * 100:F1}%，平均突破时间约{a.MeanTimeToBreachHours:F1}小时。攻击者最可能选择的初始路径为{(a.EntryVectors.FirstOrDefault()?.VectorName ?? "未知")}，后续横向移动便捷性评分为{a.LateralMovementEase}/10。";
            return a;
        }

        private ThreatIntelContextV5 CalcIntel(List<AIRiskItemV5> risks, List<PortScanResult> open)
        {
            var ps = open.Select(p => p.PortNumber).ToList();
            var intel = new ThreatIntelContextV5 { RelevantAptGroups = new(), ActiveMalwareFamilies = new(), RecentExploitTrends = new(), IocMatches = new() };
            intel.ExploitInTheWildProbability = Math.Round(Math.Min(0.95, risks.Count(r => r.Exploitability.HasPublicExploit) * 0.12 + open.Count(p => new[] { 445, 6379, 27017, 3389, 135 }.Contains(p.PortNumber)) * 0.09), 3);
            intel.RansomwareTargetLikelihood = Math.Round(Math.Min(0.98, (ps.Contains(445) ? 0.35 : 0) + (ps.Contains(3389) ? 0.2 : 0) + (ps.Contains(6379) ? 0.15 : 0) + intel.ExploitInTheWildProbability * 0.3), 3);
            intel.IndustryThreatLevel = intel.RansomwareTargetLikelihood >= 0.7 ? "严重" : intel.RansomwareTargetLikelihood >= 0.4 ? "警戒" : "稳定";
            if (ps.Contains(445) || ps.Contains(139)) { intel.RelevantAptGroups.Add("APT28 索伦之眼"); intel.ActiveMalwareFamilies.Add("LockBit勒索软件"); intel.ActiveMalwareFamilies.Add("BlackCat勒索"); }
            if (ps.Contains(80) || ps.Contains(443)) { intel.RelevantAptGroups.Add("APT31 宙斯之盾"); intel.ActiveMalwareFamilies.Add("Cobalt Strike Beacon"); }
            if (ps.Contains(6379) || ps.Contains(27017)) { intel.RecentExploitTrends.Add("2025上半年针对数据库未授权的攻击激增168%"); }
            return intel;
        }

        private ComplianceAnalysisV5 CalcCompliance(List<AIRiskItemV5> risks, List<PortScanResult> open)
        {
            var ps = open.Select(p => p.PortNumber).ToList();
            var c = new ComplianceAnalysisV5 { FailedControls = new(), FrameworkScores = new() };
            if (ps.Contains(21)) c.FailedControls.Add("CIS 2.3.1 - 禁止明文FTP协议");
            if (ps.Contains(23)) c.FailedControls.Add("CIS 2.3.2 - 禁止Telnet协议");
            if (ps.Contains(80)) c.FailedControls.Add("PCI-DSS 4.1 - 需TLS加密传输卡数据");
            if (risks.Any(r => r.Level >= RiskLevelV5.Critical)) c.FailedControls.Add("ISO 27001 A.12.6.1 - 高风险漏洞需在SLA内修复");
            c.CriticalFindings = risks.Count(r => r.Level >= RiskLevelV5.Critical);
            c.HighSeverityFindings = risks.Count(r => r.Level == RiskLevelV5.High);
            c.FrameworkScores["CIS v8"] = Math.Round(Math.Max(0, 92 - c.CriticalFindings * 4 - c.HighSeverityFindings * 1.5 - c.FailedControls.Count * 2.5), 1);
            c.FrameworkScores["NIST CSF"] = Math.Round(Math.Max(0, 88 - c.CriticalFindings * 3.5 - c.HighSeverityFindings * 1.2), 1);
            c.FrameworkScores["PCI-DSS 4.0"] = Math.Round(Math.Max(0d, 95d - c.CriticalFindings * 5d - (ps.Contains(80) ? 8d : 0d) - (ps.Contains(21) || ps.Contains(23) ? 10d : 0d)), 1);
            c.FrameworkScores["等保2.0三级"] = Math.Round(Math.Max(0, 90 - c.CriticalFindings * 3.8 - c.HighSeverityFindings * 1.6), 1);
            c.OverallComplianceScore = Math.Round(c.FrameworkScores.Values.Average(), 1);
            return c;
        }

        private double CalcFinalScore(AIRiskAssessmentReportV5 r)
        {
            var s = r.DimensionalScores.CompositeIndex * 0.48 + r.AttackChainAnalysis.BreachProbability * 10 * 0.32 + r.CvssBreakdown.AverageCvss * 0.2 + Math.Min(10, r.CvssBreakdown.TotalCriticalCves * 0.9) * 0.15 - r.DimensionalScores.EncryptionPosture * 0.05;
            return Math.Min(10, Math.Max(0, s));
        }

        private RiskLevelV5 DetermineLvl(double s)
        {
            if (s >= 9.5) return RiskLevelV5.Extreme;
            if (s >= 8.0) return RiskLevelV5.Critical;
            if (s >= 6.0) return RiskLevelV5.High;
            if (s >= 3.5) return RiskLevelV5.Medium;
            if (s >= 1.2) return RiskLevelV5.Low;
            return RiskLevelV5.Safe;
        }

        private string LevelEmoji(RiskLevelV5 l) => l switch
        {
            RiskLevelV5.Extreme => "💣",
            RiskLevelV5.Critical => "🔴",
            RiskLevelV5.High => "🟠",
            RiskLevelV5.Medium => "🟡",
            RiskLevelV5.Low => "🟢",
            _ => "✅"
        };

        private string LevelLabel(RiskLevelV5 l) => l switch
        {
            RiskLevelV5.Extreme => "极端",
            RiskLevelV5.Critical => "严重",
            RiskLevelV5.High => "高危",
            RiskLevelV5.Medium => "中危",
            RiskLevelV5.Low => "低危",
            _ => "安全"
        };

        private string GenerateSummary(AIRiskAssessmentReportV5 r)
        {
            var lvl = LevelLabel(r.OverallRiskLevel);
            return $"{LevelEmoji(r.OverallRiskLevel)} 目标 {r.TargetIp} 的综合风险评级为【{lvl}】(评分{r.OverallRiskScore:F2}/10)。"
                 + $"开放端口 {r.PortStatistics.OpenPortsCount} 个，其中严重/高危 {r.PortStatistics.CriticalPortsCount + r.PortStatistics.HighRiskPortsCount} 个，"
                 + $"识别风险项共 {r.RiskItems.Count} 条。综合攻破概率约{r.AttackChainAnalysis.BreachProbability * 100:F1}%，"
                 + $"预计攻击者平均{r.AttackChainAnalysis.MeanTimeToBreachHours:F1}小时可获得初始立足点。"
                 + $"整体安全态势：{(r.SecurityPostureScore >= 80 ? "良好" : r.SecurityPostureScore >= 60 ? "一般" : r.SecurityPostureScore >= 40 ? "风险较高" : "极度危险")}。";
        }

        private List<string> ExtractFindings(AIRiskAssessmentReportV5 r)
        {
            var f = new List<string>();
            if (r.PortStatistics.CriticalPortsCount > 0) f.Add($"🔴 存在{r.PortStatistics.CriticalPortsCount}个极端风险端口，需立即处置");
            if (r.AttackChainAnalysis.BreachProbability >= 0.7) f.Add("🚨 攻破概率>70%，建议24小时内启动应急响应");
            if (r.CvssBreakdown.WormableCves > 0) f.Add($"🐛 存在{r.CvssBreakdown.WormableCves}个可蠕虫级漏洞");
            if (r.ThreatIntel.RansomwareTargetLikelihood >= 0.5) f.Add($"💰 勒索软件针对概率{r.ThreatIntel.RansomwareTargetLikelihood * 100:F0}%，备份与零信任需加固");
            if (r.PortStatistics.RiskPatterns?.Any() == true) f.AddRange(r.PortStatistics.RiskPatterns.Take(3));
            if (!f.Any()) f.Add("✅ 无重大风险发现，建议保持安全基线并定期复查");
            return f.Take(8).ToList();
        }

        private RemediationPlanV5 GenerateFixes(AIRiskAssessmentReportV5 r)
        {
            var plan = new RemediationPlanV5 { Recommendations = new(), QuickWins = new(), LongTermStrategies = new() };
            int p0 = 0, p1 = 0, p2 = 0, p3 = 0; int effort = 0; double reduction = 0;
            var ports = (r.PortStatistics.PortRiskHeatMap?.Keys ?? Enumerable.Empty<int>()).ToList();
            var hiPorts = r.RiskItems.Where(i => i.Category == RiskItemCategoryV5.PortExposure && i.Level >= RiskLevelV5.Critical).ToList();
            foreach (var p in hiPorts.Take(5))
            {
                var rec = new RiskRecommendationV5
                {
                    Priority = RemediationPriorityV5.P0Immediate,
                    Category = "端口收敛",
                    Target = p.Target,
                    Title = $"立即关闭或内网化端口{p.TargetPort}",
                    Summary = $"{p.Description}\n当前暴露严重评级：{LevelLabel(p.Level)}({p.RiskScore:F1}/10)",
                    Rationale = $"该端口为MITRE ATT&CK重点映射初始访问向量，已被多个APT组织武器化",
                    RiskReductionPotential = Math.Round(p.RiskScore * 9.5, 1),
                    EstimatedEffortHours = 2,
                    Complexity = "低",
                    ActionSteps = new() { "1. 通过防火墙/安全组禁止公网入站访问该端口", "2. 仅允许VPN或可信办公IP通过ACL白名单访问", "3. 如业务确需公网，部署反向代理+WAF+IP地理围栏", "4. 24小时后再次扫描验证关闭效果" },
                    References = new() { "CIS v8 Control 12 - Network Infrastructure Management" }
                };
                p0++; effort += rec.EstimatedEffortHours; reduction += rec.RiskReductionPotential;
                plan.Recommendations.Add(rec);
            }
            var cveCrit = r.RiskItems.Where(i => i.Category == RiskItemCategoryV5.CveVulnerability && i.Level >= RiskLevelV5.Critical).ToList();
            foreach (var v in cveCrit.Take(5))
            {
                var rec = new RiskRecommendationV5
                {
                    Priority = RemediationPriorityV5.P1Urgent,
                    Category = "漏洞修复",
                    Target = v.Target,
                    Title = $"紧急修复{v.CveId ?? "关键漏洞"}：{v.Title}",
                    Summary = v.Description,
                    Rationale = $"CVSS {v.CvssScore:F1}，公开EXP/武器化风险极高",
                    RiskReductionPotential = Math.Round(v.RiskScore * 6.5, 1),
                    EstimatedEffortHours = 4,
                    Complexity = "中",
                    ActionSteps = new() { "1. 下载厂商紧急安全补丁/热修复", "2. 在镜像环境验证兼容性", "3. 灰度发布，先应用到10%节点", "4. 24小时内全量推送并重启服务", "5. 重新扫描验证补丁有效性" }
                };
                p1++; effort += rec.EstimatedEffortHours; reduction += rec.RiskReductionPotential;
                plan.Recommendations.Add(rec);
            }
            var highItems = r.RiskItems.Where(i => i.Level == RiskLevelV5.High).Take(5);
            foreach (var it in highItems)
            {
                var rec = new RiskRecommendationV5
                {
                    Priority = RemediationPriorityV5.P2High,
                    Category = "加固优化",
                    Target = it.Target,
                    Title = $"72小时内处置：{it.Title}",
                    Summary = it.Description,
                    Rationale = "高危风险需在SLA内处置",
                    RiskReductionPotential = Math.Round(it.RiskScore * 3.0, 1),
                    EstimatedEffortHours = 8,
                    Complexity = "中"
                };
                p2++; effort += rec.EstimatedEffortHours; reduction += rec.RiskReductionPotential;
                plan.Recommendations.Add(rec);
            }
            plan.P0ImmediateCount = p0; plan.P1UrgentCount = p1; plan.P2HighCount = p2; plan.P3NormalCount = p3;
            plan.TotalEstimatedHours = effort;
            plan.TotalRecommendations = plan.Recommendations.Count;
            plan.ProjectedRiskReduction = Math.Round(Math.Min(100, reduction / Math.Max(1, r.RiskItems.Count)), 1);
            var quickWins = new List<string>();
            if (ports.Contains(23)) quickWins.Add("⚡ 立即关闭Telnet(23)，用SSH替代 (5分钟)");
            if (ports.Contains(21)) quickWins.Add("⚡ 禁用明文FTP(21)，迁移到SFTP(22) (15分钟)");
            if (ports.Contains(6379)) quickWins.Add("⚡ Redis绑定127.0.0.1+添加requirepass (3分钟)");
            if (ports.Contains(27017)) quickWins.Add("⚡ MongoDB启用auth认证+绑定内网IP (5分钟)");
            if (ports.Contains(445) && !ports.Contains(636)) quickWins.Add("⚡ 公网阻断SMB(445)仅域内访问 (1分钟)");
            if (!quickWins.Any()) quickWins.Add("✅ 无可立即处置的端口，继续推进中长期加固");
            plan.QuickWins = quickWins;
            plan.LongTermStrategies = new List<string>
            {
                "🎯 三个月内完成：零信任架构部署(SDP/ZTNA)替代边界VPN",
                "🎯 半年内完成：全自动漏洞扫描+CI/CD阻断流水线(DevSecOps)",
                "🎯 持续推进：EDR/XDR部署，ATT&CK检测规则覆盖率达到80%+",
                "🎯 季度演练：红蓝对抗+勒索软件应急响应桌面演练"
            };
            return plan;
        }

        private List<RelatedCveV5> CheckLinkedCves(int port)
        {
            var cves = new List<RelatedCveV5>();
            var map = new Dictionary<int, (string cve, string title, double cvss, string sev, bool expl, bool kev, string desc)[]>
            {
                [445] = new[] { ("CVE-2017-0144","SMBv1永恒之蓝RCE",9.8,"Critical",true,true,"SMBv1远程代码执行，勒索软件WannaCry入口"),
                                ("CVE-2020-0796","SMBGhost RCE",10.0,"Critical",true,true,"Windows 10 SMBv3压缩内存破坏，无需认证") },
                [3389] = new[] { ("CVE-2019-0708", "BlueKeep RCE", 9.8, "Critical", true, true, "Windows RDP预认证RCE蠕虫级漏洞") },
                [135] = new[] { ("CVE-2021-1675", "PrintNightmare RCE", 7.8, "High", true, true, "打印服务权限提升，域控沦陷") },
                [6379] = new[] { ("CVE-2022-0543", "Redis Lua沙箱逃逸", 9.8, "Critical", true, true, "Debian/Ubuntu包编译缺陷RCE") },
                [80] = new[] { ("CVE-2021-44228","Log4Shell JNDI注入",10.0,"Critical",true,true,"Java Log4j2史上影响力最大漏洞"),
                               ("CVE-2022-22965","Spring4Shell RCE",9.8,"Critical",true,true,"Spring Core JDK9+数据绑定RCE") },
                [8080] = new[] { ("CVE-2017-5638", "Struts2 S2-045 OGNL RCE", 10.0, "Critical", true, true, "Struts2多版本Content-Type头RCE") },
                [27017] = new[] { ("CVE-2015-7810", "MongoDB默认无认证", 10.0, "Critical", true, false, "全球数万实例直接拖库事件") },
                [3306] = new[] { ("CVE-2016-6662", "MySQL提权", 9.8, "Critical", true, false, "my.cnf注入远程root提权") },
                [22] = new[] { ("CVE-2024-6387", "regreSSHion信号处理竞态RCE", 10.0, "Critical", true, true, "OpenSSH 8.5p1至9.8p1远程未认证RCE") },
                [9200] = new[] { ("CVE-2014-3120", "ES老版本Groovy脚本RCE", 9.8, "Critical", true, false, "Elasticsearch 1.2前默认开启动态脚本") }
            };
            if (map.TryGetValue(port, out var list))
            {
                foreach (var c in list) cves.Add(new RelatedCveV5 { CveId = c.cve, Title = c.title, CvssScore = c.cvss, Severity = c.sev, HasPublicExploit = c.expl, InKevCatalog = c.kev, Description = c.desc });
            }
            return cves;
        }

        private double ParseCvssVector(string vec)
        {
            try
            {
                if (string.IsNullOrEmpty(vec)) return 0;
                var baseScore = 0.0;
                if (vec.Contains("AV:N")) baseScore += 2.5;
                else if (vec.Contains("AV:A")) baseScore += 1.5;
                else if (vec.Contains("AV:L")) baseScore += 0.8;
                else baseScore += 0.5;
                if (vec.Contains("AC:L")) baseScore += 1.8;
                else if (vec.Contains("AC:H")) baseScore += 0.8;
                else baseScore += 1.2;
                if (vec.Contains("PR:N")) baseScore += 1.5;
                else if (vec.Contains("PR:L")) baseScore += 0.9;
                else baseScore += 0.4;
                if (vec.Contains("UI:N")) baseScore += 1.5;
                else baseScore += 0.7;
                if (vec.Contains("C:H")) baseScore += 1.1;
                else if (vec.Contains("C:L")) baseScore += 0.5;
                if (vec.Contains("I:H")) baseScore += 1.1;
                else if (vec.Contains("I:L")) baseScore += 0.5;
                if (vec.Contains("A:H")) baseScore += 0.9;
                else if (vec.Contains("A:L")) baseScore += 0.4;
                return Math.Min(10, baseScore);
            }
            catch { return 5.0; }
        }

        private double CalculateItemConfidence(RiskWeightConfigV5 p, RiskWeightConfigV5 s, List<RelatedCveV5> c)
        {
            double conf = 0.45;
            if (p != null) conf += 0.25;
            if (s != null) conf += 0.1;
            if (c != null && c.Any()) conf += Math.Min(0.2, c.Count * 0.07);
            return Math.Round(Math.Min(0.99, conf), 3);
        }

        private string ComputeFuzzyMembership(double s)
        {
            var safe = Math.Max(0, 1 - s / 1.2);
            var low = s < 1.2 ? s / 1.2 : s < 3.5 ? (3.5 - s) / 2.3 : 0;
            var med = s < 3.5 ? (s - 1.2) / 2.3 : s < 6.0 ? (6.0 - s) / 2.5 : 0;
            var hi = s < 6.0 ? (s - 3.5) / 2.5 : s < 8.0 ? (8.0 - s) / 2.0 : 0;
            var crit = s < 8.0 ? Math.Max(0, (s - 6) / 2) : 1;
            return $"Safe:{safe * 100:F0}%/Low:{low * 100:F0}%/Med:{med * 100:F0}%/High:{hi * 100:F0}%/Crit:{crit * 100:F0}%";
        }

        private double CalculatePriorityScore(AIRiskItemV5 item)
        {
            return Math.Round(item.RiskScore * (item.Exploitability.ExploitAvailabilityScore * 0.4 + 1.0)
                * (1 + item.Impact.BusinessDisruptionScore * 0.35)
                * (item.Exploitability.HasCisaKev ? 1.45 : 1.0)
                * (item.Exploitability.IsWormable ? 1.5 : 1.0), 2);
        }

        private RemediationPriorityV5 DetermineRemediationPriority(AIRiskItemV5 item)
        {
            if (item.PriorityScore >= 18 || item.Level >= RiskLevelV5.Critical) return RemediationPriorityV5.P0Immediate;
            if (item.PriorityScore >= 11 || item.Level == RiskLevelV5.High) return RemediationPriorityV5.P1Urgent;
            if (item.PriorityScore >= 6 || item.Level == RiskLevelV5.Medium) return RemediationPriorityV5.P2High;
            return item.PriorityScore >= 3 ? RemediationPriorityV5.P3Normal : RemediationPriorityV5.P4Low;
        }

        private double CalculateConfidence(int riskCount, int portCount, int vulnCount)
        {
            return Math.Round(Math.Min(0.99, 0.55 + Math.Min(riskCount, 50) * 0.008
                + Math.Min(portCount, 30) * 0.006 + Math.Min(vulnCount, 20) * 0.009), 3);
        }

        private List<string> IdentifyAdvancedSignals(List<PortScanResult> ports, List<AIRiskItemV5> items)
        {
            var signals = new List<string>();
            var ps = ports.Select(p => p.PortNumber).ToList();
            if (ps.Contains(5985) && ps.Contains(445) && ps.Contains(389))
                signals.Add("🎯 检测到完整WinRM+SMB+LDAP组合，适合Kerberoast+白银票据域攻击");
            if (ps.Contains(3306) && ps.Contains(22) && ps.Contains(6379))
                signals.Add("🎯 DB+SSH+Redis组合，常见于开发测试机公网误暴露，数据极高危");
            if (items.Count(i => i.Level >= RiskLevelV5.Critical) >= 3)
                signals.Add("🎯 多个严重风险端口集中暴露，极可能属于未加固的蜜罐/老旧服务器");
            return signals;
        }

        private double ComputeAttackSurfaceIndex(List<PortScanResult> ports)
        {
            var pn = ports.Select(p => p.PortNumber).ToList();
            var idx = 0.0;
            idx += pn.Count(p => new[] { 21, 23, 80, 110, 143 }.Contains(p)) * 1.2;
            idx += pn.Count(p => new[] { 445, 135, 139, 3389, 6379, 27017, 5985 }.Contains(p)) * 2.4;
            idx += pn.Count(p => new[] { 3306, 1433, 5432, 1521, 9200 }.Contains(p)) * 1.8;
            return Math.Round(idx + pn.Count * 0.2, 2);
        }
        #endregion
    }
}