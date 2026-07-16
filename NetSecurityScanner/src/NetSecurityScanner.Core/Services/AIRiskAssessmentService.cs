using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.Json;
using System.Threading.Tasks;
using NetSecurityScanner.Models;

namespace NetSecurityScanner.Services
{
    /// <summary>
    /// AI风险评估服务
    /// 基于端口扫描结果和漏洞数据进行智能风险评估
    /// 自动从JSON数据获取端口扫描和漏洞扫描数据
    /// 增强版风险评分算法
    /// </summary>
    public class AIRiskAssessmentService
    {
        private readonly Dictionary<int, RiskWeight> _portRiskWeights;
        private readonly Dictionary<string, ServiceRiskWeight> _serviceRiskWeights;
        private readonly Dictionary<string, double> _vulnerabilitySeverityScores;
        private readonly PortScanDataService _portScanDataService;
        private readonly JsonSerializerOptions _jsonOptions;

        public AIRiskAssessmentService()
        {
            _portRiskWeights = InitializePortRiskWeights();
            _serviceRiskWeights = InitializeServiceRiskWeights();
            _vulnerabilitySeverityScores = InitializeVulnerabilitySeverityScores();
            _portScanDataService = new PortScanDataService();
            _jsonOptions = new JsonSerializerOptions
            {
                WriteIndented = true,
                PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
                PropertyNameCaseInsensitive = true
            };
        }

        /// <summary>
        /// 初始化漏洞严重性评分
        /// Critical=10, High=7, Medium=5, Low=2
        /// </summary>
        private Dictionary<string, double> InitializeVulnerabilitySeverityScores()
        {
            return new Dictionary<string, double>
            {
                ["Critical"] = 10.0,
                ["High"] = 7.0,
                ["Medium"] = 5.0,
                ["Low"] = 2.0,
                ["Info"] = 0.5
            };
        }

        /// <summary>
        /// 初始化服务类型风险权重
        /// SSH=6, FTP=5, HTTP=4, HTTPS=3等
        /// </summary>
        private Dictionary<string, ServiceRiskWeight> InitializeServiceRiskWeights()
        {
            return new Dictionary<string, ServiceRiskWeight>(StringComparer.OrdinalIgnoreCase)
            {
                ["ssh"] = new ServiceRiskWeight { ServiceName = "SSH", Weight = 6, Category = PortRiskCategory.High, Description = "SSH远程管理，需防止暴力破解" },
                ["ftp"] = new ServiceRiskWeight { ServiceName = "FTP", Weight = 5, Category = PortRiskCategory.Medium, Description = "FTP明文传输，存在数据窃取风险" },
                ["telnet"] = new ServiceRiskWeight { ServiceName = "Telnet", Weight = 8, Category = PortRiskCategory.Critical, Description = "Telnet明文传输，风险极高" },
                ["http"] = new ServiceRiskWeight { ServiceName = "HTTP", Weight = 4, Category = PortRiskCategory.Medium, Description = "明文HTTP，建议升级为HTTPS" },
                ["https"] = new ServiceRiskWeight { ServiceName = "HTTPS", Weight = 3, Category = PortRiskCategory.Low, Description = "HTTPS加密传输，安全性较高" },
                ["smtp"] = new ServiceRiskWeight { ServiceName = "SMTP", Weight = 5, Category = PortRiskCategory.Medium, Description = "邮件服务，存在垃圾邮件风险" },
                ["pop3"] = new ServiceRiskWeight { ServiceName = "POP3", Weight = 5, Category = PortRiskCategory.Medium, Description = "邮件接收服务" },
                ["imap"] = new ServiceRiskWeight { ServiceName = "IMAP", Weight = 5, Category = PortRiskCategory.Medium, Description = "邮件访问服务" },
                ["dns"] = new ServiceRiskWeight { ServiceName = "DNS", Weight = 4, Category = PortRiskCategory.Medium, Description = "DNS服务，可能存在DNS劫持" },
                ["rdp"] = new ServiceRiskWeight { ServiceName = "RDP", Weight = 7, Category = PortRiskCategory.High, Description = "远程桌面，存在暴力破解风险" },
                ["vnc"] = new ServiceRiskWeight { ServiceName = "VNC", Weight = 7, Category = PortRiskCategory.High, Description = "VNC远程桌面，注意弱密码风险" },
                ["mysql"] = new ServiceRiskWeight { ServiceName = "MySQL", Weight = 6, Category = PortRiskCategory.High, Description = "MySQL数据库，需加强访问控制" },
                ["mssql"] = new ServiceRiskWeight { ServiceName = "MSSQL", Weight = 7, Category = PortRiskCategory.High, Description = "SQL Server数据库，需加强访问控制" },
                ["postgresql"] = new ServiceRiskWeight { ServiceName = "PostgreSQL", Weight = 6, Category = PortRiskCategory.High, Description = "PostgreSQL数据库" },
                ["oracle"] = new ServiceRiskWeight { ServiceName = "Oracle", Weight = 7, Category = PortRiskCategory.High, Description = "Oracle数据库，需加强访问控制" },
                ["mongodb"] = new ServiceRiskWeight { ServiceName = "MongoDB", Weight = 7, Category = PortRiskCategory.High, Description = "MongoDB数据库" },
                ["redis"] = new ServiceRiskWeight { ServiceName = "Redis", Weight = 9, Category = PortRiskCategory.Critical, Description = "Redis缓存，默认无密码，风险极高" },
                ["elasticsearch"] = new ServiceRiskWeight { ServiceName = "Elasticsearch", Weight = 6, Category = PortRiskCategory.High, Description = "Elasticsearch搜索服务" },
                ["smb"] = new ServiceRiskWeight { ServiceName = "SMB", Weight = 9, Category = PortRiskCategory.Critical, Description = "SMB文件共享，历史上存在严重漏洞" },
                ["netbios"] = new ServiceRiskWeight { ServiceName = "NetBIOS", Weight = 6, Category = PortRiskCategory.High, Description = "NetBIOS服务，存在信息泄露风险" },
                ["http-proxy"] = new ServiceRiskWeight { ServiceName = "HTTP-Proxy", Weight = 5, Category = PortRiskCategory.Medium, Description = "HTTP代理或备用HTTP端口" },
                ["https-alt"] = new ServiceRiskWeight { ServiceName = "HTTPS-Alt", Weight = 3, Category = PortRiskCategory.Low, Description = "HTTPS备用端口" }
            };
        }

        /// <summary>
        /// 初始化端口风险权重
        /// </summary>
        private Dictionary<int, RiskWeight> InitializePortRiskWeights()
        {
            return new Dictionary<int, RiskWeight>
            {
                // 高风险端口
                [21] = new RiskWeight { Port = 21, Service = "FTP", Weight = 8, Category = PortRiskCategory.High, Description = "FTP明文传输，易被窃听" },
                [23] = new RiskWeight { Port = 23, Service = "Telnet", Weight = 10, Category = PortRiskCategory.Critical, Description = "Telnet明文传输，存在严重安全隐患" },
                [25] = new RiskWeight { Port = 25, Service = "SMTP", Weight = 6, Category = PortRiskCategory.Medium, Description = "邮件服务，可能存在垃圾邮件风险" },
                [53] = new RiskWeight { Port = 53, Service = "DNS", Weight = 5, Category = PortRiskCategory.Medium, Description = "DNS服务，可能存在DNS劫持风险" },
                [80] = new RiskWeight { Port = 80, Service = "HTTP", Weight = 6, Category = PortRiskCategory.Medium, Description = "明文HTTP，建议升级为HTTPS" },
                [110] = new RiskWeight { Port = 110, Service = "POP3", Weight = 6, Category = PortRiskCategory.Medium, Description = "邮件接收服务" },
                [135] = new RiskWeight { Port = 135, Service = "MSRPC", Weight = 8, Category = PortRiskCategory.High, Description = "Windows RPC，历史上存在多个漏洞" },
                [139] = new RiskWeight { Port = 139, Service = "NetBIOS", Weight = 8, Category = PortRiskCategory.High, Description = "NetBIOS服务，存在信息泄露风险" },
                [143] = new RiskWeight { Port = 143, Service = "IMAP", Weight = 6, Category = PortRiskCategory.Medium, Description = "邮件访问服务" },
                [445] = new RiskWeight { Port = 445, Service = "SMB", Weight = 9, Category = PortRiskCategory.Critical, Description = "SMB文件共享，历史上存在严重漏洞（如永恒之蓝）" },
                [1433] = new RiskWeight { Port = 1433, Service = "MSSQL", Weight = 8, Category = PortRiskCategory.High, Description = "SQL Server数据库，需加强访问控制" },
                [1521] = new RiskWeight { Port = 1521, Service = "Oracle", Weight = 8, Category = PortRiskCategory.High, Description = "Oracle数据库，需加强访问控制" },
                [3306] = new RiskWeight { Port = 3306, Service = "MySQL", Weight = 7, Category = PortRiskCategory.High, Description = "MySQL数据库，需加强访问控制" },
                [3389] = new RiskWeight { Port = 3389, Service = "RDP", Weight = 8, Category = PortRiskCategory.High, Description = "远程桌面，建议限制访问IP" },
                [5432] = new RiskWeight { Port = 5432, Service = "PostgreSQL", Weight = 7, Category = PortRiskCategory.High, Description = "PostgreSQL数据库" },
                [5900] = new RiskWeight { Port = 5900, Service = "VNC", Weight = 8, Category = PortRiskCategory.High, Description = "VNC远程桌面，注意弱密码风险" },
                [6379] = new RiskWeight { Port = 6379, Service = "Redis", Weight = 9, Category = PortRiskCategory.Critical, Description = "Redis缓存，默认无密码，风险极高" },
                [8080] = new RiskWeight { Port = 8080, Service = "HTTP-Proxy", Weight = 6, Category = PortRiskCategory.Medium, Description = "HTTP代理或备用HTTP端口" },
                [8443] = new RiskWeight { Port = 8443, Service = "HTTPS-Alt", Weight = 4, Category = PortRiskCategory.Low, Description = "HTTPS备用端口" },
                [9200] = new RiskWeight { Port = 9200, Service = "Elasticsearch", Weight = 7, Category = PortRiskCategory.High, Description = "Elasticsearch搜索服务" },
                [27017] = new RiskWeight { Port = 27017, Service = "MongoDB", Weight = 8, Category = PortRiskCategory.High, Description = "MongoDB数据库" }
            };
        }

        #region 自动从JSON数据获取评估

        /// <summary>
        /// 自动执行AI风险评估 - 从JSON数据获取端口扫描和漏洞数据
        /// </summary>
        /// <returns>AI风险评估报告</returns>
        public async Task<AIRiskAssessmentReport> PerformAutoRiskAssessmentAsync()
        {
            // 从JSON获取最新的端口扫描数据
            var portScanSession = await _portScanDataService.GetLatestPortScanResultsAsync();
            
            if (portScanSession == null)
            {
                Console.WriteLine("[AI风险评估] 未找到端口扫描数据");
                return new AIRiskAssessmentReport
                {
                    AssessmentTime = DateTime.Now,
                    OverallRiskLevel = RiskLevel.Info,
                    Summary = "未找到端口扫描数据，请先执行端口扫描",
                    RiskItems = new List<AIRiskItem>(),
                    Recommendations = new List<RiskRecommendation>()
                };
            }

            Console.WriteLine($"[AI风险评估] 找到端口扫描数据: 目标={portScanSession.TargetIp}, 总端口={portScanSession.TotalPorts}, 开放端口={portScanSession.OpenPorts}, 结果数量={portScanSession.PortScanResults?.Count ?? 0}");

            // 从JSON获取漏洞扫描数据（如果有的话）
            var vulnerabilityResults = await LoadVulnerabilityResultsFromJsonAsync(portScanSession.TargetIp);
            Console.WriteLine($"[AI风险评估] 漏洞扫描数据: {vulnerabilityResults?.Count ?? 0} 个漏洞");

            // 执行综合风险评估
            var report = await AssessRiskAsync(portScanSession.PortScanResults, vulnerabilityResults);
            Console.WriteLine($"[AI风险评估] 评估完成: 风险评分={report.RiskScore:F1}, 风险等级={report.OverallRiskLevel}, 风险项数量={report.RiskItems.Count}");
            
            return report;
        }

        /// <summary>
        /// 根据扫描会话ID执行AI风险评估
        /// </summary>
        /// <param name="sessionId">端口扫描会话ID</param>
        /// <returns>AI风险评估报告</returns>
        public async Task<AIRiskAssessmentReport> PerformRiskAssessmentBySessionIdAsync(string sessionId)
        {
            var portScanSession = await _portScanDataService.GetPortScanResultsAsync(sessionId);
            
            if (portScanSession == null)
            {
                return new AIRiskAssessmentReport
                {
                    AssessmentTime = DateTime.Now,
                    OverallRiskLevel = RiskLevel.Info,
                    Summary = $"未找到扫描会话: {sessionId}",
                    RiskItems = new List<AIRiskItem>(),
                    Recommendations = new List<RiskRecommendation>()
                };
            }

            var vulnerabilityResults = await LoadVulnerabilityResultsFromJsonAsync(portScanSession.TargetIp);
            return await AssessRiskAsync(portScanSession.PortScanResults, vulnerabilityResults);
        }

        /// <summary>
        /// 根据目标IP执行AI风险评估
        /// </summary>
        /// <param name="targetIp">目标IP</param>
        /// <returns>AI风险评估报告</returns>
        public async Task<AIRiskAssessmentReport> PerformRiskAssessmentByTargetIpAsync(string targetIp)
        {
            var portScanSessions = await _portScanDataService.GetPortScanResultsByTargetAsync(targetIp);
            
            if (!portScanSessions.Any())
            {
                return new AIRiskAssessmentReport
                {
                    AssessmentTime = DateTime.Now,
                    OverallRiskLevel = RiskLevel.Info,
                    Summary = $"未找到目标 {targetIp} 的端口扫描数据",
                    RiskItems = new List<AIRiskItem>(),
                    Recommendations = new List<RiskRecommendation>()
                };
            }

            // 使用最新的扫描结果
            var latestSession = portScanSessions.OrderByDescending(s => s.ScanTime).First();
            var vulnerabilityResults = await LoadVulnerabilityResultsFromJsonAsync(targetIp);
            
            return await AssessRiskAsync(latestSession.PortScanResults, vulnerabilityResults);
        }

        /// <summary>
        /// 从JSON文件加载漏洞扫描结果
        /// </summary>
        /// <param name="targetIp">目标IP</param>
        /// <returns>漏洞扫描结果列表</returns>
        private async Task<List<VulnerabilityResult>> LoadVulnerabilityResultsFromJsonAsync(string targetIp)
        {
            try
            {
                string appDataPath = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
                string vulnDirectory = Path.Combine(appDataPath, "NetSecurityScanner", "Data", "Vulnerabilities");
                
                if (!Directory.Exists(vulnDirectory))
                {
                    return new List<VulnerabilityResult>();
                }

                // 查找目标IP对应的漏洞扫描结果文件
                var vulnFiles = Directory.GetFiles(vulnDirectory, $"vuln_{targetIp.Replace(".", "_")}_*.json")
                    .OrderByDescending(f => File.GetLastWriteTime(f));

                if (!vulnFiles.Any())
                {
                    // 尝试查找最新的漏洞扫描文件
                    var latestFile = Directory.GetFiles(vulnDirectory, "vuln_*.json")
                        .OrderByDescending(f => File.GetLastWriteTime(f))
                        .FirstOrDefault();
                    
                    if (latestFile == null)
                    {
                        return new List<VulnerabilityResult>();
                    }

                    string json = await File.ReadAllTextAsync(latestFile);
                    return JsonSerializer.Deserialize<List<VulnerabilityResult>>(json, _jsonOptions) ?? new List<VulnerabilityResult>();
                }

                string latestVulnJson = await File.ReadAllTextAsync(vulnFiles.First());
                return JsonSerializer.Deserialize<List<VulnerabilityResult>>(latestVulnJson, _jsonOptions) ?? new List<VulnerabilityResult>();
            }
            catch (Exception ex)
            {
                Console.WriteLine($"加载漏洞扫描结果失败: {ex.Message}");
                return new List<VulnerabilityResult>();
            }
        }

        /// <summary>
        /// 保存漏洞扫描结果到JSON文件
        /// </summary>
        /// <param name="targetIp">目标IP</param>
        /// <param name="vulnerabilityResults">漏洞扫描结果</param>
        /// <returns>是否保存成功</returns>
        public async Task<bool> SaveVulnerabilityResultsAsync(string targetIp, List<VulnerabilityResult> vulnerabilityResults)
        {
            try
            {
                string appDataPath = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
                string vulnDirectory = Path.Combine(appDataPath, "NetSecurityScanner", "Data", "Vulnerabilities");
                Directory.CreateDirectory(vulnDirectory);

                string timestamp = DateTime.Now.ToString("yyyyMMdd_HHmmss");
                string safeIp = targetIp.Replace(".", "_");
                string fileName = $"vuln_{safeIp}_{timestamp}.json";
                string filePath = Path.Combine(vulnDirectory, fileName);

                string json = JsonSerializer.Serialize(vulnerabilityResults, _jsonOptions);
                await File.WriteAllTextAsync(filePath, json);

                // 同时保存为最新文件
                string latestFilePath = Path.Combine(vulnDirectory, "latest_vulnerability_scan.json");
                await File.WriteAllTextAsync(latestFilePath, json);

                return true;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"保存漏洞扫描结果失败: {ex.Message}");
                return false;
            }
        }

        #endregion

        /// <summary>
        /// 执行AI风险评估
        /// </summary>
        public async Task<AIRiskAssessmentReport> AssessRiskAsync(List<PortScanResult> portScanResults, List<VulnerabilityResult> vulnerabilities = null)
        {
            var report = new AIRiskAssessmentReport
            {
                AssessmentTime = DateTime.Now,
                PortStatistics = new PortRiskStatistics(),
                RiskItems = new List<AIRiskItem>(),
                Recommendations = new List<RiskRecommendation>()
            };

            if (portScanResults == null || !portScanResults.Any())
            {
                report.OverallRiskLevel = RiskLevel.Info;
                report.Summary = "未检测到开放端口，无法进行评估";
                return report;
            }

            // 分析端口风险
            var portAnalysis = AnalyzePortRisks(portScanResults);
            report.PortStatistics = portAnalysis.Statistics;
            report.RiskItems.AddRange(portAnalysis.RiskItems);

            // 分析漏洞风险
            if (vulnerabilities != null && vulnerabilities.Any())
            {
                var vulnAnalysis = AnalyzeVulnerabilityRisks(vulnerabilities);
                report.RiskItems.AddRange(vulnAnalysis.RiskItems);
                report.VulnerabilityCount = vulnerabilities.Count;
            }

            // 计算综合风险评分
            report.RiskScore = CalculateRiskScore(report.RiskItems, portScanResults.Count);
            report.OverallRiskLevel = DetermineRiskLevel(report.RiskScore);

            // 生成评估摘要
            report.Summary = GenerateSummary(report, portScanResults);

            // 生成修复建议
            report.Recommendations = GenerateRecommendations(report.RiskItems);

            return report;
        }

        /// <summary>
        /// 分析端口风险
        /// </summary>
        private PortRiskAnalysis AnalyzePortRisks(List<PortScanResult> portScanResults)
        {
            var analysis = new PortRiskAnalysis
            {
                Statistics = new PortRiskStatistics(),
                RiskItems = new List<AIRiskItem>()
            };

            // 处理各种开放状态：开放、开放或过滤
            var openPorts = portScanResults.Where(p => 
                p.Status == "开放" || 
                p.Status == "开放或过滤" ||
                p.Status.Contains("开放")
            ).ToList();
            
            analysis.Statistics.TotalPortsScanned = portScanResults.Count;
            analysis.Statistics.OpenPortsCount = openPorts.Count;

            foreach (var port in openPorts)
            {
                var riskItem = AssessPortRisk(port);
                analysis.RiskItems.Add(riskItem);

                // 统计风险等级
                switch (riskItem.RiskLevel)
                {
                    case RiskLevel.Critical:
                        analysis.Statistics.CriticalPortsCount++;
                        break;
                    case RiskLevel.High:
                        analysis.Statistics.HighRiskPortsCount++;
                        break;
                    case RiskLevel.Medium:
                        analysis.Statistics.MediumRiskPortsCount++;
                        break;
                    case RiskLevel.Low:
                        analysis.Statistics.LowRiskPortsCount++;
                        break;
                }

                // 按服务类型统计
                var serviceType = GetServiceType(port.PortNumber);
                if (!analysis.Statistics.ServiceTypeDistribution.ContainsKey(serviceType))
                    analysis.Statistics.ServiceTypeDistribution[serviceType] = 0;
                analysis.Statistics.ServiceTypeDistribution[serviceType]++;
            }

            // 识别风险模式
            analysis.Statistics.RiskPatterns = IdentifyRiskPatterns(openPorts);

            return analysis;
        }

        /// <summary>
        /// 评估单个端口风险
        /// 增强版算法：综合考虑端口号、服务类型、已知漏洞
        /// </summary>
        private AIRiskItem AssessPortRisk(PortScanResult port)
        {
            var riskItem = new AIRiskItem
            {
                Type = RiskItemType.Port,
                Target = $"{port.TargetIp}:{port.PortNumber}",
                Title = $"开放端口: {port.PortNumber} ({port.Service})",
                Details = new Dictionary<string, string>
                {
                    ["IP地址"] = port.TargetIp,
                    ["端口"] = port.PortNumber.ToString(),
                    ["服务"] = port.Service,
                    ["版本"] = string.IsNullOrEmpty(port.ServiceVersion) ? "未知" : port.ServiceVersion,
                    ["响应时间"] = port.ResponseTime
                }
            };

            double baseScore = 0;

            // 1. 根据端口号判断风险（最高权重）
            if (_portRiskWeights.TryGetValue(port.PortNumber, out var portWeight))
            {
                baseScore = portWeight.Weight * 0.6; // 端口风险占60%
            }

            // 2. 根据服务类型判断风险
            if (!string.IsNullOrEmpty(port.Service))
            {
                var serviceName = port.Service.ToLower().Split(' ')[0]; // 取服务名称的第一个词
                if (_serviceRiskWeights.TryGetValue(serviceName, out var serviceWeight))
                {
                    baseScore = Math.Max(baseScore, serviceWeight.Weight * 0.4); // 服务风险占40%
                    
                    if (string.IsNullOrEmpty(riskItem.Description) || riskItem.Description.Contains("未知服务"))
                    {
                        riskItem.Description = serviceWeight.Description;
                    }
                }
            }

            // 3. 检查是否存在已知漏洞
            var knownVulns = CheckKnownVulnerabilities(port);
            if (knownVulns.Any())
            {
                double vulnBonus = knownVulns.Sum(v => v.Severity switch
                {
                    "Critical" => 2.0,
                    "High" => 1.5,
                    "Medium" => 1.0,
                    "Low" => 0.5,
                    _ => 0.5
                });
                baseScore = Math.Min(10, baseScore + vulnBonus);
                riskItem.Description += $" [发现{knownVulns.Count}个已知漏洞]";
                riskItem.RelatedVulnerabilities = knownVulns;
            }

            // 4. 版本信息缺失惩罚
            if (string.IsNullOrEmpty(port.ServiceVersion) || port.ServiceVersion == "unknown")
            {
                baseScore += 0.5; // 版本未知增加0.5分
            }

            riskItem.RiskScore = Math.Min(10, baseScore);
            riskItem.RiskLevel = DetermineRiskLevel(riskItem.RiskScore);
            riskItem.CVSSScore = riskItem.RiskScore;

            return riskItem;
        }

        /// <summary>
        /// 分析漏洞风险
        /// 使用增强的严重性评分：Critical=10, High=7, Medium=5, Low=2
        /// </summary>
        private VulnerabilityRiskAnalysis AnalyzeVulnerabilityRisks(List<VulnerabilityResult> vulnerabilities)
        {
            var analysis = new VulnerabilityRiskAnalysis
            {
                RiskItems = new List<AIRiskItem>()
            };

            foreach (var vuln in vulnerabilities)
            {
                // 使用增强的严重性评分
                double cvssScore = _vulnerabilitySeverityScores.GetValueOrDefault(vuln.RiskLevel, 5.0);

                var riskItem = new AIRiskItem
                {
                    Type = RiskItemType.Vulnerability,
                    Target = vuln.Target,
                    Title = vuln.Name,
                    Description = vuln.Description,
                    RiskScore = cvssScore,
                    RiskLevel = DetermineRiskLevelFromCVSS(cvssScore),
                    CVSSScore = cvssScore,
                    Details = new Dictionary<string, string>
                    {
                        ["目标"] = vuln.Target,
                        ["端口"] = vuln.Port?.ToString() ?? "N/A",
                        ["严重程度"] = vuln.RiskLevel,
                        ["CVSS评分"] = cvssScore.ToString("F1"),
                        ["解决方案"] = vuln.Solution
                    }
                };

                analysis.RiskItems.Add(riskItem);
            }

            return analysis;
        }

        /// <summary>
        /// 检查已知漏洞
        /// </summary>
        private List<VulnerabilityInfo> CheckKnownVulnerabilities(PortScanResult port)
        {
            var vulns = new List<VulnerabilityInfo>();

            // 基于端口和服务的已知漏洞数据库
            var knownVulns = new Dictionary<int, List<VulnerabilityInfo>>
            {
                [445] = new List<VulnerabilityInfo>
                {
                    new VulnerabilityInfo { CVE = "CVE-2017-0144", Name = "永恒之蓝", Severity = "Critical", Description = "SMB远程代码执行漏洞" }
                },
                [3389] = new List<VulnerabilityInfo>
                {
                    new VulnerabilityInfo { CVE = "CVE-2019-0708", Name = "BlueKeep", Severity = "Critical", Description = "RDP远程代码执行漏洞" }
                },
                [6379] = new List<VulnerabilityInfo>
                {
                    new VulnerabilityInfo { CVE = "N/A", Name = "未授权访问", Severity = "High", Description = "Redis默认无密码保护" }
                }
            };

            if (knownVulns.TryGetValue(port.PortNumber, out var portVulns))
            {
                vulns.AddRange(portVulns);
            }

            return vulns;
        }

        /// <summary>
        /// 识别风险模式
        /// </summary>
        private List<string> IdentifyRiskPatterns(List<PortScanResult> openPorts)
        {
            var patterns = new List<string>();
            var portNumbers = openPorts.Select(p => p.PortNumber).ToList();

            // 检查数据库暴露
            var dbPorts = new[] { 1433, 1521, 3306, 5432, 6379, 27017, 9200 };
            if (portNumbers.Any(p => dbPorts.Contains(p)))
            {
                patterns.Add("数据库服务直接暴露于公网");
            }

            // 检查远程管理端口
            var remotePorts = new[] { 22, 23, 3389, 5900 };
            if (portNumbers.Any(p => remotePorts.Contains(p)))
            {
                patterns.Add("远程管理服务暴露，存在暴力破解风险");
            }

            // 检查文件共享
            if (portNumbers.Contains(445) || portNumbers.Contains(139))
            {
                patterns.Add("SMB文件共享服务暴露");
            }

            // 检查明文协议
            var plainTextPorts = new[] { 21, 23, 25, 80, 110 };
            if (portNumbers.Any(p => plainTextPorts.Contains(p)))
            {
                patterns.Add("存在明文传输协议，数据可能被窃听");
            }

            // 检查高风险组合
            if (portNumbers.Contains(445) && portNumbers.Contains(3389))
            {
                patterns.Add("同时暴露SMB和RDP，攻击面较大");
            }

            return patterns;
        }

        /// <summary>
        /// 计算风险评分
        /// 增强版算法：综合考虑漏洞数量、服务类型、高危端口数量
        /// </summary>
        private double CalculateRiskScore(List<AIRiskItem> riskItems, int totalPorts)
        {
            if (!riskItems.Any()) return 0;

            // 1. 计算加权平均风险评分（占60%权重）
            var criticalCount = riskItems.Count(r => r.RiskLevel == RiskLevel.Critical);
            var highCount = riskItems.Count(r => r.RiskLevel == RiskLevel.High);
            var mediumCount = riskItems.Count(r => r.RiskLevel == RiskLevel.Medium);
            var lowCount = riskItems.Count(r => r.RiskLevel == RiskLevel.Low);

            // 加权评分：Critical=10, High=7, Medium=5, Low=2
            var weightedSum = (criticalCount * 10.0) + (highCount * 7.0) + 
                             (mediumCount * 5.0) + (lowCount * 2.0);
            var weightedAvg = weightedSum / riskItems.Count;

            // 2. 风险项数量因子（占20%权重）
            // 开放端口越多，攻击面越大
            var countFactor = Math.Min(1.5, 1 + (riskItems.Count / (double)totalPorts));

            // 3. 高危端口集中度因子（占20%权重）
            // 同时存在多个高危端口会增加整体风险
            var criticalFactor = 1.0 + (criticalCount * 0.2) + (highCount * 0.1);

            // 综合评分
            var baseScore = weightedAvg * countFactor * criticalFactor;

            // 限制在0-10范围内
            return Math.Min(10.0, Math.Max(0.0, baseScore));
        }

        /// <summary>
        /// 确定风险等级
        /// </summary>
        private RiskLevel DetermineRiskLevel(double score)
        {
            return score switch
            {
                >= 9.0 => RiskLevel.Critical,
                >= 7.0 => RiskLevel.High,
                >= 4.0 => RiskLevel.Medium,
                >= 1.0 => RiskLevel.Low,
                _ => RiskLevel.Info
            };
        }

        /// <summary>
        /// 从CVSS分数确定风险等级
        /// </summary>
        private RiskLevel DetermineRiskLevelFromCVSS(double cvss)
        {
            return cvss switch
            {
                >= 9.0 => RiskLevel.Critical,
                >= 7.0 => RiskLevel.High,
                >= 4.0 => RiskLevel.Medium,
                >= 0.1 => RiskLevel.Low,
                _ => RiskLevel.Info
            };
        }

        /// <summary>
        /// 获取服务类型
        /// </summary>
        private string GetServiceType(int port)
        {
            return port switch
            {
                21 or 22 or 23 => "远程管理",
                25 or 110 or 143 => "邮件服务",
                53 => "DNS服务",
                80 or 443 or 8080 or 8443 => "Web服务",
                135 or 139 or 445 => "文件共享",
                1433 or 1521 or 3306 or 5432 or 6379 or 27017 => "数据库",
                3389 or 5900 => "远程桌面",
                _ => "其他服务"
            };
        }

        /// <summary>
        /// 生成评估摘要
        /// </summary>
        private string GenerateSummary(AIRiskAssessmentReport report, List<PortScanResult> portScanResults)
        {
            var summary = $"扫描目标: {portScanResults.FirstOrDefault()?.TargetIp ?? "未知"}\n";
            summary += $"扫描端口数: {report.PortStatistics.TotalPortsScanned}\n";
            summary += $"开放端口数: {report.PortStatistics.OpenPortsCount}\n";
            summary += $"风险评分: {report.RiskScore:F1}/10\n";
            summary += $"风险等级: {GetRiskLevelText(report.OverallRiskLevel)}\n\n";

            if (report.PortStatistics.RiskPatterns.Any())
            {
                summary += "发现的风险模式:\n";
                foreach (var pattern in report.PortStatistics.RiskPatterns)
                {
                    summary += $"  • {pattern}\n";
                }
            }

            return summary;
        }

        /// <summary>
        /// 生成修复建议
        /// </summary>
        private List<RiskRecommendation> GenerateRecommendations(List<AIRiskItem> riskItems)
        {
            var recommendations = new List<RiskRecommendation>();

            foreach (var item in riskItems.Where(r => r.RiskLevel >= RiskLevel.Medium))
            {
                var recommendation = new RiskRecommendation
                {
                    Target = item.Target,
                    Priority = item.RiskLevel switch
                    {
                        RiskLevel.Critical => RecommendationPriority.Immediate,
                        RiskLevel.High => RecommendationPriority.High,
                        RiskLevel.Medium => RecommendationPriority.Medium,
                        _ => RecommendationPriority.Low
                    },
                    Title = $"修复: {item.Title}",
                    Description = GenerateRecommendationDescription(item),
                    ActionSteps = GenerateActionSteps(item)
                };

                recommendations.Add(recommendation);
            }

            return recommendations.OrderBy(r => r.Priority).ToList();
        }

        /// <summary>
        /// 生成建议描述
        /// </summary>
        private string GenerateRecommendationDescription(AIRiskItem item)
        {
            return item.Type switch
            {
                RiskItemType.Port => $"端口{item.Details["端口"]} ({item.Details["服务"]})存在安全风险: {item.Description}",
                RiskItemType.Vulnerability => $"发现漏洞: {item.Title} - {item.Description}",
                _ => item.Description
            };
        }

        /// <summary>
        /// 生成操作步骤
        /// </summary>
        private List<string> GenerateActionSteps(AIRiskItem item)
        {
            var steps = new List<string>();

            if (item.Type == RiskItemType.Port)
            {
                var port = int.Parse(item.Details["端口"]);

                steps.Add($"1. 评估端口{port}的业务必要性");
                steps.Add($"2. 如非必要，关闭该端口");
                steps.Add($"3. 如必须使用，配置防火墙限制访问IP");
                steps.Add($"4. 启用该服务的最新安全特性");

                if (port == 21) steps.Add("5. 考虑使用SFTP替代FTP");
                if (port == 23) steps.Add("5. 立即禁用Telnet，改用SSH");
                if (port == 80) steps.Add("5. 配置HTTPS重定向");
                if (port == 3389) steps.Add("5. 启用网络级身份验证(NLA)");
                if (port == 445) steps.Add("5. 禁用SMBv1，启用SMB签名");
            }
            else if (item.Type == RiskItemType.Vulnerability)
            {
                steps.Add("1. 确认漏洞影响范围");
                steps.Add($"2. 应用官方补丁: {item.Details["解决方案"]}");
                steps.Add("3. 验证修复效果");
                steps.Add("4. 监控相关日志");
            }

            return steps;
        }

        /// <summary>
        /// 获取风险等级文本
        /// </summary>
        private string GetRiskLevelText(RiskLevel level)
        {
            return level switch
            {
                RiskLevel.Critical => "🔴 严重",
                RiskLevel.High => "🟠 高危",
                RiskLevel.Medium => "🟡 中危",
                RiskLevel.Low => "🟢 低危",
                _ => "⚪ 信息"
            };
        }

        /// <summary>
        /// 导出风险评估报告为JSON
        /// </summary>
        public async Task<string> ExportReportAsJsonAsync(AIRiskAssessmentReport report)
        {
            return await Task.Run(() => JsonSerializer.Serialize(report, _jsonOptions));
        }

        /// <summary>
        /// 保存风险评估报告到文件
        /// </summary>
        public async Task<bool> SaveReportToFileAsync(AIRiskAssessmentReport report, string filePath)
        {
            try
            {
                string json = await ExportReportAsJsonAsync(report);
                await File.WriteAllTextAsync(filePath, json);
                return true;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"保存风险评估报告失败: {ex.Message}");
                return false;
            }
        }
    }

    #region 数据模型

    /// <summary>
    /// AI风险评估报告
    /// </summary>
    public class AIRiskAssessmentReport
    {
        public DateTime AssessmentTime { get; set; }
        public double RiskScore { get; set; }
        public RiskLevel OverallRiskLevel { get; set; }
        public string Summary { get; set; } = "";
        public PortRiskStatistics PortStatistics { get; set; } = new();
        public int VulnerabilityCount { get; set; }
        public List<AIRiskItem> RiskItems { get; set; } = new();
        public List<RiskRecommendation> Recommendations { get; set; } = new();
    }

    /// <summary>
    /// 端口风险统计
    /// </summary>
    public class PortRiskStatistics
    {
        public int TotalPortsScanned { get; set; }
        public int OpenPortsCount { get; set; }
        public int CriticalPortsCount { get; set; }
        public int HighRiskPortsCount { get; set; }
        public int MediumRiskPortsCount { get; set; }
        public int LowRiskPortsCount { get; set; }
        public Dictionary<string, int> ServiceTypeDistribution { get; set; } = new();
        public List<string> RiskPatterns { get; set; } = new();
    }

    /// <summary>
    /// AI风险项
    /// </summary>
    public class AIRiskItem
    {
        public RiskItemType Type { get; set; }
        public string Target { get; set; } = "";
        public string Title { get; set; } = "";
        public string Description { get; set; } = "";
        public double RiskScore { get; set; }
        public RiskLevel RiskLevel { get; set; }
        public double CVSSScore { get; set; }
        public Dictionary<string, string> Details { get; set; } = new();
        public List<VulnerabilityInfo> RelatedVulnerabilities { get; set; } = new();
    }

    /// <summary>
    /// 风险建议
    /// </summary>
    public class RiskRecommendation
    {
        public string Target { get; set; } = "";
        public RecommendationPriority Priority { get; set; }
        public string Title { get; set; } = "";
        public string Description { get; set; } = "";
        public List<string> ActionSteps { get; set; } = new();
    }

    /// <summary>
    /// 风险权重
    /// </summary>
    public class RiskWeight
    {
        public int Port { get; set; }
        public string Service { get; set; } = "";
        public int Weight { get; set; }
        public PortRiskCategory Category { get; set; }
        public string Description { get; set; } = "";
    }

    /// <summary>
    /// 服务类型风险权重
    /// </summary>
    public class ServiceRiskWeight
    {
        public string ServiceName { get; set; } = "";
        public int Weight { get; set; }
        public PortRiskCategory Category { get; set; }
        public string Description { get; set; } = "";
    }

    /// <summary>
    /// 漏洞信息
    /// </summary>
    public class VulnerabilityInfo
    {
        public string CVE { get; set; } = "";
        public string Name { get; set; } = "";
        public string Severity { get; set; } = "";
        public string Description { get; set; } = "";
    }

    /// <summary>
    /// 端口风险分析
    /// </summary>
    public class PortRiskAnalysis
    {
        public PortRiskStatistics Statistics { get; set; } = new();
        public List<AIRiskItem> RiskItems { get; set; } = new();
    }

    /// <summary>
    /// 漏洞风险分析
    /// </summary>
    public class VulnerabilityRiskAnalysis
    {
        public List<AIRiskItem> RiskItems { get; set; } = new();
    }

    /// <summary>
    /// 端口风险类别
    /// </summary>
    public enum PortRiskCategory
    {
        Low,
        Medium,
        High,
        Critical
    }

    /// <summary>
    /// 风险项类型
    /// </summary>
    public enum RiskItemType
    {
        Port,
        Vulnerability,
        Configuration
    }

    /// <summary>
    /// 建议优先级
    /// </summary>
    public enum RecommendationPriority
    {
        Low,
        Medium,
        High,
        Immediate
    }

    #endregion
}
