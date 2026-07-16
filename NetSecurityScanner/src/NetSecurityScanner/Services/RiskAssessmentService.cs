using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using NetSecurityScanner.Models;

namespace NetSecurityScanner.Services
{
    public class RiskAssessmentService
    {
        /// <summary>
        /// 评估漏洞风险（专家级）
        /// </summary>
        /// <param name="vulnerabilities">漏洞扫描结果</param>
        /// <param name="openPorts">开放端口列表（可选）</param>
        /// <param name="targetIp">目标IP地址</param>
        /// <returns>风险评估结果</returns>
        public RiskAssessmentResult AssessRiskExpert(List<VulnerabilityResult> vulnerabilities, List<PortScanResult> openPorts = null, string targetIp = "")
        {
            var result = new RiskAssessmentResult();
            
            // 初始化开放端口列表（如果为null）
            openPorts ??= new List<PortScanResult>();
            
            // 设置基本信息
            result.AssessmentTime = DateTime.Now;
            result.TargetIp = targetIp;
            result.OpenPorts = openPorts;
            
            // 敏感开放端口识别
            result.SensitiveOpenPorts = openPorts.Where(p => IsSensitivePort(p.PortNumber)).ToList();
            
            if (vulnerabilities == null || !vulnerabilities.Any())
            {
                // 无漏洞情况
                result.Statistics = new RiskStatistics();
                result.OverallRiskLevel = "无风险";
                result.TotalRiskScore = 0;
                result.SecurityAdvice = "系统安全状况良好，建议定期进行安全扫描和端口检查";
                
                result.RiskDistribution.Add(new RiskCategory { Category = "无风险", Count = 0, Score = 0, Description = "未发现安全漏洞" });
                return result;
            }
            
            // 按风险等级统计
            int highRiskCount = vulnerabilities.Count(v => v.RiskLevel == "高");
            int mediumRiskCount = vulnerabilities.Count(v => v.RiskLevel == "中");
            int lowRiskCount = vulnerabilities.Count(v => v.RiskLevel == "低");
            int totalVulnerabilities = vulnerabilities.Count;
            int uniqueVulnerabilityTypes = vulnerabilities.Select(v => v.Name).Distinct().Count();
            
            // 计算敏感端口数
            int sensitivePortCount = result.SensitiveOpenPorts.Count;
            int totalOpenPorts = openPorts.Count;
            
            // 转换为漏洞详情
            result.VulnerabilityDetails = vulnerabilities.Select(v => ConvertToVulnerabilityDetail(v)).ToList();
            
            // 计算平均CVSS分数
            double averageCvssScore = result.VulnerabilityDetails.Average(vd => vd.CvssScore);
            
            // 构建统计信息
            result.Statistics = new RiskStatistics
            {
                TotalVulnerabilities = totalVulnerabilities,
                HighRiskCount = highRiskCount,
                MediumRiskCount = mediumRiskCount,
                LowRiskCount = lowRiskCount,
                TotalOpenPorts = totalOpenPorts,
                SensitivePortCount = sensitivePortCount,
                UniqueVulnerabilityTypes = uniqueVulnerabilityTypes,
                AverageCvssScore = averageCvssScore
            };
            
            // 计算总体风险评分（基于CVSS和端口风险）
            result.TotalRiskScore = CalculateTotalRiskScore(vulnerabilities, openPorts);
            
            // 确定总体风险等级
            result.OverallRiskLevel = DetermineOverallRiskLevel(result.TotalRiskScore, highRiskCount, mediumRiskCount, lowRiskCount);
            
            // 构建风险分布
            result.RiskDistribution = BuildRiskDistribution(vulnerabilities);
            
            // 生成安全建议
            result.SecurityAdvice = GenerateSecurityAdvice(vulnerabilities, openPorts);
            
            return result;
        }
        
        /// <summary>
        /// 旧版风险评估方法（保持兼容性）
        /// </summary>
        /// <param name="vulnerabilities">漏洞扫描结果</param>
        /// <param name="openPorts">开放端口列表（可选）</param>
        /// <returns>风险评估结果</returns>
        public List<RiskAssessmentItem> AssessRisk(List<VulnerabilityResult> vulnerabilities, List<PortScanResult> openPorts = null)
        {
            var assessmentItems = new List<RiskAssessmentItem>();
            
            // 初始化开放端口列表（如果为null）
            openPorts ??= new List<PortScanResult>();
            
            if (vulnerabilities == null || !vulnerabilities.Any())
            {
                assessmentItems.Add(new RiskAssessmentItem
                {
                    Item = "总体安全状况",
                    Value = "无风险",
                    Status = "安全"
                });
                return assessmentItems;
            }
            
            // 按风险等级统计
            int highRiskCount = vulnerabilities.Count(v => v.RiskLevel == "高");
            int mediumRiskCount = vulnerabilities.Count(v => v.RiskLevel == "中");
            int lowRiskCount = vulnerabilities.Count(v => v.RiskLevel == "低");
            
            // 计算总体风险评分 - 改进的算法，考虑漏洞的严重性权重和数量
            double totalRiskScore = CalculateTotalRiskScore(vulnerabilities, openPorts);
            
            // 计算风险百分比
            double maxPossibleScore = vulnerabilities.Count * 10 + openPorts.Count * 4.5;
            double riskPercentage = maxPossibleScore > 0 ? Math.Min(100, (totalRiskScore / maxPossibleScore) * 100) : 0;
            
            // 添加统计信息
            assessmentItems.Add(new RiskAssessmentItem
            {
                Item = "高风险漏洞",
                Value = highRiskCount.ToString(),
                Status = highRiskCount > 0 ? "危险" : "安全"
            });
            
            assessmentItems.Add(new RiskAssessmentItem
            {
                Item = "中风险漏洞",
                Value = mediumRiskCount.ToString(),
                Status = mediumRiskCount > 0 ? "警告" : "安全"
            });
            
            assessmentItems.Add(new RiskAssessmentItem
            {
                Item = "低风险漏洞",
                Value = lowRiskCount.ToString(),
                Status = lowRiskCount > 0 ? "注意" : "安全"
            });
            
            assessmentItems.Add(new RiskAssessmentItem
            {
                Item = "总漏洞数",
                Value = vulnerabilities.Count.ToString(),
                Status = vulnerabilities.Count > 10 ? "危险" : vulnerabilities.Count > 5 ? "警告" : vulnerabilities.Count > 0 ? "注意" : "安全"
            });
            
            assessmentItems.Add(new RiskAssessmentItem
            {
                Item = "开放端口总数",
                Value = openPorts.Count.ToString(),
                Status = openPorts.Count > 15 ? "危险" : openPorts.Count > 8 ? "警告" : openPorts.Count > 0 ? "注意" : "安全"
            });
            
            assessmentItems.Add(new RiskAssessmentItem
            {
                Item = "敏感开放端口",
                Value = openPorts.Count(p => IsSensitivePort(p.PortNumber)).ToString(),
                Status = openPorts.Count(p => IsSensitivePort(p.PortNumber)) > 5 ? "危险" : openPorts.Count(p => IsSensitivePort(p.PortNumber)) > 2 ? "警告" : openPorts.Count(p => IsSensitivePort(p.PortNumber)) > 0 ? "注意" : "安全"
            });
            
            // 根据风险评分确定总体风险等级
            string overallRiskLevel = DetermineOverallRiskLevel(totalRiskScore, highRiskCount, mediumRiskCount, lowRiskCount);
            
            assessmentItems.Add(new RiskAssessmentItem
            {
                Item = "总体风险等级",
                Value = overallRiskLevel,
                Status = overallRiskLevel
            });
            
            // 添加风险评分
            assessmentItems.Add(new RiskAssessmentItem
            {
                Item = "风险评分",
                Value = $"{totalRiskScore:F1} 分 ({riskPercentage:F1}%)",
                Status = GetRiskStatusFromScore(riskPercentage)
            });
            
            // 添加漏洞类型分布（按风险等级和数量）
            var vulnerabilityTypes = vulnerabilities
                .GroupBy(v => v.Name)
                .Select(g => new { 
                    Name = g.Key, 
                    Count = g.Count(), 
                    HighestRisk = g.Max(v => v.RiskLevel),
                    AverageRisk = CalculateAverageRiskLevel(g.ToList())
                })
                .OrderByDescending(x => x.HighestRisk == "高" ? 3 : x.HighestRisk == "中" ? 2 : 1)
                .ThenByDescending(x => x.Count)
                .Take(6); // 显示前6种最常见的漏洞类型
            
            foreach (var vulnType in vulnerabilityTypes)
            {
                assessmentItems.Add(new RiskAssessmentItem
                {
                    Item = $"漏洞类型: {vulnType.Name}",
                    Value = $"{vulnType.Count} 个 ({vulnType.AverageRisk})",
                    Status = vulnType.HighestRisk
                });
            }
            
            // 添加安全建议
            string securityAdvice = GenerateSecurityAdvice(vulnerabilities, openPorts);
            assessmentItems.Add(new RiskAssessmentItem
            {
                Item = "安全建议",
                Value = securityAdvice,
                Status = "建议"
            });
            
            return assessmentItems;
        }
        
        /// <summary>
        /// AI增强的风险评分算法 - 多维度风险评估
        /// </summary>
        private double CalculateTotalRiskScore(List<VulnerabilityResult> vulnerabilities, List<PortScanResult> openPorts)
        {
            double totalRisk = 0;
            
            // 维度1：漏洞基本风险（CVSS基础评分）
            double basicVulnerabilityRisk = 0;
            
            // 维度2：漏洞可利用性风险
            double exploitabilityRisk = 0;
            
            // 维度3：漏洞趋势风险
            double trendRisk = 0;
            
            // 维度4：开放端口风险
            double openPortRisk = 0;
            
            // 维度5：端口-漏洞关联风险
            double portVulnerabilityCorrelation = CalculatePortVulnerabilityCorrelation(vulnerabilities, openPorts);
            
            // 维度6：漏洞组合风险
            double combinationRisk = CalculateVulnerabilityCombinationRisk(vulnerabilities);
            
            // 维度7：敏感服务暴露风险
            double sensitiveServiceRisk = CalculateSensitiveServiceExposureRisk(openPorts);
            
            // 维度8：漏洞修复难度风险
            double remediationDifficultyRisk = CalculateRemediationDifficultyRisk(vulnerabilities);
            
            // 维度9：攻击面大小风险
            double attackSurfaceRisk = CalculateAttackSurfaceRisk(openPorts, vulnerabilities);
            
            // 详细计算每个维度的风险
            foreach (var vuln in vulnerabilities)
            {
                // 根据风险等级分配CVSS分数（模拟）
                double cvssScore = vuln.RiskLevel == "高" ? 8.5 : 
                                  vuln.RiskLevel == "中" ? 5.5 : 2.5;
                
                // 维度1.1：基于CVE的风险调整
                double cveFactor = 1.0;
                if (!string.IsNullOrEmpty(vuln.CveId))
                {
                    // 如果有CVE编号，增加风险因子（CVE漏洞通常经过验证，风险更可信）
                    cveFactor = 1.3;
                }
                
                // 维度1.2：基于漏洞描述的风险调整
                double descriptionFactor = 1.0;
                if (!string.IsNullOrEmpty(vuln.Description))
                {
                    // 如果描述中包含特定关键词，增加风险
                    var highRiskKeywords = new List<string> { "远程代码执行", "命令注入", "SQL注入", "身份验证绕过", "任意文件读取" };
                    if (highRiskKeywords.Any(keyword => vuln.Description.Contains(keyword, StringComparison.OrdinalIgnoreCase)))
                    {
                        descriptionFactor = 1.5;
                    }
                    
                    // 基于漏洞描述的长度和详细程度调整风险
                    // 描述越详细，说明漏洞被研究得越深入，风险更可信
                    if (vuln.Description.Length > 200)
                    {
                        descriptionFactor *= 1.2;
                    }
                }
                
                // 维度1.3：基于漏洞数据库信息的风险调整
                double databaseFactor = 1.0;
                
                // 检查漏洞描述中是否包含数据库信息（如发布日期、受影响产品等）
                if (!string.IsNullOrEmpty(vuln.Description))
                {
                    // 检查是否包含发布日期
                    if (vuln.Description.Contains("发布日期"))
                    {
                        // 新发布的漏洞通常风险更高
                        // 提取发布日期并计算时间差
                        var dateMatch = System.Text.RegularExpressions.Regex.Match(vuln.Description, @"发布日期: (\d{4}-\d{2}-\d{2})");
                        if (dateMatch.Success)
                        {
                            if (DateTime.TryParse(dateMatch.Groups[1].Value, out DateTime publishDate))
                            {
                                TimeSpan age = DateTime.Now - publishDate;
                                // 发布时间在30天内的漏洞，增加风险因子
                                if (age.TotalDays < 30)
                                {
                                    databaseFactor *= 1.4;
                                }
                                // 发布时间在90天内的漏洞，增加风险因子
                                else if (age.TotalDays < 90)
                                {
                                    databaseFactor *= 1.2;
                                }
                            }
                        }
                    }
                    
                    // 检查是否包含受影响产品
                    if (vuln.Description.Contains("受影响产品"))
                    {
                        // 受影响产品越多，风险可能越高
                        var productMatch = System.Text.RegularExpressions.Regex.Match(vuln.Description, @"受影响产品: ([^
]+)");
                        if (productMatch.Success)
                        {
                            string products = productMatch.Groups[1].Value;
                            int productCount = products.Split(',').Length;
                            if (productCount > 3)
                            {
                                databaseFactor *= 1.3;
                            }
                            else if (productCount > 1)
                            {
                                databaseFactor *= 1.1;
                            }
                        }
                    }
                }
                
                // 漏洞可利用性：基于风险等级和漏洞类型
                double exploitabilityFactor = vuln.RiskLevel == "高" ? 1.8 : 
                                            vuln.RiskLevel == "中" ? 1.2 : 0.8;
                
                // 考虑漏洞类型的可利用性
                exploitabilityFactor *= IsEasyToExploitVulnerabilityType(vuln.Name) ? 1.4 : 1.0;
                
                // 漏洞趋势风险：基于已知攻击趋势
                double trendFactor = IsCriticalVulnerabilityType(vuln.Name) ? 1.5 : 1.0;
                
                // 累计各维度风险，结合CVE、描述因子和数据库因子
                basicVulnerabilityRisk += cvssScore * 1.5 * cveFactor * descriptionFactor * databaseFactor;
                exploitabilityRisk += cvssScore * exploitabilityFactor * cveFactor * databaseFactor;
                trendRisk += cvssScore * trendFactor * cveFactor * databaseFactor;
            }
            
            // 计算开放端口风险
            int sensitivePortCount = openPorts.Count(p => IsSensitivePort(p.PortNumber));
            int totalOpenPorts = openPorts.Count;
            openPortRisk = (totalOpenPorts * 1.5) + (sensitivePortCount * 3);
            
            // 计算攻击面大小风险
            attackSurfaceRisk = Math.Sqrt(totalOpenPorts * 2 + vulnerabilities.Count * 3) * 2.5;
            
            // 应用AI权重调整 - 基于历史攻击数据和威胁情报
            double[] dimensionWeights = GetAiDimensionWeights(vulnerabilities, openPorts);
            
            // 综合所有维度的风险评分
            totalRisk = (
                basicVulnerabilityRisk * dimensionWeights[0] +
                exploitabilityRisk * dimensionWeights[1] +
                trendRisk * dimensionWeights[2] +
                openPortRisk * dimensionWeights[3] +
                portVulnerabilityCorrelation * dimensionWeights[4] +
                combinationRisk * dimensionWeights[5] +
                sensitiveServiceRisk * dimensionWeights[6] +
                remediationDifficultyRisk * dimensionWeights[7] +
                attackSurfaceRisk * dimensionWeights[8]
            );
            
            // 非线性风险增长因子 - 漏洞数量越多，风险增长越快
            if (vulnerabilities.Count > 5)
            {
                totalRisk *= 1 + (vulnerabilities.Count - 5) * 0.1; // 每多5个漏洞，风险增加10%
            }
            
            // 高风险漏洞额外惩罚
            int highRiskCount = vulnerabilities.Count(v => v.RiskLevel == "高");
            if (highRiskCount > 0)
            {
                totalRisk *= 1 + (highRiskCount * 0.2); // 每个高风险漏洞增加20%风险
            }
            
            // 基于CVE数量的额外惩罚
            int cveCount = vulnerabilities.Count(v => !string.IsNullOrEmpty(v.CveId));
            if (cveCount > 2)
            {
                totalRisk *= 1 + (cveCount - 2) * 0.15; // 每个CVE漏洞增加15%风险（超过2个后）
            }
            
            return totalRisk;
        }
        
        /// <summary>
        /// AI增强：检查是否为关键漏洞类型（基于已知攻击趋势）
        /// </summary>
        private bool IsCriticalVulnerabilityType(string vulnerabilityName)
        {
            // AI增强：基于已知的高危漏洞类型列表
            var criticalVulnerabilityTypes = new List<string>
            {
                "SQL注入", "远程代码执行", "命令注入", "跨站脚本", "身份验证绕过", 
                "缓冲区溢出", "信息泄露", "权限提升", "任意文件读取", "代码注入"
            };
            
            return criticalVulnerabilityTypes.Any(type => vulnerabilityName.Contains(type, StringComparison.OrdinalIgnoreCase));
        }
        
        /// <summary>
        /// AI增强：计算端口与漏洞的关联性风险
        /// </summary>
        private double CalculatePortVulnerabilityCorrelation(List<VulnerabilityResult> vulnerabilities, List<PortScanResult> openPorts)
        {
            double correlationRisk = 0;
            
            // AI增强：检查开放端口与发现的漏洞之间的关联性
            foreach (var port in openPorts)
            {
                // 检查是否有针对该端口的漏洞
                var portVulnerabilities = vulnerabilities.Where(v => v.Port == port.PortNumber).ToList();
                if (portVulnerabilities.Any())
                {
                    // 如果有针对该端口的漏洞，增加风险分数
                    correlationRisk += portVulnerabilities.Count * 2.5;
                }
            }
            
            return correlationRisk;
        }
        
        /// <summary>
        /// AI增强：计算漏洞组合风险
        /// </summary>
        private double CalculateVulnerabilityCombinationRisk(List<VulnerabilityResult> vulnerabilities)
        {
            double combinationRisk = 0;
            
            // AI增强：检查是否存在危险的漏洞组合
            var vulnTypes = vulnerabilities.Select(v => v.Name).ToList();
            
            // 示例：如果同时存在身份验证绕过和权限提升漏洞，风险更高
            if (vulnTypes.Any(v => v.Contains("身份验证绕过", StringComparison.OrdinalIgnoreCase)) &&
                vulnTypes.Any(v => v.Contains("权限提升", StringComparison.OrdinalIgnoreCase)))
            {
                combinationRisk += 15;
            }
            
            // 示例：如果同时存在SQL注入和信息泄露漏洞，风险更高
            if (vulnTypes.Any(v => v.Contains("SQL注入", StringComparison.OrdinalIgnoreCase)) &&
                vulnTypes.Any(v => v.Contains("信息泄露", StringComparison.OrdinalIgnoreCase)))
            {
                combinationRisk += 10;
            }
            
            // 示例：如果存在多个远程代码执行漏洞，风险更高
            int rceVulns = vulnTypes.Count(v => v.Contains("远程代码执行", StringComparison.OrdinalIgnoreCase));
            if (rceVulns > 1)
            {
                combinationRisk += rceVulns * 8;
            }
            
            return combinationRisk;
        }
        
        /// <summary>
        /// 转换为漏洞详情
        /// </summary>
        private VulnerabilityDetail ConvertToVulnerabilityDetail(VulnerabilityResult vuln)
        {
            // 根据风险等级分配CVSS分数（模拟）
            double cvssScore = vuln.RiskLevel == "高" ? 8.5 : 
                              vuln.RiskLevel == "中" ? 5.5 : 2.5;
            
            // 生成CVSS向量（模拟）
            string cvssVector = vuln.RiskLevel == "高" ? "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H" :
                               vuln.RiskLevel == "中" ? "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N" :
                               "CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:N/I:L/A:N";
            
            return new VulnerabilityDetail
            {
                IpAddress = string.Empty, // VulnerabilityResult没有TargetIp属性
                VulnerabilityName = vuln.Name,
                RiskLevel = vuln.RiskLevel,
                Port = vuln.Port ?? 0, // 将int?转换为int
                Service = vuln.Service,
                CveId = vuln.CveId,
                DetectionMethod = vuln.DetectionMethod,
                Description = vuln.Description,
                Solution = vuln.Solution,
                ReferenceLinks = vuln.References, // 使用References属性替代ReferenceLinks
                CvssScore = cvssScore,
                CvssVector = cvssVector,
                ImpactDescription = GenerateImpactDescription(vuln.RiskLevel),
                Exploitability = GenerateExploitability(vuln.RiskLevel)
            };
        }
        
        /// <summary>
        /// 生成影响描述
        /// </summary>
        private string GenerateImpactDescription(string riskLevel)
        {
            switch (riskLevel)
            {
                case "高":
                    return "可能导致系统完全控制、数据泄露或服务中断，对业务造成严重影响";
                case "中":
                    return "可能导致部分功能异常、信息泄露或服务降级，对业务造成中等影响";
                case "低":
                    return "可能导致轻微信息泄露或功能异常，对业务影响有限";
                default:
                    return "影响程度未知";
            }
        }
        
        /// <summary>
        /// 生成可利用性描述
        /// </summary>
        private string GenerateExploitability(string riskLevel)
        {
            switch (riskLevel)
            {
                case "高":
                    return "存在公开漏洞利用代码，攻击者可以轻松利用，无需特殊技能";
                case "中":
                    return "可能存在漏洞利用方法，需要一定的技术技能才能利用";
                case "低":
                    return "利用难度较高，需要特定条件或高级技术技能";
                default:
                    return "可利用性未知";
            }
        }
        
        /// <summary>
        /// 构建风险分布
        /// </summary>
        private List<RiskCategory> BuildRiskDistribution(List<VulnerabilityResult> vulnerabilities)
        {
            var distribution = new List<RiskCategory>();
            
            int highRiskCount = vulnerabilities.Count(v => v.RiskLevel == "高");
            int mediumRiskCount = vulnerabilities.Count(v => v.RiskLevel == "中");
            int lowRiskCount = vulnerabilities.Count(v => v.RiskLevel == "低");
            
            // 高风险分布
            if (highRiskCount > 0)
            {
                distribution.Add(new RiskCategory 
                {
                    Category = "高", 
                    Count = highRiskCount, 
                    Score = highRiskCount * 10, 
                    Description = "需要立即修复的严重安全漏洞，可能导致系统入侵、数据泄露等重大安全事件"
                });
            }
            
            // 中风险分布
            if (mediumRiskCount > 0)
            {
                distribution.Add(new RiskCategory 
                {
                    Category = "中", 
                    Count = mediumRiskCount, 
                    Score = mediumRiskCount * 5, 
                    Description = "需要优先修复的安全漏洞，在特定条件下可能被利用"
                });
            }
            
            // 低风险分布
            if (lowRiskCount > 0)
            {
                distribution.Add(new RiskCategory 
                {
                    Category = "低", 
                    Count = lowRiskCount, 
                    Score = lowRiskCount * 2, 
                    Description = "建议修复的安全漏洞，影响较小但可能被链利用"
                });
            }
            
            return distribution;
        }
        
        /// <summary>
        /// 计算总体风险等级
        /// </summary>
        /// <param name="totalRiskScore">总风险分数</param>
        /// <param name="highRiskCount">高风险漏洞数</param>
        /// <param name="mediumRiskCount">中风险漏洞数</param>
        /// <param name="lowRiskCount">低风险漏洞数</param>
        /// <returns>总体风险等级</returns>
        private string DetermineOverallRiskLevel(double totalRiskScore, int highRiskCount, int mediumRiskCount, int lowRiskCount)
        {
            // 优先级：高风险漏洞 > 总风险分数 > 中风险漏洞 > 低风险漏洞
            if (highRiskCount > 0)
            {
                return highRiskCount > 2 ? "严重" : "高";
            }
            
            if (totalRiskScore >= 30)
            {
                return "高";
            }
            
            if (totalRiskScore >= 15 || mediumRiskCount >= 3)
            {
                return "中";
            }
            
            if (lowRiskCount > 0 || totalRiskScore > 0)
            {
                return "低";
            }
            
            return "无风险";
        }
        
        /// <summary>
        /// 根据风险分数获取风险状态
        /// </summary>
        private string GetRiskStatusFromScore(double riskPercentage)
        {
            if (riskPercentage >= 70)
                return "严重";
            if (riskPercentage >= 40)
                return "高";
            if (riskPercentage >= 20)
                return "中";
            if (riskPercentage > 0)
                return "低";
            return "无风险";
        }
        
        /// <summary>
        /// 计算平均风险等级
        /// </summary>
        private string CalculateAverageRiskLevel(List<VulnerabilityResult> vulnerabilities)
        {
            if (!vulnerabilities.Any())
                return "无风险";
            
            double totalRisk = vulnerabilities.Sum(v => 
                v.RiskLevel == "高" ? 3 : 
                v.RiskLevel == "中" ? 2 : 1);
            double averageRisk = totalRisk / vulnerabilities.Count;
            
            if (averageRisk >= 2.5)
                return "高";
            if (averageRisk >= 1.5)
                return "中";
            return "低";
        }
        
        /// <summary>
        /// AI增强：检查漏洞是否容易被利用
        /// </summary>
        private bool IsEasyToExploitVulnerabilityType(string vulnerabilityName)
        {
            // 已知容易被利用的漏洞类型
            var easyToExploitTypes = new List<string>
            {
                "SQL注入", "命令注入", "远程代码执行", "跨站脚本", "身份验证绕过",
                "任意文件读取", "文件上传漏洞", "路径遍历", "缓冲区溢出"
            };
            
            return easyToExploitTypes.Any(type => vulnerabilityName.Contains(type, StringComparison.OrdinalIgnoreCase));
        }
        
        /// <summary>
        /// AI增强：计算敏感服务暴露风险
        /// </summary>
        private double CalculateSensitiveServiceExposureRisk(List<PortScanResult> openPorts)
        {
            double risk = 0;
            
            // 敏感服务列表及风险权重
            var sensitiveServices = new Dictionary<string, double>
            {
                { "ssh", 4.0 },
                { "ftp", 3.5 },
                { "telnet", 5.0 },
                { "smb", 4.5 },
                { "rdp", 4.0 },
                { "mysql", 3.5 },
                { "mssql", 3.5 },
                { "postgresql", 3.0 },
                { "redis", 4.0 },
                { "mongodb", 3.5 }
            };
            
            foreach (var port in openPorts)
            {
                if (port.Service != null)
                {
                    string serviceName = port.Service.ToLower();
                    foreach (var sensitiveService in sensitiveServices)
                    {
                        if (serviceName.Contains(sensitiveService.Key))
                        {
                            risk += sensitiveService.Value;
                            break;
                        }
                    }
                }
            }
            
            return risk;
        }
        
        /// <summary>
        /// AI增强：计算漏洞修复难度风险
        /// </summary>
        private double CalculateRemediationDifficultyRisk(List<VulnerabilityResult> vulnerabilities)
        {
            double risk = 0;
            
            foreach (var vuln in vulnerabilities)
            {
                // 基于漏洞类型和风险等级估算修复难度
                double difficultyFactor = vuln.RiskLevel == "高" ? 1.5 :
                                         vuln.RiskLevel == "中" ? 1.0 : 0.5;
                
                // 某些类型的漏洞修复难度更高
                if (vuln.Name.Contains("远程代码执行", StringComparison.OrdinalIgnoreCase) ||
                    vuln.Name.Contains("缓冲区溢出", StringComparison.OrdinalIgnoreCase))
                {
                    difficultyFactor *= 2.0;
                }
                else if (vuln.Name.Contains("配置错误", StringComparison.OrdinalIgnoreCase))
                {
                    difficultyFactor *= 0.5; // 配置错误通常容易修复
                }
                
                risk += difficultyFactor;
            }
            
            return risk;
        }
        
        /// <summary>
        /// AI增强：计算攻击面大小风险
        /// </summary>
        private double CalculateAttackSurfaceRisk(List<PortScanResult> openPorts, List<VulnerabilityResult> vulnerabilities)
        {
            // 攻击面大小基于开放端口数和漏洞数的组合
            int totalOpenPorts = openPorts.Count;
            int totalVulnerabilities = vulnerabilities.Count;
            int sensitivePortCount = openPorts.Count(p => IsSensitivePort(p.PortNumber));
            
            // 计算攻击面风险评分
            double risk = (totalOpenPorts * 0.5) + (totalVulnerabilities * 1.0) + (sensitivePortCount * 2.0);
            
            return risk;
        }
        
        /// <summary>
        /// AI增强：获取各维度风险的权重
        /// </summary>
        private double[] GetAiDimensionWeights(List<VulnerabilityResult> vulnerabilities, List<PortScanResult> openPorts)
        {
            // 基于当前扫描结果动态调整各维度的权重
            // 默认权重分配
            double[] weights = new double[] { 0.15, 0.20, 0.15, 0.10, 0.10, 0.15, 0.05, 0.05, 0.05 };
            
            // 如果存在高风险漏洞，增加可利用性和趋势风险的权重
            int highRiskCount = vulnerabilities.Count(v => v.RiskLevel == "高");
            if (highRiskCount > 0)
            {
                weights[1] += 0.10; // 增加可利用性风险权重
                weights[2] += 0.05; // 增加趋势风险权重
            }
            
            // 如果存在敏感服务暴露，增加端口风险权重
            int sensitivePortCount = openPorts.Count(p => IsSensitivePort(p.PortNumber));
            if (sensitivePortCount > 3)
            {
                weights[3] += 0.10; // 增加开放端口风险权重
                weights[6] += 0.05; // 增加敏感服务暴露风险权重
            }
            
            // 如果漏洞数量较多，增加组合风险权重
            if (vulnerabilities.Count > 10)
            {
                weights[5] += 0.10; // 增加漏洞组合风险权重
            }
            
            // 确保权重总和为1.0
            double totalWeight = weights.Sum();
            for (int i = 0; i < weights.Length; i++)
            {
                weights[i] /= totalWeight;
            }
            
            return weights;
        }
        
        /// <summary>
        /// 检查是否为敏感端口
        /// </summary>
        private bool IsSensitivePort(int port)
        {
            // 常见敏感端口列表
            int[] sensitivePorts = { 21, 22, 23, 25, 53, 80, 443, 1433, 3306, 3389, 5432, 6379, 8080, 8443 };
            return sensitivePorts.Contains(port);
        }
        
        /// <summary>
        /// 计算总体风险等级
        /// </summary>
        public string CalculateOverallRisk(List<VulnerabilityResult> vulnerabilities)
        {
            if (vulnerabilities == null || !vulnerabilities.Any())
                return "无风险";
            
            int highRiskCount = vulnerabilities.Count(v => v.RiskLevel == "高");
            int mediumRiskCount = vulnerabilities.Count(v => v.RiskLevel == "中");
            int lowRiskCount = vulnerabilities.Count(v => v.RiskLevel == "低");
            
            // 计算总体风险评分 - 改进的算法
            double totalRiskScore = CalculateTotalRiskScore(vulnerabilities, new List<PortScanResult>());
            
            return DetermineOverallRiskLevel(totalRiskScore, highRiskCount, mediumRiskCount, lowRiskCount);
        }
        
        /// <summary>
        /// AI增强的安全建议生成
        /// </summary>
        /// <param name="vulnerabilities">漏洞扫描结果</param>
        /// <param name="openPorts">开放端口列表（可选）</param>
        /// <returns>AI驱动的安全建议</returns>
        public string GenerateSecurityAdvice(List<VulnerabilityResult> vulnerabilities, List<PortScanResult> openPorts = null)
        {
            // 初始化开放端口列表（如果为null）
            openPorts ??= new List<PortScanResult>();
            
            if (vulnerabilities == null || !vulnerabilities.Any() && !openPorts.Any())
            {
                return "🤖 AI分析结果：系统安全状况良好，建议定期进行安全扫描和端口检查，保持当前安全状态。";
            }
            
            int highRiskCount = vulnerabilities.Count(v => v.RiskLevel == "高");
            int mediumRiskCount = vulnerabilities.Count(v => v.RiskLevel == "中");
            int sensitivePortCount = openPorts.Count(p => IsSensitivePort(p.PortNumber));
            int totalOpenPorts = openPorts.Count;
            
            var adviceBuilder = new StringBuilder();
            adviceBuilder.AppendLine("🤖 AI安全建议报告");
            adviceBuilder.AppendLine("=" .PadRight(50, '='));
            
            int adviceNumber = 1;
            
            // AI增强：基于漏洞类型的针对性建议
            var vulnerabilityTypeGroups = vulnerabilities
                .GroupBy(v => GetVulnerabilityCategory(v.Name))
                .OrderByDescending(g => g.Count(v => v.RiskLevel == "高"))
                .ThenByDescending(g => g.Count());
            
            // 高风险漏洞紧急修复建议
            if (highRiskCount > 0)
            {
                adviceBuilder.AppendLine($"{adviceNumber++}. ⚠️ 紧急修复建议");
                adviceBuilder.AppendLine("   - 立即修复所有高风险漏洞，这些漏洞被攻击者利用的概率极高");
                adviceBuilder.AppendLine("   - 建议按照以下优先级顺序修复：");
                
                var highRiskVulnerabilities = vulnerabilities
                    .Where(v => v.RiskLevel == "高")
                    .OrderByDescending(v => IsEasyToExploitVulnerabilityType(v.Name) ? 1 : 0)
                    .ThenByDescending(v => IsCriticalVulnerabilityType(v.Name) ? 1 : 0)
                    .Take(5);
                
                int priority = 1;
                foreach (var vuln in highRiskVulnerabilities)
                {
                    string severity = IsEasyToExploitVulnerabilityType(vuln.Name) ? "极易被利用" : "高";
                    
                    // 使用数据库中的标准化解决方案
                    string solution = vuln.Solution;
                    
                    // 如果解决方案过于简单，添加额外建议
                    if (string.IsNullOrEmpty(solution) || solution.Length < 50)
                    {
                        // 从漏洞类别获取标准化建议
                        string category = GetVulnerabilityCategory(vuln.Name);
                        string categoryAdvice = GetCategorySpecificAdvice(category);
                        if (!string.IsNullOrEmpty(categoryAdvice))
                        {
                            solution = categoryAdvice;
                        }
                        else
                        {
                            // 默认建议
                            solution = "1. 立即更新相关软件版本\n2. 应用官方安全补丁\n3. 限制服务访问权限\n4. 启用监控和告警";
                        }
                    }
                    
                    adviceBuilder.AppendLine($"     {priority++}. {vuln.Name} ({severity})：");
                    adviceBuilder.AppendLine($"       {solution.Replace("\n", "\n       ")}");
                }
                
                if (highRiskVulnerabilities.Count() > 5)
                {
                    adviceBuilder.AppendLine($"     ... 还有 {highRiskVulnerabilities.Count() - 5} 个高风险漏洞需要修复");
                }
                adviceBuilder.AppendLine();
            }
            
            // 中风险漏洞修复建议
            if (mediumRiskCount > 0)
            {
                adviceBuilder.AppendLine($"{adviceNumber++}. 🚨 优先修复建议");
                adviceBuilder.AppendLine("   - 在7天内修复所有中风险漏洞，降低攻击者横向移动的风险");
                
                var mediumRiskGroups = vulnerabilities
                    .Where(v => v.RiskLevel == "中")
                    .GroupBy(v => GetVulnerabilityCategory(v.Name))
                    .OrderByDescending(g => g.Count());
                
                foreach (var group in mediumRiskGroups.Take(3))
                {
                    adviceBuilder.AppendLine($"   - {group.Key}：共发现 {group.Count()} 个漏洞，建议统一修复");
                }
                adviceBuilder.AppendLine();
            }
            
            // AI增强：端口安全建议
            if (openPorts.Any())
            {
                adviceBuilder.AppendLine($"{adviceNumber++}. 🔒 端口安全加固建议");
                
                if (sensitivePortCount > 0)
                {
                    var sensitiveOpenPorts = openPorts.Where(p => IsSensitivePort(p.PortNumber)).ToList();
                    var sensitivePortList = string.Join(", ", sensitiveOpenPorts.Select(p => p.PortNumber));
                    adviceBuilder.AppendLine($"   - 限制敏感端口访问：当前开放的敏感端口 {sensitivePortList}");
                    adviceBuilder.AppendLine("   - 建议措施：");
                    adviceBuilder.AppendLine("     * 配置防火墙规则，只允许特定IP访问敏感端口");
                    adviceBuilder.AppendLine("     * 对于不必要的敏感服务，建议关闭或修改默认端口");
                    adviceBuilder.AppendLine("     * 为SSH、RDP等服务启用密钥认证，禁用密码登录");
                }
                
                if (totalOpenPorts > 10)
                {
                    adviceBuilder.AppendLine($"   - 减少开放端口：当前共开放 {totalOpenPorts} 个端口，攻击面较大");
                    adviceBuilder.AppendLine("     * 关闭所有不必要的服务和端口");
                    adviceBuilder.AppendLine("     * 使用网络分段，隔离不同功能区域");
                }
                
                // 敏感服务暴露建议
                var exposedServices = openPorts
                    .Where(p => p.Service != null && IsSensitiveService(p.Service))
                    .Select(p => p.Service)
                    .Distinct()
                    .ToList();
                
                if (exposedServices.Any())
                {
                    adviceBuilder.AppendLine($"   - 敏感服务暴露：发现 {string.Join(", ", exposedServices)} 等敏感服务直接暴露在公网");
                    adviceBuilder.AppendLine("     * 建议使用VPN或跳板机访问这些服务");
                    adviceBuilder.AppendLine("     * 考虑使用Web应用防火墙(WAF)保护Web服务");
                }
                adviceBuilder.AppendLine();
            }
            
            // AI增强：基于漏洞类型的专项建议
            if (vulnerabilityTypeGroups.Any())
            {
                adviceBuilder.AppendLine($"{adviceNumber++}. 🎯 专项加固建议");
                
                foreach (var group in vulnerabilityTypeGroups.Take(3))
                {
                    string categoryAdvice = GetCategorySpecificAdvice(group.Key);
                    if (!string.IsNullOrEmpty(categoryAdvice))
                    {
                        adviceBuilder.AppendLine($"   - {group.Key}漏洞 ({group.Count()}个)：");
                        adviceBuilder.AppendLine(categoryAdvice);
                    }
                }
                adviceBuilder.AppendLine();
            }
            
            // AI增强：基于漏洞组合的关联建议
            var vulnerabilityTypes = vulnerabilities.Select(v => v.Name).ToList();
            if (vulnerabilityTypes.Any(v => v.Contains("身份验证", StringComparison.OrdinalIgnoreCase)) &&
                vulnerabilityTypes.Any(v => v.Contains("权限", StringComparison.OrdinalIgnoreCase)))
            {
                adviceBuilder.AppendLine($"{adviceNumber++}. 🔗 关联风险警告");
                adviceBuilder.AppendLine("   - 发现身份验证和权限相关漏洞同时存在，可能导致完整的权限提升攻击链");
                adviceBuilder.AppendLine("   - 建议立即审查并加固身份验证和授权机制");
                adviceBuilder.AppendLine();
            }
            
            // AI增强：长期安全建议
            adviceBuilder.AppendLine($"{adviceNumber++}. 📅 长期安全策略");
            adviceBuilder.AppendLine("   - 建立定期安全扫描机制，建议每周进行一次全系统扫描");
            adviceBuilder.AppendLine("   - 实施漏洞管理流程，建立漏洞修复SLA（高风险24小时，中风险7天）");
            adviceBuilder.AppendLine("   - 定期更新系统和应用程序，启用自动安全更新");
            adviceBuilder.AppendLine("   - 配置强密码策略，强制使用多因素认证");
            adviceBuilder.AppendLine("   - 建立安全事件响应计划，定期进行演练");
            adviceBuilder.AppendLine("   - 对员工进行定期安全意识培训，防范社会工程学攻击");
            adviceBuilder.AppendLine();
            
            // AI增强：总结和下一步行动
            adviceBuilder.AppendLine($"{adviceNumber++}. 📋 下一步行动计划");
            adviceBuilder.AppendLine("   1. 立即修复所有高风险漏洞");
            adviceBuilder.AppendLine("   2. 配置防火墙规则，限制敏感端口访问");
            adviceBuilder.AppendLine("   3. 按照优先级修复中低风险漏洞");
            adviceBuilder.AppendLine("   4. 实施长期安全策略，建立持续监控机制");
            adviceBuilder.AppendLine("   5. 修复完成后，重新进行安全扫描验证修复效果");
            
            return adviceBuilder.ToString().Trim();
        }
        
        /// <summary>
        /// AI增强：获取漏洞类别
        /// </summary>
        private string GetVulnerabilityCategory(string vulnerabilityName)
        {
            if (vulnerabilityName.Contains("SQL注入", StringComparison.OrdinalIgnoreCase))
                return "SQL注入";
            if (vulnerabilityName.Contains("跨站脚本", StringComparison.OrdinalIgnoreCase) || vulnerabilityName.Contains("XSS", StringComparison.OrdinalIgnoreCase))
                return "跨站脚本";
            if (vulnerabilityName.Contains("远程代码执行", StringComparison.OrdinalIgnoreCase) || vulnerabilityName.Contains("RCE", StringComparison.OrdinalIgnoreCase))
                return "远程代码执行";
            if (vulnerabilityName.Contains("命令注入", StringComparison.OrdinalIgnoreCase))
                return "命令注入";
            if (vulnerabilityName.Contains("身份验证", StringComparison.OrdinalIgnoreCase))
                return "身份验证";
            if (vulnerabilityName.Contains("权限", StringComparison.OrdinalIgnoreCase))
                return "权限管理";
            if (vulnerabilityName.Contains("文件", StringComparison.OrdinalIgnoreCase))
                return "文件安全";
            if (vulnerabilityName.Contains("配置", StringComparison.OrdinalIgnoreCase))
                return "配置错误";
            if (vulnerabilityName.Contains("缓冲区溢出", StringComparison.OrdinalIgnoreCase))
                return "缓冲区溢出";
            if (vulnerabilityName.Contains("注入", StringComparison.OrdinalIgnoreCase))
                return "注入漏洞";
            
            return "其他类型";
        }
        
        /// <summary>
        /// AI增强：获取特定类别的安全建议
        /// </summary>
        private string GetCategorySpecificAdvice(string category)
        {
            switch (category)
            {
                case "SQL注入":
                    return "     * 使用参数化查询或预编译语句\n     * 实施输入验证和过滤\n     * 最小权限原则配置数据库用户\n     * 使用ORM框架防止SQL注入";
                case "跨站脚本":
                    return "     * 实施严格的输入验证和输出编码\n     * 使用Content-Security-Policy (CSP)头\n     * 避免使用innerHTML等危险API\n     * 对所有用户输入进行HTML编码";
                case "远程代码执行":
                    return "     * 立即更新存在漏洞的软件版本\n     * 实施严格的输入验证\n     * 使用应用程序白名单\n     * 限制应用程序执行权限";
                case "命令注入":
                    return "     * 避免直接拼接命令\n     * 使用安全的API替代命令执行\n     * 实施严格的输入验证\n     * 最小权限原则运行应用程序";
                case "身份验证":
                    return "     * 实施强密码策略\n     * 启用多因素认证\n     * 避免使用弱加密算法\n     * 实施账户锁定机制";
                case "权限管理":
                    return "     * 实施最小权限原则\n     * 定期审查权限分配\n     * 启用权限审计日志\n     * 实施角色基础访问控制(RBAC)";
                case "文件安全":
                    return "     * 实施文件上传验证\n     * 限制文件上传目录权限\n     * 避免直接暴露文件路径\n     * 使用安全的文件存储机制";
                case "配置错误":
                    return "     * 禁用不必要的服务和功能\n     * 使用安全的默认配置\n     * 定期审查配置设置\n     * 实施配置管理策略";
                default:
                    return string.Empty;
            }
        }
        
        /// <summary>
        /// AI增强：检查是否为敏感服务
        /// </summary>
        private bool IsSensitiveService(string serviceName)
        {
            var sensitiveServices = new List<string>
            {
                "ssh", "ftp", "telnet", "smb", "rdp", "mysql", "mssql", "postgresql", "redis", "mongodb"
            };
            
            return sensitiveServices.Any(s => serviceName.ToLower().Contains(s));
        }
        
        #region 按目标分析功能
        
        /// <summary>
        /// 按目标IP进行风险评估
        /// </summary>
        public List<TargetRiskProfile> AssessRiskByTarget(List<VulnerabilityResult> vulnerabilities, List<PortScanResult> openPorts)
        {
            var profiles = new List<TargetRiskProfile>();
            
            // 按目标IP分组
            var vulnByTarget = vulnerabilities.GroupBy(v => v.Target).ToList();
            var portsByTarget = openPorts.GroupBy(p => p.TargetIp).ToList();
            
            // 获取所有目标IP
            var allTargets = vulnByTarget.Select(g => g.Key)
                .Union(portsByTarget.Select(g => g.Key))
                .Where(ip => !string.IsNullOrEmpty(ip))
                .Distinct()
                .ToList();
            
            foreach (var targetIp in allTargets)
            {
                var targetVulns = vulnByTarget.FirstOrDefault(g => g.Key == targetIp)?.ToList() ?? new List<VulnerabilityResult>();
                var targetPorts = portsByTarget.FirstOrDefault(g => g.Key == targetIp)?.ToList() ?? new List<PortScanResult>();
                
                var profile = CreateTargetRiskProfile(targetIp, targetVulns, targetPorts);
                profiles.Add(profile);
            }
            
            return profiles.OrderByDescending(p => p.TotalRiskScore).ToList();
        }
        
        /// <summary>
        /// 创建单个目标的风险画像
        /// </summary>
        private TargetRiskProfile CreateTargetRiskProfile(string targetIp, List<VulnerabilityResult> vulnerabilities, List<PortScanResult> openPorts)
        {
            var profile = new TargetRiskProfile
            {
                TargetIp = targetIp,
                AssessmentTime = DateTime.Now,
                OpenPorts = openPorts.Select(p => new PortScanResult
                {
                    TargetIp = p.TargetIp,
                    PortNumber = p.PortNumber,
                    Service = p.Service,
                    Status = p.Status,
                    ResponseTime = p.ResponseTime
                }).ToList(),
                Vulnerabilities = vulnerabilities.Select(v => new VulnerabilityDetail
                {
                    VulnerabilityName = v.Name,
                    RiskLevel = v.RiskLevel,
                    CvssScore = GetCvssScoreFromRiskLevel(v.RiskLevel),
                    Port = v.Port ?? 0,
                    Service = v.Service ?? "未知",
                    CveId = v.CveId ?? "N/A",
                    Description = v.Description ?? "暂无描述",
                    Solution = v.Solution ?? "请联系管理员修复"
                }).ToList()
            };
            
            // 计算漏洞统计
            profile.VulnStats = CalculateVulnerabilityStatistics(vulnerabilities);
            
            // 计算端口统计
            profile.PortStats = CalculatePortStatistics(openPorts);
            
            // 计算资产价值
            profile.AssetValueScore = CalculateAssetValueScore(openPorts);
            
            // 计算暴露面评分
            profile.ExposureScore = CalculateExposureScore(openPorts, vulnerabilities);
            
            // 计算总体风险评分
            profile.TotalRiskScore = CalculateTargetRiskScore(vulnerabilities, openPorts);
            
            // 确定风险等级
            profile.OverallRiskLevel = GetRiskLevelFromScore(profile.TotalRiskScore);
            
            // 计算风险分布
            profile.RiskDistribution = CalculateRiskDistribution(vulnerabilities);
            
            // 生成攻击路径
            profile.AttackPaths = GenerateAttackPaths(vulnerabilities, openPorts);
            
            // 生成修复任务
            profile.RemediationTasks = GenerateRemediationTasks(vulnerabilities, openPorts);
            
            // 生成安全建议
            profile.SecurityAdvice = GenerateTargetSecurityAdvice(profile);
            
            return profile;
        }
        
        /// <summary>
        /// 计算漏洞统计信息
        /// </summary>
        private VulnerabilityStatistics CalculateVulnerabilityStatistics(List<VulnerabilityResult> vulnerabilities)
        {
            var stats = new VulnerabilityStatistics
            {
                TotalCount = vulnerabilities.Count,
                CriticalCount = vulnerabilities.Count(v => v.RiskLevel == "严重" || v.RiskLevel == "危急"),
                HighCount = vulnerabilities.Count(v => v.RiskLevel == "高"),
                MediumCount = vulnerabilities.Count(v => v.RiskLevel == "中"),
                LowCount = vulnerabilities.Count(v => v.RiskLevel == "低"),
                InfoCount = vulnerabilities.Count(v => v.RiskLevel == "信息" || v.RiskLevel == "提示")
            };
            
            // 计算平均CVSS评分
            if (vulnerabilities.Any())
            {
                stats.AverageCvssScore = vulnerabilities.Average(v => GetCvssScoreFromRiskLevel(v.RiskLevel));
            }
            
            return stats;
        }
        
        /// <summary>
        /// 计算端口统计信息
        /// </summary>
        private PortStatistics CalculatePortStatistics(List<PortScanResult> openPorts)
        {
            var stats = new PortStatistics
            {
                TotalOpen = openPorts.Count,
                SensitiveCount = openPorts.Count(p => IsSensitivePort(p.PortNumber)),
                WebServiceCount = openPorts.Count(p => 
                    p.Service?.ToLower().Contains("http") == true || 
                    p.PortNumber is 80 or 443 or 8080 or 8443),
                DatabaseCount = openPorts.Count(p => 
                    p.Service?.ToLower().Contains("sql") == true || 
                    p.Service?.ToLower().Contains("database") == true ||
                    p.PortNumber is 3306 or 5432 or 1433 or 27017 or 6379),
                RemoteAccessCount = openPorts.Count(p => 
                    p.Service?.ToLower().Contains("ssh") == true || 
                    p.Service?.ToLower().Contains("rdp") == true ||
                    p.Service?.ToLower().Contains("telnet") == true ||
                    p.PortNumber is 22 or 3389 or 23)
            };
            
            return stats;
        }
        
        /// <summary>
        /// 计算资产价值评分
        /// </summary>
        private double CalculateAssetValueScore(List<PortScanResult> openPorts)
        {
            double score = 30; // 基础分
            
            foreach (var port in openPorts)
            {
                // 数据库服务价值高
                if (port.PortNumber is 3306 or 5432 or 1433 or 27017 or 6379)
                    score += 15;
                // Web服务
                else if (port.PortNumber is 80 or 443 or 8080 or 8443)
                    score += 10;
                // 远程访问服务
                else if (port.PortNumber is 22 or 3389)
                    score += 8;
                // 邮件服务
                else if (port.PortNumber is 25 or 110 or 143 or 587)
                    score += 5;
                // 其他服务
                else
                    score += 2;
            }
            
            return Math.Min(100, score);
        }
        
        /// <summary>
        /// 计算暴露面评分
        /// </summary>
        private double CalculateExposureScore(List<PortScanResult> openPorts, List<VulnerabilityResult> vulnerabilities)
        {
            double score = 0;
            
            // 开放端口越多，暴露面越大
            score += openPorts.Count * 2;
            
            // 敏感端口增加暴露面
            score += openPorts.Count(p => IsSensitivePort(p.PortNumber)) * 5;
            
            // 漏洞增加暴露面
            score += vulnerabilities.Count(v => v.RiskLevel == "高") * 8;
            score += vulnerabilities.Count(v => v.RiskLevel == "中") * 4;
            score += vulnerabilities.Count(v => v.RiskLevel == "低") * 1;
            
            return Math.Min(100, score);
        }
        
        /// <summary>
        /// 计算目标风险评分
        /// </summary>
        private double CalculateTargetRiskScore(List<VulnerabilityResult> vulnerabilities, List<PortScanResult> openPorts)
        {
            double score = 0;
            
            // 漏洞风险
            foreach (var vuln in vulnerabilities)
            {
                score += vuln.RiskLevel switch
                {
                    "严重" or "危急" => 25,
                    "高" => 15,
                    "中" => 8,
                    "低" => 3,
                    _ => 1
                };
            }
            
            // 开放端口风险
            score += openPorts.Count(p => IsSensitivePort(p.PortNumber)) * 3;
            
            // 服务类型风险
            foreach (var port in openPorts)
            {
                if (port.Service?.ToLower().Contains("database") == true)
                    score += 5;
                if (port.Service?.ToLower().Contains("remote") == true)
                    score += 4;
            }
            
            return Math.Min(100, score);
        }
        
        /// <summary>
        /// 根据风险评分获取风险等级
        /// </summary>
        private string GetRiskLevelFromScore(double score)
        {
            return score switch
            {
                >= 80 => "严重",
                >= 60 => "高",
                >= 40 => "中",
                >= 20 => "低",
                _ => "安全"
            };
        }
        
        /// <summary>
        /// 从风险等级获取CVSS评分
        /// </summary>
        private double GetCvssScoreFromRiskLevel(string riskLevel)
        {
            return riskLevel?.ToLower() switch
            {
                "严重" or "危急" => 9.5,
                "高" => 8.0,
                "中" => 5.5,
                "低" => 3.0,
                _ => 1.0
            };
        }
        
        /// <summary>
        /// 计算风险分布
        /// </summary>
        private List<RiskCategory> CalculateRiskDistribution(List<VulnerabilityResult> vulnerabilities)
        {
            var distribution = new List<RiskCategory>();
            var groups = vulnerabilities.GroupBy(v => v.RiskLevel).ToList();
            int total = vulnerabilities.Count;
            
            foreach (var group in groups)
            {
                distribution.Add(new RiskCategory
                {
                    Category = group.Key,
                    Count = group.Count(),
                    Percentage = total > 0 ? (double)group.Count() / total : 0,
                    Score = GetCvssScoreFromRiskLevel(group.Key)
                });
            }
            
            return distribution;
        }
        
        /// <summary>
        /// 生成攻击路径（公共方法，供攻击路径分析窗口调用）
        /// </summary>
        public List<AttackPath> GenerateAttackPathsForAnalysis(List<VulnerabilityResult> vulnerabilities, List<PortScanResult> openPorts)
        {
            return GenerateAttackPaths(vulnerabilities, openPorts);
        }
        
        /// <summary>
        /// 生成攻击路径
        /// </summary>
        private List<AttackPath> GenerateAttackPaths(List<VulnerabilityResult> vulnerabilities, List<PortScanResult> openPorts)
        {
            var paths = new List<AttackPath>();
            
            var webPorts = openPorts.Where(p => p.PortNumber is 80 or 443 or 8080 or 8443).ToList();
            var remotePorts = openPorts.Where(p => p.PortNumber is 22 or 3389 or 23).ToList();
            var dbPorts = openPorts.Where(p => p.PortNumber is 3306 or 5432 or 1433 or 27017 or 6379).ToList();
            var fileServicePorts = openPorts.Where(p => p.PortNumber is 21 or 445 or 139 or 135).ToList();
            
            var webVulns = vulnerabilities.Where(v => 
                v.Service?.ToLower().Contains("http") == true ||
                v.Name?.ToLower().Contains("sql") == true ||
                v.Name?.ToLower().Contains("xss") == true ||
                v.Name?.ToLower().Contains("csrf") == true ||
                v.Name?.ToLower().Contains("文件上传") == true).ToList();
            
            var rceVulns = vulnerabilities.Where(v =>
                v.Name?.ToLower().Contains("远程代码执行") == true ||
                v.Name?.ToLower().Contains("命令注入") == true ||
                v.Name?.ToLower().Contains("缓冲区溢出") == true).ToList();
            
            var authVulns = vulnerabilities.Where(v =>
                v.Name?.ToLower().Contains("身份验证") == true ||
                v.Name?.ToLower().Contains("认证") == true ||
                v.Name?.ToLower().Contains("弱密码") == true).ToList();
            
            var privilegeVulns = vulnerabilities.Where(v =>
                v.Name?.ToLower().Contains("权限") == true ||
                v.Name?.ToLower().Contains("提权") == true).ToList();
            
            if (webPorts.Any() && webVulns.Any())
            {
                double riskScore = Math.Min(100, webVulns.Count * 15);
                double successProb = rceVulns.Any() ? 75 : webVulns.Any(v => v.RiskLevel == "高") ? 65 : 40;
                int complexity = rceVulns.Any() ? 7 : 6;
                string impact = rceVulns.Any() 
                    ? "攻击者可利用Web漏洞执行远程代码，完全控制服务器并窃取数据"
                    : "可能导致数据泄露、会话劫持或数据库被注入恶意数据";
                
                var steps = new List<AttackStep>();
                int stepNum = 1;
                
                steps.Add(new AttackStep 
                { 
                    StepNumber = stepNum++, 
                    Title = "信息收集与侦察", 
                    Description = "使用Nmap、BurpSuite等工具扫描Web应用，收集技术栈、目录结构和输入点信息",
                    StepRisk = 3.0,
                    TargetPort = string.Join(", ", webPorts.Select(p => p.PortNumber.ToString())),
                    RequiredVulnerability = "Web服务开放"
                });
                
                if (authVulns.Any())
                {
                    steps.Add(new AttackStep 
                    { 
                        StepNumber = stepNum++, 
                        Title = "身份认证突破", 
                        Description = $"利用身份验证漏洞({string.Join(", ", authVulns.Take(2).Select(v => v.Name))})绕过登录或暴力破解",
                        StepRisk = 7.5,
                        TargetPort = string.Join(", ", webPorts.Select(p => p.PortNumber.ToString())),
                        RequiredVulnerability = string.Join("; ", authVulns.Take(2).Select(v => v.Name))
                    });
                }
                
                steps.Add(new AttackStep 
                { 
                    StepNumber = stepNum++, 
                    Title = "漏洞探测与利用", 
                    Description = rceVulns.Any()
                        ? $"利用远程代码执行漏洞({rceVulns.First().Name})获取服务器shell"
                        : $"利用Web漏洞({webVulns.First().Name})进行数据注入或XSS攻击",
                    StepRisk = rceVulns.Any() ? 9.0 : 6.5,
                    TargetPort = string.Join(", ", webPorts.Select(p => p.PortNumber.ToString())),
                    RequiredVulnerability = rceVulns.Any() ? rceVulns.First().Name : webVulns.First().Name
                });
                
                if (privilegeVulns.Any())
                {
                    steps.Add(new AttackStep 
                    { 
                        StepNumber = stepNum++, 
                        Title = "权限提升", 
                        Description = $"利用权限漏洞({privilegeVulns.First().Name})从普通用户提升为管理员或root",
                        StepRisk = 8.5,
                        TargetPort = "",
                        RequiredVulnerability = privilegeVulns.First().Name
                    });
                }
                
                steps.Add(new AttackStep 
                { 
                    StepNumber = stepNum++, 
                    Title = "数据窃取与持久化", 
                    Description = "访问敏感数据库，导出用户信息，植入后门程序维持访问权限",
                    StepRisk = 9.5,
                    TargetPort = "",
                    RequiredVulnerability = "已获取Web服务访问权限"
                });
                
                paths.Add(new AttackPath
                {
                    Name = "Web应用攻击路径",
                    Description = $"通过{webPorts.Count}个Web端口({string.Join(", ", webPorts.Select(p => p.PortNumber))})和{webVulns.Count}个Web漏洞入侵系统",
                    RiskScore = riskScore,
                    Complexity = complexity,
                    SuccessProbability = successProb,
                    Impact = impact,
                    Steps = steps
                });
            }
            
            if (remotePorts.Any())
            {
                var sshPorts = remotePorts.Where(p => p.PortNumber == 22).ToList();
                var rdpPorts = remotePorts.Where(p => p.PortNumber == 3389).ToList();
                var telnetPorts = remotePorts.Where(p => p.PortNumber == 23).ToList();
                
                double riskScore = 45;
                double successProb = 50;
                int complexity = 7;
                var impactBuilder = new System.Text.StringBuilder();
                
                if (telnetPorts.Any())
                {
                    riskScore += 20;
                    successProb += 20;
                    complexity = 4;
                    impactBuilder.Append("Telnet服务明文传输，极易被中间人攻击截获凭据");
                }
                
                if (authVulns.Any())
                {
                    riskScore += 15;
                    successProb += 15;
                    impactBuilder.Append("存在身份验证漏洞，可进行暴力破解或认证绕过。");
                }
                
                if (rceVulns.Any(v => v.Port == 22 || v.Port == 3389))
                {
                    riskScore += 25;
                    successProb += 10;
                    impactBuilder.Append("远程服务存在代码执行漏洞，可直接获取系统权限。");
                }
                
                riskScore = Math.Min(100, riskScore);
                successProb = Math.Min(95, successProb);
                
                var steps = new List<AttackStep>();
                int stepNum = 1;
                
                steps.Add(new AttackStep 
                { 
                    StepNumber = stepNum++, 
                    Title = "远程服务探测", 
                    Description = $"扫描发现{string.Join(", ", remotePorts.Select(p => $"{p.PortNumber}({p.Service ?? "未知"})"))}等远程访问服务",
                    StepRisk = 4.0,
                    TargetPort = string.Join(", ", remotePorts.Select(p => p.PortNumber.ToString())),
                    RequiredVulnerability = "远程访问服务开放"
                });
                
                if (telnetPorts.Any())
                {
                    steps.Add(new AttackStep 
                    { 
                        StepNumber = stepNum++, 
                        Title = "Telnet凭据截获", 
                        Description = "通过中间人攻击截获Telnet明文传输的用户名和密码",
                        StepRisk = 8.5,
                        TargetPort = string.Join(", ", telnetPorts.Select(p => p.PortNumber.ToString())),
                        RequiredVulnerability = "Telnet明文传输"
                    });
                }
                
                steps.Add(new AttackStep 
                { 
                    StepNumber = stepNum++, 
                    Title = "认证凭据破解", 
                    Description = "使用Hydra、Medusa等工具进行SSH/RDP暴力破解，或尝试默认密码和常见弱密码",
                    StepRisk = authVulns.Any() ? 8.0 : 6.0,
                    TargetPort = string.Join(", ", remotePorts.Where(p => p.PortNumber != 23).Select(p => p.PortNumber.ToString())),
                    RequiredVulnerability = authVulns.Any() ? string.Join("; ", authVulns.Take(2).Select(v => v.Name)) : "弱密码策略"
                });
                
                steps.Add(new AttackStep 
                { 
                    StepNumber = stepNum++, 
                    Title = "远程登录获取权限", 
                    Description = "使用破解得到的凭据通过SSH/RDP/Telnet登录系统，获得用户级访问权限",
                    StepRisk = 7.5,
                    TargetPort = string.Join(", ", remotePorts.Select(p => p.PortNumber.ToString())),
                    RequiredVulnerability = "已获取有效认证凭据"
                });
                
                if (privilegeVulns.Any())
                {
                    steps.Add(new AttackStep 
                    { 
                        StepNumber = stepNum++, 
                        Title = "本地权限提升", 
                        Description = $"利用本地权限漏洞({privilegeVulns.First().Name})从普通用户提升为管理员/root",
                        StepRisk = 9.0,
                        TargetPort = "",
                        RequiredVulnerability = privilegeVulns.First().Name
                    });
                }
                
                paths.Add(new AttackPath
                {
                    Name = "远程访问攻击路径",
                    Description = $"通过{string.Join(", ", remotePorts.Select(p => $"{p.PortNumber}({p.Service ?? "未知"})"))}等远程服务入侵系统",
                    RiskScore = riskScore,
                    Complexity = complexity,
                    SuccessProbability = successProb,
                    Impact = impactBuilder.Length > 0 ? impactBuilder.ToString() : "可能获得系统完全控制权，可执行任意命令和访问所有数据",
                    Steps = steps
                });
            }
            
            if (dbPorts.Any())
            {
                double riskScore = 55;
                double successProb = 40;
                int complexity = 8;
                var impactBuilder = new System.Text.StringBuilder();
                impactBuilder.Append("数据库被入侵可导致");
                
                if (authVulns.Any(v => dbPorts.Any(p => p.PortNumber == v.Port)))
                {
                    riskScore += 20;
                    successProb += 20;
                    impactBuilder.Append("通过认证漏洞直接访问数据库，");
                }
                
                impactBuilder.Append("敏感数据泄露、数据被篡改或删除、业务系统瘫痪");
                
                var steps = new List<AttackStep>();
                int stepNum = 1;
                
                steps.Add(new AttackStep 
                { 
                    StepNumber = stepNum++, 
                    Title = "数据库服务发现", 
                    Description = $"扫描发现{string.Join(", ", dbPorts.Select(p => $"{p.PortNumber}({p.Service ?? "未知"})"))}等数据库服务直接暴露在网络上",
                    StepRisk = 6.0,
                    TargetPort = string.Join(", ", dbPorts.Select(p => p.PortNumber.ToString())),
                    RequiredVulnerability = "数据库端口对外暴露"
                });
                
                steps.Add(new AttackStep 
                { 
                    StepNumber = stepNum++, 
                    Title = "数据库认证突破", 
                    Description = "尝试使用默认密码(mysql:root/root)、常见弱密码或暴力破解方式访问数据库",
                    StepRisk = 7.0,
                    TargetPort = string.Join(", ", dbPorts.Select(p => p.PortNumber.ToString())),
                    RequiredVulnerability = "弱密码或默认配置"
                });
                
                steps.Add(new AttackStep 
                { 
                    StepNumber = stepNum++, 
                    Title = "数据访问与窃取", 
                    Description = "连接成功后，可执行SQL查询导出所有表数据，包括用户信息、交易记录等敏感数据",
                    StepRisk = 9.0,
                    TargetPort = string.Join(", ", dbPorts.Select(p => p.PortNumber.ToString())),
                    RequiredVulnerability = "已获取数据库访问权限"
                });
                
                steps.Add(new AttackStep 
                { 
                    StepNumber = stepNum++, 
                    Title = "权限提升或命令执行", 
                    Description = "部分数据库(如MySQL、MSSQL)支持执行系统命令，可进一步获取操作系统权限",
                    StepRisk = 9.5,
                    TargetPort = string.Join(", ", dbPorts.Select(p => p.PortNumber.ToString())),
                    RequiredVulnerability = "数据库配置不当允许命令执行"
                });
                
                paths.Add(new AttackPath
                {
                    Name = "数据库入侵攻击路径",
                    Description = $"通过{string.Join(", ", dbPorts.Select(p => $"{p.PortNumber}({p.Service ?? "未知"})"))}等数据库服务入侵",
                    RiskScore = Math.Min(100, riskScore),
                    Complexity = complexity,
                    SuccessProbability = successProb,
                    Impact = impactBuilder.ToString(),
                    Steps = steps
                });
            }
            
            if (fileServicePorts.Any())
            {
                var ftpPorts = fileServicePorts.Where(p => p.PortNumber == 21).ToList();
                var smbPorts = fileServicePorts.Where(p => p.PortNumber is 445 or 139 or 135).ToList();
                
                double riskScore = 40;
                double successProb = 35;
                int complexity = 6;
                
                if (ftpPorts.Any())
                {
                    riskScore += 15;
                    successProb += 15;
                    complexity = Math.Min(complexity, 5);
                }
                
                if (smbPorts.Any())
                {
                    riskScore += 20;
                    successProb += 10;
                }
                
                var steps = new List<AttackStep>();
                int stepNum = 1;
                
                steps.Add(new AttackStep 
                { 
                    StepNumber = stepNum++, 
                    Title = "文件服务探测", 
                    Description = $"发现{string.Join(", ", fileServicePorts.Select(p => $"{p.PortNumber}({p.Service ?? "未知"})"))}等文件传输/共享服务",
                    StepRisk = 5.0,
                    TargetPort = string.Join(", ", fileServicePorts.Select(p => p.PortNumber.ToString())),
                    RequiredVulnerability = "文件服务开放"
                });
                
                if (ftpPorts.Any())
                {
                    steps.Add(new AttackStep 
                    { 
                        StepNumber = stepNum++, 
                        Title = "FTP匿名登录或弱密码破解", 
                        Description = "尝试匿名登录(anonymous/anonymous)或使用常见FTP弱密码字典进行暴力破解",
                        StepRisk = 7.0,
                        TargetPort = string.Join(", ", ftpPorts.Select(p => p.PortNumber.ToString())),
                        RequiredVulnerability = "FTP匿名登录或弱密码"
                    });
                }
                
                if (smbPorts.Any())
                {
                    steps.Add(new AttackStep 
                    { 
                        StepNumber = stepNum++, 
                        Title = "SMB共享访问或漏洞利用", 
                        Description = "尝试访问SMB共享文件夹，或利用永恒之蓝(SMB漏洞)远程执行代码",
                        StepRisk = 8.5,
                        TargetPort = string.Join(", ", smbPorts.Select(p => p.PortNumber.ToString())),
                        RequiredVulnerability = "SMB配置不当或漏洞"
                    });
                }
                
                steps.Add(new AttackStep 
                { 
                    StepNumber = stepNum++, 
                    Title = "文件上传与恶意代码植入", 
                    Description = "通过文件服务上传WebShell、后门程序或勒索软件，进一步控制服务器",
                    StepRisk = 9.0,
                    TargetPort = string.Join(", ", fileServicePorts.Select(p => p.PortNumber.ToString())),
                    RequiredVulnerability = "已获取文件服务写入权限"
                });
                
                paths.Add(new AttackPath
                {
                    Name = "文件服务攻击路径",
                    Description = $"通过{string.Join(", ", fileServicePorts.Select(p => $"{p.PortNumber}({p.Service ?? "未知"})"))}等文件服务入侵",
                    RiskScore = Math.Min(100, riskScore),
                    Complexity = complexity,
                    SuccessProbability = successProb,
                    Impact = "可上传恶意文件、WebShell或勒索软件，导致服务器被完全控制或数据被加密勒索",
                    Steps = steps
                });
            }
            
            if (vulnerabilities.Count >= 3)
            {
                var vulnTypes = vulnerabilities.Select(v => v.Name).Distinct().ToList();
                double comboRiskScore = Math.Min(100, vulnerabilities.Count * 8);
                double comboSuccessProb = Math.Min(85, 30 + vulnerabilities.Count * 5);
                
                var steps = new List<AttackStep>();
                int stepNum = 1;
                
                steps.Add(new AttackStep 
                { 
                    StepNumber = stepNum++, 
                    Title = "多漏洞信息收集", 
                    Description = $"发现{vulnerabilities.Count}个漏洞，涉及{vulnTypes.Count}种类型，可组合利用形成完整攻击链",
                    StepRisk = 5.0,
                    TargetPort = "",
                    RequiredVulnerability = string.Join(", ", vulnTypes.Take(3))
                });
                
                steps.Add(new AttackStep 
                { 
                    StepNumber = stepNum++, 
                    Title = "初始入口获取", 
                    Description = $"利用最易利用的漏洞({vulnerabilities.OrderByDescending(v => v.RiskLevel == "高" ? 3 : v.RiskLevel == "中" ? 2 : 1).First().Name})获取初始访问权限",
                    StepRisk = 7.5,
                    TargetPort = "",
                    RequiredVulnerability = vulnerabilities.OrderByDescending(v => v.RiskLevel == "高" ? 3 : v.RiskLevel == "中" ? 2 : 1).First().Name
                });
                
                steps.Add(new AttackStep 
                { 
                    StepNumber = stepNum++, 
                    Title = "横向移动与权限提升", 
                    Description = "利用其他漏洞进行内网横向移动，逐步提升权限至管理员级别",
                    StepRisk = 8.5,
                    TargetPort = "",
                    RequiredVulnerability = "多个漏洞组合利用"
                });
                
                steps.Add(new AttackStep 
                { 
                    StepNumber = stepNum++, 
                    Title = "持久化控制", 
                    Description = "在系统中植入后门、创建隐藏账户、修改系统配置以维持长期访问",
                    StepRisk = 9.5,
                    TargetPort = "",
                    RequiredVulnerability = "已获取系统控制权"
                });
                
                paths.Add(new AttackPath
                {
                    Name = "多漏洞组合攻击路径",
                    Description = $"利用{vulnerabilities.Count}个漏洞的组合效应，构建完整攻击链",
                    RiskScore = comboRiskScore,
                    Complexity = 5,
                    SuccessProbability = comboSuccessProb,
                    Impact = "多漏洞组合利用可突破单一防御层，形成从初始访问到完全控制的完整攻击链",
                    Steps = steps
                });
            }
            
            return paths.OrderByDescending(p => p.RiskScore).ToList();
        }
        
        /// <summary>
        /// 生成修复任务
        /// </summary>
        private List<RemediationTask> GenerateRemediationTasks(List<VulnerabilityResult> vulnerabilities, List<PortScanResult> openPorts)
        {
            var tasks = new List<RemediationTask>();
            int taskId = 1;
            
            // 按风险等级排序生成任务
            var sortedVulns = vulnerabilities
                .OrderByDescending(v => GetCvssScoreFromRiskLevel(v.RiskLevel))
                .ToList();
            
            foreach (var vuln in sortedVulns.Take(10))
            {
                tasks.Add(new RemediationTask
                {
                    Id = taskId++,
                    Title = $"修复: {vuln.Name}",
                    Description = vuln.Description ?? "需要修复的漏洞",
                    Priority = GetPriorityFromRiskLevel(vuln.RiskLevel),
                    PriorityLevel = vuln.RiskLevel,
                    Difficulty = vuln.RiskLevel == "高" ? 8 : vuln.RiskLevel == "中" ? 5 : 3,
                    EstimatedHours = vuln.RiskLevel == "高" ? 8 : vuln.RiskLevel == "中" ? 4 : 2,
                    RiskReduction = GetCvssScoreFromRiskLevel(vuln.RiskLevel),
                    Solution = vuln.Solution ?? "参考官方安全公告进行修复"
                });
            }
            
            return tasks;
        }
        
        /// <summary>
        /// 从风险等级获取优先级
        /// </summary>
        private int GetPriorityFromRiskLevel(string riskLevel)
        {
            return riskLevel?.ToLower() switch
            {
                "严重" or "危急" => 100,
                "高" => 80,
                "中" => 50,
                "低" => 20,
                _ => 10
            };
        }
        
        /// <summary>
        /// 生成目标安全建议
        /// </summary>
        private string GenerateTargetSecurityAdvice(TargetRiskProfile profile)
        {
            var advice = new StringBuilder();
            
            advice.AppendLine($"目标 {profile.TargetIp} 的安全建议：");
            advice.AppendLine();
            
            // 根据风险等级给出建议
            if (profile.TotalRiskScore >= 60)
            {
                advice.AppendLine("【紧急】该目标存在严重安全风险，建议立即采取以下措施：");
                advice.AppendLine("1. 立即修复所有高危漏洞");
                advice.AppendLine("2. 关闭不必要的开放端口");
                advice.AppendLine("3. 加强访问控制和监控");
            }
            else if (profile.TotalRiskScore >= 40)
            {
                advice.AppendLine("【重要】该目标存在中等风险，建议尽快修复：");
                advice.AppendLine("1. 优先修复高危和中危漏洞");
                advice.AppendLine("2. 审查开放端口的必要性");
            }
            else
            {
                advice.AppendLine("【一般】该目标安全状况良好，建议：");
                advice.AppendLine("1. 定期进行安全扫描");
                advice.AppendLine("2. 保持系统更新");
            }
            
            // 添加具体建议
            if (profile.PortStats.SensitiveCount > 0)
            {
                advice.AppendLine($"3. 注意：发现 {profile.PortStats.SensitiveCount} 个敏感端口开放，请确认是否必要");
            }
            
            if (profile.VulnStats.HighCount > 0)
            {
                advice.AppendLine($"4. 优先处理 {profile.VulnStats.HighCount} 个高危漏洞");
            }
            
            return advice.ToString();
        }
        
        #endregion
    }
}