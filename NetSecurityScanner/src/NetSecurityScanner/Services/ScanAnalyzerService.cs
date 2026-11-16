using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using NetSecurityScanner.Data;
using NetSecurityScanner.Models;
using NetSecurityScanner.Core;

namespace NetSecurityScanner.Services
{
    /// <summary>
    /// 扫描分析服务 - 提供扫描结果分析和统计功能
    /// </summary>
    public class ScanAnalyzerService
    {
        private readonly JSONDatabaseService _databaseService;
        private readonly Logger _logger;
        
        public ScanAnalyzerService()
        {
            _databaseService = new JSONDatabaseService();
            _logger = new Logger();
        }
        
        /// <summary>
        /// 获取总体统计信息
        /// </summary>
        public async Task<OverallStatistics> GetOverallStatisticsAsync()
        {
            try
            {
                _logger.Info("获取总体统计信息");
                
                var tasks = _databaseService.GetAllScanTasks();
                var results = _databaseService.GetAllScanResults();
                var vulnerabilities = _databaseService.GetAllVulnerabilities();
                
                var stats = new OverallStatistics
                {
                    TotalTasks = tasks.Count,
                    CompletedTasks = tasks.Count(t => t.Status == "完成"),
                    FailedTasks = tasks.Count(t => t.Status == "失败"),
                    InProgressTasks = tasks.Count(t => t.Status == "进行中"),
                    
                    TotalScanResults = results.Count,
                    TotalVulnerabilities = vulnerabilities.Count,
                    
                    CriticalVulnerabilities = vulnerabilities.Count(v => v.Severity == "严重"),
                    HighVulnerabilities = vulnerabilities.Count(v => v.Severity == "高"),
                    MediumVulnerabilities = vulnerabilities.Count(v => v.Severity == "中"),
                    LowVulnerabilities = vulnerabilities.Count(v => v.Severity == "低"),
                    
                    LastUpdated = DateTime.Now
                };
                
                // 计算平均CVSS分数
                if (vulnerabilities.Any())
                {
                    stats.AverageCvssScore = vulnerabilities.Average(v => v.CvssScore);
                }
                
                // 计算风险等级分布
                var riskLevels = vulnerabilities.GroupBy(v => GetRiskLevel(v.CvssScore))
                    .ToDictionary(g => g.Key, g => g.Count());
                stats.RiskLevelDistribution = riskLevels;
                
                // 计算服务分布
                var serviceDistribution = results.Where(r => !string.IsNullOrEmpty(r.Service))
                    .GroupBy(r => r.Service)
                    .OrderByDescending(g => g.Count())
                    .Take(10)
                    .ToDictionary(g => g.Key, g => g.Count());
                stats.TopServices = serviceDistribution;
                
                // 计算端口分布
                var portDistribution = results
                    .GroupBy(r => r.Port)
                    .OrderByDescending(g => g.Count())
                    .Take(10)
                    .ToDictionary(g => g.Key, g => g.Count());
                stats.TopPorts = portDistribution;
                
                _logger.Info($"统计信息获取完成: {stats.TotalTasks} 个任务, {stats.TotalVulnerabilities} 个漏洞");
                
                await Task.CompletedTask;
                return stats;
            }
            catch (Exception ex)
            {
                _logger.Error($"获取总体统计信息失败: {ex.Message}");
                return new OverallStatistics();
            }
        }
        
        /// <summary>
        /// 获取任务详细分析
        /// </summary>
        public async Task<TaskAnalysis> AnalyzeTaskAsync(int taskId)
        {
            try
            {
                _logger.Info($"分析任务: {taskId}");
                
                var task = _databaseService.GetScanTaskById(taskId);
                if (task == null)
                {
                    _logger.Warning($"任务不存在: {taskId}");
                    return null;
                }
                
                var results = _databaseService.GetScanResultsByTaskId(taskId);
                var vulnerabilities = _databaseService.GetVulnerabilitiesByTaskId(taskId);
                
                var analysis = new TaskAnalysis
                {
                    TaskId = taskId,
                    TaskName = task.TaskName,
                    TargetHosts = task.TargetHosts,
                    ScanType = task.ScanType,
                    Status = task.Status,
                    StartTime = task.StartTime ?? DateTime.Now,
                    EndTime = task.EndTime,
                    Duration = CalculateDuration(task.StartTime ?? DateTime.Now, task.EndTime),
                    
                    TotalOpenPorts = results.Count,
                    TotalVulnerabilities = vulnerabilities.Count,
                    
                    CriticalCount = vulnerabilities.Count(v => v.Severity == "严重"),
                    HighCount = vulnerabilities.Count(v => v.Severity == "高"),
                    MediumCount = vulnerabilities.Count(v => v.Severity == "中"),
                    LowCount = vulnerabilities.Count(v => v.Severity == "低"),
                    
                    Vulnerabilities = vulnerabilities,
                    ScanResults = results
                };
                
                // 计算风险评分
                analysis.RiskScore = CalculateRiskScore(vulnerabilities);
                analysis.RiskLevel = GetRiskLevelName(analysis.RiskScore);
                
                // 分析服务
                analysis.ServiceAnalysis = AnalyzeServices(results);
                
                // 分析漏洞趋势
                analysis.VulnerabilityTrend = AnalyzeVulnerabilityTrend(vulnerabilities);
                
                // 生成修复建议
                analysis.RemediationSuggestions = GenerateRemediationSuggestions(vulnerabilities);
                
                _logger.Info($"任务分析完成: {taskId}, 风险评分: {analysis.RiskScore}");
                
                await Task.CompletedTask;
                return analysis;
            }
            catch (Exception ex)
            {
                _logger.Error($"分析任务失败: {ex.Message}");
                return null;
            }
        }
        
        /// <summary>
        /// 获取趋势分析
        /// </summary>
        public async Task<TrendAnalysis> GetTrendAnalysisAsync(int days = 30)
        {
            try
            {
                _logger.Info($"获取趋势分析，时间范围: {days} 天");
                
                var startDate = DateTime.Now.AddDays(-days);
                var tasks = _databaseService.GetAllScanTasks()
                    .Where(t => t.StartTime >= startDate)
                    .OrderBy(t => t.StartTime)
                    .ToList();
                
                var analysis = new TrendAnalysis
                {
                    PeriodDays = days,
                    StartDate = startDate,
                    EndDate = DateTime.Now
                };
                
                // 按天统计
                var dailyStats = tasks
                    .Where(t => t.StartTime.HasValue)
                    .GroupBy(t => t.StartTime!.Value.Date)
                    .Select(g => new DailyScanStats
                    {
                        Date = g.Key,
                        TaskCount = g.Count(),
                        VulnerabilityCount = g.Sum(t => 
                            _databaseService.GetVulnerabilitiesByTaskId(t.TaskId).Count)
                    })
                    .ToList();
                
                analysis.DailyStatistics = dailyStats;
                
                // 计算趋势
                if (dailyStats.Count >= 2)
                {
                    var firstWeek = dailyStats.Take(7).Average(d => d.VulnerabilityCount);
                    var lastWeek = dailyStats.Skip(Math.Max(0, dailyStats.Count - 7)).Average(d => d.VulnerabilityCount);
                    
                    analysis.VulnerabilityTrend = lastWeek - firstWeek;
                    analysis.TrendDirection = analysis.VulnerabilityTrend > 0 ? "上升" : 
                        analysis.VulnerabilityTrend < 0 ? "下降" : "稳定";
                }
                
                // 统计漏洞类型分布
                var allVulnerabilities = new List<Vulnerability>();
                foreach (var task in tasks)
                {
                    allVulnerabilities.AddRange(_databaseService.GetVulnerabilitiesByTaskId(task.TaskId));
                }
                
                analysis.VulnerabilityTypeDistribution = allVulnerabilities
                    .GroupBy(v => v.CveId?.Split('-')[1] ?? "未知") // 按年份分组
                    .ToDictionary(g => g.Key, g => g.Count());
                
                _logger.Info($"趋势分析完成: {tasks.Count} 个任务, {allVulnerabilities.Count} 个漏洞");
                
                await Task.CompletedTask;
                return analysis;
            }
            catch (Exception ex)
            {
                _logger.Error($"获取趋势分析失败: {ex.Message}");
                return new TrendAnalysis { PeriodDays = days };
            }
        }
        
        /// <summary>
        /// 获取主机安全评分
        /// </summary>
        public async Task<List<HostSecurityScore>> GetHostSecurityScoresAsync()
        {
            try
            {
                _logger.Info("获取主机安全评分");
                
                var results = _databaseService.GetAllScanResults();
                var vulnerabilities = _databaseService.GetAllVulnerabilities();
                
                // 按主机分组
                var hostGroups = results.GroupBy(r => r.Host);
                var scores = new List<HostSecurityScore>();
                
                foreach (var hostGroup in hostGroups)
                {
                    var host = hostGroup.Key;
                    var hostResults = hostGroup.ToList();
                    var hostVulnerabilities = vulnerabilities
                        .Where(v => hostResults.Any(r => r.TaskId == v.VulnerabilityId))
                        .ToList();
                    
                    var score = new HostSecurityScore
                    {
                        Host = host,
                        OpenPorts = hostResults.Select(r => r.Port).Distinct().Count(),
                        TotalVulnerabilities = hostVulnerabilities.Count,
                        CriticalCount = hostVulnerabilities.Count(v => v.Severity == "严重"),
                        HighCount = hostVulnerabilities.Count(v => v.Severity == "高"),
                        MediumCount = hostVulnerabilities.Count(v => v.Severity == "中"),
                        LowCount = hostVulnerabilities.Count(v => v.Severity == "低"),
                        LastScanTime = hostResults.Max(r => r.ScanTime)
                    };
                    
                    // 计算安全评分 (100分制，漏洞越多分数越低)
                    double baseScore = 100;
                    baseScore -= score.CriticalCount * 20;
                    baseScore -= score.HighCount * 10;
                    baseScore -= score.MediumCount * 5;
                    baseScore -= score.LowCount * 2;
                    score.SecurityScore = Math.Max(0, baseScore);
                    
                    // 确定安全等级
                    score.SecurityLevel = score.SecurityScore >= 80 ? "安全" :
                        score.SecurityScore >= 60 ? "一般" :
                        score.SecurityScore >= 40 ? "危险" : "高危";
                    
                    scores.Add(score);
                }
                
                _logger.Info($"主机安全评分获取完成: {scores.Count} 个主机");
                
                await Task.CompletedTask;
                return scores.OrderBy(s => s.SecurityScore).ToList();
            }
            catch (Exception ex)
            {
                _logger.Error($"获取主机安全评分失败: {ex.Message}");
                return new List<HostSecurityScore>();
            }
        }
        
        /// <summary>
        /// 计算风险评分
        /// </summary>
        private double CalculateRiskScore(List<Vulnerability> vulnerabilities)
        {
            if (!vulnerabilities.Any())
                return 0;
            
            double totalScore = 0;
            foreach (var vuln in vulnerabilities)
            {
                double weight = vuln.Severity switch
                {
                    "严重" => 10,
                    "高" => 7,
                    "中" => 4,
                    "低" => 1,
                    _ => 1
                };
                
                totalScore += vuln.CvssScore * weight;
            }
            
            // 归一化到0-100
            return Math.Min(100, totalScore / vulnerabilities.Count * 2);
        }
        
        /// <summary>
        /// 获取风险等级名称
        /// </summary>
        private string GetRiskLevelName(double score)
        {
            return score switch
            {
                >= 80 => "严重",
                >= 60 => "高",
                >= 40 => "中",
                >= 20 => "低",
                _ => "信息"
            };
        }
        
        /// <summary>
        /// 获取风险等级
        /// </summary>
        private string GetRiskLevel(double cvssScore)
        {
            return cvssScore switch
            {
                >= 9.0 => "严重",
                >= 7.0 => "高",
                >= 4.0 => "中",
                > 0 => "低",
                _ => "信息"
            };
        }
        
        /// <summary>
        /// 计算持续时间
        /// </summary>
        private string CalculateDuration(DateTime startTime, DateTime? endTime)
        {
            if (!endTime.HasValue)
                return "进行中";
            
            var duration = endTime!.Value - startTime;
            
            if (duration.TotalHours >= 1)
                return $"{duration.TotalHours:F1} 小时";
            if (duration.TotalMinutes >= 1)
                return $"{duration.TotalMinutes:F1} 分钟";
            
            return $"{duration.TotalSeconds:F0} 秒";
        }
        
        /// <summary>
        /// 分析服务
        /// </summary>
        private List<ServiceAnalysis> AnalyzeServices(List<ScanResult> results)
        {
            return results
                .Where(r => !string.IsNullOrEmpty(r.Service))
                .GroupBy(r => r.Service)
                .Select(g => new ServiceAnalysis
                {
                    ServiceName = g.Key,
                    PortCount = g.Select(r => r.Port).Distinct().Count(),
                    InstanceCount = g.Count(),
                    RiskLevel = "未知" // 可以根据漏洞情况计算
                })
                .OrderByDescending(s => s.InstanceCount)
                .ToList();
        }
        
        /// <summary>
        /// 分析漏洞趋势
        /// </summary>
        private VulnerabilityTrend AnalyzeVulnerabilityTrend(List<Vulnerability> vulnerabilities)
        {
            var trend = new VulnerabilityTrend
            {
                TotalCount = vulnerabilities.Count
            };
            
            // 按严重程度分组
            trend.BySeverity = vulnerabilities
                .GroupBy(v => v.Severity)
                .ToDictionary(g => g.Key, g => g.Count());
            
            // 按发现时间分组 (最近7天)
            var recentDate = DateTime.Now.AddDays(-7);
            trend.RecentCount = vulnerabilities.Count(v => v.DiscoveryTime >= recentDate);
            
            return trend;
        }
        
        /// <summary>
        /// 生成修复建议
        /// </summary>
        private List<RemediationSuggestion> GenerateRemediationSuggestions(List<Vulnerability> vulnerabilities)
        {
            var suggestions = new List<RemediationSuggestion>();
            
            // 按严重程度排序
            var sortedVulns = vulnerabilities
                .OrderByDescending(v => v.CvssScore)
                .Take(10)
                .ToList();
            
            int priority = 1;
            foreach (var vuln in sortedVulns)
            {
                suggestions.Add(new RemediationSuggestion
                {
                    Priority = priority++,
                    VulnerabilityId = vuln.VulnerabilityId,
                    VulnerabilityName = vuln.Name,
                    Severity = vuln.Severity,
                    CvssScore = vuln.CvssScore,
                    Suggestion = !string.IsNullOrEmpty(vuln.Solution) 
                        ? vuln.Solution 
                        : "建议升级相关组件到最新版本",
                    EstimatedEffort = EstimateRemediationEffort(vuln)
                });
            }
            
            return suggestions;
        }
        
        /// <summary>
        /// 估计修复工作量
        /// </summary>
        private string EstimateRemediationEffort(Vulnerability vulnerability)
        {
            return vulnerability.Severity switch
            {
                "严重" => "高 (1-2天)",
                "高" => "中高 (半天-1天)",
                "中" => "中 (2-4小时)",
                "低" => "低 (1小时内)",
                _ => "未知"
            };
        }
    }
    
    /// <summary>
    /// 总体统计
    /// </summary>
    public class OverallStatistics
    {
        public int TotalTasks { get; set; }
        public int CompletedTasks { get; set; }
        public int FailedTasks { get; set; }
        public int InProgressTasks { get; set; }
        
        public int TotalScanResults { get; set; }
        public int TotalVulnerabilities { get; set; }
        
        public int CriticalVulnerabilities { get; set; }
        public int HighVulnerabilities { get; set; }
        public int MediumVulnerabilities { get; set; }
        public int LowVulnerabilities { get; set; }
        
        public double AverageCvssScore { get; set; }
        public Dictionary<string, int> RiskLevelDistribution { get; set; } = new Dictionary<string, int>();
        public Dictionary<string, int> TopServices { get; set; } = new Dictionary<string, int>();
        public Dictionary<int, int> TopPorts { get; set; } = new Dictionary<int, int>();
        
        public DateTime LastUpdated { get; set; }
    }
    
    /// <summary>
    /// 任务分析
    /// </summary>
    public class TaskAnalysis
    {
        public int TaskId { get; set; }
        public string TaskName { get; set; }
        public string TargetHosts { get; set; }
        public string ScanType { get; set; }
        public string Status { get; set; }
        public DateTime StartTime { get; set; }
        public DateTime? EndTime { get; set; }
        public string Duration { get; set; }
        
        public int TotalOpenPorts { get; set; }
        public int TotalVulnerabilities { get; set; }
        
        public int CriticalCount { get; set; }
        public int HighCount { get; set; }
        public int MediumCount { get; set; }
        public int LowCount { get; set; }
        
        public double RiskScore { get; set; }
        public string RiskLevel { get; set; }
        
        public List<Vulnerability> Vulnerabilities { get; set; } = new List<Vulnerability>();
        public List<ScanResult> ScanResults { get; set; } = new List<ScanResult>();
        public List<ServiceAnalysis> ServiceAnalysis { get; set; } = new List<ServiceAnalysis>();
        public VulnerabilityTrend VulnerabilityTrend { get; set; }
        public List<RemediationSuggestion> RemediationSuggestions { get; set; } = new List<RemediationSuggestion>();
    }
    
    /// <summary>
    /// 服务分析
    /// </summary>
    public class ServiceAnalysis
    {
        public string ServiceName { get; set; }
        public int PortCount { get; set; }
        public int InstanceCount { get; set; }
        public string RiskLevel { get; set; }
    }
    
    /// <summary>
    /// 漏洞趋势
    /// </summary>
    public class VulnerabilityTrend
    {
        public int TotalCount { get; set; }
        public int RecentCount { get; set; }
        public Dictionary<string, int> BySeverity { get; set; } = new Dictionary<string, int>();
    }
    
    /// <summary>
    /// 修复建议
    /// </summary>
    public class RemediationSuggestion
    {
        public int Priority { get; set; }
        public int VulnerabilityId { get; set; }
        public string VulnerabilityName { get; set; }
        public string Severity { get; set; }
        public double CvssScore { get; set; }
        public string Suggestion { get; set; }
        public string EstimatedEffort { get; set; }
    }
    
    /// <summary>
    /// 趋势分析
    /// </summary>
    public class TrendAnalysis
    {
        public int PeriodDays { get; set; }
        public DateTime StartDate { get; set; }
        public DateTime EndDate { get; set; }
        public List<DailyScanStats> DailyStatistics { get; set; } = new List<DailyScanStats>();
        public double VulnerabilityTrend { get; set; }
        public string TrendDirection { get; set; }
        public Dictionary<string, int> VulnerabilityTypeDistribution { get; set; } = new Dictionary<string, int>();
    }
    
    /// <summary>
    /// 每日扫描统计
    /// </summary>
    public class DailyScanStats
    {
        public DateTime Date { get; set; }
        public int TaskCount { get; set; }
        public int VulnerabilityCount { get; set; }
    }
    
    /// <summary>
    /// 主机安全评分
    /// </summary>
    public class HostSecurityScore
    {
        public string Host { get; set; }
        public int OpenPorts { get; set; }
        public int TotalVulnerabilities { get; set; }
        public int CriticalCount { get; set; }
        public int HighCount { get; set; }
        public int MediumCount { get; set; }
        public int LowCount { get; set; }
        public double SecurityScore { get; set; }
        public string SecurityLevel { get; set; }
        public DateTime LastScanTime { get; set; }
    }
}
