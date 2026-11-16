using NetSecurityScanner.Models;
using System;
using System.Collections.Generic;
using System.Linq;

namespace NetSecurityScanner.Services
{
    public class ScanComparisonService
    {
        /// <summary>
        /// 对比两次扫描结果
        /// </summary>
        public ScanComparisonResult CompareScans(ScanHistory baseline, ScanHistory current)
        {
            var result = new ScanComparisonResult
            {
                BaselineScan = baseline,
                CurrentScan = current,
                ComparisonTime = DateTime.Now
            };

            // 对比漏洞
            CompareVulnerabilities(result);

            // 对比端口
            ComparePorts(result);

            // 计算风险变化
            CalculateRiskChanges(result);

            return result;
        }

        private void CompareVulnerabilities(ScanComparisonResult result)
        {
            var baselineVulns = result.BaselineScan.Vulnerabilities ?? new List<VulnerabilityRecord>();
            var currentVulns = result.CurrentScan.Vulnerabilities ?? new List<VulnerabilityRecord>();

            // 新增的漏洞（当前有，基线没有）
            result.NewVulnerabilities = currentVulns
                .Where(cv => !baselineVulns.Any(bv => bv.CveId == cv.CveId && bv.Port == cv.Port))
                .ToList();

            // 修复的漏洞（基线有，当前没有）
            result.ResolvedVulnerabilities = baselineVulns
                .Where(bv => !currentVulns.Any(cv => cv.CveId == bv.CveId && cv.Port == bv.Port))
                .ToList();

            // 仍然存在的漏洞
            result.PersistentVulnerabilities = currentVulns
                .Where(cv => baselineVulns.Any(bv => bv.CveId == cv.CveId && bv.Port == cv.Port))
                .ToList();

            // 风险等级变化的漏洞
            result.RiskChangedVulnerabilities = new List<RiskChangedVulnerability>();
            foreach (var cv in currentVulns)
            {
                var bv = baselineVulns.FirstOrDefault(b => b.CveId == cv.CveId && b.Port == cv.Port);
                if (bv != null && bv.RiskLevel != cv.RiskLevel)
                {
                    result.RiskChangedVulnerabilities.Add(new RiskChangedVulnerability
                    {
                        Vulnerability = cv,
                        OldRiskLevel = bv.RiskLevel,
                        NewRiskLevel = cv.RiskLevel
                    });
                }
            }
        }

        private void ComparePorts(ScanComparisonResult result)
        {
            // 从扫描历史中获取开放端口列表（这里简化处理，实际应该从端口扫描结果中获取）
            var baselinePorts = new List<int>();
            var currentPorts = new List<int>();

            // 新开放的端口
            result.NewOpenPorts = currentPorts.Except(baselinePorts).ToList();

            // 已关闭的端口
            result.ClosedPorts = baselinePorts.Except(currentPorts).ToList();

            // 仍然开放的端口
            result.PersistentOpenPorts = currentPorts.Intersect(baselinePorts).ToList();
        }

        private void CalculateRiskChanges(ScanComparisonResult result)
        {
            result.BaselineRiskScore = CalculateRiskScore(result.BaselineScan.Vulnerabilities);
            result.CurrentRiskScore = CalculateRiskScore(result.CurrentScan.Vulnerabilities);
            result.RiskScoreChange = result.CurrentRiskScore - result.BaselineRiskScore;

            // 漏洞数量变化
            result.VulnerabilityCountChange = 
                (result.CurrentScan.Vulnerabilities?.Count ?? 0) - 
                (result.BaselineScan.Vulnerabilities?.Count ?? 0);

            // 严重漏洞变化
            result.CriticalCountChange = 
                (result.CurrentScan.Vulnerabilities?.Count(v => v.RiskLevel == "严重") ?? 0) - 
                (result.BaselineScan.Vulnerabilities?.Count(v => v.RiskLevel == "严重") ?? 0);
        }

        private double CalculateRiskScore(List<VulnerabilityRecord> vulnerabilities)
        {
            if (vulnerabilities == null || !vulnerabilities.Any())
                return 0;

            double score = 0;
            foreach (var vuln in vulnerabilities)
            {
                score += vuln.RiskLevel switch
                {
                    "严重" => 10,
                    "高危" => 7,
                    "中危" => 4,
                    "低危" => 1,
                    _ => 0
                };
            }

            return Math.Min(score, 100); // 最高100分
        }

        /// <summary>
        /// 生成对比报告摘要
        /// </summary>
        public string GenerateComparisonSummary(ScanComparisonResult result)
        {
            var summary = new System.Text.StringBuilder();

            summary.AppendLine("# 扫描结果对比报告");
            summary.AppendLine($"对比时间: {result.ComparisonTime:yyyy-MM-dd HH:mm:ss}");
            summary.AppendLine();

            summary.AppendLine("## 扫描信息");
            summary.AppendLine($"基线扫描: {result.BaselineScan.Target} ({result.BaselineScan.ScanTime:yyyy-MM-dd HH:mm})");
            summary.AppendLine($"当前扫描: {result.CurrentScan.Target} ({result.CurrentScan.ScanTime:yyyy-MM-dd HH:mm})");
            summary.AppendLine();

            summary.AppendLine("## 风险评分变化");
            var changeSymbol = result.RiskScoreChange > 0 ? "📈" : result.RiskScoreChange < 0 ? "📉" : "➡️";
            summary.AppendLine($"{changeSymbol} 风险评分: {result.BaselineRiskScore:F1} → {result.CurrentRiskScore:F1} ({result.RiskScoreChange:F1})");
            summary.AppendLine();

            summary.AppendLine("## 漏洞变化统计");
            summary.AppendLine($"• 新增漏洞: {result.NewVulnerabilities.Count} 个");
            summary.AppendLine($"• 修复漏洞: {result.ResolvedVulnerabilities.Count} 个");
            summary.AppendLine($"• 仍然存在: {result.PersistentVulnerabilities.Count} 个");
            summary.AppendLine($"• 风险变化: {result.RiskChangedVulnerabilities.Count} 个");
            summary.AppendLine();

            summary.AppendLine("## 端口变化");
            summary.AppendLine($"• 新开放端口: {result.NewOpenPorts.Count} 个");
            summary.AppendLine($"• 已关闭端口: {result.ClosedPorts.Count} 个");
            summary.AppendLine($"• 仍然开放: {result.PersistentOpenPorts.Count} 个");
            summary.AppendLine();

            if (result.NewVulnerabilities.Any())
            {
                summary.AppendLine("## ⚠️ 新增漏洞");
                foreach (var vuln in result.NewVulnerabilities.OrderByDescending(v => GetRiskLevelValue(v.RiskLevel)))
                {
                    summary.AppendLine($"- [{vuln.RiskLevel}] {vuln.Name} (端口: {vuln.Port})");
                }
                summary.AppendLine();
            }

            if (result.ResolvedVulnerabilities.Any())
            {
                summary.AppendLine("## ✅ 已修复漏洞");
                foreach (var vuln in result.ResolvedVulnerabilities)
                {
                    summary.AppendLine($"- [{vuln.RiskLevel}] {vuln.Name} (端口: {vuln.Port})");
                }
                summary.AppendLine();
            }

            return summary.ToString();
        }

        private int GetRiskLevelValue(string riskLevel)
        {
            return riskLevel switch
            {
                "严重" => 4,
                "高危" => 3,
                "中危" => 2,
                "低危" => 1,
                _ => 0
            };
        }
    }

    public class ScanComparisonResult
    {
        public ScanHistory BaselineScan { get; set; }
        public ScanHistory CurrentScan { get; set; }
        public DateTime ComparisonTime { get; set; }

        // 漏洞对比
        public List<VulnerabilityRecord> NewVulnerabilities { get; set; } = new();
        public List<VulnerabilityRecord> ResolvedVulnerabilities { get; set; } = new();
        public List<VulnerabilityRecord> PersistentVulnerabilities { get; set; } = new();
        public List<RiskChangedVulnerability> RiskChangedVulnerabilities { get; set; } = new();

        // 端口对比
        public List<int> NewOpenPorts { get; set; } = new();
        public List<int> ClosedPorts { get; set; } = new();
        public List<int> PersistentOpenPorts { get; set; } = new();

        // 风险评分
        public double BaselineRiskScore { get; set; }
        public double CurrentRiskScore { get; set; }
        public double RiskScoreChange { get; set; }
        public int VulnerabilityCountChange { get; set; }
        public int CriticalCountChange { get; set; }
    }

    public class RiskChangedVulnerability
    {
        public VulnerabilityRecord Vulnerability { get; set; }
        public string OldRiskLevel { get; set; }
        public string NewRiskLevel { get; set; }
    }
}
