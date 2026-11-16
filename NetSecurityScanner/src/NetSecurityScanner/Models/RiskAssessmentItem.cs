using System;
using System.Collections.Generic;

namespace NetSecurityScanner.Models
{
    /// <summary>
    /// 风险评估项
    /// </summary>
    public class RiskAssessmentItem
    {
        public string Item { get; set; } = string.Empty;
        public string Value { get; set; } = string.Empty;
        public string Status { get; set; } = string.Empty;
    }
    
    /// <summary>
    /// 漏洞详情扩展类
    /// </summary>
    public class VulnerabilityDetail
    {
        public string IpAddress { get; set; } = string.Empty;
        public string VulnerabilityName { get; set; } = string.Empty;
        public string RiskLevel { get; set; } = string.Empty;
        public int Port { get; set; }
        public string Service { get; set; } = string.Empty;
        public string CveId { get; set; } = string.Empty;
        public string DetectionMethod { get; set; } = string.Empty;
        public string Description { get; set; } = string.Empty;
        public string Solution { get; set; } = string.Empty;
        public string ReferenceLinks { get; set; } = string.Empty;
        public double CvssScore { get; set; }
        public string CvssVector { get; set; } = string.Empty;
        public string ImpactDescription { get; set; } = string.Empty;
        public string Exploitability { get; set; } = string.Empty;
    }
    
    /// <summary>
    /// 风险类别统计
    /// </summary>
    public class RiskCategory
    {
        public string Category { get; set; } = string.Empty;
        public int Count { get; set; }
        public double Score { get; set; }
        public double Percentage { get; set; }
        public string Description { get; set; } = string.Empty;
    }
    
    /// <summary>
    /// 完整风险评估结果
    /// </summary>
    public class RiskAssessmentResult
    {
        /// <summary>
        /// 基本统计信息
        /// </summary>
        public RiskStatistics Statistics { get; set; } = new RiskStatistics();
        
        /// <summary>
        /// 风险分布（按等级）
        /// </summary>
        public List<RiskCategory> RiskDistribution { get; set; } = new List<RiskCategory>();
        
        /// <summary>
        /// 漏洞详情列表
        /// </summary>
        public List<VulnerabilityDetail> VulnerabilityDetails { get; set; } = new List<VulnerabilityDetail>();
        
        /// <summary>
        /// 开放端口信息
        /// </summary>
        public List<PortScanResult> OpenPorts { get; set; } = new List<PortScanResult>();
        
        /// <summary>
        /// 敏感开放端口
        /// </summary>
        public List<PortScanResult> SensitiveOpenPorts { get; set; } = new List<PortScanResult>();
        
        /// <summary>
        /// 安全建议
        /// </summary>
        public string SecurityAdvice { get; set; } = string.Empty;
        
        /// <summary>
        /// 总体风险评分
        /// </summary>
        public double TotalRiskScore { get; set; }
        
        /// <summary>
        /// 总体风险等级
        /// </summary>
        public string OverallRiskLevel { get; set; } = string.Empty;
        
        /// <summary>
        /// 风险评估时间
        /// </summary>
        public DateTime AssessmentTime { get; set; }
        
        /// <summary>
        /// 目标IP地址
        /// </summary>
        public string TargetIp { get; set; } = string.Empty;
    }
    
    /// <summary>
    /// 风险统计信息
    /// </summary>
    public class RiskStatistics
    {
        public int TotalVulnerabilities { get; set; }
        public int HighRiskCount { get; set; }
        public int MediumRiskCount { get; set; }
        public int LowRiskCount { get; set; }
        public int TotalOpenPorts { get; set; }
        public int SensitivePortCount { get; set; }
        public int UniqueVulnerabilityTypes { get; set; }
        public double AverageCvssScore { get; set; }
    }
}