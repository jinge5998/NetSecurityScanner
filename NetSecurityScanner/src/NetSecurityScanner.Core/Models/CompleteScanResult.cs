using System;
using System.Collections.Generic;

namespace NetSecurityScanner.Models
{
    /// <summary>
    /// 完整扫描结果模型，包含端口扫描和漏洞扫描的完整数据
    /// </summary>
    public class CompleteScanResult
    {
        /// <summary>
        /// 扫描唯一标识符
        /// </summary>
        public string ScanId { get; set; } = Guid.NewGuid().ToString();
        
        /// <summary>
        /// 目标IP地址
        /// </summary>
        public string TargetIp { get; set; } = string.Empty;
        
        /// <summary>
        /// 扫描类型
        /// </summary>
        public string ScanType { get; set; } = string.Empty;
        
        /// <summary>
        /// 扫描时间
        /// </summary>
        public DateTime ScanTime { get; set; } = DateTime.Now;
        
        /// <summary>
        /// 扫描持续时间（秒）
        /// </summary>
        public double ScanDuration { get; set; }
        
        /// <summary>
        /// 开放端口数量
        /// </summary>
        public int OpenPortsCount { get; set; }
        
        /// <summary>
        /// 漏洞数量
        /// </summary>
        public int VulnerabilitiesCount { get; set; }
        
        /// <summary>
        /// 总体风险等级
        /// </summary>
        public string RiskLevel { get; set; } = string.Empty;
        
        /// <summary>
        /// 端口扫描结果列表
        /// </summary>
        public List<PortScanResult> PortScanResults { get; set; } = new List<PortScanResult>();
        
        /// <summary>
        /// 漏洞扫描结果列表
        /// </summary>
        public List<VulnerabilityResult> VulnerabilityResults { get; set; } = new List<VulnerabilityResult>();
        
        /// <summary>
        /// 风险评估结果
        /// </summary>
        public RiskAssessmentSummary RiskAssessment { get; set; } = new RiskAssessmentSummary();
    }
    
    /// <summary>
    /// 风险评估摘要
    /// </summary>
    public class RiskAssessmentSummary
    {
        /// <summary>
        /// 高风险漏洞数量
        /// </summary>
        public int HighRiskCount { get; set; }
        
        /// <summary>
        /// 中风险漏洞数量
        /// </summary>
        public int MediumRiskCount { get; set; }
        
        /// <summary>
        /// 低风险漏洞数量
        /// </summary>
        public int LowRiskCount { get; set; }
        
        /// <summary>
        /// 总漏洞数量
        /// </summary>
        public int TotalVulnerabilities { get; set; }
        
        /// <summary>
        /// 风险评分（0-100）
        /// </summary>
        public int RiskScore { get; set; }
        
        /// <summary>
        /// 风险等级
        /// </summary>
        public string RiskLevel { get; set; } = string.Empty;
        
        /// <summary>
        /// 安全建议
        /// </summary>
        public string SecurityAdvice { get; set; } = string.Empty;
    }
}