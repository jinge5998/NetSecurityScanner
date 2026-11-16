using System;
using System.Collections.Generic;

namespace NetSecurityScanner.Models
{
    /// <summary>
    /// 目标风险画像 - 按目标IP组织的完整风险评估
    /// </summary>
    public class TargetRiskProfile
    {
        /// <summary>
        /// 目标IP地址
        /// </summary>
        public string TargetIp { get; set; } = string.Empty;
        
        /// <summary>
        /// 目标主机名（如可解析）
        /// </summary>
        public string? Hostname { get; set; }
        
        /// <summary>
        /// 评估时间
        /// </summary>
        public DateTime AssessmentTime { get; set; }
        
        /// <summary>
        /// 总体风险评分 (0-100)
        /// </summary>
        public double TotalRiskScore { get; set; }
        
        /// <summary>
        /// 总体风险等级
        /// </summary>
        public string OverallRiskLevel { get; set; } = "低";
        
        /// <summary>
        /// 资产价值评分 (0-100)
        /// </summary>
        public double AssetValueScore { get; set; }
        
        /// <summary>
        /// 暴露面评分 (0-100，越高越危险)
        /// </summary>
        public double ExposureScore { get; set; }
        
        /// <summary>
        /// 漏洞统计
        /// </summary>
        public VulnerabilityStatistics VulnStats { get; set; } = new VulnerabilityStatistics();
        
        /// <summary>
        /// 端口统计
        /// </summary>
        public PortStatistics PortStats { get; set; } = new PortStatistics();
        
        /// <summary>
        /// 漏洞详情列表
        /// </summary>
        public List<VulnerabilityDetail> Vulnerabilities { get; set; } = new List<VulnerabilityDetail>();
        
        /// <summary>
        /// 开放端口列表
        /// </summary>
        public List<PortScanResult> OpenPorts { get; set; } = new List<PortScanResult>();
        
        /// <summary>
        /// 敏感端口列表
        /// </summary>
        public List<PortScanResult> SensitivePorts { get; set; } = new List<PortScanResult>();
        
        /// <summary>
        /// 攻击路径列表
        /// </summary>
        public List<AttackPath> AttackPaths { get; set; } = new List<AttackPath>();
        
        /// <summary>
        /// 风险分布
        /// </summary>
        public List<RiskCategory> RiskDistribution { get; set; } = new List<RiskCategory>();
        
        /// <summary>
        /// 修复建议列表
        /// </summary>
        public List<RemediationTask> RemediationTasks { get; set; } = new List<RemediationTask>();
        
        /// <summary>
        /// 安全建议摘要
        /// </summary>
        public string SecurityAdvice { get; set; } = string.Empty;
        
        /// <summary>
        /// 风险趋势（历史数据）
        /// </summary>
        public List<RiskTrend> RiskTrends { get; set; } = new List<RiskTrend>();
    }
    
    /// <summary>
    /// 漏洞统计信息
    /// </summary>
    public class VulnerabilityStatistics
    {
        public int TotalCount { get; set; }
        public int CriticalCount { get; set; }
        public int HighCount { get; set; }
        public int MediumCount { get; set; }
        public int LowCount { get; set; }
        public int InfoCount { get; set; }
        public double AverageCvssScore { get; set; }
        public int UniqueTypes { get; set; }
    }
    
    /// <summary>
    /// 端口统计信息
    /// </summary>
    public class PortStatistics
    {
        public int TotalOpen { get; set; }
        public int SensitiveCount { get; set; }
        public int WebServiceCount { get; set; }
        public int DatabaseCount { get; set; }
        public int RemoteAccessCount { get; set; }
        public List<int> PortRangeDistribution { get; set; } = new List<int>();
    }
    
    /// <summary>
    /// 攻击路径
    /// </summary>
    public class AttackPath
    {
        /// <summary>
        /// 路径ID
        /// </summary>
        public string PathId { get; set; } = Guid.NewGuid().ToString("N")[..8];
        
        /// <summary>
        /// 路径名称
        /// </summary>
        public string Name { get; set; } = string.Empty;
        
        /// <summary>
        /// 路径描述
        /// </summary>
        public string Description { get; set; } = string.Empty;
        
        /// <summary>
        /// 攻击步骤
        /// </summary>
        public List<AttackStep> Steps { get; set; } = new List<AttackStep>();
        
        /// <summary>
        /// 路径风险评分
        /// </summary>
        public double RiskScore { get; set; }
        
        /// <summary>
        /// 路径复杂度 (1-10)
        /// </summary>
        public int Complexity { get; set; }
        
        /// <summary>
        /// 成功概率 (0-100)
        /// </summary>
        public double SuccessProbability { get; set; }
        
        /// <summary>
        /// 潜在影响
        /// </summary>
        public string Impact { get; set; } = string.Empty;
    }
    
    /// <summary>
    /// 攻击步骤
    /// </summary>
    public class AttackStep
    {
        public int StepNumber { get; set; }
        public string Title { get; set; } = string.Empty;
        public string Description { get; set; } = string.Empty;
        public string RequiredVulnerability { get; set; } = string.Empty;
        public string TargetPort { get; set; } = string.Empty;
        public double StepRisk { get; set; }
    }
    
    /// <summary>
    /// 风险趋势数据点
    /// </summary>
    public class RiskTrend
    {
        public DateTime Timestamp { get; set; }
        public double RiskScore { get; set; }
        public int VulnerabilityCount { get; set; }
        public int OpenPortCount { get; set; }
        public string RiskLevel { get; set; } = string.Empty;
    }
    
    /// <summary>
    /// 修复任务
    /// </summary>
    public class RemediationTask
    {
        /// <summary>
        /// 任务ID
        /// </summary>
        public int Id { get; set; }
        
        /// <summary>
        /// 任务唯一标识
        /// </summary>
        public string TaskId { get; set; } = Guid.NewGuid().ToString("N")[..8];
        
        /// <summary>
        /// 优先级 (1-100，越高越优先)
        /// </summary>
        public int Priority { get; set; }
        
        /// <summary>
        /// 优先级等级
        /// </summary>
        public string PriorityLevel { get; set; } = "低";
        
        /// <summary>
        /// 任务标题
        /// </summary>
        public string Title { get; set; } = string.Empty;
        
        /// <summary>
        /// 任务描述
        /// </summary>
        public string Description { get; set; } = string.Empty;
        
        /// <summary>
        /// 关联的漏洞
        /// </summary>
        public string RelatedVulnerability { get; set; } = string.Empty;
        
        /// <summary>
        /// 关联的端口
        /// </summary>
        public int? RelatedPort { get; set; }
        
        /// <summary>
        /// 修复难度 (1-10)
        /// </summary>
        public int Difficulty { get; set; }
        
        /// <summary>
        /// 预计修复时间（小时）
        /// </summary>
        public double EstimatedHours { get; set; }
        
        /// <summary>
        /// 修复建议
        /// </summary>
        public string Solution { get; set; } = string.Empty;
        
        /// <summary>
        /// 参考链接
        /// </summary>
        public string References { get; set; } = string.Empty;
        
        /// <summary>
        /// 风险降低值
        /// </summary>
        public double RiskReduction { get; set; }
        
        /// <summary>
        /// 成本效益比
        /// </summary>
        public double CostBenefitRatio => RiskReduction / Math.Max(Difficulty, 1);
    }
    
    /// <summary>
    /// 资产价值评估
    /// </summary>
    public class AssetValue
    {
        public string ServiceName { get; set; } = string.Empty;
        public int Port { get; set; }
        public double ValueScore { get; set; }
        public string Category { get; set; } = string.Empty; // Web, Database, RemoteAccess, etc.
        public string Importance { get; set; } = string.Empty; // Critical, High, Medium, Low
        public string Justification { get; set; } = string.Empty;
    }
    
    /// <summary>
    /// 合规性检查项
    /// </summary>
    public class ComplianceItem
    {
        /// <summary>
        /// 标准名称 (OWASP/NIST等)
        /// </summary>
        public string Standard { get; set; } = string.Empty;
        
        /// <summary>
        /// 控制项ID
        /// </summary>
        public string ControlId { get; set; } = string.Empty;
        
        /// <summary>
        /// 控制项描述
        /// </summary>
        public string Description { get; set; } = string.Empty;
        
        /// <summary>
        /// 合规状态
        /// </summary>
        public string Status { get; set; } = string.Empty; // 符合/不符合/需改进
        
        /// <summary>
        /// 相关漏洞数量
        /// </summary>
        public string RelatedVulnerabilities { get; set; } = "0";
    }
}
