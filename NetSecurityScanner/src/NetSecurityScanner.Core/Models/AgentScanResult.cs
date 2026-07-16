using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Linq;

namespace NetSecurityScanner.Models;

/// <summary>
/// Agent目标类型枚举 - 定义扫描目标的类型
/// </summary>
public enum AgentTargetType
{
    /// <summary>
    /// 单个文件
    /// </summary>
    File,

    /// <summary>
    /// 目录（递归扫描）
    /// </summary>
    Directory,

    /// <summary>
    /// 配置文本内容
    /// </summary>
    ConfigText,

    /// <summary>
    /// 剪贴板内容
    /// </summary>
    Clipboard
}

/// <summary>
/// Agent扫描结果模型 - 表示一次完整的Agent安全扫描结果
/// </summary>
[Serializable]
public class AgentScanResult
{
    /// <summary>
    /// 扫描任务唯一标识符
    /// </summary>
    public Guid ScanId { get; set; } = Guid.NewGuid();

    /// <summary>
    /// 扫描目标路径
    /// </summary>
    public string TargetPath { get; set; } = string.Empty;

    /// <summary>
    /// 目标类型
    /// </summary>
    public AgentTargetType TargetType { get; set; }

    /// <summary>
    /// Agent类型（如"OpenClaw"、"Hermes"、"Custom"）
    /// </summary>
    public string AgentType { get; set; } = string.Empty;

    /// <summary>
    /// 扫描开始时间
    /// </summary>
    public DateTime StartTime { get; set; } = DateTime.Now;

    /// <summary>
    /// 扫描结束时间（进行中为null）
    /// </summary>
    public DateTime? EndTime { get; set; }

    /// <summary>
    /// 扫描耗时（毫秒）
    /// </summary>
    public long DurationMs { get; set; }

    /// <summary>
    /// 总发现数
    /// </summary>
    public int TotalFindings { get; set; }

    /// <summary>
    /// 严重漏洞数量
    /// </summary>
    public int CriticalCount { get; set; }

    /// <summary>
    /// 高危漏洞数量
    /// </summary>
    public int HighCount { get; set; }

    /// <summary>
    /// 中危漏洞数量
    /// </summary>
    public int MediumCount { get; set; }

    /// <summary>
    /// 低危漏洞数量
    /// </summary>
    public int LowCount { get; set; }

    /// <summary>
    /// 信息级发现数量
    /// </summary>
    public int InfoCount { get; set; }

    /// <summary>
    /// 各阶段扫描结果
    /// </summary>
    public Dictionary<AgentScanPhase, List<AgentVulnerability>> PhaseResults { get; set; }
        = new Dictionary<AgentScanPhase, List<AgentVulnerability>>();

    /// <summary>
    /// 所有漏洞的只读集合
    /// </summary>
    public ReadOnlyCollection<AgentVulnerability> AllVulnerabilities { get; set; }

    /// <summary>
    /// 安全评分（0-100，分数越低风险越高）
    /// </summary>
    public int Score { get; set; }

    /// <summary>
    /// 是否已完成扫描
    /// </summary>
    public bool IsCompleted { get; set; }

    /// <summary>
    /// 是否被取消
    /// </summary>
    public bool IsCancelled { get; set; }

    /// <summary>
    /// 各攻击面层级的漏洞统计摘要
    /// </summary>
    public Dictionary<AgentAttackSurfaceLayer, int> AttackSurfaceSummary { get; set; }
        = new Dictionary<AgentAttackSurfaceLayer, int>();

    /// <summary>
    /// 构造函数 - 初始化集合属性
    /// </summary>
    public AgentScanResult()
    {
        // 初始化各阶段的空列表
        foreach (AgentScanPhase phase in Enum.GetValues(typeof(AgentScanPhase)))
        {
            PhaseResults[phase] = new List<AgentVulnerability>();
        }

        // 初始化攻击面统计
        foreach (AgentAttackSurfaceLayer layer in Enum.GetValues(typeof(AgentAttackSurfaceLayer)))
        {
            AttackSurfaceSummary[layer] = 0;
        }

        AllVulnerabilities = new List<AgentVulnerability>().AsReadOnly();
    }

    /// <summary>
    /// 根据扫描阶段获取漏洞列表
    /// </summary>
    /// <param name="phase">扫描阶段</param>
    /// <returns>该阶段发现的漏洞列表</returns>
    public List<AgentVulnerability> GetVulnerabilitiesByPhase(AgentScanPhase phase)
    {
        return PhaseResults.TryGetValue(phase, out var vulnerabilities)
            ? vulnerabilities
            : new List<AgentVulnerability>();
    }

    /// <summary>
    /// 根据攻击面层级获取漏洞列表
    /// </summary>
    /// <param name="layer">攻击面层级</param>
    /// <returns>该层级发现的漏洞列表</returns>
    public List<AgentVulnerability> GetVulnerabilitiesByLayer(AgentAttackSurfaceLayer layer)
    {
        if (AllVulnerabilities == null)
            return new List<AgentVulnerability>();

        return AllVulnerabilities.Where(v => v.AttackSurfaceLayer == layer).ToList();
    }

    /// <summary>
    /// 根据风险等级获取漏洞列表
    /// </summary>
    /// <param name="level">风险等级</param>
    /// <returns>该等级的漏洞列表</returns>
    public List<AgentVulnerability> GetByRiskLevel(AgentRiskLevel level)
    {
        if (AllVulnerabilities == null)
            return new List<AgentVulnerability>();

        return AllVulnerabilities.Where(v => v.RiskLevel == level).ToList();
    }
}
