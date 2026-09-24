using System;
using System.Collections.Generic;

namespace NetSecurityScanner.Models;

/// <summary>
/// 综合扫描可重用结果（v1.0.1.3 引入，ComprehensiveScanService 唯一出参契约）。
/// </summary>
public class ComprehensiveScanResult
{
    /// <summary>扫描唯一 ID（前缀 COMPREHENSIVE_yyyyMMdd_HHmmss）</summary>
    public string ScanId { get; set; } = string.Empty;

    /// <summary>目标 IP / 域名</summary>
    public string TargetIp { get; set; } = string.Empty;

    /// <summary>扫描类型描述（TCP+UDP综合扫描 / TCP综合扫描 / UDP综合扫描）</summary>
    public string ScanType { get; set; } = string.Empty;

    /// <summary>扫描开始时间</summary>
    public DateTime ScanTime { get; set; }

    /// <summary>总耗时（秒）</summary>
    public double ScanDurationSeconds { get; set; }

    /// <summary>主机是否存活（ICMP 或 80/443 TCP 回退探测）</summary>
    public bool HostAlive { get; set; }

    /// <summary>TCP 开放端口数（=Status=="开放"）</summary>
    public int TcpOpenPorts { get; set; }

    /// <summary>UDP 开放端口数</summary>
    public int UdpOpenPorts { get; set; }

    /// <summary>所有端口扫描结果（TCP + UDP 合并）</summary>
    public List<PortScanResult> AllPortResults { get; set; } = new();

    /// <summary>漏洞扫描结果</summary>
    public List<VulnerabilityResult> VulnerabilityResults { get; set; } = new();

    /// <summary>插件扫描结果</summary>
    public List<VulnerabilityResult> PluginResults { get; set; } = new();

    /// <summary>总开放端口数（TCP + UDP）</summary>
    public int OpenPortsCount => TcpOpenPorts + UdpOpenPorts;

    /// <summary>总漏洞数（漏洞 + 插件）</summary>
    public int VulnerabilitiesCount => VulnerabilityResults.Count + PluginResults.Count;

    /// <summary>风险等级（无风险 / 低风险 / 中风险 / 高风险 / 严重风险）</summary>
    public string RiskLevel { get; set; } = "无风险";

    /// <summary>6 阶段执行详情（用于 UI 时间线展示）</summary>
    public List<ScanPhaseExecution> Phases { get; set; } = new();

    /// <summary>漏洞扫描阶段是否出错（true = 阶段失败但流程继续）</summary>
    public bool HasVulnerabilityScanError { get; set; }

    /// <summary>插件扫描阶段是否出错</summary>
    public bool HasPluginScanError { get; set; }

    /// <summary>用户是否取消（true = 通过 CancellationToken 主动中止）</summary>
    public bool Cancelled { get; set; }

    /// <summary>扫描摘要（用于 MessageBox / 复制为 Markdown）</summary>
    public string Summary
    {
        get
        {
            var sb = new System.Text.StringBuilder();
            sb.AppendLine($"目标: {TargetIp}");
            sb.AppendLine($"扫描类型: {ScanType}");
            sb.AppendLine($"主机存活: {(HostAlive ? "是" : "否（结果可能不完整）")}");
            sb.AppendLine($"开放端口: {OpenPortsCount}（TCP {TcpOpenPorts} / UDP {UdpOpenPorts}）");
            sb.AppendLine($"漏洞数: {VulnerabilitiesCount}（漏洞扫描 {VulnerabilityResults.Count} / 插件扫描 {PluginResults.Count}）");
            sb.AppendLine($"风险等级: {RiskLevel}");
            sb.AppendLine($"耗时: {ScanDurationSeconds:F1} 秒");
            if (HasVulnerabilityScanError) sb.AppendLine("⚠ 漏洞扫描阶段出现异常");
            if (HasPluginScanError) sb.AppendLine("⚠ 插件扫描阶段出现异常");
            if (Cancelled) sb.AppendLine("⛔ 扫描已被用户取消");
            return sb.ToString();
        }
    }
}

/// <summary>
/// 综合扫描单阶段执行记录
/// </summary>
public class ScanPhaseExecution
{
    /// <summary>阶段标识（来自 ScanPhase 枚举）</summary>
    public ScanPhase Phase { get; set; }

    /// <summary>阶段中文名（用于 UI 展示）</summary>
    public string PhaseName { get; set; } = string.Empty;

    /// <summary>阶段状态</summary>
    public ScanPhaseStatus Status { get; set; } = ScanPhaseStatus.Pending;

    /// <summary>阶段耗时（毫秒）</summary>
    public long DurationMs { get; set; }

    /// <summary>阶段开始时间</summary>
    public DateTime StartTime { get; set; }

    /// <summary>阶段结束时间</summary>
    public DateTime EndTime { get; set; }

    /// <summary>异常信息（如有）</summary>
    public string? ErrorMessage { get; set; }

    /// <summary>阶段输出统计（如端口数 / 漏洞数）</summary>
    public int OutputCount { get; set; }
}

/// <summary>
/// 综合扫描阶段执行状态
/// </summary>
public enum ScanPhaseStatus
{
    Pending,
    Running,
    Success,
    Failed,
    Skipped
}
