using System.Collections.Generic;

namespace NetSecurityScanner.Models;

/// <summary>
/// 综合扫描进度事件载荷（IProgress&lt;ScanPhaseProgress&gt; 的 T）
/// </summary>
public class ScanPhaseProgress
{
    /// <summary>当前阶段</summary>
    public ScanPhase Phase { get; set; }

    /// <summary>当前阶段中文名（用于 UI 步骤条）</summary>
    public string PhaseName { get; set; } = string.Empty;

    /// <summary>阶段内子进度 0-100</summary>
    public int SubProgress { get; set; }

    /// <summary>总体进度 0-100（UI 主进度条用）</summary>
    public int Progress { get; set; }

    /// <summary>当前正在处理的项（端口号 / 漏洞类型 / 插件名等）</summary>
    public string? CurrentItem { get; set; }

    /// <summary>已发现的开放端口列表（实时追加）</summary>
    public List<int> DiscoveredPorts { get; set; } = new();

    /// <summary>已用时间（毫秒）</summary>
    public long ElapsedMs { get; set; }

    /// <summary>估算剩余时间（毫秒，-1 = 未知）</summary>
    public long EstimatedRemainingMs { get; set; } = -1;

    /// <summary>当前阶段状态消息（如"扫描端口 80/1000"）</summary>
    public string Message { get; set; } = string.Empty;
}

/// <summary>
/// 综合扫描阶段枚举（6 阶段 + 终态）
/// </summary>
public enum ScanPhase
{
    /// <summary>阶段 1：主机存活探测（ICMP + 80/443 TCP 回退）</summary>
    HostDiscovery = 0,
    /// <summary>阶段 2：TCP 端口扫描（与 UDP 并发）</summary>
    TcpPortScan = 1,
    /// <summary>阶段 3：UDP 端口扫描（与 TCP 并发）</summary>
    UdpPortScan = 2,
    /// <summary>阶段 4：服务版本识别（从 PortScanner 结果合并）</summary>
    ServiceDetection = 3,
    /// <summary>阶段 5：漏洞扫描（基于开放端口）</summary>
    VulnerabilityScan = 4,
    /// <summary>阶段 6：插件扫描（PluginOrchestrator）</summary>
    PluginScan = 5,
    /// <summary>阶段 7：风险等级汇总 + 历史记录保存</summary>
    RiskAssessment = 6
}
