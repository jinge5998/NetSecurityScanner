using System.Collections.Generic;

namespace NetSecurityScanner.Models;

/// <summary>
/// 综合扫描可重用配置（v1.0.1.3 引入，ComprehensiveScanService 唯一入参契约）。
/// 桌面 UI / CLI / Web API 复用同一份配置。
/// </summary>
public class ComprehensiveScanOptions
{
    /// <summary>目标 IP / 域名（必填）</summary>
    public string TargetIp { get; set; } = string.Empty;

    /// <summary>扫描预设（Quick / Standard / Deep / Web / Database / Custom）</summary>
    public ScanPreset Preset { get; set; } = ScanPreset.Standard;

    /// <summary>仅当 Preset=Custom 时生效（支持 "1-100,443,8080-8090" 混合格式）</summary>
    public string CustomPorts { get; set; } = string.Empty;

    /// <summary>启用 TCP 端口扫描</summary>
    public bool EnableTcp { get; set; } = true;

    /// <summary>启用 UDP 端口扫描</summary>
    public bool EnableUdp { get; set; } = true;

    /// <summary>启用漏洞扫描（基于开放端口）</summary>
    public bool EnableVulnScan { get; set; } = true;

    /// <summary>启用插件扫描（PluginOrchestrator）</summary>
    public bool EnablePluginScan { get; set; } = true;

    /// <summary>并发线程数（1-1000，默认 200）</summary>
    public int Concurrency { get; set; } = 200;

    /// <summary>单端口超时秒数（1-300，默认 5）</summary>
    public int TimeoutSeconds { get; set; } = 5;

    /// <summary>单端口失败重试次数（0-3，默认 1）</summary>
    public int RetryCount { get; set; } = 1;

    /// <summary>保存结果到历史记录</summary>
    public bool SaveToHistory { get; set; } = true;

    /// <summary>主机存活探测超时毫秒（默认 3000）</summary>
    public int HostDiscoveryTimeoutMs { get; set; } = 3000;
}

/// <summary>
/// 综合扫描内置预设枚举
/// </summary>
public enum ScanPreset
{
    /// <summary>Top-100 常用端口，预估 ~5 秒</summary>
    Quick,
    /// <summary>1-1000 端口，预估 ~30 秒（默认）</summary>
    Standard,
    /// <summary>1-65535 全端口，预估 ~10 分钟（需提升 Concurrency）</summary>
    Deep,
    /// <summary>Web 服务常用端口（80/443/8000/8080/8443/9200...）</summary>
    Web,
    /// <summary>数据库常用端口（1433/1521/3306/5432/6379/27017...）</summary>
    Database,
    /// <summary>用户自定义（由 ComprehensiveScanOptions.CustomPorts 决定）</summary>
    Custom
}
