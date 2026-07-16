using System;
using System.Collections.Generic;

namespace NetSecurityScanner.Models;

/// <summary>
/// Agent扫描深度枚举 - 定义扫描的深度级别
/// </summary>
public enum AgentScanDepth
{
    /// <summary>
    /// 快速扫描：仅执行基础检查，适用于初步筛查
    /// </summary>
    Quick,

    /// <summary>
    /// 标准扫描：执行完整的常规检查，平衡速度与覆盖面
    /// </summary>
    Standard,

    /// <summary>
    /// 深度扫描：执行全面深入分析，包含复杂场景检测
    /// </summary>
    Deep
}

/// <summary>
/// Agent扫描配置选项模型 - 定义Agent安全扫描的各项配置参数
/// </summary>
[Serializable]
public class AgentScanOptions
{
    /// <summary>
    /// 扫描目标路径（文件路径、目录路径或文本内容）
    /// </summary>
    public string TargetPath { get; set; } = string.Empty;

    /// <summary>
    /// 目标类型
    /// </summary>
    public AgentTargetType TargetType { get; set; }

    /// <summary>
    /// 是否启用静态分析阶段（默认启用）
    /// </summary>
    public bool EnableStaticAnalysis { get; set; } = true;

    /// <summary>
    /// 是否启用意图研判阶段（默认启用）
    /// </summary>
    public bool EnableIntentAnalysis { get; set; } = true;

    /// <summary>
    /// 是否启用行为沙箱阶段（默认启用）
    /// </summary>
    public bool EnableBehaviorSandbox { get; set; } = true;

    /// <summary>
    /// 扫描深度（默认为标准扫描）
    /// </summary>
    public AgentScanDepth ScanDepth { get; set; } = AgentScanDepth.Standard;

    /// <summary>
    /// 是否自动检测Agent类型（默认启用）
    /// </summary>
    public bool AgentTypeAutoDetect { get; set; } = true;

    /// <summary>
    /// 是否包含依赖检查（默认启用）
    /// </summary>
    public bool IncludeDependencyCheck { get; set; } = true;

    /// <summary>
    /// 最大文件大小限制（单位：MB，默认10MB）
    /// </summary>
    public double MaxFileSizeMB { get; set; } = 10.0;

    /// <summary>
    /// 自定义关键词列表（用于扩展检测规则）
    /// </summary>
    public List<string> CustomKeywords { get; set; } = new List<string>();

    /// <summary>
    /// 创建标准扫描配置的工厂方法
    /// </summary>
    /// <param name="targetPath">目标路径</param>
    /// <param name="targetType">目标类型</param>
    /// <returns>配置好的扫描选项实例</returns>
    public static AgentScanOptions CreateStandard(string targetPath, AgentTargetType targetType)
    {
        return new AgentScanOptions
        {
            TargetPath = targetPath,
            TargetType = targetType,
            ScanDepth = AgentScanDepth.Standard,
            EnableStaticAnalysis = true,
            EnableIntentAnalysis = true,
            EnableBehaviorSandbox = true
        };
    }

    /// <summary>
    /// 创建快速扫描配置的工厂方法
    /// </summary>
    /// <param name="targetPath">目标路径</param>
    /// <param name="targetType">目标类型</param>
    /// <returns>配置好的快速扫描选项实例</returns>
    public static AgentScanOptions CreateQuick(string targetPath, AgentTargetType targetType)
    {
        return new AgentScanOptions
        {
            TargetPath = targetPath,
            TargetType = targetType,
            ScanDepth = AgentScanDepth.Quick,
            EnableStaticAnalysis = true,
            EnableIntentAnalysis = false,
            EnableBehaviorSandbox = false
        };
    }

    /// <summary>
    /// 创建深度扫描配置的工厂方法
    /// </summary>
    /// <param name="targetPath">目标路径</param>
    /// <param name="targetType">目标类型</param>
    /// <returns>配置好的深度扫描选项实例</returns>
    public static AgentScanOptions CreateDeep(string targetPath, AgentTargetType targetType)
    {
        return new AgentScanOptions
        {
            TargetPath = targetPath,
            TargetType = targetType,
            ScanDepth = AgentScanDepth.Deep,
            EnableStaticAnalysis = true,
            EnableIntentAnalysis = true,
            EnableBehaviorSandbox = true,
            IncludeDependencyCheck = true,
            MaxFileSizeMB = 50.0  // 深度扫描允许更大的文件
        };
    }
}
