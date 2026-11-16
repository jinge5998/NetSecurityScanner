namespace NetSecurityScanner.Models;

/// <summary>
/// Agent扫描阶段枚举 - 定义安全扫描的三个主要阶段
/// </summary>
public enum AgentScanPhase
{
    /// <summary>
    /// 静态分析：代码审查、配置检查、依赖分析
    /// </summary>
    StaticAnalysis,

    /// <summary>
    /// 意图研判：Prompt意图识别、恶意模式检测、行为预测
    /// </summary>
    IntentAnalysis,

    /// <summary>
    /// 行为沙箱：动态执行、工具调用监控、副作用检测
    /// </summary>
    BehaviorSandbox
}
