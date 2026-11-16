namespace NetSecurityScanner.Models;

/// <summary>
/// Agent攻击面层级枚举 - 定义AI Agent系统的六层安全攻击面
/// </summary>
public enum AgentAttackSurfaceLayer
{
    /// <summary>
    /// LLM层：Prompt注入、模型窃取、训练数据泄露
    /// </summary>
    LLM,

    /// <summary>
    /// 工具层：命令注入、SSRF、不安全工具调用
    /// </summary>
    Tool,

    /// <summary>
    /// 记忆层：记忆投毒、上下文污染、RAG注入
    /// </summary>
    Memory,

    /// <summary>
    /// 流程层：流程劫持、循环攻击、资源耗尽
    /// </summary>
    Workflow,

    /// <summary>
    /// 传输层：中间人攻击、WebSocket劫持、会话接管
    /// </summary>
    Transport,

    /// <summary>
    /// 外部接口层：API滥用、回调投毒、Webhook劫持
    /// </summary>
    External
}
