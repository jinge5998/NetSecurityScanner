using System;
using System.Collections.Generic;

namespace NetSecurityScanner.Models
{
    /// <summary>
    /// 插件单次执行状态（与 NetSecurityScanner.Plugins.PluginExecutionStatus 同义，保留独立枚举避免依赖）
    /// </summary>
    public enum PluginExecutionStatus
    {
        /// <summary>成功</summary>
        Success,
        /// <summary>失败</summary>
        Failed,
        /// <summary>超时</summary>
        Timeout,
        /// <summary>取消</summary>
        Cancelled
    }

    /// <summary>
    /// 插件单次执行记录
    /// </summary>
    public class PluginExecutionEntry
    {
        public string PluginId { get; set; } = string.Empty;
        public string PluginName { get; set; } = string.Empty;
        public string Target { get; set; } = string.Empty;
        public int Port { get; set; }
        public string ServiceType { get; set; } = string.Empty;
        public DateTime StartTime { get; set; }
        public DateTime EndTime { get; set; }
        public long DurationMs { get; set; }
        public PluginExecutionStatus Status { get; set; }
        public int VulnCount { get; set; }
        public string? ErrorMessage { get; set; }
        public long MemoryDeltaKb { get; set; }

        // v6 兼容：审计写入用到的便捷属性
        public bool Success => Status == PluginExecutionStatus.Success;
    }

    /// <summary>
    /// 插件执行统计聚合
    /// </summary>
    public class PluginExecutionStatistics
    {
        public int TotalExecutions { get; set; }
        public int SuccessCount { get; set; }
        public int FailedCount { get; set; }
        public int TimeoutCount { get; set; }
        public double SuccessRate => TotalExecutions == 0 ? 0 : (double)SuccessCount / TotalExecutions;
        public double AverageDurationMs { get; set; }
        public Dictionary<string, int> FailedByPlugin { get; set; } = new();
        public Dictionary<string, int> Top10SlowestPlugins { get; set; } = new();
    }
}
