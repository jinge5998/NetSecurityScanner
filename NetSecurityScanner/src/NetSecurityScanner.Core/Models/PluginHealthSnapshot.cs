using System;
using System.Collections.Generic;

namespace NetSecurityScanner.Models
{
    /// <summary>
    /// 插件健康快照（v6 由 HealthMonitor 周期采样 + 单次执行 EndSample 时更新）
    /// </summary>
    public class PluginHealthSnapshot
    {
        public string PluginId { get; set; } = string.Empty;
        public string Name { get; set; } = string.Empty;
        public int HealthScore { get; set; } = 100; // 0-100
        public int ConsecutiveFailures { get; set; }
        public DateTime? LastFailureAt { get; set; }
        public string? LastError { get; set; }
        public long PeakMemoryBytes { get; set; }
        public long TotalElapsedMs { get; set; }
        public int TotalExecutions { get; set; }
        public int TotalFailures { get; set; }
        public int TotalTimeouts { get; set; }
        public bool IsQuarantined { get; set; }
        public DateTime? QuarantinedAt { get; set; }
        public List<PluginExecutionSample> RecentSamples { get; set; } = new();

        // v7 扩展
        public double CpuUsagePercent { get; set; } // 0-100
        public DateTime? CooldownUntil { get; set; } // 隔离冷却期截止
    }

    public class PluginExecutionSample
    {
        public DateTime Timestamp { get; set; } = DateTime.Now;
        public bool Success { get; set; }
        public long ElapsedMs { get; set; }
        public long MemoryDeltaBytes { get; set; }
        public string? Error { get; set; }
    }
}
