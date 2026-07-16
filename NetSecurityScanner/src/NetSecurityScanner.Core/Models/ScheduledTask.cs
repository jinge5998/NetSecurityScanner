using System;
using System.Collections.Generic;

namespace NetSecurityScanner.Models
{
    /// <summary>
    /// 调度任务（v6 持久化到 data/scheduled_tasks.json）
    /// </summary>
    public class ScheduledTask
    {
        public string Id { get; set; } = Guid.NewGuid().ToString("N");
        public string Name { get; set; } = string.Empty;
        public string CronExpression { get; set; } = "0 2 * * *"; // 默认每天凌晨 2 点
        public string TargetIp { get; set; } = string.Empty;
        public List<int> Ports { get; set; } = new();
        public List<string> PluginIds { get; set; } = new();
        public int MaxRetries { get; set; } = 5;
        public bool Enabled { get; set; } = true;
        public DateTime CreatedAt { get; set; } = DateTime.Now;
        public DateTime? LastRunAt { get; set; }
        public string? LastError { get; set; }
        public int TotalRuns { get; set; }
        public int TotalFailures { get; set; }
    }
}
