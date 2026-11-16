using System;
using System.Collections.Generic;

namespace NetSecurityScanner.Models
{
    /// <summary>
    /// 告警规则（v6 持久化到 data/alert_rules.json，v7 扩展支持模板）
    /// </summary>
    public class AlertRule
    {
        public string Id { get; set; } = Guid.NewGuid().ToString("N");
        public string Name { get; set; } = string.Empty;
        public string? Description { get; set; }
        public AlertType Type { get; set; } = AlertType.ConsecutiveFailure;
        public int Threshold { get; set; } = 3; // 连续失败次数 / 健康度阈值 / 内存 MB / 超时秒
        public int TimeWindowMinutes { get; set; } = 5; // 连续失败的统计窗口
        public List<string> NotificationChannels { get; set; } = new() { "Log" }; // Tray/Popup/Log
        public bool Enabled { get; set; } = true;

        // ============== v7 扩展 ==============
        /// <summary>是否由模板自定义阈值创建（true 后不再跟随模板更新）</summary>
        public bool IsCustomized { get; set; } = false;

        /// <summary>对应的模板 Id（从模板一键启用时填充）</summary>
        public string? TemplateId { get; set; }

        /// <summary>阈值 JSON（v7：用于复杂阈值，如 {"thresholdMB":200}）</summary>
        public string? ThresholdsJson { get; set; }

        /// <summary>创建人</summary>
        public string CreatedBy { get; set; } = "system";

        /// <summary>创建时间</summary>
        public DateTime CreatedAt { get; set; } = DateTime.Now;
    }

    public enum AlertType
    {
        ConsecutiveFailure = 0,
        ExecutionTimeout = 1,
        MemoryLimitExceeded = 2,
        LowHealthScore = 3
    }
}
