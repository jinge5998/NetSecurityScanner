using System;

namespace NetSecurityScanner.Models
{
    /// <summary>
    /// 插件审计日志条目（v6 持久化到 data/plugin_audit/{yyyyMMdd}.json，JSON Lines 追加）
    /// </summary>
    public class PluginAuditEntry
    {
        public DateTime Timestamp { get; set; } = DateTime.Now;
        public string Operator { get; set; } = "system";
        public string PluginId { get; set; } = string.Empty;
        public string Action { get; set; } = string.Empty; // Install/Uninstall/Enable/Disable/Execute/Upgrade/Rollback/PolicyChange/Quarantined/MemoryLimitExceeded/PluginBlocked/DangerousOpBlocked
        public string? BeforeState { get; set; }
        public string? AfterState { get; set; }
        public string Result { get; set; } = "Success"; // Success/Failed/Blocked
        public string? Detail { get; set; }
        public string? IpAddress { get; set; }
    }
}
