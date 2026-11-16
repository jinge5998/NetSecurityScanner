using System;
using System.Collections.Generic;

namespace NetSecurityScanner.Models
{
    /// <summary>
    /// 告警规则模板（v7）。内置 8 个常用模板，管理员可一键启用。
    /// </summary>
    public class AlertTemplate
    {
        public string Id { get; set; } = string.Empty;
        public string Name { get; set; } = string.Empty;
        public string Description { get; set; } = string.Empty;
        public AlertTemplateCategory Category { get; set; }
        public Dictionary<string, object> DefaultThresholds { get; set; } = new();
        public List<NotificationChannel> RecommendedChannels { get; set; } = new() { NotificationChannel.Log, NotificationChannel.Tray };
        public string Icon { get; set; } = "🔔";
    }

    public enum AlertTemplateCategory
    {
        ConsecutiveFailure,
        MemoryLimit,
        Timeout,
        HealthBelowThreshold,
        SignatureInvalid,
        SandboxViolation,
        TraceTimeout,
        UnauthorizedRemoteApi
    }

    public enum NotificationChannel
    {
        Log,
        Tray,
        Popup
    }

    /// <summary>
    /// SIEM 上传配置（v7 由 PluginSecurityService 持有一个实例）。
    /// </summary>
    public class SiemConfig
    {
        public bool Enabled { get; set; } = false;
        public SiemProtocol Protocol { get; set; } = SiemProtocol.HttpJson;
        public string Endpoint { get; set; } = string.Empty; // SYSLOG: udp://host:port ; HTTP: https://host/path
        public string? ApiKey { get; set; }
        public int TimeoutSeconds { get; set; } = 10;
        public int RetryCount { get; set; } = 3;
    }

    public enum SiemProtocol
    {
        HttpJson,
        SyslogUdp
    }
}
