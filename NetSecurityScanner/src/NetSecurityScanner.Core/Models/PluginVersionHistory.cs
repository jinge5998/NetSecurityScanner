using System;

namespace NetSecurityScanner.Models
{
    /// <summary>
    /// 插件版本历史（v5 stub）
    /// </summary>
    public class PluginVersionHistory
    {
        public string Version { get; set; } = string.Empty;
        public DateTime ReleaseDate { get; set; }
        public string? ChangeLog { get; set; }
    }
}
