using System;

namespace NetSecurityScanner.Core.Models
{
    /// <summary>
    /// 单一 NMAP 模板定义（数据驱动）。
    /// Apply 委托把模板字段应用到 WPF 窗口上的 UI 控件。
    /// </summary>
    public class NmapTemplate
    {
        public string Id { get; set; } = "";          // 唯一 ID，如 "nmap-fast"
        public string Name { get; set; } = "";         // 显示名
        public string Icon { get; set; } = "🛠️";        // Emoji 前缀
        public string Description { get; set; } = "";  // 模板简短说明
        public string Category { get; set; } = "NMAP"; // NMAP / Scenario / Custom
        public Action<object>? Apply { get; set; } // 接受 WPF 窗口实例的 Apply 委托
    }
}
