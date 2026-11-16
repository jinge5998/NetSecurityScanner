using System;

namespace NetSecurityScanner.Models
{
    /// <summary>
    /// 插件市场评价（v5 stub：历史任务未完成，仅作为桩以通过编译）
    /// </summary>
    public class PluginReview
    {
        public string PluginId { get; set; } = string.Empty;
        public string UserName { get; set; } = string.Empty;
        public int Rating { get; set; }
        public string? Comment { get; set; }
        public DateTime CreatedAt { get; set; } = DateTime.Now;
    }
}
