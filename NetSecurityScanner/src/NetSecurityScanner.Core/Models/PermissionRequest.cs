using System;

namespace NetSecurityScanner.Models
{
    /// <summary>
    /// 插件运行时权限申请（v7）。
    /// 插件调用 RequestPermissionAsync 后写入待审批列表，管理员在管控中心处理。
    /// </summary>
    public class PermissionRequest
    {
        public string Id { get; set; } = Guid.NewGuid().ToString("N");
        public string PluginId { get; set; } = string.Empty;
        public string Permission { get; set; } = string.Empty;
        public string Reason { get; set; } = string.Empty;
        public DateTime RequestedAt { get; set; } = DateTime.Now;
        public PermissionRequestStatus Status { get; set; } = PermissionRequestStatus.Pending;
        public DateTime? ProcessedAt { get; set; }
        public string? ProcessedBy { get; set; }
        public string? OperatorNote { get; set; }
        /// <summary>冷却期截止时间（被拒后 1 小时内相同申请直接拒绝）</summary>
        public DateTime? CooldownUntil { get; set; }
    }

    public enum PermissionRequestStatus
    {
        Pending,
        Approved,
        Rejected
    }
}
