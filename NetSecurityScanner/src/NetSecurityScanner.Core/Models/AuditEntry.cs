using System;
using System.Collections.Generic;
using System.Text.Json.Serialization;

namespace NetSecurityScanner.Models
{
    /// <summary>
    /// 审计日志条目（admin 所有管理操作）。
    /// </summary>
    public class AuditEntry
    {
        [JsonPropertyName("id")]
        public string Id { get; set; } = Guid.NewGuid().ToString("N");

        [JsonPropertyName("at")]
        public DateTime At { get; set; } = DateTime.Now;

        [JsonPropertyName("actor")]
        public string Actor { get; set; } = "";          // 操作者用户名

        [JsonPropertyName("action")]
        public string Action { get; set; } = "";         // APPROVE / REJECT / SET_PERMS / DISABLE / ENABLE / RESET_PWD / ...

        [JsonPropertyName("target")]
        public string Target { get; set; } = "";         // 目标用户名

        [JsonPropertyName("detail")]
        public string Detail { get; set; } = "";         // 备注（权限列表 / 原因等）

        [JsonPropertyName("success")]
        public bool Success { get; set; }

        [JsonPropertyName("ip")]
        public string? Ip { get; set; }                  // 来源 IP（可选，本地应用为 "-"）

        public string AtDisplay => At.ToString("yyyy-MM-dd HH:mm:ss");
        public string ResultText => Success ? "✅ 成功" : "❌ 失败";
    }

    /// <summary>
    /// 审计日志持久化容器。
    /// </summary>
    public class AuditLogStore
    {
        [JsonPropertyName("entries")]
        public List<AuditEntry> Entries { get; set; } = new();
    }
}
