using System;
using System.Collections.Generic;

namespace NetSecurityScanner.Models
{
    /// <summary>
    /// 调用链 Span（v7 由 PluginTelemetryService 写入 data/plugin_traces/{yyyyMMdd}.jsonl）。
    /// 一次完整扫描 = 1 个 Trace，下含多个 Span（Orchestrator / Plugin / SubCall）。
    /// </summary>
    public class TraceSpan
    {
        public string TraceId { get; set; } = string.Empty;
        public string SpanId { get; set; } = string.Empty;
        public string? ParentSpanId { get; set; }
        public string Name { get; set; } = string.Empty; // Orchestrator.Scan / Plugin.ScanAsync / SubCall
        public string? PluginId { get; set; }
        public string? TargetIp { get; set; }
        public int? Port { get; set; }
        public DateTime StartTime { get; set; }
        public DateTime EndTime { get; set; }
        public long ElapsedMs => (long)(EndTime - StartTime).TotalMilliseconds;
        public string Status { get; set; } = "Running"; // Running / Ok / Error / Timeout / Cancelled
        public string? ErrorMessage { get; set; }
        public Dictionary<string, string> Tags { get; set; } = new();
    }

    /// <summary>
    /// 链路查询结果：按父子关系组织的 Span 树。
    /// </summary>
    public class TraceTree
    {
        public string TraceId { get; set; } = string.Empty;
        public List<TraceSpan> AllSpans { get; set; } = new();
        public List<TraceSpan> RootSpans { get; set; } = new();
        public long TotalElapsedMs { get; set; }
        public DateTime StartTime { get; set; }
        public DateTime EndTime { get; set; }
    }
}
