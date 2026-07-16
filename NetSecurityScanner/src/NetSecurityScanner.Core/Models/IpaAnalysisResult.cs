using System;
using System.Collections.Generic;

namespace NetSecurityScanner.Models
{
    /// <summary>
    /// iOS IPA 分析结果（v5 stub：add-app-scanner 历史任务未完成，仅作为桩以通过编译）
    /// </summary>
    public class IpaAnalysisResult
    {
        public string? InfoPlistRawText { get; set; }
        public List<string>? MachOSymbols { get; set; }
        public List<string>? MachODylibs { get; set; }
        public List<string>? MachOFunctions { get; set; }
        public string? BundleId { get; set; }
        public string? DisplayName { get; set; }
        public string? Version { get; set; }
        public long SizeBytes { get; set; }
        public DateTime AnalyzedAt { get; set; } = DateTime.Now;
    }
}
