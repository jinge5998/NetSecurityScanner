using System;
using System.Collections.Generic;

namespace NetSecurityScanner.Models
{
    /// <summary>
    /// iOS IPA 分析结果
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
        public List<string>? ClassNames { get; set; }
        public List<string>? MethodNames { get; set; }
        public byte[]? MachOData { get; set; }
        public string? MainExecutable { get; set; }
        public bool HasEncryptedBinary { get; set; }
        public List<string>? Frameworks { get; set; }
        public List<string>? EmbeddedBinaries { get; set; }
        public Dictionary<string, string>? Entitlements { get; set; }
        public List<string>? ProvisionedDevices { get; set; }
        public string? TeamIdentifier { get; set; }
        public string? ExecutionType { get; set; }
        public List<string>? UrlSchemes { get; set; }
        public Dictionary<string, string>? CustomInfoPlistKeys { get; set; }
        public List<string>? SdkFiles { get; set; }
        public List<string>? NativeLibs { get; set; }
    }
}