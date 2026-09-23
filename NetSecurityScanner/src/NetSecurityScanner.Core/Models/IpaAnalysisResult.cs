using System;
using System.Collections.Generic;

namespace NetSecurityScanner.Models
{
    public class MachODataEntry
    {
        public string? Name { get; set; }
        public string? Type { get; set; }
        public List<string> Imports { get; set; } = new();
        public List<string> Exports { get; set; } = new();
        public List<string> LoadCommands { get; set; } = new();
    }

    public class MainExecutableInfo
    {
        public string? Name { get; set; }
        public bool IsEncrypted { get; set; }
        public List<string> Segments { get; set; } = new();
    }

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
        public List<MachODataEntry>? MachOData { get; set; }
        public MainExecutableInfo? MainExecutable { get; set; }
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