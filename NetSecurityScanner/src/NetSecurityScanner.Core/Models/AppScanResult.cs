using System;
using System.Collections.Generic;

namespace NetSecurityScanner.Models
{
    public class AppScanResult
    {
        public string OriginalFilePath { get; set; } = string.Empty;
        public string FileName { get; set; } = string.Empty;
        public AppType AppType { get; set; }
        public long FileSize { get; set; }
        public ScanMode ScanMode { get; set; }
        public DateTime ScanStartTime { get; set; } = DateTime.Now;
        public DateTime? ScanEndTime { get; set; }
        public List<AppVulnerabilityResult> Vulnerabilities { get; set; } = new List<AppVulnerabilityResult>();
        public int HighRiskCount { get; set; }
        public int MediumRiskCount { get; set; }
        public int LowRiskCount { get; set; }
        public bool IsSuccess { get; set; }
        public string ErrorMessage { get; set; } = string.Empty;
    }

    public class AppVulnerabilityResult
    {
        public string Id { get; set; } = string.Empty;
        public string Name { get; set; } = string.Empty;
        public RiskLevel RiskLevel { get; set; }
        public VulnerabilityType VulnerabilityType { get; set; }
        public string Location { get; set; } = string.Empty;
        public double CvssScore { get; set; }
        public string Description { get; set; } = string.Empty;
        public string Suggestion { get; set; } = string.Empty;
        public bool IsResolved { get; set; }
    }

    public enum AppType
    {
        Android,
        iOS,
        MiniApp,
        Unknown
    }

    public enum RiskLevel
    {
        Info,
        Low,
        Medium,
        High,
        Critical
    }

    public enum VulnerabilityType
    {
        HardcodedKey,
        WebViewVulnerability,
        InsecureStorage,
        PermissionIssue,
        SSLCertificate,
        NetworkSecurity,
        CodeObfuscation,
        DebugMode,
        ThirdPartySDK,
        Other
    }
}
