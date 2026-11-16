namespace NetSecurityScanner.Models
{
    public class ScanConfiguration
    {
        public ScanMode Mode { get; set; }
        public string PortRange { get; set; }
        public int[] TargetPorts { get; set; }
        public string[] RiskLevels { get; set; }
        public int MaxConcurrency { get; set; }
        public int TimeoutMs { get; set; }
        public string[] DetectionMethods { get; set; }
        public bool EnableWebSpider { get; set; }
        public int MaxSpiderDepth { get; set; }
        public bool EnableWeakPasswordCheck { get; set; }
        public bool EnableExploitSimulation { get; set; }
        public string[] ComplianceFrameworks { get; set; }

        // 预设配置 - 闪电扫描
        public static ScanConfiguration LightningConfig => new()
        {
            Mode = ScanMode.Lightning,
            TargetPorts = new[] { 22, 23, 80, 443, 3389, 445, 3306, 6379, 8080, 9200 },
            RiskLevels = new[] { "严重", "高危" },
            MaxConcurrency = 50,
            TimeoutMs = 500,
            DetectionMethods = new[] { "PortConnect", "CriticalBanner" }
        };

        // 预设配置 - 标准扫描
        public static ScanConfiguration StandardConfig => new()
        {
            Mode = ScanMode.Standard,
            PortRange = "1-1000",
            RiskLevels = new[] { "严重", "高危", "中危", "低危" },
            MaxConcurrency = 20,
            TimeoutMs = 10000,
            DetectionMethods = new[] { "PortConnect", "ServiceBanner", "VersionDetection", "VulnerabilityDB" }
        };

        // 预设配置 - 深度扫描
        public static ScanConfiguration DeepConfig => new()
        {
            Mode = ScanMode.Deep,
            PortRange = "1-65535",
            RiskLevels = new[] { "严重", "高危", "中危", "低危", "信息" },
            MaxConcurrency = 10,
            TimeoutMs = 30000,
            DetectionMethods = new[] { "PortConnect", "ServiceBanner", "VersionDetection", "VulnerabilityDB", "WebCrawling", "WeakPassword", "ExploitSimulation" },
            EnableWebSpider = true,
            MaxSpiderDepth = 3,
            EnableWeakPasswordCheck = true,
            EnableExploitSimulation = true
        };
    }
}
