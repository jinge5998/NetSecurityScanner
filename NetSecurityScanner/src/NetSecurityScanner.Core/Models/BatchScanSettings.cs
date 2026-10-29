namespace NetSecurityScanner.Core.Models
{
    /// <summary>
    /// 批量扫描窗口持久化配置。不保存目标输入内容，避免误扫。
    /// </summary>
    public class BatchScanSettings
    {
        public int SchemaVersion { get; set; } = 1;
        public string ScanModeTag { get; set; } = "Standard";
        public int Concurrency { get; set; } = 10;
        public double TimeoutSeconds { get; set; } = 0.3;
        public string TargetTypeTag { get; set; } = "Range";
        public string StatusFilterTag { get; set; } = "All";
        public string ThreatFilterTag { get; set; } = "All";
    }
}
