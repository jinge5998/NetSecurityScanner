using System;

namespace NetSecurityScanner.Models
{
    /// <summary>
    /// 扫描统计信息
    /// </summary>
    public class ScanStatistics
    {
        public int TaskId { get; set; }
        public string Target { get; set; } = string.Empty;
        public DateTime StartTime { get; set; }
        public DateTime? EndTime { get; set; }
        public int TotalPorts { get; set; }
        public int OpenPorts { get; set; }
        public int ClosedPorts { get; set; }
        public int FilteredPorts { get; set; }
        public int VulnerabilitiesFound { get; set; }
        public int CriticalVulnerabilities { get; set; }
        public int HighVulnerabilities { get; set; }
        public int MediumVulnerabilities { get; set; }
        public int LowVulnerabilities { get; set; }
        public double ScanDuration { get; set; }
        public string ScanStatus { get; set; } = "Pending";
    }
}
