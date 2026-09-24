using System;

namespace NetSecurityScanner.Models
{
    public class PortInfo
    {
        public string Host { get; set; } = string.Empty;
        public int PortNumber { get; set; }
        public string Status { get; set; } = string.Empty;
        public string Service { get; set; } = string.Empty;
        public string Version { get; set; } = string.Empty;
    public string Protocol { get; set; } = string.Empty;
    public DateTime ScanTime { get; set; } = DateTime.Now;
    public string ServiceDetails { get; set; } = string.Empty;
    public string RiskLevel { get; set; } = string.Empty;
    }
}