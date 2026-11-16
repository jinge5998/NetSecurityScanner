using System;
using System.Collections.Generic;

namespace NetSecurityScanner.Models
{
    public class ScanResult
    {
        public int ResultId { get; set; }
        public int TaskId { get; set; }
        public string Host { get; set; } = string.Empty;
        public int Port { get; set; }
        public string Service { get; set; } = string.Empty;
        public bool IsVulnerable { get; set; }
        public int? VulnerabilityId { get; set; }
        public Vulnerability? Vulnerability { get; set; }
        public DateTime ScanTime { get; set; } = DateTime.Now;
    }
}