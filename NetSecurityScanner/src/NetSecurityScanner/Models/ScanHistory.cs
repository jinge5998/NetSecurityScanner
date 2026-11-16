using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;

namespace NetSecurityScanner.Models
{
    public class ScanHistory
    {
        [Key]
        public string ScanId { get; set; } = Guid.NewGuid().ToString();

        public DateTime StartTime { get; set; }
        public DateTime? EndTime { get; set; }
        public DateTime ScanTime { get; set; } = DateTime.Now;
        public TimeSpan Duration { get; set; }

        public string ScanMode { get; set; }
        public string Target { get; set; }
        public string TargetRange { get; set; }

        public int TotalPorts { get; set; }
        public int OpenPorts { get; set; }
        public int TotalVulnerabilities { get; set; }

        public int CriticalCount { get; set; }
        public int HighCount { get; set; }
        public int MediumCount { get; set; }
        public int LowCount { get; set; }
        public int InfoCount { get; set; }

        public string ScanStatus { get; set; }
        public string ScanConfiguration { get; set; }

        public string PdfReportPath { get; set; }
        public string WordReportPath { get; set; }
        public string HtmlReportPath { get; set; }

        public List<VulnerabilityRecord> Vulnerabilities { get; set; } = new();

        public string CreatedBy { get; set; }
        public string Notes { get; set; }
    }
}
