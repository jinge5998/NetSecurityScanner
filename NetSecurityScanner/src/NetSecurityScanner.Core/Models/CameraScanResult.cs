using System;
using System.Collections.Generic;
using System.Linq;

namespace NetSecurityScanner.Core.Models
{
    public class CameraScanResult
    {
        public CameraScanTarget Target { get; set; } = new();
        public List<CameraVulnFinding> Findings { get; set; } = new();
        public DateTime ScanTime { get; set; } = DateTime.Now;
        public int CriticalCount => Findings.Count(f => f.Severity == "Critical");
        public int HighRiskCount => Findings.Count(f => f.Severity == "High");
        public int MediumRiskCount => Findings.Count(f => f.Severity == "Medium");
        public int LowRiskCount => Findings.Count(f => f.Severity == "Low");
        public string OverallRiskLevel
        {
            get
            {
                if (CriticalCount > 0) return "Critical";
                if (HighRiskCount > 0) return "High";
                if (MediumRiskCount > 0) return "Medium";
                if (LowRiskCount > 0) return "Low";
                return "Info";
            }
        }
        public string RiskScore
        {
            get
            {
                var baseScore = 100.0;
                foreach (var f in Findings)
                {
                    baseScore -= f.Severity switch
                    {
                        "Critical" => 25,
                        "High" => 15,
                        "Medium" => 8,
                        "Low" => 3,
                        _ => 0
                    };
                }
                return Math.Max(0, Math.Round(baseScore)).ToString("0");
            }
        }
    }
}