using System;
using System.Collections.Generic;

namespace NetSecurityScanner.Models
{
  public class CameraRiskAssessment
  {
    public double TotalScore { get; set; }
    public string RiskLevel { get; set; } = string.Empty;
    public int VulnerabilityCount { get; set; }
    public int CriticalCount { get; set; }
    public int HighCount { get; set; }
    public int MediumCount { get; set; }
    public int WeakPasswordCount { get; set; }
    public int DangerousPortCount { get; set; }
    public List<string> TopRemediations { get; set; } = new();
    public DateTime AssessmentTime { get; set; } = DateTime.Now;
  }
}