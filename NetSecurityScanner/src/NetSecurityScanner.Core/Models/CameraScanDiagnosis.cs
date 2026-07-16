using System.Collections.Generic;

namespace NetSecurityScanner.Models
{
  public class CameraScanDiagnosis
  {
    public string Ip { get; set; } = string.Empty;
    public string Vendor { get; set; } = string.Empty;
    public string FirmwareVersion { get; set; } = string.Empty;
    public List<string> OpenPorts { get; set; } = new();
    public int VulnDbCount { get; set; }
    public bool HttpAvailable { get; set; }
    public List<string> Steps { get; set; } = new();
    public List<string> Suggestions { get; set; } = new();
    public List<CameraVulnerability> DetectedVulnerabilities { get; set; } = new();
  }
}
