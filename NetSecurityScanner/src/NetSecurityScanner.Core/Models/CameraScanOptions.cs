using System.Collections.Generic;

namespace NetSecurityScanner.Models
{
  public class CameraScanOptions
  {
    public string TargetIp { get; set; } = string.Empty;
    public string IpRange { get; set; } = string.Empty;
    public string CidrNotation { get; set; } = string.Empty;
    public string Ipv6Cidr { get; set; } = string.Empty;
    public List<int> CustomPorts { get; set; } = new();
    public bool EnableFingerprint { get; set; } = true;
    public bool EnableVulnerabilityScan { get; set; } = true;
    public bool EnableWeakPasswordScan { get; set; } = true;
    public int MaxConcurrency { get; set; } = 30;
    public int TimeoutMs { get; set; } = 3000;
    public bool UseDefaultPorts { get; set; } = true;
  }
}