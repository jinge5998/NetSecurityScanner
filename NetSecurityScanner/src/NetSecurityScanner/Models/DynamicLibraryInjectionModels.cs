using System.Collections.Generic;

namespace NetSecurityScanner.Models
{
  public class DylibInjectionReport
  {
    public double OverallScore { get; set; }
    public DylibLoadResult DylibLoadCommands { get; set; } = new();
    public FrameworkHijackResult FrameworkHijack { get; set; } = new();
    public MobileSubstrateResult MobileSubstrate { get; set; } = new();
    public List<AppVulnerabilityResult> Vulnerabilities { get; set; } = new();
  }

  public class DylibLoadResult
  {
    public bool Detected { get; set; }
    public int TotalDylibCommands { get; set; }
    public int LocalDylibCount { get; set; }
    public int SystemDylibCount { get; set; }
    public List<string> SuspiciousDylibs { get; set; } = new();
    public bool HasExternalRpath { get; set; }
    public List<string> Rpaths { get; set; } = new();
    public string Confidence { get; set; } = "低";
  }

  public class FrameworkHijackResult
  {
    public bool Detected { get; set; }
    public bool HasWeakFramework { get; set; }
    public List<string> SuspiciousFrameworks { get; set; } = new();
    public bool HasMissingFramework { get; set; }
    public List<string> MissingFrameworkNames { get; set; } = new();
    public string Confidence { get; set; } = "低";
  }

  public class MobileSubstrateResult
  {
    public bool Detected { get; set; }
    public bool HasSubstrateHook { get; set; }
    public bool HasCydiaSubstrate { get; set; }
    public bool HasSubstrateSafeMode { get; set; }
    public List<string> SubstrateReferences { get; set; } = new();
    public string Confidence { get; set; } = "低";
  }
}