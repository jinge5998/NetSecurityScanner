using System.Collections.Generic;
using NetSecurityScanner.Models;

namespace NetSecurityScanner.Core.Models
{
  public enum ObfuscationLevel
  {
    None,
    Low,
    Medium,
    High
  }

  public class ObfuscationReport
  {
    public double OverallScore { get; set; }
    public ObfuscationLevel Level { get; set; }
    public StringObfuscationResult Strings { get; set; } = new();
    public ClassNameObfuscationResult Classes { get; set; } = new();
    public AntiDebugResult AntiDebug { get; set; } = new();
    public IntegrityCheckResult Integrity { get; set; } = new();
    public LLVMObfuscationResult LLVM { get; set; } = new();
    public List<AppVulnerabilityResult> Vulnerabilities { get; set; } = new();
  }

  public class StringObfuscationResult
  {
    public bool Detected { get; set; }
    public double ShannonEntropy { get; set; }
    public double PrintableCharRatio { get; set; }
    public int TotalStrings { get; set; }
    public int ObfuscatedStrings { get; set; }
    public double ObfuscationRate { get; set; }
    public string Confidence { get; set; } = "低";
  }

  public class ClassNameObfuscationResult
  {
    public bool Detected { get; set; }
    public int TotalClassNames { get; set; }
    public int ShortNameCount { get; set; }
    public int RandomNameCount { get; set; }
    public double ShortNameRatio { get; set; }
    public string Confidence { get; set; } = "低";
  }

  public class AntiDebugResult
  {
    public bool Detected { get; set; }
    public bool HasPtraceCheck { get; set; }
    public bool HasSysctlCheck { get; set; }
    public bool HasDebugserverCheck { get; set; }
    public bool HasFlutterAntiDebug { get; set; }
    public int TotalMatches { get; set; }
    public List<string> MatchedPatterns { get; set; } = new();
    public string Confidence { get; set; } = "低";
  }

  public class IntegrityCheckResult
  {
    public bool Detected { get; set; }
    public bool HasCodeSignature { get; set; }
    public bool HasEncryptedBinary { get; set; }
    public bool HasCrcCheck { get; set; }
    public bool HasHashCheck { get; set; }
    public bool HasTamperDetection { get; set; }
    public List<string> MatchedPatterns { get; set; } = new();
    public string Confidence { get; set; } = "低";
  }

  public class LLVMObfuscationResult
  {
    public bool Detected { get; set; }
    public bool HasBogusControlFlow { get; set; }
    public bool HasControlFlowFlattening { get; set; }
    public bool HasInstructionSubstitution { get; set; }
    public double BogusBlockRatio { get; set; }
    public int TotalBasicBlocks { get; set; }
    public int BogusBasicBlocks { get; set; }
    public string Confidence { get; set; } = "低";
  }
}