using System;
using System.Collections.Generic;

namespace NetSecurityScanner.Utils
{
  public enum CvssSeverity
  {
    None,
    Low,
    Medium,
    High,
    Critical
  }

  public enum AttackVector { Network, Adjacent, Local, Physical }
  public enum AttackComplexity { Low, High }
  public enum PrivilegesRequired { None, Low, High }
  public enum UserInteraction { None, Required }
  public enum Scope { Unchanged, Changed }
  public enum CiaImpact { None, Low, High }

  public class CvssBaseMetrics
  {
    public AttackVector AV { get; set; } = AttackVector.Network;
    public AttackComplexity AC { get; set; } = AttackComplexity.Low;
    public PrivilegesRequired PR { get; set; } = PrivilegesRequired.None;
    public UserInteraction UI { get; set; } = UserInteraction.None;
    public Scope S { get; set; } = Scope.Unchanged;
    public CiaImpact C { get; set; } = CiaImpact.High;
    public CiaImpact I { get; set; } = CiaImpact.High;
    public CiaImpact A { get; set; } = CiaImpact.High;
  }

  public class CvssResult
  {
    public double Score { get; set; }
    public CvssSeverity Severity { get; set; }
    public string VectorString { get; set; } = string.Empty;
    public CvssBaseMetrics BaseMetrics { get; set; } = new();
  }

  public static class CvssCalculator
  {
    private static readonly Dictionary<string, CvssBaseMetrics> RiskLevelDefaults = new(StringComparer.OrdinalIgnoreCase)
    {
      ["严重"] = new CvssBaseMetrics { AV = AttackVector.Network, AC = AttackComplexity.Low, PR = PrivilegesRequired.None, UI = UserInteraction.None, S = Scope.Unchanged, C = CiaImpact.High, I = CiaImpact.High, A = CiaImpact.High },
      ["高危"] = new CvssBaseMetrics { AV = AttackVector.Network, AC = AttackComplexity.Low, PR = PrivilegesRequired.None, UI = UserInteraction.None, S = Scope.Unchanged, C = CiaImpact.High, I = CiaImpact.High, A = CiaImpact.None },
      ["中危"] = new CvssBaseMetrics { AV = AttackVector.Network, AC = AttackComplexity.Low, PR = PrivilegesRequired.Low, UI = UserInteraction.Required, S = Scope.Unchanged, C = CiaImpact.Low, I = CiaImpact.Low, A = CiaImpact.None },
      ["低危"] = new CvssBaseMetrics { AV = AttackVector.Adjacent, AC = AttackComplexity.High, PR = PrivilegesRequired.High, UI = UserInteraction.Required, S = Scope.Unchanged, C = CiaImpact.None, I = CiaImpact.Low, A = CiaImpact.None },
      ["信息"] = new CvssBaseMetrics { AV = AttackVector.Adjacent, AC = AttackComplexity.High, PR = PrivilegesRequired.High, UI = UserInteraction.Required, S = Scope.Unchanged, C = CiaImpact.None, I = CiaImpact.None, A = CiaImpact.None },
    };

    public static CvssResult CalculateFromRiskLevel(string riskLevel, string? cveId = null)
    {
      var metrics = RiskLevelDefaults.TryGetValue(riskLevel, out var m) ? m : RiskLevelDefaults["低危"];

      return new CvssResult
      {
        BaseMetrics = metrics,
        Score = ComputeBaseScore(metrics),
        VectorString = BuildVectorString(metrics),
        Severity = CvssSeverity.None
      };
    }

    public static CvssResult Calculate(CvssBaseMetrics metrics)
    {
      var score = ComputeBaseScore(metrics);
      return new CvssResult
      {
        BaseMetrics = metrics,
        Score = score,
        Severity = GetSeverity(score),
        VectorString = BuildVectorString(metrics)
      };
    }

    public static double ComputeBaseScore(CvssBaseMetrics m)
    {
      double impact = ComputeImpact(m);
      double exploitability = ComputeExploitability(m);

      if (impact <= 0)
        return 0.0;

      double baseScore;
      if (m.S == Scope.Unchanged)
      {
        baseScore = Math.Min(impact + exploitability, 10.0);
      }
      else
      {
        baseScore = Math.Min(1.08 * (impact + exploitability), 10.0);
      }

      return RoundUp(baseScore);
    }

    private static double ComputeImpact(CvssBaseMetrics m)
    {
      double c = GetCiaValue(m.C);
      double i = GetCiaValue(m.I);
      double a = GetCiaValue(m.A);

      double iss = 1 - ((1 - c) * (1 - i) * (1 - a));

      if (m.S == Scope.Unchanged)
        return 6.42 * iss;
      else
        return 7.52 * (iss - 0.029) - 3.25 * Math.Pow(iss - 0.02, 15);
    }

    private static double ComputeExploitability(CvssBaseMetrics m)
    {
      double av = m.AV switch
      {
        AttackVector.Network => 0.85,
        AttackVector.Adjacent => 0.62,
        AttackVector.Local => 0.55,
        AttackVector.Physical => 0.2,
        _ => 0.85
      };

      double ac = m.AC == AttackComplexity.Low ? 0.77 : 0.44;

      double pr;
      if (m.S == Scope.Unchanged)
      {
        pr = m.PR switch
        {
          PrivilegesRequired.None => 0.85,
          PrivilegesRequired.Low => 0.62,
          PrivilegesRequired.High => 0.27,
          _ => 0.85
        };
      }
      else
      {
        pr = m.PR switch
        {
          PrivilegesRequired.None => 0.85,
          PrivilegesRequired.Low => 0.68,
          PrivilegesRequired.High => 0.50,
          _ => 0.85
        };
      }

      double ui = m.UI == UserInteraction.None ? 0.85 : 0.62;

      return 8.22 * av * ac * pr * ui;
    }

    private static double GetCiaValue(CiaImpact impact) => impact switch
    {
      CiaImpact.High => 0.56,
      CiaImpact.Low => 0.22,
      _ => 0
    };

    private static CvssSeverity GetSeverity(double score) => score switch
    {
      0 => CvssSeverity.None,
      >= 0.1 and < 4.0 => CvssSeverity.Low,
      >= 4.0 and < 7.0 => CvssSeverity.Medium,
      >= 7.0 and < 9.0 => CvssSeverity.High,
      >= 9.0 => CvssSeverity.Critical,
      _ => CvssSeverity.None
    };

    private static string BuildVectorString(CvssBaseMetrics m)
    {
      var av = m.AV switch { AttackVector.Network => "N", AttackVector.Adjacent => "A", AttackVector.Local => "L", AttackVector.Physical => "P", _ => "N" };
      var ac = m.AC == AttackComplexity.Low ? "L" : "H";
      var pr = m.PR switch { PrivilegesRequired.None => "N", PrivilegesRequired.Low => "L", PrivilegesRequired.High => "H", _ => "N" };
      var ui = m.UI == UserInteraction.None ? "N" : "R";
      var s = m.S == Scope.Unchanged ? "U" : "C";
      var c = m.C switch { CiaImpact.High => "H", CiaImpact.Low => "L", _ => "N" };
      var ci = m.I switch { CiaImpact.High => "H", CiaImpact.Low => "L", _ => "N" };
      var ca = m.A switch { CiaImpact.High => "H", CiaImpact.Low => "L", _ => "N" };

      return $"CVSS:3.1/AV:{av}/AC:{ac}/PR:{pr}/UI:{ui}/S:{s}/C:{c}/I:{ci}/A:{ca}";
    }

    private static double RoundUp(double score)
    {
      int intScore = (int)(score * 100000);
      if (intScore % 10000 == 0)
        return intScore / 100000.0;

      return ((intScore / 10000) + 1) / 10.0;
    }
  }
}