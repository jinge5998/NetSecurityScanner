using System;
using System.Collections.Generic;
using NetSecurityScanner.Utils;
using Xunit;

namespace NetSecurityScanner.Tests.Services
{
  public class CvssCalculatorTests
  {
    [Theory]
    [InlineData("严重", 9.8)]
    [InlineData("高危", 9.1)]
    [InlineData("中危", 4.6)]
    [InlineData("低危", 1.8)]
    public void CalculateFromRiskLevel_ReturnsExpectedScore(string riskLevel, double expectedScore)
    {
      var result = CvssCalculator.CalculateFromRiskLevel(riskLevel);
      Assert.Equal(expectedScore, result.Score, 1);
    }

    [Fact]
    public void Calculate_NetworkCritical_ReturnsMaxScore()
    {
      var metrics = new CvssBaseMetrics
      {
        AV = AttackVector.Network,
        AC = AttackComplexity.Low,
        PR = PrivilegesRequired.None,
        UI = UserInteraction.None,
        S = Scope.Unchanged,
        C = CiaImpact.High,
        I = CiaImpact.High,
        A = CiaImpact.High
      };

      var result = CvssCalculator.Calculate(metrics);
      Assert.Equal(9.8, result.Score, 1);
      Assert.Equal(CvssSeverity.Critical, result.Severity);
      Assert.StartsWith("CVSS:3.1/", result.VectorString);
    }

    [Fact]
    public void Calculate_NoneImpact_ReturnsZero()
    {
      var metrics = new CvssBaseMetrics
      {
        AV = AttackVector.Network,
        AC = AttackComplexity.Low,
        PR = PrivilegesRequired.None,
        UI = UserInteraction.None,
        S = Scope.Unchanged,
        C = CiaImpact.None,
        I = CiaImpact.None,
        A = CiaImpact.None
      };

      var result = CvssCalculator.Calculate(metrics);
      Assert.Equal(0, result.Score);
      Assert.Equal(CvssSeverity.None, result.Severity);
    }
  }
}