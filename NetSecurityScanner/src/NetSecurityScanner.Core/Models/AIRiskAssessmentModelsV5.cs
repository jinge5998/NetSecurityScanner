using System;
using System.Collections.Generic;

namespace NetSecurityScanner.Models
{
  #region 核心枚举

  public enum RiskLevelV5
  {
    Safe = 0,
    Low = 1,
    Medium = 2,
    High = 3,
    Critical = 4,
    Extreme = 5
  }

  public enum RiskItemCategoryV5
  {
    PortExposure,
    ServiceVulnerability,
    CveVulnerability,
    ConfigurationRisk,
    AccessControl,
    DataExposure,
    AttackVector,
    RiskPattern,
    Compliance
  }

  public enum AttackPhaseV5
  {
    Reconnaissance,
    InitialAccess,
    Execution,
    Persistence,
    PrivilegeEscalation,
    DefenseEvasion,
    CredentialAccess,
    Discovery,
    LateralMovement,
    Collection,
    Exfiltration,
    Impact
  }

  public enum RemediationPriorityV5
  {
    P0Immediate = 0,
    P1Urgent = 1,
    P2High = 2,
    P3Normal = 3,
    P4Low = 4
  }

  public enum TrendDirectionV5
  {
    Improving,
    Stable,
    Worsening,
    New
  }

  #endregion

  #region 配置类

  public class RiskWeightConfigV5
  {
    public int Port { get; set; }
    public string Service { get; set; }
    public double BaseWeight { get; set; }
    public RiskLevelV5 DefaultLevel { get; set; }
    public string ThreatDescription { get; set; }
    public int HistoricalCveCount { get; set; }
    public double ExploitAvailability { get; set; }
    public double BusinessImpact { get; set; }
    public double DataSensitivity { get; set; }
    public List<string> CommonExploits { get; set; } = new();
    public List<string> RelatedTactics { get; set; } = new();
  }

  public class VulnerabilitySeverityConfigV5
  {
    public string Level { get; set; }
    public double BaseCvss { get; set; }
    public double ExploitMultiplier { get; set; }
    public double ImpactMultiplier { get; set; }
    public (double Min, double Max) CvssRange { get; set; }
    public string ColorHex { get; set; }
    public string RemediationSlaHours { get; set; }
    public string Description { get; set; }
  }

  #endregion

  #region 可利用性指标

  public class ExploitabilityMetricsV5
  {
    public double ExploitAvailabilityScore { get; set; }
    public double WeaponizationProbability { get; set; }
    public double ExploitCodeMaturity { get; set; }
    public double AttackVectorMultiplier { get; set; }
    public double PrivilegesRequired { get; set; }
    public double UserInteraction { get; set; }
    public bool HasPublicExploit { get; set; }
    public bool HasCisaKev { get; set; }
    public bool IsWormable { get; set; }
    public int DaysSinceDisclosure { get; set; }
    public List<string> KnownExploitTools { get; set; } = new();
  }

  public class ImpactMetricsV5
  {
    public double ConfidentialityImpact { get; set; }
    public double IntegrityImpact { get; set; }
    public double AvailabilityImpact { get; set; }
    public double BusinessDisruptionScore { get; set; }
    public double DataExposureVolume { get; set; }
    public double RegulatoryPenaltyRisk { get; set; }
    public double ReputationDamage { get; set; }
    public double RecoveryCostEstimate { get; set; }
  }

  #endregion

  #region 基础风险项

  public class AIRiskItemV5
  {
    public Guid Id { get; set; } = Guid.NewGuid();
    public RiskItemCategoryV5 Category { get; set; }
    public RiskLevelV5 Level { get; set; }
    public double RiskScore { get; set; }
    public double CvssScore { get; set; }
    public string CvssVector { get; set; }
    public string Title { get; set; }
    public string Target { get; set; }
    public string TargetIp { get; set; }
    public int? TargetPort { get; set; }
    public string Service { get; set; }
    public string ServiceVersion { get; set; }
    public string Description { get; set; }
    public string TechnicalSummary { get; set; }
    public string CveId { get; set; }
    public int CveCountLinked { get; set; }
    public DateTime? FirstDisclosureDate { get; set; }
    public Dictionary<string, string> Metadata { get; set; } = new();
    public ExploitabilityMetricsV5 Exploitability { get; set; } = new();
    public ImpactMetricsV5 Impact { get; set; } = new();
    public List<RelatedCveV5> RelatedCves { get; set; } = new();
    public List<string> AttackTactics { get; set; } = new();
    public List<string> EvidenceSnippets { get; set; } = new();
    public double PriorityScore { get; set; }
    public RemediationPriorityV5 RemediationPriority { get; set; }
    public TrendDirectionV5 Trend { get; set; }
    public double Confidence { get; set; }
    public string FuzzyMembership { get; set; }
    public bool IsFalsePositiveCandidate { get; set; }
    public DateTime DiscoveredAt { get; set; } = DateTime.Now;
  }

  public class RelatedCveV5
  {
    public string CveId { get; set; }
    public string Title { get; set; }
    public double CvssScore { get; set; }
    public string Severity { get; set; }
    public string Description { get; set; }
    public bool HasPublicExploit { get; set; }
    public bool InKevCatalog { get; set; }
    public DateTime? PublishedDate { get; set; }
    public List<string> References { get; set; } = new();
  }

  #endregion

  #region 多维评分

  public class DimensionalScoresV5
  {
    public double NetworkExposure { get; set; }
    public double ServiceVulnerability { get; set; }
    public double VulnerabilitySeverity { get; set; }
    public double ConfigurationRisk { get; set; }
    public double AccessControl { get; set; }
    public double DataExposure { get; set; }
    public double AuthenticationStrength { get; set; }
    public double EncryptionPosture { get; set; }
    public double PatchingCadence { get; set; }
    public double ComplianceGap { get; set; }
    public double CompositeIndex { get; set; }
    public double SecurityPostureScore { get; set; }
    public Dictionary<string, DimensionDetailV5> Dimensions { get; set; } = new();
  }

  public class DimensionDetailV5
  {
    public string Name { get; set; }
    public double Score { get; set; }
    public RiskLevelV5 Level { get; set; }
    public string Weight { get; set; }
    public string Advice { get; set; }
    public List<string> KeyFindings { get; set; } = new();
  }

  #endregion

  #region 攻击链分析

  public class AttackChainAnalysisV5
  {
    public double BreachProbability { get; set; }
    public double MeanTimeToBreachHours { get; set; }
    public double LateralMovementEase { get; set; }
    public double DwellTimeEstimateDays { get; set; }
    public int CriticalAttackPaths { get; set; }
    public List<AttackVectorChainV5> EntryVectors { get; set; } = new();
    public List<LateralPathV5> LateralPaths { get; set; } = new();
    public List<KillChainPhaseV5> KillChain { get; set; } = new();
    public List<string> TopRiskScenarios { get; set; } = new();
    public string NarrativeThreatDescription { get; set; }
  }

  public class AttackVectorChainV5
  {
    public string VectorName { get; set; }
    public AttackPhaseV5 Phase { get; set; }
    public double Probability { get; set; }
    public double CumulativeProbability { get; set; }
    public double EaseOfExploitation { get; set; }
    public double Impact { get; set; }
    public string Description { get; set; }
    public List<string> RelatedTargets { get; set; } = new();
    public List<string> ExploitationSteps { get; set; } = new();
    public List<string> DetectionPoints { get; set; } = new();
    public List<string> MitigationControls { get; set; } = new();
  }

  public class LateralPathV5
  {
    public string PathName { get; set; }
    public string FromTarget { get; set; }
    public string ToTarget { get; set; }
    public double EaseScore { get; set; }
    public double RiskAmplification { get; set; }
    public string ProtocolUsed { get; set; }
    public string Description { get; set; }
    public List<string> Tools { get; set; } = new();
  }

  public class KillChainPhaseV5
  {
    public AttackPhaseV5 Phase { get; set; }
    public string PhaseName { get; set; }
    public double Likelihood { get; set; }
    public double Coverage { get; set; }
    public List<string> ObservedTtps { get; set; } = new();
    public string Status { get; set; }
  }

  #endregion

  #region CVSS分解

  public class CvssBreakdownV5
  {
    public double AverageCvss { get; set; }
    public double MaxCvss { get; set; }
    public double WeightedAverage { get; set; }
    public double RiskWeightedScore { get; set; }
    public double ExploitabilitySubscore { get; set; }
    public double ImpactSubscore { get; set; }
    public int TotalCriticalCves { get; set; }
    public int TotalHighCves { get; set; }
    public int TotalMediumCves { get; set; }
    public int TotalLowCves { get; set; }
    public int CvesWithKnownExploit { get; set; }
    public int CvesInKevCatalog { get; set; }
    public int WormableCves { get; set; }
    public double AverageAgeDays { get; set; }
    public List<CveTrendPointV5> TrendHistory { get; set; } = new();
  }

  public class CveTrendPointV5
  {
    public DateTime Date { get; set; }
    public int NewCves { get; set; }
    public int RemediatedCves { get; set; }
    public double AverageCvss { get; set; }
  }

  #endregion

  #region 端口统计

  public class PortRiskStatisticsV5
  {
    public int TotalPortsScanned { get; set; }
    public int OpenPortsCount { get; set; }
    public int FilteredPortsCount { get; set; }
    public int ClosedPortsCount { get; set; }
    public int CriticalPortsCount { get; set; }
    public int HighRiskPortsCount { get; set; }
    public int MediumRiskPortsCount { get; set; }
    public int LowRiskPortsCount { get; set; }
    public double AttackSurfaceIndex { get; set; }
    public double ExposureRatio { get; set; }
    public Dictionary<string, int> ServiceTypeDistribution { get; set; } = new();
    public Dictionary<int, double> PortRiskHeatMap { get; set; } = new();
    public List<string> RiskPatterns { get; set; } = new();
    public List<string> AdvancedThreatSignals { get; set; } = new();
  }

  #endregion

  #region 修复建议

  public class RiskRecommendationV5
  {
    public Guid Id { get; set; } = Guid.NewGuid();
    public RemediationPriorityV5 Priority { get; set; }
    public string Category { get; set; }
    public string Target { get; set; }
    public string Title { get; set; }
    public string Summary { get; set; }
    public string Rationale { get; set; }
    public double RiskReductionPotential { get; set; }
    public int EstimatedEffortHours { get; set; }
    public string Complexity { get; set; }
    public List<string> ActionSteps { get; set; } = new();
    public List<string> References { get; set; } = new();
    public DateTime? TargetCompletionDate { get; set; }
    public string RelatedRiskItemIds { get; set; }
  }

  public class RemediationPlanV5
  {
    public int TotalRecommendations { get; set; }
    public int P0ImmediateCount { get; set; }
    public int P1UrgentCount { get; set; }
    public int P2HighCount { get; set; }
    public int P3NormalCount { get; set; }
    public int P4LowCount { get; set; }
    public int TotalEstimatedHours { get; set; }
    public double ProjectedRiskReduction { get; set; }
    public List<RiskRecommendationV5> Recommendations { get; set; } = new();
    public List<string> QuickWins { get; set; } = new();
    public List<string> LongTermStrategies { get; set; } = new();
  }

  #endregion

  #region 威胁情报上下文

  public class ThreatIntelContextV5
  {
    public string ThreatActorLikelihood { get; set; }
    public List<string> RelevantAptGroups { get; set; } = new();
    public List<string> ActiveMalwareFamilies { get; set; } = new();
    public List<string> RecentExploitTrends { get; set; } = new();
    public double ExploitInTheWildProbability { get; set; }
    public double RansomwareTargetLikelihood { get; set; }
    public string IndustryThreatLevel { get; set; }
    public List<string> IocMatches { get; set; } = new();
  }

  #endregion

  #region 合规性分析

  public class ComplianceAnalysisV5
  {
    public List<string> FailedControls { get; set; } = new();
    public Dictionary<string, double> FrameworkScores { get; set; } = new();
    public double OverallComplianceScore { get; set; }
    public int CriticalFindings { get; set; }
    public int HighSeverityFindings { get; set; }
  }

  #endregion

  #region 主报告

  public class AIRiskAssessmentReportV5
  {
    public string ReportId { get; set; } = $"RISK-{DateTime.Now:yyyyMMdd-HHmmss}-{Guid.NewGuid().ToString("N")[..8].ToUpper()}";
    public string ReportVersion { get; set; } = "5.0";
    public DateTime AssessmentTime { get; set; }
    public DateTime? PreviousAssessmentTime { get; set; }
    public string EngineVersion { get; set; } = "AI Risk Engine v5.0.0-ultra";
    public string TargetIp { get; set; }
    public string TargetName { get; set; }
    public string TargetDescription { get; set; }
    public string[] TargetTags { get; set; } = Array.Empty<string>();

    public double OverallRiskScore { get; set; }
    public RiskLevelV5 OverallRiskLevel { get; set; }
    public double ConfidenceScore { get; set; }
    public string ExecutiveSummary { get; set; }
    public string NarrativeThreatOverview { get; set; }

    public PortRiskStatisticsV5 PortStatistics { get; set; } = new();
    public DimensionalScoresV5 DimensionalScores { get; set; } = new();
    public AttackChainAnalysisV5 AttackChainAnalysis { get; set; } = new();
    public CvssBreakdownV5 CvssBreakdown { get; set; } = new();
    public ThreatIntelContextV5 ThreatIntel { get; set; } = new();
    public ComplianceAnalysisV5 Compliance { get; set; } = new();
    public RemediationPlanV5 RemediationPlan { get; set; } = new();

    public List<AIRiskItemV5> RiskItems { get; set; } = new();
    public int VulnerabilityCount { get; set; }

    public double SecurityPostureScore { get; set; }
    public double ReadinessScore { get; set; }
    public double ResilienceScore { get; set; }
    public TrendDirectionV5 OverallTrend { get; set; }
    public double ScoreDeltaFromPrevious { get; set; }

    public Dictionary<string, object> BenchmarkData { get; set; } = new();
    public List<string> KeyFindingsSummary { get; set; } = new();
    public string AssessmentScope { get; set; }
    public string[] MethodologiesUsed { get; set; } = Array.Empty<string>();
  }

  #endregion
}