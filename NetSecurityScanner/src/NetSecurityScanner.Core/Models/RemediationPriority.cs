namespace NetSecurityScanner.Models
{
    /// <summary>
    /// 修复优先级
    /// </summary>
    public class RemediationPriority
    {
        public int Priority { get; set; }
        public string VulnerabilityName { get; set; } = string.Empty;
        public string RiskLevel { get; set; } = string.Empty;
        public string RecommendedAction { get; set; } = string.Empty;
        public string Timeframe { get; set; } = string.Empty;
    }
}
