namespace NetSecurityScanner.Models
{
    /// <summary>
    /// 风险评分
    /// </summary>
    public class RiskScore
    {
        public int OverallScore { get; set; }
        public string RiskLevel { get; set; } = "低";
        public int CriticalCount { get; set; }
        public int HighCount { get; set; }
        public int MediumCount { get; set; }
        public int LowCount { get; set; }
        public string Assessment { get; set; } = string.Empty;
    }
}
