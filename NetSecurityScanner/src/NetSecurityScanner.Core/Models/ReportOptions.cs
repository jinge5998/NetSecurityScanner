namespace NetSecurityScanner.Models
{
    public enum HistoryReportFormat
    {
        PDF,
        Word,
        HTML
    }

    public class ReportOptions
    {
        public HistoryReportFormat Format { get; set; } = HistoryReportFormat.PDF;
        public bool IncludeExecutiveSummary { get; set; } = true;
        public bool IncludeVulnerabilityList { get; set; } = true;
        public bool IncludeRemediation { get; set; } = true;
        public bool IncludeStatistics { get; set; } = true;
        public bool IncludeCharts { get; set; } = true;
        public bool IncludeAppendix { get; set; } = true;
        public string CompanyName { get; set; } = "徐州鸿高电子科技有限公司";
        public string ReportType { get; set; } = "网络安全扫描报告";
        public string ConfidentialLevel { get; set; } = "机密";
        public string AuthorName { get; set; } = "NetSecurity Scanner";
        public string Logo { get; set; } = string.Empty;
        public bool IncludeCvssScore { get; set; } = true;
        public bool IncludeOwaspMapping { get; set; } = true;
        public bool IncludePriorityRanking { get; set; } = true;
    }
}