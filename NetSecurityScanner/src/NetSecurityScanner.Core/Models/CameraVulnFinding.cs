namespace NetSecurityScanner.Core.Models
{
    public class CameraVulnFinding
    {
        public string CveId { get; set; } = string.Empty;
        public string Name { get; set; } = string.Empty;
            public string Description { get; set; } = string.Empty;
        public string Severity { get; set; } = string.Empty;
        public double CvssScore { get; set; }
        public string Vendor { get; set; } = string.Empty;
        public bool Confirmed { get; set; }
        public string Evidence { get; set; } = string.Empty;
        public string Endpoint { get; set; } = string.Empty;
        public string DetectionMethod { get; set; } = string.Empty;
        public string Remedy { get; set; } = string.Empty;
    }
}