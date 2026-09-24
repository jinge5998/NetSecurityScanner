namespace NetSecurityScanner.Models
{
    public class ScanOptions
    {
        public int MaxConcurrency { get; set; } = 200; // 200线程并发
        public int Timeout { get; set; } = 2000;       // 2秒超时，提高速度
        public bool EnableServiceDetection { get; set; } = true;
        public bool EnableOsDetection { get; set; } = true;
        public string ScanType { get; set; } = "TCP";
        public int RetryCount { get; set; } = 1;       // 1次重试，提高速度
    }
}