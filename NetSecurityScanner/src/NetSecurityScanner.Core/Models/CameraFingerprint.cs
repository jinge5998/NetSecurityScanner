using System.Collections.Generic;

namespace NetSecurityScanner.Core.Models
{
    public class CameraFingerprint
    {
        public string Vendor { get; set; } = string.Empty;
        public List<string> HttpPatterns { get; set; } = new();
        public List<string> HttpServer { get; set; } = new();
        public List<string> OnvifManufacturers { get; set; } = new();
        public List<int> DefaultPorts { get; set; } = new();
        public List<string> SdkPaths { get; set; } = new();
        public string RtspUserAgent { get; set; } = string.Empty;
    }
}