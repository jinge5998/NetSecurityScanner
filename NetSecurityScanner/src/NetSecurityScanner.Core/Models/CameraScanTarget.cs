using System.Collections.Generic;

namespace NetSecurityScanner.Core.Models
{
    public class CameraScanTarget
    {
        public string IpAddress { get; set; } = string.Empty;
        public int Port { get; set; }
        public string Protocol { get; set; } = "http";
        public string DetectedVendor { get; set; } = string.Empty;
        public string HttpBanner { get; set; } = string.Empty;
        public string HttpServerHeader { get; set; } = string.Empty;
        public string HardwareVersion { get; set; } = string.Empty;
        public string FirmwareVersion { get; set; } = string.Empty;
        public bool IsReachable { get; set; }
        public List<int> OpenPorts { get; set; } = new();
        public Dictionary<int, string> PortServices { get; set; } = new();
    }
}