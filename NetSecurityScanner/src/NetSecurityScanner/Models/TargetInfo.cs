using System;
using System.Collections.Generic;

namespace NetSecurityScanner.Models
{
    public class TargetInfo
    {
        public string Host { get; set; } = string.Empty;
        public List<ServiceInfo> Services { get; set; }
        
        public TargetInfo()
        {
            Services = new List<ServiceInfo>();
        }
    }
    
    public class ServiceInfo
    {
        public string Name { get; set; } = string.Empty;
        public string Version { get; set; } = string.Empty;
        public int Port { get; set; }
        public string Protocol { get; set; } = string.Empty;
    }
}