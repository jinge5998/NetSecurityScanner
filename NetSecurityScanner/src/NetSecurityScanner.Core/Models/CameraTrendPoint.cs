using System;

namespace NetSecurityScanner.Core.Models
{
    public class CameraTrendPoint
    {
        public DateTime Date { get; set; }
        public double Total { get; set; }
        public double Online { get; set; }
        public double VulnTotal { get; set; }
    }
}