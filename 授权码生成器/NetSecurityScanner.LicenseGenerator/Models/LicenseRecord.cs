using System;

namespace NetSecurityScanner.LicenseGenerator.Models
{
    public class LicenseRecord
    {
        public string RecordId { get; set; } = Guid.NewGuid().ToString();
        public string LicenseCode { get; set; } = string.Empty;
        public string LicenseType { get; set; } = string.Empty;
        public string MachineId { get; set; } = string.Empty;
        public DateTime IssuedTime { get; set; } = DateTime.Now;
        public DateTime? ExpiryTime { get; set; }
        public string Notes { get; set; } = string.Empty;

        public string LicenseTypeDisplay
        {
            get
            {
                return LicenseType switch
                {
                    "TRIAL" => "试用版（5分钟）",
                    "YEAR1" => "1年期授权",
                    "YEAR2" => "2年期授权",
                    "PERMANENT" => "永久授权",
                    _ => LicenseType
                };
            }
        }

        public string ExpiryDisplay
        {
            get
            {
                if (LicenseType == "PERMANENT") return "永久";
                return ExpiryTime.HasValue ? ExpiryTime.Value.ToString("yyyy-MM-dd HH:mm:ss") : "-";
            }
        }
    }
}
