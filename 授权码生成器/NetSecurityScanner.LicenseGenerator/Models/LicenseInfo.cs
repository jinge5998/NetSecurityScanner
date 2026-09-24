using System;

namespace NetSecurityScanner.LicenseGenerator.Models
{
    public enum LicenseType
    {
        TRIAL = 0,
        YEAR1 = 1,
        YEAR2 = 2,
        PERMANENT = 3
    }

    public class LicensePayload
    {
        public string Type { get; set; } = string.Empty;
        public string Issued { get; set; } = string.Empty;
        public string MachineId { get; set; } = string.Empty;
        public string TypeCode { get; set; } = string.Empty;
    }
}
