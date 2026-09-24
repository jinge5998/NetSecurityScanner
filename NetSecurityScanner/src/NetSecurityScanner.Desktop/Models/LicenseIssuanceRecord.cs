using System;

namespace NetSecurityScanner.Models
{
  public class LicenseIssuanceRecord
  {
    public string Id { get; set; } = Guid.NewGuid().ToString();
    public string LicenseCode { get; set; } = string.Empty;
    public string MachineId { get; set; } = string.Empty;
    public string MachineIdPrefix { get; set; } = string.Empty;
    public LicenseType LicenseType { get; set; }
    public string LicenseTypeName => LicenseInfo.TypeToCode(LicenseType);
    public DateTime IssuedTime { get; set; }
    public DateTime? ExpiryTime { get; set; }
    public string IssuedBy { get; set; } = string.Empty;
    public string Note { get; set; } = string.Empty;
    public DateTime CreatedAt { get; set; } = DateTime.Now;

    public string ExpiryDisplay
    {
      get
      {
        if (LicenseType == LicenseType.PERMANENT) return "永久";
        return ExpiryTime?.ToString("yyyy-MM-dd HH:mm") ?? "-";
      }
    }
  }

  public class LicenseIssuanceData
  {
    public System.Collections.Generic.List<LicenseIssuanceRecord> Records { get; set; } = new System.Collections.Generic.List<LicenseIssuanceRecord>();
  }
}