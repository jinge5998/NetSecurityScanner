using System;
using System.Collections.Generic;

namespace NetSecurityScanner.Models
{
  public class LicenseIssuanceRecord
  {
    public string Id { get; set; } = Guid.NewGuid().ToString();
    public int SequenceNumber { get; set; }
    public string LicenseCode { get; set; } = string.Empty;
    public string MachineId { get; set; } = string.Empty;
    public string MachineIdPrefix { get; set; } = string.Empty;
    public LicenseType LicenseType { get; set; }
    public string LicenseTypeName => LicenseType switch
    {
      LicenseType.TRIAL => "5分钟",
      LicenseType.YEAR1 => "1年期",
      LicenseType.YEAR2 => "2年期",
      LicenseType.PERMANENT => "永久",
      _ => LicenseInfo.TypeToCode(LicenseType)
    };
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
    public List<LicenseIssuanceRecord> Records { get; set; } = new List<LicenseIssuanceRecord>();
  }
}