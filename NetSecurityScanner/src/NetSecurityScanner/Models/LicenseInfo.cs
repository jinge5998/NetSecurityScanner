using System;

namespace NetSecurityScanner.Models
{
  public enum LicenseType
  {
    TRIAL = 0,
    YEAR1 = 1,
    YEAR2 = 2,
    PERMANENT = 3
  }

  public class LicenseInfo
  {
    public LicenseType Type { get; set; }
    public DateTime IssuedTime { get; set; }
    public DateTime? ExpiryTime { get; set; }
    public string MachineId { get; set; } = string.Empty;
    public string Signature { get; set; } = string.Empty;
    public string LicenseCode { get; set; } = string.Empty;
    public bool IsTrial => Type == LicenseType.TRIAL;
    public static string TypeToCode(LicenseType type) => type switch
    {
      LicenseType.TRIAL => "T",
      LicenseType.YEAR1 => "1",
      LicenseType.YEAR2 => "2",
      LicenseType.PERMANENT => "P",
      _ => "T"
    };

    public static LicenseType CodeToType(string code) => code?.ToUpper() switch
    {
      "T" => LicenseType.TRIAL,
      "1" => LicenseType.YEAR1,
      "2" => LicenseType.YEAR2,
      "P" => LicenseType.PERMANENT,
      _ => LicenseType.TRIAL
    };
    public bool IsPermanent => Type == LicenseType.PERMANENT;
    public bool IsExpired
    {
      get
      {
        if (IsPermanent) return false;
        if (ExpiryTime == null) return true;
        return DateTime.Now > ExpiryTime.Value;
      }
    }
    public TimeSpan? RemainingTime
    {
      get
      {
        if (IsPermanent) return null;
        if (ExpiryTime == null) return TimeSpan.Zero;
        var remaining = ExpiryTime.Value - DateTime.Now;
        return remaining > TimeSpan.Zero ? remaining : TimeSpan.Zero;
      }
    }
    public string DisplayName
    {
      get
      {
        return Type switch
        {
          LicenseType.TRIAL => "试用版（5分钟）",
          LicenseType.YEAR1 => "1年期授权",
          LicenseType.YEAR2 => "2年期授权",
          LicenseType.PERMANENT => "永久授权",
          _ => "未知类型"
        };
      }
    }
  }

  public class LicensePayload
  {
    public string Type { get; set; } = string.Empty;
    public string Issued { get; set; } = string.Empty;
    public string MachineId { get; set; } = string.Empty;
    public string TypeCode { get; set; } = string.Empty;
  }

  public class LicenseStatus
  {
    public bool IsLicensed { get; set; }
    public bool IsExpired { get; set; }
    public LicenseInfo? LicenseInfo { get; set; }
    public string StatusText { get; set; } = "未授权";
    public string MachineId { get; set; } = string.Empty;
  }
}