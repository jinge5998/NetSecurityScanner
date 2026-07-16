using System;

namespace NetSecurityScanner.Models
{
  public enum CameraAlertType
  {
    Online,
    Offline,
    NewVulnerability,
    NewWeakPassword,
    HighRiskDetected,
    UnauthorizedAccess,
    /// <summary>v3-T3: 监控任务连续失败自动禁用</summary>
    TaskAutoDisabled
  }

  /// <summary>
  /// 摄像头扫描告警（v2）
  /// </summary>
  public class CameraAlert
  {
    public string AlertId { get; set; } = Guid.NewGuid().ToString();
    public string Ip { get; set; } = string.Empty;
    public CameraAlertType Type { get; set; }
    public string Level { get; set; } = "中"; // 低/中/高/严重
    public string Title { get; set; } = string.Empty;
    public string Message { get; set; } = string.Empty;
    public DateTime CreatedTime { get; set; } = DateTime.Now;
    public bool Acknowledged { get; set; }
    public string RelatedSessionId { get; set; } = string.Empty;
    public string RelatedTaskId { get; set; } = string.Empty;
  }
}
