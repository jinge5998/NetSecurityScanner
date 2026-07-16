using System;
using System.Collections.Generic;

namespace NetSecurityScanner.Models
{
  /// <summary>
  /// 摄像头扫描时间线条目
  /// </summary>
  public class CameraScanEvent
  {
    public DateTime Time { get; set; } = DateTime.Now;
    public string EventType { get; set; } = string.Empty; // Start/Progress/Result/Complete/Error
    public string Message { get; set; } = string.Empty;
    public int CurrentCount { get; set; }
    public int TotalCount { get; set; }
  }

  /// <summary>
  /// 摄像头扫描会话记录（v2）
  /// </summary>
  public class CameraScanSession
  {
    public string SessionId { get; set; } = Guid.NewGuid().ToString();
    public string SessionName { get; set; } = string.Empty;
    public DateTime StartTime { get; set; } = DateTime.Now;
    public DateTime? EndTime { get; set; }
    public TimeSpan Duration => (EndTime ?? DateTime.Now) - StartTime;
    public string Preset { get; set; } = "标准扫描";
    public string MonitoringMode { get; set; } = "单次";
    public string TemplateId { get; set; } = string.Empty;
    public List<string> TargetIps { get; set; } = new();
    public List<CameraScanResult> Results { get; set; } = new();
    public List<CameraScanEvent> ProgressTimeline { get; set; } = new();
    public string Status { get; set; } = "进行中"; // 进行中/已完成/已取消/失败
    public int TotalScanned { get; set; }
    public int OnlineCameras { get; set; }
    public int TotalVulnerabilities { get; set; }
  }
}
