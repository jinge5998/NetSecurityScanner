using System;
using System.Collections.Generic;

namespace NetSecurityScanner.Models
{
  /// <summary>
  /// 监控任务调度类型（v3-T3）。
  /// </summary>
  public enum ScheduleType
  {
    /// <summary>固定间隔（分钟）</summary>
    Interval = 0,
    /// <summary>Cron 表达式（5 字段）</summary>
    Cron = 1
  }

  /// <summary>
  /// 摄像头监控任务（v2 + v3）
  /// </summary>
  public class CameraMonitorTask
  {
    public string TaskId { get; set; } = Guid.NewGuid().ToString();
    public string Name { get; set; } = string.Empty;
    public List<string> TargetIps { get; set; } = new();
    public int IntervalMinutes { get; set; } = 30;
    public string CronExpression { get; set; } = string.Empty;
    /// <summary>v3-T3: Interval 或 Cron</summary>
    public ScheduleType ScheduleType { get; set; } = ScheduleType.Interval;
    public bool Enabled { get; set; } = true;
    public DateTime CreatedTime { get; set; } = DateTime.Now;
    public DateTime? LastRunTime { get; set; }
    public DateTime? NextRunTime { get; set; }
    public string Preset { get; set; } = "快速扫描";
    public string TemplateId { get; set; } = string.Empty;
    public List<int> MonitorPorts { get; set; } = new() { 80, 554 };
    public int ConsecutiveFailures { get; set; }
    public bool NotifyOnOffline { get; set; } = true;
    public bool NotifyOnNewVulnerability { get; set; } = true;
    public bool SoundAlert { get; set; }
  }
}
