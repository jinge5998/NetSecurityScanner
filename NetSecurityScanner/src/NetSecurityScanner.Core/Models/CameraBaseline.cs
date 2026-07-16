using System;
using System.Collections.Generic;

namespace NetSecurityScanner.Models
{
  /// <summary>
  /// 扫描基线快照（v3-T4）。
  /// 记录某一时间点的扫描结果，作为后续对比的基准。
  /// </summary>
  public class CameraBaseline
  {
    public string SessionId { get; set; } = string.Empty;
    public DateTime SnapshotTime { get; set; } = DateTime.Now;
    public string Description { get; set; } = string.Empty;
    public List<CameraScanResult> Results { get; set; } = new();
  }

  /// <summary>
  /// 基线差异（v3-T4）：Added 新增 / Removed 消失 / Changed 变化。
  /// </summary>
  public class CameraBaselineDiff
  {
    public string BaselineSessionId { get; set; } = string.Empty;
    public DateTime BaselineTime { get; set; }
    public DateTime CompareTime { get; set; } = DateTime.Now;
    public List<CameraScanResult> Added { get; set; } = new();
    public List<string> RemovedIps { get; set; } = new();
    public List<CameraBaselineChange> Changed { get; set; } = new();
  }

  /// <summary>
  /// 同一台摄像头的变化项（v3-T4）。
  /// </summary>
  public class CameraBaselineChange
  {
    public string Ip { get; set; } = string.Empty;
    public CameraScanResult? Baseline { get; set; }
    public CameraScanResult? Current { get; set; }
    public List<string> ChangeNotes { get; set; } = new();
  }
}
