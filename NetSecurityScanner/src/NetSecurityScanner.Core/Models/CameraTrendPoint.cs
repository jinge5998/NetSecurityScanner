using System;

namespace NetSecurityScanner.Models
{
  /// <summary>
  /// 摄像头扫描历史趋势点（v4-T5）
  /// </summary>
  public class CameraTrendPoint
  {
    public DateTime Date { get; set; }
    public int Total { get; set; }
    public int Online { get; set; }
    public int Offline { get; set; }
    public int VulnTotal { get; set; }
    public int HighVuln { get; set; }
  }
}
