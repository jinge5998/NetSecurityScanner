using System.Collections.Generic;

namespace NetSecurityScanner.Models
{
  /// <summary>
  /// 摄像头 IP 白/黑名单（v3-T5）。
  /// </summary>
  public class CameraIpList
  {
    public List<string> WhiteList { get; set; } = new();
    public List<string> BlackList { get; set; } = new();

    public static CameraIpList Empty => new();
  }
}
