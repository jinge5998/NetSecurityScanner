using System;

namespace NetSecurityScanner.Models
{
  /// <summary>
  /// 摄像头分组标签（v4-T2）
  /// </summary>
  public class CameraTag
  {
    public string TagId { get; set; } = Guid.NewGuid().ToString();
    public string Name { get; set; } = string.Empty;
    /// <summary>HEX 颜色字符串（如 #3498DB）</summary>
    public string Color { get; set; } = "#3498DB";
    public string Description { get; set; } = string.Empty;
    public DateTime CreatedTime { get; set; } = DateTime.Now;
  }

  /// <summary>
  /// 标签 - IP 关联（v4-T2）
  /// </summary>
  public class CameraTagAssignment
  {
    public string Ip { get; set; } = string.Empty;
    public string TagId { get; set; } = string.Empty;
  }
}
