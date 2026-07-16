using System.Collections.Generic;

namespace NetSecurityScanner.Models
{
  /// <summary>
  /// 摄像头厂商指纹规则（用于 T2 多级验证）。
  /// </summary>
  public class CameraFingerprintRule
  {
    public string Vendor { get; set; } = string.Empty;
    public List<string> HttpPatterns { get; set; } = new();
    public List<string> HttpServer { get; set; } = new();
    public List<string> OnvifManufacturers { get; set; } = new();
    public List<int> DefaultPorts { get; set; } = new();
  }
}
