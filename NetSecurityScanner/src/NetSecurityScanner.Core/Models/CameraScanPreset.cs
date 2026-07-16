using System.Collections.Generic;

namespace NetSecurityScanner.Models
{
  /// <summary>
  /// 摄像头扫描预设配置
  /// </summary>
  public class CameraScanPreset
  {
    public string Name { get; set; } = string.Empty;
    public string Description { get; set; } = string.Empty;
    public bool EnableFingerprint { get; set; } = true;
    public bool EnableVulnerabilityScan { get; set; } = true;
    public bool EnableWeakPasswordScan { get; set; } = true;
    public bool EnableAggressiveScan { get; set; } = false;
    public int MaxConcurrency { get; set; } = 30;
    public int TimeoutMs { get; set; } = 3000;
    public int MaxPasswordAttempts { get; set; } = 50;
    public bool UseDefaultPorts { get; set; } = true;
    public List<int> CustomPorts { get; set; } = new();

    public static List<CameraScanPreset> GetDefaultPresets()
    {
      return new List<CameraScanPreset>
      {
        new CameraScanPreset
        {
          Name = "快速扫描",
          Description = "仅端口扫描 + 基本指纹识别，约 30 秒/百台",
          EnableFingerprint = true,
          EnableVulnerabilityScan = false,
          EnableWeakPasswordScan = false,
          MaxConcurrency = 50,
          TimeoutMs = 2000
        },
        new CameraScanPreset
        {
          Name = "标准扫描",
          Description = "端口扫描 + 指纹 + 弱口令检测（HTTP/RTSP/ONVIF），约 2 分钟/百台",
          EnableFingerprint = true,
          EnableVulnerabilityScan = false,
          EnableWeakPasswordScan = true,
          MaxConcurrency = 30,
          TimeoutMs = 3000,
          MaxPasswordAttempts = 30
        },
        new CameraScanPreset
        {
          Name = "深度扫描",
          Description = "完整漏洞探测 + 全服务弱口令爆破（HTTP/RTSP/ONVIF/SSH/Telnet/FTP），约 5-10 分钟/百台",
          EnableFingerprint = true,
          EnableVulnerabilityScan = true,
          EnableWeakPasswordScan = true,
          EnableAggressiveScan = true,
          MaxConcurrency = 20,
          TimeoutMs = 5000,
          MaxPasswordAttempts = 100
        },
        new CameraScanPreset
        {
          Name = "自定义",
          Description = "手动配置扫描参数",
          EnableFingerprint = true,
          EnableVulnerabilityScan = true,
          EnableWeakPasswordScan = true,
          MaxConcurrency = 30,
          TimeoutMs = 3000
        }
      };
    }
  }
}
