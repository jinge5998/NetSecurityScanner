using System.Collections.Generic;

namespace NetSecurityScanner.Models
{
  /// <summary>
  /// 摄像头扫描模板（v2）
  /// </summary>
  public class CameraScanTemplate
  {
    public string Id { get; set; } = string.Empty;
    public string Name { get; set; } = string.Empty;
    public string Description { get; set; } = string.Empty;
    public string Vendor { get; set; } = string.Empty;
    public List<int> Ports { get; set; } = new();
    public List<string> WeakUsernames { get; set; } = new();
    public List<string> WeakPasswords { get; set; } = new();
    public bool EnableDeepInspection { get; set; } = true;
    public int TimeoutMs { get; set; } = 3000;
    public string IconColor { get; set; } = "#3498DB";

    public static List<CameraScanTemplate> GetDefaultTemplates()
    {
      return new List<CameraScanTemplate>
      {
        new CameraScanTemplate
        {
          Id = "hikvision",
          Name = "海康威视深度检测",
          Description = "针对海康威视摄像头的端口/弱口令/CVE 深度检测",
          Vendor = "海康威视",
          Ports = new List<int> { 80, 443, 554, 8000, 8080, 34567, 34599 },
          WeakUsernames = new List<string> { "admin", "root", "hikvision", "user" },
          WeakPasswords = new List<string> { "12345", "admin", "hik12345", "root", "123456" },
          EnableDeepInspection = true,
          TimeoutMs = 4000,
          IconColor = "#E74C3C"
        },
        new CameraScanTemplate
        {
          Id = "dahua",
          Name = "大华深度检测",
          Description = "针对大华摄像头的端口/弱口令/CVE 深度检测",
          Vendor = "大华",
          Ports = new List<int> { 80, 443, 554, 37777, 37778, 8080 },
          WeakUsernames = new List<string> { "admin", "root", "dahua", "user" },
          WeakPasswords = new List<string> { "admin", "dahua", "12345", "root" },
          EnableDeepInspection = true,
          TimeoutMs = 4000,
          IconColor = "#F39C12"
        },
        new CameraScanTemplate
        {
          Id = "universal",
          Name = "通用摄像头扫描",
          Description = "适用于未知厂商的通用摄像头扫描",
          Vendor = "通用",
          Ports = new List<int> { 80, 443, 554, 8080, 8000, 34567, 34599, 37777, 37778 },
          WeakUsernames = new List<string> { "admin", "root", "user", "support" },
          WeakPasswords = new List<string> { "admin", "root", "12345", "123456", "password" },
          EnableDeepInspection = false,
          TimeoutMs = 3000,
          IconColor = "#3498DB"
        }
      };
    }
  }
}
