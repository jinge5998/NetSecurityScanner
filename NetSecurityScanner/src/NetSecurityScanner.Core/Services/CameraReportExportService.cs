using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;
using NetSecurityScanner.Models;

namespace NetSecurityScanner.Core
{
  /// <summary>
  /// 摄像头扫描报告导出服务
  /// </summary>
  public class CameraReportExportService
  {
    private static readonly UTF8Encoding Utf8WithBom = new(true);

    public string ExportToCsv(
        string presetName,
        List<string> targetIps,
        List<CameraScanResult> results,
        System.TimeSpan duration)
    {
      var sb = new StringBuilder();
      sb.AppendLine($"# 摄像头安全扫描报告");
      sb.AppendLine($"# 扫描预设,{presetName}");
      sb.AppendLine($"# 扫描时间,{System.DateTime.Now:yyyy-MM-dd HH:mm:ss}");
      sb.AppendLine($"# 扫描耗时,{duration.TotalSeconds:F1}秒");
      sb.AppendLine($"# 目标总数,{targetIps.Count}");
      sb.AppendLine($"# 摄像头总数,{results.Count}");
      sb.AppendLine($"# 在线摄像头,{results.Count(r => r.IsOnline)}");
      sb.AppendLine();
      sb.AppendLine("IP,IP类型,厂商,型号,固件版本,MAC,序列号,风险等级,风险评分,严重漏洞,高危漏洞,中危漏洞,漏洞总数,弱口令数,开放端口数,Telnet开放,优先修复建议");

      foreach (var c in results)
      {
        if (!c.IsOnline) continue;
        sb.AppendLine(
            $"{EscapeCsvField(c.Ip)}," +
            $"{EscapeCsvField(c.IpType)}," +
            $"{EscapeCsvField(c.Vendor)}," +
            $"{EscapeCsvField(c.Model)}," +
            $"{EscapeCsvField(c.FirmwareVersion)}," +
            $"{EscapeCsvField(c.Mac)}," +
            $"{EscapeCsvField(c.SerialNumber)}," +
            $"{EscapeCsvField(c.RiskAssessment?.RiskLevel ?? "")}," +
            $"{(c.RiskAssessment?.TotalScore ?? 0):F1}," +
            $"{(c.RiskAssessment?.CriticalCount ?? 0)}," +
            $"{(c.RiskAssessment?.HighCount ?? 0)}," +
            $"{(c.RiskAssessment?.MediumCount ?? 0)}," +
            $"{c.Vulnerabilities?.Count ?? 0}," +
            $"{c.WeakPasswords?.Count ?? 0}," +
            $"{c.OpenPorts?.Count ?? 0}," +
            $"{(c.HasTelnet ? "是" : "否")}," +
            $"{EscapeCsvField(string.Join(" | ", c.RiskAssessment?.TopRemediations ?? new List<string>()))}");
      }
      return sb.ToString();
    }

    public string ExportToJson(
        string presetName,
        List<string> targetIps,
        List<CameraScanResult> results,
        System.TimeSpan duration)
    {
      var report = new
      {
        ScanId = System.Guid.NewGuid().ToString(),
        Preset = presetName,
        ScanTime = System.DateTime.Now,
        DurationSeconds = duration.TotalSeconds,
        TargetCount = targetIps.Count,
        TotalCameras = results.Count,
        OnlineCameras = results.Count(r => r.IsOnline),
        Cameras = results,
        Summary = new
        {
          TotalVulnerabilities = results.Sum(c => c.Vulnerabilities?.Count ?? 0),
          CriticalVulnerabilities = results.Sum(c => c.RiskAssessment?.CriticalCount ?? 0),
          HighVulnerabilities = results.Sum(c => c.RiskAssessment?.HighCount ?? 0),
          MediumVulnerabilities = results.Sum(c => c.RiskAssessment?.MediumCount ?? 0),
          WeakPasswords = results.Sum(c => c.WeakPasswords?.Count ?? 0),
          OpenPorts = results.Sum(c => c.OpenPorts?.Count ?? 0),
          HighRiskCameras = results.Count(c => c.IsOnline && (c.RiskAssessment?.RiskLevel == "严重" || c.RiskAssessment?.RiskLevel == "高危"))
        }
      };
      return JsonSerializer.Serialize(report, new JsonSerializerOptions { WriteIndented = true });
    }

    public async Task SaveCsvAsync(string filePath, string presetName,
        List<string> targetIps, List<CameraScanResult> results, System.TimeSpan duration)
    {
      var content = ExportToCsv(presetName, targetIps, results, duration);
      await File.WriteAllTextAsync(filePath, content, Utf8WithBom);
    }

    public async Task SaveJsonAsync(string filePath, string presetName,
        List<string> targetIps, List<CameraScanResult> results, System.TimeSpan duration)
    {
      var content = ExportToJson(presetName, targetIps, results, duration);
      await File.WriteAllTextAsync(filePath, content, Utf8WithBom);
    }

    private static string EscapeCsvField(string field)
    {
      if (string.IsNullOrEmpty(field)) return "";
      if (field.Contains(',') || field.Contains('"') || field.Contains('\n') || field.Contains('\r'))
      {
        return "\"" + field.Replace("\"", "\"\"") + "\"";
      }
      return field;
    }
  }
}
