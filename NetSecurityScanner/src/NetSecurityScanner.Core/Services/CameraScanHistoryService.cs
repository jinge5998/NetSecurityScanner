using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;
using NetSecurityScanner.Data;
using NetSecurityScanner.Models;

namespace NetSecurityScanner.Core
{
  /// <summary>
  /// 摄像头扫描结果历史记录服务
  /// </summary>
  public class CameraScanHistoryService
  {
    private const string JsonDataDir = "camera_history";
    private const string JsonFileName = "camera_scan_history.json";

    private static string GetJsonPath()
    {
      var baseDir = Path.Combine(
          Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
          "NetSecurityScanner", "data", JsonDataDir);
      Directory.CreateDirectory(baseDir);
      return Path.Combine(baseDir, JsonFileName);
    }

    /// <summary>
    /// 将摄像头扫描结果保存到扫描历史（SQLite + JSON）
    /// </summary>
    public async Task<(bool Success, string Message)> SaveToHistoryAsync(
        string presetName,
        List<string> targetIps,
        List<CameraScanResult> results,
        TimeSpan duration)
    {
      if (results == null) results = new List<CameraScanResult>();
      var onlineResults = results.Where(r => r.IsOnline).ToList();

      var target = string.Join(", ", targetIps.Take(5));
      if (targetIps.Count > 5) target += $" 等{targetIps.Count}个目标";

      var totalCritical = onlineResults.Sum(c => c.RiskAssessment?.CriticalCount ?? 0);
      var totalHigh = onlineResults.Sum(c => c.RiskAssessment?.HighCount ?? 0);
      var totalMedium = onlineResults.Sum(c => c.RiskAssessment?.MediumCount ?? 0);
      var totalWeakPasswords = onlineResults.Sum(c => c.WeakPasswords?.Count ?? 0);
      var totalVulns = onlineResults.Sum(c => c.Vulnerabilities?.Count ?? 0);
      var totalOpenPorts = onlineResults.Sum(c => c.OpenPorts?.Count ?? 0);

      var scanMode = $"摄像头扫描-{presetName}";
      var notes = $"目标: {target}\n" +
                  $"在线摄像头: {onlineResults.Count} 台\n" +
                  $"严重: {totalCritical}, 高危: {totalHigh}, 中危: {totalMedium}\n" +
                  $"弱口令: {totalWeakPasswords}, 漏洞: {totalVulns}, 开放端口: {totalOpenPorts}";

      try
      {
        // 1. 保存到 SQLite 数据库（与现有扫描历史窗口集成）
        using var ctx = new ScanDbContext();
        ctx.Database.EnsureCreated();

        var history = new ScanHistory
        {
          ScanId = Guid.NewGuid().ToString(),
          StartTime = DateTime.Now - duration,
          EndTime = DateTime.Now,
          ScanTime = DateTime.Now,
          Duration = duration,
          ScanMode = scanMode,
          Target = target,
          TargetRange = string.Join(",", targetIps),
          TotalPorts = totalOpenPorts,
          OpenPorts = totalOpenPorts,
          TotalVulnerabilities = totalVulns,
          CriticalCount = totalCritical,
          HighCount = totalHigh,
          MediumCount = totalMedium,
          LowCount = 0,
          InfoCount = 0,
          ScanStatus = "已完成",
          ScanConfiguration = JsonSerializer.Serialize(new
          {
            Preset = presetName,
            TargetCount = targetIps.Count,
            CameraResults = onlineResults.Select(c => new
            {
              c.Ip,
              c.Vendor,
              c.Model,
              c.FirmwareVersion,
              c.Mac,
              c.SerialNumber,
              c.HasTelnet,
              OpenPorts = c.OpenPorts?.Select(p => new
              {
                p.Port,
                p.Protocol,
                p.Service,
                p.Status,
                p.Banner,
                p.RiskLevel
              }),
              Vulnerabilities = c.Vulnerabilities?.Select(v => new
              {
                v.CveId,
                v.Name,
                v.Severity,
                v.CvssScore,
                v.Solution
              }),
              WeakPasswords = c.WeakPasswords?.Select(w => new
              {
                w.ServiceType,
                w.Port,
                w.Username,
                w.RiskLevel
              }),
              RiskAssessment = new
              {
                c.RiskAssessment?.TotalScore,
                c.RiskAssessment?.RiskLevel
              }
            })
          }, new JsonSerializerOptions { WriteIndented = true }),
          CreatedBy = "CameraScanner",
          Notes = notes
        };

        ctx.ScanHistories.Add(history);
        await ctx.SaveChangesAsync();

        // 2. 同时保存到 JSON 文件（兼容历史）
        await SaveToJsonFileAsync(presetName, targetIps, results, duration, history.ScanId);

        return (true, $"已保存扫描历史 (ID: {history.ScanId})，扫描历史窗口可见");
      }
      catch (Exception ex)
      {
        return (false, $"保存失败: {ex.Message}");
      }
    }

    private async Task SaveToJsonFileAsync(
        string presetName,
        List<string> targetIps,
        List<CameraScanResult> results,
        TimeSpan duration,
        string scanId)
    {
      try
      {
        var jsonPath = GetJsonPath();
        var historyList = new List<CameraScanHistoryEntry>();

        if (File.Exists(jsonPath))
        {
          try
          {
            var existingJson = await File.ReadAllTextAsync(jsonPath, Encoding.UTF8);
            historyList = JsonSerializer.Deserialize<List<CameraScanHistoryEntry>>(existingJson) ?? new List<CameraScanHistoryEntry>();
          }
          catch { /* 忽略旧文件错误 */ }
        }

        historyList.Add(new CameraScanHistoryEntry
        {
          ScanId = scanId,
          PresetName = presetName,
          TargetIps = targetIps,
          Results = results,
          ScanTime = DateTime.Now,
          Duration = duration,
          TotalCameras = results.Count,
          OnlineCameras = results.Count(r => r.IsOnline)
        });

        if (historyList.Count > 100) historyList = historyList.OrderByDescending(h => h.ScanTime).Take(100).ToList();

        var json = JsonSerializer.Serialize(historyList, new JsonSerializerOptions { WriteIndented = true });
        await File.WriteAllTextAsync(jsonPath, json, Encoding.UTF8);
      }
      catch
      {
        // 静默失败，不影响SQLite保存
      }
    }
  }

  public class CameraScanHistoryEntry
  {
    public string ScanId { get; set; } = string.Empty;
    public string PresetName { get; set; } = string.Empty;
    public List<string> TargetIps { get; set; } = new();
    public List<CameraScanResult> Results { get; set; } = new();
    public DateTime ScanTime { get; set; }
    public TimeSpan Duration { get; set; }
    public int TotalCameras { get; set; }
    public int OnlineCameras { get; set; }
  }
}
