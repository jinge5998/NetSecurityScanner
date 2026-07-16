using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.Json;
using NetSecurityScanner.Models;
using NetSecurityScanner.Utils;

namespace NetSecurityScanner.Core
{
  /// <summary>
  /// 摄像头扫描基线服务（v3-T4）。
  /// 持久化路径：<c>%LOCALAPPDATA%\NetSecurityScanner\data\camera_baseline.json</c>。
  /// </summary>
  public class CameraBaselineService
  {
    private readonly string BaselineFile = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
        "NetSecurityScanner", "data", "camera_baseline.json");

    private CameraBaseline? _current;

    public CameraBaselineService()
    {
      _current = Load();
    }

    public CameraBaseline? CurrentBaseline => _current;

    /// <summary>
    /// 保存指定 sessionId 对应的扫描结果作为最新基线。
    /// </summary>
    public CameraBaseline SaveBaseline(string sessionId, List<CameraScanResult> results, string description = "")
    {
      if (results == null) results = new List<CameraScanResult>();
      var baseline = new CameraBaseline
      {
        SessionId = string.IsNullOrEmpty(sessionId) ? Guid.NewGuid().ToString() : sessionId,
        SnapshotTime = DateTime.Now,
        Description = description,
        Results = results
      };
      _current = baseline;
      Persist();
      return baseline;
    }

    /// <summary>
    /// 与当前基线对比，返回 Added / Removed / Changed 列表。
    /// </summary>
    public CameraBaselineDiff CompareLatest(List<CameraScanResult> currentResults)
    {
      var diff = new CameraBaselineDiff
      {
        BaselineSessionId = _current?.SessionId ?? string.Empty,
        BaselineTime = _current?.SnapshotTime ?? DateTime.MinValue
      };
      if (_current == null || _current.Results.Count == 0)
      {
        // 没有基线时，全部视为 Added
        diff.Added = new List<CameraScanResult>(currentResults ?? new List<CameraScanResult>());
        return diff;
      }

      var baselineByIp = _current.Results
          .Where(r => !string.IsNullOrEmpty(r.Ip))
          .GroupBy(r => r.Ip)
          .ToDictionary(g => g.Key, g => g.First());
      var currentByIp = (currentResults ?? new List<CameraScanResult>())
          .Where(r => !string.IsNullOrEmpty(r.Ip))
          .GroupBy(r => r.Ip)
          .ToDictionary(g => g.Key, g => g.First());

      foreach (var kv in currentByIp)
      {
        if (!baselineByIp.ContainsKey(kv.Key))
        {
          diff.Added.Add(kv.Value);
        }
        else if (HasMaterialChange(baselineByIp[kv.Key], kv.Value, out var notes))
        {
          diff.Changed.Add(new CameraBaselineChange
          {
            Ip = kv.Key,
            Baseline = baselineByIp[kv.Key],
            Current = kv.Value,
            ChangeNotes = notes
          });
        }
      }

      foreach (var kv in baselineByIp)
      {
        if (!currentByIp.ContainsKey(kv.Key))
        {
          diff.RemovedIps.Add(kv.Key);
        }
      }

      return diff;
    }

    public void Clear()
    {
      _current = null;
      try
      {
        if (File.Exists(BaselineFile)) File.Delete(BaselineFile);
      }
      catch { }
    }

    private static bool HasMaterialChange(CameraScanResult baseline, CameraScanResult current, out List<string> notes)
    {
      notes = new List<string>();
      if (baseline.IsOnline != current.IsOnline)
        notes.Add($"在线状态: {baseline.IsOnline} -> {current.IsOnline}");
      if (baseline.RiskAssessment?.RiskLevel != current.RiskAssessment?.RiskLevel)
        notes.Add($"风险等级: {baseline.RiskAssessment?.RiskLevel} -> {current.RiskAssessment?.RiskLevel}");
      var bv = baseline.Vulnerabilities?.Count ?? 0;
      var cv = current.Vulnerabilities?.Count ?? 0;
      if (bv != cv)
        notes.Add($"漏洞数: {bv} -> {cv}");
      var bw = baseline.WeakPasswords?.Count ?? 0;
      var cw = current.WeakPasswords?.Count ?? 0;
      if (bw != cw)
        notes.Add($"弱口令数: {bw} -> {cw}");
      if ((baseline.OpenPorts?.Count ?? 0) != (current.OpenPorts?.Count ?? 0))
        notes.Add($"开放端口数: {baseline.OpenPorts?.Count ?? 0} -> {current.OpenPorts?.Count ?? 0}");
      return notes.Count > 0;
    }

    private void Persist()
    {
      try
      {
        Directory.CreateDirectory(Path.GetDirectoryName(BaselineFile)!);
        var json = JsonSerializer.Serialize(_current, new JsonSerializerOptions { WriteIndented = true });
        File.WriteAllText(BaselineFile, json);
      }
      catch { }
    }

    private CameraBaseline? Load()
    {
      try
      {
        if (!File.Exists(BaselineFile)) return null;
        var json = File.ReadAllText(BaselineFile);
        return JsonSerializer.Deserialize<CameraBaseline>(json);
      }
      catch
      {
        return null;
      }
    }
  }
}
