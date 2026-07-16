using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using NetSecurityScanner.Models;

namespace NetSecurityScanner.Core
{
  /// <summary>
  /// 摄像头告警服务（v2 + v3 去重）
  /// </summary>
  public class CameraAlertService
  {
    private readonly string AlertDir = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
        "NetSecurityScanner", "data", "camera_alerts");

    private readonly List<CameraAlert> _alerts = new();
    private readonly Dictionary<string, bool> _lastStatus = new(); // IP -> 是否在线
    private readonly Dictionary<string, int> _lastVulnCount = new();
    // v3-T1: 24h TTL 的指纹去重表
    // key = `${Ip}:${Type}:${Date:yyyyMMddHH}` ，value = 上次触发时间
    private readonly Dictionary<string, DateTime> _recentFingerprints = new();
    // 白名单：这些 IP 永不产生告警（v3-T5）
    private readonly HashSet<string> _whitelist = new(StringComparer.OrdinalIgnoreCase);
    private const int DedupeTtlHours = 24;
    public event EventHandler<CameraAlert>? OnAlert;

    // v3-T2: 严重/高级别告警时由 Desktop 端注入的回调（用于弹系统托盘 + 邮件）
    public static Action<string, string, string>? SystemNotifySink; // (title, message, level)
    public static Func<CameraAlert, Task>? EmailNotifySink;          // 注入 EmailNotificationService 调用
    private static EmailConfig? _cachedEmailConfig;
    private static DateTime _emailConfigLoadedAt = DateTime.MinValue;

    public CameraAlertService()
    {
      Load();
    }

    public IReadOnlyList<CameraAlert> Alerts => _alerts;

    /// <summary>
    /// 注册白名单（被白名单命中的 IP 永不产生告警）。
    /// </summary>
    public void SetWhitelist(IEnumerable<string> ips)
    {
      _whitelist.Clear();
      if (ips == null) return;
      foreach (var ip in ips)
      {
        if (!string.IsNullOrWhiteSpace(ip)) _whitelist.Add(ip.Trim());
      }
    }

    /// <summary>
    /// 触发一条告警；24h 内同 IP + Type 的重复告警会被去重。
    /// 返回 true 表示已加入告警列表，false 表示被去重或白名单命中。
    /// </summary>
    public bool Raise(CameraAlert alert)
    {
      // v3-T5: 白名单直接跳过
      if (!string.IsNullOrEmpty(alert.Ip) && _whitelist.Contains(alert.Ip))
      {
        return false;
      }

      // v3-T1: 24h 内同 IP+Type+小时 指纹命中则去重
      var fingerprint = BuildFingerprint(alert);
      if (TryGetRecent(fingerprint, out var lastTime))
      {
        // 命中且未超过 24h -> 去重
        return false;
      }
      _recentFingerprints[fingerprint] = DateTime.Now;

      _alerts.Insert(0, alert);
      if (_alerts.Count > 500) _alerts.RemoveRange(500, _alerts.Count - 500);
      OnAlert?.Invoke(this, alert);
      Save();

      // v3-T2: 严重/高 级别 → 触发系统托盘 + 邮件
      if (alert.Level == "严重" || alert.Level == "高")
      {
        try { SystemNotifySink?.Invoke(alert.Title, alert.Message, alert.Level); }
        catch { /* 静默 */ }

        // 邮件异步发送，失败不影响主流程
        _ = DispatchEmailAsync(alert);
      }

      return true;
    }

    private static async Task DispatchEmailAsync(CameraAlert alert)
    {
      try
      {
        if (EmailNotifySink != null)
        {
          await EmailNotifySink(alert);
          return;
        }
        // 默认实现：从 email_config.json 读取 SMTP 配置
        var cfg = LoadEmailConfig();
        if (cfg == null || !cfg.IsValid()) return;
        var svc = new NetSecurityScanner.Services.EmailNotificationService(
            cfg.SmtpServer, cfg.SmtpPort, cfg.Username, cfg.Password, cfg.FromAddress);
        await svc.SendScanNotificationAsync(
            cfg.ToAddress,
            $"摄像头告警 - {alert.Ip}",
            1, // 占位
            alert.Level == "严重" ? 1 : 0);
      }
      catch (Exception ex)
      {
        System.Diagnostics.Debug.WriteLine($"[CameraAlertService] 邮件发送失败: {ex.Message}");
      }
    }

    private static EmailConfig? LoadEmailConfig()
    {
      // 5 分钟缓存
      if (_cachedEmailConfig != null && (DateTime.Now - _emailConfigLoadedAt).TotalMinutes < 5)
        return _cachedEmailConfig;

      try
      {
        var path = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "NetSecurityScanner", "data", "email_config.json");
        if (!File.Exists(path)) return null;
        var json = File.ReadAllText(path);
        _cachedEmailConfig = JsonSerializer.Deserialize<EmailConfig>(json);
        _emailConfigLoadedAt = DateTime.Now;
        return _cachedEmailConfig;
      }
      catch
      {
        return null;
      }
    }

    private static string BuildFingerprint(CameraAlert alert)
    {
      var ip = alert.Ip ?? string.Empty;
      var type = alert.Type.ToString();
      var hourKey = alert.CreatedTime.ToString("yyyyMMddHH");
      return $"{ip}:{type}:{hourKey}";
    }

    private bool TryGetRecent(string fingerprint, out DateTime lastTime)
    {
      // 先惰性清理过期项（> 24h）
      var now = DateTime.Now;
      var expired = _recentFingerprints
          .Where(kv => (now - kv.Value).TotalHours > DedupeTtlHours)
          .Select(kv => kv.Key)
          .ToList();
      foreach (var key in expired) _recentFingerprints.Remove(key);

      return _recentFingerprints.TryGetValue(fingerprint, out lastTime);
    }

    /// <summary>
    /// 检查扫描结果，触发状态变化告警
    /// </summary>
    public void CheckStatusChanges(List<CameraScanResult> results)
    {
      var seenIps = new HashSet<string>();
      foreach (var r in results)
      {
        // v3-T5: 白名单跳过
        if (_whitelist.Contains(r.Ip)) continue;

        seenIps.Add(r.Ip);
        var wasOnline = _lastStatus.TryGetValue(r.Ip, out var online) && online;
        var wasVuln = _lastVulnCount.TryGetValue(r.Ip, out var vc) ? vc : 0;

        if (!wasOnline && r.IsOnline)
        {
          Raise(new CameraAlert
          {
            Ip = r.Ip,
            Type = CameraAlertType.Online,
            Level = "低",
            Title = "摄像头已上线",
            Message = $"{r.Ip} ({r.Vendor} {r.Model}) 恢复在线"
          });
        }
        else if (wasOnline && !r.IsOnline)
        {
          Raise(new CameraAlert
          {
            Ip = r.Ip,
            Type = CameraAlertType.Offline,
            Level = "中",
            Title = "摄像头离线",
            Message = $"{r.Ip} 已离线，请检查"
          });
        }

        var newVuln = r.Vulnerabilities?.Count ?? 0;
        if (newVuln > wasVuln && wasVuln > 0)
        {
          Raise(new CameraAlert
          {
            Ip = r.Ip,
            Type = CameraAlertType.NewVulnerability,
            Level = "高",
            Title = "新增漏洞",
            Message = $"{r.Ip} 新增 {newVuln - wasVuln} 个漏洞"
          });
        }

        if (r.RiskAssessment?.RiskLevel == "严重")
        {
          Raise(new CameraAlert
          {
            Ip = r.Ip,
            Type = CameraAlertType.HighRiskDetected,
            Level = "严重",
            Title = "高风险摄像头",
            Message = $"{r.Ip} 风险评分 {r.RiskAssessment.TotalScore}"
          });
        }

        if (r.WeakPasswords?.Count > 0)
        {
          Raise(new CameraAlert
          {
            Ip = r.Ip,
            Type = CameraAlertType.NewWeakPassword,
            Level = "高",
            Title = "弱口令",
            Message = $"{r.Ip} 发现 {r.WeakPasswords.Count} 个弱口令"
          });
        }

        _lastStatus[r.Ip] = r.IsOnline;
        _lastVulnCount[r.Ip] = newVuln;
      }
    }

    public List<CameraAlert> GetRecent(int count = 50) => _alerts.Take(count).ToList();

    public void Acknowledge(string alertId)
    {
      var a = _alerts.FirstOrDefault(x => x.AlertId == alertId);
      if (a != null) { a.Acknowledged = true; Save(); }
    }

    public void Clear()
    {
      _alerts.Clear();
      _recentFingerprints.Clear();
      Save();
    }

    private void Save()
    {
      try
      {
        Directory.CreateDirectory(AlertDir);
        var file = Path.Combine(AlertDir, "alerts.json");
        var json = JsonSerializer.Serialize(_alerts, new JsonSerializerOptions { WriteIndented = true });
        File.WriteAllText(file, json);
      }
      catch { }
    }

    private void Load()
    {
      try
      {
        var file = Path.Combine(AlertDir, "alerts.json");
        if (!File.Exists(file)) return;
        var json = File.ReadAllText(file);
        var list = JsonSerializer.Deserialize<List<CameraAlert>>(json);
        if (list != null)
        {
          _alerts.Clear();
          _alerts.AddRange(list);
        }
      }
      catch { }
    }
  }

  /// <summary>
  /// 邮件通知配置（v3-T2）
  /// </summary>
  public class EmailConfig
  {
    public string SmtpServer { get; set; } = string.Empty;
    public int SmtpPort { get; set; } = 587;
    public string Username { get; set; } = string.Empty;
    public string Password { get; set; } = string.Empty;
    public string FromAddress { get; set; } = string.Empty;
    public string ToAddress { get; set; } = string.Empty;

    public bool IsValid() =>
        !string.IsNullOrWhiteSpace(SmtpServer) &&
        SmtpPort > 0 &&
        !string.IsNullOrWhiteSpace(Username) &&
        !string.IsNullOrWhiteSpace(Password) &&
        !string.IsNullOrWhiteSpace(FromAddress) &&
        !string.IsNullOrWhiteSpace(ToAddress);
  }
}
