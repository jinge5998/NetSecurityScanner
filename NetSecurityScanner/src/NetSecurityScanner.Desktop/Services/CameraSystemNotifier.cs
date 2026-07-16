using System;
using System.Drawing;
using System.IO;
using System.Reflection;
using System.Windows.Forms;
using NetSecurityScanner.Core;

namespace NetSecurityScanner.Services
{
  /// <summary>
  /// 摄像头告警系统托盘通知器（v3-T2）。
  /// 封装 <see cref="NotifyIcon"/> 弹出气泡，并通过 <see cref="CameraAlertService.SystemNotifySink"/>
  /// 接入告警服务。
  /// 注意：本类需要 <c>UseWindowsForms=true</c>，目前仅在 Desktop 项目启用。
  /// </summary>
  public sealed class CameraSystemNotifier : IDisposable
  {
    private static CameraSystemNotifier? _instance;
    private static readonly object _lock = new();
    private NotifyIcon? _notifyIcon;
    private bool _initialized;
    private bool _disposed;

    public static CameraSystemNotifier Instance
    {
      get
      {
        if (_instance == null)
        {
          lock (_lock)
          {
            _instance ??= new CameraSystemNotifier();
          }
        }
        return _instance;
      }
    }

    private CameraSystemNotifier()
    {
      try
      {
        _notifyIcon = new NotifyIcon
        {
          Icon = LoadAppIcon(),
          Visible = true,
          Text = "NetSecurityScanner 摄像头告警"
        };
        _notifyIcon.BalloonTipClosed += (s, e) => { /* 静默 */ };
        _initialized = true;
      }
      catch (Exception ex)
      {
        System.Diagnostics.Debug.WriteLine($"[CameraSystemNotifier] 初始化失败: {ex.Message}");
        _initialized = false;
      }

      // 接入告警服务
      CameraAlertService.SystemNotifySink = ShowBalloon;
    }

    /// <summary>
    /// 弹出气泡通知。
    /// </summary>
    public void ShowBalloon(string title, string message, string level)
    {
      if (!_initialized || _notifyIcon == null) return;
      try
      {
        var icon = level switch
        {
          "严重" => ToolTipIcon.Error,
          "高" => ToolTipIcon.Warning,
          _ => ToolTipIcon.Info
        };
        _notifyIcon.BalloonTipIcon = icon;
        _notifyIcon.BalloonTipTitle = $"[{level}] {title}";
        _notifyIcon.BalloonTipText = Truncate(message, 250);
        _notifyIcon.ShowBalloonTip(5000);
      }
      catch (Exception ex)
      {
        System.Diagnostics.Debug.WriteLine($"[CameraSystemNotifier] 弹气泡失败: {ex.Message}");
      }
    }

    private static Icon LoadAppIcon()
    {
      try
      {
        var exePath = Assembly.GetEntryAssembly()?.Location;
        if (!string.IsNullOrEmpty(exePath) && File.Exists(exePath))
        {
          var icon = Icon.ExtractAssociatedIcon(exePath);
          if (icon != null) return icon;
        }
      }
      catch { }
      return SystemIcons.Information;
    }

    private static string Truncate(string s, int max) =>
        string.IsNullOrEmpty(s) ? string.Empty :
        s.Length <= max ? s : s.Substring(0, max) + "...";

    public void Dispose()
    {
      if (_disposed) return;
      _disposed = true;
      try
      {
        if (_notifyIcon != null)
        {
          _notifyIcon.Visible = false;
          _notifyIcon.Dispose();
          _notifyIcon = null;
        }
        CameraAlertService.SystemNotifySink = null;
      }
      catch { }
    }
  }
}
