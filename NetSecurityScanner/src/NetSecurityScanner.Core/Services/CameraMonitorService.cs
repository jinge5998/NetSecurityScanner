using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Media;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using NetSecurityScanner.Models;

namespace NetSecurityScanner.Core
{
  /// <summary>
  /// 摄像头持续监控服务（v2 + v3）
  /// v3-T2: SoundAlert 触发时播放 SystemSounds.Hand
  /// v3-T3: 支持 Cron 表达式 + 失败指数退避
  /// </summary>
  public class CameraMonitorService : IDisposable
  {
    private readonly List<CameraMonitorTask> _tasks = new();
    private readonly List<CameraMonitorTask> _activeTasks = new();
    private CancellationTokenSource? _cts;
    private readonly CameraScanSessionService _sessionService = new();
    private readonly CameraAlertService _alertService = new();
    // v3-T3: 任务连续失败计数（TaskId -> 次数）
    private readonly Dictionary<string, int> _failureCount = new();
    // 退避时间表（连续失败 1/2/3/4 次后下次运行延后 1/2/4/8 分钟）
    private static readonly int[] BackoffMinutes = { 1, 2, 4, 8 };
    private const int AutoDisableThreshold = 5;
    private readonly string TaskFile = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
        "NetSecurityScanner", "data", "camera_monitor_tasks.json");

    public event EventHandler<CameraScanResult>? OnStatusChanged;
    public event EventHandler<CameraAlert>? OnAlert;

    public IReadOnlyList<CameraMonitorTask> Tasks => _tasks;

    public CameraMonitorService()
    {
      LoadTasks();
      // v3-T2: 订阅告警服务以支持 SoundAlert
      _alertService.OnAlert += AlertService_OnAlert;
    }

    private void AlertService_OnAlert(object? sender, CameraAlert e)
    {
      // 任何启用且 SoundAlert=true 的任务都触发系统声音
      try
      {
        if (_tasks.Any(t => t.Enabled && t.SoundAlert))
        {
          SystemSounds.Hand.Play();
        }
      }
      catch { /* 静默 */ }

      // 透传告警事件
      OnAlert?.Invoke(this, e);
    }

    public void AddTask(CameraMonitorTask task)
    {
      _tasks.Add(task);
      SaveTasks();
    }

    public void RemoveTask(string taskId)
    {
      _tasks.RemoveAll(t => t.TaskId == taskId);
      _failureCount.Remove(taskId);
      SaveTasks();
    }

    public void Start()
    {
      _cts = new CancellationTokenSource();
      _ = Task.Run(() => RunMonitorLoopAsync(_cts.Token));
    }

    public void Stop()
    {
      _cts?.Cancel();
      _cts?.Dispose();
      _cts = null;
    }

    private async Task RunMonitorLoopAsync(CancellationToken ct)
    {
      while (!ct.IsCancellationRequested)
      {
        foreach (var task in _tasks.Where(t => t.Enabled))
        {
          if (ct.IsCancellationRequested) break;
          if (!ShouldRunNow(task)) continue;

          try
          {
            var session = new CameraScanSession
            {
              SessionName = $"监控 - {task.Name}",
              MonitoringMode = "持续监控",
              Preset = task.Preset,
              TemplateId = task.TemplateId,
              TargetIps = new List<string>(task.TargetIps)
            };
            session.Results = await ExecuteScanAsync(task, ct);
            task.LastRunTime = DateTime.Now;
            task.NextRunTime = ComputeNextRunTime(task);

            // 成功：清除失败计数
            _failureCount[task.TaskId] = 0;
            task.ConsecutiveFailures = 0;

            // 触发告警状态检测（产生 CameraAlert 并播放声音）
            _alertService.CheckStatusChanges(session.Results);

            // 检测状态变化
            foreach (var r in session.Results)
            {
              OnStatusChanged?.Invoke(this, r);
            }

            SaveTasks();
          }
          catch (OperationCanceledException) { break; }
          catch (Exception ex)
          {
            // v3-T3: 失败计数 + 指数退避
            var current = _failureCount.GetValueOrDefault(task.TaskId, 0) + 1;
            _failureCount[task.TaskId] = current;
            task.ConsecutiveFailures = current;

            if (current >= AutoDisableThreshold)
            {
              task.Enabled = false;
              _alertService.Raise(new CameraAlert
              {
                Ip = string.Join(",", task.TargetIps),
                Type = CameraAlertType.TaskAutoDisabled,
                Level = "严重",
                Title = $"监控任务自动禁用: {task.Name}",
                Message = $"任务 {task.Name} 连续失败 {current} 次，已自动禁用。错误: {ex.Message}",
                RelatedTaskId = task.TaskId
              });
            }
            else
            {
              // 按 BackoffMinutes 表设置下次运行时间
              var idx = Math.Min(current - 1, BackoffMinutes.Length - 1);
              task.NextRunTime = DateTime.Now.AddMinutes(BackoffMinutes[idx]);
            }
            SaveTasks();
          }
        }
        try { await Task.Delay(TimeSpan.FromMinutes(1), ct); } catch { break; }
      }
    }

    /// <summary>
    /// v3-T3: 判断任务是否到了运行时间。
    /// </summary>
    private bool ShouldRunNow(CameraMonitorTask task)
    {
      if (task.LastRunTime == null) return true; // 首次运行

      if (task.ScheduleType == ScheduleType.Cron)
      {
        if (string.IsNullOrWhiteSpace(task.CronExpression)) return false;
        var next = CronExpression.NextOccurrence(task.CronExpression, task.LastRunTime.Value);
        if (next == null) return false;
        task.NextRunTime = next;
        return DateTime.Now >= next.Value;
      }

      // Interval
      if (task.NextRunTime == null)
      {
        task.NextRunTime = task.LastRunTime.Value.AddMinutes(Math.Max(1, task.IntervalMinutes));
      }
      return DateTime.Now >= task.NextRunTime.Value;
    }

    private DateTime ComputeNextRunTime(CameraMonitorTask task)
    {
      if (task.ScheduleType == ScheduleType.Cron && !string.IsNullOrWhiteSpace(task.CronExpression))
      {
        var next = CronExpression.NextOccurrence(task.CronExpression, task.LastRunTime ?? DateTime.Now);
        if (next != null) return next.Value;
      }
      return DateTime.Now.AddMinutes(Math.Max(1, task.IntervalMinutes));
    }

    private async Task<List<CameraScanResult>> ExecuteScanAsync(CameraMonitorTask task, CancellationToken ct)
    {
      try
      {
        using var service = new CameraScannerService();
        var options = new CameraScanOptions
        {
          EnableFingerprint = true,
          EnableVulnerabilityScan = true,
          MaxConcurrency = 20,
          TimeoutMs = task.MonitorPorts.Count > 0 ? 3000 : 2000,
          CustomPorts = task.MonitorPorts
        };
        return await service.ScanCamerasAsync(options, null, ct);
      }
      catch
      {
        return new List<CameraScanResult>();
      }
    }

    private void SaveTasks()
    {
      try
      {
        var dir = Path.GetDirectoryName(TaskFile);
        if (dir != null) Directory.CreateDirectory(dir);
        var json = JsonSerializer.Serialize(_tasks, new JsonSerializerOptions { WriteIndented = true });
        File.WriteAllText(TaskFile, json);
      }
      catch { }
    }

    private void LoadTasks()
    {
      try
      {
        if (!File.Exists(TaskFile)) return;
        var json = File.ReadAllText(TaskFile);
        var list = JsonSerializer.Deserialize<List<CameraMonitorTask>>(json);
        if (list != null)
        {
          _tasks.Clear();
          _tasks.AddRange(list);
        }
      }
      catch { }
    }

    public void Dispose()
    {
      try { _alertService.OnAlert -= AlertService_OnAlert; } catch { }
      Stop();
    }
  }
}
