using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using NetSecurityScanner.Models;
using NetSecurityScanner.Utils;

namespace NetSecurityScanner.Services
{
    /// <summary>
    /// 插件调度器（v6-T5）。
    /// 职责：
    ///   1. Cron 5/6 段表达式解析
    ///   2. 后台 Timer 每分钟唤醒 + 命中点执行
    ///   3. 失败指数退避重试（1/2/4/8/16s，最多 5 次）
    ///   4. 通知：系统托盘（Tray）/ 弹窗（Popup）/ 日志（Log）
    ///   5. 告警规则匹配 + 持久化到 data/scheduled_tasks.json + data/alert_rules.json
    /// </summary>
    public class PluginScheduler : IDisposable
    {
        private readonly Func<ScheduledTask, Task<bool>> _executor;
        private readonly PluginSecurityService _security;
        private readonly string _tasksFile;
        private readonly string _alertsFile;
        private readonly string _alertsLogDir;
        private readonly List<ScheduledTask> _tasks = new();
        private readonly List<AlertRule> _alertRules = new();
        private readonly object _taskLock = new();
        private readonly Timer _timer;
        private readonly CancellationTokenSource _cts = new();

        /// <summary>通知事件（UI 层订阅后可弹托盘/弹窗）</summary>
        public event EventHandler<(string Title, string Message, string Channel)>? OnNotify;

        public IReadOnlyList<ScheduledTask> Tasks
        {
            get { lock (_taskLock) { return _tasks.ToList(); } }
        }

        public IReadOnlyList<AlertRule> AlertRules
        {
            get { lock (_taskLock) { return _alertRules.ToList(); } }
        }

        public PluginScheduler(Func<ScheduledTask, CancellationToken, Task<bool>> executor, PluginSecurityService security)
        {
            _executor = async (t) => await executor(t, _cts.Token).ConfigureAwait(false);
            _security = security;
            _tasksFile = Path.Combine(DataPaths.AppDataDirectory, "scheduled_tasks.json");
            _alertsFile = Path.Combine(DataPaths.AppDataDirectory, "alert_rules.json");
            _alertsLogDir = Path.Combine(DataPaths.AppDataDirectory, "..", "logs", "alerts");
            Directory.CreateDirectory(_alertsLogDir);
            Directory.CreateDirectory(Path.GetDirectoryName(_tasksFile)!);

            LoadTasks();
            LoadAlertRules();
            _timer = new Timer(Tick, null, TimeSpan.FromSeconds(30), TimeSpan.FromMinutes(1));
        }

        public ScheduledTask AddTask(ScheduledTask task)
        {
            if (task == null) throw new ArgumentNullException(nameof(task));
            if (string.IsNullOrEmpty(task.Id)) task.Id = Guid.NewGuid().ToString("N");
            task.CreatedAt = DateTime.Now;
            lock (_taskLock) { _tasks.Add(task); }
            SaveTasks();
            return task;
        }

        public bool RemoveTask(string id)
        {
            lock (_taskLock)
            {
                var t = _tasks.FirstOrDefault(x => x.Id == id);
                if (t == null) return false;
                _tasks.Remove(t);
            }
            SaveTasks();
            return true;
        }

        public bool UpdateTask(ScheduledTask task)
        {
            lock (_taskLock)
            {
                var existing = _tasks.FirstOrDefault(x => x.Id == task.Id);
                if (existing == null) return false;
                var idx = _tasks.IndexOf(existing);
                _tasks[idx] = task;
            }
            SaveTasks();
            return true;
        }

        public AlertRule AddOrUpdateAlertRule(AlertRule rule)
        {
            if (rule == null) throw new ArgumentNullException(nameof(rule));
            lock (_taskLock)
            {
                var existing = _alertRules.FirstOrDefault(r => r.Id == rule.Id);
                if (existing != null)
                {
                    var idx = _alertRules.IndexOf(existing);
                    _alertRules[idx] = rule;
                }
                else
                {
                    _alertRules.Add(rule);
                }
            }
            SaveAlertRules();
            return rule;
        }

        public bool RemoveAlertRule(string id)
        {
            lock (_taskLock)
            {
                var r = _alertRules.FirstOrDefault(x => x.Id == id);
                if (r == null) return false;
                _alertRules.Remove(r);
            }
            SaveAlertRules();
            return true;
        }

        /// <summary>
        /// 立即执行某个任务（供测试或手动触发）。
        /// </summary>
        public async Task<bool> RunNowAsync(ScheduledTask task, CancellationToken ct = default)
        {
            return await RunWithRetryAsync(task, ct).ConfigureAwait(false);
        }

        private void Tick(object? state)
        {
            if (_cts.IsCancellationRequested) return;
            try
            {
                var now = DateTime.Now;
                List<ScheduledTask> due;
                lock (_taskLock)
                {
                    due = _tasks.Where(t => t.Enabled && IsCronMatch(t.CronExpression, now)).ToList();
                }
                foreach (var t in due)
                {
                    _ = Task.Run(() => RunWithRetryAsync(t, _cts.Token));
                }
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"[PluginScheduler] Tick 异常: {ex.Message}");
            }
        }

        private async Task<bool> RunWithRetryAsync(ScheduledTask task, CancellationToken ct)
        {
            int[] delays = { 1, 2, 4, 8, 16 };
            for (int attempt = 0; attempt <= task.MaxRetries; attempt++)
            {
                if (ct.IsCancellationRequested) return false;
                try
                {
                    task.LastRunAt = DateTime.Now;
                    task.TotalRuns++;
                    UpdateTask(task);

                    bool ok = await _executor(task).ConfigureAwait(false);
                    if (ok)
                    {
                        task.LastError = null;
                        UpdateTask(task);
                        return true;
                    }
                }
                catch (Exception ex)
                {
                    task.LastError = ex.Message;
                }

                task.TotalFailures++;
                UpdateTask(task);

                if (attempt < task.MaxRetries && attempt < delays.Length)
                {
                    try { await Task.Delay(TimeSpan.FromSeconds(delays[attempt]), ct).ConfigureAwait(false); }
                    catch (OperationCanceledException) { return false; }
                }
            }

            // 全部失败：触发告警
            if (task.TotalFailures > 0 && task.TotalFailures % task.MaxRetries == 0)
            {
                TriggerAlert($"ScheduledTask_{task.Id}", $"定时任务 {task.Name} 连续失败达到 {task.MaxRetries} 次: {task.LastError}");
            }
            return false;
        }

        /// <summary>
        /// 触发告警：根据 AlertRule 配置推送通知。
        /// </summary>
        public void TriggerAlert(string source, string message)
        {
            var rules = AlertRules.Where(r => r.Enabled).ToList();
            var channels = rules.SelectMany(r => r.NotificationChannels).Distinct().ToList();
            if (channels.Count == 0) channels.Add("Log");

            foreach (var ch in channels)
            {
                if (ch == "Log")
                {
                    AppendAlertLog(source, message);
                }
                OnNotify?.Invoke(this, ($"⚠ {source}", message, ch));
            }
        }

        private void AppendAlertLog(string source, string message)
        {
            try
            {
                var file = Path.Combine(_alertsLogDir, $"{DateTime.Now:yyyyMMdd}.log");
                var line = $"[{DateTime.Now:HH:mm:ss}] [{source}] {message}";
                File.AppendAllText(file, line + Environment.NewLine, Encoding.UTF8);
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"[PluginScheduler] 写告警日志失败: {ex.Message}");
            }
        }

        // ----- Cron 5/6 段解析（支持 * , - /） -----
        public static bool IsCronMatch(string cron, DateTime now)
        {
            if (string.IsNullOrWhiteSpace(cron)) return false;
            var parts = cron.Trim().Split(new[] { ' ' }, StringSplitOptions.RemoveEmptyEntries);
            if (parts.Length < 5 || parts.Length > 6) return false;
            try
            {
                bool min = MatchField(parts[0], now.Minute, 0, 59);
                bool hour = MatchField(parts[1], now.Hour, 0, 23);
                bool day = MatchField(parts[2], now.Day, 1, 31);
                bool mon = MatchField(parts[3], now.Month, 1, 12);
                bool dow = MatchField(parts[4], (int)now.DayOfWeek, 0, 6);
                return min && hour && day && mon && dow;
            }
            catch
            {
                return false;
            }
        }

        private static bool MatchField(string field, int value, int min, int max)
        {
            if (field == "*") return true;
            foreach (var part in field.Split(','))
            {
                var seg = part.Trim();
                int step = 1;
                var slashIdx = seg.IndexOf('/');
                string rangePart = seg;
                if (slashIdx >= 0)
                {
                    if (!int.TryParse(seg.Substring(slashIdx + 1), out step) || step <= 0) continue;
                    rangePart = seg.Substring(0, slashIdx);
                }
                if (rangePart == "*")
                {
                    if ((value - min) % step == 0) return true;
                    continue;
                }
                var dashIdx = rangePart.IndexOf('-');
                if (dashIdx >= 0)
                {
                    int s = int.Parse(rangePart.Substring(0, dashIdx));
                    int e = int.Parse(rangePart.Substring(dashIdx + 1));
                    if (value >= s && value <= e && (value - s) % step == 0) return true;
                }
                else
                {
                    if (int.TryParse(rangePart, out int v) && v == value) return true;
                }
            }
            return false;
        }

        private void LoadTasks()
        {
            try
            {
                if (File.Exists(_tasksFile))
                {
                    var json = File.ReadAllText(_tasksFile, Encoding.UTF8);
                    var list = JsonSerializer.Deserialize<List<ScheduledTask>>(json, new JsonSerializerOptions
                    {
                        PropertyNameCaseInsensitive = true
                    });
                    if (list != null)
                    {
                        lock (_taskLock) { _tasks.Clear(); _tasks.AddRange(list); }
                    }
                }
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"[PluginScheduler] LoadTasks 失败: {ex.Message}");
            }
        }

        private void SaveTasks()
        {
            try
            {
                List<ScheduledTask> snapshot;
                lock (_taskLock) { snapshot = _tasks.ToList(); }
                var json = JsonSerializer.Serialize(snapshot, new JsonSerializerOptions
                {
                    WriteIndented = true,
                    Encoder = System.Text.Encodings.Web.JavaScriptEncoder.UnsafeRelaxedJsonEscaping
                });
                var tmp = _tasksFile + ".tmp";
                File.WriteAllText(tmp, json, Encoding.UTF8);
                if (File.Exists(_tasksFile)) File.Replace(tmp, _tasksFile, null);
                else File.Move(tmp, _tasksFile);
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"[PluginScheduler] SaveTasks 失败: {ex.Message}");
            }
        }

        private void LoadAlertRules()
        {
            try
            {
                if (File.Exists(_alertsFile))
                {
                    var json = File.ReadAllText(_alertsFile, Encoding.UTF8);
                    var list = JsonSerializer.Deserialize<List<AlertRule>>(json, new JsonSerializerOptions
                    {
                        PropertyNameCaseInsensitive = true
                    });
                    if (list != null)
                    {
                        lock (_taskLock) { _alertRules.Clear(); _alertRules.AddRange(list); }
                    }
                }
                else
                {
                    // 默认规则
                    lock (_taskLock)
                    {
                        _alertRules.Add(new AlertRule
                        {
                            Name = "连续失败 3 次",
                            Type = AlertType.ConsecutiveFailure,
                            Threshold = 3,
                            TimeWindowMinutes = 5,
                            NotificationChannels = new List<string> { "Log", "Tray" }
                        });
                        _alertRules.Add(new AlertRule
                        {
                            Name = "健康度过低",
                            Type = AlertType.LowHealthScore,
                            Threshold = 60,
                            NotificationChannels = new List<string> { "Log" }
                        });
                    }
                    SaveAlertRules();
                }
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"[PluginScheduler] LoadAlertRules 失败: {ex.Message}");
            }
        }

        private void SaveAlertRules()
        {
            try
            {
                List<AlertRule> snapshot;
                lock (_taskLock) { snapshot = _alertRules.ToList(); }
                var json = JsonSerializer.Serialize(snapshot, new JsonSerializerOptions
                {
                    WriteIndented = true,
                    Encoder = System.Text.Encodings.Web.JavaScriptEncoder.UnsafeRelaxedJsonEscaping
                });
                var tmp = _alertsFile + ".tmp";
                File.WriteAllText(tmp, json, Encoding.UTF8);
                if (File.Exists(_alertsFile)) File.Replace(tmp, _alertsFile, null);
                else File.Move(tmp, _alertsFile);
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"[PluginScheduler] SaveAlertRules 失败: {ex.Message}");
            }
        }

        public void Dispose()
        {
            _cts.Cancel();
            _timer.Dispose();
            _cts.Dispose();
        }
    }
}
