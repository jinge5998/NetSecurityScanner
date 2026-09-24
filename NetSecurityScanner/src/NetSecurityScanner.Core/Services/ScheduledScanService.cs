using NetSecurityScanner.Models;
using NetSecurityScanner.Utils;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using System.Timers;

namespace NetSecurityScanner.Services
{
    public class ScheduledScanService : IDisposable
    {
        private readonly string _configFilePath;
        private readonly List<ScheduledScan> _scheduledScans;
        private readonly System.Timers.Timer _schedulerTimer;
        private readonly BatchScanManager _batchScanManager;
        private readonly ScanHistoryService _historyService;
        private readonly EmailNotificationService _emailService;

        public event EventHandler<ScheduledScanEventArgs> ScanStarted;
        public event EventHandler<ScheduledScanEventArgs> ScanCompleted;
        public event EventHandler<ScheduledScanEventArgs> ScanFailed;

        public ScheduledScanService()
        {
            _configFilePath = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
                "NetSecurityScanner",
                "scheduled_scans.json"
            );

            _scheduledScans = LoadScheduledScans();
            _batchScanManager = new BatchScanManager();
            _historyService = new ScanHistoryService();
            _emailService = null; // 可选服务，稍后可通过依赖注入设置

            // 每分钟检查一次定时任务
            _schedulerTimer = new System.Timers.Timer(60000);
            _schedulerTimer.Elapsed += SchedulerTimer_Elapsed;
            _schedulerTimer.AutoReset = true;
        }

        public void Start()
        {
            _schedulerTimer.Start();
        }

        public void Stop()
        {
            _schedulerTimer.Stop();
        }

        private async void SchedulerTimer_Elapsed(object? sender, ElapsedEventArgs e)
        {
            var now = DateTime.Now;

            foreach (var scan in _scheduledScans.Where(s => s.IsEnabled))
            {
                if (ShouldExecuteScan(scan, now))
                {
                    await ExecuteScheduledScanAsync(scan);
                }
            }
        }

        private bool ShouldExecuteScan(ScheduledScan scan, DateTime now)
        {
            // 检查是否到了执行时间
            if (!TimeSpan.TryParse(scan.ScheduleTime, out var scheduledTime))
                return false;

            var currentTime = now.TimeOfDay;
            var timeDiff = Math.Abs((currentTime - scheduledTime).TotalMinutes);

            // 如果在1分钟窗口期内，且今天还没执行过
            if (timeDiff <= 1)
            {
                if (scan.LastRunTime.HasValue && scan.LastRunTime.Value.Date == now.Date)
                    return false;

                return scan.ScheduleType switch
                {
                    "Daily" => true,
                    "Weekly" => scan.LastRunTime == null || (now - scan.LastRunTime.Value).TotalDays >= 7,
                    "Monthly" => scan.LastRunTime == null || now.Day == 1,
                    _ => false
                };
            }

            return false;
        }

        private async Task ExecuteScheduledScanAsync(ScheduledScan scan)
        {
            try
            {
                scan.LastRunTime = DateTime.Now;
                scan.RunCount++;
                SaveScheduledScans();

                ScanStarted?.Invoke(this, new ScheduledScanEventArgs { Scan = scan });

                // 解析目标
                var targets = ParseTargets(scan.TargetValue, scan.TargetType);
                if (!targets.Any())
                {
                    ScanFailed?.Invoke(this, new ScheduledScanEventArgs { Scan = scan, Error = "没有有效的扫描目标" });
                    return;
                }

                // 创建扫描配置
                var config = CreateScanConfiguration(scan.ScanMode);

                // 执行批量扫描
                var cts = new CancellationTokenSource();
                var result = await _batchScanManager.ScanBatchAsync(targets, config, cts.Token);

                // 发送邮件通知
                if (scan.EnableEmailNotification && !string.IsNullOrEmpty(scan.NotificationEmail))
                {
                    await SendNotificationEmailAsync(scan, result);
                }

                ScanCompleted?.Invoke(this, new ScheduledScanEventArgs
                {
                    Scan = scan,
                    Result = result,
                    Duration = result.Duration
                });
            }
            catch (Exception ex)
            {
                ScanFailed?.Invoke(this, new ScheduledScanEventArgs { Scan = scan, Error = ex.Message });
            }
        }

        private List<string> ParseTargets(string targetValue, string targetType)
        {
            return targetType switch
            {
                "Single" => new List<string> { targetValue },
                "Range" => TargetParser.ParseTargets(targetValue, TargetType.Range),
                "CIDR" => TargetParser.ParseTargets(targetValue, TargetType.CIDR),
                "File" => TargetParser.ParseTargets(targetValue, TargetType.ListFile),
                _ => new List<string> { targetValue }
            };
        }

        private ScanConfiguration CreateScanConfiguration(string scanMode)
        {
            return scanMode switch
            {
                "Lightning" => ScanConfiguration.LightningConfig,
                "Standard" => ScanConfiguration.StandardConfig,
                "Deep" => ScanConfiguration.DeepConfig,
                _ => ScanConfiguration.StandardConfig
            };
        }

        private async Task SendNotificationEmailAsync(ScheduledScan scan, BatchScanResult result)
        {
            try
            {
                if (_emailService == null) return;

                var criticalCount = result.CriticalCount;
                var totalVulns = result.TotalVulnerabilities;

                await _emailService.SendScanNotificationAsync(
                    scan.NotificationEmail,
                    scan.Name,
                    totalVulns,
                    criticalCount
                );
            }
            catch (Exception ex)
            {
                // 邮件发送失败不中断扫描流程
                System.Diagnostics.Debug.WriteLine($"邮件发送失败: {ex.Message}");
            }
        }

        public List<ScheduledScan> GetAllScheduledScans()
        {
            return _scheduledScans.ToList();
        }

        public void AddScheduledScan(ScheduledScan scan)
        {
            _scheduledScans.Add(scan);
            SaveScheduledScans();
        }

        public void UpdateScheduledScan(ScheduledScan scan)
        {
            var existing = _scheduledScans.FirstOrDefault(s => s.Id == scan.Id);
            if (existing != null)
            {
                var index = _scheduledScans.IndexOf(existing);
                _scheduledScans[index] = scan;
                SaveScheduledScans();
            }
        }

        public void DeleteScheduledScan(string id)
        {
            var scan = _scheduledScans.FirstOrDefault(s => s.Id == id);
            if (scan != null)
            {
                _scheduledScans.Remove(scan);
                SaveScheduledScans();
            }
        }

        public void ToggleScheduledScan(string id, bool isEnabled)
        {
            var scan = _scheduledScans.FirstOrDefault(s => s.Id == id);
            if (scan != null)
            {
                scan.IsEnabled = isEnabled;
                SaveScheduledScans();
            }
        }

        private List<ScheduledScan> LoadScheduledScans()
        {
            try
            {
                if (File.Exists(_configFilePath))
                {
                    var json = File.ReadAllText(_configFilePath);
                    return JsonSerializer.Deserialize<List<ScheduledScan>>(json) ?? new List<ScheduledScan>();
                }
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"加载定时扫描配置失败: {ex.Message}");
            }

            return new List<ScheduledScan>();
        }

        private void SaveScheduledScans()
        {
            try
            {
                var directory = Path.GetDirectoryName(_configFilePath);
                if (!Directory.Exists(directory))
                {
                    Directory.CreateDirectory(directory);
                }

                var json = JsonSerializer.Serialize(_scheduledScans, new JsonSerializerOptions
                {
                    WriteIndented = true
                });

                File.WriteAllText(_configFilePath, json);
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"保存定时扫描配置失败: {ex.Message}");
            }
        }

        public void ConfigureEmail(string smtpServer, int smtpPort, string username, string password, string fromAddress)
        {
            // 这里可以添加邮件配置持久化
        }

        public void Dispose()
        {
            _schedulerTimer?.Stop();
            _schedulerTimer?.Dispose();
        }
    }

    public class ScheduledScanEventArgs : EventArgs
    {
        public ScheduledScan Scan { get; set; }
        public BatchScanResult Result { get; set; }
        public TimeSpan Duration { get; set; }
        public string Error { get; set; }
    }
}