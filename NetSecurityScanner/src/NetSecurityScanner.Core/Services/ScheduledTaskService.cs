using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using NetSecurityScanner.Data;
using NetSecurityScanner.Models;
using NetSecurityScanner.Core;
using NetSecurityScanner.Detection;

namespace NetSecurityScanner.Services
{
    public class ScheduledTaskService : IDisposable
    {
        private readonly Dictionary<int, ScheduledTaskInfo> _scheduledTasks;
        private readonly Dictionary<int, Timer> _taskTimers;
        private readonly Dictionary<int, List<TaskExecutionHistory>> _taskExecutionHistories;
        private readonly JSONDatabaseService _databaseService;
        private readonly PortScannerService _portScannerService;
        private readonly VulnerabilityDetectionService _vulnerabilityDetectionService;
        private readonly object _lockObject = new object();
        private int _taskIdCounter = 1;
        
        public event EventHandler<TaskExecutionCompletedEventArgs> TaskExecutionCompleted;
        public event EventHandler<TaskExecutionFailedEventArgs> TaskExecutionFailed;
        public event EventHandler<TaskStatusChangedEventArgs> TaskStatusChanged;
        
        public ScheduledTaskService(
            JSONDatabaseService databaseService,
            PortScannerService portScannerService,
            VulnerabilityDetectionService vulnerabilityDetectionService)
        {
            _scheduledTasks = new Dictionary<int, ScheduledTaskInfo>();
            _taskTimers = new Dictionary<int, Timer>();
            _taskExecutionHistories = new Dictionary<int, List<TaskExecutionHistory>>();
            _databaseService = databaseService;
            _portScannerService = portScannerService;
            _vulnerabilityDetectionService = vulnerabilityDetectionService;
        }
        
        /// <summary>
        /// 创建定时扫描任务
        /// </summary>
        public int ScheduleScanTask(
            string taskName,
            string targetHosts,
            string scanType,
            string options,
            DateTime startTime,
            string recurrencePattern = "Once",
            string priority = "Medium")
        {
            lock (_lockObject)
            {
                int taskId = _taskIdCounter++;
                
                var scheduledTask = new ScheduledTaskInfo
                {
                    TaskId = taskId,
                    TaskName = taskName,
                    TargetHosts = targetHosts,
                    ScanType = scanType,
                    Options = options,
                    StartTime = startTime,
                    RecurrencePattern = recurrencePattern,
                    Priority = priority,
                    Status = "Scheduled",
                    CreatedAt = DateTime.Now
                };
                
                _scheduledTasks.Add(taskId, scheduledTask);
                _taskExecutionHistories.Add(taskId, new List<TaskExecutionHistory>());
                
                // 计算首次执行的延迟时间
                var delayTime = startTime - DateTime.Now;
                if (delayTime.TotalMilliseconds > 0)
                {
                    var timer = new Timer(
                        async (state) => await ExecuteScheduledTaskAsync(taskId),
                        null,
                        delayTime,
                        Timeout.InfiniteTimeSpan);
                    
                    _taskTimers.Add(taskId, timer);
                }
                else
                {
                    // 如果开始时间已过，立即执行
                    Task.Run(() => ExecuteScheduledTaskAsync(taskId));
                }
                
                // 触发任务状态变更事件
                TaskStatusChanged?.Invoke(this, new TaskStatusChangedEventArgs(taskId, "Scheduled"));
                
                return taskId;
            }
        }
        
        /// <summary>
        /// 执行定时扫描任务 - 增强版本
        /// </summary>
        private async Task ExecuteScheduledTaskAsync(int taskId)
        {
            ScheduledTaskInfo task;
            lock (_lockObject)
            {
                if (!_scheduledTasks.TryGetValue(taskId, out task))
                    return;
                
                // 检查任务状态，如果是暂停状态则跳过执行
                if (task.Status == "Paused")
                    return;
                
                // 更新任务状态
                task.Status = "Running";
                task.LastExecutionTime = DateTime.Now;
                
                // 触发任务状态变更事件
                TaskStatusChanged?.Invoke(this, new TaskStatusChangedEventArgs(taskId, "Running"));
            }
            
            var executionStartTime = DateTime.Now;
            var executionHistory = new TaskExecutionHistory
            {
                TaskId = taskId,
                StartTime = executionStartTime,
                Status = "Running"
            };
            
            try
            {
                // 创建扫描任务
                var scanTask = new ScanTask
                {
                    TaskName = $"{task.TaskName} (定时执行)",
                    TargetHosts = task.TargetHosts,
                    ScanType = task.ScanType,
                    Status = "Running",
                    StartTime = DateTime.Now,
                    CreatedBy = "ScheduledTaskService",
                    Options = task.Options
                };
                
                // 根据扫描类型执行不同的扫描
                if (task.ScanType == "Port Scan")
                {
                    // 解析端口扫描选项
                    var options = Newtonsoft.Json.JsonConvert.DeserializeObject<dynamic>(task.Options);
                    string targetHost = task.TargetHosts;
                    string portRange = options.portRange;
                    string scanType = options.scanType;
                    
                    // 解析端口范围
                    var ports = ParsePortRange(portRange);
                    
                    if (ports.Count > 0)
                    {
                        // 创建扫描选项 - 200线程高并发
                        var scanOptions = new ScanOptions
                        {
                            MaxConcurrency = 200, // 200线程并发
                            Timeout = 2000,       // 2秒超时
                            RetryCount = 1,       // 1次重试
                            EnableServiceDetection = true,
                            EnableOsDetection = true,
                            ScanType = scanType
                        };
                        
                        // 执行端口扫描
                        var progress = new Progress<ScanProgressInfo>(info => {
                            // 这里可以添加进度报告逻辑
                            Console.WriteLine($"端口扫描进度: {info.Percentage}% - {info.CurrentPort}");
                        });
                        
                        var results = await _portScannerService.ScanPortsAsync(targetHost, ports, scanOptions, progress);
                        
                        // 保存扫描结果
                        scanTask.Status = "Completed";
                        scanTask.EndTime = DateTime.Now;
                        
                        if (_databaseService != null)
                        {
                            // 批量保存扫描结果
                            var scanResults = results.Where(r => r.Status == "开放").Select(result => new ScanResult
                            {
                                Host = targetHost,
                                Port = result.PortNumber,
                                Service = result.Service,
                                IsVulnerable = false,
                                ScanTime = DateTime.Now
                            }).ToList();
                            
                            // 使用优化的批量保存方法
                            _databaseService.AddScanTaskWithResults(scanTask, scanResults);
                        }
                        
                        executionHistory.Details = $"端口扫描完成，发现 {results.Where(r => r.Status == "开放").Count()} 个开放端口";
                    }
                }
                else if (task.ScanType == "Vulnerability Scan")
                {
                    // 解析漏洞扫描选项
                    var options = Newtonsoft.Json.JsonConvert.DeserializeObject<dynamic>(task.Options);
                    string targetHost = task.TargetHosts;
                    string scanDepth = options.scanDepth;
                    string scanPolicy = options.scanPolicy;
                    bool enablePoc = options.enablePoc;
                    bool enableCve = options.enableCve;
                    
                    // 创建目标信息
                    var targetInfo = new TargetInfo
                    {
                        Host = targetHost,
                        Services = new List<ServiceInfo>
                        {
                            new ServiceInfo { Name = "HTTP", Version = "2.4.49", Port = 80, Protocol = "TCP" },
                            new ServiceInfo { Name = "SSH", Version = "8.6p1", Port = 22, Protocol = "TCP" },
                            new ServiceInfo { Name = "MySQL", Version = "5.7.34", Port = 3306, Protocol = "TCP" },
                            new ServiceInfo { Name = "Nginx", Version = "1.20.0", Port = 8080, Protocol = "TCP" },
                            new ServiceInfo { Name = "Redis", Version = "6.0.0", Port = 6379, Protocol = "TCP" },
                            new ServiceInfo { Name = "PostgreSQL", Version = "13.0", Port = 5432, Protocol = "TCP" },
                            new ServiceInfo { Name = "MongoDB", Version = "4.4.0", Port = 27017, Protocol = "TCP" },
                            new ServiceInfo { Name = "FTP", Version = "1.0", Port = 21, Protocol = "TCP" }
                        }
                    };
                    
                    // 创建扫描选项
                    var vulnScanOptions = new VulnScanOptions
                    {
                        ScanDepth = scanDepth,
                        ScanPolicy = scanPolicy,
                        EnablePocVerification = enablePoc,
                        EnableCveMatching = enableCve,
                        ScanDelay = scanDepth == "深度" ? 150 : (scanDepth == "浅层" ? 30 : 80) // 减少延迟以提高速度
                    };
                    
                    // 执行漏洞扫描
                    var progress = new Progress<VulnScanProgressInfo>(info => {
                        // 这里可以添加进度报告逻辑
                        Console.WriteLine($"漏洞扫描进度: {info.Percentage}% - {info.CurrentService}");
                    });
                    
                    var vulnerabilities = await _vulnerabilityDetectionService.DetectVulnerabilitiesAsync(targetInfo, vulnScanOptions, progress);
                    
                    // 保存扫描结果
                    scanTask.Status = "Completed";
                    scanTask.EndTime = DateTime.Now;
                    
                    if (_databaseService != null)
                    {
                        _databaseService.AddScanTask(scanTask);
                        
                        // 批量保存漏洞信息和扫描结果
                        var scanResults = new List<ScanResult>();
                        foreach (var vuln in vulnerabilities)
                        {
                            _databaseService.AddVulnerability(vuln);
                            
                            var scanResult = new ScanResult
                            {
                                TaskId = scanTask.TaskId,
                                Host = targetHost,
                                Port = 0,
                                Service = vuln.Name,
                                IsVulnerable = true,
                                VulnerabilityId = vuln.VulnerabilityId,
                                ScanTime = DateTime.Now
                            };
                            
                            scanResults.Add(scanResult);
                        }
                        
                        // 批量添加扫描结果
                        if (scanResults.Count > 0)
                        {
                            _databaseService.AddScanResults(scanResults);
                        }
                    }
                    
                    executionHistory.Details = $"漏洞扫描完成，发现 {vulnerabilities.Count} 个漏洞";
                }
                
                var executionEndTime = DateTime.Now;
                executionHistory.EndTime = executionEndTime;
                executionHistory.Duration = executionEndTime - executionStartTime;
                executionHistory.Status = "Completed";
                
                lock (_lockObject)
                {
                    task.Status = "Completed";
                    task.LastExecutionTime = executionEndTime;
                    
                    // 记录执行历史
                    if (_taskExecutionHistories.ContainsKey(taskId))
                    {
                        _taskExecutionHistories[taskId].Add(executionHistory);
                        // 保留最近100条执行记录
                        if (_taskExecutionHistories[taskId].Count > 100)
                        {
                            _taskExecutionHistories[taskId] = _taskExecutionHistories[taskId].TakeLast(100).ToList();
                        }
                    }
                    
                    // 处理重复执行的任务
                    if (task.RecurrencePattern != "Once")
                    {
                        ScheduleNextExecution(task);
                    }
                    else
                    {
                        // 触发任务状态变更事件
                        TaskStatusChanged?.Invoke(this, new TaskStatusChangedEventArgs(taskId, "Completed"));
                    }
                }
                
                // 触发任务执行完成事件
                TaskExecutionCompleted?.Invoke(this, new TaskExecutionCompletedEventArgs(taskId, executionHistory));
            }
            catch (Exception ex)
            {
                var executionEndTime = DateTime.Now;
                executionHistory.EndTime = executionEndTime;
                executionHistory.Duration = executionEndTime - executionStartTime;
                executionHistory.Status = "Failed";
                executionHistory.ErrorMessage = ex.Message;
                
                lock (_lockObject)
                {
                    if (_scheduledTasks.TryGetValue(taskId, out var failedTask))
                    {
                        failedTask.Status = "Failed";
                        failedTask.LastError = ex.Message;
                        
                        // 记录执行历史
                        if (_taskExecutionHistories.ContainsKey(taskId))
                        {
                            _taskExecutionHistories[taskId].Add(executionHistory);
                            // 保留最近100条执行记录
                            if (_taskExecutionHistories[taskId].Count > 100)
                            {
                                _taskExecutionHistories[taskId] = _taskExecutionHistories[taskId].TakeLast(100).ToList();
                            }
                        }
                        
                        Console.WriteLine($"定时任务执行失败: {ex.Message}");
                        
                        // 触发任务状态变更事件
                        TaskStatusChanged?.Invoke(this, new TaskStatusChangedEventArgs(taskId, "Failed"));
                    }
                }
                
                // 触发任务执行失败事件
                TaskExecutionFailed?.Invoke(this, new TaskExecutionFailedEventArgs(taskId, ex.Message));
            }
        }
        
        /// <summary>
        /// 调度下一次执行
        /// </summary>
        private void ScheduleNextExecution(ScheduledTaskInfo task)
        {
            DateTime nextExecutionTime = task.StartTime;
            
            // 根据重复模式计算下一次执行时间
            switch (task.RecurrencePattern)
            {
                case "Daily":
                    nextExecutionTime = nextExecutionTime.AddDays(1);
                    break;
                case "Weekly":
                    nextExecutionTime = nextExecutionTime.AddDays(7);
                    break;
                case "Monthly":
                    nextExecutionTime = nextExecutionTime.AddMonths(1);
                    break;
                case "Hourly":
                    nextExecutionTime = nextExecutionTime.AddHours(1);
                    break;
                case "Minutely":
                    nextExecutionTime = nextExecutionTime.AddMinutes(1);
                    break;
                default:
                    return; // 未知的重复模式，不调度下一次执行
            }
            
            // 更新任务的开始时间
            task.StartTime = nextExecutionTime;
            task.Status = "Scheduled";
            
            // 触发任务状态变更事件
            TaskStatusChanged?.Invoke(this, new TaskStatusChangedEventArgs(task.TaskId, "Scheduled"));
            
            // 计算延迟时间
            var delayTime = nextExecutionTime - DateTime.Now;
            if (delayTime.TotalMilliseconds > 0)
            {
                // 取消现有的定时器
                if (_taskTimers.TryGetValue(task.TaskId, out var existingTimer))
                {
                    existingTimer.Dispose();
                    _taskTimers.Remove(task.TaskId);
                }
                
                // 创建新的定时器
                var timer = new Timer(
                    async (state) => await ExecuteScheduledTaskAsync(task.TaskId),
                    null,
                    delayTime,
                    Timeout.InfiniteTimeSpan);
                
                _taskTimers[task.TaskId] = timer;
            }
        }
        
        /// <summary>
        /// 暂停定时任务
        /// </summary>
        public bool PauseScheduledTask(int taskId)
        {
            lock (_lockObject)
            {
                if (_scheduledTasks.TryGetValue(taskId, out var task))
                {
                    if (task.Status == "Scheduled" || task.Status == "Running")
                    {
                        task.Status = "Paused";
                        
                        // 取消定时器
                        if (_taskTimers.TryGetValue(taskId, out var timer))
                        {
                            timer.Dispose();
                            _taskTimers.Remove(taskId);
                        }
                        
                        // 触发任务状态变更事件
                        TaskStatusChanged?.Invoke(this, new TaskStatusChangedEventArgs(taskId, "Paused"));
                        
                        return true;
                    }
                }
                
                return false;
            }
        }
        
        /// <summary>
        /// 恢复定时任务
        /// </summary>
        public bool ResumeScheduledTask(int taskId)
        {
            lock (_lockObject)
            {
                if (_scheduledTasks.TryGetValue(taskId, out var task))
                {
                    if (task.Status == "Paused")
                    {
                        task.Status = "Scheduled";
                        
                        // 计算延迟时间
                        var delayTime = task.StartTime - DateTime.Now;
                        if (delayTime.TotalMilliseconds > 0)
                        {
                            // 创建新的定时器
                            var timer = new Timer(
                                async (state) => await ExecuteScheduledTaskAsync(taskId),
                                null,
                                delayTime,
                                Timeout.InfiniteTimeSpan);
                            
                            _taskTimers[taskId] = timer;
                        }
                        else
                        {
                            // 如果开始时间已过，立即执行
                            Task.Run(() => ExecuteScheduledTaskAsync(taskId));
                        }
                        
                        // 触发任务状态变更事件
                        TaskStatusChanged?.Invoke(this, new TaskStatusChangedEventArgs(taskId, "Scheduled"));
                        
                        return true;
                    }
                }
                
                return false;
            }
        }
        
        /// <summary>
        /// 获取任务执行历史
        /// </summary>
        public List<TaskExecutionHistory> GetTaskExecutionHistory(int taskId)
        {
            lock (_lockObject)
            {
                if (_taskExecutionHistories.ContainsKey(taskId))
                {
                    return _taskExecutionHistories[taskId].OrderByDescending(h => h.StartTime).ToList();
                }
                return new List<TaskExecutionHistory>();
            }
        }
        
        /// <summary>
        /// 获取所有任务的执行历史
        /// </summary>
        public List<TaskExecutionHistory> GetAllTaskExecutionHistory()
        {
            lock (_lockObject)
            {
                return _taskExecutionHistories.Values.SelectMany(h => h).OrderByDescending(h => h.StartTime).Take(1000).ToList();
            }
        }
        
        /// <summary>
        /// 更新任务优先级
        /// </summary>
        public bool UpdateTaskPriority(int taskId, string priority)
        {
            lock (_lockObject)
            {
                if (_scheduledTasks.TryGetValue(taskId, out var task))
                {
                    task.Priority = priority;
                    return true;
                }
                return false;
            }
        }
        
        /// <summary>
        /// 获取按优先级排序的任务列表
        /// </summary>
        public List<ScheduledTaskInfo> GetTasksByPriority()
        {
            lock (_lockObject)
            {
                var priorityOrder = new Dictionary<string, int> { { "High", 1 }, { "Medium", 2 }, { "Low", 3 } };
                
                return _scheduledTasks.Values
                    .OrderBy(task => priorityOrder.TryGetValue(task.Priority, out int priority) ? priority : 4)
                    .ThenBy(task => task.CreatedAt)
                    .ToList();
            }
        }
        
        /// <summary>
        /// 取消定时任务
        /// </summary>
        public bool CancelScheduledTask(int taskId)
        {
            lock (_lockObject)
            {
                if (_scheduledTasks.TryGetValue(taskId, out var task))
                {
                    task.Status = "Cancelled";
                    
                    // 取消定时器
                    if (_taskTimers.TryGetValue(taskId, out var timer))
                    {
                        timer.Dispose();
                        _taskTimers.Remove(taskId);
                    }
                    
                    return true;
                }
                
                return false;
            }
        }
        
        /// <summary>
        /// 获取所有定时任务
        /// </summary>
        public List<ScheduledTaskInfo> GetAllScheduledTasks()
        {
            lock (_lockObject)
            {
                return new List<ScheduledTaskInfo>(_scheduledTasks.Values);
            }
        }
        
        /// <summary>
        /// 获取指定状态的定时任务
        /// </summary>
        public List<ScheduledTaskInfo> GetScheduledTasksByStatus(string status)
        {
            lock (_lockObject)
            {
                return _scheduledTasks.Values
                    .Where(task => task.Status == status)
                    .ToList();
            }
        }
        
        /// <summary>
        /// 解析端口范围
        /// </summary>
        private List<int> ParsePortRange(string portRange)
        {
            var ports = new List<int>();
            
            try
            {
                if (portRange.Contains("-"))
                {
                    // 范围格式: 1-1000
                    var parts = portRange.Split('-');
                    if (parts.Length == 2)
                    {
                        var start = int.Parse(parts[0]);
                        var end = int.Parse(parts[1]);
                        
                        for (int port = start; port <= end; port++)
                        {
                            ports.Add(port);
                        }
                    }
                }
                else if (portRange.Contains(","))
                {
                    // 列表格式: 80,443,3306
                    var portList = portRange.Split(',');
                    foreach (var portStr in portList)
                    {
                        if (int.TryParse(portStr, out int port))
                        {
                            ports.Add(port);
                        }
                    }
                }
                else
                {
                    // 单个端口
                    if (int.TryParse(portRange, out int port))
                    {
                        ports.Add(port);
                    }
                }
            }
            catch (Exception)
            {
                // 解析失败
            }
            
            return ports;
        }
        
        /// <summary>
        /// 释放资源
        /// </summary>
        public void Dispose()
        {
            lock (_lockObject)
            {
                foreach (var timer in _taskTimers.Values)
                {
                    timer.Dispose();
                }
                
                _taskTimers.Clear();
                _scheduledTasks.Clear();
            }
        }
    }
    
    public class ScheduledTaskInfo
    {
        public int TaskId { get; set; }
        public string TaskName { get; set; }
        public string TargetHosts { get; set; }
        public string ScanType { get; set; }
        public string Options { get; set; }
        public DateTime StartTime { get; set; }
        public string RecurrencePattern { get; set; } // Once, Daily, Weekly, Monthly, Hourly, Minutely
        public string Status { get; set; } // Scheduled, Running, Completed, Failed, Cancelled, Paused
        public string Priority { get; set; } = "Medium"; // High, Medium, Low
        public DateTime CreatedAt { get; set; }
        public DateTime? LastExecutionTime { get; set; }
        public string LastError { get; set; }
        
        public string NextExecution => RecurrencePattern == "Once" && Status == "Completed"
            ? "N/A"
            : Status == "Scheduled" ? StartTime.ToString("yyyy-MM-dd HH:mm:ss") : "Pending";
    }
    
    /// <summary>
    /// 任务执行历史记录
    /// </summary>
    public class TaskExecutionHistory
    {
        public int TaskId { get; set; }
        public DateTime StartTime { get; set; }
        public DateTime? EndTime { get; set; }
        public TimeSpan? Duration { get; set; }
        public string Status { get; set; }
        public string Details { get; set; }
        public string ErrorMessage { get; set; }
        
        public string DurationText => Duration.HasValue ? Duration.Value.ToString(@"hh\:mm\:ss") : "N/A";
    }
    
    /// <summary>
    /// 任务执行完成事件参数
    /// </summary>
    public class TaskExecutionCompletedEventArgs : EventArgs
    {
        public int TaskId { get; }
        public TaskExecutionHistory ExecutionHistory { get; }
        
        public TaskExecutionCompletedEventArgs(int taskId, TaskExecutionHistory executionHistory)
        {
            TaskId = taskId;
            ExecutionHistory = executionHistory;
        }
    }
    
    /// <summary>
    /// 任务执行失败事件参数
    /// </summary>
    public class TaskExecutionFailedEventArgs : EventArgs
    {
        public int TaskId { get; }
        public string ErrorMessage { get; }
        
        public TaskExecutionFailedEventArgs(int taskId, string errorMessage)
        {
            TaskId = taskId;
            ErrorMessage = errorMessage;
        }
    }
    
    /// <summary>
    /// 任务状态变更事件参数
    /// </summary>
    public class TaskStatusChangedEventArgs : EventArgs
    {
        public int TaskId { get; }
        public string NewStatus { get; }
        
        public TaskStatusChangedEventArgs(int taskId, string newStatus)
        {
            TaskId = taskId;
            NewStatus = newStatus;
        }
    }
}