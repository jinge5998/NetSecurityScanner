using System;
using System.IO;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Collections.Generic;
using System.Diagnostics;

namespace NetSecurityScanner.Services
{
    /// <summary>
    /// 日志记录服务 - 增强版本
    /// 功能：
    /// 1. 多级别日志记录
    /// 2. 日志文件轮转
    /// 3. 错误追踪和异常捕获
    /// 4. 性能监控
    /// 5. 异步日志写入
    /// </summary>
    public class LoggingService : IDisposable
    {
        private readonly string _logDirectory;
        private readonly string _errorLogPath;
        private readonly string _infoLogPath;
        private readonly string _debugLogPath;
        private readonly string _perfLogPath;
        private readonly object _fileLock = new object();
        private readonly Queue<LogEntry> _logQueue;
        private readonly CancellationTokenSource _cancellationTokenSource;
        private readonly Task _loggingTask;
        private readonly int _maxQueueSize = 10000;
        private readonly int _maxLogFileSize = 1024 * 1024 * 5; // 5MB
        private readonly int _maxLogFiles = 5;
        private bool _isDisposed = false;
        
        public event EventHandler<LogEventArgs> LogWritten;
        public event EventHandler<ErrorLoggedEventArgs> ErrorLogged;
        public event EventHandler<PerformanceLoggedEventArgs> PerformanceLogged;
        
        public int LogQueueCount => _logQueue.Count;
        public int ErrorCount { get; private set; } = 0;
        public int WarningCount { get; private set; } = 0;
        public int InfoCount { get; private set; } = 0;
        public int DebugCount { get; private set; } = 0;
        
        public LoggingService()
        {
            // 初始化日志目录
            _logDirectory = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "NetSecurityScanner", "Logs");
            Directory.CreateDirectory(_logDirectory);
            
            // 初始化日志文件路径
            _errorLogPath = Path.Combine(_logDirectory, "error.log");
            _infoLogPath = Path.Combine(_logDirectory, "info.log");
            _debugLogPath = Path.Combine(_logDirectory, "debug.log");
            _perfLogPath = Path.Combine(_logDirectory, "performance.log");
            
            // 初始化日志队列
            _logQueue = new Queue<LogEntry>();
            _cancellationTokenSource = new CancellationTokenSource();
            
            // 启动异步日志写入任务
            _loggingTask = Task.Run(() => ProcessLogQueueAsync(_cancellationTokenSource.Token), _cancellationTokenSource.Token);
        }
        
        /// <summary>
        /// 记录错误日志
        /// </summary>
        public void Error(string message, Exception ex = null)
        {
            var logEntry = new LogEntry
            {
                Level = LogLevel.Error,
                Message = message,
                Exception = ex,
                Timestamp = DateTime.Now,
                Source = GetCallerName()
            };
            
            EnqueueLog(logEntry);
            ErrorCount++;
            
            // 触发错误记录事件
            ErrorLogged?.Invoke(this, new ErrorLoggedEventArgs(message, ex));
        }
        
        /// <summary>
        /// 记录警告日志
        /// </summary>
        public void Warning(string message)
        {
            var logEntry = new LogEntry
            {
                Level = LogLevel.Warning,
                Message = message,
                Timestamp = DateTime.Now,
                Source = GetCallerName()
            };
            
            EnqueueLog(logEntry);
            WarningCount++;
        }
        
        /// <summary>
        /// 记录信息日志
        /// </summary>
        public void Info(string message)
        {
            var logEntry = new LogEntry
            {
                Level = LogLevel.Info,
                Message = message,
                Timestamp = DateTime.Now,
                Source = GetCallerName()
            };
            
            EnqueueLog(logEntry);
            InfoCount++;
        }
        
        /// <summary>
        /// 记录调试日志
        /// </summary>
        public void Debug(string message)
        {
            var logEntry = new LogEntry
            {
                Level = LogLevel.Debug,
                Message = message,
                Timestamp = DateTime.Now,
                Source = GetCallerName()
            };
            
            EnqueueLog(logEntry);
            DebugCount++;
        }
        
        /// <summary>
        /// 记录性能日志
        /// </summary>
        public void Performance(string operation, long milliseconds, string details = "")
        {
            var logEntry = new LogEntry
            {
                Level = LogLevel.Performance,
                Message = $"Operation: {operation}, Duration: {milliseconds}ms",
                Timestamp = DateTime.Now,
                Source = GetCallerName(),
                Details = details
            };
            
            EnqueueLog(logEntry);
            
            // 触发性能记录事件
            PerformanceLogged?.Invoke(this, new PerformanceLoggedEventArgs(operation, milliseconds, details));
        }
        
        /// <summary>
        /// 执行带性能监控的操作
        /// </summary>
        public T ExecuteWithPerformanceLogging<T>(string operationName, Func<T> action, string details = "")
        {
            var stopwatch = Stopwatch.StartNew();
            try
            {
                return action();
            }
            finally
            {
                stopwatch.Stop();
                Performance(operationName, stopwatch.ElapsedMilliseconds, details);
            }
        }
        
        /// <summary>
        /// 异步执行带性能监控的操作
        /// </summary>
        public async Task<T> ExecuteWithPerformanceLoggingAsync<T>(string operationName, Func<Task<T>> action, string details = "")
        {
            var stopwatch = Stopwatch.StartNew();
            try
            {
                return await action();
            }
            finally
            {
                stopwatch.Stop();
                Performance(operationName, stopwatch.ElapsedMilliseconds, details);
            }
        }
        
        /// <summary>
        /// 捕获并记录异常
        /// </summary>
        public void CatchAndLog(Action action, string operationName = "")
        {
            try
            {
                action();
            }
            catch (Exception ex)
            {
                Error($"Exception in {operationName}: {ex.Message}", ex);
            }
        }
        
        /// <summary>
        /// 异步捕获并记录异常
        /// </summary>
        public async Task CatchAndLogAsync(Func<Task> action, string operationName = "")
        {
            try
            {
                await action();
            }
            catch (Exception ex)
            {
                Error($"Exception in {operationName}: {ex.Message}", ex);
            }
        }
        
        /// <summary>
        /// 获取日志统计信息
        /// </summary>
        public LogStatistics GetStatistics()
        {
            return new LogStatistics
            {
                ErrorCount = ErrorCount,
                WarningCount = WarningCount,
                InfoCount = InfoCount,
                DebugCount = DebugCount,
                QueueCount = _logQueue.Count,
                LogDirectory = _logDirectory,
                LastLogTime = DateTime.Now
            };
        }
        
        /// <summary>
        /// 获取最近的错误日志
        /// </summary>
        public List<LogEntry> GetRecentErrors(int count = 50)
        {
            var errors = new List<LogEntry>();
            lock (_logQueue)
            {
                foreach (var entry in _logQueue)
                {
                    if (entry.Level == LogLevel.Error && errors.Count < count)
                    {
                        errors.Add(entry);
                    }
                }
            }
            return errors;
        }
        
        /// <summary>
        /// 清空日志队列
        /// </summary>
        public void ClearQueue()
        {
            lock (_logQueue)
            {
                _logQueue.Clear();
            }
        }
        
        /// <summary>
        /// 强制刷新日志队列
        /// </summary>
        public void Flush()
        {
            ProcessLogQueueSync();
        }
        
        /// <summary>
        /// 获取日志文件信息
        /// </summary>
        public LogFileInfo GetLogFileInfo()
        {
            return new LogFileInfo
            {
                ErrorLogPath = _errorLogPath,
                InfoLogPath = _infoLogPath,
                DebugLogPath = _debugLogPath,
                PerfLogPath = _perfLogPath,
                ErrorLogSize = GetFileSize(_errorLogPath),
                InfoLogSize = GetFileSize(_infoLogPath),
                DebugLogSize = GetFileSize(_debugLogPath),
                PerfLogSize = GetFileSize(_perfLogPath)
            };
        }
        
        /// <summary>
        /// 清理旧日志文件
        /// </summary>
        public void CleanupOldLogs()
        {
            try
            {
                var logFiles = Directory.GetFiles(_logDirectory, "*.log*");
                Array.Sort(logFiles, (a, b) => File.GetLastWriteTime(b).CompareTo(File.GetLastWriteTime(a)));
                
                // 保留最新的日志文件
                for (int i = _maxLogFiles; i < logFiles.Length; i++)
                {
                    try
                    {
                        File.Delete(logFiles[i]);
                    }
                    catch (Exception ex)
                    {
                        Debug($"Failed to delete old log file {logFiles[i]}: {ex.Message}");
                    }
                }
            }
            catch (Exception ex)
            {
                Error($"Error cleaning up old logs: {ex.Message}", ex);
            }
        }
        
        /// <summary>
        /// 将日志条目加入队列
        /// </summary>
        private void EnqueueLog(LogEntry entry)
        {
            lock (_logQueue)
            {
                // 限制队列大小，防止内存溢出
                if (_logQueue.Count >= _maxQueueSize)
                {
                    _logQueue.Dequeue(); // 移除最早的日志
                }
                _logQueue.Enqueue(entry);
            }
        }
        
        /// <summary>
        /// 异步处理日志队列
        /// </summary>
        private async Task ProcessLogQueueAsync(CancellationToken cancellationToken)
        {
            while (!cancellationToken.IsCancellationRequested)
            {
                try
                {
                    await Task.Delay(100, cancellationToken);
                    ProcessLogQueueSync();
                }
                catch (OperationCanceledException)
                {
                    break;
                }
                catch (Exception ex)
                {
                    // 避免日志处理自身的异常影响应用
                    Console.WriteLine($"Error in logging task: {ex.Message}");
                }
            }
        }
        
        /// <summary>
        /// 同步处理日志队列
        /// </summary>
        private void ProcessLogQueueSync()
        {
            var entriesToProcess = new List<LogEntry>();
            
            lock (_logQueue)
            {
                while (_logQueue.Count > 0 && entriesToProcess.Count < 100)
                {
                    entriesToProcess.Add(_logQueue.Dequeue());
                }
            }
            
            foreach (var entry in entriesToProcess)
            {
                WriteLogToFile(entry);
                
                // 触发日志写入事件
                LogWritten?.Invoke(this, new LogEventArgs(entry));
            }
        }
        
        /// <summary>
        /// 写入日志到文件
        /// </summary>
        private void WriteLogToFile(LogEntry entry)
        {
            string logPath = GetLogPathForLevel(entry.Level);
            string logMessage = FormatLogMessage(entry);
            
            lock (_fileLock)
            {
                try
                {
                    // 检查并轮转日志文件
                    CheckAndRotateLogFile(logPath);
                    
                    // 写入日志
                    using (var writer = new StreamWriter(logPath, true, Encoding.UTF8))
                    {
                        writer.WriteLine(logMessage);
                    }
                }
                catch (Exception ex)
                {
                    // 避免日志写入失败影响应用
                    Console.WriteLine($"Failed to write log: {ex.Message}");
                }
            }
        }
        
        /// <summary>
        /// 检查并轮转日志文件
        /// </summary>
        private void CheckAndRotateLogFile(string logPath)
        {
            if (File.Exists(logPath))
            {
                var fileInfo = new FileInfo(logPath);
                if (fileInfo.Length >= _maxLogFileSize)
                {
                    // 轮转日志文件
                    for (int i = _maxLogFiles - 1; i > 0; i--)
                    {
                        string oldPath = $"{logPath}.{i}";
                        string newPath = $"{logPath}.{i + 1}";
                        
                        if (File.Exists(oldPath))
                        {
                            if (File.Exists(newPath))
                            {
                                File.Delete(newPath);
                            }
                            File.Move(oldPath, newPath);
                        }
                    }
                    
                    // 重命名当前日志文件
                    string backupPath = $"{logPath}.1";
                    if (File.Exists(backupPath))
                    {
                        File.Delete(backupPath);
                    }
                    File.Move(logPath, backupPath);
                }
            }
        }
        
        /// <summary>
        /// 获取对应级别的日志文件路径
        /// </summary>
        private string GetLogPathForLevel(LogLevel level)
        {
            switch (level)
            {
                case LogLevel.Error:
                    return _errorLogPath;
                case LogLevel.Warning:
                case LogLevel.Info:
                    return _infoLogPath;
                case LogLevel.Debug:
                    return _debugLogPath;
                case LogLevel.Performance:
                    return _perfLogPath;
                default:
                    return _infoLogPath;
            }
        }
        /// <summary>
        /// 格式化日志消息
        /// </summary>
        private string FormatLogMessage(LogEntry entry)
        {
            var sb = new StringBuilder();
            sb.Append($"[{entry.Timestamp:yyyy-MM-dd HH:mm:ss.fff}]");
            sb.Append($"[{entry.Level.ToString().PadRight(10)}]");
            sb.Append($"[{entry.Source.PadRight(20)}]");
            sb.Append($" {entry.Message}");
            
            if (!string.IsNullOrEmpty(entry.Details))
            {
                sb.Append($" | Details: {entry.Details}");
            }
            
            if (entry.Exception != null)
            {
                sb.Append($" | Exception: {entry.Exception.Message}");
                if (!string.IsNullOrEmpty(entry.Exception.StackTrace))
                {
                    sb.Append($"\nStackTrace: {entry.Exception.StackTrace}");
                }
            }
            
            return sb.ToString();
        }
        
        /// <summary>
        /// 获取调用者名称
        /// </summary>
        private string GetCallerName()
        {
            try
            {
                var stackTrace = new StackTrace(2);
                var frame = stackTrace.GetFrame(0);
                var method = frame?.GetMethod();
                var type = method?.DeclaringType;
                return type?.Name ?? "Unknown";
            }
            catch
            {
                return "Unknown";
            }
        }
        
        /// <summary>
        /// 获取文件大小
        /// </summary>
        private long GetFileSize(string filePath)
        {
            try
            {
                if (File.Exists(filePath))
                {
                    return new FileInfo(filePath).Length;
                }
            }
            catch { }
            return 0;
        }
        
        /// <summary>
        /// 释放资源
        /// </summary>
        public void Dispose()
        {
            Dispose(true);
            GC.SuppressFinalize(this);
        }
        
        /// <summary>
        /// 释放资源
        /// </summary>
        protected virtual void Dispose(bool disposing)
        {
            if (!_isDisposed)
            {
                if (disposing)
                {
                    // 取消日志处理任务
                    _cancellationTokenSource.Cancel();
                    
                    // 等待日志处理任务完成
                    try
                    {
                        _loggingTask.Wait(TimeSpan.FromSeconds(5));
                    }
                    catch { }
                    
                    // 处理剩余的日志
                    ProcessLogQueueSync();
                    
                    // 释放资源
                    _cancellationTokenSource.Dispose();
                }
                
                _isDisposed = true;
            }
        }
        
        /// <summary>
        /// 日志级别
        /// </summary>
        public enum LogLevel
        {
            Debug,
            Info,
            Warning,
            Error,
            Performance
        }
        
        /// <summary>
        /// 日志条目
        /// </summary>
        public class LogEntry
        {
            public LogLevel Level { get; set; }
            public string Message { get; set; }
            public Exception Exception { get; set; }
            public DateTime Timestamp { get; set; }
            public string Source { get; set; }
            public string Details { get; set; }
        }
    }
    
    /// <summary>
    /// 日志统计信息
    /// </summary>
    public class LogStatistics
    {
        public int ErrorCount { get; set; }
        public int WarningCount { get; set; }
        public int InfoCount { get; set; }
        public int DebugCount { get; set; }
        public int QueueCount { get; set; }
        public string LogDirectory { get; set; }
        public DateTime LastLogTime { get; set; }
    }
    
    /// <summary>
    /// 日志文件信息
    /// </summary>
    public class LogFileInfo
    {
        public string ErrorLogPath { get; set; }
        public string InfoLogPath { get; set; }
        public string DebugLogPath { get; set; }
        public string PerfLogPath { get; set; }
        public long ErrorLogSize { get; set; }
        public long InfoLogSize { get; set; }
        public long DebugLogSize { get; set; }
        public long PerfLogSize { get; set; }
        
        public string ErrorLogSizeText => FormatFileSize(ErrorLogSize);
        public string InfoLogSizeText => FormatFileSize(InfoLogSize);
        public string DebugLogSizeText => FormatFileSize(DebugLogSize);
        public string PerfLogSizeText => FormatFileSize(PerfLogSize);
        
        private string FormatFileSize(long bytes)
        {
            if (bytes >= 1024 * 1024)
            {
                return $"{bytes / (1024.0 * 1024):F2} MB";
            }
            else if (bytes >= 1024)
            {
                return $"{bytes / 1024.0:F2} KB";
            }
            else
            {
                return $"{bytes} B";
            }
        }
    }
    
    /// <summary>
    /// 日志事件参数
    /// </summary>
    public class LogEventArgs : EventArgs
    {
        public object LogEntry { get; }
        
        public LogEventArgs(object logEntry)
        {
            LogEntry = logEntry;
        }
    }
    
    /// <summary>
    /// 错误记录事件参数
    /// </summary>
    public class ErrorLoggedEventArgs : EventArgs
    {
        public string Message { get; }
        public Exception Exception { get; }
        
        public ErrorLoggedEventArgs(string message, Exception exception)
        {
            Message = message;
            Exception = exception;
        }
    }
    
    /// <summary>
    /// 性能记录事件参数
    /// </summary>
    public class PerformanceLoggedEventArgs : EventArgs
    {
        public string Operation { get; }
        public long Duration { get; }
        public string Details { get; }
        
        public PerformanceLoggedEventArgs(string operation, long duration, string details)
        {
            Operation = operation;
            Duration = duration;
            Details = details;
        }
    }
}
