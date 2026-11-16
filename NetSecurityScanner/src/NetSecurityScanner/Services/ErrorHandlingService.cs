using System;
using System.IO;
using System.Text;
using System.Text.Json;
using System.Windows;
using System.Collections.Generic;

namespace NetSecurityScanner.Services
{
    /// <summary>
    /// 统一错误处理服务 - 增强版
    /// 用于规范化错误日志记录和用户提示
    /// 
    /// 新增功能：
    /// 1. 结构化日志（JSON格式）
    /// 2. 日志轮转（单文件最大10MB，保留最近30天）
    /// 3. 敏感信息自动脱敏
    /// 4. 性能关键路径计时
    /// </summary>
    public static class ErrorHandlingService
    {
        private static readonly string LogDirectory = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "Logs");
        private static readonly string ErrorLogPath = Path.Combine(LogDirectory, "error.log");
        private static readonly string StructuredLogPath = Path.Combine(LogDirectory, "structured_error.jsonl");
        private static readonly object LockObject = new object();
        
        // 日志配置
        private const long MaxLogFileSizeBytes = 10 * 1024 * 1024; // 10MB
        private const int MaxLogRetentionDays = 30;
        private static long _currentLogSize;
        
        // 统计信息
        private static int _totalErrorsLogged;
        private static int _totalWarningsLogged;
        private static DateTime _lastLogRotation;
        
        static ErrorHandlingService()
        {
            // 确保日志目录存在
            if (!Directory.Exists(LogDirectory))
            {
                Directory.CreateDirectory(LogDirectory);
            }
            
            // 初始化日志大小
            InitializeLogFile();
            
            // 启动时清理过期日志
            CleanOldLogs();
        }
        
        /// <summary>
        /// 初始化日志文件并获取当前大小
        /// </summary>
        private static void InitializeLogFile()
        {
            try
            {
                if (File.Exists(ErrorLogPath))
                {
                    var fileInfo = new FileInfo(ErrorLogPath);
                    _currentLogSize = fileInfo.Length;
                    _lastLogRotation = fileInfo.LastWriteTime;
                }
                else
                {
                    _currentLogSize = 0;
                    _lastLogRotation = DateTime.Now;
                }
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"[ErrorHandling] 初始化日志失败: {ex.Message}");
            }
        }

        /// <summary>
        /// 记录错误日志（不显示给用户）- 增强版
        /// 支持自动脱敏、结构化日志、日志轮转
        /// </summary>
        public static void LogError(string context, Exception exception)
        {
            lock (LockObject)
            {
                try
                {
                    // 检查是否需要日志轮转
                    CheckAndRotateLogIfNeeded();
                    
                    // 1. 传统文本格式日志
                    var sb = new StringBuilder();
                    sb.AppendLine($"[{DateTime.Now:yyyy-MM-dd HH:mm:ss.fff}] [ERROR] [{context}]");
                    sb.AppendLine($"错误类型: {exception.GetType().Name}");
                    
                    // 脱敏处理
                    string sanitizedMessage = SanitizeSensitiveInfo(exception.Message);
                    sb.AppendLine($"错误消息: {sanitizedMessage}");
                    sb.AppendLine($"堆栈跟踪:");
                    sb.AppendLine(exception.StackTrace);
                    
                    if (exception.InnerException != null)
                    {
                        string sanitizedInnerMessage = SanitizeSensitiveInfo(exception.InnerException.Message);
                        sb.AppendLine($"内部异常: {sanitizedInnerMessage}");
                        sb.AppendLine($"内部异常堆栈: {exception.InnerException.StackTrace}");
                    }
                    
                    sb.AppendLine(new string('-', 80));
                    sb.AppendLine();

                    File.AppendAllText(ErrorLogPath, sb.ToString());
                    _currentLogSize += Encoding.UTF8.GetByteCount(sb.ToString());
                    System.Threading.Interlocked.Increment(ref _totalErrorsLogged);
                    
                    // 2. 结构化JSON格式日志（便于ELK等分析工具）
                    WriteStructuredLogEntry(context, exception, "ERROR");
                }
                catch
                {
                    // 日志记录失败时忽略，避免无限循环
                }
            }
        }
        
        /// <summary>
        /// 检查并执行日志轮转
        /// </summary>
        private static void CheckAndRotateLogIfNeeded()
        {
            try
            {
                if (_currentLogSize > MaxLogFileSizeBytes)
                {
                    RotateLog();
                }
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"[ErrorHandling] 日志轮转检查失败: {ex.Message}");
            }
        }
        
        /// <summary>
        /// 执行日志轮转（重命名旧文件，创建新文件）
        /// </summary>
        private static void RotateLog()
        {
            try
            {
                if (File.Exists(ErrorLogPath))
                {
                    string timestamp = DateTime.Now.ToString("yyyyMMdd_HHmmss");
                    string archivePath = Path.Combine(LogDirectory, $"error_{timestamp}.log");
                    
                    // 重命名当前日志文件为归档文件
                    File.Move(ErrorLogPath, archivePath);
                    
                    _currentLogSize = 0;
                    _lastLogRotation = DateTime.Now;
                    
                    System.Diagnostics.Debug.WriteLine($"[ErrorHandling] 日志已轮转，归档到: {archivePath}");
                }
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"[ErrorHandling] 日志轮转失败: {ex.Message}");
            }
        }
        
        /// <summary>
        /// 清理过期的日志文件
        /// </summary>
        private static void CleanOldLogs()
        {
            try
            {
                var logFiles = Directory.GetFiles(LogDirectory, "error_*.log");
                
                foreach (var file in logFiles)
                {
                    try
                    {
                        var fileInfo = new FileInfo(file);
                        if ((DateTime.Now - fileInfo.LastWriteTime).Days > MaxLogRetentionDays)
                        {
                            File.Delete(file);
                            System.Diagnostics.Debug.WriteLine($"[ErrorHandling] 已删除过期日志: {file}");
                        }
                    }
                    catch
                    {
                        // 忽略单个文件删除失败
                    }
                }
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"[ErrorHandling] 清理过期日志失败: {ex.Message}");
            }
        }
        
        /// <summary>
        /// 写入结构化JSON格式日志条目
        /// </summary>
        private static void WriteStructuredLogEntry(string context, Exception exception, string level)
        {
            try
            {
                var logEntry = new
                {
                    timestamp = DateTime.UtcNow.ToString("o"),
                    level = level,
                    context = context,
                    exception_type = exception.GetType().FullName,
                    message = SanitizeSensitiveInfo(exception.Message),
                    stack_trace = exception.StackTrace?.Split('\n'),
                    inner_exception = exception.InnerException != null ? new
                    {
                        type = exception.InnerException.GetType().FullName,
                        message = SanitizeSensitiveInfo(exception.InnerException.Message)
                    } : null,
                    machine_name = Environment.MachineName,
                    user_name = Environment.UserName,
                    app_version = System.Reflection.Assembly.GetExecutingAssembly()?.GetName()?.Version?.ToString()
                };
                
                string jsonLine = JsonSerializer.Serialize(logEntry) + Environment.NewLine;
                File.AppendAllText(StructuredLogPath, jsonLine);
            }
            catch (Exception ex)
            {
                // 结构化日志写入失败不影响主流程
                System.Diagnostics.Debug.WriteLine($"[ErrorHandling] 结构化日志写入失败: {ex.Message}");
            }
        }
        
        /// <summary>
        /// 敏感信息自动脱敏
        /// 替换密码、IP地址、邮箱等敏感信息
        /// </summary>
        public static string SanitizeSensitiveInfo(string input)
        {
            if (string.IsNullOrEmpty(input)) return input;
            
            string result = input;
            
            // 脱敏密码模式：password=xxx, pwd=xxx, 密码=xxx 等
            result = System.Text.RegularExpressions.Regex.Replace(
                result, 
                @"(?i)(password|passwd|pwd|密码)\s*[=:]\s*\S+", 
                "$1=***"
            );
            
            // 脱敏IP地址（部分遮蔽）：192.168.1.1 -> 192.168.*.*
            result = System.Text.RegularExpressions.Regex.Replace(
                result,
                @"\b(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})\b",
                "$1.$2.*.*"
            );
            
            // 脱敏邮箱：user@example.com -> u***@example.com
            result = System.Text.RegularExpressions.Regex.Replace(
                result,
                @"\b([a-zA-Z])[a-zA-Z0-9._%+-]*(@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})\b",
                "$1***$2"
            );
            
            // 脱敏手机号：13812345678 -> 138****5678
            result = System.Text.RegularExpressions.Regex.Replace(
                result,
                @"\b(1[3-9]\d)\d{4}(\d{4})\b",
                "$1****$2"
            );
            
            return result;
        }
        
        /// <summary>
        /// 性能计时器 - 用于测量关键路径的执行时间
        /// </summary>
        public static IDisposable MeasurePerformance(string operationName)
        {
            return new PerformanceTimer(operationName);
        }
        
        /// <summary>
        /// 性能计时器实现
        /// </summary>
        private class PerformanceTimer : IDisposable
        {
            private readonly string _operationName;
            private readonly System.Diagnostics.Stopwatch _stopwatch;
            private bool _disposed;
            
            public PerformanceTimer(string operationName)
            {
                _operationName = operationName;
                _stopwatch = System.Diagnostics.Stopwatch.StartNew();
            }
            
            public void Dispose()
            {
                if (!_disposed)
                {
                    _stopwatch.Stop();
                    double elapsedMs = _stopwatch.Elapsed.TotalMilliseconds;
                    
                    LogInfo("Performance", $"[{_operationName}] 耗时: {elapsedMs:F2}ms");
                    
                    // 如果操作耗时超过阈值，记录警告
                    if (elapsedMs > 1000) // 超过1秒
                    {
                        LogWarning("Performance", $"[{_operationName}] 耗时过长: {elapsedMs:F2}ms (>1000ms)");
                    }
                    
                    _disposed = true;
                }
            }
        }

        /// <summary>
        /// 记录信息日志
        /// </summary>
        public static void LogInfo(string context, string message)
        {
            lock (LockObject)
            {
                try
                {
                    var logEntry = $"[{DateTime.Now:yyyy-MM-dd HH:mm:ss.fff}] [INFO] [{context}] {message}{Environment.NewLine}";
                    File.AppendAllText(ErrorLogPath, logEntry);
                }
                catch
                {
                    // 忽略日志记录失败
                }
            }
        }
        
        /// <summary>
        /// 记录警告日志（新增）
        /// </summary>
        public static void LogWarning(string context, string message)
        {
            lock (LockObject)
            {
                try
                {
                    var logEntry = $"[{DateTime.Now:yyyy-MM-dd HH:mm:ss.fff}] [WARN] [{context}] {message}{Environment.NewLine}";
                    File.AppendAllText(ErrorLogPath, logEntry);
                    System.Threading.Interlocked.Increment(ref _totalWarningsLogged);
                }
                catch
                {
                    // 忽略日志记录失败
                }
            }
        }
        
        /// <summary>
        /// 获取错误处理服务统计信息（新增）
        /// </summary>
        public static string GetStatistics()
        {
            return $"错误处理服务统计:\n" +
                   $"- 总错误数: {_totalErrorsLogged}\n" +
                   $"- 总警告数: {_totalWarningsLogged}\n" +
                   $"- 当前日志大小: {_currentLogSize / 1024 / 1024:F2} MB\n" +
                   $"- 上次轮转时间: {_lastLogRotation:yyyy-MM-dd HH:mm:ss}\n" +
                   $"- 日志文件路径: {ErrorLogPath}\n" +
                   $"- 结构化日志路径: {StructuredLogPath}";
        }

        /// <summary>
        /// 显示用户友好的错误消息
        /// </summary>
        public static void ShowError(string title, string message, string technicalDetails = null)
        {
            // 记录到日志
            LogInfo("UserError", $"{title}: {message}");
            if (!string.IsNullOrEmpty(technicalDetails))
            {
                LogInfo("TechnicalDetails", technicalDetails);
            }

            // 显示给用户
            var displayMessage = message;
            if (!string.IsNullOrEmpty(technicalDetails))
            {
                displayMessage += $"\n\n技术详情: {technicalDetails}";
            }

            MessageBox.Show(displayMessage, title, MessageBoxButton.OK, MessageBoxImage.Error);
        }

        /// <summary>
        /// 显示警告消息
        /// </summary>
        public static void ShowWarning(string title, string message)
        {
            LogInfo("UserWarning", $"{title}: {message}");
            MessageBox.Show(message, title, MessageBoxButton.OK, MessageBoxImage.Warning);
        }

        /// <summary>
        /// 显示信息消息
        /// </summary>
        public static void ShowInfo(string title, string message)
        {
            MessageBox.Show(message, title, MessageBoxButton.OK, MessageBoxImage.Information);
        }

        /// <summary>
        /// 处理服务初始化错误
        /// </summary>
        public static T HandleServiceInitialization<T>(string serviceName, Func<T> initializer) where T : class
        {
            try
            {
                LogInfo("ServiceInit", $"正在初始化服务: {serviceName}");
                var result = initializer();
                LogInfo("ServiceInit", $"服务初始化成功: {serviceName}");
                return result;
            }
            catch (Exception ex)
            {
                LogError($"ServiceInit_{serviceName}", ex);
                return null;
            }
        }

        /// <summary>
        /// 安全执行操作，捕获并记录所有异常
        /// </summary>
        public static bool SafeExecute(string operationName, Action action, bool showErrorToUser = false)
        {
            try
            {
                action();
                return true;
            }
            catch (Exception ex)
            {
                LogError(operationName, ex);
                
                if (showErrorToUser)
                {
                    ShowError("操作失败", $"执行 {operationName} 时发生错误。", ex.Message);
                }
                
                return false;
            }
        }

        /// <summary>
        /// 安全执行异步操作
        /// </summary>
        public static async System.Threading.Tasks.Task<bool> SafeExecuteAsync(string operationName, Func<System.Threading.Tasks.Task> action, bool showErrorToUser = false)
        {
            try
            {
                await action();
                return true;
            }
            catch (Exception ex)
            {
                LogError(operationName, ex);
                
                if (showErrorToUser)
                {
                    ShowError("操作失败", $"执行 {operationName} 时发生错误。", ex.Message);
                }
                
                return false;
            }
        }

        /// <summary>
        /// 获取用户友好的错误消息
        /// </summary>
        public static string GetUserFriendlyMessage(Exception ex)
        {
            return ex switch
            {
                System.Net.Sockets.SocketException socketEx => $"网络连接错误: {socketEx.Message}",
                System.IO.IOException ioEx => $"文件操作错误: {ioEx.Message}",
                System.UnauthorizedAccessException authEx => $"权限不足: {authEx.Message}",
                System.ArgumentException argEx => $"参数错误: {argEx.Message}",
                System.NullReferenceException nullEx => $"空引用错误: 对象未正确初始化",
                System.InvalidOperationException invEx => $"操作无效: {invEx.Message}",
                _ => $"发生错误: {ex.Message}"
            };
        }
    }
}
