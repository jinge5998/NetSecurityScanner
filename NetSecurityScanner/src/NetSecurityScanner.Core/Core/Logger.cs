using System;
using System.IO;
using System.Text;
using System.Threading;
using NetSecurityScanner.Models;

namespace NetSecurityScanner.Core
{
    /// <summary>
    /// 日志记录器 - 用于记录扫描过程中的事件和错误
    /// </summary>
    public class Logger : IDisposable
    {
        private string _logDirectory;
        private string _logFilePath;
        private StreamWriter _logWriter;
        private object _lock = new object();
        private LogLevel _minLogLevel;
        private int _errorCount;
        private int _warningCount;
        private int _infoCount;
        private int _debugCount;

        /// <summary>
        /// 日志级别
        /// </summary>
        public enum LogLevel
        {
            Debug,
            Info,
            Warning,
            Error,
            Critical
        }

        /// <summary>
        /// 错误计数
        /// </summary>
        public int ErrorCount => _errorCount;

        /// <summary>
        /// 警告计数
        /// </summary>
        public int WarningCount => _warningCount;

        /// <summary>
        /// 信息计数
        /// </summary>
        public int InfoCount => _infoCount;

        /// <summary>
        /// 调试计数
        /// </summary>
        public int DebugCount => _debugCount;

        /// <summary>
        /// 总日志条目数
        /// </summary>
        public int TotalLogEntries => _errorCount + _warningCount + _infoCount + _debugCount;

        /// <summary>
        /// 初始化日志记录器
        /// </summary>
        /// <param name="logDirectory">日志目录</param>
        /// <param name="minLogLevel">最小日志级别</param>
        public Logger(string logDirectory = "Logs", LogLevel minLogLevel = LogLevel.Info)
        {
            _logDirectory = logDirectory;
            _minLogLevel = minLogLevel;
            _errorCount = 0;
            _warningCount = 0;
            _infoCount = 0;
            _debugCount = 0;

            InitializeLogger();
        }

        /// <summary>
        /// 初始化日志记录器
        /// </summary>
        private void InitializeLogger()
        {
            // 创建日志目录
            if (!Directory.Exists(_logDirectory))
            {
                Directory.CreateDirectory(_logDirectory);
            }

            // 创建日志文件
            string timestamp = DateTime.Now.ToString("yyyyMMdd_HHmmss");
            _logFilePath = Path.Combine(_logDirectory, $"scan_log_{timestamp}.txt");

            try
            {
                _logWriter = new StreamWriter(_logFilePath, true, Encoding.UTF8);
                _logWriter.AutoFlush = true;

                // 写入日志头
                WriteLogHeader();
            }
            catch (Exception ex)
            {
                Console.WriteLine($"无法初始化日志记录器: {ex.Message}");
                _logWriter = null;
            }
        }

        /// <summary>
        /// 写入日志头
        /// </summary>
        private void WriteLogHeader()
        {
            string header = $"==============================================\n"
                          + $"网络安全漏洞扫描器日志\n"
                          + $"启动时间: {DateTime.Now}\n"
                          + $"日志级别: {_minLogLevel}\n"
                          + $"==============================================\n";

            WriteToLog(header);
        }

        /// <summary>
        /// 写入调试日志
        /// </summary>
        /// <param name="message">日志消息</param>
        /// <param name="exception">异常信息</param>
        public void Debug(string message, Exception exception = null)
        {
            Log(LogLevel.Debug, message, exception);
        }

        /// <summary>
        /// 写入信息日志
        /// </summary>
        /// <param name="message">日志消息</param>
        /// <param name="exception">异常信息</param>
        public void Info(string message, Exception exception = null)
        {
            Log(LogLevel.Info, message, exception);
        }

        /// <summary>
        /// 写入警告日志
        /// </summary>
        /// <param name="message">日志消息</param>
        /// <param name="exception">异常信息</param>
        public void Warning(string message, Exception exception = null)
        {
            Log(LogLevel.Warning, message, exception);
        }

        /// <summary>
        /// 写入错误日志
        /// </summary>
        /// <param name="message">日志消息</param>
        /// <param name="exception">异常信息</param>
        public void Error(string message, Exception exception = null)
        {
            Log(LogLevel.Error, message, exception);
        }

        /// <summary>
        /// 写入严重错误日志
        /// </summary>
        /// <param name="message">日志消息</param>
        /// <param name="exception">异常信息</param>
        public void Critical(string message, Exception exception = null)
        {
            Log(LogLevel.Critical, message, exception);
        }

        /// <summary>
        /// 记录日志
        /// </summary>
        /// <param name="level">日志级别</param>
        /// <param name="message">日志消息</param>
        /// <param name="exception">异常信息</param>
        private void Log(LogLevel level, string message, Exception exception = null)
        {
            if (level < _minLogLevel)
                return;

            lock (_lock)
            {
                try
                {
                    // 增加计数
                    switch (level)
                    {
                        case LogLevel.Debug:
                            Interlocked.Increment(ref _debugCount);
                            break;
                        case LogLevel.Info:
                            Interlocked.Increment(ref _infoCount);
                            break;
                        case LogLevel.Warning:
                            Interlocked.Increment(ref _warningCount);
                            break;
                        case LogLevel.Error:
                        case LogLevel.Critical:
                            Interlocked.Increment(ref _errorCount);
                            break;
                    }

                    // 构建日志消息
                    StringBuilder logMessage = new StringBuilder();
                    logMessage.AppendLine($"[{DateTime.Now:yyyy-MM-dd HH:mm:ss.fff}] [{level.ToString().ToUpper()}] {message}");

                    // 添加异常信息
                    if (exception != null)
                    {
                        logMessage.AppendLine($"异常类型: {exception.GetType().Name}");
                        logMessage.AppendLine($"异常消息: {exception.Message}");
                        logMessage.AppendLine($"堆栈跟踪: {exception.StackTrace}");
                        if (exception.InnerException != null)
                        {
                            logMessage.AppendLine($"内部异常: {exception.InnerException.Message}");
                        }
                    }

                    logMessage.AppendLine();

                    // 写入日志文件
                    WriteToLog(logMessage.ToString());

                    // 控制台输出（对于错误和严重错误）
                    if (level >= LogLevel.Error)
                    {
                        Console.Error.WriteLine($"[{level.ToString().ToUpper()}] {message}");
                        if (exception != null)
                        {
                            Console.Error.WriteLine($"异常: {exception.Message}");
                        }
                    }
                }
                catch (Exception ex)
                {
                    // 日志记录器本身的错误
                    Console.WriteLine($"日志记录错误: {ex.Message}");
                }
            }
        }

        /// <summary>
        /// 写入日志到文件
        /// </summary>
        /// <param name="content">日志内容</param>
        private void WriteToLog(string content)
        {
            if (_logWriter != null)
            {
                try
                {
                    _logWriter.Write(content);
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"写入日志文件失败: {ex.Message}");
                }
            }
            else
            {
                // 如果日志写入器未初始化，输出到控制台
                Console.WriteLine(content);
            }
        }

        /// <summary>
        /// 记录扫描开始
        /// </summary>
        /// <param name="host">主机地址</param>
        /// <param name="portCount">端口数量</param>
        /// <param name="scanOptions">扫描选项</param>
        public void LogScanStart(string host, int portCount, ScanOptions scanOptions)
        {
            Info($"开始扫描主机: {host}");
            Info($"扫描端口数量: {portCount}");
            Info($"扫描类型: {scanOptions.ScanType}");
            Info($"最大并发数: {scanOptions.MaxConcurrency}");
            Info($"超时时间: {scanOptions.Timeout} ms");
            Info($"是否启用服务检测: {scanOptions.EnableServiceDetection}");
        }

        /// <summary>
        /// 记录扫描完成
        /// </summary>
        /// <param name="host">主机地址</param>
        /// <param name="portCount">扫描端口数量</param>
        /// <param name="openPorts">开放端口数量</param>
        /// <param name="scanTime">扫描时间</param>
        public void LogScanComplete(string host, int portCount, int openPorts, TimeSpan scanTime)
        {
            Info($"扫描完成: {host}");
            Info($"扫描端口数量: {portCount}");
            Info($"开放端口数量: {openPorts}");
            Info($"扫描时间: {scanTime}");
            Info($"扫描速度: {portCount / scanTime.TotalSeconds:F2} 端口/秒");
        }

        /// <summary>
        /// 记录端口扫描结果
        /// </summary>
        /// <param name="host">主机地址</param>
        /// <param name="port">端口号</param>
        /// <param name="status">状态</param>
        /// <param name="service">服务名称</param>
        public void LogPortScanResult(string host, int port, string status, string service = null)
        {
            if (status == "Open")
            {
                Info($"端口开放: {host}:{port} - {status} - 服务: {service ?? "未知"}");
            }
            else if (status == "Error")
            {
                Warning($"端口扫描错误: {host}:{port} - {status}");
            }
            else
            {
                Debug($"端口扫描结果: {host}:{port} - {status}");
            }
        }

        /// <summary>
        /// 记录批量扫描开始
        /// </summary>
        /// <param name="batchNumber">批次编号</param>
        /// <param name="totalBatches">总批次数</param>
        /// <param name="batchSize">批次大小</param>
        public void LogBatchStart(int batchNumber, int totalBatches, int batchSize)
        {
            Info($"开始批次扫描: {batchNumber}/{totalBatches}, 批次大小: {batchSize}");
        }

        /// <summary>
        /// 记录批量扫描完成
        /// </summary>
        /// <param name="batchNumber">批次编号</param>
        /// <param name="totalBatches">总批次数</param>
        /// <param name="batchSize">批次大小</param>
        /// <param name="timeTaken">耗时</param>
        public void LogBatchComplete(int batchNumber, int totalBatches, int batchSize, TimeSpan timeTaken)
        {
            Info($"批次扫描完成: {batchNumber}/{totalBatches}, 耗时: {timeTaken}, 速度: {batchSize / timeTaken.TotalSeconds:F2} 端口/秒");
        }

        /// <summary>
        /// 记录Socket池事件
        /// </summary>
        /// <param name="message">事件消息</param>
        public void LogSocketPoolEvent(string message)
        {
            Debug($"Socket池事件: {message}");
        }

        /// <summary>
        /// 记录缓存事件
        /// </summary>
        /// <param name="message">事件消息</param>
        public void LogCacheEvent(string message)
        {
            Debug($"缓存事件: {message}");
        }

        /// <summary>
        /// 获取日志统计信息
        /// </summary>
        /// <returns>日志统计信息</returns>
        public string GetLogStatistics()
        {
            StringBuilder stats = new StringBuilder();
            stats.AppendLine("=== 日志统计信息 ===");
            stats.AppendLine($"总日志条目: {TotalLogEntries}");
            stats.AppendLine($"错误: {_errorCount}");
            stats.AppendLine($"警告: {_warningCount}");
            stats.AppendLine($"信息: {_infoCount}");
            stats.AppendLine($"调试: {_debugCount}");
            stats.AppendLine($"日志文件: {_logFilePath}");
            return stats.ToString();
        }

        /// <summary>
        /// 写入日志摘要
        /// </summary>
        public void WriteLogSummary()
        {
            StringBuilder summary = new StringBuilder();
            summary.AppendLine("==============================================");
            summary.AppendLine("扫描日志摘要");
            summary.AppendLine("==============================================");
            summary.AppendLine($"扫描结束时间: {DateTime.Now}");
            summary.AppendLine($"总日志条目: {TotalLogEntries}");
            summary.AppendLine($"错误: {_errorCount}");
            summary.AppendLine($"警告: {_warningCount}");
            summary.AppendLine($"信息: {_infoCount}");
            summary.AppendLine($"调试: {_debugCount}");
            summary.AppendLine("==============================================");

            WriteToLog(summary.ToString());
        }

        /// <summary>
        /// 释放资源
        /// </summary>
        public void Dispose()
        {
            lock (_lock)
            {
                try
                {
                    if (_logWriter != null)
                    {
                        WriteLogSummary();
                        _logWriter.Flush();
                        _logWriter.Close();
                        _logWriter.Dispose();
                        _logWriter = null;
                    }
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"关闭日志文件失败: {ex.Message}");
                }
            }
        }
    }
}
