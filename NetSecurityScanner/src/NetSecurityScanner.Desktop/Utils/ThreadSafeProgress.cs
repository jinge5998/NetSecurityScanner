using System;
using System.Windows;
using System.Windows.Threading;

namespace NetSecurityScanner.Utils
{
    /// <summary>
    /// 线程安全的进度报告类，确保在UI线程上执行进度更新
    /// </summary>
    /// <typeparam name="T">进度值的类型</typeparam>
    public class ThreadSafeProgress<T> : IProgress<T>
    {
        private readonly Action<T> _handler;
        private readonly Window _window;

        public ThreadSafeProgress(Window window, Action<T> handler)
        {
            _window = window ?? throw new ArgumentNullException(nameof(window));
            _handler = handler ?? throw new ArgumentNullException(nameof(handler));
        }

        public void Report(T value)
        {
            try
            {
                // 检查是否在UI线程上，如果不是，则调度到UI线程
                if (_window.Dispatcher.CheckAccess())
                {
                    // 如果在UI线程上，直接执行
                    ExecuteHandler(value);
                }
                else
                {
                    // 如果不在UI线程上，使用BeginInvoke异步调度
                    // 使用BeginInvoke而不是Invoke，避免阻塞后台线程
                    _window.Dispatcher.BeginInvoke(new Action(() => ExecuteHandler(value)));
                }
            }
            catch (Exception ex)
            {
                // 记录Report方法中的异常
                LogException("Report", ex);
            }
        }

        private void ExecuteHandler(T value)
        {
            try
            {
                _handler(value);
            }
            catch (Exception ex)
            {
                // 记录处理程序中的异常
                LogException("ExecuteHandler", ex);
            }
        }

        private void LogException(string methodName, Exception ex)
        {
            try
            {
                string logPath = System.IO.Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "logs");
                System.IO.Directory.CreateDirectory(logPath);
                string logFile = System.IO.Path.Combine(logPath, $"app_{DateTime.Now:yyyyMMdd}.log");
                string logMessage = $"[{DateTime.Now:HH:mm:ss.fff}] ThreadSafeProgress.{methodName} 异常: {ex.Message}\n{ex.StackTrace}";
                System.IO.File.AppendAllText(logFile, logMessage + Environment.NewLine);
            }
            catch (Exception)
            {
                // 如果日志写入失败，忽略错误
            }
        }
    }
}