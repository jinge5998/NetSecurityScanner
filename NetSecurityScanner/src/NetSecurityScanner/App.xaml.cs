using System;
using System.Collections.Generic;
using System.Configuration;
using System.Data;
using System.Linq;
using System.Threading.Tasks;
using System.Windows;

namespace NetSecurityScanner
{
    /// <summary>
    /// Interaction logic for App.xaml
    /// </summary>
    public partial class App : Application
    {
        protected override void OnStartup(StartupEventArgs e)
        {
            base.OnStartup(e);
            
            // 注册全局异常处理
            AppDomain.CurrentDomain.UnhandledException += OnUnhandledException;
            DispatcherUnhandledException += OnDispatcherUnhandledException;
            TaskScheduler.UnobservedTaskException += OnUnobservedTaskException;
        }
        
        protected override void OnExit(ExitEventArgs e)
        {
            // 取消注册全局异常处理
            AppDomain.CurrentDomain.UnhandledException -= OnUnhandledException;
            DispatcherUnhandledException -= OnDispatcherUnhandledException;
            TaskScheduler.UnobservedTaskException -= OnUnobservedTaskException;
            
            base.OnExit(e);
        }
        
        // 处理UI线程异常
        private void OnDispatcherUnhandledException(object sender, System.Windows.Threading.DispatcherUnhandledExceptionEventArgs e)
        {
            ShowExceptionDialog("UI线程异常", e.Exception);
            e.Handled = true;
        }
        
        // 处理非UI线程异常
        private void OnUnhandledException(object? sender, UnhandledExceptionEventArgs e)
        {
            var ex = e.ExceptionObject as Exception;
            if (ex != null)
            {
                ShowExceptionDialog("应用程序异常", ex);
            }
        }
        
        // 处理Task线程异常（静默处理，避免弹窗干扰）
        private void OnUnobservedTaskException(object? sender, UnobservedTaskExceptionEventArgs e)
        {
            // 记录日志但不弹窗 - 这类异常通常来自已超时的后台任务
            LogException("任务线程异常（已静默处理）", e.Exception);
            
            // 标记为已观察，防止终结器线程重新抛出
            e.SetObserved();
        }
        
        // 显示异常对话框并记录日志
        private void ShowExceptionDialog(string title, Exception ex)
        {
            // 记录异常到日志文件
            LogException(title, ex);
            
            // 显示异常对话框
            MessageBox.Show(
                $"发生{title}：\n\n{ex.Message}\n\n{ex.StackTrace}",
                title,
                MessageBoxButton.OK,
                MessageBoxImage.Error);
        }
        
        // 记录异常到日志文件
        private void LogException(string title, Exception ex)
        {
            try
            {
                string logPath = System.IO.Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "logs");
                System.IO.Directory.CreateDirectory(logPath);
                string logFile = System.IO.Path.Combine(logPath, $"app_{DateTime.Now:yyyyMMdd}.log");
                
                string logMessage = $"[{DateTime.Now:HH:mm:ss.fff}] {title}：\n{ex.Message}\n{ex.StackTrace}";
                
                if (ex.InnerException != null)
                {
                    logMessage += $"\n内部异常：{ex.InnerException.Message}\n{ex.InnerException.StackTrace}";
                }
                
                System.IO.File.AppendAllText(logFile, logMessage + Environment.NewLine);
            }
            catch (Exception)
            {
                // 如果日志写入失败，忽略错误
            }
        }
    }
}