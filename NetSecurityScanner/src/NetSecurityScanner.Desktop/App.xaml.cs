using System;
using System.Collections.Generic;
using System.Configuration;
using System.Data;
using System.Linq;
using System.Reflection;
using System.Threading.Tasks;
using System.Windows;
using NetSecurityScanner.Models;
using NetSecurityScanner.Services;
using NetSecurityScanner.Views;
using NetSecurityScanner.Utils;

namespace NetSecurityScanner
{
    public partial class App : Application
    {
        protected override void OnStartup(StartupEventArgs e)
        {
            base.OnStartup(e);

            AppDomain.CurrentDomain.UnhandledException += OnUnhandledException;
            DispatcherUnhandledException += OnDispatcherUnhandledException;
            TaskScheduler.UnobservedTaskException += OnUnobservedTaskException;

            var licenseService = new LicenseService();
            if (!licenseService.IsLicensed())
            {
                var mainWindow = MainWindow;
                if (mainWindow != null)
                {
                    var dialog = new LicenseDialog { Owner = mainWindow };
                    var result = dialog.ShowDialog();
                    if (result != true)
                    {
                        MessageBox.Show("软件未授权，无法使用。请联系管理员获取授权码。", "未授权", MessageBoxButton.OK, MessageBoxImage.Warning);
                        Shutdown();
                        return;
                    }
                }
            }

            var license = licenseService.LoadLicense();
            if (license != null && !license.IsPermanent && license.RemainingTime.HasValue)
            {
                var remaining = license.RemainingTime.Value;
                if (remaining.TotalDays <= 30 && remaining > TimeSpan.Zero)
                {
                    string urgency = remaining.TotalDays <= 1 ? "紧急" : "提醒";
                    MessageBox.Show(
                        $"您的授权将在 {remaining.Days} 天后到期，请及时续期！\n授权类型：{license.DisplayName}\n到期时间：{license.ExpiryTime:yyyy-MM-dd HH:mm:ss}",
                        $"授权到期{urgency}",
                        MessageBoxButton.OK,
                        MessageBoxImage.Warning);
                }
            }

            CheckForUpdatesOnStartup();
        }
        
        protected override void OnExit(ExitEventArgs e)
        {
            AppDomain.CurrentDomain.UnhandledException -= OnUnhandledException;
            DispatcherUnhandledException -= OnDispatcherUnhandledException;
            TaskScheduler.UnobservedTaskException -= OnUnobservedTaskException;
            
            base.OnExit(e);
        }
        
        private void OnDispatcherUnhandledException(object sender, System.Windows.Threading.DispatcherUnhandledExceptionEventArgs e)
        {
            ShowExceptionDialog("UI线程异常", e.Exception);
            e.Handled = true;
        }
        
        private void OnUnhandledException(object? sender, UnhandledExceptionEventArgs e)
        {
            var ex = e.ExceptionObject as Exception;
            if (ex != null)
            {
                ShowExceptionDialog("应用程序异常", ex);
            }
        }
        
        private void OnUnobservedTaskException(object? sender, UnobservedTaskExceptionEventArgs e)
        {
            LogException("任务线程异常（已静默处理）", e.Exception);
            e.SetObserved();
        }
        
        private void ShowExceptionDialog(string title, Exception ex)
        {
            LogException(title, ex);
            MessageBox.Show(
                $"发生{title}：\n\n{ex.Message}\n\n{ex.StackTrace}",
                title,
                MessageBoxButton.OK,
                MessageBoxImage.Error);
        }
        
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
            }
        }

        private void CheckForUpdatesOnStartup()
        {
            Task.Run(async () =>
            {
                try
                {
                    var settingsService = new SettingsService();
                    var updateSettings = await settingsService.GetUpdateSettingsAsync();

                    if (!updateSettings.CheckOnStartup)
                        return;

                    if (updateSettings.LastCheckTime.HasValue)
                    {
                        var hoursSinceLastCheck = (DateTime.Now - updateSettings.LastCheckTime.Value).TotalHours;
                        if (hoursSinceLastCheck < updateSettings.NotifyIntervalHours)
                            return;
                    }

                    var currentVersion = VersionHelper.GetVersion();

                    using var updateChecker = new UpdateCheckService();
                    var updateInfo = await updateChecker.CheckForUpdateAsync(currentVersion, updateSettings);

                    updateSettings.LastCheckTime = DateTime.Now;
                    await settingsService.SaveUpdateSettingsAsync(updateSettings);

                    if (updateInfo == null)
                        return;

                    if (updateInfo.Version == updateSettings.SkippedVersion)
                        return;

                    await Dispatcher.InvokeAsync(() =>
                    {
                        if (MainWindow != null)
                        {
                            var updateDialog = new UpdateDialog(updateInfo, updateSettings) { Owner = MainWindow };
                            updateDialog.ShowDialog();
                        }
                    });
                }
                catch (Exception ex)
                {
                    LogException("启动时版本检查失败", ex);
                }
            });
        }
    }
}
