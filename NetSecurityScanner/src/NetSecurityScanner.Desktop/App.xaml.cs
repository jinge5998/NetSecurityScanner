using System;
using System.Collections.Generic;
using System.Configuration;
using System.Data;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Threading.Tasks;
using System.Windows;
using LiveChartsCore;
using LiveChartsCore.SkiaSharpView;
using NetSecurityScanner.Models;
using NetSecurityScanner.Services;
using NetSecurityScanner.Views;
using NetSecurityScanner.Utils;
using SkiaSharp;

namespace NetSecurityScanner
{
    public partial class App : Application
    {
        private static string _bootLogFile = null!;

        protected override void OnStartup(StartupEventArgs e)
        {
            try
            {
                string logDir = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "logs");
                Directory.CreateDirectory(logDir);
                _bootLogFile = Path.Combine(logDir, $"boot_{DateTime.Now:yyyyMMdd_HHmmss}.log");
                BootLog("=== APP BOOT START ===");
                BootLog($"BaseDir: {AppDomain.CurrentDomain.BaseDirectory}");
                BootLog($"Version: {Assembly.GetExecutingAssembly().GetName().Version}");
                BootLog($"OS: {Environment.OSVersion} 64BitOS={Environment.Is64BitOperatingSystem} 64BitProc={Environment.Is64BitProcess}");
            }
            catch (Exception ex)
            {
                File.WriteAllText(Path.Combine(AppDomain.CurrentDomain.BaseDirectory, $"fatal_{Guid.NewGuid():N}.txt"),
                    $"EARLY BOOT FAIL: {ex}");
            }

            // ===== 全局启动初始化（必须在 WPF 控件创建前完成） =====

            // 1) 启动目录规范化：保证 SkiaSharp 加载字体等资源时使用绝对路径，
            //    避免从其他目录启动 EXE 后出现 IO 异常。
            try
            {
                Environment.CurrentDirectory = AppContext.BaseDirectory;
                BootLog($"CurrentDirectory set to: {Environment.CurrentDirectory}");
            }
            catch (Exception ex)
            {
                BootLog($"SetCurrentDirectory failed: {ex.Message}");
            }

            // 2) 解析中文字体（在图表首次创建前完成）。
            var chineseTypeface = CjkFontResolver.Resolved;
            BootLog($"[AI Risk Font] Resolved CJK typeface: {CjkFontResolver.ResolvedFamilyName} (Handle={(chineseTypeface?.Handle ?? IntPtr.Zero)})");

            // 3) 全局 LiveCharts 字体注册：所有未显式指定字体的图表组件都使用该中文字体。
            //    注：LiveChartsCore 2.0.0-rc2 仅暴露 HasGlobalSKTypeface，不支持 TextSettings/FontBuilder。
            try
            {
                LiveCharts.Configure(config => config.HasGlobalSKTypeface(chineseTypeface));
                BootLog("[LiveCharts] Global CJK typeface configured");
            }
            catch (Exception ex)
            {
                BootLog($"LiveCharts.Configure failed: {ex.Message}");
            }

            try
            {
                base.OnStartup(e);
                BootLog("base.OnStartup OK");
            }
            catch (Exception ex)
            {
                BootLog($"base.OnStartup FAILED: {ex}");
                FailAndExit("应用启动初始化失败", ex);
                return;
            }

            AppDomain.CurrentDomain.UnhandledException += OnUnhandledException;
            DispatcherUnhandledException += OnDispatcherUnhandledException;
            TaskScheduler.UnobservedTaskException += OnUnobservedTaskException;
            BootLog("Exception handlers registered");

            LicenseService licenseService = null!;
            try
            {
                licenseService = new LicenseService();
                BootLog("LicenseService created");

                if (!licenseService.IsLicensed())
                {
                    BootLog("Not licensed -> showing LicenseDialog");
                    var dialog = new LicenseDialog
                    {
                        WindowStartupLocation = WindowStartupLocation.CenterScreen,
                        Topmost = true
                    };
                    var result = dialog.ShowDialog();
                    BootLog($"LicenseDialog result: {result}");
                    if (result != true)
                    {
                        MessageBox.Show("软件未授权，无法使用。请联系管理员获取授权码。", "未授权",
                            MessageBoxButton.OK, MessageBoxImage.Warning);
                        Shutdown();
                        return;
                    }
                }
                else
                {
                    BootLog("License OK");
                }
            }
            catch (Exception ex)
            {
                BootLog($"License check exception: {ex}");
                MessageBox.Show($"授权检查失败：{ex.Message}\n将尝试以受限模式启动。", "授权警告",
                    MessageBoxButton.OK, MessageBoxImage.Warning);
            }

            try
            {
                if (licenseService != null)
                {
                    var license = licenseService.LoadLicense();
                    if (license != null && !license.IsPermanent && license.RemainingTime.HasValue)
                    {
                        var remaining = license.RemainingTime.Value;
                        if (remaining.TotalDays <= 30 && remaining > TimeSpan.Zero)
                        {
                            string urgency = remaining.TotalDays <= 1 ? "紧急" : "提醒";
                            MessageBox.Show(
                                $"您的授权将在 {remaining.Days} 天后到期，请及时续期！\n授权类型：{license.DisplayName}\n到期时间：{license.ExpiryTime:yyyy-MM-dd HH:mm:ss}",
                                $"授权到期{urgency}", MessageBoxButton.OK, MessageBoxImage.Warning);
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                BootLog($"License expiry check warning (non-fatal): {ex.Message}");
            }

            MainWindow mainWindow = null!;
            try
            {
                BootLog("Creating MainWindow...");
                mainWindow = new MainWindow();
                BootLog("MainWindow constructed OK");

                mainWindow.WindowStartupLocation = WindowStartupLocation.CenterScreen;
                mainWindow.ShowActivated = true;
                mainWindow.Topmost = false;
                BootLog("Calling mainWindow.Show()...");
                mainWindow.Show();
                BootLog("MainWindow.Show() OK");

                MainWindow = mainWindow;
                BootLog("=== MAIN WINDOW SHOWN ===");
            }
            catch (Exception ex)
            {
                BootLog($"MAIN WINDOW FAILED: {ex}");
                if (ex.InnerException != null)
                    BootLog($"INNER: {ex.InnerException}");
                FailAndExit("主窗口初始化失败", ex);
                return;
            }

            try
            {
                BootLog("[Update] 检查上次更新遗留的延迟替换文件...");
                var pendingApplied = GitHubAutoUpdater.TryApplyPendingFilesOnStartup();
                BootLog($"[Update] pending 文件应用结果: {(pendingApplied ? "已应用" : "无遗留")}");
            }
            catch (Exception ex)
            {
                BootLog($"[Update] pending 文件检查异常: {ex.Message}");
            }

            try
            {
                CheckForUpdatesOnStartup();
            }
            catch (Exception ex)
            {
                BootLog($"Update check start warning: {ex.Message}");
            }

            BootLog("=== OnStartup completed successfully ===");
        }

        private static void BootLog(string msg)
        {
            try
            {
                if (!string.IsNullOrEmpty(_bootLogFile))
                {
                    File.AppendAllText(_bootLogFile,
                        $"[{DateTime.Now:HH:mm:ss.fff}] {msg}{Environment.NewLine}");
                }
            }
            catch { }
        }

        private void FailAndExit(string title, Exception ex)
        {
            try
            {
                BootLog($"FailAndExit: {title}");
                MessageBox.Show(
                    $"{title}：\n\n{ex.Message}\n\n{ex.StackTrace}\n\n" +
                    $"详细日志已保存至：{_bootLogFile}",
                    "程序启动失败", MessageBoxButton.OK, MessageBoxImage.Error);
            }
            finally
            {
                Shutdown(-1);
            }
        }

        protected override void OnExit(ExitEventArgs e)
        {
            BootLog($"=== APP EXIT code={e.ApplicationExitCode} ===");
            AppDomain.CurrentDomain.UnhandledException -= OnUnhandledException;
            DispatcherUnhandledException -= OnDispatcherUnhandledException;
            TaskScheduler.UnobservedTaskException -= OnUnobservedTaskException;
            base.OnExit(e);
        }

        private void OnDispatcherUnhandledException(object sender, System.Windows.Threading.DispatcherUnhandledExceptionEventArgs e)
        {
            BootLog($"DispatcherUnhandledException: {e.Exception}");
            ShowExceptionDialog("UI线程异常", e.Exception);
            e.Handled = true;
        }

        private void OnUnhandledException(object? sender, UnhandledExceptionEventArgs e)
        {
            var ex = e.ExceptionObject as Exception;
            if (ex != null)
            {
                BootLog($"UnhandledException (isTerminating={e.IsTerminating}): {ex}");
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
                title, MessageBoxButton.OK, MessageBoxImage.Error);
        }

        private void LogException(string title, Exception ex)
        {
            try
            {
                string logPath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "logs");
                Directory.CreateDirectory(logPath);
                string logFile = Path.Combine(logPath, $"app_{DateTime.Now:yyyyMMdd}.log");
                string logMessage = $"[{DateTime.Now:HH:mm:ss.fff}] {title}：\n{ex.Message}\n{ex.StackTrace}";
                if (ex.InnerException != null)
                {
                    logMessage += $"\n内部异常：{ex.InnerException.Message}\n{ex.InnerException.StackTrace}";
                }
                File.AppendAllText(logFile, logMessage + Environment.NewLine);
            }
            catch (Exception) { }
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