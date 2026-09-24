using System;
using System.ComponentModel;
using System.Windows;
using NetSecurityScanner.Utils;
using NetSecurityScanner.Services;
using UpdateSettingsModel = NetSecurityScanner.Models.UpdateSettings;
using UpdateInfoModel = NetSecurityScanner.Models.UpdateInfo;

namespace NetSecurityScanner.Views
{
    public partial class UpdateDialog : Window
    {
        private readonly UpdateInfoModel _updateInfo;
        private readonly UpdateSettingsModel _updateSettings;
        private bool _isClosingHandled = false;
        private bool _isUpdating = false;
        private GitHubAutoUpdater? _autoUpdater;

        public UpdateDialog(UpdateInfoModel updateInfo, UpdateSettingsModel updateSettings)
        {
            InitializeComponent();
            _updateInfo = updateInfo;
            _updateSettings = updateSettings;
            DisplayUpdateInfo();
        }

        private void DisplayUpdateInfo()
        {
            NewVersionTextBlock.Text = $"v{_updateInfo.Version}";
            CurrentVersionTextBlock.Text = $"v{GetCurrentVersion()}";
            ReleaseDateTextBlock.Text = _updateInfo.ReleaseDate.ToString("yyyy-MM-dd");
            ReleaseNotesTextBox.Text = _updateInfo.ReleaseNotes;

            if (!string.IsNullOrEmpty(_updateInfo.HtmlUrl))
            {
                GitHubReleaseUrlTextBlock.Text = _updateInfo.HtmlUrl;
                GitHubReleaseUrlTextBlock.ToolTip = "点击在浏览器中打开 GitHub Release 页面";
            }
            else
            {
                GitHubReleaseUrlTextBlock.Text = "（暂无 GitHub 页面）";
                GitHubReleaseUrlTextBlock.Foreground = System.Windows.Media.Brushes.Gray;
                GitHubReleaseUrlTextBlock.Cursor = System.Windows.Input.Cursors.Arrow;
            }

            if (!string.IsNullOrEmpty(_updateInfo.BaiduDownloadUrl))
            {
                BaiduUrlTextBlock.Text = _updateInfo.BaiduDownloadUrl;
            }
            else
            {
                BaiduUrlTextBlock.Text = "（暂无备用链接）";
                BaiduUrlTextBlock.Foreground = System.Windows.Media.Brushes.Gray;
                BaiduUrlTextBlock.Cursor = System.Windows.Input.Cursors.Arrow;
            }

            if (!string.IsNullOrEmpty(_updateInfo.BaiduExtractionCode))
            {
                ExtractionCodeTextBlock.Text = _updateInfo.BaiduExtractionCode;
                CopyCodeButton.Visibility = Visibility.Visible;
            }
            else
            {
                ExtractionCodeTextBlock.Text = "—";
                CopyCodeButton.Visibility = Visibility.Collapsed;
            }

            var hasAutoUpdate = !string.IsNullOrEmpty(_updateInfo.WindowsAssetDownloadUrl);
            AutoUpdatePanel.Visibility = hasAutoUpdate ? Visibility.Visible : Visibility.Collapsed;
            AutoUpdateButton.Visibility = hasAutoUpdate ? Visibility.Visible : Visibility.Collapsed;

            if (hasAutoUpdate)
            {
                AssetSizeTextBlock.Text = FormatBytes(_updateInfo.WindowsAssetSize);
                AssetNameTextBlock.Text = _updateInfo.WindowsAssetName ?? "GitHub Release";
            }
        }

        private string GetCurrentVersion()
        {
            return VersionHelper.GetVersion();
        }

        private async void AutoUpdateButton_Click(object sender, RoutedEventArgs e)
        {
            if (_isUpdating) return;

            if (string.IsNullOrEmpty(_updateInfo.WindowsAssetDownloadUrl))
            {
                MessageBox.Show("无法获取自动更新下载地址，请使用手动下载方式。", "提示", MessageBoxButton.OK, MessageBoxImage.Information);
                return;
            }

            var confirm = MessageBox.Show(
                "即将从 GitHub 自动下载并安装最新版本。\n\n" +
                "⚠️ 更新过程中应用将自动重启，请确保：\n" +
                "1. 已保存所有工作\n" +
                "2. 网络连接稳定\n\n" +
                "是否继续？",
                "确认自动更新",
                MessageBoxButton.YesNo,
                MessageBoxImage.Question);

            if (confirm != MessageBoxResult.Yes) return;

            _isUpdating = true;
            SetButtonsEnabled(false);
            ProgressPanel.Visibility = Visibility.Visible;
            AutoUpdateButton.Content = "更新中...";
            AutoUpdateButton.IsEnabled = false;

            try
            {
                _autoUpdater = new GitHubAutoUpdater();
                _autoUpdater.ProgressChanged += OnUpdateProgressChanged;

                var progress = new Progress<(string Message, int Percent)>(p =>
                {
                    Dispatcher.Invoke(() =>
                    {
                        ProgressMessageTextBlock.Text = p.Message;
                        UpdateProgressBar.Value = p.Percent;
                    });
                });

                var success = await _autoUpdater.DownloadAndInstallAsync(
                    _updateInfo.WindowsAssetDownloadUrl!,
                    _updateInfo.WindowsAssetName ?? "update.zip",
                    progress);

                if (success)
                {
                    ProgressMessageTextBlock.Text = "✅ 更新完成！3 秒后自动重启应用...";
                    UpdateProgressBar.Value = 100;

                    var settingsService = new SettingsService();
                    _updateSettings.LastCheckTime = DateTime.Now;
                    await settingsService.SaveUpdateSettingsAsync(_updateSettings);

                    _autoUpdater.ScheduleRestart(delaySeconds: 3);

                    ProgressMessageTextBlock.Text = "正在准备重启，请稍候...";

                    await System.Threading.Tasks.Task.Delay(1000);

                    System.Windows.Application.Current.Shutdown();
                    return;
                }
                else
                {
                    ProgressMessageTextBlock.Text = "❌ 更新失败";
                    SetButtonsEnabled(true);
                    _isUpdating = false;
                    AutoUpdateButton.Content = "🚀 一键更新";
                    AutoUpdateButton.IsEnabled = true;

                    var retry = MessageBox.Show(
                        "自动更新失败！\n\n是否打开下载页面手动更新？",
                        "更新失败",
                        MessageBoxButton.YesNo,
                        MessageBoxImage.Warning);

                    if (retry == MessageBoxResult.Yes)
                    {
                        try
                        {
                            UpdatePackageDownloader.OpenDownloadLink(GetPreferredManualDownloadUrl());
                        }
                        catch { }
                    }
                }
            }
            catch (Exception ex)
            {
                ProgressMessageTextBlock.Text = $"❌ 更新出错: {ex.Message}";
                SetButtonsEnabled(true);
                _isUpdating = false;
                AutoUpdateButton.Content = "🚀 一键更新";
                AutoUpdateButton.IsEnabled = true;
            }
        }

        private void OnUpdateProgressChanged(object? sender, AutoUpdateProgressEventArgs e)
        {
            Dispatcher.Invoke(() =>
            {
                ProgressMessageTextBlock.Text = e.Message;
                UpdateProgressBar.Value = e.ProgressPercent;

                if (e.IsError)
                {
                    ProgressMessageTextBlock.Foreground = System.Windows.Media.Brushes.Red;
                }
                else
                {
                    ProgressMessageTextBlock.Foreground = System.Windows.Media.Brushes.Black;
                }
            });
        }

        private void DownloadButton_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                var url = GetPreferredManualDownloadUrl();
                UpdatePackageDownloader.OpenDownloadLink(url);
                DialogResult = true;
            }
            catch (Exception ex)
            {
                MessageBox.Show($"打开下载链接失败：{ex.Message}", "错误", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        private string GetPreferredManualDownloadUrl()
        {
            if (!string.IsNullOrEmpty(_updateInfo.HtmlUrl))
                return _updateInfo.HtmlUrl;

            if (!string.IsNullOrEmpty(_updateInfo.BaiduDownloadUrl))
                return _updateInfo.BaiduDownloadUrl;

            return UpdatePackageDownloader.DefaultDownloadUrl;
        }

        private void GitHubReleaseUrlTextBlock_Click(object sender, System.Windows.Input.MouseButtonEventArgs e)
        {
            try
            {
                if (!string.IsNullOrEmpty(_updateInfo.HtmlUrl))
                {
                    UpdatePackageDownloader.OpenDownloadLink(_updateInfo.HtmlUrl);
                }
            }
            catch { }
        }

        private void RemindLaterButton_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                _updateSettings.LastCheckTime = DateTime.Now;
                var settingsService = new SettingsService();
                settingsService.SaveUpdateSettingsAsync(_updateSettings).GetAwaiter().GetResult();
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"保存更新设置失败: {ex.Message}");
            }

            DialogResult = false;
            Close();
        }

        private void SkipButton_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                _updateSettings.SkippedVersion = _updateInfo.Version;
                var settingsService = new SettingsService();
                settingsService.SaveUpdateSettingsAsync(_updateSettings).GetAwaiter().GetResult();
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"保存更新设置失败: {ex.Message}");
            }

            DialogResult = false;
            Close();
        }

        private void BaiduUrlTextBlock_Click(object sender, System.Windows.Input.MouseButtonEventArgs e)
        {
            try
            {
                var url = !string.IsNullOrEmpty(_updateInfo.BaiduDownloadUrl)
                    ? _updateInfo.BaiduDownloadUrl
                    : UpdatePackageDownloader.DefaultDownloadUrl;
                UpdatePackageDownloader.OpenDownloadLink(url);
            }
            catch { }
        }

        private void CopyCodeButton_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                var code = !string.IsNullOrEmpty(_updateInfo.BaiduExtractionCode)
                    ? _updateInfo.BaiduExtractionCode
                    : UpdatePackageDownloader.DefaultExtractionCode;
                Clipboard.SetText(code);
                CopyCodeButton.Content = "已复制";
                var timer = new System.Windows.Threading.DispatcherTimer { Interval = TimeSpan.FromSeconds(2) };
                timer.Tick += (s, args) => { CopyCodeButton.Content = "复制"; timer.Stop(); };
                timer.Start();
            }
            catch { }
        }

        private void SetButtonsEnabled(bool enabled)
        {
            AutoUpdateButton.IsEnabled = enabled;
            ManualDownloadButton.IsEnabled = enabled;
            RemindLaterButton.IsEnabled = enabled;
            SkipButton.IsEnabled = enabled;
        }

        private static string FormatBytes(long bytes)
        {
            if (bytes <= 0) return "未知";
            string[] units = { "B", "KB", "MB", "GB" };
            var unitIndex = 0;
            double size = bytes;
            while (size >= 1024 && unitIndex < units.Length - 1)
            {
                size /= 1024;
                unitIndex++;
            }
            return $"{size:F1} {units[unitIndex]}";
        }

        protected override void OnClosing(CancelEventArgs e)
        {
            if (_isUpdating)
            {
                e.Cancel = true;
                return;
            }

            _autoUpdater?.Dispose();

            base.OnClosing(e);
            if (!_isClosingHandled && DialogResult != true)
            {
                _isClosingHandled = true;
                SaveRemindLater();
            }
        }

        private void SaveRemindLater()
        {
            try
            {
                _updateSettings.LastCheckTime = DateTime.Now;
                var settingsService = new SettingsService();
                settingsService.SaveUpdateSettingsAsync(_updateSettings).GetAwaiter().GetResult();
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"保存更新设置失败: {ex.Message}");
            }
        }
    }
}