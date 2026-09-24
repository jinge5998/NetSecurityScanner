using System;
using System.ComponentModel;
using System.Windows;
using NetSecurityScanner.Utils;
using NetSecurityScanner.Services;

namespace NetSecurityScanner.Views
{
    public partial class UpdateDialog : Window
    {
        private readonly Models.UpdateInfo _updateInfo;
        private readonly Models.UpdateSettings _updateSettings;
        private bool _isClosingHandled = false;

        public UpdateDialog(Models.UpdateInfo updateInfo, Models.UpdateSettings updateSettings)
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

            if (!string.IsNullOrEmpty(_updateInfo.BaiduDownloadUrl))
            {
                BaiduUrlTextBlock.Text = _updateInfo.BaiduDownloadUrl;
            }
            else
            {
                BaiduUrlTextBlock.Text = UpdatePackageDownloader.DefaultDownloadUrl;
            }

            if (!string.IsNullOrEmpty(_updateInfo.BaiduExtractionCode))
            {
                ExtractionCodeTextBlock.Text = _updateInfo.BaiduExtractionCode;
            }
            else
            {
                ExtractionCodeTextBlock.Text = UpdatePackageDownloader.DefaultExtractionCode;
            }
        }

        private string GetCurrentVersion()
        {
            return VersionHelper.GetVersion();
        }

        private void DownloadButton_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                var url = !string.IsNullOrEmpty(_updateInfo.BaiduDownloadUrl)
                    ? _updateInfo.BaiduDownloadUrl
                    : UpdatePackageDownloader.DefaultDownloadUrl;
                UpdatePackageDownloader.OpenDownloadLink(url);
                DialogResult = true;
            }
            catch (Exception ex)
            {
                MessageBox.Show($"打开下载链接失败：{ex.Message}", "错误", MessageBoxButton.OK, MessageBoxImage.Error);
            }
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
                timer.Tick += (s, args) => { CopyCodeButton.Content = "复制提取码"; timer.Stop(); };
                timer.Start();
            }
            catch { }
        }

        private void CopyAllButton_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                var url = !string.IsNullOrEmpty(_updateInfo.BaiduDownloadUrl)
                    ? _updateInfo.BaiduDownloadUrl
                    : UpdatePackageDownloader.DefaultDownloadUrl;
                var code = !string.IsNullOrEmpty(_updateInfo.BaiduExtractionCode)
                    ? _updateInfo.BaiduExtractionCode
                    : UpdatePackageDownloader.DefaultExtractionCode;
                var allText = $"下载地址：{url}\n提取码：{code}";
                Clipboard.SetText(allText);
                CopyAllButton.Content = "已复制";
                CopyCodeButton.Content = "已复制";
                var timer = new System.Windows.Threading.DispatcherTimer { Interval = TimeSpan.FromSeconds(2) };
                timer.Tick += (s, args) => { CopyAllButton.Content = "复制全部"; CopyCodeButton.Content = "复制提取码"; timer.Stop(); };
                timer.Start();
            }
            catch { }
        }

        protected override void OnClosing(CancelEventArgs e)
        {
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
