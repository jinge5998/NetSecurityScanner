using System;
using System.Linq;
using System.Net;
using System.Text.RegularExpressions;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Threading;
using NetSecurityScanner.Models;
using NetSecurityScanner.Services;

namespace NetSecurityScanner.Desktop.Views
{
    public partial class ComprehensiveScanDialog : Window
    {
        private readonly JsonDatabaseService _db;
        private readonly DispatcherTimer _previewDebounce;

        public ComprehensiveScanDialog()
        {
            InitializeComponent();
            _db = new JsonDatabaseService();
            _previewDebounce = new DispatcherTimer { Interval = TimeSpan.FromMilliseconds(200) };
            _previewDebounce.Tick += (s, e) => { _previewDebounce.Stop(); UpdatePreview(); };
            Loaded += ComprehensiveScanDialog_Loaded;
        }

        private async void ComprehensiveScanDialog_Loaded(object sender, RoutedEventArgs e)
        {
            ApplyPreset(ScanPreset.Standard, "1-1000");
            await LoadLastHistoryAsync();
            UpdatePreview();
        }

        private void PresetCombo_SelectionChanged(object sender, SelectionChangedEventArgs e)
        {
            if (!IsLoaded) return;
            var preset = GetSelectedPreset();
            switch (preset)
            {
                case ScanPreset.Quick:
                    ApplyPreset(preset, "Top100"); break;
                case ScanPreset.Standard:
                    ApplyPreset(preset, "1-1000"); break;
                case ScanPreset.Deep:
                    ApplyPreset(preset, "1-65535"); break;
                case ScanPreset.Web:
                    ApplyPreset(preset, "Web 端口"); break;
                case ScanPreset.Database:
                    ApplyPreset(preset, "Database 端口"); break;
                case ScanPreset.Custom:
                    ApplyPreset(preset, ""); break;
            }
            UpdatePreview();
        }

        private void ApplyPreset(ScanPreset preset, string hint)
        {
            PortRangeTextBox.IsEnabled = preset == ScanPreset.Custom;
            PortRangeTextBox.Text = preset switch
            {
                ScanPreset.Quick => "1-100",
                ScanPreset.Standard => "1-1000",
                ScanPreset.Deep => "1-65535",
                ScanPreset.Web => "80,443,8000,8080,8443,9200",
                ScanPreset.Database => "1433,1521,3306,5432,6379,27017",
                _ => PortRangeTextBox.Text
            };
            PresetHintText.Text = hint;
            _previewDebounce.Stop();
            _previewDebounce.Start();
        }

        private ScanPreset GetSelectedPreset()
        {
            var tag = (PresetCombo.SelectedItem as ComboBoxItem)?.Tag?.ToString();
            return tag switch
            {
                "Quick" => ScanPreset.Quick,
                "Standard" => ScanPreset.Standard,
                "Deep" => ScanPreset.Deep,
                "Web" => ScanPreset.Web,
                "Database" => ScanPreset.Database,
                "Custom" => ScanPreset.Custom,
                _ => ScanPreset.Standard
            };
        }

        private void UpdatePreview()
        {
            try
            {
                var preset = GetSelectedPreset();
                int portCount = 0;
                if (preset == ScanPreset.Custom)
                {
                    try { portCount = ScanPresetRegistry.ParsePortList(PortRangeTextBox.Text ?? "").Count; }
                    catch { portCount = 0; }
                    PortRangeTextBox.Text = PortRangeTextBox.Text ?? "";
                }
                else
                {
                    portCount = ScanPresetRegistry.GetPorts(preset).Count;
                }
                PreviewPortCountText.Text = $"{portCount} 个端口";

                if (int.TryParse(ConcurrencyTextBox.Text, out int conc) && int.TryParse(TimeoutTextBox.Text, out int timeout))
                {
                    var dur = ScanPresetRegistry.EstimateDuration(portCount, conc, timeout);
                    PreviewDurationText.Text = $"预计耗时 ~{(int)dur.TotalSeconds} 秒";
                }
            }
            catch
            {
                PreviewPortCountText.Text = "0 个端口";
                PreviewDurationText.Text = "预计耗时 --";
            }
        }

        private async System.Threading.Tasks.Task LoadLastHistoryAsync()
        {
            try
            {
                var target = TargetIpTextBox.Text?.Trim() ?? "";
                if (string.IsNullOrEmpty(target)) { LastHistoryText.Text = "（暂无历史）"; return; }
                var history = await _db.GetScanHistoryAsync();
                var same = history?
                    .Where(h => string.Equals(h.TargetIp, target, StringComparison.OrdinalIgnoreCase))
                    .OrderByDescending(h => h.ScanTime)
                    .FirstOrDefault();
                if (same == null) { LastHistoryText.Text = "（暂无历史）"; return; }
                LastHistoryText.Text = $"{same.ScanTime:yyyy-MM-dd HH:mm}\n开放端口 {same.OpenPortsCount} / 漏洞 {same.VulnerabilitiesCount} / 风险 {same.RiskLevel}";
            }
            catch
            {
                LastHistoryText.Text = "（暂无历史）";
            }
        }

        private void StartButton_Click(object sender, RoutedEventArgs e)
        {
            ClearError(IpErrorTextBlock);
            ClearError(PortErrorTextBlock);
            ClearError(ProtocolErrorTextBlock);

            var target = TargetIpTextBox.Text?.Trim() ?? "";
            if (string.IsNullOrEmpty(target))
            {
                ShowError(IpErrorTextBlock, "请输入目标 IP 或域名");
                return;
            }
            if (!IsValidTarget(target))
            {
                ShowError(IpErrorTextBlock, "格式无效。请输入 IPv4（如 192.168.1.1）或域名（如 example.com）");
                return;
            }

            var preset = GetSelectedPreset();
            string portText = PortRangeTextBox.Text?.Trim() ?? "";
            if (preset == ScanPreset.Custom)
            {
                if (string.IsNullOrEmpty(portText))
                {
                    ShowError(PortErrorTextBlock, "Custom 模式必须填写端口");
                    return;
                }
                try { ScanPresetRegistry.ParsePortList(portText); }
                catch (Exception ex)
                {
                    ShowError(PortErrorTextBlock, ex.Message);
                    return;
                }
            }

            if (TcpCheckBox.IsChecked != true && UdpCheckBox.IsChecked != true)
            {
                ShowError(ProtocolErrorTextBlock, "请至少选择一种协议（TCP / UDP）");
                return;
            }

            // 校验并发数 / 超时 / 重试
            if (!int.TryParse(ConcurrencyTextBox.Text, out int conc) || conc < 1 || conc > 1000)
            {
                MessageBox.Show("并发数必须是 1-1000 的整数", "参数无效", MessageBoxButton.OK, MessageBoxImage.Warning);
                return;
            }
            if (!int.TryParse(TimeoutTextBox.Text, out int timeout) || timeout < 1 || timeout > 300)
            {
                MessageBox.Show("超时必须是 1-300 秒的整数", "参数无效", MessageBoxButton.OK, MessageBoxImage.Warning);
                return;
            }
            if (!int.TryParse(RetryTextBox.Text, out int retry) || retry < 0 || retry > 3)
            {
                MessageBox.Show("重试次数必须是 0-3 的整数", "参数无效", MessageBoxButton.OK, MessageBoxImage.Warning);
                return;
            }

            DialogResult = true;
            Close();
        }

        private static bool IsValidTarget(string target)
        {
            if (IPAddress.TryParse(target, out _)) return true;
            var domainPattern = @"^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*\.[a-zA-Z]{2,}$";
            return Regex.IsMatch(target, domainPattern);
        }

        /// <summary>由 MainWindow 在 ShowDialog 返回 true 后调用</summary>
        public ComprehensiveScanOptions BuildOptions()
        {
            var preset = GetSelectedPreset();
            int.TryParse(ConcurrencyTextBox.Text, out int conc);
            int.TryParse(TimeoutTextBox.Text, out int timeout);
            int.TryParse(RetryTextBox.Text, out int retry);

            return new ComprehensiveScanOptions
            {
                TargetIp = TargetIpTextBox.Text.Trim(),
                Preset = preset,
                CustomPorts = PortRangeTextBox.Text?.Trim() ?? "",
                EnableTcp = TcpCheckBox.IsChecked == true,
                EnableUdp = UdpCheckBox.IsChecked == true,
                EnableVulnScan = VulnScanCheckBox.IsChecked == true,
                EnablePluginScan = PluginScanCheckBox.IsChecked == true,
                Concurrency = Math.Clamp(conc, 1, 1000),
                TimeoutSeconds = Math.Clamp(timeout, 1, 300),
                RetryCount = Math.Clamp(retry, 0, 3),
                SaveToHistory = SaveHistoryCheckBox.IsChecked == true,
                HostDiscoveryTimeoutMs = 3000
            };
        }

        private void ShowError(TextBlock errorBlock, string message)
        {
            errorBlock.Text = message;
            errorBlock.Visibility = Visibility.Visible;
        }

        private void ClearError(TextBlock errorBlock)
        {
            errorBlock.Text = "";
            errorBlock.Visibility = Visibility.Collapsed;
        }
    }
}
