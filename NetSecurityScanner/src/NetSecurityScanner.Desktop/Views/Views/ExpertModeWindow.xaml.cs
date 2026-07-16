using Microsoft.Win32;
using NetSecurityScanner.Core;
using NetSecurityScanner.Core.Models;
using NetSecurityScanner.Models;
using NetSecurityScanner.Plugins;
using NetSecurityScanner.Services;
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Threading;

namespace NetSecurityScanner.Views
{
    public partial class ExpertModeWindow : Window
    {
        private PortScanner _portScanner;
        private VulnerabilityScanner _vulnerabilityScanner;
        private Plugins.DefaultPlugins.WeakPasswordPlugin _weakPasswordPlugin;
        private CancellationTokenSource _cancellationTokenSource;
        private ExpertScanConfiguration _currentConfig;
        private JsonDatabaseService _jsonDatabaseService;
        private List<PortScanResult> _allPortScanResults;
        private List<VulnerabilityResult> _allVulnResults;
        private int _totalScannedTargets;
        private int _totalOpenPorts;
        private bool _useRustScanner = true; // default to Rust
        private RustScannerClient? _rustClient;
        private PluginScheduler? _scheduler;
        private List<ScanHistoryItem> _scanHistory = new();
        private ScanProfileConfig? _recommendedConfig;
        private string? _recommendReason;
        private DispatcherTimer? _elapsedTimer;
        private DateTime _scanStartTime;

        public ExpertModeWindow()
        {
            try
            {
                InitializeComponent();
                _portScanner = new PortScanner();
                _vulnerabilityScanner = new VulnerabilityScanner();
                _weakPasswordPlugin = new Plugins.DefaultPlugins.WeakPasswordPlugin();
                _ = _weakPasswordPlugin.InitializeAsync(new Dictionary<string, object> { ["Timeout"] = 3000, ["MaxAttempts"] = 3 });
                _jsonDatabaseService = new JsonDatabaseService();
                _allPortScanResults = new List<PortScanResult>();
                _allVulnResults = new List<VulnerabilityResult>();
                this.Loaded += ExpertModeWindow_Loaded;
                this.Closing += ExpertModeWindow_Closing;
                this.Dispatcher.UnhandledException += (s, ex) =>
                {
                    MessageBox.Show($"窗口未处理异常: {ex.Exception.Message}\n\n{ex.Exception.StackTrace}", 
                        "运行时错误", MessageBoxButton.OK, MessageBoxImage.Error);
                    ex.Handled = true;
                };
            }
            catch (Exception ex)
            {
                MessageBox.Show($"初始化专家模式窗口失败: {ex.Message}\n\n{ex.StackTrace}", 
                    "初始化错误", MessageBoxButton.OK, MessageBoxImage.Error);
                throw;
            }
        }

        private void ExpertModeWindow_Loaded(object sender, RoutedEventArgs e)
        {
            try
            {
                InitializeControls();
                RealTimePortResultsDataGrid.MouseDoubleClick += RealTimePortResultsDataGrid_MouseDoubleClick;
                RealTimeVulnResultsDataGrid.MouseDoubleClick += RealTimeVulnResultsDataGrid_MouseDoubleClick;
                LoadDefaultConfig();
                UpdateConfigSummary();
                ParseTargetCount();
                UpdateScanPlanPreview();

                try
                {
                    var exe = RustScannerClient.FindRustScannerExecutable();
                    _useRustScanner = exe != null;
                    RustEngineRadio.IsChecked = _useRustScanner;
                    BuiltInEngineRadio.IsChecked = !_useRustScanner;
                    if (EngineStatusTextBlock != null)
                    {
                        EngineStatusTextBlock.Text = _useRustScanner ? "Rust引擎就绪" : "Rust引擎未找到，将使用内置扫描器";
                        EngineStatusTextBlock.Foreground = _useRustScanner ? new SolidColorBrush(Color.FromRgb(0x27, 0xAE, 0x60)) : new SolidColorBrush(Color.FromRgb(0xE6, 0x7E, 0x22));
                    }
                }
                catch { _useRustScanner = false; }

                TargetInputTextBox.TextChanged += (_, __) =>
                {
                    ParseTargetCount();
                    UpdateScanPlanPreview();
                };

                // Restore last used config
                try
                {
                    var configPath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                        "NetSecurityScanner", "expert_last_config.json");
                    if (File.Exists(configPath))
                    {
                        var json = File.ReadAllText(configPath, Encoding.UTF8);
                        var doc = JsonDocument.Parse(json);
                        if (doc.RootElement.TryGetProperty("Config", out var configElement))
                        {
                            var config = JsonSerializer.Deserialize<ExpertScanConfiguration>(configElement.GetRawText(),
                                new JsonSerializerOptions { PropertyNameCaseInsensitive = true });
                            if (config != null)
                            {
                                ApplyConfig(config);
                                AppendLog("已恢复上次使用的配置");
                            }
                        }
                        if (doc.RootElement.TryGetProperty("SelectedTab", out var tabEl))
                        {
                            var tabIndex = tabEl.GetInt32();
                            if (ExpertTabControl != null && tabIndex >= 0 && tabIndex < ExpertTabControl.Items.Count)
                                ExpertTabControl.SelectedIndex = tabIndex;
                        }
                        if (doc.RootElement.TryGetProperty("UseRustScanner", out var rustEl))
                        {
                            _useRustScanner = rustEl.GetBoolean();
                            if (RustEngineRadio != null) RustEngineRadio.IsChecked = _useRustScanner;
                            if (BuiltInEngineRadio != null) BuiltInEngineRadio.IsChecked = !_useRustScanner;
                        }
                    }
                }
                catch { /* ignore restore errors */ }
            }
            catch (Exception ex)
            {
                MessageBox.Show($"窗口加载时发生错误: {ex.Message}\n\n{ex.StackTrace}",
                    "加载错误", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        private void InitializeControls()
        {
            try
            {
                TcpConcurrencySlider.ValueChanged += (s, e) => { if (TcpConcurrencyValueTextBlock != null) TcpConcurrencyValueTextBlock.Text = ((int)TcpConcurrencySlider.Value).ToString(); };
                UdpConcurrencySlider.ValueChanged += (s, e) => { if (UdpConcurrencyValueTextBlock != null) UdpConcurrencyValueTextBlock.Text = ((int)UdpConcurrencySlider.Value).ToString(); };
                TcpTimeoutSlider.ValueChanged += (s, e) => { if (TcpTimeoutValueTextBlock != null) TcpTimeoutValueTextBlock.Text = $"{(int)TcpTimeoutSlider.Value}ms"; };
                UdpTimeoutSlider.ValueChanged += (s, e) => { if (UdpTimeoutValueTextBlock != null) UdpTimeoutValueTextBlock.Text = $"{(int)UdpTimeoutSlider.Value}ms"; };
                RetrySlider.ValueChanged += (s, e) => { if (RetryValueTextBlock != null) RetryValueTextBlock.Text = ((int)RetrySlider.Value).ToString(); };
                PacketRateSlider.ValueChanged += (s, e) => { if (PacketRateValueTextBlock != null) PacketRateValueTextBlock.Text = $"{(int)PacketRateSlider.Value} pps"; };
                if (ServiceDetectTimeoutSlider != null)
                {
                    ServiceDetectTimeoutSlider.ValueChanged += (s, e) => { if (ServiceDetectTimeoutValueTextBlock != null) ServiceDetectTimeoutValueTextBlock.Text = $"{(int)ServiceDetectTimeoutSlider.Value}ms"; };
                }

                CommonPortsRadio.Checked += (s, e) => { if (CustomPortsTextBox != null) CustomPortsTextBox.IsEnabled = false; };
                CustomPortsRadio.Checked += (s, e) => { if (CustomPortsTextBox != null) CustomPortsTextBox.IsEnabled = true; };

                if (ScheduleModeComboBox != null)
                    ScheduleModeComboBox.SelectionChanged += ScheduleModeComboBox_SelectionChanged;
            }
            catch (Exception ex)
            {
                MessageBox.Show($"控件初始化失败: {ex.Message}", "初始化错误", MessageBoxButton.OK, MessageBoxImage.Warning);
            }
        }

        private void LoadDefaultConfig()
        {
            _currentConfig = new ExpertScanConfiguration();
        }

        private void TargetTypeRadio_Checked(object sender, RoutedEventArgs e)
        {
            if (TargetHintTextBlock == null)
                return;

            if (SingleIpRadio?.IsChecked == true)
            {
                TargetHintTextBlock.Text = "提示：输入单个IP地址，如 192.168.1.1 或 www.example.com";
            }
            else if (IpRangeRadio?.IsChecked == true)
            {
                TargetHintTextBlock.Text = "提示：输入IP段范围，如 192.168.1.1-192.168.1.254";
            }
            else if (CidrRadio?.IsChecked == true)
            {
                TargetHintTextBlock.Text = "提示：输入CIDR格式，如 192.168.1.0/24";
            }
            else if (FileRadio?.IsChecked == true)
            {
                TargetHintTextBlock.Text = "提示：点击导入文件按钮加载目标列表文件（每行一个IP）";
            }
            else if (RegexRadio?.IsChecked == true)
            {
                TargetHintTextBlock.Text = "提示：输入正则表达式模式，如 192\\.168\\.1\\.[0-9]+";
            }
            ParseTargetCount();
        }

        private void ScanEngineRadio_Checked(object sender, RoutedEventArgs e)
        {
            if (EngineStatusTextBlock == null) return;
            _useRustScanner = RustEngineRadio?.IsChecked == true;
            try
            {
                if (_useRustScanner)
                {
                    var exe = RustScannerClient.FindRustScannerExecutable();
                    EngineStatusTextBlock.Text = exe != null ? "Rust引擎就绪" : "Rust引擎未找到，将降级为内置扫描器";
                    EngineStatusTextBlock.Foreground = exe != null ? new SolidColorBrush(Color.FromRgb(0x27, 0xAE, 0x60)) : new SolidColorBrush(Color.FromRgb(0xE6, 0x7E, 0x22));
                }
                else
                {
                    EngineStatusTextBlock.Text = "使用内置C#扫描引擎";
                    EngineStatusTextBlock.Foreground = new SolidColorBrush(Color.FromRgb(0x34, 0x98, 0xDB));
                }
            }
            catch
            {
                EngineStatusTextBlock.Text = "Rust引擎状态未知";
                EngineStatusTextBlock.Foreground = new SolidColorBrush(Color.FromRgb(0xE6, 0x7E, 0x22));
            }
            UpdateScanPlanPreview();
        }

        private void ParseTargetCount()
        {
            try
            {
                if (TargetInputTextBox == null || TargetCountTextBlock == null)
                    return;

                var input = TargetInputTextBox.Text?.Trim() ?? "";
                int count = 0;

                if (string.IsNullOrEmpty(input))
                {
                    count = 0;
                }
                else if (SingleIpRadio?.IsChecked == true || RegexRadio?.IsChecked == true)
                {
                    count = string.IsNullOrWhiteSpace(input) ? 0 : 1;
                }
                else if (IpRangeRadio?.IsChecked == true)
                {
                    var parts = input.Split('-');
                    if (parts.Length == 2 && System.Net.IPAddress.TryParse(parts[0].Trim(), out _) && System.Net.IPAddress.TryParse(parts[1].Trim(), out _))
                    {
                        long start = IPToLong(parts[0].Trim());
                        long end = IPToLong(parts[1].Trim());
                        count = (int)(end - start + 1);
                        if (count > 65536) count = 65536;
                    }
                    else
                    {
                        count = 0;
                    }
                }
                else if (CidrRadio?.IsChecked == true)
                {
                    if (input.Contains('/'))
                    {
                        var parts = input.Split('/');
                        if (int.TryParse(parts[1], out int prefix))
                        {
                            int hostBits = 32 - prefix;
                            count = (int)Math.Pow(2, hostBits);
                        }
                    }
                }
                else if (FileRadio?.IsChecked == true)
                {
                    count = input.Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries).Length;
                }
                else
                {
                    count = input.Split(new[] { ',', '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries).Length;
                }

                TargetCountTextBlock.Text = $"目标数量: {count}";
            }
            catch
            {
                if (TargetCountTextBlock != null)
                    TargetCountTextBlock.Text = "目标数量: -";
            }
        }

        private long IPToLong(string ip)
        {
            var bytes = System.Net.IPAddress.Parse(ip).GetAddressBytes();
            return (long)bytes[0] << 24 | (long)bytes[1] << 16 | (long)bytes[2] << 8 | bytes[3];
        }

        private void ImportFileButton_Click(object sender, RoutedEventArgs e)
        {
            var dialog = new OpenFileDialog
            {
                Filter = "文本文件 (*.txt;*.csv)|*.txt;*.csv|所有文件 (*.*)|*.*",
                Title = "导入目标列表"
            };

            if (dialog.ShowDialog() == true)
            {
                try
                {
                    var lines = File.ReadAllLines(dialog.FileName);
                    var targets = lines.Where(l => !string.IsNullOrWhiteSpace(l)).Select(l => l.Trim()).ToList();
                    TargetInputTextBox.Text = string.Join(Environment.NewLine, targets);
                    FileRadio.IsChecked = true;
                    ParseTargetCount();
                    MessageBox.Show($"成功导入 {targets.Count} 个目标", "导入成功", MessageBoxButton.OK, MessageBoxImage.Information);
                }
                catch (Exception ex)
                {
                    MessageBox.Show($"导入文件失败: {ex.Message}", "错误", MessageBoxButton.OK, MessageBoxImage.Error);
                }
            }
        }

        private void BrowseOutputButton_Click(object sender, RoutedEventArgs e)
        {
            var dialog = new Microsoft.Win32.OpenFileDialog
            {
                Title = "选择输出目录",
                FileName = "placeholder",
                CheckFileExists = false,
                CheckPathExists = true,
                ValidateNames = false
            };

            if (dialog.ShowDialog() == true)
            {
                var dir = System.IO.Path.GetDirectoryName(dialog.FileName);
                if (!string.IsNullOrEmpty(dir))
                {
                    OutputDirTextBox.Text = dir;
                }
            }
        }

        private void LoadPresetButton_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                var presetDir = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                    "NetSecurityScanner", "expert_presets");
                if (!Directory.Exists(presetDir))
                {
                    MessageBox.Show("暂无已保存的预设", "提示", MessageBoxButton.OK, MessageBoxImage.Information);
                    return;
                }

                var files = Directory.GetFiles(presetDir, "*.json");
                if (files.Length == 0)
                {
                    MessageBox.Show("暂无已保存的预设", "提示", MessageBoxButton.OK, MessageBoxImage.Information);
                    return;
                }

                var presetList = new Dictionary<string, string>();
                foreach (var f in files)
                    presetList[Path.GetFileNameWithoutExtension(f)] = f;

                // Show selection dialog
                var dialog = new Window
                {
                    Title = "加载预设",
                    Width = 400,
                    Height = 350,
                    WindowStartupLocation = WindowStartupLocation.CenterOwner,
                    Owner = this,
                    ResizeMode = ResizeMode.NoResize
                };
                var panel = new StackPanel { Margin = new Thickness(15) };
                panel.Children.Add(new TextBlock { Text = "选择要加载的预设:", FontSize = 14, FontWeight = FontWeights.Bold, Margin = new Thickness(0, 0, 0, 10) });
                var listBox = new ListBox { Height = 200 };
                foreach (var name in presetList.Keys)
                    listBox.Items.Add(name);
                panel.Children.Add(listBox);
                var btnPanel = new StackPanel { Orientation = Orientation.Horizontal, HorizontalAlignment = HorizontalAlignment.Right, Margin = new Thickness(0, 10, 0, 0) };
                var loadBtn = new Button { Content = "加载", Width = 80, Height = 30, Background = new SolidColorBrush(Color.FromRgb(0x27, 0xAE, 0x60)), Foreground = Brushes.White, BorderThickness = new Thickness(0), Margin = new Thickness(5, 0, 0, 0) };
                var deleteBtn = new Button { Content = "删除", Width = 80, Height = 30, Background = new SolidColorBrush(Color.FromRgb(0xE7, 0x4C, 0x3C)), Foreground = Brushes.White, BorderThickness = new Thickness(0), Margin = new Thickness(5, 0, 0, 0) };
                var cancelBtn = new Button { Content = "取消", Width = 80, Height = 30, Margin = new Thickness(5, 0, 0, 0) };
                btnPanel.Children.Add(loadBtn);
                btnPanel.Children.Add(deleteBtn);
                btnPanel.Children.Add(cancelBtn);
                panel.Children.Add(btnPanel);
                dialog.Content = panel;

                loadBtn.Click += (_, __) =>
                {
                    if (listBox.SelectedItem == null) return;
                    var name = listBox.SelectedItem.ToString()!;
                    var path = presetList[name];
                    var json = File.ReadAllText(path, Encoding.UTF8);
                    var config = JsonSerializer.Deserialize<ExpertScanConfiguration>(json, new JsonSerializerOptions { PropertyNameCaseInsensitive = true });
                    if (config != null)
                    {
                        ApplyConfig(config);
                        UpdateConfigSummary();
                        AppendLog($"已加载预设: {name}");
                    }
                    dialog.DialogResult = true;
                    dialog.Close();
                };
                deleteBtn.Click += (_, __) =>
                {
                    if (listBox.SelectedItem == null) return;
                    var name = listBox.SelectedItem.ToString()!;
                    if (MessageBox.Show($"确认删除预设 \"{name}\"？", "确认", MessageBoxButton.YesNo, MessageBoxImage.Question) == MessageBoxResult.Yes)
                    {
                        File.Delete(presetList[name]);
                        listBox.Items.Remove(name);
                        presetList.Remove(name);
                        AppendLog($"已删除预设: {name}");
                    }
                };
                cancelBtn.Click += (_, __) => dialog.Close();

                dialog.ShowDialog();
            }
            catch (Exception ex)
            {
                MessageBox.Show($"加载预设失败: {ex.Message}", "错误", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        private void SavePresetButton_Click(object sender, RoutedEventArgs e)
        {
            // Custom input dialog
            var inputDialog = new Window
            {
                Title = "保存预设",
                Width = 400,
                Height = 180,
                WindowStartupLocation = WindowStartupLocation.CenterOwner,
                Owner = this,
                ResizeMode = ResizeMode.NoResize
            };
            var panel = new StackPanel { Margin = new Thickness(15) };
            panel.Children.Add(new TextBlock { Text = "请输入预设名称:", FontSize = 14, FontWeight = FontWeights.Bold, Margin = new Thickness(0, 0, 0, 10) });
            var inputBox = new TextBox { Text = $"自定义预设_{DateTime.Now:yyyyMMdd_HHmmss}", Height = 28, BorderBrush = new SolidColorBrush(Color.FromRgb(0xBD, 0xC3, 0xC7)), BorderThickness = new Thickness(1) };
            inputBox.SelectAll();
            panel.Children.Add(inputBox);
            var btnPanel = new StackPanel { Orientation = Orientation.Horizontal, HorizontalAlignment = HorizontalAlignment.Right, Margin = new Thickness(0, 15, 0, 0) };
            var saveBtn = new Button { Content = "保存", Width = 80, Height = 30, Background = new SolidColorBrush(Color.FromRgb(0x27, 0xAE, 0x60)), Foreground = Brushes.White, BorderThickness = new Thickness(0), Margin = new Thickness(5, 0, 0, 0) };
            var cancelBtn = new Button { Content = "取消", Width = 80, Height = 30, Margin = new Thickness(5, 0, 0, 0) };
            btnPanel.Children.Add(saveBtn);
            btnPanel.Children.Add(cancelBtn);
            panel.Children.Add(btnPanel);
            inputDialog.Content = panel;

            saveBtn.Click += (_, __) =>
            {
                var input = inputBox.Text?.Trim() ?? "";
                if (string.IsNullOrWhiteSpace(input)) return;

                try
                {
                    var config = CollectConfig();
                    var presetDir = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                        "NetSecurityScanner", "expert_presets");
                    Directory.CreateDirectory(presetDir);
                    var safeName = string.Join("_", input.Split(Path.GetInvalidFileNameChars()));
                    var filePath = Path.Combine(presetDir, $"{safeName}.json");
                    var json = JsonSerializer.Serialize(config, new JsonSerializerOptions { WriteIndented = true });
                    File.WriteAllText(filePath, json, Encoding.UTF8);
                    MessageBox.Show($"预设已保存: {input}", "保存成功", MessageBoxButton.OK, MessageBoxImage.Information);
                    AppendLog($"已保存预设: {input}");
                }
                catch (Exception ex)
                {
                    MessageBox.Show($"保存预设失败: {ex.Message}", "错误", MessageBoxButton.OK, MessageBoxImage.Error);
                }
                inputDialog.DialogResult = true;
                inputDialog.Close();
            };
            cancelBtn.Click += (_, __) => inputDialog.Close();

            inputDialog.ShowDialog();
        }

        private ExpertScanConfiguration CollectConfig()
        {
            var config = new ExpertScanConfiguration();

            // Target type
            if (SingleIpRadio?.IsChecked == true) config.TargetType = "Single";
            else if (IpRangeRadio?.IsChecked == true) config.TargetType = "Range";
            else if (CidrRadio?.IsChecked == true) config.TargetType = "CIDR";
            else if (FileRadio?.IsChecked == true) config.TargetType = "File";
            else if (RegexRadio?.IsChecked == true) config.TargetType = "Regex";

            config.TargetValue = TargetInputTextBox?.Text?.Trim() ?? "";
            config.ReverseDns = ReverseDnsCheckBox?.IsChecked == true;
            config.HostDiscovery = HostDiscoveryCheckBox?.IsChecked == true;
            config.ExcludeHosts = ExcludeHostsTextBox?.Text?.Trim() ?? "";

            // Port settings
            if (CommonPortsRadio?.IsChecked == true) config.PortMode = "Common";
            else if (SensitivePortsRadio?.IsChecked == true) config.PortMode = "Sensitive";
            else if (AllPortsRadio?.IsChecked == true) config.PortMode = "All";
            else if (CustomPortsRadio?.IsChecked == true) config.PortMode = "Custom";

            config.CustomPorts = CustomPortsTextBox?.Text?.Trim() ?? "";
            config.TcpScan = TcpScanCheckBox?.IsChecked == true;
            config.UdpScan = UdpScanCheckBox?.IsChecked == true;
            config.SynScan = SynScanCheckBox?.IsChecked == true;
            config.ServiceDetection = ServiceVersionCheckBox?.IsChecked == true;
            config.OsDetection = OsDetectCheckBox?.IsChecked == true;
            config.ScriptScan = ScriptScanCheckBox?.IsChecked == true;
            config.ServiceIntensity = ServiceIntensityComboBox?.SelectedIndex ?? 1;
            config.ExcludePorts = ExcludePortsTextBox?.Text?.Trim() ?? "";

            // Performance
            config.TcpConcurrency = (int)(TcpConcurrencySlider?.Value ?? 50);
            config.UdpConcurrency = (int)(UdpConcurrencySlider?.Value ?? 20);
            config.TcpTimeout = (int)(TcpTimeoutSlider?.Value ?? 500);
            config.UdpTimeout = (int)(UdpTimeoutSlider?.Value ?? 1000);
            config.RetryCount = (int)(RetrySlider?.Value ?? 1);
            config.ServiceDetectTimeout = (int)(ServiceDetectTimeoutSlider?.Value ?? 2000);

            // Rate limit
            config.RateLimit = RateLimitCheckBox?.IsChecked == true;
            config.PacketRate = (int)(PacketRateSlider?.Value ?? 1000);
            config.Randomize = RandomizeCheckBox?.IsChecked == true;
            config.StealthMode = StealthModeCheckBox?.IsChecked == true;
            config.RandomPortOrder = RandomPortOrderCheckBox?.IsChecked == true;

            // Update RandomTargetOrder from new checkbox too
            if (RandomTargetOrderCheckBox?.IsChecked == true)
                config.Randomize = true;

            // Advanced
            config.SourcePort = SourcePortTextBox?.Text?.Trim() ?? "";
            config.Mtu = MtuTextBox?.Text?.Trim() ?? "1500";
            config.FragmentPackets = FragmentPacketsCheckBox?.IsChecked == true;
            config.BadChecksum = BadChecksumCheckBox?.IsChecked == true;
            config.DecoyScan = DecoyScanCheckBox?.IsChecked == true;
            config.DecoyIps = DecoyIpsTextBox?.Text?.Trim() ?? "";
            config.IdleScan = IdleScanCheckBox?.IsChecked == true;
            config.ZombieHost = ZombieHostTextBox?.Text?.Trim() ?? "";
            config.SourceRouting = SourceRoutingCheckBox?.IsChecked == true;
            config.Verbosity = VerbosityComboBox?.SelectedIndex ?? 1;
            config.SaveOutput = SaveOutputCheckBox?.IsChecked == true;
            config.OutputDir = OutputDirTextBox?.Text?.Trim() ?? "";

            return config;
        }

        private void ApplyConfig(ExpertScanConfiguration config)
        {
            _currentConfig = config;

            // Apply target settings
            switch (config.TargetType)
            {
                case "Single": SingleIpRadio.IsChecked = true; break;
                case "Range": IpRangeRadio.IsChecked = true; break;
                case "CIDR": CidrRadio.IsChecked = true; break;
                case "File": FileRadio.IsChecked = true; break;
                case "Regex": RegexRadio.IsChecked = true; break;
            }
            TargetInputTextBox.Text = config.TargetValue;
            ReverseDnsCheckBox.IsChecked = config.ReverseDns;
            HostDiscoveryCheckBox.IsChecked = config.HostDiscovery;
            ExcludeHostsTextBox.Text = config.ExcludeHosts;

            // Apply port settings
            switch (config.PortMode)
            {
                case "Common": CommonPortsRadio.IsChecked = true; break;
                case "Sensitive": SensitivePortsRadio.IsChecked = true; break;
                case "All": AllPortsRadio.IsChecked = true; break;
                case "Custom": CustomPortsRadio.IsChecked = true; break;
            }
            CustomPortsTextBox.Text = config.CustomPorts;
            TcpScanCheckBox.IsChecked = config.TcpScan;
            UdpScanCheckBox.IsChecked = config.UdpScan;
            SynScanCheckBox.IsChecked = config.SynScan;
            ServiceVersionCheckBox.IsChecked = config.ServiceDetection;
            OsDetectCheckBox.IsChecked = config.OsDetection;
            ScriptScanCheckBox.IsChecked = config.ScriptScan;
            if (config.ServiceIntensity >= 0 && config.ServiceIntensity <= 4)
                ServiceIntensityComboBox.SelectedIndex = config.ServiceIntensity;
            ExcludePortsTextBox.Text = config.ExcludePorts;

            // Apply performance settings
            TcpConcurrencySlider.Value = config.TcpConcurrency;
            UdpConcurrencySlider.Value = config.UdpConcurrency;
            TcpTimeoutSlider.Value = config.TcpTimeout;
            UdpTimeoutSlider.Value = config.UdpTimeout;
            RetrySlider.Value = config.RetryCount;
            if (ServiceDetectTimeoutSlider != null)
                ServiceDetectTimeoutSlider.Value = config.ServiceDetectTimeout;
            RateLimitCheckBox.IsChecked = config.RateLimit;
            PacketRateSlider.Value = config.PacketRate;
            RandomizeCheckBox.IsChecked = config.Randomize;
            StealthModeCheckBox.IsChecked = config.StealthMode;
            if (RandomPortOrderCheckBox != null)
                RandomPortOrderCheckBox.IsChecked = config.RandomPortOrder;
            if (RandomTargetOrderCheckBox != null)
                RandomTargetOrderCheckBox.IsChecked = config.Randomize;

            // Apply advanced settings
            SourcePortTextBox.Text = config.SourcePort;
            MtuTextBox.Text = config.Mtu;
            FragmentPacketsCheckBox.IsChecked = config.FragmentPackets;
            BadChecksumCheckBox.IsChecked = config.BadChecksum;
            DecoyScanCheckBox.IsChecked = config.DecoyScan;
            DecoyIpsTextBox.Text = config.DecoyIps;
            IdleScanCheckBox.IsChecked = config.IdleScan;
            ZombieHostTextBox.Text = config.ZombieHost;
            SourceRoutingCheckBox.IsChecked = config.SourceRouting;
            if (config.Verbosity >= 0 && config.Verbosity <= 3)
                VerbosityComboBox.SelectedIndex = config.Verbosity;
            SaveOutputCheckBox.IsChecked = config.SaveOutput;
            OutputDirTextBox.Text = config.OutputDir;

            UpdateConfigSummary();
            ParseTargetCount();
        }

        private void UpdateConfigSummary()
        {
            try
            {
                if (TcpConcurrencySlider == null)
                    return;

                // 更新扫描计划预览
                UpdateScanPlanPreview();
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"[ExpertModeWindow] 更新配置摘要失败: {ex.Message}");
            }
        }

        private void StartExpertScanButton_Click(object sender, RoutedEventArgs e)
        {
            var config = CollectConfig();

            if (string.IsNullOrWhiteSpace(config.TargetValue))
            {
                MessageBox.Show("请输入扫描目标", "输入错误", MessageBoxButton.OK, MessageBoxImage.Warning);
                return;
            }

            _currentConfig = config;

            // Pre-check target count
            var preTargets = ResolveTargets(config);
            if (preTargets.Count > 256)
            {
                var warn = MessageBox.Show(
                    $"目标数量较多({preTargets.Count}个)，扫描可能耗时较长。\n\n是否继续？",
                    "目标数量警告", MessageBoxButton.YesNo, MessageBoxImage.Warning);
                if (warn == MessageBoxResult.No) return;
            }

            var confirmResult = MessageBox.Show(
                $"即将开始专家模式扫描\n\n" +
                $"目标: {config.TargetValue}\n" +
                $"端口模式: {GetPortModeText()}\n" +
                $"TCP并发: {config.TcpConcurrency}, UDP并发: {config.UdpConcurrency}\n" +
                $"TCP超时: {config.TcpTimeout}ms, UDP超时: {config.UdpTimeout}ms\n\n" +
                $"是否确认开始扫描？",
                "确认扫描",
                MessageBoxButton.YesNo,
                MessageBoxImage.Question
            );

            if (confirmResult == MessageBoxResult.No)
                return;

            _cancellationTokenSource = new CancellationTokenSource();
            _scanStartTime = DateTime.Now;
            _elapsedTimer = new DispatcherTimer { Interval = TimeSpan.FromSeconds(1) };
            _elapsedTimer.Tick += (s, e) =>
            {
                var elapsed = DateTime.Now - _scanStartTime;
                if (ElapsedTextBlock != null)
                    ElapsedTextBlock.Text = $"已用: {elapsed:hh\\:mm\\:ss}";
                if (_totalScannedTargets > 0 && ExpertScanProgressBar.Value > 0)
                {
                    var progress = ExpertScanProgressBar.Value / 100.0;
                    if (progress > 0.01)
                    {
                        var remaining = TimeSpan.FromTicks((long)(elapsed.Ticks / progress * (1 - progress)));
                        if (RemainingTextBlock != null)
                            RemainingTextBlock.Text = $"预计剩余: {remaining:hh\\:mm\\:ss}";
                    }
                }
            };
            _elapsedTimer.Start();

            // Auto-switch to results tab
            if (ExpertTabControl != null)
                ExpertTabControl.SelectedIndex = 4; // "实时结果" tab (0-indexed)

            StartExpertScanButton.IsEnabled = false;
            StartExpertScanButton.Content = "⏳ 扫描中...";
            CancelExpertButton.IsEnabled = true;

            Task.Run(async () => await ExecuteExpertScanAsync(config, _cancellationTokenSource.Token));
        }

        private string GetPortModeText()
        {
            if (AllPortsRadio.IsChecked == true) return "全部端口(1-65535)";
            if (SensitivePortsRadio.IsChecked == true) return "敏感端口";
            if (CustomPortsRadio.IsChecked == true) return "自定义端口";
            return "常用端口(Top 1000)";
        }

        private async Task ExecuteExpertScanAsync(ExpertScanConfiguration config, CancellationToken cancellationToken)
        {
            try
            {
                config.StartTime = DateTime.Now;
                _allPortScanResults = new List<PortScanResult>();
                _allVulnResults = new List<VulnerabilityResult>();
                _totalScannedTargets = 0;
                _totalOpenPorts = 0;

                var scanOptions = new ScanOptions
                {
                    MaxConcurrency = config.StealthMode ? Math.Min(config.TcpConcurrency, 20) : config.TcpConcurrency,
                    Timeout = config.TcpTimeout,
                    RetryCount = config.RetryCount,
                    EnableServiceDetection = config.ServiceDetection,
                    EnableOsDetection = config.OsDetection,
                    ScanType = config.TcpScan ? "TCP" : "UDP"
                };

                if (config.StealthMode)
                {
                    AppendLog("⚠️ Stealth模式已启用：并发数限制为≤20，建议配合速率限制使用");
                }

                var targets = ResolveTargets(config);
                if (targets.Count == 0)
                {
                    Dispatcher.Invoke(() =>
                    {
                        MessageBox.Show("无法解析目标地址", "错误", MessageBoxButton.OK, MessageBoxImage.Error);
                        ResetScanButtons();
                    });
                    return;
                }

                var ports = ResolvePorts(config);
                if (ports.Count == 0)
                {
                    Dispatcher.Invoke(() =>
                    {
                        MessageBox.Show("未配置有效的端口列表", "错误", MessageBoxButton.OK, MessageBoxImage.Error);
                        ResetScanButtons();
                    });
                    return;
                }

                // 初始化实时结果显示
                Dispatcher.Invoke(() =>
                {
                    TotalTargetsStat.Text = targets.Count.ToString();
                    ScannedTargetsStat.Text = "0";
                    OpenPortsStat.Text = "0";
                    VulnerabilitiesStat.Text = "0";
                    ExpertScanProgressBar.Value = 0;
                    ExpertScanProgressText.Text = "准备扫描...";
                    RealTimePortResultsDataGrid.ItemsSource = _allPortScanResults;
                    RealTimeVulnResultsDataGrid.ItemsSource = _allVulnResults;
                    StartExpertScanButton.Content = $"⏳ 扫描中: {0}/{targets.Count}";
                });

                AppendLog($"开始专家模式扫描: {targets.Count} 个目标");
                AppendLog($"扫描模式: TCP={config.TcpScan}, UDP={config.UdpScan}, 服务检测={config.ServiceDetection}");
                AppendLog($"端口范围: {ports.Count} 个端口 (并发: TCP={config.TcpConcurrency}, UDP={config.UdpConcurrency})");

                int completedCount = 0;
                foreach (var target in targets)
                {
                    if (cancellationToken.IsCancellationRequested)
                        break;

                    Dispatcher.Invoke(() =>
                    {
                        StartExpertScanButton.Content = $"⏳ 扫描中: {target} ({completedCount}/{targets.Count})";
                        ExpertScanProgressText.Text = $"扫描中: {target} ({completedCount + 1}/{targets.Count})";
                    });

                    AppendLog($"[{completedCount + 1}/{targets.Count}] 开始扫描目标: {target}");

                    try
                    {
                        List<PortScanResult> allResults;
                        if (_useRustScanner)
                        {
                            allResults = await ExecuteRustScanAsync(target, ports, config, cancellationToken);
                        }
                        else
                        {
                            var progress = new Progress<int>(p => { });
                            allResults = await ExecuteNativeScanAsync(target, ports, config, progress, cancellationToken);
                        }

                        var openCount = allResults.Count(r => r.Status == "开放");
                        AppendLog($"  目标 {target} 扫描完成: {openCount}/{allResults.Count} 个端口开放");

                        // 实时更新端口扫描结果
                        var openPorts = allResults.Where(r => r.Status == "开放").ToList();
                        Dispatcher.Invoke(() =>
                        {
                            foreach (var result in allResults)
                            {
                                result.TargetIp = target;
                                _allPortScanResults.Add(result);
                            }
                            RealTimePortResultsDataGrid.Items.Refresh();
                            
                            // 更新统计
                            _totalScannedTargets++;
                            _totalOpenPorts += openPorts.Count;
                            ScannedTargetsStat.Text = _totalScannedTargets.ToString();
                            OpenPortsStat.Text = _totalOpenPorts.ToString();
                            
                            // 更新进度条
                            ExpertScanProgressBar.Value = (double)_totalScannedTargets / targets.Count * 100;
                            ExpertScanProgressText.Text = $"扫描中: {_totalScannedTargets}/{targets.Count} 目标";
                        });

                        // 漏洞扫描
                        if (config.ScriptScan && openPorts.Any())
                        {
                            AppendLog($"  开始漏洞扫描: {target} ({openPorts.Count} 个开放端口)...");
                            var vulnResults = await _vulnerabilityScanner.ScanVulnerabilitiesAsync(target, openPorts, cancellationToken);
                            
                            // 实时更新漏洞扫描结果
                            Dispatcher.Invoke(() =>
                            {
                                foreach (var vuln in vulnResults)
                                {
                                    _allVulnResults.Add(vuln);
                                }
                                RealTimeVulnResultsDataGrid.Items.Refresh();
                                VulnerabilitiesStat.Text = _allVulnResults.Count.ToString();
                            });

                            AppendLog($"  漏洞扫描完成: 发现 {vulnResults.Count} 个漏洞");
                        }
                        else if (config.ScriptScan)
                        {
                            AppendLog($"  跳过漏洞扫描: 无开放端口");
                        }

                        // 弱口令扫描
                        var weakPassPorts = openPorts.Where(p =>
                            p.PortNumber == 21 || p.PortNumber == 22 || p.PortNumber == 23 ||
                            p.PortNumber == 3306 || p.PortNumber == 6379 || p.PortNumber == 27017).ToList();
                        if (weakPassPorts.Any())
                        {
                            AppendLog($"  开始弱口令检测: {target} ({weakPassPorts.Count} 个相关端口)...");
                            var weakPassResults = new List<VulnerabilityResult>();
                            foreach (var wp in weakPassPorts)
                            {
                                if (cancellationToken.IsCancellationRequested) break;
                                try
                                {
                                    var ctx = new ScanContext
                                    {
                                        Target = target,
                                        Port = wp.PortNumber,
                                        ServiceName = wp.Service ?? "",
                                        Timeout = 3000
                                    };
                                    var wpResults = await _weakPasswordPlugin.ScanAsync(ctx, cancellationToken);
                                    weakPassResults.AddRange(wpResults);
                                }
                                catch (Exception wpEx)
                                {
                                    AppendLog($"  弱口令检测端口 {wp.PortNumber} 异常: {wpEx.Message}");
                                }
                            }

                            if (weakPassResults.Any())
                            {
                                Dispatcher.Invoke(() =>
                                {
                                    foreach (var vuln in weakPassResults)
                                    {
                                        _allVulnResults.Add(vuln);
                                    }
                                    RealTimeVulnResultsDataGrid.Items.Refresh();
                                    VulnerabilitiesStat.Text = _allVulnResults.Count.ToString();
                                });
                            }

                            AppendLog($"  弱口令检测完成: 发现 {weakPassResults.Count} 个弱口令/未授权访问漏洞");
                        }

                        // Save to scan history database
                        var scanResult = new CompleteScanResult
                        {
                            TargetIp = target,
                            ScanType = $"专家模式-{"TCP" + (config.UdpScan ? "+UDP" : "")}扫描",
                            ScanTime = DateTime.Now,
                            ScanDuration = (DateTime.Now - config.StartTime).TotalSeconds,
                            OpenPortsCount = openPorts.Count,
                            VulnerabilitiesCount = _allVulnResults.Count,
                            RiskLevel = openPorts.Count > 10 ? "中" : "低",
                            PortScanResults = allResults,
                            VulnerabilityResults = _allVulnResults,
                            RiskAssessment = new RiskAssessmentSummary
                            {
                                TotalVulnerabilities = _allVulnResults.Count,
                                RiskScore = Math.Min(100, openPorts.Count * 5 + _allVulnResults.Count * 10),
                                RiskLevel = _allVulnResults.Count > 5 ? "高风险" : (openPorts.Count > 10 ? "中风险" : "低风险"),
                                SecurityAdvice = $"专家模式扫描完成，发现 {openPorts.Count} 个开放端口和 {_allVulnResults.Count} 个漏洞。建议对高危端口和漏洞进行安全加固。"
                            }
                        };
                        
                        // Save to history database
                        try
                        {
                            await _jsonDatabaseService.SaveScanResultAsync(scanResult);
                        }
                        catch (Exception saveEx)
                        {
                            Console.WriteLine($"保存扫描历史记录失败: {saveEx.Message}");
                        }

                        // Save results to file
                        if (config.SaveOutput && !string.IsNullOrWhiteSpace(config.OutputDir))
                        {
                            var safeFileName = target.Replace(".", "_").Replace("/", "_");
                            var filePath = Path.Combine(config.OutputDir, $"expert_scan_{safeFileName}_{DateTime.Now:yyyyMMdd_HHmmss}.json");
                            Directory.CreateDirectory(Path.GetDirectoryName(filePath));
                            var json = JsonSerializer.Serialize(allResults, new JsonSerializerOptions { WriteIndented = true });
                            File.WriteAllText(filePath, json);
                        }

                        completedCount++;
                    }
                    catch (OperationCanceledException)
                    {
                        break;
                    }
                    catch (Exception ex)
                    {
                        Dispatcher.Invoke(() =>
                        {
                            MessageBox.Show($"扫描 {target} 时出错: {ex.Message}", "扫描错误", MessageBoxButton.OK, MessageBoxImage.Warning);
                        });
                    }
                }

                // 判断是否被取消
                bool wasCancelled = cancellationToken.IsCancellationRequested;

                Dispatcher.Invoke(() =>
                {
                    StartExpertScanButton.Content = "🚀 开始专家扫描";
                    StartExpertScanButton.IsEnabled = true;
                    CancelExpertButton.IsEnabled = false;
                    CancelExpertButton.Content = "❌ 取消";

                    if (wasCancelled)
                    {
                        ExpertScanProgressText.Text = $"已取消 - 扫描了 {completedCount}/{targets.Count} 个目标";
                        MessageBox.Show($"扫描已取消！\n共扫描 {completedCount}/{targets.Count} 个目标\n发现 {_totalOpenPorts} 个开放端口\n发现 {_allVulnResults.Count} 个漏洞", 
                            "扫描已取消", MessageBoxButton.OK, MessageBoxImage.Warning);
                    }
                    else
                    {
                        ExpertScanProgressBar.Value = 100;
                        ExpertScanProgressText.Text = "扫描完成";
                        RefreshCharts();
                        MessageBox.Show($"专家模式扫描完成！\n共扫描 {completedCount}/{targets.Count} 个目标\n发现 {_totalOpenPorts} 个开放端口\n发现 {_allVulnResults.Count} 个漏洞", 
                            "扫描完成", MessageBoxButton.OK, MessageBoxImage.Information);
                    }
                });
            }
            catch (Exception ex)
            {
                Dispatcher.Invoke(() =>
                {
                    MessageBox.Show($"扫描过程中发生错误: {ex.Message}", "错误", MessageBoxButton.OK, MessageBoxImage.Error);
                    ResetScanButtons();
                });
            }
        }

        private async Task<List<PortScanResult>> ExecuteRustScanAsync(string target, List<int> ports, ExpertScanConfiguration config, CancellationToken cancellationToken)
        {
            var allResults = new List<PortScanResult>();
            try
            {
                if (_rustClient == null)
                {
                    _rustClient = new RustScannerClient();
                    _rustClient.OnLog += (s, msg) => AppendLog($"[Rust] {msg}");
                    _rustClient.OnProgressChanged += (s, p) =>
                    {
                        Dispatcher.Invoke(() =>
                        {
                            if (p.ProgressPercent > 0)
                                ExpertScanProgressBar.Value = p.ProgressPercent;
                        });
                    };
                }

                var profileConfig = new ScanProfileConfig
                {
                    TcpConcurrency = config.TcpConcurrency,
                    UdpConcurrency = config.UdpConcurrency,
                    TimeoutMs = config.TcpTimeout,
                    RetryCount = config.RetryCount,
                    EnableServiceDetection = config.ServiceDetection,
                    EnablePingProbe = config.HostDiscovery
                };

                var protocol = config.TcpScan && config.UdpScan ? "tcp,udp" : (config.UdpScan ? "udp" : "tcp");
                var rustResults = await _rustClient.ScanPortsAsync(
                    new List<string> { target }, ports, protocol,
                    config.TcpConcurrency, config.TcpTimeout, config.UdpTimeout,
                    config.ServiceDetection, true, cancellationToken, profileConfig);

                foreach (var r in rustResults)
                {
                    allResults.Add(new PortScanResult
                    {
                        TargetIp = r.TargetIp,
                        PortNumber = r.Port,
                        Status = r.Status == "open" ? "开放" : "关闭",
                        Service = r.Service ?? "",
                        ServiceVersion = r.Version ?? "",
                        ResponseTime = r.ScanTimeMs > 0 ? r.ScanTimeMs.ToString() : "-"
                    });
                }
                AppendLog($"  Rust扫描完成: {target} - {rustResults.Count(r2 => r2.Status == "open")} 个开放端口");
            }
            catch (Exception ex)
            {
                AppendLog($"  Rust引擎扫描失败，降级到内置扫描器: {ex.Message}");
                var progress = new Progress<int>(p => { });
                allResults = await ExecuteNativeScanAsync(target, ports, config, progress, cancellationToken);
            }
            return allResults;
        }

        private async Task<List<PortScanResult>> ExecuteNativeScanAsync(string target, List<int> ports, ExpertScanConfiguration config, IProgress<int> progress, CancellationToken cancellationToken)
        {
            var allResults = new List<PortScanResult>();
            var tasks = new List<Task<List<PortScanResult>>>();
            if (config.TcpScan)
                tasks.Add(_portScanner.ScanTcpPortsAsync(target, ports, progress, cancellationToken));
            if (config.UdpScan)
                tasks.Add(_portScanner.ScanUdpPortsAsync(target, ports, progress, cancellationToken));

            if (tasks.Count > 0)
            {
                var resultsArray = await Task.WhenAll(tasks);
                var tcpResults = resultsArray.Length > 0 ? resultsArray[0] : new List<PortScanResult>();
                var udpResults = resultsArray.Length > 1 ? resultsArray[1] : new List<PortScanResult>();
                var mergedPorts = new Dictionary<int, PortScanResult>();
                foreach (var r in tcpResults) { mergedPorts[r.PortNumber] = r; }
                foreach (var r in udpResults) { if (!mergedPorts.ContainsKey(r.PortNumber)) { mergedPorts[r.PortNumber] = r; } }
                allResults = mergedPorts.Values.ToList();
            }
            return allResults;
        }

        private List<string> ResolveTargets(ExpertScanConfiguration config)
        {
            var targets = new List<string>();

            switch (config.TargetType)
            {
                case "Single":
                    if (!string.IsNullOrWhiteSpace(config.TargetValue))
                        targets.Add(config.TargetValue.Trim());
                    break;

                case "Range":
                    var parts = config.TargetValue.Split('-');
                    if (parts.Length == 2 && System.Net.IPAddress.TryParse(parts[0].Trim(), out var startIp) &&
                        System.Net.IPAddress.TryParse(parts[1].Trim(), out var endIp))
                    {
                        long start = IPToLong(parts[0].Trim());
                        long end = IPToLong(parts[1].Trim());
                        long limit = Math.Min(end, start + 255);
                        for (long ip = start; ip <= limit; ip++)
                        {
                            targets.Add(LongToIP(ip));
                        }
                    }
                    break;

                case "CIDR":
                    if (config.TargetValue.Contains('/'))
                    {
                        var cidrParts = config.TargetValue.Split('/');
                        if (System.Net.IPAddress.TryParse(cidrParts[0], out var baseIp) && int.TryParse(cidrParts[1], out int prefix))
                        {
                            long baseLong = IPToLong(cidrParts[0]);
                            int hostBits = 32 - prefix;
                            long mask = (1L << hostBits) - 1;
                            long network = baseLong & ~mask;
                            long broadcast = network | mask;
                            long limit = Math.Min(broadcast, network + 255);
                            for (long ip = network + 1; ip <= limit; ip++)
                            {
                                targets.Add(LongToIP(ip));
                            }
                        }
                    }
                    break;

                case "File":
                    var lines = config.TargetValue.Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries);
                    targets.AddRange(lines.Select(l => l.Trim()).Where(l => !string.IsNullOrEmpty(l)));
                    break;

                case "Regex":
                    try
                    {
                        var regex = new System.Text.RegularExpressions.Regex(config.TargetValue);
                        var testIps = new List<string>();
                        
                        // Test common private network ranges
                        for (int i = 1; i <= 254; i++)
                        {
                            testIps.Add($"192.168.1.{i}");
                            testIps.Add($"192.168.0.{i}");
                            testIps.Add($"10.0.0.{i}");
                            testIps.Add($"10.0.1.{i}");
                            testIps.Add($"172.16.0.{i}");
                        }
                        
                        foreach (var testIp in testIps)
                        {
                            if (regex.IsMatch(testIp) && !targets.Contains(testIp))
                            {
                                targets.Add(testIp);
                            }
                        }
                        
                        // If no IPs matched, add the raw value as a target
                        if (targets.Count == 0)
                        {
                            targets.Add(config.TargetValue);
                        }
                    }
                    catch (Exception ex)
                    {
                        System.Diagnostics.Debug.WriteLine($"正则表达式解析失败: {ex.Message}");
                    }
                    break;

                default:
                    if (!string.IsNullOrWhiteSpace(config.TargetValue))
                        targets.Add(config.TargetValue.Trim());
                    break;
            }

            // Exclude hosts
            if (!string.IsNullOrWhiteSpace(config.ExcludeHosts))
            {
                var excluded = config.ExcludeHosts.Split(new[] { ',', ' ' }, StringSplitOptions.RemoveEmptyEntries)
                    .Select(s => s.Trim()).ToHashSet();
                targets.RemoveAll(t => excluded.Contains(t));
            }

            // 随机化目标顺序
            if (config.Randomize)
            {
                var rnd = new Random();
                targets = targets.OrderBy(t => rnd.Next()).ToList();
            }

            return targets;
        }

        private string LongToIP(long ipLong)
        {
            return $"{(ipLong >> 24) & 0xFF}.{(ipLong >> 16) & 0xFF}.{(ipLong >> 8) & 0xFF}.{ipLong & 0xFF}";
        }

        private List<int> ResolvePorts(ExpertScanConfiguration config)
        {
            var ports = new List<int>();

            switch (config.PortMode)
            {
                case "Common":
                    ports = Enumerable.Range(1, 1000).ToList();
                    break;
                case "Sensitive":
                    var sensitivePorts = new[] { 21, 22, 23, 25, 53, 110, 135, 139, 143, 443, 445, 993, 995,
                        1433, 1521, 3306, 3389, 5432, 5900, 6379, 8080, 8443, 9200, 27017, 5000, 5001, 8888, 9090 };
                    ports = sensitivePorts.ToList();
                    break;
                case "All":
                    ports = Enumerable.Range(1, 65535).ToList();
                    break;
                case "Custom":
                    if (!string.IsNullOrWhiteSpace(config.CustomPorts))
                    {
                        foreach (var part in config.CustomPorts.Split(new[] { ',', ' ' }, StringSplitOptions.RemoveEmptyEntries))
                        {
                            if (part.Contains('-'))
                            {
                                var rangeParts = part.Split('-');
                                if (int.TryParse(rangeParts[0], out int start) && int.TryParse(rangeParts[1], out int end))
                                {
                                    ports.AddRange(Enumerable.Range(Math.Max(1, start), Math.Min(end, 65535) - Math.Max(1, start) + 1));
                                }
                            }
                            else if (int.TryParse(part, out int p))
                            {
                                if (p >= 1 && p <= 65535)
                                    ports.Add(p);
                            }
                        }
                    }
                    break;
            }

            // Exclude ports
            if (!string.IsNullOrWhiteSpace(config.ExcludePorts))
            {
                var excluded = config.ExcludePorts.Split(new[] { ',', ' ' }, StringSplitOptions.RemoveEmptyEntries)
                    .Where(s => int.TryParse(s, out _))
                    .Select(int.Parse).ToHashSet();
                ports.RemoveAll(p => excluded.Contains(p));
            }

            var finalPorts = ports.Distinct().ToList();
            if (config.RandomPortOrder)
            {
                var rnd = new Random();
                finalPorts = finalPorts.OrderBy(p => rnd.Next()).ToList();
            }
            else
            {
                finalPorts = finalPorts.OrderBy(p => p).ToList();
            }
            return finalPorts;
        }

        private void NmapFastBtn_Click(object sender, RoutedEventArgs e)
        {
            CommonPortsRadio.IsChecked = true;
            TcpScanCheckBox.IsChecked = true;
            UdpScanCheckBox.IsChecked = false;
            SynScanCheckBox.IsChecked = false;
            ServiceVersionCheckBox.IsChecked = false;
            OsDetectCheckBox.IsChecked = false;
            ScriptScanCheckBox.IsChecked = false;
            TcpConcurrencySlider.Value = 200;
            TcpTimeoutSlider.Value = 200;
            UdpTimeoutSlider.Value = 500;
            RetrySlider.Value = 0;
            RateLimitCheckBox.IsChecked = false;
            StealthModeCheckBox.IsChecked = false;
            ServiceIntensityComboBox.SelectedIndex = 0;
            UpdateConfigSummary();
            ShowTemplateApplied(" 快速扫描 (-F): 常用端口、200并发、200ms超时、不重试");
        }

        private void NmapStealthBtn_Click(object sender, RoutedEventArgs e)
        {
            CommonPortsRadio.IsChecked = true;
            TcpScanCheckBox.IsChecked = true;
            UdpScanCheckBox.IsChecked = false;
            SynScanCheckBox.IsChecked = true;
            ServiceVersionCheckBox.IsChecked = true;
            OsDetectCheckBox.IsChecked = false;
            ScriptScanCheckBox.IsChecked = false;
            TcpConcurrencySlider.Value = 10;
            TcpTimeoutSlider.Value = 5000;
            UdpTimeoutSlider.Value = 1000;
            RetrySlider.Value = 1;
            RateLimitCheckBox.IsChecked = true;
            PacketRateSlider.Value = 100;
            StealthModeCheckBox.IsChecked = true;
            ServiceIntensityComboBox.SelectedIndex = 1;
            UpdateConfigSummary();
            ShowTemplateApplied("🥷 隐蔽扫描 (-sS): SYN半开、10并发、限速100pps、Stealth模式");
        }

        private void NmapAggressiveBtn_Click(object sender, RoutedEventArgs e)
        {
            AllPortsRadio.IsChecked = true;
            TcpScanCheckBox.IsChecked = true;
            UdpScanCheckBox.IsChecked = true;
            SynScanCheckBox.IsChecked = false;
            ServiceVersionCheckBox.IsChecked = true;
            OsDetectCheckBox.IsChecked = true;
            ScriptScanCheckBox.IsChecked = true;
            TcpConcurrencySlider.Value = 30;
            TcpTimeoutSlider.Value = 3000;
            UdpTimeoutSlider.Value = 5000;
            RetrySlider.Value = 2;
            RateLimitCheckBox.IsChecked = false;
            StealthModeCheckBox.IsChecked = false;
            ServiceIntensityComboBox.SelectedIndex = 3;
            ReverseDnsCheckBox.IsChecked = true;
            UpdateConfigSummary();
            ShowTemplateApplied("💥 激进扫描 (-A): 全端口、TCP+UDP、服务+OS+脚本检测、30并发");
        }

        private void NmapPingScanBtn_Click(object sender, RoutedEventArgs e)
        {
            CidrRadio.IsChecked = true;
            CommonPortsRadio.IsChecked = true;
            TcpScanCheckBox.IsChecked = false;
            UdpScanCheckBox.IsChecked = false;
            SynScanCheckBox.IsChecked = false;
            ServiceVersionCheckBox.IsChecked = false;
            OsDetectCheckBox.IsChecked = false;
            ScriptScanCheckBox.IsChecked = false;
            TcpConcurrencySlider.Value = 200;
            TcpTimeoutSlider.Value = 500;
            UdpTimeoutSlider.Value = 500;
            RetrySlider.Value = 0;
            HostDiscoveryCheckBox.IsChecked = true;
            UpdateConfigSummary();
            ShowTemplateApplied(" Ping扫描 (-sn): 仅主机发现、不扫描端口");
        }

        private void NmapFullPortsBtn_Click(object sender, RoutedEventArgs e)
        {
            AllPortsRadio.IsChecked = true;
            TcpScanCheckBox.IsChecked = true;
            UdpScanCheckBox.IsChecked = false;
            SynScanCheckBox.IsChecked = true;
            ServiceVersionCheckBox.IsChecked = true;
            OsDetectCheckBox.IsChecked = false;
            ScriptScanCheckBox.IsChecked = false;
            TcpConcurrencySlider.Value = 20;
            TcpTimeoutSlider.Value = 1000;
            UdpTimeoutSlider.Value = 1000;
            RetrySlider.Value = 1;
            RateLimitCheckBox.IsChecked = false;
            StealthModeCheckBox.IsChecked = false;
            ServiceIntensityComboBox.SelectedIndex = 2;
            UpdateConfigSummary();
            ShowTemplateApplied("🔍 全端口扫描 (-p-): 1-65535全端口、SYN半开、20并发");
        }

        private void NmapVersionBtn_Click(object sender, RoutedEventArgs e)
        {
            CommonPortsRadio.IsChecked = true;
            TcpScanCheckBox.IsChecked = true;
            UdpScanCheckBox.IsChecked = false;
            SynScanCheckBox.IsChecked = false;
            ServiceVersionCheckBox.IsChecked = true;
            OsDetectCheckBox.IsChecked = false;
            ScriptScanCheckBox.IsChecked = false;
            TcpConcurrencySlider.Value = 20;
            TcpTimeoutSlider.Value = 2000;
            UdpTimeoutSlider.Value = 1000;
            RetrySlider.Value = 1;
            RateLimitCheckBox.IsChecked = false;
            StealthModeCheckBox.IsChecked = false;
            ServiceIntensityComboBox.SelectedIndex = 3;
            UpdateConfigSummary();
            ShowTemplateApplied("️ 版本检测 (-sV): 常用端口、服务版本增强检测");
        }

        private void NmapOsBtn_Click(object sender, RoutedEventArgs e)
        {
            CommonPortsRadio.IsChecked = true;
            TcpScanCheckBox.IsChecked = true;
            UdpScanCheckBox.IsChecked = false;
            SynScanCheckBox.IsChecked = true;
            ServiceVersionCheckBox.IsChecked = true;
            OsDetectCheckBox.IsChecked = true;
            ScriptScanCheckBox.IsChecked = false;
            TcpConcurrencySlider.Value = 15;
            TcpTimeoutSlider.Value = 2000;
            UdpTimeoutSlider.Value = 1000;
            RetrySlider.Value = 2;
            RateLimitCheckBox.IsChecked = false;
            StealthModeCheckBox.IsChecked = false;
            ServiceIntensityComboBox.SelectedIndex = 2;
            UpdateConfigSummary();
            ShowTemplateApplied("🖥️ 系统检测 (-O): SYN半开、服务检测、OS识别");
        }

        private void NmapDefaultBtn_Click(object sender, RoutedEventArgs e)
        {
            CommonPortsRadio.IsChecked = true;
            TcpScanCheckBox.IsChecked = true;
            UdpScanCheckBox.IsChecked = false;
            SynScanCheckBox.IsChecked = false;
            ServiceVersionCheckBox.IsChecked = true;
            OsDetectCheckBox.IsChecked = false;
            ScriptScanCheckBox.IsChecked = false;
            TcpConcurrencySlider.Value = 50;
            TcpTimeoutSlider.Value = 500;
            UdpTimeoutSlider.Value = 1000;
            RetrySlider.Value = 1;
            RateLimitCheckBox.IsChecked = false;
            StealthModeCheckBox.IsChecked = false;
            ServiceIntensityComboBox.SelectedIndex = 1;
            UpdateConfigSummary();
            ShowTemplateApplied(" 默认扫描: 常用端口、TCP扫描、服务版本检测");
        }

        private void PresetWebServerBtn_Click(object sender, RoutedEventArgs e)
        {
            CommonPortsRadio.IsChecked = true;
            CustomPortsTextBox.Text = "21,22,23,25,53,80,110,143,443,993,995,1433,3306,3389,5432,8080,8443";
            CustomPortsRadio.IsChecked = true;
            TcpScanCheckBox.IsChecked = true;
            UdpScanCheckBox.IsChecked = false;
            SynScanCheckBox.IsChecked = false;
            ServiceVersionCheckBox.IsChecked = true;
            OsDetectCheckBox.IsChecked = false;
            ScriptScanCheckBox.IsChecked = false;
            TcpConcurrencySlider.Value = 30;
            TcpTimeoutSlider.Value = 2000;
            UdpTimeoutSlider.Value = 1000;
            RetrySlider.Value = 1;
            RateLimitCheckBox.IsChecked = false;
            StealthModeCheckBox.IsChecked = false;
            ServiceIntensityComboBox.SelectedIndex = 2;
            UpdateConfigSummary();
            ShowTemplateApplied("🌐 Web服务器检测: 80/443/8080/8443等Web相关端口、增强服务检测");
        }

        private void PresetDatabaseBtn_Click(object sender, RoutedEventArgs e)
        {
            CustomPortsRadio.IsChecked = true;
            CustomPortsTextBox.Text = "1433,1521,3306,5432,5984,6379,7474,8529,9200,11211,27017,28017";
            TcpScanCheckBox.IsChecked = true;
            UdpScanCheckBox.IsChecked = false;
            SynScanCheckBox.IsChecked = false;
            ServiceVersionCheckBox.IsChecked = true;
            OsDetectCheckBox.IsChecked = false;
            ScriptScanCheckBox.IsChecked = false;
            TcpConcurrencySlider.Value = 20;
            TcpTimeoutSlider.Value = 2000;
            UdpTimeoutSlider.Value = 1000;
            RetrySlider.Value = 1;
            RateLimitCheckBox.IsChecked = false;
            StealthModeCheckBox.IsChecked = false;
            ServiceIntensityComboBox.SelectedIndex = 3;
            UpdateConfigSummary();
            ShowTemplateApplied("️ 数据库安全检测: MySQL/PostgreSQL/Redis/MongoDB等数据库端口、暴力检测");
        }

        private void PresetWifiBtn_Click(object sender, RoutedEventArgs e)
        {
            CommonPortsRadio.IsChecked = true;
            CustomPortsTextBox.Text = "22,23,80,443,5000,8080,8443,9000,10000";
            TcpScanCheckBox.IsChecked = true;
            UdpScanCheckBox.IsChecked = true;
            SynScanCheckBox.IsChecked = false;
            ServiceVersionCheckBox.IsChecked = true;
            OsDetectCheckBox.IsChecked = true;
            ScriptScanCheckBox.IsChecked = false;
            TcpConcurrencySlider.Value = 20;
            TcpTimeoutSlider.Value = 2000;
            UdpTimeoutSlider.Value = 2000;
            RetrySlider.Value = 1;
            RateLimitCheckBox.IsChecked = false;
            StealthModeCheckBox.IsChecked = false;
            ServiceIntensityComboBox.SelectedIndex = 2;
            UpdateConfigSummary();
            ShowTemplateApplied("📶 WiFi路由器检测: 管理端口、TCP+UDP、服务+OS检测");
        }

        private void PresetComplianceBtn_Click(object sender, RoutedEventArgs e)
        {
            CommonPortsRadio.IsChecked = true;
            TcpScanCheckBox.IsChecked = true;
            UdpScanCheckBox.IsChecked = true;
            SynScanCheckBox.IsChecked = false;
            ServiceVersionCheckBox.IsChecked = true;
            OsDetectCheckBox.IsChecked = true;
            ScriptScanCheckBox.IsChecked = false;
            TcpConcurrencySlider.Value = 20;
            TcpTimeoutSlider.Value = 2000;
            UdpTimeoutSlider.Value = 3000;
            RetrySlider.Value = 2;
            RateLimitCheckBox.IsChecked = false;
            StealthModeCheckBox.IsChecked = false;
            ServiceIntensityComboBox.SelectedIndex = 3;
            ReverseDnsCheckBox.IsChecked = true;
            OutputHtmlCheckBox.IsChecked = true;
            UpdateConfigSummary();
            ShowTemplateApplied("✅ 合规性检查: 全协议、详细检测、生成HTML报告");
        }

        private void PresetVulnBtn_Click(object sender, RoutedEventArgs e)
        {
            AllPortsRadio.IsChecked = true;
            TcpScanCheckBox.IsChecked = true;
            UdpScanCheckBox.IsChecked = true;
            SynScanCheckBox.IsChecked = true;
            ServiceVersionCheckBox.IsChecked = true;
            OsDetectCheckBox.IsChecked = true;
            ScriptScanCheckBox.IsChecked = true;
            TcpConcurrencySlider.Value = 15;
            TcpTimeoutSlider.Value = 3000;
            UdpTimeoutSlider.Value = 5000;
            RetrySlider.Value = 2;
            RateLimitCheckBox.IsChecked = false;
            StealthModeCheckBox.IsChecked = false;
            ServiceIntensityComboBox.SelectedIndex = 4;
            ReverseDnsCheckBox.IsChecked = true;
            OutputJsonCheckBox.IsChecked = true;
            OutputHtmlCheckBox.IsChecked = true;
            OutputCsvCheckBox.IsChecked = true;
            UpdateConfigSummary();
            ShowTemplateApplied(" 漏洞专项检测: 全端口、全协议、暴力级检测、多格式输出");
        }

        private void PresetStealthBtn_Click(object sender, RoutedEventArgs e)
        {
            SensitivePortsRadio.IsChecked = true;
            TcpScanCheckBox.IsChecked = true;
            UdpScanCheckBox.IsChecked = false;
            SynScanCheckBox.IsChecked = true;
            ServiceVersionCheckBox.IsChecked = true;
            OsDetectCheckBox.IsChecked = false;
            ScriptScanCheckBox.IsChecked = false;
            TcpConcurrencySlider.Value = 5;
            TcpTimeoutSlider.Value = 5000;
            UdpTimeoutSlider.Value = 1000;
            RetrySlider.Value = 1;
            RateLimitCheckBox.IsChecked = true;
            PacketRateSlider.Value = 50;
            StealthModeCheckBox.IsChecked = true;
            RandomizeCheckBox.IsChecked = true;
            ServiceIntensityComboBox.SelectedIndex = 0;
            UpdateConfigSummary();
            ShowTemplateApplied("👻 隐蔽审计: 敏感端口、SYN半开、5并发、限速50pps、随机化顺序");
        }

        private void ShowTemplateApplied(string message)
        {
            UpdateConfigSummary();
            if (TemplateNotificationBorder != null && TemplateNotificationText != null)
            {
                TemplateNotificationText.Text = "✅ " + message;
                TemplateNotificationBorder.Visibility = Visibility.Visible;
                // Auto-hide after 3 seconds
                var timer = new DispatcherTimer { Interval = TimeSpan.FromSeconds(3) };
                timer.Tick += (s, e) => { TemplateNotificationBorder.Visibility = Visibility.Collapsed; timer.Stop(); };
                timer.Start();
            }
        }

        private void ExportNmapButton_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                var config = CollectConfig();
                var nmapCmd = GenerateNmapCommand(config);
                
                SafeSetClipboard(nmapCmd);
                
                var result = MessageBox.Show(
                    $"Nmap命令已复制到剪贴板：\n\n{nmapCmd}\n\n是否保存到文件？",
                    "导出Nmap命令",
                    MessageBoxButton.YesNo,
                    MessageBoxImage.Information
                );
                
                if (result == MessageBoxResult.Yes)
                {
                    var dialog = new Microsoft.Win32.SaveFileDialog
                    {
                        Filter = "批处理文件 (*.bat)|*.bat|Shell脚本 (*.sh)|*.sh|文本文件 (*.txt)|*.txt",
                        FileName = $"nmap_scan_{DateTime.Now:yyyyMMdd_HHmmss}.bat"
                    };
                    
                    if (dialog.ShowDialog() == true)
                    {
                        var content = dialog.FileName.EndsWith(".sh") 
                            ? $"#!/bin/bash\n{nmapCmd}"
                            : $"@echo off\n{nmapCmd}\npause";
                        File.WriteAllText(dialog.FileName, content);
                        MessageBox.Show($"命令已保存到: {dialog.FileName}", "保存成功", MessageBoxButton.OK, MessageBoxImage.Information);
                    }
                }
            }
            catch (Exception ex)
            {
                MessageBox.Show($"导出失败: {ex.Message}", "错误", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        private string GenerateNmapCommand(ExpertScanConfiguration config)
        {
            var parts = new List<string> { "nmap" };
            
            // 扫描类型
            if (config.SynScan) parts.Add("-sS");
            else if (config.UdpScan && !config.TcpScan) parts.Add("-sU");
            else if (config.UdpScan && config.TcpScan) parts.Add("-sS -sU");
            
            // 版本检测
            if (config.ServiceDetection) parts.Add("-sV");
            
            // OS检测
            if (config.OsDetection) parts.Add("-O");
            
            // 脚本扫描
            if (config.ScriptScan) parts.Add("-sC");
            
            // 端口范围
            if (config.PortMode == "All") parts.Add("-p-");
            else if (config.PortMode == "Sensitive") parts.Add("--top-ports 100");
            else if (config.PortMode == "Custom" && !string.IsNullOrWhiteSpace(config.CustomPorts))
                parts.Add($"-p {config.CustomPorts}");
            else parts.Add("--top-ports 1000");
            
            // 速率控制
            if (config.RateLimit) parts.Add($"--max-rate {config.PacketRate}");
            
            // 隐蔽模式
            if (config.StealthMode)
            {
                parts.Add("-T2");
                parts.Add("--max-retries 2");
            }
            
            // 随机化
            if (config.Randomize) parts.Add("--randomize-hosts");
            
            // 数据包分片
            if (config.FragmentPackets) parts.Add("-f");
            
            // 诱饵扫描
            if (config.DecoyScan && !string.IsNullOrWhiteSpace(config.DecoyIps))
                parts.Add($"-D {config.DecoyIps}");
            
            // 源端口
            if (!string.IsNullOrWhiteSpace(config.SourcePort) && int.TryParse(config.SourcePort, out _))
                parts.Add($"--source-port {config.SourcePort}");
            
            // 超时
            if (config.TcpTimeout != 500) parts.Add($"--max-rtt-timeout {config.TcpTimeout}ms");
            
            // 并发
            if (config.TcpConcurrency != 50) parts.Add($"--max-parallelism {config.TcpConcurrency}");
            
            // 重试
            if (config.RetryCount != 1) parts.Add($"--max-retries {config.RetryCount}");
            
            // 日志级别
            if (config.Verbosity == 0) parts.Add("-q");
            else if (config.Verbosity >= 2) parts.Add("-v");
            if (config.Verbosity == 3) parts.Add("-vv");
            
            // 输出
            if (config.SaveOutput && !string.IsNullOrWhiteSpace(config.OutputDir))
            {
                var baseName = $"scan_{DateTime.Now:yyyyMMdd_HHmmss}";
                parts.Add($"-oN \"{Path.Combine(config.OutputDir, baseName + ".txt")}\"");
            }
            
            // 目标
            parts.Add(config.TargetValue);
            
            return string.Join(" ", parts);
        }

        private void ValidateConfigButton_Click(object sender, RoutedEventArgs e)
        {
            var errors = new List<string>();
            var warnings = new List<string>();
            
            // 验证目标
            var targetValue = TargetInputTextBox.Text.Trim();
            if (string.IsNullOrWhiteSpace(targetValue))
            {
                errors.Add("未输入扫描目标");
            }
            else
            {
                if (SingleIpRadio.IsChecked == true)
                {
                    if (!System.Net.IPAddress.TryParse(targetValue, out _) && !IsValidHostname(targetValue))
                        warnings.Add($"目标 '{targetValue}' 可能不是有效的IP地址或主机名");
                }
                else if (IpRangeRadio.IsChecked == true)
                {
                    var parts = targetValue.Split('-');
                    if (parts.Length != 2 || !System.Net.IPAddress.TryParse(parts[0].Trim(), out _) || !System.Net.IPAddress.TryParse(parts[1].Trim(), out _))
                        errors.Add("IP段范围格式错误，应为: 起始IP-结束IP");
                }
                else if (CidrRadio.IsChecked == true)
                {
                    if (!targetValue.Contains('/') || !System.Net.IPAddress.TryParse(targetValue.Split('/')[0], out _))
                        errors.Add("CIDR格式错误，应为: IP/前缀长度");
                }
            }
            
            // 验证端口
            if (CustomPortsRadio.IsChecked == true)
            {
                var customPorts = CustomPortsTextBox.Text.Trim();
                if (string.IsNullOrWhiteSpace(customPorts))
                    errors.Add("自定义端口模式但未输入端口列表");
                else if (!ValidatePortList(customPorts, out string portError))
                    errors.Add(portError);
            }
            
            // 验证并发设置
            if (TcpConcurrencySlider.Value > 200)
                warnings.Add($"TCP并发数({(int)TcpConcurrencySlider.Value})较高，可能导致网络拥塞或触发IDS告警");
            
            // 验证超时设置
            if (TcpTimeoutSlider.Value < 100)
                warnings.Add($"TCP超时({(int)TcpTimeoutSlider.Value}ms)过短，可能导致误判端口关闭");
            
            // 验证高级选项冲突
            if (StealthModeCheckBox.IsChecked == true && TcpConcurrencySlider.Value > 20)
                warnings.Add("Stealth模式建议降低并发数(≤20)以保持隐蔽性");
            
            if (RateLimitCheckBox.IsChecked == true && PacketRateSlider.Value > 5000)
                warnings.Add($"速率限制({(int)PacketRateSlider.Value}pps)仍然较高，建议降低");
            
            // 显示结果
            var message = "";
            if (errors.Count == 0 && warnings.Count == 0)
            {
                message = "✅ 配置验证通过！\n\n所有设置均正确，可以开始扫描。";
                MessageBox.Show(message, "验证通过", MessageBoxButton.OK, MessageBoxImage.Information);
            }
            else
            {
                if (errors.Count > 0) message += "❌ 错误:\n" + string.Join("\n", errors.Select(e => "  • " + e)) + "\n\n";
                if (warnings.Count > 0) message += "⚠️ 警告:\n" + string.Join("\n", warnings.Select(w => "  • " + w));
                MessageBox.Show(message, "验证结果", MessageBoxButton.OK, errors.Count > 0 ? MessageBoxImage.Error : MessageBoxImage.Warning);
            }
        }

        private bool IsValidHostname(string hostname)
        {
            if (string.IsNullOrWhiteSpace(hostname)) return false;
            if (hostname.Length > 253) return false;
            return System.Text.RegularExpressions.Regex.IsMatch(hostname, @"^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$");
        }

        private bool ValidatePortList(string portList, out string error)
        {
            error = "";
            var parts = portList.Split(new[] { ',', ' ', '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries);
            
            foreach (var part in parts)
            {
                if (part.Contains('-'))
                {
                    var range = part.Split('-');
                    if (range.Length != 2 || !int.TryParse(range[0], out int start) || !int.TryParse(range[1], out int end))
                    {
                        error = $"端口范围 '{part}' 格式错误";
                        return false;
                    }
                    if (start < 1 || end > 65535 || start > end)
                    {
                        error = $"端口范围 '{part}' 无效 (应在1-65535之间且起始≤结束)";
                        return false;
                    }
                }
                else if (!int.TryParse(part, out int port) || port < 1 || port > 65535)
                {
                    error = $"端口 '{part}' 无效 (应为1-65535之间的整数)";
                    return false;
                }
            }
            
            return true;
        }

        private void UpdateScanPlanPreview()
        {
            try
            {
                if (TargetCountPreviewText == null || PortCountPreviewText == null) return;
                
                var config = CollectConfig();
                var targets = ResolveTargets(config);
                var ports = ResolvePorts(config);
                
                int targetCount = targets.Count;
                int portCount = ports.Count;
                long totalScans = (long)targetCount * portCount;
                
                // 估算耗时：每个端口扫描约需 timeout/concurrency 毫秒
                double msPerPort = config.TcpTimeout / (double)Math.Max(1, config.TcpConcurrency);
                double totalMs = totalScans * msPerPort;
                
                string timeEstimate;
                if (totalMs < 1000) timeEstimate = $"{(int)totalMs}毫秒";
                else if (totalMs < 60000) timeEstimate = $"{totalMs/1000:F1}秒";
                else if (totalMs < 3600000) timeEstimate = $"{totalMs/60000:F1}分钟";
                else timeEstimate = $"{totalMs/3600000:F1}小时";
                
                TargetCountPreviewText.Text = targetCount.ToString("N0");
                PortCountPreviewText.Text = portCount.ToString("N0");
                EstimatedTimePreviewText.Text = timeEstimate;
                TotalScansPreviewText.Text = totalScans.ToString("N0");
                
                // 根据数量设置颜色警告
                if (totalScans > 100000)
                {
                    TotalScansPreviewText.Foreground = new SolidColorBrush(System.Windows.Media.Color.FromRgb(0xE7, 0x4C, 0x3C));
                }
                else if (totalScans > 10000)
                {
                    TotalScansPreviewText.Foreground = new SolidColorBrush(System.Windows.Media.Color.FromRgb(0xE6, 0x7E, 0x22));
                }
                else
                {
                    TotalScansPreviewText.Foreground = new SolidColorBrush(System.Windows.Media.Color.FromRgb(0x9B, 0x59, 0xB6));
                }
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"[ExpertModeWindow] 更新扫描计划预览失败: {ex.Message}");
            }
        }

        private void CancelExpertButton_Click(object sender, RoutedEventArgs e)
        {
            if (_cancellationTokenSource != null && !_cancellationTokenSource.IsCancellationRequested)
            {
                _cancellationTokenSource.Cancel();
                CancelExpertButton.IsEnabled = false;
                CancelExpertButton.Content = "⏳ 取消中...";
            }
        }

        private void ExportHtmlButton_Click(object sender, RoutedEventArgs e)
        {
            if (_allPortScanResults.Count == 0 && _allVulnResults.Count == 0)
            {
                MessageBox.Show("暂无扫描结果可导出", "提示", MessageBoxButton.OK, MessageBoxImage.Information);
                return;
            }

            var dialog = new SaveFileDialog
            {
                Filter = "HTML文件 (*.html)|*.html",
                FileName = $"ExpertScan_Report_{DateTime.Now:yyyyMMdd_HHmmss}.html",
                Title = "导出HTML报告"
            };

            if (dialog.ShowDialog() == true)
            {
                try
                {
                    var html = GenerateHtmlReport();
                    File.WriteAllText(dialog.FileName, html);
                    MessageBox.Show($"HTML报告已保存到:\n{dialog.FileName}", "导出成功", MessageBoxButton.OK, MessageBoxImage.Information);
                }
                catch (Exception ex)
                {
                    MessageBox.Show($"导出失败: {ex.Message}", "错误", MessageBoxButton.OK, MessageBoxImage.Error);
                }
            }
        }

        private void ExportCsvButton_Click(object sender, RoutedEventArgs e)
        {
            if (_allPortScanResults.Count == 0 && _allVulnResults.Count == 0)
            {
                MessageBox.Show("暂无扫描结果可导出", "提示", MessageBoxButton.OK, MessageBoxImage.Information);
                return;
            }

            var dialog = new SaveFileDialog
            {
                Filter = "CSV文件 (*.csv)|*.csv",
                FileName = $"ExpertScan_Report_{DateTime.Now:yyyyMMdd_HHmmss}.csv",
                Title = "导出CSV报告"
            };

            if (dialog.ShowDialog() == true)
            {
                try
                {
                    var csv = GenerateCsvReport();
                    File.WriteAllText(dialog.FileName, csv, new System.Text.UTF8Encoding(true));
                    MessageBox.Show($"CSV报告已保存到:\n{dialog.FileName}", "导出成功", MessageBoxButton.OK, MessageBoxImage.Information);
                }
                catch (Exception ex)
                {
                    MessageBox.Show($"导出失败: {ex.Message}", "错误", MessageBoxButton.OK, MessageBoxImage.Error);
                }
            }
        }

        private void ExportJsonButton_Click(object sender, RoutedEventArgs e)
        {
            if (_allPortScanResults.Count == 0 && _allVulnResults.Count == 0)
            {
                MessageBox.Show("暂无扫描结果可导出", "提示", MessageBoxButton.OK, MessageBoxImage.Information);
                return;
            }

            var dialog = new SaveFileDialog
            {
                Filter = "JSON文件 (*.json)|*.json",
                FileName = $"ExpertScan_Report_{DateTime.Now:yyyyMMdd_HHmmss}.json",
                Title = "导出JSON报告"
            };

            if (dialog.ShowDialog() == true)
            {
                try
                {
                    var report = new
                    {
                        ExportTime = DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss"),
                        TotalTargets = _totalScannedTargets,
                        TotalOpenPorts = _totalOpenPorts,
                        TotalVulnerabilities = _allVulnResults.Count,
                        PortScanResults = _allPortScanResults,
                        VulnerabilityResults = _allVulnResults
                    };
                    var json = JsonSerializer.Serialize(report, new JsonSerializerOptions { WriteIndented = true, Encoder = System.Text.Encodings.Web.JavaScriptEncoder.UnsafeRelaxedJsonEscaping });
                    File.WriteAllText(dialog.FileName, json, new System.Text.UTF8Encoding(true));
                    MessageBox.Show($"JSON报告已保存到:\n{dialog.FileName}", "导出成功", MessageBoxButton.OK, MessageBoxImage.Information);
                }
                catch (Exception ex)
                {
                    MessageBox.Show($"导出失败: {ex.Message}", "错误", MessageBoxButton.OK, MessageBoxImage.Error);
                }
            }
        }

        private string GenerateHtmlReport()
        {
            var sb = new System.Text.StringBuilder();
            sb.AppendLine("<!DOCTYPE html>");
            sb.AppendLine("<html lang=\"zh-CN\">");
            sb.AppendLine("<head>");
            sb.AppendLine("<meta charset=\"UTF-8\">");
            sb.AppendLine("<meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\">");
            sb.AppendLine("<title>专家模式扫描报告</title>");
            sb.AppendLine("<style>");
            sb.AppendLine("body { font-family: 'Microsoft YaHei', sans-serif; margin: 20px; background: #f5f5f5; }");
            sb.AppendLine(".container { max-width: 1200px; margin: 0 auto; background: white; padding: 30px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }");
            sb.AppendLine("h1 { color: #2C3E50; border-bottom: 3px solid #3498DB; padding-bottom: 10px; }");
            sb.AppendLine("h2 { color: #34495E; margin-top: 30px; }");
            sb.AppendLine(".summary { display: flex; gap: 20px; margin: 20px 0; }");
            sb.AppendLine(".summary-item { flex: 1; background: #ECF0F1; padding: 15px; border-radius: 6px; text-align: center; }");
            sb.AppendLine(".summary-item .number { font-size: 32px; font-weight: bold; color: #2C3E50; }");
            sb.AppendLine(".summary-item .label { color: #7F8C8D; margin-top: 5px; }");
            sb.AppendLine("table { width: 100%; border-collapse: collapse; margin-top: 15px; }");
            sb.AppendLine("th { background: #3498DB; color: white; padding: 10px; text-align: left; }");
            sb.AppendLine("td { padding: 8px 10px; border-bottom: 1px solid #ECF0F1; }");
            sb.AppendLine("tr:hover { background: #F8F9FA; }");
            sb.AppendLine(".high { color: #E74C3C; font-weight: bold; }");
            sb.AppendLine(".medium { color: #E67E22; font-weight: bold; }");
            sb.AppendLine(".low { color: #27AE60; font-weight: bold; }");
            sb.AppendLine("</style>");
            sb.AppendLine("</head>");
            sb.AppendLine("<body>");
            sb.AppendLine("<div class=\"container\">");
            sb.AppendLine($"<h1>🔧 专家模式扫描报告</h1>");
            sb.AppendLine($"<p>生成时间: {DateTime.Now:yyyy-MM-dd HH:mm:ss}</p>");

            sb.AppendLine("<div class=\"summary\">");
            sb.AppendLine($"<div class=\"summary-item\"><div class=\"number\">{_totalScannedTargets}</div><div class=\"label\">扫描目标数</div></div>");
            sb.AppendLine($"<div class=\"summary-item\"><div class=\"number\">{_totalOpenPorts}</div><div class=\"label\">开放端口</div></div>");
            sb.AppendLine($"<div class=\"summary-item\"><div class=\"number\">{_allVulnResults.Count}</div><div class=\"label\">发现漏洞</div></div>");
            sb.AppendLine("</div>");

            if (_allPortScanResults.Count > 0)
            {
                sb.AppendLine("<h2>📊 端口扫描结果</h2>");
                sb.AppendLine("<table><tr><th>目标IP</th><th>端口</th><th>状态</th><th>服务</th><th>版本</th><th>响应时间(ms)</th></tr>");
                foreach (var r in _allPortScanResults)
                {
                    var statusColor = r.Status == "开放" ? "color:#27AE60;font-weight:bold;" : "color:#E74C3C;";
                    sb.AppendLine($"<tr><td>{r.TargetIp}</td><td>{r.PortNumber}</td><td style=\"{statusColor}\">{r.Status}</td><td>{r.Service}</td><td>{r.ServiceVersion}</td><td>{r.ResponseTime}</td></tr>");
                }
                sb.AppendLine("</table>");
            }

            if (_allVulnResults.Count > 0)
            {
                sb.AppendLine("<h2>⚠️ 漏洞扫描结果</h2>");
                sb.AppendLine("<table><tr><th>序号</th><th>漏洞名称</th><th>CVE</th><th>风险等级</th><th>端口</th><th>服务</th><th>目标</th><th>描述</th></tr>");
                foreach (var v in _allVulnResults)
                {
                    string levelClass = v.RiskLevel switch
                    {
                        "高危" or "严重" => "high",
                        "中危" => "medium",
                        "低危" or "信息" => "low",
                        _ => ""
                    };
                    sb.AppendLine($"<tr><td>{v.Id}</td><td>{v.Name}</td><td>{v.CveId}</td><td class=\"{levelClass}\">{v.RiskLevel}</td><td>{v.Port}</td><td>{v.Service}</td><td>{v.Target}</td><td>{v.Description}</td></tr>");
                }
                sb.AppendLine("</table>");
            }

            sb.AppendLine("</div></body></html>");
            return sb.ToString();
        }

        private string GenerateCsvReport()
        {
            var sb = new System.Text.StringBuilder();
            sb.AppendLine("报告类型,目标IP,端口,状态,服务,版本,风险等级,CVE,描述");

            foreach (var r in _allPortScanResults)
            {
                sb.AppendLine($"端口扫描,{r.TargetIp},{r.PortNumber},{r.Status},{EscapeCsv(r.Service)},{EscapeCsv(r.ServiceVersion)},,,");
            }

            foreach (var v in _allVulnResults)
            {
                sb.AppendLine($"漏洞扫描,{v.Target},{v.Port},,{EscapeCsv(v.Service)},{v.RiskLevel},{EscapeCsv(v.CveId)},{EscapeCsv(v.Description)}");
            }

            return sb.ToString();
        }

        private string EscapeCsv(string value)
        {
            if (string.IsNullOrEmpty(value)) return "";
            if (value.Contains(",") || value.Contains("\"") || value.Contains("\n"))
            {
                return $"\"{value.Replace("\"", "\"\"")}\"";
            }
            return value;
        }

        private void AppendLog(string message)
        {
            if (ScanLogTextBox == null) return;

            Dispatcher.Invoke(() =>
            {
                var timestamp = DateTime.Now.ToString("HH:mm:ss");
                ScanLogTextBox.AppendText($"[{timestamp}] {message}\r\n");
                ScanLogTextBox.ScrollToEnd();
            });
        }

        private void ClearResultsButton_Click(object sender, RoutedEventArgs e)
        {
            _allPortScanResults.Clear();
            _allVulnResults.Clear();
            _totalScannedTargets = 0;
            _totalOpenPorts = 0;

            if (RealTimePortResultsDataGrid != null)
                RealTimePortResultsDataGrid.Items.Refresh();
            if (RealTimeVulnResultsDataGrid != null)
                RealTimeVulnResultsDataGrid.Items.Refresh();

            TotalTargetsStat.Text = "0";
            ScannedTargetsStat.Text = "0";
            OpenPortsStat.Text = "0";
            VulnerabilitiesStat.Text = "0";
            ExpertScanProgressBar.Value = 0;
            ExpertScanProgressText.Text = "就绪";

            AppendLog("已清空所有扫描结果");
        }

        private void CopyResultsButton_Click(object sender, RoutedEventArgs e)
        {
            if (_allPortScanResults.Count == 0 && _allVulnResults.Count == 0)
            {
                MessageBox.Show("暂无扫描结果可复制", "提示", MessageBoxButton.OK, MessageBoxImage.Information);
                return;
            }

            var sb = new System.Text.StringBuilder();
            sb.AppendLine("=== 端口扫描结果 ===");
            sb.AppendLine("目标IP\t端口\t状态\t服务\t版本\t响应时间(ms)");
            foreach (var r in _allPortScanResults)
            {
                sb.AppendLine($"{r.TargetIp}\t{r.PortNumber}\t{r.Status}\t{r.Service}\t{r.ServiceVersion}\t{r.ResponseTime}");
            }

            if (_allVulnResults.Count > 0)
            {
                sb.AppendLine();
                sb.AppendLine("=== 漏洞扫描结果 ===");
                sb.AppendLine("序号\t漏洞名称\tCVE\t风险等级\t端口\t服务\t目标\t描述");
                foreach (var v in _allVulnResults)
                {
                    sb.AppendLine($"{v.Id}\t{v.Name}\t{v.CveId}\t{v.RiskLevel}\t{v.Port}\t{v.Service}\t{v.Target}\t{v.Description}");
                }
            }

            SafeSetClipboard(sb.ToString());
            MessageBox.Show("扫描结果已复制到剪贴板", "复制成功", MessageBoxButton.OK, MessageBoxImage.Information);
            AppendLog("已复制扫描结果到剪贴板");
        }

        private void ClearLogButton_Click(object sender, RoutedEventArgs e)
        {
            if (ScanLogTextBox != null)
                ScanLogTextBox.Clear();
        }

        private void CopySelectedRows_Click(object sender, RoutedEventArgs e)
        {
            var sb = new System.Text.StringBuilder();
            sb.AppendLine("目标IP\t端口\t状态\t服务\t版本\t响应时间(ms)");

            foreach (var item in RealTimePortResultsDataGrid.SelectedItems)
            {
                if (item is PortScanResult r)
                {
                    sb.AppendLine($"{r.TargetIp}\t{r.PortNumber}\t{r.Status}\t{r.Service}\t{r.ServiceVersion}\t{r.ResponseTime}");
                }
            }

            SafeSetClipboard(sb.ToString());
            AppendLog($"已复制 {RealTimePortResultsDataGrid.SelectedItems.Count} 行端口结果");
        }

        private void DeleteSelectedRows_Click(object sender, RoutedEventArgs e)
        {
            foreach (var item in RealTimePortResultsDataGrid.SelectedItems.Cast<PortScanResult>().ToList())
            {
                _allPortScanResults.Remove(item);
            }
            RealTimePortResultsDataGrid.Items.Refresh();
            AppendLog($"已删除 {RealTimePortResultsDataGrid.SelectedItems.Count} 行端口结果");
        }

        private void SortByPort_Click(object sender, RoutedEventArgs e)
        {
            var sorted = _allPortScanResults.OrderBy(r => r.PortNumber).ToList();
            _allPortScanResults.Clear();
            _allPortScanResults.AddRange(sorted);
            RealTimePortResultsDataGrid.Items.Refresh();
            AppendLog("已按端口号排序");
        }

        private void FilterOpenPorts_Click(object sender, RoutedEventArgs e)
        {
            var filtered = _allPortScanResults.Where(r => r.Status == "开放").ToList();
            RealTimePortResultsDataGrid.ItemsSource = null;
            RealTimePortResultsDataGrid.ItemsSource = filtered;
            AppendLog($"已筛选开放端口，共 {filtered.Count} 个");
        }

        private void CopyVulnSelectedRows_Click(object sender, RoutedEventArgs e)
        {
            var sb = new System.Text.StringBuilder();
            sb.AppendLine("序号\t漏洞名称\tCVE\t风险等级\t端口\t服务\t目标\t描述");

            foreach (var item in RealTimeVulnResultsDataGrid.SelectedItems)
            {
                if (item is VulnerabilityResult v)
                {
                    sb.AppendLine($"{v.Id}\t{v.Name}\t{v.CveId}\t{v.RiskLevel}\t{v.Port}\t{v.Service}\t{v.Target}\t{v.Description}");
                }
            }

            SafeSetClipboard(sb.ToString());
            AppendLog($"已复制 {RealTimeVulnResultsDataGrid.SelectedItems.Count} 行漏洞结果");
        }

        private void SortByRiskLevel_Click(object sender, RoutedEventArgs e)
        {
            var riskOrder = new Dictionary<string, int> { { "严重", 0 }, { "高危", 1 }, { "中危", 2 }, { "低危", 3 }, { "信息", 4 } };
            var sorted = _allVulnResults.OrderBy(v => riskOrder.ContainsKey(v.RiskLevel) ? riskOrder[v.RiskLevel] : 5).ToList();
            _allVulnResults.Clear();
            _allVulnResults.AddRange(sorted);
            RealTimeVulnResultsDataGrid.Items.Refresh();
            AppendLog("已按风险等级排序");
        }

        private void FilterHighRisk_Click(object sender, RoutedEventArgs e)
        {
            var filtered = _allVulnResults.Where(v => v.RiskLevel == "高危" || v.RiskLevel == "严重").ToList();
            RealTimeVulnResultsDataGrid.ItemsSource = null;
            RealTimeVulnResultsDataGrid.ItemsSource = filtered;
            AppendLog($"已筛选高危漏洞，共 {filtered.Count} 个");
        }

        private void FilterMediumRisk_Click(object sender, RoutedEventArgs e)
        {
            var filtered = _allVulnResults.Where(v => v.RiskLevel == "中危").ToList();
            RealTimeVulnResultsDataGrid.ItemsSource = null;
            RealTimeVulnResultsDataGrid.ItemsSource = filtered;
            AppendLog($"已筛选中危漏洞，共 {filtered.Count} 个");
        }

        private void RealTimePortResultsDataGrid_MouseDoubleClick(object sender, MouseButtonEventArgs e)
        {
            if (RealTimePortResultsDataGrid.SelectedItem is PortScanResult result)
            {
                var relatedVulns = _allVulnResults.Where(v => v.Port == result.PortNumber && v.Target == result.TargetIp).ToList();
                var vulnText = relatedVulns.Count > 0 
                    ? string.Join("\n", relatedVulns.Select(v => $"  [{v.RiskLevel}] {v.Name} ({v.CveId})"))
                    : "  无关联漏洞";
                
                MessageBox.Show(
                    $"目标: {result.TargetIp}\n" +
                    $"端口: {result.PortNumber}\n" +
                    $"状态: {result.Status}\n" +
                    $"服务: {result.Service}\n" +
                    $"版本: {result.ServiceVersion}\n" +
                    $"响应时间: {result.ResponseTime}ms\n\n" +
                    $"关联漏洞:\n{vulnText}",
                    "端口详情", MessageBoxButton.OK, MessageBoxImage.Information);
            }
        }

        private void RealTimeVulnResultsDataGrid_MouseDoubleClick(object sender, MouseButtonEventArgs e)
        {
            if (RealTimeVulnResultsDataGrid.SelectedItem is VulnerabilityResult result)
            {
                MessageBox.Show(
                    $"漏洞名称: {result.Name}\n" +
                    $"CVE编号: {result.CveId}\n" +
                    $"风险等级: {result.RiskLevel}\n" +
                    $"目标: {result.Target}\n" +
                    $"端口: {result.Port}\n" +
                    $"服务: {result.Service}\n\n" +
                    $"描述:\n{result.Description}",
                    "漏洞详情", MessageBoxButton.OK, MessageBoxImage.Information);
            }
        }

        private async void DeepScanPort_Click(object sender, RoutedEventArgs e)
        {
            if (RealTimePortResultsDataGrid.SelectedItem is PortScanResult result && result.Status == "开放")
            {
                AppendLog($"开始深度漏洞扫描: {result.TargetIp}:{result.PortNumber}");
                try
                {
                    var vulns = await _vulnerabilityScanner.ScanVulnerabilitiesAsync(result.TargetIp, 
                        new List<PortScanResult> { result }, CancellationToken.None);
                    foreach (var v in vulns)
                    {
                        _allVulnResults.Add(v);
                    }
                    Dispatcher.Invoke(() =>
                    {
                        RealTimeVulnResultsDataGrid.Items.Refresh();
                        VulnerabilitiesStat.Text = _allVulnResults.Count.ToString();
                    });
                    AppendLog($"深度扫描完成: 发现 {vulns.Count} 个漏洞");
                }
                catch (Exception ex)
                {
                    MessageBox.Show($"深度漏洞扫描失败: {ex.Message}", "错误", MessageBoxButton.OK, MessageBoxImage.Error);
                }
            }
            else
            {
                MessageBox.Show("请选择一个开放端口的行进行深度扫描", "提示", MessageBoxButton.OK, MessageBoxImage.Information);
            }
        }

        private void ExportPdfButton_Click(object sender, RoutedEventArgs e)
        {
            if (_allPortScanResults.Count == 0 && _allVulnResults.Count == 0)
            {
                MessageBox.Show("暂无扫描结果可导出", "提示", MessageBoxButton.OK, MessageBoxImage.Information);
                return;
            }

            var dialog = new SaveFileDialog
            {
                Filter = "PDF文件 (*.pdf)|*.pdf",
                FileName = $"ExpertScan_Report_{DateTime.Now:yyyyMMdd_HHmmss}.pdf",
                Title = "导出PDF报告"
            };

            if (dialog.ShowDialog() == true)
            {
                try
                {
                    // Generate PDF using HTML-to-PDF approach (same as MainWindow)
                    var html = GenerateHtmlReport();
                    var tempHtml = Path.Combine(Path.GetTempPath(), $"expert_report_{Guid.NewGuid():N}.html");
                    File.WriteAllText(tempHtml, html, Encoding.UTF8);
                    
                    // Use the project's ReportEngine if available, otherwise simple file save
                    try
                    {
                        var reportEngineType = System.Reflection.Assembly.GetExecutingAssembly().GetType("NetSecurityScanner.Services.ReportEngine")
                            ?? System.Reflection.Assembly.GetEntryAssembly()?.GetType("NetSecurityScanner.Services.ReportEngine");
                        if (reportEngineType != null)
                        {
                            dynamic engine = Activator.CreateInstance(reportEngineType);
                            engine.GeneratePdfFromHtml(tempHtml, dialog.FileName);
                        }
                        else
                        {
                            throw new InvalidOperationException("ReportEngine not available");
                        }
                    }
                    catch
                    {
                        // Fallback: save as HTML with .pdf extension note
                        File.Copy(tempHtml, dialog.FileName.Replace(".pdf", ".html"), true);
                        MessageBox.Show("PDF引擎不可用，已导出为HTML格式。可使用浏览器打印为PDF。", "提示", MessageBoxButton.OK, MessageBoxImage.Information);
                        return;
                    }
                    
                    if (File.Exists(dialog.FileName))
                        MessageBox.Show($"PDF报告已保存到:\n{dialog.FileName}", "导出成功", MessageBoxButton.OK, MessageBoxImage.Information);
                }
                catch (Exception ex)
                {
                    MessageBox.Show($"导出PDF失败: {ex.Message}\n\n建议使用「导出HTML」后在浏览器中打印为PDF。", "错误", MessageBoxButton.OK, MessageBoxImage.Error);
                }
            }
        }

        private void SafeSetClipboard(string text)
        {
            var thread = new Thread(() =>
            {
                for (int i = 0; i < 4; i++)
                {
                    Thread.Sleep(new[] { 0, 30, 60, 120 }[i]);
                    try
                    {
                        Dispatcher.Invoke(() => Clipboard.SetText(text));
                        return;
                    }
                    catch { }
                }
                // Fallback: show in MessageBox
                Dispatcher.Invoke(() => MessageBox.Show($"剪贴板复制失败，请手动复制：\n\n{text}", "复制", MessageBoxButton.OK, MessageBoxImage.Information));
            });
            thread.SetApartmentState(ApartmentState.STA);
            thread.Start();
        }

        private void ExpertModeWindow_Closing(object sender, System.ComponentModel.CancelEventArgs e)
        {
            if (_cancellationTokenSource != null && !_cancellationTokenSource.IsCancellationRequested)
            {
                var result = MessageBox.Show("扫描正在进行中，确定要关闭窗口吗？", "确认关闭", MessageBoxButton.YesNo, MessageBoxImage.Question);
                if (result == MessageBoxResult.No)
                {
                    e.Cancel = true;
                    return;
                }
                _cancellationTokenSource.Cancel();
            }

            // Save config on closing
            try
            {
                var config = CollectConfig();
                var configPath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                    "NetSecurityScanner", "expert_last_config.json");
                Directory.CreateDirectory(Path.GetDirectoryName(configPath)!);

                var saveData = new
                {
                    Config = config,
                    SelectedTab = ExpertTabControl?.SelectedIndex ?? 0,
                    UseRustScanner = _useRustScanner
                };
                var json = JsonSerializer.Serialize(saveData, new JsonSerializerOptions { WriteIndented = true });
                File.WriteAllText(configPath, json, Encoding.UTF8);
            }
            catch { }
        }

        private void PasteFromClipboardButton_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                if (Clipboard.ContainsText())
                {
                    var text = Clipboard.GetText();
                    if (!string.IsNullOrWhiteSpace(text))
                    {
                        TargetInputTextBox.Text = text;
                        ParseTargetCount();
                        UpdateScanPlanPreview();
                        AppendLog("已从剪贴板粘贴目标列表");
                    }
                }
                else
                {
                    MessageBox.Show("剪贴板中没有文本内容", "提示", MessageBoxButton.OK, MessageBoxImage.Information);
                }
            }
            catch (Exception ex)
            {
                MessageBox.Show($"粘贴失败: {ex.Message}", "错误", MessageBoxButton.OK, MessageBoxImage.Warning);
            }
        }

        private void RecommendButton_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                var config = CollectConfig();
                var targets = ResolveTargets(config);
                int count = targets.Count;

                // Simple recommend logic based on target count
                if (count <= 5)
                {
                    _recommendedConfig = ScanProfileConfigFactory.GetDefault(ScanProfile.Deep);
                    _recommendReason = $"目标数较少({count}个)，推荐深度扫描以获得最全面的结果";
                }
                else if (count <= 50)
                {
                    _recommendedConfig = ScanProfileConfigFactory.GetDefault(ScanProfile.Standard);
                    _recommendReason = $"目标数适中({count}个)，推荐标准扫描以平衡速度和精度";
                }
                else
                {
                    _recommendedConfig = ScanProfileConfigFactory.GetDefault(ScanProfile.Quick);
                    _recommendReason = $"目标数较多({count}个)，推荐快速扫描以缩短耗时，可按需对重点目标深度扫描";
                }

                RecommendResultTextBlock.Text = $"📊 {_recommendReason}\n" +
                    $"推荐模式: {_recommendedConfig.Profile} | " +
                    $"TCP并发: {_recommendedConfig.TcpConcurrency} | " +
                    $"超时: {_recommendedConfig.TimeoutMs}ms | " +
                    $"重试: {_recommendedConfig.RetryCount}";
                RecommendResultTextBlock.Foreground = new SolidColorBrush(Color.FromRgb(0x1A, 0xBC, 0x9C));
                ApplyRecommendButton.Visibility = Visibility.Visible;
            }
            catch (Exception ex)
            {
                RecommendResultTextBlock.Text = $"推荐失败: {ex.Message}";
                RecommendResultTextBlock.Foreground = new SolidColorBrush(Color.FromRgb(0xE7, 0x4C, 0x3C));
            }
        }

        private void ApplyRecommendButton_Click(object sender, RoutedEventArgs e)
        {
            if (_recommendedConfig == null) return;
            try
            {
                TcpConcurrencySlider.Value = _recommendedConfig.TcpConcurrency;
                UdpConcurrencySlider.Value = _recommendedConfig.UdpConcurrency;
                TcpTimeoutSlider.Value = _recommendedConfig.TimeoutMs;
                UdpTimeoutSlider.Value = _recommendedConfig.TimeoutMs;
                RetrySlider.Value = _recommendedConfig.RetryCount;
                ServiceVersionCheckBox.IsChecked = _recommendedConfig.EnableServiceDetection;
                HostDiscoveryCheckBox.IsChecked = _recommendedConfig.EnablePingProbe;
                UpdateConfigSummary();
                UpdateScanPlanPreview();
                AppendLog($"已应用推荐模式: {_recommendedConfig.Profile}");
            }
            catch (Exception ex)
            {
                MessageBox.Show($"应用推荐失败: {ex.Message}", "错误", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        private void ResetScanButtons()
        {
            StartExpertScanButton.Content = "🚀 开始专家扫描";
            StartExpertScanButton.IsEnabled = true;
            CancelExpertButton.IsEnabled = false;
            if (_elapsedTimer != null) { _elapsedTimer.Stop(); _elapsedTimer = null; }
            if (ElapsedTextBlock != null) ElapsedTextBlock.Text = "已用: 00:00:00";
            if (RemainingTextBlock != null) RemainingTextBlock.Text = "预计剩余: --:--:--";
        }

        private void ExpertTabControl_SelectionChanged(object sender, SelectionChangedEventArgs e)
        {
            if (ExpertTabControl == null) return;
            if (ExpertTabControl.SelectedIndex == 6) // Tab 7: 定时扫描 (0-indexed)
            {
                _ = RefreshScheduledTasksAsync();
            }
            else if (ExpertTabControl.SelectedIndex == 7) // Tab 8: 扫描历史 (0-indexed)
            {
                _ = LoadScanHistoryAsync();
            }
            else if (ExpertTabControl.SelectedIndex == 8) // Tab 9: 数据可视化 (0-indexed)
            {
                RefreshCharts();
            }
        }

        private void ScheduleModeComboBox_SelectionChanged(object sender, SelectionChangedEventArgs e)
        {
            if (CronInputPanel == null || ScheduleModeComboBox == null) return;
            var selected = ScheduleModeComboBox.SelectedItem as ComboBoxItem;
            var tag = selected?.Tag?.ToString() ?? "once";
            CronInputPanel.Visibility = tag == "custom" ? Visibility.Visible : Visibility.Collapsed;
        }

        private string BuildCronExpression(string mode, string time)
        {
            var parts = time.Split(':');
            int hour = parts.Length > 0 && int.TryParse(parts[0], out int h) ? h : 2;
            int minute = parts.Length > 1 && int.TryParse(parts[1], out int m) ? m : 0;

            return mode switch
            {
                "once" => $"{minute} {hour} {(DateTime.Now.Day + (DateTime.Now.Hour >= hour ? 1 : 0))} {DateTime.Now.Month} *",
                "daily" => $"{minute} {hour} * * *",
                "weekly" => $"{minute} {hour} * * {(int)DateTime.Now.DayOfWeek}",
                "custom" => CronExpressionTextBox?.Text?.Trim() ?? "0 2 * * *",
                _ => $"{minute} {hour} * * *"
            };
        }

        private async void CreateScheduleButton_Click(object sender, RoutedEventArgs e)
        {
            var target = ScheduledTargetTextBox?.Text?.Trim();
            if (string.IsNullOrWhiteSpace(target))
            {
                MessageBox.Show("请输入扫描目标", "输入错误", MessageBoxButton.OK, MessageBoxImage.Warning);
                return;
            }

            var name = ScheduledTaskNameTextBox?.Text?.Trim();
            if (string.IsNullOrWhiteSpace(name))
                name = $"专家扫描-{target}-{DateTime.Now:yyyyMMdd_HHmmss}";

            var selectedMode = (ScheduleModeComboBox?.SelectedItem as ComboBoxItem)?.Tag?.ToString() ?? "once";
            var time = ScheduleTimeTextBox?.Text?.Trim() ?? "02:00";
            var cron = BuildCronExpression(selectedMode, time);

            try
            {
                if (_scheduler == null)
                {
                    var governor = PluginGovernor.Instance;
                    if (!governor.IsInitialized)
                    {
                        var manager = new PluginManager();
                        await manager.LoadAllPluginsAsync();
                        var orchestrator = PluginOrchestrator.Instance;
                        if (!orchestrator.IsInitialized)
                            await orchestrator.InitializeAsync();
                        await governor.InitializeAsync(manager, orchestrator);
                    }
                    _scheduler = governor.Scheduler;
                }

                var task = new ScheduledTask
                {
                    Name = name,
                    TargetIp = target,
                    CronExpression = cron,
                    Enabled = true,
                    MaxRetries = 3
                };

                _scheduler.AddTask(task);
                await RefreshScheduledTasksAsync();
                AppendLog($"已创建定时扫描任务: {name} (Cron: {cron})");
                MessageBox.Show($"定时扫描任务已创建\n名称: {name}\nCron: {cron}", "创建成功", MessageBoxButton.OK, MessageBoxImage.Information);
            }
            catch (Exception ex)
            {
                MessageBox.Show($"创建定时任务失败: {ex.Message}", "错误", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        private async void RefreshScheduleButton_Click(object sender, RoutedEventArgs e)
        {
            await RefreshScheduledTasksAsync();
        }

        private async Task RefreshScheduledTasksAsync()
        {
            try
            {
                if (_scheduler == null)
                {
                    var governor = PluginGovernor.Instance;
                    if (!governor.IsInitialized)
                    {
                        var manager = new PluginManager();
                        await manager.LoadAllPluginsAsync();
                        var orchestrator = PluginOrchestrator.Instance;
                        if (!orchestrator.IsInitialized)
                            await orchestrator.InitializeAsync();
                        await governor.InitializeAsync(manager, orchestrator);
                    }
                    _scheduler = governor.Scheduler;
                }

                var tasks = _scheduler.Tasks.Select(t => new
                {
                    t.Id,
                    t.Name,
                    Target = t.TargetIp ?? "",
                    t.CronExpression,
                    Status = t.Enabled ? "启用" : "禁用",
                    t.LastRunAt,
                    t.TotalRuns
                }).ToList();

                Dispatcher.Invoke(() =>
                {
                    ScheduledTasksDataGrid.ItemsSource = tasks;
                });
            }
            catch (Exception ex)
            {
                AppendLog($"刷新定时任务失败: {ex.Message}");
            }
        }

        private async void EnableScheduledTask_Click(object sender, RoutedEventArgs e)
        {
            if (ScheduledTasksDataGrid?.SelectedItem == null) return;
            dynamic? item = ScheduledTasksDataGrid.SelectedItem;
            if (item == null) return;
            try
            {
                var id = (string)item.Id;
                var task = _scheduler?.Tasks.FirstOrDefault(t => t.Id == id);
                if (task != null)
                {
                    task.Enabled = true;
                    _scheduler?.UpdateTask(task);
                    await RefreshScheduledTasksAsync();
                }
            }
            catch { }
        }

        private async void DisableScheduledTask_Click(object sender, RoutedEventArgs e)
        {
            if (ScheduledTasksDataGrid?.SelectedItem == null) return;
            dynamic? item = ScheduledTasksDataGrid.SelectedItem;
            if (item == null) return;
            try
            {
                var id = (string)item.Id;
                var task = _scheduler?.Tasks.FirstOrDefault(t => t.Id == id);
                if (task != null)
                {
                    task.Enabled = false;
                    _scheduler?.UpdateTask(task);
                    await RefreshScheduledTasksAsync();
                }
            }
            catch { }
        }

        private async void DeleteScheduledTask_Click(object sender, RoutedEventArgs e)
        {
            if (ScheduledTasksDataGrid?.SelectedItem == null) return;
            dynamic? item = ScheduledTasksDataGrid.SelectedItem;
            if (item == null) return;
            try
            {
                var id = (string)item.Id;
                var result = MessageBox.Show("确认删除此定时任务？", "确认删除", MessageBoxButton.YesNo, MessageBoxImage.Question);
                if (result == MessageBoxResult.Yes)
                {
                    _scheduler?.RemoveTask(id);
                    await RefreshScheduledTasksAsync();
                }
            }
            catch { }
        }

        #region 扫描历史与差异对比

        private async Task LoadScanHistoryAsync()
        {
            try
            {
                var results = await _jsonDatabaseService.GetScanHistoryAsync();
                _scanHistory = results.OrderByDescending(r => r.ScanTime).ToList();
                Dispatcher.Invoke(() =>
                {
                    ScanHistoryDataGrid.ItemsSource = _scanHistory;
                });
            }
            catch (Exception ex)
            {
                AppendLog($"加载扫描历史失败: {ex.Message}");
            }
        }

        private async void RefreshHistoryButton_Click(object sender, RoutedEventArgs e)
        {
            await LoadScanHistoryAsync();
            AppendLog("已刷新扫描历史");
        }

        private async void CompareScansButton_Click(object sender, RoutedEventArgs e)
        {
            if (ScanHistoryDataGrid.SelectedItems.Count != 2)
            {
                MessageBox.Show("请选择恰好两条记录进行对比", "提示", MessageBoxButton.OK, MessageBoxImage.Information);
                return;
            }

            var items = ScanHistoryDataGrid.SelectedItems.Cast<ScanHistoryItem>().ToList();
            var item1 = items[0];
            var item2 = items[1];

            // Load complete scan results for both items
            var scan1 = await _jsonDatabaseService.GetScanResultByIdAsync(item1.ScanId);
            var scan2 = await _jsonDatabaseService.GetScanResultByIdAsync(item2.ScanId);

            if (scan1 == null || scan2 == null)
            {
                MessageBox.Show("无法加载完整的扫描结果数据，请确认记录文件存在", "错误", MessageBoxButton.OK, MessageBoxImage.Error);
                return;
            }

            var diffWindow = new ScanDiffWindow(scan1, scan2);
            diffWindow.Owner = this;
            diffWindow.ShowDialog();
        }

        private void ViewScanDetail_Click(object sender, RoutedEventArgs e)
        {
            if (ScanHistoryDataGrid.SelectedItem is ScanHistoryItem record)
            {
                var detail = $"扫描ID: {record.ScanId}\n" +
                             $"目标: {record.TargetIp}\n" +
                             $"扫描类型: {record.ScanType}\n" +
                             $"扫描时间: {record.ScanTime:yyyy-MM-dd HH:mm:ss}\n" +
                             $"开放端口: {record.OpenPortsCount}\n" +
                             $"漏洞数量: {record.VulnerabilitiesCount}\n" +
                             $"风险等级: {record.RiskLevel}\n" +
                             $"扫描耗时: {record.Duration:F1}秒";
                MessageBox.Show(detail, "扫描记录详情", MessageBoxButton.OK, MessageBoxImage.Information);
            }
        }

        private async void DeleteScanRecord_Click(object sender, RoutedEventArgs e)
        {
            if (ScanHistoryDataGrid.SelectedItem is ScanHistoryItem record)
            {
                var result = MessageBox.Show($"确认删除目标 {record.TargetIp} 的扫描记录？", "确认删除", MessageBoxButton.YesNo, MessageBoxImage.Question);
                if (result == MessageBoxResult.Yes)
                {
                    try
                    {
                        await _jsonDatabaseService.DeleteScanResultAsync(record.ScanId);
                        await LoadScanHistoryAsync();
                        AppendLog($"已删除扫描记录: {record.TargetIp}");
                    }
                    catch (Exception ex)
                    {
                        MessageBox.Show($"删除失败: {ex.Message}", "错误", MessageBoxButton.OK, MessageBoxImage.Error);
                    }
                }
            }
        }

        #region 数据可视化

        private void RefreshCharts()
        {
            try
            {
                if (_allPortScanResults == null || _allVulnResults == null) return;

                var openPorts = _allPortScanResults.Where(r => r.Status == "开放").ToList();

                var portDistribution = new Dictionary<string, int>
                {
                    { "TCP", openPorts.Count },
                    { "UDP", 0 }
                };
                var portColors = new Dictionary<string, Color>
                {
                    { "TCP", Color.FromRgb(0x34, 0x98, 0xDB) },
                    { "UDP", Color.FromRgb(0xE6, 0x7E, 0x22) }
                };
                DrawPieChart(PortDistributionPieChart, portDistribution, portColors);

                var topPorts = openPorts
                    .GroupBy(r => r.PortNumber)
                    .OrderByDescending(g => g.Count())
                    .Take(10)
                    .ToDictionary(g => g.Key.ToString(), g => g.Count());
                DrawBarChart(TopPortsBarChart, topPorts, Color.FromRgb(0x34, 0x98, 0xDB));

                var riskDistribution = new Dictionary<string, int>
                {
                    { "严重", _allVulnResults.Count(v => v.RiskLevel == "严重") },
                    { "高危", _allVulnResults.Count(v => v.RiskLevel == "高危") },
                    { "中危", _allVulnResults.Count(v => v.RiskLevel == "中危") },
                    { "低危", _allVulnResults.Count(v => v.RiskLevel == "低危") },
                    { "信息", _allVulnResults.Count(v => v.RiskLevel == "信息" || v.RiskLevel == "提示") }
                };
                var riskColors = new Dictionary<string, Color>
                {
                    { "严重", Color.FromRgb(0xE7, 0x4C, 0x3C) },
                    { "高危", Color.FromRgb(0xE6, 0x7E, 0x22) },
                    { "中危", Color.FromRgb(0xF1, 0xC4, 0x0F) },
                    { "低危", Color.FromRgb(0x34, 0x98, 0xDB) },
                    { "信息", Color.FromRgb(0x95, 0xA5, 0xA6) }
                };
                DrawPieChart(RiskLevelPieChart, riskDistribution, riskColors);
                DrawBarChart(RiskLevelBarChart, riskDistribution, Color.FromRgb(0xE7, 0x4C, 0x3C));

                var serviceDistribution = openPorts
                    .Where(r => !string.IsNullOrEmpty(r.Service))
                    .GroupBy(r => r.Service)
                    .OrderByDescending(g => g.Count())
                    .Take(10)
                    .ToDictionary(g => g.Key, g => g.Count());
                DrawBarChart(ServiceTypeBarChart, serviceDistribution, Color.FromRgb(0x27, 0xAE, 0x60));
            }
            catch (Exception ex)
            {
                Console.WriteLine($"刷新图表失败: {ex.Message}");
            }
        }

        private void DrawPieChart(Canvas canvas, Dictionary<string, int> data, Dictionary<string, Color> colors)
        {
            if (canvas == null) return;
            canvas.Children.Clear();

            double total = data.Values.Sum();
            if (total == 0) total = 1;

            double centerX = canvas.Width / 2;
            double centerY = canvas.Height / 2;
            double radius = Math.Min(centerX, centerY) - 10;

            double startAngle = -90;
            int legendIndex = 0;

            foreach (var item in data)
            {
                double sweepAngle = (item.Value / total) * 360;

                var geometry = new StreamGeometry();
                using (var ctx = geometry.Open())
                {
                    ctx.BeginFigure(new Point(centerX, centerY), true, true);
                    double startRad = startAngle * Math.PI / 180;
                    double endRad = (startAngle + sweepAngle) * Math.PI / 180;
                    Point startPoint = new Point(centerX + radius * Math.Cos(startRad), centerY + radius * Math.Sin(startRad));
                    Point endPoint = new Point(centerX + radius * Math.Cos(endRad), centerY + radius * Math.Sin(endRad));
                    ctx.LineTo(startPoint, true, false);
                    ctx.ArcTo(endPoint, new Size(radius, radius), 0, sweepAngle > 180, SweepDirection.Clockwise, true, false);
                }
                geometry.Freeze();

                var path = new System.Windows.Shapes.Path
                {
                    Fill = new SolidColorBrush(colors.ContainsKey(item.Key) ? colors[item.Key] : Color.FromRgb(0x95, 0xA5, 0xA6)),
                    Data = geometry
                };
                canvas.Children.Add(path);

                startAngle += sweepAngle;
                legendIndex++;
            }

            if (data.Values.All(v => v == 0))
            {
                var ellipse = new System.Windows.Shapes.Ellipse
                {
                    Width = radius * 2,
                    Height = radius * 2,
                    Fill = new SolidColorBrush(Color.FromRgb(0xEC, 0xF0, 0xF1))
                };
                Canvas.SetLeft(ellipse, centerX - radius);
                Canvas.SetTop(ellipse, centerY - radius);
                canvas.Children.Add(ellipse);
            }
        }

        private void DrawBarChart(Canvas canvas, Dictionary<string, int> data, Color barColor)
        {
            if (canvas == null) return;
            canvas.Children.Clear();

            double width = canvas.Width;
            double height = canvas.Height;
            double padding = 30;
            double chartWidth = width - padding * 2;
            double chartHeight = height - padding * 2;

            if (data.Count == 0) return;

            int maxValue = Math.Max(1, data.Values.Max());
            int barCount = data.Count;
            double barWidth = Math.Max(10, (chartWidth / barCount) - 5);
            double gap = 5;

            int index = 0;
            foreach (var item in data)
            {
                double barHeight = (item.Value / (double)maxValue) * chartHeight;
                double x = padding + index * (barWidth + gap);
                double y = height - padding - barHeight;

                var rect = new System.Windows.Shapes.Rectangle
                {
                    Width = barWidth,
                    Height = barHeight,
                    Fill = new SolidColorBrush(barColor)
                };
                Canvas.SetLeft(rect, x);
                Canvas.SetTop(rect, y);
                canvas.Children.Add(rect);

                var label = new TextBlock
                {
                    Text = item.Key,
                    FontSize = 10,
                    Foreground = new SolidColorBrush(Color.FromRgb(0x7F, 0x8C, 0x8D)),
                    TextTrimming = TextTrimming.CharacterEllipsis,
                    Width = barWidth,
                    TextAlignment = TextAlignment.Center
                };
                Canvas.SetLeft(label, x);
                Canvas.SetTop(label, height - padding + 2);
                canvas.Children.Add(label);

                var valueLabel = new TextBlock
                {
                    Text = item.Value.ToString(),
                    FontSize = 10,
                    Foreground = new SolidColorBrush(Color.FromRgb(0x2C, 0x3E, 0x50)),
                    FontWeight = FontWeights.Bold,
                    TextAlignment = TextAlignment.Center,
                    Width = barWidth
                };
                Canvas.SetLeft(valueLabel, x);
                Canvas.SetTop(valueLabel, y - 15);
                canvas.Children.Add(valueLabel);

                index++;
            }
        }

        private void ExportChartImageButton_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                var tabItem = ExpertTabControl?.SelectedContent as ScrollViewer;
                if (tabItem == null) return;

                var panel = tabItem.Content as StackPanel;
                if (panel == null) return;

                var dialog = new SaveFileDialog
                {
                    Filter = "PNG图片 (*.png)|*.png",
                    FileName = $"chart_export_{DateTime.Now:yyyyMMdd_HHmmss}.png",
                    Title = "导出图表图片"
                };

                if (dialog.ShowDialog() == true)
                {
                    panel.Measure(new Size(panel.ActualWidth, panel.ActualHeight));
                    panel.Arrange(new Rect(new Point(0, 0), panel.DesiredSize));

                    var renderBitmap = new RenderTargetBitmap(
                        (int)panel.ActualWidth,
                        (int)panel.ActualHeight,
                        96, 96,
                        PixelFormats.Pbgra32);
                    renderBitmap.Render(panel);

                    var encoder = new PngBitmapEncoder();
                    encoder.Frames.Add(BitmapFrame.Create(renderBitmap));

                    using (var stream = File.Create(dialog.FileName))
                    {
                        encoder.Save(stream);
                    }

                    MessageBox.Show($"图表已导出到: {dialog.FileName}", "导出成功", MessageBoxButton.OK, MessageBoxImage.Information);
                }
            }
            catch (Exception ex)
            {
                MessageBox.Show($"导出图片失败: {ex.Message}", "错误", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        #endregion

        #region 目标管理增强

        private void DeduplicateButton_Click(object sender, RoutedEventArgs e)
        {
            if (TargetInputTextBox == null || TargetCountTextBlock == null) return;

            try
            {
                var input = TargetInputTextBox.Text ?? "";
                var lines = input.Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries)
                                 .Select(l => l.Trim())
                                 .Where(l => !string.IsNullOrEmpty(l))
                                 .ToList();
                int originalCount = lines.Count;
                var distinctLines = lines.Distinct().ToList();
                int newCount = distinctLines.Count;

                TargetInputTextBox.Text = string.Join(Environment.NewLine, distinctLines);
                ParseTargetCount();

                MessageBox.Show($"去重完成：原 {originalCount} 条 → 现 {newCount} 条", "去重完成", MessageBoxButton.OK, MessageBoxImage.Information);
            }
            catch (Exception ex)
            {
                MessageBox.Show($"去重失败: {ex.Message}", "错误", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        private void ExportTargetsButton_Click(object sender, RoutedEventArgs e)
        {
            if (TargetInputTextBox == null) return;

            try
            {
                var dialog = new SaveFileDialog
                {
                    Filter = "文本文件 (*.txt)|*.txt",
                    FileName = $"targets_{DateTime.Now:yyyyMMdd_HHmmss}.txt",
                    Title = "导出目标列表"
                };

                if (dialog.ShowDialog() == true)
                {
                    var input = TargetInputTextBox.Text ?? "";
                    File.WriteAllText(dialog.FileName, input, Encoding.UTF8);
                    MessageBox.Show($"目标已导出到: {dialog.FileName}", "导出成功", MessageBoxButton.OK, MessageBoxImage.Information);
                }
            }
            catch (Exception ex)
            {
                MessageBox.Show($"导出失败: {ex.Message}", "错误", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        #endregion

        #region 专项工具

        private async void StartWeakPasswordScanButton_Click(object sender, RoutedEventArgs e)
        {
            if (WeakPasswordTargetTextBox == null || WeakPasswordStatusTextBlock == null) return;
            var target = WeakPasswordTargetTextBox.Text.Trim();
            if (string.IsNullOrEmpty(target))
            {
                MessageBox.Show("请输入目标地址", "提示", MessageBoxButton.OK, MessageBoxImage.Warning);
                return;
            }

            var serviceItem = WeakPasswordServiceComboBox?.SelectedItem as ComboBoxItem;
            var service = serviceItem?.Content?.ToString() ?? "SSH";
            int port = service switch
            {
                "SSH" => 22,
                "FTP" => 21,
                "MySQL" => 3306,
                "MSSQL" => 1433,
                _ => 22
            };

            WeakPasswordStatusTextBlock.Text = $"状态：正在检测 {target}:{port} ({service})...";
            StartWeakPasswordScanButton.IsEnabled = false;

            var results = new List<WeakPasswordResult>();
            try
            {
                var ctx = new ScanContext
                {
                    Target = target,
                    Port = port,
                    ServiceName = service,
                    Timeout = 3000
                };
                var wpResults = await _weakPasswordPlugin.ScanAsync(ctx, CancellationToken.None);
                foreach (var v in wpResults)
                {
                    results.Add(new WeakPasswordResult
                    {
                        Username = "anonymous",
                        Password = v.RiskLevel == "高" ? "anonymous@" : "(未授权)",
                        Service = service,
                        Target = target,
                        Port = port,
                        Vulnerability = v.Name
                    });
                }
            }
            catch (Exception ex)
            {
                WeakPasswordStatusTextBlock.Text = $"状态：检测失败 - {ex.Message}";
                StartWeakPasswordScanButton.IsEnabled = true;
                return;
            }

            WeakPasswordResultDataGrid.ItemsSource = results;
            WeakPasswordStatusTextBlock.Text = results.Count > 0
                ? $"状态：发现 {results.Count} 个弱口令漏洞"
                : "状态：未发现弱口令漏洞";
            StartWeakPasswordScanButton.IsEnabled = true;
            AppendLog($"[弱口令检测] {target}:{port} ({service}) - 发现 {results.Count} 个漏洞");
        }

        private async void StartDirScanButton_Click(object sender, RoutedEventArgs e)
        {
            if (DirScanUrlTextBox == null || DirScanStatusTextBlock == null) return;
            var url = DirScanUrlTextBox.Text.Trim();
            if (string.IsNullOrEmpty(url))
            {
                MessageBox.Show("请输入目标URL", "提示", MessageBoxButton.OK, MessageBoxImage.Warning);
                return;
            }
            if (!url.StartsWith("http://") && !url.StartsWith("https://"))
                url = "http://" + url;

            var dictItem = DirScanDictComboBox?.SelectedItem as ComboBoxItem;
            var dictName = dictItem?.Content?.ToString() ?? "常用目录字典";
            var paths = GetDirectoryWordlist(dictName);

            DirScanStatusTextBlock.Text = $"状态：正在扫描 {url} ({paths.Count} 条路径)...";
            StartDirScanButton.IsEnabled = false;
            var foundPaths = new List<string>();

            try
            {
                using var httpClient = new System.Net.Http.HttpClient();
                httpClient.Timeout = TimeSpan.FromSeconds(5);
                var baseUrl = url.TrimEnd('/');
                int checkedCount = 0;

                foreach (var path in paths)
                {
                    if (checkedCount++ % 10 == 0)
                        DirScanStatusTextBlock.Text = $"状态：扫描中 {checkedCount}/{paths.Count}...";

                    try
                    {
                        var testUrl = $"{baseUrl}/{path.TrimStart('/')}";
                        var response = await httpClient.GetAsync(testUrl);
                        if (response.StatusCode == System.Net.HttpStatusCode.OK ||
                            response.StatusCode == System.Net.HttpStatusCode.Forbidden ||
                            response.StatusCode == System.Net.HttpStatusCode.Unauthorized ||
                            (int)response.StatusCode == 301 ||
                            (int)response.StatusCode == 302)
                        {
                            foundPaths.Add($"[{(int)response.StatusCode}] {testUrl}");
                        }
                    }
                    catch { }
                }
            }
            catch (Exception ex)
            {
                DirScanStatusTextBlock.Text = $"状态：扫描失败 - {ex.Message}";
                StartDirScanButton.IsEnabled = true;
                return;
            }

            DirScanResultListBox.ItemsSource = foundPaths;
            DirScanStatusTextBlock.Text = foundPaths.Count > 0
                ? $"状态：发现 {foundPaths.Count} 个可访问路径"
                : "状态：未发现可访问路径";
            StartDirScanButton.IsEnabled = true;
            AppendLog($"[目录扫描] {url} - 发现 {foundPaths.Count} 个路径");
        }

        private async void StartPocVerifyButton_Click(object sender, RoutedEventArgs e)
        {
            if (PocTargetTextBox == null || PocStatusTextBlock == null) return;
            var target = PocTargetTextBox.Text.Trim();
            if (string.IsNullOrEmpty(target))
            {
                MessageBox.Show("请输入目标地址", "提示", MessageBoxButton.OK, MessageBoxImage.Warning);
                return;
            }

            PocStatusTextBlock.Text = $"状态：正在验证 {target}...";
            StartPocVerifyButton.IsEnabled = false;

            var pocResults = new List<string>();
            try
            {
                var commonPorts = new[] { 80, 443, 22, 21, 3306, 6379, 8080, 8443, 9200, 27017 };
                foreach (var port in commonPorts)
                {
                    try
                    {
                        using var client = new System.Net.Sockets.TcpClient();
                        var connectTask = client.ConnectAsync(target, port);
                        var timeoutTask = Task.Delay(2000);
                        if (await Task.WhenAny(connectTask, timeoutTask) == timeoutTask)
                            continue;

                        pocResults.Add($"[开放] {target}:{port} - 存在服务");
                        client.Close();
                    }
                    catch { }
                }

                if (pocResults.Count > 0)
                {
                    pocResults.Insert(0, $"目标 {target} POC验证结果：");
                    pocResults.Add($"共发现 {pocResults.Count - 1} 个开放端口，建议进一步深度漏洞扫描。");
                }
                else
                {
                    pocResults.Add($"目标 {target} 未检测到常见服务端口开放。");
                }
            }
            catch (Exception ex)
            {
                pocResults.Add($"POC验证失败: {ex.Message}");
            }

            PocResultTextBox.Text = string.Join("\n", pocResults);
            PocStatusTextBlock.Text = $"状态：验证完成 - {pocResults.Count} 条结果";
            StartPocVerifyButton.IsEnabled = true;
            AppendLog($"[POC验证] {target} - {pocResults.Count} 条结果");
        }

        private async void StartCmsIdentifyButton_Click(object sender, RoutedEventArgs e)
        {
            if (CmsIdentifyUrlTextBox == null || CmsStatusTextBlock == null) return;
            var url = CmsIdentifyUrlTextBox.Text.Trim();
            if (string.IsNullOrEmpty(url))
            {
                MessageBox.Show("请输入目标URL", "提示", MessageBoxButton.OK, MessageBoxImage.Warning);
                return;
            }
            if (!url.StartsWith("http://") && !url.StartsWith("https://"))
                url = "http://" + url;

            CmsStatusTextBlock.Text = $"状态：正在识别 {url}...";
            StartCmsIdentifyButton.IsEnabled = false;

            string cmsResult;
            try
            {
                using var httpClient = new System.Net.Http.HttpClient();
                httpClient.Timeout = TimeSpan.FromSeconds(10);
                httpClient.DefaultRequestHeaders.Add("User-Agent", "Mozilla/5.0");

                var response = await httpClient.GetAsync(url);
                var html = await response.Content.ReadAsStringAsync();
                var headers = response.Headers.ToString();
                var content = (html + " " + headers).ToLower();

                var cmsSignatures = new Dictionary<string, List<string>>
                {
                    { "WordPress", new List<string> { "wp-content", "wp-includes", "wordpress" } },
                    { "Drupal", new List<string> { "drupal", "sites/all", "sites/default" } },
                    { "Joomla", new List<string> { "joomla", "components/com_", "media/system/js" } },
                    { "DedeCMS", new List<string> { "dede", "dedecms", "/templets/" } },
                    { "Discuz", new List<string> { "discuz", "forum.php", "uc_client" } },
                    { "ThinkPHP", new List<string> { "thinkphp", "think\\", "/index.php/" } },
                    { "Spring Boot", new List<string> { "whitelabel error", "spring", "actuator" } },
                    { "Tomcat", new List<string> { "tomcat", "coyote", "jsp" } },
                    { "Nginx", new List<string> { "nginx" } },
                    { "Apache", new List<string> { "apache" } }
                };

                string identified = "未知";
                int matchCount = 0;
                foreach (var kv in cmsSignatures)
                {
                    int hits = kv.Value.Count(sig => content.Contains(sig));
                    if (hits > matchCount)
                    {
                        matchCount = hits;
                        identified = kv.Key;
                    }
                }

                var serverHeader = "";
                if (response.Headers.Server != null)
                    serverHeader = response.Headers.Server.ToString();

                cmsResult = $"CMS识别结果：{identified}\n" +
                            $"匹配特征数：{matchCount}\n" +
                            $"服务器：{serverHeader}\n" +
                            $"HTTP状态码：{(int)response.StatusCode}\n" +
                            $"页面大小：{html.Length} 字节";
            }
            catch (Exception ex)
            {
                cmsResult = $"CMS识别失败: {ex.Message}";
            }

            CmsResultTextBlock.Text = cmsResult;
            CmsStatusTextBlock.Text = "状态：识别完成";
            StartCmsIdentifyButton.IsEnabled = true;
            AppendLog($"[CMS识别] {url} - {cmsResult.Split('\n')[0]}");
        }

        private List<string> GetDirectoryWordlist(string dictName)
        {
            var common = new List<string>
            {
                "admin", "login", "index.php", "index.html", "robots.txt", "sitemap.xml",
                ".git", ".env", ".svn", "backup", "config", "test", "api", "wp-admin",
                "wp-login.php", "phpmyadmin", "phpinfo.php", "info.php", "console",
                "dashboard", "manage", "system", "upload", "uploads", "images", "img",
                "css", "js", "lib", "static", "assets", "public", "private",
                "data", "db", "database", "sql", "log", "logs", "temp", "tmp",
                "docs", "doc", "help", "readme", "readme.txt", "readme.md",
                "license", "changelog", "version", "status", "health",
                ".htaccess", "web.config", "crossdomain.xml", ".well-known",
                "vendor", "node_modules", "composer.json", "package.json",
                "WEB-INF", "META-INF", "swagger", "swagger-ui", "api-docs",
                "actuator", "actuator/health", "actuator/env", "actuator/info",
                "cgi-bin", "scripts", "bin", "include", "includes", "templates"
            };

            return dictName switch
            {
                "PHP字典" => common.Where(p =>
                    p.EndsWith(".php") || p.Contains("php") || p.StartsWith(".") ||
                    p == "admin" || p == "login" || p == "config" || p == "upload" ||
                    p == "backup" || p == "test" || p == "api" || p == "temp").ToList(),
                "ASP字典" => common.Select(p => p.Replace(".php", ".asp").Replace(".html", ".aspx")).ToList(),
                "JSP字典" => common.Select(p => p.Replace(".php", ".jsp").Replace(".html", ".jsp")).ToList(),
                _ => common
            };
        }

        #endregion

        #endregion
    }

    public class ExpertScanConfiguration
    {
        public DateTime StartTime { get; set; } = DateTime.Now;
        public string TargetType { get; set; } = "Single";
        public string TargetValue { get; set; } = "";
        public bool ReverseDns { get; set; } = false;
        public bool HostDiscovery { get; set; } = true;
        public string ExcludeHosts { get; set; } = "";

        public string PortMode { get; set; } = "Common";
        public string CustomPorts { get; set; } = "";
        public bool TcpScan { get; set; } = true;
        public bool UdpScan { get; set; } = false;
        public bool SynScan { get; set; } = false;
        public bool ServiceDetection { get; set; } = true;
        public bool OsDetection { get; set; } = false;
        public bool ScriptScan { get; set; } = false;
        public int ServiceIntensity { get; set; } = 1;
        public string ExcludePorts { get; set; } = "";

        public int TcpConcurrency { get; set; } = 50;
        public int UdpConcurrency { get; set; } = 20;
        public int TcpTimeout { get; set; } = 500;
        public int UdpTimeout { get; set; } = 1000;
        public int RetryCount { get; set; } = 1;
        public int ServiceDetectTimeout { get; set; } = 2000;

        public bool RateLimit { get; set; } = false;
        public int PacketRate { get; set; } = 1000;
        public bool Randomize { get; set; } = false;
        public bool StealthMode { get; set; } = false;
        public bool RandomPortOrder { get; set; } = false;

        public string SourcePort { get; set; } = "";
        public string Mtu { get; set; } = "1500";
        public bool FragmentPackets { get; set; } = false;
        public bool BadChecksum { get; set; } = false;
        public bool DecoyScan { get; set; } = false;
        public string DecoyIps { get; set; } = "";
        public bool IdleScan { get; set; } = false;
        public string ZombieHost { get; set; } = "";
        public bool SourceRouting { get; set; } = false;
        public int Verbosity { get; set; } = 1;
        public bool SaveOutput { get; set; } = true;
        public string OutputDir { get; set; } = "";
    }

    public class WeakPasswordResult
    {
        public string Username { get; set; } = "";
        public string Password { get; set; } = "";
        public string Service { get; set; } = "";
        public string Target { get; set; } = "";
        public int Port { get; set; }
        public string Vulnerability { get; set; } = "";
    }
}
