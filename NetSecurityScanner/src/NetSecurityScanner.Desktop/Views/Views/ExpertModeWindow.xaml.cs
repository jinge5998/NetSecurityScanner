using Microsoft.Win32;
using NetSecurityScanner.Core;
using NetSecurityScanner.Core.Models;
using NetSecurityScanner.Core.Services;
using NetSecurityScanner.Models;
using NetSecurityScanner.Plugins;
using NetSecurityScanner.Services;
using NetSecurityScanner.Utils;
using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Collections.Specialized;
using System.ComponentModel;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using Xceed.Words.NET;
using System.Windows.Threading;

namespace NetSecurityScanner.Views
{
    /// <summary>
    /// 线程安全的 ObservableCollection，支持 AddRange 批量添加（仅触发一次 CollectionChanged）
    /// 解决 DataGrid 大量更新时的 UI 卡顿问题
    /// </summary>
    public class BulkObservableCollection<T> : ObservableCollection<T>
    {
        private bool _suppressNotification;

        protected override void OnCollectionChanged(NotifyCollectionChangedEventArgs e)
        {
            if (!_suppressNotification)
                base.OnCollectionChanged(e);
        }

        /// <summary>
        /// 批量添加元素，仅触发一次 CollectionChanged 通知。
        ///
        /// 关键：这里刻意"一律"发送 Reset 通知，而不是 Add 范围通知。
        /// WPF 的 ListCollectionView（DataGrid 的默认视图）在收到携带 items 的
        /// NotifyCollectionChangedAction.Add 通知时，会走 ValidateCollectionChangedEventArgs
        /// 校验并抛出 NotSupportedException("不支持范围操作")。
        /// 该限制与 items 数量无关（实测仅 3 条同样会抛），
        /// 因此范围 Add 通知在此 DataGrid 配置下完全不可用，必须退化为 Reset（全量重绘）。
        /// 由于 DataGrid 已开启行虚拟化，全量重绘只渲染可见行，性能仍然可接受。
        /// </summary>
        public void AddRange(IEnumerable<T> items)
        {
            if (items == null)
                throw new ArgumentNullException(nameof(items));

            var list = items.ToList();
            if (list.Count == 0)
                return;

            _suppressNotification = true;
            try
            {
                foreach (var item in list)
                    Add(item);
            }
            finally
            {
                _suppressNotification = false;
            }

            OnCollectionChanged(new NotifyCollectionChangedEventArgs(NotifyCollectionChangedAction.Reset));
        }

        /// <summary>
        /// 批量添加元素，仅触发一次 Reset 通知（比 Add 更轻量，DataGrid 会全量刷新）
        /// </summary>
        public void AddRangeReset(IEnumerable<T> items)
        {
            if (items == null)
                throw new ArgumentNullException(nameof(items));

            _suppressNotification = true;
            try
            {
                Clear();
                foreach (var item in items)
                    Add(item);
            }
            finally
            {
                _suppressNotification = false;
            }
            OnCollectionChanged(new NotifyCollectionChangedEventArgs(NotifyCollectionChangedAction.Reset));
        }
    }

    public partial class ExpertModeWindow : Window
    {
        private PortScanner _portScanner;
        private VulnerabilityScanner _vulnerabilityScanner;
        private Plugins.DefaultPlugins.WeakPasswordPlugin _weakPasswordPlugin;
        private CancellationTokenSource _cancellationTokenSource;
        private ExpertScanConfiguration _currentConfig;
        private JsonDatabaseService _jsonDatabaseService;
        private BulkObservableCollection<PortScanResult> _allPortScanResults;
        private BulkObservableCollection<VulnerabilityResult> _allVulnResults;
        private int _totalScannedTargets;
        private int _totalOpenPorts;
        private bool _useRustScanner = true; // default to Rust
        private RustScannerClient? _rustClient;
        private string? _currentRustExe; // 缓存本次专家模式会话使用的 Rust 引擎路径
        private bool _rustServiceStarted; // 标记 Rust 服务是否已启动（跨目标复用）
        private PluginScheduler? _scheduler;
        private List<ScanHistoryItem> _scanHistory = new();
        private ScanProfileConfig? _recommendedConfig;
        private string? _recommendReason;
        private DispatcherTimer? _elapsedTimer;
        // 模板应用提示通知的复用计时器（避免反复创建 DispatcherTimer 泄露）
        private DispatcherTimer? _templateNotificationTimer;
        // 目录扫描专用取消令牌（支持扫描过程中途取消）
        private CancellationTokenSource? _dirScanCts;
        private DateTime _scanStartTime;
        private bool _isScanning; // 标记是否正在扫描，替代对 _cancellationTokenSource 状态的判断
        private bool _userRequestedCancel; // 标记用户是否主动点击了"取消"按钮，用于日志区分
        // 后台扫描任务的完成信号，用于 Closing 时优雅等待（避免资源竞态）
        private TaskCompletionSource<bool> _scanTaskCompletionSource;
        // 保护 _allPortScanResults / _allVulnResults 多线程读写的互斥锁
        private readonly object _resultsLock = new object();

        // 当前扫描策略：把「性能调优」Tab 配置的并发/超时下发给 PortScanner。
        // 存为字段而非层层传参：ExecuteNativeScanAsync 有 7 个调用点（含多处 Rust 降级），
        // 逐个加参数既易漏改也易在将来新增分支时遗漏。
        private NetSecurityScanner.Models.ScanPolicy? _currentScanPolicy;

        // 自适应并发控制器（默认关闭，需在「性能调优」Tab 勾选后启用）：
        // 扫描过程中按内存压力动态收敛并发，避免全端口大范围扫描时内存暴涨。
        private AdaptiveConcurrencyController? _adaptiveController;
        // 自适应并发开关（由 UI 复选框绑定，未找到控件时默认关闭，保持既有行为）
        private bool _adaptiveConcurrencyEnabled;

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
                _allPortScanResults = new BulkObservableCollection<PortScanResult>();
                _allVulnResults = new BulkObservableCollection<VulnerabilityResult>();
                this.Loaded += ExpertModeWindow_Loaded;
                this.Closing += ExpertModeWindow_Closing;
                this.Dispatcher.UnhandledException += (s, ex) =>
                {
                    // 同时落盘一份完整堆栈：UI 弹窗里的堆栈容易被截断，
                    // 而线程类问题（例如 "调用线程无法访问此对象"）必须靠完整堆栈才能定位到具体控件与方法。
                    try { WriteExpertErrorLog(ex.Exception); } catch { }

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
                    RefreshRustEngineStatus();
                }
                catch { _useRustScanner = false; }

                TargetInputTextBox.TextChanged += (_, __) =>
                {
                    ParseTargetCount();
                    UpdateScanPlanPreview();
                };

                // 实时验证：目标/端口变化时启用/禁用"开始扫描"按钮 + 边框颜色 + Tooltip
                TargetInputTextBox.TextChanged += (_, __) => UpdateStartButtonState();
                if (CustomPortsTextBox != null)
                {
                    CustomPortsTextBox.TextChanged += (_, __) => UpdateStartButtonState();
                }
                if (CustomPortsRadio != null) CustomPortsRadio.Checked += (_, __) => UpdateStartButtonState();
                if (CommonPortsRadio != null) CommonPortsRadio.Checked += (_, __) => UpdateStartButtonState();
                if (SensitivePortsRadio != null) SensitivePortsRadio.Checked += (_, __) => UpdateStartButtonState();
                if (AllPortsRadio != null) AllPortsRadio.Checked += (_, __) => UpdateStartButtonState();

                // 初始化按钮状态（考虑已恢复的旧配置或默认空值）
                UpdateStartButtonState();

                // 加载 POC 插件列表到专项工具 Tab
                LoadPocPlugins();

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

                // 注册 NMAP 模板（数据驱动 19 个模板：14 原有 + 5 新增）
                RegisterNmapTemplates();

                // 加载自定义模板列表
                RefreshCustomTemplateList();
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
            if (_useRustScanner)
            {
                RefreshRustEngineStatus();
            }
            else
            {
                EngineStatusTextBlock.Text = "使用内置C#扫描引擎";
                EngineStatusTextBlock.Foreground = new SolidColorBrush(Color.FromRgb(0x34, 0x98, 0xDB));
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
                        if (int.TryParse(parts[1], out int prefix) && prefix >= 0 && prefix <= 32)
                        {
                            if (prefix == 0)
                            {
                                // /0 涵盖全部 IPv4 空间，按 65536 上限占位避免溢出
                                count = 65536;
                            }
                            else
                            {
                                int hostBits = 32 - prefix;
                                long rawCount = 1L << hostBits;  // 用 long 计算避免溢出
                                count = (int)Math.Min(rawCount, 65536);
                            }
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

        /// <summary>
        /// 从外部 JSON 文件导入配置 - 与加载预设不同，可以从任意位置选择配置文件
        /// </summary>
        private void ImportConfigButton_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                var dialog = new Microsoft.Win32.OpenFileDialog
                {
                    Filter = "配置文件 (*.json)|*.json|所有文件 (*.*)|*.*",
                    Title = "导入配置文件"
                };

                if (dialog.ShowDialog() != true) return;

                var json = File.ReadAllText(dialog.FileName, Encoding.UTF8);
                var config = JsonSerializer.Deserialize<ExpertScanConfiguration>(json,
                    new JsonSerializerOptions { PropertyNameCaseInsensitive = true });

                if (config == null)
                {
                    MessageBox.Show("配置文件解析失败，请检查文件格式是否正确。", "导入失败", MessageBoxButton.OK, MessageBoxImage.Error);
                    return;
                }

                ApplyConfig(config);
                UpdateConfigSummary();
                UpdateScanPlanPreview();
                MessageBox.Show($"配置已从文件导入:\n{dialog.FileName}\n\n提示：目标、端口模式、并发、超时、输出格式等设置已更新。",
                    "导入成功", MessageBoxButton.OK, MessageBoxImage.Information);
                AppendLog($"已导入配置文件: {Path.GetFileName(dialog.FileName)}");
            }
            catch (JsonException jex)
            {
                MessageBox.Show($"JSON 格式错误: {jex.Message}\n\n请确保文件是有效的 ExpertScanConfiguration 格式。",
                    "导入失败", MessageBoxButton.OK, MessageBoxImage.Error);
            }
            catch (Exception ex)
            {
                MessageBox.Show($"导入失败: {ex.Message}", "错误", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        /// <summary>
        /// 导出当前配置到外部 JSON 文件 - 可分享给他人，或在不同机器间同步
        /// </summary>
        private void ExportConfigButton_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                var config = CollectConfig();

                var dialog = new Microsoft.Win32.SaveFileDialog
                {
                    Filter = "配置文件 (*.json)|*.json",
                    FileName = $"expert_config_{DateTime.Now:yyyyMMdd_HHmmss}.json",
                    Title = "导出配置文件"
                };

                if (dialog.ShowDialog() != true) return;

                var json = JsonSerializer.Serialize(config,
                    new JsonSerializerOptions
                    {
                        WriteIndented = true,
                        Encoder = System.Text.Encodings.Web.JavaScriptEncoder.UnsafeRelaxedJsonEscaping
                    });
                File.WriteAllText(dialog.FileName, json, new System.Text.UTF8Encoding(true));
                MessageBox.Show($"配置已导出到:\n{dialog.FileName}\n\n可使用「导入配置」功能在其他环境加载此配置。",
                    "导出成功", MessageBoxButton.OK, MessageBoxImage.Information);
                AppendLog($"已导出配置到: {dialog.FileName}");
            }
            catch (Exception ex)
            {
                MessageBox.Show($"导出配置失败: {ex.Message}", "错误", MessageBoxButton.OK, MessageBoxImage.Error);
            }
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
            // NseScriptArgsTextBox 已从 XAML 移除，保留配置字段为空（兼容旧配置文件）
            config.NseScriptArgs = "";
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
            config.RandomTargetOrder = RandomTargetOrderCheckBox?.IsChecked == true;

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
            config.OutputJson = OutputJsonCheckBox?.IsChecked == true;
            config.OutputHtml = OutputHtmlCheckBox?.IsChecked == true;
            config.OutputCsv = OutputCsvCheckBox?.IsChecked == true;
            config.ShowOpenOnly = ShowOpenOnlyCheckBox?.IsChecked == true;
            config.PingProbe = PingProbeCheckBox?.IsChecked == true;
            var spRange = GetSourcePortRange();
            config.SourcePortMin = spRange.min;
            config.SourcePortMax = spRange.max;

            return config;
        }

        private void ApplyConfig(ExpertScanConfiguration config)
        {
            _currentConfig = config;

            // Apply target settings
            if (SingleIpRadio != null)
            {
                switch (config.TargetType)
                {
                    case "Single": SingleIpRadio.IsChecked = true; break;
                    case "Range": IpRangeRadio.IsChecked = true; break;
                    case "CIDR": CidrRadio.IsChecked = true; break;
                    case "File": FileRadio.IsChecked = true; break;
                    case "Regex": RegexRadio.IsChecked = true; break;
                }
            }
            if (IpRangeRadio != null && config.TargetType == "Range") IpRangeRadio.IsChecked = true;
            if (CidrRadio != null && config.TargetType == "CIDR") CidrRadio.IsChecked = true;
            if (FileRadio != null && config.TargetType == "File") FileRadio.IsChecked = true;
            if (RegexRadio != null && config.TargetType == "Regex") RegexRadio.IsChecked = true;

            if (TargetInputTextBox != null) TargetInputTextBox.Text = config.TargetValue;
            if (ReverseDnsCheckBox != null) ReverseDnsCheckBox.IsChecked = config.ReverseDns;
            if (HostDiscoveryCheckBox != null) HostDiscoveryCheckBox.IsChecked = config.HostDiscovery;
            if (ExcludeHostsTextBox != null) ExcludeHostsTextBox.Text = config.ExcludeHosts;

            // Apply port settings
            if (CommonPortsRadio != null && config.PortMode == "Common") CommonPortsRadio.IsChecked = true;
            if (SensitivePortsRadio != null && config.PortMode == "Sensitive") SensitivePortsRadio.IsChecked = true;
            if (AllPortsRadio != null && config.PortMode == "All") AllPortsRadio.IsChecked = true;
            if (CustomPortsRadio != null && config.PortMode == "Custom") CustomPortsRadio.IsChecked = true;

            if (CustomPortsTextBox != null) CustomPortsTextBox.Text = config.CustomPorts;
            if (TcpScanCheckBox != null) TcpScanCheckBox.IsChecked = config.TcpScan;
            if (UdpScanCheckBox != null) UdpScanCheckBox.IsChecked = config.UdpScan;
            if (SynScanCheckBox != null) SynScanCheckBox.IsChecked = config.SynScan;
            if (ServiceVersionCheckBox != null) ServiceVersionCheckBox.IsChecked = config.ServiceDetection;
            if (OsDetectCheckBox != null) OsDetectCheckBox.IsChecked = config.OsDetection;
            if (ScriptScanCheckBox != null) ScriptScanCheckBox.IsChecked = config.ScriptScan;
            // NseScriptArgsTextBox 已从 XAML 移除，配置值仅做持久化，不再回填控件
            if (ServiceIntensityComboBox != null)
            {
                int maxIndex = ServiceIntensityComboBox.Items.Count - 1;
                int safeIndex = Math.Clamp(config.ServiceIntensity, 0, Math.Max(0, maxIndex));
                ServiceIntensityComboBox.SelectedIndex = safeIndex;
            }
            if (ExcludePortsTextBox != null) ExcludePortsTextBox.Text = config.ExcludePorts;

            // Apply performance settings
            if (TcpConcurrencySlider != null) TcpConcurrencySlider.Value = config.TcpConcurrency;
            if (UdpConcurrencySlider != null) UdpConcurrencySlider.Value = config.UdpConcurrency;
            if (TcpTimeoutSlider != null) TcpTimeoutSlider.Value = config.TcpTimeout;
            if (UdpTimeoutSlider != null) UdpTimeoutSlider.Value = config.UdpTimeout;
            if (RetrySlider != null) RetrySlider.Value = config.RetryCount;
            if (ServiceDetectTimeoutSlider != null)
                ServiceDetectTimeoutSlider.Value = config.ServiceDetectTimeout;
            if (RateLimitCheckBox != null) RateLimitCheckBox.IsChecked = config.RateLimit;
            if (PacketRateSlider != null) PacketRateSlider.Value = config.PacketRate;
            if (RandomizeCheckBox != null) RandomizeCheckBox.IsChecked = config.Randomize;
            if (StealthModeCheckBox != null) StealthModeCheckBox.IsChecked = config.StealthMode;
            if (RandomPortOrderCheckBox != null)
                RandomPortOrderCheckBox.IsChecked = config.RandomPortOrder;
            if (RandomTargetOrderCheckBox != null)
                RandomTargetOrderCheckBox.IsChecked = config.RandomTargetOrder;

            // Apply advanced settings
            if (SourcePortTextBox != null) SourcePortTextBox.Text = config.SourcePort;
            if (MtuTextBox != null) MtuTextBox.Text = config.Mtu;
            if (FragmentPacketsCheckBox != null) FragmentPacketsCheckBox.IsChecked = config.FragmentPackets;
            if (BadChecksumCheckBox != null) BadChecksumCheckBox.IsChecked = config.BadChecksum;
            if (DecoyScanCheckBox != null) DecoyScanCheckBox.IsChecked = config.DecoyScan;
            if (DecoyIpsTextBox != null) DecoyIpsTextBox.Text = config.DecoyIps;
            if (IdleScanCheckBox != null) IdleScanCheckBox.IsChecked = config.IdleScan;
            if (ZombieHostTextBox != null) ZombieHostTextBox.Text = config.ZombieHost;
            if (SourceRoutingCheckBox != null) SourceRoutingCheckBox.IsChecked = config.SourceRouting;
            if (VerbosityComboBox != null && config.Verbosity >= 0 && config.Verbosity <= 3)
                VerbosityComboBox.SelectedIndex = config.Verbosity;
            if (SaveOutputCheckBox != null) SaveOutputCheckBox.IsChecked = config.SaveOutput;
            if (OutputDirTextBox != null) OutputDirTextBox.Text = config.OutputDir;
            if (OutputJsonCheckBox != null) OutputJsonCheckBox.IsChecked = config.OutputJson;
            if (OutputHtmlCheckBox != null) OutputHtmlCheckBox.IsChecked = config.OutputHtml;
            if (OutputCsvCheckBox != null) OutputCsvCheckBox.IsChecked = config.OutputCsv;
            if (ShowOpenOnlyCheckBox != null) ShowOpenOnlyCheckBox.IsChecked = config.ShowOpenOnly;
            if (PingProbeCheckBox != null) PingProbeCheckBox.IsChecked = config.PingProbe;
            if (SourcePortMinTextBox != null) SourcePortMinTextBox.Text = config.SourcePortMin.ToString();
            if (SourcePortMaxTextBox != null) SourcePortMaxTextBox.Text = config.SourcePortMax.ToString();

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
            // 防止并发：扫描进行中再次点击直接忽略
            if (StartExpertScanButton != null && !StartExpertScanButton.IsEnabled)
            {
                return;
            }
            if (_isScanning)
            {
                AppendLog("扫描进行中，请先点击「停止」或等待当前扫描完成");
                return;
            }

            var config = CollectConfig();

            if (string.IsNullOrWhiteSpace(config.TargetValue))
            {
                MessageBox.Show("请输入扫描目标", "输入错误", MessageBoxButton.OK, MessageBoxImage.Warning);
                return;
            }

            // 自定义端口模式下，校验端口列表非空
            if (config.PortMode == "Custom" && string.IsNullOrWhiteSpace(config.CustomPorts))
            {
                MessageBox.Show("已选择「自定义端口」模式，请填写至少一个端口", "输入错误", MessageBoxButton.OK, MessageBoxImage.Warning);
                if (CustomPortsTextBox != null) CustomPortsTextBox.Focus();
                return;
            }

            _currentConfig = config;

            // Task 8.7：正则目标预校验。若目标类型是"Regex"，先验证正则表达式是否合法，
            // 避免把异常推迟到 ResolveTargets() 内被吞掉、退化为字面量匹配
            if (config.TargetType == "Regex")
            {
                try
                {
                    _ = new System.Text.RegularExpressions.Regex(config.TargetValue ?? "");
                }
                catch (ArgumentException rex)
                {
                    MessageBox.Show(
                        $"正则表达式无效: {rex.Message}\n\n请检查括号、字符类、转义符等。",
                        "目标配置错误", MessageBoxButton.OK, MessageBoxImage.Error);
                    AppendLog($"❌ 正则预校验失败: {rex.Message}");
                    return;
                }
            }

            // 预检查 OutputDir 设置，避免启动后才报错
            if (config.SaveOutput && string.IsNullOrWhiteSpace(config.OutputDir))
            {
                var dir = MessageBox.Show(
                    "已勾选「保存扫描输出到文件」，但输出目录为空。\n\n是否继续扫描（结果将只显示在界面，不保存到文件）？",
                    "输出目录未设置",
                    MessageBoxButton.YesNo,
                    MessageBoxImage.Question);
                if (dir == MessageBoxResult.No) return;
            }

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

            // 释放旧的 CancellationTokenSource，避免资源泄露
            _cancellationTokenSource?.Dispose();
            _cancellationTokenSource = new CancellationTokenSource();
            _scanStartTime = DateTime.Now;
            _isScanning = true;
            _userRequestedCancel = false;
            _elapsedTimer?.Stop();
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

            // 扫描进行中：禁用其他控制类按钮，防止状态错乱
            SetControlsEnabledWhileScanning(false);

            // Task 8.1：使用 TaskCompletionSource 包装后台任务，让 Closing 事件能安全等待完成
            _scanTaskCompletionSource = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
            _ = Task.Run(async () =>
            {
                try
                {
                    await ExecuteExpertScanAsync(config, _cancellationTokenSource.Token);
                }
                catch (Exception ex)
                {
                    AppendLog($"❌ 后台扫描任务异常: {ex.GetType().Name} - {ex.Message}");
                }
                finally
                {
                    _scanTaskCompletionSource?.TrySetResult(true);
                }
            });
        }

        /// <summary>
        /// 扫描过程中切换底部控制按钮的可用状态，避免与扫描流程冲突
        /// </summary>
        private void SetControlsEnabledWhileScanning(bool enabled)
        {
            if (LoadPresetButton != null) LoadPresetButton.IsEnabled = enabled;
            if (SavePresetButton != null) SavePresetButton.IsEnabled = enabled;
            if (ExportNmapButton != null) ExportNmapButton.IsEnabled = enabled;
            if (ValidateConfigButton != null) ValidateConfigButton.IsEnabled = enabled;
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
                // 修复线程错误：本方法运行在 Task.Run 后台线程，
                // 而 BulkObservableCollection 绑定到 DataGrid，直接 Clear() 会触发 Reset 通知，
                // DataGrid 在后台线程处理通知会抛出 "调用线程无法访问此对象" 异常。
                // 因此必须把集合清空调度到 UI 线程执行。
                Dispatcher.Invoke(() =>
                {
                    _allPortScanResults.Clear();
                    _allVulnResults.Clear();
                });
                _totalScannedTargets = 0;
                _totalOpenPorts = 0;

                // 把「性能调优」Tab 的配置转换成 PortScanner 能识别的 ScanPolicy。
                //
                // 重要背景：此处原先构造的是遗留模型 ScanOptions，但 PortScanner 并不接受它，
                // 该变量从未被使用，等于界面上配置的并发/超时/重试被全部丢弃，扫描器退回内部默认值：
                //   TCP 并发 = min(300, max(20, 端口数/10))，TCP 超时 = 500ms（端口数<=20 时为 800ms）
                // 后果是：用户在深度扫描里设置「20 并发 / 2000ms 超时」实际跑的是「300 并发 / 500ms」，
                // 超时过短会直接造成慢响应端口被误判为关闭，且调参毫无效果。
                // 现在统一改为下发 ScanPolicy，确保配置真正生效。
                _currentScanPolicy = BuildScanPolicy(config);

                if (config.StealthMode)
                {
                    AppendLog("⚠️ Stealth模式已启用：并发数限制为≤20，建议配合速率限制使用");
                }

                AppendLog($"⚙️ 扫描参数: TCP并发={_currentScanPolicy.RateLimitConfig.MaxConcurrentConnections}, " +
                          $"TCP超时={_currentScanPolicy.TimeoutConfig.TcpTimeout}ms, " +
                          $"UDP并发={_currentScanPolicy.RateLimitConfig.UdpMaxConcurrentConnections}, " +
                          $"UDP超时={_currentScanPolicy.TimeoutConfig.UdpTimeout}ms, " +
                          $"重试={config.RetryCount}, " +
                          $"限速={(config.RateLimit ? $"{_currentScanPolicy.RateLimitConfig.PortScanRate} 端口/秒" : "关闭")}");

                // 限速与自适应并发均依赖扫描策略下发，只有内置 C# 扫描器支持；
                // Rust 引擎走独立进程通信，这两项对其无效，需如实告知，避免用户误以为已生效。
                if (_useRustScanner && (config.RateLimit || _adaptiveConcurrencyEnabled))
                {
                    AppendLog("ℹ️ 注意：速率限制/自适应并发仅对内置 C# 扫描器生效；若本次扫描由 Rust 引擎执行则该项不生效。");
                }

                // 初始化自适应并发控制器（默认关闭，需在「性能调优」Tab 勾选）
                if (_adaptiveConcurrencyEnabled)
                {
                    var baseConcurrency = _currentScanPolicy.RateLimitConfig.MaxConcurrentConnections;
                    _adaptiveController = new AdaptiveConcurrencyController(
                        baseConcurrency: baseConcurrency,
                        minConcurrency: Math.Max(1, baseConcurrency / 4),
                        maxConcurrency: baseConcurrency);
                    // 控制器内部还有一道硬上限 ProcessorCount*4（它原本面向 CPU 密集任务，
                    // 而端口扫描是 IO 密集场景，需要更高并发），这里如实提示实际生效上限，
                    // 避免用户设了 200 却只跑 32 却不知道原因。
                    var effectiveMax = Math.Min(Environment.ProcessorCount * 4, baseConcurrency);
                    AppendLog($"🧠 自适应并发已启用: 基准 {baseConcurrency}, 下限 {Math.Max(1, baseConcurrency / 4)}, 实际上限 {effectiveMax}（CPU 核数限制）");
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

                // 预启动 Rust 服务（跨目标复用，避免每次启动/停止的开销）
                if (_useRustScanner)
                {
                    _rustServiceStarted = false;
                    try
                    {
                        if (_rustClient == null)
                        {
                            _rustClient = new RustScannerClient();
                            _rustClient.OnLog += (s, msg) => AppendLog($"[Rust] {msg}");
                            _rustClient.OnProgressChanged += (s, p) =>
                            {
                                if (p.ProgressPercent > 0)
                                {
                                    Dispatcher.BeginInvoke(new Action(() =>
                                    {
                                        ExpertScanProgressBar.Value = p.ProgressPercent;
                                    }), DispatcherPriority.Background);
                                }
                            };
                        }

                        var exe = !string.IsNullOrEmpty(_currentRustExe) && File.Exists(_currentRustExe)
                            ? _currentRustExe
                            : RustScannerClient.FindRustScannerExecutable();
                        if (exe != null)
                        {
                            _currentRustExe = exe;
                            var started = await _rustClient.StartServiceAsync(
                                exe,
                                config.TcpConcurrency > 0 ? config.TcpConcurrency : 1000,
                                config.TcpTimeout > 0 ? config.TcpTimeout : 200,
                                config.UdpTimeout > 0 ? config.UdpTimeout : 500);
                            if (started)
                            {
                                var connected = await _rustClient.ConnectAsync();
                                _rustServiceStarted = connected;
                                if (connected)
                                    AppendLog("🚀 Rust 引擎已预启动，将在多目标间复用");
                                else
                                    AppendLog("⚠️ Rust 引擎连接失败，将降级到内置扫描器");
                            }
                            else
                            {
                                AppendLog("⚠️ Rust 引擎启动失败，将降级到内置扫描器");
                            }
                        }
                        else
                        {
                            AppendLog("⚠️ 找不到 Rust 引擎，将降级到内置扫描器");
                        }
                    }
                    catch (Exception ex)
                    {
                        AppendLog($"⚠️ Rust 引擎预启动异常: {ex.Message}，将降级到内置扫描器");
                        _rustServiceStarted = false;
                    }
                }

                int completedCount = 0;
                var failedTargets = new List<string>();
                foreach (var target in targets)
                {
                    if (cancellationToken.IsCancellationRequested)
                        break;

                    // 记录本目标扫描的开始时间（用于准确计算本目标耗时）
                    var targetStartTime = DateTime.Now;
                    // 本目标的漏洞结果（独立保存，避免多目标间互相污染历史记录）
                    var targetVulnResults = new List<VulnerabilityResult>();

                    Dispatcher.BeginInvoke(new Action(() =>
                    {
                        StartExpertScanButton.Content = $"⏳ 扫描中: {target} ({completedCount}/{targets.Count})";
                        ExpertScanProgressText.Text = $"扫描中: {target} ({completedCount + 1}/{targets.Count})";
                    }), DispatcherPriority.Background);

                    AppendLog($"[{completedCount + 1}/{targets.Count}] 开始扫描目标: {target}");

                    // 自适应并发：按内存压力调节本目标的并发（未启用时为空操作）
                    ApplyAdaptiveConcurrency();

                    // 反向 DNS 解析（若启用且目标是 IP）
                    string resolvedHostname = null;
                    if (config.ReverseDns && System.Net.IPAddress.TryParse(target, out _))
                    {
                        AppendLog($"  正在执行反向 DNS 解析: {target}");
                        resolvedHostname = await ResolveHostnameAsync(target, cancellationToken);
                        // Task 8.3：根据返回值类型输出精确日志（区分"无 PTR"、"超时"、"网络错误"等）
                        if (string.IsNullOrWhiteSpace(resolvedHostname))
                        {
                            AppendLog($"  反向 DNS 解析: {target} 无 PTR 记录");
                        }
                        else if (resolvedHostname == "__TIMEOUT__")
                        {
                            AppendLog($"  反向 DNS 解析超时: {target}");
                        }
                        else if (resolvedHostname.StartsWith("__SOCKERR:"))
                        {
                            AppendLog($"  反向 DNS 网络错误: {target} - {resolvedHostname.Substring("__SOCKERR:".Length)}");
                        }
                        else if (resolvedHostname.StartsWith("__"))
                        {
                            AppendLog($"  反向 DNS 解析失败: {target} - {resolvedHostname}");
                        }
                        else
                        {
                            AppendLog($"  反向 DNS 解析成功: {target} -> {resolvedHostname}");
                        }
                    }

                    // 主机存活探测（若启用）
                    if (config.HostDiscovery)
                    {
                        bool alive = await IsHostAliveAsync(target, cancellationToken);
                        if (!alive)
                        {
                            AppendLog($"  ⚠️ 主机存活探测失败: {target} 可能不在线，仍尝试扫描");
                        }
                        else
                        {
                            AppendLog($"  ✓ 主机存活: {target}");
                        }
                    }

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
                        foreach (var result in allResults)
                        {
                            result.TargetIp = target;
                        }

                        // 使用 BeginInvoke + Background 优先级在 UI 线程批量添加（不阻塞扫描线程）
                        // AddRange 内部已改为 Reset 通知（规避 ListCollectionView 的范围操作限制），
                        // 一次调用即只触发一次通知，无需再分批。
                        var capturedOpenCount = openPorts.Count;
                        var resultsSnapshot = allResults; // 捕获到本地，便于 lambda 闭包
                        Dispatcher.BeginInvoke(new Action(() =>
                        {
                            try
                            {
                                _allPortScanResults.AddRange(resultsSnapshot);
                            }
                            catch (Exception addEx)
                            {
                                AppendLog($"  ⚠️ 写入实时端口结果失败: {addEx.Message}");
                            }
                            _totalScannedTargets++;
                            _totalOpenPorts += capturedOpenCount;
                            if (ScannedTargetsStat != null) ScannedTargetsStat.Text = _totalScannedTargets.ToString();
                            if (OpenPortsStat != null) OpenPortsStat.Text = _totalOpenPorts.ToString();
                            if (ExpertScanProgressBar != null) ExpertScanProgressBar.Value = (double)_totalScannedTargets / targets.Count * 100;
                            if (ExpertScanProgressText != null) ExpertScanProgressText.Text = $"扫描中: {_totalScannedTargets}/{targets.Count} 目标";
                        }), DispatcherPriority.Background);

                        // 漏洞扫描 - 发现开放端口即进行基础漏洞匹配（不强制要求开启 ScriptScan 或 ServiceDetection）
                        // 修复：RSUT 协议扫描时，即使未勾选服务检测/NSE脚本，也应执行基础漏洞库匹配
                        bool shouldRunVulnScan = openPorts.Any();
                        if (shouldRunVulnScan)
                        {
                            AppendLog($"  开始漏洞扫描: {target} ({openPorts.Count} 个开放端口)...");
                            var vulnResults = await _vulnerabilityScanner.ScanVulnerabilitiesAsync(target, openPorts, cancellationToken);

                            // 使用 BeginInvoke + AddRange（Reset 通知）批量更新，仅触发一次 CollectionChanged
                            targetVulnResults.AddRange(vulnResults);
                            var vulnSnapshot = vulnResults;
                            Dispatcher.BeginInvoke(new Action(() =>
                            {
                                try
                                {
                                    _allVulnResults.AddRange(vulnSnapshot);
                                    if (VulnerabilitiesStat != null) VulnerabilitiesStat.Text = _allVulnResults.Count.ToString();
                                }
                                catch (Exception addEx)
                                {
                                    AppendLog($"  ⚠️ 写入实时漏洞结果失败: {addEx.Message}");
                                }
                            }), DispatcherPriority.Background);

                            AppendLog($"  漏洞扫描完成: 发现 {vulnResults.Count} 个漏洞");
                        }
                        else if (openPorts.Count == 0)
                        {
                            AppendLog($"  跳过漏洞扫描: 无开放端口");
                        }
                        else if (!config.ScriptScan && !config.ServiceDetection)
                        {
                            AppendLog($"  跳过漏洞扫描: 脚本扫描和服务检测均未启用");
                        }

                        // 弱口令扫描（含 PostgreSQL 5432 / MSSQL 1433）
                        var weakPassPorts = openPorts.Where(p =>
                            p.PortNumber == 21 || p.PortNumber == 22 || p.PortNumber == 23 ||
                            p.PortNumber == 3306 || p.PortNumber == 5432 || p.PortNumber == 1433 ||
                            p.PortNumber == 6379 || p.PortNumber == 27017).ToList();
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
                                targetVulnResults.AddRange(weakPassResults);
                                var weakSnapshot = weakPassResults;
                                Dispatcher.BeginInvoke(new Action(() =>
                                {
                                    try
                                    {
                                        _allVulnResults.AddRange(weakSnapshot);
                                        if (VulnerabilitiesStat != null) VulnerabilitiesStat.Text = _allVulnResults.Count.ToString();
                                    }
                                    catch (Exception addEx)
                                    {
                                        AppendLog($"  ⚠️ 写入弱口令结果失败: {addEx.Message}");
                                    }
                                }), DispatcherPriority.Background);
                            }

                            AppendLog($"  弱口令检测完成: 发现 {weakPassResults.Count} 个弱口令/未授权访问漏洞");
                        }

                        // 计算本目标耗时（注意：不是累计时间，是本目标开始到现在的真实耗时）
                        var targetDuration = (DateTime.Now - targetStartTime).TotalSeconds;
                        // 综合风险等级：同时考虑开放端口数和高危漏洞
                        string targetRiskLevel = CalculateRiskLevel(openPorts.Count, targetVulnResults.Count);

                        // Save to scan history database - 使用本目标的漏洞数据，避免累积污染
                        var scanResult = new CompleteScanResult
                        {
                            TargetIp = target,
                            ScanType = $"专家模式-{"TCP" + (config.UdpScan ? "+UDP" : "")}扫描",
                            ScanTime = targetStartTime,
                            ScanDuration = targetDuration,
                            OpenPortsCount = openPorts.Count,
                            VulnerabilitiesCount = targetVulnResults.Count,
                            RiskLevel = targetRiskLevel,
                            PortScanResults = allResults,
                            VulnerabilityResults = new List<VulnerabilityResult>(targetVulnResults),
                            RiskAssessment = new RiskAssessmentSummary
                            {
                                TotalVulnerabilities = targetVulnResults.Count,
                                RiskScore = Math.Min(100, openPorts.Count * 5 + targetVulnResults.Count * 10),
                                RiskLevel = targetRiskLevel == "高" ? "高风险" : (targetRiskLevel == "中" ? "中风险" : "低风险"),
                                SecurityAdvice = $"专家模式扫描完成，发现 {openPorts.Count} 个开放端口和 {targetVulnResults.Count} 个漏洞。建议对高危端口和漏洞进行安全加固。"
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

                        // Save results to file - 使用唯一时间戳避免多目标时文件覆盖
                        if (config.SaveOutput && !string.IsNullOrWhiteSpace(config.OutputDir))
                        {
                            var safeFileName = target.Replace(".", "_").Replace("/", "_");
                            var filePath = Path.Combine(config.OutputDir, $"expert_scan_{safeFileName}_{targetStartTime:yyyyMMdd_HHmmss_fff}.json");
                            var dir = Path.GetDirectoryName(filePath);
                            if (!string.IsNullOrEmpty(dir) && !Directory.Exists(dir))
                            {
                                Directory.CreateDirectory(dir);
                            }
                            var json = JsonSerializer.Serialize(scanResult, new JsonSerializerOptions { WriteIndented = true });
                            File.WriteAllText(filePath, json, new System.Text.UTF8Encoding(true));
                        }

                        completedCount++;
                    }
                    catch (OperationCanceledException)
                    {
                        break;
                    }
                    catch (Exception ex)
                    {
                        // 此处刻意不再同步弹窗：
                        // 1) 多目标扫描时每个失败目标都 Dispatcher.Invoke 弹一次窗，
                        //    会阻塞后台扫描线程，用户必须逐个点掉 N 个对话框，表现为"界面卡死"；
                        // 2) 同步 Invoke 在 UI 线程正忙于处理批量结果通知时还会长时间排队。
                        // 改为记录日志，扫描结束后在汇总弹窗里统一告知失败数量。
                        AppendLog($"  ❌ 扫描 {target} 时出错: {ex.GetType().Name} - {ex.Message}");
                        failedTargets.Add(target);
                    }
                }

                // 判断是否被取消
                bool wasCancelled = cancellationToken.IsCancellationRequested;

                // 统一清理：释放 CTS、复位标志、停止计时器、恢复按钮
                FinalizeScan();

                // 窗口可能已被强制关闭（Closing 里 3 秒超时后直接销毁），
                // 此时 Dispatcher 已经开始关闭，再调用 Invoke 会抛异常并打断收尾流程。
                if (Dispatcher.HasShutdownStarted || Dispatcher.HasShutdownFinished)
                    return;

                Dispatcher.Invoke(() =>
                {
                    if (wasCancelled)
                    {
                        // 区分"用户取消"和"外部取消"
                        if (_userRequestedCancel)
                        {
                            AppendLog("🛑 用户主动取消了扫描");
                        }
                        else
                        {
                            AppendLog("⚠️ 扫描被外部取消（窗口关闭/超时等）");
                        }
                        ExpertScanProgressText.Text = $"已取消 - 扫描了 {completedCount}/{targets.Count} 个目标";
                        var cancelSummary = $"扫描已取消！\n共扫描 {completedCount}/{targets.Count} 个目标\n发现 {_totalOpenPorts} 个开放端口\n发现 {_allVulnResults.Count} 个漏洞";
                        if (failedTargets.Count > 0)
                            cancelSummary += $"\n⚠️ {failedTargets.Count} 个目标扫描失败（详见扫描日志）";
                        MessageBox.Show(cancelSummary, "扫描已取消", MessageBoxButton.OK, MessageBoxImage.Warning);
                    }
                    else
                    {
                        AppendLog("✅ 扫描正常完成");
                        if (ExpertScanProgressBar != null) ExpertScanProgressBar.Value = 100;
                        if (ExpertScanProgressText != null) ExpertScanProgressText.Text = "扫描完成";
                        // 扫描完成后自动按风险评分降序排列结果，让高危端口优先可见
                        // 使用 BulkObservableCollection.AddRangeReset 批量更新（仅触发一次 Reset）
                        try
                        {
                            if (_allPortScanResults != null && _allPortScanResults.Count > 0)
                            {
                                var sortedByRisk = Services.PortScanner.SortByRiskDesc(_allPortScanResults.ToList());
                                _allPortScanResults.AddRangeReset(sortedByRisk);
                            }
                        }
                        catch (Exception sortEx)
                        {
                            AppendLog($"结果排序失败: {sortEx.Message}");
                        }
                        try { RefreshCharts(); } catch { /* 图表未初始化时安全忽略 */ }
                        int finalVulnCount = _allVulnResults?.Count ?? 0;
                        var doneSummary = $"专家模式扫描完成！\n共扫描 {completedCount}/{targets.Count} 个目标\n发现 {_totalOpenPorts} 个开放端口\n发现 {finalVulnCount} 个漏洞";
                        if (failedTargets.Count > 0)
                            doneSummary += $"\n⚠️ {failedTargets.Count} 个目标扫描失败：{string.Join(", ", failedTargets.Take(3))}{(failedTargets.Count > 3 ? "..." : "")}";
                        MessageBox.Show(doneSummary, "扫描完成", MessageBoxButton.OK, MessageBoxImage.Information);
                    }
                });
            }
            catch (Exception ex)
            {
                Dispatcher.Invoke(() =>
                {
                    AppendLog($"❌ 扫描异常: {ex.Message}");
                    MessageBox.Show($"扫描过程中发生错误: {ex.Message}", "错误", MessageBoxButton.OK, MessageBoxImage.Error);
                });
                // 异常路径也要清理资源（FinalizeScan 内部 try/catch 保护）
                FinalizeScan();
            }
        }

        private async Task<List<PortScanResult>> ExecuteRustScanAsync(string target, List<int> ports, ExpertScanConfiguration config, CancellationToken cancellationToken)
        {
            var allResults = new List<PortScanResult>();
            try
            {
                // 使用预启动的 Rust 服务（跨目标复用）
                if (_rustClient == null || !_rustServiceStarted)
                {
                    // 服务未预启动，尝试按需启动
                    if (_rustClient == null)
                    {
                        _rustClient = new RustScannerClient();
                        _rustClient.OnLog += (s, msg) => AppendLog($"[Rust] {msg}");
                        _rustClient.OnProgressChanged += (s, p) =>
                        {
                            if (p.ProgressPercent > 0)
                            {
                                Dispatcher.BeginInvoke(new Action(() =>
                                {
                                    ExpertScanProgressBar.Value = p.ProgressPercent;
                                }), DispatcherPriority.Background);
                            }
                        };
                    }

                    var exe = !string.IsNullOrEmpty(_currentRustExe) && File.Exists(_currentRustExe)
                        ? _currentRustExe
                        : RustScannerClient.FindRustScannerExecutable();
                    if (exe == null)
                    {
                        AppendLog("  ⚠️ 找不到 Rust 引擎可执行文件，降级到内置 C# 扫描器");
                        var progress = new Progress<int>(p => { });
                        return await ExecuteNativeScanAsync(target, ports, config, progress, cancellationToken);
                    }
                    _currentRustExe = exe;

                    var started = await _rustClient.StartServiceAsync(
                        exe,
                        config.TcpConcurrency > 0 ? config.TcpConcurrency : 1000,
                        config.TcpTimeout > 0 ? config.TcpTimeout : 200,
                        config.UdpTimeout > 0 ? config.UdpTimeout : 500);
                    if (!started)
                    {
                        AppendLog("  ⚠️ Rust 服务启动失败, 降级到内置 C# 扫描器");
                        var progress = new Progress<int>(p => { });
                        return await ExecuteNativeScanAsync(target, ports, config, progress, cancellationToken);
                    }

                    var connected = await _rustClient.ConnectAsync();
                    if (!connected)
                    {
                        AppendLog("  ⚠️ 连接 Rust 服务失败, 降级到内置 C# 扫描器");
                        try { _rustClient.StopService(); } catch { }
                        var progress = new Progress<int>(p => { });
                        return await ExecuteNativeScanAsync(target, ports, config, progress, cancellationToken);
                    }
                    _rustServiceStarted = true;
                }
                else
                {
                    // 服务已预启动，但若上次扫描遇到异常需要重置连接
                    if (!_rustClient.IsConnected)
                    {
                        AppendLog("  ⚠️ Rust 连接已断开，尝试重新连接...");
                        try
                        {
                            var connected = await _rustClient.ConnectAsync();
                            if (!connected)
                            {
                                AppendLog("  ⚠️ 重新连接 Rust 服务失败，降级到内置扫描器");
                                var progress = new Progress<int>(p => { });
                                return await ExecuteNativeScanAsync(target, ports, config, progress, cancellationToken);
                            }
                        }
                        catch
                        {
                            AppendLog("  ⚠️ 重新连接 Rust 服务异常，降级到内置扫描器");
                            var progress = new Progress<int>(p => { });
                            return await ExecuteNativeScanAsync(target, ports, config, progress, cancellationToken);
                        }
                    }
                }

                var profileConfig = new ScanProfileConfig
                {
                    TcpConcurrency = config.TcpConcurrency,
                    UdpConcurrency = config.UdpConcurrency,
                    TimeoutMs = config.TcpTimeout,
                    // UDP 超时单独下发，避免 Rust 端复用 TCP 超时导致 UDP 结果失真
                    UdpTimeoutMs = config.UdpTimeout > 0 ? config.UdpTimeout : 0,
                    RetryCount = config.RetryCount,
                    EnableServiceDetection = config.ServiceDetection,
                    EnablePingProbe = config.PingProbe && config.HostDiscovery
                };

                // Rust 引擎的协议取值约定为 tcp / udp / both（见 scanner.rs 的 ScanConfig.protocol 注释）。
                // 此前传 "tcp,udp" 会被 Rust 走 else 分支按 both 处理，但并不会命中
                // proto == "both" 的 UDP 并发名额分配逻辑，导致 UDP 并发控制失效、UDP 扫描大量超时。
                // 因此 TCP+UDP 同时勾选时必须传 "both"。
                var protocol = config.TcpScan && config.UdpScan ? "both" : (config.UdpScan ? "udp" : "tcp");
                var rustResults = await _rustClient.ScanPortsAsync(
                    new List<string> { target }, ports, protocol,
                    config.TcpConcurrency, config.TcpTimeout, config.UdpTimeout,
                    config.ServiceDetection, true, cancellationToken, profileConfig);

                AppendLog($"  Rust返回原始结果数: {rustResults.Count}");
                foreach (var r in rustResults)
                {
                    // 修复：增强状态判断兼容性，支持多种 open 状态格式（如 "OPEN", "Open", " open " 等）
                    // 同时支持 Rust 端返回的中文状态 "开放" / "关闭" / "过滤"
                    string statusNormalized = r.Status?.Trim().ToLowerInvariant() ?? "";
                    bool isOpen = statusNormalized == "open" || statusNormalized == "opened" || statusNormalized == "true" || statusNormalized == "开放";
                    string confidence = isOpen ? "高" : "低";
                    AppendLog($"    原始结果: {r.TargetIp}:{r.Port} status=[{r.Status}] normalized=[{statusNormalized}] isOpen={isOpen} svc={r.Service}");
                    allResults.Add(new PortScanResult
                    {
                        TargetIp = !string.IsNullOrWhiteSpace(r.TargetIp) ? r.TargetIp : target,
                        PortNumber = r.Port,
                        Status = isOpen ? "开放" : "关闭",
                        Service = r.Service ?? "",
                        ServiceVersion = r.Version ?? "",
                        ResponseTime = r.ScanTimeMs > 0 ? r.ScanTimeMs.ToString() : "-",
                        Confidence = confidence,
                        ScanDurationMs = r.ScanTimeMs
                    });
                }
                AppendLog($"  Rust扫描完成: {target} - {allResults.Count(r2 => r2.Status == "开放")} 个开放端口");
                // 注意：不再 StopService()，由外部循环统一管理生命周期
            }
            catch (Exception ex)
            {
                AppendLog($"  Rust引擎扫描失败，降级到内置扫描器: {ex.Message}");
                _rustServiceStarted = false; // 标记服务不可用，下次尝试重新启动
                try { _rustClient?.StopService(); } catch { }
                var progress = new Progress<int>(p => { });
                allResults = await ExecuteNativeScanAsync(target, ports, config, progress, cancellationToken);
            }
            return allResults;
        }

        private async Task<List<PortScanResult>> ExecuteNativeScanAsync(string target, List<int> ports, ExpertScanConfiguration config, IProgress<int> progress, CancellationToken cancellationToken)
        {
            var allResults = new List<PortScanResult>();

            // 用一个字典记录哪个结果是 TCP / UDP，避免按索引读取的脆弱写法
            // 即使将来调整 tasks 的顺序（先 UDP 后 TCP）也不会出错
            var tcpResults = new List<PortScanResult>();
            var udpResults = new List<PortScanResult>();

            // 读取当前生效的扫描策略（由 ExecuteExpertScanAsync 依据「性能调优」Tab 生成）。
            // 传入后 PortScanner 才会使用用户配置的并发与超时，否则走其内部默认值。
            var policy = _currentScanPolicy;

            var tasks = new List<Task>();
            if (config.TcpScan)
                tasks.Add(_portScanner.ScanTcpPortsAsync(target, ports, progress, cancellationToken, policy)
                    .ContinueWith(t => { if (t.Status == TaskStatus.RanToCompletion) lock (tcpResults) { tcpResults.AddRange(t.Result); } },
                        TaskScheduler.Default));
            if (config.UdpScan)
                tasks.Add(_portScanner.ScanUdpPortsAsync(target, ports, progress, cancellationToken, policy)
                    .ContinueWith(t => { if (t.Status == TaskStatus.RanToCompletion) lock (udpResults) { udpResults.AddRange(t.Result); } },
                        TaskScheduler.Default));

            if (tasks.Count > 0)
            {
                try
                {
                    await Task.WhenAll(tasks);
                }
                catch (Exception ex)
                {
                    // 某个扫描任务失败时记录并继续
                    AppendLog($"  扫描任务执行异常: {ex.Message}");
                }

                // 合并：TCP 优先，UDP 只在 TCP 未覆盖的端口上补充（避免对同一端口的两种协议结果混淆）
                var mergedPorts = new Dictionary<int, PortScanResult>();
                foreach (var r in tcpResults) { mergedPorts[r.PortNumber] = r; }
                foreach (var r in udpResults) { if (!mergedPorts.ContainsKey(r.PortNumber)) { mergedPorts[r.PortNumber] = r; } }
                allResults = mergedPorts.Values.ToList();
            }
            return allResults;
        }

        /// <summary>
        /// 依据「性能调优」Tab 的配置构造扫描策略（PortScanner 唯一识别的配置模型）。
        ///
        /// 映射关系：
        ///   TCP并发 -> RateLimitConfig.MaxConcurrentConnections
        ///   UDP并发 -> RateLimitConfig.UdpMaxConcurrentConnections
        ///   TCP超时 -> TimeoutConfig.TcpTimeout
        ///   UDP超时 -> TimeoutConfig.UdpTimeout
        ///
        /// 两个易踩的坑：
        /// 1) 并发值必须 > 0。PortScanner 内部用 `new SemaphoreSlim(maxConcurrent)`，
        ///    传 0 或负数会直接抛 ArgumentOutOfRangeException，导致整个扫描任务失败。
        ///    界面滑块理论上不会给出 0，但预设文件/历史配置反序列化可能带入 0，故此处兜底。
        /// 2) SmallPortRangeTimeout 必须跟随用户配置的 TCP 超时。
        ///    PortScanner 在端口数 <= 20 时会改用该值（默认 800ms）覆盖 TcpTimeout，
        ///    若不一起设置，小端口范围扫描仍会忽略用户的超时配置。
        /// </summary>
        private NetSecurityScanner.Models.ScanPolicy BuildScanPolicy(ExpertScanConfiguration config)
        {
            var tcpConcurrency = config.TcpConcurrency > 0 ? config.TcpConcurrency : 50;
            var udpConcurrency = config.UdpConcurrency > 0 ? config.UdpConcurrency : 20;
            var tcpTimeout = config.TcpTimeout > 0 ? config.TcpTimeout : 500;
            var udpTimeout = config.UdpTimeout > 0 ? config.UdpTimeout : 1000;

            // Stealth 模式要求低并发慢速扫描，这里强制收敛（与界面提示的"≤20"保持一致）
            if (config.StealthMode)
            {
                tcpConcurrency = Math.Min(tcpConcurrency, 20);
                udpConcurrency = Math.Min(udpConcurrency, 10);
            }

            return new NetSecurityScanner.Models.ScanPolicy
            {
                Name = "专家模式自定义策略",
                Description = $"TCP并发{tcpConcurrency}/超时{tcpTimeout}ms, UDP并发{udpConcurrency}/超时{udpTimeout}ms",
                NetworkScanConfig = new NetSecurityScanner.Models.NetworkScanConfig
                {
                    EnableTcpScan = config.TcpScan,
                    EnableUdpScan = config.UdpScan,
                    PortTimeout = tcpTimeout,
                    SmallPortRangeThreshold = 20
                },
                RateLimitConfig = new NetSecurityScanner.Models.RateLimitConfig
                {
                    MaxConcurrentConnections = tcpConcurrency,
                    UdpMaxConcurrentConnections = udpConcurrency,
                    // 速率限制：用户勾选后才启用。此前该配置只用于生成 Nmap 命令，
                    // 实际扫描全速跑，勾选与否毫无区别。
                    // 注意 PortScanRate 本身有默认值(100)，但 PortScanner 仅在
                    // EnableRateLimit=true 时才限流，故未勾选时不会被意外限速。
                    EnableRateLimit = config.RateLimit,
                    PortScanRate = config.PacketRate > 0 ? config.PacketRate : 100
                },
                TimeoutConfig = new NetSecurityScanner.Models.TimeoutConfig
                {
                    TcpTimeout = tcpTimeout,
                    UdpTimeout = udpTimeout,
                    SmallPortRangeTimeout = tcpTimeout
                }
            };
        }

        /// <summary>
        /// 「自适应并发」复选框状态变化。
        ///
        /// 允许扫描中途切换：开启时若正在扫描就即时创建控制器（下次目标立即生效），
        /// 关闭时立即释放。这样既不用禁用控件，也不会出现"开关与控制器状态不一致"。
        /// 未扫描时不必创建控制器——扫描开始时 ExecuteExpertScanAsync 会按最终配置创建。
        /// </summary>
        private void AdaptiveConcurrencyCheckBox_Changed(object sender, RoutedEventArgs e)
        {
            _adaptiveConcurrencyEnabled = AdaptiveConcurrencyCheckBox?.IsChecked == true;

            if (_adaptiveConcurrencyEnabled)
            {
                if (_isScanning && _adaptiveController == null && _currentScanPolicy != null)
                {
                    var baseConcurrency = _currentScanPolicy.RateLimitConfig.MaxConcurrentConnections;
                    _adaptiveController = new AdaptiveConcurrencyController(
                        baseConcurrency: baseConcurrency,
                        minConcurrency: Math.Max(1, baseConcurrency / 4),
                        maxConcurrency: baseConcurrency);
                }
                AppendLog("🧠 自适应并发已开启：扫描中将根据内存压力动态调节并发");
            }
            else
            {
                DisposeAdaptiveConcurrency();
                AppendLog("自适应并发已关闭：将使用固定并发");
            }
        }

        /// <summary>
        /// 自适应并发：按当前内存压力动态调节 TCP 并发（仅在用户启用时生效，否则为空操作）。
        ///
        /// 为什么需要：全端口扫描（65535 端口 × 多目标）会在短时间内产生海量 PortScanResult 对象，
        /// 内存吃紧时若仍维持高并发，轻则 GC 频繁拖慢扫描，重则 OOM 导致程序崩溃、扫描结果全丢。
        ///
        /// 实现方式：每个目标扫描前调用一次，直接改写 _currentScanPolicy 的并发值，
        /// 由于策略是共享字段，后续目标与 Rust 降级路径都会自动使用调整后的并发。
        ///
        /// 注意：这里捕获所有异常——自适应调节属于优化项，绝不能因它出错而中断扫描。
        /// </summary>
        private void ApplyAdaptiveConcurrency()
        {
            if (!_adaptiveConcurrencyEnabled || _adaptiveController == null || _currentScanPolicy == null)
                return;

            try
            {
                var current = _currentScanPolicy.RateLimitConfig.MaxConcurrentConnections;
                var adjusted = _adaptiveController.AdjustConcurrency(current);
                adjusted = Math.Max(1, adjusted); // 并发必须 > 0，否则 SemaphoreSlim 构造会抛异常

                if (adjusted != current)
                {
                    _currentScanPolicy.RateLimitConfig.MaxConcurrentConnections = adjusted;
                    var direction = adjusted < current ? "↓ 内存压力升高" : "↑ 内存压力缓解";
                    AppendLog($"🧠 自适应并发: {current} → {adjusted}（{direction}）");
                }

                _adaptiveController.CheckAndTriggerGc();
            }
            catch (Exception ex)
            {
                AppendLog($"⚠️ 自适应并发调节失败（已忽略，不影响扫描）: {ex.Message}");
            }
        }

        /// <summary>
        /// 释放自适应并发控制器持有的资源（内存监控器）。
        /// 无论扫描正常完成、被取消还是异常终止都会走到这里。
        /// </summary>
        private void DisposeAdaptiveConcurrency()
        {
            try
            {
                _adaptiveController?.Dispose();
            }
            catch { /* 释放阶段的异常不影响主流程 */ }
            finally
            {
                _adaptiveController = null;
            }
        }

        /// <summary>
        /// 综合计算单目标风险等级
        /// 风险权重：每个开放端口 = 5 分，每个漏洞 = 10 分，超过 50 分 = 高，20-50 = 中，< 20 = 低
        /// </summary>
        private string CalculateRiskLevel(int openPortCount, int vulnerabilityCount)
        {
            int score = openPortCount * 5 + vulnerabilityCount * 10;
            if (score >= 50 || vulnerabilityCount >= 5) return "高";
            if (score >= 20) return "中";
            return "低";
        }

        /// <summary>
        /// 反向 DNS 解析：IP -> 主机名
        /// 改进：返回特定哨兵字符串标识错误类型，调用方能区分"无 PTR 记录"、"超时"、"网络错误"等情况
        /// 哨兵：null=无 PTR，__TIMEOUT__=超时，__INVALID_IP__=IP 非法，__SOCKERR:xxx=Socket 错误，__ERR:xxx=其它异常
        /// </summary>
        private async Task<string> ResolveHostnameAsync(string ip, CancellationToken cancellationToken)
        {
            try
            {
                // 使用独立的CTS，避免与外部cancellationToken混淆
                using (var cts = new CancellationTokenSource(2000)) // 2秒超时
                {
                    using (var linkedCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, cts.Token))
                    {
                        // 使用Task.WhenAny确保超时机制可靠
                        var dnsTask = Dns.GetHostEntryAsync(ip);
                        var timeoutTask = Task.Delay(2500, linkedCts.Token);

                        var completedTask = await Task.WhenAny(dnsTask, timeoutTask).ConfigureAwait(false);

                        if (completedTask == timeoutTask)
                        {
                            // 取消dnsTask避免泄漏
                            try { cts.Cancel(); } catch { }
                            // 关键：dnsTask 此时仍在后台运行。若它最终因 DNS 解析失败而抛出
                            // （例如无 PTR 记录时报"不知道这样的主机"），异常无人接管就会变成
                            // UnobservedTaskException，并在 finalizer 线程被重新抛出。
                            // 实测日志中已出现大量此类告警，必须在此消化。
                            ObserveTaskException(dnsTask);
                            return "__TIMEOUT__";
                        }

                        // 检查dnsTask是否已取消
                        if (dnsTask.IsCanceled)
                        {
                            ObserveTaskException(dnsTask);
                            return "__TIMEOUT__";
                        }

                        var entry = await dnsTask;
                        if (!string.IsNullOrWhiteSpace(entry.HostName) && entry.HostName != ip)
                            return entry.HostName;
                        if (entry.Aliases != null && entry.Aliases.Length > 0)
                            return entry.Aliases[0];
                        return null;  // 真的无 PTR
                    }
                }
            }
            catch (OperationCanceledException) { return "__TIMEOUT__"; }
            catch (SocketException sex) { return $"__SOCKERR:{sex.SocketErrorCode}"; }
            catch (ArgumentException) { return "__INVALID_IP__"; }
            catch (Exception ex) { return $"__ERR:{ex.GetType().Name}"; }
        }

        /// <summary>
        /// 主机存活探测：尝试 TCP 连接常见端口 + ICMP ping（如可用）
        /// </summary>
        private async Task<bool> IsHostAliveAsync(string target, CancellationToken cancellationToken)
        {
            // 尝试 TCP 连接常见端口，至少一个成功即认为主机存活
            int[] probePorts = { 80, 443, 22, 21, 3389, 8080 };
            using (var cts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken))
            {
                cts.CancelAfter(2000);
                var tasks = probePorts.Select(p =>
                {
                    return Task.Run(async () =>
                    {
                        TcpClient tcp = null;
                        try
                        {
                            tcp = new TcpClient();
                            var connectTask = tcp.ConnectAsync(target, p);
                            var timeoutTask = Task.Delay(1500, cts.Token);
                            var completed = await Task.WhenAny(connectTask, timeoutTask);

                            // 连接任务先完成：必须 await 它，既拿到真实结果也把异常"消化"掉，
                            // 避免 ConnectionRefused 等异常逃逸成未观察任务异常
                            if (completed == connectTask)
                            {
                                try
                                {
                                    await connectTask;
                                    return tcp.Connected;
                                }
                                catch
                                {
                                    return false;
                                }
                            }

                            // 超时或取消分支：connectTask 仍在后台运行。
                            // 若不显式观察，等下面 Dispose() 释放 socket 后，ConnectAsync 会抛出
                            // SocketException("已中止 I/O 操作")，该异常无人 await，
                            // 最终触发 TaskScheduler.UnobservedTaskException
                            // （即日志里反复出现的 "任务线程异常（已静默处理）: TcpClient.CompleteConnectAsync"）。
                            ObserveTaskException(connectTask);
                            return false;
                        }
                        catch
                        {
                            return false;
                        }
                        finally
                        {
                            try { tcp?.Dispose(); } catch { }
                        }
                    }, cts.Token);
                }).ToList();

                try
                {
                    var results = await Task.WhenAll(tasks);
                    return results.Any(r => r);
                }
                catch (Exception ex)
                {
                    // Task 8.4：fail-secure（安全失败），探测异常时返回 false，宁可漏报也不误报
                    // 这样上层可以基于探测结果决定是否继续扫描，避免在主机确实不可达时仍误判为在线
                    AppendLog($"  ⚠️ 主机存活探测异常: {ex.GetType().Name} - {ex.Message}");
                    return false;
                }
            }
        }

        /// <summary>
        /// 显式观察被放弃的后台任务的异常，避免其变成
        /// TaskScheduler.UnobservedTaskException（日志中的"任务线程异常（已静默处理）"）。
        /// 典型场景：Task.WhenAny 超时后原连接任务仍在运行，且随后相关 socket 被释放。
        /// </summary>
        private static void ObserveTaskException(Task task)
        {
            if (task == null) return;
            _ = task.ContinueWith(t => { _ = t.Exception; },
                CancellationToken.None,
                TaskContinuationOptions.OnlyOnFaulted | TaskContinuationOptions.ExecuteSynchronously,
                TaskScheduler.Default);
        }

        /// <summary>
        /// 将专家模式窗口的异常写入 logs\expert_error_yyyyMMdd.log。
        /// 线程类异常（"调用线程无法访问此对象"）只有完整堆栈才能定位，
        /// 而弹窗中的堆栈常被截断，因此需要独立落盘一份。
        /// </summary>
        private static void WriteExpertErrorLog(Exception ex)
        {
            try
            {
                var dir = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "logs");
                Directory.CreateDirectory(dir);
                var file = Path.Combine(dir, $"expert_error_{DateTime.Now:yyyyMMdd}.log");
                var content =
                    $"[{DateTime.Now:yyyy-MM-dd HH:mm:ss.fff}] {ex.GetType().FullName}: {ex.Message}{Environment.NewLine}" +
                    $"Thread: {System.Threading.Thread.CurrentThread.ManagedThreadId} (IsThreadPool: {System.Threading.Thread.CurrentThread.IsThreadPoolThread}){Environment.NewLine}" +
                    $"{ex.StackTrace}{Environment.NewLine}" +
                    new string('-', 80) + Environment.NewLine;
                File.AppendAllText(file, content);
            }
            catch
            {
                // 日志写入失败绝不能影响主流程
            }
        }

        /// <summary>
        /// 解析待扫描目标。
        /// 实现已下沉到 <see cref="ExpertScanPlanner.ResolveTargets"/>（Core 层纯函数，可独立测试），
        /// 此处仅把日志回调接到界面日志框，保持原有 UI 行为。
        /// </summary>
        private List<string> ResolveTargets(ExpertScanConfiguration config)
        {
            return ExpertScanPlanner.ResolveTargets(config, AppendLog);
        }

        private string LongToIP(long ipLong) => ExpertScanPlanner.LongToIP(ipLong);

        /// <summary>
        /// 解析待扫描端口。
        /// 实现已下沉到 <see cref="ExpertScanPlanner.ResolvePorts"/>（Core 层纯函数，可独立测试）。
        /// </summary>
        private List<int> ResolvePorts(ExpertScanConfiguration config)
        {
            return ExpertScanPlanner.ResolvePorts(config, AppendLog);
        }

        // ======================== NMAP 模板应用（数据驱动） ========================
        // 14 个原有模板 + 5 个新增标准 nmap 模板
        // 模板通过 NmapTemplateRegistry 注册，XAML 按钮 Tag 指向模板 ID，由
        // ApplyNmapTemplateButton_Click 统一分发。

        private void RegisterNmapTemplates()
        {
            try
            {
                NmapTemplateRegistry.Clear();

                // ===== 原有 14 个模板（行为保持一致） =====
                NmapTemplateRegistry.Register(new NmapTemplate
                {
                    Id = "nmap-fast",
                    Name = "快速扫描 (-F)",
                    Icon = "⚡",
                    Category = "NMAP",
                    Description = "常用端口、200并发、200ms超时、不重试",
                    Apply = (w) => ApplyTemplateFast(w)
                });
                NmapTemplateRegistry.Register(new NmapTemplate
                {
                    Id = "nmap-stealth",
                    Name = "隐蔽扫描 (-sS)",
                    Icon = "🥷",
                    Category = "NMAP",
                    Description = "SYN半开、10并发、限速100pps、Stealth模式",
                    Apply = (w) => ApplyTemplateStealth(w)
                });
                NmapTemplateRegistry.Register(new NmapTemplate
                {
                    Id = "nmap-aggressive",
                    Name = "激进扫描 (-A)",
                    Icon = "💥",
                    Category = "NMAP",
                    Description = "全端口、TCP+UDP、服务+OS+脚本检测、30并发",
                    Apply = (w) => ApplyTemplateAggressive(w)
                });
                NmapTemplateRegistry.Register(new NmapTemplate
                {
                    Id = "nmap-ping",
                    Name = "Ping扫描 (-sn)",
                    Icon = "📡",
                    Category = "NMAP",
                    Description = "仅主机发现、不扫描端口",
                    Apply = (w) => ApplyTemplatePing(w)
                });
                NmapTemplateRegistry.Register(new NmapTemplate
                {
                    Id = "nmap-fullports",
                    Name = "全端口扫描 (-p-)",
                    Icon = "🔍",
                    Category = "NMAP",
                    Description = "1-65535全端口、SYN半开、20并发",
                    Apply = (w) => ApplyTemplateFullPorts(w)
                });
                NmapTemplateRegistry.Register(new NmapTemplate
                {
                    Id = "nmap-version",
                    Name = "版本检测 (-sV)",
                    Icon = "🔬",
                    Category = "NMAP",
                    Description = "常用端口、服务版本增强检测",
                    Apply = (w) => ApplyTemplateVersion(w)
                });
                NmapTemplateRegistry.Register(new NmapTemplate
                {
                    Id = "nmap-os",
                    Name = "系统检测 (-O)",
                    Icon = "🖥️",
                    Category = "NMAP",
                    Description = "SYN半开、服务检测、OS识别",
                    Apply = (w) => ApplyTemplateOs(w)
                });
                NmapTemplateRegistry.Register(new NmapTemplate
                {
                    Id = "nmap-default",
                    Name = "默认扫描 (无参数)",
                    Icon = "📋",
                    Category = "NMAP",
                    Description = "常用端口、TCP扫描、服务版本检测",
                    Apply = (w) => ApplyTemplateDefault(w)
                });
                NmapTemplateRegistry.Register(new NmapTemplate
                {
                    Id = "preset-web",
                    Name = "Web服务器检测",
                    Icon = "🌐",
                    Category = "Scenario",
                    Description = "80/443/8080/8443等Web相关端口、增强服务检测",
                    Apply = (w) => ApplyTemplateWeb(w)
                });
                NmapTemplateRegistry.Register(new NmapTemplate
                {
                    Id = "preset-database",
                    Name = "数据库安全检测",
                    Icon = "🗄️",
                    Category = "Scenario",
                    Description = "MySQL/PostgreSQL/Redis/MongoDB等数据库端口、暴力检测",
                    Apply = (w) => ApplyTemplateDatabase(w)
                });
                NmapTemplateRegistry.Register(new NmapTemplate
                {
                    Id = "preset-wifi",
                    Name = "WiFi路由器检测",
                    Icon = "📶",
                    Category = "Scenario",
                    Description = "管理端口、TCP+UDP、服务+OS检测",
                    Apply = (w) => ApplyTemplateWifi(w)
                });
                NmapTemplateRegistry.Register(new NmapTemplate
                {
                    Id = "preset-compliance",
                    Name = "合规性检查",
                    Icon = "✅",
                    Category = "Scenario",
                    Description = "全协议、详细检测、生成HTML报告",
                    Apply = (w) => ApplyTemplateCompliance(w)
                });
                NmapTemplateRegistry.Register(new NmapTemplate
                {
                    Id = "preset-vuln",
                    Name = "漏洞专项检测",
                    Icon = "🔥",
                    Category = "Scenario",
                    Description = "全端口、全协议、暴力级检测、多格式输出",
                    Apply = (w) => ApplyTemplateVuln(w)
                });
                NmapTemplateRegistry.Register(new NmapTemplate
                {
                    Id = "preset-stealth",
                    Name = "隐蔽审计",
                    Icon = "👻",
                    Category = "Scenario",
                    Description = "敏感端口、SYN半开、5并发、限速50pps、随机化顺序",
                    Apply = (w) => ApplyTemplateStealthAudit(w)
                });

                // ===== 5 个新增标准 nmap 模板 =====
                RegisterIntenseAndOtherTemplates();
            }
            catch (Exception ex)
            {
                AppendLog($"❌ 注册 NMAP 模板失败: {ex.Message}");
            }
        }

        private void RegisterIntenseAndOtherTemplates()
        {
            NmapTemplateRegistry.Register(new NmapTemplate
            {
                Id = "nmap-intense",
                Name = "Intense Scan",
                Icon = "🔥",
                Category = "NMAP",
                Description = "T4 时序 + 服务/OS/脚本检测 + 详细输出",
                Apply = (w) => ApplyTemplateIntense(w)
            });
            NmapTemplateRegistry.Register(new NmapTemplate
            {
                Id = "nmap-intense-udp",
                Name = "Intense Scan Plus UDP",
                Icon = "🔥",
                Category = "NMAP",
                Description = "TCP+UDP 全面深度扫描（-sS -sU -T4 -A -v）",
                Apply = (w) => ApplyTemplateIntensePlusUDP(w)
            });
            NmapTemplateRegistry.Register(new NmapTemplate
            {
                Id = "nmap-regular",
                Name = "Regular Scan",
                Icon = "📋",
                Category = "NMAP",
                Description = "常用端口、TCP + 服务版本检测（nmap 默认行为）",
                Apply = (w) => ApplyTemplateRegular(w)
            });
            NmapTemplateRegistry.Register(new NmapTemplate
            {
                Id = "nmap-slow",
                Name = "Slow Comprehensive Scan",
                Icon = "🐢",
                Category = "NMAP",
                Description = "全端口全协议、最深度扫描（耗时长）",
                Apply = (w) => ApplyTemplateSlowComprehensive(w)
            });
            NmapTemplateRegistry.Register(new NmapTemplate
            {
                Id = "nmap-traceroute",
                Name = "Quick Traceroute",
                Icon = "🛰️",
                Category = "NMAP",
                Description = "仅主机发现 + 路由追踪（-sn --traceroute）",
                Apply = (w) => ApplyTemplateQuickTraceroute(w)
            });

            // ===== 新增 3 个专业 nmap 模板 =====
            NmapTemplateRegistry.Register(new NmapTemplate
            {
                Id = "nmap-vuln",
                Name = "漏洞脚本扫描",
                Icon = "🛡️",
                Category = "NMAP",
                Description = "NSE 漏洞检测脚本（--script vuln + 服务检测 + 全端口）",
                Apply = (w) => ApplyTemplateVulnScan(w)
            });
            NmapTemplateRegistry.Register(new NmapTemplate
            {
                Id = "nmap-safe-scripts",
                Name = "安全脚本扫描",
                Icon = "🔒",
                Category = "NMAP",
                Description = "NSE 安全脚本（--script safe + 服务版本检测）",
                Apply = (w) => ApplyTemplateSafeScripts(w)
            });
            NmapTemplateRegistry.Register(new NmapTemplate
            {
                Id = "nmap-firewall-evasion",
                Name = "防火墙规避",
                Icon = "🛡️",
                Category = "NMAP",
                Description = "数据包分片 + 诱饵 + 源端口 + 慢速规避防火墙",
                Apply = (w) => ApplyTemplateFirewallEvasion(w)
            });
        }

        // 统一按钮点击：Tag 指向模板 ID
        private void ApplyNmapTemplateButton_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                if (sender is not FrameworkElement fe || fe.Tag is not string id) return;
                var template = NmapTemplateRegistry.Get(id);
                if (template?.Apply == null)
                {
                    AppendLog($"⚠️ 模板 {id} 未注册或无 Apply 委托");
                    return;
                }
                template.Apply(this);

                // 同步刷新预览面板
                if (NmapCommandPreviewTextBox != null)
                {
                    try
                    {
                        NmapCommandPreviewTextBox.Text = GenerateNmapCommand(CollectConfig());
                    }
                    catch { /* 忽略 */ }
                }
            }
            catch (Exception ex)
            {
                AppendLog($"❌ 应用模板失败: {ex.Message}");
            }
        }

        // ======================== 各模板 Apply 实现 ========================
        // 约定：w 可能是注册时传入的窗口实例；为安全起见，控件访问全部加 null 守卫。
        // 字段值严格保持与原 14 个 Click handler 一致（除 PresetStealthBtn 的字段修复）。

        private void ApplyTemplateFast(object wObj)
        {
            var w = wObj as ExpertModeWindow ?? this;
            if (w.CommonPortsRadio != null) w.CommonPortsRadio.IsChecked = true;
            if (w.TcpScanCheckBox != null) w.TcpScanCheckBox.IsChecked = true;
            if (w.UdpScanCheckBox != null) w.UdpScanCheckBox.IsChecked = false;
            if (w.SynScanCheckBox != null) w.SynScanCheckBox.IsChecked = false;
            if (w.ServiceVersionCheckBox != null) w.ServiceVersionCheckBox.IsChecked = false;
            if (w.OsDetectCheckBox != null) w.OsDetectCheckBox.IsChecked = false;
            if (w.ScriptScanCheckBox != null) w.ScriptScanCheckBox.IsChecked = false;
            if (w.TcpConcurrencySlider != null) w.TcpConcurrencySlider.Value = 200;
            if (w.TcpTimeoutSlider != null) w.TcpTimeoutSlider.Value = 200;
            if (w.UdpTimeoutSlider != null) w.UdpTimeoutSlider.Value = 500;
            if (w.RetrySlider != null) w.RetrySlider.Value = 0;
            if (w.RateLimitCheckBox != null) w.RateLimitCheckBox.IsChecked = false;
            if (w.StealthModeCheckBox != null) w.StealthModeCheckBox.IsChecked = false;
            if (w.ServiceIntensityComboBox != null) w.ServiceIntensityComboBox.SelectedIndex = 0;
            w.UpdateConfigSummary();
            w.ShowTemplateApplied("⚡ 快速扫描 (-F): 常用端口、200并发、200ms超时、不重试");
        }

        private void ApplyTemplateStealth(object wObj)
        {
            var w = wObj as ExpertModeWindow ?? this;
            if (w.CommonPortsRadio != null) w.CommonPortsRadio.IsChecked = true;
            if (w.TcpScanCheckBox != null) w.TcpScanCheckBox.IsChecked = true;
            if (w.UdpScanCheckBox != null) w.UdpScanCheckBox.IsChecked = false;
            if (w.SynScanCheckBox != null) w.SynScanCheckBox.IsChecked = true;
            if (w.ServiceVersionCheckBox != null) w.ServiceVersionCheckBox.IsChecked = true;
            if (w.OsDetectCheckBox != null) w.OsDetectCheckBox.IsChecked = false;
            if (w.ScriptScanCheckBox != null) w.ScriptScanCheckBox.IsChecked = false;
            if (w.TcpConcurrencySlider != null) w.TcpConcurrencySlider.Value = 10;
            if (w.TcpTimeoutSlider != null) w.TcpTimeoutSlider.Value = 5000;
            if (w.UdpTimeoutSlider != null) w.UdpTimeoutSlider.Value = 1000;
            if (w.RetrySlider != null) w.RetrySlider.Value = 1;
            if (w.RateLimitCheckBox != null) w.RateLimitCheckBox.IsChecked = true;
            if (w.PacketRateSlider != null) w.PacketRateSlider.Value = 100;
            if (w.StealthModeCheckBox != null) w.StealthModeCheckBox.IsChecked = true;
            if (w.ServiceIntensityComboBox != null) w.ServiceIntensityComboBox.SelectedIndex = 1;
            w.UpdateConfigSummary();
            w.ShowTemplateApplied("🥷 隐蔽扫描 (-sS): SYN半开、10并发、限速100pps、Stealth模式");
        }

        private void ApplyTemplateAggressive(object wObj)
        {
            var w = wObj as ExpertModeWindow ?? this;
            if (w.AllPortsRadio != null) w.AllPortsRadio.IsChecked = true;
            if (w.TcpScanCheckBox != null) w.TcpScanCheckBox.IsChecked = true;
            if (w.UdpScanCheckBox != null) w.UdpScanCheckBox.IsChecked = true;
            if (w.SynScanCheckBox != null) w.SynScanCheckBox.IsChecked = false;
            if (w.ServiceVersionCheckBox != null) w.ServiceVersionCheckBox.IsChecked = true;
            if (w.OsDetectCheckBox != null) w.OsDetectCheckBox.IsChecked = true;
            if (w.ScriptScanCheckBox != null) w.ScriptScanCheckBox.IsChecked = true;
            if (w.TcpConcurrencySlider != null) w.TcpConcurrencySlider.Value = 30;
            if (w.TcpTimeoutSlider != null) w.TcpTimeoutSlider.Value = 3000;
            if (w.UdpTimeoutSlider != null) w.UdpTimeoutSlider.Value = 5000;
            if (w.RetrySlider != null) w.RetrySlider.Value = 2;
            if (w.RateLimitCheckBox != null) w.RateLimitCheckBox.IsChecked = false;
            if (w.StealthModeCheckBox != null) w.StealthModeCheckBox.IsChecked = false;
            if (w.ServiceIntensityComboBox != null) w.ServiceIntensityComboBox.SelectedIndex = 3;
            if (w.ReverseDnsCheckBox != null) w.ReverseDnsCheckBox.IsChecked = true;
            w.UpdateConfigSummary();
            w.ShowTemplateApplied("💥 激进扫描 (-A): 全端口、TCP+UDP、服务+OS+脚本检测、30并发");
        }

        private void ApplyTemplatePing(object wObj)
        {
            var w = wObj as ExpertModeWindow ?? this;
            if (w.CidrRadio != null) w.CidrRadio.IsChecked = true;
            if (w.CommonPortsRadio != null) w.CommonPortsRadio.IsChecked = true;
            if (w.TcpScanCheckBox != null) w.TcpScanCheckBox.IsChecked = false;
            if (w.UdpScanCheckBox != null) w.UdpScanCheckBox.IsChecked = false;
            if (w.SynScanCheckBox != null) w.SynScanCheckBox.IsChecked = false;
            if (w.ServiceVersionCheckBox != null) w.ServiceVersionCheckBox.IsChecked = false;
            if (w.OsDetectCheckBox != null) w.OsDetectCheckBox.IsChecked = false;
            if (w.ScriptScanCheckBox != null) w.ScriptScanCheckBox.IsChecked = false;
            if (w.TcpConcurrencySlider != null) w.TcpConcurrencySlider.Value = 200;
            if (w.TcpTimeoutSlider != null) w.TcpTimeoutSlider.Value = 500;
            if (w.UdpTimeoutSlider != null) w.UdpTimeoutSlider.Value = 500;
            if (w.RetrySlider != null) w.RetrySlider.Value = 0;
            if (w.HostDiscoveryCheckBox != null) w.HostDiscoveryCheckBox.IsChecked = true;
            w.UpdateConfigSummary();
            w.ShowTemplateApplied("📡 Ping扫描 (-sn): 仅主机发现、不扫描端口");
        }

        private void ApplyTemplateFullPorts(object wObj)
        {
            var w = wObj as ExpertModeWindow ?? this;
            if (w.AllPortsRadio != null) w.AllPortsRadio.IsChecked = true;
            if (w.TcpScanCheckBox != null) w.TcpScanCheckBox.IsChecked = true;
            if (w.UdpScanCheckBox != null) w.UdpScanCheckBox.IsChecked = false;
            if (w.SynScanCheckBox != null) w.SynScanCheckBox.IsChecked = true;
            if (w.ServiceVersionCheckBox != null) w.ServiceVersionCheckBox.IsChecked = true;
            if (w.OsDetectCheckBox != null) w.OsDetectCheckBox.IsChecked = false;
            if (w.ScriptScanCheckBox != null) w.ScriptScanCheckBox.IsChecked = false;
            if (w.TcpConcurrencySlider != null) w.TcpConcurrencySlider.Value = 20;
            if (w.TcpTimeoutSlider != null) w.TcpTimeoutSlider.Value = 1000;
            if (w.UdpTimeoutSlider != null) w.UdpTimeoutSlider.Value = 1000;
            if (w.RetrySlider != null) w.RetrySlider.Value = 1;
            if (w.RateLimitCheckBox != null) w.RateLimitCheckBox.IsChecked = false;
            if (w.StealthModeCheckBox != null) w.StealthModeCheckBox.IsChecked = false;
            if (w.ServiceIntensityComboBox != null) w.ServiceIntensityComboBox.SelectedIndex = 2;
            w.UpdateConfigSummary();
            w.ShowTemplateApplied("🔍 全端口扫描 (-p-): 1-65535全端口、SYN半开、20并发");
        }

        private void ApplyTemplateVersion(object wObj)
        {
            var w = wObj as ExpertModeWindow ?? this;
            if (w.CommonPortsRadio != null) w.CommonPortsRadio.IsChecked = true;
            if (w.TcpScanCheckBox != null) w.TcpScanCheckBox.IsChecked = true;
            if (w.UdpScanCheckBox != null) w.UdpScanCheckBox.IsChecked = false;
            if (w.SynScanCheckBox != null) w.SynScanCheckBox.IsChecked = false;
            if (w.ServiceVersionCheckBox != null) w.ServiceVersionCheckBox.IsChecked = true;
            if (w.OsDetectCheckBox != null) w.OsDetectCheckBox.IsChecked = false;
            if (w.ScriptScanCheckBox != null) w.ScriptScanCheckBox.IsChecked = false;
            if (w.TcpConcurrencySlider != null) w.TcpConcurrencySlider.Value = 20;
            if (w.TcpTimeoutSlider != null) w.TcpTimeoutSlider.Value = 2000;
            if (w.UdpTimeoutSlider != null) w.UdpTimeoutSlider.Value = 1000;
            if (w.RetrySlider != null) w.RetrySlider.Value = 1;
            if (w.RateLimitCheckBox != null) w.RateLimitCheckBox.IsChecked = false;
            if (w.StealthModeCheckBox != null) w.StealthModeCheckBox.IsChecked = false;
            if (w.ServiceIntensityComboBox != null) w.ServiceIntensityComboBox.SelectedIndex = 3;
            w.UpdateConfigSummary();
            w.ShowTemplateApplied("🔬 版本检测 (-sV): 常用端口、服务版本增强检测");
        }

        private void ApplyTemplateOs(object wObj)
        {
            var w = wObj as ExpertModeWindow ?? this;
            if (w.CommonPortsRadio != null) w.CommonPortsRadio.IsChecked = true;
            if (w.TcpScanCheckBox != null) w.TcpScanCheckBox.IsChecked = true;
            if (w.UdpScanCheckBox != null) w.UdpScanCheckBox.IsChecked = false;
            if (w.SynScanCheckBox != null) w.SynScanCheckBox.IsChecked = true;
            if (w.ServiceVersionCheckBox != null) w.ServiceVersionCheckBox.IsChecked = true;
            if (w.OsDetectCheckBox != null) w.OsDetectCheckBox.IsChecked = true;
            if (w.ScriptScanCheckBox != null) w.ScriptScanCheckBox.IsChecked = false;
            if (w.TcpConcurrencySlider != null) w.TcpConcurrencySlider.Value = 15;
            if (w.TcpTimeoutSlider != null) w.TcpTimeoutSlider.Value = 2000;
            if (w.UdpTimeoutSlider != null) w.UdpTimeoutSlider.Value = 1000;
            if (w.RetrySlider != null) w.RetrySlider.Value = 2;
            if (w.RateLimitCheckBox != null) w.RateLimitCheckBox.IsChecked = false;
            if (w.StealthModeCheckBox != null) w.StealthModeCheckBox.IsChecked = false;
            if (w.ServiceIntensityComboBox != null) w.ServiceIntensityComboBox.SelectedIndex = 2;
            w.UpdateConfigSummary();
            w.ShowTemplateApplied("🖥️ 系统检测 (-O): SYN半开、服务检测、OS识别");
        }

        private void ApplyTemplateDefault(object wObj)
        {
            var w = wObj as ExpertModeWindow ?? this;
            if (w.CommonPortsRadio != null) w.CommonPortsRadio.IsChecked = true;
            if (w.TcpScanCheckBox != null) w.TcpScanCheckBox.IsChecked = true;
            if (w.UdpScanCheckBox != null) w.UdpScanCheckBox.IsChecked = false;
            if (w.SynScanCheckBox != null) w.SynScanCheckBox.IsChecked = false;
            if (w.ServiceVersionCheckBox != null) w.ServiceVersionCheckBox.IsChecked = true;
            if (w.OsDetectCheckBox != null) w.OsDetectCheckBox.IsChecked = false;
            if (w.ScriptScanCheckBox != null) w.ScriptScanCheckBox.IsChecked = false;
            if (w.TcpConcurrencySlider != null) w.TcpConcurrencySlider.Value = 50;
            if (w.TcpTimeoutSlider != null) w.TcpTimeoutSlider.Value = 500;
            if (w.UdpTimeoutSlider != null) w.UdpTimeoutSlider.Value = 1000;
            if (w.RetrySlider != null) w.RetrySlider.Value = 1;
            if (w.RateLimitCheckBox != null) w.RateLimitCheckBox.IsChecked = false;
            if (w.StealthModeCheckBox != null) w.StealthModeCheckBox.IsChecked = false;
            if (w.ServiceIntensityComboBox != null) w.ServiceIntensityComboBox.SelectedIndex = 1;
            w.UpdateConfigSummary();
            w.ShowTemplateApplied("📋 默认扫描: 常用端口、TCP扫描、服务版本检测");
        }

        private void ApplyTemplateWeb(object wObj)
        {
            var w = wObj as ExpertModeWindow ?? this;
            if (w.CommonPortsRadio != null) w.CommonPortsRadio.IsChecked = true;
            if (w.CustomPortsTextBox != null) w.CustomPortsTextBox.Text = "21,22,23,25,53,80,110,143,443,993,995,1433,3306,3389,5432,8080,8443";
            if (w.CustomPortsRadio != null) w.CustomPortsRadio.IsChecked = true;
            if (w.TcpScanCheckBox != null) w.TcpScanCheckBox.IsChecked = true;
            if (w.UdpScanCheckBox != null) w.UdpScanCheckBox.IsChecked = false;
            if (w.SynScanCheckBox != null) w.SynScanCheckBox.IsChecked = false;
            if (w.ServiceVersionCheckBox != null) w.ServiceVersionCheckBox.IsChecked = true;
            if (w.OsDetectCheckBox != null) w.OsDetectCheckBox.IsChecked = false;
            if (w.ScriptScanCheckBox != null) w.ScriptScanCheckBox.IsChecked = false;
            if (w.TcpConcurrencySlider != null) w.TcpConcurrencySlider.Value = 30;
            if (w.TcpTimeoutSlider != null) w.TcpTimeoutSlider.Value = 2000;
            if (w.UdpTimeoutSlider != null) w.UdpTimeoutSlider.Value = 1000;
            if (w.RetrySlider != null) w.RetrySlider.Value = 1;
            if (w.RateLimitCheckBox != null) w.RateLimitCheckBox.IsChecked = false;
            if (w.StealthModeCheckBox != null) w.StealthModeCheckBox.IsChecked = false;
            if (w.ServiceIntensityComboBox != null) w.ServiceIntensityComboBox.SelectedIndex = 2;
            w.UpdateConfigSummary();
            w.ShowTemplateApplied("🌐 Web服务器检测: 80/443/8080/8443等Web相关端口、增强服务检测");
        }

        private void ApplyTemplateDatabase(object wObj)
        {
            var w = wObj as ExpertModeWindow ?? this;
            if (w.CustomPortsRadio != null) w.CustomPortsRadio.IsChecked = true;
            if (w.CustomPortsTextBox != null) w.CustomPortsTextBox.Text = "1433,1521,3306,5432,5984,6379,7474,8529,9200,11211,27017,28017";
            if (w.TcpScanCheckBox != null) w.TcpScanCheckBox.IsChecked = true;
            if (w.UdpScanCheckBox != null) w.UdpScanCheckBox.IsChecked = false;
            if (w.SynScanCheckBox != null) w.SynScanCheckBox.IsChecked = false;
            if (w.ServiceVersionCheckBox != null) w.ServiceVersionCheckBox.IsChecked = true;
            if (w.OsDetectCheckBox != null) w.OsDetectCheckBox.IsChecked = false;
            if (w.ScriptScanCheckBox != null) w.ScriptScanCheckBox.IsChecked = false;
            if (w.TcpConcurrencySlider != null) w.TcpConcurrencySlider.Value = 20;
            if (w.TcpTimeoutSlider != null) w.TcpTimeoutSlider.Value = 2000;
            if (w.UdpTimeoutSlider != null) w.UdpTimeoutSlider.Value = 1000;
            if (w.RetrySlider != null) w.RetrySlider.Value = 1;
            if (w.RateLimitCheckBox != null) w.RateLimitCheckBox.IsChecked = false;
            if (w.StealthModeCheckBox != null) w.StealthModeCheckBox.IsChecked = false;
            if (w.ServiceIntensityComboBox != null) w.ServiceIntensityComboBox.SelectedIndex = 3;
            w.UpdateConfigSummary();
            w.ShowTemplateApplied("🗄️ 数据库安全检测: MySQL/PostgreSQL/Redis/MongoDB等数据库端口、暴力检测");
        }

        private void ApplyTemplateWifi(object wObj)
        {
            var w = wObj as ExpertModeWindow ?? this;
            if (w.CommonPortsRadio != null) w.CommonPortsRadio.IsChecked = true;
            if (w.CustomPortsTextBox != null) w.CustomPortsTextBox.Text = "22,23,80,443,5000,8080,8443,9000,10000";
            if (w.TcpScanCheckBox != null) w.TcpScanCheckBox.IsChecked = true;
            if (w.UdpScanCheckBox != null) w.UdpScanCheckBox.IsChecked = true;
            if (w.SynScanCheckBox != null) w.SynScanCheckBox.IsChecked = false;
            if (w.ServiceVersionCheckBox != null) w.ServiceVersionCheckBox.IsChecked = true;
            if (w.OsDetectCheckBox != null) w.OsDetectCheckBox.IsChecked = true;
            if (w.ScriptScanCheckBox != null) w.ScriptScanCheckBox.IsChecked = false;
            if (w.TcpConcurrencySlider != null) w.TcpConcurrencySlider.Value = 20;
            if (w.TcpTimeoutSlider != null) w.TcpTimeoutSlider.Value = 2000;
            if (w.UdpTimeoutSlider != null) w.UdpTimeoutSlider.Value = 2000;
            if (w.RetrySlider != null) w.RetrySlider.Value = 1;
            if (w.RateLimitCheckBox != null) w.RateLimitCheckBox.IsChecked = false;
            if (w.StealthModeCheckBox != null) w.StealthModeCheckBox.IsChecked = false;
            if (w.ServiceIntensityComboBox != null) w.ServiceIntensityComboBox.SelectedIndex = 2;
            w.UpdateConfigSummary();
            w.ShowTemplateApplied("📶 WiFi路由器检测: 管理端口、TCP+UDP、服务+OS检测");
        }

        private void ApplyTemplateCompliance(object wObj)
        {
            var w = wObj as ExpertModeWindow ?? this;
            if (w.CommonPortsRadio != null) w.CommonPortsRadio.IsChecked = true;
            if (w.TcpScanCheckBox != null) w.TcpScanCheckBox.IsChecked = true;
            if (w.UdpScanCheckBox != null) w.UdpScanCheckBox.IsChecked = true;
            if (w.SynScanCheckBox != null) w.SynScanCheckBox.IsChecked = false;
            if (w.ServiceVersionCheckBox != null) w.ServiceVersionCheckBox.IsChecked = true;
            if (w.OsDetectCheckBox != null) w.OsDetectCheckBox.IsChecked = true;
            if (w.ScriptScanCheckBox != null) w.ScriptScanCheckBox.IsChecked = false;
            if (w.TcpConcurrencySlider != null) w.TcpConcurrencySlider.Value = 20;
            if (w.TcpTimeoutSlider != null) w.TcpTimeoutSlider.Value = 2000;
            if (w.UdpTimeoutSlider != null) w.UdpTimeoutSlider.Value = 3000;
            if (w.RetrySlider != null) w.RetrySlider.Value = 2;
            if (w.RateLimitCheckBox != null) w.RateLimitCheckBox.IsChecked = false;
            if (w.StealthModeCheckBox != null) w.StealthModeCheckBox.IsChecked = false;
            if (w.ServiceIntensityComboBox != null) w.ServiceIntensityComboBox.SelectedIndex = 3;
            if (w.ReverseDnsCheckBox != null) w.ReverseDnsCheckBox.IsChecked = true;
            if (w.OutputHtmlCheckBox != null) w.OutputHtmlCheckBox.IsChecked = true;
            w.UpdateConfigSummary();
            w.ShowTemplateApplied("✅ 合规性检查: 全协议、详细检测、生成HTML报告");
        }

        private void ApplyTemplateVuln(object wObj)
        {
            var w = wObj as ExpertModeWindow ?? this;
            if (w.AllPortsRadio != null) w.AllPortsRadio.IsChecked = true;
            if (w.TcpScanCheckBox != null) w.TcpScanCheckBox.IsChecked = true;
            if (w.UdpScanCheckBox != null) w.UdpScanCheckBox.IsChecked = true;
            if (w.SynScanCheckBox != null) w.SynScanCheckBox.IsChecked = true;
            if (w.ServiceVersionCheckBox != null) w.ServiceVersionCheckBox.IsChecked = true;
            if (w.OsDetectCheckBox != null) w.OsDetectCheckBox.IsChecked = true;
            if (w.ScriptScanCheckBox != null) w.ScriptScanCheckBox.IsChecked = true;
            if (w.TcpConcurrencySlider != null) w.TcpConcurrencySlider.Value = 15;
            if (w.TcpTimeoutSlider != null) w.TcpTimeoutSlider.Value = 3000;
            if (w.UdpTimeoutSlider != null) w.UdpTimeoutSlider.Value = 5000;
            if (w.RetrySlider != null) w.RetrySlider.Value = 2;
            if (w.RateLimitCheckBox != null) w.RateLimitCheckBox.IsChecked = false;
            if (w.StealthModeCheckBox != null) w.StealthModeCheckBox.IsChecked = false;
            if (w.ServiceIntensityComboBox != null) w.ServiceIntensityComboBox.SelectedIndex = 4;
            if (w.ReverseDnsCheckBox != null) w.ReverseDnsCheckBox.IsChecked = true;
            if (w.OutputJsonCheckBox != null) w.OutputJsonCheckBox.IsChecked = true;
            if (w.OutputHtmlCheckBox != null) w.OutputHtmlCheckBox.IsChecked = true;
            if (w.OutputCsvCheckBox != null) w.OutputCsvCheckBox.IsChecked = true;
            w.UpdateConfigSummary();
            w.ShowTemplateApplied("🔥 漏洞专项检测: 全端口、全协议、暴力级检测、多格式输出");
        }

        private void ApplyTemplateStealthAudit(object wObj)
        {
            // Task 4 修复：原 PresetStealthBtn_Click 用 RandomizeCheckBox（数据包选项），
            // 但 GenerateNmapCommand 输出的 --randomize-hosts 实际是“目标顺序”randomize。
            // 正确控件应为 RandomizeCheckBox（数据包选项面板中），因为 CollectConfig
            // 读取 RandomizeCheckBox 映射到 config.Randomize，而 GenerateNmapCommand
            // 用 config.Randomize 才会输出 --randomize-hosts。
            var w = wObj as ExpertModeWindow ?? this;
            if (w.SensitivePortsRadio != null) w.SensitivePortsRadio.IsChecked = true;
            if (w.TcpScanCheckBox != null) w.TcpScanCheckBox.IsChecked = true;
            if (w.UdpScanCheckBox != null) w.UdpScanCheckBox.IsChecked = false;
            if (w.SynScanCheckBox != null) w.SynScanCheckBox.IsChecked = true;
            if (w.ServiceVersionCheckBox != null) w.ServiceVersionCheckBox.IsChecked = true;
            if (w.OsDetectCheckBox != null) w.OsDetectCheckBox.IsChecked = false;
            if (w.ScriptScanCheckBox != null) w.ScriptScanCheckBox.IsChecked = false;
            if (w.TcpConcurrencySlider != null) w.TcpConcurrencySlider.Value = 5;
            if (w.TcpTimeoutSlider != null) w.TcpTimeoutSlider.Value = 5000;
            if (w.UdpTimeoutSlider != null) w.UdpTimeoutSlider.Value = 1000;
            if (w.RetrySlider != null) w.RetrySlider.Value = 1;
            if (w.RateLimitCheckBox != null) w.RateLimitCheckBox.IsChecked = true;
            if (w.PacketRateSlider != null) w.PacketRateSlider.Value = 50;
            if (w.StealthModeCheckBox != null) w.StealthModeCheckBox.IsChecked = true;
            // 关键修复：config.Randomize 由 CollectConfig 从 RandomizeCheckBox 读取，
            // 因此必须勾选 RandomizeCheckBox 才能在 GenerateNmapCommand 中输出 --randomize-hosts。
            if (w.RandomizeCheckBox != null) w.RandomizeCheckBox.IsChecked = true;
            if (w.ServiceIntensityComboBox != null) w.ServiceIntensityComboBox.SelectedIndex = 0;
            w.UpdateConfigSummary();
            w.ShowTemplateApplied("👻 隐蔽审计: 敏感端口、SYN半开、5并发、限速50pps、随机化目标顺序");
        }

        // ===== 5 个新增模板 Apply =====

        private void ApplyTemplateIntense(object wObj)
        {
            var w = wObj as ExpertModeWindow ?? this;
            if (w.AllPortsRadio != null) w.AllPortsRadio.IsChecked = true;
            if (w.TcpScanCheckBox != null) w.TcpScanCheckBox.IsChecked = true;
            if (w.UdpScanCheckBox != null) w.UdpScanCheckBox.IsChecked = false;
            if (w.SynScanCheckBox != null) w.SynScanCheckBox.IsChecked = false;
            if (w.ServiceVersionCheckBox != null) w.ServiceVersionCheckBox.IsChecked = true;
            if (w.OsDetectCheckBox != null) w.OsDetectCheckBox.IsChecked = true;
            if (w.ScriptScanCheckBox != null) w.ScriptScanCheckBox.IsChecked = true;
            if (w.TcpConcurrencySlider != null) w.TcpConcurrencySlider.Value = 50;
            if (w.TcpTimeoutSlider != null) w.TcpTimeoutSlider.Value = 1000;
            if (w.UdpTimeoutSlider != null) w.UdpTimeoutSlider.Value = 1000;
            if (w.RetrySlider != null) w.RetrySlider.Value = 2;
            if (w.ServiceIntensityComboBox != null) w.ServiceIntensityComboBox.SelectedIndex = 7;
            w.UpdateConfigSummary();
            w.ShowTemplateApplied("🔥 Intense Scan (-T4 -A -v): T4 时序 + 服务/OS/脚本检测 + 详细输出");
        }

        private void ApplyTemplateIntensePlusUDP(object wObj)
        {
            // 改为独立完整配置，不再链式调用 ApplyTemplateIntense，
            // 避免因 ServiceIntensityComboBox 容量问题导致连锁崩溃。
            var w = wObj as ExpertModeWindow ?? this;
            if (w.AllPortsRadio != null) w.AllPortsRadio.IsChecked = true;
            if (w.TcpScanCheckBox != null) w.TcpScanCheckBox.IsChecked = true;
            if (w.UdpScanCheckBox != null) w.UdpScanCheckBox.IsChecked = true;
            if (w.UdpConcurrencySlider != null) w.UdpConcurrencySlider.Value = 30;
            if (w.UdpTimeoutSlider != null) w.UdpTimeoutSlider.Value = 2000;
            if (w.SynScanCheckBox != null) w.SynScanCheckBox.IsChecked = false;
            if (w.ServiceVersionCheckBox != null) w.ServiceVersionCheckBox.IsChecked = true;
            if (w.OsDetectCheckBox != null) w.OsDetectCheckBox.IsChecked = true;
            if (w.ScriptScanCheckBox != null) w.ScriptScanCheckBox.IsChecked = true;
            if (w.TcpConcurrencySlider != null) w.TcpConcurrencySlider.Value = 50;
            if (w.TcpTimeoutSlider != null) w.TcpTimeoutSlider.Value = 1000;
            if (w.RetrySlider != null) w.RetrySlider.Value = 2;
            if (w.ServiceIntensityComboBox != null && w.ServiceIntensityComboBox.Items.Count > 7)
                w.ServiceIntensityComboBox.SelectedIndex = 7;
            else if (w.ServiceIntensityComboBox != null)
                w.ServiceIntensityComboBox.SelectedIndex = w.ServiceIntensityComboBox.Items.Count - 1;
            w.UpdateConfigSummary();
            w.ShowTemplateApplied("🔥 Intense Scan Plus UDP (-sS -sU -T4 -A -v): TCP+UDP 全面深度扫描");
        }

        private void ApplyTemplateRegular(object wObj)
        {
            var w = wObj as ExpertModeWindow ?? this;
            if (w.CommonPortsRadio != null) w.CommonPortsRadio.IsChecked = true;
            if (w.TcpScanCheckBox != null) w.TcpScanCheckBox.IsChecked = true;
            if (w.ServiceVersionCheckBox != null) w.ServiceVersionCheckBox.IsChecked = true;
            if (w.TcpConcurrencySlider != null) w.TcpConcurrencySlider.Value = 50;
            if (w.TcpTimeoutSlider != null) w.TcpTimeoutSlider.Value = 500;
            if (w.UdpTimeoutSlider != null) w.UdpTimeoutSlider.Value = 1000;
            if (w.RetrySlider != null) w.RetrySlider.Value = 1;
            if (w.ServiceIntensityComboBox != null) w.ServiceIntensityComboBox.SelectedIndex = 1;
            w.UpdateConfigSummary();
            w.ShowTemplateApplied("📋 Regular Scan: 常用端口、TCP + 服务版本检测（nmap 默认行为）");
        }

        private void ApplyTemplateSlowComprehensive(object wObj)
        {
            var w = wObj as ExpertModeWindow ?? this;
            if (w.AllPortsRadio != null) w.AllPortsRadio.IsChecked = true;
            if (w.TcpScanCheckBox != null) w.TcpScanCheckBox.IsChecked = true;
            if (w.UdpScanCheckBox != null) w.UdpScanCheckBox.IsChecked = true;
            if (w.SynScanCheckBox != null) w.SynScanCheckBox.IsChecked = true;
            if (w.ServiceVersionCheckBox != null) w.ServiceVersionCheckBox.IsChecked = true;
            if (w.OsDetectCheckBox != null) w.OsDetectCheckBox.IsChecked = true;
            if (w.ScriptScanCheckBox != null) w.ScriptScanCheckBox.IsChecked = true;
            if (w.TcpConcurrencySlider != null) w.TcpConcurrencySlider.Value = 20;
            if (w.TcpTimeoutSlider != null) w.TcpTimeoutSlider.Value = 3000;
            if (w.UdpTimeoutSlider != null) w.UdpTimeoutSlider.Value = 5000;
            if (w.RetrySlider != null) w.RetrySlider.Value = 3;
            if (w.ServiceIntensityComboBox != null) w.ServiceIntensityComboBox.SelectedIndex = 9;
            if (w.HostDiscoveryCheckBox != null) w.HostDiscoveryCheckBox.IsChecked = true;
            w.UpdateConfigSummary();
            w.ShowTemplateApplied("🐢 Slow Comprehensive Scan: 全端口全协议、最深度扫描（耗时长）");
        }

        private void ApplyTemplateQuickTraceroute(object wObj)
        {
            var w = wObj as ExpertModeWindow ?? this;
            if (w.TcpScanCheckBox != null) w.TcpScanCheckBox.IsChecked = false;
            if (w.UdpScanCheckBox != null) w.UdpScanCheckBox.IsChecked = false;
            if (w.SynScanCheckBox != null) w.SynScanCheckBox.IsChecked = false;
            if (w.ServiceVersionCheckBox != null) w.ServiceVersionCheckBox.IsChecked = false;
            if (w.OsDetectCheckBox != null) w.OsDetectCheckBox.IsChecked = false;
            if (w.ScriptScanCheckBox != null) w.ScriptScanCheckBox.IsChecked = false;
            if (w.HostDiscoveryCheckBox != null) w.HostDiscoveryCheckBox.IsChecked = true;
            if (w.TcpConcurrencySlider != null) w.TcpConcurrencySlider.Value = 50;
            if (w.TcpTimeoutSlider != null) w.TcpTimeoutSlider.Value = 1000;
            if (w.RetrySlider != null) w.RetrySlider.Value = 0;
            w.UpdateConfigSummary();
            w.ShowTemplateApplied("🛰️ Quick Traceroute (-sn --traceroute): 仅主机发现 + 路由追踪");
        }

        /// <summary>
        /// 漏洞脚本扫描：使用 NSE vuln 类别脚本检测已知漏洞
        /// </summary>
        private void ApplyTemplateVulnScan(object wObj)
        {
            var w = wObj as ExpertModeWindow ?? this;
            if (w.CommonPortsRadio != null) w.CommonPortsRadio.IsChecked = true;
            if (w.TcpScanCheckBox != null) w.TcpScanCheckBox.IsChecked = true;
            if (w.UdpScanCheckBox != null) w.UdpScanCheckBox.IsChecked = false;
            if (w.SynScanCheckBox != null) w.SynScanCheckBox.IsChecked = true;
            if (w.ServiceVersionCheckBox != null) w.ServiceVersionCheckBox.IsChecked = true;
            if (w.OsDetectCheckBox != null) w.OsDetectCheckBox.IsChecked = false;
            if (w.ScriptScanCheckBox != null) w.ScriptScanCheckBox.IsChecked = true;
            if (w.TcpConcurrencySlider != null) w.TcpConcurrencySlider.Value = 50;
            if (w.TcpTimeoutSlider != null) w.TcpTimeoutSlider.Value = 2000;
            if (w.UdpTimeoutSlider != null) w.UdpTimeoutSlider.Value = 2000;
            if (w.RetrySlider != null) w.RetrySlider.Value = 1;
            if (w.RateLimitCheckBox != null) w.RateLimitCheckBox.IsChecked = false;
            if (w.RandomPortOrderCheckBox != null) w.RandomPortOrderCheckBox.IsChecked = false;
            if (w.RandomTargetOrderCheckBox != null) w.RandomTargetOrderCheckBox.IsChecked = false;
            if (w.ShowOpenOnlyCheckBox != null) w.ShowOpenOnlyCheckBox.IsChecked = true;
            if (w.VerbosityComboBox != null) w.VerbosityComboBox.SelectedIndex = 2; // 详细输出
            if (w.ServiceIntensityComboBox != null) w.ServiceIntensityComboBox.SelectedIndex = 2;
            w.UpdateConfigSummary();
            w.ShowTemplateApplied("🛡️ 漏洞脚本扫描: SYN半开 + 服务检测 + NSE漏洞脚本");
        }

        /// <summary>
        /// 安全脚本扫描：使用 NSE safe 类别脚本进行安全审计
        /// </summary>
        private void ApplyTemplateSafeScripts(object wObj)
        {
            var w = wObj as ExpertModeWindow ?? this;
            if (w.CommonPortsRadio != null) w.CommonPortsRadio.IsChecked = true;
            if (w.TcpScanCheckBox != null) w.TcpScanCheckBox.IsChecked = true;
            if (w.UdpScanCheckBox != null) w.UdpScanCheckBox.IsChecked = false;
            if (w.SynScanCheckBox != null) w.SynScanCheckBox.IsChecked = true;
            if (w.ServiceVersionCheckBox != null) w.ServiceVersionCheckBox.IsChecked = true;
            if (w.OsDetectCheckBox != null) w.OsDetectCheckBox.IsChecked = false;
            if (w.ScriptScanCheckBox != null) w.ScriptScanCheckBox.IsChecked = true;
            if (w.TcpConcurrencySlider != null) w.TcpConcurrencySlider.Value = 100;
            if (w.TcpTimeoutSlider != null) w.TcpTimeoutSlider.Value = 1000;
            if (w.UdpTimeoutSlider != null) w.UdpTimeoutSlider.Value = 1000;
            if (w.RetrySlider != null) w.RetrySlider.Value = 1;
            if (w.RateLimitCheckBox != null) w.RateLimitCheckBox.IsChecked = false;
            if (w.ShowOpenOnlyCheckBox != null) w.ShowOpenOnlyCheckBox.IsChecked = true;
            if (w.VerbosityComboBox != null) w.VerbosityComboBox.SelectedIndex = 1;
            w.UpdateConfigSummary();
            w.ShowTemplateApplied("🔒 安全脚本扫描: SYN半开 + 服务检测 + NSE安全脚本");
        }

        /// <summary>
        /// 防火墙规避扫描：使用多种规避技术绕过防火墙/IDS
        /// </summary>
        private void ApplyTemplateFirewallEvasion(object wObj)
        {
            var w = wObj as ExpertModeWindow ?? this;
            if (w.CommonPortsRadio != null) w.CommonPortsRadio.IsChecked = true;
            if (w.TcpScanCheckBox != null) w.TcpScanCheckBox.IsChecked = true;
            if (w.UdpScanCheckBox != null) w.UdpScanCheckBox.IsChecked = false;
            if (w.SynScanCheckBox != null) w.SynScanCheckBox.IsChecked = true;
            if (w.ServiceVersionCheckBox != null) w.ServiceVersionCheckBox.IsChecked = false;
            if (w.OsDetectCheckBox != null) w.OsDetectCheckBox.IsChecked = false;
            if (w.ScriptScanCheckBox != null) w.ScriptScanCheckBox.IsChecked = false;
            if (w.TcpConcurrencySlider != null) w.TcpConcurrencySlider.Value = 10;
            if (w.TcpTimeoutSlider != null) w.TcpTimeoutSlider.Value = 5000;
            if (w.UdpTimeoutSlider != null) w.UdpTimeoutSlider.Value = 5000;
            if (w.RetrySlider != null) w.RetrySlider.Value = 2;
            if (w.RateLimitCheckBox != null) w.RateLimitCheckBox.IsChecked = true;
            if (w.PacketRateSlider != null) w.PacketRateSlider.Value = 50;
            if (w.StealthModeCheckBox != null) w.StealthModeCheckBox.IsChecked = true;
            if (w.FragmentPacketsCheckBox != null) w.FragmentPacketsCheckBox.IsChecked = true;
            if (w.DecoyScanCheckBox != null) w.DecoyScanCheckBox.IsChecked = true;
            if (w.DecoyIpsTextBox != null) w.DecoyIpsTextBox.Text = "192.168.1.1,192.168.1.2,192.168.1.3";
            if (w.SourcePortTextBox != null) w.SourcePortTextBox.Text = "53";
            if (w.MtuTextBox != null) w.MtuTextBox.Text = "24";
            if (w.RandomizeCheckBox != null) w.RandomizeCheckBox.IsChecked = true;
            if (w.RandomPortOrderCheckBox != null) w.RandomPortOrderCheckBox.IsChecked = true;
            if (w.BadChecksumCheckBox != null) w.BadChecksumCheckBox.IsChecked = true;
            if (w.VerbosityComboBox != null) w.VerbosityComboBox.SelectedIndex = 0; // 安静模式
            w.UpdateConfigSummary();
            w.ShowTemplateApplied("🛡️ 防火墙规避: 分片 + 诱饵 + 源端口53 + 慢速 + 随机化");
        }

        private void ShowTemplateApplied(string message)
        {
            UpdateConfigSummary();
            if (TemplateNotificationBorder != null && TemplateNotificationText != null)
            {
                TemplateNotificationText.Text = "✅ " + message;
                TemplateNotificationBorder.Visibility = Visibility.Visible;
                // 复用单一计时器，避免反复创建 DispatcherTimer 造成泄露
                if (_templateNotificationTimer == null)
                {
                    _templateNotificationTimer = new DispatcherTimer { Interval = TimeSpan.FromSeconds(3) };
                    _templateNotificationTimer.Tick += (s, e) =>
                    {
                        try
                        {
                            if (TemplateNotificationBorder != null)
                                TemplateNotificationBorder.Visibility = Visibility.Collapsed;
                        }
                        catch { }
                        if (_templateNotificationTimer != null) _templateNotificationTimer.Stop();
                    };
                }
                _templateNotificationTimer.Stop();
                _templateNotificationTimer.Start();
            }
        }

        // ======================== 模板预览面板 ========================

        private void RefreshNmapPreviewBtn_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                if (NmapCommandPreviewTextBox == null) return;
                var config = CollectConfig();
                NmapCommandPreviewTextBox.Text = GenerateNmapCommand(config);
            }
            catch (Exception ex) { AppendLog($"❌ 预览生成失败: {ex.Message}"); }
        }

        private void CopyNmapPreviewBtn_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                if (NmapCommandPreviewTextBox == null) return;
                SafeSetClipboard(NmapCommandPreviewTextBox.Text);
                AppendLog("✅ Nmap 命令已复制到剪贴板");
            }
            catch (Exception ex) { AppendLog($"❌ 复制失败: {ex.Message}"); }
        }

        // ======================== 自定义模板保存/加载 ========================

        private void SaveCustomTemplateBtn_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                var name = PromptForText("保存自定义模板", "请输入模板名称：", "我的模板");
                if (string.IsNullOrWhiteSpace(name)) return;

                var config = CollectConfig();
                var configDict = new Dictionary<string, object>();
                foreach (var prop in typeof(ExpertScanConfiguration).GetProperties())
                {
                    try { configDict[prop.Name] = prop.GetValue(config) ?? ""; }
                    catch { /* 跳过无法读取的属性 */ }
                }

                var template = new CustomNmapTemplate
                {
                    Name = name.Trim(),
                    Description = $"用户自定义 - 创建于 {DateTime.Now:yyyy-MM-dd HH:mm}",
                    Config = configDict
                };
                if (CustomNmapTemplateStore.Save(template))
                {
                    AppendLog($"✅ 自定义模板 \"{name}\" 已保存");
                    RefreshCustomTemplateList();
                }
                else AppendLog("❌ 自定义模板保存失败");
            }
            catch (Exception ex) { AppendLog($"❌ 保存失败: {ex.Message}"); }
        }

        private void RefreshCustomTemplateList()
        {
            try
            {
                if (CustomTemplateComboBox == null) return;
                var list = CustomNmapTemplateStore.LoadAll();
                CustomTemplateComboBox.ItemsSource = list;
                CustomTemplateComboBox.DisplayMemberPath = "Name";
            }
            catch (Exception ex) { AppendLog($"⚠️ 加载自定义模板列表失败: {ex.Message}"); }
        }

        private void CustomTemplateComboBox_SelectionChanged(object sender, System.Windows.Controls.SelectionChangedEventArgs e)
        {
            try
            {
                if (CustomTemplateComboBox?.SelectedItem is not CustomNmapTemplate t) return;
                var config = CollectConfig();
                var type = typeof(ExpertScanConfiguration);
                foreach (var kv in t.Config)
                {
                    var prop = type.GetProperty(kv.Key);
                    if (prop == null || !prop.CanWrite) continue;
                    try
                    {
                        object? val = null;
                        if (kv.Value is System.Text.Json.JsonElement je)
                        {
                            val = System.Text.Json.JsonSerializer.Deserialize(je.GetRawText(), prop.PropertyType);
                        }
                        else
                        {
                            val = Convert.ChangeType(kv.Value, prop.PropertyType);
                        }
                        if (val != null) prop.SetValue(config, val);
                    }
                    catch { /* 跳过无法转换的属性 */ }
                }
                ApplyConfig(config);
                AppendLog($"✅ 已应用自定义模板: {t.Name}");
            }
            catch (Exception ex) { AppendLog($"❌ 应用自定义模板失败: {ex.Message}"); }
        }

        private void DeleteCustomTemplateBtn_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                if (CustomTemplateComboBox?.SelectedItem is not CustomNmapTemplate t) return;
                var confirm = MessageBox.Show($"确定删除自定义模板 \"{t.Name}\" 吗？", "确认删除", MessageBoxButton.YesNo, MessageBoxImage.Question);
                if (confirm != MessageBoxResult.Yes) return;
                if (CustomNmapTemplateStore.Delete(t.Id))
                {
                    AppendLog($"✅ 已删除自定义模板: {t.Name}");
                    RefreshCustomTemplateList();
                }
            }
            catch (Exception ex) { AppendLog($"❌ 删除失败: {ex.Message}"); }
        }

        // 不依赖 Microsoft.VisualBasic 的简易输入框
        private static string? PromptForText(string title, string prompt, string defaultText = "")
        {
            try
            {
                var win = new Window
                {
                    Title = title,
                    Width = 420,
                    Height = 200,
                    WindowStartupLocation = WindowStartupLocation.CenterOwner,
                    ResizeMode = ResizeMode.NoResize,
                    ShowInTaskbar = false
                };
                var sp = new StackPanel { Margin = new Thickness(10) };
                sp.Children.Add(new TextBlock { Text = prompt, Margin = new Thickness(0, 0, 0, 8) });
                var tb = new TextBox { Text = defaultText, Margin = new Thickness(0, 0, 0, 8) };
                sp.Children.Add(tb);
                var btnPanel = new StackPanel { Orientation = Orientation.Horizontal, HorizontalAlignment = HorizontalAlignment.Right };
                var ok = new Button { Content = "确定", Width = 80, Margin = new Thickness(0, 0, 8, 0), IsDefault = true };
                var cancel = new Button { Content = "取消", Width = 80, IsCancel = true };
                string? result = null;
                ok.Click += (s, e) => { result = tb.Text; win.DialogResult = true; };
                btnPanel.Children.Add(ok);
                btnPanel.Children.Add(cancel);
                sp.Children.Add(btnPanel);
                win.Content = sp;
                return win.ShowDialog() == true ? result : null;
            }
            catch { return null; }
        }

        private void ExportNmapButton_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                var config = CollectConfig();
                if (string.IsNullOrWhiteSpace(config.TargetValue))
                {
                    MessageBox.Show("请先输入扫描目标", "提示", MessageBoxButton.OK, MessageBoxImage.Warning);
                    return;
                }
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
                        // 严格按文件实际扩展名决定脚本头，避免用户在保存对话框中改为 .sh 仍生成 .bat 头
                        string content;
                        if (dialog.FileName.EndsWith(".sh", StringComparison.OrdinalIgnoreCase))
                            content = $"#!/bin/bash\n{nmapCmd}";
                        else if (dialog.FileName.EndsWith(".bat", StringComparison.OrdinalIgnoreCase))
                            content = $"@echo off\n{nmapCmd}\npause";
                        else
                            content = nmapCmd;
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

        /// <summary>
        /// 生成等效 Nmap 命令。
        /// ⚠️ 该命令仅用于「命令预览框」与「导出 Nmap 命令」，程序自身从不执行 nmap；
        /// 实际扫描由 Rust 引擎或 C# 内置扫描器完成，仅消费并发/超时/重试/协议等少量参数。
        /// 实现已下沉到 <see cref="NmapCommandBuilder.Build"/>（Core 层纯函数，可独立测试）。
        /// </summary>
        private string GenerateNmapCommand(ExpertScanConfiguration config)
        {
            return NmapCommandBuilder.Build(config);
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

        #region 扫描预设

        /// <summary>
        /// 快速扫描预设：常见端口 + 短超时 + 高并发 + 关闭服务检测
        /// 适用于资产快速盘点、大规模 IP 段快速探测
        /// </summary>
        private void QuickScanPresetButton_Click(object sender, RoutedEventArgs e)
        {
            AppendLog("⚡ 应用快速扫描预设...");

            // 目标配置：保持用户当前输入不变

            // 端口模式：常用端口（Top 1000）
            CommonPortsRadio.IsChecked = true;
            CustomPortsTextBox.Text = "21,22,23,25,53,80,110,143,443,993,995,1433,3306,3389,5432,6379,8080,8443,9200,27017";

            // 协议：仅 TCP
            TcpScanCheckBox.IsChecked = true;
            UdpScanCheckBox.IsChecked = false;
            SynScanCheckBox.IsChecked = false;

            // 服务检测：关闭（快速）
            ServiceVersionCheckBox.IsChecked = false;
            OsDetectCheckBox.IsChecked = false;
            ScriptScanCheckBox.IsChecked = false;
            ServiceIntensityComboBox.SelectedIndex = 0;

            // 性能：高并发 + 短超时
            TcpConcurrencySlider.Value = 200;
            UdpConcurrencySlider.Value = 50;
            TcpTimeoutSlider.Value = 200;
            UdpTimeoutSlider.Value = 500;
            RetrySlider.Value = 0;
            ServiceDetectTimeoutSlider.Value = 1000;

            // 速率限制：关闭
            RateLimitCheckBox.IsChecked = false;

            // 探测：启用 Ping 探测
            PingProbeCheckBox.IsChecked = true;

            // 随机化：关闭
            RandomPortOrderCheckBox.IsChecked = false;
            RandomTargetOrderCheckBox.IsChecked = false;

            // 高级：关闭所有额外选项
            StealthModeCheckBox.IsChecked = false;
            FragmentPacketsCheckBox.IsChecked = false;
            DecoyScanCheckBox.IsChecked = false;
            IdleScanCheckBox.IsChecked = false;
            SourceRoutingCheckBox.IsChecked = false;

            // 日志级别：安静
            VerbosityComboBox.SelectedIndex = 0;

            // 引擎：Rust
            RustEngineRadio.IsChecked = true;

            // 更新 UI
            UpdateConfigSummary();
            UpdateScanPlanPreview();
            UpdateStartButtonState();

            AppendLog("✅ 已应用快速扫描预设：常见端口 + 200ms超时 + 200并发 + 关闭服务检测");
            AppendLog("💡 适合：大规模资产快速盘点、内网存活探测");
        }

        /// <summary>
        /// 深度扫描预设：全部端口 + 长超时 + 服务检测 + 全量漏洞检测
        /// 适用于安全审计、渗透测试、合规检查
        /// </summary>
        private void DeepScanPresetButton_Click(object sender, RoutedEventArgs e)
        {
            AppendLog("🔍 应用深度扫描预设...");

            // 目标配置：保持用户当前输入不变

            // 端口模式：全部端口（1-65535）
            AllPortsRadio.IsChecked = true;

            // 协议：TCP + UDP
            TcpScanCheckBox.IsChecked = true;
            UdpScanCheckBox.IsChecked = true;
            SynScanCheckBox.IsChecked = false;

            // 服务检测：全开
            ServiceVersionCheckBox.IsChecked = true;
            OsDetectCheckBox.IsChecked = true;
            ScriptScanCheckBox.IsChecked = true;
            ServiceIntensityComboBox.SelectedIndex = 3; // 全部检测

            // 性能：低并发 + 长超时（确保准确性）
            TcpConcurrencySlider.Value = 20;
            UdpConcurrencySlider.Value = 10;
            TcpTimeoutSlider.Value = 3000;
            UdpTimeoutSlider.Value = 5000;
            RetrySlider.Value = 2;
            ServiceDetectTimeoutSlider.Value = 5000;

            // 速率限制：启用
            RateLimitCheckBox.IsChecked = true;
            PacketRateSlider.Value = 500;

            // 探测：启用 Ping 探测
            PingProbeCheckBox.IsChecked = true;

            // 随机化：启用（避免触发 IDS 模式检测）
            RandomPortOrderCheckBox.IsChecked = true;
            RandomTargetOrderCheckBox.IsChecked = true;

            // 高级：启用数据包分片（绕过简单 IDS）
            StealthModeCheckBox.IsChecked = false;
            FragmentPacketsCheckBox.IsChecked = true;
            DecoyScanCheckBox.IsChecked = false;
            IdleScanCheckBox.IsChecked = false;
            SourceRoutingCheckBox.IsChecked = false;

            // 日志级别：详细
            VerbosityComboBox.SelectedIndex = 2;

            // 引擎：Rust
            RustEngineRadio.IsChecked = true;

            // 输出：HTML + CSV
            OutputJsonCheckBox.IsChecked = true;
            OutputHtmlCheckBox.IsChecked = true;
            OutputCsvCheckBox.IsChecked = true;

            // 更新 UI
            UpdateConfigSummary();
            UpdateScanPlanPreview();
            UpdateStartButtonState();

            AppendLog("✅ 已应用深度扫描预设：全端口 + 3s超时 + 服务检测 + 全量漏洞检测");
            AppendLog("💡 适合：安全审计、渗透测试、合规检查");
        }

        #endregion

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
                else if (totalMs < 60000) timeEstimate = $"{totalMs / 1000:F1}秒";
                else if (totalMs < 3600000) timeEstimate = $"{totalMs / 60000:F1}分钟";
                else timeEstimate = $"{totalMs / 3600000:F1}小时";

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
                _userRequestedCancel = true;
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

        /// <summary>
        /// 按目标分类导出 - 弹出选择对话框，让用户选择 HTML/CSV/JSON
        /// 生成的结果会按目标 IP 分组，便于多目标场景下查看
        /// </summary>
        private void ExportByTargetButton_Click(object sender, RoutedEventArgs e)
        {
            if (_allPortScanResults.Count == 0 && _allVulnResults.Count == 0)
            {
                MessageBox.Show("暂无扫描结果可导出", "提示", MessageBoxButton.OK, MessageBoxImage.Information);
                return;
            }

            // 统计目标数量，决定是否值得按目标分组
            var targetGroups = _allPortScanResults.Select(r => r.TargetIp)
                .Concat(_allVulnResults.Select(v => v.Target))
                .Where(t => !string.IsNullOrEmpty(t))
                .Distinct()
                .ToList();

            if (targetGroups.Count <= 1)
            {
                var result = MessageBox.Show(
                    $"当前仅扫描了 1 个目标({targetGroups.FirstOrDefault() ?? "无"})，按目标导出与普通导出效果相同。\n\n" +
                    "选择「是」调用普通导出（HTML/CSV/JSON 三选一）\n" +
                    "选择「否」取消导出",
                    "提示", MessageBoxButton.YesNo, MessageBoxImage.Question);
                if (result != MessageBoxResult.Yes) return;
                // 复用普通导出：弹一个简化的格式选择对话框
                ExportWithFormatSelection();  // 调用一个共用的导出方法
                return;
            }

            // 弹出格式选择对话框
            var formatDialog = new Window
            {
                Title = "选择导出格式（按目标分类）",
                Width = 320,
                Height = 250,
                WindowStartupLocation = WindowStartupLocation.CenterOwner,
                Owner = this,
                ResizeMode = ResizeMode.NoResize
            };
            var formatPanel = new StackPanel { Margin = new Thickness(20) };
            formatPanel.Children.Add(new TextBlock
            {
                Text = $"📊 检测到 {targetGroups.Count} 个目标\n\n请选择导出格式：",
                FontSize = 13,
                Margin = new Thickness(0, 0, 0, 15)
            });

            string? chosenFormat = null;
            void AddFormatButton(string label, string format)
            {
                var btn = new Button
                {
                    Content = label,
                    Height = 35,
                    Margin = new Thickness(0, 0, 0, 8),
                    Background = new SolidColorBrush(Color.FromRgb(0x16, 0xA0, 0x85)),
                    Foreground = Brushes.White,
                    BorderThickness = new Thickness(0),
                    FontSize = 13
                };
                btn.Click += (_, __) => { chosenFormat = format; formatDialog.Close(); };
                formatPanel.Children.Add(btn);
            }
            AddFormatButton("📄 HTML（按目标分章节）", "html");
            AddFormatButton("📊 CSV（多目标列表）", "csv");
            AddFormatButton("💾 JSON（按目标分组）", "json");
            AddFormatButton("📝 DOCX（Word 文档）", "docx");

            var cancelBtn = new Button
            {
                Content = "取消",
                Height = 30,
                Margin = new Thickness(0, 5, 0, 0)
            };
            cancelBtn.Click += (_, __) => formatDialog.Close();
            formatPanel.Children.Add(cancelBtn);

            formatDialog.Content = formatPanel;
            formatDialog.ShowDialog();

            if (string.IsNullOrEmpty(chosenFormat)) return;

            try
            {
                switch (chosenFormat)
                {
                    case "html":
                        ExportByTargetHtml();
                        break;
                    case "csv":
                        ExportByTargetCsv();
                        break;
                    case "json":
                        ExportByTargetJson();
                        break;
                }
            }
            catch (Exception ex)
            {
                MessageBox.Show($"按目标导出失败: {ex.Message}", "错误", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        /// <summary>
        /// 弹出格式选择对话框（HTML/CSV/JSON），复用普通导出逻辑
        /// </summary>
        private void ExportWithFormatSelection()
        {
            var formatDialog = new Window
            {
                Title = "选择导出格式",
                Width = 320,
                Height = 220,
                WindowStartupLocation = WindowStartupLocation.CenterOwner,
                Owner = this,
                ResizeMode = ResizeMode.NoResize
            };
            var panel = new StackPanel { Margin = new Thickness(20) };
            panel.Children.Add(new TextBlock
            {
                Text = "请选择导出格式：",
                FontSize = 13,
                Margin = new Thickness(0, 0, 0, 15)
            });

            string? chosenFormat = null;
            void AddBtn(string label, string fmt)
            {
                var b = new Button
                {
                    Content = label,
                    Height = 35,
                    Margin = new Thickness(0, 0, 0, 8),
                    Background = new SolidColorBrush(Color.FromRgb(0x16, 0xA0, 0x85)),
                    Foreground = Brushes.White,
                    BorderThickness = new Thickness(0),
                    FontSize = 13
                };
                b.Click += (_, __) => { chosenFormat = fmt; formatDialog.Close(); };
                panel.Children.Add(b);
            }
            AddBtn("📄 HTML 报告", "html");
            AddBtn("📊 CSV 报告", "csv");
            AddBtn("💾 JSON 报告", "json");
            var cancelBtn = new Button { Content = "取消", Height = 30, Margin = new Thickness(0, 5, 0, 0) };
            cancelBtn.Click += (_, __) => formatDialog.Close();
            panel.Children.Add(cancelBtn);

            formatDialog.Content = panel;
            formatDialog.ShowDialog();

            if (string.IsNullOrEmpty(chosenFormat)) return;

            try
            {
                switch (chosenFormat)
                {
                    case "html": ExportHtmlButton_Click(this, new RoutedEventArgs()); break;
                    case "csv": ExportCsvButton_Click(this, new RoutedEventArgs()); break;
                    case "json": ExportJsonButton_Click(this, new RoutedEventArgs()); break;
                    case "docx": ExportDocxButton_Click(this, new RoutedEventArgs()); break;
                }
            }
            catch (Exception ex)
            {
                MessageBox.Show($"导出失败: {ex.Message}", "错误", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        private void ExportByTargetHtml()
        {
            var dialog = new SaveFileDialog
            {
                Filter = "HTML文件 (*.html)|*.html",
                FileName = $"ExpertScan_ByTarget_{DateTime.Now:yyyyMMdd_HHmmss}.html",
                Title = "按目标导出 HTML 报告"
            };
            if (dialog.ShowDialog() != true) return;

            var sb = new System.Text.StringBuilder();
            sb.AppendLine("<!DOCTYPE html>");
            sb.AppendLine("<html lang=\"zh-CN\"><head><meta charset=\"UTF-8\"><title>专家模式按目标分类报告</title>");
            sb.AppendLine("<style>");
            sb.AppendLine("body { font-family: 'Microsoft YaHei', sans-serif; margin: 20px; background: #f5f5f5; }");
            sb.AppendLine(".container { max-width: 1200px; margin: 0 auto; background: white; padding: 30px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }");
            sb.AppendLine("h1 { color: #2C3E50; border-bottom: 3px solid #16A085; padding-bottom: 10px; }");
            sb.AppendLine("h2 { color: #16A085; margin-top: 30px; border-left: 4px solid #16A085; padding-left: 10px; }");
            sb.AppendLine(".summary { display: flex; gap: 20px; margin: 20px 0; }");
            sb.AppendLine(".summary-item { flex: 1; background: #ECF0F1; padding: 15px; border-radius: 6px; text-align: center; }");
            sb.AppendLine(".summary-item .number { font-size: 32px; font-weight: bold; color: #2C3E50; }");
            sb.AppendLine(".summary-item .label { color: #7F8C8D; margin-top: 5px; }");
            sb.AppendLine("table { width: 100%; border-collapse: collapse; margin-top: 10px; }");
            sb.AppendLine("th { background: #16A085; color: white; padding: 10px; text-align: left; }");
            sb.AppendLine("td { padding: 8px 10px; border-bottom: 1px solid #ECF0F1; }");
            sb.AppendLine(".high { color: #E74C3C; font-weight: bold; }");
            sb.AppendLine(".medium { color: #E67E22; font-weight: bold; }");
            sb.AppendLine(".low { color: #27AE60; font-weight: bold; }");
            sb.AppendLine("</style></head><body><div class=\"container\">");
            sb.AppendLine($"<h1>📊 专家模式按目标分类报告</h1>");
            sb.AppendLine($"<p>生成时间: {DateTime.Now:yyyy-MM-dd HH:mm:ss} | 总目标数: {_totalScannedTargets}</p>");

            // 总体统计
            sb.AppendLine("<div class=\"summary\">");
            sb.AppendLine($"<div class=\"summary-item\"><div class=\"number\">{_totalScannedTargets}</div><div class=\"label\">扫描目标数</div></div>");
            sb.AppendLine($"<div class=\"summary-item\"><div class=\"number\">{_totalOpenPorts}</div><div class=\"label\">开放端口</div></div>");
            sb.AppendLine($"<div class=\"summary-item\"><div class=\"number\">{_allVulnResults.Count}</div><div class=\"label\">发现漏洞</div></div>");
            sb.AppendLine("</div>");

            // 按目标分组
            var allTargets = _allPortScanResults.Select(r => r.TargetIp)
                .Concat(_allVulnResults.Select(v => v.Target))
                .Where(t => !string.IsNullOrEmpty(t))
                .Distinct()
                .OrderBy(t => t, StringComparer.OrdinalIgnoreCase);

            foreach (var target in allTargets)
            {
                var portResults = _allPortScanResults.Where(r => r.TargetIp == target).ToList();
                var vulnResults = _allVulnResults.Where(v => v.Target == target).ToList();
                var openCount = portResults.Count(p => p.Status == "开放");

                sb.AppendLine($"<h2>🎯 目标: {target}</h2>");
                sb.AppendLine($"<p>📊 本目标开放端口: {openCount} | 发现漏洞: {vulnResults.Count}</p>");

                if (portResults.Count > 0)
                {
                    sb.AppendLine("<h3>端口扫描结果</h3>");
                    sb.AppendLine("<table><tr><th>端口</th><th>状态</th><th>服务</th><th>版本</th><th>响应时间</th></tr>");
                    foreach (var p in portResults)
                    {
                        var color = p.Status == "开放" ? "color:#27AE60;font-weight:bold;" : "color:#95A5A6;";
                        sb.AppendLine($"<tr><td>{p.PortNumber}</td><td style=\"{color}\">{p.Status}</td><td>{p.Service}</td><td>{p.ServiceVersion}</td><td>{p.ResponseTime}</td></tr>");
                    }
                    sb.AppendLine("</table>");
                }

                if (vulnResults.Count > 0)
                {
                    sb.AppendLine("<h3>漏洞扫描结果</h3>");
                    sb.AppendLine("<table><tr><th>名称</th><th>CVE</th><th>风险</th><th>端口</th><th>描述</th></tr>");
                    foreach (var v in vulnResults)
                    {
                        string levelClass = v.RiskLevel switch
                        {
                            "高危" or "严重" => "high",
                            "中危" => "medium",
                            _ => "low"
                        };
                        sb.AppendLine($"<tr><td>{v.Name}</td><td>{v.CveId}</td><td class=\"{levelClass}\">{v.RiskLevel}</td><td>{v.Port}</td><td>{v.Description}</td></tr>");
                    }
                    sb.AppendLine("</table>");
                }
            }

            sb.AppendLine("</div></body></html>");
            File.WriteAllText(dialog.FileName, sb.ToString(), Encoding.UTF8);
            MessageBox.Show($"按目标 HTML 报告已保存到:\n{dialog.FileName}", "导出成功", MessageBoxButton.OK, MessageBoxImage.Information);
            AppendLog($"按目标导出 HTML: {dialog.FileName}");
        }

        private void ExportByTargetCsv()
        {
            var dialog = new SaveFileDialog
            {
                Filter = "CSV文件 (*.csv)|*.csv",
                FileName = $"ExpertScan_ByTarget_{DateTime.Now:yyyyMMdd_HHmmss}.csv",
                Title = "按目标导出 CSV 报告"
            };
            if (dialog.ShowDialog() != true) return;

            var sb = new System.Text.StringBuilder();
            sb.AppendLine("目标IP,类型,端口,状态,服务,版本,风险等级,CVE,描述");

            // 端口结果
            foreach (var p in _allPortScanResults)
            {
                sb.AppendLine($"{p.TargetIp},端口扫描,{p.PortNumber},{p.Status},{EscapeCsv(p.Service)},{EscapeCsv(p.ServiceVersion)},,,");
            }
            // 漏洞结果
            foreach (var v in _allVulnResults)
            {
                sb.AppendLine($"{v.Target},漏洞扫描,{v.Port},,{EscapeCsv(v.Service)},,{v.RiskLevel},{EscapeCsv(v.CveId)},{EscapeCsv(v.Description)}");
            }

            File.WriteAllText(dialog.FileName, sb.ToString(), new System.Text.UTF8Encoding(true));
            MessageBox.Show($"按目标 CSV 报告已保存到:\n{dialog.FileName}", "导出成功", MessageBoxButton.OK, MessageBoxImage.Information);
            AppendLog($"按目标导出 CSV: {dialog.FileName}");
        }

        private void ExportByTargetJson()
        {
            var dialog = new SaveFileDialog
            {
                Filter = "JSON文件 (*.json)|*.json",
                FileName = $"ExpertScan_ByTarget_{DateTime.Now:yyyyMMdd_HHmmss}.json",
                Title = "按目标导出 JSON 报告"
            };
            if (dialog.ShowDialog() != true) return;

            var allTargets = _allPortScanResults.Select(r => r.TargetIp)
                .Concat(_allVulnResults.Select(v => v.Target))
                .Where(t => !string.IsNullOrEmpty(t))
                .Distinct()
                .OrderBy(t => t, StringComparer.OrdinalIgnoreCase);

            var targetResults = allTargets.Select(t => new
            {
                TargetIp = t,
                PortResults = _allPortScanResults.Where(p => p.TargetIp == t).ToList(),
                VulnerabilityResults = _allVulnResults.Where(v => v.Target == t).ToList(),
                OpenPortCount = _allPortScanResults.Count(p => p.TargetIp == t && p.Status == "开放"),
                VulnerabilityCount = _allVulnResults.Count(v => v.Target == t)
            }).ToList();

            var report = new
            {
                ExportTime = DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss"),
                ExportType = "按目标分类",
                TotalTargets = _totalScannedTargets,
                TotalOpenPorts = _totalOpenPorts,
                TotalVulnerabilities = _allVulnResults.Count,
                TargetResults = targetResults
            };
            var json = JsonSerializer.Serialize(report, new JsonSerializerOptions
            {
                WriteIndented = true,
                Encoder = System.Text.Encodings.Web.JavaScriptEncoder.UnsafeRelaxedJsonEscaping
            });
            File.WriteAllText(dialog.FileName, json, new System.Text.UTF8Encoding(true));
            MessageBox.Show($"按目标 JSON 报告已保存到:\n{dialog.FileName}", "导出成功", MessageBoxButton.OK, MessageBoxImage.Information);
            AppendLog($"按目标导出 JSON: {dialog.FileName}");
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
            sb.AppendLine($"<h1>🔧 {_reportTitle}</h1>");
            sb.AppendLine($"<p>生成时间: {DateTime.Now:yyyy-MM-dd HH:mm:ss}</p>");
            if (!string.IsNullOrEmpty(_reportCompany))
                sb.AppendLine($"<p>公司: {_reportCompany}</p>");
            if (!string.IsNullOrEmpty(_reportAuthor))
                sb.AppendLine($"<p>扫描人员: {_reportAuthor}</p>");
            if (!string.IsNullOrEmpty(_reportDescription))
                sb.AppendLine($"<p>备注: {_reportDescription}</p>");

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

        /// <summary>
        /// 异步追加日志到 UI 和日志文件（使用 BeginInvoke + Background 优先级，不阻塞扫描线程）
        /// 若 Dispatcher 已关闭（窗口关闭后），安全忽略
        /// </summary>
        private void AppendLog(string message)
        {
            if (ScanLogTextBox == null || Dispatcher.HasShutdownStarted)
                return;

            var timestamp = DateTime.Now.ToString("HH:mm:ss");
            var logLine = $"[{timestamp}] {message}";

            // 写入日志文件（使用进程安全的文件追加方式）
            try
            {
                var logDir = Path.GetDirectoryName(System.Reflection.Assembly.GetExecutingAssembly().Location);
                if (string.IsNullOrEmpty(logDir))
                    logDir = AppDomain.CurrentDomain.BaseDirectory;

                logDir = Path.Combine(logDir, "logs");

                if (!Directory.Exists(logDir))
                {
                    Directory.CreateDirectory(logDir);
                }

                var logFile = Path.Combine(logDir, $"expert_scan_{DateTime.Now:yyyyMMdd}.log");

                // 使用FileStream确保进程安全
                using (var fs = new FileStream(logFile, FileMode.Append, FileAccess.Write, FileShare.Read))
                using (var writer = new StreamWriter(fs, Encoding.UTF8))
                {
                    writer.WriteLine(logLine);
                }
            }
            catch (Exception)
            {
                // 如果文件写入失败，在UI中显示错误（仅调试时）
                // System.Diagnostics.Debug.WriteLine($"日志写入失败: {ex.Message}");
            }

            Dispatcher.BeginInvoke(new Action(() =>
            {
                if (ScanLogTextBox == null) return;
                ScanLogTextBox.AppendText(logLine + "\r\n");
                ScanLogTextBox.ScrollToEnd();
            }), DispatcherPriority.Background);
        }

        private void ClearResultsButton_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                // BulkObservableCollection.Clear() 触发 Reset 通知，DataGrid 自动清空
                int portCount = _allPortScanResults?.Count ?? 0;
                int vulnCount = _allVulnResults?.Count ?? 0;
                _allPortScanResults?.Clear();
                _allVulnResults?.Clear();

                _totalScannedTargets = 0;
                _totalOpenPorts = 0;

                // 统计标签 - NRE 防护
                if (TotalTargetsStat != null) TotalTargetsStat.Text = "0";
                if (ScannedTargetsStat != null) ScannedTargetsStat.Text = "0";
                if (OpenPortsStat != null) OpenPortsStat.Text = "0";
                if (VulnerabilitiesStat != null) VulnerabilitiesStat.Text = "0";
                if (ExpertScanProgressBar != null) ExpertScanProgressBar.Value = 0;
                if (ExpertScanProgressText != null) ExpertScanProgressText.Text = "就绪";

                // 同步刷新数据可视化 Tab 中的图表，避免显示陈旧数据
                try { RefreshCharts(); } catch { /* 图表未初始化时安全忽略 */ }

                AppendLog($"已清空所有扫描结果（清除了 {portCount} 个端口 + {vulnCount} 个漏洞）");
            }
            catch (Exception ex)
            {
                AppendLog($"清空结果失败: {ex.Message}");
            }
        }

        private void ResetPortFilterButton_Click(object sender, RoutedEventArgs e)
        {
            if (RealTimePortResultsDataGrid == null) return;
            try
            {
                // 重新绑定到 BulkObservableCollection，新结果将自动增量更新
                RealTimePortResultsDataGrid.ItemsSource = _allPortScanResults;
                RealTimePortResultsDataGrid.Items.Refresh();
                AppendLog($"已重置端口结果筛选，当前显示全部 {_allPortScanResults.Count} 条");
            }
            catch (Exception ex)
            {
                AppendLog($"重置端口筛选失败: {ex.Message}");
            }
        }

        private void ResetVulnFilterButton_Click(object sender, RoutedEventArgs e)
        {
            if (RealTimeVulnResultsDataGrid == null) return;
            try
            {
                // 重新绑定到 BulkObservableCollection，新结果将自动增量更新
                RealTimeVulnResultsDataGrid.ItemsSource = _allVulnResults;
                RealTimeVulnResultsDataGrid.Items.Refresh();
                AppendLog($"已重置漏洞结果筛选，当前显示全部 {_allVulnResults.Count} 条");
            }
            catch (Exception ex)
            {
                AppendLog($"重置漏洞筛选失败: {ex.Message}");
            }
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
            AppendLog("日志已清空");
        }

        /// <summary>
        /// 导出扫描日志到文件
        /// </summary>
        private void ExportLogButton_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                if (ScanLogTextBox == null || string.IsNullOrWhiteSpace(ScanLogTextBox.Text))
                {
                    MessageBox.Show("暂无日志可导出", "提示", MessageBoxButton.OK, MessageBoxImage.Information);
                    return;
                }

                var dialog = new SaveFileDialog
                {
                    Filter = "文本文件 (*.txt)|*.txt|日志文件 (*.log)|*.log",
                    FileName = $"expert_scan_log_{DateTime.Now:yyyyMMdd_HHmmss}.log",
                    Title = "导出扫描日志"
                };

                if (dialog.ShowDialog() == true)
                {
                    var content = ScanLogTextBox.Text;
                    // 添加导出元信息（时间戳、总行数）
                    var sb = new System.Text.StringBuilder();
                    sb.AppendLine($"=== 专家模式扫描日志 ===");
                    sb.AppendLine($"导出时间: {DateTime.Now:yyyy-MM-dd HH:mm:ss}");
                    sb.AppendLine($"日志行数: {content.Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries).Length}");
                    sb.AppendLine($"==========================================");
                    sb.AppendLine();
                    sb.AppendLine(content);
                    File.WriteAllText(dialog.FileName, sb.ToString(), Encoding.UTF8);
                    MessageBox.Show($"日志已导出到:\n{dialog.FileName}", "导出成功", MessageBoxButton.OK, MessageBoxImage.Information);
                    AppendLog($"已导出扫描日志到 {dialog.FileName}");
                }
            }
            catch (Exception ex)
            {
                MessageBox.Show($"导出日志失败: {ex.Message}", "错误", MessageBoxButton.OK, MessageBoxImage.Error);
            }
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
            // NRE 防护：DataGrid 或数据源可能为 null
            if (RealTimePortResultsDataGrid == null || _allPortScanResults == null) return;
            try
            {
                var selected = RealTimePortResultsDataGrid.SelectedItems?.Cast<PortScanResult>().ToList();
                if (selected == null || selected.Count == 0)
                {
                    AppendLog("未选中任何端口结果");
                    return;
                }
                // Task 8.5：列表写操作加锁
                lock (_resultsLock)
                {
                    foreach (var item in selected)
                    {
                        _allPortScanResults.Remove(item);
                    }
                }
                RealTimePortResultsDataGrid.Items.Refresh();
                AppendLog($"已删除 {selected.Count} 行端口结果");
            }
            catch (Exception ex)
            {
                AppendLog($"删除失败: {ex.Message}");
            }
        }

        private void SortByPort_Click(object sender, RoutedEventArgs e)
        {
            if (RealTimePortResultsDataGrid == null || _allPortScanResults == null) return;
            try
            {
                // Task 8.5：先在锁内取快照 + 排序，再回写，避免后台 Add 干扰
                List<PortScanResult> sorted;
                lock (_resultsLock)
                {
                    sorted = _allPortScanResults.OrderBy(r => r.PortNumber).ToList();
                    _allPortScanResults.Clear();
                    _allPortScanResults.AddRange(sorted);
                }
                RealTimePortResultsDataGrid.Items.Refresh();
                AppendLog("已按端口号排序");
            }
            catch (Exception ex)
            {
                AppendLog($"排序失败: {ex.Message}");
            }
        }

        private void CopyPortNumber_Click(object sender, RoutedEventArgs e)
        {
            if (RealTimePortResultsDataGrid == null) return;
            try
            {
                var ports = RealTimePortResultsDataGrid.SelectedItems?.Cast<PortScanResult>()
                    .Select(r => r.PortNumber.ToString())
                    .Where(s => !string.IsNullOrEmpty(s))
                    .ToList();
                if (ports == null || ports.Count == 0)
                {
                    AppendLog("未选中任何端口结果");
                    return;
                }
                SafeSetClipboard(string.Join(",", ports));
                AppendLog($"已复制 {ports.Count} 个端口号");
            }
            catch (Exception ex)
            {
                AppendLog($"复制端口号失败: {ex.Message}");
            }
        }

        private void CopyServiceName_Click(object sender, RoutedEventArgs e)
        {
            if (RealTimePortResultsDataGrid == null) return;
            try
            {
                var services = RealTimePortResultsDataGrid.SelectedItems?.Cast<PortScanResult>()
                    .Select(r => string.IsNullOrEmpty(r.Service) ? "未知服务" : r.Service)
                    .Distinct()
                    .ToList();
                if (services == null || services.Count == 0)
                {
                    AppendLog("未选中任何端口结果");
                    return;
                }
                SafeSetClipboard(string.Join(",", services));
                AppendLog($"已复制 {services.Count} 个服务名");
            }
            catch (Exception ex)
            {
                AppendLog($"复制服务名失败: {ex.Message}");
            }
        }

        private void SortByRiskScore_Click(object sender, RoutedEventArgs e)
        {
            if (RealTimePortResultsDataGrid == null || _allPortScanResults == null) return;
            try
            {
                // 按风险评分降序、端口号升序排序（高危在前）
                var sorted = Services.PortScanner.SortByRiskDesc(_allPortScanResults.ToList());
                _allPortScanResults.AddRangeReset(sorted);
                var highRiskCount = _allPortScanResults.Count(r => r.RiskScore >= 15);
                AppendLog($"已按风险评分降序排序，前 {highRiskCount} 个为高危/严重端口");
            }
            catch (Exception ex)
            {
                AppendLog($"风险排序失败: {ex.Message}");
            }
        }

        private void FilterOpenPorts_Click(object sender, RoutedEventArgs e)
        {
            if (RealTimePortResultsDataGrid == null || _allPortScanResults == null) return;
            try
            {
                // Task 8.5：先在锁内取快照 + 过滤，再绑定到 UI
                List<PortScanResult> filtered;
                lock (_resultsLock)
                {
                    filtered = _allPortScanResults.Where(r => r.Status == "开放").ToList();
                }
                RealTimePortResultsDataGrid.ItemsSource = null;
                RealTimePortResultsDataGrid.ItemsSource = filtered;
                AppendLog($"已筛选开放端口，共 {filtered.Count} 个");
            }
            catch (Exception ex)
            {
                AppendLog($"筛选失败: {ex.Message}");
            }
        }

        private void FilterHighRiskPorts_Click(object sender, RoutedEventArgs e)
        {
            if (RealTimePortResultsDataGrid == null || _allPortScanResults == null) return;
            try
            {
                // 筛选高危+严重端口（RiskScore >= 15）
                List<PortScanResult> filtered;
                lock (_resultsLock)
                {
                    filtered = _allPortScanResults.Where(r => r.RiskScore >= 15).ToList();
                }
                RealTimePortResultsDataGrid.ItemsSource = null;
                RealTimePortResultsDataGrid.ItemsSource = filtered;
                AppendLog($"已筛选高危/严重端口，共 {filtered.Count} 个");
            }
            catch (Exception ex)
            {
                AppendLog($"高危筛选失败: {ex.Message}");
            }
        }

        // 端口预设场景：ComboBox 选择事件
        private void PortPresetComboBox_SelectionChanged(object sender, SelectionChangedEventArgs e)
        {
            if (PresetDescriptionTextBlock == null) return;
            var item = PortPresetComboBox?.SelectedItem as ComboBoxItem;
            if (item == null || item.Tag == null)
            {
                PresetDescriptionTextBlock.Text = "";
                return;
            }
            string tag = item.Tag.ToString() ?? "";
            if (tag == "-1")
            {
                PresetDescriptionTextBlock.Text = "";
                return;
            }

            if (Enum.TryParse<PortServiceMapping.PortPreset>(tag, out var preset))
            {
                var info = PortServiceMapping.GetAllPresets().FirstOrDefault(p => p.Preset == preset);
                if (info != null)
                {
                    PresetDescriptionTextBlock.Text = $"{info.Name}: {info.Description}（{info.Ports.Count} 个端口）";
                }
            }
        }

        // 端口预设场景：应用预设按钮
        private void ApplyPresetButton_Click(object sender, RoutedEventArgs e)
        {
            var item = PortPresetComboBox?.SelectedItem as ComboBoxItem;
            if (item == null || item.Tag == null)
            {
                MessageBox.Show("请先选择一个预设场景", "提示", MessageBoxButton.OK, MessageBoxImage.Information);
                return;
            }
            string tag = item.Tag.ToString() ?? "";
            if (tag == "-1" || !Enum.TryParse<PortServiceMapping.PortPreset>(tag, out var preset))
            {
                MessageBox.Show("请先选择一个预设场景", "提示", MessageBoxButton.OK, MessageBoxImage.Information);
                return;
            }

            // 切换到自定义端口模式
            CustomPortsRadio.IsChecked = true;
            CustomPortsTextBox.IsEnabled = true;

            // 获取预设端口列表
            var ports = PortServiceMapping.GetPresetPorts(preset);
            if (ports == null || ports.Count == 0)
            {
                MessageBox.Show("该预设场景没有可用端口", "提示", MessageBoxButton.OK, MessageBoxImage.Warning);
                return;
            }

            // 填入自定义端口文本框（去重排序）
            var sortedPorts = ports.Distinct().OrderBy(p => p).ToList();
            CustomPortsTextBox.Text = string.Join(",", sortedPorts);

            var info = PortServiceMapping.GetAllPresets().FirstOrDefault(p => p.Preset == preset);
            string info2 = info != null ? $"{info.Name}（{info.Description}）" : preset.ToString();
            AppendLog($"已应用端口预设: {info2}，共 {sortedPorts.Count} 个端口");
        }

        private void CopyVulnSelectedRows_Click(object sender, RoutedEventArgs e)
        {
            // Task 8.5：null 守卫
            if (RealTimeVulnResultsDataGrid == null) return;
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
            // Task 8.5：null 守卫
            if (RealTimeVulnResultsDataGrid == null || _allVulnResults == null) return;
            try
            {
                var riskOrder = new Dictionary<string, int> { { "严重", 0 }, { "高危", 1 }, { "中危", 2 }, { "低危", 3 }, { "信息", 4 } };
                List<VulnerabilityResult> sorted;
                lock (_resultsLock)
                {
                    sorted = _allVulnResults.OrderBy(v => riskOrder.ContainsKey(v.RiskLevel) ? riskOrder[v.RiskLevel] : 5).ToList();
                    _allVulnResults.Clear();
                    _allVulnResults.AddRange(sorted);
                }
                RealTimeVulnResultsDataGrid.Items.Refresh();
                AppendLog("已按风险等级排序");
            }
            catch (Exception ex)
            {
                AppendLog($"风险等级排序失败: {ex.Message}");
            }
        }

        private void FilterHighRisk_Click(object sender, RoutedEventArgs e)
        {
            // Task 8.5：null 守卫
            if (RealTimeVulnResultsDataGrid == null || _allVulnResults == null) return;
            try
            {
                List<VulnerabilityResult> filtered;
                lock (_resultsLock)
                {
                    filtered = _allVulnResults.Where(v => v.RiskLevel == "高危" || v.RiskLevel == "严重").ToList();
                }
                RealTimeVulnResultsDataGrid.ItemsSource = null;
                RealTimeVulnResultsDataGrid.ItemsSource = filtered;
                AppendLog($"已筛选高危漏洞，共 {filtered.Count} 个");
            }
            catch (Exception ex)
            {
                AppendLog($"高危漏洞筛选失败: {ex.Message}");
            }
        }

        private void FilterMediumRisk_Click(object sender, RoutedEventArgs e)
        {
            // Task 8.5：null 守卫
            if (RealTimeVulnResultsDataGrid == null || _allVulnResults == null) return;
            try
            {
                List<VulnerabilityResult> filtered;
                lock (_resultsLock)
                {
                    filtered = _allVulnResults.Where(v => v.RiskLevel == "中危").ToList();
                }
                RealTimeVulnResultsDataGrid.ItemsSource = null;
                RealTimeVulnResultsDataGrid.ItemsSource = filtered;
                AppendLog($"已筛选中危漏洞，共 {filtered.Count} 个");
            }
            catch (Exception ex)
            {
                AppendLog($"中危漏洞筛选失败: {ex.Message}");
            }
        }

        private void RealTimePortResultsDataGrid_MouseDoubleClick(object sender, MouseButtonEventArgs e)
        {
            // Task 8.5：null 守卫 + 锁内取快照
            if (RealTimePortResultsDataGrid == null || _allVulnResults == null) return;
            if (RealTimePortResultsDataGrid.SelectedItem is PortScanResult result)
            {
                List<VulnerabilityResult> relatedVulns;
                lock (_resultsLock)
                {
                    relatedVulns = _allVulnResults.Where(v => v.Port == result.PortNumber && v.Target == result.TargetIp).ToList();
                }
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
            // Task 8.5：扫描进行中禁止触发深度扫描，避免数据竞争
            if (_isScanning)
            {
                AppendLog("⚠️ 扫描进行中，请等待扫描完成后再触发深度漏洞扫描");
                return;
            }

            // Task 8.5：DataGrid / 数据源 / 扫描器为空时早退
            if (RealTimePortResultsDataGrid == null || _allVulnResults == null || _vulnerabilityScanner == null)
            {
                AppendLog("⚠️ 深度扫描所需组件尚未初始化");
                return;
            }

            if (RealTimePortResultsDataGrid.SelectedItem is PortScanResult result && result.Status == "开放")
            {
                AppendLog($"开始深度漏洞扫描: {result.TargetIp}:{result.PortNumber}");
                try
                {
                    var vulns = await _vulnerabilityScanner.ScanVulnerabilitiesAsync(result.TargetIp,
                        new List<PortScanResult> { result }, CancellationToken.None);
                    // Task 8.5：写操作加锁，UI 操作放 lock 外避免死锁
                    List<VulnerabilityResult> snapshot;
                    lock (_resultsLock)
                    {
                        foreach (var v in vulns)
                        {
                            _allVulnResults.Add(v);
                        }
                        snapshot = _allVulnResults.ToList();
                    }
                    Dispatcher.Invoke(() =>
                    {
                        RealTimeVulnResultsDataGrid.ItemsSource = snapshot;
                        RealTimeVulnResultsDataGrid.Items.Refresh();
                        VulnerabilitiesStat.Text = snapshot.Count.ToString();
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
                string tempHtml = Path.Combine(Path.GetTempPath(), $"expert_report_{Guid.NewGuid():N}.html");
                try
                {
                    // Generate PDF using HTML-to-PDF approach (same as MainWindow)
                    var html = GenerateHtmlReport();
                    File.WriteAllText(tempHtml, html, Encoding.UTF8);

                    // Use the project's ReportEngine if available, otherwise simple file save
                    object engine = null;
                    try
                    {
                        var reportEngineType = System.Reflection.Assembly.GetExecutingAssembly().GetType("NetSecurityScanner.Services.ReportEngine")
                            ?? System.Reflection.Assembly.GetEntryAssembly()?.GetType("NetSecurityScanner.Services.ReportEngine");
                        if (reportEngineType != null)
                        {
                            engine = Activator.CreateInstance(reportEngineType);
                            dynamic dynEngine = engine;
                            dynEngine.GeneratePdfFromHtml(tempHtml, dialog.FileName);
                        }
                        else
                        {
                            throw new InvalidOperationException("ReportEngine not available");
                        }
                    }
                    catch
                    {
                        // Fallback: save as HTML with .pdf extension note
                        var htmlOut = Path.ChangeExtension(dialog.FileName, ".html");
                        if (string.IsNullOrEmpty(htmlOut)) htmlOut = dialog.FileName + ".html";
                        File.Copy(tempHtml, htmlOut, true);
                        MessageBox.Show("PDF引擎不可用，已导出为HTML格式。可使用浏览器打印为PDF。", "提示", MessageBoxButton.OK, MessageBoxImage.Information);
                        return;
                    }
                    finally
                    {
                        // Dispose engine if it implements IDisposable
                        if (engine is IDisposable disp) try { disp.Dispose(); } catch { }
                    }

                    if (File.Exists(dialog.FileName))
                        MessageBox.Show($"PDF报告已保存到:\n{dialog.FileName}", "导出成功", MessageBoxButton.OK, MessageBoxImage.Information);
                }
                catch (Exception ex)
                {
                    MessageBox.Show($"导出PDF失败: {ex.Message}\n\n建议使用「导出HTML」后在浏览器中打印为PDF。", "错误", MessageBoxButton.OK, MessageBoxImage.Error);
                }
                finally
                {
                    // 删除临时 HTML 文件，避免临时目录累积
                    try { if (File.Exists(tempHtml)) File.Delete(tempHtml); } catch { }
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

        private async void ExpertModeWindow_Closing(object? sender, System.ComponentModel.CancelEventArgs e)
        {
            // 先停止计时器，避免在窗口关闭后继续触发
            try { _elapsedTimer?.Stop(); } catch { }
            try { _templateNotificationTimer?.Stop(); } catch { }

            // Task 8.1：扫描进行中时，暂缓关闭 → 优雅等待后台任务完成 → 真正释放资源
            if (_isScanning)
            {
                var result = MessageBox.Show(
                    "扫描正在进行中，确定要关闭窗口吗？\n\n选择「是」会等待后台任务完成后再关闭（最多 3 秒）。",
                    "确认关闭", MessageBoxButton.YesNo, MessageBoxImage.Question);
                if (result == MessageBoxResult.No)
                {
                    e.Cancel = true;
                    return;
                }

                // 暂缓关闭，先优雅结束后台任务
                e.Cancel = true;
                try { _cancellationTokenSource?.Cancel(); } catch { }
                AppendLog("🛑 等待后台扫描任务完成...");

                // 等待后台任务完成（带超时），避免 dispose 时任务还在 await
                try
                {
                    if (_scanTaskCompletionSource != null)
                    {
                        await _scanTaskCompletionSource.Task.WaitAsync(TimeSpan.FromSeconds(3));
                    }
                }
                catch (TimeoutException)
                {
                    AppendLog("⚠️ 后台任务未在 3 秒内结束，强制关闭");
                }
                catch (Exception)
                {
                    // 忽略其他异常，进入强制关闭流程
                }

                // 标记已结束并安全释放资源
                _isScanning = false;
                SafeDispose();
                // 此时重新发起关闭：本次事件已通过 e.Cancel=true 暂缓，重新调用 Close() 真正关闭窗口
                Close();
                return;
            }

            // 非扫描状态：保留原有"保存配置 + 释放资源"逻辑
            // Save config on closing
            try
            {
                var config = CollectConfig();
                var configPath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                    "NetSecurityScanner", "expert_last_config.json");
                // 确保父目录存在，避免首次运行时因目录不存在而抛异常
                var dir = Path.GetDirectoryName(configPath);
                if (!string.IsNullOrEmpty(dir) && !Directory.Exists(dir))
                {
                    Directory.CreateDirectory(dir);
                }

                var saveData = new
                {
                    Config = config,
                    SelectedTab = ExpertTabControl?.SelectedIndex ?? 0,
                    UseRustScanner = _useRustScanner
                };
                var json = JsonSerializer.Serialize(saveData, new JsonSerializerOptions { WriteIndented = true });
                File.WriteAllText(configPath, json, Encoding.UTF8);
            }
            catch (Exception ex)
            {
                // 静默失败，但保留诊断信息
                System.Diagnostics.Debug.WriteLine($"[ExpertModeWindow] 保存配置失败: {ex.Message}");
            }

            SafeDispose();
        }

        /// <summary>
        /// 统一安全释放所有托管/非托管资源（用于 Closing 和 FinalizeScan 之间的复用）
        /// </summary>
        private void SafeDispose()
        {
            try { _cancellationTokenSource?.Dispose(); _cancellationTokenSource = null; } catch { }
            try { _rustClient?.Dispose(); _rustClient = null; } catch { }
            try { _portScanner?.Dispose(); } catch { }
            try { _vulnerabilityScanner?.Dispose(); } catch { }
            try { _ = _weakPasswordPlugin?.InitializeAsync(new Dictionary<string, object>()); } catch { }
            _weakPasswordPlugin = null;
            // JsonDatabaseService 不实现 IDisposable，仅释放引用即可
            _jsonDatabaseService = null;
            try { _elapsedTimer?.Stop(); } catch { }
            _elapsedTimer = null;
            try { _templateNotificationTimer?.Stop(); } catch { }
            _templateNotificationTimer = null;
        }

        private void PasteFromClipboardButton_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                if (!Clipboard.ContainsText())
                {
                    MessageBox.Show("剪贴板中没有文本内容", "提示", MessageBoxButton.OK, MessageBoxImage.Information);
                    return;
                }

                var text = Clipboard.GetText();
                if (string.IsNullOrWhiteSpace(text))
                {
                    MessageBox.Show("剪贴板内容为空或仅含空白字符", "提示", MessageBoxButton.OK, MessageBoxImage.Information);
                    return;
                }

                // 防御性：剪贴板内容可能超大，超过 100K 字符时截断避免 UI 卡顿
                const int maxLen = 100_000;
                if (text.Length > maxLen)
                {
                    var confirm = MessageBox.Show(
                        $"剪贴板内容过长（{text.Length:N0} 字符），将仅粘贴前 {maxLen:N0} 字符，是否继续？",
                        "内容过长",
                        MessageBoxButton.YesNo,
                        MessageBoxImage.Question);
                    if (confirm != MessageBoxResult.Yes) return;
                    text = text.Substring(0, maxLen);
                }

                TargetInputTextBox.Text = text;
                ParseTargetCount();
                UpdateScanPlanPreview();

                int lineCount = text.Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries).Length;
                AppendLog($"已从剪贴板粘贴 {lineCount} 行目标，共 {TargetCountTextBlock.Text}");
            }
            catch (Exception ex)
            {
                // 剪贴板被其他程序占用时会抛 COMException
                MessageBox.Show($"粘贴失败: {ex.Message}\n\n（剪贴板可能被其他程序占用，请稍后重试）",
                    "错误", MessageBoxButton.OK, MessageBoxImage.Warning);
            }
        }

        private void RecommendButton_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                var config = CollectConfig();
                var targets = ResolveTargets(config);
                int count = targets.Count;

                if (count == 0)
                {
                    RecommendResultTextBlock.Text = "⚠️ 当前未解析到任何目标，请先输入有效的扫描目标（IP/CIDR/范围/文件/正则）。";
                    RecommendResultTextBlock.Foreground = new SolidColorBrush(Color.FromRgb(0xE6, 0x7E, 0x22));
                    ApplyRecommendButton.Visibility = Visibility.Collapsed;
                    _recommendedConfig = null;
                    return;
                }

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

                if (_recommendedConfig == null)
                {
                    RecommendResultTextBlock.Text = "⚠️ 推荐配置生成失败（Factory 返回空）";
                    RecommendResultTextBlock.Foreground = new SolidColorBrush(Color.FromRgb(0xE7, 0x4C, 0x3C));
                    ApplyRecommendButton.Visibility = Visibility.Collapsed;
                    return;
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
                ApplyRecommendButton.Visibility = Visibility.Collapsed;
                _recommendedConfig = null;
            }
        }

        private void ApplyRecommendButton_Click(object sender, RoutedEventArgs e)
        {
            if (_recommendedConfig == null) return;
            try
            {
                // 检测是否会覆盖用户已有设置
                bool willOverwrite = TcpConcurrencySlider.Value != _recommendedConfig.TcpConcurrency ||
                                     TcpTimeoutSlider.Value != _recommendedConfig.TimeoutMs ||
                                     RetrySlider.Value != _recommendedConfig.RetryCount;

                if (willOverwrite)
                {
                    var confirm = MessageBox.Show(
                        $"应用推荐模式将覆盖当前的扫描参数设置：\n\n" +
                        $"• TCP并发: {(int)TcpConcurrencySlider.Value} → {_recommendedConfig.TcpConcurrency}\n" +
                        $"• UDP并发: {(int)UdpConcurrencySlider.Value} → {_recommendedConfig.UdpConcurrency}\n" +
                        $"• TCP超时: {(int)TcpTimeoutSlider.Value}ms → {_recommendedConfig.TimeoutMs}ms\n" +
                        $"• 重试次数: {(int)RetrySlider.Value} → {_recommendedConfig.RetryCount}\n\n" +
                        $"是否继续？",
                        "应用推荐",
                        MessageBoxButton.YesNo,
                        MessageBoxImage.Question);
                    if (confirm != MessageBoxResult.Yes) return;
                }

                // Task 8.2：所有字段访问加 null 守卫，避免 XAML 改动时 NRE
                if (TcpConcurrencySlider != null) TcpConcurrencySlider.Value = _recommendedConfig.TcpConcurrency;
                if (UdpConcurrencySlider != null) UdpConcurrencySlider.Value = _recommendedConfig.UdpConcurrency;
                if (TcpTimeoutSlider != null) TcpTimeoutSlider.Value = _recommendedConfig.TimeoutMs;
                if (UdpTimeoutSlider != null) UdpTimeoutSlider.Value = _recommendedConfig.TimeoutMs;  // 同源
                if (RetrySlider != null) RetrySlider.Value = _recommendedConfig.RetryCount;
                if (ServiceVersionCheckBox != null) ServiceVersionCheckBox.IsChecked = _recommendedConfig.EnableServiceDetection;
                if (HostDiscoveryCheckBox != null) HostDiscoveryCheckBox.IsChecked = _recommendedConfig.EnablePingProbe;

                // 兜底：通过反射把 ScanProfileConfig 中所有未手动赋值的属性尝试匹配到 UI 控件
                // 当未来扩展字段（如 PortRange、ServiceIntensity 等）只需在 XAML 加同名控件即可自动应用
                try
                {
                    var configType = _recommendedConfig.GetType();
                    var properties = configType.GetProperties();
                    foreach (var prop in properties)
                    {
                        // 跳过已显式赋值的字段
                        if (prop.Name == nameof(ScanProfileConfig.TcpConcurrency) ||
                            prop.Name == nameof(ScanProfileConfig.UdpConcurrency) ||
                            prop.Name == nameof(ScanProfileConfig.TimeoutMs) ||
                            prop.Name == nameof(ScanProfileConfig.RetryCount) ||
                            prop.Name == nameof(ScanProfileConfig.EnableServiceDetection) ||
                            prop.Name == nameof(ScanProfileConfig.EnablePingProbe))
                            continue;

                        // 尝试通过 FindName 查找同名的 UI 控件
                        var control = this.FindName(prop.Name) as FrameworkElement;
                        if (control == null) continue;

                        try
                        {
                            if (control is CheckBox cb && prop.PropertyType == typeof(bool))
                            {
                                var v = prop.GetValue(_recommendedConfig);
                                if (v is bool b) cb.IsChecked = b;
                            }
                            else if (control is Slider sl && (prop.PropertyType == typeof(int) || prop.PropertyType == typeof(double)))
                            {
                                var v = prop.GetValue(_recommendedConfig);
                                if (v != null) sl.Value = Convert.ToDouble(v);
                            }
                            else if (control is ComboBox cmb && prop.PropertyType == typeof(int))
                            {
                                var v = prop.GetValue(_recommendedConfig);
                                if (v is int i) cmb.SelectedIndex = i;
                            }
                            else if (control is TextBox tb && prop.PropertyType == typeof(string))
                            {
                                tb.Text = (prop.GetValue(_recommendedConfig) as string) ?? "";
                            }
                        }
                        catch
                        {
                            // 单个控件失败不影响整体
                        }
                    }
                }
                catch (Exception ex)
                {
                    AppendLog($"推荐模式部分字段应用失败: {ex.Message}");
                }

                UpdateConfigSummary();
                UpdateScanPlanPreview();
                AppendLog($"✅ 已应用推荐模式: {_recommendedConfig.Profile}（已同步所有可匹配字段）");
            }
            catch (Exception ex)
            {
                MessageBox.Show($"应用推荐失败: {ex.Message}", "错误", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        private void ResetScanButtons()
        {
            FinalizeScan();
        }

        /// <summary>
        /// 统一处理扫描结束的资源清理（标志复位、按钮恢复、计时器停止、CTS 释放）
        /// 所有退出路径（正常完成、用户取消、异常）都应调用此方法
        /// </summary>
        private void FinalizeScan()
        {
            try { _isScanning = false; } catch { }

            // 释放自适应并发控制器（无论正常完成/取消/异常都会走到这里）
            DisposeAdaptiveConcurrency();

            // 清理 Rust 服务（预启动模式）— 非UI操作，可在任意线程执行
            if (_rustServiceStarted)
            {
                try
                {
                    _rustClient?.StopService();
                    AppendLog("Rust 引擎已关闭");
                }
                catch { }
                _rustServiceStarted = false;
            }

            try
            {
                _cancellationTokenSource?.Dispose();
                _cancellationTokenSource = null;
            }
            catch { }

            // 修复线程错误：FinalizeScan 可能被后台扫描线程（Task.Run 中的 ExecuteExpertScanAsync）调用，
            // 而 DispatcherTimer 与所有 UI 控件只能在其所属 UI 线程上访问，
            // 否则抛出 InvalidOperationException: "调用线程无法访问此对象，因为另一个线程拥有该对象"
            Action uiReset = () =>
            {
                try { _elapsedTimer?.Stop(); } catch { }
                if (StartExpertScanButton != null)
                {
                    StartExpertScanButton.IsEnabled = true;
                    StartExpertScanButton.Content = "🚀 开始专家扫描";
                }
                if (CancelExpertButton != null)
                {
                    CancelExpertButton.IsEnabled = false;
                    CancelExpertButton.Content = "❌ 取消";
                }
                if (ElapsedTextBlock != null) ElapsedTextBlock.Text = "已用: 00:00:00";
                if (RemainingTextBlock != null) RemainingTextBlock.Text = "预计剩余: --:--:--";
                try { SetControlsEnabledWhileScanning(true); } catch { }
            };

            try
            {
                if (Dispatcher.CheckAccess())
                {
                    uiReset();
                }
                else
                {
                    // 后台线程：异步调度到 UI 线程，避免阻塞扫描收尾流程
                    Dispatcher.BeginInvoke(uiReset);
                }
            }
            catch { /* Dispatcher 可能已关闭（窗口正在销毁），安全忽略 */ }
        }

        /// <summary>
        /// 根据当前输入实时验证，决定是否启用"开始扫描"按钮，并更新输入框视觉反馈
        /// </summary>
        private void UpdateStartButtonState()
        {
            if (StartExpertScanButton == null) return; // 容错：UI 可能尚未加载
            if (_isScanning) return; // 扫描中不改变按钮状态

            var input = TargetInputTextBox?.Text?.Trim() ?? "";
            bool hasTarget = !string.IsNullOrWhiteSpace(input);

            bool hasValidPorts = true;
            if (CustomPortsRadio?.IsChecked == true)
            {
                var customPorts = CustomPortsTextBox?.Text?.Trim() ?? "";
                hasValidPorts = !string.IsNullOrWhiteSpace(customPorts);
            }

            bool canStart = hasTarget && hasValidPorts;

            // 目标输入框视觉反馈
            if (TargetInputTextBox != null)
            {
                if (hasTarget)
                {
                    // 恢复正常边框
                    TargetInputTextBox.BorderBrush = new SolidColorBrush(Color.FromRgb(0xBD, 0xC3, 0xC7));
                    TargetInputTextBox.BorderThickness = new Thickness(1);
                    TargetInputTextBox.ToolTip = null;
                }
                else
                {
                    // 红色边框 + Tooltip
                    TargetInputTextBox.BorderBrush = new SolidColorBrush(Color.FromRgb(0xE7, 0x4C, 0x3C));
                    TargetInputTextBox.BorderThickness = new Thickness(2);
                    TargetInputTextBox.ToolTip = "目标不能为空，请输入 IP/CIDR/范围/正则/文件路径";
                }
            }

            // 自定义端口输入框视觉反馈
            if (CustomPortsTextBox != null)
            {
                if (CustomPortsRadio?.IsChecked == true)
                {
                    if (hasValidPorts)
                    {
                        CustomPortsTextBox.BorderBrush = new SolidColorBrush(Color.FromRgb(0xBD, 0xC3, 0xC7));
                        CustomPortsTextBox.BorderThickness = new Thickness(1);
                        CustomPortsTextBox.ToolTip = null;
                    }
                    else
                    {
                        CustomPortsTextBox.BorderBrush = new SolidColorBrush(Color.FromRgb(0xE7, 0x4C, 0x3C));
                        CustomPortsTextBox.BorderThickness = new Thickness(2);
                        CustomPortsTextBox.ToolTip = "已选择「自定义端口」模式，请填写至少一个端口";
                    }
                }
                else
                {
                    // 非自定义模式下清空视觉反馈
                    CustomPortsTextBox.BorderBrush = new SolidColorBrush(Color.FromRgb(0xBD, 0xC3, 0xC7));
                    CustomPortsTextBox.BorderThickness = new Thickness(1);
                    CustomPortsTextBox.ToolTip = null;
                }
            }

            // 按钮状态
            StartExpertScanButton.IsEnabled = canStart;
            if (!canStart)
            {
                string reason = !hasTarget ? "请先输入扫描目标" : "请填写至少一个自定义端口";
                StartExpertScanButton.ToolTip = reason;
            }
            else
            {
                StartExpertScanButton.ToolTip = "开始专家模式扫描";
            }
        }

        /// <summary>
        /// 探测 Rust 扫描引擎可用性，并更新 UI 状态显示
        /// </summary>
        private void RefreshRustEngineStatus()
        {
            if (EngineStatusTextBlock == null) return;
            try
            {
                var exe = RustScannerClient.FindRustScannerExecutable();
                if (exe != null)
                {
                    EngineStatusTextBlock.Text = "✅ Rust 引擎就绪（高性能，推荐）";
                    EngineStatusTextBlock.Foreground = new SolidColorBrush(Color.FromRgb(0x27, 0xAE, 0x60));
                    if (EnginePathTextBlock != null)
                    {
                        try
                        {
                            var fileInfo = new FileInfo(exe);
                            EnginePathTextBlock.Text = $"路径: {exe}  ({fileInfo.Length / 1024} KB, {fileInfo.LastWriteTime:yyyy-MM-dd})";
                        }
                        catch
                        {
                            EnginePathTextBlock.Text = $"路径: {exe}";
                        }
                        EnginePathTextBlock.Foreground = new SolidColorBrush(Color.FromRgb(0x7F, 0x8C, 0x8D));
                    }
                }
                else
                {
                    EngineStatusTextBlock.Text = "⚠️ Rust 引擎未找到，将自动降级到内置 C# 扫描器";
                    EngineStatusTextBlock.Foreground = new SolidColorBrush(Color.FromRgb(0xE6, 0x7E, 0x22));
                    if (EnginePathTextBlock != null)
                    {
                        EnginePathTextBlock.Text = "未找到 rust-scanner-service.exe。请先构建 Rust 服务 (cargo build --release) 并将 rust-scanner-service.exe 放到本应用根目录、tools/ 或 rust/ 子目录。";
                        EnginePathTextBlock.Foreground = new SolidColorBrush(Color.FromRgb(0xC0, 0x39, 0x2B));
                    }
                }
            }
            catch (Exception ex)
            {
                EngineStatusTextBlock.Text = $"❌ Rust 引擎状态异常: {ex.Message}";
                EngineStatusTextBlock.Foreground = new SolidColorBrush(Color.FromRgb(0xE7, 0x4C, 0x3C));
            }
        }

        /// <summary>
        /// 异步自检 Rust 引擎：启动、连接、查询状态、停止
        /// </summary>
        private async void TestRustEngineButton_Click(object sender, RoutedEventArgs e)
        {
            if (TestRustEngineButton == null) return;
            TestRustEngineButton.IsEnabled = false;
            AppendLog("🧪 开始 Rust 引擎自检...");
            try
            {
                var exe = RustScannerClient.FindRustScannerExecutable();
                if (exe == null)
                {
                    AppendLog("❌ 自检失败: 找不到 rust-scanner-service.exe");
                    MessageBox.Show("未找到 Rust 引擎可执行文件。\n\n请先构建并复制 rust-scanner-service.exe 到本应用根目录或 tools/ 子目录。",
                        "Rust 引擎自检", MessageBoxButton.OK, MessageBoxImage.Warning);
                    return;
                }

                using var client = new RustScannerClient();
                var started = await client.StartServiceAsync(exe, 200, 200, 500);
                if (!started)
                {
                    AppendLog("❌ Rust 服务进程启动失败");
                    MessageBox.Show("Rust 引擎进程启动失败，请查看日志。", "Rust 引擎自检",
                        MessageBoxButton.OK, MessageBoxImage.Error);
                    return;
                }

                var connected = await client.ConnectAsync();
                if (!connected)
                {
                    client.StopService();
                    AppendLog("❌ 无法连接 Rust 服务");
                    MessageBox.Show("Rust 引擎已启动但无法建立连接 (TCP 9527)。", "Rust 引擎自检",
                        MessageBoxButton.OK, MessageBoxImage.Error);
                    return;
                }

                var status = await client.GetStatusAsync();
                client.StopService();

                AppendLog($"✅ Rust 引擎自检通过: PID 启动成功, TCP 9527 已连接, 状态查询 {(status != null ? "成功" : "降级")}");
                MessageBox.Show(
                    $"✅ Rust 引擎自检通过\n\n" +
                    $"• 可执行文件: {exe}\n" +
                    $"• TCP 端口: 9527\n" +
                    $"• 状态: 正常\n\n" +
                    (status != null ? $"• CPU: {status.CpuPercent:F1}%   内存: {status.MemoryPercent:F1}%" : "• 状态查询降级 (Rust 端未实现 status 响应)"),
                    "Rust 引擎自检", MessageBoxButton.OK, MessageBoxImage.Information);
            }
            catch (Exception ex)
            {
                AppendLog($"❌ Rust 引擎自检异常: {ex.Message}");
                MessageBox.Show($"自检过程发生异常: {ex.Message}", "Rust 引擎自检",
                    MessageBoxButton.OK, MessageBoxImage.Error);
            }
            finally
            {
                if (TestRustEngineButton != null) TestRustEngineButton.IsEnabled = true;
            }
        }

        /// <summary>
        /// 在资源管理器中打开 Rust 引擎所在目录
        /// </summary>
        private void OpenRustFolderButton_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                var dir = RustScannerClient.FindRustScannerDirectory();
                if (dir == null)
                {
                    AppendLog("❌ 找不到 Rust 引擎，无法打开目录");
                    MessageBox.Show("未找到 Rust 引擎，无法打开目录。", "打开目录", MessageBoxButton.OK, MessageBoxImage.Warning);
                    return;
                }
                System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo
                {
                    FileName = dir,
                    UseShellExecute = true,
                    Verb = "open"
                });
                AppendLog($"📂 已打开 Rust 引擎目录: {dir}");
            }
            catch (Exception ex)
            {
                AppendLog($"❌ 打开目录失败: {ex.Message}");
            }
        }

        /// <summary>
        /// 复制 Rust 引擎完整路径到剪贴板
        /// </summary>
        private void CopyRustPathButton_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                var exe = RustScannerClient.FindRustScannerExecutable();
                if (exe == null)
                {
                    MessageBox.Show("未找到 Rust 引擎。", "复制路径", MessageBoxButton.OK, MessageBoxImage.Warning);
                    return;
                }
                try { Clipboard.SetText(exe); } catch { }
                AppendLog($"📋 已复制 Rust 引擎路径: {exe}");
            }
            catch (Exception ex)
            {
                AppendLog($"❌ 复制路径失败: {ex.Message}");
            }
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
            // 限制 hour/minute 在合法范围
            hour = Math.Clamp(hour, 0, 23);
            minute = Math.Clamp(minute, 0, 59);

            return mode switch
            {
                "once" => BuildOnceCron(hour, minute),
                "daily" => $"{minute} {hour} * * *",
                "weekly" => $"{minute} {hour} * * {(int)DateTime.Now.DayOfWeek}",
                "custom" => CronExpressionTextBox?.Text?.Trim() ?? "0 2 * * *",
                _ => $"{minute} {hour} * * *"
            };
        }

        /// <summary>
        /// 构建"仅一次"模式的 Cron 表达式，确保日期合法（不产生 32 日等越界值）
        /// </summary>
        private string BuildOnceCron(int hour, int minute)
        {
            var now = DateTime.Now;
            // 候选执行时间：今天 hour:minute 或 明天 hour:minute（取未来最近的一个）
            var todayCandidate = new DateTime(now.Year, now.Month, now.Day, hour, minute, 0);
            var execTime = todayCandidate > now ? todayCandidate : todayCandidate.AddDays(1);

            // 处理月末：若明天超出当月最大天数，Cron 月日字段仍然会按当月匹配，
            // 但 Cron 解析器在日期越界时会跳过。我们改用"X-X 月"形式并不安全，
            // 因此改用"下个月 1 日"作为兜底，确保一定能执行。
            if (execTime.Day == 1 && todayCandidate <= now)
            {
                // 已经过了今天，但明天就是 1 号，Cron 表达式可直接用
                return $"{minute} {hour} {execTime.Day} {execTime.Month} *";
            }

            // 简单方案：使用"日 月"两个字段，标准 Cron 解析器会自动跳过无效日期
            // 对于 Quartz/Cronos 等库，"X Y * * *" 中 X>当月最大天数 会被自动顺延
            return $"{minute} {hour} {execTime.Day} {execTime.Month} *";
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

                if (_scheduler == null)
                {
                    AppendLog("⚠️ 调度器未就绪，无法刷新任务列表");
                    return;
                }

                var tasks = _scheduler.Tasks.Select(t => new ScheduledTaskViewModel
                {
                    Id = t.Id ?? string.Empty,
                    Name = t.Name ?? string.Empty,
                    Target = t.TargetIp ?? string.Empty,
                    CronExpression = t.CronExpression ?? string.Empty,
                    Status = t.Enabled ? "启用" : "禁用",
                    LastRunAt = t.LastRunAt,
                    TotalRuns = t.TotalRuns
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
            if (await ApplyScheduledTaskStatusAsync(sender, true))
            {
                AppendLog("已启用定时任务");
            }
        }

        private async void DisableScheduledTask_Click(object sender, RoutedEventArgs e)
        {
            if (await ApplyScheduledTaskStatusAsync(sender, false))
            {
                AppendLog("已禁用定时任务");
            }
        }

        /// <summary>
        /// 通用：查找右键点击的 MenuItem 对应的 DataGrid 行（SelectedItem），并切换启用状态
        /// </summary>
        private async Task<bool> ApplyScheduledTaskStatusAsync(object sender, bool enable)
        {
            try
            {
                // ContextMenu 的 PlacementTarget 即 DataGrid
                var menuItem = sender as MenuItem;
                var dataGrid = menuItem?.Parent is ContextMenu cm ? cm.PlacementTarget as DataGrid : null;
                dataGrid ??= ScheduledTasksDataGrid;
                if (dataGrid == null) return false;

                if (dataGrid.SelectedItem is not ScheduledTaskViewModel vm)
                {
                    AppendLog("⚠️ 请先在任务列表中选择一条任务");
                    return false;
                }
                if (string.IsNullOrEmpty(vm.Id))
                {
                    AppendLog("⚠️ 选中任务的 Id 为空，无法操作");
                    return false;
                }

                var task = _scheduler?.Tasks.FirstOrDefault(t => t.Id == vm.Id);
                if (task == null)
                {
                    AppendLog($"⚠️ 未在调度器中找到任务 {vm.Id}");
                    return false;
                }
                task.Enabled = enable;
                _scheduler?.UpdateTask(task);
                await RefreshScheduledTasksAsync();
                return true;
            }
            catch (Exception ex)
            {
                AppendLog($"切换任务状态失败: {ex.Message}");
                return false;
            }
        }

        private async void DeleteScheduledTask_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                var menuItem = sender as MenuItem;
                var dataGrid = menuItem?.Parent is ContextMenu cm ? cm.PlacementTarget as DataGrid : null;
                dataGrid ??= ScheduledTasksDataGrid;
                if (dataGrid == null) return;

                if (dataGrid.SelectedItem is not ScheduledTaskViewModel vm)
                {
                    AppendLog("⚠️ 请先在任务列表中选择一条任务");
                    return;
                }
                if (string.IsNullOrEmpty(vm.Id))
                {
                    AppendLog("⚠️ 选中任务的 Id 为空，无法删除");
                    return;
                }
                var result = MessageBox.Show($"确认删除定时任务「{vm.Name}」？", "确认删除", MessageBoxButton.YesNo, MessageBoxImage.Question);
                if (result != MessageBoxResult.Yes) return;
                _scheduler?.RemoveTask(vm.Id);
                await RefreshScheduledTasksAsync();
                AppendLog($"已删除定时任务: {vm.Name}");
            }
            catch (Exception ex)
            {
                AppendLog($"删除定时任务失败: {ex.Message}");
            }
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
            if (ScanHistoryDataGrid.SelectedItems.Count == 0)
            {
                MessageBox.Show("请先在历史记录中选择两条扫描进行对比。\n\n操作方法：\n1. 按住 Ctrl 键\n2. 依次点击两条记录\n3. 点击「对比选中」按钮", "提示", MessageBoxButton.OK, MessageBoxImage.Information);
                return;
            }
            if (ScanHistoryDataGrid.SelectedItems.Count == 1)
            {
                MessageBox.Show("当前只选择了 1 条记录，请再选择 1 条（按住 Ctrl 多选）后进行对比。", "提示", MessageBoxButton.OK, MessageBoxImage.Information);
                return;
            }
            if (ScanHistoryDataGrid.SelectedItems.Count > 2)
            {
                MessageBox.Show($"当前选择了 {ScanHistoryDataGrid.SelectedItems.Count} 条记录，对比功能仅支持 2 条。请重新选择恰好 2 条。", "提示", MessageBoxButton.OK, MessageBoxImage.Information);
                return;
            }

            var items = ScanHistoryDataGrid.SelectedItems.Cast<ScanHistoryItem>().ToList();
            var item1 = items[0];
            var item2 = items[1];

            // 目标必须相同，否则对比没有意义
            if (!string.Equals(item1.TargetIp, item2.TargetIp, StringComparison.OrdinalIgnoreCase))
            {
                var confirm = MessageBox.Show(
                    $"所选两条记录的目标不同：\n  1) {item1.TargetIp}\n  2) {item2.TargetIp}\n\n" +
                    $"对不同目标的扫描结果做差异对比意义不大，建议选择同一目标的两次扫描。\n\n是否仍然继续？",
                    "目标不一致",
                    MessageBoxButton.YesNo,
                    MessageBoxImage.Warning);
                if (confirm != MessageBoxResult.Yes) return;
            }

            // 加载完整的扫描结果进行对比
            var scan1 = await _jsonDatabaseService.GetScanResultByIdAsync(item1.ScanId);
            var scan2 = await _jsonDatabaseService.GetScanResultByIdAsync(item2.ScanId);

            if (scan1 == null || scan2 == null)
            {
                MessageBox.Show("无法加载完整的扫描结果数据，请确认记录文件存在。\n\n可能是早期版本的扫描记录，与当前数据格式不兼容。", "错误", MessageBoxButton.OK, MessageBoxImage.Error);
                return;
            }

            try
            {
                var diffWindow = new ScanDiffWindow(scan1, scan2);
                diffWindow.Owner = this;
                diffWindow.ShowDialog();
            }
            catch (Exception ex)
            {
                MessageBox.Show($"打开对比窗口失败: {ex.Message}", "错误", MessageBoxButton.OK, MessageBoxImage.Error);
            }
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

        /// <summary>
        /// 双击扫描历史记录行 -> 加载完整扫描结果并生成报告
        /// </summary>
        private async void ScanHistoryDataGrid_MouseDoubleClick(object sender, MouseButtonEventArgs e)
        {
            try
            {
                if (ScanHistoryDataGrid.SelectedItem is not ScanHistoryItem record)
                    return;

                // 加载完整扫描结果
                var scanResult = await _jsonDatabaseService.GetScanResultByIdAsync(record.ScanId);
                if (scanResult == null)
                {
                    // 没有完整结果文件，回退到显示基本信息
                    var detail = $"扫描ID: {record.ScanId}\n" +
                                 $"目标: {record.TargetIp}\n" +
                                 $"扫描类型: {record.ScanType}\n" +
                                 $"扫描时间: {record.ScanTime:yyyy-MM-dd HH:mm:ss}\n" +
                                 $"开放端口: {record.OpenPortsCount}\n" +
                                 $"漏洞数量: {record.VulnerabilitiesCount}\n" +
                                 $"风险等级: {record.RiskLevel}\n" +
                                 $"扫描耗时: {record.Duration:F1}秒\n\n" +
                                 "⚠️ 完整扫描结果数据文件不存在，无法生成详细报告。\n" +
                                 "可能是早期版本的扫描记录，数据格式不兼容。";
                    MessageBox.Show(detail, "扫描记录详情", MessageBoxButton.OK, MessageBoxImage.Information);
                    return;
                }

                // 有完整数据 -> 构造报告预览窗口
                ShowScanDetailReport(scanResult);
            }
            catch (Exception ex)
            {
                AppendLog($"查看扫描详情失败: {ex.Message}");
                MessageBox.Show($"查看扫描详情失败: {ex.Message}", "错误", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        /// <summary>
        /// 显示扫描详情报告对话框
        /// </summary>
        private void ShowScanDetailReport(CompleteScanResult scanResult)
        {
            // 构建报告内容
            var sb = new System.Text.StringBuilder();
            sb.AppendLine($"═══ 扫描报告 ═══");
            sb.AppendLine($"扫描ID: {scanResult.ScanId}");
            sb.AppendLine($"目标: {scanResult.TargetIp}");
            sb.AppendLine($"扫描类型: {scanResult.ScanType}");
            sb.AppendLine($"扫描时间: {scanResult.ScanTime:yyyy-MM-dd HH:mm:ss}");
            sb.AppendLine($"扫描耗时: {scanResult.ScanDuration:F1}秒");
            sb.AppendLine($"开放端口: {scanResult.OpenPortsCount}");
            sb.AppendLine($"漏洞数量: {scanResult.VulnerabilitiesCount}");
            sb.AppendLine($"风险等级: {scanResult.RiskLevel}");
            sb.AppendLine();

            // 端口列表
            if (scanResult.PortScanResults != null && scanResult.PortScanResults.Count > 0)
            {
                sb.AppendLine($"─── 端口列表 ({scanResult.PortScanResults.Count} 个) ───");
                foreach (var port in scanResult.PortScanResults.Take(50))
                {
                    sb.AppendLine($"  {port.PortNumber,-6} {port.Status,-10} {port.Service ?? "-",-20} {port.ServiceVersion ?? "-"}");
                }
                if (scanResult.PortScanResults.Count > 50)
                    sb.AppendLine($"  ... 还有 {scanResult.PortScanResults.Count - 50} 个端口未显示");
                sb.AppendLine();
            }

            // 漏洞列表
            if (scanResult.VulnerabilityResults != null && scanResult.VulnerabilityResults.Count > 0)
            {
                sb.AppendLine($"─── 漏洞列表 ({scanResult.VulnerabilityResults.Count} 个) ───");
                foreach (var vuln in scanResult.VulnerabilityResults.Take(30))
                {
                    sb.AppendLine($"  [{vuln.RiskLevel}] {vuln.Name} ({vuln.CveId ?? "N/A"})");
                }
                if (scanResult.VulnerabilityResults.Count > 30)
                    sb.AppendLine($"  ... 还有 {scanResult.VulnerabilityResults.Count - 30} 个漏洞未显示");
                sb.AppendLine();
            }

            // 显示在对话框中
            var scrollViewer = new ScrollViewer
            {
                Margin = new Thickness(0, 0, 0, 10),
                Content = new TextBlock
                {
                    Text = sb.ToString(),
                    TextWrapping = TextWrapping.Wrap,
                    Foreground = Brushes.White,
                    FontSize = 13,
                    LineHeight = 20
                }
            };
            Grid.SetRow(scrollViewer, 0);

            var copyBtn = new Button
            {
                Content = "📋 复制报告",
                Width = 100,
                Height = 32,
                Margin = new Thickness(0, 0, 10, 0),
                Cursor = Cursors.Hand
            };
            copyBtn.Click += (s, args) =>
            {
                try
                {
                    Clipboard.SetText(sb.ToString());
                    MessageBox.Show("报告内容已复制到剪贴板", "复制成功", MessageBoxButton.OK, MessageBoxImage.Information);
                }
                catch (Exception ex)
                {
                    MessageBox.Show($"复制失败: {ex.Message}", "错误", MessageBoxButton.OK, MessageBoxImage.Error);
                }
            };

            var btnPanel = new StackPanel
            {
                Orientation = Orientation.Horizontal,
                HorizontalAlignment = HorizontalAlignment.Right
            };
            btnPanel.Children.Add(copyBtn);
            btnPanel.Children.Add(new Button
            {
                Content = "关闭",
                Width = 80,
                Height = 32,
                Cursor = Cursors.Hand,
                IsCancel = true
            });
            Grid.SetRow(btnPanel, 1);

            var grid = new Grid
            {
                Margin = new Thickness(15),
                RowDefinitions =
                {
                    new RowDefinition { Height = new GridLength(1, GridUnitType.Star) },
                    new RowDefinition { Height = GridLength.Auto }
                }
            };
            grid.Children.Add(scrollViewer);
            grid.Children.Add(btnPanel);

            var detailWindow = new Window
            {
                Title = $"扫描报告 - {scanResult.TargetIp}",
                Width = 750,
                Height = 600,
                WindowStartupLocation = WindowStartupLocation.CenterOwner,
                Owner = this,
                WindowStyle = WindowStyle.SingleBorderWindow,
                ResizeMode = ResizeMode.CanResize,
                Background = new SolidColorBrush(Color.FromRgb(0x2C, 0x3E, 0x50)),
                Foreground = Brushes.White,
                FontFamily = new System.Windows.Media.FontFamily("Consolas"),
                Content = grid
            };

            detailWindow.ShowDialog();
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

            // 排除 0 值项，避免生成退化的几何路径
            var nonZeroData = data.Where(kv => kv.Value > 0).ToDictionary(kv => kv.Key, kv => kv.Value);
            double total = nonZeroData.Values.Sum();
            if (total == 0)
            {
                // 全 0 时画一个灰色圆
                var centerX = canvas.Width / 2;
                var centerY = canvas.Height / 2;
                double radius = Math.Min(centerX, centerY) - 10;
                if (radius < 1)
                {
                    // 退路：canvas 还未完成布局时使用合理默认值
                    centerX = 100; centerY = 100; radius = 90;
                }
                var ellipse = new System.Windows.Shapes.Ellipse
                {
                    Width = radius * 2,
                    Height = radius * 2,
                    Fill = new SolidColorBrush(Color.FromRgb(0xEC, 0xF0, 0xF1))
                };
                Canvas.SetLeft(ellipse, centerX - radius);
                Canvas.SetTop(ellipse, centerY - radius);
                canvas.Children.Add(ellipse);
                return;
            }

            double centerX2 = canvas.Width / 2;
            double centerY2 = canvas.Height / 2;
            double radius2 = Math.Min(centerX2, centerY2) - 10;
            if (radius2 < 1)
            {
                centerX2 = 100; centerY2 = 100; radius2 = 90;
            }

            double startAngle = -90;
            foreach (var item in nonZeroData)
            {
                double sweepAngle = (item.Value / total) * 360;
                if (sweepAngle <= 0) continue;

                var geometry = new StreamGeometry();
                using (var ctx = geometry.Open())
                {
                    ctx.BeginFigure(new Point(centerX2, centerY2), true, true);
                    double startRad = startAngle * Math.PI / 180;
                    double endRad = (startAngle + sweepAngle) * Math.PI / 180;
                    Point startPoint = new Point(centerX2 + radius2 * Math.Cos(startRad), centerY2 + radius2 * Math.Sin(startRad));
                    Point endPoint = new Point(centerX2 + radius2 * Math.Cos(endRad), centerY2 + radius2 * Math.Sin(endRad));
                    ctx.LineTo(startPoint, true, false);
                    ctx.ArcTo(endPoint, new Size(radius2, radius2), 0, sweepAngle > 180, SweepDirection.Clockwise, true, false);
                }
                geometry.Freeze();

                var path = new System.Windows.Shapes.Path
                {
                    Fill = new SolidColorBrush(colors.ContainsKey(item.Key) ? colors[item.Key] : Color.FromRgb(0x95, 0xA5, 0xA6)),
                    Data = geometry
                };
                canvas.Children.Add(path);

                startAngle += sweepAngle;
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
                // 强制切到数据可视化 Tab，避免在其他 Tab 截图到无关内容
                if (ExpertTabControl?.SelectedIndex != 8)
                {
                    AppendLog("ℹ️ 已自动切换到「数据可视化」Tab");
                    ExpertTabControl.SelectedIndex = 8;
                    // 切 Tab 后立刻强制布局，避免 ActualWidth/Height 仍为 0
                    ExpertTabControl.UpdateLayout();
                    Dispatcher.Invoke(() => { }, DispatcherPriority.Loaded);
                }

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

                if (dialog.ShowDialog() != true) return;

                // 强制完成一次布局，确保 ActualWidth/ActualHeight 是最新的
                panel.UpdateLayout();
                double width = panel.ActualWidth;
                double height = panel.ActualHeight;
                if (width < 1 || height < 1)
                {
                    // 退路：使用 ScrollViewer 视口尺寸
                    width = tabItem.ActualWidth > 0 ? tabItem.ActualWidth : 1100;
                    height = tabItem.ActualHeight > 0 ? tabItem.ActualHeight : 800;
                }

                var renderBitmap = new RenderTargetBitmap(
                    (int)width,
                    (int)height,
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
                if (string.IsNullOrWhiteSpace(input))
                {
                    MessageBox.Show("目标列表为空，无需去重", "提示", MessageBoxButton.OK, MessageBoxImage.Information);
                    return;
                }

                var lines = input.Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries)
                                 .Select(l => l.Trim())
                                 .Where(l => !string.IsNullOrEmpty(l))
                                 .ToList();
                int originalCount = lines.Count;
                if (originalCount == 0)
                {
                    MessageBox.Show("目标列表为空，无需去重", "提示", MessageBoxButton.OK, MessageBoxImage.Information);
                    return;
                }

                var distinctLines = lines.Distinct(StringComparer.OrdinalIgnoreCase).ToList();
                int newCount = distinctLines.Count;

                TargetInputTextBox.Text = string.Join(Environment.NewLine, distinctLines);
                ParseTargetCount();
                UpdateScanPlanPreview();

                if (originalCount == newCount)
                {
                    MessageBox.Show($"目标列表无重复项，共 {newCount} 条", "去重完成", MessageBoxButton.OK, MessageBoxImage.Information);
                }
                else
                {
                    MessageBox.Show($"去重完成：原 {originalCount} 条 → 现 {newCount} 条（已移除 {originalCount - newCount} 条重复）", "去重完成", MessageBoxButton.OK, MessageBoxImage.Information);
                }
                AppendLog($"目标去重：{originalCount} → {newCount}");
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
                var input = TargetInputTextBox.Text ?? "";
                var lines = input.Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries)
                                 .Select(l => l.Trim())
                                 .Where(l => !string.IsNullOrEmpty(l))
                                 .ToList();

                if (lines.Count == 0)
                {
                    MessageBox.Show("目标列表为空，无可导出内容", "提示", MessageBoxButton.OK, MessageBoxImage.Information);
                    return;
                }

                var dialog = new SaveFileDialog
                {
                    Filter = "文本文件 (*.txt)|*.txt",
                    FileName = $"targets_{DateTime.Now:yyyyMMdd_HHmmss}.txt",
                    Title = "导出目标列表"
                };

                if (dialog.ShowDialog() == true)
                {
                    File.WriteAllText(dialog.FileName, string.Join(Environment.NewLine, lines), Encoding.UTF8);
                    MessageBox.Show($"已导出 {lines.Count} 个目标到:\n{dialog.FileName}", "导出成功", MessageBoxButton.OK, MessageBoxImage.Information);
                    AppendLog($"导出 {lines.Count} 个目标到 {dialog.FileName}");
                }
            }
            catch (Exception ex)
            {
                MessageBox.Show($"导出失败: {ex.Message}", "错误", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        /// <summary>
        /// 预览所有解析后的目标 - 用于在扫描前确认目标数量和具体内容
        /// </summary>
        private void PreviewTargetsButton_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                var config = CollectConfig();
                var targets = ResolveTargets(config);
                var ports = ResolvePorts(config);

                if (targets.Count == 0)
                {
                    MessageBox.Show("当前未解析到任何目标，请检查输入。", "无目标", MessageBoxButton.OK, MessageBoxImage.Information);
                    return;
                }

                var preview = new Window
                {
                    Title = $"目标预览 - 共 {targets.Count} 个",
                    Width = 600,
                    Height = 500,
                    WindowStartupLocation = WindowStartupLocation.CenterOwner,
                    Owner = this,
                    ResizeMode = ResizeMode.CanResize
                };
                var panel = new StackPanel { Margin = new Thickness(12) };
                panel.Children.Add(new TextBlock
                {
                    Text = $"📋 解析结果概览",
                    FontSize = 16,
                    FontWeight = FontWeights.Bold,
                    Margin = new Thickness(0, 0, 0, 8)
                });
                panel.Children.Add(new TextBlock
                {
                    Text = $"目标类型: {GetTargetTypeDisplay(config.TargetType)} | " +
                           $"目标数量: {targets.Count} | " +
                           $"端口数量: {ports.Count} | " +
                           $"总扫描数: {targets.Count * ports.Count:N0}",
                    FontSize = 12,
                    Foreground = new SolidColorBrush(Color.FromRgb(0x7F, 0x8C, 0x8D)),
                    Margin = new Thickness(0, 0, 0, 8)
                });

                // 端口范围概览
                if (ports.Count > 0)
                {
                    var portPreview = ports.Count <= 10
                        ? string.Join(", ", ports.Take(10))
                        : $"{string.Join(", ", ports.Take(5))}, ... , {string.Join(", ", ports.TakeLast(5))}";
                    panel.Children.Add(new TextBlock
                    {
                        Text = $"端口列表: {portPreview}",
                        FontSize = 11,
                        Foreground = new SolidColorBrush(Color.FromRgb(0x34, 0x98, 0xDB)),
                        TextWrapping = TextWrapping.Wrap,
                        Margin = new Thickness(0, 0, 0, 8)
                    });
                }

                var targetsBox = new TextBox
                {
                    Text = string.Join(Environment.NewLine, targets),
                    IsReadOnly = true,
                    VerticalScrollBarVisibility = ScrollBarVisibility.Auto,
                    HorizontalScrollBarVisibility = ScrollBarVisibility.Auto,
                    FontFamily = new System.Windows.Media.FontFamily("Consolas"),
                    FontSize = 12,
                    Height = 320,
                    BorderBrush = new SolidColorBrush(Color.FromRgb(0xBD, 0xC3, 0xC7)),
                    BorderThickness = new Thickness(1)
                };
                panel.Children.Add(targetsBox);

                var btnPanel = new StackPanel
                {
                    Orientation = Orientation.Horizontal,
                    HorizontalAlignment = HorizontalAlignment.Right,
                    Margin = new Thickness(0, 10, 0, 0)
                };
                var copyBtn = new Button
                {
                    Content = "📋 复制全部",
                    Width = 100,
                    Height = 30,
                    Background = new SolidColorBrush(Color.FromRgb(0x34, 0x98, 0xDB)),
                    Foreground = Brushes.White,
                    BorderThickness = new Thickness(0),
                    Margin = new Thickness(5, 0, 0, 0)
                };
                copyBtn.Click += (_, __) =>
                {
                    SafeSetClipboard(targetsBox.Text);
                    AppendLog($"已复制 {targets.Count} 个目标到剪贴板");
                };
                var closeBtn = new Button
                {
                    Content = "关闭",
                    Width = 80,
                    Height = 30,
                    Margin = new Thickness(5, 0, 0, 0)
                };
                closeBtn.Click += (_, __) => preview.Close();
                btnPanel.Children.Add(copyBtn);
                btnPanel.Children.Add(closeBtn);
                panel.Children.Add(btnPanel);

                preview.Content = panel;
                preview.ShowDialog();
                AppendLog($"[目标预览] 显示 {targets.Count} 个解析后的目标");
            }
            catch (Exception ex)
            {
                MessageBox.Show($"预览失败: {ex.Message}", "错误", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        private string GetTargetTypeDisplay(string type)
        {
            return type switch
            {
                "Single" => "单个IP/域名",
                "Range" => "IP段范围",
                "CIDR" => "CIDR网段",
                "File" => "文件列表",
                "Regex" => "正则模式",
                _ => type ?? "未知"
            };
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
                "PostgreSQL" => 5432,
                "Redis" => 6379,
                "Telnet" => 23,
                "MongoDB" => 27017,
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

                // 根据插件返回的漏洞结果，提取真实凭证信息
                foreach (var v in wpResults)
                {
                    // 解析实际尝试的账号/密码（来自插件扫描时实际使用的凭证）
                    var creds = ExtractRealCredentials(v, service);
                    results.Add(new WeakPasswordResult
                    {
                        Username = creds.username,
                        Password = creds.password,
                        Service = service,
                        Target = target,
                        Port = port,
                        Vulnerability = v.Name
                    });
                }

                // 如果插件没有发现漏洞，添加一条"已检测但未发现"记录
                if (wpResults.Count == 0)
                {
                    results.Add(new WeakPasswordResult
                    {
                        Username = "(无)",
                        Password = "(无)",
                        Service = service,
                        Target = target,
                        Port = port,
                        Vulnerability = "未发现弱口令"
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
            WeakPasswordStatusTextBlock.Text = results.Count > 0 && results[0].Vulnerability != "未发现弱口令"
                ? $"状态：发现 {results.Count} 个弱口令漏洞"
                : "状态：未发现弱口令漏洞";
            StartWeakPasswordScanButton.IsEnabled = true;
            AppendLog($"[弱口令检测] {target}:{port} ({service}) - 共 {results.Count} 条结果");
        }

        /// <summary>
        /// 根据漏洞名称和描述提取插件实际尝试的凭证信息
        /// </summary>
        private (string username, string password) ExtractRealCredentials(NetSecurityScanner.Models.VulnerabilityResult v, string service)
        {
            // 防御性检查：v 为空时返回明确的占位说明，避免 NullReferenceException
            if (v == null)
            {
                return ("(未知)", "(无凭证)");
            }

            // 插件实际尝试的凭证（与 WeakPasswordPlugin 内部字典保持一致）
            // FTP 端口尝试 anonymous/anonymous@ 登录
            if (service == "FTP" && !string.IsNullOrEmpty(v.Name) && v.Name.Contains("匿名登录"))
            {
                return ("anonymous", "anonymous@");
            }
            // SSH Banner 探测 - 不涉及凭证尝试
            if (service == "SSH" && !string.IsNullOrEmpty(v.Name) && v.Name.Contains("SSH"))
            {
                return ("(Banner探测)", "(无凭证尝试)");
            }
            // Telnet 明文协议检测
            if (service == "Telnet")
            {
                return ("(协议特征)", "(明文传输)");
            }
            // MySQL 远程访问检测
            if (service == "MySQL" && !string.IsNullOrEmpty(v.Name) && v.Name.Contains("MySQL"))
            {
                return ("(未验证)", "(无凭证尝试)");
            }
            // Redis 未授权访问
            if (service == "Redis" && !string.IsNullOrEmpty(v.Name) && v.Name.Contains("未授权"))
            {
                return ("(空认证)", "(无密码)");
            }
            // MSSQL 探测 - 插件检测端口暴露情况
            if (service == "MSSQL" && !string.IsNullOrEmpty(v.Name) && v.Name.Contains("MSSQL"))
            {
                return ("(sa探测)", "(建议禁用sa)");
            }
            // PostgreSQL 探测
            if (service == "PostgreSQL" && !string.IsNullOrEmpty(v.Name) && v.Name.Contains("PostgreSQL"))
            {
                return ("(postgres)", "(建议强密码)");
            }
            // 默认情况
            return ("(探测)", "(无凭证)");
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
            if (paths == null || paths.Count == 0)
            {
                DirScanStatusTextBlock.Text = "状态：字典为空，无法扫描";
                MessageBox.Show($"所选字典「{dictName}」没有可用路径，请选择其他字典。", "字典为空", MessageBoxButton.OK, MessageBoxImage.Warning);
                return;
            }

            DirScanStatusTextBlock.Text = $"状态：正在扫描 {url} ({paths.Count} 条路径, 并发20)...";
            StartDirScanButton.IsEnabled = false;
            var foundPaths = new List<string>();
            // 并发控制：SemaphoreSlim 限制同时连接数，避免打满目标服务器与本地句柄
            _dirScanCts?.Cancel();
            _dirScanCts = new CancellationTokenSource();
            var cts = _dirScanCts;
            var concurrencyLimit = 20;
            using var semaphore = new SemaphoreSlim(concurrencyLimit, concurrencyLimit);
            // 使用单实例 HttpClient 避免每次请求创建新实例造成的 socket 耗尽
            using var httpClient = new System.Net.Http.HttpClient(new System.Net.Http.HttpClientHandler
            {
                // 忽略 SSL 证书错误，便于扫描自签名 HTTPS 站点
                ServerCertificateCustomValidationCallback = (_, _, _, _) => true,
                MaxConnectionsPerServer = concurrencyLimit
            });
            httpClient.Timeout = TimeSpan.FromSeconds(8);
            httpClient.DefaultRequestHeaders.Add("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36");
            var baseUrl = url.TrimEnd('/');
            int checkedCount = 0;
            int total = paths.Count;
            // 进度更新节流，避免频繁刷新导致 UI 卡顿
            var progressLock = new object();
            var lastProgress = DateTime.MinValue;

            try
            {
                // 并发执行：每个路径一个 Task，通过 Semaphore 控制并发上限
                var tasks = paths.Select(async path =>
                {
                    await semaphore.WaitAsync(cts.Token);
                    if (cts.IsCancellationRequested) { semaphore.Release(); return; }
                    bool shouldUpdateProgress = false;
                    int localCount;
                    lock (progressLock)
                    {
                        checkedCount++;
                        localCount = checkedCount;
                        // 每 200ms 或全部完成时刷新一次进度
                        if ((DateTime.Now - lastProgress).TotalMilliseconds > 200 || localCount == total)
                        {
                            lastProgress = DateTime.Now;
                            shouldUpdateProgress = true;
                        }
                    }
                    // 注意：Dispatcher 调度移到 lock 外，避免并发任务在持锁状态下同步阻塞等待 UI 线程（死锁风险）
                    if (shouldUpdateProgress)
                    {
                        Dispatcher.BeginInvoke(new Action(() =>
                            DirScanStatusTextBlock.Text = $"状态：扫描中 {localCount}/{total}..."));
                    }
                    try
                    {
                        var testUrl = $"{baseUrl}/{path.TrimStart('/')}";
                        var response = await httpClient.GetAsync(testUrl, System.Net.Http.HttpCompletionOption.ResponseHeadersRead, cts.Token);
                        var code = (int)response.StatusCode;
                        // 2xx/3xx/401/403 视为路径存在（可能敏感）
                        if (code == 200 || code == 201 || code == 204 ||
                            code == 301 || code == 302 || code == 307 || code == 308 ||
                            code == 401 || code == 403 || code == 405)
                        {
                            lock (foundPaths)
                            {
                                foundPaths.Add($"[{code}] {testUrl}");
                            }
                        }
                        response.Dispose();
                    }
                    catch (OperationCanceledException) { }
                    catch { }
                    finally { semaphore.Release(); }
                }).ToArray();
                await Task.WhenAll(tasks);
            }
            catch (OperationCanceledException)
            {
                AppendLog("[目录扫描] 用户取消扫描");
            }
            catch (Exception ex)
            {
                DirScanStatusTextBlock.Text = $"状态：扫描失败 - {ex.Message}";
                StartDirScanButton.IsEnabled = true;
                return;
            }
            finally
            {
                _dirScanCts = null;
            }

            // 按状态码排序展示
            foundPaths = foundPaths.OrderBy(p => p).ToList();
            DirScanResultListBox.ItemsSource = foundPaths;
            DirScanStatusTextBlock.Text = foundPaths.Count > 0
                ? $"状态：发现 {foundPaths.Count} 个可访问路径"
                : "状态：未发现可访问路径";
            StartDirScanButton.IsEnabled = true;
            AppendLog($"[目录扫描] {url} ({dictName}) - 发现 {foundPaths.Count} 个路径");
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

            // 验证目标地址格式（IP 或域名）
            if (!System.Net.IPAddress.TryParse(target, out _) && !IsValidHostname(target))
            {
                var confirm = MessageBox.Show($"目标「{target}」不是有效的 IP 或域名，是否继续？", "格式提示", MessageBoxButton.YesNo, MessageBoxImage.Question);
                if (confirm != MessageBoxResult.Yes) return;
            }

            PocStatusTextBlock.Text = $"状态：正在验证 {target}...";
            StartPocVerifyButton.IsEnabled = false;

            var pocResults = new List<string>();
            int hitCount = 0; // 单独统计命中数，不包括说明性文字
            try
            {
                // 使用选中的 POC 插件验证；未选择时使用全部内置 POC
                var selectedPlugins = PocPluginListBox?.SelectedItems?.Cast<string>()
                    .Where(s => !string.IsNullOrEmpty(s))
                    .ToList() ?? new List<string>();
                bool useAll = selectedPlugins.Count == 0;

                // 常见端口与对应 POC 插件名（仅保留端口连通性 + 简易 Banner 验证）
                var portPocMap = new Dictionary<int, string>
                {
                    { 80, "HTTP Banner POC" },
                    { 443, "HTTPS Banner POC" },
                    { 22, "SSH Banner POC" },
                    { 21, "FTP Anonymous POC" },
                    { 3306, "MySQL Connect POC" },
                    { 6379, "Redis Unauthorized POC" },
                    { 8080, "Tomcat Default POC" },
                    { 8443, "HTTPS Alt POC" },
                    { 9200, "Elasticsearch POC" },
                    { 27017, "MongoDB Unauthorized POC" }
                };

                int checkedCount = 0;
                var portsToCheck = portPocMap.Keys.ToList();
                if (!useAll)
                {
                    // 根据用户选择过滤端口：使用 POC 名称的简化形式做包含匹配
                    // 例：用户选 "MySQL Connect POC" -> 关键字 "MySQL Connect" -> 命中 "MySQL Connect POC"
                    // 注：String.Replace(string, string, StringComparison) 仅在 .NET 7+ 可用，
                    // 项目目标框架为 net6.0-windows，此处手动实现不区分大小写替换
                    var keywords = selectedPlugins
                        .Select(p => p.ReplaceIgnoreCase("POC", "")
                                     .ReplaceIgnoreCase("PoC", "")
                                     .Trim())
                        .Where(k => !string.IsNullOrEmpty(k))
                        .ToList();

                    portsToCheck = portPocMap
                        .Where(kv => keywords.Any(kw => kv.Value.Contains(kw, StringComparison.OrdinalIgnoreCase)))
                        .Select(kv => kv.Key)
                        .ToList();

                    if (portsToCheck.Count == 0)
                    {
                        AppendLog("⚠️ 所选 POC 未匹配任何内置端口，将扫描全部内置端口");
                        portsToCheck = portPocMap.Keys.ToList();
                    }
                }

                if (portsToCheck.Count == 0)
                {
                    pocResults.Add("无可扫描的端口（POC 列表为空）");
                }
                else
                {
                    foreach (var port in portsToCheck)
                    {
                        if (checkedCount++ % 2 == 0)
                            PocStatusTextBlock.Text = $"状态：扫描中 {checkedCount}/{portsToCheck.Count}...";
                        try
                        {
                            using var client = new System.Net.Sockets.TcpClient();
                            var connectTask = client.ConnectAsync(target, port);
                            var timeoutTask = Task.Delay(2000);
                            if (await Task.WhenAny(connectTask, timeoutTask) == timeoutTask)
                                continue;

                            // 简单读取 Banner 验证服务
                            string banner = "";
                            try
                            {
                                client.ReceiveTimeout = 1500;
                                var buffer = new byte[128];
                                using var stream = client.GetStream();
                                int bytesRead = await stream.ReadAsync(buffer, 0, buffer.Length);
                                if (bytesRead > 0)
                                    banner = System.Text.Encoding.ASCII.GetString(buffer, 0, bytesRead).Trim();
                            }
                            catch { }

                            var pocName = portPocMap[port];
                            if (string.IsNullOrEmpty(banner))
                                pocResults.Add($"[命中] {target}:{port} - {pocName}（端口开放）");
                            else
                                pocResults.Add($"[命中] {target}:{port} - {pocName} - Banner: {banner.Split('\n')[0]}");
                            hitCount++;
                            client.Close();
                        }
                        catch { }
                    }
                }

                // 在结果区顶部插入摘要（在所有命中行之后追加总结行）
                if (hitCount > 0)
                {
                    pocResults.Add($"──────────────");
                    pocResults.Add($"汇总：目标 {target} 共发现 {hitCount} 个端口开放，建议对命中端口进行深度漏洞扫描。");
                }
                else
                {
                    pocResults.Add($"目标 {target} 未检测到常见服务端口开放（共检查 {portsToCheck.Count} 个端口）。");
                }
            }
            catch (Exception ex)
            {
                pocResults.Add($"POC验证失败: {ex.Message}");
            }

            PocResultTextBox.Text = string.Join("\n", pocResults);
            PocStatusTextBlock.Text = hitCount > 0
                ? $"状态：验证完成 - 命中 {hitCount} 个端口"
                : "状态：验证完成 - 未发现开放端口";
            StartPocVerifyButton.IsEnabled = true;
            AppendLog($"[POC验证] {target} - 命中 {hitCount} 个端口");
        }

        /// <summary>
        /// POC 插件列表 - 全选
        /// </summary>
        private void PocSelectAllButton_Click(object sender, RoutedEventArgs e)
        {
            if (PocPluginListBox == null) return;
            PocPluginListBox.SelectAll();
            AppendLog($"[POC] 已全选 {PocPluginListBox.SelectedItems.Count} 个插件");
        }

        /// <summary>
        /// POC 插件列表 - 全不选
        /// </summary>
        private void PocSelectNoneButton_Click(object sender, RoutedEventArgs e)
        {
            if (PocPluginListBox == null) return;
            PocPluginListBox.SelectedItems.Clear();
            AppendLog("[POC] 已清空所有选择（将使用全部内置 POC）");
        }

        /// <summary>
        /// POC 插件列表 - 反选
        /// </summary>
        private void PocSelectInvertButton_Click(object sender, RoutedEventArgs e)
        {
            if (PocPluginListBox == null || PocPluginListBox.Items.Count == 0) return;
            var originallySelected = PocPluginListBox.SelectedItems.Cast<object>().ToList();
            PocPluginListBox.SelectedItems.Clear();
            foreach (var item in PocPluginListBox.Items)
            {
                if (!originallySelected.Contains(item))
                    PocPluginListBox.SelectedItems.Add(item);
            }
            AppendLog($"[POC] 已反选，当前选中 {PocPluginListBox.SelectedItems.Count} 个插件");
        }

        /// <summary>
        /// 加载 POC 插件列表到专项工具 Tab 的 ListBox
        /// </summary>
        private void LoadPocPlugins()
        {
            try
            {
                if (PocPluginListBox == null) return;
                PocPluginListBox.Items.Clear();

                // 加载内置 POC 插件（与 StartPocVerifyButton_Click 中的端口映射保持一致）
                var builtInPocs = new List<string>
                {
                    "HTTP Banner POC",
                    "HTTPS Banner POC",
                    "SSH Banner POC",
                    "FTP Anonymous POC",
                    "MySQL Connect POC",
                    "Redis Unauthorized POC",
                    "Tomcat Default POC",
                    "HTTPS Alt POC",
                    "Elasticsearch POC",
                    "MongoDB Unauthorized POC"
                };

                // 尝试从 PluginOrchestrator 加载已注册的 POC 插件
                try
                {
                    var orchestrator = PluginOrchestrator.Instance;
                    if (orchestrator.IsInitialized)
                    {
                        var loadedPlugins = orchestrator.LoadedPlugins?.Values;
                        if (loadedPlugins != null)
                        {
                            // IVulnerabilityScannerPlugin 没有 Metadata 属性，使用 Name 字段匹配
                            var pocPluginNames = loadedPlugins
                                .Where(p => p != null &&
                                            (p.Name != null &&
                                             (p.Name.Contains("POC", StringComparison.OrdinalIgnoreCase) ||
                                              p.Name.Contains("PoC", StringComparison.OrdinalIgnoreCase))))
                                .Select(p => p.Name)
                                .Where(n => !string.IsNullOrEmpty(n))
                                .ToList();
                            foreach (var p in pocPluginNames)
                                if (!builtInPocs.Contains(p)) builtInPocs.Add(p);
                        }
                    }
                }
                catch { /* 静默失败，使用内置列表 */ }

                foreach (var p in builtInPocs)
                    PocPluginListBox.Items.Add(p);

                AppendLog($"已加载 {builtInPocs.Count} 个 POC 插件");
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"[ExpertModeWindow] 加载 POC 插件失败: {ex.Message}");
            }
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
                    // 国际主流 CMS
                    { "WordPress", new List<string> { "wp-content", "wp-includes", "wordpress", "wp-json", "xmlrpc.php" } },
                    { "Drupal", new List<string> { "drupal", "sites/all", "sites/default", "Drupal.settings" } },
                    { "Joomla", new List<string> { "joomla", "components/com_", "media/system/js", "/index.php?option=" } },
                    { "Magento", new List<string> { "magento", "skin/frontend", "Mage.Cookies", "Mage/Translate" } },
                    { "Shopify", new List<string> { "cdn.shopify.com", "shopify" } },
                    { "Ghost", new List<string> { "ghost", "ghost-head", "casper" } },
                    { "Typecho", new List<string> { "typecho", "typechoComments", "usr/themes" } },
                    // 国产 CMS
                    { "DedeCMS", new List<string> { "dede", "dedecms", "/templets/", "dede/login.php", "/plus/" } },
                    { "Discuz", new List<string> { "discuz", "forum.php", "uc_client", "uc_server", "portal.php" } },
                    { "PHPCMS", new List<string> { "phpcms", "phpsso", "caches/caches" } },
                    { "帝国CMS", new List<string> { "empirecms", "e/class", "e/data", "d/js" } },
                    { "织梦CMS", new List<string> { "dede", "/templets/default", "style/dedecms.css" } },
                    { "PHPOK", new List<string> { "phpok", "phpok\\control" } },
                    { "EduSoho", new List<string> { "edusoho", "assets/libs/echo" } },
                    { "MCMS", new List<string> { "mcms", "mdiy", "mcode" } },
                    // 框架 / 中间件
                    { "ThinkPHP", new List<string> { "thinkphp", "think\\", "/index.php/", "think\\trace" } },
                    { "Laravel", new List<string> { "laravel", "__laravel", "laravel_session" } },
                    { "Symfony", new List<string> { "symfony", "Symfony\\", "symfony-logo" } },
                    { "CodeIgniter", new List<string> { "codeigniter", "ci_session", "welcome.php" } },
                    { "Yii", new List<string> { "yii", "yii\\", "baseUrl" } },
                    { "Django", new List<string> { "django", "csrfmiddlewaretoken", "csrftoken" } },
                    { "Flask", new List<string> { "flask", "werkzeug" } },
                    { "Express", new List<string> { "x-powered-by", "express", "csrf-token" } },
                    { "Spring Boot", new List<string> { "whitelabel error", "spring", "actuator", "X-Application-Context" } },
                    { "Struts", new List<string> { "struts", "struts2", "org.apache.struts2" } },
                    // Web 服务器 / 中间件
                    { "Tomcat", new List<string> { "tomcat", "coyote", "jsp", "org.apache.jsp" } },
                    { "Nginx", new List<string> { "nginx" } },
                    { "Apache", new List<string> { "apache", "mod_jk" } },
                    { "IIS", new List<string> { "iis", "microsoft-iis", "x-aspnet-version", "x-powered-by: asp.net" } },
                    { "Jetty", new List<string> { "jetty" } },
                    // 容器 / 云
                    { "Docker", new List<string> { "docker", "docker swarm" } },
                    { "Kubernetes", new List<string> { "kubernetes", "k8s" } }
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
                // 基础入口
                "admin", "login", "index.php", "index.html", "index.asp", "index.aspx", "index.jsp", "index.do",
                "robots.txt", "sitemap.xml", "sitemap.txt", "crossdomain.xml", "clientaccesspolicy.xml",
                // 敏感文件 / 配置泄露
                ".git", ".git/config", ".git/HEAD", ".svn", ".svn/entries", ".env", ".env.local", ".env.production",
                ".htaccess", "web.config", "Web.config", "config.php", "config.ini", "config.json", "config.yml",
                "configuration.php", "wp-config.php", "database.yml", "settings.php", "settings.json",
                "package.json", "composer.json", "composer.lock", "yarn.lock", "package-lock.json",
                "Dockerfile", "docker-compose.yml", "docker-compose.yaml", ".dockerignore",
                "credentials", "secrets", "secret.json", "password.txt", "passwords.txt", "creds.txt",
                // 备份 / 压缩包
                "backup", "backup.zip", "backup.tar.gz", "backup.rar", "backup.sql", "backup.tgz",
                "db.sql", "dump.sql", "data.sql", "database.sql", "db.zip",
                "www.zip", "web.zip", "site.zip", "html.zip", "1.zip", "1.tar.gz",
                ".bak", "index.php.bak", "config.php.bak", "web.config.bak",
                // 管理后台
                "admin.php", "admin.html", "admin/index", "admin/login", "admincp", "admincp.php",
                "manage", "manage.php", "manager", "manager.php", "panel", "cpanel",
                "wp-admin", "wp-login.php", "wp-config.php", "wp-content", "wp-includes",
                "administrator", "administrator/index.php", "admin1.php", "admin2.php", "yanc",
                // PHP / 信息泄露
                "phpmyadmin", "phpMyAdmin", "pma", "pma/index.php", "mysqladmin",
                "phpinfo.php", "info.php", "test.php", "php.php", "info.html",
                "console", "shell", "shell.php", "c99.php", "c100.php", "r57.php",
                // 应用框架 / 调试入口
                "dashboard", "system", "api", "api-docs", "swagger", "swagger-ui", "swagger-ui.html", "swagger.json",
                "actuator", "actuator/health", "actuator/env", "actuator/info", "actuator/mappings", "actuator/beans",
                "actuator/loggers", "actuator/heapdump", "actuator/threaddump", "actuator/configprops",
                "h2-console", "trace", "jolokia", "metrics", "env",
                // 上传 / 静态资源
                "upload", "uploads", "upload.php", "upload.jsp", "files", "file", "download",
                "images", "img", "css", "js", "lib", "static", "assets", "public", "private",
                // 数据 / 日志 / 临时
                "data", "db", "database", "sql", "log", "logs", "log.txt", "error.log", "access.log",
                "temp", "tmp", "cache", "tmp.php", "debug.log", "app.log",
                // 文档
                "docs", "doc", "help", "readme", "readme.txt", "readme.md", "README.md",
                "license", "changelog", "version", "VERSION", "status", "health",
                // 容器 / 依赖路径
                "vendor", "node_modules", "node_modules/.env", "bower_components",
                // Java / 容器路径
                "WEB-INF", "WEB-INF/web.xml", "META-INF", "META-INF/MANIFEST.MF",
                "cgi-bin", "scripts", "bin", "include", "includes", "templates",
                // .NET / 部署路径
                "bin", "obj", "App_Data", "App_Code", "App_Browsers",
                // 其他常见目录
                "old", "new", "test", "tests", "testing", "demo", "examples",
                "install", "setup", "setup.php", "install.php", "install/",
                "search", "user", "users", "account", "accounts", "profile",
                "cart", "order", "orders", "checkout", "payment", "pay",
                "register", "signup", "signin", "login.php", "login.html", "login.jsp"
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

        #region 报告设置与 DOCX 导出

        private static string _reportTitle = "专家模式扫描报告";
        private static string _reportCompany = "";
        private static string _reportAuthor = "";
        private static string _reportDescription = "";

        private void ReportSettingButton_Click(object sender, RoutedEventArgs e)
        {
            var dlg = new Window
            {
                Title = "报告设置",
                Width = 450,
                Height = 380,
                WindowStartupLocation = WindowStartupLocation.CenterOwner,
                Owner = this,
                ResizeMode = ResizeMode.NoResize,
                Background = new SolidColorBrush(Color.FromRgb(0xF5, 0xF7, 0xFA))
            };

            var panel = new StackPanel { Margin = new Thickness(20) };

            panel.Children.Add(new TextBlock
            {
                Text = "自定义报告信息",
                FontWeight = FontWeights.Bold,
                FontSize = 16,
                Foreground = new SolidColorBrush(Color.FromRgb(0x2C, 0x3E, 0x50)),
                Margin = new Thickness(0, 0, 0, 15)
            });

            var titleBox = new TextBox { Text = _reportTitle, Height = 28, Margin = new Thickness(0, 0, 0, 10) };
            panel.Children.Add(new TextBlock { Text = "报告标题：", FontWeight = FontWeights.SemiBold, Foreground = new SolidColorBrush(Color.FromRgb(0x34, 0x49, 0x5E)) });
            panel.Children.Add(titleBox);

            var companyBox = new TextBox { Text = _reportCompany, Height = 28, Margin = new Thickness(0, 0, 0, 10) };
            panel.Children.Add(new TextBlock { Text = "公司名称：", FontWeight = FontWeights.SemiBold, Foreground = new SolidColorBrush(Color.FromRgb(0x34, 0x49, 0x5E)) });
            panel.Children.Add(companyBox);

            var authorBox = new TextBox { Text = _reportAuthor, Height = 28, Margin = new Thickness(0, 0, 0, 10) };
            panel.Children.Add(new TextBlock { Text = "扫描人员：", FontWeight = FontWeights.SemiBold, Foreground = new SolidColorBrush(Color.FromRgb(0x34, 0x49, 0x5E)) });
            panel.Children.Add(authorBox);

            var descBox = new TextBox { Text = _reportDescription, Height = 55, TextWrapping = TextWrapping.Wrap, AcceptsReturn = true, Margin = new Thickness(0, 0, 0, 15) };
            panel.Children.Add(new TextBlock { Text = "备注说明：", FontWeight = FontWeights.SemiBold, Foreground = new SolidColorBrush(Color.FromRgb(0x34, 0x49, 0x5E)) });
            panel.Children.Add(descBox);

            var btnPanel = new StackPanel { Orientation = Orientation.Horizontal, HorizontalAlignment = HorizontalAlignment.Right };
            var okBtn = new Button
            {
                Content = "✅ 确定",
                Width = 80,
                Height = 32,
                Background = new SolidColorBrush(Color.FromRgb(0x27, 0xAE, 0x60)),
                Foreground = Brushes.White,
                BorderThickness = new Thickness(0),
                Margin = new Thickness(0, 0, 10, 0)
            };
            okBtn.Click += (_, _) =>
            {
                _reportTitle = titleBox.Text.Trim();
                _reportCompany = companyBox.Text.Trim();
                _reportAuthor = authorBox.Text.Trim();
                _reportDescription = descBox.Text.Trim();
                dlg.DialogResult = true;
                dlg.Close();
                AppendLog($"[报告设置] 标题={_reportTitle}, 公司={_reportCompany}, 人员={_reportAuthor}");
            };
            var cancelBtn = new Button
            {
                Content = "取消",
                Width = 80,
                Height = 32,
                Background = new SolidColorBrush(Color.FromRgb(0x95, 0xA5, 0xA6)),
                Foreground = Brushes.White,
                BorderThickness = new Thickness(0)
            };
            cancelBtn.Click += (_, _) => { dlg.DialogResult = false; dlg.Close(); };
            btnPanel.Children.Add(okBtn);
            btnPanel.Children.Add(cancelBtn);
            panel.Children.Add(btnPanel);

            dlg.Content = panel;
            dlg.ShowDialog();
        }

        private void ExportDocxButton_Click(object sender, RoutedEventArgs e)
        {
            if (_allPortScanResults.Count == 0 && _allVulnResults.Count == 0)
            {
                MessageBox.Show("暂无扫描结果可导出", "提示", MessageBoxButton.OK, MessageBoxImage.Information);
                return;
            }

            var dialog = new SaveFileDialog
            {
                Filter = "Word文档 (*.docx)|*.docx",
                FileName = $"ExpertScan_Report_{DateTime.Now:yyyyMMdd_HHmmss}.docx",
                Title = "导出DOCX报告"
            };

            if (dialog.ShowDialog() != true) return;

            try
            {
                using var doc = Xceed.Words.NET.DocX.Create(dialog.FileName);

                var titlePara = doc.InsertParagraph(_reportTitle);
                titlePara.FontSize(22).Bold();
                titlePara.Alignment = Xceed.Document.NET.Alignment.center;

                var timePara = doc.InsertParagraph($"生成时间: {DateTime.Now:yyyy-MM-dd HH:mm:ss}");
                timePara.FontSize(10);
                timePara.Alignment = Xceed.Document.NET.Alignment.right;

                if (!string.IsNullOrEmpty(_reportCompany))
                {
                    var p = doc.InsertParagraph($"公司: {_reportCompany}");
                    p.FontSize(10);
                }
                if (!string.IsNullOrEmpty(_reportAuthor))
                {
                    var p = doc.InsertParagraph($"扫描人员: {_reportAuthor}");
                    p.FontSize(10);
                }
                if (!string.IsNullOrEmpty(_reportDescription))
                {
                    var p = doc.InsertParagraph($"备注: {_reportDescription}");
                    p.FontSize(10);
                }

                doc.InsertParagraph();
                var overviewHeader = doc.InsertParagraph("扫描概览");
                overviewHeader.FontSize(16).Bold();
                var overviewPara = doc.InsertParagraph($"扫描目标数: {_totalScannedTargets}  |  开放端口: {_totalOpenPorts}  |  发现漏洞: {_allVulnResults.Count}");
                overviewPara.FontSize(11);

                if (_allPortScanResults.Count > 0)
                {
                    doc.InsertParagraph();
                    var portHeader = doc.InsertParagraph("端口扫描结果");
                    portHeader.FontSize(14).Bold();

                    var portTable = doc.AddTable(_allPortScanResults.Count + 1, 5);
                    portTable.Rows[0].Cells[0].Paragraphs[0].Append("目标IP").Bold();
                    portTable.Rows[0].Cells[1].Paragraphs[0].Append("端口").Bold();
                    portTable.Rows[0].Cells[2].Paragraphs[0].Append("状态").Bold();
                    portTable.Rows[0].Cells[3].Paragraphs[0].Append("服务").Bold();
                    portTable.Rows[0].Cells[4].Paragraphs[0].Append("版本").Bold();

                    for (int i = 0; i < _allPortScanResults.Count; i++)
                    {
                        var r = _allPortScanResults[i];
                        portTable.Rows[i + 1].Cells[0].Paragraphs[0].Append(r.TargetIp ?? "");
                        portTable.Rows[i + 1].Cells[1].Paragraphs[0].Append(r.PortNumber.ToString());
                        portTable.Rows[i + 1].Cells[2].Paragraphs[0].Append(r.Status ?? "");
                        portTable.Rows[i + 1].Cells[3].Paragraphs[0].Append(r.Service ?? "");
                        portTable.Rows[i + 1].Cells[4].Paragraphs[0].Append(r.ServiceVersion ?? "");
                    }
                }

                if (_allVulnResults.Count > 0)
                {
                    doc.InsertParagraph();
                    var vulnHeader = doc.InsertParagraph("漏洞扫描结果");
                    vulnHeader.FontSize(14).Bold();

                    var vulnTable = doc.AddTable(_allVulnResults.Count + 1, 5);
                    vulnTable.Rows[0].Cells[0].Paragraphs[0].Append("漏洞名称").Bold();
                    vulnTable.Rows[0].Cells[1].Paragraphs[0].Append("CVE").Bold();
                    vulnTable.Rows[0].Cells[2].Paragraphs[0].Append("风险等级").Bold();
                    vulnTable.Rows[0].Cells[3].Paragraphs[0].Append("端口").Bold();
                    vulnTable.Rows[0].Cells[4].Paragraphs[0].Append("描述").Bold();

                    for (int i = 0; i < _allVulnResults.Count; i++)
                    {
                        var v = _allVulnResults[i];
                        vulnTable.Rows[i + 1].Cells[0].Paragraphs[0].Append(v.Name ?? "");
                        vulnTable.Rows[i + 1].Cells[1].Paragraphs[0].Append(v.CveId ?? "");
                        vulnTable.Rows[i + 1].Cells[2].Paragraphs[0].Append(v.RiskLevel ?? "");
                        vulnTable.Rows[i + 1].Cells[3].Paragraphs[0].Append(v.Port.ToString());
                        vulnTable.Rows[i + 1].Cells[4].Paragraphs[0].Append(v.Description ?? "");
                    }
                }

                doc.Save();
                MessageBox.Show($"DOCX报告已保存到:\n{dialog.FileName}", "导出成功", MessageBoxButton.OK, MessageBoxImage.Information);
                AppendLog($"[DOCX导出] 已保存到 {dialog.FileName}");
            }
            catch (Exception ex)
            {
                MessageBox.Show($"导出DOCX失败: {ex.Message}", "错误", MessageBoxButton.OK, MessageBoxImage.Error);
                AppendLog($"[DOCX导出] 失败: {ex.Message}");
            }
        }

        #endregion

        #region 目标分组管理

        private readonly Dictionary<string, List<string>> _targetGroups = new();
        private const string AllGroupsKey = "全部分组";

        private void AddGroupButton_Click(object sender, RoutedEventArgs e)
        {
            var input = Microsoft.VisualBasic.Interaction.InputBox(
                "请输入新分组名称：", "新建目标分组", "分组" + (_targetGroups.Count + 1));
            if (string.IsNullOrWhiteSpace(input)) return;

            var groupName = input.Trim();
            if (_targetGroups.ContainsKey(groupName))
            {
                MessageBox.Show($"分组「{groupName}」已存在", "提示", MessageBoxButton.OK, MessageBoxImage.Warning);
                return;
            }

            _targetGroups[groupName] = new List<string>();
            if (TargetGroupComboBox != null)
            {
                TargetGroupComboBox.Items.Add(new ComboBoxItem { Content = groupName, Tag = groupName });
            }
            UpdateGroupInfo();
            AppendLog($"[目标分组] 新建分组: {groupName}");
        }

        private void DeleteGroupButton_Click(object sender, RoutedEventArgs e)
        {
            if (TargetGroupComboBox == null) return;
            var selected = TargetGroupComboBox.SelectedItem as ComboBoxItem;
            var groupName = selected?.Tag?.ToString();
            if (string.IsNullOrEmpty(groupName) || groupName == "all")
            {
                MessageBox.Show("请选择一个具体的分组进行删除", "提示", MessageBoxButton.OK, MessageBoxImage.Warning);
                return;
            }

            var confirm = MessageBox.Show($"确定删除分组「{groupName}」？该分组下的目标将移回未分组。", "确认删除",
                MessageBoxButton.YesNo, MessageBoxImage.Question);
            if (confirm != MessageBoxResult.Yes) return;

            _targetGroups.Remove(groupName);
            TargetGroupComboBox.Items.Remove(selected);
            TargetGroupComboBox.SelectedIndex = 0;
            UpdateGroupInfo();
            AppendLog($"[目标分组] 删除分组: {groupName}");
        }

        private void AssignGroupButton_Click(object sender, RoutedEventArgs e)
        {
            if (TargetGroupComboBox == null) return;
            var selected = TargetGroupComboBox.SelectedItem as ComboBoxItem;
            var groupName = selected?.Tag?.ToString();

            if (string.IsNullOrEmpty(groupName) || groupName == "all")
            {
                MessageBox.Show("请先选择一个目标分组", "提示", MessageBoxButton.OK, MessageBoxImage.Warning);
                return;
            }

            var targets = ParseTargetList();
            if (targets.Count == 0)
            {
                MessageBox.Show("当前目标输入框为空，无法分配", "提示", MessageBoxButton.OK, MessageBoxImage.Warning);
                return;
            }

            if (!_targetGroups.ContainsKey(groupName))
                _targetGroups[groupName] = new List<string>();

            foreach (var t in targets)
            {
                if (!_targetGroups[groupName].Contains(t))
                    _targetGroups[groupName].Add(t);
            }

            UpdateGroupInfo();
            AppendLog($"[目标分组] 已将 {targets.Count} 个目标分配到「{groupName}」");
        }

        private void UpdateGroupInfo()
        {
            if (GroupInfoTextBlock == null || TargetGroupComboBox == null) return;
            var selected = TargetGroupComboBox.SelectedItem as ComboBoxItem;
            var groupName = selected?.Tag?.ToString() ?? "all";

            if (groupName == "all")
            {
                var totalTargets = _targetGroups.Values.SelectMany(v => v).Distinct().Count();
                GroupInfoTextBlock.Text = $"当前分组：全部分组 | 分组数：{_targetGroups.Count} | 总目标数：{totalTargets}";
            }
            else
            {
                var count = _targetGroups.TryGetValue(groupName, out var list) ? list.Count : 0;
                GroupInfoTextBlock.Text = $"当前分组：{groupName} | 目标数：{count}";
            }
        }

        private List<string> ParseTargetList()
        {
            var text = TargetInputTextBox?.Text?.Trim() ?? "";
            if (string.IsNullOrEmpty(text)) return new List<string>();

            return text.Split(new[] { '\n', '\r', ',', ';' }, StringSplitOptions.RemoveEmptyEntries)
                .Select(t => t.Trim())
                .Where(t => !string.IsNullOrEmpty(t))
                .Distinct()
                .ToList();
        }

        #endregion

        #region Ping 探测与源端口范围

        private bool IsPingProbeEnabled => PingProbeCheckBox?.IsChecked == true;

        private (int min, int max) GetSourcePortRange()
        {
            int min = 0, max = 0;
            if (SourcePortMinTextBox != null) int.TryParse(SourcePortMinTextBox.Text, out min);
            if (SourcePortMaxTextBox != null) int.TryParse(SourcePortMaxTextBox.Text, out max);
            if (min < 0) min = 0;
            if (max < 0) max = 0;
            if (max > 0 && min > max) (min, max) = (max, min);
            return (min, max);
        }

        #endregion

        #endregion
    }

    // ExpertScanConfiguration 已迁移至 NetSecurityScanner.Core/Models/ExpertScanConfiguration.cs，
    // 使 Core.Tests 能够引用它，从而为专家模式的纯逻辑建立测试覆盖。
    // 本文件顶部已有 using NetSecurityScanner.Core.Models，其余代码无需改动。
    // 序列化兼容性：预设 JSON 由 System.Text.Json 按属性名读写、不含类型名，
    // 因此跨命名空间迁移不影响既有预设文件的加载。

    public class WeakPasswordResult
    {
        public string Username { get; set; } = "";
        public string Password { get; set; } = "";
        public string Service { get; set; } = "";
        public string Target { get; set; } = "";
        public int Port { get; set; }
        public string Vulnerability { get; set; } = "";
    }

    /// <summary>
    /// 定时任务列表展示模型（强类型，避免 dynamic 绑定异常）
    /// </summary>
    public class ScheduledTaskViewModel
    {
        public string Id { get; set; } = "";
        public string Name { get; set; } = "";
        public string Target { get; set; } = "";
        public string CronExpression { get; set; } = "";
        public string Status { get; set; } = "";
        public DateTime? LastRunAt { get; set; }
        public int TotalRuns { get; set; }
    }

    /// <summary>
    /// .NET 6 兼容扩展：String.Replace(string, string, StringComparison) 在 .NET 7+ 才提供，
    /// 此扩展在 net6.0-windows 下提供不区分大小写替换能力
    /// </summary>
    internal static class StringExtensions
    {
        public static string ReplaceIgnoreCase(this string source, string oldValue, string newValue)
        {
            if (string.IsNullOrEmpty(source)) return source ?? string.Empty;
            if (string.IsNullOrEmpty(oldValue)) return source;
            newValue ??= string.Empty;

            var sb = new System.Text.StringBuilder(source.Length);
            int idx = 0;
            int next;
            while ((next = source.IndexOf(oldValue, idx, StringComparison.OrdinalIgnoreCase)) >= 0)
            {
                sb.Append(source, idx, next - idx);
                sb.Append(newValue);
                idx = next + oldValue.Length;
            }
            sb.Append(source, idx, source.Length - idx);
            return sb.ToString();
        }
    }
}