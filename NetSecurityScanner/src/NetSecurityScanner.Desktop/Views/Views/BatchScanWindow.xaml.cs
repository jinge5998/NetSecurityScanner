using Microsoft.Win32;
using NetSecurityScanner.Core.Models;
using NetSecurityScanner.Core.Services;
using NetSecurityScanner.Models;
using NetSecurityScanner.Services;
using NetSecurityScanner.Utils;
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Threading;

namespace NetSecurityScanner.Views
{
    public partial class BatchScanWindow : Window
    {
        // 深度扫描附加探测的常见 UDP 端口
        private static readonly int[] CommonUdpPorts = { 53, 67, 68, 69, 123, 137, 138, 161, 162, 445, 500, 514, 520, 623, 1900, 4500, 5353, 11211 };

        private readonly ScanHistoryService _historyService;
        private List<string> _parsedTargets;
        private ObservableCollection<IpScanItem> _ipItems;
        private CancellationTokenSource _cancellationTokenSource;
        private DispatcherTimer _elapsedTimer;
        private Stopwatch _totalStopwatch;
        private int _completedCount;
        private int _failedCount;
        private int _canceledCount;
        private int _totalVulns;
        private int _totalCritical;
        private readonly BatchScanSettingsService _settingsService = new();
        private DispatcherTimer _settingsSaveTimer;
        private bool _loadingSettings;
        private AsyncPauseController _pauseController;

        // 扫描引擎配置（A1/A2：模式联动 ScanProfileConfig，统一走 Rust 服务并自动回退内置）
        private RustScannerClient _rustClient;
        private ScanProfileConfig _profileConfig = ScanProfileConfigFactory.CreateStandard();
        private ScanConfiguration _scanConfig = ScanConfiguration.StandardConfig;
        private List<int> _scanPorts = new List<int>();
        private bool _isDeepMode;
        private int _currentRunCount;
        private ListCollectionView _ipItemsView;
        private readonly ConcurrentDictionary<string, List<PortScanResult>> _portResultsByIp = new(StringComparer.OrdinalIgnoreCase);

        public BatchScanWindow()
        {
            InitializeComponent();
            Title = $"批量扫描 v{VersionHelper.GetVersion()}";
            _historyService = new ScanHistoryService();
            _parsedTargets = new List<string>();
            _ipItems = new ObservableCollection<IpScanItem>();
            _totalStopwatch = new Stopwatch();

            IpListView.ItemsSource = _ipItems;
            _ipItemsView = (ListCollectionView)CollectionViewSource.GetDefaultView(_ipItems);
            _ipItemsView.Filter = IpItemFilter;
            IpListView.ItemsSource = _ipItemsView;

            ConcurrencySlider.ValueChanged += (s, e) => { ConcurrencyValueTextBlock.Text = ConcurrencySlider.Value.ToString("F0"); MarkSettingsDirty(); };
            TimeoutSlider.ValueChanged += (s, e) => { TimeoutValueTextBlock.Text = $"{TimeoutSlider.Value:F1}s"; MarkSettingsDirty(); };

            _settingsSaveTimer = new DispatcherTimer { Interval = TimeSpan.FromMilliseconds(500) };
            _settingsSaveTimer.Tick += (s, e) =>
            {
                _settingsSaveTimer.Stop();
                _settingsService.Save(CaptureSettingsFromUi());
            };

            _elapsedTimer = new DispatcherTimer { Interval = TimeSpan.FromSeconds(1) };
            _elapsedTimer.Tick += (s, e) =>
            {
                if (_totalStopwatch.IsRunning)
                {
                    ElapsedTimeTextBlock.Text = $"已用时间: {_totalStopwatch.Elapsed:hh\\:mm\\:ss}";
                    if (_completedCount > 0)
                    {
                        double avgMs = _totalStopwatch.Elapsed.TotalMilliseconds / _completedCount;
                        double remainingMs = avgMs * (_parsedTargets.Count - _completedCount - _failedCount);
                        var remaining = TimeSpan.FromMilliseconds(remainingMs);
                        RemainingTimeTextBlock.Text = $"预计剩余: {remaining:hh\\:mm\\:ss}";
                    }
                }
            };

            LoadAndApplySettings();
        }

        /// <summary>
        /// 配置变化时调用：500ms 防抖后统一落盘，避免拖动滑块时高频写盘。
        /// InitializeComponent 期间（计时器尚未创建）与配置回填期间不触发。
        /// </summary>
        private void MarkSettingsDirty()
        {
            if (_loadingSettings || _settingsSaveTimer == null) return;
            _settingsSaveTimer.Stop();
            _settingsSaveTimer.Start();
        }

        private BatchScanSettings CaptureSettingsFromUi() => new()
        {
            ScanModeTag = (BatchScanModeComboBox.SelectedItem as ComboBoxItem)?.Tag?.ToString() ?? "Standard",
            Concurrency = (int)ConcurrencySlider.Value,
            TimeoutSeconds = Math.Round(TimeoutSlider.Value, 1),
            TargetTypeTag = (BatchTargetTypeComboBox.SelectedItem as ComboBoxItem)?.Tag?.ToString() ?? "Range",
            StatusFilterTag = (StatusFilterComboBox.SelectedItem as ComboBoxItem)?.Tag?.ToString() ?? "All",
            ThreatFilterTag = (ThreatFilterComboBox.SelectedItem as ComboBoxItem)?.Tag?.ToString() ?? "All"
        };

        /// <summary>
        /// 启动时还原配置。先设下拉框（其 SelectionChanged 会联动超时默认值），后设滑块以保留已存值。
        /// </summary>
        private void LoadAndApplySettings()
        {
            var settings = _settingsService.Load();
            _loadingSettings = true;
            try
            {
                SelectComboItemByTag(BatchScanModeComboBox, settings.ScanModeTag);
                SelectComboItemByTag(BatchTargetTypeComboBox, settings.TargetTypeTag);
                SelectComboItemByTag(StatusFilterComboBox, settings.StatusFilterTag);
                SelectComboItemByTag(ThreatFilterComboBox, settings.ThreatFilterTag);
                ConcurrencySlider.Value = Math.Clamp(settings.Concurrency, (int)ConcurrencySlider.Minimum, (int)ConcurrencySlider.Maximum);
                TimeoutSlider.Value = Math.Clamp(settings.TimeoutSeconds, TimeoutSlider.Minimum, TimeoutSlider.Maximum);
            }
            finally
            {
                _loadingSettings = false;
            }
        }

        private static void SelectComboItemByTag(ComboBox combo, string tag)
        {
            foreach (var item in combo.Items)
            {
                if (item is ComboBoxItem cbi && string.Equals(cbi.Tag?.ToString(), tag, StringComparison.OrdinalIgnoreCase))
                {
                    combo.SelectedItem = cbi;
                    return;
                }
            }
            if (combo.Items.Count > 0) combo.SelectedIndex = 0;
        }

        private void BatchTargetTypeComboBox_SelectionChanged(object sender, SelectionChangedEventArgs e)
        {
            MarkSettingsDirty();
            if (BatchTargetTypeComboBox?.SelectedItem is ComboBoxItem selectedItem)
            {
                string tag = selectedItem.Tag?.ToString();
                BatchTargetHintTextBlock.Text = tag switch
                {
                    "Range" => "提示：输入 IP 段，如 192.168.1.1-192.168.1.254",
                    "CIDR" => "提示：输入 CIDR 格式，如 192.168.1.0/24",
                    "File" => "提示：点击'导入目标文件'按钮选择文件",
                    "List" => "提示：每行输入一个 IP 地址",
                    _ => "提示：输入目标值"
                };
                ImportFileButton.Visibility = tag == "File" ? Visibility.Visible : Visibility.Collapsed;
            }
        }

        /// <summary>
        /// 扫描模式切换时，同步探测超时滑块到对应预设默认值（Quick=0.1s, Standard=0.3s, Deep=0.5s）。
        /// </summary>
        private void BatchScanModeComboBox_SelectionChanged(object sender, SelectionChangedEventArgs e)
        {
            if (TimeoutSlider == null) return;
            MarkSettingsDirty();
            string tag = (BatchScanModeComboBox.SelectedItem as ComboBoxItem)?.Tag?.ToString() ?? "Standard";
            TimeoutSlider.Value = tag switch
            {
                "Lightning" => 0.1,
                "Deep" => 0.5,
                _ => 0.3
            };
        }

        private void ImportFileButton_Click(object sender, RoutedEventArgs e)
        {
            var dialog = new OpenFileDialog { Filter = "文本文件|*.txt|所有文件|*.*", Title = "选择目标列表文件" };
            if (dialog.ShowDialog() == true)
            {
                BatchTargetValueTextBox.Text = dialog.FileName;
            }
        }

        private void ParseTargetsButton_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                string targetValue = BatchTargetValueTextBox.Text.Trim();
                if (string.IsNullOrEmpty(targetValue))
                {
                    MessageBox.Show("请输入目标值", "提示", MessageBoxButton.OK, MessageBoxImage.Information);
                    return;
                }

                if (BatchTargetTypeComboBox.SelectedItem is not ComboBoxItem selectedItem) return;
                string tag = selectedItem.Tag?.ToString();
                TargetType targetType = tag switch
                {
                    "Range" => TargetType.Range,
                    "CIDR" => TargetType.CIDR,
                    "File" => TargetType.ListFile,
                    "List" => TargetType.Single,
                    _ => TargetType.Single
                };

                _parsedTargets = TargetParser.ParseTargets(targetValue, targetType);
                var outcome = BatchScanOrchestrator.ValidateTargets(_parsedTargets);
                if (outcome.Error != null)
                {
                    ParsedTargetCountTextBlock.Text = "已解析: 0 个目标";
                    ParsedTargetCountTextBlock.Foreground = System.Windows.Media.Brushes.Red;
                    MessageBox.Show(outcome.Error, "解析失败", MessageBoxButton.OK, MessageBoxImage.Warning);
                    return;
                }

                _parsedTargets = outcome.Targets;
                _ipItems.Clear();
                foreach (var ip in _parsedTargets)
                {
                    _ipItems.Add(new IpScanItem { IpAddress = ip, Status = "等待中", StatusIcon = "...", ProgressText = "0%", DurationText = "00:00" });
                }
                ParsedTargetCountTextBlock.Text = $"已解析: {_parsedTargets.Count} 个目标 (总计 {outcome.Total} / 去重 {outcome.Deduped} / 忽略 {outcome.Invalid})";
                ParsedTargetCountTextBlock.Foreground = System.Windows.Media.Brushes.Green;
                TotalTargetsTextBlock.Text = $"总目标: {_parsedTargets.Count}";
            }
            catch (Exception ex)
            {
                MessageBox.Show($"解析目标失败: {ex.Message}", "错误", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        private async void StartBatchScanButton_Click(object sender, RoutedEventArgs e)
        {
            await RunBatchScanAsync(_parsedTargets, rescanOnlyFailed: false);
        }

        /// <summary>
        /// 一键重扫所有失败目标：重置其状态后仅对失败项重新执行完整流水线。
        /// </summary>
        private async void RescanFailedButton_Click(object sender, RoutedEventArgs e)
        {
            var failedTargets = _ipItems.Where(i => i.Status == "失败").Select(i => i.IpAddress).ToList();
            if (!failedTargets.Any())
            {
                MessageBox.Show("当前没有失败的扫描目标", "提示", MessageBoxButton.OK, MessageBoxImage.Information);
                return;
            }

            foreach (var ip in failedTargets)
            {
                var item = _ipItems.FirstOrDefault(i => i.IpAddress.Equals(ip, StringComparison.OrdinalIgnoreCase));
                if (item != null)
                {
                    item.Status = "等待中";
                    item.StatusIcon = "...";
                    item.ProgressText = "0%";
                    item.DurationText = "00:00";
                    item.ErrorMessage = "";
                }
            }

            await RunBatchScanAsync(failedTargets, rescanOnlyFailed: true);
        }

        /// <summary>
        /// 批量扫描主流程（两阶段：阶段1 一次 Rust 多目标端口扫描；阶段2 按并发上限逐目标漏洞扫描）。
        /// </summary>
        /// <param name="targets">待扫描目标。</param>
        /// <param name="rescanOnlyFailed">true 表示仅重扫失败目标（保留已成功项结果）。</param>
        private async Task RunBatchScanAsync(List<string> targets, bool rescanOnlyFailed)
        {
            if (targets == null || !targets.Any())
            {
                MessageBox.Show("请先解析扫描目标", "提示", MessageBoxButton.OK, MessageBoxImage.Information);
                return;
            }

            BuildScanConfigFromUi();

            _completedCount = 0;
            _failedCount = 0;
            _totalVulns = 0;
            _totalCritical = 0;
            _currentRunCount = targets.Count;
            _portResultsByIp.Clear();
            _cancellationTokenSource = new CancellationTokenSource();
            var token = _cancellationTokenSource.Token;

            StartBatchScanButton.IsEnabled = false;
            RescanFailedButton.IsEnabled = false;
            StopBatchScanButton.IsEnabled = true;
            ExportBatchReportButton.IsEnabled = false;

            _totalStopwatch.Restart();
            _elapsedTimer.Start();

            var vulnScanner = new VulnerabilityScanner();

            try
            {
                await vulnScanner.InitializeAsync(token);
                await StartRustServiceAsync(token);

                // 阶段1：端口扫描（单次 Rust 调用覆盖全部目标，结果流式回填）
                BatchScanStatusTextBlock.Text = $"阶段1/2: 端口扫描 ({_scanPorts.Count} 端口 × {targets.Count} 目标)...";
                await PortScanAllTargetsAsync(targets, token);

                // 阶段2：漏洞扫描（仅对有开放端口的目标，按并发上限执行）
                var targetsWithPorts = targets.Where(t => _portResultsByIp.TryGetValue(t, out var l) && l.Count > 0).ToList();
                BatchScanStatusTextBlock.Text = $"阶段2/2: 漏洞扫描 ({targetsWithPorts.Count} 个目标有开放端口)...";

                int concurrency = (int)ConcurrencySlider.Value;
                var semaphore = new SemaphoreSlim(concurrency);
                var tasks = targets.Select((ip, index) => ScanVulnerabilitiesForTargetAsync(ip, index, semaphore, token, vulnScanner)).ToList();
                await Task.WhenAll(tasks);
            }
            catch (OperationCanceledException) { }
            finally
            {
                StopRustService();
                _totalStopwatch.Stop();
                _elapsedTimer.Stop();

                StartBatchScanButton.IsEnabled = true;
                StopBatchScanButton.IsEnabled = false;
                RescanFailedButton.IsEnabled = _ipItems.Any(i => i.Status == "失败");
                ExportBatchReportButton.IsEnabled = true;

                BatchScanStatusTextBlock.Text = "扫描完成";
                ElapsedTimeTextBlock.Text = $"已用时间: {_totalStopwatch.Elapsed:hh\\:mm\\:ss}";
                RemainingTimeTextBlock.Text = "预计剩余: 00:00:00";

                MessageBox.Show(
                    $"批量扫描完成！\n\n总目标: {targets.Count}\n已完成: {_completedCount}\n失败: {_failedCount}\n总漏洞: {_totalVulns}\n严重漏洞: {_totalCritical}\n耗时: {_totalStopwatch.Elapsed:hh\\:mm\\:ss}",
                    "扫描完成", MessageBoxButton.OK, MessageBoxImage.Information);
            }
        }

        /// <summary>
        /// 根据 UI 选择构建扫描配置：扫描模式联动 ScanProfileConfig 与 ScanConfiguration 预设。
        /// </summary>
        private void BuildScanConfigFromUi()
        {
            string tag = (BatchScanModeComboBox.SelectedItem as ComboBoxItem)?.Tag?.ToString() ?? "Standard";
            _isDeepMode = tag == "Deep";

            _scanConfig = tag switch
            {
                "Lightning" => ScanConfiguration.LightningConfig,
                "Deep" => ScanConfiguration.DeepConfig,
                _ => ScanConfiguration.StandardConfig
            };

            _profileConfig = tag switch
            {
                "Lightning" => ScanProfileConfigFactory.CreateQuick(),
                "Deep" => ScanProfileConfigFactory.CreateDeep(),
                _ => ScanProfileConfigFactory.CreateStandard()
            };

            // UI 超时滑块（秒）覆盖单次探测超时
            int timeoutMs = Math.Clamp((int)(TimeoutSlider.Value * 1000), 50, 5000);
            _profileConfig.TimeoutMs = timeoutMs;
            _profileConfig.Normalize();

            // 闪电扫描使用预设的 Top 端口列表，其余按端口范围解析
            _scanPorts = tag == "Lightning" && _scanConfig.TargetPorts != null
                ? _scanConfig.TargetPorts.ToList()
                : ParsePortRange(_scanConfig.PortRange);
        }

        private static List<int> ParsePortRange(string range)
        {
            var ports = new List<int>();
            if (string.IsNullOrWhiteSpace(range)) return ports;

            foreach (var part in range.Split(','))
            {
                if (part.Contains('-'))
                {
                    var bounds = part.Split('-');
                    if (bounds.Length == 2 &&
                        int.TryParse(bounds[0].Trim(), out int start) &&
                        int.TryParse(bounds[1].Trim(), out int end) &&
                        start >= 1 && end <= 65535 && end >= start)
                    {
                        ports.AddRange(Enumerable.Range(start, end - start + 1));
                    }
                }
                else if (int.TryParse(part.Trim(), out int port) && port >= 1 && port <= 65535)
                {
                    ports.Add(port);
                }
            }
            return ports.Distinct().ToList();
        }

        /// <summary>
        /// 预启动 Rust 扫描服务（跨目标复用），失败时静默降级到内置扫描器。
        /// </summary>
        private async Task StartRustServiceAsync(CancellationToken token)
        {
            _rustClient = new RustScannerClient();
            _rustClient.OnResultReceived += RustClient_OnResultReceived;
            _rustClient.OnProgressChanged += RustClient_OnProgressChanged;

            try
            {
                var exe = RustScannerClient.FindRustScannerExecutable();
                if (exe != null)
                {
                    var started = await _rustClient.StartServiceAsync(
                        exe,
                        _profileConfig.TcpConcurrency,
                        _profileConfig.TimeoutMs,
                        _profileConfig.UdpTimeoutMs > 0 ? _profileConfig.UdpTimeoutMs : 500);
                    if (started)
                    {
                        await _rustClient.ConnectAsync();
                    }
                }
            }
            catch (Exception)
            {
                // 启动失败不阻断：ScanPortsAsync 内部会自动回退到内置扫描器
            }
        }

        private void StopRustService()
        {
            try
            {
                if (_rustClient != null)
                {
                    _rustClient.OnResultReceived -= RustClient_OnResultReceived;
                    _rustClient.OnProgressChanged -= RustClient_OnProgressChanged;
                    _rustClient.StopService();
                    _rustClient.Dispose();
                }
            }
            catch { }
            _rustClient = null;
        }

        /// <summary>
        /// 阶段1：一次调用扫描全部目标的 TCP 端口；深度模式追加常见 UDP 端口探测。
        /// </summary>
        private async Task PortScanAllTargetsAsync(List<string> targets, CancellationToken token)
        {
            foreach (var ip in targets)
            {
                SetItemStatus(ip, "端口扫描中", "-->");
            }

            await _rustClient.ScanPortsAsync(
                targets,
                _scanPorts,
                "tcp",
                _profileConfig.TcpConcurrency,
                _profileConfig.TimeoutMs,
                500,
                detectService: _profileConfig.EnableServiceDetection,
                includeClosed: false,
                cancellationToken: token,
                profileConfig: _profileConfig);

            if (_isDeepMode && !token.IsCancellationRequested)
            {
                BatchScanStatusTextBlock.Text = "阶段1/2: UDP 常见端口探测...";
                await _rustClient.ScanPortsAsync(
                    targets,
                    CommonUdpPorts.ToList(),
                    "udp",
                    _profileConfig.UdpConcurrency,
                    _profileConfig.TimeoutMs,
                    _profileConfig.UdpTimeoutMs > 0 ? _profileConfig.UdpTimeoutMs : 1500,
                    detectService: false,
                    includeClosed: false,
                    cancellationToken: token,
                    profileConfig: _profileConfig);
            }
        }

        private void RustClient_OnResultReceived(object sender, RustPortResult result)
        {
            if (result == null || string.IsNullOrEmpty(result.TargetIp)) return;

            var mapped = new PortScanResult
            {
                TargetIp = result.TargetIp,
                PortNumber = result.Port,
                Status = "开放",
                Service = string.IsNullOrEmpty(result.Service) ? (result.Protocol == "UDP" ? "UDP" : "Unknown") : result.Service,
                ServiceVersion = !string.IsNullOrEmpty(result.Version) ? result.Version : result.Banner ?? "",
                ScanDurationMs = result.ScanTimeMs
            };

            var list = _portResultsByIp.GetOrAdd(result.TargetIp, _ => new List<PortScanResult>());
            lock (list)
            {
                // Rust 与回退路径均只返回开放端口；去重防止 TCP/UDP 同端口重复计数
                if (!list.Any(p => p.PortNumber == mapped.PortNumber && p.Service == mapped.Service))
                {
                    list.Add(mapped);
                }
            }

            Dispatcher.BeginInvoke(() =>
            {
                var item = _ipItems.FirstOrDefault(i => i.IpAddress.Equals(result.TargetIp, StringComparison.OrdinalIgnoreCase));
                if (item != null)
                {
                    item.OpenPortsCount = list.Count;
                }
            });
        }

        private void RustClient_OnProgressChanged(object sender, RustScanProgress progress)
        {
            if (progress == null) return;
            Dispatcher.BeginInvoke(() =>
            {
                if (!string.IsNullOrEmpty(progress.CurrentTarget))
                {
                    CurrentScanningTargetTextBlock.Text = $"当前: {progress.CurrentTarget}";
                    var item = _ipItems.FirstOrDefault(i => i.IpAddress.Equals(progress.CurrentTarget, StringComparison.OrdinalIgnoreCase));
                    if (item != null && progress.ProgressPercent > 0)
                    {
                        item.ProgressText = $"{progress.ProgressPercent}%";
                    }
                }
            });
        }

        /// <summary>
        /// 阶段2：对单个目标执行漏洞扫描（无开放端口的目标直接标记完成）。
        /// </summary>
        private async Task ScanVulnerabilitiesForTargetAsync(string ip, int index, SemaphoreSlim semaphore, CancellationToken token, VulnerabilityScanner vulnScanner)
        {
            await semaphore.WaitAsync(token);
            var itemStopwatch = new Stopwatch();

            try
            {
                _portResultsByIp.TryGetValue(ip, out var openPorts);
                openPorts = openPorts ?? new List<PortScanResult>();

                _ = Dispatcher.BeginInvoke(() =>
                {
                    _ipItems[index].Status = "漏洞扫描中";
                    _ipItems[index].StatusIcon = "-->";
                    BatchScanStatusTextBlock.Text = $"正在扫描 {ip}...";
                });

                itemStopwatch.Start();

                List<VulnerabilityResult> vulnResults = new List<VulnerabilityResult>();
                if (openPorts.Count > 0)
                {
                    vulnResults = (await vulnScanner.ScanVulnerabilitiesAsync(ip, openPorts, token)).ToList();
                }

                itemStopwatch.Stop();

                // A5: 持久化到扫描历史（每个目标独立上下文，失败不影响扫描结果）
                try
                {
                    await new ScanHistoryService().SaveScanResultAsync(ip, vulnResults, _scanConfig);
                }
                catch { }

                _ = Dispatcher.BeginInvoke(() =>
                {
                    _ipItems[index].Status = "已完成";
                    _ipItems[index].StatusIcon = "OK";
                    _ipItems[index].ProgressText = "100%";
                    _ipItems[index].DurationText = itemStopwatch.Elapsed.ToString(@"mm\:ss");
                    _ipItems[index].PortResults = openPorts;
                    _ipItems[index].VulnResults = vulnResults;
                    _ipItems[index].OpenPortsCount = openPorts.Count;
                    _ipItems[index].VulnCount = vulnResults.Count;
                    _ipItems[index].CriticalCount = vulnResults.Count(v => v.RiskLevel == "严重" || v.RiskLevel == "严重风险");
                    _ipItems[index].HighCount = vulnResults.Count(v => v.RiskLevel == "高" || v.RiskLevel == "高危" || v.RiskLevel == "高风险");

                    if (_ipItems[index].CriticalCount > 0)
                        _ipItems[index].ThreatLevel = "Critical";
                    else if (_ipItems[index].HighCount > 0)
                        _ipItems[index].ThreatLevel = "High";
                    else if (_ipItems[index].VulnCount > 0)
                        _ipItems[index].ThreatLevel = "Medium";
                    else if (_ipItems[index].OpenPortsCount > 0)
                        _ipItems[index].ThreatLevel = "Low";
                    else
                        _ipItems[index].ThreatLevel = "None";

                    Interlocked.Increment(ref _completedCount);
                    Interlocked.Add(ref _totalVulns, vulnResults.Count);
                    Interlocked.Add(ref _totalCritical, _ipItems[index].CriticalCount);

                    UpdateGlobalStatistics();
                    UpdateProgressBar();
                });
            }
            catch (OperationCanceledException) { throw; }
            catch (Exception ex)
            {
                itemStopwatch.Stop();
                _ = Dispatcher.BeginInvoke(() =>
                {
                    _ipItems[index].Status = "失败";
                    _ipItems[index].StatusIcon = "X";
                    _ipItems[index].ProgressText = "失败";
                    _ipItems[index].DurationText = itemStopwatch.Elapsed.ToString(@"mm\:ss");
                    _ipItems[index].ErrorMessage = ex.Message;

                    Interlocked.Increment(ref _failedCount);
                    UpdateGlobalStatistics();
                    UpdateProgressBar();
                });
            }
            finally
            {
                semaphore.Release();
            }
        }

        private void SetItemStatus(string ip, string status, string icon)
        {
            Dispatcher.BeginInvoke(() =>
            {
                var item = _ipItems.FirstOrDefault(i => i.IpAddress.Equals(ip, StringComparison.OrdinalIgnoreCase));
                if (item != null)
                {
                    item.Status = status;
                    item.StatusIcon = icon;
                }
            });
        }

        private void UpdateGlobalStatistics()
        {
            CompletedTargetsTextBlock.Text = $"已完成: {_completedCount}";
            FailedTargetsTextBlock.Text = $"失败: {_failedCount}";
            TotalVulnerabilitiesTextBlock.Text = $"总漏洞: {_totalVulns}";
            TotalCriticalTextBlock.Text = $"严重: {_totalCritical}";
        }

        private void UpdateProgressBar()
        {
            int total = _currentRunCount > 0 ? _currentRunCount : _parsedTargets.Count;
            int done = _completedCount + _failedCount;
            BatchScanProgressBar.Value = total > 0 ? (double)done / total * 100 : 0;
            BatchScanProgressTextBlock.Text = $"{done}/{total}";
        }

        private void IpListView_SelectionChanged(object sender, SelectionChangedEventArgs e)
        {
            if (IpListView.SelectedItem is IpScanItem item)
            {
                SelectedIpTextBlock.Text = item.IpAddress;
                SelectedIpStatusTextBlock.Text = $"状态: {item.Status}";
                SelectedIpPortsTextBlock.Text = $"开放端口: {item.OpenPortsCount}";
                SelectedIpVulnsTextBlock.Text = $"漏洞: {item.VulnCount}";

                PortResultDataGrid.ItemsSource = item.PortResults;
                VulnResultDataGrid.ItemsSource = item.VulnResults;
            }
        }

        /// <summary>
        /// IP 列表过滤器：状态（"扫描中"匹配端口/漏洞扫描中两种中间态）+ 威胁级别组合筛选。
        /// </summary>
        private bool IpItemFilter(object obj)
        {
            if (obj is not IpScanItem item) return false;

            string statusTag = (StatusFilterComboBox?.SelectedItem as ComboBoxItem)?.Tag?.ToString() ?? "All";
            string threatTag = (ThreatFilterComboBox?.SelectedItem as ComboBoxItem)?.Tag?.ToString() ?? "All";

            bool statusOk = statusTag switch
            {
                "All" => true,
                "扫描中" => item.Status.Contains("扫描中"),
                _ => item.Status == statusTag
            };
            bool threatOk = threatTag == "All" || item.ThreatLevel == threatTag;
            return statusOk && threatOk;
        }

        private void FilterComboBox_SelectionChanged(object sender, SelectionChangedEventArgs e)
        {
            _ipItemsView?.Refresh();
            MarkSettingsDirty();
        }

        private void CopyIpMenuItem_Click(object sender, RoutedEventArgs e)
        {
            if (IpListView.SelectedItem is IpScanItem item)
            {
                Clipboard.SetText(item.IpAddress);
                BatchScanStatusTextBlock.Text = $"已复制: {item.IpAddress}";
            }
        }

        private void RemoveTargetMenuItem_Click(object sender, RoutedEventArgs e)
        {
            if (IpListView.SelectedItem is not IpScanItem item) return;

            if (StopBatchScanButton.IsEnabled)
            {
                MessageBox.Show("扫描进行中，请先停止扫描再移除目标", "提示", MessageBoxButton.OK, MessageBoxImage.Information);
                return;
            }

            _ipItems.Remove(item);
            _parsedTargets.Remove(item.IpAddress);
            TotalTargetsTextBlock.Text = $"总目标: {_parsedTargets.Count}";
            ParsedTargetCountTextBlock.Text = $"已解析: {_parsedTargets.Count} 个目标";
        }

        private async void ExportSingleTargetMenuItem_Click(object sender, RoutedEventArgs e)
        {
            if (IpListView.SelectedItem is not IpScanItem item) return;
            if (item.Status != "已完成" && item.Status != "失败")
            {
                MessageBox.Show("该目标尚未完成扫描，暂无结果可导出", "提示", MessageBoxButton.OK, MessageBoxImage.Information);
                return;
            }

            var dialog = new SaveFileDialog
            {
                Filter = "HTML文件|*.html|CSV文件|*.csv",
                FileName = $"扫描报告_{item.IpAddress}_{DateTime.Now:yyyyMMdd_HHmmss}",
                Title = $"导出 {item.IpAddress} 的扫描报告"
            };
            if (dialog.ShowDialog() != true) return;

            try
            {
                string content = Path.GetExtension(dialog.FileName).Equals(".html", StringComparison.OrdinalIgnoreCase)
                    ? GenerateSingleTargetHtmlReport(item)
                    : GenerateSingleTargetCsvReport(item);
                await File.WriteAllTextAsync(dialog.FileName, content, Encoding.UTF8);
                MessageBox.Show($"报告已保存到:\n{dialog.FileName}", "导出成功", MessageBoxButton.OK, MessageBoxImage.Information);
            }
            catch (Exception ex)
            {
                MessageBox.Show($"导出失败: {ex.Message}", "错误", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        private static string GenerateSingleTargetHtmlReport(IpScanItem item)
        {
            string Esc(string s) => System.Net.WebUtility.HtmlEncode(s ?? "");
            var sb = new StringBuilder();
            sb.AppendLine("<!DOCTYPE html><html><head><meta charset='UTF-8'><title>扫描报告</title>");
            sb.AppendLine("<style>body{font-family:Arial,sans-serif;margin:40px;background:#f5f5f5}");
            sb.AppendLine(".header{background:#9B59B6;color:white;padding:24px;text-align:center;border-radius:8px}");
            sb.AppendLine("table{width:100%;background:white;border-collapse:collapse;margin:16px 0}");
            sb.AppendLine("th{background:#9B59B6;color:white;padding:10px;text-align:left}");
            sb.AppendLine("td{padding:8px;border-bottom:1px solid #ddd}</style></head><body>");
            sb.AppendLine($"<div class='header'><h1>目标扫描报告: {Esc(item.IpAddress)}</h1><p>生成时间: {DateTime.Now:yyyy-MM-dd HH:mm:ss}</p></div>");
            sb.AppendLine($"<p><strong>状态:</strong> {Esc(item.Status)} &nbsp; <strong>威胁级别:</strong> {Esc(item.ThreatLevel)} &nbsp; <strong>开放端口:</strong> {item.OpenPortsCount} &nbsp; <strong>漏洞:</strong> {item.VulnCount} (严重 {item.CriticalCount} / 高危 {item.HighCount}) &nbsp; <strong>耗时:</strong> {Esc(item.DurationText)}</p>");
            if (!string.IsNullOrEmpty(item.ErrorMessage))
            {
                sb.AppendLine($"<p><strong>错误信息:</strong> {Esc(item.ErrorMessage)}</p>");
            }

            sb.AppendLine("<h2>开放端口</h2><table><thead><tr><th>端口</th><th>服务</th><th>版本</th></tr></thead><tbody>");
            foreach (var p in item.PortResults)
            {
                sb.AppendLine($"<tr><td>{p.PortNumber}</td><td>{Esc(p.Service)}</td><td>{Esc(p.ServiceVersion)}</td></tr>");
            }
            sb.AppendLine("</tbody></table>");

            sb.AppendLine("<h2>漏洞列表</h2><table><thead><tr><th>漏洞名称</th><th>风险等级</th><th>端口</th><th>描述</th></tr></thead><tbody>");
            foreach (var v in item.VulnResults)
            {
                sb.AppendLine($"<tr><td>{Esc(v.Name)}</td><td>{Esc(v.RiskLevel)}</td><td>{v.Port}</td><td>{Esc(v.Description)}</td></tr>");
            }
            sb.AppendLine("</tbody></table>");
            sb.AppendLine("<p style='text-align:center;color:#7f8c8d;margin-top:32px'>由 NetSecurityScanner 生成</p></body></html>");
            return sb.ToString();
        }

        private static string GenerateSingleTargetCsvReport(IpScanItem item)
        {
            var sb = new StringBuilder();
            sb.AppendLine("IP地址,状态,威胁级别,开放端口数,漏洞数,严重,高危,扫描时长,错误信息");
            sb.AppendLine($"{item.IpAddress},{item.Status},{item.ThreatLevel},{item.OpenPortsCount},{item.VulnCount},{item.CriticalCount},{item.HighCount},{item.DurationText},{item.ErrorMessage}");
            sb.AppendLine();
            sb.AppendLine("端口,服务,版本");
            foreach (var p in item.PortResults)
            {
                sb.AppendLine($"{p.PortNumber},{p.Service},{p.ServiceVersion}");
            }
            sb.AppendLine();
            sb.AppendLine("漏洞名称,风险等级,端口,描述");
            foreach (var v in item.VulnResults)
            {
                sb.AppendLine($"\"{v.Name}\",{v.RiskLevel},{v.Port},\"{v.Description}\"");
            }
            return sb.ToString();
        }

        private void StopBatchScanButton_Click(object sender, RoutedEventArgs e)
        {
            _cancellationTokenSource?.Cancel();
            BatchScanStatusTextBlock.Text = "正在停止...";
        }

        private void PauseBatchScanButton_Click(object sender, RoutedEventArgs e)
        {
        }

        private void ResumeBatchScanButton_Click(object sender, RoutedEventArgs e)
        {
        }

        private void RescanCategoryMenuItem_SubmenuOpened(object sender, RoutedEventArgs e)
        {
        }

        private async void ExportBatchReportButton_Click(object sender, RoutedEventArgs e)
        {
            await ExportBatchReportAsync();
        }

        private async Task ExportBatchReportAsync()
        {
            var dialog = new SaveFileDialog
            {
                Filter = "HTML文件|*.html|CSV文件|*.csv|JSON文件|*.json",
                FileName = $"批量扫描报告_{DateTime.Now:yyyyMMdd_HHmmss}",
                Title = "保存批量扫描报告"
            };

            if (dialog.ShowDialog() != true) return;

            try
            {
                string filePath = dialog.FileName;
                string extension = Path.GetExtension(filePath).ToLower();

                if (extension == ".html")
                {
                    var html = GenerateHtmlReport();
                    await File.WriteAllTextAsync(filePath, html);
                }
                else if (extension == ".json")
                {
                    var json = GenerateJsonReport();
                    await File.WriteAllTextAsync(filePath, json, new UTF8Encoding(false));
                }
                else
                {
                    var csv = GenerateCsvReport();
                    // 带 BOM 的 UTF-8，保证 Excel 打开中文不乱码
                    await File.WriteAllTextAsync(filePath, csv, new UTF8Encoding(true));
                }

                MessageBox.Show($"报告已保存到:\n{filePath}", "报告生成成功", MessageBoxButton.OK, MessageBoxImage.Information);
            }
            catch (Exception ex)
            {
                MessageBox.Show($"生成报告失败: {ex.Message}", "错误", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        private string GenerateHtmlReport()
        {
            var sb = new StringBuilder();
            sb.AppendLine("<!DOCTYPE html><html><head><meta charset='UTF-8'><title>批量扫描报告</title>");
            sb.AppendLine("<style>body{font-family:Arial,sans-serif;margin:40px;background:#f5f5f5}");
            sb.AppendLine(".header{background:linear-gradient(135deg,#9B59B6,#3498DB);color:white;padding:30px;text-align:center;border-radius:8px}");
            sb.AppendLine(".summary{background:white;padding:20px;margin:20px 0;border-radius:8px;box-shadow:0 2px 4px rgba(0,0,0,0.1)}");
            sb.AppendLine("table{width:100%;background:white;border-collapse:collapse;margin:20px 0}");
            sb.AppendLine("th{background:#9B59B6;color:white;padding:12px;text-align:left}");
            sb.AppendLine("td{padding:10px;border-bottom:1px solid #ddd}");
            sb.AppendLine(".critical{color:#e74c3c;font-weight:bold}.high{color:#e67e22;font-weight:bold}</style></head><body>");
            sb.AppendLine($"<div class='header'><h1>批量扫描报告</h1><p>生成时间: {DateTime.Now:yyyy-MM-dd HH:mm:ss}</p></div>");
            sb.AppendLine("<div class='summary'><h2>扫描概要</h2>");
            sb.AppendLine($"<p><strong>总目标数:</strong> {_parsedTargets.Count}</p>");
            sb.AppendLine($"<p><strong>已完成:</strong> {_completedCount}</p>");
            sb.AppendLine($"<p><strong>失败:</strong> {_failedCount}</p>");
            sb.AppendLine($"<p><strong>总漏洞数:</strong> {_totalVulns}</p>");
            sb.AppendLine($"<p><strong>严重漏洞:</strong> <span class='critical'>{_totalCritical}</span></p>");
            sb.AppendLine($"<p><strong>执行时长:</strong> {_totalStopwatch.Elapsed:hh\\:mm\\:ss}</p></div>");
            sb.AppendLine("<h2>详细结果</h2><table><thead><tr><th>IP地址</th><th>状态</th><th>开放端口</th><th>漏洞数</th><th>严重</th><th>高危</th><th>扫描时长</th></tr></thead><tbody>");

            foreach (var item in _ipItems)
            {
                sb.AppendLine($"<tr><td>{item.IpAddress}</td><td>{item.Status}</td><td>{item.OpenPortsCount}</td><td>{item.VulnCount}</td><td class='critical'>{item.CriticalCount}</td><td class='high'>{item.HighCount}</td><td>{item.DurationText}</td></tr>");
            }

            sb.AppendLine("</tbody></table>");

            foreach (var item in _ipItems.Where(i => i.VulnResults != null && i.VulnResults.Count > 0))
            {
                sb.AppendLine($"<h3>{item.IpAddress} 漏洞详情</h3><table><thead><tr><th>漏洞名称</th><th>风险等级</th><th>端口</th><th>描述</th></tr></thead><tbody>");
                foreach (var v in item.VulnResults)
                {
                    sb.AppendLine($"<tr><td>{v.Name}</td><td>{v.RiskLevel}</td><td>{v.Port}</td><td>{v.Description}</td></tr>");
                }
                sb.AppendLine("</tbody></table>");
            }

            sb.AppendLine($"<p style='text-align:center;color:#7f8c8d;margin-top:40px'>由 NetSecurityScanner 生成</p></body></html>");
            return sb.ToString();
        }

        /// <summary>
        /// 生成 JSON 格式批量扫描报告（含汇总与每目标端口/漏洞明细）。
        /// </summary>
        private string GenerateJsonReport()
        {
            var report = new
            {
                generatedAt = DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss"),
                scanMode = _scanConfig.Mode.ToString(),
                summary = new
                {
                    totalTargets = _parsedTargets.Count,
                    completed = _completedCount,
                    failed = _failedCount,
                    totalVulnerabilities = _totalVulns,
                    criticalVulnerabilities = _totalCritical,
                    duration = _totalStopwatch.Elapsed.ToString(@"hh\:mm\:ss")
                },
                targets = _ipItems.Select(item => new
                {
                    ip = item.IpAddress,
                    status = item.Status,
                    threatLevel = item.ThreatLevel,
                    openPortsCount = item.OpenPortsCount,
                    vulnerabilityCount = item.VulnCount,
                    criticalCount = item.CriticalCount,
                    highCount = item.HighCount,
                    scanDuration = item.DurationText,
                    errorMessage = item.ErrorMessage,
                    openPorts = item.PortResults.Select(p => new
                    {
                        port = p.PortNumber,
                        service = p.Service,
                        version = p.ServiceVersion
                    }),
                    vulnerabilities = item.VulnResults.Select(v => new
                    {
                        cveId = v.CveId,
                        name = v.Name,
                        riskLevel = v.RiskLevel,
                        port = v.Port,
                        service = v.Service,
                        description = v.Description,
                        solution = v.Solution
                    })
                })
            };

            return System.Text.Json.JsonSerializer.Serialize(report, new System.Text.Json.JsonSerializerOptions
            {
                WriteIndented = true,
                Encoder = System.Text.Encodings.Web.JavaScriptEncoder.UnsafeRelaxedJsonEscaping
            });
        }

        private string GenerateCsvReport()
        {
            var sb = new StringBuilder();
            sb.AppendLine("IP地址,状态,开放端口数,漏洞数,严重,高危,扫描时长,错误信息");
            foreach (var item in _ipItems)
            {
                sb.AppendLine($"{item.IpAddress},{item.Status},{item.OpenPortsCount},{item.VulnCount},{item.CriticalCount},{item.HighCount},{item.DurationText},{item.ErrorMessage}");
            }
            return sb.ToString();
        }

        private void CloseBatchWindowButton_Click(object sender, RoutedEventArgs e)
        {
            _cancellationTokenSource?.Cancel();
            Close();
        }

        protected override void OnClosing(System.ComponentModel.CancelEventArgs e)
        {
            _settingsSaveTimer.Stop();
            _settingsService.Save(CaptureSettingsFromUi());
            _pauseController?.Resume();
            _cancellationTokenSource?.Cancel();
            _elapsedTimer.Stop();
            base.OnClosing(e);
        }
    }

    public class IpScanItem : System.ComponentModel.INotifyPropertyChanged
    {
        private string _status = "等待中";
        private string _statusIcon = "...";
        private string _progressText = "0%";
        private string _durationText = "00:00";
        private int _openPortsCount;
        private int _vulnCount;
        private int _criticalCount;
        private int _highCount;
        private string _threatLevel = "None";
        private string _errorMessage = "";
        private BatchScanFailureCategory _failureCategory = BatchScanFailureCategory.None;
        private string _failureText = "";

        public string IpAddress { get; set; } = "";
        public string Status { get => _status; set { _status = value; OnPropertyChanged(nameof(Status)); } }
        public string StatusIcon { get => _statusIcon; set { _statusIcon = value; OnPropertyChanged(nameof(StatusIcon)); } }
        public string ProgressText { get => _progressText; set { _progressText = value; OnPropertyChanged(nameof(ProgressText)); } }
        public string DurationText { get => _durationText; set { _durationText = value; OnPropertyChanged(nameof(DurationText)); } }
        public int OpenPortsCount { get => _openPortsCount; set { _openPortsCount = value; OnPropertyChanged(nameof(OpenPortsCount)); } }
        public int VulnCount { get => _vulnCount; set { _vulnCount = value; OnPropertyChanged(nameof(VulnCount)); } }
        public int CriticalCount { get => _criticalCount; set { _criticalCount = value; OnPropertyChanged(nameof(CriticalCount)); } }
        public int HighCount { get => _highCount; set { _highCount = value; OnPropertyChanged(nameof(HighCount)); } }
        public string ThreatLevel { get => _threatLevel; set { _threatLevel = value; OnPropertyChanged(nameof(ThreatLevel)); } }
        public string ErrorMessage { get => _errorMessage; set { _errorMessage = value; OnPropertyChanged(nameof(ErrorMessage)); } }
        public BatchScanFailureCategory FailureCategory { get => _failureCategory; set { _failureCategory = value; OnPropertyChanged(nameof(FailureCategory)); } }
        public string FailureText { get => _failureText; set { _failureText = value; OnPropertyChanged(nameof(FailureText)); } }
        public List<PortScanResult> PortResults { get; set; } = new List<PortScanResult>();
        public List<VulnerabilityResult> VulnResults { get; set; } = new List<VulnerabilityResult>();

        public event System.ComponentModel.PropertyChangedEventHandler PropertyChanged;
        private void OnPropertyChanged(string name) =>
            PropertyChanged?.Invoke(this, new System.ComponentModel.PropertyChangedEventArgs(name));
    }

    public class ThreatLevelToBrushConverter : System.Windows.Data.IValueConverter
    {
        public object Convert(object value, Type targetType, object parameter, System.Globalization.CultureInfo culture)
        {
            if (value is string threatLevel)
            {
                return threatLevel switch
                {
                    "Critical" => new System.Windows.Media.SolidColorBrush(System.Windows.Media.Color.FromRgb(231, 76, 60)),
                    "High" => new System.Windows.Media.SolidColorBrush(System.Windows.Media.Color.FromRgb(230, 126, 34)),
                    "Medium" => new System.Windows.Media.SolidColorBrush(System.Windows.Media.Color.FromRgb(241, 196, 15)),
                    "Low" => new System.Windows.Media.SolidColorBrush(System.Windows.Media.Color.FromRgb(255, 235, 156)),
                    _ => System.Windows.Media.Brushes.Transparent
                };
            }
            return System.Windows.Media.Brushes.Transparent;
        }

        public object ConvertBack(object value, Type targetType, object parameter, System.Globalization.CultureInfo culture)
        {
            return System.Windows.Data.Binding.DoNothing;
        }
    }

    public class ThreatLevelToForegroundConverter : System.Windows.Data.IValueConverter
    {
        public object Convert(object value, Type targetType, object parameter, System.Globalization.CultureInfo culture)
        {
            if (value is string threatLevel && threatLevel != "None")
            {
                return System.Windows.Media.Brushes.White;
            }
            return new System.Windows.Media.SolidColorBrush(System.Windows.Media.Color.FromRgb(44, 62, 80));
        }

        public object ConvertBack(object value, Type targetType, object parameter, System.Globalization.CultureInfo culture)
        {
            return System.Windows.Data.Binding.DoNothing;
        }
    }
}