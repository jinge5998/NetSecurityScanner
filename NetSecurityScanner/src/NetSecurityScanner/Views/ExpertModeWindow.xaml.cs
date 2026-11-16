using Microsoft.Win32;
using NetSecurityScanner.Models;
using NetSecurityScanner.Services;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.Json;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;

namespace NetSecurityScanner.Views
{
    public partial class ExpertModeWindow : Window
    {
        private PortScanner _portScanner;
        private VulnerabilityScanner _vulnerabilityScanner;
        private CancellationTokenSource _cancellationTokenSource;
        private ExpertScanConfiguration _currentConfig;
        private JsonDatabaseService _jsonDatabaseService;
        private List<PortScanResult> _allPortScanResults;
        private List<VulnerabilityResult> _allVulnResults;
        private int _totalScannedTargets;
        private int _totalOpenPorts;

        public ExpertModeWindow()
        {
            try
            {
                InitializeComponent();
                _portScanner = new PortScanner();
                _vulnerabilityScanner = new VulnerabilityScanner();
                _jsonDatabaseService = new JsonDatabaseService();
                _allPortScanResults = new List<PortScanResult>();
                _allVulnResults = new List<VulnerabilityResult>();
                this.Loaded += ExpertModeWindow_Loaded;
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
                LoadDefaultConfig();
                UpdateConfigSummary();
                ParseTargetCount();
                UpdateScanPlanPreview();

                TargetInputTextBox.TextChanged += (_, __) =>
                {
                    ParseTargetCount();
                    UpdateScanPlanPreview();
                };
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

                CommonPortsRadio.Checked += (s, e) => { if (CustomPortsTextBox != null) CustomPortsTextBox.IsEnabled = false; };
                CustomPortsRadio.Checked += (s, e) => { if (CustomPortsTextBox != null) CustomPortsTextBox.IsEnabled = true; };
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
            var dialog = new OpenFileDialog
            {
                Filter = "JSON配置文件 (*.json)|*.json",
                Title = "加载扫描预设"
            };

            if (dialog.ShowDialog() == true)
            {
                try
                {
                    var json = File.ReadAllText(dialog.FileName);
                    var config = JsonSerializer.Deserialize<ExpertScanConfiguration>(json);
                    if (config != null)
                    {
                        ApplyConfig(config);
                        MessageBox.Show("预设加载成功", "成功", MessageBoxButton.OK, MessageBoxImage.Information);
                    }
                }
                catch (Exception ex)
                {
                    MessageBox.Show($"加载预设失败: {ex.Message}", "错误", MessageBoxButton.OK, MessageBoxImage.Error);
                }
            }
        }

        private void SavePresetButton_Click(object sender, RoutedEventArgs e)
        {
            var dialog = new SaveFileDialog
            {
                Filter = "JSON配置文件 (*.json)|*.json",
                Title = "保存扫描预设",
                FileName = $"ExpertScan_{DateTime.Now:yyyyMMdd_HHmmss}.json"
            };

            if (dialog.ShowDialog() == true)
            {
                try
                {
                    var config = CollectConfig();
                    var json = JsonSerializer.Serialize(config, new JsonSerializerOptions { WriteIndented = true });
                    File.WriteAllText(dialog.FileName, json);
                    MessageBox.Show($"预设已保存到: {dialog.FileName}", "成功", MessageBoxButton.OK, MessageBoxImage.Information);
                }
                catch (Exception ex)
                {
                    MessageBox.Show($"保存预设失败: {ex.Message}", "错误", MessageBoxButton.OK, MessageBoxImage.Error);
                }
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
            config.ServiceIntensity = ServiceIntensityComboBox?.SelectedIndex ?? 1;
            config.ExcludePorts = ExcludePortsTextBox?.Text?.Trim() ?? "";

            // Performance
            config.TcpConcurrency = (int)(TcpConcurrencySlider?.Value ?? 50);
            config.UdpConcurrency = (int)(UdpConcurrencySlider?.Value ?? 20);
            config.TcpTimeout = (int)(TcpTimeoutSlider?.Value ?? 500);
            config.UdpTimeout = (int)(UdpTimeoutSlider?.Value ?? 1000);
            config.RetryCount = (int)(RetrySlider?.Value ?? 1);

            // Rate limit
            config.RateLimit = RateLimitCheckBox?.IsChecked == true;
            config.PacketRate = (int)(PacketRateSlider?.Value ?? 1000);
            config.Randomize = RandomizeCheckBox?.IsChecked == true;
            config.StealthMode = StealthModeCheckBox?.IsChecked == true;

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
            RateLimitCheckBox.IsChecked = config.RateLimit;
            PacketRateSlider.Value = config.PacketRate;
            RandomizeCheckBox.IsChecked = config.Randomize;
            StealthModeCheckBox.IsChecked = config.StealthMode;

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
                    MaxConcurrency = config.TcpConcurrency,
                    Timeout = config.TcpTimeout,
                    RetryCount = config.RetryCount,
                    EnableServiceDetection = config.ServiceDetection,
                    EnableOsDetection = config.OsDetection,
                    ScanType = config.TcpScan ? "TCP" : "UDP"
                };

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
                        List<PortScanResult> tcpResults = new List<PortScanResult>();
                        List<PortScanResult> udpResults = new List<PortScanResult>();
                        var progress = new Progress<int>(p => { /* ignore progress here */ });

                        // TCP和UDP同时扫描支持
                        var tasks = new List<Task<List<PortScanResult>>>();
                        if (config.TcpScan)
                        {
                            tasks.Add(_portScanner.ScanTcpPortsAsync(target, ports, progress, cancellationToken));
                        }
                        if (config.UdpScan)
                        {
                            tasks.Add(_portScanner.ScanUdpPortsAsync(target, ports, progress, cancellationToken));
                        }

                        if (tasks.Count > 0)
                        {
                            var resultsArray = await Task.WhenAll(tasks);
                            foreach (var r in resultsArray)
                            {
                                if (r != null)
                                {
                                    if (r.Any(p => _allPortScanResults.All(existing => existing.TargetIp == target && existing.PortNumber == p.PortNumber)))
                                    {
                                        // TCP结果优先
                                    }
                                }
                            }
                            // 合并TCP和UDP结果
                            tcpResults = resultsArray.Length > 0 ? resultsArray[0] : new List<PortScanResult>();
                            udpResults = resultsArray.Length > 1 ? resultsArray[1] : new List<PortScanResult>();
                        }

                        // 去重合并（TCP优先）
                        var allResults = new List<PortScanResult>();
                        var mergedPorts = new Dictionary<int, PortScanResult>();
                        foreach (var r in tcpResults) { mergedPorts[r.PortNumber] = r; }
                        foreach (var r in udpResults) { if (!mergedPorts.ContainsKey(r.PortNumber)) { mergedPorts[r.PortNumber] = r; } }
                        allResults = mergedPorts.Values.ToList();

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

            return ports.Distinct().OrderBy(p => p).ToList();
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
            MessageBox.Show($"模板已应用\n\n{message}", "模板应用成功", MessageBoxButton.OK, MessageBoxImage.Information);
        }

        private void ExportNmapButton_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                var config = CollectConfig();
                var nmapCmd = GenerateNmapCommand(config);
                
                Clipboard.SetText(nmapCmd);
                
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

            Clipboard.SetText(sb.ToString());
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

            Clipboard.SetText(sb.ToString());
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

            Clipboard.SetText(sb.ToString());
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

        private void ResetScanButtons()
        {
            StartExpertScanButton.Content = "🚀 开始专家扫描";
            StartExpertScanButton.IsEnabled = true;
            CancelExpertButton.IsEnabled = false;
        }
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

        public bool RateLimit { get; set; } = false;
        public int PacketRate { get; set; } = 1000;
        public bool Randomize { get; set; } = false;
        public bool StealthMode { get; set; } = false;

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
}
