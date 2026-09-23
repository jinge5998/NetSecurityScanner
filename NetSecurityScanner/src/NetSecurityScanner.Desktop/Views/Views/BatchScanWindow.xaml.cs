using Microsoft.Win32;
using NetSecurityScanner.Models;
using NetSecurityScanner.Services;
using NetSecurityScanner.Utils;
using System;
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
using System.Windows.Threading;

namespace NetSecurityScanner.Views
{
    public partial class BatchScanWindow : Window
    {
        private readonly BatchScanManager _batchScanManager;
        private readonly ScanHistoryService _historyService;
        private List<string> _parsedTargets;
        private ObservableCollection<IpScanItem> _ipItems;
        private CancellationTokenSource _cancellationTokenSource;
        private DispatcherTimer _elapsedTimer;
        private Stopwatch _totalStopwatch;
        private int _completedCount;
        private int _failedCount;
        private int _totalVulns;
        private int _totalCritical;

        public BatchScanWindow()
        {
            InitializeComponent();
            Title = $"批量扫描 v{VersionHelper.GetVersion()}";
            _batchScanManager = new BatchScanManager();
            _historyService = new ScanHistoryService();
            _parsedTargets = new List<string>();
            _ipItems = new ObservableCollection<IpScanItem>();
            _totalStopwatch = new Stopwatch();

            IpListView.ItemsSource = _ipItems;

            ConcurrencySlider.ValueChanged += (s, e) => ConcurrencyValueTextBlock.Text = ConcurrencySlider.Value.ToString("F0");
            TimeoutSlider.ValueChanged += (s, e) => TimeoutValueTextBlock.Text = TimeoutSlider.Value.ToString("F0");

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

            BatchTargetTypeComboBox.SelectedIndex = 0;
        }

        private void BatchTargetTypeComboBox_SelectionChanged(object sender, SelectionChangedEventArgs e)
        {
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
                if (_parsedTargets.Any())
                {
                    _ipItems.Clear();
                    foreach (var ip in _parsedTargets)
                    {
                        _ipItems.Add(new IpScanItem { IpAddress = ip, Status = "等待中", StatusIcon = "...", ProgressText = "0%", DurationText = "00:00" });
                    }
                    ParsedTargetCountTextBlock.Text = $"已解析: {_parsedTargets.Count} 个目标";
                    ParsedTargetCountTextBlock.Foreground = System.Windows.Media.Brushes.Green;
                    TotalTargetsTextBlock.Text = $"总目标: {_parsedTargets.Count}";
                    MessageBox.Show($"成功解析 {_parsedTargets.Count} 个扫描目标", "解析成功", MessageBoxButton.OK, MessageBoxImage.Information);
                }
                else
                {
                    ParsedTargetCountTextBlock.Text = "已解析: 0 个目标";
                    ParsedTargetCountTextBlock.Foreground = System.Windows.Media.Brushes.Red;
                    MessageBox.Show("未能解析到有效的扫描目标", "解析失败", MessageBoxButton.OK, MessageBoxImage.Warning);
                }
            }
            catch (Exception ex)
            {
                MessageBox.Show($"解析目标失败: {ex.Message}", "错误", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        private async void StartBatchScanButton_Click(object sender, RoutedEventArgs e)
        {
            if (!_parsedTargets.Any())
            {
                MessageBox.Show("请先解析扫描目标", "提示", MessageBoxButton.OK, MessageBoxImage.Information);
                return;
            }

            _completedCount = 0;
            _failedCount = 0;
            _totalVulns = 0;
            _totalCritical = 0;
            _cancellationTokenSource = new CancellationTokenSource();
            var token = _cancellationTokenSource.Token;

            StartBatchScanButton.IsEnabled = false;
            StopBatchScanButton.IsEnabled = true;
            ExportBatchReportButton.IsEnabled = false;

            _totalStopwatch.Restart();
            _elapsedTimer.Start();

            int concurrency = (int)ConcurrencySlider.Value;
            int timeoutMs = (int)TimeoutSlider.Value * 1000;

            var portScanner = new PortScanner();
            var vulnScanner = new VulnerabilityScanner();

            try
            {
                await vulnScanner.InitializeAsync(token);
                var semaphore = new SemaphoreSlim(concurrency);
                var tasks = _parsedTargets.Select((ip, index) => ScanSingleTargetAsync(ip, index, semaphore, timeoutMs, token, portScanner, vulnScanner)).ToList();
                await Task.WhenAll(tasks);
            }
            catch (OperationCanceledException) { }
            finally
            {
                _totalStopwatch.Stop();
                _elapsedTimer.Stop();

                StartBatchScanButton.IsEnabled = true;
                StopBatchScanButton.IsEnabled = false;
                ExportBatchReportButton.IsEnabled = true;

                BatchScanStatusTextBlock.Text = "扫描完成";
                ElapsedTimeTextBlock.Text = $"已用时间: {_totalStopwatch.Elapsed:hh\\:mm\\:ss}";
                RemainingTimeTextBlock.Text = "预计剩余: 00:00:00";

                MessageBox.Show(
                    $"批量扫描完成！\n\n总目标: {_parsedTargets.Count}\n已完成: {_completedCount}\n失败: {_failedCount}\n总漏洞: {_totalVulns}\n严重漏洞: {_totalCritical}\n耗时: {_totalStopwatch.Elapsed:hh\\:mm\\:ss}",
                    "扫描完成", MessageBoxButton.OK, MessageBoxImage.Information);
            }
        }

        private async Task ScanSingleTargetAsync(string ip, int index, SemaphoreSlim semaphore, int timeoutMs, CancellationToken token, PortScanner portScanner, VulnerabilityScanner vulnScanner)
        {
            await semaphore.WaitAsync(token);
            var itemStopwatch = new Stopwatch();

            try
            {
                _ = Dispatcher.BeginInvoke(() =>
                {
                    _ipItems[index].Status = "扫描中";
                    _ipItems[index].StatusIcon = "-->";
                    CurrentScanningTargetTextBlock.Text = $"当前: {ip}";
                    BatchScanStatusTextBlock.Text = $"正在扫描 {ip}...";
                });

                itemStopwatch.Start();
                var ports = new List<int> { 21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 993, 995, 1433, 1521, 3306, 3389, 5432, 5900, 6379, 8080, 8443, 9200, 27017 };
                var progress = new Progress<int>(p =>
                {
                    Dispatcher.BeginInvoke(() =>
                    {
                        _ipItems[index].ProgressText = $"{p}%";
                        _ipItems[index].DurationText = itemStopwatch.Elapsed.ToString(@"mm\:ss");
                    });
                });

                var tcpResults = await portScanner.ScanTcpPortsAsync(ip, ports, progress, token);
                var openPorts = tcpResults.Where(x => x.Status == "开放").ToList();

                List<VulnerabilityResult> vulnResults = new List<VulnerabilityResult>();
                if (openPorts.Count > 0)
                {
                    vulnResults = (await vulnScanner.ScanVulnerabilitiesAsync(ip, openPorts, token)).ToList();
                }

                itemStopwatch.Stop();

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

        private void UpdateGlobalStatistics()
        {
            CompletedTargetsTextBlock.Text = $"已完成: {_completedCount}";
            FailedTargetsTextBlock.Text = $"失败: {_failedCount}";
            TotalVulnerabilitiesTextBlock.Text = $"总漏洞: {_totalVulns}";
            TotalCriticalTextBlock.Text = $"严重: {_totalCritical}";
        }

        private void UpdateProgressBar()
        {
            int total = _parsedTargets.Count;
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

        private void StopBatchScanButton_Click(object sender, RoutedEventArgs e)
        {
            _cancellationTokenSource?.Cancel();
            BatchScanStatusTextBlock.Text = "正在停止...";
        }

        private async void ExportBatchReportButton_Click(object sender, RoutedEventArgs e)
        {
            await ExportBatchReportAsync();
        }

        private async Task ExportBatchReportAsync()
        {
            var dialog = new SaveFileDialog
            {
                Filter = "HTML文件|*.html|CSV文件|*.csv",
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
                else
                {
                    var csv = GenerateCsvReport();
                    await File.WriteAllTextAsync(filePath, csv);
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
            _cancellationTokenSource?.Cancel();
            _elapsedTimer.Stop();
            base.OnClosing(e);
        }
    }

    public class IpScanItem
    {
        public string IpAddress { get; set; } = "";
        public string Status { get; set; } = "等待中";
        public string StatusIcon { get; set; } = "...";
        public string ProgressText { get; set; } = "0%";
        public string DurationText { get; set; } = "00:00";
        public int OpenPortsCount { get; set; }
        public int VulnCount { get; set; }
        public int CriticalCount { get; set; }
        public int HighCount { get; set; }
        public string ThreatLevel { get; set; } = "None";
        public string ErrorMessage { get; set; } = "";
        public List<PortScanResult> PortResults { get; set; } = new List<PortScanResult>();
        public List<VulnerabilityResult> VulnResults { get; set; } = new List<VulnerabilityResult>();
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