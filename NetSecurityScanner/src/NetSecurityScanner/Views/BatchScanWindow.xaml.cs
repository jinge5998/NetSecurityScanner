using Microsoft.Win32;
using NetSecurityScanner.Models;
using NetSecurityScanner.Services;
using NetSecurityScanner.Utils;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;

namespace NetSecurityScanner.Views
{
    public partial class BatchScanWindow : Window
    {
        private readonly BatchScanManager _batchScanManager;
        private readonly ScanHistoryService _historyService;
        private List<string> _parsedTargets;
        private List<BatchScanResultItem> _scanResults;
        private CancellationTokenSource _cancellationTokenSource;

        public BatchScanWindow()
        {
            InitializeComponent();
            _batchScanManager = new BatchScanManager();
            _historyService = new ScanHistoryService();
            _parsedTargets = new List<string>();
            _scanResults = new List<BatchScanResultItem>();

            SetupEventHandlers();
            
            // 设置初始选中项
            BatchTargetTypeComboBox.SelectedIndex = 0;
        }

        private void SetupEventHandlers()
        {
            // 滑块值变化事件
            ConcurrencySlider.ValueChanged += (s, e) =>
            {
                ConcurrencyValueTextBlock.Text = ConcurrencySlider.Value.ToString("F0");
            };

            TimeoutSlider.ValueChanged += (s, e) =>
            {
                TimeoutValueTextBlock.Text = $"{TimeoutSlider.Value:F0}秒";
            };

            // 批量扫描进度事件
            _batchScanManager.ProgressChanged += (s, e) =>
            {
                Dispatcher.Invoke(() =>
                {
                    BatchScanProgressBar.Value = e.Percentage;
                    BatchScanProgressTextBlock.Text = $"{e.CompletedCount}/{e.TotalCount}";
                    BatchScanStatusTextBlock.Text = e.Status;
                    CurrentScanningTargetTextBlock.Text = $"当前扫描: {e.CurrentTarget}";
                });
            };

            _batchScanManager.TargetCompleted += (s, e) =>
            {
                Dispatcher.Invoke(() =>
                {
                    UpdateScanResult(e);
                    UpdateStatistics();
                });
            };
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
            var dialog = new OpenFileDialog
            {
                Filter = "文本文件|*.txt|所有文件|*.*",
                Title = "选择目标列表文件"
            };

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

                if (BatchTargetTypeComboBox.SelectedItem is not ComboBoxItem selectedItem)
                {
                    MessageBox.Show("请选择目标类型", "提示", MessageBoxButton.OK, MessageBoxImage.Information);
                    return;
                }

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
                    ParsedTargetCountTextBlock.Text = $"已解析: {_parsedTargets.Count} 个目标";
                    ParsedTargetCountTextBlock.Foreground = System.Windows.Media.Brushes.Green;
                    MessageBox.Show($"成功解析 {_parsedTargets.Count} 个扫描目标", "解析成功", MessageBoxButton.OK, MessageBoxImage.Information);
                }
                else
                {
                    ParsedTargetCountTextBlock.Text = "已解析: 0 个目标";
                    ParsedTargetCountTextBlock.Foreground = System.Windows.Media.Brushes.Red;
                    MessageBox.Show("未能解析到有效的扫描目标，请检查输入", "解析失败", MessageBoxButton.OK, MessageBoxImage.Warning);
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

            try
            {
                // 重置结果
                _scanResults.Clear();
                InitializeResultGrid();

                // 更新UI状态
                StartBatchScanButton.IsEnabled = false;
                StopBatchScanButton.IsEnabled = true;
                ExportBatchReportButton.IsEnabled = false;
                BatchScanStatusTextBlock.Text = "正在扫描...";

                // 创建扫描配置
                var config = CreateScanConfiguration();

                // 创建取消令牌
                _cancellationTokenSource = new CancellationTokenSource();

                // 执行批量扫描
                var result = await _batchScanManager.ScanBatchAsync(_parsedTargets, config, _cancellationTokenSource.Token);

                // 扫描完成
                BatchScanStatusTextBlock.Text = "扫描完成";
                MessageBox.Show(
                    $"批量扫描完成！\n" +
                    $"总目标: {result.TotalTargets}\n" +
                    $"成功: {result.TargetResults.Count}\n" +
                    $"失败: {result.FailedTargets.Count}\n" +
                    $"总漏洞: {result.TotalVulnerabilities}\n" +
                    $"执行时长: {result.Duration.TotalMinutes:F1} 分钟",
                    "扫描完成", MessageBoxButton.OK, MessageBoxImage.Information);

                // 自动生成报告
                if (GenerateReportCheckBox.IsChecked == true)
                {
                    await GenerateBatchReportAsync(result);
                }
            }
            catch (OperationCanceledException)
            {
                BatchScanStatusTextBlock.Text = "扫描已取消";
                MessageBox.Show("批量扫描已取消", "取消", MessageBoxButton.OK, MessageBoxImage.Information);
            }
            catch (Exception ex)
            {
                BatchScanStatusTextBlock.Text = "扫描失败";
                MessageBox.Show($"批量扫描失败: {ex.Message}", "错误", MessageBoxButton.OK, MessageBoxImage.Error);
            }
            finally
            {
                StartBatchScanButton.IsEnabled = true;
                StopBatchScanButton.IsEnabled = false;
                ExportBatchReportButton.IsEnabled = _scanResults.Any();
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

        private void CloseBatchWindowButton_Click(object sender, RoutedEventArgs e)
        {
            _cancellationTokenSource?.Cancel();
            Close();
        }

        private ScanConfiguration CreateScanConfiguration()
        {
            if (BatchScanModeComboBox.SelectedItem is not ComboBoxItem selectedItem)
                return ScanConfiguration.StandardConfig;

            string modeTag = selectedItem.Tag?.ToString();
            var config = modeTag switch
            {
                "Lightning" => ScanConfiguration.LightningConfig,
                "Standard" => ScanConfiguration.StandardConfig,
                "Deep" => ScanConfiguration.DeepConfig,
                _ => ScanConfiguration.StandardConfig
            };

            // 应用自定义参数
            config.MaxConcurrency = (int)ConcurrencySlider.Value;
            config.TimeoutMs = (int)TimeoutSlider.Value * 1000;

            return config;
        }

        private void InitializeResultGrid()
        {
            for (int i = 0; i < _parsedTargets.Count; i++)
            {
                _scanResults.Add(new BatchScanResultItem
                {
                    Index = i + 1,
                    Target = _parsedTargets[i],
                    Status = "等待中",
                    OpenPorts = "-",
                    VulnerabilityCount = "-",
                    CriticalCount = "-",
                    HighCount = "-",
                    MediumCount = "-",
                    ScanDuration = "-",
                    ErrorMessage = ""
                });
            }

            BatchScanResultsDataGrid.ItemsSource = _scanResults;
            UpdateStatistics();
        }

        private void UpdateScanResult(List<VulnerabilityResult> vulnerabilities)
        {
            // 找到当前正在扫描的目标并更新结果
            // 这里简化处理，实际应该根据目标匹配
            var pendingItem = _scanResults.FirstOrDefault(r => r.Status == "等待中" || r.Status == "扫描中");
            if (pendingItem != null)
            {
                pendingItem.Status = "已完成";
                pendingItem.VulnerabilityCount = vulnerabilities?.Count.ToString() ?? "0";
                pendingItem.CriticalCount = vulnerabilities?.Count(v => v.RiskLevel == "严重").ToString() ?? "0";
                pendingItem.HighCount = vulnerabilities?.Count(v => v.RiskLevel == "高危").ToString() ?? "0";
                pendingItem.MediumCount = vulnerabilities?.Count(v => v.RiskLevel == "中危").ToString() ?? "0";
                pendingItem.OpenPorts = vulnerabilities?.Select(v => v.Port).Distinct().Count().ToString() ?? "0";

                // 刷新DataGrid
                BatchScanResultsDataGrid.Items.Refresh();
            }
        }

        private void UpdateStatistics()
        {
            int total = _scanResults.Count;
            int completed = _scanResults.Count(r => r.Status == "已完成");
            int failed = _scanResults.Count(r => r.Status == "失败");
            int totalVulns = _scanResults.Sum(r => int.TryParse(r.VulnerabilityCount, out int v) ? v : 0);
            int totalCritical = _scanResults.Sum(r => int.TryParse(r.CriticalCount, out int v) ? v : 0);

            TotalTargetsTextBlock.Text = $"总目标: {total}";
            CompletedTargetsTextBlock.Text = $"已完成: {completed}";
            FailedTargetsTextBlock.Text = $"失败: {failed}";
            TotalVulnerabilitiesTextBlock.Text = $"总漏洞: {totalVulns}";
            TotalCriticalTextBlock.Text = $"严重: {totalCritical}";
        }

        private async Task GenerateBatchReportAsync(BatchScanResult result)
        {
            try
            {
                var dialog = new SaveFileDialog
                {
                    Filter = "HTML文件|*.html|CSV文件|*.csv",
                    FileName = $"批量扫描报告_{DateTime.Now:yyyyMMdd_HHmmss}",
                    Title = "保存批量扫描报告"
                };

                if (dialog.ShowDialog() != true) return;

                string filePath = dialog.FileName;
                string extension = System.IO.Path.GetExtension(filePath).ToLower();

                if (extension == ".html")
                {
                    // 生成HTML报告
                    var htmlContent = GenerateHtmlReport(result);
                    await File.WriteAllTextAsync(filePath, htmlContent);
                }
                else if (extension == ".csv")
                {
                    // 生成CSV报告
                    var csvContent = GenerateCsvReport(result);
                    await File.WriteAllTextAsync(filePath, csvContent);
                }

                MessageBox.Show($"报告已保存到:\n{filePath}", "报告生成成功", MessageBoxButton.OK, MessageBoxImage.Information);
            }
            catch (Exception ex)
            {
                MessageBox.Show($"生成报告失败: {ex.Message}", "错误", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        private async Task ExportBatchReportAsync()
        {
            // 从 _scanResults 构建实际的批量扫描结果
            var targetResults = new List<List<VulnerabilityResult>>();
            var failedTargets = new List<FailedTarget>();

            foreach (var item in _scanResults)
            {
                if (item.Status == "已完成" || item.Status == "完成")
                {
                    var vulns = new List<VulnerabilityResult>();
                    int criticalCount = int.TryParse(item.CriticalCount, out int cc) ? cc : 0;
                    int highCount = int.TryParse(item.HighCount, out int hc) ? hc : 0;
                    int mediumCount = int.TryParse(item.MediumCount, out int mc) ? mc : 0;
                    int totalVulnCount = int.TryParse(item.VulnerabilityCount, out int vc) ? vc : 0;
                    int lowCount = totalVulnCount - criticalCount - highCount - mediumCount;
                    if (lowCount < 0) lowCount = 0;

                    for (int i = 0; i < criticalCount; i++)
                        vulns.Add(new VulnerabilityResult { RiskLevel = "严重", Target = item.Target ?? "" });
                    for (int i = 0; i < highCount; i++)
                        vulns.Add(new VulnerabilityResult { RiskLevel = "高危", Target = item.Target ?? "" });
                    for (int i = 0; i < mediumCount; i++)
                        vulns.Add(new VulnerabilityResult { RiskLevel = "中危", Target = item.Target ?? "" });
                    for (int i = 0; i < lowCount; i++)
                        vulns.Add(new VulnerabilityResult { RiskLevel = "低危", Target = item.Target ?? "" });

                    targetResults.Add(vulns);
                }
                else if (item.Status == "失败" || item.Status == "错误")
                {
                    failedTargets.Add(new FailedTarget
                    {
                        Target = item.Target ?? "",
                        Error = item.ErrorMessage ?? "未知错误"
                    });
                }
            }

            var batchResult = new BatchScanResult
            {
                TotalTargets = _scanResults.Count,
                TargetResults = targetResults,
                FailedTargets = failedTargets
            };

            await GenerateBatchReportAsync(batchResult);
        }

        private string GenerateHtmlReport(BatchScanResult result)
        {
            var sb = new System.Text.StringBuilder();
            sb.AppendLine("<!DOCTYPE html>");
            sb.AppendLine("<html><head><meta charset='UTF-8'>");
            sb.AppendLine("<title>批量扫描报告</title>");
            sb.AppendLine("<style>");
            sb.AppendLine("body { font-family: Arial, sans-serif; margin: 40px; background: #f5f5f5; }");
            sb.AppendLine(".header { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 30px; text-align: center; border-radius: 8px; }");
            sb.AppendLine(".summary { background: white; padding: 20px; margin: 20px 0; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }");
            sb.AppendLine("table { width: 100%; background: white; border-collapse: collapse; margin: 20px 0; }");
            sb.AppendLine("th { background: #3498db; color: white; padding: 12px; text-align: left; }");
            sb.AppendLine("td { padding: 10px; border-bottom: 1px solid #ddd; }");
            sb.AppendLine("tr:hover { background: #f5f5f5; }");
            sb.AppendLine(".critical { color: #e74c3c; font-weight: bold; }");
            sb.AppendLine(".high { color: #e67e22; font-weight: bold; }");
            sb.AppendLine("</style></head><body>");

            sb.AppendLine("<div class='header'><h1>🚀 批量扫描报告</h1>");
            sb.AppendLine($"<p>生成时间: {DateTime.Now:yyyy-MM-dd HH:mm:ss}</p></div>");

            sb.AppendLine("<div class='summary'>");
            sb.AppendLine($"<h2>📊 扫描概要</h2>");
            sb.AppendLine($"<p><strong>总目标数:</strong> {result.TotalTargets}</p>");
            sb.AppendLine($"<p><strong>成功扫描:</strong> {result.TargetResults.Count}</p>");
            sb.AppendLine($"<p><strong>扫描失败:</strong> {result.FailedTargets.Count}</p>");
            sb.AppendLine($"<p><strong>总漏洞数:</strong> {result.TotalVulnerabilities}</p>");
            sb.AppendLine($"<p><strong>严重漏洞:</strong> <span class='critical'>{result.CriticalCount}</span></p>");
            sb.AppendLine($"<p><strong>高危漏洞:</strong> <span class='high'>{result.HighCount}</span></p>");
            sb.AppendLine($"<p><strong>执行时长:</strong> {result.Duration.TotalMinutes:F1} 分钟</p>");
            sb.AppendLine("</div>");

            sb.AppendLine("<h2>📋 详细结果</h2>");
            sb.AppendLine("<table><thead><tr>");
            sb.AppendLine("<th>序号</th><th>目标</th><th>状态</th><th>漏洞数</th><th>严重</th><th>高危</th><th>中危</th>");
            sb.AppendLine("</tr></thead><tbody>");

            foreach (var item in _scanResults)
            {
                sb.AppendLine("<tr>");
                sb.AppendLine($"<td>{item.Index}</td>");
                sb.AppendLine($"<td>{item.Target}</td>");
                sb.AppendLine($"<td>{item.Status}</td>");
                sb.AppendLine($"<td>{item.VulnerabilityCount}</td>");
                sb.AppendLine($"<td class='critical'>{item.CriticalCount}</td>");
                sb.AppendLine($"<td class='high'>{item.HighCount}</td>");
                sb.AppendLine($"<td>{item.MediumCount}</td>");
                sb.AppendLine("</tr>");
            }

            sb.AppendLine("</tbody></table>");
            sb.AppendLine($"<p style='text-align: center; color: #7f8c8d; margin-top: 40px;'>由 NetSecurityScanner 生成</p>");
            sb.AppendLine("</body></html>");

            return sb.ToString();
        }

        private string GenerateCsvReport(BatchScanResult result)
        {
            var sb = new System.Text.StringBuilder();
            sb.AppendLine("序号,目标,状态,开放端口,漏洞数,严重,高危,中危,扫描时长,错误信息");

            foreach (var item in _scanResults)
            {
                sb.AppendLine($"{item.Index},{item.Target},{item.Status},{item.OpenPorts},{item.VulnerabilityCount},{item.CriticalCount},{item.HighCount},{item.MediumCount},{item.ScanDuration},{item.ErrorMessage}");
            }

            return sb.ToString();
        }

        protected override void OnClosing(System.ComponentModel.CancelEventArgs e)
        {
            _cancellationTokenSource?.Cancel();
            base.OnClosing(e);
        }
    }

    public class BatchScanResultItem
    {
        public int Index { get; set; }
        public string Target { get; set; }
        public string Status { get; set; }
        public string OpenPorts { get; set; }
        public string VulnerabilityCount { get; set; }
        public string CriticalCount { get; set; }
        public string HighCount { get; set; }
        public string MediumCount { get; set; }
        public string ScanDuration { get; set; }
        public string ErrorMessage { get; set; }
    }
}
