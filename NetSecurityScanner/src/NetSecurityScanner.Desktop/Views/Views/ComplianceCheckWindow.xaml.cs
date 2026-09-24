using Microsoft.Win32;
using NetSecurityScanner.Services;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;

namespace NetSecurityScanner.Views
{
    public partial class ComplianceCheckWindow : Window
    {
        private readonly ComplianceCheckService _complianceService;
        private ComplianceReport? _currentReport;

        public ComplianceCheckWindow()
        {
            InitializeComponent();
            _complianceService = new ComplianceCheckService();
            ResultsDataGrid.SelectionChanged += ResultsDataGrid_SelectionChanged;
        }

        private async void StartCheckButton_Click(object sender, RoutedEventArgs e)
        {
            var target = TargetTextBox.Text.Trim();
            if (string.IsNullOrEmpty(target))
            {
                MessageBox.Show("请输入检查目标", "提示", MessageBoxButton.OK, MessageBoxImage.Information);
                return;
            }

            StartCheckButton.IsEnabled = false;
            CheckProgressBar.Visibility = Visibility.Visible;
            StatusTextBlock.Text = "正在执行合规性检查...";

            try
            {
                var context = new ComplianceCheckContext
                {
                    Target = target,
                    OpenPorts = new List<int>() // 端口应从扫描结果获取
                };

                // 尝试从应用的扫描结果中获取开放端口
                try
                {
                    var portScanDataPath = System.IO.Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "port_scan_results.json");
                    if (System.IO.File.Exists(portScanDataPath))
                    {
                        var json = System.IO.File.ReadAllText(portScanDataPath);
                        var scanData = System.Text.Json.JsonSerializer.Deserialize<System.Text.Json.JsonElement>(json);
                        if (scanData.ValueKind == System.Text.Json.JsonValueKind.Array)
                        {
                            var ports = new List<int>();
                            foreach (var item in scanData.EnumerateArray())
                            {
                                if (item.TryGetProperty("Status", out var status) &&
                                    (status.GetString() == "开放" || status.GetString() == "Open") &&
                                    item.TryGetProperty("Port", out var port))
                                {
                                    ports.Add(port.GetInt32());
                                }
                            }
                            context.OpenPorts = ports.Distinct().ToList();
                        }
                    }
                }
                catch (Exception ex)
                {
                    System.Diagnostics.Debug.WriteLine($"[ComplianceCheckWindow] 解析扫描数据端口失败: {ex.Message}");
                }

                var selectedType = CheckTypeComboBox.SelectedIndex;
                _currentReport = selectedType switch
                {
                    1 => await _complianceService.RunChecksByTypeAsync(ComplianceType.DengBao20, context),
                    2 => await _complianceService.RunChecksByTypeAsync(ComplianceType.CIS, context),
                    _ => await _complianceService.RunAllChecksAsync(context)
                };

                DisplayResults();
                StatusTextBlock.Text = $"检查完成，合规评分: {_currentReport.ComplianceScore:F1}%";
                ExportReportButton.IsEnabled = true;
            }
            catch (Exception ex)
            {
                StatusTextBlock.Text = $"检查失败: {ex.Message}";
                MessageBox.Show($"检查失败: {ex.Message}", "错误", MessageBoxButton.OK, MessageBoxImage.Error);
            }
            finally
            {
                StartCheckButton.IsEnabled = true;
                CheckProgressBar.Visibility = Visibility.Collapsed;
            }
        }

        private void DisplayResults()
        {
            if (_currentReport == null) return;

            ResultsDataGrid.ItemsSource = _currentReport.Results;
            ResultCountTextBlock.Text = $"({_currentReport.TotalChecks})";

            // 更新统计
            ComplianceScoreText.Text = $"{_currentReport.ComplianceScore:F1}";
            ScoreDescriptionText.Text = _currentReport.ComplianceScore >= 80 ? "优秀" :
                                       _currentReport.ComplianceScore >= 60 ? "良好" : "需改进";

            PassCountText.Text = _currentReport.PassCount.ToString();
            FailCountText.Text = _currentReport.FailCount.ToString();
            WarningCountText.Text = _currentReport.WarningCount.ToString();
            NaCountText.Text = _currentReport.NotApplicableCount.ToString();
        }

        private void ResultsDataGrid_SelectionChanged(object sender, SelectionChangedEventArgs e)
        {
            if (ResultsDataGrid.SelectedItem is ComplianceCheckResult result)
            {
                DisplayDetail(result);
            }
        }

        private void DisplayDetail(ComplianceCheckResult result)
        {
            DetailPanel.Children.Clear();

            // 检查项名称
            DetailPanel.Children.Add(new TextBlock
            {
                Text = result.Item,
                FontSize = 18,
                FontWeight = FontWeights.Bold,
                Margin = new Thickness(0, 0, 0, 10)
            });

            // 状态
            var statusColor = result.Status switch
            {
                ComplianceStatus.Pass => Brushes.Green,
                ComplianceStatus.Fail => Brushes.Red,
                ComplianceStatus.Warning => Brushes.Orange,
                _ => Brushes.Gray
            };

            DetailPanel.Children.Add(new TextBlock
            {
                Text = $"状态: {result.Status}",
                FontWeight = FontWeights.Bold,
                Foreground = statusColor,
                Margin = new Thickness(0, 0, 0, 10)
            });

            // 其他信息
            AddDetailItem("检查ID:", result.CheckId);
            AddDetailItem("类别:", result.Category);
            AddDetailItem("要求:", result.Requirement);
            AddDetailItem("检查方法:", result.CheckMethod);
            AddDetailItem("备注:", result.Remark);
        }

        private void AddDetailItem(string label, string value)
        {
            var panel = new StackPanel { Orientation = Orientation.Vertical, Margin = new Thickness(0, 5, 0, 5) };
            panel.Children.Add(new TextBlock { Text = label, FontWeight = FontWeights.SemiBold, FontSize = 12 });
            panel.Children.Add(new TextBlock { Text = value, TextWrapping = TextWrapping.Wrap, Margin = new Thickness(0, 2, 0, 0) });
            DetailPanel.Children.Add(panel);
        }

        private async void ExportReportButton_Click(object sender, RoutedEventArgs e)
        {
            if (_currentReport == null) return;

            try
            {
                var dialog = new SaveFileDialog
                {
                    Filter = "JSON文件|*.json|CSV文件|*.csv|HTML文件|*.html",
                    FileName = $"合规性报告_{DateTime.Now:yyyyMMdd_HHmmss}",
                    Title = "导出合规性报告"
                };

                if (dialog.ShowDialog() != true) return;

                string filePath = dialog.FileName;
                string extension = Path.GetExtension(filePath).ToLower();

                switch (extension)
                {
                    case ".json":
                        await ExportToJsonAsync(filePath);
                        break;
                    case ".csv":
                        await ExportToCsvAsync(filePath);
                        break;
                    case ".html":
                        await ExportToHtmlAsync(filePath);
                        break;
                }

                MessageBox.Show($"报告已导出到:\n{filePath}", "导出成功", MessageBoxButton.OK, MessageBoxImage.Information);
            }
            catch (Exception ex)
            {
                MessageBox.Show($"导出失败: {ex.Message}", "错误", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        private async Task ExportToJsonAsync(string filePath)
        {
            var json = JsonSerializer.Serialize(_currentReport, new JsonSerializerOptions { WriteIndented = true });
            await File.WriteAllTextAsync(filePath, json);
        }

        private async Task ExportToCsvAsync(string filePath)
        {
            var sb = new StringBuilder();
            sb.AppendLine("检查ID,类别,检查项,要求,检查方法,状态,备注");
            foreach (var r in _currentReport!.Results)
            {
                sb.AppendLine($"{r.CheckId},{r.Category},{r.Item},{r.Requirement},{r.CheckMethod},{r.Status},{r.Remark}");
            }
            await File.WriteAllTextAsync(filePath, sb.ToString());
        }

        private async Task ExportToHtmlAsync(string filePath)
        {
            var html = GenerateHtmlReport();
            await File.WriteAllTextAsync(filePath, html);
        }

        private string GenerateHtmlReport()
        {
            var sb = new StringBuilder();
            sb.AppendLine("<!DOCTYPE html><html><head><meta charset='utf-8'/><title>合规性检查报告</title>");
            sb.AppendLine("<style>body{font-family:Arial;margin:40px;}table{border-collapse:collapse;width:100%;}th,td{border:1px solid #ddd;padding:8px;text-align:left;}th{background:#4CAF50;color:white;}.pass{color:green;}.fail{color:red;}.warning{color:orange;}</style>");
            sb.AppendLine("</head><body>");
            sb.AppendLine($"<h1>合规性检查报告</h1>");
            sb.AppendLine($"<p>目标: {_currentReport!.Target}</p>");
            sb.AppendLine($"<p>检查时间: {_currentReport.CheckTime:yyyy-MM-dd HH:mm:ss}</p>");
            sb.AppendLine($"<p>合规评分: {_currentReport.ComplianceScore:F1}%</p>");
            sb.AppendLine("<table><tr><th>检查ID</th><th>类别</th><th>检查项</th><th>要求</th><th>状态</th></tr>");
            foreach (var r in _currentReport.Results)
            {
                var cssClass = r.Status.ToString().ToLower();
                sb.AppendLine($"<tr><td>{r.CheckId}</td><td>{r.Category}</td><td>{r.Item}</td><td>{r.Requirement}</td><td class='{cssClass}'>{r.Status}</td></tr>");
            }
            sb.AppendLine("</table></body></html>");
            return sb.ToString();
        }

        private void CloseButton_Click(object sender, RoutedEventArgs e)
        {
            Close();
        }
    }
}
