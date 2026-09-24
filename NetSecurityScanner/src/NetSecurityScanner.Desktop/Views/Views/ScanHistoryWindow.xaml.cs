using Microsoft.Win32;
using NetSecurityScanner.Models;
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
using System.Windows.Input;
using System.Windows.Media;

namespace NetSecurityScanner.Views
{
    public partial class ScanHistoryWindow : Window
    {
        private readonly ScanHistoryService _historyService;
        private List<ScanHistory> _allHistory;
        private List<ScanHistory> _filteredHistory;

        public ScanHistoryWindow()
        {
            InitializeComponent();
            _historyService = new ScanHistoryService();
            _allHistory = new List<ScanHistory>();
            _filteredHistory = new List<ScanHistory>();

            Loaded += ScanHistoryWindow_Loaded;
        }

        private async void ScanHistoryWindow_Loaded(object sender, RoutedEventArgs e)
        {
            await LoadHistoryAsync();
        }

        private async Task LoadHistoryAsync()
        {
            try
            {
                _allHistory = await _historyService.GetScanHistoryAsync();
                ApplyFilters();
            }
            catch (Exception ex)
            {
                MessageBox.Show($"加载扫描历史失败: {ex.Message}", "错误", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        private void ApplyFilters()
        {
            _filteredHistory = _allHistory.ToList();

            // 搜索筛选
            var searchText = SearchTextBox.Text.Trim().ToLower();
            if (!string.IsNullOrEmpty(searchText))
            {
                _filteredHistory = _filteredHistory.Where(h =>
                    h.Target.ToLower().Contains(searchText) ||
                    h.ScanId.ToLower().Contains(searchText) ||
                    (h.ScanMode?.ToLower().Contains(searchText) ?? false)
                ).ToList();
            }

            // 风险等级筛选
            if (RiskFilterComboBox.SelectedItem is ComboBoxItem riskItem && riskItem.Content.ToString() != "所有风险等级")
            {
                var riskLevel = riskItem.Content.ToString();
                _filteredHistory = _filteredHistory.Where(h =>
                    (riskLevel == "严重" && h.CriticalCount > 0) ||
                    (riskLevel == "高危" && h.HighCount > 0) ||
                    (riskLevel == "中危" && h.MediumCount > 0) ||
                    (riskLevel == "低危" && h.LowCount > 0)
                ).ToList();
            }

            // 时间筛选
            if (DateFilterComboBox.SelectedItem is ComboBoxItem dateItem && dateItem.Content.ToString() != "所有时间")
            {
                var now = DateTime.Now;
                _filteredHistory = dateItem.Content.ToString() switch
                {
                    "今天" => _filteredHistory.Where(h => h.ScanTime.Date == now.Date).ToList(),
                    "最近7天" => _filteredHistory.Where(h => h.ScanTime >= now.AddDays(-7)).ToList(),
                    "最近30天" => _filteredHistory.Where(h => h.ScanTime >= now.AddDays(-30)).ToList(),
                    _ => _filteredHistory
                };
            }

            HistoryDataGrid.ItemsSource = _filteredHistory;
        }

        private void SearchTextBox_TextChanged(object sender, TextChangedEventArgs e)
        {
            ApplyFilters();
        }

        private void RiskFilterComboBox_SelectionChanged(object sender, SelectionChangedEventArgs e)
        {
            ApplyFilters();
        }

        private void DateFilterComboBox_SelectionChanged(object sender, SelectionChangedEventArgs e)
        {
            ApplyFilters();
        }

        private async void RefreshButton_Click(object sender, RoutedEventArgs e)
        {
            await LoadHistoryAsync();
        }

        private void HistoryDataGrid_SelectionChanged(object sender, SelectionChangedEventArgs e)
        {
            bool hasSelection = HistoryDataGrid.SelectedItem != null;
            ViewDetailsButton.IsEnabled = hasSelection;
            GenerateReportButton.IsEnabled = hasSelection;
            DeleteButton.IsEnabled = hasSelection;
        }

        private void ViewDetailsButton_Click(object sender, RoutedEventArgs e)
        {
            if (HistoryDataGrid.SelectedItem is ScanHistory history)
            {
                var detailsWindow = new ScanHistoryDetailsWindow(history);
                detailsWindow.ShowDialog();
            }
        }

        /// <summary>
        /// 为选中的扫描历史记录生成专业报告（Word/HTML/CSV/TXT）。
        /// 通过 JsonDatabaseService 获取完整扫描结果后调用历史报告生成器。
        /// </summary>
        private async void GenerateReportButton_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                if (HistoryDataGrid.SelectedItem is not ScanHistory history)
                {
                    MessageBox.Show("请先选择一条扫描记录", "提示", MessageBoxButton.OK, MessageBoxImage.Information);
                    return;
                }

                var jsonDb = new JsonDatabaseService();
                var completeResult = await jsonDb.GetScanResultByIdAsync(history.ScanId);
                if (completeResult == null)
                {
                    MessageBox.Show(
                        $"无法获取扫描记录 {history.ScanId} 的完整数据。\n可能原因：数据库中未保存完整扫描结果。",
                        "生成报告失败",
                        MessageBoxButton.OK,
                        MessageBoxImage.Warning);
                    return;
                }

                var (selectedFormat, dialogResult) = ShowReportFormatDialog();
                if (dialogResult != true) return;

                var filePath = ShowSaveFileDialog(selectedFormat, history.Target);
                if (string.IsNullOrEmpty(filePath)) return;

                var directoryPath = System.IO.Path.GetDirectoryName(filePath);
                if (!string.IsNullOrEmpty(directoryPath) && !Directory.Exists(directoryPath))
                    Directory.CreateDirectory(directoryPath);

                Mouse.OverrideCursor = Cursors.Wait;

                var completeResults = new List<CompleteScanResult> { completeResult };
                string generatedFilePath = selectedFormat switch
                {
                    ReportFormat.Word => await Task.Run(() => HistoryWordReportGenerator.GenerateFromHistoryRecordToPath(completeResult, filePath)),
                    ReportFormat.Html => await GenerateHtmlReportAsync(completeResult, filePath),
                    ReportFormat.Csv => await GenerateCsvReportAsync(completeResults, filePath),
                    _ => await GenerateTxtReportAsync(completeResults, filePath),
                };

                Mouse.OverrideCursor = null;

                if (!string.IsNullOrEmpty(generatedFilePath) && File.Exists(generatedFilePath))
                {
                    var fileInfo = new FileInfo(generatedFilePath);
                    var sizeStr = fileInfo.Length > 1024 * 1024
                        ? $"{fileInfo.Length / (1024.0 * 1024.0):F2} MB"
                        : $"{fileInfo.Length / 1024.0:F1} KB";

                    var formatName = selectedFormat switch
                    {
                        ReportFormat.Word => "Word",
                        ReportFormat.Html => "HTML",
                        ReportFormat.Csv => "CSV",
                        _ => "文本"
                    };

                    var resultMessage = $"报告已成功生成！\n\n" +
                                       $"格式：{formatName}\n" +
                                       $"保存位置：{generatedFilePath}\n" +
                                       $"文件大小：{sizeStr}\n" +
                                       $"生成时间：{DateTime.Now:yyyy-MM-dd HH:mm:ss}\n\n" +
                                       $"是否立即打开查看？";

                    var openResult = MessageBox.Show(resultMessage, "报告生成成功", MessageBoxButton.YesNo, MessageBoxImage.Information);

                    if (openResult == MessageBoxResult.Yes)
                    {
                        try
                        {
                            System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo
                            {
                                FileName = generatedFilePath,
                                UseShellExecute = true
                            });
                        }
                        catch (Exception openEx)
                        {
                            System.Diagnostics.Debug.WriteLine($"[ReportExport] 打开文件失败: {openEx.Message}");
                        }
                    }
                }
                else
                {
                    MessageBox.Show("报告生成失败，可能原因：选中的记录中无有效扫描数据。",
                                    "生成失败", MessageBoxButton.OK, MessageBoxImage.Warning);
                }
            }
            catch (Exception ex)
            {
                Mouse.OverrideCursor = null;
                System.Diagnostics.Debug.WriteLine($"[ScanHistory.GenerateReport] 异常: {ex}");
                MessageBox.Show($"生成报告失败: {ex.Message}", "错误", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        private (ReportFormat format, bool? result) ShowReportFormatDialog()
        {
            var formatDialog = new Window
            {
                Title = "生成扫描报告",
                Width = 480,
                Height = 420,
                WindowStartupLocation = WindowStartupLocation.CenterScreen,
                ResizeMode = ResizeMode.NoResize,
                WindowStyle = WindowStyle.ToolWindow,
                Background = new SolidColorBrush(Color.FromRgb(250, 250, 252))
            };

            var mainStack = new StackPanel { Margin = new Thickness(28) };

            var headerBorder = new Border
            {
                Background = new SolidColorBrush(Color.FromRgb(26, 54, 93)),
                CornerRadius = new CornerRadius(6),
                Padding = new Thickness(16, 12, 16, 12),
                Margin = new Thickness(0, 0, 0, 18)
            };
            var headerStack = new StackPanel();
            headerStack.Children.Add(new TextBlock
            {
                Text = "生成扫描报告",
                FontSize = 17,
                FontWeight = FontWeights.Bold,
                Foreground = Brushes.White
            });
            headerStack.Children.Add(new TextBlock
            {
                Text = "选择报告格式，然后指定保存位置即可生成报告",
                FontSize = 11,
                Foreground = new SolidColorBrush(Color.FromRgb(180, 200, 230)),
                Margin = new Thickness(0, 4, 0, 0)
            });
            headerBorder.Child = headerStack;
            mainStack.Children.Add(headerBorder);

            mainStack.Children.Add(new TextBlock
            {
                Text = "选择报告格式：",
                FontSize = 12,
                FontWeight = FontWeights.SemiBold,
                Margin = new Thickness(0, 0, 0, 8),
                Foreground = new SolidColorBrush(Color.FromRgb(55, 65, 81))
            });

            var formatItems = new[]
            {
                new { Icon = "📝", Name = "Word文件 (.docx)", Desc = "可编辑文档格式，方便二次修改和协作（推荐）", Tag = ReportFormat.Word },
                new { Icon = "🌐", Name = "HTML文件 (.html)", Desc = "网页格式报告，可直接在浏览器中查看", Tag = ReportFormat.Html },
                new { Icon = "📊", Name = "CSV文件 (.csv)", Desc = "数据表格格式，适合导入Excel进行数据分析", Tag = ReportFormat.Csv },
                new { Icon = "📃", Name = "文本文件 (.txt)", Desc = "纯文本格式，体积小、兼容性好", Tag = ReportFormat.Txt }
            };

            var formatComboBox = new ComboBox
            {
                Width = 410,
                Height = 34,
                FontSize = 12,
                Margin = new Thickness(0, 0, 0, 4),
                HorizontalAlignment = HorizontalAlignment.Left
            };

            foreach (var item in formatItems)
            {
                formatComboBox.Items.Add(new ComboBoxItem
                {
                    Content = $"{item.Icon} {item.Name}  — {item.Desc}",
                    Tag = item.Tag
                });
            }
            formatComboBox.SelectedIndex = 0;
            mainStack.Children.Add(formatComboBox);

            var buttonPanel = new StackPanel
            {
                Orientation = Orientation.Horizontal,
                HorizontalAlignment = HorizontalAlignment.Right,
                Margin = new Thickness(0, 30, 0, 0)
            };

            var nextButton = new Button
            {
                Content = "下一步 → 选择保存位置",
                Width = 180,
                Height = 36,
                Margin = new Thickness(5, 0, 0, 0),
                FontWeight = FontWeights.SemiBold
            };
            var cancelButton = new Button
            {
                Content = "取消",
                Width = 80,
                Height = 36,
                Margin = new Thickness(5, 0, 0, 0)
            };

            buttonPanel.Children.Add(cancelButton);
            buttonPanel.Children.Add(nextButton);
            mainStack.Children.Add(buttonPanel);

            formatDialog.Content = mainStack;

            ReportFormat selectedFormat = ReportFormat.Word;
            bool? dialogResult = false;

            nextButton.Click += (s, args) =>
            {
                selectedFormat = (ReportFormat)((ComboBoxItem)formatComboBox.SelectedItem).Tag;
                dialogResult = true;
                formatDialog.Close();
            };

            cancelButton.Click += (s, args) =>
            {
                dialogResult = false;
                formatDialog.Close();
            };

            formatDialog.ShowDialog();
            return (selectedFormat, dialogResult);
        }

        private string ShowSaveFileDialog(ReportFormat selectedFormat, string targetIp)
        {
            var safeTargetIp = (targetIp ?? "unknown").Replace(".", "_").Replace(",", "_").Replace(" ", "").Trim();
            if (safeTargetIp.Length > 30) safeTargetIp = safeTargetIp.Substring(0, 30);

            var timestamp = DateTime.Now.ToString("yyyyMMdd_HHmmss");
            var defaultFileName = $"SecurityReport_{safeTargetIp}_{timestamp}";

            string filter;
            string defaultExt;
            switch (selectedFormat)
            {
                case ReportFormat.Word:
                    filter = "Word文件 (*.docx)|*.docx";
                    defaultExt = "docx";
                    break;
                case ReportFormat.Html:
                    filter = "HTML文件 (*.html)|*.html";
                    defaultExt = "html";
                    break;
                case ReportFormat.Csv:
                    filter = "CSV文件 (*.csv)|*.csv";
                    defaultExt = "csv";
                    break;
                default:
                    filter = "文本文件 (*.txt)|*.txt";
                    defaultExt = "txt";
                    break;
            }

            var saveDialog = new Microsoft.Win32.SaveFileDialog
            {
                Title = "保存扫描报告",
                Filter = filter,
                DefaultExt = defaultExt,
                FileName = $"{defaultFileName}.{defaultExt}"
            };

            var desktopPath = Environment.GetFolderPath(Environment.SpecialFolder.Desktop);
            if (Directory.Exists(desktopPath))
                saveDialog.InitialDirectory = desktopPath;

            if (saveDialog.ShowDialog() == true)
                return saveDialog.FileName;

            return null;
        }

        private async Task<string> GenerateHtmlReportAsync(CompleteScanResult result, string savePath)
        {
            return await Task.Run(() =>
            {
                try
                {
                    var sb = new StringBuilder();
                    sb.AppendLine("<!DOCTYPE html>");
                    sb.AppendLine("<html lang='zh-CN'><head><meta charset='UTF-8'>");
                    sb.AppendLine("<title>网络安全扫描报告</title>");
                    sb.AppendLine("<style>");
                    sb.AppendLine("body { font-family: 'Microsoft YaHei', sans-serif; margin: 40px; background: #f5f5f5; }");
                    sb.AppendLine(".header { background: linear-gradient(135deg, #1a365d 0%, #2563eb 100%); color: white; padding: 30px; border-radius: 8px; }");
                    sb.AppendLine(".info { background: white; padding: 20px; margin: 20px 0; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }");
                    sb.AppendLine("table { border-collapse: collapse; width: 100%; background: white; }");
                    sb.AppendLine("th { background: #1e293b; color: white; padding: 10px; text-align: left; }");
                    sb.AppendLine("td { border: 1px solid #e2e8f0; padding: 8px; }");
                    sb.AppendLine("</style></head><body>");

                    sb.AppendLine($"<div class='header'><h1>📋 网络安全扫描报告</h1>");
                    sb.AppendLine($"<p>目标: {result.TargetIp} | 扫描时间: {result.ScanTime:yyyy-MM-dd HH:mm:ss}</p></div>");

                    sb.AppendLine("<div class='info'>");
                    sb.AppendLine("<h2>扫描概要</h2>");
                    var ports = result.PortScanResults ?? new List<PortScanResult>();
                    var openPorts = ports.Where(p => p?.Status == "开放" || p?.Status?.ToLower() == "open").ToList();
                    sb.AppendLine($"<p><strong>开放端口数:</strong> {openPorts.Count}</p>");
                    var vulns = result.VulnerabilityResults ?? new List<VulnerabilityResult>();
                    sb.AppendLine($"<p><strong>发现漏洞数:</strong> {vulns.Count}</p>");
                    sb.AppendLine("</div>");

                    if (openPorts.Any())
                    {
                        sb.AppendLine("<div class='info'>");
                        sb.AppendLine("<h2>开放端口</h2>");
                        sb.AppendLine("<table><tr><th>端口</th><th>服务</th><th>状态</th></tr>");
                        foreach (var p in openPorts)
                        {
                            sb.AppendLine($"<tr><td>{p.PortNumber}</td><td>{p.Service}</td><td>{p.Status}</td></tr>");
                        }
                        sb.AppendLine("</table></div>");
                    }

                    if (vulns.Any())
                    {
                        sb.AppendLine("<div class='info'>");
                        sb.AppendLine("<h2>漏洞列表</h2>");
                        sb.AppendLine("<table><tr><th>CVE</th><th>名称</th><th>风险等级</th><th>描述</th></tr>");
                        foreach (var v in vulns)
                        {
                            sb.AppendLine($"<tr><td>{v.CveId}</td><td>{v.Name}</td><td>{v.RiskLevel}</td><td>{v.Description}</td></tr>");
                        }
                        sb.AppendLine("</table></div>");
                    }

                    sb.AppendLine("</body></html>");

                    File.WriteAllText(savePath, sb.ToString(), Encoding.UTF8);
                    return savePath;
                }
                catch (Exception ex)
                {
                    System.Diagnostics.Debug.WriteLine($"[HTML Report] 生成失败: {ex.Message}");
                    return string.Empty;
                }
            });
        }

        private async Task<string> GenerateCsvReportAsync(List<CompleteScanResult> results, string savePath)
        {
            return await Task.Run(() =>
            {
                try
                {
                    var sb = new StringBuilder();
                    sb.AppendLine("目标IP,CVE,漏洞名称,风险等级,端口,服务,描述,修复建议");
                    foreach (var result in results)
                    {
                        var vulns = result.VulnerabilityResults ?? new List<VulnerabilityResult>();
                        foreach (var v in vulns)
                        {
                            sb.AppendLine($"{result.TargetIp},{v.CveId},{v.Name},{v.RiskLevel},{v.Port},{v.Service},{v.Description},{v.Solution}");
                        }
                    }
                    File.WriteAllText(savePath, sb.ToString(), Encoding.UTF8);
                    return savePath;
                }
                catch (Exception ex)
                {
                    System.Diagnostics.Debug.WriteLine($"[CSV Report] 生成失败: {ex.Message}");
                    return string.Empty;
                }
            });
        }

        private async Task<string> GenerateTxtReportAsync(List<CompleteScanResult> results, string savePath)
        {
            return await Task.Run(() =>
            {
                try
                {
                    var sb = new StringBuilder();
                    sb.AppendLine("=".PadRight(60, '='));
                    sb.AppendLine("网络安全扫描报告");
                    sb.AppendLine("=".PadRight(60, '='));
                    sb.AppendLine();

                    foreach (var result in results)
                    {
                        sb.AppendLine($"目标: {result.TargetIp}");
                        sb.AppendLine($"扫描时间: {result.ScanTime:yyyy-MM-dd HH:mm:ss}");
                        sb.AppendLine();

                        var ports = result.PortScanResults ?? new List<PortScanResult>();
                        var openPorts = ports.Where(p => p?.Status == "开放" || p?.Status?.ToLower() == "open").ToList();
                        sb.AppendLine($"开放端口数: {openPorts.Count}");
                        if (openPorts.Any())
                        {
                            foreach (var p in openPorts)
                            {
                                sb.AppendLine($"  - {p.PortNumber}/{p.Service}: {p.Status}");
                            }
                        }
                        sb.AppendLine();

                        var vulns = result.VulnerabilityResults ?? new List<VulnerabilityResult>();
                        sb.AppendLine($"发现漏洞数: {vulns.Count}");
                        if (vulns.Any())
                        {
                            sb.AppendLine("漏洞详情:");
                            foreach (var v in vulns)
                            {
                                sb.AppendLine($"  [{v.RiskLevel}] {v.CveId} - {v.Name}");
                                sb.AppendLine($"    端口: {v.Port} | 服务: {v.Service}");
                                sb.AppendLine($"    描述: {v.Description}");
                                sb.AppendLine($"    修复: {v.Solution}");
                            }
                        }

                        sb.AppendLine();
                        sb.AppendLine("-".PadRight(60, '-'));
                    }

                    sb.AppendLine("=".PadRight(60, '='));
                    sb.AppendLine($"报告生成时间: {DateTime.Now:yyyy-MM-dd HH:mm:ss}");
                    sb.AppendLine("=".PadRight(60, '='));

                    File.WriteAllText(savePath, sb.ToString(), Encoding.UTF8);
                    return savePath;
                }
                catch (Exception ex)
                {
                    System.Diagnostics.Debug.WriteLine($"[TXT Report] 生成失败: {ex.Message}");
                    return string.Empty;
                }
            });
        }

        private async void DeleteButton_Click(object sender, RoutedEventArgs e)
        {
            if (HistoryDataGrid.SelectedItem is ScanHistory history)
            {
                var result = MessageBox.Show(
                    $"确定要删除扫描记录 '{history.ScanId}' 吗？\n目标: {history.Target}\n时间: {history.ScanTime:yyyy-MM-dd HH:mm}",
                    "确认删除",
                    MessageBoxButton.YesNo,
                    MessageBoxImage.Question);

                if (result == MessageBoxResult.Yes)
                {
                    try
                    {
                        // 从数据库中删除
                        await _historyService.DeleteScanHistoryAsync(history.ScanId);
                        await LoadHistoryAsync();
                        MessageBox.Show("记录已删除", "成功", MessageBoxButton.OK, MessageBoxImage.Information);
                    }
                    catch (Exception ex)
                    {
                        MessageBox.Show($"删除失败: {ex.Message}", "错误", MessageBoxButton.OK, MessageBoxImage.Error);
                    }
                }
            }
        }

        private async void ExportButton_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                var dialog = new SaveFileDialog
                {
                    Filter = "CSV文件|*.csv|JSON文件|*.json",
                    FileName = $"扫描历史_{DateTime.Now:yyyyMMdd_HHmmss}",
                    Title = "导出扫描历史"
                };

                if (dialog.ShowDialog() != true) return;

                string filePath = dialog.FileName;
                string extension = Path.GetExtension(filePath).ToLower();

                if (extension == ".csv")
                {
                    await ExportToCsvAsync(filePath);
                }
                else if (extension == ".json")
                {
                    await ExportToJsonAsync(filePath);
                }

                MessageBox.Show($"扫描历史已导出到:\n{filePath}", "导出成功", MessageBoxButton.OK, MessageBoxImage.Information);
            }
            catch (Exception ex)
            {
                MessageBox.Show($"导出失败: {ex.Message}", "错误", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        private async Task ExportToCsvAsync(string filePath)
        {
            var sb = new StringBuilder();
            sb.AppendLine("扫描ID,目标,扫描时间,扫描模式,漏洞总数,严重,高危,中危,低危,扫描时长,状态");

            foreach (var history in _filteredHistory)
            {
                sb.AppendLine($"{history.ScanId},{history.Target},{history.ScanTime:yyyy-MM-dd HH:mm},{history.ScanMode}," +
                    $"{history.TotalVulnerabilities},{history.CriticalCount},{history.HighCount}," +
                    $"{history.MediumCount},{history.LowCount},{history.Duration},{history.ScanStatus}");
            }

            await File.WriteAllTextAsync(filePath, sb.ToString(), Encoding.UTF8);
        }

        private async Task ExportToJsonAsync(string filePath)
        {
            var json = JsonSerializer.Serialize(_filteredHistory, new JsonSerializerOptions
            {
                WriteIndented = true,
                PropertyNamingPolicy = JsonNamingPolicy.CamelCase
            });

            await File.WriteAllTextAsync(filePath, json, Encoding.UTF8);
        }

        private void CloseButton_Click(object sender, RoutedEventArgs e)
        {
            Close();
        }

        /// <summary>
        /// v5-T4: 右键 "用插件深挖"。从 DataGridRow 反查 DataGrid 与选中行，
        /// 提取 ScanHistory.Target 字符串作为目标 IP，通过 PluginOrchestrator.ScanTargetAsync
        /// 触发多插件联合扫描（无开放端口信息时回退 80/443）并提示结果。
        /// </summary>
        private async void DeepScanMenuItem_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                if (sender is not MenuItem menuItem) return;
                if (menuItem.DataContext is not DataGridRow row) return;

                var dataGrid = FindVisualParent<DataGrid>(menuItem);
                if (dataGrid == null || dataGrid.SelectedItem == null) return;
                var selectedItem = dataGrid.SelectedItem;

                string? targetIp = null;
                var type = selectedItem.GetType();
                var ipProp = type.GetProperty("Target")
                    ?? type.GetProperty("TargetIp")
                    ?? type.GetProperty("Ip");
                if (ipProp != null) targetIp = ipProp.GetValue(selectedItem)?.ToString();

                if (string.IsNullOrEmpty(targetIp))
                {
                    MessageBox.Show("无法获取目标", "提示", MessageBoxButton.OK, MessageBoxImage.Warning);
                    return;
                }

                // 解析 CIDR/IP 段：仅当 target 是单 IP（不含 -,/, :, 空格）时才用于深挖
                if (targetIp.Contains('-') || targetIp.Contains('/') ||
                    targetIp.Contains(' ') || targetIp.Contains(':'))
                {
                    var ans = MessageBox.Show(
                        $"目标 \"{targetIp}\" 是多 IP/段，将仅使用默认端口尝试深挖，是否继续？",
                        "插件深挖",
                        MessageBoxButton.YesNo,
                        MessageBoxImage.Question);
                    if (ans != MessageBoxResult.Yes) return;
                }

                // 历史记录不存端口明细，回退到 80/443 让插件自行决定是否命中
                var ports = new List<int> { 80, 443 };

                var confirm = MessageBox.Show(
                    $"将使用所有适用插件重新扫描 {targetIp} (端口: 80,443)，是否继续？",
                    "插件深挖",
                    MessageBoxButton.YesNo,
                    MessageBoxImage.Question);
                if (confirm != MessageBoxResult.Yes) return;

                Mouse.OverrideCursor = Cursors.Wait;
                var results = await PluginOrchestrator.Instance.ScanTargetAsync(targetIp, ports);
                Mouse.OverrideCursor = null;

                MessageBox.Show(
                    $"深挖完成：发现 {results.Count} 个漏洞",
                    "完成",
                    MessageBoxButton.OK,
                    MessageBoxImage.Information);
            }
            catch (Exception ex)
            {
                Mouse.OverrideCursor = null;
                System.Diagnostics.Debug.WriteLine($"[ScanHistory.DeepScan] 异常: {ex}");
                MessageBox.Show($"深挖失败: {ex.Message}", "错误", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        /// <summary>
        /// 在可视化树中向上查找指定类型的父元素。
        /// </summary>
        private static T? FindVisualParent<T>(DependencyObject child) where T : DependencyObject
        {
            var parent = VisualTreeHelper.GetParent(child);
            while (parent != null && parent is not T)
                parent = VisualTreeHelper.GetParent(parent);
            return parent as T;
        }
    }
}
