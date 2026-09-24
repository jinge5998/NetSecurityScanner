using LiveChartsCore;
using LiveChartsCore.SkiaSharpView;
using LiveChartsCore.SkiaSharpView.Painting;
using LiveChartsCore.SkiaSharpView.VisualElements;
using NetSecurityScanner.Models;
using NetSecurityScanner.Services;
using SkiaSharp;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using System.Windows.Media;

namespace NetSecurityScanner.Views
{
    public partial class StatisticsDashboardWindow : Window
    {
        private readonly JsonDatabaseService _jsonDatabaseService;
        private readonly ScanHistoryService _scanHistoryService;
        private List<CompleteScanResult> _jsonResults = new();
        private const string ChineseFont = "Microsoft YaHei";

        public StatisticsDashboardWindow()
        {
            InitializeComponent();
            _jsonDatabaseService = new JsonDatabaseService();

            try { _scanHistoryService = new ScanHistoryService(); }
            catch { _scanHistoryService = null; }

            Loaded += StatisticsDashboardWindow_Loaded;
        }

        private async void StatisticsDashboardWindow_Loaded(object sender, RoutedEventArgs e)
        {
            await LoadStatisticsAsync();
        }

        private async void RefreshButton_Click(object sender, RoutedEventArgs e)
        {
            await LoadStatisticsAsync();
        }

        private async void TimeRangeComboBox_SelectionChanged(object sender, SelectionChangedEventArgs e)
        {
            await LoadStatisticsAsync();
        }

        private async void RiskFilterComboBox_SelectionChanged(object sender, SelectionChangedEventArgs e)
        {
            await LoadStatisticsAsync();
        }

        private void ExportButton_Click(object sender, RoutedEventArgs e)
        {
            var dialog = new Microsoft.Win32.SaveFileDialog
            {
                Filter = "Text Files (*.txt)|*.txt|All Files (*.*)|*.*",
                FileName = $"StatisticsReport_{DateTime.Now:yyyyMMdd_HHmmss}.txt"
            };

            if (dialog.ShowDialog() == true)
            {
                ExportStatisticsToFile(dialog.FileName);
            }
        }

        private async Task LoadStatisticsAsync()
        {
            try
            {
                if (LastUpdateTimeTextBlock != null)
                    LastUpdateTimeTextBlock.Text = $"最后更新: {DateTime.Now:yyyy-MM-dd HH:mm:ss}";

                var jsonResults = await SafeGetJsonHistory() ?? new List<Services.ScanHistoryItem>();
                var dbResults = await SafeGetDbHistory() ?? new List<ScanHistory>();

                _jsonResults = new List<CompleteScanResult>();

                int timeRangeDays = GetTimeRangeDays();
                DateTime startDate = DateTime.Now.Date.AddDays(-timeRangeDays);

                var filteredJsonResults = jsonResults.Where(h => h != null && h.ScanTime >= startDate).ToList();
                var filteredDbResults = dbResults.Where(h => h != null && h.StartTime >= startDate).ToList();

                RiskDistributionPanel?.Children.Clear();

                try { CalculateOverallStats(filteredJsonResults, filteredDbResults); } catch { }
                try { RenderRiskDistribution(filteredJsonResults, filteredDbResults); } catch { }
                try { RenderVulnBarChart(filteredDbResults); } catch { }
                try { RenderScanTrend(filteredJsonResults, filteredDbResults); } catch { }
                try { RenderTopVulnerabilities(filteredJsonResults, filteredDbResults); } catch { }
                try { RenderPortAnalysis(filteredJsonResults, filteredDbResults); } catch { }
                try { RenderServiceDistribution(filteredJsonResults, filteredDbResults); } catch { }
                try { RenderScanHistory(filteredJsonResults, filteredDbResults); } catch { }
            }
            catch (Exception ex)
            {
                MessageBox.Show($"加载统计数据失败: {ex.Message}", "错误", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        private async Task<List<Services.ScanHistoryItem>> SafeGetJsonHistory()
        {
            try { return await _jsonDatabaseService.GetScanHistoryAsync(); }
            catch { return new List<Services.ScanHistoryItem>(); }
        }

        private async Task<List<ScanHistory>> SafeGetDbHistory()
        {
            try
            {
                if (_scanHistoryService == null) return new List<ScanHistory>();
                return await _scanHistoryService.GetScanHistoryAsync();
            }
            catch { return new List<ScanHistory>(); }
        }

        private async void ScanHistoryDataGrid_MouseDoubleClick(object sender, MouseButtonEventArgs e)
        {
            if (ScanHistoryDataGrid?.SelectedItem == null || _scanHistoryService == null)
                return;

            var selectedItem = ScanHistoryDataGrid.SelectedItem;

            string scanId = null;
            string target = null;
            DateTime scanTime = DateTime.MinValue;

            if (selectedItem is ScanHistoryRecord record)
            {
                scanId = record.ScanId;
                target = record.TargetIp;
                scanTime = record.ScanTime;
            }
            else
            {
                var properties = selectedItem.GetType().GetProperties();
                foreach (var prop in properties)
                {
                    if (prop.Name == "ScanId") scanId = prop.GetValue(selectedItem)?.ToString();
                    if (prop.Name == "TargetIp") target = prop.GetValue(selectedItem)?.ToString();
                    if (prop.Name == "ScanTime") scanTime = (DateTime)(prop.GetValue(selectedItem) ?? DateTime.MinValue);
                }
            }

            if (string.IsNullOrEmpty(scanId))
                return;

            try
            {
                var history = await _scanHistoryService.GetScanByIdAsync(scanId);
                if (history == null)
                {
                    MessageBox.Show($"未找到扫描记录: {scanId}", "提示", MessageBoxButton.OK, MessageBoxImage.Information);
                    return;
                }

                ShowScanHistoryDetail(history);
            }
            catch (Exception ex)
            {
                MessageBox.Show($"加载扫描详情失败: {ex.Message}", "错误", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        private void ShowScanHistoryDetail(ScanHistory history)
        {
            if (history == null) return;

            var detailWindow = new Window
            {
                Title = $"扫描详情 - {history.Target ?? ""} ({history.StartTime:yyyy-MM-dd HH:mm:ss})",
                Width = 900,
                Height = 700,
                WindowStartupLocation = WindowStartupLocation.CenterOwner,
                Owner = this,
                Background = new SolidColorBrush(Color.FromRgb(0xF5, 0xF7, 0xFA))
            };

            var mainGrid = new Grid { Margin = new Thickness(20) };
            mainGrid.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
            mainGrid.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
            mainGrid.RowDefinitions.Add(new RowDefinition { Height = new GridLength(1, GridUnitType.Star) });

            var infoBorder = new Border
            {
                Background = new SolidColorBrush(Colors.White),
                CornerRadius = new CornerRadius(8),
                BorderBrush = new SolidColorBrush(Color.FromRgb(0xE0, 0xE0, 0xE0)),
                BorderThickness = new Thickness(1),
                Padding = new Thickness(15),
                Margin = new Thickness(0, 0, 0, 15)
            };

            var infoStack = new StackPanel();
            infoStack.Children.Add(CreateInfoTextBlock("扫描ID", history.ScanId ?? ""));
            infoStack.Children.Add(CreateInfoTextBlock("目标地址", history.Target ?? ""));
            infoStack.Children.Add(CreateInfoTextBlock("扫描时间", history.StartTime.ToString("yyyy-MM-dd HH:mm:ss")));
            infoStack.Children.Add(CreateInfoTextBlock("持续时间", history.Duration.ToString(@"hh\:mm\:ss")));
            infoStack.Children.Add(CreateInfoTextBlock("扫描模式", history.ScanMode ?? ""));
            infoStack.Children.Add(CreateInfoTextBlock("开放端口", history.OpenPorts.ToString()));
            infoStack.Children.Add(CreateInfoTextBlock("漏洞总数", history.TotalVulnerabilities.ToString()));
            infoStack.Children.Add(CreateInfoTextBlock("风险分布", $"严重:{history.CriticalCount} 高:{history.HighCount} 中:{history.MediumCount} 低:{history.LowCount}"));
            infoBorder.Child = infoStack;
            Grid.SetRow(infoBorder, 0);
            mainGrid.Children.Add(infoBorder);

            var vulnHeaderBorder = new Border
            {
                Background = new SolidColorBrush(Colors.White),
                CornerRadius = new CornerRadius(8, 8, 0, 0),
                BorderBrush = new SolidColorBrush(Color.FromRgb(0xE0, 0xE0, 0xE0)),
                BorderThickness = new Thickness(1, 1, 1, 0),
                Padding = new Thickness(15),
                Margin = new Thickness(0, 0, 0, 0)
            };

            var vulnHeaderText = new TextBlock
            {
                Text = $"漏洞列表 ({history.Vulnerabilities?.Count ?? 0})",
                FontWeight = FontWeights.Bold,
                FontSize = 14,
                Foreground = new SolidColorBrush(Color.FromRgb(0x2C, 0x3E, 0x50))
            };
            vulnHeaderBorder.Child = vulnHeaderText;
            Grid.SetRow(vulnHeaderBorder, 1);
            mainGrid.Children.Add(vulnHeaderBorder);

            var vulnBorder = new Border
            {
                Background = new SolidColorBrush(Colors.White),
                CornerRadius = new CornerRadius(0, 0, 8, 8),
                BorderBrush = new SolidColorBrush(Color.FromRgb(0xE0, 0xE0, 0xE0)),
                BorderThickness = new Thickness(1, 0, 1, 1),
                Padding = new Thickness(15)
            };

            var vulnDataGrid = new DataGrid
            {
                AutoGenerateColumns = false,
                CanUserAddRows = false,
                GridLinesVisibility = DataGridGridLinesVisibility.Horizontal,
                AlternatingRowBackground = new SolidColorBrush(Color.FromRgb(0xF8, 0xF9, 0xFA)),
                IsReadOnly = true,
                SelectionMode = DataGridSelectionMode.Extended,
                HeadersVisibility = DataGridHeadersVisibility.Column,
                ItemsSource = history.Vulnerabilities ?? new List<VulnerabilityRecord>()
            };

            vulnDataGrid.Columns.Add(new DataGridTextColumn { Header = "CVE编号", Binding = new System.Windows.Data.Binding("CveId"), Width = 130 });
            vulnDataGrid.Columns.Add(new DataGridTextColumn { Header = "漏洞名称", Binding = new System.Windows.Data.Binding("Name"), Width = new DataGridLength(1, DataGridLengthUnitType.Star) });
            vulnDataGrid.Columns.Add(new DataGridTextColumn { Header = "端口", Binding = new System.Windows.Data.Binding("Port"), Width = 60 });
            vulnDataGrid.Columns.Add(new DataGridTextColumn { Header = "服务", Binding = new System.Windows.Data.Binding("Service"), Width = 100 });
            vulnDataGrid.Columns.Add(new DataGridTextColumn { Header = "风险等级", Binding = new System.Windows.Data.Binding("RiskLevel"), Width = 80 });
            vulnDataGrid.Columns.Add(new DataGridTextColumn { Header = "检测方法", Binding = new System.Windows.Data.Binding("DetectionMethod"), Width = 120 });

            vulnBorder.Child = vulnDataGrid;
            Grid.SetRow(vulnBorder, 2);
            mainGrid.Children.Add(vulnBorder);

            detailWindow.Content = mainGrid;
            detailWindow.ShowDialog();
        }

        private UIElement CreateInfoTextBlock(string label, string value)
        {
            var panel = new StackPanel { Orientation = Orientation.Horizontal, Margin = new Thickness(0, 4, 0, 4) };
            panel.Children.Add(new TextBlock
            {
                Text = $"{label}: ",
                FontWeight = FontWeights.SemiBold,
                Width = 90,
                Foreground = new SolidColorBrush(Color.FromRgb(0x7F, 0x8C, 0x8D))
            });
            panel.Children.Add(new TextBlock
            {
                Text = value,
                Foreground = new SolidColorBrush(Color.FromRgb(0x2C, 0x3E, 0x50))
            });
            return panel;
        }

        private int GetTimeRangeDays()
        {
            if (TimeRangeComboBox == null) return 7;

            var selectedItem = TimeRangeComboBox.SelectedItem as ComboBoxItem;
            return selectedItem?.Content?.ToString() switch
            {
                "最近7天" => 7,
                "最近30天" => 30,
                "最近90天" => 90,
                "全部时间" => 3650,
                _ => 7
            };
        }

        private void CalculateOverallStats(List<Services.ScanHistoryItem> jsonHistory, List<ScanHistory> dbHistory)
        {
            jsonHistory ??= new();
            dbHistory ??= new();

            int totalScans = jsonHistory.Count + dbHistory.Count;
            int totalVulns = jsonHistory.Sum(h => h?.VulnerabilitiesCount ?? 0) + dbHistory.Sum(h => h?.TotalVulnerabilities ?? 0);
            int totalPorts = dbHistory.Sum(h => h?.OpenPorts ?? 0);

            int criticalVulns = jsonHistory.Sum(h => h?.RiskLevel switch
            {
                "高" => h.VulnerabilitiesCount,
                "高危" => h.VulnerabilitiesCount,
                _ => 0
            }) + dbHistory.Sum(h => h?.CriticalCount ?? 0 + h?.HighCount ?? 0);

            int totalTargets = jsonHistory.Select(h => h?.TargetIp).Where(t => !string.IsNullOrEmpty(t)).Distinct().Count() +
                               dbHistory.Select(h => h?.Target).Where(t => !string.IsNullOrEmpty(t)).Distinct().Count();

            var allDates = jsonHistory.Select(h => h?.ScanTime.Date ?? DateTime.MinValue)
                .Concat(dbHistory.Select(h => h?.StartTime.Date ?? DateTime.MinValue));
            if (allDates.Any())
            {
                var minDate = allDates.Min();
                var maxDate = allDates.Max();
                var days = (maxDate - minDate).Days + 1;

                if (TimeRangeTextBlock != null) TimeRangeTextBlock.Text = maxDate.ToString("MM-dd");
                if (DaysCountTextBlock != null) DaysCountTextBlock.Text = $"{days} 天";

                double avgScansPerDay = days > 0 ? (double)totalScans / days : 0;
                if (AvgScansPerDayTextBlock != null) AvgScansPerDayTextBlock.Text = $"{avgScansPerDay:F1} 次/天";
            }

            if (TotalScansTextBlock != null) TotalScansTextBlock.Text = totalScans.ToString();
            if (TotalVulnsTextBlock != null) TotalVulnsTextBlock.Text = totalVulns.ToString();
            if (CriticalVulnsTextBlock != null) CriticalVulnsTextBlock.Text = criticalVulns.ToString();
            if (TotalPortsTextBlock != null) TotalPortsTextBlock.Text = totalPorts.ToString();
            if (TotalTargetsTextBlock != null) TotalTargetsTextBlock.Text = totalTargets.ToString();

            double vulnsPerScan = totalScans > 0 ? (double)totalVulns / totalScans : 0;
            if (VulnsPerScanTextBlock != null) VulnsPerScanTextBlock.Text = $"{vulnsPerScan:F1} 个/次";

            double criticalPercent = totalVulns > 0 ? (double)criticalVulns / totalVulns * 100 : 0;
            if (CriticalPercentTextBlock != null) CriticalPercentTextBlock.Text = $"{criticalPercent:F1}%";

            double avgPortsPerScan = totalScans > 0 ? (double)totalPorts / totalScans : 0;
            if (AvgPortsPerScanTextBlock != null) AvgPortsPerScanTextBlock.Text = $"{avgPortsPerScan:F1} 个/次";

            if (UniqueTargetsTextBlock != null) UniqueTargetsTextBlock.Text = $"{totalTargets} 个唯一";
        }

        private void RenderRiskDistribution(List<Services.ScanHistoryItem> jsonHistory, List<ScanHistory> dbHistory)
        {
            jsonHistory ??= new();
            dbHistory ??= new();

            int severe = dbHistory.Sum(h => h?.CriticalCount ?? 0)
                + jsonHistory.Where(h => h?.RiskLevel == "严重").Sum(h => h?.VulnerabilitiesCount ?? 0);
            int high = dbHistory.Sum(h => h?.HighCount ?? 0)
                + jsonHistory.Where(h => h?.RiskLevel == "高" || h?.RiskLevel == "高危").Sum(h => h?.VulnerabilitiesCount ?? 0);
            int medium = dbHistory.Sum(h => h?.MediumCount ?? 0)
                + jsonHistory.Where(h => h?.RiskLevel == "中" || h?.RiskLevel == "中危").Sum(h => h?.VulnerabilitiesCount ?? 0);
            int low = dbHistory.Sum(h => h?.LowCount ?? 0)
                + jsonHistory.Where(h => h?.RiskLevel == "低" || h?.RiskLevel == "低危").Sum(h => h?.VulnerabilitiesCount ?? 0);

            int total = severe + high + medium + low;
            if (total == 0) total = 1;

            var series = new ISeries[]
            {
                new PieSeries<int> { Values = new[] { severe }, Name = "严重", Fill = new SolidColorPaint(SKColors.Red), DataLabelsPaint = new SolidColorPaint(new SKColor(0xFF, 0xFF, 0xFF)) { FontFamily = ChineseFont } },
                new PieSeries<int> { Values = new[] { high }, Name = "高", Fill = new SolidColorPaint(SKColors.Orange), DataLabelsPaint = new SolidColorPaint(new SKColor(0xFF, 0xFF, 0xFF)) { FontFamily = ChineseFont } },
                new PieSeries<int> { Values = new[] { medium }, Name = "中", Fill = new SolidColorPaint(SKColors.Goldenrod), DataLabelsPaint = new SolidColorPaint(new SKColor(0xFF, 0xFF, 0xFF)) { FontFamily = ChineseFont } },
                new PieSeries<int> { Values = new[] { low }, Name = "低", Fill = new SolidColorPaint(SKColors.Green), DataLabelsPaint = new SolidColorPaint(new SKColor(0xFF, 0xFF, 0xFF)) { FontFamily = ChineseFont } }
            };

            if (RiskPieChart != null)
            {
                RiskPieChart.Series = series;
                RiskPieChart.Title = new LabelVisual
                {
                    Text = "风险等级分布",
                    TextSize = 16,
                    Padding = new LiveChartsCore.Drawing.Padding(10),
                    Paint = new SolidColorPaint(new SKColor(0x2C, 0x3E, 0x50)) { FontFamily = ChineseFont }
                };
                RiskPieChart.LegendTextPaint = new SolidColorPaint(new SKColor(0x2C, 0x3E, 0x50)) { FontFamily = ChineseFont };
                RiskPieChart.LegendPosition = LiveChartsCore.Measure.LegendPosition.Bottom;
            }

            RenderRiskDetails("严重", severe, total, System.Windows.Media.Brushes.Red);
            RenderRiskDetails("高", high, total, System.Windows.Media.Brushes.Orange);
            RenderRiskDetails("中", medium, total, System.Windows.Media.Brushes.Goldenrod);
            RenderRiskDetails("低", low, total, System.Windows.Media.Brushes.Green);
        }

        private void RenderRiskDetails(string level, int count, int total, System.Windows.Media.Brush color)
        {
            double percentage = (double)count / total * 100;

            var itemPanel = new StackPanel { Margin = new Thickness(0, 0, 0, 12) };

            var labelPanel = new StackPanel { Orientation = Orientation.Horizontal };
            var ellipse = new System.Windows.Shapes.Ellipse
            {
                Width = 10,
                Height = 10,
                Fill = color,
                Margin = new Thickness(0, 0, 8, 0)
            };
            labelPanel.Children.Add(ellipse);
            labelPanel.Children.Add(new TextBlock
            {
                Text = level,
                FontWeight = FontWeights.SemiBold,
                Width = 40,
                VerticalAlignment = VerticalAlignment.Center
            });
            labelPanel.Children.Add(new TextBlock
            {
                Text = $"{count} ({percentage:F1}%)",
                Foreground = System.Windows.Media.Brushes.Gray,
                VerticalAlignment = VerticalAlignment.Center
            });
            itemPanel.Children.Add(labelPanel);

            var progressBar = new ProgressBar
            {
                Height = 20,
                Maximum = 100,
                Value = percentage,
                Background = System.Windows.Media.Brushes.LightGray,
                Foreground = color
            };
            itemPanel.Children.Add(progressBar);

            RiskDistributionPanel?.Children.Add(itemPanel);
        }

        private void RenderVulnBarChart(List<ScanHistory> dbHistory)
        {
            dbHistory ??= new();

            var last7Days = Enumerable.Range(0, 7)
                .Select(i => DateTime.Now.Date.AddDays(-i))
                .OrderBy(d => d)
                .ToList();

            var severeValues = new List<int>();
            var highValues = new List<int>();
            var labels = new List<string>();

            foreach (var date in last7Days)
            {
                var dayScans = dbHistory.Where(h => h?.StartTime.Date == date).ToList();
                severeValues.Add(dayScans.Sum(h => h?.CriticalCount ?? 0));
                highValues.Add(dayScans.Sum(h => h?.HighCount ?? 0));
                labels.Add(date.ToString("MM-dd"));
            }

            var series = new ISeries[]
            {
                new ColumnSeries<int>
                {
                    Values = severeValues,
                    Name = "严重",
                    Fill = new SolidColorPaint(SKColors.Red),
                    Stroke = new SolidColorPaint(SKColors.Red, 2)
                },
                new ColumnSeries<int>
                {
                    Values = highValues,
                    Name = "高",
                    Fill = new SolidColorPaint(SKColors.Orange),
                    Stroke = new SolidColorPaint(SKColors.Orange, 2)
                }
            };

            if (VulnBarChart != null)
            {
                VulnBarChart.Series = series;
                VulnBarChart.XAxes = new[]
                {
                    new Axis
                    {
                        Labels = labels.ToArray(),
                        LabelsPaint = new SolidColorPaint(new SKColor(0x2C, 0x3E, 0x50)) { FontFamily = ChineseFont }
                    }
                };
                VulnBarChart.YAxes = new[]
                {
                    new Axis
                    {
                        LabelsPaint = new SolidColorPaint(new SKColor(0x2C, 0x3E, 0x50)) { FontFamily = ChineseFont }
                    }
                };
            }
        }

        private void RenderScanTrend(List<Services.ScanHistoryItem> jsonHistory, List<ScanHistory> dbHistory)
        {
            jsonHistory ??= new();
            dbHistory ??= new();

            int timeRangeDays = GetTimeRangeDays();
            var dates = Enumerable.Range(0, timeRangeDays)
                .Select(i => DateTime.Now.Date.AddDays(-i))
                .OrderBy(d => d)
                .ToList();

            var trendData = new List<ScanTrendItem>();
            var scanCountValues = new List<int>();
            var labels = new List<string>();

            foreach (var date in dates)
            {
                var jsonCount = jsonHistory.Count(h => h?.ScanTime.Date == date);
                var dbCount = dbHistory.Count(h => h?.StartTime.Date == date);
                var dayDbScans = dbHistory.Where(h => h?.StartTime.Date == date).ToList();

                var item = new ScanTrendItem
                {
                    Date = date.ToString("MM-dd"),
                    ScanCount = jsonCount + dbCount,
                    PortCount = dayDbScans.Sum(h => h?.OpenPorts ?? 0),
                    VulnerabilityCount = jsonHistory.Where(h => h?.ScanTime.Date == date).Sum(h => h?.VulnerabilitiesCount ?? 0) +
                                        dayDbScans.Sum(h => h?.TotalVulnerabilities ?? 0),
                    CriticalCount = dayDbScans.Sum(h => h?.CriticalCount ?? 0),
                    HighCount = dayDbScans.Sum(h => h?.HighCount ?? 0),
                    MediumCount = dayDbScans.Sum(h => h?.MediumCount ?? 0),
                    LowCount = dayDbScans.Sum(h => h?.LowCount ?? 0)
                };

                trendData.Add(item);
                scanCountValues.Add(item.ScanCount);
                labels.Add(item.Date);
            }

            if (ScanTrendDataGrid != null) ScanTrendDataGrid.ItemsSource = trendData;

            var series = new ISeries[]
            {
                new LineSeries<int>
                {
                    Values = scanCountValues,
                    Name = "扫描次数",
                    Fill = null,
                    Stroke = new SolidColorPaint(new SKColor(0x34, 0x98, 0xDB), 3),
                    GeometryFill = new SolidColorPaint(new SKColor(0x34, 0x98, 0xDB, 100)),
                    GeometryStroke = new SolidColorPaint(new SKColor(0x34, 0x98, 0xDB), 2),
                    GeometrySize = 20
                }
            };

            if (ScanTrendChart != null)
            {
                ScanTrendChart.Series = series;
                ScanTrendChart.XAxes = new[]
                {
                    new Axis
                    {
                        Labels = labels.ToArray(),
                        LabelsPaint = new SolidColorPaint(new SKColor(0x2C, 0x3E, 0x50)) { FontFamily = ChineseFont },
                        LabelsRotation = -45
                    }
                };
                ScanTrendChart.YAxes = new[]
                {
                    new Axis
                    {
                        LabelsPaint = new SolidColorPaint(new SKColor(0x2C, 0x3E, 0x50)) { FontFamily = ChineseFont }
                    }
                };
            }
        }

        private void RenderTopVulnerabilities(List<Services.ScanHistoryItem> jsonHistory, List<ScanHistory> dbHistory)
        {
            var vulnCounts = new Dictionary<string, (int Count, string RiskLevel, string CveId)>();

            foreach (var scan in dbHistory ?? new List<ScanHistory>())
            {
                if (scan?.Vulnerabilities != null)
                {
                    foreach (var vuln in scan.Vulnerabilities)
                    {
                        if (vuln == null) continue;
                        string key = vuln.Name ?? vuln.CveId ?? "Unknown";
                        if (vulnCounts.ContainsKey(key))
                        {
                            var (count, _, _) = vulnCounts[key];
                            vulnCounts[key] = (count + 1, vuln.RiskLevel ?? "Unknown", vuln.CveId ?? "");
                        }
                        else
                        {
                            vulnCounts[key] = (1, vuln.RiskLevel ?? "Unknown", vuln.CveId ?? "");
                        }
                    }
                }
            }

            var topVulns = vulnCounts
                .OrderByDescending(kvp => kvp.Value.Count)
                .Take(15)
                .Select((kvp, index) => new TopVulnerabilityItem
                {
                    Rank = index + 1,
                    Name = kvp.Key,
                    Count = kvp.Value.Count,
                    RiskLevel = kvp.Value.RiskLevel,
                    CveId = kvp.Value.CveId
                })
                .ToList();

            if (TopVulnerabilitiesDataGrid != null) TopVulnerabilitiesDataGrid.ItemsSource = topVulns;

            RenderVulnTypeChart(vulnCounts);
        }

        private void RenderVulnTypeChart(Dictionary<string, (int Count, string RiskLevel, string CveId)> vulnCounts)
        {
            var topTypes = vulnCounts.OrderByDescending(kvp => kvp.Value.Count).Take(10).ToList();

            var values = new List<int>();
            var labels = new List<string>();

            foreach (var (key, value) in topTypes)
            {
                values.Add(value.Count);
                labels.Add(key.Length > 15 ? key.Substring(0, 15) + "..." : key);
            }

            if (VulnTypeChart != null)
            {
                VulnTypeChart.Series = new ISeries[]
                {
                    new ColumnSeries<int>
                    {
                        Values = values,
                        Name = "漏洞数量",
                        Stroke = new SolidColorPaint(SKColors.White, 1),
                        Fill = null
                    }
                };

                VulnTypeChart.XAxes = new[]
                {
                    new Axis
                    {
                        Labels = labels.ToArray(),
                        LabelsRotation = -45,
                        LabelsPaint = new SolidColorPaint(new SKColor(0x2C, 0x3E, 0x50)) { FontFamily = ChineseFont }
                    }
                };
                VulnTypeChart.YAxes = new[]
                {
                    new Axis
                    {
                        LabelsPaint = new SolidColorPaint(new SKColor(0x2C, 0x3E, 0x50)) { FontFamily = ChineseFont }
                    }
                };
            }
        }

        private void RenderPortAnalysis(List<Services.ScanHistoryItem> jsonHistory, List<ScanHistory> dbHistory)
        {
            var portCounts = new Dictionary<int, int>();

            foreach (var scan in dbHistory ?? new List<ScanHistory>())
            {
                if (scan?.Vulnerabilities != null)
                {
                    foreach (var vuln in scan.Vulnerabilities)
                    {
                        if (vuln == null) continue;
                        if (vuln.Port.HasValue && vuln.Port.Value > 0)
                        {
                            if (portCounts.ContainsKey(vuln.Port.Value))
                                portCounts[vuln.Port.Value]++;
                            else
                                portCounts[vuln.Port.Value] = 1;
                        }
                    }
                }
            }

            var topPorts = portCounts.OrderByDescending(kvp => kvp.Value).Take(20).ToList();

            var values = new List<int>();
            var labels = new List<string>();

            foreach (var (port, count) in topPorts)
            {
                values.Add(count);
                labels.Add(port.ToString());
            }

            if (PortChart != null)
            {
                PortChart.Series = new ISeries[]
                {
                    new ColumnSeries<int>
                    {
                        Values = values,
                        Name = "出现次数",
                        Fill = new SolidColorPaint(new SKColor(0x34, 0x98, 0xDB))
                    }
                };

                PortChart.XAxes = new[]
                {
                    new Axis
                    {
                        Labels = labels.ToArray(),
                        LabelsRotation = -45,
                        LabelsPaint = new SolidColorPaint(new SKColor(0x2C, 0x3E, 0x50)) { FontFamily = ChineseFont }
                    }
                };
                PortChart.YAxes = new[]
                {
                    new Axis
                    {
                        LabelsPaint = new SolidColorPaint(new SKColor(0x2C, 0x3E, 0x50)) { FontFamily = ChineseFont }
                    }
                };
            }
        }

        private void RenderServiceDistribution(List<Services.ScanHistoryItem> jsonHistory, List<ScanHistory> dbHistory)
        {
            ServiceDistributionPanel?.Children.Clear();

            var serviceCounts = new Dictionary<string, int>();

            foreach (var scan in dbHistory ?? new List<ScanHistory>())
            {
                if (scan?.Vulnerabilities != null)
                {
                    foreach (var vuln in scan.Vulnerabilities)
                    {
                        if (vuln == null) continue;
                        string service = string.IsNullOrEmpty(vuln.Service) ? "Unknown" : vuln.Service;
                        if (serviceCounts.ContainsKey(service))
                            serviceCounts[service]++;
                        else
                            serviceCounts[service] = 1;
                    }
                }
            }

            var topServices = serviceCounts.OrderByDescending(kvp => kvp.Value).Take(15);
            int total = serviceCounts.Values.Sum();
            if (total == 0) total = 1;

            foreach (var kvp in topServices)
            {
                double percentage = (double)kvp.Value / total * 100;

                var itemPanel = new StackPanel { Margin = new Thickness(0, 0, 0, 8) };

                var labelPanel = new StackPanel { Orientation = Orientation.Horizontal };
                labelPanel.Children.Add(new TextBlock
                {
                    Text = kvp.Key,
                    FontWeight = FontWeights.SemiBold,
                    Width = 120
                });
                labelPanel.Children.Add(new TextBlock
                {
                    Text = $"{kvp.Value} ({percentage:F1}%)",
                    Foreground = System.Windows.Media.Brushes.Gray
                });
                itemPanel.Children.Add(labelPanel);

                var progressBar = new ProgressBar
                {
                    Height = 15,
                    Maximum = 100,
                    Value = percentage,
                    Background = System.Windows.Media.Brushes.LightGray,
                    Foreground = System.Windows.Media.Brushes.SteelBlue
                };
                itemPanel.Children.Add(progressBar);

                ServiceDistributionPanel?.Children.Add(itemPanel);
            }
        }

        private void RenderScanHistory(List<Services.ScanHistoryItem> jsonHistory, List<ScanHistory> dbHistory)
        {
            var combinedHistory = new List<ScanHistoryRecord>();

            foreach (var item in (jsonHistory ?? new()).OrderByDescending(h => h?.ScanTime))
            {
                if (item == null) continue;
                combinedHistory.Add(new ScanHistoryRecord
                {
                    ScanTime = item.ScanTime,
                    TargetIp = item.TargetIp ?? "",
                    ScanType = item.ScanType ?? "",
                    OpenPortsCount = 0,
                    VulnerabilitiesCount = item.VulnerabilitiesCount,
                    RiskLevel = item.RiskLevel ?? "",
                    ScanId = item.ScanId ?? ""
                });
            }

            foreach (var item in (dbHistory ?? new()).OrderByDescending(h => h?.StartTime))
            {
                if (item == null) continue;
                combinedHistory.Add(new ScanHistoryRecord
                {
                    ScanTime = item.StartTime,
                    TargetIp = item.Target ?? "",
                    ScanType = item.ScanMode ?? "",
                    OpenPortsCount = item.OpenPorts,
                    VulnerabilitiesCount = item.TotalVulnerabilities,
                    RiskLevel = GetRiskLevel(item),
                    ScanId = item.ScanId ?? ""
                });
            }

            if (ScanHistoryDataGrid != null)
                ScanHistoryDataGrid.ItemsSource = combinedHistory.OrderByDescending(h => h.ScanTime).ToList();
        }

        private string GetRiskLevel(ScanHistory history)
        {
            if (history == null) return "信息";
            if (history.CriticalCount > 0) return "严重";
            if (history.HighCount > 0) return "高";
            if (history.MediumCount > 0) return "中";
            if (history.LowCount > 0) return "低";
            return "信息";
        }

        private void ExportStatisticsToFile(string filePath)
        {
            try
            {
                var content = new System.Text.StringBuilder();
                content.AppendLine("=====================================");
                content.AppendLine("网络安全漏洞扫描 - 统计分析报告");
                content.AppendLine($"生成时间: {DateTime.Now:yyyy-MM-dd HH:mm:ss}");
                content.AppendLine("=====================================");
                content.AppendLine();

                content.AppendLine("【总体统计】");
                content.AppendLine($"总扫描次数: {TotalScansTextBlock?.Text ?? "N/A"}");
                content.AppendLine($"总漏洞数: {TotalVulnsTextBlock?.Text ?? "N/A"}");
                content.AppendLine($"严重/高漏洞: {CriticalVulnsTextBlock?.Text ?? "N/A"}");
                content.AppendLine($"开放端口: {TotalPortsTextBlock?.Text ?? "N/A"}");
                content.AppendLine($"扫描目标: {TotalTargetsTextBlock?.Text ?? "N/A"}");
                content.AppendLine($"统计周期: {TimeRangeTextBlock?.Text ?? "N/A"} ({DaysCountTextBlock?.Text ?? "N/A"})");
                content.AppendLine();

                if (ScanTrendDataGrid?.ItemsSource is System.Collections.IEnumerable trendItems)
                {
                    content.AppendLine("【扫描趋势明细】");
                    foreach (var item in trendItems)
                    {
                        if (item is ScanTrendItem trend)
                        {
                            content.AppendLine($"{trend.Date}: 扫描{trend.ScanCount}次, " +
                                             $"漏洞{trend.VulnerabilityCount}个, " +
                                             $"严重{trend.CriticalCount}个, 高{trend.HighCount}个");
                        }
                    }
                    content.AppendLine();
                }

                System.IO.File.WriteAllText(filePath, content.ToString(), System.Text.Encoding.UTF8);
                MessageBox.Show($"统计报告已导出到:\n{filePath}", "导出成功", MessageBoxButton.OK, MessageBoxImage.Information);
            }
            catch (Exception ex)
            {
                MessageBox.Show($"导出失败: {ex.Message}", "错误", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }
    }

    public class ScanTrendItem
    {
        public string Date { get; set; } = "";
        public int ScanCount { get; set; }
        public int PortCount { get; set; }
        public int VulnerabilityCount { get; set; }
        public int CriticalCount { get; set; }
        public int HighCount { get; set; }
        public int MediumCount { get; set; }
        public int LowCount { get; set; }
    }

    public class TopVulnerabilityItem
    {
        public int Rank { get; set; }
        public string Name { get; set; } = "";
        public string CveId { get; set; } = "";
        public int Count { get; set; }
        public string RiskLevel { get; set; } = "";
    }

    public class ScanHistoryRecord
    {
        public DateTime ScanTime { get; set; }
        public string TargetIp { get; set; } = "";
        public string ScanType { get; set; } = "";
        public int OpenPortsCount { get; set; }
        public int VulnerabilitiesCount { get; set; }
        public string RiskLevel { get; set; } = "";
        public string ScanId { get; set; } = "";
    }
}
