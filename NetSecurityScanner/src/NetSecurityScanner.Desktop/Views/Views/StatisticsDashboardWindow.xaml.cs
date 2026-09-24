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
using System.Windows.Threading;

namespace NetSecurityScanner.Views
{
    public partial class StatisticsDashboardWindow : Window
    {
        private readonly JsonDatabaseService _jsonDatabaseService;
        private readonly ScanHistoryService _scanHistoryService;
        private List<CompleteScanResult> _jsonResults = new();
        private const string ChineseFont = "Microsoft YaHei";
        private DispatcherTimer _autoRefreshTimer;
        private bool _isAutoRefreshing = false;
#pragma warning disable CS0414
        private string _currentGranularity = "Month";
#pragma warning restore CS0414
        private DateTime? _customStartDate;
        private DateTime? _customEndDate;

        public StatisticsDashboardWindow()
        {
            InitializeComponent();
            _jsonDatabaseService = new JsonDatabaseService();

            try { _scanHistoryService = new ScanHistoryService(); }
            catch { _scanHistoryService = null; }

            Loaded += StatisticsDashboardWindow_Loaded;
            SetupAutoRefreshTimer();
        }

        private void SetupAutoRefreshTimer()
        {
            _autoRefreshTimer = new DispatcherTimer
            {
                Interval = TimeSpan.FromSeconds(60)
            };
            _autoRefreshTimer.Tick += async (s, e) =>
            {
                if (!_isAutoRefreshing)
                {
                    _isAutoRefreshing = true;
                    await LoadStatisticsAsync();
                    _isAutoRefreshing = false;
                }
            };
        }

        private void AutoRefreshCheckBox_Changed(object sender, RoutedEventArgs e)
        {
            if (AutoRefreshCheckBox?.IsChecked == true)
                _autoRefreshTimer.Start();
            else
                _autoRefreshTimer.Stop();
        }

        private void GranularityRadioButton_Changed(object sender, RoutedEventArgs e)
        {
            if (GranularityDay?.IsChecked == true) _currentGranularity = "Day";
            else if (GranularityWeek?.IsChecked == true) _currentGranularity = "Week";
            else _currentGranularity = "Month";
        }

        private void CustomDatePicker_SelectedDateChanged(object sender, SelectionChangedEventArgs e)
        {
        }

        private async void ApplyCustomDateBtn_Click(object sender, RoutedEventArgs e)
        {
            var startDate = CustomStartDatePicker?.SelectedDate;
            var endDate = CustomEndDatePicker?.SelectedDate;

            if (startDate == null || endDate == null)
            {
                MessageBox.Show("请选择开始日期和结束日期", "提示", MessageBoxButton.OK, MessageBoxImage.Information);
                return;
            }

            if (startDate > endDate)
            {
                MessageBox.Show("开始日期不能晚于结束日期", "提示", MessageBoxButton.OK, MessageBoxImage.Warning);
                return;
            }

            _customStartDate = startDate;
            _customEndDate = endDate;

            if (TimeRangeComboBox != null)
            {
                var customItem = TimeRangeComboBox.Items.Cast<ComboBoxItem>()
                    .FirstOrDefault(x => x.Content?.ToString() == "自定义");
                if (customItem != null)
                {
                    TimeRangeComboBox.SelectedItem = customItem;
                }
            }

            await LoadStatisticsAsync();
        }

        private void ExportButton_Click(object sender, RoutedEventArgs e)
        {
            var formatDialog = new Window
            {
                Title = "导出格式选择",
                Width = 300,
                Height = 180,
                WindowStartupLocation = WindowStartupLocation.CenterOwner,
                Owner = this,
                ResizeMode = ResizeMode.NoResize,
                Background = new SolidColorBrush(Color.FromRgb(0xF5, 0xF7, 0xFA))
            };

            var stackPanel = new StackPanel { Margin = new Thickness(20) };
            stackPanel.Children.Add(new TextBlock
            {
                Text = "请选择导出格式：",
                FontSize = 14,
                FontWeight = FontWeights.SemiBold,
                Margin = new Thickness(0, 0, 0, 15)
            });

            var txtButton = new Button
            {
                Content = "📄 导出为 TXT 文本",
                Height = 36,
                Margin = new Thickness(0, 5, 0, 5),
                Background = new SolidColorBrush(Color.FromRgb(0x34, 0x98, 0xDB)),
                Foreground = Brushes.White,
                BorderThickness = new Thickness(0)
            };

            var csvButton = new Button
            {
                Content = "📊 导出为 CSV 表格",
                Height = 36,
                Margin = new Thickness(0, 5, 0, 5),
                Background = new SolidColorBrush(Color.FromRgb(0x27, 0xAE, 0x60)),
                Foreground = Brushes.White,
                BorderThickness = new Thickness(0)
            };

            txtButton.Click += (s, args) =>
            {
                formatDialog.Close();
                ExportToTxt();
            };

            csvButton.Click += (s, args) =>
            {
                formatDialog.Close();
                ExportToCsv();
            };

            stackPanel.Children.Add(txtButton);
            stackPanel.Children.Add(csvButton);
            formatDialog.Content = stackPanel;
            formatDialog.ShowDialog();
        }

        private void ExportToTxt()
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

        private void ExportToCsv()
        {
            var dialog = new Microsoft.Win32.SaveFileDialog
            {
                Filter = "CSV Files (*.csv)|*.csv|All Files (*.*)|*.*",
                FileName = $"StatisticsReport_{DateTime.Now:yyyyMMdd_HHmmss}.csv"
            };

            if (dialog.ShowDialog() == true)
            {
                try
                {
                    var csv = new System.Text.StringBuilder();
                    csv.AppendLine("日期,扫描次数,开放端口,漏洞总数,严重,高危,中危,低危");

                    if (ScanTrendDataGrid?.ItemsSource is System.Collections.IEnumerable trendItems)
                    {
                        foreach (var item in trendItems)
                        {
                            if (item is ScanTrendItem trend)
                            {
                                csv.AppendLine($"{trend.Date},{trend.ScanCount},{trend.PortCount}," +
                                             $"{trend.VulnerabilityCount},{trend.CriticalCount}," +
                                             $"{trend.HighCount},{trend.MediumCount},{trend.LowCount}");
                            }
                        }
                    }

                    csv.AppendLine();
                    csv.AppendLine("=== 总体统计 ===");
                    csv.AppendLine($"总扫描次数,{TotalScansTextBlock?.Text ?? "N/A"}");
                    csv.AppendLine($"总漏洞数,{TotalVulnsTextBlock?.Text ?? "N/A"}");
                    csv.AppendLine($"严重/高危,{CriticalVulnsTextBlock?.Text ?? "N/A"}");
                    csv.AppendLine($"开放端口,{TotalPortsTextBlock?.Text ?? "N/A"}");
                    csv.AppendLine($"扫描目标,{TotalTargetsTextBlock?.Text ?? "N/A"}");

                    System.IO.File.WriteAllText(dialog.FileName, csv.ToString(), System.Text.Encoding.UTF8);
                    MessageBox.Show($"CSV报告已导出到:\n{dialog.FileName}", "导出成功", MessageBoxButton.OK, MessageBoxImage.Information);
                }
                catch (Exception ex)
                {
                    MessageBox.Show($"导出CSV失败: {ex.Message}", "错误", MessageBoxButton.OK, MessageBoxImage.Error);
                }
            }
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
            if (TimeRangeComboBox == null) return;

            var selectedItem = TimeRangeComboBox.SelectedItem as ComboBoxItem;
            var content = selectedItem?.Content?.ToString();

            if (content == "自定义")
            {
                if (_customStartDate.HasValue && _customEndDate.HasValue)
                {
                    await LoadStatisticsAsync();
                }
            }
            else
            {
                _customStartDate = null;
                _customEndDate = null;
                await LoadStatisticsAsync();
            }
        }

        private async void RiskFilterComboBox_SelectionChanged(object sender, SelectionChangedEventArgs e)
        {
            await LoadStatisticsAsync();
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

                var timeRange = GetSelectedTimeRange();
                if (timeRange == null) return;

                DateTime startDate = timeRange.Value.Start;
                DateTime endDate = timeRange.Value.End;

                var filteredJsonResults = jsonResults.Where(h => h != null && h.ScanTime >= startDate && h.ScanTime <= endDate).ToList();
                var filteredDbResults = dbResults.Where(h => h != null && h.StartTime >= startDate && h.StartTime <= endDate).ToList();

                RiskDistributionPanel?.Children.Clear();

                try { CalculateOverallStats(filteredJsonResults, filteredDbResults); } catch { }
                try { RenderPeriodComparisonCards(jsonResults, dbResults); } catch { }
                try { RenderRiskDistribution(filteredJsonResults, filteredDbResults); } catch { }
                try { RenderVulnBarChart(filteredDbResults); } catch { }
                try { RenderScanTrend(filteredJsonResults, filteredDbResults); } catch { }
                try { RenderTopVulnerabilities(filteredJsonResults, filteredDbResults); } catch { }
                try { RenderPortAnalysis(filteredJsonResults, filteredDbResults); } catch { }
                try { RenderServiceDistribution(filteredJsonResults, filteredDbResults); } catch { }
                try { RenderScanHistory(filteredJsonResults, filteredDbResults); } catch { }
                try { RenderTimeDimensionAnalysis(); } catch { }
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

        private (DateTime Start, DateTime End, string Label)? GetSelectedTimeRange()
        {
            if (TimeRangeComboBox == null) return (DateTime.Now.AddDays(-7), DateTime.Now, "最近7天");

            var selectedItem = TimeRangeComboBox.SelectedItem as ComboBoxItem;
            var content = selectedItem?.Content?.ToString() ?? "本周";
            var now = DateTime.Now;

            return content switch
            {
                "本周" => (GetStartOfWeek(now), now, "本周"),
                "本月" => (new DateTime(now.Year, now.Month, 1), now, "本月"),
                "本季度" => (GetStartOfQuarter(now), now, "本季度"),
                "本年度" => (new DateTime(now.Year, 1, 1), now, "本年度"),
                "最近7天" => (now.AddDays(-7), now, "最近7天"),
                "最近30天" => (now.AddDays(-30), now, "最近30天"),
                "最近90天" => (now.AddDays(-90), now, "最近90天"),
                "全部时间" => (DateTime.MinValue.AddYears(1900), now, "全部时间"),
                "自定义..." => (_customStartDate ?? now.AddDays(-7), _customEndDate ?? now, "自定义"),
                _ => (now.AddDays(-7), now, "最近7天")
            };
        }

        private DateTime GetStartOfWeek(DateTime date)
        {
            int diff = (7 + (date.DayOfWeek - DayOfWeek.Monday)) % 7;
            return date.AddDays(-diff).Date;
        }

        private DateTime GetStartOfQuarter(DateTime date)
        {
            int quarterMonth = ((date.Month - 1) / 3) * 3 + 1;
            return new DateTime(date.Year, quarterMonth, 1);
        }

        private int GetTimeRangeDays()
        {
            var range = GetSelectedTimeRange();
            if (range == null) return 7;
            return Math.Max(1, (int)(range.Value.End - range.Value.Start).TotalDays);
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

        private void RenderPeriodComparisonCards(List<Services.ScanHistoryItem> jsonHistory, List<ScanHistory> dbHistory)
        {
            var now = DateTime.Now;

            var weekStats = CalculatePeriodStats(jsonHistory, dbHistory, GetStartOfWeek(now), now);
            var monthStats = CalculatePeriodStats(jsonHistory, dbHistory, new DateTime(now.Year, now.Month, 1), now);
            var quarterStats = CalculatePeriodStats(jsonHistory, dbHistory, GetStartOfQuarter(now), now);
            var yearStats = CalculatePeriodStats(jsonHistory, dbHistory, new DateTime(now.Year, 1, 1), now);

            if (WeekScanCountText != null) WeekScanCountText.Text = weekStats.CurrentCount.ToString();
            if (WeekVulnCountText != null) WeekVulnCountText.Text = weekStats.CurrentVulnCount.ToString();
            if (WeekScanChangeText != null)
            {
                WeekScanChangeText.Text = FormatChange(weekStats.CurrentCount, weekStats.PreviousCount);
                WeekScanChangeText.Foreground = GetChangeBrush(weekStats.ChangePercent);
            }

            if (MonthScanCountText != null) MonthScanCountText.Text = monthStats.CurrentCount.ToString();
            if (MonthVulnCountText != null) MonthVulnCountText.Text = monthStats.CurrentVulnCount.ToString();
            if (MonthScanChangeText != null)
            {
                MonthScanChangeText.Text = FormatChange(monthStats.CurrentCount, monthStats.PreviousCount);
                MonthScanChangeText.Foreground = GetChangeBrush(monthStats.ChangePercent);
            }

            if (QuarterScanCountText != null) QuarterScanCountText.Text = quarterStats.CurrentCount.ToString();
            if (QuarterVulnCountText != null) QuarterVulnCountText.Text = quarterStats.CurrentVulnCount.ToString();
            if (QuarterScanChangeText != null)
            {
                QuarterScanChangeText.Text = FormatChange(quarterStats.CurrentCount, quarterStats.PreviousCount);
                QuarterScanChangeText.Foreground = GetChangeBrush(quarterStats.ChangePercent);
            }

            if (YearScanCountText != null) YearScanCountText.Text = yearStats.CurrentCount.ToString();
            if (YearVulnCountText != null) YearVulnCountText.Text = yearStats.CurrentVulnCount.ToString();
            if (YearScanChangeText != null)
            {
                YearScanChangeText.Text = FormatChange(yearStats.CurrentCount, yearStats.PreviousCount);
                YearScanChangeText.Foreground = GetChangeBrush(yearStats.ChangePercent);
            }
        }

        private PeriodStatisticsResult CalculatePeriodStats(
            List<Services.ScanHistoryItem> jsonHistory,
            List<ScanHistory> dbHistory,
            DateTime startDate,
            DateTime endDate)
        {
            var periodLength = Math.Max(1, (endDate - startDate).Days);
            var previousStart = startDate.AddDays(-periodLength);
            var previousEnd = startDate.AddDays(-1);

            var currentJson = jsonHistory.Where(h => h != null && h.ScanTime >= startDate && h.ScanTime <= endDate).ToList();
            var currentDb = dbHistory.Where(h => h != null && h.StartTime >= startDate && h.StartTime <= endDate).ToList();
            var previousJson = jsonHistory.Where(h => h != null && h.ScanTime >= previousStart && h.ScanTime <= previousEnd).ToList();
            var previousDb = dbHistory.Where(h => h != null && h.StartTime >= previousStart && h.StartTime <= previousEnd).ToList();

            int currentCount = currentJson.Count + currentDb.Count;
            int previousCount = previousJson.Count + previousDb.Count;

            int currentVulnCount = currentJson.Sum(h => h?.VulnerabilitiesCount ?? 0) + currentDb.Sum(h => h?.TotalVulnerabilities ?? 0);
            int currentPortCount = currentDb.Sum(h => h?.OpenPorts ?? 0);

            double changePercent = previousCount > 0 ? ((double)(currentCount - previousCount) / previousCount) * 100 : (currentCount > 0 ? 100 : 0);

            return new PeriodStatisticsResult
            {
                CurrentCount = currentCount,
                PreviousCount = previousCount,
                CurrentVulnCount = currentVulnCount,
                CurrentPortCount = currentPortCount,
                ChangePercent = changePercent
            };
        }

        private string FormatChange(int current, int previous)
        {
            if (previous == 0) return current > 0 ? "新增" : "无数据";
            int change = current - previous;
            string sign = change > 0 ? "↑" : "↓";
            double percent = Math.Abs((double)change / previous * 100);
            return $"{sign}{Math.Abs(change)}次 ({percent:F0}%)";
        }

        private System.Windows.Media.Brush GetChangeBrush(double changePercent)
        {
            if (changePercent > 0) return System.Windows.Media.Brushes.Green;
            if (changePercent < 0) return System.Windows.Media.Brushes.Red;
            return System.Windows.Media.Brushes.Gray;
        }

        private class PeriodStatisticsResult
        {
            public int CurrentCount { get; set; }
            public int PreviousCount { get; set; }
            public int CurrentVulnCount { get; set; }
            public int CurrentPortCount { get; set; }
            public double ChangePercent { get; set; }
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

            var severePct = (double)severe / total * 100;
            var highPct = (double)high / total * 100;
            var mediumPct = (double)medium / total * 100;
            var lowPct = (double)low / total * 100;

            var series = new ISeries[]
            {
                new PieSeries<int>
                {
                    Values = new[] { severe },
                    Name = "严重",
                    Fill = new SolidColorPaint(SKColors.Red),
                    DataLabelsPaint = new SolidColorPaint(new SKColor(0xFF, 0xFF, 0xFF)) { FontFamily = ChineseFont },
                    DataLabelsSize = 12,
                    DataLabelsPosition = LiveChartsCore.Measure.PolarLabelsPosition.Middle,
                    DataLabelsFormatter = point => severePct > 5 ? $"{severePct:F0}%" : "",
                    ToolTipLabelFormatter = point => $"严重漏洞: {severe}个 ({severePct:F1}%)"
                },
                new PieSeries<int>
                {
                    Values = new[] { high },
                    Name = "高",
                    Fill = new SolidColorPaint(SKColors.Orange),
                    DataLabelsPaint = new SolidColorPaint(new SKColor(0xFF, 0xFF, 0xFF)) { FontFamily = ChineseFont },
                    DataLabelsSize = 12,
                    DataLabelsPosition = LiveChartsCore.Measure.PolarLabelsPosition.Middle,
                    DataLabelsFormatter = point => highPct > 5 ? $"{highPct:F0}%" : "",
                    ToolTipLabelFormatter = point => $"高危漏洞: {high}个 ({highPct:F1}%)"
                },
                new PieSeries<int>
                {
                    Values = new[] { medium },
                    Name = "中",
                    Fill = new SolidColorPaint(SKColors.Goldenrod),
                    DataLabelsPaint = new SolidColorPaint(new SKColor(0xFF, 0xFF, 0xFF)) { FontFamily = ChineseFont },
                    DataLabelsSize = 12,
                    DataLabelsPosition = LiveChartsCore.Measure.PolarLabelsPosition.Middle,
                    DataLabelsFormatter = point => mediumPct > 5 ? $"{mediumPct:F0}%" : "",
                    ToolTipLabelFormatter = point => $"中危漏洞: {medium}个 ({mediumPct:F1}%)"
                },
                new PieSeries<int>
                {
                    Values = new[] { low },
                    Name = "低",
                    Fill = new SolidColorPaint(SKColors.Green),
                    DataLabelsPaint = new SolidColorPaint(new SKColor(0xFF, 0xFF, 0xFF)) { FontFamily = ChineseFont },
                    DataLabelsSize = 12,
                    DataLabelsPosition = LiveChartsCore.Measure.PolarLabelsPosition.Middle,
                    DataLabelsFormatter = point => lowPct > 5 ? $"{lowPct:F0}%" : "",
                    ToolTipLabelFormatter = point => $"低危漏洞: {low}个 ({lowPct:F1}%)"
                }
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
                RiskPieChart.TooltipTextPaint = new SolidColorPaint(new SKColor(0x2C, 0x3E, 0x50)) { FontFamily = ChineseFont };
                RiskPieChart.TooltipBackgroundPaint = new SolidColorPaint(new SKColor(0xFF, 0xFF, 0xFF));
                RiskPieChart.InitialRotation = -90;
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
                    Stroke = new SolidColorPaint(SKColors.Red, 2),
                    DataLabelsPaint = new SolidColorPaint(new SKColor(0x2C, 0x3E, 0x50)) { FontFamily = ChineseFont },
                    DataLabelsSize = 11,
                    DataLabelsPosition = LiveChartsCore.Measure.DataLabelsPosition.Top,
                    DataLabelsFormatter = point => $"{point.Coordinate.PrimaryValue}",
                    YToolTipLabelFormatter = point => $"严重: {point.Coordinate.PrimaryValue}个"
                },
                new ColumnSeries<int>
                {
                    Values = highValues,
                    Name = "高",
                    Fill = new SolidColorPaint(SKColors.Orange),
                    Stroke = new SolidColorPaint(SKColors.Orange, 2),
                    DataLabelsPaint = new SolidColorPaint(new SKColor(0x2C, 0x3E, 0x50)) { FontFamily = ChineseFont },
                    DataLabelsSize = 11,
                    DataLabelsPosition = LiveChartsCore.Measure.DataLabelsPosition.Top,
                    DataLabelsFormatter = point => $"{point.Coordinate.PrimaryValue}",
                    YToolTipLabelFormatter = point => $"高危: {point.Coordinate.PrimaryValue}个"
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
                        LabelsPaint = new SolidColorPaint(new SKColor(0x2C, 0x3E, 0x50)) { FontFamily = ChineseFont },
                        SeparatorsPaint = new SolidColorPaint(new SKColor(0xE8, 0xE8, 0xE8), 1)
                    }
                };
                VulnBarChart.YAxes = new[]
                {
                    new Axis
                    {
                        LabelsPaint = new SolidColorPaint(new SKColor(0x2C, 0x3E, 0x50)) { FontFamily = ChineseFont },
                        SeparatorsPaint = new SolidColorPaint(new SKColor(0xE8, 0xE8, 0xE8), 1)
                    }
                };
                VulnBarChart.TooltipTextPaint = new SolidColorPaint(new SKColor(0x2C, 0x3E, 0x50)) { FontFamily = ChineseFont };
                VulnBarChart.TooltipBackgroundPaint = new SolidColorPaint(new SKColor(0xFF, 0xFF, 0xFF));
                VulnBarChart.LegendTextPaint = new SolidColorPaint(new SKColor(0x2C, 0x3E, 0x50)) { FontFamily = ChineseFont };
                VulnBarChart.LegendPosition = LiveChartsCore.Measure.LegendPosition.Bottom;
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
            var vulnCountValues = new List<int>();
            var portCountValues = new List<int>();
            var labels = new List<string>();

            foreach (var date in dates)
            {
                var jsonCount = jsonHistory.Count(h => h?.ScanTime.Date == date);
                var dbCount = dbHistory.Count(h => h?.StartTime.Date == date);
                var dayDbScans = dbHistory.Where(h => h?.StartTime.Date == date).ToList();

                var vulnCount = jsonHistory.Where(h => h?.ScanTime.Date == date).Sum(h => h?.VulnerabilitiesCount ?? 0) +
                              dayDbScans.Sum(h => h?.TotalVulnerabilities ?? 0);
                var portCount = dayDbScans.Sum(h => h?.OpenPorts ?? 0);

                var item = new ScanTrendItem
                {
                    Date = date.ToString("MM-dd"),
                    ScanCount = jsonCount + dbCount,
                    PortCount = portCount,
                    VulnerabilityCount = vulnCount,
                    CriticalCount = dayDbScans.Sum(h => h?.CriticalCount ?? 0),
                    HighCount = dayDbScans.Sum(h => h?.HighCount ?? 0),
                    MediumCount = dayDbScans.Sum(h => h?.MediumCount ?? 0),
                    LowCount = dayDbScans.Sum(h => h?.LowCount ?? 0)
                };

                trendData.Add(item);
                scanCountValues.Add(item.ScanCount);
                vulnCountValues.Add(item.VulnerabilityCount);
                portCountValues.Add(item.PortCount);
                labels.Add(item.Date);
            }

            if (ScanTrendDataGrid != null) ScanTrendDataGrid.ItemsSource = trendData;

            var series = new ISeries[]
            {
                new LineSeries<int>
                {
                    Values = scanCountValues,
                    Name = "扫描次数",
                    Fill = new SolidColorPaint(new SKColor(0x34, 0x98, 0xDB, 50)),
                    Stroke = new SolidColorPaint(new SKColor(0x34, 0x98, 0xDB), 3),
                    GeometryFill = new SolidColorPaint(new SKColor(0x34, 0x98, 0xDB)),
                    GeometryStroke = new SolidColorPaint(SKColors.White, 2),
                    GeometrySize = 12,
                    YToolTipLabelFormatter = point => $"扫描: {point.Coordinate.PrimaryValue}次",
                    DataLabelsPaint = new SolidColorPaint(new SKColor(0x34, 0x98, 0xDB)) { FontFamily = ChineseFont },
                    DataLabelsSize = 10,
                    DataLabelsPosition = LiveChartsCore.Measure.DataLabelsPosition.Top,
                    DataLabelsFormatter = point => point.Coordinate.PrimaryValue > 0 ? $"{point.Coordinate.PrimaryValue}" : ""
                },
                new LineSeries<int>
                {
                    Values = vulnCountValues,
                    Name = "漏洞数",
                    Fill = new SolidColorPaint(new SKColor(0xE7, 0x4C, 0x3C, 50)),
                    Stroke = new SolidColorPaint(new SKColor(0xE7, 0x4C, 0x3C), 3),
                    GeometryFill = new SolidColorPaint(new SKColor(0xE7, 0x4C, 0x3C)),
                    GeometryStroke = new SolidColorPaint(SKColors.White, 2),
                    GeometrySize = 12,
                    YToolTipLabelFormatter = point => $"漏洞: {point.Coordinate.PrimaryValue}个",
                    DataLabelsPaint = new SolidColorPaint(new SKColor(0xE7, 0x4C, 0x3C)) { FontFamily = ChineseFont },
                    DataLabelsSize = 10,
                    DataLabelsPosition = LiveChartsCore.Measure.DataLabelsPosition.Top,
                    DataLabelsFormatter = point => point.Coordinate.PrimaryValue > 0 ? $"{point.Coordinate.PrimaryValue}" : ""
                },
                new LineSeries<int>
                {
                    Values = portCountValues,
                    Name = "开放端口",
                    Fill = new SolidColorPaint(new SKColor(0x27, 0xAE, 0x60, 50)),
                    Stroke = new SolidColorPaint(new SKColor(0x27, 0xAE, 0x60), 3),
                    GeometryFill = new SolidColorPaint(new SKColor(0x27, 0xAE, 0x60)),
                    GeometryStroke = new SolidColorPaint(SKColors.White, 2),
                    GeometrySize = 12,
                    YToolTipLabelFormatter = point => $"端口: {point.Coordinate.PrimaryValue}个",
                    DataLabelsPaint = new SolidColorPaint(new SKColor(0x27, 0xAE, 0x60)) { FontFamily = ChineseFont },
                    DataLabelsSize = 10,
                    DataLabelsPosition = LiveChartsCore.Measure.DataLabelsPosition.Top,
                    DataLabelsFormatter = point => point.Coordinate.PrimaryValue > 0 ? $"{point.Coordinate.PrimaryValue}" : ""
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
                        LabelsRotation = -45,
                        SeparatorsPaint = new SolidColorPaint(new SKColor(0xE8, 0xE8, 0xE8), 1)
                    }
                };
                ScanTrendChart.YAxes = new[]
                {
                    new Axis
                    {
                        LabelsPaint = new SolidColorPaint(new SKColor(0x2C, 0x3E, 0x50)) { FontFamily = ChineseFont },
                        SeparatorsPaint = new SolidColorPaint(new SKColor(0xE8, 0xE8, 0xE8), 1)
                    }
                };
                ScanTrendChart.TooltipTextPaint = new SolidColorPaint(new SKColor(0x2C, 0x3E, 0x50)) { FontFamily = ChineseFont };
                ScanTrendChart.TooltipBackgroundPaint = new SolidColorPaint(new SKColor(0xFF, 0xFF, 0xFF));
                ScanTrendChart.LegendTextPaint = new SolidColorPaint(new SKColor(0x2C, 0x3E, 0x50)) { FontFamily = ChineseFont };
                ScanTrendChart.LegendPosition = LiveChartsCore.Measure.LegendPosition.Bottom;
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

            var riskColors = new SKColor[]
            {
                new SKColor(0xE7, 0x4C, 0x3C),
                new SKColor(0xE6, 0x7E, 0x22),
                new SKColor(0xF3, 0x9C, 0x12),
                new SKColor(0x27, 0xAE, 0x60),
                new SKColor(0x34, 0x98, 0xDB)
            };

            if (VulnTypeChart != null)
            {
                VulnTypeChart.Series = new ISeries[]
                {
                    new ColumnSeries<int>
                    {
                        Values = values,
                        Name = "漏洞数量",
                        Stroke = new SolidColorPaint(SKColors.White, 2),
                        Fill = new SolidColorPaint(new SKColor(0x9B, 0x59, 0xB6)),
                        DataLabelsPaint = new SolidColorPaint(new SKColor(0x2C, 0x3E, 0x50)) { FontFamily = ChineseFont },
                        DataLabelsSize = 11,
                        DataLabelsPosition = LiveChartsCore.Measure.DataLabelsPosition.Top,
                        DataLabelsFormatter = point => $"{point.Coordinate.PrimaryValue}",
                        YToolTipLabelFormatter = point =>
                        {
                            var idx = (int)point.Coordinate.SecondaryValue;
                            if (idx >= 0 && idx < topTypes.Count)
                            {
                                var item = topTypes[idx];
                                return $"{item.Key}\n出现: {item.Value.Count}次";
                            }
                            return $"漏洞: {point.Coordinate.PrimaryValue}个";
                        }
                    }
                };

                VulnTypeChart.XAxes = new[]
                {
                    new Axis
                    {
                        Labels = labels.ToArray(),
                        LabelsRotation = -45,
                        LabelsPaint = new SolidColorPaint(new SKColor(0x2C, 0x3E, 0x50)) { FontFamily = ChineseFont },
                        SeparatorsPaint = new SolidColorPaint(new SKColor(0xE8, 0xE8, 0xE8), 1)
                    }
                };
                VulnTypeChart.YAxes = new[]
                {
                    new Axis
                    {
                        LabelsPaint = new SolidColorPaint(new SKColor(0x2C, 0x3E, 0x50)) { FontFamily = ChineseFont },
                        SeparatorsPaint = new SolidColorPaint(new SKColor(0xE8, 0xE8, 0xE8), 1)
                    }
                };
                VulnTypeChart.TooltipTextPaint = new SolidColorPaint(new SKColor(0x2C, 0x3E, 0x50)) { FontFamily = ChineseFont };
                VulnTypeChart.TooltipBackgroundPaint = new SolidColorPaint(new SKColor(0xFF, 0xFF, 0xFF));
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
                        Fill = new SolidColorPaint(new SKColor(0x34, 0x98, 0xDB)),
                        Stroke = new SolidColorPaint(SKColors.White, 2),
                        DataLabelsPaint = new SolidColorPaint(new SKColor(0x2C, 0x3E, 0x50)) { FontFamily = ChineseFont },
                        DataLabelsSize = 10,
                        DataLabelsPosition = LiveChartsCore.Measure.DataLabelsPosition.Top,
                        DataLabelsFormatter = point => $"{point.Coordinate.PrimaryValue}",
                        YToolTipLabelFormatter = point =>
                        {
                            var idx = (int)point.Coordinate.SecondaryValue;
                            if (idx >= 0 && idx < topPorts.Count)
                            {
                                var item = topPorts[idx];
                                return $"端口 {item.Key}\n出现: {item.Value}次";
                            }
                            return $"端口: {point.Coordinate.PrimaryValue}次";
                        }
                    }
                };

                PortChart.XAxes = new[]
                {
                    new Axis
                    {
                        Labels = labels.ToArray(),
                        LabelsRotation = -45,
                        LabelsPaint = new SolidColorPaint(new SKColor(0x2C, 0x3E, 0x50)) { FontFamily = ChineseFont },
                        SeparatorsPaint = new SolidColorPaint(new SKColor(0xE8, 0xE8, 0xE8), 1)
                    }
                };
                PortChart.YAxes = new[]
                {
                    new Axis
                    {
                        LabelsPaint = new SolidColorPaint(new SKColor(0x2C, 0x3E, 0x50)) { FontFamily = ChineseFont },
                        SeparatorsPaint = new SolidColorPaint(new SKColor(0xE8, 0xE8, 0xE8), 1)
                    }
                };
                PortChart.TooltipTextPaint = new SolidColorPaint(new SKColor(0x2C, 0x3E, 0x50)) { FontFamily = ChineseFont };
                PortChart.TooltipBackgroundPaint = new SolidColorPaint(new SKColor(0xFF, 0xFF, 0xFF));
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

                content.AppendLine("【多周期统计对比】");
                content.AppendLine($"本周扫描: {WeekScanCountText?.Text ?? "N/A"} 次 {WeekScanChangeText?.Text ?? ""}");
                content.AppendLine($"本月扫描: {MonthScanCountText?.Text ?? "N/A"} 次 {MonthScanChangeText?.Text ?? ""}");
                content.AppendLine($"本季度扫描: {QuarterScanCountText?.Text ?? "N/A"} 次 {QuarterScanChangeText?.Text ?? ""}");
                content.AppendLine($"本年度扫描: {YearScanCountText?.Text ?? "N/A"} 次 {YearScanChangeText?.Text ?? ""}");
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

        private void TimeGranularityComboBox_SelectionChanged(object sender, SelectionChangedEventArgs e)
        {
            RenderTimeDimensionAnalysis();
        }

        private void ComparePeriodComboBox_SelectionChanged(object sender, SelectionChangedEventArgs e)
        {
            RenderTimeDimensionAnalysis();
        }

        private async void RenderTimeDimensionAnalysis()
        {
            try
            {
                var jsonHistory = await SafeGetJsonHistory();
                var dbHistory = await SafeGetDbHistory();

                RenderTimeDimensionCards(jsonHistory, dbHistory);
                RenderTimeDimensionTrendChart(jsonHistory, dbHistory);
                RenderComparisonChart(jsonHistory, dbHistory);
            }
            catch { }
        }

        private void RenderTimeDimensionCards(List<Services.ScanHistoryItem> jsonHistory, List<ScanHistory> dbHistory)
        {
            var now = DateTime.Now;

            var todayStats = CalculatePeriodStats(jsonHistory, dbHistory, now.Date, now);
            var weekStats = CalculatePeriodStats(jsonHistory, dbHistory, GetStartOfWeek(now), now);
            var monthStats = CalculatePeriodStats(jsonHistory, dbHistory, new DateTime(now.Year, now.Month, 1), now);
            var quarterStats = CalculatePeriodStats(jsonHistory, dbHistory, GetStartOfQuarter(now), now);
            var yearStats = CalculatePeriodStats(jsonHistory, dbHistory, new DateTime(now.Year, 1, 1), now);

            if (DayScanCountText != null) DayScanCountText.Text = todayStats.CurrentCount.ToString();
            if (DayVulnCountText != null) DayVulnCountText.Text = todayStats.CurrentVulnCount.ToString();
            if (DayChangeText != null)
            {
                var yesterdayStats = CalculatePeriodStats(jsonHistory, dbHistory, now.Date.AddDays(-1), now.Date.AddDays(-1));
                DayChangeText.Text = FormatGrowth(todayStats.CurrentCount, yesterdayStats.CurrentCount);
                DayChangeText.Foreground = GetChangeBrush(todayStats.ChangePercent);
            }

            if (WeekPeriodScanCountText != null) WeekPeriodScanCountText.Text = weekStats.CurrentCount.ToString();
            if (WeekPeriodVulnCountText != null) WeekPeriodVulnCountText.Text = weekStats.CurrentVulnCount.ToString();
            if (WeekPeriodChangeText != null)
            {
                WeekPeriodChangeText.Text = FormatGrowth(weekStats.CurrentCount, weekStats.PreviousCount);
                WeekPeriodChangeText.Foreground = GetChangeBrush(weekStats.ChangePercent);
            }

            if (MonthPeriodScanCountText != null) MonthPeriodScanCountText.Text = monthStats.CurrentCount.ToString();
            if (MonthPeriodVulnCountText != null) MonthPeriodVulnCountText.Text = monthStats.CurrentVulnCount.ToString();
            if (MonthPeriodChangeText != null)
            {
                MonthPeriodChangeText.Text = FormatGrowth(monthStats.CurrentCount, monthStats.PreviousCount);
                MonthPeriodChangeText.Foreground = GetChangeBrush(monthStats.ChangePercent);
            }

            if (QuarterPeriodScanCountText != null) QuarterPeriodScanCountText.Text = quarterStats.CurrentCount.ToString();
            if (QuarterPeriodVulnCountText != null) QuarterPeriodVulnCountText.Text = quarterStats.CurrentVulnCount.ToString();
            if (QuarterPeriodChangeText != null)
            {
                QuarterPeriodChangeText.Text = FormatGrowth(quarterStats.CurrentCount, quarterStats.PreviousCount);
                QuarterPeriodChangeText.Foreground = GetChangeBrush(quarterStats.ChangePercent);
            }

            if (YearPeriodScanCountText != null) YearPeriodScanCountText.Text = yearStats.CurrentCount.ToString();
            if (YearPeriodVulnCountText != null) YearPeriodVulnCountText.Text = yearStats.CurrentVulnCount.ToString();
            if (YearPeriodChangeText != null)
            {
                var lastYearStats = CalculatePeriodStats(jsonHistory, dbHistory, new DateTime(now.Year - 1, 1, 1), new DateTime(now.Year - 1, 12, 31));
                YearPeriodChangeText.Text = FormatGrowth(yearStats.CurrentCount, lastYearStats.CurrentCount);
                YearPeriodChangeText.Foreground = GetChangeBrush(yearStats.ChangePercent);
            }
        }

        private string FormatGrowth(int current, int previous)
        {
            if (previous == 0) return current > 0 ? "↑ 新增" : "--";
            var change = ((double)(current - previous) / previous) * 100;
            if (change > 0) return $"↑ {change:F0}%";
            if (change < 0) return $"↓ {Math.Abs(change):F0}%";
            return "持平";
        }

        private void RenderTimeDimensionTrendChart(List<Services.ScanHistoryItem> jsonHistory, List<ScanHistory> dbHistory)
        {
            var granularity = (TimeGranularityComboBox?.SelectedItem as ComboBoxItem)?.Content?.ToString() ?? "按日";
            var now = DateTime.Now;
            var dates = new List<DateTime>();
            var labels = new List<string>();

            int periods = granularity switch
            {
                "按周" => 12,
                "按月" => 12,
                "按季度" => 8,
                "按年" => 5,
                _ => 30
            };

            for (int i = periods - 1; i >= 0; i--)
            {
                DateTime start, end;
                if (granularity == "按周")
                {
                    start = GetStartOfWeek(now).AddDays(-i * 7);
                    end = start.AddDays(6);
                }
                else if (granularity == "按月")
                {
                    start = new DateTime(now.Year, now.Month, 1).AddMonths(-i);
                    end = start.AddMonths(1).AddDays(-1);
                }
                else if (granularity == "按季度")
                {
                    int quarterOffset = i * 3;
                    int targetMonth = now.Month - quarterOffset;
                    int targetYear = now.Year;
                    while (targetMonth <= 0) { targetMonth += 12; targetYear--; }
                    int quarterMonth = ((targetMonth - 1) / 3) * 3 + 1;
                    start = new DateTime(targetYear, quarterMonth, 1);
                    end = start.AddMonths(3).AddDays(-1);
                }
                else if (granularity == "按年")
                {
                    start = new DateTime(now.Year - i, 1, 1);
                    end = new DateTime(now.Year - i, 12, 31);
                }
                else
                {
                    start = now.Date.AddDays(-i);
                    end = start;
                }

                dates.Add(start);
                labels.Add(granularity switch
                {
                    "按周" => start.ToString("MM/dd"),
                    "按月" => start.ToString("yyyy-MM"),
                    "按季度" => $"Q{(start.Month - 1) / 3 + 1}/{start.Year}",
                    "按年" => start.ToString("yyyy"),
                    _ => start.ToString("MM-dd")
                });
            }

            var scanValues = new List<int>();
            var vulnValues = new List<int>();
            var portValues = new List<int>();

            foreach (var date in dates)
            {
                DateTime start, end;
                if (granularity == "按周")
                {
                    start = GetStartOfWeek(date);
                    end = start.AddDays(6);
                }
                else if (granularity == "按月")
                {
                    start = new DateTime(date.Year, date.Month, 1);
                    end = start.AddMonths(1).AddDays(-1);
                }
                else if (granularity == "按季度")
                {
                    int quarterMonth = ((date.Month - 1) / 3) * 3 + 1;
                    start = new DateTime(date.Year, quarterMonth, 1);
                    end = start.AddMonths(3).AddDays(-1);
                }
                else if (granularity == "按年")
                {
                    start = new DateTime(date.Year, 1, 1);
                    end = new DateTime(date.Year, 12, 31);
                }
                else
                {
                    start = date.Date;
                    end = start;
                }

                var periodStats = CalculatePeriodStats(jsonHistory, dbHistory, start, end);
                scanValues.Add(periodStats.CurrentCount);
                vulnValues.Add(periodStats.CurrentVulnCount);
                portValues.Add(periodStats.CurrentPortCount);
            }

            if (TimeDimensionTrendChart != null)
            {
                TimeDimensionTrendChart.Series = new ISeries[]
                {
                    new LineSeries<int>
                    {
                        Values = scanValues,
                        Name = "扫描次数",
                        Fill = new SolidColorPaint(new SKColor(0x34, 0x98, 0xDB, 40)),
                        Stroke = new SolidColorPaint(new SKColor(0x34, 0x98, 0xDB), 3),
                        GeometryFill = new SolidColorPaint(new SKColor(0x34, 0x98, 0xDB)),
                        GeometryStroke = new SolidColorPaint(SKColors.White, 2),
                        GeometrySize = 10,
                        YToolTipLabelFormatter = point => $"扫描: {point.Coordinate.PrimaryValue}次",
                        DataLabelsPaint = new SolidColorPaint(new SKColor(0x34, 0x98, 0xDB)) { FontFamily = ChineseFont },
                        DataLabelsSize = 9,
                        DataLabelsPosition = LiveChartsCore.Measure.DataLabelsPosition.Top
                    },
                    new LineSeries<int>
                    {
                        Values = vulnValues,
                        Name = "漏洞数",
                        Fill = new SolidColorPaint(new SKColor(0xE7, 0x4C, 0x3C, 40)),
                        Stroke = new SolidColorPaint(new SKColor(0xE7, 0x4C, 0x3C), 3),
                        GeometryFill = new SolidColorPaint(new SKColor(0xE7, 0x4C, 0x3C)),
                        GeometryStroke = new SolidColorPaint(SKColors.White, 2),
                        GeometrySize = 10,
                        YToolTipLabelFormatter = point => $"漏洞: {point.Coordinate.PrimaryValue}个",
                        DataLabelsPaint = new SolidColorPaint(new SKColor(0xE7, 0x4C, 0x3C)) { FontFamily = ChineseFont },
                        DataLabelsSize = 9,
                        DataLabelsPosition = LiveChartsCore.Measure.DataLabelsPosition.Top
                    },
                    new LineSeries<int>
                    {
                        Values = portValues,
                        Name = "开放端口",
                        Fill = new SolidColorPaint(new SKColor(0x27, 0xAE, 0x60, 40)),
                        Stroke = new SolidColorPaint(new SKColor(0x27, 0xAE, 0x60), 3),
                        GeometryFill = new SolidColorPaint(new SKColor(0x27, 0xAE, 0x60)),
                        GeometryStroke = new SolidColorPaint(SKColors.White, 2),
                        GeometrySize = 10,
                        YToolTipLabelFormatter = point => $"端口: {point.Coordinate.PrimaryValue}个",
                        DataLabelsPaint = new SolidColorPaint(new SKColor(0x27, 0xAE, 0x60)) { FontFamily = ChineseFont },
                        DataLabelsSize = 9,
                        DataLabelsPosition = LiveChartsCore.Measure.DataLabelsPosition.Top
                    }
                };

                TimeDimensionTrendChart.XAxes = new[]
                {
                    new Axis
                    {
                        Labels = labels.ToArray(),
                        LabelsRotation = granularity == "按月" || granularity == "按季度" ? 0 : -45,
                        LabelsPaint = new SolidColorPaint(new SKColor(0x2C, 0x3E, 0x50)) { FontFamily = ChineseFont },
                        SeparatorsPaint = new SolidColorPaint(new SKColor(0xE8, 0xE8, 0xE8), 1)
                    }
                };
                TimeDimensionTrendChart.YAxes = new[]
                {
                    new Axis
                    {
                        LabelsPaint = new SolidColorPaint(new SKColor(0x2C, 0x3E, 0x50)) { FontFamily = ChineseFont },
                        SeparatorsPaint = new SolidColorPaint(new SKColor(0xE8, 0xE8, 0xE8), 1)
                    }
                };
                TimeDimensionTrendChart.TooltipTextPaint = new SolidColorPaint(new SKColor(0x2C, 0x3E, 0x50)) { FontFamily = ChineseFont };
                TimeDimensionTrendChart.TooltipBackgroundPaint = new SolidColorPaint(new SKColor(0xFF, 0xFF, 0xFF));
                TimeDimensionTrendChart.LegendTextPaint = new SolidColorPaint(new SKColor(0x2C, 0x3E, 0x50)) { FontFamily = ChineseFont };
                TimeDimensionTrendChart.LegendPosition = LiveChartsCore.Measure.LegendPosition.Bottom;
            }
        }

        private void RenderComparisonChart(List<Services.ScanHistoryItem> jsonHistory, List<ScanHistory> dbHistory)
        {
            var compareMode = (ComparePeriodComboBox?.SelectedItem as ComboBoxItem)?.Content?.ToString() ?? "与上一周期";
            var now = DateTime.Now;

            var periods = new List<string>();
            var scanGrowth = new List<double>();
            var vulnGrowth = new List<double>();
            var portGrowth = new List<double>();

            int numPeriods = 6;
            for (int i = numPeriods - 1; i >= 0; i--)
            {
                DateTime currentStart, currentEnd, prevStart, prevEnd;
                string label;

                if (compareMode == "与去年同月")
                {
                    currentStart = new DateTime(now.Year, now.Month, 1).AddMonths(-i);
                    currentEnd = currentStart.AddMonths(1).AddDays(-1);
                    prevStart = new DateTime(now.Year - 1, now.Month, 1).AddMonths(-i);
                    prevEnd = prevStart.AddMonths(1).AddDays(-1);
                    label = currentStart.ToString("yyyy-MM");
                }
                else if (compareMode == "与上一季度同期")
                {
                    int quarterOffset = i * 3;
                    int currentQuarterMonth = now.Month - quarterOffset;
                    int currentYear = now.Year;
                    while (currentQuarterMonth <= 0) { currentQuarterMonth += 12; currentYear--; }
                    int currentQuarterStart = ((currentQuarterMonth - 1) / 3) * 3 + 1;
                    currentStart = new DateTime(currentYear, currentQuarterStart, 1);
                    currentEnd = currentStart.AddMonths(3).AddDays(-1);

                    int prevQuarterMonth = currentQuarterMonth - 3;
                    int prevYear = currentYear;
                    if (prevQuarterMonth <= 0) { prevQuarterMonth += 12; prevYear--; }
                    int prevQuarterStart = ((prevQuarterMonth - 1) / 3) * 3 + 1;
                    prevStart = new DateTime(prevYear, prevQuarterStart, 1);
                    prevEnd = prevStart.AddMonths(3).AddDays(-1);

                    label = $"Q{(currentQuarterStart - 1) / 3 + 1}/{currentYear}";
                }
                else
                {
                    currentStart = now.Date.AddDays(-i);
                    currentEnd = currentStart;
                    prevStart = currentStart.AddDays(-1);
                    prevEnd = prevStart;

                    if (compareMode == "与上一月同期")
                    {
                        currentStart = new DateTime(now.Year, now.Month, 1).AddMonths(-i);
                        currentEnd = currentStart.AddMonths(1).AddDays(-1);
                        prevStart = currentStart.AddMonths(-1);
                        prevEnd = prevStart.AddMonths(1).AddDays(-1);
                        label = currentStart.ToString("yyyy-MM");
                    }
                    else if (compareMode == "与上一季度同期")
                    {
                        int quarterOffset = i * 3;
                        int targetMonth = now.Month - quarterOffset;
                        int targetYear = now.Year;
                        while (targetMonth <= 0) { targetMonth += 12; targetYear--; }
                        int quarterMonth = ((targetMonth - 1) / 3) * 3 + 1;
                        currentStart = new DateTime(targetYear, quarterMonth, 1);
                        currentEnd = currentStart.AddMonths(3).AddDays(-1);

                        int prevQuarterMonth = quarterMonth - 3;
                        int prevYear = targetYear;
                        if (prevQuarterMonth <= 0) { prevQuarterMonth += 12; prevYear--; }
                        int prevQuarterStart = ((prevQuarterMonth - 1) / 3) * 3 + 1;
                        prevStart = new DateTime(prevYear, prevQuarterStart, 1);
                        prevEnd = prevStart.AddMonths(3).AddDays(-1);

                        label = $"Q{(quarterMonth - 1) / 3 + 1}/{targetYear}";
                    }
                    else
                    {
                        label = currentStart.ToString("MM-dd");
                    }
                }

                var currentStats = CalculatePeriodStats(jsonHistory, dbHistory, currentStart, currentEnd);
                var prevStats = CalculatePeriodStats(jsonHistory, dbHistory, prevStart, prevEnd);

                periods.Add(label);

                double scanG = CalculateGrowthRate(currentStats.CurrentCount, prevStats.CurrentCount);
                double vulnG = CalculateGrowthRate(currentStats.CurrentVulnCount, prevStats.CurrentVulnCount);
                double portG = CalculateGrowthRate(currentStats.CurrentPortCount, prevStats.CurrentPortCount);

                scanGrowth.Add(scanG);
                vulnGrowth.Add(vulnG);
                portGrowth.Add(portG);
            }

            if (ComparisonChart != null)
            {
                ComparisonChart.Series = new ISeries[]
                {
                    new ColumnSeries<double>
                    {
                        Values = scanGrowth,
                        Name = "扫描增长",
                        Fill = new SolidColorPaint(new SKColor(0x34, 0x98, 0xDB)),
                        Stroke = new SolidColorPaint(SKColors.White, 2),
                        DataLabelsPaint = new SolidColorPaint(new SKColor(0x2C, 0x3E, 0x50)) { FontFamily = ChineseFont },
                        DataLabelsSize = 10,
                        DataLabelsPosition = LiveChartsCore.Measure.DataLabelsPosition.Top,
                        DataLabelsFormatter = point => $"{point.Coordinate.PrimaryValue:F0}%"
                    },
                    new ColumnSeries<double>
                    {
                        Values = vulnGrowth,
                        Name = "漏洞增长",
                        Fill = new SolidColorPaint(new SKColor(0xE7, 0x4C, 0x3C)),
                        Stroke = new SolidColorPaint(SKColors.White, 2),
                        DataLabelsPaint = new SolidColorPaint(new SKColor(0x2C, 0x3E, 0x50)) { FontFamily = ChineseFont },
                        DataLabelsSize = 10,
                        DataLabelsPosition = LiveChartsCore.Measure.DataLabelsPosition.Top,
                        DataLabelsFormatter = point => $"{point.Coordinate.PrimaryValue:F0}%"
                    },
                    new ColumnSeries<double>
                    {
                        Values = portGrowth,
                        Name = "端口增长",
                        Fill = new SolidColorPaint(new SKColor(0x27, 0xAE, 0x60)),
                        Stroke = new SolidColorPaint(SKColors.White, 2),
                        DataLabelsPaint = new SolidColorPaint(new SKColor(0x2C, 0x3E, 0x50)) { FontFamily = ChineseFont },
                        DataLabelsSize = 10,
                        DataLabelsPosition = LiveChartsCore.Measure.DataLabelsPosition.Top,
                        DataLabelsFormatter = point => $"{point.Coordinate.PrimaryValue:F0}%"
                    }
                };

                ComparisonChart.XAxes = new[]
                {
                    new Axis
                    {
                        Labels = periods.ToArray(),
                        LabelsPaint = new SolidColorPaint(new SKColor(0x2C, 0x3E, 0x50)) { FontFamily = ChineseFont },
                        SeparatorsPaint = new SolidColorPaint(new SKColor(0xE8, 0xE8, 0xE8), 1)
                    }
                };
                ComparisonChart.YAxes = new[]
                {
                    new Axis
                    {
                        LabelsPaint = new SolidColorPaint(new SKColor(0x2C, 0x3E, 0x50)) { FontFamily = ChineseFont },
                        SeparatorsPaint = new SolidColorPaint(new SKColor(0xE8, 0xE8, 0xE8), 1),
                        Labeler = value => $"{value:F0}%"
                    }
                };
                ComparisonChart.TooltipTextPaint = new SolidColorPaint(new SKColor(0x2C, 0x3E, 0x50)) { FontFamily = ChineseFont };
                ComparisonChart.TooltipBackgroundPaint = new SolidColorPaint(new SKColor(0xFF, 0xFF, 0xFF));
                ComparisonChart.LegendTextPaint = new SolidColorPaint(new SKColor(0x2C, 0x3E, 0x50)) { FontFamily = ChineseFont };
                ComparisonChart.LegendPosition = LiveChartsCore.Measure.LegendPosition.Bottom;
            }
        }

        private double CalculateGrowthRate(int current, int previous)
        {
            if (previous == 0) return current > 0 ? 100 : 0;
            return ((double)(current - previous) / previous) * 100;
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

    public class TimeDimensionItem
    {
        public string Period { get; set; } = "";
        public int ScanCount { get; set; }
        public int VulnCount { get; set; }
        public int PortCount { get; set; }
        public int CriticalCount { get; set; }
        public int HighCount { get; set; }
        public double ChangePercent { get; set; }
        public string ChangeLabel { get; set; } = "";
    }

    public class ComparisonItem
    {
        public string Period { get; set; } = "";
        public double ScanGrowth { get; set; }
        public double VulnGrowth { get; set; }
        public double PortGrowth { get; set; }
    }
}