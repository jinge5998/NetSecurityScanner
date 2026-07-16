using NetSecurityScanner.Models;
using NetSecurityScanner.Services;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Input;
using System.Windows.Media;

namespace NetSecurityScanner.Views
{
    /// <summary>
    /// 插件执行日志窗口（v4-T3）
    /// </summary>
    public partial class PluginExecutionLogWindow : Window
    {
        private readonly PluginExecutionLogService _logService;

        private DataGrid _logDataGrid;
        private TextBlock _totalExecValueText;
        private TextBlock _successRateValueText;
        private TextBlock _avgDurationValueText;
        private TextBlock _failedCountValueText;
        private TextBlock _recordCountText;
        private ComboBox _timeRangeComboBox;
        private Button _refreshButton;
        private Button _clearButton;
        private Button _reRunButton;
        private List<PluginExecutionEntry> _currentEntries = new();

        public PluginExecutionLogWindow()
        {
            Title = "插件执行日志";
            Width = 1150;
            Height = 720;
            WindowStartupLocation = WindowStartupLocation.CenterOwner;
            Background = Brushes.White;
            MinWidth = 900;
            MinHeight = 600;

            _logService = new PluginExecutionLogService();

            BuildUI();

            KeyDown += Window_KeyDown;

            Loaded += async (s, e) =>
            {
                try
                {
                    await ReloadAsync();
                }
                catch (Exception ex)
                {
                    MessageBox.Show($"加载执行日志失败: {ex.Message}", "错误", MessageBoxButton.OK, MessageBoxImage.Error);
                }
            };
        }

        private void Window_KeyDown(object sender, KeyEventArgs e)
        {
            if (e.Key == Key.F5)
            {
                _ = ReloadAsync();
                e.Handled = true;
            }
            else if (e.Key == Key.Escape)
            {
                Close();
            }
        }

        // ---------------- UI 构建 ----------------
        private void BuildUI()
        {
            var rootGrid = new Grid { Margin = new Thickness(15) };
            rootGrid.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
            rootGrid.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
            rootGrid.RowDefinitions.Add(new RowDefinition { Height = new GridLength(1, GridUnitType.Star) });
            rootGrid.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });

            // 1. 顶部标题栏
            var header = CreateHeader();
            Grid.SetRow(header, 0);
            rootGrid.Children.Add(header);

            // 2. 工具栏 + 统计卡片
            var stats = CreateStatsPanel();
            Grid.SetRow(stats, 1);
            rootGrid.Children.Add(stats);

            // 3. 中部 DataGrid
            var grid = CreateDataGridArea();
            Grid.SetRow(grid, 2);
            rootGrid.Children.Add(grid);

            // 4. 底部
            var bottom = CreateBottomBar();
            Grid.SetRow(bottom, 3);
            rootGrid.Children.Add(bottom);

            Content = rootGrid;
        }

        private Border CreateHeader()
        {
            var border = new Border
            {
                Background = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#3498DB")),
                CornerRadius = new CornerRadius(8),
                Padding = new Thickness(15, 12, 15, 12),
                Margin = new Thickness(0, 0, 0, 10)
            };
            var grid = new Grid();
            grid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
            grid.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });

            var titlePanel = new StackPanel();
            titlePanel.Children.Add(new TextBlock
            {
                Text = "📋  插件执行日志",
                FontSize = 22,
                FontWeight = FontWeights.Bold,
                Foreground = Brushes.White
            });
            titlePanel.Children.Add(new TextBlock
            {
                Text = "查看每个插件的扫描执行历史与统计",
                FontSize = 12,
                Foreground = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#D6EAF8")),
                Margin = new Thickness(0, 4, 0, 0)
            });
            Grid.SetColumn(titlePanel, 0);
            grid.Children.Add(titlePanel);

            var rightPanel = new StackPanel { Orientation = Orientation.Horizontal, VerticalAlignment = VerticalAlignment.Center };

            _timeRangeComboBox = new ComboBox
            {
                Width = 130,
                Height = 30,
                Margin = new Thickness(0, 0, 8, 0),
                FontSize = 12,
                VerticalContentAlignment = VerticalAlignment.Center
            };
            _timeRangeComboBox.Items.Add(new ComboBoxItem { Content = "最近 1 天", Tag = 1 });
            _timeRangeComboBox.Items.Add(new ComboBoxItem { Content = "最近 3 天", Tag = 3 });
            _timeRangeComboBox.Items.Add(new ComboBoxItem { Content = "最近 7 天", Tag = 7, IsSelected = true });
            _timeRangeComboBox.Items.Add(new ComboBoxItem { Content = "最近 30 天", Tag = 30 });
            _timeRangeComboBox.SelectionChanged += TimeRangeComboBox_SelectionChanged;
            rightPanel.Children.Add(_timeRangeComboBox);

            _refreshButton = new Button
            {
                Content = "🔄 刷新",
                Width = 90,
                Height = 30,
                Margin = new Thickness(0, 0, 8, 0),
                Background = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#27AE60")),
                Foreground = Brushes.White,
                BorderThickness = new Thickness(0),
                FontWeight = FontWeights.SemiBold,
                Cursor = Cursors.Hand
            };
            _refreshButton.Click += RefreshButton_Click;
            rightPanel.Children.Add(_refreshButton);

            _reRunButton = new Button
            {
                Content = "▶ 重新执行选中",
                Width = 120,
                Height = 30,
                Margin = new Thickness(0, 0, 8, 0),
                Background = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#5B6CFF")),
                Foreground = Brushes.White,
                BorderThickness = new Thickness(0),
                FontWeight = FontWeights.SemiBold,
                Cursor = Cursors.Hand,
                ToolTip = "使用所选日志的 目标 / 端口 重新执行扫描"
            };
            _reRunButton.Click += ReRunButton_Click;
            rightPanel.Children.Add(_reRunButton);

            _clearButton = new Button
            {
                Content = "🗑 清空",
                Width = 90,
                Height = 30,
                Background = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#E74C3C")),
                Foreground = Brushes.White,
                BorderThickness = new Thickness(0),
                FontWeight = FontWeights.SemiBold,
                Cursor = Cursors.Hand
            };
            _clearButton.Click += ClearButton_Click;
            rightPanel.Children.Add(_clearButton);

            Grid.SetColumn(rightPanel, 1);
            grid.Children.Add(rightPanel);

            border.Child = grid;
            return border;
        }

        private Border CreateStatsPanel()
        {
            var border = new Border
            {
                Background = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#F8F9FA")),
                CornerRadius = new CornerRadius(8),
                Padding = new Thickness(10, 10, 10, 10),
                Margin = new Thickness(0, 0, 0, 10)
            };
            var grid = new Grid();
            grid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
            grid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
            grid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
            grid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });

            grid.Children.Add(BuildStatCard("📊 总执行数", "0", "#3498DB", out _totalExecValueText));
            Grid.SetColumn(grid.Children[0], 0);
            grid.Children.Add(BuildStatCard("✅ 成功率", "0%", "#27AE60", out _successRateValueText));
            Grid.SetColumn(grid.Children[1], 1);
            grid.Children.Add(BuildStatCard("⏱ 平均耗时", "0 ms", "#9B59B6", out _avgDurationValueText));
            Grid.SetColumn(grid.Children[2], 2);
            grid.Children.Add(BuildStatCard("❌ 失败数", "0", "#E74C3C", out _failedCountValueText));
            Grid.SetColumn(grid.Children[3], 3);

            border.Child = grid;
            return border;
        }

        private static Border BuildStatCard(string title, string value, string valueColor, out TextBlock valueText)
        {
            var border = new Border
            {
                Background = Brushes.White,
                CornerRadius = new CornerRadius(8),
                BorderBrush = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#E2E8F0")),
                BorderThickness = new Thickness(1),
                Padding = new Thickness(15, 12, 15, 12),
                Margin = new Thickness(5, 0, 5, 0)
            };
            var panel = new StackPanel();
            panel.Children.Add(new TextBlock
            {
                Text = title,
                FontSize = 12,
                FontWeight = FontWeights.SemiBold,
                Foreground = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#7F8C8D"))
            });
            valueText = new TextBlock
            {
                Text = value,
                FontSize = 28,
                FontWeight = FontWeights.Bold,
                Foreground = new SolidColorBrush((Color)ColorConverter.ConvertFromString(valueColor)),
                Margin = new Thickness(0, 6, 0, 0)
            };
            panel.Children.Add(valueText);
            border.Child = panel;
            return border;
        }

        private Border CreateDataGridArea()
        {
            var border = new Border
            {
                Background = Brushes.White,
                CornerRadius = new CornerRadius(8),
                BorderBrush = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#E2E8F0")),
                BorderThickness = new Thickness(1)
            };
            var panel = new DockPanel();

            // 顶部小标题
            var headerPanel = new Border
            {
                Background = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#F8F9FA")),
                Padding = new Thickness(12, 8, 12, 8)
            };
            var headerGrid = new Grid();
            headerGrid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
            headerGrid.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });
            headerGrid.Children.Add(new TextBlock
            {
                Text = "📄 最近执行记录",
                FontSize = 14,
                FontWeight = FontWeights.Bold,
                Foreground = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#2C3E50")),
                VerticalAlignment = VerticalAlignment.Center
            });
            _recordCountText = new TextBlock
            {
                Text = "共 0 条",
                FontSize = 12,
                Foreground = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#7F8C8D")),
                VerticalAlignment = VerticalAlignment.Center
            };
            Grid.SetColumn(_recordCountText, 1);
            headerGrid.Children.Add(_recordCountText);
            headerPanel.Child = headerGrid;
            DockPanel.SetDock(headerPanel, Dock.Top);
            panel.Children.Add(headerPanel);

            _logDataGrid = new DataGrid
            {
                AutoGenerateColumns = false,
                IsReadOnly = true,
                CanUserAddRows = false,
                CanUserDeleteRows = false,
                SelectionMode = DataGridSelectionMode.Single,
                GridLinesVisibility = DataGridGridLinesVisibility.Horizontal,
                HeadersVisibility = DataGridHeadersVisibility.Column,
                RowHeight = 30,
                AlternatingRowBackground = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#F8F9FA")),
                BorderThickness = new Thickness(0),
                Margin = new Thickness(0)
            };

            _logDataGrid.Columns.Add(new DataGridTextColumn { Header = "时间", Binding = new Binding("StartTimeText") { StringFormat = "yyyy-MM-dd HH:mm:ss" }, Width = new DataGridLength(150) });
            _logDataGrid.Columns.Add(new DataGridTextColumn { Header = "插件名", Binding = new Binding("PluginName"), Width = new DataGridLength(140) });
            _logDataGrid.Columns.Add(new DataGridTextColumn { Header = "目标", Binding = new Binding("Target"), Width = new DataGridLength(130) });
            _logDataGrid.Columns.Add(new DataGridTextColumn { Header = "端口", Binding = new Binding("Port"), Width = new DataGridLength(60) });
            _logDataGrid.Columns.Add(new DataGridTextColumn { Header = "服务", Binding = new Binding("ServiceType"), Width = new DataGridLength(70) });

            // 状态列：使用模板列绘制色块
            var statusCol = new DataGridTemplateColumn { Header = "状态", Width = new DataGridLength(80) };
            var statusFactory = new FrameworkElementFactory(typeof(Border));
            statusFactory.SetBinding(Border.BackgroundProperty, new Binding("StatusColor"));
            statusFactory.SetValue(Border.CornerRadiusProperty, new CornerRadius(4));
            statusFactory.SetValue(Border.PaddingProperty, new Thickness(6, 3, 6, 3));
            statusFactory.SetValue(Border.HorizontalAlignmentProperty, HorizontalAlignment.Center);
            var statusTextFactory = new FrameworkElementFactory(typeof(TextBlock));
            statusTextFactory.SetBinding(TextBlock.TextProperty, new Binding("StatusText"));
            statusTextFactory.SetValue(TextBlock.ForegroundProperty, Brushes.White);
            statusTextFactory.SetValue(TextBlock.FontWeightProperty, FontWeights.SemiBold);
            statusTextFactory.SetValue(TextBlock.FontSizeProperty, 11.0);
            statusFactory.AppendChild(statusTextFactory);
            statusCol.CellTemplate = new DataTemplate { VisualTree = statusFactory };
            _logDataGrid.Columns.Add(statusCol);

            _logDataGrid.Columns.Add(new DataGridTextColumn { Header = "耗时(ms)", Binding = new Binding("DurationMs"), Width = new DataGridLength(80) });
            _logDataGrid.Columns.Add(new DataGridTextColumn { Header = "漏洞数", Binding = new Binding("VulnCount"), Width = new DataGridLength(60) });
            _logDataGrid.Columns.Add(new DataGridTextColumn { Header = "错误信息", Binding = new Binding("ErrorMessage"), Width = new DataGridLength(1, DataGridLengthUnitType.Star) });

            // 行样式触发器：失败/超时整行红色背景
            var rowStyle = new Style(typeof(DataGridRow));
            var failureTrigger = new DataTrigger
            {
                Binding = new Binding("StatusRaw"),
                Value = PluginExecutionStatus.Failed
            };
            failureTrigger.Setters.Add(new Setter(DataGridRow.BackgroundProperty, new SolidColorBrush((Color)ColorConverter.ConvertFromString("#FADBD8"))));
            failureTrigger.Setters.Add(new Setter(DataGridRow.ForegroundProperty, new SolidColorBrush((Color)ColorConverter.ConvertFromString("#922B21"))));
            rowStyle.Triggers.Add(failureTrigger);

            var timeoutTrigger = new DataTrigger
            {
                Binding = new Binding("StatusRaw"),
                Value = PluginExecutionStatus.Timeout
            };
            timeoutTrigger.Setters.Add(new Setter(DataGridRow.BackgroundProperty, new SolidColorBrush((Color)ColorConverter.ConvertFromString("#F5B7B1"))));
            timeoutTrigger.Setters.Add(new Setter(DataGridRow.ForegroundProperty, new SolidColorBrush((Color)ColorConverter.ConvertFromString("#7B241C"))));
            rowStyle.Triggers.Add(timeoutTrigger);

            var cancelledTrigger = new DataTrigger
            {
                Binding = new Binding("StatusRaw"),
                Value = PluginExecutionStatus.Cancelled
            };
            cancelledTrigger.Setters.Add(new Setter(DataGridRow.BackgroundProperty, new SolidColorBrush((Color)ColorConverter.ConvertFromString("#FDEBD0"))));
            cancelledTrigger.Setters.Add(new Setter(DataGridRow.ForegroundProperty, new SolidColorBrush((Color)ColorConverter.ConvertFromString("#7E5109"))));
            rowStyle.Triggers.Add(cancelledTrigger);

            _logDataGrid.RowStyle = rowStyle;

            panel.Children.Add(_logDataGrid);
            border.Child = panel;
            return border;
        }

        private Border CreateBottomBar()
        {
            var border = new Border
            {
                Background = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#F8F9FA")),
                Padding = new Thickness(10, 8, 10, 8),
                Margin = new Thickness(0, 10, 0, 0),
                CornerRadius = new CornerRadius(8)
            };
            var panel = new StackPanel { Orientation = Orientation.Horizontal, HorizontalAlignment = HorizontalAlignment.Right };

            var closeBtn = new Button
            {
                Content = "关闭",
                Width = 100,
                Height = 32,
                Cursor = Cursors.Hand
            };
            closeBtn.Click += (s, e) => Close();
            panel.Children.Add(closeBtn);

            border.Child = panel;
            return border;
        }

        // ---------------- 数据加载 ----------------
        private int GetSelectedDays()
        {
            if (_timeRangeComboBox?.SelectedItem is ComboBoxItem item && item.Tag is int days)
            {
                return Math.Max(1, days);
            }
            return 7;
        }

        private async Task ReloadAsync()
        {
            int days = GetSelectedDays();
            try
            {
                if (_refreshButton != null) _refreshButton.IsEnabled = false;
                if (_clearButton != null) _clearButton.IsEnabled = false;
                if (_timeRangeComboBox != null) _timeRangeComboBox.IsEnabled = false;

                var stats = await _logService.GetStatisticsAsync(days);
                var entries = await _logService.GetRecentEntriesAsync(days, 50);

                _currentEntries = entries;
                ApplyEntries(entries);
                ApplyStats(stats, entries.Count);
            }
            catch (Exception ex)
            {
                MessageBox.Show($"刷新执行日志失败: {ex.Message}", "错误", MessageBoxButton.OK, MessageBoxImage.Error);
            }
            finally
            {
                if (_refreshButton != null) _refreshButton.IsEnabled = true;
                if (_clearButton != null) _clearButton.IsEnabled = true;
                if (_timeRangeComboBox != null) _timeRangeComboBox.IsEnabled = true;
            }
        }

        private void ApplyEntries(List<PluginExecutionEntry> entries)
        {
            var rows = entries.Select(e => new PluginExecutionRow
            {
                PluginId = e.PluginId,
                PluginName = e.PluginName,
                Target = e.Target,
                Port = e.Port,
                ServiceType = e.ServiceType,
                StartTimeText = e.StartTime,
                StartTime = e.StartTime,
                EndTime = e.EndTime,
                DurationMs = e.DurationMs,
                VulnCount = e.VulnCount,
                ErrorMessage = e.ErrorMessage ?? string.Empty,
                StatusRaw = e.Status,
                StatusText = StatusToText(e.Status),
                StatusColor = StatusToColor(e.Status)
            }).ToList();

            _logDataGrid.ItemsSource = rows;
            if (_recordCountText != null)
            {
                _recordCountText.Text = $"共 {rows.Count} 条";
            }
        }

        private void ApplyStats(PluginExecutionStatistics stats, int displayedCount)
        {
            if (_totalExecValueText != null)
            {
                _totalExecValueText.Text = stats.TotalExecutions.ToString();
            }
            if (_successRateValueText != null)
            {
                var pct = stats.SuccessRate * 100.0;
                _successRateValueText.Text = $"{pct:F1}%";
                _successRateValueText.Foreground = new SolidColorBrush((Color)ColorConverter.ConvertFromString(
                    pct >= 80 ? "#27AE60" : (pct >= 50 ? "#F39C12" : "#E74C3C")));
            }
            if (_avgDurationValueText != null)
            {
                _avgDurationValueText.Text = $"{(int)Math.Round(stats.AverageDurationMs)} ms";
            }
            if (_failedCountValueText != null)
            {
                _failedCountValueText.Text = (stats.FailedCount + stats.TimeoutCount).ToString();
            }
        }

        private static string StatusToText(PluginExecutionStatus status)
        {
            return status switch
            {
                PluginExecutionStatus.Success => "成功",
                PluginExecutionStatus.Failed => "失败",
                PluginExecutionStatus.Timeout => "超时",
                PluginExecutionStatus.Cancelled => "取消",
                _ => status.ToString()
            };
        }

        private static string StatusToColor(PluginExecutionStatus status)
        {
            return status switch
            {
                PluginExecutionStatus.Success => "#27AE60",
                PluginExecutionStatus.Failed => "#E74C3C",
                PluginExecutionStatus.Timeout => "#C0392B",
                PluginExecutionStatus.Cancelled => "#F39C12",
                _ => "#95A5A6"
            };
        }

        // ---------------- 事件 ----------------
        private async void RefreshButton_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                await ReloadAsync();
            }
            catch (Exception ex)
            {
                MessageBox.Show($"刷新失败: {ex.Message}", "错误", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        private async void ReRunButton_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                if (_logDataGrid?.SelectedItem is not PluginExecutionRow row)
                {
                    MessageBox.Show("请先选择一条日志记录", "提示", MessageBoxButton.OK, MessageBoxImage.Warning);
                    return;
                }
                if (string.IsNullOrEmpty(row.Target))
                {
                    MessageBox.Show("该日志条目缺少目标信息，无法重新执行", "提示", MessageBoxButton.OK, MessageBoxImage.Warning);
                    return;
                }

                var confirm = MessageBox.Show(
                    $"将重新执行插件扫描:\n目标: {row.Target}\n端口: {row.Port}\n插件: {row.PluginName}",
                    "重新执行", MessageBoxButton.YesNo, MessageBoxImage.Question);
                if (confirm != MessageBoxResult.Yes) return;

                Mouse.OverrideCursor = Cursors.Wait;
                try
                {
                    var results = await PluginOrchestrator.Instance.ScanTargetAsync(
                        row.Target, new List<int> { row.Port });
                    MessageBox.Show($"重新执行完成：发现 {results.Count} 个漏洞（{row.PluginName} @ {row.Target}:{row.Port}）",
                        "完成", MessageBoxButton.OK, MessageBoxImage.Information);
                }
                finally
                {
                    Mouse.OverrideCursor = null;
                }
            }
            catch (Exception ex)
            {
                Mouse.OverrideCursor = null;
                MessageBox.Show($"重新执行失败: {ex.Message}", "错误", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        private async void ClearButton_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                var result = MessageBox.Show("确定要清空所有插件执行日志吗？\n\n此操作不可撤销。", "二次确认",
                    MessageBoxButton.YesNo, MessageBoxImage.Warning);
                if (result != MessageBoxResult.Yes) return;

                await _logService.ClearAllAsync();
                await ReloadAsync();
            }
            catch (Exception ex)
            {
                MessageBox.Show($"清空失败: {ex.Message}", "错误", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        private async void TimeRangeComboBox_SelectionChanged(object sender, SelectionChangedEventArgs e)
        {
            try
            {
                if (IsLoaded) await ReloadAsync();
            }
            catch (Exception ex)
            {
                MessageBox.Show($"切换时间范围失败: {ex.Message}", "错误", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }
    }

    /// <summary>
    /// DataGrid 行绑定模型
    /// </summary>
    public class PluginExecutionRow
    {
        public string PluginId { get; set; } = string.Empty;
        public string PluginName { get; set; } = string.Empty;
        public string Target { get; set; } = string.Empty;
        public int Port { get; set; }
        public string ServiceType { get; set; } = string.Empty;
        public DateTime StartTimeText { get; set; }
        public DateTime StartTime { get; set; }
        public DateTime EndTime { get; set; }
        public long DurationMs { get; set; }
        public int VulnCount { get; set; }
        public string ErrorMessage { get; set; } = string.Empty;
        public PluginExecutionStatus StatusRaw { get; set; }
        public string StatusText { get; set; } = string.Empty;
        public string StatusColor { get; set; } = "#95A5A6";
    }
}
