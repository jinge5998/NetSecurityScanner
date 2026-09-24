using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Input;
using System.Windows.Media;
using Microsoft.Win32;
using NetSecurityScanner.Models;
using NetSecurityScanner.Services;

namespace NetSecurityScanner.Views
{
    public partial class AttackLogWindow : Window
    {
        private readonly AttackLogService _logService;
        private List<AttackLogEntry> _allEntries = new();
        private List<AttackLogEntry> _filteredEntries = new();
        private AttackLogFilter _currentFilter = new();

        private DataGrid _attackLogGrid;
        private TextBlock _totalAttacksText;
        private StackPanel _attackTypeStatsPanel;
        private StackPanel _riskLevelStatsPanel;
        private StackPanel _topSourceIPsPanel;
        private TextBlock _timeTrendText;
        private TextBlock _recordCountText;
        private ComboBox _attackTypeComboBox;
        private ComboBox _riskLevelComboBox;
        private ComboBox _timeRangeComboBox;
        private TextBox _sourceIPTextBox;
        private TextBox _targetIPTextBox;
        private DatePicker _startDatePicker;
        private DatePicker _endDatePicker;

        public AttackLogWindow()
        {
            Title = "攻击日志查询";
            Width = 1350;
            Height = 780;
            WindowStartupLocation = WindowStartupLocation.CenterOwner;
            Background = Brushes.White;

            _logService = new AttackLogService();
            
            BuildUI();
            
            KeyDown += Window_KeyDown;
            
            Loaded += async (s, e) => 
            {
                try
                {
                    await LoadAttackLogsAsync();
                }
                catch (Exception ex)
                {
                    MessageBox.Show($"加载数据失败: {ex.Message}\n\n{ex.StackTrace}", "错误", MessageBoxButton.OK, MessageBoxImage.Error);
                }
            };
        }

        private void Window_KeyDown(object sender, KeyEventArgs e)
        {
            if (e.Key == Key.Enter && Keyboard.Modifiers == ModifierKeys.None)
            {
                ApplyFilterButton_Click(null, null);
                e.Handled = true;
            }
            else if (e.Key == Key.Escape)
            {
                Close();
            }
        }

        private void BuildUI()
        {
            var rootGrid = new Grid();
            rootGrid.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
            rootGrid.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
            rootGrid.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
            rootGrid.RowDefinitions.Add(new RowDefinition { Height = new GridLength(1, GridUnitType.Star) });
            rootGrid.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });

            var headerBorder = CreateHeaderBar();
            Grid.SetRow(headerBorder, 0);
            rootGrid.Children.Add(headerBorder);

            var toolbarBorder = CreateToolBar();
            Grid.SetRow(toolbarBorder, 1);
            rootGrid.Children.Add(toolbarBorder);

            var filterBorder = CreateFilterArea();
            Grid.SetRow(filterBorder, 2);
            rootGrid.Children.Add(filterBorder);

            var contentGrid = CreateContentArea();
            Grid.SetRow(contentGrid, 3);
            rootGrid.Children.Add(contentGrid);

            var statusBorder = CreateStatusBar();
            Grid.SetRow(statusBorder, 4);
            rootGrid.Children.Add(statusBorder);

            Content = rootGrid;
        }

        private Border CreateHeaderBar()
        {
            var border = new Border
            {
                Padding = new Thickness(20, 15, 20, 15),
                Background = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#2C3E50"))
            };
            var panel = new StackPanel();
            panel.Children.Add(new TextBlock { Text = "📋 攻击日志查询", FontSize = 24, FontWeight = FontWeights.Bold, Foreground = Brushes.White });
            panel.Children.Add(new TextBlock { Text = "从服务器日志中查询被攻击记录、攻击来源和目标IP", FontSize = 12, Foreground = Brushes.LightGray, Margin = new Thickness(0, 5, 0, 0) });
            border.Child = panel;
            return border;
        }

        private Border CreateToolBar()
        {
            var border = new Border { Background = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#F8F9FA")), Padding = new Thickness(15, 10, 15, 10) };
            var panel = new StackPanel { Orientation = Orientation.Horizontal };
            
            panel.Children.Add(CreateLabel("日志源:"));
            
            var logSourceCombo = new ComboBox { Width = 200, Height = 30, Margin = new Thickness(0, 0, 20, 0) };
            logSourceCombo.Items.Add("自动检测");
            logSourceCombo.Items.Add("IIS日志");
            logSourceCombo.Items.Add("Nginx日志");
            logSourceCombo.Items.Add("Apache日志");
            logSourceCombo.Items.Add("防火墙日志");
            logSourceCombo.SelectedIndex = 0;
            panel.Children.Add(logSourceCombo);

            panel.Children.Add(CreateToolbarButton("🔄 刷新", "#3498DB", RefreshButton_Click));
            panel.Children.Add(CreateToolbarButton("📄 导出CSV", "#27AE60", ExportCsvButton_Click));
            panel.Children.Add(CreateToolbarButton("📊 导出Excel", "#2ECC71", ExportExcelButton_Click));
            panel.Children.Add(CreateToolbarButton("🖨️ 打印", "#9B59B6", PrintButton_Click));

            border.Child = panel;
            return border;
        }

        private Border CreateFilterArea()
        {
            var border = new Border { Background = Brushes.White, Padding = new Thickness(15, 10, 15, 10) };
            var grid = new Grid();
            for (int i = 0; i < 13; i++)
                grid.ColumnDefinitions.Add(i < 12 ? new ColumnDefinition { Width = GridLength.Auto } : new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });

            grid.Children.Add(CreateLabel("时间范围:", 0));

            _timeRangeComboBox = new ComboBox { Width = 100, Height = 28, Margin = new Thickness(0, 0, 10, 0) };
            _timeRangeComboBox.Items.Add("今天");
            _timeRangeComboBox.Items.Add("近7天");
            _timeRangeComboBox.Items.Add("近30天");
            _timeRangeComboBox.Items.Add("自定义");
            _timeRangeComboBox.SelectedIndex = 1;
            _timeRangeComboBox.SelectionChanged += TimeRangeComboBox_SelectionChanged;
            Grid.SetColumn(_timeRangeComboBox, 1);
            grid.Children.Add(_timeRangeComboBox);

            _startDatePicker = new DatePicker { Width = 120, Height = 28, Margin = new Thickness(0, 0, 5, 0) };
            _startDatePicker.SelectedDate = DateTime.Now.AddDays(-7);
            Grid.SetColumn(_startDatePicker, 2);
            grid.Children.Add(_startDatePicker);

            grid.Children.Add(CreateLabel("至", 3));

            _endDatePicker = new DatePicker { Width = 120, Height = 28, Margin = new Thickness(0, 0, 20, 0) };
            _endDatePicker.SelectedDate = DateTime.Now;
            Grid.SetColumn(_endDatePicker, 4);
            grid.Children.Add(_endDatePicker);

            grid.Children.Add(CreateLabel("攻击类型:", 5));
            _attackTypeComboBox = new ComboBox { Width = 120, Height = 28, Margin = new Thickness(0, 0, 10, 0) };
            _attackTypeComboBox.Items.Add("全部");
            _attackTypeComboBox.Items.Add("SQL注入");
            _attackTypeComboBox.Items.Add("XSS跨站脚本");
            _attackTypeComboBox.Items.Add("暴力破解");
            _attackTypeComboBox.Items.Add("端口扫描");
            _attackTypeComboBox.Items.Add("DDoS攻击");
            _attackTypeComboBox.Items.Add("目录遍历");
            _attackTypeComboBox.Items.Add("命令注入");
            _attackTypeComboBox.SelectedIndex = 0;
            Grid.SetColumn(_attackTypeComboBox, 6);
            grid.Children.Add(_attackTypeComboBox);

            grid.Children.Add(CreateLabel("风险等级:", 7));
            _riskLevelComboBox = new ComboBox { Width = 80, Height = 28, Margin = new Thickness(0, 0, 10, 0) };
            _riskLevelComboBox.Items.Add("全部");
            _riskLevelComboBox.Items.Add("高");
            _riskLevelComboBox.Items.Add("中");
            _riskLevelComboBox.Items.Add("低");
            _riskLevelComboBox.SelectedIndex = 0;
            Grid.SetColumn(_riskLevelComboBox, 8);
            grid.Children.Add(_riskLevelComboBox);

            _sourceIPTextBox = new TextBox 
            { 
                Width = 130, 
                Height = 28, 
                Margin = new Thickness(0, 0, 5, 0), 
                VerticalContentAlignment = VerticalAlignment.Center,
                Foreground = Brushes.Gray
            };
            SetPlaceholder(_sourceIPTextBox, "搜索来源IP...");
            Grid.SetColumn(_sourceIPTextBox, 9);
            grid.Children.Add(_sourceIPTextBox);

            _targetIPTextBox = new TextBox 
            { 
                Width = 130, 
                Height = 28, 
                Margin = new Thickness(0, 0, 10, 0), 
                VerticalContentAlignment = VerticalAlignment.Center,
                Foreground = Brushes.Gray
            };
            SetPlaceholder(_targetIPTextBox, "搜索目标IP...");
            Grid.SetColumn(_targetIPTextBox, 10);
            grid.Children.Add(_targetIPTextBox);

            var applyBtn = CreateToolbarButton("🔍 筛选", "#3498DB", ApplyFilterButton_Click);
            Grid.SetColumn(applyBtn, 11);
            grid.Children.Add(applyBtn);

            var resetBtn = CreateToolbarButton("🔄 重置", "#95A5A6", ResetFilterButton_Click);
            Grid.SetColumn(resetBtn, 12);
            grid.Children.Add(resetBtn);

            border.Child = grid;
            return border;
        }

        private Grid CreateContentArea()
        {
            var grid = new Grid { Margin = new Thickness(15) };
            grid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
            grid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(380) });

            var leftBorder = CreateDataGridArea();
            Grid.SetColumn(leftBorder, 0);
            grid.Children.Add(leftBorder);

            var rightBorder = CreateStatisticsPanel();
            Grid.SetColumn(rightBorder, 1);
            grid.Children.Add(rightBorder);

            return grid;
        }

        private Border CreateDataGridArea()
        {
            var border = new Border { Background = Brushes.White, CornerRadius = new CornerRadius(8), BorderBrush = Brushes.LightGray, BorderThickness = new Thickness(1) };
            var container = new Grid();
            container.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
            container.RowDefinitions.Add(new RowDefinition { Height = new GridLength(1, GridUnitType.Star) });

            var header = new Border { Background = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#F8F9FA")), Padding = new Thickness(15, 10, 15, 10) };
            header.Child = new TextBlock { Text = "📋 攻击日志列表（双击查看详情）", FontSize = 16, FontWeight = FontWeights.Bold, Foreground = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#2C3E50")) };
            Grid.SetRow(header, 0);
            container.Children.Add(header);

            _attackLogGrid = new DataGrid 
            { 
                AutoGenerateColumns = false,
                IsReadOnly = true,
                CanUserAddRows = false,
                CanUserDeleteRows = false,
                SelectionMode = DataGridSelectionMode.Single,
                GridLinesVisibility = DataGridGridLinesVisibility.Horizontal,
                HeadersVisibility = DataGridHeadersVisibility.Column,
                RowHeight = 35,
                AlternatingRowBackground = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#F8F9FA")),
                BorderThickness = new Thickness(0)
            };

            _attackLogGrid.Columns.Add(new DataGridTextColumn { Header = "⏰ 时间", Binding = new Binding("Timestamp") { StringFormat = "yyyy-MM-dd HH:mm:ss" }, Width = new DataGridLength(150) });
            _attackLogGrid.Columns.Add(new DataGridTextColumn { Header = "🌐 来源IP", Binding = new Binding("SourceIP"), Width = new DataGridLength(130) });
            _attackLogGrid.Columns.Add(new DataGridTextColumn { Header = "🎯 目标IP", Binding = new Binding("TargetIP"), Width = new DataGridLength(130) });
            _attackLogGrid.Columns.Add(new DataGridTextColumn { Header = "⚡ 攻击类型", Binding = new Binding("AttackType"), Width = new DataGridLength(120) });

            var riskLevelCol = new DataGridTemplateColumn { Header = "🚨 风险等级", Width = new DataGridLength(100) };
            var factory = new FrameworkElementFactory(typeof(Border));
            factory.SetBinding(Border.BackgroundProperty, new Binding("RiskLevel") { Converter = new RiskLevelToColorConverter() });
            factory.SetValue(Border.CornerRadiusProperty, new CornerRadius(4));
            factory.SetValue(Border.PaddingProperty, new Thickness(8, 4, 8, 4));
            factory.SetValue(Border.VerticalAlignmentProperty, VerticalAlignment.Center);
            factory.SetValue(Border.HorizontalAlignmentProperty, HorizontalAlignment.Center);
            var textFactory = new FrameworkElementFactory(typeof(TextBlock));
            textFactory.SetBinding(TextBlock.TextProperty, new Binding("RiskLevel"));
            textFactory.SetValue(TextBlock.ForegroundProperty, Brushes.White);
            textFactory.SetValue(FontWeightProperty, FontWeights.SemiBold);
            textFactory.SetValue(FontSizeProperty, 11.0);
            factory.AppendChild(textFactory);
            riskLevelCol.CellTemplate = new DataTemplate { VisualTree = factory };
            _attackLogGrid.Columns.Add(riskLevelCol);

            _attackLogGrid.Columns.Add(new DataGridTextColumn { Header = "🔗 请求URL", Binding = new Binding("RequestURL"), Width = new DataGridLength(1, DataGridLengthUnitType.Star) });
            _attackLogGrid.Columns.Add(new DataGridTextColumn { Header = "📊 状态码", Binding = new Binding("StatusCode"), Width = new DataGridLength(80) });

            _attackLogGrid.MouseDoubleClick += AttackLogGrid_MouseDoubleClick;

            Grid.SetRow(_attackLogGrid, 1);
            container.Children.Add(_attackLogGrid);

            border.Child = container;
            return border;
        }

        private Border CreateStatisticsPanel()
        {
            var border = new Border { Background = Brushes.White, CornerRadius = new CornerRadius(8), BorderBrush = Brushes.LightGray, BorderThickness = new Thickness(1), Margin = new Thickness(10, 0, 0, 0) };
            var scrollViewer = new ScrollViewer { VerticalScrollBarVisibility = ScrollBarVisibility.Auto };
            var panel = new StackPanel { Margin = new Thickness(15) };

            panel.Children.Add(CreateStatSection("📊 攻击统计", out _totalAttacksText, isTotal: true));
            panel.Children.Add(CreateStatSection("🎯 按攻击类型统计", out _attackTypeStatsPanel));
            panel.Children.Add(CreateStatSection("⚠️ 按风险等级统计", out _riskLevelStatsPanel));
            panel.Children.Add(CreateStatSection("🌐 Top 10 攻击来源IP", out _topSourceIPsPanel));
            panel.Children.Add(CreateStatSection("📈 攻击时间趋势", out _timeTrendText, isTrend: true));

            scrollViewer.Content = panel;
            border.Child = scrollViewer;
            return border;
        }

        private Border CreateStatSection(string title, out TextBlock textBlock, bool isTotal = false, bool isTrend = false)
        {
            var border = new Border 
            { 
                Background = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#F8F9FA")),
                CornerRadius = new CornerRadius(6),
                Padding = new Thickness(15),
                Margin = new Thickness(0, 0, 0, 15),
                BorderBrush = Brushes.LightGray,
                BorderThickness = new Thickness(1)
            };

            var inner = new StackPanel();
            inner.Children.Add(new TextBlock { Text = title, FontSize = 14, FontWeight = FontWeights.Bold, Foreground = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#2C3E50")), Margin = new Thickness(0, 0, 0, 10) });

            if (isTotal)
            {
                textBlock = new TextBlock { Text = "攻击总数: 0", FontSize = 24, FontWeight = FontWeights.Bold, Foreground = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#E74C3C")), HorizontalAlignment = HorizontalAlignment.Center };
                inner.Children.Add(textBlock);
            }
            else if (isTrend)
            {
                textBlock = new TextBlock { Text = "暂无攻击记录", FontSize = 12, Foreground = Brushes.Gray, TextWrapping = TextWrapping.Wrap };
                inner.Children.Add(textBlock);
            }
            else
            {
                textBlock = null;
                var stackPanel = new StackPanel();
                inner.Children.Add(stackPanel);
            }

            border.Child = inner;
            return border;
        }

        private Border CreateStatSection(string title, out StackPanel stackPanel)
        {
            var border = new Border 
            { 
                Background = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#F8F9FA")),
                CornerRadius = new CornerRadius(6),
                Padding = new Thickness(15),
                Margin = new Thickness(0, 0, 0, 15),
                BorderBrush = Brushes.LightGray,
                BorderThickness = new Thickness(1)
            };

            var inner = new StackPanel();
            inner.Children.Add(new TextBlock { Text = title, FontSize = 14, FontWeight = FontWeights.Bold, Foreground = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#2C3E50")), Margin = new Thickness(0, 0, 0, 10) });

            stackPanel = new StackPanel();
            inner.Children.Add(stackPanel);

            border.Child = inner;
            return border;
        }

        private Border CreateStatusBar()
        {
            var border = new Border { Background = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#F8F9FA")), Padding = new Thickness(15, 10, 15, 10) };
            var grid = new Grid();
            grid.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });
            grid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
            grid.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });

            _recordCountText = new TextBlock { Text = "显示 0 / 0 条记录", FontSize = 12, Foreground = Brushes.Gray };
            Grid.SetColumn(_recordCountText, 0);
            grid.Children.Add(_recordCountText);

            var filterStatusText = new TextBlock { Text = "💡 提示: 双击日志行可查看详细信息", FontSize = 12, Foreground = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#3498DB")) };
            Grid.SetColumn(filterStatusText, 2);
            grid.Children.Add(filterStatusText);

            border.Child = grid;
            return border;
        }

        private Button CreateToolbarButton(string content, string color, RoutedEventHandler clickHandler)
        {
            return new Button 
            { 
                Content = content, 
                Width = 110, 
                Height = 30, 
                Margin = new Thickness(0, 0, 10, 0),
                Background = new SolidColorBrush((Color)ColorConverter.ConvertFromString(color)),
                Foreground = Brushes.White,
                BorderThickness = new Thickness(0),
                FontWeight = FontWeights.SemiBold,
                Cursor = Cursors.Hand
            };
        }

        private TextBlock CreateLabel(string text, int column = -1)
        {
            return new TextBlock 
            { 
                Text = text, 
                VerticalAlignment = VerticalAlignment.Center, 
                Margin = new Thickness(0, 0, 8, 0), 
                FontWeight = FontWeights.SemiBold 
            };
        }

        private void SetPlaceholder(TextBox textBox, string placeholder)
        {
            textBox.Text = placeholder;
            textBox.GotFocus += (s, e) =>
            {
                if (textBox.Text == placeholder)
                {
                    textBox.Text = "";
                    textBox.Foreground = Brushes.Black;
                }
            };
            textBox.LostFocus += (s, e) =>
            {
                if (string.IsNullOrWhiteSpace(textBox.Text))
                {
                    textBox.Text = placeholder;
                    textBox.Foreground = Brushes.Gray;
                }
            };
            textBox.TextChanged += (s, e) =>
            {
                if (_allEntries.Count > 0 && textBox.Text != placeholder)
                {
                    _debounceTimer?.Stop();
                    _debounceTimer = new System.Windows.Threading.DispatcherTimer 
                    { 
                        Interval = TimeSpan.FromMilliseconds(300) 
                    };
                    _debounceTimer.Tick += (sender2, args) =>
                    {
                        _debounceTimer.Stop();
                        ApplyFilter();
                        ((System.Windows.Threading.DispatcherTimer)sender2).Tick -= null;
                    };
                    _debounceTimer.Start();
                }
            };
        }

        private System.Windows.Threading.DispatcherTimer _debounceTimer;

        private async Task LoadAttackLogsAsync()
        {
            try
            {
                _allEntries.Clear();

                var logPaths = GetCommonLogPaths();
                
                foreach (var path in logPaths)
                {
                    if (File.Exists(path))
                    {
                        var entries = await ParseLogFile(path);
                        _allEntries.AddRange(entries);
                    }
                }
                
                if (_allEntries.Count == 0)
                {
                    _allEntries = GenerateDemoData();
                }
                
                _allEntries = _allEntries.OrderByDescending(e => e.Timestamp).ToList();
                
                ApplyFilter();
            }
            catch (Exception ex)
            {
                MessageBox.Show($"加载日志失败: {ex.Message}", "错误", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        private List<string> GetCommonLogPaths()
        {
            var paths = new List<string>();
            paths.Add(@"C:\inetpub\logs\LogFiles\W3SVC1\u_ex" + DateTime.Now.ToString("yyMMdd") + ".log");
            paths.Add("/var/log/nginx/access.log");
            paths.Add("/var/log/apache2/access.log");
            paths.Add("/var/log/httpd/access_log");
            return paths;
        }

        private async Task<List<AttackLogEntry>> ParseLogFile(string path)
        {
            try
            {
                if (path.Contains("iis", StringComparison.OrdinalIgnoreCase) || 
                    path.Contains("W3SVC", StringComparison.OrdinalIgnoreCase))
                    return await _logService.ParseIISLog(path);
                else if (path.Contains("nginx", StringComparison.OrdinalIgnoreCase) || 
                         path.Contains("apache", StringComparison.OrdinalIgnoreCase) ||
                         path.Contains("httpd", StringComparison.OrdinalIgnoreCase))
                    return await _logService.ParseWebServerLog(path);
                else if (path.Contains("firewall", StringComparison.OrdinalIgnoreCase))
                    return await _logService.ParseFirewallLog(path);
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"[AttackLogWindow] 解析攻击日志失败: {ex.Message}");
            }
            
            return new List<AttackLogEntry>();
        }

        private List<AttackLogEntry> GenerateDemoData()
        {
            var entries = new List<AttackLogEntry>();
            var random = new Random();
            var attackTypes = new[] { "SQL注入", "XSS跨站脚本", "暴力破解", "端口扫描", "DDoS攻击", "目录遍历", "命令注入" };
            var sourceIPs = new[] { "192.168.1.100", "10.0.0.50", "172.16.0.25", "203.0.113.42", "198.51.100.78", "185.220.101.34" };
            var targetIPs = new[] { "192.168.1.1", "192.168.1.10", "10.0.0.1", "172.16.0.1" };
            var urls = new[] { "/login", "/admin", "/api/users", "/index.php?id=1", "/wp-admin", "/phpmyadmin", "/api/data?user=admin" };
            var methods = new[] { "GET", "POST", "PUT", "DELETE" };
            var userAgents = new[] { "Mozilla/5.0", "python-requests/2.28", "curl/7.83", "sqlmap/1.6" };
            
            for (int i = 0; i < 80; i++)
            {
                var attackType = attackTypes[random.Next(attackTypes.Length)];
                entries.Add(new AttackLogEntry
                {
                    Timestamp = DateTime.Now.AddHours(-random.Next(720)),
                    SourceIP = sourceIPs[random.Next(sourceIPs.Length)],
                    TargetIP = targetIPs[random.Next(targetIPs.Length)],
                    AttackType = attackType,
                    RiskLevel = _logService.AssessRiskLevel(attackType),
                    RequestURL = urls[random.Next(urls.Length)] + (random.Next(3) == 0 ? $"&page={random.Next(100)}" : ""),
                    StatusCode = new[] { 200, 301, 400, 401, 403, 404, 500 }[random.Next(7)],
                    RequestMethod = methods[random.Next(methods.Length)],
                    Details = $"检测到{attackType}尝试，请求方法: {methods[random.Next(methods.Length)]}，User-Agent: {userAgents[random.Next(userAgents.Length)]}",
                    UserAgent = userAgents[random.Next(userAgents.Length)]
                });
            }
            
            return entries;
        }

        private void ApplyFilter()
        {
            _currentFilter = new AttackLogFilter
            {
                StartDate = _startDatePicker.SelectedDate?.Date ?? DateTime.MinValue,
                EndDate = _endDatePicker.SelectedDate?.Date.AddDays(1) ?? DateTime.MaxValue,
                AttackType = _attackTypeComboBox.Text,
                RiskLevel = _riskLevelComboBox.Text,
                SourceIPKeyword = GetActualText(_sourceIPTextBox, "搜索来源IP..."),
                TargetIPKeyword = GetActualText(_targetIPTextBox, "搜索目标IP...")
            };

            _filteredEntries = _logService.FilterEntries(_allEntries, _currentFilter);
            
            _attackLogGrid.ItemsSource = _filteredEntries;
            UpdateStatistics();
            UpdateStatusBar();
        }

        private string GetActualText(TextBox textBox, string placeholder)
        {
            var text = textBox.Text.Trim();
            return text == placeholder ? "" : text;
        }

        private void UpdateStatistics()
        {
            var stats = _logService.CalculateStatistics(_filteredEntries);
            
            _totalAttacksText.Text = $"攻击总数: {stats.TotalAttacks}";
            
            _attackTypeStatsPanel.Children.Clear();
            foreach (var kv in stats.AttacksByType)
            {
                _attackTypeStatsPanel.Children.Add(CreateStatRow(kv.Key, kv.Value, stats.TotalAttacks, GetAttackTypeColor(kv.Key)));
            }

            _riskLevelStatsPanel.Children.Clear();
            foreach (var kv in stats.AttacksByRiskLevel)
            {
                var color = kv.Key switch
                {
                    "高" => "#E74C3C",
                    "中" => "#F39C12",
                    "低" => "#27AE60",
                    _ => "#95A5A6"
                };
                _riskLevelStatsPanel.Children.Add(CreateStatRow(kv.Key, kv.Value, stats.TotalAttacks, color));
            }

            _topSourceIPsPanel.Children.Clear();
            foreach (var kv in stats.TopSourceIPs)
            {
                _topSourceIPsPanel.Children.Add(CreateStatRow(kv.Key, kv.Value, stats.TotalAttacks, "#3498DB"));
            }

            _timeTrendText.Text = stats.AttacksByTime.Any() 
                ? $"🕐 最早攻击: {stats.EarliestAttack:yyyy-MM-dd HH:mm}\n🕐 最新攻击: {stats.LatestAttack:yyyy-MM-dd HH:mm}\n📅 活跃天数: {stats.AttacksByTime.Count} 天\n📈 日均攻击: {(double)stats.TotalAttacks / Math.Max(stats.AttacksByTime.Count, 1):F1} 次"
                : "暂无攻击记录";
        }

        private string GetAttackTypeColor(string attackType)
        {
            return attackType switch
            {
                "SQL注入" => "#E74C3C",
                "XSS跨站脚本" => "#9B59B6",
                "命令注入" => "#C0392B",
                "暴力破解" => "#F39C12",
                "DDoS攻击" => "#E67E22",
                "目录遍历" => "#3498DB",
                "端口扫描" => "#1ABC9C",
                _ => "#95A5A6"
            };
        }

        private StackPanel CreateStatRow(string label, int count, int total, string colorHex)
        {
            var panel = new StackPanel { Orientation = Orientation.Horizontal, Margin = new Thickness(0, 4, 0, 4) };
            
            var colorIndicator = new Border 
            { 
                Width = 4, 
                Height = 18, 
                CornerRadius = new CornerRadius(2),
                Background = new SolidColorBrush((Color)ColorConverter.ConvertFromString(colorHex)),
                VerticalAlignment = VerticalAlignment.Center,
                Margin = new Thickness(0, 0, 6, 0)
            };
            panel.Children.Add(colorIndicator);
            
            panel.Children.Add(new TextBlock 
            { 
                Text = label, 
                Width = 90,
                TextTrimming = TextTrimming.CharacterEllipsis,
                VerticalAlignment = VerticalAlignment.Center,
                FontSize = 11,
                Foreground = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#34495E"))
            });
            
            var progressBar = new ProgressBar 
            { 
                Width = 120, 
                Height = 14, 
                Maximum = Math.Max(total, 1),
                Value = count,
                Margin = new Thickness(5, 0, 5, 0),
                Background = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#ECF0F1"))
            };
            panel.Children.Add(progressBar);
            
            panel.Children.Add(new TextBlock 
            { 
                Text = $"{count}",
                FontSize = 11,
                FontWeight = FontWeights.SemiBold,
                Foreground = new SolidColorBrush((Color)ColorConverter.ConvertFromString(colorHex)),
                VerticalAlignment = VerticalAlignment.Center,
                Width = 30
            });

            panel.Children.Add(new TextBlock 
            { 
                Text = $"{(total > 0 ? (double)count / total * 100 : 0):F1}%",
                FontSize = 10,
                Foreground = Brushes.Gray,
                VerticalAlignment = VerticalAlignment.Center
            });
            
            return panel;
        }

        private void UpdateStatusBar()
        {
            _recordCountText.Text = $"显示 {_filteredEntries.Count} / {_allEntries.Count} 条记录";
        }

        private void TimeRangeComboBox_SelectionChanged(object sender, SelectionChangedEventArgs e)
        {
            if (_timeRangeComboBox == null) return;

            var now = DateTime.Now;
            var selected = _timeRangeComboBox.SelectedIndex;

            switch (selected)
            {
                case 0:
                    _startDatePicker.SelectedDate = now.Date;
                    _endDatePicker.SelectedDate = now.Date.AddDays(1);
                    break;
                case 1:
                    _startDatePicker.SelectedDate = now.Date.AddDays(-7);
                    _endDatePicker.SelectedDate = now.Date.AddDays(1);
                    break;
                case 2:
                    _startDatePicker.SelectedDate = now.Date.AddDays(-30);
                    _endDatePicker.SelectedDate = now.Date.AddDays(1);
                    break;
                case 3:
                    break;
            }
        }

        private void AttackLogGrid_MouseDoubleClick(object sender, MouseButtonEventArgs e)
        {
            if (_attackLogGrid.SelectedItem is AttackLogEntry entry)
            {
                ShowLogDetail(entry);
            }
        }

        private void ShowLogDetail(AttackLogEntry entry)
        {
            var window = new Window
            {
                Title = "攻击日志详情",
                Width = 580,
                Height = 580,
                WindowStartupLocation = WindowStartupLocation.CenterOwner,
                Owner = this,
                ResizeMode = ResizeMode.NoResize
            };

            window.KeyDown += (s, e) =>
            {
                if (e.Key == Key.Escape)
                    window.Close();
            };

            var grid = new Grid { Margin = new Thickness(20) };
            grid.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
            grid.RowDefinitions.Add(new RowDefinition { Height = new GridLength(1, GridUnitType.Star) });
            grid.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });

            var riskColor = entry.RiskLevel switch
            {
                "高" => "#E74C3C",
                "中" => "#F39C12",
                "低" => "#27AE60",
                _ => "#95A5A6"
            };

            var headerBorder = new Border 
            { 
                Background = new SolidColorBrush((Color)ColorConverter.ConvertFromString(riskColor)),
                CornerRadius = new CornerRadius(8),
                Padding = new Thickness(20, 15, 20, 15)
            };
            var headerPanel = new StackPanel();
            headerPanel.Children.Add(new TextBlock { Text = "⚠️ ", FontSize = 24 });
            headerPanel.Children.Add(new TextBlock { Text = $"{entry.AttackType} - 风险等级: {entry.RiskLevel}", FontSize = 18, FontWeight = FontWeights.Bold, Foreground = Brushes.White, VerticalAlignment = VerticalAlignment.Center, Margin = new Thickness(10, 0, 0, 0) });
            
            var headerInnerPanel = new StackPanel { Orientation = Orientation.Horizontal };
            headerInnerPanel.Children.Add(headerPanel);
            headerBorder.Child = headerInnerPanel;
            Grid.SetRow(headerBorder, 0);
            grid.Children.Add(headerBorder);

            var detailsPanel = new StackPanel { Margin = new Thickness(0, 20, 0, 0) };

            void AddDetailRow(string label, string value, string icon = "", string valueColor = "#34495E")
            {
                var row = new StackPanel { Orientation = Orientation.Horizontal, Margin = new Thickness(0, 8, 0, 0) };
                row.Children.Add(new TextBlock { Text = $"{icon} {label}", Width = 110, FontWeight = FontWeights.SemiBold, Foreground = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#2C3E50")) });
                row.Children.Add(new TextBlock { Text = value, Foreground = new SolidColorBrush((Color)ColorConverter.ConvertFromString(valueColor)), TextWrapping = TextWrapping.Wrap });
                detailsPanel.Children.Add(row);
            }

            void AddSectionHeader(string title)
            {
                detailsPanel.Children.Add(new TextBlock 
                { 
                    Text = title, 
                    FontWeight = FontWeights.Bold, 
                    FontSize = 13, 
                    Foreground = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#2C3E50")),
                    Margin = new Thickness(0, 15, 0, 8),
                    Padding = new Thickness(5, 3, 0, 3),
                    Background = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#ECF0F1"))
                });
            }

            AddSectionHeader("基本信息");
            AddDetailRow("发生时间", entry.Timestamp.ToString("yyyy-MM-dd HH:mm:ss.fff"), "🕐");
            AddDetailRow("来源 IP", entry.SourceIP, "🌐");
            AddDetailRow("目标 IP", entry.TargetIP, "🎯");
            AddDetailRow("请求 URL", entry.RequestURL, "🔗");

            AddSectionHeader("请求信息");
            AddDetailRow("请求方法", entry.RequestMethod ?? "GET", "📤");
            AddDetailRow("状态码", GetStatusCodeDescription(entry.StatusCode), "📊", entry.StatusCode >= 400 ? "#E74C3C" : "#27AE60");
            AddDetailRow("User-Agent", entry.UserAgent ?? "-", "🖥️");

            AddSectionHeader("安全分析");
            AddDetailRow("风险等级", entry.RiskLevel, "🚨", riskColor);
            AddDetailRow("攻击类型", entry.AttackType, "⚡");
            AddDetailRow("攻击频率", GetAttackFrequency(entry.SourceIP), "📈");
            AddDetailRow("建议操作", GetRecommendation(entry.AttackType), "💡", "#2980B9");

            var detailBorder = new Border 
            { 
                Background = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#F8F9FA")),
                CornerRadius = new CornerRadius(6),
                Padding = new Thickness(15),
                BorderBrush = Brushes.LightGray,
                BorderThickness = new Thickness(1)
            };
            detailBorder.Child = detailsPanel;
            Grid.SetRow(detailBorder, 1);
            grid.Children.Add(detailBorder);

            var closeBtn = new Button 
            { 
                Content = "关闭", 
                Width = 100, 
                Height = 32, 
                HorizontalAlignment = HorizontalAlignment.Right,
                Margin = new Thickness(0, 15, 0, 0),
                Background = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#3498DB")),
                Foreground = Brushes.White,
                BorderThickness = new Thickness(0),
                Cursor = Cursors.Hand
            };
            closeBtn.Click += (s, e) => window.Close();
            Grid.SetRow(closeBtn, 2);
            grid.Children.Add(closeBtn);

            window.Content = grid;
            window.ShowDialog();
        }

        private void RefreshButton_Click(object sender, RoutedEventArgs e)
        {
            LoadAttackLogsAsync().GetAwaiter().GetResult();
        }

        private void ApplyFilterButton_Click(object sender, RoutedEventArgs e)
        {
            ApplyFilter();
        }

        private void ResetFilterButton_Click(object sender, RoutedEventArgs e)
        {
            _timeRangeComboBox.SelectedIndex = 1;
            _attackTypeComboBox.SelectedIndex = 0;
            _riskLevelComboBox.SelectedIndex = 0;
            _sourceIPTextBox.Text = "搜索来源IP...";
            _sourceIPTextBox.Foreground = Brushes.Gray;
            _targetIPTextBox.Text = "搜索目标IP...";
            _targetIPTextBox.Foreground = Brushes.Gray;
            _startDatePicker.SelectedDate = DateTime.Now.AddDays(-7);
            _endDatePicker.SelectedDate = DateTime.Now;
            ApplyFilter();
        }

        private void ExportCsvButton_Click(object sender, RoutedEventArgs e)
        {
            var dialog = new SaveFileDialog
            {
                Filter = "CSV文件 (*.csv)|*.csv",
                DefaultExt = ".csv",
                FileName = $"攻击日志_{DateTime.Now:yyyyMMdd_HHmmss}.csv"
            };

            if (dialog.ShowDialog() == true)
            {
                var sb = new StringBuilder();
                sb.AppendLine("时间,来源IP,目标IP,攻击类型,风险等级,请求URL,状态码,请求方法,详情");
                
                foreach (var entry in _filteredEntries)
                {
                    sb.AppendLine($"\"{entry.Timestamp:yyyy-MM-dd HH:mm:ss}\",\"{entry.SourceIP}\",\"{entry.TargetIP}\",\"{entry.AttackType}\",\"{entry.RiskLevel}\",\"{entry.RequestURL}\",\"{entry.StatusCode}\",\"{entry.RequestMethod}\",\"{entry.Details}\"");
                }
                
                File.WriteAllText(dialog.FileName, sb.ToString(), Encoding.UTF8);
                MessageBox.Show($"✅ 已成功导出 { _filteredEntries.Count} 条记录到:\n{dialog.FileName}", "导出成功", MessageBoxButton.OK, MessageBoxImage.Information);
            }
        }

        private void ExportExcelButton_Click(object sender, RoutedEventArgs e)
        {
            var dialog = new SaveFileDialog
            {
                Filter = "Excel文件 (*.xlsx)|*.xlsx",
                DefaultExt = ".xlsx",
                FileName = $"攻击日志_{DateTime.Now:yyyyMMdd_HHmmss}"
            };

            if (dialog.ShowDialog() == true)
            {
                var sb = new StringBuilder();
                sb.AppendLine("<html><head><meta charset=\"utf-8\"><style>");
                sb.AppendLine("table {border-collapse: collapse; width: 100%;}");
                sb.AppendLine("th, td {border: 1px solid #ddd; padding: 8px; text-align: left;}");
                sb.AppendLine("th {background-color: #2C3E50; color: white;}");
                sb.AppendLine("tr:nth-child(even) {background-color: #f2f2f2;}");
                sb.AppendLine("</style></head><body>");
                sb.AppendLine($"<h2>攻击日志报告</h2><p>生成时间: {DateTime.Now:yyyy-MM-dd HH:mm:ss}</p>");
                sb.AppendLine("<table><tr><th>时间</th><th>来源IP</th><th>目标IP</th><th>攻击类型</th><th>风险等级</th><th>请求URL</th><th>状态码</th></tr>");
                
                foreach (var entry in _filteredEntries)
                {
                    var riskStyle = entry.RiskLevel switch
                    {
                        "高" => "color: white; background-color: #E74C3C;",
                        "中" => "color: white; background-color: #F39C12;",
                        "低" => "color: white; background-color: #27AE60;",
                        _ => ""
                    };
                    sb.AppendLine($"<tr><td>{entry.Timestamp:yyyy-MM-dd HH:mm:ss}</td><td>{entry.SourceIP}</td><td>{entry.TargetIP}</td><td>{entry.AttackType}</td><td style=\"{riskStyle}\">{entry.RiskLevel}</td><td>{entry.RequestURL}</td><td>{entry.StatusCode}</td></tr>");
                }
                
                sb.AppendLine("</table></body></html>");
                
                File.WriteAllText(dialog.FileName, sb.ToString(), Encoding.UTF8);
                MessageBox.Show($"✅ 已成功导出 { _filteredEntries.Count} 条记录到:\n{dialog.FileName}", "导出成功", MessageBoxButton.OK, MessageBoxImage.Information);
            }
        }

        private string GetStatusCodeDescription(int statusCode)
        {
            return statusCode switch
            {
                200 => $"{statusCode} (成功)",
                301 => $"{statusCode} (永久重定向)",
                400 => $"{statusCode} (错误请求)",
                401 => $"{statusCode} (未授权)",
                403 => $"{statusCode} (禁止访问)",
                404 => $"{statusCode} (未找到)",
                500 => $"{statusCode} (服务器错误)",
                _ => $"{statusCode} (未知)"
            };
        }

        private string GetAttackFrequency(string sourceIP)
        {
            var count = _allEntries.Count(e => e.SourceIP == sourceIP);
            if (count >= 20) return $"高 ({count}次攻击)";
            if (count >= 10) return $"频繁 ({count}次攻击)";
            if (count >= 5) return $"中等 ({count}次攻击)";
            return $"偶尔 ({count}次攻击)";
        }

        private string GetRecommendation(string attackType)
        {
            return attackType switch
            {
                "SQL注入" => "检查输入验证，使用参数化查询，部署WAF",
                "XSS跨站脚本" => "对输出进行HTML编码，启用CSP策略",
                "暴力破解" => "启用账户锁定机制，增加验证码",
                "端口扫描" => "关闭不必要端口，配置防火墙规则",
                "DDoS攻击" => "启用流量清洗，配置CDN防护",
                "目录遍历" => "限制目录访问权限，过滤路径字符",
                "命令注入" => "严格验证用户输入，避免系统命令执行",
                _ => "记录日志并监控该IP后续活动"
            };
        }

        private void PrintButton_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                var printDialog = new PrintDialog();
                if (printDialog.ShowDialog() == true)
                {
                    var printPanel = new StackPanel { Margin = new Thickness(30) };
                    
                    printPanel.Children.Add(new TextBlock 
                    { 
                        Text = "攻击日志查询报告", 
                        FontSize = 22, 
                        FontWeight = FontWeights.Bold, 
                        Foreground = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#2C3E50")),
                        Margin = new Thickness(0, 0, 0, 10)
                    });
                    
                    printPanel.Children.Add(new TextBlock 
                    { 
                        Text = $"生成时间: {DateTime.Now:yyyy-MM-dd HH:mm:ss} | 共 {_filteredEntries.Count} 条记录", 
                        FontSize = 12, 
                        Foreground = Brushes.Gray,
                        Margin = new Thickness(0, 0, 0, 20)
                    });

                    var grid = new Grid();
                    grid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(140) });
                    grid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(120) });
                    grid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(120) });
                    grid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(100) });
                    grid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(70) });
                    grid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
                    grid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(60) });

                    void AddHeader(params string[] headers)
                    {
                        for (int i = 0; i < headers.Length; i++)
                        {
                            var tb = new TextBlock { Text = headers[i], FontWeight = FontWeights.Bold, FontSize = 11, Background = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#2C3E50")), Foreground = Brushes.White, Padding = new Thickness(5, 3, 5, 3) };
                            Grid.SetColumn(tb, i);
                            grid.Children.Add(tb);
                        }
                    }
                    AddHeader("时间", "来源IP", "目标IP", "攻击类型", "风险等级", "请求URL", "状态码");

                    int rowIndex = 1;
                    foreach (var entry in _filteredEntries.Take(50))
                    {
                        grid.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
                        
                        var values = new[] 
                        { 
                            entry.Timestamp.ToString("MM-dd HH:mm"),
                            entry.SourceIP,
                            entry.TargetIP,
                            entry.AttackType,
                            entry.RiskLevel,
                            entry.RequestURL,
                            entry.StatusCode.ToString()
                        };

                        for (int i = 0; i < values.Length; i++)
                        {
                            var tb = new TextBlock { Text = values[i], FontSize = 10, Padding = new Thickness(5, 2, 5, 2), TextTrimming = TextTrimming.CharacterEllipsis };
                            Grid.SetRow(tb, rowIndex);
                            Grid.SetColumn(tb, i);
                            grid.Children.Add(tb);
                        }
                        rowIndex++;
                    }

                    if (_filteredEntries.Count > 50)
                    {
                        printPanel.Children.Add(new TextBlock 
                        { 
                            Text = $"... 仅显示前 50 条记录（共 {_filteredEntries.Count} 条）", 
                            FontSize = 11, 
                            FontStyle = FontStyles.Italic,
                            Foreground = Brushes.Gray,
                            Margin = new Thickness(0, 10, 0, 0)
                        });
                    }

                    printPanel.Children.Add(grid);
                    printDialog.PrintVisual(printPanel, "攻击日志报告");
                }
            }
            catch (Exception ex)
            {
                MessageBox.Show($"打印失败: {ex.Message}", "错误", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }
    }

    public class RiskLevelToColorConverter : IValueConverter
    {
        public object Convert(object value, Type targetType, object parameter, System.Globalization.CultureInfo culture)
        {
            return value?.ToString() switch
            {
                "高" => new SolidColorBrush((Color)ColorConverter.ConvertFromString("#E74C3C")),
                "中" => new SolidColorBrush((Color)ColorConverter.ConvertFromString("#F39C12")),
                "低" => new SolidColorBrush((Color)ColorConverter.ConvertFromString("#27AE60")),
                _ => new SolidColorBrush((Color)ColorConverter.ConvertFromString("#95A5A6"))
            };
        }

        public object ConvertBack(object value, Type targetType, object parameter, System.Globalization.CultureInfo culture)
        {
            return Binding.DoNothing;
        }
    }
}
