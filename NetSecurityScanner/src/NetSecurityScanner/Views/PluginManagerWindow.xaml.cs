using Microsoft.Win32;
using NetSecurityScanner.Plugins;
using NetSecurityScanner.Services;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Input;
using System.Windows.Media;

namespace NetSecurityScanner.Views
{
    public partial class PluginManagerWindow : Window
    {
        private readonly PluginManager _pluginManager;
        private IVulnerabilityScannerPlugin? _selectedPlugin;
        private Dictionary<string, bool> _pluginEnabledStates = new();

        private DataGrid _pluginsDataGrid;
        private StackPanel _pluginDetailPanel;
        private Button _configureButton;
        private Button _enableDisableButton;
        private Button _uninstallButton;
        private Button _checkUpdatesButton;
        private TextBox _searchTextBox;
        private ComboBox _categoryFilterComboBox;
        private List<PluginDisplayInfo> _allPluginDisplayInfos;

        public PluginManagerWindow()
        {
            Title = "插件管理器";
            Width = 1050;
            Height = 700;
            WindowStartupLocation = WindowStartupLocation.CenterOwner;
            Background = Brushes.White;

            _pluginManager = new PluginManager();

            BuildUI();

            KeyDown += Window_KeyDown;

            Loaded += async (s, e) =>
            {
                try
                {
                    await _pluginManager.LoadAllPluginsAsync();
                    foreach (var plugin in _pluginManager.Plugins.Values)
                    {
                        var config = _pluginManager.GetPluginConfig(plugin.PluginId);
                        if (config != null && config.TryGetValue("IsEnabled", out var enabledVal))
                        {
                            _pluginEnabledStates[plugin.PluginId] = Convert.ToBoolean(enabledVal);
                        }
                        else
                        {
                            _pluginEnabledStates[plugin.PluginId] = true;
                        }
                    }
                    RefreshPluginList();
                }
                catch (Exception ex)
                {
                    MessageBox.Show($"加载插件失败: {ex.Message}", "错误", MessageBoxButton.OK, MessageBoxImage.Error);
                }
            };
        }

        private void Window_KeyDown(object sender, KeyEventArgs e)
        {
            if (e.Key == Key.Enter)
            {
                RefreshPluginList();
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
            rootGrid.RowDefinitions.Add(new RowDefinition { Height = new GridLength(1, GridUnitType.Star) });
            rootGrid.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });

            var headerBorder = CreateHeaderBar();
            Grid.SetRow(headerBorder, 0);
            rootGrid.Children.Add(headerBorder);

            var toolbarBorder = CreateToolBar();
            Grid.SetRow(toolbarBorder, 1);
            rootGrid.Children.Add(toolbarBorder);

            var contentGrid = CreateContentArea();
            Grid.SetRow(contentGrid, 2);
            rootGrid.Children.Add(contentGrid);

            var bottomBar = CreateBottomBar();
            Grid.SetRow(bottomBar, 3);
            rootGrid.Children.Add(bottomBar);

            Content = rootGrid;
        }

        private Border CreateHeaderBar()
        {
            var border = new Border
            {
                Padding = new Thickness(20, 15, 20, 15),
                Background = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#6C5CE7"))
            };
            var panel = new StackPanel();
            panel.Children.Add(new TextBlock { Text = "🔌 插件管理器", FontSize = 24, FontWeight = FontWeights.Bold, Foreground = Brushes.White });
            panel.Children.Add(new TextBlock { Text = "管理漏洞扫描插件，安装、配置和卸载插件", FontSize = 12, Foreground = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#E8DAEF")), Margin = new Thickness(0, 5, 0, 0) });
            border.Child = panel;
            return border;
        }

        private Border CreateToolBar()
        {
            var border = new Border { Background = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#F8F9FA")), Padding = new Thickness(15, 10, 15, 10) };
            var grid = new Grid();
            grid.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
            grid.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });

            // Row 0: existing buttons
            var panel = new StackPanel { Orientation = Orientation.Horizontal };

            var installBtn = CreateToolbarButton("📥 安装插件", "#6C5CE7", InstallPluginButton_Click);
            panel.Children.Add(installBtn);

            var refreshBtn = CreateToolbarButton("🔄 刷新", "#3498DB", (s, e) => RefreshPluginList());
            panel.Children.Add(refreshBtn);

            var openFolderBtn = CreateToolbarButton("📂 打开插件目录", "#95A5A6", OpenPluginFolderButton_Click);
            panel.Children.Add(openFolderBtn);

            var marketBtn = CreateToolbarButton("🏪 插件市场", "#27AE60", OpenPluginMarket_Click);
            panel.Children.Add(marketBtn);

            var checkUpdatesBtn = CreateToolbarButton("🔄 检查更新", "#E67E22", CheckUpdatesButton_Click);
            _checkUpdatesButton = checkUpdatesBtn;
            panel.Children.Add(checkUpdatesBtn);

            Grid.SetRow(panel, 0);
            grid.Children.Add(panel);

            // Row 1: search and filter
            var filterPanel = new StackPanel { Orientation = Orientation.Horizontal };

            _searchTextBox = new TextBox
            {
                Width = 200,
                Height = 28,
                VerticalContentAlignment = VerticalAlignment.Center,
                Margin = new Thickness(0, 5, 10, 0),
                Tag = "搜索插件..."
            };
            _searchTextBox.GotFocus += (s, e) =>
            {
                if (_searchTextBox.Text == "搜索插件...")
                {
                    _searchTextBox.Text = "";
                    _searchTextBox.Foreground = Brushes.Black;
                }
            };
            _searchTextBox.LostFocus += (s, e) =>
            {
                if (string.IsNullOrWhiteSpace(_searchTextBox.Text))
                {
                    _searchTextBox.Text = "搜索插件...";
                    _searchTextBox.Foreground = Brushes.Gray;
                }
            };
            _searchTextBox.Foreground = Brushes.Gray;
            _searchTextBox.Text = "搜索插件...";
            _searchTextBox.TextChanged += SearchTextBox_TextChanged;
            filterPanel.Children.Add(_searchTextBox);

            _categoryFilterComboBox = new ComboBox
            {
                Width = 150,
                Height = 28,
                Margin = new Thickness(0, 5, 0, 0),
                VerticalContentAlignment = VerticalAlignment.Center
            };
            _categoryFilterComboBox.Items.Add("全部类别");
            _categoryFilterComboBox.Items.Add("SSH");
            _categoryFilterComboBox.Items.Add("Telnet");
            _categoryFilterComboBox.Items.Add("FTP");
            _categoryFilterComboBox.Items.Add("MySQL");
            _categoryFilterComboBox.Items.Add("Redis");
            _categoryFilterComboBox.Items.Add("HTTP");
            _categoryFilterComboBox.Items.Add("HTTPS");
            _categoryFilterComboBox.Items.Add("SMTP");
            _categoryFilterComboBox.Items.Add("DNS");
            _categoryFilterComboBox.SelectedIndex = 0;
            _categoryFilterComboBox.SelectionChanged += CategoryFilterComboBox_SelectionChanged;
            filterPanel.Children.Add(_categoryFilterComboBox);

            Grid.SetRow(filterPanel, 1);
            grid.Children.Add(filterPanel);

            border.Child = grid;
            return border;
        }

        private Grid CreateContentArea()
        {
            var grid = new Grid { Margin = new Thickness(15) };
            grid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
            grid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(380) });

            var leftBorder = new Border { Background = Brushes.White, CornerRadius = new CornerRadius(8), BorderBrush = Brushes.LightGray, BorderThickness = new Thickness(1) };
            var leftContainer = new Grid();
            leftContainer.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
            leftContainer.RowDefinitions.Add(new RowDefinition { Height = new GridLength(1, GridUnitType.Star) });

            var listHeader = new Border { Background = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#F8F9FA")), Padding = new Thickness(15, 10, 15, 10) };
            listHeader.Child = new TextBlock { Text = "📋 已安装插件", FontSize = 16, FontWeight = FontWeights.Bold, Foreground = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#2C3E50")) };
            Grid.SetRow(listHeader, 0);
            leftContainer.Children.Add(listHeader);

            _pluginsDataGrid = new DataGrid
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

            _pluginsDataGrid.Columns.Add(new DataGridTextColumn { Header = "名称", Binding = new Binding("Name"), Width = new DataGridLength(150) });
            _pluginsDataGrid.Columns.Add(new DataGridTextColumn { Header = "版本", Binding = new Binding("Version"), Width = new DataGridLength(70) });
            _pluginsDataGrid.Columns.Add(new DataGridTextColumn { Header = "作者", Binding = new Binding("Author"), Width = new DataGridLength(120) });
            _pluginsDataGrid.Columns.Add(new DataGridTextColumn { Header = "类别", Binding = new Binding("Category"), Width = new DataGridLength(100) });

            var statusCol = new DataGridTemplateColumn { Header = "状态", Width = new DataGridLength(90) };
            var factory = new FrameworkElementFactory(typeof(Border));
            factory.SetBinding(Border.BackgroundProperty, new Binding("StatusColor"));
            factory.SetValue(Border.CornerRadiusProperty, new CornerRadius(4));
            factory.SetValue(Border.PaddingProperty, new Thickness(8, 4, 8, 4));
            factory.SetValue(Border.HorizontalAlignmentProperty, HorizontalAlignment.Center);
            var textFactory = new FrameworkElementFactory(typeof(TextBlock));
            textFactory.SetBinding(TextBlock.TextProperty, new Binding("StatusText"));
            textFactory.SetValue(TextBlock.ForegroundProperty, Brushes.White);
            textFactory.SetValue(FontWeightProperty, FontWeights.SemiBold);
            textFactory.SetValue(FontSizeProperty, 11.0);
            factory.AppendChild(textFactory);
            statusCol.CellTemplate = new DataTemplate { VisualTree = factory };
            _pluginsDataGrid.Columns.Add(statusCol);

            _pluginsDataGrid.SelectionChanged += PluginsDataGrid_SelectionChanged;

            Grid.SetRow(_pluginsDataGrid, 1);
            leftContainer.Children.Add(_pluginsDataGrid);

            leftBorder.Child = leftContainer;
            Grid.SetColumn(leftBorder, 0);
            grid.Children.Add(leftBorder);

            var rightBorder = new Border { Background = Brushes.White, CornerRadius = new CornerRadius(8), BorderBrush = Brushes.LightGray, BorderThickness = new Thickness(1), Margin = new Thickness(10, 0, 0, 0) };
            var scrollViewer = new ScrollViewer { VerticalScrollBarVisibility = ScrollBarVisibility.Auto };
            _pluginDetailPanel = new StackPanel { Margin = new Thickness(15) };
            _pluginDetailPanel.Children.Add(new TextBlock { Text = "👈 请从左侧选择一个插件查看详情", HorizontalAlignment = HorizontalAlignment.Center, Foreground = Brushes.Gray, FontSize = 14, Margin = new Thickness(20) });
            scrollViewer.Content = _pluginDetailPanel;
            rightBorder.Child = scrollViewer;
            Grid.SetColumn(rightBorder, 1);
            grid.Children.Add(rightBorder);

            return grid;
        }

        private Border CreateBottomBar()
        {
            var border = new Border { Background = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#F8F9FA")), Padding = new Thickness(15, 10, 15, 10) };
            var panel = new StackPanel { Orientation = Orientation.Horizontal, HorizontalAlignment = HorizontalAlignment.Right };

            _configureButton = new Button { Content = "⚙️ 配置", Width = 100, Height = 35, Margin = new Thickness(5), IsEnabled = false, Cursor = Cursors.Hand };
            _configureButton.Click += ConfigureButton_Click;
            panel.Children.Add(_configureButton);

            _enableDisableButton = new Button { Content = "✅ 启用/禁用", Width = 120, Height = 35, Margin = new Thickness(5), IsEnabled = false, Cursor = Cursors.Hand };
            _enableDisableButton.Click += EnableDisableButton_Click;
            panel.Children.Add(_enableDisableButton);

            _uninstallButton = new Button { Content = "🗑️ 卸载", Width = 100, Height = 35, Margin = new Thickness(5), IsEnabled = false, Background = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#E74C3C")), Foreground = Brushes.White, BorderThickness = new Thickness(0), Cursor = Cursors.Hand };
            _uninstallButton.Click += UninstallButton_Click;
            panel.Children.Add(_uninstallButton);

            var closeBtn = new Button { Content = "❌ 关闭", Width = 100, Height = 35, Margin = new Thickness(5), Cursor = Cursors.Hand };
            closeBtn.Click += (s, e) => Close();
            panel.Children.Add(closeBtn);

            border.Child = panel;
            return border;
        }

        private Button CreateToolbarButton(string content, string color, RoutedEventHandler clickHandler)
        {
            return new Button
            {
                Content = content,
                Width = 130,
                Height = 30,
                Margin = new Thickness(0, 0, 10, 0),
                Background = new SolidColorBrush((Color)ColorConverter.ConvertFromString(color)),
                Foreground = Brushes.White,
                BorderThickness = new Thickness(0),
                FontWeight = FontWeights.SemiBold,
                Cursor = Cursors.Hand
            };
        }

        private void RefreshPluginList()
        {
            var pluginInfos = _pluginManager.Plugins.Values.Select(p =>
            {
                var status = p.GetStatus();
                var isEnabled = _pluginEnabledStates.TryGetValue(p.PluginId, out var enabled) ? enabled : true;
                return new PluginDisplayInfo
                {
                    PluginId = p.PluginId,
                    Name = p.Name,
                    Version = p.Version,
                    Author = p.Author,
                    Category = string.Join(", ", p.SupportedScanTypes.Take(3)),
                    StatusText = !isEnabled ? "已禁用" : (status.IsInitialized ? "正常" : "未初始化"),
                    StatusColor = !isEnabled ? "#95A5A6" : (status.IsInitialized ? "#27AE60" : "#F39C12"),
                    IsEnabled = isEnabled,
                    IsBuiltIn = p.PluginId.StartsWith("builtin.")
                };
            }).ToList();

            _allPluginDisplayInfos = pluginInfos;
            ApplyFilters();
        }

        private void PluginsDataGrid_SelectionChanged(object sender, SelectionChangedEventArgs e)
        {
            if (_pluginsDataGrid.SelectedItem is PluginDisplayInfo info)
            {
                _selectedPlugin = _pluginManager.Plugins.Values.FirstOrDefault(p => p.PluginId == info.PluginId);
                DisplayPluginDetails(_selectedPlugin, info);
            }
        }

        private void DisplayPluginDetails(IVulnerabilityScannerPlugin? plugin, PluginDisplayInfo? displayInfo)
        {
            _pluginDetailPanel.Children.Clear();

            if (plugin == null)
            {
                _pluginDetailPanel.Children.Add(new TextBlock { Text = "👈 请从左侧选择一个插件查看详情", HorizontalAlignment = HorizontalAlignment.Center, Foreground = Brushes.Gray, FontSize = 14, Margin = new Thickness(20) });
                _configureButton.IsEnabled = false;
                _enableDisableButton.IsEnabled = false;
                _uninstallButton.IsEnabled = false;
                return;
            }

            var status = plugin.GetStatus();
            var isEnabled = displayInfo?.IsEnabled ?? true;

            _pluginDetailPanel.Children.Add(new TextBlock { Text = plugin.Name, FontSize = 20, FontWeight = FontWeights.Bold, Foreground = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#2C3E50")), Margin = new Thickness(0, 0, 0, 5) });

            var statusBorder = new Border
            {
                Background = new SolidColorBrush((Color)ColorConverter.ConvertFromString(displayInfo?.StatusColor ?? "#95A5A6")),
                CornerRadius = new CornerRadius(4),
                Padding = new Thickness(10, 4, 10, 4),
                HorizontalAlignment = HorizontalAlignment.Left,
                Margin = new Thickness(0, 0, 0, 15)
            };
            statusBorder.Child = new TextBlock { Text = displayInfo?.StatusText ?? "未知", Foreground = Brushes.White, FontWeight = FontWeights.SemiBold, FontSize = 12 };
            _pluginDetailPanel.Children.Add(statusBorder);

            AddSectionHeader("基本信息");
            AddDetailRow("插件 ID", plugin.PluginId, "🆔");
            AddDetailRow("版本", plugin.Version, "📌");
            AddDetailRow("作者", plugin.Author, "👤");
            AddDetailRow("描述", plugin.Description, "📝");
            AddDetailRow("支持类型", string.Join(", ", plugin.SupportedScanTypes), "🎯");

            AddSectionHeader("扫描统计");
            AddDetailRow("扫描次数", status.ScanCount.ToString(), "📊");
            AddDetailRow("发现漏洞", status.VulnerabilityFound.ToString(), "🔍");
            AddDetailRow("最后扫描", status.LastScanTime?.ToString("yyyy-MM-dd HH:mm:ss") ?? "从未扫描", "🕐");
            AddDetailRow("状态消息", status.Message, "💬");

            if (plugin.ConfigParameters?.Any() == true)
            {
                AddSectionHeader("配置参数");
                foreach (var param in plugin.ConfigParameters)
                {
                    AddDetailRow(param.DisplayName, $"{param.Description} (类型: {param.Type}, 默认: {param.DefaultValue ?? "无"})", "⚙️");
                }
            }

            AddSectionHeader("操作");
            var viewLogBtn = new Button
            {
                Content = "📋 查看日志",
                Height = 30,
                Padding = new Thickness(15, 0, 15, 0),
                Margin = new Thickness(0, 5, 0, 0),
                Background = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#3498DB")),
                Foreground = Brushes.White,
                BorderThickness = new Thickness(0),
                Cursor = Cursors.Hand,
                HorizontalAlignment = HorizontalAlignment.Left
            };
            viewLogBtn.Click += (s, ev) => ViewPluginLog(plugin);
            _pluginDetailPanel.Children.Add(viewLogBtn);

            _configureButton.IsEnabled = plugin.ConfigParameters?.Any() == true;
            _enableDisableButton.IsEnabled = true;
            _enableDisableButton.Content = isEnabled ? "🚫 禁用" : "✅ 启用";
            _uninstallButton.IsEnabled = !plugin.PluginId.StartsWith("builtin.");
        }

        private void AddSectionHeader(string title)
        {
            _pluginDetailPanel.Children.Add(new TextBlock
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

        private void AddDetailRow(string label, string value, string icon = "")
        {
            var row = new StackPanel { Orientation = Orientation.Horizontal, Margin = new Thickness(0, 4, 0, 4) };
            row.Children.Add(new TextBlock { Text = $"{icon} {label}", Width = 100, FontWeight = FontWeights.SemiBold, Foreground = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#2C3E50")), VerticalAlignment = VerticalAlignment.Top });
            row.Children.Add(new TextBlock { Text = value, Foreground = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#34495E")), TextWrapping = TextWrapping.Wrap });
            _pluginDetailPanel.Children.Add(row);
        }

        private void ConfigureButton_Click(object sender, RoutedEventArgs e)
        {
            if (_selectedPlugin == null || !_selectedPlugin.ConfigParameters.Any()) return;

            var dialog = new Window
            {
                Title = $"配置插件 - {_selectedPlugin.Name}",
                Width = 500,
                Height = 450,
                WindowStartupLocation = WindowStartupLocation.CenterOwner,
                Owner = this,
                ResizeMode = ResizeMode.NoResize
            };

            var grid = new Grid { Margin = new Thickness(20) };
            grid.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
            grid.RowDefinitions.Add(new RowDefinition { Height = new GridLength(1, GridUnitType.Star) });
            grid.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });

            var headerBorder = new Border { Background = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#6C5CE7")), CornerRadius = new CornerRadius(8), Padding = new Thickness(15) };
            headerBorder.Child = new TextBlock { Text = $"⚙️ 配置 {_selectedPlugin.Name}", FontSize = 16, FontWeight = FontWeights.Bold, Foreground = Brushes.White };
            Grid.SetRow(headerBorder, 0);
            grid.Children.Add(headerBorder);

            var scrollViewer = new ScrollViewer { VerticalScrollBarVisibility = ScrollBarVisibility.Auto, Margin = new Thickness(0, 15, 0, 0) };
            var formPanel = new StackPanel();

            var currentConfig = _pluginManager.GetPluginConfig(_selectedPlugin.PluginId) ?? new Dictionary<string, object>();
            var inputControls = new Dictionary<string, FrameworkElement>();

            foreach (var param in _selectedPlugin.ConfigParameters)
            {
                var paramPanel = new StackPanel { Margin = new Thickness(0, 8, 0, 8) };
                paramPanel.Children.Add(new TextBlock { Text = param.DisplayName, FontWeight = FontWeights.SemiBold, Foreground = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#2C3E50")) });
                paramPanel.Children.Add(new TextBlock { Text = param.Description, FontSize = 11, Foreground = Brushes.Gray, Margin = new Thickness(0, 2, 0, 5) });

                FrameworkElement inputControl;

                switch (param.Type)
                {
                    case PluginConfigType.Boolean:
                        var checkBox = new CheckBox { Content = "启用", IsChecked = currentConfig.TryGetValue(param.Name, out var boolVal) ? Convert.ToBoolean(boolVal) : (param.DefaultValue != null && Convert.ToBoolean(param.DefaultValue)) };
                        inputControl = checkBox;
                        break;

                    case PluginConfigType.Enum:
                        var comboBox = new ComboBox { Width = 250, HorizontalAlignment = HorizontalAlignment.Left };
                        if (param.Options != null)
                        {
                            foreach (var opt in param.Options)
                            {
                                comboBox.Items.Add(opt);
                            }
                        }
                        var currentEnumVal = currentConfig.TryGetValue(param.Name, out var enumVal) ? enumVal?.ToString() : param.DefaultValue?.ToString();
                        if (currentEnumVal != null && comboBox.Items.Contains(currentEnumVal))
                            comboBox.SelectedItem = currentEnumVal;
                        else if (comboBox.Items.Count > 0)
                            comboBox.SelectedIndex = 0;
                        inputControl = comboBox;
                        break;

                    case PluginConfigType.Password:
                        var passwordBox = new PasswordBox { Width = 250, HorizontalAlignment = HorizontalAlignment.Left };
                        inputControl = passwordBox;
                        break;

                    case PluginConfigType.FilePath:
                        var filePathPanel = new StackPanel { Orientation = Orientation.Horizontal };
                        var filePathTextBox = new TextBox { Width = 200, Height = 28, VerticalContentAlignment = VerticalAlignment.Center };
                        var currentFilePath = currentConfig.TryGetValue(param.Name, out var fpVal) ? fpVal?.ToString() : param.DefaultValue?.ToString();
                        filePathTextBox.Text = currentFilePath ?? "";
                        var browseBtn = new Button { Content = "浏览", Width = 60, Height = 28, Margin = new Thickness(5, 0, 0, 0) };
                        browseBtn.Click += (s, ev) =>
                        {
                            var fileDialog = new OpenFileDialog { Title = $"选择{param.DisplayName}" };
                            if (fileDialog.ShowDialog() == true)
                                filePathTextBox.Text = fileDialog.FileName;
                        };
                        filePathPanel.Children.Add(filePathTextBox);
                        filePathPanel.Children.Add(browseBtn);
                        inputControl = filePathPanel;
                        break;

                    default:
                        var textBox = new TextBox { Width = 250, Height = 28, HorizontalAlignment = HorizontalAlignment.Left, VerticalContentAlignment = VerticalAlignment.Center };
                        var currentVal = currentConfig.TryGetValue(param.Name, out var val) ? val?.ToString() : param.DefaultValue?.ToString();
                        textBox.Text = currentVal ?? "";
                        inputControl = textBox;
                        break;
                }

                paramPanel.Children.Add(inputControl);
                inputControls[param.Name] = inputControl;
                formPanel.Children.Add(paramPanel);
            }

            scrollViewer.Content = formPanel;
            Grid.SetRow(scrollViewer, 1);
            grid.Children.Add(scrollViewer);

            var buttonPanel = new StackPanel { Orientation = Orientation.Horizontal, HorizontalAlignment = HorizontalAlignment.Right, Margin = new Thickness(0, 15, 0, 0) };
            var saveBtn = new Button { Content = "💾 保存", Width = 100, Height = 32, Margin = new Thickness(5), Background = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#27AE60")), Foreground = Brushes.White, BorderThickness = new Thickness(0), Cursor = Cursors.Hand };
            var cancelBtn = new Button { Content = "取消", Width = 80, Height = 32, Margin = new Thickness(5), Cursor = Cursors.Hand };

            saveBtn.Click += async (s, ev) =>
            {
                // Validation
                var validationErrors = new List<string>();
                foreach (var param in _selectedPlugin.ConfigParameters)
                {
                    if (!inputControls.TryGetValue(param.Name, out var element)) continue;

                    if (param.IsRequired)
                    {
                        var value = GetControlValue(element);
                        if (string.IsNullOrWhiteSpace(value?.ToString()))
                        {
                            validationErrors.Add($"\"{param.DisplayName}\" 为必填项");
                            HighlightErrorControl(element);
                        }
                    }

                    if (param.Type == PluginConfigType.Integer && element is TextBox intTb)
                    {
                        if (!string.IsNullOrWhiteSpace(intTb.Text) && !int.TryParse(intTb.Text, out _))
                        {
                            validationErrors.Add($"\"{param.DisplayName}\" 必须为整数");
                            intTb.BorderBrush = Brushes.Red;
                        }
                    }

                    if (param.Type == PluginConfigType.Float && element is TextBox floatTb)
                    {
                        if (!string.IsNullOrWhiteSpace(floatTb.Text) && !double.TryParse(floatTb.Text, out _))
                        {
                            validationErrors.Add($"\"{param.DisplayName}\" 必须为数字");
                            floatTb.BorderBrush = Brushes.Red;
                        }
                    }
                }

                if (validationErrors.Any())
                {
                    MessageBox.Show(string.Join("\n", validationErrors), "配置验证失败", MessageBoxButton.OK, MessageBoxImage.Warning);
                    return;
                }

                var newConfig = new Dictionary<string, object>();
                foreach (var kv in inputControls)
                {
                    var element = kv.Value;
                    if (element is TextBox tb)
                    {
                        if (int.TryParse(tb.Text, out var intVal)) newConfig[kv.Key] = intVal;
                        else if (double.TryParse(tb.Text, out var doubleVal)) newConfig[kv.Key] = doubleVal;
                        else newConfig[kv.Key] = tb.Text;
                    }
                    else if (element is CheckBox cb)
                    {
                        newConfig[kv.Key] = cb.IsChecked == true;
                    }
                    else if (element is ComboBox combo)
                    {
                        newConfig[kv.Key] = combo.SelectedItem?.ToString() ?? "";
                    }
                    else if (element is PasswordBox pb)
                    {
                        newConfig[kv.Key] = pb.Password;
                    }
                    else if (element is StackPanel sp && sp.Children.Count > 0 && sp.Children[0] is TextBox filePathTb)
                    {
                        newConfig[kv.Key] = filePathTb.Text;
                    }
                }

                var success = await _pluginManager.UpdatePluginConfigAsync(_selectedPlugin.PluginId, newConfig);
                if (success)
                {
                    MessageBox.Show("配置已保存！", "成功", MessageBoxButton.OK, MessageBoxImage.Information);
                    dialog.Close();
                    RefreshPluginList();
                }
                else
                {
                    MessageBox.Show("配置保存失败！", "错误", MessageBoxButton.OK, MessageBoxImage.Error);
                }
            };

            cancelBtn.Click += (s, ev) => dialog.Close();

            buttonPanel.Children.Add(saveBtn);
            buttonPanel.Children.Add(cancelBtn);
            Grid.SetRow(buttonPanel, 2);
            grid.Children.Add(buttonPanel);

            dialog.Content = grid;
            dialog.KeyDown += (s, e) => { if (e.Key == Key.Escape) dialog.Close(); };
            dialog.ShowDialog();
        }

        private async void EnableDisableButton_Click(object sender, RoutedEventArgs e)
        {
            if (_selectedPlugin == null) return;

            var currentEnabled = _pluginEnabledStates.TryGetValue(_selectedPlugin.PluginId, out var en) ? en : true;
            _pluginEnabledStates[_selectedPlugin.PluginId] = !currentEnabled;

            var currentConfig = _pluginManager.GetPluginConfig(_selectedPlugin.PluginId) ?? new Dictionary<string, object>();
            currentConfig["IsEnabled"] = !currentEnabled;
            await _pluginManager.UpdatePluginConfigAsync(_selectedPlugin.PluginId, currentConfig);

            RefreshPluginList();

            if (_pluginsDataGrid.ItemsSource is List<PluginDisplayInfo> items)
            {
                var item = items.FirstOrDefault(i => i.PluginId == _selectedPlugin.PluginId);
                if (item != null)
                {
                    _pluginsDataGrid.SelectedItem = item;
                    DisplayPluginDetails(_selectedPlugin, item);
                }
            }
        }

        private async void UninstallButton_Click(object sender, RoutedEventArgs e)
        {
            if (_selectedPlugin == null) return;

            var result = MessageBox.Show($"确定要卸载插件 '{_selectedPlugin.Name}' 吗？\n\n此操作不可撤销。", "确认卸载", MessageBoxButton.YesNo, MessageBoxImage.Question);
            if (result == MessageBoxResult.Yes)
            {
                var success = await _pluginManager.UninstallPluginAsync(_selectedPlugin.PluginId);
                if (success)
                {
                    MessageBox.Show("插件已卸载！", "成功", MessageBoxButton.OK, MessageBoxImage.Information);
                    _selectedPlugin = null;
                    RefreshPluginList();
                    DisplayPluginDetails(null, null);
                }
                else
                {
                    MessageBox.Show("卸载失败！", "错误", MessageBoxButton.OK, MessageBoxImage.Error);
                }
            }
        }

        private async void InstallPluginButton_Click(object sender, RoutedEventArgs e)
        {
            var dialog = new OpenFileDialog
            {
                Filter = "DLL文件|*.dll",
                Title = "选择插件文件"
            };

            if (dialog.ShowDialog() == true)
            {
                var success = await _pluginManager.InstallPluginAsync(dialog.FileName);
                if (success)
                {
                    MessageBox.Show("插件安装成功！", "成功", MessageBoxButton.OK, MessageBoxImage.Information);
                    RefreshPluginList();
                }
                else
                {
                    MessageBox.Show("插件安装失败！请确保文件是有效的插件DLL。", "错误", MessageBoxButton.OK, MessageBoxImage.Error);
                }
            }
        }

        private void OpenPluginFolderButton_Click(object sender, RoutedEventArgs e)
        {
            var pluginFolder = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "Plugins");
            if (!Directory.Exists(pluginFolder))
            {
                Directory.CreateDirectory(pluginFolder);
            }
            Process.Start("explorer.exe", pluginFolder);
        }

        private void OpenPluginMarket_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                var marketWindow = new PluginMarketWindow { Owner = this };
                marketWindow.ShowDialog();
                RefreshPluginList();
            }
            catch (Exception ex)
            {
                MessageBox.Show($"打开插件市场失败: {ex.Message}", "错误", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        private void SearchTextBox_TextChanged(object sender, TextChangedEventArgs e)
        {
            ApplyFilters();
        }

        private void CategoryFilterComboBox_SelectionChanged(object sender, SelectionChangedEventArgs e)
        {
            ApplyFilters();
        }

        private void ApplyFilters()
        {
            if (_allPluginDisplayInfos == null) return;

            var keyword = _searchTextBox?.Text?.Trim().ToLower() ?? "";
            var selectedCategory = _categoryFilterComboBox?.SelectedItem?.ToString() ?? "全部类别";

            // If the search box shows placeholder text, treat as empty
            if (keyword == "搜索插件...") keyword = "";

            var filtered = _allPluginDisplayInfos.AsEnumerable();

            if (!string.IsNullOrWhiteSpace(keyword))
            {
                filtered = filtered.Where(p =>
                    p.Name.ToLower().Contains(keyword) ||
                    p.Author.ToLower().Contains(keyword) ||
                    p.PluginId.ToLower().Contains(keyword));
            }

            if (selectedCategory != "全部类别")
            {
                filtered = filtered.Where(p => p.Category.Contains(selectedCategory));
            }

            _pluginsDataGrid.ItemsSource = filtered.ToList();
        }

        private async void CheckUpdatesButton_Click(object sender, RoutedEventArgs e)
        {
            if (_checkUpdatesButton != null) _checkUpdatesButton.IsEnabled = false;
            try
            {
                var marketService = new PluginMarketService();
                var updates = await marketService.CheckForUpdatesAsync();
                if (updates.Count > 0)
                {
                    MessageBox.Show($"发现 {updates.Count} 个插件有可用更新！\n\n请前往插件市场查看详情。", "检查更新", MessageBoxButton.OK, MessageBoxImage.Information);
                }
                else
                {
                    MessageBox.Show("所有插件都是最新版本。", "检查更新", MessageBoxButton.OK, MessageBoxImage.Information);
                }
            }
            catch (Exception ex)
            {
                MessageBox.Show($"检查更新失败: {ex.Message}", "错误", MessageBoxButton.OK, MessageBoxImage.Error);
            }
            finally
            {
                if (_checkUpdatesButton != null) _checkUpdatesButton.IsEnabled = true;
            }
        }

        private object GetControlValue(FrameworkElement element)
        {
            if (element is TextBox tb) return tb.Text;
            if (element is CheckBox cb) return cb.IsChecked == true;
            if (element is ComboBox combo) return combo.SelectedItem?.ToString() ?? "";
            if (element is PasswordBox pb) return pb.Password;
            if (element is StackPanel sp && sp.Children.Count > 0 && sp.Children[0] is TextBox filePathTb) return filePathTb.Text;
            return null;
        }

        private void HighlightErrorControl(FrameworkElement element)
        {
            if (element is TextBox tb) tb.BorderBrush = Brushes.Red;
            else if (element is ComboBox cb) cb.BorderBrush = Brushes.Red;
        }

        private void ViewPluginLog(IVulnerabilityScannerPlugin plugin)
        {
            var logWindow = new Window
            {
                Title = $"插件日志 - {plugin.Name}",
                Width = 650,
                Height = 450,
                WindowStartupLocation = WindowStartupLocation.CenterOwner,
                Owner = this
            };

            var grid = new Grid { Margin = new Thickness(15) };
            grid.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
            grid.RowDefinitions.Add(new RowDefinition { Height = new GridLength(1, GridUnitType.Star) });
            grid.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });

            var headerBorder = new Border
            {
                Background = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#3498DB")),
                CornerRadius = new CornerRadius(8),
                Padding = new Thickness(15)
            };
            headerBorder.Child = new TextBlock
            {
                Text = $"📋 {plugin.Name} 运行日志",
                FontSize = 16,
                FontWeight = FontWeights.Bold,
                Foreground = Brushes.White
            };
            Grid.SetRow(headerBorder, 0);
            grid.Children.Add(headerBorder);

            var status = plugin.GetStatus();
            var logEntries = new List<string>();
            logEntries.Add($"[{DateTime.Now:yyyy-MM-dd HH:mm:ss}] 查看插件日志");
            logEntries.Add($"[{DateTime.Now:yyyy-MM-dd HH:mm:ss}] 插件ID: {plugin.PluginId}");
            logEntries.Add($"[{DateTime.Now:yyyy-MM-dd HH:mm:ss}] 版本: {plugin.Version}");
            logEntries.Add($"[{DateTime.Now:yyyy-MM-dd HH:mm:ss}] 状态: {(status.IsInitialized ? "已初始化" : "未初始化")}");
            logEntries.Add($"[{DateTime.Now:yyyy-MM-dd HH:mm:ss}] 扫描次数: {status.ScanCount}");
            logEntries.Add($"[{DateTime.Now:yyyy-MM-dd HH:mm:ss}] 发现漏洞: {status.VulnerabilityFound}");
            logEntries.Add($"[{DateTime.Now:yyyy-MM-dd HH:mm:ss}] 最后扫描: {status.LastScanTime?.ToString("yyyy-MM-dd HH:mm:ss") ?? "从未扫描"}");
            if (!string.IsNullOrEmpty(status.Message))
            {
                logEntries.Add($"[{DateTime.Now:yyyy-MM-dd HH:mm:ss}] 状态消息: {status.Message}");
            }
            logEntries.Add($"[{DateTime.Now:yyyy-MM-dd HH:mm:ss}] 支持类型: {string.Join(", ", plugin.SupportedScanTypes)}");

            var logText = new TextBox
            {
                IsReadOnly = true,
                TextWrapping = TextWrapping.Wrap,
                VerticalScrollBarVisibility = ScrollBarVisibility.Auto,
                AcceptsReturn = true,
                Text = string.Join("\n", logEntries),
                Margin = new Thickness(0, 10, 0, 0),
                FontFamily = new FontFamily("Consolas"),
                FontSize = 12,
                Background = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#F8F9FA")),
                BorderBrush = Brushes.LightGray
            };
            Grid.SetRow(logText, 1);
            grid.Children.Add(logText);

            var closeBtn = new Button
            {
                Content = "关闭",
                Width = 80,
                Height = 30,
                Margin = new Thickness(0, 10, 0, 0),
                HorizontalAlignment = HorizontalAlignment.Right,
                Cursor = Cursors.Hand
            };
            closeBtn.Click += (s, e) => logWindow.Close();
            Grid.SetRow(closeBtn, 2);
            grid.Children.Add(closeBtn);

            logWindow.Content = grid;
            logWindow.KeyDown += (s, e) => { if (e.Key == Key.Escape) logWindow.Close(); };
            logWindow.ShowDialog();
        }
    }

    public class PluginDisplayInfo
    {
        public string PluginId { get; set; } = "";
        public string Name { get; set; } = "";
        public string Version { get; set; } = "";
        public string Author { get; set; } = "";
        public string Category { get; set; } = "";
        public string StatusText { get; set; } = "";
        public string StatusColor { get; set; } = "#95A5A6";
        public bool IsEnabled { get; set; } = true;
        public bool IsBuiltIn { get; set; }
    }
}
