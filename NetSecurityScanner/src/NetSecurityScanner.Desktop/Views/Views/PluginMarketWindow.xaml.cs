using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Media;
using NetSecurityScanner.Models;
using NetSecurityScanner.Services;

namespace NetSecurityScanner.Views
{
    /// <summary>
    /// PluginMarketWindow.xaml 的交互逻辑
    /// </summary>
    public partial class PluginMarketWindow : Window
    {
        private readonly PluginMarketService _pluginMarketService;
        private List<Plugin> _allPlugins;
        private CancellationTokenSource _cancellationTokenSource;

        private TextBox SearchTextBox;
        private ComboBox CategoryFilterComboBox;
        private ComboBox SortComboBox;
        private ItemsControl PluginsItemsControl;
        private Grid LoadingGrid;
        private TextBlock LoadingTextBlock;
        private Button CheckUpdatesButton;
        private Button MyPluginsButton;

        public PluginMarketWindow()
        {
            Title = "插件市场";
            Height = 600;
            Width = 900;
            WindowStartupLocation = WindowStartupLocation.CenterOwner;

            _pluginMarketService = new PluginMarketService();
            _allPlugins = new List<Plugin>();

            BuildUI();

            Loaded += PluginMarketWindow_Loaded;
        }

        private void BuildUI()
        {
            var rootGrid = new Grid();
            rootGrid.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
            rootGrid.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
            rootGrid.RowDefinitions.Add(new RowDefinition { Height = new GridLength(1, GridUnitType.Star) });

            var headerBorder = CreateHeaderBar();
            Grid.SetRow(headerBorder, 0);
            rootGrid.Children.Add(headerBorder);

            var filterBorder = CreateFilterBar();
            Grid.SetRow(filterBorder, 1);
            rootGrid.Children.Add(filterBorder);

            var contentPanel = CreateContentArea();
            Grid.SetRow(contentPanel, 2);
            rootGrid.Children.Add(contentPanel);

            var loadingOverlay = CreateLoadingOverlay();
            Grid.SetRow(loadingOverlay, 2);
            rootGrid.Children.Add(loadingOverlay);

            Content = rootGrid;
        }

        private Border CreateHeaderBar()
        {
            var border = new Border
            {
                Background = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#2196F3")),
                Padding = new Thickness(20, 15, 20, 15)
            };

            var headerGrid = new Grid();
            headerGrid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
            headerGrid.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });

            // 左侧标题
            var titlePanel = new StackPanel { Orientation = Orientation.Horizontal };
            titlePanel.Children.Add(new TextBlock { Text = "\U0001F50C", FontSize = 24, Margin = new Thickness(0, 0, 10, 0) });

            var titleTextPanel = new StackPanel();
            titleTextPanel.Children.Add(new TextBlock { Text = "插件市场", FontSize = 20, FontWeight = FontWeights.Bold, Foreground = Brushes.White });
            titleTextPanel.Children.Add(new TextBlock { Text = "扩展您的安全扫描能力", FontSize = 12, Foreground = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#E3F2FD")) });
            titlePanel.Children.Add(titleTextPanel);

            Grid.SetColumn(titlePanel, 0);
            headerGrid.Children.Add(titlePanel);

            // 右侧按钮
            var buttonPanel = new StackPanel { Orientation = Orientation.Horizontal };

            CheckUpdatesButton = new Button
            {
                Content = "检查更新",
                Background = Brushes.White,
                Foreground = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#2196F3")),
                Padding = new Thickness(15, 8, 15, 8),
                Margin = new Thickness(0, 0, 10, 0)
            };
            CheckUpdatesButton.Click += CheckUpdatesButton_Click;
            buttonPanel.Children.Add(CheckUpdatesButton);

            MyPluginsButton = new Button
            {
                Content = "我的插件",
                Background = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#1976D2")),
                Foreground = Brushes.White,
                Padding = new Thickness(15, 8, 15, 8)
            };
            MyPluginsButton.Click += MyPluginsButton_Click;
            buttonPanel.Children.Add(MyPluginsButton);

            Grid.SetColumn(buttonPanel, 1);
            headerGrid.Children.Add(buttonPanel);

            border.Child = headerGrid;
            return border;
        }

        private Border CreateFilterBar()
        {
            var border = new Border
            {
                Background = Brushes.White,
                BorderBrush = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#E0E0E0")),
                BorderThickness = new Thickness(0, 0, 0, 1),
                Padding = new Thickness(20, 15, 20, 15)
            };

            var filterGrid = new Grid();
            filterGrid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
            filterGrid.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });
            filterGrid.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });

            // 搜索框
            SearchTextBox = new TextBox
            {
                Padding = new Thickness(10, 8, 10, 8),
                FontSize = 14,
                BorderBrush = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#E0E0E0"))
            };
            SearchTextBox.TextChanged += SearchTextBox_TextChanged;
            Grid.SetColumn(SearchTextBox, 0);
            filterGrid.Children.Add(SearchTextBox);

            // 类别筛选
            CategoryFilterComboBox = new ComboBox
            {
                Width = 150,
                Margin = new Thickness(10, 0, 10, 0)
            };
            CategoryFilterComboBox.Items.Add(new ComboBoxItem { Content = "全部类别", IsSelected = true });
            CategoryFilterComboBox.Items.Add(new ComboBoxItem { Content = "漏洞检测" });
            CategoryFilterComboBox.Items.Add(new ComboBoxItem { Content = "端口扫描" });
            CategoryFilterComboBox.Items.Add(new ComboBoxItem { Content = "报告生成" });
            CategoryFilterComboBox.Items.Add(new ComboBoxItem { Content = "数据分析" });
            CategoryFilterComboBox.Items.Add(new ComboBoxItem { Content = "界面扩展" });
            CategoryFilterComboBox.Items.Add(new ComboBoxItem { Content = "集成工具" });
            CategoryFilterComboBox.SelectionChanged += CategoryFilterComboBox_SelectionChanged;
            Grid.SetColumn(CategoryFilterComboBox, 1);
            filterGrid.Children.Add(CategoryFilterComboBox);

            // 排序方式
            SortComboBox = new ComboBox
            {
                Width = 120
            };
            SortComboBox.Items.Add(new ComboBoxItem { Content = "人气排序", IsSelected = true });
            SortComboBox.Items.Add(new ComboBoxItem { Content = "最新发布" });
            SortComboBox.Items.Add(new ComboBoxItem { Content = "最近更新" });
            SortComboBox.Items.Add(new ComboBoxItem { Content = "评分最高" });
            SortComboBox.SelectionChanged += SortComboBox_SelectionChanged;
            Grid.SetColumn(SortComboBox, 2);
            filterGrid.Children.Add(SortComboBox);

            border.Child = filterGrid;
            return border;
        }

        private ScrollViewer CreateContentArea()
        {
            PluginsItemsControl = new ItemsControl
            {
                Margin = new Thickness(20)
            };

            // ItemsPanel: WrapPanel
            var wrapPanelFactory = new FrameworkElementFactory(typeof(WrapPanel));
            PluginsItemsControl.ItemsPanel = new ItemsPanelTemplate(wrapPanelFactory);

            // ItemTemplate: Plugin Card
            var cardTemplate = CreatePluginCardTemplate();
            PluginsItemsControl.ItemTemplate = cardTemplate;

            var scrollViewer = new ScrollViewer
            {
                VerticalScrollBarVisibility = ScrollBarVisibility.Auto,
                Content = PluginsItemsControl
            };

            return scrollViewer;
        }

        private DataTemplate CreatePluginCardTemplate()
        {
            // 卡片外层 Border
            var cardBorder = new FrameworkElementFactory(typeof(Border));
            cardBorder.SetValue(Border.WidthProperty, 280.0);
            cardBorder.SetValue(Border.MarginProperty, new Thickness(10));
            cardBorder.SetValue(Border.PaddingProperty, new Thickness(15));
            cardBorder.SetValue(Border.BackgroundProperty, Brushes.White);
            cardBorder.SetValue(Border.BorderBrushProperty, new SolidColorBrush((Color)ColorConverter.ConvertFromString("#E0E0E0")));
            cardBorder.SetValue(Border.BorderThicknessProperty, new Thickness(1));
            cardBorder.SetValue(Border.CornerRadiusProperty, new CornerRadius(8));
            cardBorder.SetValue(Border.EffectProperty, new System.Windows.Media.Effects.DropShadowEffect
            {
                ShadowDepth = 1,
                BlurRadius = 3,
                Opacity = 0.2
            });

            // 卡片内容：垂直 StackPanel（替代 Grid，避免 RowDefinitions 问题）
            var cardPanel = new FrameworkElementFactory(typeof(StackPanel));

            // Row 0: Name + Version
            var namePanel = new FrameworkElementFactory(typeof(StackPanel));
            namePanel.SetValue(StackPanel.OrientationProperty, Orientation.Horizontal);
            namePanel.SetValue(StackPanel.MarginProperty, new Thickness(0, 0, 0, 5));

            var nameText = new FrameworkElementFactory(typeof(TextBlock));
            nameText.SetBinding(TextBlock.TextProperty, new Binding("Name"));
            nameText.SetValue(TextBlock.FontWeightProperty, FontWeights.Bold);
            nameText.SetValue(TextBlock.FontSizeProperty, 16.0);
            namePanel.AppendChild(nameText);

            var versionSeparator = new FrameworkElementFactory(typeof(TextBlock));
            versionSeparator.SetValue(TextBlock.TextProperty, " v");
            versionSeparator.SetValue(TextBlock.ForegroundProperty, Brushes.Gray);
            namePanel.AppendChild(versionSeparator);

            var versionText = new FrameworkElementFactory(typeof(TextBlock));
            versionText.SetBinding(TextBlock.TextProperty, new Binding("Version"));
            versionText.SetValue(TextBlock.ForegroundProperty, Brushes.Gray);
            namePanel.AppendChild(versionText);

            cardPanel.AppendChild(namePanel);

            // Row 1: Author + Rating + Downloads
            var authorPanel = new FrameworkElementFactory(typeof(StackPanel));
            authorPanel.SetValue(StackPanel.OrientationProperty, Orientation.Horizontal);
            authorPanel.SetValue(StackPanel.MarginProperty, new Thickness(0, 0, 0, 10));

            var authorText = new FrameworkElementFactory(typeof(TextBlock));
            authorText.SetBinding(TextBlock.TextProperty, new Binding("Author"));
            authorText.SetValue(TextBlock.ForegroundProperty, Brushes.Gray);
            authorText.SetValue(TextBlock.FontSizeProperty, 12.0);
            authorPanel.AppendChild(authorText);

            var starText = new FrameworkElementFactory(typeof(TextBlock));
            starText.SetValue(TextBlock.TextProperty, " \u2B50 ");
            starText.SetValue(TextBlock.ForegroundProperty, Brushes.Gold);
            authorPanel.AppendChild(starText);

            var ratingText = new FrameworkElementFactory(typeof(TextBlock));
            ratingText.SetBinding(TextBlock.TextProperty, new Binding("Rating"));
            ratingText.SetValue(TextBlock.FontSizeProperty, 12.0);
            authorPanel.AppendChild(ratingText);

            var openParen = new FrameworkElementFactory(typeof(TextBlock));
            openParen.SetValue(TextBlock.TextProperty, " (");
            openParen.SetValue(TextBlock.ForegroundProperty, Brushes.Gray);
            openParen.SetValue(TextBlock.FontSizeProperty, 12.0);
            authorPanel.AppendChild(openParen);

            var downloadText = new FrameworkElementFactory(typeof(TextBlock));
            downloadText.SetBinding(TextBlock.TextProperty, new Binding("DownloadCount"));
            downloadText.SetValue(TextBlock.ForegroundProperty, Brushes.Gray);
            downloadText.SetValue(TextBlock.FontSizeProperty, 12.0);
            authorPanel.AppendChild(downloadText);

            var downloadSuffix = new FrameworkElementFactory(typeof(TextBlock));
            downloadSuffix.SetValue(TextBlock.TextProperty, " \u4E0B\u8F7D)");
            downloadSuffix.SetValue(TextBlock.ForegroundProperty, Brushes.Gray);
            downloadSuffix.SetValue(TextBlock.FontSizeProperty, 12.0);
            authorPanel.AppendChild(downloadSuffix);

            cardPanel.AppendChild(authorPanel);

            // Row 2: Description
            var descText = new FrameworkElementFactory(typeof(TextBlock));
            descText.SetBinding(TextBlock.TextProperty, new Binding("Description"));
            descText.SetValue(TextBlock.TextWrappingProperty, TextWrapping.Wrap);
            descText.SetValue(TextBlock.MarginProperty, new Thickness(0, 0, 0, 10));
            descText.SetValue(TextBlock.MaxHeightProperty, 60.0);
            descText.SetValue(TextBlock.TextTrimmingProperty, TextTrimming.CharacterEllipsis);
            cardPanel.AppendChild(descText);

            // Row 3: Buttons
            var buttonPanel = new FrameworkElementFactory(typeof(StackPanel));
            buttonPanel.SetValue(StackPanel.OrientationProperty, Orientation.Horizontal);
            buttonPanel.SetValue(StackPanel.HorizontalAlignmentProperty, HorizontalAlignment.Right);

            var detailsButton = new FrameworkElementFactory(typeof(Button));
            detailsButton.SetValue(Button.ContentProperty, "\u8BE6\u60C5");
            detailsButton.SetValue(Button.MarginProperty, new Thickness(0, 0, 5, 0));
            detailsButton.SetValue(Button.PaddingProperty, new Thickness(10, 5, 10, 5));
            detailsButton.AddHandler(Button.ClickEvent, new RoutedEventHandler(PluginDetailsButton_Click));
            detailsButton.SetBinding(Button.TagProperty, new Binding());
            buttonPanel.AppendChild(detailsButton);

            // v5-T3: 试运行按钮（在"安装"前）— 不真正安装，调用 PluginOrchestrator.TryRunAsync 模拟结果
            var tryRunButton = new FrameworkElementFactory(typeof(Button));
            tryRunButton.SetValue(Button.ContentProperty, "\u25B6 \u8BD5\u8FD0\u884C");
            tryRunButton.SetValue(Button.MarginProperty, new Thickness(0, 0, 5, 0));
            tryRunButton.SetValue(Button.PaddingProperty, new Thickness(10, 5, 10, 5));
            tryRunButton.SetValue(Button.BackgroundProperty, new SolidColorBrush((Color)ColorConverter.ConvertFromString("#FF9800")));
            tryRunButton.SetValue(Button.ForegroundProperty, Brushes.White);
            tryRunButton.AddHandler(Button.ClickEvent, new RoutedEventHandler(TryRunPluginButton_Click));
            tryRunButton.SetBinding(Button.TagProperty, new Binding());
            buttonPanel.AppendChild(tryRunButton);

            var installButton = new FrameworkElementFactory(typeof(Button));
            installButton.SetValue(Button.ContentProperty, "\u5B89\u88C5");
            installButton.SetValue(Button.PaddingProperty, new Thickness(10, 5, 10, 5));
            installButton.SetValue(Button.BackgroundProperty, new SolidColorBrush((Color)ColorConverter.ConvertFromString("#4CAF50")));
            installButton.SetValue(Button.ForegroundProperty, Brushes.White);
            installButton.AddHandler(Button.ClickEvent, new RoutedEventHandler(InstallPluginButton_Click));
            installButton.SetBinding(Button.TagProperty, new Binding());
            buttonPanel.AppendChild(installButton);

            cardPanel.AppendChild(buttonPanel);

            cardBorder.AppendChild(cardPanel);

            var template = new DataTemplate { VisualTree = cardBorder };
            return template;
        }

        private Grid CreateLoadingOverlay()
        {
            LoadingGrid = new Grid
            {
                Background = new SolidColorBrush(Color.FromArgb(128, 255, 255, 255)),
                Visibility = Visibility.Collapsed
            };

            var loadingPanel = new StackPanel
            {
                HorizontalAlignment = HorizontalAlignment.Center,
                VerticalAlignment = VerticalAlignment.Center
            };

            var progressBar = new ProgressBar
            {
                IsIndeterminate = true,
                Width = 200,
                Height = 5,
                Margin = new Thickness(0, 0, 0, 10)
            };
            loadingPanel.Children.Add(progressBar);

            LoadingTextBlock = new TextBlock
            {
                Text = "\u52A0\u8F7D\u4E2D...",
                HorizontalAlignment = HorizontalAlignment.Center
            };
            loadingPanel.Children.Add(LoadingTextBlock);

            LoadingGrid.Children.Add(loadingPanel);
            return LoadingGrid;
        }

        private async void PluginMarketWindow_Loaded(object sender, RoutedEventArgs e)
        {
            await LoadPluginsAsync();
        }

        private async Task LoadPluginsAsync()
        {
            try
            {
                LoadingGrid.Visibility = Visibility.Visible;

                var criteria = new PluginSearchCriteria
                {
                    Page = 1,
                    PageSize = 50
                };

                var response = await _pluginMarketService.GetPluginsAsync(criteria);
                _allPlugins = response.Plugins;

                PluginsItemsControl.ItemsSource = _allPlugins;
            }
            catch (Exception ex)
            {
                MessageBox.Show($"加载插件列表失败: {ex.Message}", "错误", MessageBoxButton.OK, MessageBoxImage.Error);
            }
            finally
            {
                LoadingGrid.Visibility = Visibility.Collapsed;
            }
        }

        private void SearchTextBox_TextChanged(object sender, TextChangedEventArgs e)
        {
            FilterPlugins();
        }

        private void CategoryFilterComboBox_SelectionChanged(object sender, SelectionChangedEventArgs e)
        {
            FilterPlugins();
        }

        private void SortComboBox_SelectionChanged(object sender, SelectionChangedEventArgs e)
        {
            SortPlugins();
        }

        private void FilterPlugins()
        {
            if (_allPlugins == null) return;

            var keyword = SearchTextBox.Text?.ToLower() ?? "";
            var categoryIndex = CategoryFilterComboBox.SelectedIndex;

            var filtered = _allPlugins.AsEnumerable();

            // 关键词过滤
            if (!string.IsNullOrWhiteSpace(keyword))
            {
                filtered = filtered.Where(p =>
                    p.Name.ToLower().Contains(keyword) ||
                    p.Description.ToLower().Contains(keyword));
            }

            // 类别过滤
            if (categoryIndex > 0)
            {
                var category = (PluginCategory)(categoryIndex - 1);
                filtered = filtered.Where(p => p.Category == category);
            }

            PluginsItemsControl.ItemsSource = filtered.ToList();
        }

        private void SortPlugins()
        {
            if (_allPlugins == null) return;

            var sortIndex = SortComboBox.SelectedIndex;
            var currentItems = PluginsItemsControl.ItemsSource as List<Plugin> ?? _allPlugins;

            IEnumerable<Plugin> sorted = sortIndex switch
            {
                0 => currentItems.OrderByDescending(p => p.DownloadCount),
                1 => currentItems.OrderByDescending(p => p.PublishDate),
                2 => currentItems.OrderByDescending(p => p.LastUpdateDate),
                3 => currentItems.OrderByDescending(p => p.Rating),
                _ => currentItems.OrderByDescending(p => p.DownloadCount)
            };

            PluginsItemsControl.ItemsSource = sorted.ToList();
        }

        private async void InstallPluginButton_Click(object sender, RoutedEventArgs e)
        {
            var button = sender as Button;
            var plugin = button?.Tag as Plugin;

            if (plugin == null) return;

            var result = MessageBox.Show(
                $"确定要安装插件 \"{plugin.Name}\" 吗？\n\n版本: {plugin.Version}\n作者: {plugin.Author}\n大小: {FormatFileSize(plugin.Size)}",
                "确认安装",
                MessageBoxButton.YesNo,
                MessageBoxImage.Question);

            if (result != MessageBoxResult.Yes) return;

            try
            {
                button.IsEnabled = false;
                button.Content = "安装中...";

                var progress = new Progress<double>(value =>
                {
                    Dispatcher.Invoke(() =>
                    {
                        button.Content = $"{value:F0}%";
                    });
                });

                _cancellationTokenSource = new CancellationTokenSource();
                var success = await _pluginMarketService.InstallPluginAsync(plugin, progress, _cancellationTokenSource.Token);

                if (success)
                {
                    MessageBox.Show($"插件 \"{plugin.Name}\" 安装成功！", "安装成功", MessageBoxButton.OK, MessageBoxImage.Information);
                    button.Content = "已安装";
                    button.Background = Brushes.Gray;
                }
                else
                {
                    MessageBox.Show($"插件 \"{plugin.Name}\" 安装失败。", "安装失败", MessageBoxButton.OK, MessageBoxImage.Error);
                    button.Content = "安装";
                    button.IsEnabled = true;
                }
            }
            catch (Exception ex)
            {
                MessageBox.Show($"安装插件时出错: {ex.Message}", "错误", MessageBoxButton.OK, MessageBoxImage.Error);
                button.Content = "安装";
                button.IsEnabled = true;
            }
        }

        private void PluginDetailsButton_Click(object sender, RoutedEventArgs e)
        {
            var button = sender as Button;
            var plugin = button?.Tag as Plugin;

            if (plugin == null) return;

            var details = $"插件名称: {plugin.Name}\n" +
                         $"版本: {plugin.Version}\n" +
                         $"作者: {plugin.Author}\n" +
                         $"类别: {GetCategoryName(plugin.Category)}\n" +
                         $"下载次数: {plugin.DownloadCount}\n" +
                         $"评分: {plugin.Rating:F1}/5.0 ({plugin.RatingCount} 评价)\n" +
                         $"发布日期: {plugin.PublishDate:yyyy-MM-dd}\n" +
                         $"最后更新: {plugin.LastUpdateDate:yyyy-MM-dd}\n" +
                         $"大小: {FormatFileSize(plugin.Size)}\n\n" +
                         $"描述:\n{plugin.Description}";

            MessageBox.Show(details, "插件详情", MessageBoxButton.OK, MessageBoxImage.Information);
        }

        /// <summary>
        /// v5-T3: 商店试运行按钮。调用 PluginOrchestrator.TryRunAsync(Plugin) 生成模拟结果，
        /// 不真正安装到本地，不调用任何网络。弹窗显示"将看到什么类型的漏洞"用于决策安装。
        /// </summary>
        private void TryRunPluginButton_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                if (sender is not Button button) return;
                if (button.Tag is not Plugin plugin) return;

                var results = PluginOrchestrator.Instance.TryRunAsync(plugin);
                if (results == null || results.Count == 0)
                {
                    MessageBox.Show(
                        $"插件 \"{plugin.Name}\" 的试运行未产生模拟结果。\n\n（属于正常情况 - 部分插件可能不需要报告漏洞，例如合规评分类。）",
                        "试运行完成",
                        MessageBoxButton.OK,
                        MessageBoxImage.Information);
                    return;
                }

                var sb = new System.Text.StringBuilder();
                sb.AppendLine($"插件 \"{plugin.Name}\" 的模拟运行结果（{results.Count} 条）：");
                sb.AppendLine();
                for (int i = 0; i < results.Count; i++)
                {
                    var r = results[i];
                    sb.AppendLine($"  {i + 1}. [{r.RiskLevel}] {r.Name}");
                    sb.AppendLine($"     端口: {r.Port}    服务: {r.Service}");
                    sb.AppendLine($"     {r.Description}");
                    sb.AppendLine();
                }
                sb.AppendLine("⚠ 这只是模拟演示，未真正调用网络。");
                sb.AppendLine("   如需真实扫描请先点击\"安装\"。");

                MessageBox.Show(sb.ToString(), $"▶ 试运行 - {plugin.Name}",
                    MessageBoxButton.OK, MessageBoxImage.Information);
            }
            catch (Exception ex)
            {
                MessageBox.Show($"试运行失败: {ex.Message}", "错误", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        private async void CheckUpdatesButton_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                LoadingGrid.Visibility = Visibility.Visible;
                LoadingTextBlock.Text = "正在检查更新...";

                var updates = await _pluginMarketService.CheckForUpdatesAsync();

                if (updates.Count > 0)
                {
                    MessageBox.Show($"发现 {updates.Count} 个插件有可用更新。", "检查更新", MessageBoxButton.OK, MessageBoxImage.Information);
                }
                else
                {
                    MessageBox.Show("所有插件都是最新版本。", "检查更新", MessageBoxButton.OK, MessageBoxImage.Information);
                }

                // 刷新列表
                await LoadPluginsAsync();
            }
            catch (Exception ex)
            {
                MessageBox.Show($"检查更新失败: {ex.Message}", "错误", MessageBoxButton.OK, MessageBoxImage.Error);
            }
            finally
            {
                LoadingGrid.Visibility = Visibility.Collapsed;
                LoadingTextBlock.Text = "加载中...";
            }
        }

        private void MyPluginsButton_Click(object sender, RoutedEventArgs e)
        {
            var installedPlugins = _pluginMarketService.GetInstalledPlugins();

            if (installedPlugins.Count == 0)
            {
                MessageBox.Show("您还没有安装任何插件。", "我的插件", MessageBoxButton.OK, MessageBoxImage.Information);
                return;
            }

            var pluginList = string.Join("\n", installedPlugins.Select(p => $"• {p.Name} v{p.Version}"));
            MessageBox.Show($"已安装的插件 ({installedPlugins.Count}):\n\n{pluginList}", "我的插件", MessageBoxButton.OK, MessageBoxImage.Information);
        }

        private string GetCategoryName(PluginCategory category)
        {
            return category switch
            {
                PluginCategory.VulnerabilityDetection => "漏洞检测",
                PluginCategory.PortScanning => "端口扫描",
                PluginCategory.Reporting => "报告生成",
                PluginCategory.DataAnalysis => "数据分析",
                PluginCategory.UIExtension => "界面扩展",
                PluginCategory.Integration => "集成工具",
                PluginCategory.Other => "其他",
                _ => "未知"
            };
        }

        private string FormatFileSize(long bytes)
        {
            string[] sizes = { "B", "KB", "MB", "GB" };
            int order = 0;
            double size = bytes;
            while (size >= 1024 && order < sizes.Length - 1)
            {
                order++;
                size /= 1024;
            }
            return $"{size:F1} {sizes[order]}";
        }
    }
}
