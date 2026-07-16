using NetSecurityScanner.Models;
using NetSecurityScanner.Plugins;
using NetSecurityScanner.Services;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using System.Windows.Media;

namespace NetSecurityScanner.Views
{
    /// <summary>
    /// 插件手动扫描窗口（v5-T2）
    /// - 目标输入（IP + 端口，支持逗号 / 范围 / 单端口）
    /// - 插件多选（默认全选）
    /// - 进度反馈 + 异常兜底
    ///
    /// UI 全部在 C# 代码中构建（与 PluginExecutionLogWindow 等保持一致）。
    /// </summary>
    public partial class PluginQuickInvokeWindow : Window
    {
        private readonly PluginOrchestrator _orchestrator;
        private CancellationTokenSource? _cts;

        // UI 控件引用（缓存便于在事件中更新）
        private TextBox _ipTextBox;
        private TextBox _portsTextBox;
        private TextBlock _portPreviewText;
        private ItemsControl _pluginListControl;   // 用 ItemsControl 渲染 CheckBox 列表
        private ProgressBar _progressBar;
        private TextBlock _statusText;

        private Button _executeButton;
        private Button _cancelButton;
        private Button _closeButton;

        // 缓存 CheckBox 引用，便于"全选 / 反选 / 读取选中"
        private readonly List<CheckBox> _pluginCheckBoxes = new List<CheckBox>();
        private readonly List<IVulnerabilityScannerPlugin> _loadedPlugins = new List<IVulnerabilityScannerPlugin>();

        public PluginQuickInvokeWindow()
        {
            Title = "插件手动扫描";
            Width = 760;
            Height = 640;
            WindowStartupLocation = WindowStartupLocation.CenterOwner;
            Background = Brushes.White;
            MinWidth = 620;
            MinHeight = 520;

            _orchestrator = PluginOrchestrator.Instance;

            BuildUI();

            // 关闭窗口时取消后台任务
            Closing += (s, e) =>
            {
                try
                {
                    _cts?.Cancel();
                    _cts?.Dispose();
                }
                catch { /* 静默 */ }
            };

            // 键盘快捷键
            KeyDown += Window_KeyDown;

            Loaded += async (s, e) =>
            {
                try
                {
                    await EnsureInitializedAsync();
                    LoadPluginsToCheckBox();
                    UpdateStatus($"就绪 | 已加载插件 {_loadedPlugins.Count} 个", "#27AE60");
                }
                catch (Exception ex)
                {
                    UpdateStatus($"初始化失败: {ex.Message}", "#E74C3C");
                }
            };
        }

        // ============================================================
        // UI 构建
        // ============================================================
        private void BuildUI()
        {
            var root = new Grid { Margin = new Thickness(15) };
            root.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto }); // 0 header
            root.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto }); // 1 target card
            root.RowDefinitions.Add(new RowDefinition { Height = new GridLength(1, GridUnitType.Star) }); // 2 plugins card
            root.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto }); // 3 progress card
            root.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto }); // 4 bottom

            var header = CreateHeader();
            Grid.SetRow(header, 0);
            root.Children.Add(header);

            var targetCard = CreateTargetCard();
            Grid.SetRow(targetCard, 1);
            root.Children.Add(targetCard);

            var pluginsCard = CreatePluginsCard();
            Grid.SetRow(pluginsCard, 2);
            root.Children.Add(pluginsCard);

            var progressCard = CreateProgressCard();
            Grid.SetRow(progressCard, 3);
            root.Children.Add(progressCard);

            var bottom = CreateBottomBar();
            Grid.SetRow(bottom, 4);
            root.Children.Add(bottom);

            Content = root;
        }

        private Border CreateHeader()
        {
            var border = new Border
            {
                Background = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#8E44AD")),
                CornerRadius = new CornerRadius(8),
                Padding = new Thickness(15, 10, 15, 10),
                Margin = new Thickness(0, 0, 0, 10)
            };
            var grid = new Grid();
            grid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
            grid.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });

            var title = new TextBlock
            {
                Text = "🔌  插件手动扫描",
                FontSize = 20,
                FontWeight = FontWeights.Bold,
                Foreground = Brushes.White,
                VerticalAlignment = VerticalAlignment.Center
            };
            Grid.SetColumn(title, 0);
            grid.Children.Add(title);

            var headerRight = new StackPanel { Orientation = Orientation.Horizontal, VerticalAlignment = VerticalAlignment.Center };
            var subtitle = new TextBlock
            {
                Text = "v5-T2 · 选择插件 + 目标，单次执行",
                FontSize = 11,
                Foreground = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#E8DAEF")),
                VerticalAlignment = VerticalAlignment.Center,
                Margin = new Thickness(0, 0, 12, 0)
            };
            headerRight.Children.Add(subtitle);

            var closeHeaderBtn = new Button
            {
                Content = "✕",
                Width = 28,
                Height = 28,
                FontWeight = FontWeights.Bold,
                Background = Brushes.Transparent,
                Foreground = Brushes.White,
                BorderThickness = new Thickness(0),
                Cursor = Cursors.Hand
            };
            closeHeaderBtn.Click += (s, e) => Close();
            headerRight.Children.Add(closeHeaderBtn);

            Grid.SetColumn(headerRight, 1);
            grid.Children.Add(headerRight);

            border.Child = grid;
            return border;
        }

        private Border CreateTargetCard()
        {
            var border = new Border
            {
                Background = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#F8F9FA")),
                CornerRadius = new CornerRadius(8),
                Padding = new Thickness(15, 12, 15, 12),
                Margin = new Thickness(0, 0, 0, 10)
            };

            var panel = new StackPanel();

            // 标题
            var title = new TextBlock
            {
                Text = "🎯  扫描目标",
                FontSize = 14,
                FontWeight = FontWeights.Bold,
                Foreground = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#2C3E50")),
                Margin = new Thickness(0, 0, 0, 8)
            };
            panel.Children.Add(title);

            // IP 行
            var ipRow = new StackPanel { Orientation = Orientation.Horizontal, Margin = new Thickness(0, 0, 0, 6) };
            ipRow.Children.Add(new TextBlock
            {
                Text = "目标 IP：",
                Width = 80,
                VerticalAlignment = VerticalAlignment.Center,
                FontSize = 12
            });
            _ipTextBox = new TextBox
            {
                Width = 280,
                Height = 28,
                VerticalContentAlignment = VerticalAlignment.Center,
                FontSize = 12,
                Padding = new Thickness(4, 0, 4, 0)
            };
            _ipTextBox.SetCurrentValue(TextBox.TextProperty, "192.168.1.1");
            ipRow.Children.Add(_ipTextBox);

            // 端口行
            var portRow = new StackPanel { Orientation = Orientation.Horizontal, Margin = new Thickness(0, 0, 0, 4) };
            portRow.Children.Add(new TextBlock
            {
                Text = "端口列表：",
                Width = 80,
                VerticalAlignment = VerticalAlignment.Center,
                FontSize = 12
            });
            _portsTextBox = new TextBox
            {
                Width = 420,
                Height = 28,
                VerticalContentAlignment = VerticalAlignment.Center,
                FontSize = 12,
                Padding = new Thickness(4, 0, 4, 0)
            };
            _portsTextBox.SetCurrentValue(TextBox.TextProperty, "80,443,554,22,21,3306,3389,8080");
            _portsTextBox.TextChanged += (s, e) => UpdatePortPreview();
            portRow.Children.Add(_portsTextBox);

            // 解析预览
            _portPreviewText = new TextBlock
            {
                FontSize = 11,
                Foreground = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#7F8C8D")),
                Margin = new Thickness(84, 4, 0, 0),
                TextWrapping = TextWrapping.Wrap
            };
            UpdatePortPreview();

            panel.Children.Add(ipRow);
            panel.Children.Add(portRow);
            panel.Children.Add(_portPreviewText);

            border.Child = panel;
            return border;
        }

        private Border CreatePluginsCard()
        {
            var border = new Border
            {
                Background = Brushes.White,
                CornerRadius = new CornerRadius(8),
                BorderBrush = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#E2E8F0")),
                BorderThickness = new Thickness(1),
                Margin = new Thickness(0, 0, 0, 10)
            };

            var panel = new DockPanel();

            // 顶部小标题栏
            var header = new Border
            {
                Background = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#F8F9FA")),
                Padding = new Thickness(12, 8, 12, 8)
            };
            var headerGrid = new Grid();
            headerGrid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
            headerGrid.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });

            var titleText = new TextBlock
            {
                Text = "🧩  选择插件（默认全选）",
                FontSize = 14,
                FontWeight = FontWeights.Bold,
                Foreground = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#2C3E50")),
                VerticalAlignment = VerticalAlignment.Center
            };
            Grid.SetColumn(titleText, 0);
            headerGrid.Children.Add(titleText);

            var rightPanel = new StackPanel { Orientation = Orientation.Horizontal, VerticalAlignment = VerticalAlignment.Center };
            var selectAllBtn = new Button
            {
                Content = "全选",
                Width = 50,
                Height = 24,
                Margin = new Thickness(0, 0, 4, 0),
                FontSize = 11,
                Cursor = Cursors.Hand
            };
            selectAllBtn.Click += (s, e) => SetAllCheckBoxes(true);
            rightPanel.Children.Add(selectAllBtn);

            var invertBtn = new Button
            {
                Content = "反选",
                Width = 50,
                Height = 24,
                FontSize = 11,
                Cursor = Cursors.Hand
            };
            invertBtn.Click += (s, e) =>
            {
                foreach (var cb in _pluginCheckBoxes) cb.IsChecked = !cb.IsChecked;
            };
            rightPanel.Children.Add(invertBtn);

            Grid.SetColumn(rightPanel, 1);
            headerGrid.Children.Add(rightPanel);
            header.Child = headerGrid;

            DockPanel.SetDock(header, Dock.Top);
            panel.Children.Add(header);

            // 滚动 + CheckBox 列表
            var scrollViewer = new ScrollViewer
            {
                VerticalScrollBarVisibility = ScrollBarVisibility.Auto,
                HorizontalScrollBarVisibility = ScrollBarVisibility.Disabled,
                Padding = new Thickness(8)
            };

            _pluginListControl = new ItemsControl
            {
                Background = Brushes.White
            };
            // 提前渲染一次空状态
            _pluginListControl.ItemsSource = new List<CheckBox>
            {
                new CheckBox
                {
                    Content = "（正在加载插件...）",
                    IsEnabled = false,
                    Margin = new Thickness(4)
                }
            };

            scrollViewer.Content = _pluginListControl;
            panel.Children.Add(scrollViewer);

            border.Child = panel;
            return border;
        }

        private Border CreateProgressCard()
        {
            var border = new Border
            {
                Background = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#F8F9FA")),
                CornerRadius = new CornerRadius(8),
                Padding = new Thickness(15, 10, 15, 10),
                Margin = new Thickness(0, 0, 0, 10)
            };

            var panel = new StackPanel();

            _progressBar = new ProgressBar
            {
                Height = 18,
                Minimum = 0,
                Maximum = 100,
                Value = 0,
                IsIndeterminate = false
            };
            panel.Children.Add(_progressBar);

            _statusText = new TextBlock
            {
                Text = "就绪",
                FontSize = 12,
                Foreground = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#2C3E50")),
                Margin = new Thickness(0, 6, 0, 0)
            };
            panel.Children.Add(_statusText);

            border.Child = panel;
            return border;
        }

        private Border CreateBottomBar()
        {
            var border = new Border
            {
                Background = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#F8F9FA")),
                Padding = new Thickness(10, 8, 10, 8),
                CornerRadius = new CornerRadius(8)
            };
            var panel = new StackPanel
            {
                Orientation = Orientation.Horizontal,
                HorizontalAlignment = HorizontalAlignment.Right
            };

            _executeButton = new Button
            {
                Content = "▶ 执行",
                Width = 100,
                Height = 32,
                Margin = new Thickness(0, 0, 8, 0),
                Background = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#27AE60")),
                Foreground = Brushes.White,
                BorderThickness = new Thickness(0),
                FontWeight = FontWeights.SemiBold,
                Cursor = Cursors.Hand
            };
            _executeButton.Click += ExecuteButton_Click;
            panel.Children.Add(_executeButton);

            _cancelButton = new Button
            {
                Content = "⏹ 取消",
                Width = 100,
                Height = 32,
                Margin = new Thickness(0, 0, 8, 0),
                Background = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#E67E22")),
                Foreground = Brushes.White,
                BorderThickness = new Thickness(0),
                FontWeight = FontWeights.SemiBold,
                Cursor = Cursors.Hand,
                IsEnabled = false
            };
            _cancelButton.Click += CancelButton_Click;
            panel.Children.Add(_cancelButton);

            _closeButton = new Button
            {
                Content = "关闭",
                Width = 100,
                Height = 32,
                Cursor = Cursors.Hand
            };
            _closeButton.Click += (s, e) => Close();
            panel.Children.Add(_closeButton);

            border.Child = panel;
            return border;
        }

        // ============================================================
        // 初始化 & 数据加载
        // ============================================================
        private async Task EnsureInitializedAsync()
        {
            UpdateStatus("正在初始化插件编排器...", "#3498DB");
            await _orchestrator.InitializeAsync().ConfigureAwait(true);
        }

        private void LoadPluginsToCheckBox()
        {
            _pluginCheckBoxes.Clear();
            _loadedPlugins.Clear();

            var plugins = _orchestrator.LoadedPlugins;
            if (plugins != null)
            {
                foreach (var kv in plugins)
                {
                    if (kv.Value != null) _loadedPlugins.Add(kv.Value);
                }
            }

            if (_loadedPlugins.Count == 0)
            {
                _pluginListControl.ItemsSource = new List<CheckBox>
                {
                    new CheckBox
                    {
                        Content = "（暂无可用插件，请先在【插件管理】中加载插件）",
                        IsEnabled = false,
                        Margin = new Thickness(4)
                    }
                };
                return;
            }

            var items = new List<CheckBox>();
            foreach (var plugin in _loadedPlugins)
            {
                // "适用服务/端口"：用 SupportedScanTypes，没有则用 Description 截断
                string applicable = "通用";
                if (plugin.SupportedScanTypes != null && plugin.SupportedScanTypes.Count > 0)
                {
                    applicable = string.Join(" / ", plugin.SupportedScanTypes);
                }
                else if (!string.IsNullOrWhiteSpace(plugin.Description))
                {
                    applicable = plugin.Description.Length > 30
                        ? plugin.Description.Substring(0, 30) + "..."
                        : plugin.Description;
                }

                var cb = new CheckBox
                {
                    Content = $"{plugin.Name}   |   {applicable}",
                    IsChecked = true, // 默认全选
                    Margin = new Thickness(4, 4, 4, 4),
                    Tag = plugin,
                    ToolTip = $"ID: {plugin.PluginId}\n版本: {plugin.Version}\n作者: {plugin.Author}\n适用: {applicable}"
                };
                _pluginCheckBoxes.Add(cb);
                items.Add(cb);
            }

            _pluginListControl.ItemsSource = items;
        }

        private void SetAllCheckBoxes(bool isChecked)
        {
            foreach (var cb in _pluginCheckBoxes)
            {
                cb.IsChecked = isChecked;
            }
        }

        // ============================================================
        // 端口解析
        // ============================================================
        private void UpdatePortPreview()
        {
            if (_portPreviewText == null) return;
            var text = _portsTextBox?.Text ?? string.Empty;
            var ports = ParsePortsInput(text);
            if (ports.Count == 0)
            {
                _portPreviewText.Text = "⚠ 当前未解析到有效端口（支持 80,443,554 或 1-1024）";
                _portPreviewText.Foreground = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#E67E22"));
            }
            else if (ports.Count > 2048)
            {
                _portPreviewText.Text = $"已解析 {ports.Count} 个端口（较多，扫描会变慢）";
                _portPreviewText.Foreground = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#E67E22"));
            }
            else
            {
                var sample = ports.Count > 12
                    ? string.Join(",", ports.Take(12)) + $" ...（共 {ports.Count} 个）"
                    : string.Join(",", ports);
                _portPreviewText.Text = $"✓ 将扫描 {ports.Count} 个端口：{sample}";
                _portPreviewText.Foreground = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#27AE60"));
            }
        }

        /// <summary>
        /// 解析端口输入，支持：
        /// - 逗号 / 空格 / 分号 / 竖线 分隔
        /// - 单端口：22
        /// - 范围：1-1024
        /// 异常或空输入时返回空列表。
        /// </summary>
        public static List<int> ParsePortsInput(string text)
        {
            var result = new List<int>();
            if (string.IsNullOrWhiteSpace(text)) return result;

            try
            {
                // 统一替换常见分隔符为逗号
                var normalized = text
                    .Replace(';', ',')
                    .Replace('|', ',')
                    .Replace(' ', ',')
                    .Replace('\n', ',')
                    .Replace('\r', ',')
                    .Replace('\t', ',');

                var parts = normalized.Split(new[] { ',' }, StringSplitOptions.RemoveEmptyEntries);
                var seen = new HashSet<int>();

                foreach (var raw in parts)
                {
                    var token = raw.Trim();
                    if (string.IsNullOrEmpty(token)) continue;

                    if (token.Contains('-'))
                    {
                        // 范围
                        var range = token.Split(new[] { '-' }, 2, StringSplitOptions.RemoveEmptyEntries);
                        if (range.Length != 2) continue;
                        if (!int.TryParse(range[0].Trim(), out int start)) continue;
                        if (!int.TryParse(range[1].Trim(), out int end)) continue;
                        if (start > end) (start, end) = (end, start);
                        if (start < 1) start = 1;
                        if (end > 65535) end = 65535;
                        // 防止单条范围爆炸
                        int span = end - start + 1;
                        if (span > 65536) end = start + 65535;
                        for (int p = start; p <= end; p++)
                        {
                            if (seen.Add(p)) result.Add(p);
                        }
                    }
                    else
                    {
                        if (!int.TryParse(token, out int port)) continue;
                        if (port < 1 || port > 65535) continue;
                        if (seen.Add(port)) result.Add(port);
                    }
                }

                result.Sort();
            }
            catch
            {
                return new List<int>();
            }

            return result;
        }

        // ============================================================
        // 事件
        // ============================================================
        private void Window_KeyDown(object sender, KeyEventArgs e)
        {
            if (e.Key == Key.Escape)
            {
                if (_cts != null && !_cts.IsCancellationRequested)
                {
                    CancelButton_Click(this, new RoutedEventArgs());
                }
                else
                {
                    Close();
                }
                e.Handled = true;
            }
        }

        private async void ExecuteButton_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                var ip = _ipTextBox?.Text?.Trim() ?? string.Empty;
                if (string.IsNullOrEmpty(ip))
                {
                    MessageBox.Show("请输入目标 IP", "提示", MessageBoxButton.OK, MessageBoxImage.Information);
                    return;
                }

                var ports = ParsePortsInput(_portsTextBox?.Text ?? string.Empty);
                if (ports.Count == 0)
                {
                    MessageBox.Show("请输入至少一个有效端口（例如 80,443,554 或 1-1024）",
                        "提示", MessageBoxButton.OK, MessageBoxImage.Information);
                    return;
                }

                // 收集选中的插件 ID
                var selectedIds = new List<string>();
                foreach (var cb in _pluginCheckBoxes)
                {
                    if (cb.IsChecked == true && cb.Tag is IVulnerabilityScannerPlugin p)
                    {
                        selectedIds.Add(p.PluginId);
                    }
                }

                if (selectedIds.Count == 0 && _loadedPlugins.Count > 0)
                {
                    MessageBox.Show("请至少选择一个插件", "提示", MessageBoxButton.OK, MessageBoxImage.Information);
                    return;
                }

                // UI 状态切换
                SetExecutingState(true);
                _progressBar.Value = 10;
                UpdateStatus($"开始扫描 {ip}（{ports.Count} 个端口）...", "#3498DB");

                _cts?.Dispose();
                _cts = new CancellationTokenSource();
                var ct = _cts.Token;

                var sw = System.Diagnostics.Stopwatch.StartNew();
                List<VulnerabilityResult> results;
                try
                {
                    var progress = new Progress<(int current, int total, string ipLabel)>(p =>
                    {
                        if (p.total <= 0) return;
                        double ratio = (double)p.current / Math.Max(1, p.total);
                        _progressBar.Value = Math.Min(99, 10 + ratio * 85);
                        UpdateStatus($"扫描中 ({p.current}/{p.total}) {p.ipLabel}", "#3498DB");
                    });

                    results = await _orchestrator
                        .ScanTargetAsync(ip, ports, selectedIds, ct)
                        .ConfigureAwait(true);
                }
                catch (OperationCanceledException)
                {
                    UpdateStatus("⚠ 用户已取消扫描", "#E67E22");
                    MessageBox.Show("扫描已取消", "提示", MessageBoxButton.OK, MessageBoxImage.Information);
                    return;
                }
                catch (Exception ex)
                {
                    UpdateStatus($"❌ 扫描异常: {ex.Message}", "#E74C3C");
                    MessageBox.Show($"扫描异常: {ex.Message}", "错误", MessageBoxButton.OK, MessageBoxImage.Error);
                    return;
                }
                finally
                {
                    sw.Stop();
                }

                _progressBar.Value = 100;
                UpdateStatus(
                    $"✓ 扫描完成 | 耗时 {sw.ElapsedMilliseconds} ms | 发现 {results?.Count ?? 0} 个漏洞",
                    "#27AE60");

                MessageBox.Show(
                    $"扫描完成，共发现 {results?.Count ?? 0} 个漏洞。\n\n耗时：{sw.ElapsedMilliseconds} ms",
                    "扫描结果", MessageBoxButton.OK, MessageBoxImage.Information);
            }
            catch (Exception ex)
            {
                MessageBox.Show($"执行扫描失败: {ex.Message}", "错误", MessageBoxButton.OK, MessageBoxImage.Error);
            }
            finally
            {
                SetExecutingState(false);
            }
        }

        private void CancelButton_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                if (_cts != null && !_cts.IsCancellationRequested)
                {
                    _cts.Cancel();
                    UpdateStatus("正在取消...", "#E67E22");
                    _cancelButton.IsEnabled = false;
                }
            }
            catch (Exception ex)
            {
                MessageBox.Show($"取消失败: {ex.Message}", "错误", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        // ============================================================
        // 辅助
        // ============================================================
        private void SetExecutingState(bool executing)
        {
            if (_executeButton != null) _executeButton.IsEnabled = !executing;
            if (_cancelButton != null) _cancelButton.IsEnabled = executing;
            if (_closeButton != null) _closeButton.IsEnabled = !executing;
            if (_ipTextBox != null) _ipTextBox.IsEnabled = !executing;
            if (_portsTextBox != null) _portsTextBox.IsEnabled = !executing;
            if (_pluginListControl != null) _pluginListControl.IsEnabled = !executing;
            foreach (var cb in _pluginCheckBoxes)
            {
                cb.IsEnabled = !executing;
            }
            _progressBar.IsIndeterminate = executing;
        }

        private void UpdateStatus(string text, string colorHex)
        {
            if (_statusText == null) return;
            _statusText.Text = text;
            try
            {
                _statusText.Foreground = new SolidColorBrush((Color)ColorConverter.ConvertFromString(colorHex));
            }
            catch
            {
                _statusText.Foreground = Brushes.Black;
            }
        }
    }
}
