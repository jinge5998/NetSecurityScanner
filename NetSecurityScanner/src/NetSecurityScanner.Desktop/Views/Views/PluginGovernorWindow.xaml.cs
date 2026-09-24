using NetSecurityScanner.Models;
using NetSecurityScanner.Services;
using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Shapes;
using System.Windows.Threading;

namespace NetSecurityScanner.Views
{
    /// <summary>
    /// 插件管控中心（v6 - PluginGovernorWindow）
    /// 4 个 TabControl 标签页：
    ///   1. 安全治理（白/黑名单/权限矩阵/审计）
    ///   2. 版本与依赖（本地版本/待更新/依赖图/回滚）
    ///   3. 健康监控（健康度排行/隔离列表）
    ///   4. 调度与告警（定时任务/告警规则）
    /// </summary>
    public partial class PluginGovernorWindow : Window
    {
        private readonly PluginGovernor _governor;

        // ====== Tab 1: 安全治理 ======
        private DataGrid _whitelistGrid;
        private DataGrid _blacklistGrid;
        private DataGrid _permissionMatrixGrid;
        private DataGrid _auditGrid;
        private DatePicker _auditDatePicker;
        private TextBox _dangerousOpsTextBox;
        private TextBlock _policyModifiedText;

        // ====== Tab 2: 版本与依赖 ======
        private DataGrid _versionGrid;
        private TextBlock _pendingUpdateBadge;
        private TreeView _dependencyTreeView;
        private DataGrid _backupsGrid;
        private ComboBox _versionPluginSelector;

        // ====== Tab 3: 健康监控 ======
        private DataGrid _healthRankingGrid;
        private DataGrid _quarantinedGrid;
        private TextBlock _healthAvgText;
        private TextBlock _healthIsolatedText;

        // ====== Tab 4: 调度与告警 ======
        private DataGrid _tasksGrid;
        private DataGrid _alertRulesGrid;
        private Button _addTaskButton;
        private Button _removeTaskButton;
        private Button _addAlertButton;
        private Button _removeAlertButton;

        // ====== Tab 5: 运行时大屏 ======
        private TextBlock _kpiHealthText;
        private TextBlock _kpiPendingText;
        private TextBlock _kpiIsolatedText;
        private TextBlock _kpiTasksText;
        private Canvas _healthBarCanvas;
        private ListView _eventStreamList;
        private ObservableCollection<EventStreamRow> _eventStream = new();
        private DispatcherTimer _dashboardTimer;

        // ====== Tab 6: 权限审批 ======
        private DataGrid _permissionRequestGrid;
        private TextBlock _permissionRequestSummary;
        private ObservableCollection<PermissionRequestRow> _permissionRequests = new();

        // ====== Tab 7: 告警模板 ======
        private ItemsControl _alertTemplateItems;
        private readonly Dictionary<string, bool> _templateEnabledCache = new();

        // ====== 状态栏 ======
        private TextBlock _statusHealthText;
        private TextBlock _statusPendingText;
        private TextBlock _statusIsolatedText;
        private TextBlock _statusTasksText;

        public PluginGovernorWindow()
        {
            Title = "插件管控中心";
            Width = 1200;
            Height = 760;
            WindowStartupLocation = WindowStartupLocation.CenterOwner;
            Background = Brushes.White;
            MinWidth = 1000;
            MinHeight = 600;

            _governor = PluginGovernor.Instance;

            BuildUI();

            // 启动运行时大屏 5 秒自动刷新
            _dashboardTimer = new DispatcherTimer
            {
                Interval = TimeSpan.FromSeconds(5)
            };
            _dashboardTimer.Tick += async (s, e) =>
            {
                try { await ReloadRuntimeDashboardAsync(); }
                catch (Exception ex) { System.Diagnostics.Debug.WriteLine($"[RuntimeDashboard] 刷新失败: {ex.Message}"); }
            };
            _dashboardTimer.Start();

            KeyDown += (s, e) =>
            {
                if (e.Key == Key.F5) _ = ReloadAllAsync();
                else if (e.Key == Key.Escape) Close();
            };

            Loaded += async (s, e) =>
            {
                try { await ReloadAllAsync(); }
                catch (Exception ex)
                {
                    MessageBox.Show($"加载管控中心失败: {ex.Message}", "错误", MessageBoxButton.OK, MessageBoxImage.Error);
                }
            };

            Closed += (s, e) =>
            {
                if (_dashboardTimer != null)
                {
                    _dashboardTimer.Stop();
                    _dashboardTimer = null;
                }
                // 不关闭 Governor（单例），只取消本窗口订阅
            };
        }

        // ================ UI 构建 ================
        private void BuildUI()
        {
            var root = new DockPanel();

            // 顶部状态栏
            var statusBar = BuildStatusBar();
            DockPanel.SetDock(statusBar, Dock.Top);
            root.Children.Add(statusBar);

            // 底部按钮栏
            var bottomBar = BuildBottomBar();
            DockPanel.SetDock(bottomBar, Dock.Bottom);
            root.Children.Add(bottomBar);

            // 中间 TabControl
            var tabs = new TabControl { Margin = new Thickness(10) };

            // Tab 1: 安全治理
            var tab1 = new TabItem { Header = "🛡 安全治理" };
            tab1.Content = BuildSecurityTab();
            tabs.Items.Add(tab1);

            // Tab 2: 版本与依赖
            var tab2 = new TabItem { Header = "🔄 版本与依赖" };
            tab2.Content = BuildVersionTab();
            tabs.Items.Add(tab2);

            // Tab 3: 健康监控
            var tab3 = new TabItem { Header = "💚 健康监控" };
            tab3.Content = BuildHealthTab();
            tabs.Items.Add(tab3);

            // Tab 4: 调度与告警
            var tab4 = new TabItem { Header = "⏰ 调度与告警" };
            tab4.Content = BuildSchedulerTab();
            tabs.Items.Add(tab4);

            // Tab 5: 运行时大屏（v7）
            var tab5 = new TabItem { Header = "🩺 运行时大屏" };
            tab5.Content = BuildRuntimeDashboardTab();
            tabs.Items.Add(tab5);

            // Tab 6: 权限审批（v7）
            var tab6 = new TabItem { Header = "📋 权限审批" };
            tab6.Content = BuildPermissionApprovalTab();
            tabs.Items.Add(tab6);

            // Tab 7: 告警模板（v7）
            var tab7 = new TabItem { Header = "🎯 告警模板" };
            tab7.Content = BuildAlertTemplateTab();
            tabs.Items.Add(tab7);

            root.Children.Add(tabs);

            Content = root;
        }

        private Border BuildStatusBar()
        {
            var border = new Border
            {
                Background = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#2C3E50")),
                Padding = new Thickness(15, 8, 15, 8)
            };
            var panel = new StackPanel { Orientation = Orientation.Horizontal };

            panel.Children.Add(new TextBlock
            {
                Text = "🛡  插件管控中心  |  ",
                Foreground = Brushes.White,
                FontWeight = FontWeights.Bold,
                FontSize = 14,
                VerticalAlignment = VerticalAlignment.Center
            });

            _statusHealthText = new TextBlock
            {
                Text = "平均健康度: --",
                Foreground = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#1ABC9C")),
                Margin = new Thickness(10, 0, 0, 0),
                VerticalAlignment = VerticalAlignment.Center
            };
            panel.Children.Add(_statusHealthText);

            _statusPendingText = new TextBlock
            {
                Text = "待更新: 0",
                Foreground = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#F39C12")),
                Margin = new Thickness(15, 0, 0, 0),
                VerticalAlignment = VerticalAlignment.Center
            };
            panel.Children.Add(_statusPendingText);

            _statusIsolatedText = new TextBlock
            {
                Text = "已隔离: 0",
                Foreground = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#E74C3C")),
                Margin = new Thickness(15, 0, 0, 0),
                VerticalAlignment = VerticalAlignment.Center
            };
            panel.Children.Add(_statusIsolatedText);

            _statusTasksText = new TextBlock
            {
                Text = "调度任务: 0",
                Foreground = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#3498DB")),
                Margin = new Thickness(15, 0, 0, 0),
                VerticalAlignment = VerticalAlignment.Center
            };
            panel.Children.Add(_statusTasksText);

            border.Child = panel;
            return border;
        }

        private Border BuildBottomBar()
        {
            var border = new Border
            {
                Background = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#ECF0F1")),
                Padding = new Thickness(15, 8, 15, 8)
            };
            var panel = new StackPanel { Orientation = Orientation.Horizontal, HorizontalAlignment = HorizontalAlignment.Right };

            var refreshBtn = new Button
            {
                Content = "🔄 刷新 (F5)",
                Width = 110,
                Height = 32,
                Margin = new Thickness(5),
                Background = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#3498DB")),
                Foreground = Brushes.White,
                BorderThickness = new Thickness(0),
                Cursor = Cursors.Hand
            };
            refreshBtn.Click += async (s, e) => await ReloadAllAsync();
            panel.Children.Add(refreshBtn);

            var closeBtn = new Button
            {
                Content = "关闭",
                Width = 80,
                Height = 32,
                Margin = new Thickness(5),
                Cursor = Cursors.Hand
            };
            closeBtn.Click += (s, e) => Close();
            panel.Children.Add(closeBtn);

            border.Child = panel;
            return border;
        }

        // ---------------- Tab 1: 安全治理 ----------------
        private UIElement BuildSecurityTab()
        {
            var grid = new Grid { Margin = new Thickness(5) };
            grid.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
            grid.RowDefinitions.Add(new RowDefinition { Height = new GridLength(1, GridUnitType.Star) });
            grid.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });

            // 顶部：危险操作拦截规则编辑 + 保存
            var topPanel = new StackPanel { Orientation = Orientation.Horizontal, Margin = new Thickness(0, 0, 0, 8) };
            topPanel.Children.Add(new TextBlock
            {
                Text = "危险操作拦截（逗号分隔）:",
                VerticalAlignment = VerticalAlignment.Center,
                FontWeight = FontWeights.SemiBold,
                Margin = new Thickness(0, 0, 5, 0)
            });
            _dangerousOpsTextBox = new TextBox
            {
                Width = 350,
                Height = 28,
                VerticalContentAlignment = VerticalAlignment.Center,
                Margin = new Thickness(0, 0, 10, 0)
            };
            topPanel.Children.Add(_dangerousOpsTextBox);

            var saveBtn = new Button
            {
                Content = "💾 保存策略",
                Width = 110,
                Height = 30,
                Background = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#27AE60")),
                Foreground = Brushes.White,
                BorderThickness = new Thickness(0),
                Cursor = Cursors.Hand
            };
            saveBtn.Click += SavePolicyButton_Click;
            topPanel.Children.Add(saveBtn);

            _policyModifiedText = new TextBlock
            {
                Text = "未修改",
                VerticalAlignment = VerticalAlignment.Center,
                Margin = new Thickness(15, 0, 0, 0),
                Foreground = Brushes.Gray
            };
            topPanel.Children.Add(_policyModifiedText);

            Grid.SetRow(topPanel, 0);
            grid.Children.Add(topPanel);

            // 中部：白/黑/权限/审计 四个面板
            var tabSub = new TabControl { Margin = new Thickness(0, 5, 0, 0) };

            // 白名单
            var wl = new TabItem { Header = "✅ 白名单" };
            _whitelistGrid = BuildSimpleStringGrid();
            wl.Content = new DockPanel();
            BuildStringGridEditor((DockPanel)wl.Content, _whitelistGrid, "Whitelist");
            tabSub.Items.Add(wl);

            // 黑名单
            var bl = new TabItem { Header = "🚫 黑名单" };
            _blacklistGrid = BuildSimpleStringGrid();
            bl.Content = new DockPanel();
            BuildStringGridEditor((DockPanel)bl.Content, _blacklistGrid, "Blacklist");
            tabSub.Items.Add(bl);

            // 权限矩阵
            var pm = new TabItem { Header = "🔐 权限矩阵" };
            _permissionMatrixGrid = new DataGrid
            {
                AutoGenerateColumns = false,
                IsReadOnly = false,
                CanUserAddRows = true,
                HeadersVisibility = DataGridHeadersVisibility.Column,
                RowHeight = 30,
                Margin = new Thickness(3)
            };
            _permissionMatrixGrid.Columns.Add(new DataGridTextColumn { Header = "PluginId", Binding = new Binding("PluginId"), Width = new DataGridLength(200) });
            _permissionMatrixGrid.Columns.Add(new DataGridTextColumn { Header = "允许权限（逗号分隔）", Binding = new Binding("PermissionsText"), Width = new DataGridLength(1, DataGridLengthUnitType.Star) });
            pm.Content = _permissionMatrixGrid;
            tabSub.Items.Add(pm);

            // 审计日志
            var au = new TabItem { Header = "📋 审计日志" };
            var auPanel = new DockPanel { Margin = new Thickness(3) };
            var auBar = new StackPanel { Orientation = Orientation.Horizontal, Margin = new Thickness(0, 0, 0, 5) };
            auBar.Children.Add(new TextBlock { Text = "日期:", VerticalAlignment = VerticalAlignment.Center, Margin = new Thickness(0, 0, 5, 0) });
            _auditDatePicker = new DatePicker
            {
                SelectedDate = DateTime.Today,
                Width = 140,
                VerticalAlignment = VerticalAlignment.Center
            };
            _auditDatePicker.SelectedDateChanged += (s, e) => ReloadAuditGrid();
            auBar.Children.Add(_auditDatePicker);
            var refreshAuBtn = new Button { Content = "查询", Width = 70, Height = 26, Margin = new Thickness(10, 0, 0, 0) };
            refreshAuBtn.Click += (s, e) => ReloadAuditGrid();
            auBar.Children.Add(refreshAuBtn);
            DockPanel.SetDock(auBar, Dock.Top);
            auPanel.Children.Add(auBar);

            _auditGrid = new DataGrid
            {
                AutoGenerateColumns = false,
                IsReadOnly = true,
                HeadersVisibility = DataGridHeadersVisibility.Column,
                RowHeight = 26,
                GridLinesVisibility = DataGridGridLinesVisibility.Horizontal
            };
            _auditGrid.Columns.Add(new DataGridTextColumn { Header = "时间", Binding = new Binding("Timestamp") { StringFormat = "yyyy-MM-dd HH:mm:ss" }, Width = new DataGridLength(150) });
            _auditGrid.Columns.Add(new DataGridTextColumn { Header = "操作人", Binding = new Binding("Operator"), Width = new DataGridLength(100) });
            _auditGrid.Columns.Add(new DataGridTextColumn { Header = "插件 ID", Binding = new Binding("PluginId"), Width = new DataGridLength(150) });
            _auditGrid.Columns.Add(new DataGridTextColumn { Header = "动作", Binding = new Binding("Action"), Width = new DataGridLength(120) });
            _auditGrid.Columns.Add(new DataGridTextColumn { Header = "结果", Binding = new Binding("Result"), Width = new DataGridLength(80) });
            _auditGrid.Columns.Add(new DataGridTextColumn { Header = "详情", Binding = new Binding("Detail"), Width = new DataGridLength(1, DataGridLengthUnitType.Star) });
            auPanel.Children.Add(_auditGrid);
            au.Content = auPanel;
            tabSub.Items.Add(au);

            Grid.SetRow(tabSub, 1);
            grid.Children.Add(tabSub);

            return grid;
        }

        private DataGrid BuildSimpleStringGrid()
        {
            var grid = new DataGrid
            {
                AutoGenerateColumns = false,
                IsReadOnly = false,
                CanUserAddRows = true,
                HeadersVisibility = DataGridHeadersVisibility.Column,
                RowHeight = 28,
                Margin = new Thickness(3)
            };
            grid.Columns.Add(new DataGridTextColumn { Header = "值", Binding = new Binding("."), Width = new DataGridLength(1, DataGridLengthUnitType.Star) });
            return grid;
        }

        private void BuildStringGridEditor(DockPanel parent, DataGrid grid, string policyKey)
        {
            var bar = new StackPanel { Orientation = Orientation.Horizontal, Margin = new Thickness(3, 3, 3, 3) };
            var addBtn = new Button { Content = "➕ 添加", Width = 80, Height = 26, Margin = new Thickness(0, 0, 5, 0) };
            addBtn.Click += (s, e) =>
            {
                var list = (grid.ItemsSource as List<string>) ?? new List<string>();
                list.Add("");
                grid.ItemsSource = null;
                grid.ItemsSource = list;
            };
            var delBtn = new Button { Content = "➖ 删除选中", Width = 100, Height = 26 };
            delBtn.Click += (sender, ev) =>
            {
                if (grid.SelectedItem is string sel)
                {
                    var list = (grid.ItemsSource as List<string>) ?? new List<string>();
                    list.Remove(sel);
                    grid.ItemsSource = null;
                    grid.ItemsSource = list;
                }
            };
            bar.Children.Add(addBtn);
            bar.Children.Add(delBtn);
            DockPanel.SetDock(bar, Dock.Top);
            parent.Children.Add(bar);
            parent.Children.Add(grid);
        }

        // ---------------- Tab 2: 版本与依赖 ----------------
        private UIElement BuildVersionTab()
        {
            var grid = new Grid { Margin = new Thickness(5) };
            grid.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
            grid.RowDefinitions.Add(new RowDefinition { Height = new GridLength(1, GridUnitType.Star) });
            grid.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });

            // 顶部：选择插件 + 状态徽章
            var top = new StackPanel { Orientation = Orientation.Horizontal, Margin = new Thickness(0, 0, 0, 8) };
            top.Children.Add(new TextBlock { Text = "选择插件:", VerticalAlignment = VerticalAlignment.Center, Margin = new Thickness(0, 0, 5, 0) });
            _versionPluginSelector = new ComboBox { Width = 220, Height = 28, VerticalAlignment = VerticalAlignment.Center, Margin = new Thickness(0, 0, 10, 0) };
            _versionPluginSelector.SelectionChanged += (s, e) => ReloadDependencyTree();
            top.Children.Add(_versionPluginSelector);

            _pendingUpdateBadge = new TextBlock
            {
                Text = "● 待更新 0",
                Foreground = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#E67E22")),
                FontWeight = FontWeights.Bold,
                VerticalAlignment = VerticalAlignment.Center,
                Margin = new Thickness(10, 0, 0, 0)
            };
            top.Children.Add(_pendingUpdateBadge);

            var upgradeBtn = new Button
            {
                Content = "🔄 升级选中",
                Width = 110,
                Height = 28,
                Margin = new Thickness(15, 0, 0, 0),
                Background = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#27AE60")),
                Foreground = Brushes.White,
                BorderThickness = new Thickness(0),
                Cursor = Cursors.Hand
            };
            upgradeBtn.Click += UpgradeButton_Click;
            top.Children.Add(upgradeBtn);

            var recheckBtn = new Button
            {
                Content = "🔍 重新检查更新",
                Width = 130,
                Height = 28,
                Margin = new Thickness(10, 0, 0, 0),
                Background = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#3498DB")),
                Foreground = Brushes.White,
                BorderThickness = new Thickness(0),
                Cursor = Cursors.Hand
            };
            recheckBtn.Click += async (s, e) => await RecheckUpdatesAsync();
            top.Children.Add(recheckBtn);

            Grid.SetRow(top, 0);
            grid.Children.Add(top);

            // 中部 Tab: 版本表 / 依赖图 / 回滚记录
            var sub = new TabControl();

            // 版本表
            var versionTab = new TabItem { Header = "本地版本" };
            _versionGrid = new DataGrid
            {
                AutoGenerateColumns = false,
                IsReadOnly = true,
                RowHeight = 28,
                GridLinesVisibility = DataGridGridLinesVisibility.Horizontal,
                HeadersVisibility = DataGridHeadersVisibility.Column
            };
            _versionGrid.Columns.Add(new DataGridTextColumn { Header = "插件 ID", Binding = new Binding("PluginId"), Width = new DataGridLength(200) });
            _versionGrid.Columns.Add(new DataGridTextColumn { Header = "本地版本", Binding = new Binding("LocalVersion"), Width = new DataGridLength(100) });
            _versionGrid.Columns.Add(new DataGridTextColumn { Header = "远端版本", Binding = new Binding("RemoteVersion"), Width = new DataGridLength(100) });
            _versionGrid.Columns.Add(new DataGridTextColumn { Header = "状态", Binding = new Binding("StatusText"), Width = new DataGridLength(120) });
            _versionGrid.Columns.Add(new DataGridTextColumn { Header = "最低 Core 要求", Binding = new Binding("MinCoreVersion"), Width = new DataGridLength(120) });
            versionTab.Content = _versionGrid;
            sub.Items.Add(versionTab);

            // 依赖图
            var depTab = new TabItem { Header = "依赖图" };
            _dependencyTreeView = new TreeView { Margin = new Thickness(3) };
            depTab.Content = _dependencyTreeView;
            sub.Items.Add(depTab);

            // 回滚记录
            var rbTab = new TabItem { Header = "回滚记录" };
            _backupsGrid = new DataGrid
            {
                AutoGenerateColumns = false,
                IsReadOnly = true,
                RowHeight = 28,
                HeadersVisibility = DataGridHeadersVisibility.Column
            };
            _backupsGrid.Columns.Add(new DataGridTextColumn { Header = "插件 ID", Binding = new Binding("PluginId"), Width = new DataGridLength(200) });
            _backupsGrid.Columns.Add(new DataGridTextColumn { Header = "版本", Binding = new Binding("Version"), Width = new DataGridLength(120) });
            _backupsGrid.Columns.Add(new DataGridTextColumn { Header = "操作", Binding = new Binding("Action"), Width = new DataGridLength(100) });
            _backupsGrid.Columns.Add(new DataGridTextColumn { Header = "时间", Binding = new Binding("Timestamp") { StringFormat = "yyyy-MM-dd HH:mm:ss" }, Width = new DataGridLength(1, DataGridLengthUnitType.Star) });
            var rollbackCol = new DataGridTemplateColumn { Header = "回滚", Width = new DataGridLength(80) };
            var rollbackBtnFactory = new FrameworkElementFactory(typeof(Button));
            rollbackBtnFactory.SetValue(Button.ContentProperty, "回滚");
            rollbackBtnFactory.SetValue(Button.WidthProperty, 60.0);
            rollbackBtnFactory.SetValue(Button.HeightProperty, 22.0);
            rollbackBtnFactory.SetValue(Button.CursorProperty, Cursors.Hand);
            rollbackBtnFactory.AddHandler(Button.ClickEvent, new RoutedEventHandler(RollbackBtn_Click));
            rollbackCol.CellTemplate = new DataTemplate { VisualTree = rollbackBtnFactory };
            _backupsGrid.Columns.Add(rollbackCol);
            rbTab.Content = _backupsGrid;
            sub.Items.Add(rbTab);

            Grid.SetRow(sub, 1);
            grid.Children.Add(sub);

            return grid;
        }

        private void RollbackBtn_Click(object sender, RoutedEventArgs e)
        {
            if (((FrameworkElement)sender).DataContext is BackupRecordInfo rec)
            {
                if (MessageBox.Show($"确定回滚 {rec.PluginId} 到 {rec.Version} 吗？", "回滚确认", MessageBoxButton.YesNo, MessageBoxImage.Question) == MessageBoxResult.Yes)
                {
                    _ = RollbackAsync(rec.PluginId, rec.Version);
                }
            }
        }

        private async Task RollbackAsync(string id, string version)
        {
            try
            {
                var ok = await _governor.VersionManager.RollbackAsync(id, version);
                MessageBox.Show(ok ? "回滚成功！" : "回滚失败！", "提示", MessageBoxButton.OK, ok ? MessageBoxImage.Information : MessageBoxImage.Error);
                await ReloadVersionTabAsync();
            }
            catch (Exception ex)
            {
                MessageBox.Show($"回滚失败: {ex.Message}", "错误", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        private async void UpgradeButton_Click(object sender, RoutedEventArgs e)
        {
            if (_versionPluginSelector.SelectedItem is string id)
            {
                var ok = await _governor.VersionManager.UpgradeAsync(id);
                MessageBox.Show(ok ? "升级成功！" : "升级失败（请检查 core 版本要求）", "提示", MessageBoxButton.OK, ok ? MessageBoxImage.Information : MessageBoxImage.Warning);
                await ReloadVersionTabAsync();
            }
        }

        private async Task RecheckUpdatesAsync()
        {
            try
            {
                var pm = PluginOrchestrator.Instance.LoadedPlugins.Count > 0
                    ? null
                    : (await EnsurePluginManager()).Item1;
                var manager = pm ?? (await EnsurePluginManager()).Item1;
                await _governor.VersionManager.CheckUpdatesAsync(manager);
                await ReloadVersionTabAsync();
            }
            catch (Exception ex)
            {
                MessageBox.Show($"检查更新失败: {ex.Message}", "错误", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        private async Task<(NetSecurityScanner.Plugins.PluginManager, NetSecurityScanner.Services.PluginOrchestrator)> EnsurePluginManager()
        {
            var orchestrator = PluginOrchestrator.Instance;
            if (!orchestrator.IsInitialized)
            {
                await orchestrator.InitializeAsync();
            }
            // 暂用一个反射 / 简单代理 — 这里使用新实例（不与已加载实例冲突）
            var pm = new NetSecurityScanner.Plugins.PluginManager();
            await pm.LoadAllPluginsAsync();
            return (pm, orchestrator);
        }

        // ---------------- Tab 3: 健康监控 ----------------
        private UIElement BuildHealthTab()
        {
            var grid = new Grid { Margin = new Thickness(5) };
            grid.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
            grid.RowDefinitions.Add(new RowDefinition { Height = new GridLength(1, GridUnitType.Star) });

            // 顶部摘要
            var top = new StackPanel { Orientation = Orientation.Horizontal, Margin = new Thickness(0, 0, 0, 8) };
            _healthAvgText = new TextBlock
            {
                Text = "平均健康度: --",
                FontWeight = FontWeights.Bold,
                Foreground = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#27AE60")),
                VerticalAlignment = VerticalAlignment.Center,
                Margin = new Thickness(0, 0, 20, 0)
            };
            top.Children.Add(_healthAvgText);
            _healthIsolatedText = new TextBlock
            {
                Text = "已隔离: 0",
                FontWeight = FontWeights.Bold,
                Foreground = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#E74C3C")),
                VerticalAlignment = VerticalAlignment.Center
            };
            top.Children.Add(_healthIsolatedText);
            Grid.SetRow(top, 0);
            grid.Children.Add(top);

            var sub = new TabControl();

            // 健康度排行
            var rankTab = new TabItem { Header = "健康度排行" };
            _healthRankingGrid = new DataGrid
            {
                AutoGenerateColumns = false,
                IsReadOnly = true,
                RowHeight = 28,
                GridLinesVisibility = DataGridGridLinesVisibility.Horizontal,
                HeadersVisibility = DataGridHeadersVisibility.Column
            };
            _healthRankingGrid.Columns.Add(new DataGridTextColumn { Header = "插件 ID", Binding = new Binding("PluginId"), Width = new DataGridLength(200) });
            _healthRankingGrid.Columns.Add(new DataGridTextColumn { Header = "健康度", Binding = new Binding("HealthScore"), Width = new DataGridLength(80) });
            _healthRankingGrid.Columns.Add(new DataGridTextColumn { Header = "累计执行", Binding = new Binding("TotalExecutions"), Width = new DataGridLength(80) });
            _healthRankingGrid.Columns.Add(new DataGridTextColumn { Header = "失败", Binding = new Binding("TotalFailures"), Width = new DataGridLength(60) });
            _healthRankingGrid.Columns.Add(new DataGridTextColumn { Header = "超时", Binding = new Binding("TotalTimeouts"), Width = new DataGridLength(60) });
            _healthRankingGrid.Columns.Add(new DataGridTextColumn { Header = "峰值内存", Binding = new Binding("PeakMemoryText"), Width = new DataGridLength(100) });
            _healthRankingGrid.Columns.Add(new DataGridTextColumn { Header = "累计耗时(ms)", Binding = new Binding("TotalElapsedMs"), Width = new DataGridLength(100) });
            _healthRankingGrid.Columns.Add(new DataGridTextColumn { Header = "状态", Binding = new Binding("StatusText"), Width = new DataGridLength(100) });
            rankTab.Content = _healthRankingGrid;
            sub.Items.Add(rankTab);

            // 隔离列表
            var qTab = new TabItem { Header = "已隔离" };
            _quarantinedGrid = new DataGrid
            {
                AutoGenerateColumns = false,
                IsReadOnly = true,
                RowHeight = 28,
                HeadersVisibility = DataGridHeadersVisibility.Column
            };
            _quarantinedGrid.Columns.Add(new DataGridTextColumn { Header = "插件 ID", Binding = new Binding("PluginId"), Width = new DataGridLength(200) });
            _quarantinedGrid.Columns.Add(new DataGridTextColumn { Header = "隔离时间", Binding = new Binding("QuarantinedAt") { StringFormat = "yyyy-MM-dd HH:mm:ss" }, Width = new DataGridLength(180) });
            _quarantinedGrid.Columns.Add(new DataGridTextColumn { Header = "最近错误", Binding = new Binding("LastError"), Width = new DataGridLength(1, DataGridLengthUnitType.Star) });
            var unqCol = new DataGridTemplateColumn { Header = "操作", Width = new DataGridLength(100) };
            var unqBtnFactory = new FrameworkElementFactory(typeof(Button));
            unqBtnFactory.SetValue(Button.ContentProperty, "解除隔离");
            unqBtnFactory.SetValue(Button.WidthProperty, 80.0);
            unqBtnFactory.SetValue(Button.HeightProperty, 22.0);
            unqBtnFactory.AddHandler(Button.ClickEvent, new RoutedEventHandler(UnquarantineBtn_Click));
            unqCol.CellTemplate = new DataTemplate { VisualTree = unqBtnFactory };
            _quarantinedGrid.Columns.Add(unqCol);
            qTab.Content = _quarantinedGrid;
            sub.Items.Add(qTab);

            Grid.SetRow(sub, 1);
            grid.Children.Add(sub);

            return grid;
        }

        private void UnquarantineBtn_Click(object sender, RoutedEventArgs e)
        {
            if (((FrameworkElement)sender).DataContext is PluginHealthSnapshot s)
            {
                _governor.Health.Unquarantine(s.PluginId);
                _ = ReloadHealthTabAsync();
            }
        }

        // ---------------- Tab 4: 调度与告警 ----------------
        private UIElement BuildSchedulerTab()
        {
            var grid = new Grid { Margin = new Thickness(5) };
            grid.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
            grid.RowDefinitions.Add(new RowDefinition { Height = new GridLength(1, GridUnitType.Star) });

            var top = new StackPanel { Orientation = Orientation.Horizontal, Margin = new Thickness(0, 0, 0, 8) };
            _addTaskButton = new Button { Content = "➕ 新建任务", Width = 100, Height = 28, Margin = new Thickness(0, 0, 5, 0) };
            _addTaskButton.Click += AddTaskButton_Click;
            top.Children.Add(_addTaskButton);
            _removeTaskButton = new Button { Content = "➖ 删除任务", Width = 100, Height = 28 };
            _removeTaskButton.Click += RemoveTaskButton_Click;
            top.Children.Add(_removeTaskButton);
            Grid.SetRow(top, 0);
            grid.Children.Add(top);

            var sub = new TabControl();

            // 定时任务
            var tTab = new TabItem { Header = "定时任务" };
            _tasksGrid = new DataGrid
            {
                AutoGenerateColumns = false,
                IsReadOnly = true,
                RowHeight = 28,
                HeadersVisibility = DataGridHeadersVisibility.Column,
                GridLinesVisibility = DataGridGridLinesVisibility.Horizontal
            };
            _tasksGrid.Columns.Add(new DataGridTextColumn { Header = "任务名", Binding = new Binding("Name"), Width = new DataGridLength(180) });
            _tasksGrid.Columns.Add(new DataGridTextColumn { Header = "Cron", Binding = new Binding("CronExpression"), Width = new DataGridLength(140) });
            _tasksGrid.Columns.Add(new DataGridTextColumn { Header = "目标 IP", Binding = new Binding("TargetIp"), Width = new DataGridLength(140) });
            _tasksGrid.Columns.Add(new DataGridTextColumn { Header = "端口", Binding = new Binding("PortsText"), Width = new DataGridLength(120) });
            _tasksGrid.Columns.Add(new DataGridTextColumn { Header = "已运行", Binding = new Binding("TotalRuns"), Width = new DataGridLength(60) });
            _tasksGrid.Columns.Add(new DataGridTextColumn { Header = "失败", Binding = new Binding("TotalFailures"), Width = new DataGridLength(60) });
            _tasksGrid.Columns.Add(new DataGridTextColumn { Header = "启用", Binding = new Binding("EnabledText"), Width = new DataGridLength(60) });
            tTab.Content = _tasksGrid;
            sub.Items.Add(tTab);

            // 告警规则
            var aTab = new TabItem { Header = "告警规则" };
            var aPanel = new DockPanel();
            var aBar = new StackPanel { Orientation = Orientation.Horizontal, Margin = new Thickness(3) };
            _addAlertButton = new Button { Content = "➕ 新建规则", Width = 100, Height = 26, Margin = new Thickness(0, 0, 5, 0) };
            _addAlertButton.Click += AddAlertButton_Click;
            aBar.Children.Add(_addAlertButton);
            _removeAlertButton = new Button { Content = "➖ 删除规则", Width = 100, Height = 26 };
            _removeAlertButton.Click += RemoveAlertButton_Click;
            aBar.Children.Add(_removeAlertButton);
            DockPanel.SetDock(aBar, Dock.Top);
            aPanel.Children.Add(aBar);
            _alertRulesGrid = new DataGrid
            {
                AutoGenerateColumns = false,
                IsReadOnly = true,
                RowHeight = 28,
                HeadersVisibility = DataGridHeadersVisibility.Column
            };
            _alertRulesGrid.Columns.Add(new DataGridTextColumn { Header = "名称", Binding = new Binding("Name"), Width = new DataGridLength(150) });
            _alertRulesGrid.Columns.Add(new DataGridTextColumn { Header = "类型", Binding = new Binding("TypeText"), Width = new DataGridLength(160) });
            _alertRulesGrid.Columns.Add(new DataGridTextColumn { Header = "阈值", Binding = new Binding("Threshold"), Width = new DataGridLength(80) });
            _alertRulesGrid.Columns.Add(new DataGridTextColumn { Header = "时间窗(分)", Binding = new Binding("TimeWindowMinutes"), Width = new DataGridLength(100) });
            _alertRulesGrid.Columns.Add(new DataGridTextColumn { Header = "通知渠道", Binding = new Binding("ChannelsText"), Width = new DataGridLength(150) });
            _alertRulesGrid.Columns.Add(new DataGridTextColumn { Header = "启用", Binding = new Binding("EnabledText"), Width = new DataGridLength(60) });
            aPanel.Children.Add(_alertRulesGrid);
            aTab.Content = aPanel;
            sub.Items.Add(aTab);

            Grid.SetRow(sub, 1);
            grid.Children.Add(sub);

            return grid;
        }

        // ================ 数据加载 ================
        private async Task ReloadAllAsync()
        {
            await ReloadSecurityTabAsync();
            await ReloadVersionTabAsync();
            await ReloadHealthTabAsync();
            await ReloadSchedulerTabAsync();
            await ReloadRuntimeDashboardAsync();
            await ReloadPermissionApprovalTabAsync();
            await ReloadAlertTemplateTabAsync();
            UpdateStatusBar();
        }

        private void UpdateStatusBar()
        {
            try
            {
                var snaps = _governor.Health.GetAllSnapshots();
                var avg = snaps.Count > 0 ? (int)snaps.Average(s => s.HealthScore) : 100;
                _statusHealthText.Text = $"平均健康度: {avg}";
                _statusHealthText.Foreground = avg < 60
                    ? new SolidColorBrush((Color)ColorConverter.ConvertFromString("#E74C3C"))
                    : new SolidColorBrush((Color)ColorConverter.ConvertFromString("#1ABC9C"));

                var pending = _governor.VersionManager.PendingUpdates.Count;
                _statusPendingText.Text = $"待更新: {pending}";

                var isolated = _governor.Health.GetQuarantined().Count;
                _statusIsolatedText.Text = $"已隔离: {isolated}";

                var tasks = _governor.Scheduler.Tasks.Count(t => t.Enabled);
                _statusTasksText.Text = $"调度任务: {tasks}";
            }
            catch { /* 静默 */ }
        }

        private async Task ReloadSecurityTabAsync()
        {
            try
            {
                var policy = _governor.Security.CurrentPolicy;
                _whitelistGrid.ItemsSource = new List<string>(policy.Whitelist);
                _blacklistGrid.ItemsSource = new List<string>(policy.Blacklist);
                _dangerousOpsTextBox.Text = string.Join(",", policy.DangerousOpBlockList);
                _policyModifiedText.Text = $"最后修改: {policy.LastModified:yyyy-MM-dd HH:mm:ss} by {policy.LastModifiedBy}";

                _permissionMatrixGrid.ItemsSource = policy.PermissionMatrix
                    .Select(kv => new PermissionRow { PluginId = kv.Key, PermissionsText = string.Join(",", kv.Value ?? new List<string>()) })
                    .ToList();
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"[PluginGovernorWindow] 加载安全策略失败: {ex.Message}");
            }
            ReloadAuditGrid();
            await Task.CompletedTask;
        }

        private void ReloadAuditGrid()
        {
            try
            {
                var date = _auditDatePicker.SelectedDate ?? DateTime.Today;
                var entries = _governor.Security.GetAuditEntries(date);
                _auditGrid.ItemsSource = entries.OrderByDescending(e => e.Timestamp).ToList();
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"[PluginGovernorWindow] 加载审计失败: {ex.Message}");
            }
        }

        private async Task ReloadVersionTabAsync()
        {
            try
            {
                var pending = _governor.VersionManager.PendingUpdates;
                _pendingUpdateBadge.Text = $"● 待更新 {pending.Count}";

                var allPlugins = PluginOrchestrator.Instance.LoadedPlugins;
                var rows = allPlugins.Values.Select(p =>
                {
                    var hasUpdate = pending.TryGetValue(p.PluginId, out var remote);
                    return new VersionRow
                    {
                        PluginId = p.PluginId,
                        LocalVersion = p.Version,
                        RemoteVersion = hasUpdate ? remote!.Version : "-",
                        StatusText = hasUpdate ? "可升级" : "最新",
                        MinCoreVersion = hasUpdate ? (remote!.MinCoreVersion ?? "-") : "-"
                    };
                }).ToList();
                _versionGrid.ItemsSource = rows;

                // 插件下拉
                var selectedId = _versionPluginSelector.SelectedItem as string;
                _versionPluginSelector.ItemsSource = allPlugins.Keys.OrderBy(k => k).ToList();
                if (selectedId != null && allPlugins.ContainsKey(selectedId))
                    _versionPluginSelector.SelectedItem = selectedId;
                else if (_versionPluginSelector.Items.Count > 0)
                    _versionPluginSelector.SelectedIndex = 0;

                // 回滚记录
                var backups = _governor.VersionManager.ListBackups();
                var backupRows = new List<BackupRecordInfo>();
                foreach (var kv in backups)
                {
                    foreach (var v in kv.Value)
                    {
                        backupRows.Add(new BackupRecordInfo
                        {
                            PluginId = kv.Key,
                            Version = v,
                            Action = "已备份",
                            Timestamp = DateTime.Now // 真实环境应来自元数据
                        });
                    }
                }
                _backupsGrid.ItemsSource = backupRows.OrderByDescending(r => r.Timestamp).ToList();
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"[PluginGovernorWindow] 加载版本失败: {ex.Message}");
            }
            await Task.CompletedTask;
        }

        private void ReloadDependencyTree()
        {
            try
            {
                if (_versionPluginSelector.SelectedItem is not string id) return;
                if (!PluginOrchestrator.Instance.LoadedPlugins.TryGetValue(id, out var plugin)) return;

                // 把 IVulnerabilityScannerPlugin 转成 Models.Plugin 以便 VersionManager 解析依赖
                var rootModel = ToPluginModel(plugin);
                var installedModels = PluginOrchestrator.Instance.LoadedPlugins.Values.Select(ToPluginModel).ToList();
                var graph = _governor.VersionManager.ResolveDependency(rootModel, installedModels);
                _dependencyTreeView.Items.Clear();
                _dependencyTreeView.Items.Add(BuildDepNode(graph.Root));
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"[PluginGovernorWindow] 加载依赖图失败: {ex.Message}");
            }
        }

        private static NetSecurityScanner.Models.Plugin ToPluginModel(NetSecurityScanner.Plugins.IVulnerabilityScannerPlugin p)
        {
            return new NetSecurityScanner.Models.Plugin
            {
                Id = p.PluginId,
                Name = p.Name,
                Version = p.Version ?? "1.0.0",
                Author = p.Author ?? string.Empty,
                Description = p.Description ?? string.Empty,
                Dependencies = new List<string>()
            };
        }

        private TreeViewItem BuildDepNode(PluginDependencyNode node)
        {
            var label = node.Status switch
            {
                DependencyStatus.Satisfied => $"🟢 {node.PluginId} ({node.Version})",
                DependencyStatus.Missing => $"🔴 {node.PluginId} [缺失]",
                DependencyStatus.VersionTooLow => $"🟡 {node.PluginId} ({node.Version} < {node.MinRequiredVersion})",
                _ => node.PluginId
            };
            var item = new TreeViewItem { Header = label };
            foreach (var c in node.Children)
            {
                item.Items.Add(BuildDepNode(c));
            }
            if (node.Status == DependencyStatus.Missing)
            {
                var installItem = new TreeViewItem { Header = "⚡ 一键安装" };
                installItem.MouseDoubleClick += async (s, e) =>
                {
                    await _governor.VersionManager.InstallDependenciesAsync(new List<string> { node.PluginId });
                    ReloadDependencyTree();
                };
                item.Items.Add(installItem);
            }
            return item;
        }

        private async Task ReloadHealthTabAsync()
        {
            try
            {
                var snaps = _governor.Health.GetAllSnapshots();
                _healthRankingGrid.ItemsSource = snaps.Select(s => new HealthRow
                {
                    PluginId = s.PluginId,
                    HealthScore = s.HealthScore,
                    TotalExecutions = s.TotalExecutions,
                    TotalFailures = s.TotalFailures,
                    TotalTimeouts = s.TotalTimeouts,
                    PeakMemoryText = $"{s.PeakMemoryBytes / 1024.0 / 1024.0:F1} MB",
                    TotalElapsedMs = s.TotalElapsedMs,
                    StatusText = s.IsQuarantined ? "🔴 已隔离" : (s.HealthScore < 60 ? "⚠ 低健康度" : "🟢 正常")
                }).ToList();
                _quarantinedGrid.ItemsSource = snaps.Where(s => s.IsQuarantined).ToList();

                if (snaps.Count > 0)
                {
                    var avg = (int)snaps.Average(s => s.HealthScore);
                    _healthAvgText.Text = $"平均健康度: {avg}";
                }
                else
                {
                    _healthAvgText.Text = "平均健康度: --";
                }
                _healthIsolatedText.Text = $"已隔离: {snaps.Count(s => s.IsQuarantined)}";
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"[PluginGovernorWindow] 加载健康监控失败: {ex.Message}");
            }
            await Task.CompletedTask;
        }

        private async Task ReloadSchedulerTabAsync()
        {
            try
            {
                var tasks = _governor.Scheduler.Tasks;
                _tasksGrid.ItemsSource = tasks.Select(t => new TaskRow
                {
                    Id = t.Id,
                    Name = t.Name,
                    CronExpression = t.CronExpression,
                    TargetIp = t.TargetIp,
                    PortsText = t.Ports == null ? "" : string.Join(",", t.Ports),
                    TotalRuns = t.TotalRuns,
                    TotalFailures = t.TotalFailures,
                    EnabledText = t.Enabled ? "✅" : "❌"
                }).ToList();

                var rules = _governor.Scheduler.AlertRules;
                _alertRulesGrid.ItemsSource = rules.Select(r => new AlertRow
                {
                    Id = r.Id,
                    Name = r.Name,
                    TypeText = r.Type.ToString(),
                    Threshold = r.Threshold,
                    TimeWindowMinutes = r.TimeWindowMinutes,
                    ChannelsText = string.Join(",", r.NotificationChannels),
                    EnabledText = r.Enabled ? "✅" : "❌"
                }).ToList();
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"[PluginGovernorWindow] 加载调度失败: {ex.Message}");
            }
            await Task.CompletedTask;
        }

        // ---------------- Tab 5: 运行时大屏（v7） ----------------
        private UIElement BuildRuntimeDashboardTab()
        {
            var grid = new Grid { Margin = new Thickness(8) };
            grid.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto }); // KPI 行
            grid.RowDefinitions.Add(new RowDefinition { Height = new GridLength(1, GridUnitType.Star) }); // 主区域
            grid.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto }); // 状态

            // ===== 顶部 KPI 卡片 =====
            var kpiPanel = new StackPanel { Orientation = Orientation.Horizontal, Margin = new Thickness(0, 0, 0, 10) };
            kpiPanel.Children.Add(BuildKpiCard("平均健康度", "--", "#27AE60", out _kpiHealthText));
            kpiPanel.Children.Add(BuildKpiCard("待更新", "0", "#F39C12", out _kpiPendingText));
            kpiPanel.Children.Add(BuildKpiCard("已隔离", "0", "#E74C3C", out _kpiIsolatedText));
            kpiPanel.Children.Add(BuildKpiCard("调度任务", "0", "#3498DB", out _kpiTasksText));
            Grid.SetRow(kpiPanel, 0);
            grid.Children.Add(kpiPanel);

            // ===== 中部：柱状图 + 事件流 =====
            var midGrid = new Grid();
            midGrid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
            midGrid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(5) });
            midGrid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1.4, GridUnitType.Star) });

            // 左：Top 5 健康度柱状图
            var chartBorder = new Border
            {
                BorderBrush = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#BDC3C7")),
                BorderThickness = new Thickness(1),
                CornerRadius = new CornerRadius(4),
                Background = Brushes.White,
                Padding = new Thickness(10)
            };
            var chartPanel = new StackPanel();
            chartPanel.Children.Add(new TextBlock
            {
                Text = "📊 Top 5 插件健康度",
                FontWeight = FontWeights.Bold,
                FontSize = 14,
                Foreground = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#2C3E50")),
                Margin = new Thickness(0, 0, 0, 8)
            });
            _healthBarCanvas = new Canvas
            {
                Height = 240,
                Background = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#ECF0F1"))
            };
            chartPanel.Children.Add(_healthBarCanvas);
            chartBorder.Child = chartPanel;
            midGrid.Children.Add(chartBorder);

            // 分隔条
            midGrid.Children.Add(new Border
            {
                Background = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#ECF0F1")),
                Width = 5
            });
            Grid.SetColumn(midGrid.Children[1], 1);

            // 右：事件流
            var streamBorder = new Border
            {
                BorderBrush = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#BDC3C7")),
                BorderThickness = new Thickness(1),
                CornerRadius = new CornerRadius(4),
                Background = Brushes.White,
                Padding = new Thickness(10)
            };
            var streamPanel = new DockPanel();
            streamPanel.Children.Add(new TextBlock
            {
                Text = "📡 事件流（今日告警 / 隔离 / 签名失败）",
                FontWeight = FontWeights.Bold,
                FontSize = 14,
                Foreground = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#2C3E50")),
                Margin = new Thickness(0, 0, 0, 8)
            });
            DockPanel.SetDock((UIElement)streamPanel.Children[0], Dock.Top);
            _eventStreamList = new ListView
            {
                ItemsSource = _eventStream,
                Background = Brushes.White,
                BorderThickness = new Thickness(0)
            };
            var gridFactory = new FrameworkElementFactory(typeof(Grid));
            var col1 = new FrameworkElementFactory(typeof(ColumnDefinition));
            col1.SetValue(ColumnDefinition.WidthProperty, new GridLength(140));
            var col2 = new FrameworkElementFactory(typeof(ColumnDefinition));
            col2.SetValue(ColumnDefinition.WidthProperty, new GridLength(80));
            var col3 = new FrameworkElementFactory(typeof(ColumnDefinition));
            col3.SetValue(ColumnDefinition.WidthProperty, new GridLength(120));
            var col4 = new FrameworkElementFactory(typeof(ColumnDefinition));
            col4.SetValue(ColumnDefinition.WidthProperty, new GridLength(60));
            var col5 = new FrameworkElementFactory(typeof(ColumnDefinition));
            col5.SetValue(ColumnDefinition.WidthProperty, new GridLength(80));
            var col6 = new FrameworkElementFactory(typeof(ColumnDefinition));
            col6.SetValue(ColumnDefinition.WidthProperty, new GridLength(1, GridUnitType.Star));
            gridFactory.AppendChild(col1);
            gridFactory.AppendChild(col2);
            gridFactory.AppendChild(col3);
            gridFactory.AppendChild(col4);
            gridFactory.AppendChild(col5);
            gridFactory.AppendChild(col6);
            gridFactory.AppendChild(MakeListCell("TimeText"));
            gridFactory.AppendChild(MakeListCell("SeverityText"));
            gridFactory.AppendChild(MakeListCell("PluginId"));
            gridFactory.AppendChild(MakeListCell("Action"));
            gridFactory.AppendChild(MakeListCell("Result"));
            gridFactory.AppendChild(MakeListCell("Detail"));
            _eventStreamList.ItemTemplate = new DataTemplate { VisualTree = gridFactory };
            _eventStreamList.MouseDoubleClick += EventStreamList_MouseDoubleClick;
            streamPanel.Children.Add(_eventStreamList);
            streamBorder.Child = streamPanel;
            Grid.SetColumn(streamBorder, 2);
            midGrid.Children.Add(streamBorder);

            Grid.SetRow(midGrid, 1);
            grid.Children.Add(midGrid);

            // 底部状态
            var footer = new TextBlock
            {
                Text = "⏱ 自动刷新间隔 5 秒",
                Foreground = Brushes.Gray,
                FontSize = 11,
                Margin = new Thickness(0, 6, 0, 0)
            };
            Grid.SetRow(footer, 2);
            grid.Children.Add(footer);

            return grid;
        }

        private static FrameworkElementFactory MakeListCell(string bindingPath)
        {
            var tb = new FrameworkElementFactory(typeof(TextBlock));
            tb.SetValue(TextBlock.TextProperty, new Binding(bindingPath));
            tb.SetValue(TextBlock.MarginProperty, new Thickness(4, 2, 4, 2));
            tb.SetValue(TextBlock.VerticalAlignmentProperty, VerticalAlignment.Center);
            return tb;
        }

        private Border BuildKpiCard(string title, string value, string colorHex, out TextBlock valueText)
        {
            var border = new Border
            {
                Background = Brushes.White,
                BorderBrush = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#BDC3C7")),
                BorderThickness = new Thickness(1),
                CornerRadius = new CornerRadius(4),
                Padding = new Thickness(15, 10, 15, 10),
                Margin = new Thickness(0, 0, 10, 0),
                Width = 220
            };
            var sp = new StackPanel();
            sp.Children.Add(new TextBlock
            {
                Text = title,
                Foreground = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#7F8C8D")),
                FontSize = 12
            });
            valueText = new TextBlock
            {
                Text = value,
                FontSize = 28,
                FontWeight = FontWeights.Bold,
                Foreground = new SolidColorBrush((Color)ColorConverter.ConvertFromString(colorHex)),
                Margin = new Thickness(0, 4, 0, 0)
            };
            sp.Children.Add(valueText);
            border.Child = sp;
            return border;
        }

        private void EventStreamList_MouseDoubleClick(object sender, MouseButtonEventArgs e)
        {
            if (_eventStreamList.SelectedItem is EventStreamRow row && !string.IsNullOrEmpty(row.PluginId))
            {
                // 简单跳转：在 健康监控 tab 中高亮该插件（切换到 Tab 3）
                if (_healthRankingGrid != null)
                {
                    _healthRankingGrid.Items.Refresh();
                    // 选中匹配的行
                    foreach (var item in _healthRankingGrid.Items)
                    {
                        if (item is HealthRow hr && hr.PluginId == row.PluginId)
                        {
                            _healthRankingGrid.SelectedItem = hr;
                            _healthRankingGrid.ScrollIntoView(hr);
                            break;
                        }
                    }
                }
                MessageBox.Show($"已在「健康监控」Tab 中定位插件: {row.PluginId}", "跳转", MessageBoxButton.OK, MessageBoxImage.Information);
            }
        }

        private async Task ReloadRuntimeDashboardAsync()
        {
            try
            {
                // ===== KPI =====
                var snaps = _governor.Health.GetAllSnapshots();
                var avg = snaps.Count > 0 ? (int)snaps.Average(s => s.HealthScore) : 100;
                if (_kpiHealthText != null) _kpiHealthText.Text = avg.ToString();

                var pending = _governor.VersionManager.PendingUpdates.Count;
                if (_kpiPendingText != null) _kpiPendingText.Text = pending.ToString();

                var isolated = _governor.Health.GetQuarantined().Count;
                if (_kpiIsolatedText != null) _kpiIsolatedText.Text = isolated.ToString();

                var tasksEnabled = _governor.Scheduler.Tasks.Count(t => t.Enabled);
                if (_kpiTasksText != null) _kpiTasksText.Text = tasksEnabled.ToString();

                // ===== Top 5 健康度柱状图 =====
                DrawHealthBarChart(snaps.OrderByDescending(s => s.HealthScore).Take(5).ToList());

                // ===== 事件流 =====
                var today = DateTime.Today;
                var entries = _governor.Security.GetAuditEntries(today);
                var filtered = entries
                    .Where(e =>
                        e.Action == "Quarantined" ||
                        e.Action == "MemoryLimitExceeded" ||
                        e.Action == "PluginBlocked" ||
                        e.Action == "DangerousOpBlocked" ||
                        e.Action == "SignatureFailed" ||
                        e.Action.StartsWith("Permission") ||
                        e.Result == "Blocked" || e.Result == "Failed")
                    .OrderByDescending(e => e.Timestamp)
                    .Take(100)
                    .Select(e => new EventStreamRow
                    {
                        Timestamp = e.Timestamp,
                        TimeText = e.Timestamp.ToString("HH:mm:ss"),
                        PluginId = e.PluginId,
                        Action = e.Action,
                        Result = e.Result,
                        Detail = e.Detail ?? "",
                        SeverityText = e.Result == "Blocked" || e.Result == "Failed" ? "⚠ 异常" : "ℹ 信息"
                    })
                    .ToList();

                _eventStream.Clear();
                foreach (var item in filtered) _eventStream.Add(item);
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"[PluginGovernorWindow] 加载运行时大屏失败: {ex.Message}");
            }
            await Task.CompletedTask;
        }

        private void DrawHealthBarChart(List<PluginHealthSnapshot> top5)
        {
            if (_healthBarCanvas == null) return;
            _healthBarCanvas.Children.Clear();

            const double leftPad = 130;
            const double topPad = 10;
            const double barHeight = 28;
            const double barGap = 14;
            const double maxBarWidth = 320;

            // 坐标轴/标题背景
            if (top5.Count == 0)
            {
                var empty = new TextBlock
                {
                    Text = "暂无插件健康度数据",
                    Foreground = Brushes.Gray,
                    FontSize = 12
                };
                Canvas.SetLeft(empty, 20);
                Canvas.SetTop(empty, 100);
                _healthBarCanvas.Children.Add(empty);
                return;
            }

            for (int i = 0; i < top5.Count; i++)
            {
                var snap = top5[i];
                double y = topPad + i * (barHeight + barGap);

                // 名称
                var nameText = new TextBlock
                {
                    Text = Truncate(snap.PluginId, 18),
                    FontSize = 12,
                    Foreground = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#2C3E50")),
                    Width = leftPad - 10,
                    TextAlignment = TextAlignment.Right,
                    VerticalAlignment = VerticalAlignment.Center
                };
                Canvas.SetLeft(nameText, 0);
                Canvas.SetTop(nameText, y + 5);
                _healthBarCanvas.Children.Add(nameText);

                // 柱子
                double width = Math.Max(2, maxBarWidth * snap.HealthScore / 100.0);
                var barColor = snap.HealthScore switch
                {
                    >= 80 => "#27AE60",
                    >= 60 => "#F39C12",
                    _ => "#E74C3C"
                };
                var rect = new Rectangle
                {
                    Width = width,
                    Height = barHeight,
                    Fill = new SolidColorBrush((Color)ColorConverter.ConvertFromString(barColor)),
                    RadiusX = 2,
                    RadiusY = 2,
                    Stroke = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#7F8C8D")),
                    StrokeThickness = 0.5
                };
                Canvas.SetLeft(rect, leftPad);
                Canvas.SetTop(rect, y);
                _healthBarCanvas.Children.Add(rect);

                // 数值标签
                var scoreText = new TextBlock
                {
                    Text = snap.HealthScore.ToString(),
                    FontWeight = FontWeights.Bold,
                    Foreground = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#2C3E50")),
                    FontSize = 12
                };
                Canvas.SetLeft(scoreText, leftPad + width + 6);
                Canvas.SetTop(scoreText, y + 5);
                _healthBarCanvas.Children.Add(scoreText);
            }
        }

        private static string Truncate(string s, int max)
        {
            if (string.IsNullOrEmpty(s)) return "";
            return s.Length <= max ? s : s.Substring(0, max - 1) + "…";
        }

        // ---------------- Tab 6: 权限审批（v7） ----------------
        private UIElement BuildPermissionApprovalTab()
        {
            var grid = new Grid { Margin = new Thickness(8) };
            grid.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
            grid.RowDefinitions.Add(new RowDefinition { Height = new GridLength(1, GridUnitType.Star) });

            var header = new StackPanel { Orientation = Orientation.Horizontal, Margin = new Thickness(0, 0, 0, 8) };
            _permissionRequestSummary = new TextBlock
            {
                Text = "待审批权限申请: 0",
                FontWeight = FontWeights.Bold,
                Foreground = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#2C3E50")),
                VerticalAlignment = VerticalAlignment.Center,
                Margin = new Thickness(0, 0, 15, 0)
            };
            header.Children.Add(_permissionRequestSummary);
            var refreshBtn = new Button
            {
                Content = "🔄 刷新",
                Width = 90,
                Height = 28,
                Cursor = Cursors.Hand
            };
            refreshBtn.Click += async (s, e) => await ReloadPermissionApprovalTabAsync();
            header.Children.Add(refreshBtn);
            Grid.SetRow(header, 0);
            grid.Children.Add(header);

            _permissionRequestGrid = new DataGrid
            {
                AutoGenerateColumns = false,
                IsReadOnly = true,
                RowHeight = 32,
                HeadersVisibility = DataGridHeadersVisibility.Column,
                GridLinesVisibility = DataGridGridLinesVisibility.Horizontal,
                ItemsSource = _permissionRequests
            };
            _permissionRequestGrid.Columns.Add(new DataGridTextColumn { Header = "PluginId", Binding = new Binding("PluginId"), Width = new DataGridLength(180) });
            _permissionRequestGrid.Columns.Add(new DataGridTextColumn { Header = "Permission", Binding = new Binding("Permission"), Width = new DataGridLength(180) });
            _permissionRequestGrid.Columns.Add(new DataGridTextColumn { Header = "Reason", Binding = new Binding("Reason"), Width = new DataGridLength(1, DataGridLengthUnitType.Star) });
            _permissionRequestGrid.Columns.Add(new DataGridTextColumn { Header = "RequestedAt", Binding = new Binding("RequestedAtText"), Width = new DataGridLength(160) });

            var actCol = new DataGridTemplateColumn { Header = "操作", Width = new DataGridLength(180) };
            var actFactory = new FrameworkElementFactory(typeof(StackPanel));
            actFactory.SetValue(StackPanel.OrientationProperty, Orientation.Horizontal);

            var approveBtn = new FrameworkElementFactory(typeof(Button));
            approveBtn.SetValue(Button.ContentProperty, "通过");
            approveBtn.SetValue(Button.WidthProperty, 70.0);
            approveBtn.SetValue(Button.HeightProperty, 24.0);
            approveBtn.SetValue(Button.MarginProperty, new Thickness(2));
            approveBtn.SetValue(Button.BackgroundProperty, new SolidColorBrush((Color)ColorConverter.ConvertFromString("#27AE60")));
            approveBtn.SetValue(Button.ForegroundProperty, Brushes.White);
            approveBtn.SetValue(Button.BorderThicknessProperty, new Thickness(0));
            approveBtn.SetValue(Button.CursorProperty, Cursors.Hand);
            approveBtn.SetValue(Button.TagProperty, "approve");
            approveBtn.AddHandler(Button.ClickEvent, new RoutedEventHandler(PermissionDecisionBtn_Click));
            actFactory.AppendChild(approveBtn);

            var rejectBtn = new FrameworkElementFactory(typeof(Button));
            rejectBtn.SetValue(Button.ContentProperty, "拒绝");
            rejectBtn.SetValue(Button.WidthProperty, 70.0);
            rejectBtn.SetValue(Button.HeightProperty, 24.0);
            rejectBtn.SetValue(Button.MarginProperty, new Thickness(2));
            rejectBtn.SetValue(Button.BackgroundProperty, new SolidColorBrush((Color)ColorConverter.ConvertFromString("#E74C3C")));
            rejectBtn.SetValue(Button.ForegroundProperty, Brushes.White);
            rejectBtn.SetValue(Button.BorderThicknessProperty, new Thickness(0));
            rejectBtn.SetValue(Button.CursorProperty, Cursors.Hand);
            rejectBtn.SetValue(Button.TagProperty, "reject");
            rejectBtn.AddHandler(Button.ClickEvent, new RoutedEventHandler(PermissionDecisionBtn_Click));
            actFactory.AppendChild(rejectBtn);

            actCol.CellTemplate = new DataTemplate { VisualTree = actFactory };
            _permissionRequestGrid.Columns.Add(actCol);
            Grid.SetRow(_permissionRequestGrid, 1);
            grid.Children.Add(_permissionRequestGrid);

            return grid;
        }

        private async void PermissionDecisionBtn_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                if (sender is not Button btn) return;
                if (btn.DataContext is not PermissionRequestRow row) return;

                var isApprove = (btn.Tag as string) == "approve";
                var req = _governor.PermissionRequest.GetAll().FirstOrDefault(r => r.Id == row.Id);
                if (req == null)
                {
                    MessageBox.Show("该申请已被处理或不存在。", "提示", MessageBoxButton.OK, MessageBoxImage.Information);
                    await ReloadPermissionApprovalTabAsync();
                    return;
                }

                var dialog = new PermissionRequestDialog(req) { Owner = this };
                if (dialog.ShowDialog() != true) return;

                var op = SessionContext.Instance.Current?.Username ?? "admin";
                var note = dialog.OperatorNote ?? "";
                if (isApprove)
                {
                    await _governor.PermissionRequest.ApproveAsync(req.Id, op, note);
                }
                else
                {
                    await _governor.PermissionRequest.RejectAsync(req.Id, op, note);
                }
                MessageBox.Show(isApprove ? "已通过" : "已拒绝", "完成", MessageBoxButton.OK, MessageBoxImage.Information);
                await ReloadPermissionApprovalTabAsync();
            }
            catch (Exception ex)
            {
                MessageBox.Show($"处理失败: {ex.Message}", "错误", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        private async Task ReloadPermissionApprovalTabAsync()
        {
            try
            {
                var pending = _governor.PermissionRequest.GetPending();
                _permissionRequests.Clear();
                foreach (var r in pending)
                {
                    _permissionRequests.Add(new PermissionRequestRow
                    {
                        Id = r.Id,
                        PluginId = r.PluginId,
                        Permission = r.Permission,
                        Reason = r.Reason,
                        RequestedAt = r.RequestedAt,
                        RequestedAtText = r.RequestedAt.ToString("yyyy-MM-dd HH:mm:ss")
                    });
                }
                if (_permissionRequestSummary != null)
                {
                    _permissionRequestSummary.Text = $"待审批权限申请: {pending.Count}";
                }
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"[PluginGovernorWindow] 加载权限申请失败: {ex.Message}");
            }
            await Task.CompletedTask;
        }

        // ---------------- Tab 7: 告警模板（v7） ----------------
        private UIElement BuildAlertTemplateTab()
        {
            var grid = new Grid { Margin = new Thickness(8) };
            grid.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
            grid.RowDefinitions.Add(new RowDefinition { Height = new GridLength(1, GridUnitType.Star) });

            var header = new TextBlock
            {
                Text = "🎯 内置告警模板（一键启用即可创建对应告警规则）",
                FontWeight = FontWeights.Bold,
                FontSize = 14,
                Foreground = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#2C3E50")),
                Margin = new Thickness(0, 0, 0, 10)
            };
            Grid.SetRow(header, 0);
            grid.Children.Add(header);

            var scroll = new ScrollViewer
            {
                VerticalScrollBarVisibility = ScrollBarVisibility.Auto,
                HorizontalScrollBarVisibility = ScrollBarVisibility.Disabled
            };
            _alertTemplateItems = new ItemsControl { ItemsSource = null };
            _alertTemplateItems.ItemsPanel = new ItemsPanelTemplate(new FrameworkElementFactory(typeof(WrapPanel)));
            _alertTemplateItems.ItemTemplate = CreateAlertTemplateItemTemplate();
            scroll.Content = _alertTemplateItems;
            Grid.SetRow(scroll, 1);
            grid.Children.Add(scroll);

            return grid;
        }

        private DataTemplate CreateAlertTemplateItemTemplate()
        {
            var border = new FrameworkElementFactory(typeof(Border));
            border.SetValue(Border.WidthProperty, 280.0);
            border.SetValue(Border.HeightProperty, 180.0);
            border.SetValue(Border.MarginProperty, new Thickness(0, 0, 10, 10));
            border.SetValue(Border.CornerRadiusProperty, new CornerRadius(6));
            border.SetValue(Border.BorderBrushProperty, new SolidColorBrush((Color)ColorConverter.ConvertFromString("#BDC3C7")));
            border.SetValue(Border.BorderThicknessProperty, new Thickness(1));
            border.SetValue(Border.BackgroundProperty, Brushes.White);
            border.SetValue(Border.PaddingProperty, new Thickness(12));

            var sp = new FrameworkElementFactory(typeof(StackPanel));

            // 第一行：图标 + 名称
            var titlePanel = new FrameworkElementFactory(typeof(StackPanel));
            titlePanel.SetValue(StackPanel.OrientationProperty, Orientation.Horizontal);
            var icon = new FrameworkElementFactory(typeof(TextBlock));
            icon.SetValue(TextBlock.TextProperty, new Binding("Icon"));
            icon.SetValue(TextBlock.FontSizeProperty, 22.0);
            icon.SetValue(TextBlock.VerticalAlignmentProperty, VerticalAlignment.Center);
            titlePanel.AppendChild(icon);
            var name = new FrameworkElementFactory(typeof(TextBlock));
            name.SetValue(TextBlock.TextProperty, new Binding("Name"));
            name.SetValue(TextBlock.FontWeightProperty, FontWeights.Bold);
            name.SetValue(TextBlock.FontSizeProperty, 14.0);
            name.SetValue(TextBlock.MarginProperty, new Thickness(8, 0, 0, 0));
            name.SetValue(TextBlock.ForegroundProperty, new SolidColorBrush((Color)ColorConverter.ConvertFromString("#2C3E50")));
            name.SetValue(TextBlock.VerticalAlignmentProperty, VerticalAlignment.Center);
            titlePanel.AppendChild(name);
            sp.AppendChild(titlePanel);

            // 描述
            var desc = new FrameworkElementFactory(typeof(TextBlock));
            desc.SetValue(TextBlock.TextProperty, new Binding("Description"));
            desc.SetValue(TextBlock.TextWrappingProperty, TextWrapping.Wrap);
            desc.SetValue(TextBlock.MarginProperty, new Thickness(0, 8, 0, 0));
            desc.SetValue(TextBlock.ForegroundProperty, new SolidColorBrush((Color)ColorConverter.ConvertFromString("#34495E")));
            desc.SetValue(TextBlock.FontSizeProperty, 12.0);
            sp.AppendChild(desc);

            // 推荐渠道
            var ch = new FrameworkElementFactory(typeof(TextBlock));
            ch.SetValue(TextBlock.TextProperty, new Binding("ChannelsText"));
            ch.SetValue(TextBlock.MarginProperty, new Thickness(0, 6, 0, 0));
            ch.SetValue(TextBlock.ForegroundProperty, new SolidColorBrush((Color)ColorConverter.ConvertFromString("#7F8C8D")));
            ch.SetValue(TextBlock.FontSizeProperty, 11.0);
            ch.SetValue(TextBlock.TextWrappingProperty, TextWrapping.Wrap);
            sp.AppendChild(ch);

            // 启用按钮
            var btn = new FrameworkElementFactory(typeof(Button));
            btn.SetValue(Button.ContentProperty, new Binding("ButtonText"));
            btn.SetValue(Button.WidthProperty, 240.0);
            btn.SetValue(Button.HeightProperty, 28.0);
            btn.SetValue(Button.MarginProperty, new Thickness(0, 10, 0, 0));
            btn.SetValue(Button.BorderThicknessProperty, new Thickness(0));
            btn.SetValue(Button.CursorProperty, Cursors.Hand);
            btn.SetValue(Button.BackgroundProperty, new SolidColorBrush((Color)ColorConverter.ConvertFromString("#3498DB")));
            btn.SetValue(Button.ForegroundProperty, Brushes.White);
            btn.SetValue(Button.TagProperty, new Binding("Id"));
            btn.AddHandler(Button.ClickEvent, new RoutedEventHandler(EnableAlertTemplateBtn_Click));
            sp.AppendChild(btn);

            border.AppendChild(sp);
            return new DataTemplate { VisualTree = border };
        }

        private async void EnableAlertTemplateBtn_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                if (sender is not Button btn) return;
                var templateId = btn.Tag as string;
                if (string.IsNullOrEmpty(templateId)) return;

                var op = SessionContext.Instance.Current?.Username ?? "admin";
                var rule = _governor.AlertTemplate.EnableTemplate(templateId, op);
                _templateEnabledCache[templateId] = true;

                MessageBox.Show($"已根据模板 [{rule.Name}] 创建告警规则（阈值={rule.Threshold}）", "启用成功", MessageBoxButton.OK, MessageBoxImage.Information);
                await ReloadAlertTemplateTabAsync();
                await ReloadSchedulerTabAsync();
            }
            catch (Exception ex)
            {
                MessageBox.Show($"启用失败: {ex.Message}", "错误", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        private async Task ReloadAlertTemplateTabAsync()
        {
            try
            {
                var templates = _governor.AlertTemplate.ListTemplates();
                var existingRuleTemplateIds = new HashSet<string>(
                    _governor.Scheduler.AlertRules
                        .Where(r => !string.IsNullOrEmpty(r.TemplateId))
                        .Select(r => r.TemplateId!)
                );
                var view = templates.Select(t => new AlertTemplateCard
                {
                    Id = t.Id,
                    Name = t.Name,
                    Description = t.Description,
                    Icon = t.Icon,
                    ChannelsText = "推荐渠道: " + string.Join(" · ", t.RecommendedChannels),
                    IsEnabled = existingRuleTemplateIds.Contains(t.Id) || _templateEnabledCache.ContainsKey(t.Id),
                    ButtonText = (existingRuleTemplateIds.Contains(t.Id) || _templateEnabledCache.ContainsKey(t.Id)) ? "✅ 已启用" : "启用"
                }).ToList();
                if (_alertTemplateItems != null) _alertTemplateItems.ItemsSource = view;
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"[PluginGovernorWindow] 加载告警模板失败: {ex.Message}");
            }
            await Task.CompletedTask;
        }

        // ================ 按钮回调 ================
        private async void SavePolicyButton_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                var policy = _governor.Security.CurrentPolicy;
                policy.Whitelist = ((List<string>?)_whitelistGrid.ItemsSource) ?? new List<string>();
                policy.Blacklist = ((List<string>?)_blacklistGrid.ItemsSource) ?? new List<string>();
                policy.DangerousOpBlockList = string.IsNullOrWhiteSpace(_dangerousOpsTextBox.Text)
                    ? new List<string>()
                    : _dangerousOpsTextBox.Text.Split(',').Select(s => s.Trim()).Where(s => !string.IsNullOrEmpty(s)).ToList();

                var permRows = (_permissionMatrixGrid.ItemsSource as IEnumerable<PermissionRow>)?.ToList() ?? new List<PermissionRow>();
                var matrix = new Dictionary<string, List<string>>();
                foreach (var r in permRows)
                {
                    if (string.IsNullOrWhiteSpace(r.PluginId)) continue;
                    matrix[r.PluginId] = string.IsNullOrWhiteSpace(r.PermissionsText)
                        ? new List<string>()
                        : r.PermissionsText.Split(',').Select(s => s.Trim()).Where(s => !string.IsNullOrEmpty(s)).ToList();
                }
                policy.PermissionMatrix = matrix;

                var op = SessionContext.Instance.Current?.Username ?? "admin";
                await _governor.Security.SavePolicyAsync(policy, op);
                _policyModifiedText.Text = $"最后修改: {DateTime.Now:yyyy-MM-dd HH:mm:ss} by {op}";
                MessageBox.Show("策略已保存并立即生效！", "成功", MessageBoxButton.OK, MessageBoxImage.Information);
                await ReloadSecurityTabAsync();
            }
            catch (Exception ex)
            {
                MessageBox.Show($"保存失败: {ex.Message}", "错误", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        private void AddTaskButton_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                var task = new ScheduledTask
                {
                    Name = $"新任务-{DateTime.Now:HHmmss}",
                    CronExpression = "0 2 * * *",
                    TargetIp = "127.0.0.1",
                    Ports = new List<int> { 80, 443 },
                    PluginIds = new List<string>(),
                    MaxRetries = 3,
                    Enabled = true
                };

                // 弹窗编辑
                var dialog = BuildTaskEditDialog(task, isNew: true);
                if (dialog.ShowDialog() == true)
                {
                    _governor.Scheduler.AddTask(task);
                    _ = ReloadSchedulerTabAsync();
                }
            }
            catch (Exception ex)
            {
                MessageBox.Show($"新建任务失败: {ex.Message}", "错误", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        private void RemoveTaskButton_Click(object sender, RoutedEventArgs e)
        {
            if (_tasksGrid.SelectedItem is TaskRow row)
            {
                if (MessageBox.Show($"确定删除任务 {row.Name} 吗？", "确认", MessageBoxButton.YesNo, MessageBoxImage.Question) == MessageBoxResult.Yes)
                {
                    _governor.Scheduler.RemoveTask(row.Id);
                    _ = ReloadSchedulerTabAsync();
                }
            }
        }

        private void AddAlertButton_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                var rule = new AlertRule
                {
                    Name = $"新告警-{DateTime.Now:HHmmss}",
                    Type = AlertType.ConsecutiveFailure,
                    Threshold = 3,
                    TimeWindowMinutes = 5,
                    NotificationChannels = new List<string> { "Log" },
                    Enabled = true
                };
                _governor.Scheduler.AddOrUpdateAlertRule(rule);
                _ = ReloadSchedulerTabAsync();
            }
            catch (Exception ex)
            {
                MessageBox.Show($"新建告警规则失败: {ex.Message}", "错误", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        private void RemoveAlertButton_Click(object sender, RoutedEventArgs e)
        {
            if (_alertRulesGrid.SelectedItem is AlertRow row)
            {
                if (MessageBox.Show($"确定删除告警规则 {row.Name} 吗？", "确认", MessageBoxButton.YesNo, MessageBoxImage.Question) == MessageBoxResult.Yes)
                {
                    _governor.Scheduler.RemoveAlertRule(row.Id);
                    _ = ReloadSchedulerTabAsync();
                }
            }
        }

        private Window BuildTaskEditDialog(ScheduledTask task, bool isNew)
        {
            var dialog = new Window
            {
                Title = isNew ? "新建定时任务" : "编辑定时任务",
                Width = 460,
                Height = 380,
                WindowStartupLocation = WindowStartupLocation.CenterOwner,
                Owner = this,
                ResizeMode = ResizeMode.NoResize
            };

            var grid = new Grid { Margin = new Thickness(20) };
            grid.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
            grid.RowDefinitions.Add(new RowDefinition { Height = new GridLength(1, GridUnitType.Star) });
            grid.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });

            var form = new StackPanel();
            var nameBox = new TextBox { Text = task.Name, Margin = new Thickness(0, 2, 0, 8) };
            form.Children.Add(new TextBlock { Text = "任务名称" }); form.Children.Add(nameBox);
            var cronBox = new TextBox { Text = task.CronExpression, Margin = new Thickness(0, 2, 0, 8) };
            form.Children.Add(new TextBlock { Text = "Cron 表达式（5 段: 分 时 日 月 周）" }); form.Children.Add(cronBox);
            var ipBox = new TextBox { Text = task.TargetIp, Margin = new Thickness(0, 2, 0, 8) };
            form.Children.Add(new TextBlock { Text = "目标 IP" }); form.Children.Add(ipBox);
            var portsBox = new TextBox { Text = string.Join(",", task.Ports), Margin = new Thickness(0, 2, 0, 8) };
            form.Children.Add(new TextBlock { Text = "端口（逗号分隔）" }); form.Children.Add(portsBox);
            var retryBox = new TextBox { Text = task.MaxRetries.ToString(), Margin = new Thickness(0, 2, 0, 8) };
            form.Children.Add(new TextBlock { Text = "最大重试次数（0-5）" }); form.Children.Add(retryBox);
            var enableBox = new CheckBox { Content = "启用", IsChecked = task.Enabled, Margin = new Thickness(0, 4, 0, 0) };
            form.Children.Add(enableBox);

            var scroll = new ScrollViewer { Content = form, VerticalScrollBarVisibility = ScrollBarVisibility.Auto };
            Grid.SetRow(scroll, 1);
            grid.Children.Add(scroll);

            var btns = new StackPanel { Orientation = Orientation.Horizontal, HorizontalAlignment = HorizontalAlignment.Right, Margin = new Thickness(0, 12, 0, 0) };
            var okBtn = new Button { Content = "保存", Width = 80, Height = 30, Margin = new Thickness(0, 0, 5, 0), Background = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#27AE60")), Foreground = Brushes.White, BorderThickness = new Thickness(0) };
            var cancelBtn = new Button { Content = "取消", Width = 80, Height = 30 };
            okBtn.Click += (s, e) =>
            {
                task.Name = nameBox.Text.Trim();
                task.CronExpression = cronBox.Text.Trim();
                task.TargetIp = ipBox.Text.Trim();
                task.Ports = string.IsNullOrWhiteSpace(portsBox.Text)
                    ? new List<int>()
                    : portsBox.Text.Split(',').Select(p => int.TryParse(p.Trim(), out var n) ? n : 0).Where(n => n > 0 && n <= 65535).ToList();
                task.MaxRetries = int.TryParse(retryBox.Text, out var r) ? Math.Clamp(r, 0, 5) : 0;
                task.Enabled = enableBox.IsChecked == true;
                dialog.DialogResult = true;
                dialog.Close();
            };
            cancelBtn.Click += (s, e) => dialog.Close();
            btns.Children.Add(okBtn);
            btns.Children.Add(cancelBtn);
            Grid.SetRow(btns, 2);
            grid.Children.Add(btns);

            dialog.Content = grid;
            return dialog;
        }
    }

    // ====== 行模型（供 DataGrid 绑定）======
    public class PermissionRow
    {
        public string PluginId { get; set; } = "";
        public string PermissionsText { get; set; } = "";
    }

    public class VersionRow
    {
        public string PluginId { get; set; } = "";
        public string LocalVersion { get; set; } = "";
        public string RemoteVersion { get; set; } = "";
        public string StatusText { get; set; } = "";
        public string MinCoreVersion { get; set; } = "";
    }

    public class BackupRecordInfo
    {
        public string PluginId { get; set; } = "";
        public string Version { get; set; } = "";
        public string Action { get; set; } = "";
        public DateTime Timestamp { get; set; }
    }

    public class HealthRow
    {
        public string PluginId { get; set; } = "";
        public int HealthScore { get; set; }
        public int TotalExecutions { get; set; }
        public int TotalFailures { get; set; }
        public int TotalTimeouts { get; set; }
        public string PeakMemoryText { get; set; } = "";
        public long TotalElapsedMs { get; set; }
        public string StatusText { get; set; } = "";
    }

    public class TaskRow
    {
        public string Id { get; set; } = "";
        public string Name { get; set; } = "";
        public string CronExpression { get; set; } = "";
        public string TargetIp { get; set; } = "";
        public string PortsText { get; set; } = "";
        public int TotalRuns { get; set; }
        public int TotalFailures { get; set; }
        public string EnabledText { get; set; } = "";
    }

    public class AlertRow
    {
        public string Id { get; set; } = "";
        public string Name { get; set; } = "";
        public string TypeText { get; set; } = "";
        public int Threshold { get; set; }
        public int TimeWindowMinutes { get; set; }
        public string ChannelsText { get; set; } = "";
        public string EnabledText { get; set; } = "";
    }

    // ====== Tab 5 行模型：事件流 ======
    public class EventStreamRow
    {
        public DateTime Timestamp { get; set; }
        public string TimeText { get; set; } = "";
        public string SeverityText { get; set; } = "";
        public string PluginId { get; set; } = "";
        public string Action { get; set; } = "";
        public string Result { get; set; } = "";
        public string Detail { get; set; } = "";
    }

    // ====== Tab 6 行模型：权限申请 ======
    public class PermissionRequestRow
    {
        public string Id { get; set; } = "";
        public string PluginId { get; set; } = "";
        public string Permission { get; set; } = "";
        public string Reason { get; set; } = "";
        public DateTime RequestedAt { get; set; }
        public string RequestedAtText { get; set; } = "";
    }

    // ====== Tab 7 行模型：告警模板卡片 ======
    public class AlertTemplateCard
    {
        public string Id { get; set; } = "";
        public string Name { get; set; } = "";
        public string Description { get; set; } = "";
        public string Icon { get; set; } = "🔔";
        public string ChannelsText { get; set; } = "";
        public bool IsEnabled { get; set; }
        public string ButtonText { get; set; } = "启用";
    }
}
