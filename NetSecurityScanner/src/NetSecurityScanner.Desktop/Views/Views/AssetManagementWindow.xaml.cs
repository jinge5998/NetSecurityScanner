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
    public partial class AssetManagementWindow : Window
    {
        private readonly AssetManagementService _assetService;
        private readonly AuthService _authService;

        public AssetManagementWindow()
        {
            InitializeComponent();
            _assetService = new AssetManagementService();
            _authService = new AuthService();
            Loaded += AssetManagementWindow_Loaded;
            // 订阅会话变化，登录/登出后立即刷新按钮可用性
            SessionContext.Instance.Changed += (_, _) => RefreshUiByPermission();
        }

        private async void AssetManagementWindow_Loaded(object sender, RoutedEventArgs e)
        {
            // 先按当前会话刷新一次
            RefreshUiByPermission();

            // 未登录时强制弹登录窗口；登录成功才进入，否则关闭
            if (SessionContext.Instance.Current == null)
            {
                var login = new LoginWindow { Owner = this };
                var ok = login.ShowDialog();
                if (ok != true)
                {
                    Close();
                    return;
                }
            }

            // 登录后再次校验是否有 Asset:View 权限
            var current = SessionContext.Instance.Current;
            if (current == null ||
                (!current.IsAdmin &&
                 (current.Permissions == null || !current.Permissions.Contains(Permission.AssetView))))
            {
                MessageBox.Show("无资产管理查看权限", "权限不足", MessageBoxButton.OK, MessageBoxImage.Warning);
                Close();
                return;
            }

            RefreshUiByPermission();
            await RefreshAssetsAsync();
        }

        /// <summary>
        /// 按当前会话的权限刷新所有工具栏/状态栏按钮可用性、角色徽章、用户名显示。
        /// </summary>
        private void RefreshUiByPermission()
        {
            var current = SessionContext.Instance.Current;

            // 顶部状态栏
            if (current == null)
            {
                RoleBadgeText.Text = "🔒 未登录";
                RoleBadgeText.Foreground = (Brush)new BrushConverter().ConvertFromString("#636e72")!;
                CurrentUserText.Text = "请先登录";
                LoginLogoutButton.Content = "🔑 登录";
            }
            else
            {
                var display = string.IsNullOrWhiteSpace(current.DisplayName) ? current.Username : current.DisplayName;
                if (current.IsAdmin)
                {
                    RoleBadgeText.Text = "👑 管理员";
                    RoleBadgeText.Foreground = (Brush)new BrushConverter().ConvertFromString("#e17055")!;
                }
                else
                {
                    var perms = current.Permissions ?? new List<string>();
                    if (perms.Contains(Permission.AssetDelete) || perms.Contains(Permission.AssetImport))
                    {
                        RoleBadgeText.Text = "🛠 操作员";
                        RoleBadgeText.Foreground = (Brush)new BrushConverter().ConvertFromString("#0984e3")!;
                    }
                    else if (perms.Contains(Permission.AssetAdd) || perms.Contains(Permission.AssetEdit))
                    {
                        RoleBadgeText.Text = "🛠 操作员";
                        RoleBadgeText.Foreground = (Brush)new BrushConverter().ConvertFromString("#0984e3")!;
                    }
                    else
                    {
                        RoleBadgeText.Text = "👁 查看者";
                        RoleBadgeText.Foreground = (Brush)new BrushConverter().ConvertFromString("#636e72")!;
                    }
                }
                CurrentUserText.Text = display;
                LoginLogoutButton.Content = "🚪 登出";
            }

            // 工具栏权限联动
            bool loggedIn = current != null;
            bool isAdmin = loggedIn && current!.IsAdmin;
            var permissions = current?.Permissions ?? new List<string>();
            bool Has(string p) => isAdmin || (permissions != null && permissions.Contains(p));

            AddAssetButton.IsEnabled = Has(Permission.AssetAdd);
            EditAssetButton.IsEnabled = Has(Permission.AssetEdit);
            DeleteAssetButton.IsEnabled = Has(Permission.AssetDelete);
            ImportButton.IsEnabled = Has(Permission.AssetImport);
            ExportButton.IsEnabled = Has(Permission.AssetView);
            SearchButton.IsEnabled = Has(Permission.AssetView);
            RefreshButton.IsEnabled = Has(Permission.AssetView);
            AssetTypeFilter.IsEnabled = Has(Permission.AssetView);
            AssetStatusFilter.IsEnabled = Has(Permission.AssetView);
            SearchTextBox.IsEnabled = Has(Permission.AssetView);
            ViewChangeLogButton.IsEnabled = Has(Permission.AssetView);

            // 权限不足时给禁用按钮加上 ToolTip 提示
            string toolTip = loggedIn ? "权限不足" : "请先登录";
            if (!AddAssetButton.IsEnabled) AddAssetButton.ToolTip = toolTip;
            if (!EditAssetButton.IsEnabled) EditAssetButton.ToolTip = toolTip;
            if (!DeleteAssetButton.IsEnabled) DeleteAssetButton.ToolTip = toolTip;
            if (!ImportButton.IsEnabled) ImportButton.ToolTip = toolTip;

            // 选中行按钮联动
            ApplySelectionButtonState();
        }

        private void ApplySelectionButtonState()
        {
            var current = SessionContext.Instance.Current;
            bool loggedIn = current != null;
            bool isAdmin = loggedIn && current!.IsAdmin;
            var permissions = current?.Permissions ?? new List<string>();
            bool hasSelection = AssetsDataGrid.SelectedItem != null;
            bool canEdit = isAdmin || (permissions != null && permissions.Contains(Permission.AssetEdit));
            bool canDelete = isAdmin || (permissions != null && permissions.Contains(Permission.AssetDelete));
            EditAssetButton.IsEnabled = hasSelection && canEdit;
            DeleteAssetButton.IsEnabled = hasSelection && canDelete;
        }

        private async Task RefreshAssetsAsync()
        {
            try
            {
                var assets = ApplyFilters(_assetService.GetAllAssets()).ToList();
                AssetsDataGrid.ItemsSource = assets;
                UpdateStatistics(assets);
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"[AssetManagementWindow] 刷新资产列表失败: {ex.Message}");
            }
        }

        private IEnumerable<Asset> ApplyFilters(IEnumerable<Asset> source)
        {
            var typeTag = (AssetTypeFilter.SelectedItem as ComboBoxItem)?.Tag?.ToString() ?? "";
            var statusTag = (AssetStatusFilter.SelectedItem as ComboBoxItem)?.Tag?.ToString() ?? "";
            IEnumerable<Asset> q = source;
            if (!string.IsNullOrEmpty(typeTag))
                q = q.Where(a => string.Equals(a.AssetType, typeTag, StringComparison.OrdinalIgnoreCase));
            if (!string.IsNullOrEmpty(statusTag) && Enum.TryParse<AssetStatus>(statusTag, out var st))
                q = q.Where(a => a.Status == st);
            return q;
        }

        private void UpdateStatistics(List<Asset> filteredAssets)
        {
            try
            {
                var stats = _assetService.GetStatistics();
                if (TotalAssetsText != null) TotalAssetsText.Text = filteredAssets.Count.ToString();
                if (OnlineAssetsText != null) OnlineAssetsText.Text = filteredAssets.Count(a => a.Status == AssetStatus.Online).ToString();
                if (OfflineAssetsText != null) OfflineAssetsText.Text = filteredAssets.Count(a => a.Status == AssetStatus.Offline).ToString();
                if (MaintenanceAssetsText != null) MaintenanceAssetsText.Text = filteredAssets.Count(a => a.Status == AssetStatus.Maintenance).ToString();

                if (ChangeLogListBox != null)
                    ChangeLogListBox.ItemsSource = stats.RecentChanges.Select(c =>
                        $"{c.ChangedAt:MM-dd HH:mm} - {c.ChangedBy}: {c.NewValue ?? c.OldValue}").ToList();

                RenderTypeDistribution(filteredAssets);
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"[AssetManagementWindow] 更新统计信息失败: {ex.Message}");
            }
        }

        private void RenderTypeDistribution(List<Asset> assets)
        {
            if (TypeDistributionPanel == null) return;
            TypeDistributionPanel.Children.Clear();

            var groups = assets.GroupBy(a => a.AssetType)
                .Select(g => new { Type = string.IsNullOrEmpty(g.Key) ? "未分类" : g.Key, Count = g.Count() })
                .OrderByDescending(g => g.Count)
                .ToList();

            int max = groups.Count > 0 ? groups.Max(g => g.Count) : 1;
            if (max == 0) max = 1;
            int total = assets.Count == 0 ? 1 : assets.Count;

            foreach (var g in groups)
            {
                double pct = (double)g.Count / total * 100.0;
                var row = new StackPanel { Margin = new Thickness(0, 0, 0, 6) };

                var label = new TextBlock
                {
                    Text = $"{g.Type}: {g.Count} ({pct:0.0}%)",
                    FontSize = 11,
                    Margin = new Thickness(0, 0, 0, 2)
                };
                row.Children.Add(label);

                var bar = new ProgressBar
                {
                    Height = 8,
                    Minimum = 0,
                    Maximum = max,
                    Value = g.Count,
                    Foreground = (Brush)new BrushConverter().ConvertFromString("#0984e3")!,
                    Background = (Brush)new BrushConverter().ConvertFromString("#dfe6e9")!,
                    BorderThickness = new Thickness(0)
                };
                row.Children.Add(bar);

                TypeDistributionPanel.Children.Add(row);
            }

            if (groups.Count == 0)
            {
                TypeDistributionPanel.Children.Add(new TextBlock
                {
                    Text = "暂无数据",
                    FontSize = 11,
                    Foreground = (Brush)new BrushConverter().ConvertFromString("#b2bec3")!
                });
            }
        }

        private void AssetsDataGrid_SelectionChanged(object sender, SelectionChangedEventArgs e)
        {
            ApplySelectionButtonState();
        }

        private void AssetsDataGrid_MouseDoubleClick(object sender, MouseButtonEventArgs e)
        {
            if (AssetsDataGrid.SelectedItem is Asset asset)
            {
                var detail = new AssetDetailWindow(asset) { Owner = this };
                detail.ShowDialog();
            }
        }

        private void LoginLogoutButton_Click(object sender, RoutedEventArgs e)
        {
            if (SessionContext.Instance.Current == null)
            {
                var login = new LoginWindow { Owner = this };
                if (login.ShowDialog() == true)
                {
                    RefreshUiByPermission();
                    _ = RefreshAssetsAsync();
                }
            }
            else
            {
                _authService.Logout();
                RefreshUiByPermission();
            }
        }

        private void ViewChangeLogButton_Click(object sender, RoutedEventArgs e)
        {
            var win = new AssetChangeLogWindow { Owner = this };
            win.ShowDialog();
        }

        private async void AddAssetButton_Click(object sender, RoutedEventArgs e)
        {
            var operatorName = SessionContext.Instance.Current?.Username ?? "";
            var dialog = new Window
            {
                Title = "添加资产",
                Width = 450,
                Height = 500,
                WindowStartupLocation = WindowStartupLocation.CenterOwner,
                Owner = this,
                Background = Brushes.White
            };

            var panel = new StackPanel { Margin = new Thickness(20) };

            var fields = new Dictionary<string, TextBox>();
            var comboBoxes = new Dictionary<string, ComboBox>();

            string[] labels = { "名称", "IP地址", "MAC地址", "资产类型", "操作系统", "负责人", "部门", "位置", "描述" };

            foreach (var label in labels)
            {
                panel.Children.Add(new TextBlock { Text = label + ":", FontWeight = FontWeights.Bold, Margin = new Thickness(0, 8, 0, 3) });
                if (label == "资产类型")
                {
                    var combo = new ComboBox { Width = 380, HorizontalAlignment = HorizontalAlignment.Left };
                    combo.Items.Add("Server");
                    combo.Items.Add("Workstation");
                    combo.Items.Add("NetworkDevice");
                    combo.Items.Add("SecurityDevice");
                    combo.Items.Add("Database");
                    combo.Items.Add("Application");
                    combo.Items.Add("Other");
                    combo.SelectedIndex = 0;
                    comboBoxes[label] = combo;
                    panel.Children.Add(combo);
                }
                else if (label == "描述")
                {
                    var tb = new TextBox { Width = 380, Height = 60, TextWrapping = TextWrapping.Wrap, HorizontalAlignment = HorizontalAlignment.Left };
                    fields[label] = tb;
                    panel.Children.Add(tb);
                }
                else
                {
                    var tb = new TextBox { Width = 380, HorizontalAlignment = HorizontalAlignment.Left };
                    fields[label] = tb;
                    panel.Children.Add(tb);
                }
            }

            var btnPanel = new StackPanel { Orientation = Orientation.Horizontal, HorizontalAlignment = HorizontalAlignment.Right, Margin = new Thickness(0, 15, 0, 0) };
            var saveBtn = new Button { Content = "保存", Width = 80, Height = 30, Margin = new Thickness(5, 0, 0, 0), Cursor = Cursors.Hand };
            var cancelBtn = new Button { Content = "取消", Width = 80, Height = 30, Margin = new Thickness(5, 0, 0, 0), Cursor = Cursors.Hand };
            btnPanel.Children.Add(saveBtn);
            btnPanel.Children.Add(cancelBtn);
            panel.Children.Add(btnPanel);

            cancelBtn.Click += (s, ev) => dialog.Close();
            saveBtn.Click += async (s, ev) =>
            {
                var name = fields["名称"].Text.Trim();
                var ip = fields["IP地址"].Text.Trim();

                if (string.IsNullOrWhiteSpace(name) || string.IsNullOrWhiteSpace(ip))
                {
                    MessageBox.Show("名称和IP地址为必填项！", "验证失败", MessageBoxButton.OK, MessageBoxImage.Warning);
                    return;
                }

                var asset = new Asset
                {
                    Name = name,
                    IPAddress = ip,
                    MacAddress = fields["MAC地址"].Text.Trim(),
                    AssetType = comboBoxes["资产类型"].SelectedItem?.ToString() ?? "Other",
                    OperatingSystem = fields["操作系统"].Text.Trim(),
                    Owner = fields["负责人"].Text.Trim(),
                    Department = fields["部门"].Text.Trim(),
                    Location = fields["位置"].Text.Trim(),
                    Status = AssetStatus.Online,
                    Description = fields["描述"].Text.Trim()
                };

                try
                {
                    if (await _assetService.AddAssetAsync(asset, operatorName))
                    {
                        await RefreshAssetsAsync();
                        dialog.Close();
                        MessageBox.Show("资产添加成功！", "成功", MessageBoxButton.OK, MessageBoxImage.Information);
                    }
                    else
                    {
                        MessageBox.Show("资产添加失败，IP地址可能已存在！", "错误", MessageBoxButton.OK, MessageBoxImage.Error);
                    }
                }
                catch (UnauthorizedAccessException ex)
                {
                    MessageBox.Show($"无权限: {ex.Message}", "权限不足", MessageBoxButton.OK, MessageBoxImage.Warning);
                }
            };

            dialog.Content = new ScrollViewer { Content = panel };
            dialog.KeyDown += (s, ev) => { if (ev.Key == Key.Escape) dialog.Close(); };
            dialog.ShowDialog();
        }

        private async void EditAssetButton_Click(object sender, RoutedEventArgs e)
        {
            if (AssetsDataGrid.SelectedItem is not Asset asset) return;

            var operatorName = SessionContext.Instance.Current?.Username ?? "";
            var dialog = new Window
            {
                Title = $"编辑资产 - {asset.Name}",
                Width = 450,
                Height = 500,
                WindowStartupLocation = WindowStartupLocation.CenterOwner,
                Owner = this,
                Background = Brushes.White
            };

            var panel = new StackPanel { Margin = new Thickness(20) };

            var fields = new Dictionary<string, TextBox>();
            var comboBoxes = new Dictionary<string, ComboBox>();

            string[] labels = { "名称", "IP地址", "MAC地址", "资产类型", "操作系统", "负责人", "部门", "位置", "描述" };

            foreach (var label in labels)
            {
                panel.Children.Add(new TextBlock { Text = label + ":", FontWeight = FontWeights.Bold, Margin = new Thickness(0, 8, 0, 3) });
                if (label == "资产类型")
                {
                    var combo = new ComboBox { Width = 380, HorizontalAlignment = HorizontalAlignment.Left };
                    combo.Items.Add("Server");
                    combo.Items.Add("Workstation");
                    combo.Items.Add("NetworkDevice");
                    combo.Items.Add("SecurityDevice");
                    combo.Items.Add("Database");
                    combo.Items.Add("Application");
                    combo.Items.Add("Other");
                    combo.SelectedItem = asset.AssetType;
                    comboBoxes[label] = combo;
                    panel.Children.Add(combo);
                }
                else if (label == "描述")
                {
                    var tb = new TextBox { Width = 380, Height = 60, TextWrapping = TextWrapping.Wrap, HorizontalAlignment = HorizontalAlignment.Left, Text = asset.Description ?? "" };
                    fields[label] = tb;
                    panel.Children.Add(tb);
                }
                else
                {
                    var value = label switch
                    {
                        "名称" => asset.Name,
                        "IP地址" => asset.IPAddress,
                        "MAC地址" => asset.MacAddress ?? "",
                        "操作系统" => asset.OperatingSystem ?? "",
                        "负责人" => asset.Owner ?? "",
                        "部门" => asset.Department ?? "",
                        "位置" => asset.Location ?? "",
                        _ => ""
                    };
                    var tb = new TextBox { Width = 380, HorizontalAlignment = HorizontalAlignment.Left, Text = value };
                    fields[label] = tb;
                    panel.Children.Add(tb);
                }
            }

            var btnPanel = new StackPanel { Orientation = Orientation.Horizontal, HorizontalAlignment = HorizontalAlignment.Right, Margin = new Thickness(0, 15, 0, 0) };
            var saveBtn = new Button { Content = "保存", Width = 80, Height = 30, Margin = new Thickness(5, 0, 0, 0), Cursor = Cursors.Hand };
            var cancelBtn = new Button { Content = "取消", Width = 80, Height = 30, Margin = new Thickness(5, 0, 0, 0), Cursor = Cursors.Hand };
            btnPanel.Children.Add(saveBtn);
            btnPanel.Children.Add(cancelBtn);
            panel.Children.Add(btnPanel);

            cancelBtn.Click += (s, ev) => dialog.Close();
            saveBtn.Click += async (s, ev) =>
            {
                var name = fields["名称"].Text.Trim();
                var ip = fields["IP地址"].Text.Trim();

                if (string.IsNullOrWhiteSpace(name) || string.IsNullOrWhiteSpace(ip))
                {
                    MessageBox.Show("名称和IP地址为必填项！", "验证失败", MessageBoxButton.OK, MessageBoxImage.Warning);
                    return;
                }

                var updatedAsset = new Asset
                {
                    Id = asset.Id,
                    Name = name,
                    IPAddress = ip,
                    MacAddress = fields["MAC地址"].Text.Trim(),
                    AssetType = comboBoxes["资产类型"].SelectedItem?.ToString() ?? asset.AssetType,
                    OperatingSystem = fields["操作系统"].Text.Trim(),
                    Owner = fields["负责人"].Text.Trim(),
                    Department = fields["部门"].Text.Trim(),
                    Location = fields["位置"].Text.Trim(),
                    Status = asset.Status,
                    Description = fields["描述"].Text.Trim(),
                    Tags = asset.Tags,
                    CreatedAt = asset.CreatedAt,
                    CreatedBy = asset.CreatedBy,
                    LastModified = asset.LastModified,
                    LastModifiedBy = asset.LastModifiedBy
                };

                try
                {
                    if (await _assetService.UpdateAssetAsync(updatedAsset, operatorName))
                    {
                        await RefreshAssetsAsync();
                        dialog.Close();
                        MessageBox.Show("资产更新成功！", "成功", MessageBoxButton.OK, MessageBoxImage.Information);
                    }
                    else
                    {
                        MessageBox.Show("资产更新失败！", "错误", MessageBoxButton.OK, MessageBoxImage.Error);
                    }
                }
                catch (UnauthorizedAccessException ex)
                {
                    MessageBox.Show($"无权限: {ex.Message}", "权限不足", MessageBoxButton.OK, MessageBoxImage.Warning);
                }
            };

            dialog.Content = new ScrollViewer { Content = panel };
            dialog.KeyDown += (s, ev) => { if (ev.Key == Key.Escape) dialog.Close(); };
            dialog.ShowDialog();
        }

        private async void DeleteAssetButton_Click(object sender, RoutedEventArgs e)
        {
            if (AssetsDataGrid.SelectedItem is not Asset asset) return;

            var operatorName = SessionContext.Instance.Current?.Username ?? "";
            var result = MessageBox.Show($"确定要删除资产 '{asset.Name}' 吗？", "确认删除",
                MessageBoxButton.YesNo, MessageBoxImage.Question);

            if (result != MessageBoxResult.Yes) return;

            try
            {
                if (await _assetService.DeleteAssetAsync(asset.Id, operatorName))
                {
                    await RefreshAssetsAsync();
                    MessageBox.Show("资产已删除！", "成功", MessageBoxButton.OK, MessageBoxImage.Information);
                }
            }
            catch (UnauthorizedAccessException ex)
            {
                MessageBox.Show($"无权限: {ex.Message}", "权限不足", MessageBoxButton.OK, MessageBoxImage.Warning);
            }
        }

        private void AssetTypeFilter_SelectionChanged(object sender, SelectionChangedEventArgs e)
        {
            _ = RefreshAssetsAsync();
        }

        private void AssetStatusFilter_SelectionChanged(object sender, SelectionChangedEventArgs e)
        {
            _ = RefreshAssetsAsync();
        }

        private void SearchButton_Click(object sender, RoutedEventArgs e)
        {
            var keyword = SearchTextBox.Text.Trim();
            var results = _assetService.SearchAssets(keyword);
            var filtered = ApplyFilters(results).ToList();
            AssetsDataGrid.ItemsSource = filtered;
            UpdateStatistics(filtered);
        }

        private void RefreshButton_Click(object sender, RoutedEventArgs e)
        {
            _ = RefreshAssetsAsync();
        }

        private async void ImportButton_Click(object sender, RoutedEventArgs e)
        {
            var operatorName = SessionContext.Instance.Current?.Username ?? "";
            var dialog = new OpenFileDialog
            {
                Filter = "JSON文件|*.json|CSV文件|*.csv|所有文件|*.*",
                Title = "导入资产数据"
            };

            if (dialog.ShowDialog() != true) return;

            try
            {
                var ext = Path.GetExtension(dialog.FileName).ToLower();
                List<NetworkDevice> devices = new();

                if (ext == ".json")
                {
                    var json = await File.ReadAllTextAsync(dialog.FileName);
                    var importedAssets = JsonSerializer.Deserialize<List<Asset>>(json);
                    if (importedAssets != null)
                    {
                        foreach (var a in importedAssets)
                        {
                            devices.Add(new NetworkDevice
                            {
                                Hostname = a.Name,
                                IPAddress = a.IPAddress,
                                MacAddress = a.MacAddress,
                                DeviceType = Enum.TryParse<DeviceType>(a.AssetType, out var dt) ? dt : DeviceType.Other,
                                Status = a.Status == AssetStatus.Online ? DeviceStatus.Online : DeviceStatus.Offline
                            });
                        }
                    }
                }
                else if (ext == ".csv")
                {
                    var lines = await File.ReadAllLinesAsync(dialog.FileName);
                    foreach (var line in lines.Skip(1))
                    {
                        var parts = line.Split(',');
                        if (parts.Length >= 2)
                        {
                            devices.Add(new NetworkDevice
                            {
                                Hostname = parts[0].Trim(),
                                IPAddress = parts[1].Trim(),
                                DeviceType = parts.Length > 2 && Enum.TryParse<DeviceType>(parts[2].Trim(), out var dt) ? dt : DeviceType.Other,
                                Status = DeviceStatus.Online
                            });
                        }
                    }
                }

                if (devices.Count == 0)
                {
                    MessageBox.Show("未找到可导入的资产数据！", "提示", MessageBoxButton.OK, MessageBoxImage.Warning);
                    return;
                }

                int imported = await _assetService.ImportFromScanResultsAsync(devices, operatorName);
                await RefreshAssetsAsync();
                MessageBox.Show($"成功导入 {imported} 个资产！\n（跳过 {devices.Count - imported} 个重复IP）", "导入完成", MessageBoxButton.OK, MessageBoxImage.Information);
            }
            catch (UnauthorizedAccessException ex)
            {
                MessageBox.Show($"无权限: {ex.Message}", "权限不足", MessageBoxButton.OK, MessageBoxImage.Warning);
            }
            catch (Exception ex)
            {
                MessageBox.Show($"导入失败: {ex.Message}", "错误", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        private async void ExportButton_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                var dialog = new SaveFileDialog
                {
                    Filter = "JSON文件|*.json|CSV文件|*.csv",
                    FileName = $"资产清单_{DateTime.Now:yyyyMMdd}",
                    Title = "导出资产"
                };

                if (dialog.ShowDialog() != true) return;

                var assets = _assetService.GetAllAssets();
                string ext = Path.GetExtension(dialog.FileName).ToLower();

                if (ext == ".json")
                {
                    var json = JsonSerializer.Serialize(assets, new JsonSerializerOptions { WriteIndented = true });
                    await File.WriteAllTextAsync(dialog.FileName, json);
                }
                else if (ext == ".csv")
                {
                    var sb = new StringBuilder();
                    sb.AppendLine("名称,IP地址,MAC地址,类型,部门,负责人,状态,描述");
                    foreach (var a in assets)
                    {
                        sb.AppendLine($"{a.Name},{a.IPAddress},{a.MacAddress},{a.AssetType},{a.Department},{a.Owner},{a.Status},{a.Description}");
                    }
                    await File.WriteAllTextAsync(dialog.FileName, sb.ToString());
                }

                MessageBox.Show($"资产已导出到:\n{dialog.FileName}", "导出成功", MessageBoxButton.OK, MessageBoxImage.Information);
            }
            catch (Exception ex)
            {
                MessageBox.Show($"导出失败: {ex.Message}", "错误", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        private void CloseButton_Click(object sender, RoutedEventArgs e)
        {
            Close();
        }
    }
}
