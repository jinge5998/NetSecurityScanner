using Microsoft.Win32;
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

        public AssetManagementWindow()
        {
            InitializeComponent();
            _assetService = new AssetManagementService();
            Loaded += AssetManagementWindow_Loaded;
        }

        private void AssetManagementWindow_Loaded(object sender, RoutedEventArgs e)
        {
            RefreshAssets();
        }

        private void RefreshAssets()
        {
            try
            {
                var assets = _assetService.GetAllAssets();
                AssetsDataGrid.ItemsSource = assets;
                UpdateStatistics();
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"[AssetManagementWindow] 刷新资产列表失败: {ex.Message}");
            }
        }

        private void UpdateStatistics()
        {
            try
            {
                var stats = _assetService.GetStatistics();
                if (TotalAssetsText != null) TotalAssetsText.Text = stats.TotalAssets.ToString();
                if (OnlineAssetsText != null) OnlineAssetsText.Text = stats.OnlineAssets.ToString();

                if (ChangeLogListBox != null)
                    ChangeLogListBox.ItemsSource = stats.RecentChanges.Select(c =>
                        $"{c.ChangedAt:MM-dd HH:mm} - {c.ChangeType}: {c.NewValue}").ToList();
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"[AssetManagementWindow] 更新统计信息失败: {ex.Message}");
            }
        }

        private void AssetsDataGrid_SelectionChanged(object sender, SelectionChangedEventArgs e)
        {
            bool hasSelection = AssetsDataGrid.SelectedItem != null;
            EditAssetButton.IsEnabled = hasSelection;
            DeleteAssetButton.IsEnabled = hasSelection;
        }

        private async void AddAssetButton_Click(object sender, RoutedEventArgs e)
        {
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

                if (await _assetService.AddAssetAsync(asset))
                {
                    RefreshAssets();
                    dialog.Close();
                    MessageBox.Show("资产添加成功！", "成功", MessageBoxButton.OK, MessageBoxImage.Information);
                }
                else
                {
                    MessageBox.Show("资产添加失败，IP地址可能已存在！", "错误", MessageBoxButton.OK, MessageBoxImage.Error);
                }
            };

            dialog.Content = new ScrollViewer { Content = panel };
            dialog.KeyDown += (s, ev) => { if (ev.Key == Key.Escape) dialog.Close(); };
            dialog.ShowDialog();
        }

        private void EditAssetButton_Click(object sender, RoutedEventArgs e)
        {
            if (AssetsDataGrid.SelectedItem is not Asset asset) return;

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
                    LastModified = asset.LastModified
                };

                if (await _assetService.UpdateAssetAsync(updatedAsset))
                {
                    RefreshAssets();
                    dialog.Close();
                    MessageBox.Show("资产更新成功！", "成功", MessageBoxButton.OK, MessageBoxImage.Information);
                }
                else
                {
                    MessageBox.Show("资产更新失败！", "错误", MessageBoxButton.OK, MessageBoxImage.Error);
                }
            };

            dialog.Content = new ScrollViewer { Content = panel };
            dialog.KeyDown += (s, ev) => { if (ev.Key == Key.Escape) dialog.Close(); };
            dialog.ShowDialog();
        }

        private async void DeleteAssetButton_Click(object sender, RoutedEventArgs e)
        {
            if (AssetsDataGrid.SelectedItem is Asset asset)
            {
                var result = MessageBox.Show($"确定要删除资产 '{asset.Name}' 吗？", "确认删除", 
                    MessageBoxButton.YesNo, MessageBoxImage.Question);
                
                if (result == MessageBoxResult.Yes)
                {
                    if (await _assetService.DeleteAssetAsync(asset.Id))
                    {
                        RefreshAssets();
                        MessageBox.Show("资产已删除！", "成功", MessageBoxButton.OK, MessageBoxImage.Information);
                    }
                }
            }
        }

        private void SearchButton_Click(object sender, RoutedEventArgs e)
        {
            var keyword = SearchTextBox.Text.Trim();
            var results = _assetService.SearchAssets(keyword);
            AssetsDataGrid.ItemsSource = results;
        }

        private void RefreshButton_Click(object sender, RoutedEventArgs e)
        {
            RefreshAssets();
        }

        private async void ImportButton_Click(object sender, RoutedEventArgs e)
        {
            var dialog = new Microsoft.Win32.OpenFileDialog
            {
                Filter = "JSON文件|*.json|CSV文件|*.csv|所有文件|*.*",
                Title = "导入资产数据"
            };

            if (dialog.ShowDialog() != true) return;

            try
            {
                var ext = System.IO.Path.GetExtension(dialog.FileName).ToLower();
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

                int imported = await _assetService.ImportFromScanResultsAsync(devices);
                RefreshAssets();
                MessageBox.Show($"成功导入 {imported} 个资产！\n（跳过 {devices.Count - imported} 个重复IP）", "导入完成", MessageBoxButton.OK, MessageBoxImage.Information);
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
