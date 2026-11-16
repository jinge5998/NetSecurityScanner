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

namespace NetSecurityScanner.Views
{
    public partial class ScanHistoryWindow : Window
    {
        private readonly ScanHistoryService _historyService;
        private List<ScanHistory> _allHistory;
        private List<ScanHistory> _filteredHistory;

        public ScanHistoryWindow()
        {
            InitializeComponent();
            _historyService = new ScanHistoryService();
            _allHistory = new List<ScanHistory>();
            _filteredHistory = new List<ScanHistory>();

            Loaded += ScanHistoryWindow_Loaded;
        }

        private async void ScanHistoryWindow_Loaded(object sender, RoutedEventArgs e)
        {
            await LoadHistoryAsync();
        }

        private async Task LoadHistoryAsync()
        {
            try
            {
                _allHistory = await _historyService.GetScanHistoryAsync();
                ApplyFilters();
            }
            catch (Exception ex)
            {
                MessageBox.Show($"加载扫描历史失败: {ex.Message}", "错误", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        private void ApplyFilters()
        {
            _filteredHistory = _allHistory.ToList();

            // 搜索筛选
            var searchText = SearchTextBox.Text.Trim().ToLower();
            if (!string.IsNullOrEmpty(searchText))
            {
                _filteredHistory = _filteredHistory.Where(h =>
                    h.Target.ToLower().Contains(searchText) ||
                    h.ScanId.ToLower().Contains(searchText) ||
                    (h.ScanMode?.ToLower().Contains(searchText) ?? false)
                ).ToList();
            }

            // 风险等级筛选
            if (RiskFilterComboBox.SelectedItem is ComboBoxItem riskItem && riskItem.Content.ToString() != "所有风险等级")
            {
                var riskLevel = riskItem.Content.ToString();
                _filteredHistory = _filteredHistory.Where(h =>
                    (riskLevel == "严重" && h.CriticalCount > 0) ||
                    (riskLevel == "高危" && h.HighCount > 0) ||
                    (riskLevel == "中危" && h.MediumCount > 0) ||
                    (riskLevel == "低危" && h.LowCount > 0)
                ).ToList();
            }

            // 时间筛选
            if (DateFilterComboBox.SelectedItem is ComboBoxItem dateItem && dateItem.Content.ToString() != "所有时间")
            {
                var now = DateTime.Now;
                _filteredHistory = dateItem.Content.ToString() switch
                {
                    "今天" => _filteredHistory.Where(h => h.ScanTime.Date == now.Date).ToList(),
                    "最近7天" => _filteredHistory.Where(h => h.ScanTime >= now.AddDays(-7)).ToList(),
                    "最近30天" => _filteredHistory.Where(h => h.ScanTime >= now.AddDays(-30)).ToList(),
                    _ => _filteredHistory
                };
            }

            HistoryDataGrid.ItemsSource = _filteredHistory;
        }

        private void SearchTextBox_TextChanged(object sender, TextChangedEventArgs e)
        {
            ApplyFilters();
        }

        private void RiskFilterComboBox_SelectionChanged(object sender, SelectionChangedEventArgs e)
        {
            ApplyFilters();
        }

        private void DateFilterComboBox_SelectionChanged(object sender, SelectionChangedEventArgs e)
        {
            ApplyFilters();
        }

        private async void RefreshButton_Click(object sender, RoutedEventArgs e)
        {
            await LoadHistoryAsync();
        }

        private void HistoryDataGrid_SelectionChanged(object sender, SelectionChangedEventArgs e)
        {
            bool hasSelection = HistoryDataGrid.SelectedItem != null;
            ViewDetailsButton.IsEnabled = hasSelection;
            DeleteButton.IsEnabled = hasSelection;
        }

        private void ViewDetailsButton_Click(object sender, RoutedEventArgs e)
        {
            if (HistoryDataGrid.SelectedItem is ScanHistory history)
            {
                var detailsWindow = new ScanHistoryDetailsWindow(history);
                detailsWindow.ShowDialog();
            }
        }

        private async void DeleteButton_Click(object sender, RoutedEventArgs e)
        {
            if (HistoryDataGrid.SelectedItem is ScanHistory history)
            {
                var result = MessageBox.Show(
                    $"确定要删除扫描记录 '{history.ScanId}' 吗？\n目标: {history.Target}\n时间: {history.ScanTime:yyyy-MM-dd HH:mm}",
                    "确认删除",
                    MessageBoxButton.YesNo,
                    MessageBoxImage.Question);

                if (result == MessageBoxResult.Yes)
                {
                    try
                    {
                        // 从数据库中删除
                        await _historyService.DeleteScanHistoryAsync(history.ScanId);
                        await LoadHistoryAsync();
                        MessageBox.Show("记录已删除", "成功", MessageBoxButton.OK, MessageBoxImage.Information);
                    }
                    catch (Exception ex)
                    {
                        MessageBox.Show($"删除失败: {ex.Message}", "错误", MessageBoxButton.OK, MessageBoxImage.Error);
                    }
                }
            }
        }

        private async void ExportButton_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                var dialog = new SaveFileDialog
                {
                    Filter = "CSV文件|*.csv|JSON文件|*.json",
                    FileName = $"扫描历史_{DateTime.Now:yyyyMMdd_HHmmss}",
                    Title = "导出扫描历史"
                };

                if (dialog.ShowDialog() != true) return;

                string filePath = dialog.FileName;
                string extension = Path.GetExtension(filePath).ToLower();

                if (extension == ".csv")
                {
                    await ExportToCsvAsync(filePath);
                }
                else if (extension == ".json")
                {
                    await ExportToJsonAsync(filePath);
                }

                MessageBox.Show($"扫描历史已导出到:\n{filePath}", "导出成功", MessageBoxButton.OK, MessageBoxImage.Information);
            }
            catch (Exception ex)
            {
                MessageBox.Show($"导出失败: {ex.Message}", "错误", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        private async Task ExportToCsvAsync(string filePath)
        {
            var sb = new StringBuilder();
            sb.AppendLine("扫描ID,目标,扫描时间,扫描模式,漏洞总数,严重,高危,中危,低危,扫描时长,状态");

            foreach (var history in _filteredHistory)
            {
                sb.AppendLine($"{history.ScanId},{history.Target},{history.ScanTime:yyyy-MM-dd HH:mm},{history.ScanMode}," +
                    $"{history.TotalVulnerabilities},{history.CriticalCount},{history.HighCount}," +
                    $"{history.MediumCount},{history.LowCount},{history.Duration},{history.ScanStatus}");
            }

            await File.WriteAllTextAsync(filePath, sb.ToString(), Encoding.UTF8);
        }

        private async Task ExportToJsonAsync(string filePath)
        {
            var json = JsonSerializer.Serialize(_filteredHistory, new JsonSerializerOptions
            {
                WriteIndented = true,
                PropertyNamingPolicy = JsonNamingPolicy.CamelCase
            });

            await File.WriteAllTextAsync(filePath, json, Encoding.UTF8);
        }

        private void CloseButton_Click(object sender, RoutedEventArgs e)
        {
            Close();
        }
    }
}
