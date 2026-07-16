using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Avalonia;
using Avalonia.Controls;
using Avalonia.Diagnostics;
using Avalonia.Interactivity;
using NetSecurityScanner.Services;
using NetSecurityScanner.Models;

namespace NetSecurityScanner.Views;

public partial class ScanHistoryWindow : Window
{
    private JsonDatabaseService? _dbService;
    
    public ScanHistoryWindow()
    {
        InitializeComponent();
#if DEBUG
        this.AttachDevTools();
#endif
        Loaded += OnLoaded;
    }
    
    private async void OnLoaded(object? sender, EventArgs e)
    {
        _dbService = new JsonDatabaseService();
        
        var refreshBtn = this.FindControl<Button>("RefreshButton");
        var closeBtn = this.FindControl<Button>("CloseButton");
        
        if (refreshBtn != null) refreshBtn.Click += Refresh_Click;
        if (closeBtn != null) closeBtn.Click += (_, _) => Close();
        
        await LoadHistoryRecords();
    }
    
    private async Task LoadHistoryRecords()
    {
        var grid = this.FindControl<DataGrid>("HistoryDataGrid");
        if (grid == null || _dbService == null) return;
        
        try
        {
            var records = await _dbService.GetScanHistoryAsync();
            Avalonia.Threading.Dispatcher.UIThread.Post(() =>
            {
                grid.ItemsSource = records.OrderByDescending(r => r.ScanTime).ToList();
            });
        }
        catch (Exception ex)
        {
            Console.WriteLine($"加载历史记录失败: {ex.Message}");
        }
    }
    
    private async void GenerateReport_Click(object? sender, RoutedEventArgs e)
    {
        var grid = this.FindControl<DataGrid>("HistoryDataGrid");
        if (grid?.SelectedItem is not ScanHistoryItem selectedItem)
        {
            await ShowMessageAsync("请先选择一条历史记录", "提示");
            return;
        }
        
        try
        {
            var completeResult = await _dbService?.GetScanResultByIdAsync(selectedItem.ScanId)!;
            if (completeResult == null)
            {
                await ShowMessageAsync("无法加载选中的扫描结果详情", "错误");
                return;
            }
            
            var reportPath = HistoryReportGenerator.GenerateFromHistoryRecord(completeResult);
            if (!string.IsNullOrEmpty(reportPath))
            {
                await ShowMessageAsync($"PDF报告已成功生成！\n\n{reportPath}", "成功");
            }
            else
            {
                await ShowMessageAsync("报告生成失败：选中的记录可能没有有效数据", "错误");
            }
        }
        catch (Exception ex)
        {
            await ShowMessageAsync($"报告生成失败: {ex.Message}", "错误");
        }
    }
    
    private async void Refresh_Click(object? sender, RoutedEventArgs e)
    {
        await LoadHistoryRecords();
    }
    
    private async Task ShowMessageAsync(string message, string title)
    {
        var dialog = new Window { Title = title, Width = 450, Height = 180, WindowStartupLocation = WindowStartupLocation.CenterOwner };
        var panel = new StackPanel { Margin = new Thickness(20) };
        panel.Children.Add(new TextBlock { Text = message, TextWrapping = Avalonia.Media.TextWrapping.Wrap });
        var btn = new Button { Content = "确定", HorizontalAlignment = Avalonia.Layout.HorizontalAlignment.Right, Margin = new Thickness(0,15,0,0) };
        btn.Click += (_, _) => dialog.Close();
        panel.Children.Add(btn);
        dialog.Content = panel;
        await dialog.ShowDialog(this);
    }
}
