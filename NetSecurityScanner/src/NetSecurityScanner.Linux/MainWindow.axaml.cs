using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Avalonia;
using Avalonia.Controls;
using Avalonia.Data;
using Avalonia.Diagnostics;
using Avalonia.Interactivity;
using Avalonia.Media;
using Avalonia.Threading;
using NetSecurityScanner.Services;
using NetSecurityScanner.Models;
using NetSecurityScanner.Utils;

namespace NetSecurityScanner;

public partial class MainWindow : Window
{
    private PortScanner? _portScanner;
    private VulnerabilityScanner? _vulnerabilityScanner;
    private RiskAssessmentService? _riskAssessmentService;
    private JsonDatabaseService? _jsonDatabaseService;
    private PortManagementService? _portManagementService;
    private ScanHistoryService? _scanHistoryService;
    private LoggingService? _loggingService;
    
    private bool _isScanning = false;
    private CancellationTokenSource? _scanCts;
    
    public MainWindow()
    {
        InitializeComponent();
        
#if DEBUG
        this.AttachDevTools();
#endif
        
        Loaded += MainWindow_Loaded;
        Closing += MainWindow_Closing;
    }
    
    private void MainWindow_Loaded(object? sender, EventArgs e)
    {
        InitializeServices();
        UpdateDateTimeTimer();
        Log("系统初始化完成，就绪");
    }
    
    private void MainWindow_Closing(object? sender, WindowClosingEventArgs e)
    {
        if (_isScanning)
        {
            StopScan_Click(null, null!);
        }
    }
    
    private void InitializeServices()
    {
        try
        {
            Log("开始初始化服务...");
            
            _portScanner = new PortScanner();
            _riskAssessmentService = new RiskAssessmentService();
            _portManagementService = new PortManagementService();
            _vulnerabilityScanner = new VulnerabilityScanner();
            _jsonDatabaseService = new JsonDatabaseService();
            _scanHistoryService = new ScanHistoryService();
            _loggingService = new LoggingService();
            
            Log("所有服务初始化完成");
        }
        catch (Exception ex)
        {
            Log($"服务初始化失败: {ex.Message}");
        }
    }
    
    private async void UpdateDateTimeTimer()
    {
        var statusTime = this.FindControl<TextBlock>("StatusTime");
        while (true)
        {
            await Task.Delay(1000);
            Dispatcher.UIThread.Post(() =>
            {
                if (statusTime != null) statusTime.Text = DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss");
            });
        }
    }
    
    private async void StartScan_Click(object? sender, RoutedEventArgs e)
    {
        var targetBox = this.FindControl<TextBox>("TargetTextBox");
        string target = targetBox?.Text?.Trim() ?? "";
        
        if (string.IsNullOrEmpty(target))
        {
            await ShowMessageAsync("请输入目标IP地址或域名", "提示");
            return;
        }
        
        _isScanning = true;
        _scanCts = new CancellationTokenSource();
        UpdateScanButtonStates(true);
        UpdateScanStatus($"正在扫描 {target} ...", 0, true);
        
        try
        {
            List<int> ports = GetCommonPorts();
            var results = await _portScanner!.ScanTcpPortsAsync(target, ports, null, _scanCts.Token);
            
            UpdateScanStatus($"端口扫描完成，发现 {results.Count} 个开放端口", 100, false);
            
            ShowPortScanResults(results);
            
            var completeResult = new CompleteScanResult
            {
                TargetIp = target,
                ScanType = "综合扫描",
                ScanTime = DateTime.Now,
                OpenPortsCount = results.Count,
                PortScanResults = results,
                VulnerabilityResults = new List<VulnerabilityResult>()
            };
            _jsonDatabaseService?.SaveScanResultAsync(completeResult);
            Log("扫描结果已保存到历史记录");
        }
        catch (OperationCanceledException)
        {
            UpdateScanStatus("扫描已取消", 0, false);
        }
        catch (Exception ex)
        {
            Log($"扫描失败: {ex.Message}");
            UpdateScanStatus($"扫描失败: {ex.Message}", 0, false);
        }
        finally
        {
            _isScanning = false;
            UpdateScanButtonStates(false);
        }
    }
    
    private void StopScan_Click(object? sender, RoutedEventArgs e)
    {
        _scanCts?.Cancel();
        Log("用户请求停止扫描");
    }
    
    private List<int> GetCommonPorts()
    {
        return new List<int> { 21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 993, 995, 1433, 1521, 3306, 3389, 5432, 5900, 8080, 8443, 8888, 27017 };
    }
    
    private void UpdateScanButtonStates(bool isScanning)
    {
        var startBtn = this.FindControl<Button>("StartScanButton");
        var stopBtn = this.FindControl<Button>("StopButton");
        if (startBtn != null) startBtn.IsEnabled = !isScanning;
        if (stopBtn != null) stopBtn.IsEnabled = isScanning;
    }
    
    private void UpdateScanStatus(string text, int progress, bool showProgress)
    {
        var statusText = this.FindControl<TextBlock>("StatusText");
        if (statusText != null) statusText.Text = text;
        
        var progressBar = this.FindControl<ProgressBar>("ScanProgressBar");
        if (progressBar != null)
        {
            progressBar.IsVisible = showProgress;
            if (showProgress) progressBar.Value = progress;
        }
    }
    
    private void ShowPortScanResults(List<PortScanResult> results)
    {
        var panel = this.FindControl<StackPanel>("PortScanPanel");
        if (panel == null) return;
        
        panel.Children.Clear();
        
        if (!results.Any())
        {
            panel.Children.Add(new TextBlock 
            { 
                Text = "未发现开放端口", 
                Foreground = Brushes.Gray,
                HorizontalAlignment = Avalonia.Layout.HorizontalAlignment.Center
            });
            return;
        }
        
        var dataGrid = new DataGrid
        {
            AutoGenerateColumns = false,
            IsReadOnly = true,
            ItemsSource = results,
            CanUserResizeColumns = true
        };
        
        dataGrid.Columns.Add(new DataGridTextColumn { Header = "端口号", Binding = new Binding("PortNumber"), Width = new DataGridLength(80) });
        dataGrid.Columns.Add(new DataGridTextColumn { Header = "状态", Binding = new Binding("Status"), Width = new DataGridLength(80) });
        dataGrid.Columns.Add(new DataGridTextColumn { Header = "服务", Binding = new Binding("Service"), Width = new DataGridLength(120) });
        dataGrid.Columns.Add(new DataGridTextColumn { Header = "版本", Binding = new Binding("ServiceVersion"), Width = new DataGridLength(150) });
        dataGrid.Columns.Add(new DataGridTextColumn { Header = "响应时间", Binding = new Binding("ResponseTime"), Width = new DataGridLength(80) });
        
        panel.Children.Add(dataGrid);
    }
    
    private void Log(string message)
    {
        Console.WriteLine($"[MainWindow] {message}");
        Dispatcher.UIThread.Post(() => UpdateScanStatus(message, 0, _isScanning));
    }
    
    private void Exit_Click(object? sender, RoutedEventArgs e) => Close();
    
    private async void OpenPluginManager_Click(object? sender, RoutedEventArgs e)
    {
        var pluginWindow = new Views.PluginManagerWindow();
        await pluginWindow.ShowDialog(this);
    }
    
    private async void OpenPortScan_Click(object? sender, RoutedEventArgs e)
    {
        var portScanWindow = new Views.PortScanWindow();
        await portScanWindow.ShowDialog(this);
    }
    
    private async void About_Click(object? sender, RoutedEventArgs e)
    {
        await ShowMessageAsync(
            $"网络安全漏洞扫描系统 v{VersionHelper.GetVersion()}\n\n" +
            "基于 Avalonia UI 的跨平台安全扫描工具\n" +
            "支持 Linux / Windows / macOS",
            "关于");
    }
    
    private async Task ShowMessageAsync(string message, string title)
    {
        var dialog = new Window
        {
            Title = title,
            Width = 400,
            Height = 150,
            WindowStartupLocation = WindowStartupLocation.CenterOwner
        };
        var panel = new StackPanel { Margin = new Thickness(20) };
        panel.Children.Add(new TextBlock { Text = message, TextWrapping = TextWrapping.Wrap });
        var okBtn = new Button { Content = "确定", HorizontalAlignment = Avalonia.Layout.HorizontalAlignment.Right, Margin = new Thickness(0, 10, 0, 0) };
        okBtn.Click += (_, _) => dialog.Close();
        panel.Children.Add(okBtn);
        dialog.Content = panel;
        await dialog.ShowDialog(this);
    }
}
