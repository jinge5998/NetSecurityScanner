using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Avalonia.Controls;
using Avalonia.Diagnostics;
using Avalonia.Interactivity;
using NetSecurityScanner.Services;
using NetSecurityScanner.Models;

namespace NetSecurityScanner.Views;

public partial class PortScanWindow : Window
{
    private PortScanner? _portScanner;
    private CancellationTokenSource? _cts;
    private bool _isScanning = false;
    
    public PortScanWindow()
    {
        InitializeComponent();
#if DEBUG
#endif
        Loaded += OnLoaded;
    }
    
    private void OnLoaded(object? sender, EventArgs e)
    {
        _portScanner = new PortScanner();
        
        var startBtn = this.FindControl<Button>("StartPortScanButton");
        var stopBtn = this.FindControl<Button>("StopPortScanButton");
        
        if (startBtn != null) startBtn.Click += StartScan_Click;
        if (stopBtn != null) stopBtn.Click += StopScan_Click;
    }
    
    private async void StartScan_Click(object? sender, RoutedEventArgs e)
    {
        var targetBox = this.FindControl<TextBox>("TargetIpTextBox");
        var resultGrid = this.FindControl<DataGrid>("PortScanResultsDataGrid");
        var startBtn = this.FindControl<Button>("StartPortScanButton");
        var stopBtn = this.FindControl<Button>("StopPortScanButton");
        var progressBar = this.FindControl<ProgressBar>("ScanProgressBar");
        var statusText = this.FindControl<TextBlock>("ScanProgressText");
        
        string target = targetBox?.Text?.Trim() ?? "";
        if (string.IsNullOrWhiteSpace(target))
        {
            if (statusText != null) statusText.Text = "请输入有效的IP地址";
            return;
        }
        
        _isScanning = true;
        _cts = new CancellationTokenSource();
        if (startBtn != null) startBtn.IsEnabled = false;
        if (stopBtn != null) stopBtn.IsEnabled = true;
        if (progressBar != null)
        {
            progressBar.IsVisible = true;
            progressBar.Value = 0;
        }
        if (statusText != null) statusText.Text = $"正在扫描 {target}...";
        
        try
        {
            List<int> ports = GetCommonPorts();
            var results = await _portScanner!.ScanTcpPortsAsync(target, ports, null, _cts.Token);
            
            if (resultGrid != null) resultGrid.ItemsSource = results;
            if (statusText != null) statusText.Text = $"扫描完成！发现 {results.Count} 个开放端口";
        }
        catch (OperationCanceledException)
        {
            if (statusText != null) statusText.Text = "扫描已取消";
        }
        catch (Exception ex)
        {
            if (statusText != null) statusText.Text = $"扫描失败: {ex.Message}";
        }
        finally
        {
            _isScanning = false;
            if (startBtn != null) startBtn.IsEnabled = true;
            if (stopBtn != null) stopBtn.IsEnabled = false;
            if (progressBar != null) progressBar.Value = 100;
        }
    }
    
    private void StopScan_Click(object? sender, RoutedEventArgs e)
    {
        _cts?.Cancel();
    }
    
    private List<int> GetCommonPorts()
    {
        return new List<int> { 21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 993, 995, 1433, 1521, 3306, 3389, 5432, 5900, 8080, 8443, 8888, 27017 };
    }
}
