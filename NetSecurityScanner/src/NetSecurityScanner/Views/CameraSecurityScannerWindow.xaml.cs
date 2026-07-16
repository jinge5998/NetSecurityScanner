using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Diagnostics;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using NetSecurityScanner.Core;
using NetSecurityScanner.Models;

namespace NetSecurityScanner.Views
{
  public partial class CameraSecurityScannerWindow : Window
  {
    private CancellationTokenSource? _cts;
    private Stopwatch? _elapsedTimer;
    private readonly List<CameraScanResult> _allResults = new();

    public CameraSecurityScannerWindow()
    {
      InitializeComponent();
      UpdateStatusBar();
    }

    private async void StartScan_Click(object sender, RoutedEventArgs e)
    {
      var targetIp = SingleIpTextBox.Text.Trim();
      var ipRange = IpRangeTextBox.Text.Trim();
      var cidr = CidrTextBox.Text.Trim();

      if (string.IsNullOrEmpty(targetIp) && string.IsNullOrEmpty(ipRange) && string.IsNullOrEmpty(cidr))
      {
        MessageBox.Show("请输入至少一个目标（单IP、IP段或CIDR）", "输入错误", MessageBoxButton.OK, MessageBoxImage.Warning);
        return;
      }

      var options = new CameraScanOptions
      {
        TargetIp = targetIp,
        IpRange = ipRange,
        CidrNotation = cidr,
        EnableFingerprint = FingerprintCheck.IsChecked ?? true,
        EnableVulnerabilityScan = VulnScanCheck.IsChecked ?? true,
        EnableWeakPasswordScan = WeakPasswordCheck.IsChecked ?? true,
        MaxConcurrency = int.TryParse(ConcurrencyTextBox.Text, out var c) ? c : 30,
        TimeoutMs = int.TryParse(TimeoutTextBox.Text, out var t) ? t : 3000,
        UseDefaultPorts = true
      };

      SetScanningUIState(true);
      _allResults.Clear();
      ClearResults();

      _cts = new CancellationTokenSource();
      _elapsedTimer = Stopwatch.StartNew();

      try
      {
        var service = new CameraScannerService();
        try
        {
          var progress = new Progress<CameraScanProgress>(p =>
          {
            Dispatcher.Invoke(() => UpdateProgress(p));
          });

          var results = await Task.Run(() => service.ScanCamerasAsync(options, progress, _cts.Token));
          _allResults.AddRange(results);

          await Dispatcher.InvokeAsync(() =>
          {
            DisplayResults(results);
            ScanStatusText.Text = "状态: 扫描完成";
            ScanProgressBar.Value = 100;
            ScanProgressText.Text = "100%";
            ExportReportButton.IsEnabled = results.Any(r => r.IsOnline);
          });
        }
        finally
        {
          service.Dispose();
        }
      }
      catch (OperationCanceledException)
      {
        ScanStatusText.Text = "状态: 扫描已取消";
      }
      catch (Exception ex)
      {
        ScanStatusText.Text = "状态: 扫描失败";
        MessageBox.Show($"扫描失败: {ex.Message}", "错误", MessageBoxButton.OK, MessageBoxImage.Error);
      }
      finally
      {
        _cts?.Dispose();
        _cts = null;
        _elapsedTimer?.Stop();
        SetScanningUIState(false);
        UpdateStatusBar();
      }
    }

    private void StopScan_Click(object sender, RoutedEventArgs e)
    {
      _cts?.Cancel();
      ScanStatusText.Text = "状态: 正在停止...";
    }

    private void ImportTargets_Click(object sender, RoutedEventArgs e)
    {
      var dialog = new Microsoft.Win32.OpenFileDialog
      {
        Filter = "文本文件 (*.txt)|*.txt|CSV文件 (*.csv)|*.csv|所有文件 (*.*)|*.*",
        Title = "导入IP目标列表"
      };

      if (dialog.ShowDialog() == true)
      {
        try
        {
          var lines = System.IO.File.ReadAllLines(dialog.FileName);
          var ips = new List<string>();
          foreach (var line in lines)
          {
            var ip = line.Trim();
            if (string.IsNullOrEmpty(ip) || ip.StartsWith("#") || ip.StartsWith("//"))
              continue;
            ips.Add(ip);
          }

          if (ips.Count == 0)
          {
            MessageBox.Show("文件中未找到有效的IP地址", "提示", MessageBoxButton.OK, MessageBoxImage.Information);
            return;
          }

          IpRangeTextBox.Text = string.Join(",", ips);
          SingleIpTextBox.Text = string.Empty;
          CidrTextBox.Text = string.Empty;
          ScanStatusText.Text = $"状态: 已导入 {ips.Count} 个目标IP";
        }
        catch (Exception ex)
        {
          MessageBox.Show($"导入失败: {ex.Message}", "错误", MessageBoxButton.OK, MessageBoxImage.Error);
        }
      }
    }

    private void AutoDiscover_Click(object sender, RoutedEventArgs e)
    {
      try
      {
        var interfaces = System.Net.NetworkInformation.NetworkInterface.GetAllNetworkInterfaces();
        var localNetworks = new List<string>();

        foreach (var ni in interfaces)
        {
          if (ni.OperationalStatus != System.Net.NetworkInformation.OperationalStatus.Up)
            continue;

          var ipProps = ni.GetIPProperties();
          foreach (var unicast in ipProps.UnicastAddresses)
          {
            if (unicast.Address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork
                && !System.Net.IPAddress.IsLoopback(unicast.Address))
            {
              var ip = unicast.Address;
              var mask = unicast.IPv4Mask;
              if (mask != null)
              {
                var network = new System.Net.IPAddress(
                    BitConverter.GetBytes(BitConverter.ToUInt32(ip.GetAddressBytes(), 0)
                        & BitConverter.ToUInt32(mask.GetAddressBytes(), 0)));
                var cidr = GetCidrFromMask(mask);
                localNetworks.Add($"{network}/{cidr}");
              }
            }
          }
        }

        if (localNetworks.Count == 0)
        {
          MessageBox.Show("未检测到活跃的本地网络接口", "提示", MessageBoxButton.OK, MessageBoxImage.Information);
          return;
        }

        var result = MessageBox.Show(
            $"检测到以下本地网络:\n{string.Join("\n", localNetworks)}\n\n是否使用第一个网络开始扫描？",
            "自动发现", MessageBoxButton.YesNo, MessageBoxImage.Question);

        if (result == MessageBoxResult.Yes)
        {
          SingleIpTextBox.Text = string.Empty;
          IpRangeTextBox.Text = string.Empty;
          CidrTextBox.Text = localNetworks[0];
          ScanStatusText.Text = $"状态: 已设置扫描范围 {localNetworks[0]}";
        }
      }
      catch (Exception ex)
      {
        MessageBox.Show($"自动发现失败: {ex.Message}", "错误", MessageBoxButton.OK, MessageBoxImage.Error);
      }
    }

    private static int GetCidrFromMask(System.Net.IPAddress mask)
    {
      var bytes = mask.GetAddressBytes();
      uint maskValue = BitConverter.ToUInt32(bytes, 0);
      int cidr = 0;
      while (maskValue > 0)
      {
        cidr++;
        maskValue <<= 1;
      }
      return cidr;
    }

    private void ExportReport_Click(object sender, RoutedEventArgs e)
    {
      var dialog = new Microsoft.Win32.SaveFileDialog
      {
        Filter = "HTML文件 (*.html)|*.html|文本文件 (*.txt)|*.txt|CSV文件 (*.csv)|*.csv",
        DefaultExt = ".html",
        FileName = $"摄像头安全扫描报告_{DateTime.Now:yyyyMMdd_HHmmss}"
      };

      if (dialog.ShowDialog() == true)
      {
        try
        {
          var content = GenerateReport(dialog.FileName);
          System.IO.File.WriteAllText(dialog.FileName, content, Encoding.UTF8);
          MessageBox.Show($"报告已导出到: {dialog.FileName}", "导出成功", MessageBoxButton.OK, MessageBoxImage.Information);
        }
        catch (Exception ex)
        {
          MessageBox.Show($"导出失败: {ex.Message}", "错误", MessageBoxButton.OK, MessageBoxImage.Error);
        }
      }
    }

    private void ExportJsonButton_Click(object sender, RoutedEventArgs e)
    {
      var dialog = new Microsoft.Win32.SaveFileDialog
      {
        Filter = "JSON文件 (*.json)|*.json",
        DefaultExt = ".json",
        FileName = $"摄像头安全扫描报告_{DateTime.Now:yyyyMMdd_HHmmss}.json"
      };

      if (dialog.ShowDialog() == true)
      {
        try
        {
          var json = System.Text.Json.JsonSerializer.Serialize(_allResults, new System.Text.Json.JsonSerializerOptions
          {
            WriteIndented = true,
            Encoder = System.Text.Encodings.Web.JavaScriptEncoder.UnsafeRelaxedJsonEscaping
          });
          System.IO.File.WriteAllText(dialog.FileName, json, Encoding.UTF8);
          MessageBox.Show($"JSON报告已导出到: {dialog.FileName}", "导出成功", MessageBoxButton.OK, MessageBoxImage.Information);
        }
        catch (Exception ex)
        {
          MessageBox.Show($"导出失败: {ex.Message}", "错误", MessageBoxButton.OK, MessageBoxImage.Error);
        }
      }
    }

    private void FilterTextBox_TextChanged(object sender, TextChangedEventArgs e)
    {
      ApplyFilter();
    }

    private void FilterTextBox_GotFocus(object sender, RoutedEventArgs e)
    {
      if (FilterTextBox.Text == "🔍 搜索过滤（IP / 厂商 / 型号 / 风险等级）...")
      {
        FilterTextBox.Text = string.Empty;
        FilterTextBox.Foreground = System.Windows.Media.Brushes.Black;
      }
    }

    private void FilterTextBox_LostFocus(object sender, RoutedEventArgs e)
    {
      if (string.IsNullOrWhiteSpace(FilterTextBox.Text))
      {
        FilterTextBox.Text = "🔍 搜索过滤（IP / 厂商 / 型号 / 风险等级）...";
        FilterTextBox.Foreground = new System.Windows.Media.SolidColorBrush(
            System.Windows.Media.Color.FromRgb(0x95, 0xA5, 0xA6));
      }
    }

    private void CopyButton_Click(object sender, RoutedEventArgs e)
    {
      if (CameraDataGrid.SelectedItem is CameraScanResult camera)
      {
        var sb = new StringBuilder();
        sb.AppendLine($"IP: {camera.Ip}");
        sb.AppendLine($"厂商: {camera.Vendor}");
        sb.AppendLine($"型号: {camera.Model}");
        sb.AppendLine($"固件: {camera.FirmwareVersion}");
        sb.AppendLine($"风险等级: {camera.RiskAssessment.RiskLevel} (评分: {camera.RiskAssessment.TotalScore:F1})");
        sb.AppendLine($"漏洞: {camera.Vulnerabilities.Count} | 弱口令: {camera.WeakPasswords.Count} | 开放端口: {camera.OpenPorts.Count}");
        if (camera.RiskAssessment.TopRemediations.Any())
        {
          sb.AppendLine("修复建议:");
          foreach (var r in camera.RiskAssessment.TopRemediations)
            sb.AppendLine($"  - {r}");
        }
        Clipboard.SetText(sb.ToString());
        ScanStatusText.Text = "状态: 已复制到剪贴板";
      }
      else
      {
        MessageBox.Show("请先在摄像头列表中选择一个设备", "提示", MessageBoxButton.OK, MessageBoxImage.Information);
      }
    }

    private void ContextMenu_CopyIp_Click(object sender, RoutedEventArgs e)
    {
      if (CameraDataGrid.SelectedItem is CameraScanResult camera)
      {
        Clipboard.SetText(camera.Ip);
        ScanStatusText.Text = $"状态: IP {camera.Ip} 已复制到剪贴板";
      }
    }

    private void ContextMenu_OpenBrowser_Click(object sender, RoutedEventArgs e)
    {
      if (CameraDataGrid.SelectedItem is CameraScanResult camera)
      {
        try
        {
          var url = camera.OpenPorts.Any(p => p.Port == 443) ? $"https://{camera.Ip}" : $"http://{camera.Ip}";
          Process.Start(new ProcessStartInfo
          {
            FileName = url,
            UseShellExecute = true
          });
        }
        catch (Exception ex)
        {
          MessageBox.Show($"无法打开浏览器: {ex.Message}", "错误", MessageBoxButton.OK, MessageBoxImage.Error);
        }
      }
    }

    private async void ContextMenu_Rescan_Click(object sender, RoutedEventArgs e)
    {
      if (CameraDataGrid.SelectedItem is CameraScanResult camera)
      {
        var result = MessageBox.Show($"确定要重新扫描 {camera.Ip} 吗？", "确认重扫",
            MessageBoxButton.YesNo, MessageBoxImage.Question);
        if (result != MessageBoxResult.Yes) return;

        SingleIpTextBox.Text = camera.Ip;
        IpRangeTextBox.Text = string.Empty;
        CidrTextBox.Text = string.Empty;

        StartScan_Click(sender, e);
      }
    }

    private void ContextMenu_CopyAll_Click(object sender, RoutedEventArgs e)
    {
      CopyButton_Click(sender, e);
    }

    private void ApplyFilter()
    {
      var filter = FilterTextBox.Text?.Trim() ?? string.Empty;
      if (filter == "🔍 搜索过滤（IP / 厂商 / 型号 / 风险等级）...")
        filter = string.Empty;

      if (CameraDataGrid.ItemsSource is ObservableCollection<CameraScanResult>)
      {
        ICollectionView view = CollectionViewSource.GetDefaultView(CameraDataGrid.ItemsSource);
        if (view != null)
        {
          view.Filter = item =>
          {
            if (string.IsNullOrEmpty(filter))
              return true;

            if (item is not CameraScanResult camera)
              return false;

            return (camera.Ip?.Contains(filter, StringComparison.OrdinalIgnoreCase) ?? false)
                || (camera.Vendor?.Contains(filter, StringComparison.OrdinalIgnoreCase) ?? false)
                || (camera.Model?.Contains(filter, StringComparison.OrdinalIgnoreCase) ?? false)
                || (camera.FirmwareVersion?.Contains(filter, StringComparison.OrdinalIgnoreCase) ?? false)
                || (camera.RiskAssessment?.RiskLevel?.Contains(filter, StringComparison.OrdinalIgnoreCase) ?? false)
                || (camera.SerialNumber?.Contains(filter, StringComparison.OrdinalIgnoreCase) ?? false);
          };
        }
      }
    }

    private void CameraDataGrid_SelectionChanged(object sender, SelectionChangedEventArgs e)
    {
      if (CameraDataGrid.SelectedItem is CameraScanResult camera)
      {
        ShowCameraDetail(camera);
      }
    }

    private void UpdateProgress(CameraScanProgress progress)
    {
      ScanPhaseText.Text = progress.Phase;
      ScanStatusText.Text = $"状态: {progress.Phase} - {progress.Message}";

      if (progress.TotalCount > 0)
      {
        var pct = (double)progress.CompletedCount / progress.TotalCount * 100;
        ScanProgressBar.Value = Math.Min(pct, 100);
        ScanProgressText.Text = $"{pct:F0}%";
      }
    }

    private void DisplayResults(List<CameraScanResult> results)
    {
      var onlineCameras = results.Where(r => r.IsOnline).ToList();

      CameraDataGrid.ItemsSource = new ObservableCollection<CameraScanResult>(onlineCameras);
      ApplyFilter();

      TotalFoundText.Text = $"已发现: {onlineCameras.Count}";
      OnlineCountText.Text = onlineCameras.Count.ToString();

      var criticalCount = onlineCameras.Sum(c => c.RiskAssessment.CriticalCount);
      var highCount = onlineCameras.Sum(c => c.RiskAssessment.HighCount);
      CriticalCountText.Text = criticalCount.ToString();
      HighCountText.Text = highCount.ToString();
      MediumCountText.Text = onlineCameras.Sum(c => c.RiskAssessment.MediumCount).ToString();

      if (onlineCameras.Any())
      {
        var allPorts = new ObservableCollection<CameraPortInfoEx>();
        foreach (var camera in onlineCameras)
        {
          foreach (var port in camera.OpenPorts)
          {
            allPorts.Add(new CameraPortInfoEx
            {
              Ip = camera.Ip,
              Port = port.Port,
              Protocol = port.Protocol,
              Service = port.Service,
              Status = port.Status,
              Banner = port.Banner,
              IsDefaultPort = port.IsDefaultPort,
              RiskLevel = port.RiskLevel
            });
          }
        }
        PortDataGrid.ItemsSource = allPorts;

        var allVulns = new ObservableCollection<CameraVulnerabilityRecord>();
        foreach (var camera in onlineCameras)
        {
          foreach (var vuln in camera.Vulnerabilities)
          {
            allVulns.Add(new CameraVulnerabilityRecord
            {
              CameraIp = camera.Ip,
              CveId = vuln.CveId,
              Name = vuln.Name,
              Severity = vuln.Severity,
              CvssScore = vuln.CvssScore,
              AffectedVendor = vuln.AffectedVendor,
              AffectedVersions = vuln.AffectedVersions,
              FixedVersion = vuln.FixedVersion,
              IsVerified = vuln.IsVerified,
              Solution = vuln.Solution
            });
          }
        }
        VulnDataGrid.ItemsSource = allVulns;

        var allWeakPasswords = new ObservableCollection<CameraWeakPasswordRecord>();
        foreach (var camera in onlineCameras)
        {
          foreach (var wp in camera.WeakPasswords)
          {
            allWeakPasswords.Add(new CameraWeakPasswordRecord
            {
              CameraIp = camera.Ip,
              ServiceType = wp.ServiceType,
              Port = wp.Port,
              Username = wp.Username,
              Password = wp.Password,
              RiskLevel = wp.RiskLevel,
              Suggestion = wp.Suggestion
            });
          }
        }
        WeakPasswordDataGrid.ItemsSource = allWeakPasswords;
      }
    }

    private void ShowCameraDetail(CameraScanResult camera)
    {
      var sb = new StringBuilder();
      sb.AppendLine($"==============================");
      sb.AppendLine($"摄像头详情: {camera.Ip}");
      sb.AppendLine($"==============================");
      sb.AppendLine($"厂商: {camera.Vendor}");
      sb.AppendLine($"型号: {camera.Model}");
      sb.AppendLine($"固件版本: {camera.FirmwareVersion}");
      sb.AppendLine($"在线状态: {(camera.IsOnline ? "在线" : "离线")}");
      sb.AppendLine($"开放端口: {camera.OpenPorts.Count}");
      sb.AppendLine($"漏洞数量: {camera.Vulnerabilities.Count}");
      sb.AppendLine($"弱口令: {camera.WeakPasswords.Count}");
      sb.AppendLine();
      sb.AppendLine("--- 风险评估 ---");
      sb.AppendLine($"综合评分: {camera.RiskAssessment.TotalScore:F1}/100");
      sb.AppendLine($"风险等级: {camera.RiskAssessment.RiskLevel}");
      sb.AppendLine();

      if (camera.RiskAssessment.TopRemediations.Any())
      {
        sb.AppendLine("--- 优先修复建议 ---");
        for (var i = 0; i < camera.RiskAssessment.TopRemediations.Count; i++)
        {
          sb.AppendLine($"{i + 1}. {camera.RiskAssessment.TopRemediations[i]}");
        }
      }

      StatusBarText.Text = sb.ToString().Replace("\n", " | ");
    }

    private void ClearResults()
    {
      CameraDataGrid.ItemsSource = null;
      PortDataGrid.ItemsSource = null;
      VulnDataGrid.ItemsSource = null;
      WeakPasswordDataGrid.ItemsSource = null;
      FilterTextBox.Text = "🔍 搜索过滤（IP / 厂商 / 型号 / 风险等级）...";
      FilterTextBox.Foreground = new System.Windows.Media.SolidColorBrush(
          System.Windows.Media.Color.FromRgb(0x95, 0xA5, 0xA6));
      TotalFoundText.Text = "已发现: 0";
      CriticalCountText.Text = "0";
      HighCountText.Text = "0";
      MediumCountText.Text = "0";
      OnlineCountText.Text = "0";
      ScanPhaseText.Text = "就绪";
    }

    private void SetScanningUIState(bool isScanning)
    {
      StartScanButton.IsEnabled = !isScanning;
      StopScanButton.IsEnabled = isScanning;
      ExportReportButton.IsEnabled = !isScanning && _allResults.Any(r => r.IsOnline);
      ExportJsonButton.IsEnabled = !isScanning && _allResults.Any(r => r.IsOnline);
      CopyButton.IsEnabled = !isScanning;
      FilterTextBox.IsEnabled = !isScanning;
      SingleIpTextBox.IsEnabled = !isScanning;
      IpRangeTextBox.IsEnabled = !isScanning;
      CidrTextBox.IsEnabled = !isScanning;
      ConcurrencyTextBox.IsEnabled = !isScanning;
      TimeoutTextBox.IsEnabled = !isScanning;
      FingerprintCheck.IsEnabled = !isScanning;
      VulnScanCheck.IsEnabled = !isScanning;
      WeakPasswordCheck.IsEnabled = !isScanning;
      ImportTargetsButton.IsEnabled = !isScanning;
      AutoDiscoverButton.IsEnabled = !isScanning;

      if (!isScanning)
      {
        ScanProgressBar.Value = 0;
        ScanProgressText.Text = "0%";
      }
    }

    private void UpdateStatusBar()
    {
      TimeText.Text = DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss");
    }

    private string GenerateReport(string filePath)
    {
      var sb = new StringBuilder();
      var onlineResults = _allResults.Where(r => r.IsOnline).ToList();

      if (filePath.EndsWith(".html", StringComparison.OrdinalIgnoreCase))
      {
        var totalCritical = onlineResults.Sum(c => c.RiskAssessment.CriticalCount);
        var totalHigh = onlineResults.Sum(c => c.RiskAssessment.HighCount);
        var totalMedium = onlineResults.Sum(c => c.RiskAssessment.MediumCount);
        var totalWeakPasswords = onlineResults.Sum(c => c.RiskAssessment.WeakPasswordCount);
        var totalOpenPorts = onlineResults.Sum(c => c.OpenPorts.Count);

        sb.AppendLine("<!DOCTYPE html><html><head><meta charset='UTF-8'>");
        sb.AppendLine("<title>摄像头安全扫描报告</title>");
        sb.AppendLine("<style>body{font-family:'Microsoft YaHei',Arial;margin:20px;background:#f5f5f5}");
        sb.AppendLine("h1{color:#2C3E50;border-bottom:3px solid #27AE60;padding-bottom:10px}");
        sb.AppendLine("h2{color:#2C3E50;margin-top:20px}");
        sb.AppendLine("h3{color:#2C3E50;margin-top:15px}");
        sb.AppendLine(".summary{background:#fff;border:1px solid #ddd;padding:15px;border-radius:6px;margin:10px 0}");
        sb.AppendLine(".summary p{margin:5px 0}");
        sb.AppendLine(".critical{color:#E74C3C;font-weight:bold}");
        sb.AppendLine(".high{color:#E67E22;font-weight:bold}");
        sb.AppendLine(".medium{color:#F39C12}");
        sb.AppendLine(".low{color:#27AE60}");
        sb.AppendLine("table{border-collapse:collapse;width:100%;margin:10px 0;background:white}");
        sb.AppendLine("th{background:#2C3E50;color:white;padding:10px;text-align:left}");
        sb.AppendLine("td{padding:8px;border-bottom:1px solid #ddd}");
        sb.AppendLine("</style></head><body>");
        sb.AppendLine($"<h1>📷 摄像头安全扫描报告</h1>");
        sb.AppendLine($"<div class='summary'>");
        sb.AppendLine($"<h2>📊 扫描汇总</h2>");
        sb.AppendLine($"<p><strong>扫描时间:</strong> {DateTime.Now:yyyy-MM-dd HH:mm:ss}</p>");
        sb.AppendLine($"<p><strong>扫描目标总数:</strong> {_allResults.Count} 台</p>");
        sb.AppendLine($"<p><strong>在线摄像头:</strong> {onlineResults.Count} 台</p>");
        sb.AppendLine($"<p><strong>严重漏洞:</strong> <span class='critical'>{totalCritical}</span> 个 | 高危漏洞: <span class='high'>{totalHigh}</span> 个 | 中危漏洞: <span class='medium'>{totalMedium}</span> 个</p>");
        sb.AppendLine($"<p><strong>发现弱口令:</strong> {totalWeakPasswords} 处 | 开放端口总数: {totalOpenPorts} 个</p>");
        sb.AppendLine($"</div>");

        if (onlineResults.Any(c => c.RiskAssessment.TopRemediations.Any()))
        {
          sb.AppendLine("<h2>🎯 全局修复建议汇总</h2>");
          var allRemediations = onlineResults.SelectMany(c => c.RiskAssessment.TopRemediations)
              .GroupBy(r => r)
              .OrderByDescending(g => g.Count())
              .Select(g => $"{g.Key} (<strong>{g.Count()}</strong> 台设备受影响)")
              .Take(10)
              .ToList();
          sb.AppendLine("<ol>");
          foreach (var r in allRemediations)
          {
            sb.AppendLine($"<li>{r}</li>");
          }
          sb.AppendLine("</ol>");
        }

        foreach (var camera in onlineResults)
        {
          var riskClass = camera.RiskAssessment.RiskLevel switch
          {
            "严重" => "critical",
            "高危" => "high",
            "中危" => "medium",
            _ => "low"
          };
          sb.AppendLine($"<h2>{camera.Ip} - {camera.Vendor} {camera.Model} <span class='{riskClass}'>({camera.RiskAssessment.RiskLevel} - {camera.RiskAssessment.TotalScore:F1}分)</span></h2>");
          sb.AppendLine($"<p>固件版本: {camera.FirmwareVersion} | 序列号: {camera.SerialNumber} | MAC: {camera.Mac}</p>");

          if (camera.OpenPorts.Any())
          {
            sb.AppendLine("<h3>开放端口</h3><table><tr><th>端口</th><th>服务</th><th>风险等级</th></tr>");
            foreach (var p in camera.OpenPorts)
            {
              var portRiskClass = p.RiskLevel == "高危" || p.RiskLevel == "严重" ? "critical" :
                                 p.RiskLevel == "中危" ? "medium" : "low";
              sb.AppendLine($"<tr><td>{p.Port}</td><td>{p.Service}</td><td class='{portRiskClass}'>{p.RiskLevel}</td></tr>");
            }
            sb.AppendLine("</table>");
          }

          if (camera.Vulnerabilities.Any())
          {
            sb.AppendLine("<h3>漏洞信息</h3><table><tr><th>CVE</th><th>名称</th><th>严重等级</th><th>CVSS</th><th>修复建议</th></tr>");
            foreach (var v in camera.Vulnerabilities)
            {
              var severityClass = v.Severity switch
              {
                "Critical" => "critical",
                "High" => "high",
                "Medium" => "medium",
                _ => "low"
              };
              sb.AppendLine($"<tr><td>{v.CveId}</td><td>{v.Name}</td><td class='{severityClass}'>{v.Severity}</td><td>{v.CvssScore}</td><td>{v.Solution}</td></tr>");
            }
            sb.AppendLine("</table>");
          }

          if (camera.WeakPasswords.Any())
          {
            sb.AppendLine("<h3>弱口令</h3><table><tr><th>服务</th><th>端口</th><th>用户名</th><th>密码</th><th>风险等级</th><th>修复建议</th></tr>");
            foreach (var wp in camera.WeakPasswords)
            {
              sb.AppendLine($"<tr><td>{wp.ServiceType}</td><td>{wp.Port}</td><td>{wp.Username}</td><td>{wp.Password}</td><td>{wp.RiskLevel}</td><td>{wp.Suggestion}</td></tr>");
            }
            sb.AppendLine("</table>");
          }

          if (camera.RiskAssessment.TopRemediations.Any())
          {
            sb.AppendLine("<h3>优先修复建议</h3><ol>");
            foreach (var r in camera.RiskAssessment.TopRemediations)
            {
              sb.AppendLine($"<li>{r}</li>");
            }
            sb.AppendLine("</ol>");
          }
        }
        sb.AppendLine("<hr><p style='color:#888'>生成自 NetSecurityScanner v1.0.1.0 摄像头安全扫描模块</p>");
        sb.AppendLine("</body></html>");
      }
      else if (filePath.EndsWith(".csv", StringComparison.OrdinalIgnoreCase))
      {
        sb.AppendLine("IP,厂商,型号,固件版本,风险等级,风险评分,严重漏洞,高危漏洞,中危漏洞,漏洞总数,弱口令数,开放端口数");
        foreach (var camera in onlineResults)
        {
          var vendor = camera.Vendor.Replace(",", ";");
          var model = camera.Model.Replace(",", ";");
          var firmware = camera.FirmwareVersion.Replace(",", ";");
          sb.AppendLine($"{camera.Ip},{vendor},{model},{firmware},{camera.RiskAssessment.RiskLevel},{camera.RiskAssessment.TotalScore:F1}," +
                      $"{camera.RiskAssessment.CriticalCount},{camera.RiskAssessment.HighCount},{camera.RiskAssessment.MediumCount}," +
                      $"{camera.Vulnerabilities.Count},{camera.WeakPasswords.Count},{camera.OpenPorts.Count}");
        }
      }
      else
      {
        var totalCritical = onlineResults.Sum(c => c.RiskAssessment.CriticalCount);
        var totalHigh = onlineResults.Sum(c => c.RiskAssessment.HighCount);
        var totalMedium = onlineResults.Sum(c => c.RiskAssessment.MediumCount);

        sb.AppendLine("摄像头安全扫描报告");
        sb.AppendLine($"扫描时间: {DateTime.Now:yyyy-MM-dd HH:mm:ss}");
        sb.AppendLine($"扫描总数: {_allResults.Count} | 在线: {onlineResults.Count} | 严重漏洞: {totalCritical} | 高危漏洞: {totalHigh} | 中危漏洞: {totalMedium}");
        sb.AppendLine(new string('=', 80));

        foreach (var camera in onlineResults)
        {
          sb.AppendLine($"\n{camera.Ip} - {camera.Vendor} {camera.Model}");
          sb.AppendLine($"  固件: {camera.FirmwareVersion} | 风险: {camera.RiskAssessment.RiskLevel} | 评分: {camera.RiskAssessment.TotalScore:F1}");
          sb.AppendLine($"  严重漏洞: {camera.RiskAssessment.CriticalCount} | 高危: {camera.RiskAssessment.HighCount} | 中危: {camera.RiskAssessment.MediumCount} | 弱口令: {camera.WeakPasswords.Count}");
          if (camera.OpenPorts.Any())
          {
            sb.AppendLine($"  开放端口: {string.Join(", ", camera.OpenPorts.Select(p => $"{p.Port}({p.Service})"))}");
          }
          if (camera.Vulnerabilities.Any())
          {
            sb.AppendLine("  漏洞:");
            foreach (var v in camera.Vulnerabilities)
              sb.AppendLine($"    [{v.Severity}] {v.CveId} - {v.Name} (CVSS {v.CvssScore})");
          }
          if (camera.WeakPasswords.Any())
          {
            sb.AppendLine("  弱口令:");
            foreach (var wp in camera.WeakPasswords)
              sb.AppendLine($"    {wp.ServiceType}:{wp.Port} {wp.Username}:{wp.Password}");
          }
        }
      }

      return sb.ToString();
    }
  }

  public class CameraPortInfoEx
  {
    public string Ip { get; set; } = string.Empty;
    public int Port { get; set; }
    public string Protocol { get; set; } = string.Empty;
    public string Service { get; set; } = string.Empty;
    public string Status { get; set; } = string.Empty;
    public string Banner { get; set; } = string.Empty;
    public bool IsDefaultPort { get; set; }
    public string RiskLevel { get; set; } = string.Empty;
  }

  public class CameraVulnerabilityRecord
  {
    public string CameraIp { get; set; } = string.Empty;
    public string CveId { get; set; } = string.Empty;
    public string Name { get; set; } = string.Empty;
    public string Severity { get; set; } = string.Empty;
    public double CvssScore { get; set; }
    public string AffectedVendor { get; set; } = string.Empty;
    public string AffectedVersions { get; set; } = string.Empty;
    public string FixedVersion { get; set; } = string.Empty;
    public bool IsVerified { get; set; }
    public string Solution { get; set; } = string.Empty;
  }

  public class CameraWeakPasswordRecord
  {
    public string CameraIp { get; set; } = string.Empty;
    public string ServiceType { get; set; } = string.Empty;
    public int Port { get; set; }
    public string Username { get; set; } = string.Empty;
    public string Password { get; set; } = string.Empty;
    public string RiskLevel { get; set; } = string.Empty;
    public string Suggestion { get; set; } = string.Empty;
  }
}