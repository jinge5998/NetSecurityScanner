using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Diagnostics;
using System.Globalization;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Input;
using System.Windows.Media;
using NetSecurityScanner.Core;
using NetSecurityScanner.Models;
using NetSecurityScanner.Services;

namespace NetSecurityScanner.Views
{
  public partial class CameraSecurityScannerWindow : Window
  {
    private CancellationTokenSource? _cts;
    private Stopwatch? _elapsedTimer;
    private readonly List<CameraScanResult> _allResults = new();
    private readonly CameraScanHistoryService _historyService = new();
    private readonly CameraReportExportService _exportService = new();
    private readonly CameraScanRecommendationEngine _recommendationEngine = new();
    // v4 支持服务
    private readonly CameraTagService _tagService = new();
    private readonly CameraTrendService _trendService = new();
    private List<string> _currentTargetIps = new();
    private string _currentPresetName = "标准扫描";
    // v4 上下文
    private List<CameraTag> _cachedTags = new();

    public CameraSecurityScannerWindow()
    {
      try
      {
        InitializeComponent();
        LoadPresets();
        ApplyPreset(1);
        LoadTemplates();
        LoadTagFilter();
        LoadTrendPreview();
      }
      catch (Exception ex)
      {
        var logDir = System.IO.Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "logs");
        System.IO.Directory.CreateDirectory(logDir);
        var logFile = System.IO.Path.Combine(logDir, $"app_{DateTime.Now:yyyyMMdd}.log");
        var fullError = $"CameraSecurityScannerWindow InitializeComponent失败: {ex.GetType().FullName}: {ex.Message}\n堆栈: {ex.StackTrace}";
        if (ex.InnerException != null)
          fullError += $"\n内部异常: {ex.InnerException.GetType().FullName}: {ex.InnerException.Message}\n内部堆栈: {ex.InnerException.StackTrace}";
        System.IO.File.AppendAllText(logFile, $"[{DateTime.Now:HH:mm:ss.fff}] {fullError}{Environment.NewLine}");
        throw;
      }
      UpdateStatusBar();
    }

    private void LoadTemplates()
    {
      if (TemplateComboBox == null) return;
      TemplateComboBox.Items.Clear();
      var templateService = new CameraScanTemplateService();
      foreach (var t in templateService.Templates)
      {
        TemplateComboBox.Items.Add($"{t.Name} - {t.Description}");
      }
      TemplateComboBox.SelectedIndex = -1;
    }

    private void TemplateComboBox_SelectionChanged(object sender, System.Windows.Controls.SelectionChangedEventArgs e)
    {
      if (TemplateComboBox?.SelectedIndex < 0) return;
      var templates = CameraScanTemplate.GetDefaultTemplates();
      if (TemplateComboBox.SelectedIndex >= templates.Count) return;
      var t = templates[TemplateComboBox.SelectedIndex];
      ScanStatusText.Text = $"状态: 已选择模板 [{t.Name}] - 端口: {string.Join(",", t.Ports)}";
    }

    // ============================================================
    // v4 主窗口集成：标签/弱口令/趋势/Dashboard
    // ============================================================

    /// <summary>
    /// v4-T2.5: 把现有标签加载到 "按标签过滤" 下拉框。
    /// </summary>
    private void LoadTagFilter()
    {
      try
      {
        if (TagFilterComboBox == null) return;
        _cachedTags = _tagService.GetAll();
        TagFilterComboBox.Items.Clear();
        TagFilterComboBox.Items.Add(new ComboBoxItem { Content = "（全部）", Tag = string.Empty, IsSelected = true });
        foreach (var t in _cachedTags)
        {
          TagFilterComboBox.Items.Add(new ComboBoxItem { Content = t.Name, Tag = t.TagId });
        }
        TagFilterComboBox.DisplayMemberPath = "Content";
      }
      catch (Exception ex)
      {
        WriteDiagLog($"LoadTagFilter 异常: {ex.Message}");
      }
    }

    /// <summary>
    /// v4-T5.4: 历史趋势预览（Dashboard 折叠后此函数为占位实现，仅记录日志）。
    /// </summary>
    private void LoadTrendPreview()
    {
      try
      {
        // Dashboard 区域已从主窗口移除，趋势预览通过历史趋势窗口查看
        System.Diagnostics.Debug.WriteLine("[CameraScan] LoadTrendPreview (Dashboard hidden, use 高级 → 历史趋势)");
      }
      catch (Exception ex)
      {
        WriteDiagLog($"LoadTrendPreview 异常: {ex.Message}");
      }
    }

    /// <summary>
    /// v4-T1.4: 扫描完成后刷新顶部 RiskDashboard + 厂商柱图 + 风险仪表。
    /// 当前 UI 已简化（Dashboard 折叠），仅记录统计信息，不再更新控件。
    /// </summary>
    private void UpdateDashboard(CameraScanStatistics stat)
    {
      try
      {
        if (stat == null) stat = new CameraScanStatistics();
        // Dashboard 区域已从主窗口移除，统计仅写入日志，供高级视图使用
        System.Diagnostics.Debug.WriteLine($"[CameraDashboard] Total={stat.Total} Online={stat.Online} Risk={stat.RiskDistribution?.Count ?? 0} VendorTop={stat.VendorTopN?.Count ?? 0}");
      }
      catch (Exception ex)
      {
        WriteDiagLog($"UpdateDashboard 异常: {ex.Message}");
      }
    }

    /// <summary>
    /// v4-T2.4: 打开 "标签管理" 窗口。
    /// </summary>
    private void TagManageButton_Click(object sender, RoutedEventArgs e)
    {
      try
      {
        var w = new CameraTagManageWindow { Owner = this };
        w.ShowDialog();
        // 关闭后刷新下拉
        LoadTagFilter();
        ScanStatusText.Text = "状态: 已返回标签管理，标签下拉已刷新";
      }
      catch (Exception ex)
      {
        MessageBox.Show($"打开标签管理失败: {ex.Message}", "错误", MessageBoxButton.OK, MessageBoxImage.Error);
      }
    }

    /// <summary>
    /// v4-T4.4: 打开 "弱口令字典编辑器" 窗口。
    /// </summary>
    private void WeakPwdButton_Click(object sender, RoutedEventArgs e)
    {
      try
      {
        var w = new CameraWeakPasswordEditorWindow { Owner = this };
        w.ShowDialog();
        ScanStatusText.Text = "状态: 已返回弱口令编辑器";
      }
      catch (Exception ex)
      {
        MessageBox.Show($"打开弱口令编辑器失败: {ex.Message}", "错误", MessageBoxButton.OK, MessageBoxImage.Error);
      }
    }

    /// <summary>
    /// v4-T5.4: 打开 "历史趋势" 窗口。
    /// </summary>
    private void TrendButton_Click(object sender, RoutedEventArgs e)
    {
      try
      {
        var w = new CameraTrendWindow { Owner = this };
        w.ShowDialog();
        // 返回时刷新主窗口迷你趋势
        LoadTrendPreview();
        ScanStatusText.Text = "状态: 已返回历史趋势窗口";
      }
      catch (Exception ex)
      {
        MessageBox.Show($"打开历史趋势失败: {ex.Message}", "错误", MessageBoxButton.OK, MessageBoxImage.Error);
      }
    }

    /// <summary>
    /// 高级按钮点击：弹出高级工具菜单（标签/弱口令/趋势/统计图表）。
    /// </summary>
    private void AdvancedMenuButton_Click(object sender, RoutedEventArgs e)
    {
      try
      {
        if (sender is System.Windows.Controls.Button btn && btn.ContextMenu != null)
        {
          btn.ContextMenu.PlacementTarget = btn;
          btn.ContextMenu.Placement = System.Windows.Controls.Primitives.PlacementMode.Bottom;
          btn.ContextMenu.IsOpen = true;
        }
      }
      catch (Exception ex)
      {
        WriteDiagLog($"AdvancedMenuButton 异常: {ex.Message}");
      }
    }

    /// <summary>
    /// 显示/隐藏顶部统计图表（Dashboard 折叠开关）。
    /// </summary>
    private void ShowDashboardButton_Click(object sender, RoutedEventArgs e)
    {
      try
      {
        // 折叠/展开 Dashboard 区域：当前未默认显示 Dashboard，此项为占位开关
        if (sender is System.Windows.Controls.MenuItem mi)
        {
          mi.IsChecked = !mi.IsChecked;
          ScanStatusText.Text = mi.IsChecked
            ? "状态: 已开启统计图表（当前为简化版，未来可扩展）"
            : "状态: 已隐藏统计图表";
        }
      }
      catch (Exception ex)
      {
        WriteDiagLog($"ShowDashboardButton 异常: {ex.Message}");
      }
    }

    /// <summary>
    /// v4-T2.5: 按标签过滤当前结果。
    /// </summary>
    private void TagFilterComboBox_SelectionChanged(object sender, System.Windows.Controls.SelectionChangedEventArgs e)
    {
      ApplyFilter();
    }

    /// <summary>
    /// 工具栏: 按风险等级过滤(全部/严重/高危/中危/低危/安全/仅有弱口令)
    /// </summary>
    private void RiskFilterComboBox_SelectionChanged(object sender, System.Windows.Controls.SelectionChangedEventArgs e)
    {
      ApplyFilter();
    }

    /// <summary>
    /// 工具栏: 一键清空所有过滤条件(搜索/标签/风险等级)
    /// </summary>
    private void ClearFilterButton_Click(object sender, RoutedEventArgs e)
    {
      try
      {
        // 清空搜索框
        if (FilterTextBox != null)
        {
          FilterTextBox.Text = string.Empty;
          // 触发失焦效果(显示占位符)
          FilterTextBox_LostFocus(FilterTextBox, new RoutedEventArgs());
        }

        // 还原标签过滤为"全部"
        if (TagFilterComboBox != null && TagFilterComboBox.Items.Count > 0)
        {
          TagFilterComboBox.SelectedIndex = 0;
        }

        // 还原风险过滤为"全部"
        if (RiskFilterComboBox != null && RiskFilterComboBox.Items.Count > 0)
        {
          RiskFilterComboBox.SelectedIndex = 0;
        }

        // 取消按标签分组
        if (GroupByTagCheck != null)
        {
          GroupByTagCheck.IsChecked = false;
        }

        ApplyFilter();
        ScanStatusText.Text = "状态: 已清空所有过滤条件";
      }
      catch (Exception ex)
      {
        WriteDiagLog($"ClearFilterButton_Click 异常: {ex.Message}");
      }
    }

    /// <summary>
    /// v4-T2.5: 按标签分组排序（同一标签的 IP 排在一起）。
    /// </summary>
    private void GroupByTagCheck_Changed(object sender, RoutedEventArgs e)
    {
      ApplyFilter();
    }

    /// <summary>
    /// v4-T3.3: 双击行打开详情窗口。
    /// </summary>
    private void ResultsDataGrid_MouseDoubleClick(object sender, System.Windows.Input.MouseButtonEventArgs e)
    {
      try
      {
        if (CameraDataGrid?.SelectedItem is CameraScanResult camera)
        {
          OpenDetailWindow(camera);
        }
      }
      catch (Exception ex)
      {
        WriteDiagLog($"ResultsDataGrid_MouseDoubleClick 异常: {ex.Message}");
      }
    }

    /// <summary>
    /// v4-T3.2: 右键 "查看详情" 菜单。
    /// </summary>
    private void ContextViewDetail_Click(object sender, RoutedEventArgs e)
    {
      if (CameraDataGrid?.SelectedItem is CameraScanResult camera)
      {
        OpenDetailWindow(camera);
      }
    }

    /// <summary>
    /// v4-T3.2: 右键 "复制 IP" 菜单。
    /// </summary>
    private void ContextCopyIp_Click(object sender, RoutedEventArgs e)
    {
      if (CameraDataGrid?.SelectedItem is CameraScanResult camera)
      {
        try
        {
          Clipboard.SetText(camera.Ip ?? string.Empty);
          ScanStatusText.Text = $"状态: 已复制 IP {camera.Ip}";
        }
        catch { }
      }
    }

    /// <summary>
    /// v4-T3.2: 右键 "复制 CVE" 菜单。
    /// </summary>
    private void ContextCopyCve_Click(object sender, RoutedEventArgs e)
    {
      if (CameraDataGrid?.SelectedItem is CameraScanResult camera)
      {
        var cves = camera.Vulnerabilities?
            .Where(v => !string.IsNullOrWhiteSpace(v.CveId))
            .Select(v => v.CveId)
            .Distinct()
            .ToList();
        if (cves == null || cves.Count == 0)
        {
          MessageBox.Show("当前设备无 CVE 漏洞可复制", "提示", MessageBoxButton.OK, MessageBoxImage.Information);
          return;
        }
        try
        {
          var text = string.Join(Environment.NewLine, cves);
          Clipboard.SetText(text);
          ScanStatusText.Text = $"状态: 已复制 {cves.Count} 个 CVE";
        }
        catch { }
      }
    }

    /// <summary>
    /// v4-T3.2: 右键 "过滤同厂商" 菜单。
    /// </summary>
    private void ContextFilterSameVendor_Click(object sender, RoutedEventArgs e)
    {
      if (CameraDataGrid?.SelectedItem is CameraScanResult camera)
      {
        if (string.IsNullOrWhiteSpace(camera.Vendor))
        {
          MessageBox.Show("当前设备厂商为空，无法过滤", "提示", MessageBoxButton.OK, MessageBoxImage.Information);
          return;
        }
        // 把厂商名作为关键字写入 FilterTextBox 触发过滤
        if (FilterTextBox != null)
        {
          FilterTextBox.Text = camera.Vendor.Trim();
          FilterTextBox.Foreground = Brushes.Black;
        }
        ScanStatusText.Text = $"状态: 已按厂商 [{camera.Vendor}] 过滤";
      }
    }

    /// <summary>
    /// v4-T3.2: 右键 "跳转 NVD 详情" 菜单。
    /// </summary>
    private void ContextOpenNvd_Click(object sender, RoutedEventArgs e)
    {
      if (CameraDataGrid?.SelectedItem is CameraScanResult camera)
      {
        var cve = camera.Vulnerabilities?
            .Where(v => !string.IsNullOrWhiteSpace(v.CveId))
            .Select(v => v.CveId)
            .FirstOrDefault();
        if (string.IsNullOrEmpty(cve))
        {
          MessageBox.Show("当前设备无 CVE 可跳转", "提示", MessageBoxButton.OK, MessageBoxImage.Information);
          return;
        }
        try
        {
          var url = $"https://nvd.nist.gov/vuln/detail/{cve}";
          Process.Start(new ProcessStartInfo { FileName = url, UseShellExecute = true });
          ScanStatusText.Text = $"状态: 已打开 NVD 详情 - {cve}";
        }
        catch (Exception ex)
        {
          MessageBox.Show($"无法打开浏览器: {ex.Message}", "错误", MessageBoxButton.OK, MessageBoxImage.Error);
        }
      }
    }

    /// <summary>
    /// 打开摄像头详情窗口。
    /// </summary>
    private void OpenDetailWindow(CameraScanResult camera)
    {
      try
      {
        if (camera == null) return;
        var w = new CameraDetailWindow(camera) { Owner = this };
        w.ShowDialog();
      }
      catch (Exception ex)
      {
        MessageBox.Show($"打开详情窗口失败: {ex.Message}", "错误", MessageBoxButton.OK, MessageBoxImage.Error);
      }
    }

    private async void MonitorButton_Click(object sender, RoutedEventArgs e)
    {
      var targetInput = TargetInputTextBox?.Text?.Trim();
      if (string.IsNullOrEmpty(targetInput))
      {
        MessageBox.Show("请先输入要监控的 IP 列表", "提示", MessageBoxButton.OK, MessageBoxImage.Information);
        return;
      }

      var dialog = new CameraMonitorDialog();
      if (dialog.ShowDialog() != true) return;

      var monitorService = new CameraMonitorService();
      monitorService.OnAlert += (s, alert) => Dispatcher.Invoke(() =>
        ScanStatusText.Text = $"🔔 告警: {alert.Title} - {alert.Message}");

      var task = new CameraMonitorTask
      {
        Name = $"监控-{targetInput}",
        TargetIps = targetInput.Split(',', ';').Select(s => s.Trim()).ToList(),
        IntervalMinutes = dialog.IntervalMinutes,
        Preset = _currentPresetName,
        NotifyOnOffline = true,
        NotifyOnNewVulnerability = true,
        SoundAlert = dialog.EnableSound
      };
      monitorService.AddTask(task);
      monitorService.Start();
      ScanStatusText.Text = $"状态: 已启动持续监控，每 {dialog.IntervalMinutes} 分钟扫描一次";
      MessageBox.Show($"持续监控已启动，间隔 {dialog.IntervalMinutes} 分钟\n任务ID: {task.TaskId}", "监控中", MessageBoxButton.OK, MessageBoxImage.Information);
    }

    private void AlertsButton_Click(object sender, RoutedEventArgs e)
    {
      var service = new CameraAlertService();
      var alerts = service.GetRecent(50);
      if (alerts.Count == 0)
      {
        MessageBox.Show("暂无告警", "告警历史", MessageBoxButton.OK, MessageBoxImage.Information);
        return;
      }

      var sb = new StringBuilder();
      sb.AppendLine($"=== 告警历史 (共 {alerts.Count} 条) ===\n");
      foreach (var a in alerts.Take(20))
      {
        sb.AppendLine($"[{a.Level}] {a.Title}");
        sb.AppendLine($"  IP: {a.Ip} | {a.CreatedTime:yyyy-MM-dd HH:mm:ss}");
        sb.AppendLine($"  {a.Message}\n");
      }
      MessageBox.Show(sb.ToString(), "告警历史", MessageBoxButton.OK, MessageBoxImage.Information);
    }

    private void LoadPresets()
    {
      if (PresetComboBox == null) return;
      PresetComboBox.Items.Clear();
      foreach (var preset in CameraScanPreset.GetDefaultPresets())
      {
        PresetComboBox.Items.Add(preset.Name);
      }
      PresetComboBox.SelectedIndex = 1;
    }

    private void ApplyPreset(int index)
    {
      var presets = CameraScanPreset.GetDefaultPresets();
      if (index < 0 || index >= presets.Count) return;
      var preset = presets[index];
      _currentPresetName = preset.Name;

      if (FingerprintCheck != null) FingerprintCheck.IsChecked = preset.EnableFingerprint;
      if (VulnScanCheck != null) VulnScanCheck.IsChecked = preset.EnableVulnerabilityScan;
      if (WeakPasswordCheck != null) WeakPasswordCheck.IsChecked = preset.EnableWeakPasswordScan;
      if (AggressiveScanCheck != null) AggressiveScanCheck.IsChecked = preset.EnableAggressiveScan;
      if (ConcurrencyTextBox != null) ConcurrencyTextBox.Text = preset.MaxConcurrency.ToString();
      if (TimeoutTextBox != null) TimeoutTextBox.Text = preset.TimeoutMs.ToString();
    }

    private void PresetComboBox_SelectionChanged(object sender, System.Windows.Controls.SelectionChangedEventArgs e)
    {
      if (PresetComboBox?.SelectedItem is string name)
      {
        ApplyPreset(PresetComboBox.SelectedIndex);
        ScanStatusText.Text = $"状态: 已选择扫描预设 [{name}]";
      }
    }

    private void RecommendButton_Click(object sender, RoutedEventArgs e)
    {
      var targetInput = TargetInputTextBox.Text?.Trim() ?? string.Empty;
      var mode = ScanModeComboBox?.SelectedIndex ?? 0;
      var sampleCount = 0;

      try
      {
        var probeOptions = new CameraScanOptions
        {
          TargetIp = mode == 0 ? targetInput : string.Empty,
          IpRange = mode == 1 ? targetInput : string.Empty,
          CidrNotation = mode == 2 ? targetInput : string.Empty
        };
        sampleCount = CameraScannerService.EstimateIpCount(probeOptions);
      }
      catch { sampleCount = 50; }

      var rec = _recommendationEngine.Recommend(sampleCount);
      ApplyPreset(CameraScanPreset.GetDefaultPresets().FindIndex(p => p.Name == rec.Preset.Name));
      RecommendationText.Text = $"💡 {rec.Reason} | 预计 {rec.EstimatedSeconds}秒，覆盖{rec.Coverage}";
      ScanStatusText.Text = $"状态: 已应用智能推荐 - {rec.Preset.Name}";
    }

    private async void StartScan_Click(object sender, RoutedEventArgs e)
    {
      WriteDiagLog("=== 点击开始扫描 ===");
      try
      {
        if (TargetInputTextBox == null)
        {
          WriteDiagLog("严重错误: TargetInputTextBox 为 null");
          MessageBox.Show("界面未初始化完成", "错误", MessageBoxButton.OK, MessageBoxImage.Error);
          return;
        }
        if (ScanModeComboBox == null)
        {
          WriteDiagLog("严重错误: ScanModeComboBox 为 null");
          MessageBox.Show("界面未初始化完成", "错误", MessageBoxButton.OK, MessageBoxImage.Error);
          return;
        }

        var scanMode = ScanModeComboBox.SelectedIndex;
        var targetInput = TargetInputTextBox.Text?.Trim() ?? string.Empty;
        WriteDiagLog($"目标: '{targetInput}', 模式: {scanMode}, UI线程: {Dispatcher.CheckAccess()}");

        string targetIp = string.Empty, ipRange = string.Empty, cidr = string.Empty;

        switch (scanMode)
        {
          case 0:
            targetIp = targetInput;
            break;
          case 1:
            ipRange = targetInput;
            break;
          case 2:
            cidr = targetInput;
            break;
        }

        if (string.IsNullOrEmpty(targetIp) && string.IsNullOrEmpty(ipRange) && string.IsNullOrEmpty(cidr))
        {
          WriteDiagLog("用户输入为空, 提示错误并返回");
          MessageBox.Show("请输入目标（单IP、IP段 或 CIDR）", "输入错误", MessageBoxButton.OK, MessageBoxImage.Warning);
          return;
        }

        var options = new CameraScanOptions
        {
          TargetIp = targetIp,
          IpRange = ipRange,
          CidrNotation = cidr,
          Ipv6Cidr = cidr.Contains(":") ? cidr : string.Empty,
          EnableFingerprint = FingerprintCheck?.IsChecked ?? true,
          EnableVulnerabilityScan = VulnScanCheck?.IsChecked ?? true,
          EnableWeakPasswordScan = WeakPasswordCheck?.IsChecked ?? true,
          MaxConcurrency = int.TryParse(ConcurrencyTextBox?.Text, out var c) ? c : 30,
          TimeoutMs = int.TryParse(TimeoutTextBox?.Text, out var t) ? t : 3000,
          UseDefaultPorts = true
        };
        WriteDiagLog($"扫描选项构建完成: TP='{targetIp}', IR='{ipRange}', CIDR='{cidr}'");

        SetScanningUIState(true);
        _allResults.Clear();
        ClearResults();

        _cts = new CancellationTokenSource();
        _elapsedTimer = Stopwatch.StartNew();
        WriteDiagLog("CTS 创建, 计时器启动, 进入扫描循环");

        try
        {
          WriteDiagLog("实例化 CameraScannerService...");
          var service = new CameraScannerService();
          try
          {
            var progress = new Progress<CameraScanProgress>(p =>
            {
              Dispatcher.Invoke(() => UpdateProgress(p));
            });

            WriteDiagLog("调用 Task.Run 启动 ScanCamerasAsync...");
            var results = await Task.Run(() => service.ScanCamerasAsync(options, progress, _cts.Token));
            WriteDiagLog($"ScanCamerasAsync 返回, 共 {results?.Count ?? 0} 个结果");
            _allResults.AddRange(results ?? new List<CameraScanResult>());
            _currentTargetIps = ExtractTargetIps(options);
            WriteDiagLog($"目标 IP 解析: {_currentTargetIps?.Count ?? 0} 个" +
                (_currentTargetIps?.Count > 0 ? $" (前5: {string.Join(",", _currentTargetIps.Take(5))}{(_currentTargetIps.Count > 5 ? "..." : "")})" : ""));

            await Dispatcher.InvokeAsync(() =>
            {
              DisplayResults(results ?? new List<CameraScanResult>());
              ScanStatusText.Text = "状态: 扫描完成";
              ScanProgressBar.Value = 100;
              ScanProgressText.Text = "100%";
              ExportReportButton.IsEnabled = results?.Any(r => r.IsOnline) ?? false;
              ExportCsvButton.IsEnabled = results?.Any(r => r.IsOnline) ?? false;
              ExportDetailJsonButton.IsEnabled = results?.Any(r => r.IsOnline) ?? false;
            });
            WriteDiagLog("UI 更新完成");

            // 扫描完成后自动保存到历史
            if (results != null && results.Any(r => r.IsOnline))
            {
              _ = SaveToHistoryAsync();
              WriteDiagLog("已触发自动保存历史");
            }
          }
          finally
          {
            service.Dispose();
            WriteDiagLog("Service 已释放");
          }
        }
        catch (OperationCanceledException)
        {
          WriteDiagLog("=== 扫描已取消 ===");
          ScanStatusText.Text = "状态: 扫描已取消";
        }
        catch (Exception ex)
        {
          var errorMsg = $"扫描失败: {ex.GetType().FullName}: {ex.Message}";
          WriteDiagLog($"=== 扫描异常 === {errorMsg}");
          WriteDiagLog($"堆栈: {ex.StackTrace}");
          if (ex.InnerException != null)
          {
            WriteDiagLog($"内部异常: {ex.InnerException.GetType().FullName}: {ex.InnerException.Message}");
            WriteDiagLog($"内部堆栈: {ex.InnerException.StackTrace}");
          }
          ScanStatusText.Text = "状态: 扫描失败";
          MessageBox.Show(errorMsg, "错误", MessageBoxButton.OK, MessageBoxImage.Error);
        }
        finally
        {
          _cts?.Dispose();
          _cts = null;
          _elapsedTimer?.Stop();
          SetScanningUIState(false);
          UpdateStatusBar();
          WriteDiagLog("=== 扫描流程结束 (finally) ===");
        }
      }
      catch (Exception ex)
      {
        WriteDiagLog($"=== StartScan_Click 顶层异常 === {ex.GetType().FullName}: {ex.Message}");
        WriteDiagLog($"堆栈: {ex.StackTrace}");
        try
        {
          MessageBox.Show($"启动扫描失败: {ex.Message}", "错误", MessageBoxButton.OK, MessageBoxImage.Error);
        }
        catch { }
      }
    }

    private void WriteDiagLog(string message)
    {
      try
      {
        var logDir = System.IO.Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "logs");
        System.IO.Directory.CreateDirectory(logDir);
        var logFile = System.IO.Path.Combine(logDir, "camera_diag.log");
        var line = $"[{DateTime.Now:HH:mm:ss.fff}] {message}{Environment.NewLine}";
        System.IO.File.AppendAllText(logFile, line);
        System.Diagnostics.Debug.WriteLine(line);
      }
      catch { /* 静默 */ }
    }

    private void StopScan_Click(object sender, RoutedEventArgs e)
    {
      WriteDiagLog("=== 点击停止扫描 ===");
      if (_cts == null)
      {
        WriteDiagLog("停止忽略: _cts 为 null (无正在进行的扫描)");
        return;
      }
      try
      {
        _cts.Cancel();
        WriteDiagLog("已调用 _cts.Cancel()，等待子任务响应...");
      }
      catch (ObjectDisposedException)
      {
        WriteDiagLog("停止忽略: _cts 已被释放");
      }
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

          ScanModeComboBox.SelectedIndex = 1;
          TargetInputTextBox.Text = string.Join(",", ips);
          ScanStatusText.Text = $"状态: 已导入 {ips.Count} 个目标IP";
        }
        catch (Exception ex)
        {
          MessageBox.Show($"导入失败: {ex.Message}", "错误", MessageBoxButton.OK, MessageBoxImage.Error);
        }
      }
    }

    private async void AutoDiscover_Click(object sender, RoutedEventArgs e)
    {
      AutoDiscoverButton.IsEnabled = false;
      SetScanningUIState(true);
      ScanStatusText.Text = "状态: 正在自动发现摄像头...";
      ScanPhaseText.Text = "自动发现";
      ScanProgressBar.IsIndeterminate = true;
      _allResults.Clear();
      ClearResults();

      try
      {
        using var discoveryService = new CameraDiscoveryService();
        var discoveredCameras = new List<DiscoveredCamera>();

        discoveryService.CameraDiscovered += camera =>
        {
          Dispatcher.Invoke(() =>
          {
            discoveredCameras.Add(camera);
            ScanStatusText.Text = $"状态: 发现 {discoveredCameras.Count} 台设备 - {camera.Ip} ({camera.DiscoveryMethod})";
          });
        };

        var cts = new CancellationTokenSource(TimeSpan.FromSeconds(30));
        var results = await Task.Run(() => discoveryService.DiscoverAsync(15000, cts.Token));

        if (results.Count == 0)
        {
          MessageBox.Show("未发现摄像头设备。\n\n可能原因：\n1. 网络中没有启用了UPnP/ONVIF的摄像头\n2. 防火墙或VLAN隔离了发现协议\n3. 摄像头未接入同一局域网\n\n建议：手动输入IP范围进行扫描", "自动发现结果", MessageBoxButton.OK, MessageBoxImage.Information);
          return;
        }

        var sb = new StringBuilder();
        sb.AppendLine($"自动发现完成，共发现 {results.Count} 台设备：\n");
        foreach (var cam in results)
        {
          sb.AppendLine($"  {cam.Ip}  [{cam.DiscoveryMethod}]  {(string.IsNullOrEmpty(cam.Vendor) ? "" : cam.Vendor)}  {(string.IsNullOrEmpty(cam.DeviceName) ? "" : cam.DeviceName)}  {(string.IsNullOrEmpty(cam.Model) ? "" : cam.Model)}");
        }
        sb.AppendLine("\n是否立即对发现的设备执行完整扫描？");

        var dialogResult = MessageBox.Show(sb.ToString(), "自动发现结果", MessageBoxButton.YesNo, MessageBoxImage.Question);

        if (dialogResult == MessageBoxResult.Yes)
        {
          ScanModeComboBox.SelectedIndex = 0;
          var ipList = string.Join(",", results.Select(r => r.Ip));
          TargetInputTextBox.Text = results.Count == 1 ? results[0].Ip : ipList;

          if (results.Count == 1)
          {
            StartScan_Click(sender, e);
          }
          else
          {
            ImportTargets_Click(sender, e);
            StartScan_Click(sender, e);
          }
        }
        else
        {
          ScanStatusText.Text = $"状态: 发现 {results.Count} 台设备（就绪）";
          SetScanningUIState(false);
        }
      }
      catch (OperationCanceledException)
      {
        ScanStatusText.Text = "状态: 自动发现超时";
        SetScanningUIState(false);
      }
      catch (Exception ex)
      {
        ScanStatusText.Text = "状态: 自动发现失败";
        MessageBox.Show($"自动发现失败: {ex.Message}", "错误", MessageBoxButton.OK, MessageBoxImage.Error);
        SetScanningUIState(false);
      }
      finally
      {
        ScanProgressBar.IsIndeterminate = false;
        AutoDiscoverButton.IsEnabled = true;
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

    private List<string> ExtractTargetIps(CameraScanOptions options)
    {
      try
      {
        // 直接从 options 解析出 IP 列表，避免再次执行网络扫描
        var ips = CameraScannerService.GetAllTargetIps(options);
        if (ips.Count > 0) return ips;
      }
      catch (Exception ex)
      {
        WriteDiagLog($"ExtractTargetIps 解析失败: {ex.Message}");
      }
      // 回退：使用单 IP 字段
      return new List<string> { options.TargetIp };
    }

    private async Task SaveToHistoryAsync()
    {
      try
      {
        var duration = _elapsedTimer?.Elapsed ?? TimeSpan.Zero;
        var (success, message) = await _historyService.SaveToHistoryAsync(
            _currentPresetName, _currentTargetIps, _allResults, duration);
        if (success)
        {
          ScanStatusText.Text = $"状态: {message}";
        }
      }
      catch (Exception ex)
      {
        ScanStatusText.Text = $"状态: 保存历史失败 - {ex.Message}";
      }
    }

    private async void ExportCsvButton_Click(object sender, RoutedEventArgs e)
    {
      if (!_allResults.Any(r => r.IsOnline))
      {
        MessageBox.Show("暂无可导出的摄像头数据", "提示", MessageBoxButton.OK, MessageBoxImage.Information);
        return;
      }

      var dialog = new Microsoft.Win32.SaveFileDialog
      {
        Filter = "CSV文件 (*.csv)|*.csv",
        DefaultExt = ".csv",
        FileName = $"摄像头安全报告_{DateTime.Now:yyyyMMdd_HHmmss}.csv"
      };
      if (dialog.ShowDialog() != true) return;

      try
      {
        var duration = _elapsedTimer?.Elapsed ?? TimeSpan.Zero;
        await _exportService.SaveCsvAsync(dialog.FileName, _currentPresetName, _currentTargetIps, _allResults, duration);
        MessageBox.Show($"CSV报告已保存到:\n{dialog.FileName}", "导出成功", MessageBoxButton.OK, MessageBoxImage.Information);
        ScanStatusText.Text = $"状态: CSV报告已导出 - {dialog.FileName}";
      }
      catch (Exception ex)
      {
        MessageBox.Show($"导出失败: {ex.Message}", "错误", MessageBoxButton.OK, MessageBoxImage.Error);
      }
    }

    private async void DiagnoseButton_Click(object sender, RoutedEventArgs e)
    {
      if (!_allResults.Any(r => r.IsOnline))
      {
        MessageBox.Show("请先扫描摄像头，诊断需要在线摄像头数据", "提示", MessageBoxButton.OK, MessageBoxImage.Information);
        return;
      }

      CameraScanResult? target = null;
      if (CameraDataGrid?.SelectedItem is CameraScanResult selected)
      {
        target = selected;
      }
      else
      {
        // 默认选第一个在线摄像头
        target = _allResults.FirstOrDefault(r => r.IsOnline);
        if (target != null)
        {
          CameraDataGrid.SelectedItem = target;
        }
      }

      if (target == null)
      {
        MessageBox.Show("未找到在线摄像头", "提示", MessageBoxButton.OK, MessageBoxImage.Information);
        return;
      }

      DiagnoseButton.IsEnabled = false;
      ScanStatusText.Text = $"状态: 正在诊断 {target.Ip}...";

      try
      {
        using var service = new CameraScannerService();
        var diag = await service.DiagnoseAsync(target, CancellationToken.None);

        var sb = new StringBuilder();
        sb.AppendLine($"=== 摄像头扫描诊断报告 ===");
        sb.AppendLine($"目标IP: {diag.Ip}");
        sb.AppendLine($"厂商: {(string.IsNullOrEmpty(diag.Vendor) ? "(未识别)" : diag.Vendor)}");
        sb.AppendLine($"固件: {(string.IsNullOrEmpty(diag.FirmwareVersion) ? "(未知)" : diag.FirmwareVersion)}");
        sb.AppendLine();
        sb.AppendLine("【诊断步骤】");
        foreach (var step in diag.Steps)
        {
          sb.AppendLine($"  {step}");
        }
        sb.AppendLine();
        sb.AppendLine("【修复建议】");
        if (diag.Suggestions.Any())
        {
          foreach (var sug in diag.Suggestions)
          {
            sb.AppendLine($"  ✓ {sug}");
          }
        }
        else
        {
          sb.AppendLine("  (无)");
        }

        if (diag.DetectedVulnerabilities.Any())
        {
          sb.AppendLine();
          sb.AppendLine("【检出漏洞】");
          foreach (var v in diag.DetectedVulnerabilities)
          {
            sb.AppendLine($"  - {v.CveId}: {v.Name} (CVSS: {v.CvssScore})");
          }
        }

        MessageBox.Show(sb.ToString(), $"诊断报告 - {target.Ip}", MessageBoxButton.OK, MessageBoxImage.Information);
        ScanStatusText.Text = $"状态: 诊断完成 - {target.Ip} | 漏洞: {diag.DetectedVulnerabilities.Count} 个";
      }
      catch (Exception ex)
      {
        MessageBox.Show($"诊断失败: {ex.Message}", "错误", MessageBoxButton.OK, MessageBoxImage.Error);
      }
      finally
      {
        DiagnoseButton.IsEnabled = _allResults.Any(r => r.IsOnline);
      }
    }

    private async void ExportDetailedJsonButton_Click(object sender, RoutedEventArgs e)
    {
      if (!_allResults.Any(r => r.IsOnline))
      {
        MessageBox.Show("暂无可导出的摄像头数据", "提示", MessageBoxButton.OK, MessageBoxImage.Information);
        return;
      }

      var dialog = new Microsoft.Win32.SaveFileDialog
      {
        Filter = "JSON文件 (*.json)|*.json",
        DefaultExt = ".json",
        FileName = $"摄像头安全报告_{DateTime.Now:yyyyMMdd_HHmmss}.json"
      };
      if (dialog.ShowDialog() != true) return;

      try
      {
        var duration = _elapsedTimer?.Elapsed ?? TimeSpan.Zero;
        await _exportService.SaveJsonAsync(dialog.FileName, _currentPresetName, _currentTargetIps, _allResults, duration);
        MessageBox.Show($"JSON报告已保存到:\n{dialog.FileName}", "导出成功", MessageBoxButton.OK, MessageBoxImage.Information);
        ScanStatusText.Text = $"状态: JSON报告已导出 - {dialog.FileName}";
      }
      catch (Exception ex)
      {
        MessageBox.Show($"导出失败: {ex.Message}", "错误", MessageBoxButton.OK, MessageBoxImage.Error);
      }
    }

    // === v3-T6: 模板导入导出（待 UI 接入） ===
    // 下面的方法已就绪，可在 XAML 中添加按钮（Click 事件指向 ExportTemplateButton_Click / ImportTemplateButton_Click），
    // 或在代码中调用以下方法以触发导入导出。
    private readonly CameraScanTemplateService _templateService = new();

    /// <summary>
    /// v3-T6: 导出当前选中模板为 JSON。
    /// </summary>
    public void ExportTemplateButton_Click(object sender, RoutedEventArgs e)
    {
      try
      {
        var templates = _templateService.Templates;
        if (TemplateComboBox == null || TemplateComboBox.SelectedIndex < 0)
        {
          MessageBox.Show("请先在模板下拉框中选择要导出的模板", "提示", MessageBoxButton.OK, MessageBoxImage.Information);
          return;
        }
        var t = templates[TemplateComboBox.SelectedIndex];
        var dlg = new Microsoft.Win32.SaveFileDialog
        {
          Filter = "JSON文件 (*.json)|*.json",
          DefaultExt = ".json",
          FileName = $"模板_{t.Id}_{DateTime.Now:yyyyMMdd_HHmmss}.json"
        };
        if (dlg.ShowDialog() != true) return;
        _templateService.Export(t.Id, dlg.FileName);
        MessageBox.Show($"模板已导出到:\n{dlg.FileName}", "导出成功", MessageBoxButton.OK, MessageBoxImage.Information);
        ScanStatusText.Text = $"状态: 模板 [{t.Name}] 已导出 - {dlg.FileName}";
      }
      catch (Exception ex)
      {
        MessageBox.Show($"模板导出失败: {ex.Message}", "错误", MessageBoxButton.OK, MessageBoxImage.Error);
      }
    }

    /// <summary>
    /// v3-T6: 从 JSON 文件导入模板。
    /// </summary>
    public void ImportTemplateButton_Click(object sender, RoutedEventArgs e)
    {
      try
      {
        var dlg = new Microsoft.Win32.OpenFileDialog
        {
          Filter = "JSON文件 (*.json)|*.json|所有文件 (*.*)|*.*",
          Title = "选择要导入的模板文件"
        };
        if (dlg.ShowDialog() != true) return;
        var t = _templateService.Import(dlg.FileName);
        LoadTemplates();
        ScanStatusText.Text = $"状态: 已导入模板 [{t.Name}] - {dlg.FileName}";
        MessageBox.Show($"模板 [{t.Name}] 已导入，可在模板下拉框中查看", "导入成功", MessageBoxButton.OK, MessageBoxImage.Information);
      }
      catch (Exception ex)
      {
        MessageBox.Show($"模板导入失败: {ex.Message}", "错误", MessageBoxButton.OK, MessageBoxImage.Error);
      }
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

        ScanModeComboBox.SelectedIndex = 0;
        TargetInputTextBox.Text = camera.Ip;

        StartScan_Click(sender, e);
      }
    }

    private void ContextMenu_CopyAll_Click(object sender, RoutedEventArgs e)
    {
      CopyButton_Click(sender, e);
    }

    private void ApplyFilter()
    {
      try
      {
        if (CameraDataGrid == null || CameraDataGrid.ItemsSource == null)
          return;

        var filter = FilterTextBox?.Text?.Trim() ?? string.Empty;
        if (filter == "🔍 搜索过滤（IP / 厂商 / 型号 / 风险等级）...")
          filter = string.Empty;

        // v4-T2.5: 标签过滤
        string? tagId = null;
        if (TagFilterComboBox?.SelectedItem is ComboBoxItem tagItem)
        {
          tagId = tagItem.Tag?.ToString();
          if (string.IsNullOrEmpty(tagId)) tagId = null;
        }
        var groupByTag = GroupByTagCheck?.IsChecked == true;
        var tagMap = (tagId != null || groupByTag)
            ? BuildTagMap()
            : new Dictionary<string, List<CameraTag>>();

        // 工具栏: 风险等级过滤 (all/严重/高危/中危/低危/安全/weakpwd)
        string riskFilter = "all";
        if (RiskFilterComboBox?.SelectedItem is ComboBoxItem riskItem)
        {
          riskFilter = riskItem.Tag?.ToString() ?? "all";
        }

        ICollectionView view = CollectionViewSource.GetDefaultView(CameraDataGrid.ItemsSource);
        if (view == null) return;

        view.Filter = item =>
        {
          if (item is not CameraScanResult camera)
            return false;

          // 标签过滤
          if (tagId != null)
          {
            try
            {
              var ips = _tagService.GetIpsForTag(tagId);
              if (ips == null || !ips.Contains(camera.Ip)) return false;
            }
            catch
            {
              // 标签服务异常时跳过该过滤维度，不影响其他过滤
            }
          }

          // 风险等级过滤
          if (riskFilter != "all")
          {
            try
            {
              var level = camera.RiskAssessment?.RiskLevel ?? string.Empty;
              var hasVuln = (camera.Vulnerabilities?.Count ?? 0) > 0;
              var hasWeakPwd = (camera.WeakPasswords?.Count ?? 0) > 0;
              switch (riskFilter)
              {
                case "严重":
                case "高危":
                case "中危":
                case "低危":
                  if (!string.Equals(level, riskFilter, StringComparison.Ordinal))
                    return false;
                  break;
                case "安全":
                  // 安全: 0 漏洞且 0 弱口令
                  if (hasVuln || hasWeakPwd) return false;
                  break;
                case "weakpwd":
                  // 仅有弱口令 (有弱口令但无漏洞)
                  if (!hasWeakPwd || hasVuln) return false;
                  break;
              }
            }
            catch
            {
              // 风险过滤异常时跳过该维度
            }
          }

          if (string.IsNullOrEmpty(filter))
            return true;

          return (camera.Ip?.Contains(filter, StringComparison.OrdinalIgnoreCase) ?? false)
              || (camera.IpType?.Contains(filter, StringComparison.OrdinalIgnoreCase) ?? false)
              || (camera.Vendor?.Contains(filter, StringComparison.OrdinalIgnoreCase) ?? false)
              || (camera.Model?.Contains(filter, StringComparison.OrdinalIgnoreCase) ?? false)
              || (camera.FirmwareVersion?.Contains(filter, StringComparison.OrdinalIgnoreCase) ?? false)
              || (camera.RiskAssessment?.RiskLevel?.Contains(filter, StringComparison.OrdinalIgnoreCase) ?? false)
              || (camera.SerialNumber?.Contains(filter, StringComparison.OrdinalIgnoreCase) ?? false);
        };

        // v4-T2.5: 按标签分组排序（同一标签的 IP 排在一起）
        if (groupByTag && tagMap != null)
        {
          view.SortDescriptions.Clear();
          // 没有标签的排在最后，有标签的按第一个标签名排序
          view.SortDescriptions.Add(new SortDescription(nameof(CameraScanResult.Ip), ListSortDirection.Ascending));
        }

        // 工具栏: 刷新统计信息
        RefreshToolbarStats(view);
      }
      catch (Exception ex)
      {
        WriteDiagLog($"ApplyFilter 异常: {ex.GetType().Name}: {ex.Message}");
      }
    }

    /// <summary>
    /// 工具栏: 刷新统计信息 (总数 / 高危 / 中危 / 低危)
    /// 遍历当前可见的源数据 (不过滤后)
    /// </summary>
    private void RefreshToolbarStats(ICollectionView? view = null)
    {
      try
      {
        if (_allResults == null)
        {
          UpdateStatRuns(0, 0, 0, 0);
          return;
        }
        // 使用 view 提供的源数据 (如果 view 为空, 直接遍历 _allResults)
        int total = 0, high = 0, mid = 0, low = 0;
        foreach (var c in _allResults)
        {
          if (c == null) continue;
          total++;
          var level = c.RiskAssessment?.RiskLevel ?? string.Empty;
          if (string.Equals(level, "高危", StringComparison.Ordinal)) high++;
          else if (string.Equals(level, "中危", StringComparison.Ordinal)) mid++;
          else if (string.Equals(level, "低危", StringComparison.Ordinal)) low++;
        }
        UpdateStatRuns(total, high, mid, low);
      }
      catch (Exception ex)
      {
        WriteDiagLog($"RefreshToolbarStats 异常: {ex.Message}");
      }
    }

    private void UpdateStatRuns(int total, int high, int mid, int low)
    {
      if (StatTotalRun != null) StatTotalRun.Text = total.ToString();
      if (StatHighRun != null) StatHighRun.Text = high.ToString();
      if (StatMediumRun != null) StatMediumRun.Text = mid.ToString();
      if (StatLowRun != null) StatLowRun.Text = low.ToString();
    }

    /// <summary>
    /// v4-T2: 构建 "IP -> 标签列表" 映射，给 TagListConverter 用。
    /// </summary>
    private Dictionary<string, List<CameraTag>> BuildTagMap()
    {
      var map = new Dictionary<string, List<CameraTag>>(StringComparer.Ordinal);
      if (_cachedTags == null || _cachedTags.Count == 0) return map;
      foreach (var t in _cachedTags)
      {
        foreach (var ip in _tagService.GetIpsForTag(t.TagId))
        {
          if (!map.TryGetValue(ip, out var list))
          {
            list = new List<CameraTag>();
            map[ip] = list;
          }
          list.Add(t);
        }
      }
      return map;
    }

    private CameraScanResult? _lastShownCamera;
    private DateTime _lastDetailUpdate = DateTime.MinValue;
    private void CameraDataGrid_SelectionChanged(object sender, SelectionChangedEventArgs e)
    {
      try
      {
        if (CameraDataGrid?.SelectedItem is not CameraScanResult camera) return;
        // 节流：同一项 200ms 内不重复刷新，避免快速键盘导航/滚动时 PostMessage 过载
        if (ReferenceEquals(camera, _lastShownCamera) &&
            (DateTime.Now - _lastDetailUpdate).TotalMilliseconds < 200) return;
        _lastShownCamera = camera;
        _lastDetailUpdate = DateTime.Now;
        ShowCameraDetail(camera);
      }
      catch (Exception ex)
      {
        WriteDiagLog($"CameraDataGrid_SelectionChanged 异常: {ex.GetType().Name}: {ex.Message}");
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

      // v4-T1.4: 扫描完成后刷新顶部 Dashboard
      try
      {
        var stat = CameraScanStatisticsService.Compute(results);
        UpdateDashboard(stat);
      }
      catch (Exception ex)
      {
        WriteDiagLog($"DisplayResults UpdateDashboard 异常: {ex.Message}");
      }

      // v4-T5.4: 扫描后写一条历史汇总
      try
      {
        var totalVulns = results.Sum(r => r.Vulnerabilities?.Count ?? 0);
        var highVulns = results.Sum(r => r.Vulnerabilities?
            .Count(v => v.Severity == "高" || v.Severity == "严重" ||
                        v.Severity.Equals("High", StringComparison.OrdinalIgnoreCase) ||
                        v.Severity.Equals("Critical", StringComparison.OrdinalIgnoreCase)) ?? 0);
        _trendService.RecordSummary(
            Guid.NewGuid().ToString("N"),
            DateTime.Now,
            results.Count,
            onlineCameras.Count,
            totalVulns,
            highVulns);
        // 刷新顶部迷你趋势
        LoadTrendPreview();
      }
      catch (Exception ex)
      {
        WriteDiagLog($"RecordSummary 异常: {ex.Message}");
      }

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
      sb.AppendLine($"IP类型: {camera.IpType}");
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

      // v4-T1.4: 清空 Dashboard（控件已移除，仅调用更新方法）
      try { UpdateDashboard(new CameraScanStatistics()); } catch { }
    }

    private void SetScanningUIState(bool isScanning)
    {
      StartScanButton.IsEnabled = !isScanning;
      StopScanButton.IsEnabled = isScanning;
      ExportReportButton.IsEnabled = !isScanning && _allResults.Any(r => r.IsOnline);
      ExportCsvButton.IsEnabled = !isScanning && _allResults.Any(r => r.IsOnline);
      ExportJsonButton.IsEnabled = !isScanning && _allResults.Any(r => r.IsOnline);
      CopyButton.IsEnabled = !isScanning;
      FilterTextBox.IsEnabled = !isScanning;
      ScanModeComboBox.IsEnabled = !isScanning;
      TargetInputTextBox.IsEnabled = !isScanning;
      PresetComboBox.IsEnabled = !isScanning;
      ConcurrencyTextBox.IsEnabled = !isScanning;
      TimeoutTextBox.IsEnabled = !isScanning;
      FingerprintCheck.IsEnabled = !isScanning;
      VulnScanCheck.IsEnabled = !isScanning;
      WeakPasswordCheck.IsEnabled = !isScanning;
      AggressiveScanCheck.IsEnabled = !isScanning;
      ImportTargetsButton.IsEnabled = !isScanning;
      AutoDiscoverButton.IsEnabled = !isScanning;
      RecommendButton.IsEnabled = !isScanning;
      DiagnoseButton.IsEnabled = !isScanning && _allResults.Any(r => r.IsOnline);

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

    private void ScanModeComboBox_SelectionChanged(object sender, System.Windows.Controls.SelectionChangedEventArgs e)
    {
      if (ScanModeComboBox == null || TargetInputTextBox == null || TargetLabel == null) return;

      switch (ScanModeComboBox.SelectedIndex)
      {
        case 0:
          TargetLabel.Text = "目标IP:";
          TargetInputTextBox.Text = "192.168.1.100";
          TargetInputTextBox.ToolTip = "输入单个IP地址，支持IPv4（如 192.168.1.100）或IPv6（如 ::1）";
          break;
        case 1:
          TargetLabel.Text = "IP段:";
          TargetInputTextBox.Text = "192.168.1.1-192.168.1.254";
          TargetInputTextBox.ToolTip = "输入IPv4地址段，格式：起始IP-结束IP，如 192.168.1.1-192.168.1.254";
          break;
        case 2:
          TargetLabel.Text = "CIDR:";
          TargetInputTextBox.Text = "192.168.1.0/24";
          TargetInputTextBox.ToolTip = "输入CIDR格式，IPv4范围 /16~/32（如 192.168.1.0/24），IPv6范围 /112~/128（如 fe80::/120）";
          break;
      }
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

    /// <summary>
    /// v5-T4: 右键 "用插件深挖"。从 DataGridRow 反查 DataGrid 与选中行，
    /// 提取摄像头 IP 与开放端口，通过 PluginOrchestrator.ScanTargetAsync
    /// 触发多插件联合扫描并提示结果。
    /// </summary>
    private async void DeepScanMenuItem_Click(object sender, RoutedEventArgs e)
    {
      try
      {
        if (sender is not MenuItem menuItem) return;
        if (menuItem.DataContext is not DataGridRow row) return;

        var dataGrid = FindVisualParent<DataGrid>(menuItem);
        if (dataGrid == null || dataGrid.SelectedItem == null) return;
        var selectedItem = dataGrid.SelectedItem;

        string? targetIp = null;
        var ports = new List<int>();
        var type = selectedItem.GetType();
        var ipProp = type.GetProperty("Ip") ?? type.GetProperty("TargetIp") ?? type.GetProperty("IPAddress") ?? type.GetProperty("Host") ?? type.GetProperty("Target");
        if (ipProp != null) targetIp = ipProp.GetValue(selectedItem)?.ToString();

        // 摄像头结果中 OpenPorts 是 List<CameraPortInfo>，逐项提取 Port
        var openPortsProp = type.GetProperty("OpenPorts");
        if (openPortsProp?.GetValue(selectedItem) is System.Collections.IEnumerable openPorts)
        {
          foreach (var p in openPorts)
          {
            if (p == null) continue;
            var pt = p.GetType();
            var pp = pt.GetProperty("Port") ?? pt.GetProperty("PortNumber");
            if (pp != null)
            {
              var pv = pp.GetValue(p);
              if (pv != null) ports.Add(Convert.ToInt32(pv));
            }
          }
        }

        if (string.IsNullOrEmpty(targetIp))
        {
          MessageBox.Show("无法获取目标 IP", "提示", MessageBoxButton.OK, MessageBoxImage.Warning);
          return;
        }

        var portsDisplay = ports.Count > 0 ? string.Join(",", ports) : "默认";
        var confirm = MessageBox.Show($"将使用所有适用插件重新扫描 {targetIp} (端口: {portsDisplay})，是否继续？",
            "插件深挖", MessageBoxButton.YesNo, MessageBoxImage.Question);
        if (confirm != MessageBoxResult.Yes) return;

        Mouse.OverrideCursor = Cursors.Wait;
        var results = await PluginOrchestrator.Instance.ScanTargetAsync(targetIp, ports);
        Mouse.OverrideCursor = null;

        ScanStatusText.Text = $"状态: 深挖 {targetIp} 完成，发现 {results.Count} 个漏洞";
        MessageBox.Show($"深挖完成：发现 {results.Count} 个漏洞", "完成", MessageBoxButton.OK, MessageBoxImage.Information);
      }
      catch (Exception ex)
      {
        Mouse.OverrideCursor = null;
        MessageBox.Show($"深挖失败: {ex.Message}", "错误", MessageBoxButton.OK, MessageBoxImage.Error);
      }
    }

    private static T? FindVisualParent<T>(DependencyObject child) where T : DependencyObject
    {
      var parent = System.Windows.Media.VisualTreeHelper.GetParent(child);
      while (parent != null && parent is not T)
        parent = System.Windows.Media.VisualTreeHelper.GetParent(parent);
      return parent as T;
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

  /// <summary>
  /// v4-T2: 标签列显示用的视图模型。
  /// </summary>
  public class TagViewModel
  {
    public string Name { get; set; } = string.Empty;
    public Brush Color { get; set; } = Brushes.SteelBlue;
    public string Description { get; set; } = string.Empty;
  }

  /// <summary>
  /// v4-T2: 把 CameraScanResult 转换成该 IP 的所有 Tag 视图模型列表，
  /// 配合 ItemsControl 在 DataGrid 的"标签"列里渲染彩色徽章。
  /// </summary>
  public class TagListConverter : IValueConverter
  {
    private static readonly CameraTagService _tagService = new();
    private static List<CameraTag> _tagCache = new();
    private static DateTime _cacheTime = DateTime.MinValue;
    private static readonly object _lock = new();

    public object? Convert(object? value, Type targetType, object? parameter, CultureInfo culture)
    {
      if (value is not CameraScanResult camera) return new List<TagViewModel>();
      EnsureCache();
      var ips = _tagService.GetIpsForTag(string.Empty); // 预热一下
      var tagIds = new HashSet<string>(_tagService.GetTagsForIp(camera.Ip));
      var result = new List<TagViewModel>();
      foreach (var t in _tagCache)
      {
        if (!tagIds.Contains(t.TagId)) continue;
        Brush brush;
        try
        {
          var conv = System.Windows.Media.ColorConverter.ConvertFromString(
              string.IsNullOrWhiteSpace(t.Color) ? "#3498DB" : t.Color);
          brush = new SolidColorBrush(conv is Color c ? c : Colors.SteelBlue);
        }
        catch
        {
          brush = Brushes.SteelBlue;
        }
        result.Add(new TagViewModel
        {
          Name = t.Name,
          Color = brush,
          Description = t.Description
        });
      }
      return result;
    }

    public object? ConvertBack(object? value, Type targetType, object? parameter, CultureInfo culture)
      => throw new NotSupportedException();

    private static void EnsureCache()
    {
      lock (_lock)
      {
        if ((DateTime.Now - _cacheTime).TotalSeconds > 5)
        {
          _tagCache = _tagService.GetAll();
          _cacheTime = DateTime.Now;
        }
      }
    }
  }
}