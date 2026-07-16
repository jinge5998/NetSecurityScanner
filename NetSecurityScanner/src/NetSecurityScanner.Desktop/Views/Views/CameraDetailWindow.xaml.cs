using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using NetSecurityScanner.Models;

namespace NetSecurityScanner.Views
{
  /// <summary>
  /// 摄像头详情窗口（v4-T3）：左侧基本/端口/漏洞/弱口令 4 个 Tab，右侧概览与优先修复建议。
  /// </summary>
  public partial class CameraDetailWindow : Window
  {
    private readonly CameraScanResult _camera;

    public CameraDetailWindow(CameraScanResult camera)
    {
      _camera = camera ?? throw new ArgumentNullException(nameof(camera));
      InitializeComponent();
      Loaded += (s, e) => LoadData();
    }

    private void LoadData()
    {
      try
      {
        Title = $"摄像头详情 - {_camera.Ip}";
        TitleText.Text = $"{_camera.Ip} - {_camera.Vendor} {_camera.Model}";
        SubTitleText.Text = string.IsNullOrEmpty(_camera.FirmwareVersion)
            ? _camera.IpType
            : $"{_camera.IpType} | 固件 {_camera.FirmwareVersion} | MAC {_camera.Mac}";

        // 风险评分
        var score = _camera.RiskAssessment?.TotalScore ?? 0;
        RiskScoreText.Text = score.ToString("F1");
        var level = _camera.RiskAssessment?.RiskLevel ?? "中危";
        RiskLevelText.Text = level;
        RiskLevelBadge.Background = LevelToBrush(level);

        // 右侧概览
        SummaryVendorText.Text = $"厂商: {_camera.Vendor}";
        SummaryModelText.Text = $"型号: {_camera.Model}";
        SummaryFirmwareText.Text = $"固件: {_camera.FirmwareVersion}";
        SummarySerialText.Text = $"序列号: {_camera.SerialNumber}";
        SummaryMacText.Text = $"MAC: {_camera.Mac}";
        PortCountText.Text = $"开放端口: {_camera.OpenPorts?.Count ?? 0}";

        var vulns = _camera.Vulnerabilities ?? new List<CameraVulnerability>();
        var critical = vulns.Count(v => MatchesLevel(v.Severity, "严重"));
        var high = vulns.Count(v => MatchesLevel(v.Severity, "高"));
        var medium = vulns.Count(v => MatchesLevel(v.Severity, "中"));
        VulnTotalText.Text = $"漏洞总数: {vulns.Count}";
        VulnCriticalText.Text = $"严重: {critical}";
        VulnHighText.Text = $"高危: {high}";
        VulnMediumText.Text = $"中危: {medium}";
        WeakPwdCountText.Text = $"弱口令: {_camera.WeakPasswords?.Count ?? 0}";

        // 优先修复建议
        var rems = _camera.RiskAssessment?.TopRemediations ?? new List<string>();
        RemediationsList.ItemsSource = rems;

        // 基本信息 Tab
        BuildBasicInfo();

        // 端口 Tab
        PortGrid.ItemsSource = new System.Collections.ObjectModel.ObservableCollection<CameraPortInfo>(
            _camera.OpenPorts ?? new List<CameraPortInfo>());

        // 漏洞 Tab
        VulnGrid.ItemsSource = new System.Collections.ObjectModel.ObservableCollection<CameraVulnerability>(vulns);

        // 弱口令 Tab
        var wps = (_camera.WeakPasswords ?? new List<CameraWeakPassword>())
            .Select(wp => new
            {
              wp.ServiceType,
              wp.Port,
              wp.Username,
              wp.Password,
              wp.RiskLevel,
              wp.Suggestion
            })
            .ToList();
        WeakPwdGrid.ItemsSource = wps;
      }
      catch (Exception ex)
      {
        MessageBox.Show($"加载详情失败: {ex.Message}", "错误", MessageBoxButton.OK, MessageBoxImage.Error);
      }
    }

    private void BuildBasicInfo()
    {
      BasicInfoGrid.Children.Clear();
      var rows = new List<(string Label, string Value)>
      {
        ("IP", _camera.Ip ?? "--"),
        ("IP 类型", _camera.IpType ?? "--"),
        ("厂商", _camera.Vendor ?? "--"),
        ("型号", _camera.Model ?? "--"),
        ("固件版本", _camera.FirmwareVersion ?? "--"),
        ("序列号", _camera.SerialNumber ?? "--"),
        ("MAC 地址", _camera.Mac ?? "--"),
        ("在线状态", _camera.IsOnline ? "在线" : "离线"),
        ("开放端口", (_camera.OpenPorts?.Count ?? 0).ToString()),
        ("扫描时间", _camera.ScanTime == default ? "--" : _camera.ScanTime.ToString("yyyy-MM-dd HH:mm:ss")),
        ("响应时间", $"{_camera.ResponseTimeMs} ms"),
        ("风险等级", _camera.RiskAssessment?.RiskLevel ?? "--")
      };

      var labelStyle = new Style(typeof(TextBlock));
      labelStyle.Setters.Add(new Setter(TextBlock.FontWeightProperty, FontWeights.SemiBold));
      labelStyle.Setters.Add(new Setter(TextBlock.ForegroundProperty, new SolidColorBrush(Color.FromRgb(0x33, 0x41, 0x55))));
      labelStyle.Setters.Add(new Setter(TextBlock.MarginProperty, new Thickness(0, 6, 8, 6)));

      var valueStyle = new Style(typeof(TextBlock));
      valueStyle.Setters.Add(new Setter(TextBlock.ForegroundProperty, new SolidColorBrush(Color.FromRgb(0x1E, 0x29, 0x3B))));
      valueStyle.Setters.Add(new Setter(TextBlock.MarginProperty, new Thickness(0, 6, 0, 6)));
      valueStyle.Setters.Add(new Setter(TextBlock.TextWrappingProperty, TextWrapping.Wrap));

      for (int i = 0; i < rows.Count; i++)
      {
        var (label, value) = rows[i];
        var lbl = new TextBlock { Text = label, Style = labelStyle };
        var val = new TextBlock { Text = value, Style = valueStyle };
        Grid.SetRow(lbl, i); Grid.SetColumn(lbl, 0);
        Grid.SetRow(val, i); Grid.SetColumn(val, 1);
        BasicInfoGrid.Children.Add(lbl);
        BasicInfoGrid.Children.Add(val);
      }
    }

    private static bool MatchesLevel(string? severity, string keyword)
    {
      if (string.IsNullOrEmpty(severity)) return false;
      var s = severity.Trim();
      if (s.Equals(keyword, StringComparison.OrdinalIgnoreCase)) return true;
      return s.Contains(keyword);
    }

    private static Brush LevelToBrush(string level)
    {
      if (string.IsNullOrEmpty(level)) return new SolidColorBrush(Color.FromRgb(0x95, 0xA5, 0xA6));
      if (level.Contains("严重")) return new SolidColorBrush(Color.FromRgb(0xC0, 0x39, 0x2B));
      if (level.Contains("高")) return new SolidColorBrush(Color.FromRgb(0xE6, 0x7E, 0x22));
      if (level.Contains("中")) return new SolidColorBrush(Color.FromRgb(0xF3, 0x9C, 0x12));
      if (level.Contains("低")) return new SolidColorBrush(Color.FromRgb(0x27, 0xAE, 0x60));
      return new SolidColorBrush(Color.FromRgb(0x34, 0x98, 0xDB));
    }

    private void CopyAll_Click(object sender, RoutedEventArgs e)
    {
      try
      {
        var sb = new StringBuilder();
        sb.AppendLine($"=== 摄像头详情: {_camera.Ip} ===");
        sb.AppendLine($"厂商: {_camera.Vendor}");
        sb.AppendLine($"型号: {_camera.Model}");
        sb.AppendLine($"固件: {_camera.FirmwareVersion}");
        sb.AppendLine($"MAC: {_camera.Mac}");
        sb.AppendLine($"风险等级: {_camera.RiskAssessment?.RiskLevel} (评分: {_camera.RiskAssessment?.TotalScore:F1})");
        sb.AppendLine($"开放端口: {_camera.OpenPorts?.Count ?? 0}");
        sb.AppendLine($"漏洞: {_camera.Vulnerabilities?.Count ?? 0}");
        sb.AppendLine($"弱口令: {_camera.WeakPasswords?.Count ?? 0}");
        if (_camera.Vulnerabilities != null)
        {
          sb.AppendLine("\n--- 漏洞 ---");
          foreach (var v in _camera.Vulnerabilities)
            sb.AppendLine($"  [{v.Severity}] {v.CveId} - {v.Name} (CVSS {v.CvssScore})");
        }
        if (_camera.WeakPasswords != null)
        {
          sb.AppendLine("\n--- 弱口令 ---");
          foreach (var wp in _camera.WeakPasswords)
            sb.AppendLine($"  {wp.ServiceType}:{wp.Port} {wp.Username}:{wp.Password}");
        }
        if (_camera.RiskAssessment?.TopRemediations != null)
        {
          sb.AppendLine("\n--- 优先修复建议 ---");
          foreach (var r in _camera.RiskAssessment.TopRemediations)
            sb.AppendLine($"  - {r}");
        }
        Clipboard.SetText(sb.ToString());
        MessageBox.Show("已复制到剪贴板", "提示", MessageBoxButton.OK, MessageBoxImage.Information);
      }
      catch (Exception ex)
      {
        MessageBox.Show($"复制失败: {ex.Message}", "错误", MessageBoxButton.OK, MessageBoxImage.Error);
      }
    }

    private void Close_Click(object sender, RoutedEventArgs e)
    {
      Close();
    }
  }
}
