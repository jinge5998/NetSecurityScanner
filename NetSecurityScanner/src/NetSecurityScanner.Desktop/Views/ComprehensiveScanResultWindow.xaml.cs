using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using Microsoft.Win32;
using NetSecurityScanner.Core.Services;
using NetSecurityScanner.Models;
using NetSecurityScanner.Services;

namespace NetSecurityScanner.Views
{
    public partial class ComprehensiveScanResultWindow : Window
    {
        private readonly ComprehensiveScanResult _result;
        private readonly ScanExportService _exportService;
        private readonly JsonDatabaseService _db;
        private List<VulnerabilityResult> _allVulns = new();
        private List<VulnerabilityResult> _allPlugins = new();

        public ComprehensiveScanResultWindow(ComprehensiveScanResult result)
        {
            InitializeComponent();
            _result = result ?? throw new ArgumentNullException(nameof(result));
            _exportService = new ScanExportService();
            _db = new JsonDatabaseService();
            Loaded += ComprehensiveScanResultWindow_Loaded;
        }

        private void ComprehensiveScanResultWindow_Loaded(object sender, RoutedEventArgs e)
        {
            if (_result == null) return;
            Title = $"🛡️ 综合扫描结果 - {_result.TargetIp}";
            TitleText.Text = $"🛡️ 综合扫描结果 - {_result.TargetIp}";
            SubtitleText.Text = $"{_result.ScanTime:yyyy-MM-dd HH:mm:ss}  |  耗时 {_result.ScanDurationSeconds:F1} 秒  |  {_result.ScanType}";

            ApplyRiskBadge(_result.RiskLevel);
            BuildOverview();
            LoadPorts();
            LoadVulns();
            LoadServices();
            LoadPlugins();
        }

        private void ApplyRiskBadge(string level)
        {
            RiskBadgeText.Text = level ?? "无风险";
            RiskBadge.Background = (level ?? "") switch
            {
                "严重风险" => new SolidColorBrush(Color.FromRgb(0xC0, 0x39, 0x2B)),
                "高风险" => new SolidColorBrush(Color.FromRgb(0xE7, 0x4C, 0x3C)),
                "中风险" => new SolidColorBrush(Color.FromRgb(0xF3, 0x9C, 0x12)),
                "低风险" => new SolidColorBrush(Color.FromRgb(0xF1, 0xC4, 0x0F)),
                _ => new SolidColorBrush(Color.FromRgb(0x27, 0xAE, 0x60))
            };
        }

        private void BuildOverview()
        {
            OverviewPanel.Children.Clear();

            // 摘要
            var summaryBorder = BuildSectionBorder("📋 扫描摘要");
            var summaryPanel = new StackPanel();
            AddKvRow(summaryPanel, "目标", _result.TargetIp);
            AddKvRow(summaryPanel, "扫描类型", _result.ScanType);
            AddKvRow(summaryPanel, "扫描时间", _result.ScanTime.ToString("yyyy-MM-dd HH:mm:ss"));
            AddKvRow(summaryPanel, "总耗时", $"{_result.ScanDurationSeconds:F1} 秒");
            AddKvRow(summaryPanel, "主机存活", _result.HostAlive ? "✅ 是" : "❌ 否（结果可能不完整）");
            AddKvRow(summaryPanel, "开放端口", $"{_result.OpenPortsCount}（TCP {_result.TcpOpenPorts} / UDP {_result.UdpOpenPorts}）");
            AddKvRow(summaryPanel, "漏洞总数", $"{_result.VulnerabilitiesCount}（漏洞扫描 {_result.VulnerabilityResults.Count} / 插件扫描 {_result.PluginResults.Count}）");
            AddKvRow(summaryPanel, "风险等级", _result.RiskLevel);
            if (_result.HasVulnerabilityScanError) AddKvRow(summaryPanel, "⚠ 异常", "漏洞扫描阶段出现异常");
            if (_result.HasPluginScanError) AddKvRow(summaryPanel, "⚠ 异常", "插件扫描阶段出现异常");
            if (_result.Cancelled) AddKvRow(summaryPanel, "⛔ 状态", "扫描已被用户取消");
            summaryBorder.Child = summaryPanel;
            OverviewPanel.Children.Add(summaryBorder);

            // 阶段时间线
            var phaseBorder = BuildSectionBorder("⏱ 阶段时间线");
            var phasePanel = new StackPanel();
            foreach (var p in _result.Phases)
            {
                var statusIcon = p.Status switch
                {
                    ScanPhaseStatus.Success => "✅",
                    ScanPhaseStatus.Failed => "❌",
                    ScanPhaseStatus.Skipped => "⏭",
                    ScanPhaseStatus.Running => "🔄",
                    _ => "⏳"
                };
                var tb = new TextBlock
                {
                    Text = $"{statusIcon} {p.PhaseName}  -  {p.DurationMs} ms  {(string.IsNullOrEmpty(p.ErrorMessage) ? "" : $"  ({p.ErrorMessage})")}",
                    FontSize = 12,
                    Margin = new Thickness(0, 2, 0, 2)
                };
                phasePanel.Children.Add(tb);
            }
            phaseBorder.Child = phasePanel;
            OverviewPanel.Children.Add(phaseBorder);
        }

        private Border BuildSectionBorder(string title)
        {
            var border = new Border
            {
                BorderBrush = new SolidColorBrush(Color.FromRgb(0xDD, 0xE1, 0xE7)),
                BorderThickness = new Thickness(1),
                CornerRadius = new CornerRadius(6),
                Padding = new Thickness(12),
                Margin = new Thickness(0, 0, 0, 10),
                Background = Brushes.White
            };
            border.Child = new TextBlock
            {
                Text = title,
                FontWeight = FontWeights.Bold,
                FontSize = 13,
                Foreground = new SolidColorBrush(Color.FromRgb(0x2C, 0x3E, 0x50)),
                Margin = new Thickness(0, 0, 0, 6)
            };
            return border;
        }

        private void AddKvRow(StackPanel parent, string key, string value)
        {
            var sp = new StackPanel { Orientation = Orientation.Horizontal, Margin = new Thickness(0, 2, 0, 2) };
            sp.Children.Add(new TextBlock
            {
                Text = $"{key}:",
                FontWeight = FontWeights.SemiBold,
                Width = 100,
                Foreground = new SolidColorBrush(Color.FromRgb(0x7F, 0x8C, 0x8D)),
                FontSize = 12
            });
            sp.Children.Add(new TextBlock
            {
                Text = value ?? "-",
                FontSize = 12,
                TextWrapping = TextWrapping.Wrap
            });
            parent.Children.Add(sp);
        }

        private void LoadPorts()
        {
            // v1.0.1.4 P0 修复: 同时显示"开放"和"开放或过滤"状态的端口
            // UDP 扫描常返回"开放或过滤",旧逻辑只过滤"开放"会导致 UDP 结果不可见
            var openPorts = _result.AllPortResults?
                .Where(p => p.Status == "开放" || p.Status == "开放或过滤")
                .OrderBy(p => p.PortNumber)
                .ToList() ?? new List<PortScanResult>();
            PortsDataGrid.ItemsSource = openPorts;
        }

        private void LoadVulns()
        {
            _allVulns = _result.VulnerabilityResults?.ToList() ?? new List<VulnerabilityResult>();
            _allPlugins = _result.PluginResults?.ToList() ?? new List<VulnerabilityResult>();
            VulnCountText.Text = $"共 {_allVulns.Count} 个";
            VulnsDataGrid.ItemsSource = _allVulns;
        }

        private void VulnFilterCombo_SelectionChanged(object sender, SelectionChangedEventArgs e)
        {
            if (!IsLoaded) return;
            var tag = (VulnFilterCombo.SelectedItem as ComboBoxItem)?.Tag?.ToString() ?? "";
            IEnumerable<VulnerabilityResult> q = _allVulns;
            if (!string.IsNullOrEmpty(tag))
                q = q.Where(v => (v.RiskLevel ?? "").Contains(tag));
            var list = q.ToList();
            VulnsDataGrid.ItemsSource = list;
            VulnCountText.Text = $"共 {list.Count} 个（已按 {tag} 筛选）";
        }

        private void LoadServices()
        {
            // v1.0.1.4 P0 修复: 服务识别也包含"开放或过滤"端口
            var openPorts = _result.AllPortResults?
                .Where(p => p.Status == "开放" || p.Status == "开放或过滤")
                .ToList() ?? new List<PortScanResult>();

            var services = openPorts
                .GroupBy(p => string.IsNullOrEmpty(p.Service) ? "未知" : p.Service)
                .Select(g => new
                {
                    Service = g.Key,
                    Count = g.Count(),
                    Ports = string.Join(", ", g.Select(p => p.PortNumber).OrderBy(n => n)),
                    Versions = string.Join("; ", g.Select(p => p.ServiceVersion).Where(v => !string.IsNullOrEmpty(v)).Distinct())
                })
                .OrderByDescending(s => s.Count)
                .ToList();
            ServicesDataGrid.ItemsSource = services;
        }

        private void LoadPlugins()
        {
            PluginsDataGrid.ItemsSource = _allPlugins;
        }

        private async void ExportJsonButton_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                var dlg = new SaveFileDialog
                {
                    Filter = "JSON 文件|*.json",
                    FileName = $"综合扫描_{_result.TargetIp}_{DateTime.Now:yyyyMMdd_HHmmss}.json",
                    Title = "导出综合扫描结果（JSON）"
                };
                if (dlg.ShowDialog() != true) return;

                var options = new ExportOptions
                {
                    Title = $"综合扫描结果 - {_result.TargetIp}",
                    TotalTargets = 1,
                    TotalOpenPorts = _result.OpenPortsCount,
                    TotalVulnerabilities = _result.VulnerabilitiesCount
                };
                var content = _exportService.ExportToJson(_result.AllPortResults, _result.VulnerabilityResults, options);
                await File.WriteAllTextAsync(dlg.FileName, content);
                MessageBox.Show($"已导出到:\n{dlg.FileName}", "导出成功", MessageBoxButton.OK, MessageBoxImage.Information);
            }
            catch (Exception ex)
            {
                MessageBox.Show($"导出 JSON 失败: {ex.Message}", "错误", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        private async void ExportCsvButton_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                var dlg = new SaveFileDialog
                {
                    Filter = "CSV 文件|*.csv",
                    FileName = $"综合扫描_{_result.TargetIp}_{DateTime.Now:yyyyMMdd_HHmmss}.csv",
                    Title = "导出综合扫描结果（CSV）"
                };
                if (dlg.ShowDialog() != true) return;

                var options = new ExportOptions
                {
                    Title = $"综合扫描结果 - {_result.TargetIp}",
                    TotalTargets = 1,
                    TotalOpenPorts = _result.OpenPortsCount,
                    TotalVulnerabilities = _result.VulnerabilitiesCount
                };
                var content = _exportService.ExportToCsv(_result.AllPortResults, _result.VulnerabilityResults, options);
                await File.WriteAllTextAsync(dlg.FileName, content);
                MessageBox.Show($"已导出到:\n{dlg.FileName}", "导出成功", MessageBoxButton.OK, MessageBoxImage.Information);
            }
            catch (Exception ex)
            {
                MessageBox.Show($"导出 CSV 失败: {ex.Message}", "错误", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        private async void CompareButton_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                var history = await _db.GetScanHistoryAsync();
                var sameTarget = history?
                    .Where(h => string.Equals(h.TargetIp, _result.TargetIp, StringComparison.OrdinalIgnoreCase) && h.ScanId != _result.ScanId)
                    .OrderByDescending(h => h.ScanTime)
                    .FirstOrDefault();

                if (sameTarget == null)
                {
                    MessageBox.Show($"暂无目标 {_result.TargetIp} 的历史扫描可对比。\n（先对同一目标跑一次扫描再回来对比。）",
                        "无历史", MessageBoxButton.OK, MessageBoxImage.Information);
                    return;
                }

                var sb = new StringBuilder();
                sb.AppendLine($"📈 历史对比：{_result.ScanId} vs {sameTarget.ScanId}");
                sb.AppendLine($"─────────────────────────────────────");
                sb.AppendLine($"本次扫描: {_result.ScanTime:yyyy-MM-dd HH:mm:ss}  开放端口 {_result.OpenPortsCount}  漏洞 {_result.VulnerabilitiesCount}  风险 {_result.RiskLevel}");
                sb.AppendLine($"历史扫描: {sameTarget.ScanTime:yyyy-MM-dd HH:mm:ss}  开放端口 {sameTarget.OpenPortsCount}  漏洞 {sameTarget.VulnerabilitiesCount}  风险 {sameTarget.RiskLevel}");
                sb.AppendLine();

                // v1.0.1.4 P0 修复: 对比时同时考虑"开放"和"开放或过滤"端口
                var currentPorts = new HashSet<int>(_result.AllPortResults
                    .Where(p => p.Status == "开放" || p.Status == "开放或过滤")
                    .Select(p => p.PortNumber));
                var historyPorts = new HashSet<int>(sameTarget.PortScanResults?
                    .Where(p => p.Status == "开放" || p.Status == "开放或过滤")
                    .Select(p => p.PortNumber) ?? new List<int>());

                var newPorts = currentPorts.Except(historyPorts).OrderBy(p => p).ToList();
                var closedPorts = historyPorts.Except(currentPorts).OrderBy(p => p).ToList();
                var persistentPorts = currentPorts.Intersect(historyPorts).OrderBy(p => p).ToList();

                sb.AppendLine($"🆕 新增开放端口 ({newPorts.Count}): {(newPorts.Count > 0 ? string.Join(", ", newPorts) : "无")}");
                sb.AppendLine($"❌ 关闭端口 ({closedPorts.Count}): {(closedPorts.Count > 0 ? string.Join(", ", closedPorts) : "无")}");
                sb.AppendLine($"🔁 持续开放 ({persistentPorts.Count}): {(persistentPorts.Count > 0 ? string.Join(", ", persistentPorts) : "无")}");

                MessageBox.Show(sb.ToString(), "历史对比结果", MessageBoxButton.OK, MessageBoxImage.Information);
            }
            catch (Exception ex)
            {
                MessageBox.Show($"对比失败: {ex.Message}", "错误", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        private void CopyMarkdownButton_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                var sb = new StringBuilder();
                sb.AppendLine($"# 综合扫描结果");
                sb.AppendLine();
                sb.AppendLine($"- **目标**:`{_result.TargetIp}`");
                sb.AppendLine($"- **扫描类型**:{_result.ScanType}");
                sb.AppendLine($"- **扫描时间**:`{_result.ScanTime:yyyy-MM-dd HH:mm:ss}`");
                sb.AppendLine($"- **耗时**:{_result.ScanDurationSeconds:F1} 秒");
                sb.AppendLine($"- **主机存活**:{(_result.HostAlive ? "是" : "否")}");
                sb.AppendLine($"- **开放端口**:{_result.OpenPortsCount}（TCP {_result.TcpOpenPorts} / UDP {_result.UdpOpenPorts}）");
                sb.AppendLine($"- **漏洞数**:{_result.VulnerabilitiesCount}");
                sb.AppendLine($"- **风险等级**:**{_result.RiskLevel}**");
                sb.AppendLine();
                sb.AppendLine("## 阶段耗时");
                sb.AppendLine();
                sb.AppendLine("| 阶段 | 状态 | 耗时 | 输出 |");
                sb.AppendLine("|---|---|---|---|");
                foreach (var p in _result.Phases)
                {
                    sb.AppendLine($"| {p.PhaseName} | {p.Status} | {p.DurationMs} ms | {p.OutputCount} |");
                }
                sb.AppendLine();
                if (_result.AllPortResults?.Any(p => p.Status == "开放") == true)
                {
                    sb.AppendLine("## 开放端口");
                    sb.AppendLine();
                    sb.AppendLine("| 端口 | 协议 | 服务 | 版本 |");
                    sb.AppendLine("|---|---|---|---|");
                    foreach (var port in _result.AllPortResults.Where(p => p.Status == "开放").OrderBy(p => p.PortNumber))
                    {
                        // PortScanResult 不带 Protocol 字段，默认显示 TCP（v1.0.1.3 已知限制：UDP 端口也显示为 TCP）
                        sb.AppendLine($"| {port.PortNumber} | TCP | {port.Service} | {port.ServiceVersion} |");
                    }
                }

                try { Clipboard.SetText(sb.ToString()); } catch { /* 剪贴板不可用时静默 */ }
                MessageBox.Show("Markdown 摘要已复制到剪贴板。", "复制成功", MessageBoxButton.OK, MessageBoxImage.Information);
            }
            catch (Exception ex)
            {
                MessageBox.Show($"复制失败: {ex.Message}", "错误", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        private void CloseButton_Click(object sender, RoutedEventArgs e)
        {
            Close();
        }
    }
}
