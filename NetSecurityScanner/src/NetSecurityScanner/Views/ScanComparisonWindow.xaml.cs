using Microsoft.Win32;
using NetSecurityScanner.Models;
using NetSecurityScanner.Services;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;

namespace NetSecurityScanner.Views
{
    public partial class ScanComparisonWindow : Window
    {
        private readonly ScanHistoryService _historyService;
        private readonly ScanComparisonService _comparisonService;
        private List<ScanHistory> _scanHistoryList;
        private ScanComparisonResult _comparisonResult;

        public ScanComparisonWindow()
        {
            InitializeComponent();
            _historyService = new ScanHistoryService();
            _comparisonService = new ScanComparisonService();
            _scanHistoryList = new List<ScanHistory>();

            Loaded += ScanComparisonWindow_Loaded;
        }

        private async void ScanComparisonWindow_Loaded(object sender, RoutedEventArgs e)
        {
            await LoadScanHistoryAsync();
        }

        private async Task LoadScanHistoryAsync()
        {
            try
            {
                _scanHistoryList = await _historyService.GetScanHistoryAsync();

                // 填充下拉框
                var scanItems = _scanHistoryList.Select(s => new
                {
                    Display = $"{s.Target} - {s.ScanTime:yyyy-MM-dd HH:mm} ({s.TotalVulnerabilities}个漏洞)",
                    Value = s
                }).ToList();

                BaselineScanComboBox.ItemsSource = scanItems;
                BaselineScanComboBox.DisplayMemberPath = "Display";
                BaselineScanComboBox.SelectedValuePath = "Value";

                CurrentScanComboBox.ItemsSource = scanItems;
                CurrentScanComboBox.DisplayMemberPath = "Display";
                CurrentScanComboBox.SelectedValuePath = "Value";

                if (scanItems.Count >= 2)
                {
                    BaselineScanComboBox.SelectedIndex = 1; // 选择倒数第二个
                    CurrentScanComboBox.SelectedIndex = 0;  // 选择最新的
                }
            }
            catch (Exception ex)
            {
                MessageBox.Show($"加载扫描历史失败: {ex.Message}", "错误", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        private void BaselineScanComboBox_SelectionChanged(object sender, SelectionChangedEventArgs e)
        {
            UpdateScanInfo(BaselineScanComboBox.SelectedItem, BaselineScanInfoTextBlock);
        }

        private void CurrentScanComboBox_SelectionChanged(object sender, SelectionChangedEventArgs e)
        {
            UpdateScanInfo(CurrentScanComboBox.SelectedItem, CurrentScanInfoTextBlock);
        }

        private void UpdateScanInfo(object selectedItem, TextBlock infoTextBlock)
        {
            if (selectedItem == null)
            {
                infoTextBlock.Text = "请选择扫描记录";
                return;
            }

            dynamic item = selectedItem;
            ScanHistory scan = item.Value;

            infoTextBlock.Text = $"目标: {scan.Target} | 时间: {scan.ScanTime:yyyy-MM-dd HH:mm} | 漏洞: {scan.TotalVulnerabilities}个 | 风险: {scan.ScanStatus}";
        }

        private void CompareButton_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                if (BaselineScanComboBox.SelectedItem == null || CurrentScanComboBox.SelectedItem == null)
                {
                    MessageBox.Show("请选择基线扫描和当前扫描", "提示", MessageBoxButton.OK, MessageBoxImage.Information);
                    return;
                }

                dynamic baselineItem = BaselineScanComboBox.SelectedItem;
                dynamic currentItem = CurrentScanComboBox.SelectedItem;

                ScanHistory baseline = baselineItem.Value;
                ScanHistory current = currentItem.Value;

                if (baseline.ScanId == current.ScanId)
                {
                    MessageBox.Show("基线扫描和当前扫描不能相同", "提示", MessageBoxButton.OK, MessageBoxImage.Warning);
                    return;
                }

                // 执行对比
                _comparisonResult = _comparisonService.CompareScans(baseline, current);

                // 显示结果
                DisplayComparisonResult();

                ComparisonResultTabControl.Visibility = Visibility.Visible;
                ExportComparisonButton.IsEnabled = true;

                MessageBox.Show("扫描对比完成！", "对比完成", MessageBoxButton.OK, MessageBoxImage.Information);
            }
            catch (Exception ex)
            {
                MessageBox.Show($"对比扫描失败: {ex.Message}", "错误", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        private void DisplayComparisonResult()
        {
            if (_comparisonResult == null) return;

            // 风险评分
            BaselineRiskScoreTextBlock.Text = _comparisonResult.BaselineRiskScore.ToString("F1");
            CurrentRiskScoreTextBlock.Text = _comparisonResult.CurrentRiskScore.ToString("F1");

            var change = _comparisonResult.RiskScoreChange;
            RiskScoreChangeTextBlock.Text = $"({(change >= 0 ? "+" : "")}{change:F1})";
            RiskScoreChangeTextBlock.Foreground = change > 0
                ? System.Windows.Media.Brushes.Red
                : change < 0
                    ? System.Windows.Media.Brushes.Green
                    : System.Windows.Media.Brushes.Gray;

            // 统计卡片
            ResolvedCountTextBlock.Text = _comparisonResult.ResolvedVulnerabilities.Count.ToString();
            NewCountTextBlock.Text = _comparisonResult.NewVulnerabilities.Count.ToString();
            PersistentCountTextBlock.Text = _comparisonResult.PersistentVulnerabilities.Count.ToString();
            RiskChangedCountTextBlock.Text = _comparisonResult.RiskChangedVulnerabilities.Count.ToString();

            // 端口变化
            NewPortsTextBlock.Text = $"新开放: {_comparisonResult.NewOpenPorts.Count}";
            ClosedPortsTextBlock.Text = $"已关闭: {_comparisonResult.ClosedPorts.Count}";
            PersistentPortsTextBlock.Text = $"仍开放: {_comparisonResult.PersistentOpenPorts.Count}";

            // 漏洞列表
            NewVulnerabilitiesDataGrid.ItemsSource = _comparisonResult.NewVulnerabilities;
            ResolvedVulnerabilitiesDataGrid.ItemsSource = _comparisonResult.ResolvedVulnerabilities;
            PersistentVulnerabilitiesDataGrid.ItemsSource = _comparisonResult.PersistentVulnerabilities;
        }

        private async void ExportComparisonButton_Click(object sender, RoutedEventArgs e)
        {
            if (_comparisonResult == null) return;

            try
            {
                var dialog = new SaveFileDialog
                {
                    Filter = "文本文件|*.txt|HTML文件|*.html",
                    FileName = $"扫描对比报告_{DateTime.Now:yyyyMMdd_HHmmss}",
                    Title = "导出对比报告"
                };

                if (dialog.ShowDialog() != true) return;

                string filePath = dialog.FileName;
                string extension = System.IO.Path.GetExtension(filePath).ToLower();

                string content;
                if (extension == ".html")
                {
                    content = GenerateHtmlComparisonReport();
                }
                else
                {
                    content = _comparisonService.GenerateComparisonSummary(_comparisonResult);
                }

                await File.WriteAllTextAsync(filePath, content);

                MessageBox.Show($"对比报告已保存到:\n{filePath}", "导出成功", MessageBoxButton.OK, MessageBoxImage.Information);
            }
            catch (Exception ex)
            {
                MessageBox.Show($"导出报告失败: {ex.Message}", "错误", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        private string GenerateHtmlComparisonReport()
        {
            if (_comparisonResult == null) return string.Empty;

            var sb = new System.Text.StringBuilder();
            sb.AppendLine("<!DOCTYPE html>");
            sb.AppendLine("<html><head><meta charset='UTF-8'>");
            sb.AppendLine("<title>扫描结果对比报告</title>");
            sb.AppendLine("<style>");
            sb.AppendLine("body { font-family: Arial, sans-serif; margin: 40px; background: #f5f5f5; }");
            sb.AppendLine(".header { background: linear-gradient(135deg, #f093fb 0%, #f5576c 100%); color: white; padding: 30px; text-align: center; border-radius: 8px; }");
            sb.AppendLine(".summary { background: white; padding: 20px; margin: 20px 0; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }");
            sb.AppendLine(".stat-grid { display: grid; grid-template-columns: repeat(4, 1fr); gap: 15px; margin: 20px 0; }");
            sb.AppendLine(".stat-card { padding: 20px; border-radius: 8px; text-align: center; }");
            sb.AppendLine(".stat-card.resolved { background: #E8F5E9; color: #27AE60; }");
            sb.AppendLine(".stat-card.new { background: #FFEBEE; color: #E74C3C; }");
            sb.AppendLine(".stat-card.persistent { background: #FFF3E0; color: #E67E22; }");
            sb.AppendLine(".stat-card.changed { background: #E3F2FD; color: #3498DB; }");
            sb.AppendLine(".stat-number { font-size: 36px; font-weight: bold; }");
            sb.AppendLine("table { width: 100%; background: white; border-collapse: collapse; margin: 20px 0; }");
            sb.AppendLine("th { background: #3498db; color: white; padding: 12px; text-align: left; }");
            sb.AppendLine("td { padding: 10px; border-bottom: 1px solid #ddd; }");
            sb.AppendLine("tr:hover { background: #f5f5f5; }");
            sb.AppendLine(".risk-critical { color: #e74c3c; font-weight: bold; }");
            sb.AppendLine(".risk-high { color: #e67e22; font-weight: bold; }");
            sb.AppendLine(".risk-medium { color: #f1c40f; font-weight: bold; }");
            sb.AppendLine("</style></head><body>");

            sb.AppendLine("<div class='header'><h1>📊 扫描结果对比报告</h1>");
            sb.AppendLine($"<p>对比时间: {_comparisonResult.ComparisonTime:yyyy-MM-dd HH:mm:ss}</p></div>");

            // 扫描信息
            sb.AppendLine("<div class='summary'>");
            sb.AppendLine("<h2>📅 扫描信息</h2>");
            sb.AppendLine($"<p><strong>基线扫描:</strong> {_comparisonResult.BaselineScan.Target} ({_comparisonResult.BaselineScan.ScanTime:yyyy-MM-dd HH:mm})</p>");
            sb.AppendLine($"<p><strong>当前扫描:</strong> {_comparisonResult.CurrentScan.Target} ({_comparisonResult.CurrentScan.ScanTime:yyyy-MM-dd HH:mm})</p>");
            sb.AppendLine("</div>");

            // 风险评分变化
            sb.AppendLine("<div class='summary'>");
            sb.AppendLine("<h2>📈 风险评分变化</h2>");
            var changeSymbol = _comparisonResult.RiskScoreChange > 0 ? "📈" : _comparisonResult.RiskScoreChange < 0 ? "📉" : "➡️";
            sb.AppendLine($"<p style='font-size: 24px; text-align: center;'>{changeSymbol} {_comparisonResult.BaselineRiskScore:F1} → {_comparisonResult.CurrentRiskScore:F1} ({_comparisonResult.RiskScoreChange:F1})</p>");
            sb.AppendLine("</div>");

            // 统计卡片
            sb.AppendLine("<div class='stat-grid'>");
            sb.AppendLine($"<div class='stat-card resolved'><div class='stat-number'>{_comparisonResult.ResolvedVulnerabilities.Count}</div><div>✅ 已修复</div></div>");
            sb.AppendLine($"<div class='stat-card new'><div class='stat-number'>{_comparisonResult.NewVulnerabilities.Count}</div><div>⚠️ 新增</div></div>");
            sb.AppendLine($"<div class='stat-card persistent'><div class='stat-number'>{_comparisonResult.PersistentVulnerabilities.Count}</div><div>📌 仍存在</div></div>");
            sb.AppendLine($"<div class='stat-card changed'><div class='stat-number'>{_comparisonResult.RiskChangedVulnerabilities.Count}</div><div>🔄 风险变化</div></div>");
            sb.AppendLine("</div>");

            // 新增漏洞
            if (_comparisonResult.NewVulnerabilities.Any())
            {
                sb.AppendLine("<div class='summary'>");
                sb.AppendLine("<h2>⚠️ 新增漏洞</h2>");
                sb.AppendLine("<table><thead><tr><th>CVE编号</th><th>漏洞名称</th><th>风险等级</th><th>端口</th><th>服务</th></tr></thead><tbody>");
                foreach (var vuln in _comparisonResult.NewVulnerabilities)
                {
                    var riskClass = vuln.RiskLevel == "严重" ? "risk-critical" : vuln.RiskLevel == "高危" ? "risk-high" : "risk-medium";
                    sb.AppendLine($"<tr><td>{vuln.CveId}</td><td>{vuln.Name}</td><td class='{riskClass}'>{vuln.RiskLevel}</td><td>{vuln.Port}</td><td>{vuln.Service}</td></tr>");
                }
                sb.AppendLine("</tbody></table>");
                sb.AppendLine("</div>");
            }

            // 已修复漏洞
            if (_comparisonResult.ResolvedVulnerabilities.Any())
            {
                sb.AppendLine("<div class='summary'>");
                sb.AppendLine("<h2>✅ 已修复漏洞</h2>");
                sb.AppendLine("<table><thead><tr><th>CVE编号</th><th>漏洞名称</th><th>风险等级</th><th>端口</th><th>服务</th></tr></thead><tbody>");
                foreach (var vuln in _comparisonResult.ResolvedVulnerabilities)
                {
                    sb.AppendLine($"<tr><td>{vuln.CveId}</td><td>{vuln.Name}</td><td>{vuln.RiskLevel}</td><td>{vuln.Port}</td><td>{vuln.Service}</td></tr>");
                }
                sb.AppendLine("</tbody></table>");
                sb.AppendLine("</div>");
            }

            sb.AppendLine($"<p style='text-align: center; color: #7f8c8d; margin-top: 40px;'>由 NetSecurityScanner 生成</p>");
            sb.AppendLine("</body></html>");

            return sb.ToString();
        }

        private void CloseComparisonButton_Click(object sender, RoutedEventArgs e)
        {
            Close();
        }
    }
}
