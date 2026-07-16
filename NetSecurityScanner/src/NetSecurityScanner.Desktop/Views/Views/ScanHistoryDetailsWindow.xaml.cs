using Microsoft.Win32;
using NetSecurityScanner.Models;
using System;
using System.IO;
using System.Text;
using System.Threading.Tasks;
using System.Windows;

namespace NetSecurityScanner.Views
{
    public partial class ScanHistoryDetailsWindow : Window
    {
        private readonly ScanHistory _history;

        public ScanHistoryDetailsWindow(ScanHistory history)
        {
            InitializeComponent();
            _history = history;
            LoadDetails();
        }

        private void LoadDetails()
        {
            if (_history == null) return;

            // 基本信息
            if (ScanIdTextBlock != null) ScanIdTextBlock.Text = $"扫描ID: {_history.ScanId}";
            if (TargetTextBlock != null) TargetTextBlock.Text = $"目标: {_history.Target}";
            if (ScanTimeTextBlock != null) ScanTimeTextBlock.Text = $"扫描时间: {_history.ScanTime:yyyy-MM-dd HH:mm:ss}";
            if (ScanModeTextBlock != null) ScanModeTextBlock.Text = $"扫描模式: {_history.ScanMode}";

            // 统计信息
            if (TotalVulnsTextBlock != null) TotalVulnsTextBlock.Text = $"漏洞总数: {_history.TotalVulnerabilities}";
            if (CriticalTextBlock != null) CriticalTextBlock.Text = $"严重: {_history.CriticalCount}";
            if (HighTextBlock != null) HighTextBlock.Text = $"高危: {_history.HighCount}";
            if (DurationTextBlock != null) DurationTextBlock.Text = $"扫描时长: {_history.Duration}";
            if (StatusTextBlock != null) StatusTextBlock.Text = $"状态: {_history.ScanStatus}";

            // 漏洞列表
            if (VulnerabilitiesDataGrid != null)
                VulnerabilitiesDataGrid.ItemsSource = _history.Vulnerabilities ?? new System.Collections.Generic.List<VulnerabilityRecord>();
        }

        private async void ExportButton_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                var dialog = new SaveFileDialog
                {
                    Filter = "文本文件|*.txt|HTML文件|*.html",
                    FileName = $"扫描详情_{_history.ScanId}_{_history.ScanTime:yyyyMMdd}",
                    Title = "导出扫描详情"
                };

                if (dialog.ShowDialog() != true) return;

                string filePath = dialog.FileName;
                string extension = Path.GetExtension(filePath).ToLower();

                string content;
                if (extension == ".html")
                {
                    content = GenerateHtmlContent();
                }
                else
                {
                    content = GenerateTextContent();
                }

                await File.WriteAllTextAsync(filePath, content, Encoding.UTF8);

                MessageBox.Show($"扫描详情已导出到:\n{filePath}", "导出成功", MessageBoxButton.OK, MessageBoxImage.Information);
            }
            catch (Exception ex)
            {
                MessageBox.Show($"导出失败: {ex.Message}", "错误", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        private string GenerateTextContent()
        {
            var sb = new StringBuilder();
            sb.AppendLine("=".PadRight(60, '='));
            sb.AppendLine("扫描详情报告");
            sb.AppendLine("=".PadRight(60, '='));
            sb.AppendLine();
            sb.AppendLine($"扫描ID: {_history.ScanId}");
            sb.AppendLine($"目标: {_history.Target}");
            sb.AppendLine($"扫描时间: {_history.ScanTime:yyyy-MM-dd HH:mm:ss}");
            sb.AppendLine($"扫描模式: {_history.ScanMode}");
            sb.AppendLine($"扫描时长: {_history.Duration}");
            sb.AppendLine();
            sb.AppendLine("漏洞统计:");
            sb.AppendLine($"  总数: {_history.TotalVulnerabilities}");
            sb.AppendLine($"  严重: {_history.CriticalCount}");
            sb.AppendLine($"  高危: {_history.HighCount}");
            sb.AppendLine($"  中危: {_history.MediumCount}");
            sb.AppendLine($"  低危: {_history.LowCount}");
            sb.AppendLine();
            sb.AppendLine("漏洞详情:");
            sb.AppendLine("-".PadRight(60, '-'));

            if (_history.Vulnerabilities != null)
            {
                foreach (var vuln in _history.Vulnerabilities)
                {
                    sb.AppendLine($"CVE: {vuln.CveId}");
                    sb.AppendLine($"名称: {vuln.Name}");
                    sb.AppendLine($"风险等级: {vuln.RiskLevel}");
                    sb.AppendLine($"端口: {vuln.Port}");
                    sb.AppendLine($"服务: {vuln.Service}");
                    sb.AppendLine($"描述: {vuln.Description}");
                    sb.AppendLine($"修复建议: {vuln.Solution}");
                    sb.AppendLine("-".PadRight(60, '-'));
                }
            }

            sb.AppendLine();
            sb.AppendLine("=".PadRight(60, '='));
            sb.AppendLine("报告结束");
            sb.AppendLine("=".PadRight(60, '='));

            return sb.ToString();
        }

        private string GenerateHtmlContent()
        {
            var sb = new StringBuilder();
            sb.AppendLine("<!DOCTYPE html>");
            sb.AppendLine("<html><head><meta charset='UTF-8'>");
            sb.AppendLine("<title>扫描详情报告</title>");
            sb.AppendLine("<style>");
            sb.AppendLine("body { font-family: Arial, sans-serif; margin: 40px; background: #f5f5f5; }");
            sb.AppendLine(".header { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 30px; text-align: center; border-radius: 8px; }");
            sb.AppendLine(".info { background: white; padding: 20px; margin: 20px 0; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }");
            sb.AppendLine(".vulnerability { background: white; padding: 15px; margin: 10px 0; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); border-left: 4px solid #3498db; }");
            sb.AppendLine(".risk-critical { border-left-color: #e74c3c; }");
            sb.AppendLine(".risk-high { border-left-color: #e67e22; }");
            sb.AppendLine(".risk-medium { border-left-color: #f1c40f; }");
            sb.AppendLine(".risk-low { border-left-color: #27ae60; }");
            sb.AppendLine("h1, h2, h3 { margin-top: 0; }");
            sb.AppendLine("</style></head><body>");

            sb.AppendLine("<div class='header'><h1>📋 扫描详情报告</h1>");
            sb.AppendLine($"<p>扫描ID: {_history.ScanId}</p></div>");

            sb.AppendLine("<div class='info'>");
            sb.AppendLine("<h2>基本信息</h2>");
            sb.AppendLine($"<p><strong>目标:</strong> {_history.Target}</p>");
            sb.AppendLine($"<p><strong>扫描时间:</strong> {_history.ScanTime:yyyy-MM-dd HH:mm:ss}</p>");
            sb.AppendLine($"<p><strong>扫描模式:</strong> {_history.ScanMode}</p>");
            sb.AppendLine($"<p><strong>扫描时长:</strong> {_history.Duration}</p>");
            sb.AppendLine("</div>");

            sb.AppendLine("<div class='info'>");
            sb.AppendLine("<h2>漏洞统计</h2>");
            sb.AppendLine($"<p><strong>总数:</strong> {_history.TotalVulnerabilities}</p>");
            sb.AppendLine($"<p><strong>严重:</strong> <span style='color: #e74c3c;'>{_history.CriticalCount}</span></p>");
            sb.AppendLine($"<p><strong>高危:</strong> <span style='color: #e67e22;'>{_history.HighCount}</span></p>");
            sb.AppendLine($"<p><strong>中危:</strong> {_history.MediumCount}</p>");
            sb.AppendLine($"<p><strong>低危:</strong> {_history.LowCount}</p>");
            sb.AppendLine("</div>");

            sb.AppendLine("<h2>漏洞详情</h2>");

            if (_history.Vulnerabilities != null)
            {
                foreach (var vuln in _history.Vulnerabilities)
                {
                    var riskClass = vuln.RiskLevel switch
                    {
                        "严重" => "risk-critical",
                        "高危" => "risk-high",
                        "中危" => "risk-medium",
                        _ => "risk-low"
                    };

                    sb.AppendLine($"<div class='vulnerability {riskClass}'>");
                    sb.AppendLine($"<h3>{vuln.Name}</h3>");
                    sb.AppendLine($"<p><strong>CVE:</strong> {vuln.CveId}</p>");
                    sb.AppendLine($"<p><strong>风险等级:</strong> {vuln.RiskLevel}</p>");
                    sb.AppendLine($"<p><strong>端口:</strong> {vuln.Port}</p>");
                    sb.AppendLine($"<p><strong>服务:</strong> {vuln.Service}</p>");
                    sb.AppendLine($"<p><strong>描述:</strong> {vuln.Description}</p>");
                    sb.AppendLine($"<p><strong>修复建议:</strong> {vuln.Solution}</p>");
                    sb.AppendLine("</div>");
                }
            }

            sb.AppendLine($"<p style='text-align: center; color: #7f8c8d; margin-top: 40px;'>由 NetSecurityScanner 生成</p>");
            sb.AppendLine("</body></html>");

            return sb.ToString();
        }

        private void CloseButton_Click(object sender, RoutedEventArgs e)
        {
            Close();
        }
    }
}
