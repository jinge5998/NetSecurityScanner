using Microsoft.Win32;
using NetSecurityScanner.Models;
using NetSecurityScanner.Services;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using System.Windows.Media;

namespace NetSecurityScanner.Views
{
    public partial class RemediationWizardWindow : Window
    {
        private readonly VulnerabilityRemediationService _remediationService;
        private RemediationPlan _remediationPlan;
        private RemediationPlanItem _currentItem;
        private List<VulnerabilityResult> _vulnerabilities;

        public RemediationWizardWindow(List<VulnerabilityResult> vulnerabilities)
        {
            InitializeComponent();
            _remediationService = new VulnerabilityRemediationService();
            _vulnerabilities = vulnerabilities ?? new List<VulnerabilityResult>();

            Loaded += RemediationWizardWindow_Loaded;
        }

        private void RemediationWizardWindow_Loaded(object sender, RoutedEventArgs e)
        {
            GenerateRemediationPlan();
        }

        private void GenerateRemediationPlan()
        {
            if (!_vulnerabilities.Any())
            {
                MessageBox.Show("没有需要修复的漏洞", "提示", MessageBoxButton.OK, MessageBoxImage.Information);
                return;
            }

            _remediationPlan = _remediationService.GenerateRemediationPlan(_vulnerabilities);
            UpdatePlanOverview();
            RenderVulnerabilityList();
        }

        private void UpdatePlanOverview()
        {
            if (_remediationPlan == null) return;

            TotalVulnerabilitiesTextBlock.Text = _remediationPlan.TotalVulnerabilities.ToString();
            EstimatedTimeTextBlock.Text = $"{_remediationPlan.EstimatedTotalTime.TotalMinutes:F0}分钟";

            int completed = _remediationPlan.Items.Count(i => i.Status == "Completed");
            CompletedCountTextBlock.Text = completed.ToString();

            double progress = _remediationPlan.TotalVulnerabilities > 0
                ? (double)completed / _remediationPlan.TotalVulnerabilities * 100
                : 0;
            ProgressTextBlock.Text = $"{progress:F0}%";
        }

        private void RenderVulnerabilityList()
        {
            VulnerabilityListPanel.Children.Clear();

            foreach (var item in _remediationPlan.Items)
            {
                var vulnBorder = new Border
                {
                    BorderBrush = GetRiskColor(item.Vulnerability.RiskLevel),
                    BorderThickness = new Thickness(2),
                    CornerRadius = new CornerRadius(4),
                    Padding = new Thickness(10),
                    Margin = new Thickness(0, 0, 0, 5),
                    Background = item.Status == "Completed" ? Brushes.LightGreen :
                                item.Status == "Skipped" ? Brushes.LightYellow : Brushes.White,
                    Cursor = Cursors.Hand,
                    Tag = item
                };

                vulnBorder.MouseLeftButtonUp += VulnerabilityItem_Click;

                var stackPanel = new StackPanel();

                // 优先级和风险等级
                var headerPanel = new StackPanel { Orientation = Orientation.Horizontal };
                headerPanel.Children.Add(new TextBlock
                {
                    Text = $"#{item.Priority}",
                    FontWeight = FontWeights.Bold,
                    Margin = new Thickness(0, 0, 10, 0),
                    Foreground = Brushes.Gray
                });
                headerPanel.Children.Add(new TextBlock
                {
                    Text = item.Vulnerability.RiskLevel,
                    FontWeight = FontWeights.Bold,
                    Foreground = GetRiskColor(item.Vulnerability.RiskLevel)
                });

                if (item.Status == "Completed")
                {
                    headerPanel.Children.Add(new TextBlock
                    {
                        Text = " ✓",
                        FontWeight = FontWeights.Bold,
                        Foreground = Brushes.Green,
                        Margin = new Thickness(10, 0, 0, 0)
                    });
                }

                stackPanel.Children.Add(headerPanel);

                // 漏洞名称
                stackPanel.Children.Add(new TextBlock
                {
                    Text = item.Vulnerability.Name,
                    FontWeight = FontWeights.SemiBold,
                    TextTrimming = TextTrimming.CharacterEllipsis,
                    Margin = new Thickness(0, 5, 0, 0)
                });

                // 端口和服务
                stackPanel.Children.Add(new TextBlock
                {
                    Text = $"端口 {item.Vulnerability.Port} | {item.Vulnerability.Service}",
                    FontSize = 11,
                    Foreground = Brushes.Gray,
                    Margin = new Thickness(0, 2, 0, 0)
                });

                // 预计修复时间
                stackPanel.Children.Add(new TextBlock
                {
                    Text = $"预计: {item.EstimatedTime.TotalMinutes:F0}分钟",
                    FontSize = 11,
                    Foreground = Brushes.Blue,
                    Margin = new Thickness(0, 2, 0, 0)
                });

                vulnBorder.Child = stackPanel;
                VulnerabilityListPanel.Children.Add(vulnBorder);
            }
        }

        private void VulnerabilityItem_Click(object sender, MouseButtonEventArgs e)
        {
            if (sender is Border border && border.Tag is RemediationPlanItem item)
            {
                _currentItem = item;
                DisplayRemediationGuide(item);
            }
        }

        private void DisplayRemediationGuide(RemediationPlanItem item)
        {
            // 更新当前漏洞信息
            CurrentVulnTitleTextBlock.Text = item.RemediationGuide.Title;
            CurrentVulnDescriptionTextBlock.Text = item.RemediationGuide.Description;
            CurrentVulnRiskTextBlock.Text = $"风险等级: {item.Vulnerability.RiskLevel}";
            CurrentVulnRiskTextBlock.Foreground = GetRiskColor(item.Vulnerability.RiskLevel);
            CurrentVulnPortTextBlock.Text = $"端口: {item.Vulnerability.Port}";
            CurrentVulnServiceTextBlock.Text = $"服务: {item.Vulnerability.Service}";

            // 渲染修复步骤
            RemediationStepsPanel.Children.Clear();

            foreach (var step in item.RemediationGuide.Steps)
            {
                var stepBorder = new Border
                {
                    Background = step.IsCompleted ? Brushes.LightGreen : Brushes.White,
                    BorderBrush = Brushes.LightGray,
                    BorderThickness = new Thickness(1),
                    CornerRadius = new CornerRadius(4),
                    Padding = new Thickness(15),
                    Margin = new Thickness(0, 0, 0, 10)
                };

                var stepStack = new StackPanel();

                // 步骤标题
                var titlePanel = new StackPanel { Orientation = Orientation.Horizontal };
                titlePanel.Children.Add(new TextBlock
                {
                    Text = $"步骤 {step.StepNumber}: ",
                    FontWeight = FontWeights.Bold,
                    FontSize = 14
                });
                titlePanel.Children.Add(new TextBlock
                {
                    Text = step.Title,
                    FontWeight = FontWeights.Bold,
                    FontSize = 14
                });

                if (step.IsAutomated)
                {
                    titlePanel.Children.Add(new TextBlock
                    {
                        Text = " [可自动执行]",
                        Foreground = Brushes.Green,
                        FontSize = 12,
                        Margin = new Thickness(5, 0, 0, 0)
                    });
                }

                stepStack.Children.Add(titlePanel);

                // 步骤描述
                stepStack.Children.Add(new TextBlock
                {
                    Text = step.Description,
                    TextWrapping = TextWrapping.Wrap,
                    Margin = new Thickness(0, 5, 0, 0)
                });

                // 命令框
                if (!string.IsNullOrEmpty(step.Command))
                {
                    var commandBorder = new Border
                    {
                        Background = Brushes.Black,
                        CornerRadius = new CornerRadius(4),
                        Padding = new Thickness(10),
                        Margin = new Thickness(0, 10, 0, 0)
                    };

                    var commandText = new TextBlock
                    {
                        Text = step.Command,
                        Foreground = Brushes.LightGreen,
                        FontFamily = new FontFamily("Consolas"),
                        TextWrapping = TextWrapping.Wrap
                    };

                    commandBorder.Child = commandText;
                    stepStack.Children.Add(commandBorder);
                }

                stepBorder.Child = stepStack;
                RemediationStepsPanel.Children.Add(stepBorder);
            }

            // 参考链接
            if (item.RemediationGuide.References.Any())
            {
                var refBorder = new Border
                {
                    Background = Brushes.LightBlue,
                    CornerRadius = new CornerRadius(4),
                    Padding = new Thickness(10),
                    Margin = new Thickness(0, 10, 0, 0)
                };

                var refStack = new StackPanel();
                refStack.Children.Add(new TextBlock
                {
                    Text = "📚 参考链接:",
                    FontWeight = FontWeights.Bold,
                    Margin = new Thickness(0, 0, 0, 5)
                });

                foreach (var reference in item.RemediationGuide.References)
                {
                    var linkText = new TextBlock
                    {
                        Text = reference,
                        Foreground = Brushes.Blue,
                        TextDecorations = TextDecorations.Underline,
                        Cursor = Cursors.Hand,
                        Margin = new Thickness(0, 2, 0, 0)
                    };
                    linkText.MouseLeftButtonUp += (s, e) =>
                    {
                        try
                        {
                            System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo
                            {
                                FileName = reference,
                                UseShellExecute = true
                            });
                        }
                        catch (Exception ex)
                        {
                            System.Diagnostics.Debug.WriteLine($"[RemediationWizardWindow] 打开参考链接失败: {ex.Message}");
                        }
                    };
                    refStack.Children.Add(linkText);
                }

                refBorder.Child = refStack;
                RemediationStepsPanel.Children.Add(refBorder);
            }
        }

        private Brush GetRiskColor(string riskLevel)
        {
            return riskLevel switch
            {
                "严重" => Brushes.Red,
                "高危" => Brushes.Orange,
                "中危" => Brushes.Goldenrod,
                "低危" => Brushes.Green,
                _ => Brushes.Gray
            };
        }

        private void CopyCommandButton_Click(object sender, RoutedEventArgs e)
        {
            if (_currentItem == null) return;

            var commands = string.Join("\n\n", _currentItem.RemediationGuide.Steps
                .Where(s => !string.IsNullOrEmpty(s.Command))
                .Select(s => $"# {s.Title}\n{s.Command}"));

            if (!string.IsNullOrEmpty(commands))
            {
                Clipboard.SetText(commands);
                MessageBox.Show("命令已复制到剪贴板", "复制成功", MessageBoxButton.OK, MessageBoxImage.Information);
            }
        }

        private void MarkCompletedButton_Click(object sender, RoutedEventArgs e)
        {
            if (_currentItem == null) return;

            _currentItem.Status = "Completed";
            UpdatePlanOverview();
            RenderVulnerabilityList();

            // 自动选择下一个未完成的漏洞
            var nextItem = _remediationPlan.Items.FirstOrDefault(i => i.Status == "Pending");
            if (nextItem != null)
            {
                _currentItem = nextItem;
                DisplayRemediationGuide(nextItem);
            }
        }

        private void SkipButton_Click(object sender, RoutedEventArgs e)
        {
            if (_currentItem == null) return;

            _currentItem.Status = "Skipped";
            UpdatePlanOverview();
            RenderVulnerabilityList();

            // 自动选择下一个未完成的漏洞
            var nextItem = _remediationPlan.Items.FirstOrDefault(i => i.Status == "Pending");
            if (nextItem != null)
            {
                _currentItem = nextItem;
                DisplayRemediationGuide(nextItem);
            }
        }

        private async void GenerateReportButton_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                var dialog = new SaveFileDialog
                {
                    Filter = "文本文件|*.txt|HTML文件|*.html",
                    FileName = $"漏洞修复报告_{DateTime.Now:yyyyMMdd_HHmmss}",
                    Title = "保存修复报告"
                };

                if (dialog.ShowDialog() != true) return;

                string filePath = dialog.FileName;
                string extension = System.IO.Path.GetExtension(filePath).ToLower();

                string content;
                if (extension == ".html")
                {
                    content = GenerateHtmlReport();
                }
                else
                {
                    content = GenerateTextReport();
                }

                await File.WriteAllTextAsync(filePath, content);

                MessageBox.Show($"修复报告已保存到:\n{filePath}", "导出成功", MessageBoxButton.OK, MessageBoxImage.Information);
            }
            catch (Exception ex)
            {
                MessageBox.Show($"生成报告失败: {ex.Message}", "错误", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        private string GenerateTextReport()
        {
            var sb = new StringBuilder();
            sb.AppendLine("=".PadRight(60, '='));
            sb.AppendLine("漏洞修复报告");
            sb.AppendLine("=".PadRight(60, '='));
            sb.AppendLine($"生成时间: {DateTime.Now:yyyy-MM-dd HH:mm:ss}");
            sb.AppendLine($"总漏洞数: {_remediationPlan.TotalVulnerabilities}");
            sb.AppendLine($"已完成: {_remediationPlan.Items.Count(i => i.Status == "Completed")}");
            sb.AppendLine($"已跳过: {_remediationPlan.Items.Count(i => i.Status == "Skipped")}");
            sb.AppendLine($"待修复: {_remediationPlan.Items.Count(i => i.Status == "Pending")}");
            sb.AppendLine();

            foreach (var item in _remediationPlan.Items)
            {
                sb.AppendLine("-".PadRight(60, '-'));
                sb.AppendLine($"优先级: #{item.Priority}");
                sb.AppendLine($"漏洞: {item.Vulnerability.Name}");
                sb.AppendLine($"风险等级: {item.Vulnerability.RiskLevel}");
                sb.AppendLine($"端口: {item.Vulnerability.Port}");
                sb.AppendLine($"服务: {item.Vulnerability.Service}");
                sb.AppendLine($"状态: {item.Status}");
                sb.AppendLine($"预计修复时间: {item.EstimatedTime.TotalMinutes}分钟");
                sb.AppendLine();

                sb.AppendLine("修复步骤:");
                foreach (var step in item.RemediationGuide.Steps)
                {
                    sb.AppendLine($"  {step.StepNumber}. {step.Title}");
                    sb.AppendLine($"     {step.Description}");
                    if (!string.IsNullOrEmpty(step.Command))
                    {
                        sb.AppendLine($"     命令: {step.Command}");
                    }
                    sb.AppendLine();
                }

                if (item.RemediationGuide.References.Any())
                {
                    sb.AppendLine("参考链接:");
                    foreach (var reference in item.RemediationGuide.References)
                    {
                        sb.AppendLine($"  - {reference}");
                    }
                }

                sb.AppendLine();
            }

            sb.AppendLine("=".PadRight(60, '='));
            sb.AppendLine("报告结束");
            sb.AppendLine("=".PadRight(60, '='));

            return sb.ToString();
        }

        private string GenerateHtmlReport()
        {
            var sb = new StringBuilder();
            sb.AppendLine("<!DOCTYPE html>");
            sb.AppendLine("<html><head><meta charset='UTF-8'>");
            sb.AppendLine("<title>漏洞修复报告</title>");
            sb.AppendLine("<style>");
            sb.AppendLine("body { font-family: Arial, sans-serif; margin: 40px; background: #f5f5f5; }");
            sb.AppendLine(".header { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 30px; text-align: center; border-radius: 8px; }");
            sb.AppendLine(".summary { background: white; padding: 20px; margin: 20px 0; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }");
            sb.AppendLine(".vulnerability { background: white; padding: 20px; margin: 20px 0; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); border-left: 4px solid #3498db; }");
            sb.AppendLine(".step { background: #f8f9fa; padding: 15px; margin: 10px 0; border-radius: 4px; }");
            sb.AppendLine(".command { background: #2c3e50; color: #2ecc71; padding: 10px; border-radius: 4px; font-family: monospace; margin: 10px 0; }");
            sb.AppendLine(".risk-critical { border-left-color: #e74c3c; }");
            sb.AppendLine(".risk-high { border-left-color: #e67e22; }");
            sb.AppendLine(".risk-medium { border-left-color: #f1c40f; }");
            sb.AppendLine(".risk-low { border-left-color: #27ae60; }");
            sb.AppendLine(".status-completed { background: #d4edda; }");
            sb.AppendLine(".status-skipped { background: #fff3cd; }");
            sb.AppendLine("h1, h2, h3 { margin-top: 0; }");
            sb.AppendLine("</style></head><body>");

            sb.AppendLine("<div class='header'><h1>🔧 漏洞修复报告</h1>");
            sb.AppendLine($"<p>生成时间: {DateTime.Now:yyyy-MM-dd HH:mm:ss}</p></div>");

            // 概要
            sb.AppendLine("<div class='summary'>");
            sb.AppendLine("<h2>📊 修复概览</h2>");
            sb.AppendLine($"<p><strong>总漏洞数:</strong> {_remediationPlan.TotalVulnerabilities}</p>");
            sb.AppendLine($"<p><strong>已完成:</strong> {_remediationPlan.Items.Count(i => i.Status == "Completed")}</p>");
            sb.AppendLine($"<p><strong>已跳过:</strong> {_remediationPlan.Items.Count(i => i.Status == "Skipped")}</p>");
            sb.AppendLine($"<p><strong>待修复:</strong> {_remediationPlan.Items.Count(i => i.Status == "Pending")}</p>");
            sb.AppendLine($"<p><strong>预计总耗时:</strong> {_remediationPlan.EstimatedTotalTime.TotalMinutes}分钟</p>");
            sb.AppendLine("</div>");

            // 漏洞详情
            foreach (var item in _remediationPlan.Items)
            {
                var riskClass = item.Vulnerability.RiskLevel switch
                {
                    "严重" => "risk-critical",
                    "高危" => "risk-high",
                    "中危" => "risk-medium",
                    _ => "risk-low"
                };

                var statusClass = item.Status switch
                {
                    "Completed" => "status-completed",
                    "Skipped" => "status-skipped",
                    _ => ""
                };

                sb.AppendLine($"<div class='vulnerability {riskClass} {statusClass}'>");
                sb.AppendLine($"<h3>#{item.Priority} {item.Vulnerability.Name}</h3>");
                sb.AppendLine($"<p><strong>风险等级:</strong> {item.Vulnerability.RiskLevel} | ");
                sb.AppendLine($"<strong>端口:</strong> {item.Vulnerability.Port} | ");
                sb.AppendLine($"<strong>服务:</strong> {item.Vulnerability.Service} | ");
                sb.AppendLine($"<strong>状态:</strong> {item.Status}</p>");

                sb.AppendLine("<h4>修复步骤:</h4>");
                foreach (var step in item.RemediationGuide.Steps)
                {
                    sb.AppendLine("<div class='step'>");
                    sb.AppendLine($"<strong>步骤 {step.StepNumber}: {step.Title}</strong>");
                    sb.AppendLine($"<p>{step.Description}</p>");
                    if (!string.IsNullOrEmpty(step.Command))
                    {
                        sb.AppendLine($"<div class='command'>{System.Web.HttpUtility.HtmlEncode(step.Command)}</div>");
                    }
                    sb.AppendLine("</div>");
                }

                sb.AppendLine("</div>");
            }

            sb.AppendLine($"<p style='text-align: center; color: #7f8c8d; margin-top: 40px;'>由 NetSecurityScanner 生成</p>");
            sb.AppendLine("</body></html>");

            return sb.ToString();
        }

        private void CloseWizardButton_Click(object sender, RoutedEventArgs e)
        {
            Close();
        }
    }
}
