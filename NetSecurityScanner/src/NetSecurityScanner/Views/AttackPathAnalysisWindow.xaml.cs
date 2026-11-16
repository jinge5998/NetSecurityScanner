using Microsoft.Win32;
using NetSecurityScanner.Models;
using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Text.Json;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Media;

namespace NetSecurityScanner.Views
{
    public partial class AttackPathAnalysisWindow : Window
    {
        private List<AttackPath> _attackPaths = new List<AttackPath>();
        private List<AttackPath> _allAttackPaths = new List<AttackPath>();
        private ObservableCollection<AttackPathDisplayModel> _attackPathItems = new ObservableCollection<AttackPathDisplayModel>();
        private string _currentFilter = "全部";

        public AttackPathAnalysisWindow(List<AttackPath> attackPaths = null)
        {
            InitializeComponent();
            _attackPaths = attackPaths ?? new List<AttackPath>();
            _allAttackPaths = new List<AttackPath>(_attackPaths);
            LoadAttackPaths();
            CalculateOverallRiskSummary();
        }

        private void CalculateOverallRiskSummary()
        {
            if (!_attackPaths.Any())
            {
                StatusText.Text = "未检测到攻击路径";
                return;
            }

            var criticalCount = _attackPaths.Count(p => p.RiskScore >= 80);
            var highCount = _attackPaths.Count(p => p.RiskScore >= 60 && p.RiskScore < 80);
            var mediumCount = _attackPaths.Count(p => p.RiskScore >= 40 && p.RiskScore < 60);
            var lowCount = _attackPaths.Count(p => p.RiskScore < 40);
            var avgRiskScore = _attackPaths.Average(p => p.RiskScore);

            var summary = $"严重:{criticalCount} | 高危:{highCount} | 中危:{mediumCount} | 低危:{lowCount} | 平均风险:{avgRiskScore:F0}";
            StatusText.Text = summary;
        }

        private void LoadAttackPaths()
        {
            _attackPathItems.Clear();
            
            var filteredPaths = _currentFilter == "全部"
                ? _attackPaths
                : _attackPaths.Where(p => GetRiskLevel(p.RiskScore) == _currentFilter).ToList();

            var sortedPaths = filteredPaths.OrderByDescending(p => p.RiskScore).ThenByDescending(p => p.SuccessProbability);

            foreach (var path in sortedPaths)
            {
                var displayModel = new AttackPathDisplayModel
                {
                    PathId = path.PathId,
                    Name = path.Name,
                    Description = path.Description,
                    RiskScore = path.RiskScore,
                    RiskLevel = GetRiskLevel(path.RiskScore),
                    SuccessProbability = path.SuccessProbability,
                    Complexity = path.Complexity,
                    StepCount = path.Steps.Count,
                    EstimatedTime = EstimateAttackTime(path),
                    Priority = GetPriorityLevel(path)
                };
                
                _attackPathItems.Add(displayModel);
            }

            AttackPathListBox.ItemsSource = _attackPathItems;
            PathCountText.Text = $"共 {_attackPathItems.Count} 条路径";
            StatusText.Text = $"已加载 {_attackPathItems.Count} 条攻击路径";
            LastUpdateText.Text = $"更新时间: {DateTime.Now:yyyy-MM-dd HH:mm:ss}";
        }

        private void ApplyFilter(string filter)
        {
            _currentFilter = filter;
            LoadAttackPaths();

            FilterAllButton.Background = new SolidColorBrush((Color)ColorConverter.ConvertFromString(filter == "全部" ? "#3498db" : "#e0e0e0"));
            FilterAllButton.Foreground = new SolidColorBrush((Color)ColorConverter.ConvertFromString(filter == "全部" ? "White" : "#2c3e50"));

            FilterCriticalButton.Background = new SolidColorBrush((Color)ColorConverter.ConvertFromString(filter == "严重" ? "#c0392b" : "#e0e0e0"));
            FilterCriticalButton.Foreground = new SolidColorBrush((Color)ColorConverter.ConvertFromString(filter == "严重" ? "White" : "#2c3e50"));

            FilterHighButton.Background = new SolidColorBrush((Color)ColorConverter.ConvertFromString(filter == "高危" ? "#e67e22" : "#e0e0e0"));
            FilterHighButton.Foreground = new SolidColorBrush((Color)ColorConverter.ConvertFromString(filter == "高危" ? "White" : "#2c3e50"));

            FilterMediumButton.Background = new SolidColorBrush((Color)ColorConverter.ConvertFromString(filter == "中危" ? "#f39c12" : "#e0e0e0"));
            FilterMediumButton.Foreground = new SolidColorBrush((Color)ColorConverter.ConvertFromString(filter == "中危" ? "White" : "#2c3e50"));
        }

        private void FilterAllButton_Click(object sender, RoutedEventArgs e) => ApplyFilter("全部");
        private void FilterCriticalButton_Click(object sender, RoutedEventArgs e) => ApplyFilter("严重");
        private void FilterHighButton_Click(object sender, RoutedEventArgs e) => ApplyFilter("高危");
        private void FilterMediumButton_Click(object sender, RoutedEventArgs e) => ApplyFilter("中危");

        private string EstimateAttackTime(AttackPath path)
        {
            double baseTime = path.Steps.Count * 2;
            double complexityFactor = path.Complexity / 5.0;
            double successFactor = (100 - path.SuccessProbability) / 100.0;

            double estimatedHours = baseTime * complexityFactor * (1 + successFactor);

            if (estimatedHours < 1)
                return "< 1小时";
            if (estimatedHours < 24)
                return $"{estimatedHours:F0}小时";
            if (estimatedHours < 168)
                return $"{estimatedHours / 24:F0}天";
            return "> 1周";
        }

        private string GetPriorityLevel(AttackPath path)
        {
            double priorityScore = path.RiskScore * 0.4 + path.SuccessProbability * 0.3 + (10 - path.Complexity) * 3;

            if (priorityScore >= 70) return "🔴 紧急";
            if (priorityScore >= 50) return "🟠 高优";
            if (priorityScore >= 30) return "🟡 中优";
            return "🟢 低优";
        }

        private string GetRiskLevel(double riskScore)
        {
            if (riskScore >= 80) return "严重";
            if (riskScore >= 60) return "高危";
            if (riskScore >= 40) return "中危";
            return "低危";
        }

        private void AttackPathListBox_SelectionChanged(object sender, SelectionChangedEventArgs e)
        {
            if (AttackPathListBox.SelectedItem is AttackPathDisplayModel selectedPath)
            {
                var attackPath = _attackPaths.FirstOrDefault(p => p.PathId == selectedPath.PathId);
                if (attackPath != null)
                {
                    ShowAttackPathDetail(attackPath);
                }
            }
        }

        private void ShowAttackPathDetail(AttackPath path)
        {
            EmptyStatePanel.Visibility = Visibility.Collapsed;
            DetailPanel.Visibility = Visibility.Visible;

            DetailNameText.Text = path.Name;
            DetailDescriptionText.Text = path.Description;
            DetailRiskScoreText.Text = path.RiskScore.ToString("F1");
            DetailRiskScoreBar.Value = path.RiskScore;
            DetailSuccessProbText.Text = $"{path.SuccessProbability:F0}%";
            DetailSuccessProbBar.Value = path.SuccessProbability;
            DetailEstimatedTimeText.Text = EstimateAttackTime(path);
            DetailComplexityText.Text = $"复杂度: {path.Complexity}/10";
            DetailPriorityText.Text = GetPriorityLevel(path);
            DetailPriorityText.Foreground = new SolidColorBrush((Color)ColorConverter.ConvertFromString(
                GetPriorityLevel(path).Contains("P0") ? "#c0392b" :
                GetPriorityLevel(path).Contains("P1") ? "#e67e22" :
                GetPriorityLevel(path).Contains("P2") ? "#f39c12" : "#27ae60"));
            DetailStepCountText.Text = $"步骤: {path.Steps.Count}";
            DetailImpactText.Text = path.Impact;

            AttackStepsPanel.Children.Clear();
            for (int i = 0; i < path.Steps.Count; i++)
            {
                var step = path.Steps[i];
                var stepBorder = CreateStepVisual(step, i == path.Steps.Count - 1);
                AttackStepsPanel.Children.Add(stepBorder);
            }

            DefenseAdvicePanel.Children.Clear();
            var defenseAdvices = GenerateDefenseAdvices(path);
            foreach (var advice in defenseAdvices)
            {
                var adviceBorder = CreateDefenseAdviceItem(advice);
                DefenseAdvicePanel.Children.Add(adviceBorder);
            }

            StatusText.Text = $"正在查看: {path.Name}";
        }

        private Border CreateStepVisual(AttackStep step, bool isLast)
        {
            var riskColor = step.StepRisk >= 8.0 ? "#e74c3c" :
                           step.StepRisk >= 6.0 ? "#e67e22" :
                           step.StepRisk >= 4.0 ? "#f39c12" : "#27ae60";
            var riskLabel = step.StepRisk >= 8.0 ? "极危" :
                           step.StepRisk >= 6.0 ? "高危" :
                           step.StepRisk >= 4.0 ? "中危" : "低危";

            var border = new Border
            {
                Background = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#ffffff")),
                CornerRadius = new CornerRadius(6),
                Padding = new Thickness(15),
                Margin = new Thickness(0, 0, 0, 10),
                BorderBrush = new SolidColorBrush((Color)ColorConverter.ConvertFromString(riskColor)),
                BorderThickness = new Thickness(2)
            };

            var stackPanel = new StackPanel();

            var headerGrid = new Grid();
            headerGrid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(40) });
            headerGrid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
            headerGrid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(120) });

            var stepNumber = new Border
            {
                Width = 30,
                Height = 30,
                CornerRadius = new CornerRadius(15),
                Background = new SolidColorBrush((Color)ColorConverter.ConvertFromString(riskColor)),
                Child = new TextBlock
                {
                    Text = step.StepNumber.ToString(),
                    Foreground = Brushes.White,
                    FontWeight = FontWeights.Bold,
                    FontSize = 14,
                    HorizontalAlignment = HorizontalAlignment.Center,
                    VerticalAlignment = VerticalAlignment.Center
                }
            };
            Grid.SetColumn(stepNumber, 0);

            var titleText = new TextBlock
            {
                Text = step.Title,
                FontSize = 15,
                FontWeight = FontWeights.SemiBold,
                Foreground = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#2c3e50")),
                VerticalAlignment = VerticalAlignment.Center,
                Margin = new Thickness(10, 0, 0, 0)
            };
            Grid.SetColumn(titleText, 1);

            var riskBadge = new Border
            {
                CornerRadius = new CornerRadius(4),
                Padding = new Thickness(8, 3, 8, 3),
                Background = new SolidColorBrush((Color)ColorConverter.ConvertFromString(riskColor)),
                HorizontalAlignment = HorizontalAlignment.Right,
                Child = new TextBlock
                {
                    Text = $"{riskLabel} {step.StepRisk:F1}",
                    FontSize = 11,
                    FontWeight = FontWeights.SemiBold,
                    Foreground = Brushes.White,
                    HorizontalAlignment = HorizontalAlignment.Center
                }
            };
            Grid.SetColumn(riskBadge, 2);

            headerGrid.Children.Add(stepNumber);
            headerGrid.Children.Add(titleText);
            headerGrid.Children.Add(riskBadge);

            stackPanel.Children.Add(headerGrid);

            var descText = new TextBlock
            {
                Text = step.Description,
                FontSize = 13,
                Foreground = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#7f8c8d")),
                TextWrapping = TextWrapping.Wrap,
                Margin = new Thickness(0, 10, 0, 8)
            };
            stackPanel.Children.Add(descText);

            if (!string.IsNullOrEmpty(step.TargetPort))
            {
                var portInfo = new TextBlock
                {
                    FontSize = 12,
                    TextWrapping = TextWrapping.Wrap,
                    Margin = new Thickness(0, 0, 0, 4)
                };
                portInfo.Inlines.Add(new System.Windows.Documents.Run { Text = "🔌 目标端口: ", FontWeight = FontWeights.SemiBold, Foreground = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#2c3e50")) });
                portInfo.Inlines.Add(new System.Windows.Documents.Run { Text = step.TargetPort, Foreground = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#3498db")) });
                stackPanel.Children.Add(portInfo);
            }

            if (!string.IsNullOrEmpty(step.RequiredVulnerability))
            {
                var vulnInfo = new TextBlock
                {
                    FontSize = 12,
                    TextWrapping = TextWrapping.Wrap,
                    Margin = new Thickness(0, 0, 0, 0)
                };
                vulnInfo.Inlines.Add(new System.Windows.Documents.Run { Text = "🎯 依赖漏洞: ", FontWeight = FontWeights.SemiBold, Foreground = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#2c3e50")) });
                vulnInfo.Inlines.Add(new System.Windows.Documents.Run { Text = step.RequiredVulnerability, Foreground = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#e74c3c")) });
                stackPanel.Children.Add(vulnInfo);
            }

            if (!isLast)
            {
                var connectorPanel = new StackPanel
                {
                    HorizontalAlignment = HorizontalAlignment.Left,
                    Margin = new Thickness(15, 5, 0, 5)
                };
                var connectorLine = new System.Windows.Shapes.Line
                {
                    X1 = 0,
                    Y1 = 0,
                    X2 = 0,
                    Y2 = 15,
                    Stroke = new SolidColorBrush((Color)ColorConverter.ConvertFromString(riskColor)),
                    StrokeThickness = 2,
                    StrokeDashArray = new System.Windows.Media.DoubleCollection(new double[] { 4, 4 })
                };
                var arrowHead = new System.Windows.Shapes.Polygon
                {
                    Points = new System.Windows.Media.PointCollection(new[] {
                        new System.Windows.Point(-5, 12),
                        new System.Windows.Point(0, 18),
                        new System.Windows.Point(5, 12)
                    }),
                    Fill = new SolidColorBrush((Color)ColorConverter.ConvertFromString(riskColor))
                };
                connectorPanel.Children.Add(connectorLine);
                connectorPanel.Children.Add(arrowHead);
                stackPanel.Children.Add(connectorPanel);
            }

            border.Child = stackPanel;
            return border;
        }

        private Border CreateDefenseAdviceItem(string advice)
        {
            var border = new Border
            {
                Background = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#ffffff")),
                CornerRadius = new CornerRadius(6),
                Padding = new Thickness(15),
                Margin = new Thickness(0, 0, 0, 8),
                BorderBrush = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#bbf7d0")),
                BorderThickness = new Thickness(1)
            };

            var textBlock = new TextBlock
            {
                Text = $"• {advice}",
                FontSize = 13,
                Foreground = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#2c3e50")),
                TextWrapping = TextWrapping.Wrap
            };

            border.Child = textBlock;
            return border;
        }

        private List<string> GenerateDefenseAdvices(AttackPath path)
        {
            var advices = new List<string>();

            var targetPorts = path.Steps.Where(s => !string.IsNullOrEmpty(s.TargetPort)).Select(s => s.TargetPort).Distinct().ToList();
            var requiredVulns = path.Steps.Where(s => !string.IsNullOrEmpty(s.RequiredVulnerability)).Select(s => s.RequiredVulnerability).Distinct().ToList();

            if (path.Name.Contains("Web", StringComparison.OrdinalIgnoreCase))
            {
                advices.Add("部署Web应用防火墙(WAF)，配置OWASP核心规则集");
                advices.Add("启用HTTPS加密传输，配置TLS 1.3及以上版本，禁用弱加密算法");
                advices.Add("实施内容安全策略(CSP)，防止XSS攻击");
                if (requiredVulns.Any(v => v.Contains("SQL", StringComparison.OrdinalIgnoreCase)))
                    advices.Add("使用参数化查询和ORM框架，彻底消除SQL注入风险");
                if (requiredVulns.Any(v => v.Contains("上传", StringComparison.OrdinalIgnoreCase)))
                    advices.Add("配置严格的文件上传验证，限制类型、大小并使用独立域名存储");
                advices.Add("定期进行渗透测试和代码审计");
            }

            if (path.Name.Contains("远程", StringComparison.OrdinalIgnoreCase))
            {
                advices.Add("强制启用双因素认证(2FA)，禁用纯密码认证");
                advices.Add("配置IP白名单和地理围栏，限制SSH/RDP访问来源");
                advices.Add("使用fail2ban等工具配置失败登录自动封禁");
                if (targetPorts.Any(p => p.Contains("23")))
                    advices.Add("立即禁用Telnet服务，改用SSH加密通信");
                if (targetPorts.Any(p => p.Contains("22")))
                    advices.Add("禁用SSH密码登录，仅允许密钥认证，修改默认端口");
                advices.Add("配置sudo最小权限，禁止root直接远程登录");
            }

            if (path.Name.Contains("数据库", StringComparison.OrdinalIgnoreCase))
            {
                advices.Add("数据库端口禁止对外暴露，仅允许应用服务器通过内网访问");
                advices.Add("实施最小权限原则，为每个应用创建独立数据库账户");
                advices.Add("启用数据库审计日志，实时监控异常SQL查询和访问模式");
                advices.Add("配置定期自动备份，验证备份恢复流程");
                if (targetPorts.Any(p => p.Contains("6379") || p.Contains("27017")))
                    advices.Add("Redis/MongoDB等NoSQL数据库必须配置认证密码并绑定内网IP");
            }

            if (path.Name.Contains("文件", StringComparison.OrdinalIgnoreCase))
            {
                advices.Add("关闭FTP匿名访问，使用SFTP或FTPS替代明文FTP");
                if (targetPorts.Any(p => p.Contains("445") || p.Contains("139")))
                    advices.Add("更新SMB服务补丁，禁用SMBv1协议，配置访问控制列表");
                advices.Add("配置文件完整性监控，定期扫描恶意文件和后门");
                advices.Add("限制文件上传目录执行权限，防止WebShell执行");
            }

            if (path.Name.Contains("组合", StringComparison.OrdinalIgnoreCase))
            {
                advices.Add("实施纵深防御策略，单一防护层被突破仍有其他防护");
                advices.Add("部署网络入侵检测系统(IDS)，监控异常流量和攻击特征");
                advices.Add("实施网络分段和微隔离，限制攻击者横向移动");
                advices.Add("建立安全事件响应中心(SOC)，实现7x24小时安全监控");
                advices.Add("制定漏洞修复SLA，高风险漏洞24小时内必须修复");
            }

            if (advices.Count == 0)
            {
                advices.Add("定期进行安全评估和漏洞扫描");
                advices.Add("及时更新系统和应用程序安全补丁");
                advices.Add("配置防火墙规则，遵循最小开放原则");
                advices.Add("部署入侵检测和防御系统(IDS/IPS)");
                advices.Add("建立安全事件响应流程和应急预案");
            }

            return advices;
        }

        private void RefreshButton_Click(object sender, RoutedEventArgs e)
        {
            LoadAttackPaths();
            StatusText.Text = "已刷新攻击路径列表";
        }

        private void ExportButton_Click(object sender, RoutedEventArgs e)
        {
            var saveFileDialog = new SaveFileDialog
            {
                Filter = "JSON文件|*.json|文本文件|*.txt",
                DefaultExt = ".json",
                Title = "导出攻击路径分析报告"
            };

            if (saveFileDialog.ShowDialog() == true)
            {
                try
                {
                    if (saveFileDialog.FilterIndex == 1)
                    {
                        var options = new JsonSerializerOptions { WriteIndented = true };
                        var json = JsonSerializer.Serialize(_attackPaths, options);
                        File.WriteAllText(saveFileDialog.FileName, json);
                    }
                    else
                    {
                        var content = GenerateTextReport();
                        File.WriteAllText(saveFileDialog.FileName, content);
                    }

                    MessageBox.Show("导出成功！", "提示", MessageBoxButton.OK, MessageBoxImage.Information);
                    StatusText.Text = $"已导出到: {saveFileDialog.FileName}";
                }
                catch (Exception ex)
                {
                    MessageBox.Show($"导出失败: {ex.Message}", "错误", MessageBoxButton.OK, MessageBoxImage.Error);
                }
            }
        }

        private string GenerateTextReport()
        {
            var report = new System.Text.StringBuilder();
            report.AppendLine("================================================================================");
            report.AppendLine("                        攻击路径分析报告");
            report.AppendLine($"                    生成时间: {DateTime.Now:yyyy-MM-dd HH:mm:ss}");
            report.AppendLine("================================================================================");
            report.AppendLine();

            report.AppendLine($"【总体概况】");
            report.AppendLine($"攻击路径总数: {_attackPaths.Count}");
            
            var criticalCount = _attackPaths.Count(p => p.RiskScore >= 80);
            var highCount = _attackPaths.Count(p => p.RiskScore >= 60 && p.RiskScore < 80);
            var mediumCount = _attackPaths.Count(p => p.RiskScore >= 40 && p.RiskScore < 60);
            var lowCount = _attackPaths.Count(p => p.RiskScore < 40);
            var avgRiskScore = _attackPaths.Any() ? _attackPaths.Average(p => p.RiskScore) : 0;

            report.AppendLine($"严重风险路径: {criticalCount} 条");
            report.AppendLine($"高危风险路径: {highCount} 条");
            report.AppendLine($"中危风险路径: {mediumCount} 条");
            report.AppendLine($"低危风险路径: {lowCount} 条");
            report.AppendLine($"平均风险评分: {avgRiskScore:F1}/100");
            report.AppendLine();

            report.AppendLine("【攻击路径优先级排序】");
            report.AppendLine();

            var sortedPaths = _attackPaths.OrderByDescending(p => p.RiskScore).ToList();
            for (int i = 0; i < sortedPaths.Count; i++)
            {
                var path = sortedPaths[i];
                report.AppendLine($"----------------------------------------");
                report.AppendLine($"优先级排名: #{i + 1}");
                report.AppendLine($"路径名称: {path.Name}");
                report.AppendLine($"修复优先级: {GetPriorityLevel(path)}");
                report.AppendLine($"路径描述: {path.Description}");
                report.AppendLine();
                report.AppendLine($"风险评估:");
                report.AppendLine($"  - 风险评分: {path.RiskScore:F1}/100 ({GetRiskLevel(path.RiskScore)})");
                report.AppendLine($"  - 成功概率: {path.SuccessProbability:F0}%");
                report.AppendLine($"  - 攻击复杂度: {path.Complexity}/10");
                report.AppendLine($"  - 预估攻击时间: {EstimateAttackTime(path)}");
                report.AppendLine($"  - 攻击步骤数: {path.Steps.Count}");
                report.AppendLine();

                report.AppendLine($"潜在影响:");
                report.AppendLine($"  {path.Impact}");
                report.AppendLine();

                report.AppendLine("攻击步骤流程:");
                foreach (var step in path.Steps)
                {
                    var riskLabel = step.StepRisk >= 8.0 ? "极危" :
                                   step.StepRisk >= 6.0 ? "高危" :
                                   step.StepRisk >= 4.0 ? "中危" : "低危";
                    report.AppendLine($"  {step.StepNumber}. {step.Title} [{riskLabel} {step.StepRisk:F1}]");
                    report.AppendLine($"     描述: {step.Description}");
                    if (!string.IsNullOrEmpty(step.TargetPort))
                        report.AppendLine($"     目标端口: {step.TargetPort}");
                    if (!string.IsNullOrEmpty(step.RequiredVulnerability))
                        report.AppendLine($"     依赖漏洞: {step.RequiredVulnerability}");
                    report.AppendLine();
                }

                report.AppendLine("防御建议:");
                var advices = GenerateDefenseAdvices(path);
                foreach (var advice in advices)
                {
                    report.AppendLine($"  • {advice}");
                }
                report.AppendLine();
            }

            report.AppendLine("================================================================================");
            report.AppendLine("                              报告结束");
            report.AppendLine("================================================================================");
            report.AppendLine();
            report.AppendLine("免责声明: 本报告仅用于安全评估和防御目的，请勿用于非法用途。");

            return report.ToString();
        }

        private void CloseButton_Click(object sender, RoutedEventArgs e)
        {
            Close();
        }
    }

    public class AttackPathDisplayModel
    {
        public string PathId { get; set; } = string.Empty;
        public string Name { get; set; } = string.Empty;
        public string Description { get; set; } = string.Empty;
        public double RiskScore { get; set; }
        public string RiskLevel { get; set; } = "低危";
        public double SuccessProbability { get; set; }
        public int Complexity { get; set; }
        public int StepCount { get; set; }
        public string EstimatedTime { get; set; } = string.Empty;
        public string Priority { get; set; } = string.Empty;
    }

    public class PriorityToColorConverter : IValueConverter
    {
        public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
        {
            if (value is string priority)
            {
                return priority switch
                {
                    "P0-立即修复" => new SolidColorBrush((Color)ColorConverter.ConvertFromString("#c0392b")),
                    "P1-紧急" => new SolidColorBrush((Color)ColorConverter.ConvertFromString("#e67e22")),
                    "P2-高优先级" => new SolidColorBrush((Color)ColorConverter.ConvertFromString("#f39c12")),
                    _ => new SolidColorBrush((Color)ColorConverter.ConvertFromString("#27ae60"))
                };
            }
            return new SolidColorBrush((Color)ColorConverter.ConvertFromString("#27ae60"));
        }

        public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture)
        {
            return Binding.DoNothing;
        }
    }
}
