using LiveChartsCore;
using LiveChartsCore.SkiaSharpView;
using LiveChartsCore.SkiaSharpView.Painting;
using NetSecurityScanner.Models;
using NetSecurityScanner.Services;
using SkiaSharp;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using PortResult = NetSecurityScanner.Models.PortScanResult;

namespace NetSecurityScanner.Views
{
    public partial class ScanVisualizationWindow : Window
    {
        private readonly ScanHistoryService _historyService;
        private List<ScanHistory> _scanHistory;
        private List<PortResult> _currentPortResults;
        private List<VulnerabilityResult> _currentVulnerabilities;

        public ScanVisualizationWindow()
        {
            InitializeComponent();
            _historyService = new ScanHistoryService();
            _scanHistory = new List<ScanHistory>();
            _currentPortResults = new List<PortResult>();
            _currentVulnerabilities = new List<VulnerabilityResult>();

            Loaded += ScanVisualizationWindow_Loaded;
        }

        public ScanVisualizationWindow(List<PortResult> ports, List<VulnerabilityResult> vulnerabilities) : this()
        {
            _currentPortResults = ports ?? new List<PortResult>();
            _currentVulnerabilities = vulnerabilities ?? new List<VulnerabilityResult>();
        }

        private async void ScanVisualizationWindow_Loaded(object sender, RoutedEventArgs e)
        {
            await LoadDataAsync();
            UpdateStatisticsCards();
            InitializeCharts();
        }

        private async Task LoadDataAsync()
        {
            try
            {
                _scanHistory = await _historyService.GetScanHistoryAsync();
            }
            catch (Exception ex)
            {
                MessageBox.Show($"加载数据失败: {ex.Message}", "错误", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        private void UpdateStatisticsCards()
        {
            int criticalCount = _currentVulnerabilities.Count(v => v.RiskLevel == "严重");
            int highCount = _currentVulnerabilities.Count(v => v.RiskLevel == "高危");
            int openPorts = _currentPortResults.Count(p => p.Status == "开放");
            
            // 计算安全评分 (100 - 扣分)
            int score = 100;
            score -= criticalCount * 10;
            score -= highCount * 5;
            score -= _currentVulnerabilities.Count(v => v.RiskLevel == "中危") * 2;
            score = Math.Max(0, score);

            if (CriticalCountText != null) CriticalCountText.Text = criticalCount.ToString();
            if (HighCountText != null) HighCountText.Text = highCount.ToString();
            if (OpenPortsText != null) OpenPortsText.Text = openPorts.ToString();
            if (SecurityScoreText != null) SecurityScoreText.Text = score.ToString();
        }

        private void InitializeCharts()
        {
            InitializeRiskPieChart();
            InitializeVulnTypePieChart();
            InitializePortBarChart();
            InitializeServiceBarChart();
            InitializeTrendLineChart();
            InitializeTopLists();
            InitializeSecuritySuggestions();
        }

        private void InitializeRiskPieChart()
        {
            var riskCounts = new Dictionary<string, int>
            {
                ["严重"] = _currentVulnerabilities.Count(v => v.RiskLevel == "严重"),
                ["高危"] = _currentVulnerabilities.Count(v => v.RiskLevel == "高危"),
                ["中危"] = _currentVulnerabilities.Count(v => v.RiskLevel == "中危"),
                ["低危"] = _currentVulnerabilities.Count(v => v.RiskLevel == "低危")
            };

            var colors = new[]
            {
                new SKColor(231, 76, 60),   // 红色 - 严重
                new SKColor(230, 126, 34),  // 橙色 - 高危
                new SKColor(241, 196, 15),  // 黄色 - 中危
                new SKColor(46, 204, 113)   // 绿色 - 低危
            };

            var series = new List<ISeries>();
            int colorIndex = 0;
            foreach (var kvp in riskCounts.Where(x => x.Value > 0))
            {
                series.Add(new PieSeries<int>
                {
                    Values = new[] { kvp.Value },
                    Name = kvp.Key,
                    Fill = new SolidColorPaint(colors[colorIndex % colors.Length]),
                    DataLabelsSize = 14,
                    DataLabelsPaint = new SolidColorPaint(SKColors.White),
                    DataLabelsPosition = LiveChartsCore.Measure.PolarLabelsPosition.Middle,
                    DataLabelsFormatter = point => $"{kvp.Key}\n{point.Coordinate.PrimaryValue}"
                });
                colorIndex++;
            }

            if (RiskPieChart != null) RiskPieChart.Series = series;
        }

        private void InitializeVulnTypePieChart()
        {
            // 按漏洞名称分组统计
            var vulnTypes = _currentVulnerabilities
                .GroupBy(v => v.Name)
                .Select(g => new { Name = g.Key, Count = g.Count() })
                .OrderByDescending(x => x.Count)
                .Take(8)
                .ToList();

            var colors = new[]
            {
                new SKColor(155, 89, 182),
                new SKColor(52, 152, 219),
                new SKColor(26, 188, 156),
                new SKColor(241, 196, 15),
                new SKColor(230, 126, 34),
                new SKColor(231, 76, 60),
                new SKColor(149, 165, 166),
                new SKColor(52, 73, 94)
            };

            var series = new List<ISeries>();
            int colorIndex = 0;
            foreach (var vuln in vulnTypes)
            {
                series.Add(new PieSeries<int>
                {
                    Values = new[] { vuln.Count },
                    Name = vuln.Name.Length > 15 ? vuln.Name.Substring(0, 15) + "..." : vuln.Name,
                    Fill = new SolidColorPaint(colors[colorIndex % colors.Length]),
                    DataLabelsSize = 12,
                    DataLabelsPaint = new SolidColorPaint(SKColors.White),
                    DataLabelsPosition = LiveChartsCore.Measure.PolarLabelsPosition.Middle
                });
                colorIndex++;
            }

            if (VulnTypePieChart != null) VulnTypePieChart.Series = series;
        }

        private void InitializePortBarChart()
        {
            // 按端口分组统计
            var portGroups = _currentPortResults
                .Where(p => p.Status == "开放")
                .GroupBy(p => p.PortNumber)
                .Select(g => new { Port = g.Key, Count = g.Count() })
                .OrderByDescending(x => x.Count)
                .Take(15)
                .ToList();

            var series = new List<ISeries>
            {
                new ColumnSeries<int>
                {
                    Values = portGroups.Select(x => x.Count).ToArray(),
                    Fill = new SolidColorPaint(new SKColor(108, 92, 231)),
                    DataLabelsSize = 12,
                    DataLabelsPaint = new SolidColorPaint(SKColors.Black),
                    DataLabelsPosition = LiveChartsCore.Measure.DataLabelsPosition.Top
                }
            };

            if (PortBarChart != null)
            {
                PortBarChart.Series = series;
                PortBarChart.XAxes = new[]
                {
                    new Axis
                    {
                        Labels = portGroups.Select(x => x.Port.ToString()).ToArray(),
                        LabelsRotation = 45,
                        TextSize = 12
                    }
                };
                PortBarChart.YAxes = new[]
                {
                    new Axis
                    {
                        Name = "数量",
                        TextSize = 12
                    }
                };
            }
        }

        private void InitializeServiceBarChart()
        {
            // 按服务类型分组统计
            var serviceGroups = _currentPortResults
                .Where(p => (p.Status == "开放") && !string.IsNullOrEmpty(p.Service))
                .GroupBy(p => p.Service)
                .Select(g => new { Service = g.Key, Count = g.Count() })
                .OrderByDescending(x => x.Count)
                .Take(12)
                .ToList();

            var series = new List<ISeries>
            {
                new RowSeries<int>
                {
                    Values = serviceGroups.Select(x => x.Count).ToArray(),
                    Fill = new SolidColorPaint(new SKColor(0, 184, 148)),
                    DataLabelsSize = 12,
                    DataLabelsPaint = new SolidColorPaint(SKColors.White),
                    DataLabelsPosition = LiveChartsCore.Measure.DataLabelsPosition.Middle
                }
            };

            if (ServiceBarChart != null)
            {
                ServiceBarChart.Series = series;
                ServiceBarChart.YAxes = new[]
                {
                    new Axis
                    {
                        Labels = serviceGroups.Select(x => x.Service).ToArray(),
                        TextSize = 12
                    }
                };
                ServiceBarChart.XAxes = new[]
                {
                    new Axis
                    {
                        Name = "数量",
                        TextSize = 12
                    }
                };
            }
        }

        private void InitializeTrendLineChart()
        {
            // 最近30天的扫描趋势
            var last30Days = Enumerable.Range(0, 30)
                .Select(i => DateTime.Now.Date.AddDays(-i))
                .OrderBy(d => d)
                .ToList();

            var scanCounts = last30Days.Select(date => 
                _scanHistory.Count(h => h.ScanTime.Date == date)).ToArray();
            
            var vulnCounts = last30Days.Select(date =>
                _scanHistory.Where(h => h.ScanTime.Date == date).Sum(h => h.TotalVulnerabilities)).ToArray();

            var series = new List<ISeries>
            {
                new LineSeries<int>
                {
                    Values = scanCounts,
                    Name = "扫描次数",
                    Stroke = new SolidColorPaint(new SKColor(108, 92, 231), 3),
                    Fill = new SolidColorPaint(new SKColor(108, 92, 231, 50)),
                    GeometrySize = 6,
                    DataLabelsSize = 10
                },
                new LineSeries<int>
                {
                    Values = vulnCounts,
                    Name = "漏洞数量",
                    Stroke = new SolidColorPaint(new SKColor(231, 76, 60), 3),
                    Fill = new SolidColorPaint(new SKColor(231, 76, 60, 50)),
                    GeometrySize = 6,
                    DataLabelsSize = 10
                }
            };

            if (TrendLineChart != null)
            {
                TrendLineChart.Series = series;
                TrendLineChart.XAxes = new[]
                {
                    new Axis
                    {
                        Labels = last30Days.Select(d => d.ToString("MM-dd")).ToArray(),
                        LabelsRotation = 45,
                        TextSize = 11
                    }
                };
                TrendLineChart.YAxes = new[]
                {
                    new Axis
                    {
                        Name = "数量",
                        TextSize = 12
                    }
                };
                TrendLineChart.LegendPosition = LiveChartsCore.Measure.LegendPosition.Top;
            }
        }

        private void InitializeTopLists()
        {
            // TOP 10 高危端口
            var topPorts = _currentPortResults
                .Where(p => p.Status == "开放")
                .GroupBy(p => new { p.PortNumber, p.Service })
                .Select(g => new TopPortItem
                {
                    Port = g.Key.PortNumber,
                    Service = g.Key.Service ?? "Unknown",
                    Count = g.Count()
                })
                .OrderByDescending(x => x.Count)
                .Take(10)
                .ToList();
            if (TopPortsDataGrid != null) TopPortsDataGrid.ItemsSource = topPorts;

            // TOP 10 常见漏洞
            var topVulns = _currentVulnerabilities
                .GroupBy(v => v.Name)
                .Select((g, index) => new TopVulnItem
                {
                    Rank = index + 1,
                    Name = g.Key,
                    Count = g.Count()
                })
                .OrderBy(x => x.Rank)
                .Take(10)
                .ToList();
            if (TopVulnsDataGrid != null) TopVulnsDataGrid.ItemsSource = topVulns;
        }

        private void InitializeSecuritySuggestions()
        {
            if (SecuritySuggestionsPanel != null) SecuritySuggestionsPanel.Children.Clear();

            var suggestions = new List<string>();

            // 根据漏洞情况生成建议
            int criticalCount = _currentVulnerabilities.Count(v => v.RiskLevel == "严重");
            int highCount = _currentVulnerabilities.Count(v => v.RiskLevel == "高危");

            if (criticalCount > 0)
            {
                suggestions.Add($"🔴 发现 {criticalCount} 个严重漏洞，建议立即修复");
            }
            if (highCount > 0)
            {
                suggestions.Add($"🟠 发现 {highCount} 个高危漏洞，建议尽快修复");
            }

            // 检查常见服务
            var hasWeakSsh = _currentVulnerabilities.Any(v => v.Name.Contains("SSH") && v.RiskLevel != "低危");
            var hasWeakMysql = _currentVulnerabilities.Any(v => v.Name.Contains("MySQL") && v.RiskLevel != "低危");
            var hasWeakRedis = _currentVulnerabilities.Any(v => v.Name.Contains("Redis") && v.RiskLevel != "低危");

            if (hasWeakSsh)
            {
                suggestions.Add("🔧 SSH服务存在安全问题，建议：\n  • 禁用root登录\n  • 使用密钥认证\n  • 修改默认端口");
            }
            if (hasWeakMysql)
            {
                suggestions.Add("🔧 MySQL数据库存在安全问题，建议：\n  • 删除匿名用户\n  • 设置强密码\n  • 限制网络访问");
            }
            if (hasWeakRedis)
            {
                suggestions.Add("🔧 Redis存在未授权访问风险，建议：\n  • 设置访问密码\n  • 绑定本地地址\n  • 禁用危险命令");
            }

            // 通用建议
            suggestions.Add("🛡️ 安全加固建议：\n  • 定期更新系统和软件\n  • 启用防火墙规则\n  • 实施最小权限原则\n  • 定期备份重要数据");

            foreach (var suggestion in suggestions)
            {
                var border = new Border
                {
                    Background = new SolidColorBrush(Colors.LightYellow),
                    BorderBrush = new SolidColorBrush(Colors.Goldenrod),
                    BorderThickness = new Thickness(1),
                    CornerRadius = new CornerRadius(4),
                    Padding = new Thickness(12),
                    Margin = new Thickness(0, 0, 0, 10)
                };

                var textBlock = new TextBlock
                {
                    Text = suggestion,
                    TextWrapping = TextWrapping.Wrap,
                    FontSize = 13
                };

                border.Child = textBlock;
                if (SecuritySuggestionsPanel != null) SecuritySuggestionsPanel.Children.Add(border);
            }
        }
    }

    public class TopPortItem
    {
        public int Port { get; set; }
        public string Service { get; set; } = "";
        public int Count { get; set; }
    }

    public class TopVulnItem
    {
        public int Rank { get; set; }
        public string Name { get; set; } = "";
        public int Count { get; set; }
    }
}
