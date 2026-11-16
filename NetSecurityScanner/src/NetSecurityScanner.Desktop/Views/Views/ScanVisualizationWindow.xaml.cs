using LiveChartsCore;
using LiveChartsCore.Defaults;
using LiveChartsCore.SkiaSharpView;
using LiveChartsCore.SkiaSharpView.Painting;
using LiveChartsCore.SkiaSharpView.VisualElements;
using NetSecurityScanner.Models;
using NetSecurityScanner.Services;
using SkiaSharp;
using System;
using System.Collections.Generic;
using System.IO;
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
        private readonly ScanAnalyticsService _analyticsService;
        private List<ScanHistoryItem> _history;
        private List<PortResult> _currentPortResults;
        private List<VulnerabilityResult> _currentVulnerabilities;
        private static SKTypeface? _chineseTypeface;
        private static bool _fontResolverInitialized = false;

        private static readonly SKColor ColorCritical = new(231, 76, 60);
        private static readonly SKColor ColorHigh = new(230, 126, 34);
        private static readonly SKColor ColorMedium = new(241, 196, 15);
        private static readonly SKColor ColorLow = new(46, 204, 113);
        private static readonly SKColor ColorScan = new(108, 92, 231);
        private static readonly SKColor ColorVuln = new(231, 76, 60);
        private static readonly SKColor ColorPort = new(52, 152, 219);

        public ScanVisualizationWindow()
        {
            EnsureChineseFontResolver();
            InitializeComponent();
            _analyticsService = new ScanAnalyticsService();
            _history = new List<ScanHistoryItem>();
            _currentPortResults = new List<PortResult>();
            _currentVulnerabilities = new List<VulnerabilityResult>();
            Loaded += ScanVisualizationWindow_Loaded;
        }

        public ScanVisualizationWindow(List<PortResult> ports, List<VulnerabilityResult> vulnerabilities) : this()
        {
            _currentPortResults = ports ?? new List<PortResult>();
            _currentVulnerabilities = vulnerabilities ?? new List<VulnerabilityResult>();
        }

        private static void EnsureChineseFontResolver()
        {
            if (_fontResolverInitialized) return;
            _fontResolverInitialized = true;

            string[] fontCandidates =
            {
                @"C:\Windows\Fonts\msyh.ttc",
                @"C:\Windows\Fonts\msyh.ttf",
                @"C:\Windows\Fonts\msyhbd.ttc",
                @"C:\Windows\Fonts\simhei.ttf",
                @"C:\Windows\Fonts\simsun.ttc",
                @"/System/Library/Fonts/PingFang.ttc",
                @"/usr/share/fonts/truetype/wqy/wqy-microhei.ttc",
                @"/usr/share/fonts/opentype/noto/NotoSansCJK-Regular.ttc"
            };
            foreach (var p in fontCandidates)
            {
                try
                {
                    if (File.Exists(p))
                    {
                        _chineseTypeface = SKTypeface.FromFile(p);
                        if (_chineseTypeface != null) break;
                    }
                }
                catch { }
            }

            if (_chineseTypeface == null)
            {
                try
                {
                    using var mgr = SKFontManager.Default;
                    var families = new[] { "Microsoft YaHei", "微软雅黑", "SimHei", "黑体", "SimSun", "宋体", "WenQuanYi Micro Hei", "Noto Sans CJK SC" };
                    foreach (var f in families)
                    {
                        try
                        {
                            var tf = mgr?.MatchCharacter(f, 0x4e2d);
                            if (tf != null) { _chineseTypeface = tf; break; }
                        }
                        catch { }
                    }
                }
                catch { }
            }

            try
            {
                var method = typeof(LiveChartsSkiaSharp).GetMethod(
                    "OverrideSkiaSharpTypefaceResolver",
                    System.Reflection.BindingFlags.Public | System.Reflection.BindingFlags.Static);
                if (method != null)
                {
                    method.Invoke(null, new object[]
                    {
                        new Func<string, SKFontStyleWeight, SKFontStyleSlant, SKTypeface>((text, weight, slant) =>
                            _chineseTypeface ?? SKTypeface.FromFamilyName(SKTypeface.Default.FamilyName) ?? SKTypeface.Default)
                    });
                }
            }
            catch { }
        }

        private static SolidColorPaint MakeLabelPaint(SKColor color)
        {
            return new SolidColorPaint(color)
            {
                SKTypeface = _chineseTypeface ?? SKTypeface.Default,
                IsAntialias = true
            };
        }

        private static SolidColorPaint MakePaint(SKColor color, float textSize = 12)
        {
            return new SolidColorPaint(color)
            {
                SKTypeface = _chineseTypeface ?? SKTypeface.Default,
                IsAntialias = true
            };
        }

        private static Axis MakeAxis(string[]? labels = null, string? name = null, bool rotate = false, bool secondAxis = false)
        {
            var axis = new Axis();
            if (labels != null) axis.Labels = labels;
            if (name != null) axis.Name = name;
            axis.NamePaint = MakeLabelPaint(new SKColor(50, 50, 50));
            axis.LabelsPaint = MakeLabelPaint(new SKColor(80, 80, 80));
            axis.LabelsRotation = rotate ? 35 : 0;
            axis.SeparatorsPaint = new SolidColorPaint(secondAxis ? new SKColor(180, 180, 180) : new SKColor(230, 230, 230));
            if (secondAxis) axis.Position = LiveChartsCore.Measure.AxisPosition.End;
            return axis;
        }

        private async void ScanVisualizationWindow_Loaded(object sender, RoutedEventArgs e)
        {
            try
            {
                await LoadDataAsync(useMockIfEmpty: true);
                RefreshAll();
            }
            catch (Exception ex)
            {
                MessageBox.Show($"加载可视化数据失败: {ex.Message}\n\n{ex.StackTrace}", "错误",
                    MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        private async Task LoadDataAsync(bool useMockIfEmpty = false)
        {
            try
            {
                _history = await _analyticsService.GetAllScanHistoryAsync();
            }
            catch (Exception ex)
            {
                MessageBox.Show($"加载历史数据失败: {ex.Message}", "错误", MessageBoxButton.OK, MessageBoxImage.Warning);
            }

            if ((_history == null || _history.Count == 0) && useMockIfEmpty)
            {
                var mock = _analyticsService.GenerateMockDataIfEmpty();
                _history = (List<ScanHistoryItem>)mock["History"];
            }
        }

        private void RefreshButton_Click(object sender, RoutedEventArgs e)
        {
            _ = Task.Run(async () =>
            {
                await LoadDataAsync(useMockIfEmpty: false);
                Dispatcher.Invoke(RefreshAll);
            });
        }

        private async void MockButton_Click(object sender, RoutedEventArgs e)
        {
            var result = MessageBox.Show(
                "将生成 1 年的模拟扫描数据用于演示，是否继续？\n（不会覆盖真实历史数据）",
                "生成演示数据", MessageBoxButton.YesNo, MessageBoxImage.Question);
            if (result != MessageBoxResult.Yes) return;

            var mock = _analyticsService.GenerateMockDataIfEmpty();
            _history = (List<ScanHistoryItem>)mock["History"];
            await Task.Delay(500);
            RefreshAll();
            MessageBox.Show($"演示数据加载成功！共 {_history.Count} 条扫描记录，包含 365 天范围。",
                "成功", MessageBoxButton.OK, MessageBoxImage.Information);
        }

        private void PeriodComboBox_SelectionChanged(object sender, SelectionChangedEventArgs e)
        {
            if (!IsLoaded) return;
            RefreshAll();
        }

        private TimePeriodType GetSelectedPeriod(out int periods)
        {
            var tag = (PeriodComboBox.SelectedItem as ComboBoxItem)?.Tag?.ToString() ?? "Weekly";
            switch (tag)
            {
                case "Daily": periods = 7; return TimePeriodType.Daily;
                case "Weekly": periods = 12; return TimePeriodType.Weekly;
                case "Monthly": periods = 12; return TimePeriodType.Monthly;
                case "Quarterly": periods = 8; return TimePeriodType.Quarterly;
                case "Yearly": periods = 5; return TimePeriodType.Yearly;
                default: periods = 12; return TimePeriodType.Weekly;
            }
        }

        private void RefreshAll()
        {
            try
            {
                RefreshPeriodOverviewCards();
                RefreshCurrentPeriodKpi();
                RefreshTrendMultiChart();
                RefreshRiskMixPieChart();
                RefreshStackedRiskChart();
                RefreshTopTargetsBarChart();
                RefreshPortVsVulnChart();
                RefreshPeriodDetailGrid();
            }
            catch (Exception ex)
            {
                MessageBox.Show($"刷新图表出错: {ex.Message}", "提示", MessageBoxButton.OK, MessageBoxImage.Warning);
            }
        }

        private void RefreshPeriodOverviewCards()
        {
            var all = _analyticsService.GetAllPeriodSummaries(_history);

            void Apply(string prefix, PeriodStatisticsSummary s)
            {
                var scanTb = FindName($"{prefix}ScanText") as TextBlock;
                var vulnTb = FindName($"{prefix}VulnText") as TextBlock;
                var trendTb = FindName($"{prefix}TrendText") as TextBlock;
                if (scanTb != null) scanTb.Text = $"{s.TotalScans} 次";
                if (vulnTb != null) vulnTb.Text = $"漏洞 {s.TotalVulns}";
                if (trendTb != null)
                {
                    bool rising = s.TrendChangePercent > 0;
                    string arrow = rising ? "📈" : "📉";
                    trendTb.Text = $"{arrow} {Math.Abs(s.TrendChangePercent)}%";
                    trendTb.Foreground = rising ? new SolidColorBrush(Colors.DarkRed) : new SolidColorBrush(Colors.ForestGreen);
                }
            }

            if (all == null || all.Count == 0) return;
            Apply("Day", all.FirstOrDefault(s => s.PeriodType == TimePeriodType.Daily) ?? new PeriodStatisticsSummary());
            Apply("Week", all.FirstOrDefault(s => s.PeriodType == TimePeriodType.Weekly) ?? new PeriodStatisticsSummary());
            Apply("Month", all.FirstOrDefault(s => s.PeriodType == TimePeriodType.Monthly) ?? new PeriodStatisticsSummary());
            Apply("Quarter", all.FirstOrDefault(s => s.PeriodType == TimePeriodType.Quarterly) ?? new PeriodStatisticsSummary());
            Apply("Year", all.FirstOrDefault(s => s.PeriodType == TimePeriodType.Yearly) ?? new PeriodStatisticsSummary());
        }

        private void RefreshCurrentPeriodKpi()
        {
            var period = GetSelectedPeriod(out _);
            var s = _analyticsService.GetPeriodSummary(_history, period, 0);

            if (CriticalKpiText != null) CriticalKpiText.Text = s.CriticalVulns.ToString();
            if (HighKpiText != null) HighKpiText.Text = s.HighVulns.ToString();
            if (MediumKpiText != null) MediumKpiText.Text = s.MediumVulns.ToString();
            if (TargetsKpiText != null) TargetsKpiText.Text = s.UniqueTargetsScanned.ToString();
            if (PortsKpiText != null) PortsKpiText.Text = s.TotalOpenPorts.ToString();
            if (RiskIndexKpiText != null) RiskIndexKpiText.Text = s.AverageRiskIndex.ToString("F0");
            if (RiskLevelKpiText != null)
            {
                RiskLevelKpiText.Text = s.RiskLevel;
                RiskLevelKpiText.Foreground = new SolidColorBrush(s.RiskLevel switch
                {
                    "极高风险" => Colors.Yellow,
                    "高风险" => Colors.Salmon,
                    "中风险" => Colors.LightGoldenrodYellow,
                    "低风险" => Colors.LightCyan,
                    _ => Colors.LightGreen
                });
            }

            if (PeriodRangeText != null) PeriodRangeText.Text = $"统计周期：{s.PeriodDisplay}  · 共 {s.TotalScans} 次扫描 · 平均 {s.AverageVulnsPerScan} 漏洞/次";
        }

        private void RefreshTrendMultiChart()
        {
            var type = GetSelectedPeriod(out int periods);
            var data = _analyticsService.GenerateTimeSeriesData(_history, type, periods);
            var labels = data.Select(d => d.Label).ToArray();
            bool rotate = periods > 8;

            var series = new List<ISeries>
            {
                new LineSeries<int>
                {
                    Values = data.Select(d => d.ScanCount).ToArray(),
                    Name = "扫描次数",
                    Stroke = new SolidColorPaint(ColorScan, 3),
                    Fill = new SolidColorPaint(new SKColor(ColorScan.Red, ColorScan.Green, ColorScan.Blue, 60)),
                    GeometrySize = 7,
                    GeometryStroke = new SolidColorPaint(SKColors.White, 2),
                    DataLabelsPaint = MakePaint(SKColors.DarkSlateGray, 10),
                    DataLabelsPosition = LiveChartsCore.Measure.DataLabelsPosition.Top
                },
                new LineSeries<int>
                {
                    Values = data.Select(d => d.TotalVulnerabilities).ToArray(),
                    Name = "漏洞总数",
                    Stroke = new SolidColorPaint(ColorVuln, 3),
                    Fill = new SolidColorPaint(new SKColor(ColorVuln.Red, ColorVuln.Green, ColorVuln.Blue, 40)),
                    GeometrySize = 7,
                    GeometryStroke = new SolidColorPaint(SKColors.White, 2),
                    DataLabelsPaint = MakePaint(SKColors.DarkRed, 10),
                    DataLabelsPosition = LiveChartsCore.Measure.DataLabelsPosition.Top
                },
                new LineSeries<int>
                {
                    Values = data.Select(d => d.CriticalCount + d.HighCount).ToArray(),
                    Name = "严重+高危",
                    Stroke = new SolidColorPaint(new SKColor(142, 68, 173), 2),
                    GeometrySize = 5
                }
            };

            if (TrendMultiChart != null)
            {
                TrendMultiChart.Series = series;
                TrendMultiChart.XAxes = new[] { MakeAxis(labels, rotate: rotate) };
                TrendMultiChart.YAxes = new[] { MakeAxis(name: "数量") };
            }
        }

        private void RefreshRiskMixPieChart()
        {
            var type = GetSelectedPeriod(out int _);
            var data = _analyticsService.GenerateTimeSeriesData(_history, type, 12);
            int critical = data.Sum(d => d.CriticalCount);
            int high = data.Sum(d => d.HighCount);
            int medium = data.Sum(d => d.MediumCount);
            int low = data.Sum(d => d.LowCount);
            int info = Math.Max(0, data.Sum(d => d.TotalVulnerabilities) - critical - high - medium - low);

            var buckets = new (string Name, int Count, SKColor Color)[]
            {
                ("严重", critical, ColorCritical),
                ("高危", high, ColorHigh),
                ("中危", medium, ColorMedium),
                ("低危", low, ColorLow),
                ("信息/其他", info, new SKColor(52, 152, 219))
            };

            var series = new List<ISeries>();
            foreach (var b in buckets.Where(x => x.Count > 0))
            {
                series.Add(new PieSeries<int>
                {
                    Values = new[] { b.Count },
                    Name = $"{b.Name} ({b.Count})",
                    Fill = new SolidColorPaint(b.Color),
                    DataLabelsPaint = MakePaint(SKColors.White, 13),
                    DataLabelsPosition = LiveChartsCore.Measure.PolarLabelsPosition.Middle
                });
            }

            if (series.Count == 0)
            {
                series.Add(new PieSeries<int>
                {
                    Values = new[] { 1 },
                    Name = "暂无数据",
                    Fill = new SolidColorPaint(new SKColor(189, 195, 199)),
                    DataLabelsPaint = MakePaint(SKColors.White, 12)
                });
            }

            if (RiskMixPieChart != null) RiskMixPieChart.Series = series;
        }

        private void RefreshStackedRiskChart()
        {
            var type = GetSelectedPeriod(out int periods);
            var data = _analyticsService.GenerateTimeSeriesData(_history, type, periods);
            var labels = data.Select(d => d.Label).ToArray();
            bool rotate = periods > 8;

            var series = new List<ISeries>
            {
                new StackedColumnSeries<int> { Values = data.Select(d => d.CriticalCount).ToArray(), Name = "严重", Fill = new SolidColorPaint(ColorCritical), Stroke = new SolidColorPaint(SKColors.White, 1) },
                new StackedColumnSeries<int> { Values = data.Select(d => d.HighCount).ToArray(),     Name = "高危", Fill = new SolidColorPaint(ColorHigh),    Stroke = new SolidColorPaint(SKColors.White, 1) },
                new StackedColumnSeries<int> { Values = data.Select(d => d.MediumCount).ToArray(),   Name = "中危", Fill = new SolidColorPaint(ColorMedium),  Stroke = new SolidColorPaint(SKColors.White, 1) },
                new StackedColumnSeries<int> { Values = data.Select(d => d.LowCount).ToArray(),      Name = "低危", Fill = new SolidColorPaint(ColorLow),     Stroke = new SolidColorPaint(SKColors.White, 1) }
            };

            if (StackedRiskChart != null)
            {
                StackedRiskChart.Series = series;
                StackedRiskChart.XAxes = new[] { MakeAxis(labels, rotate: rotate) };
                StackedRiskChart.YAxes = new[] { MakeAxis(name: "漏洞数") };
            }
        }

        private void RefreshTopTargetsBarChart()
        {
            var topTargets = _history
                .GroupBy(h => h.TargetIp ?? string.Empty, StringComparer.OrdinalIgnoreCase)
                .Select(g => new
                {
                    Target = string.IsNullOrEmpty(g.Key) ? "(未指定)" : g.Key,
                    Scans = g.Count(),
                    Vulns = g.Sum(x => x.VulnerabilitiesCount)
                })
                .OrderByDescending(x => x.Scans)
                .ThenByDescending(x => x.Vulns)
                .Take(10)
                .ToList();

            var labels = topTargets.Select(t => t.Target.Length > 15 ? t.Target.Substring(0, 15) + "…" : t.Target).Reverse().ToArray();

            var series = new List<ISeries>
            {
                new StackedRowSeries<int>
                {
                    Name = "扫描次数",
                    Values = topTargets.Select(t => t.Scans).Reverse().ToArray(),
                    Fill = new SolidColorPaint(ColorScan),
                    DataLabelsPaint = MakePaint(SKColors.DarkSlateBlue, 11),
                    DataLabelsPosition = LiveChartsCore.Measure.DataLabelsPosition.End
                },
                new StackedRowSeries<int>
                {
                    Name = "漏洞总数",
                    Values = topTargets.Select(t => t.Vulns).Reverse().ToArray(),
                    Fill = new SolidColorPaint(ColorVuln)
                }
            };

            if (TopTargetsBarChart != null)
            {
                TopTargetsBarChart.Series = series;
                TopTargetsBarChart.YAxes = new[] { MakeAxis(labels) };
                TopTargetsBarChart.XAxes = new[] { MakeAxis(name: "数量") };
            }
        }

        private void RefreshPortVsVulnChart()
        {
            var type = GetSelectedPeriod(out int periods);
            var data = _analyticsService.GenerateTimeSeriesData(_history, type, periods);
            var labels = data.Select(d => d.Label).ToArray();
            bool rotate = periods > 8;

            var series = new List<ISeries>
            {
                new ColumnSeries<int>
                {
                    Values = data.Select(d => d.OpenPorts).ToArray(),
                    Name = "开放端口数",
                    Fill = new SolidColorPaint(ColorPort),
                    DataLabelsPaint = MakePaint(SKColors.DarkBlue, 10),
                    DataLabelsPosition = LiveChartsCore.Measure.DataLabelsPosition.Top
                },
                new ColumnSeries<int>
                {
                    Values = data.Select(d => d.TotalVulnerabilities).ToArray(),
                    Name = "漏洞数量",
                    Fill = new SolidColorPaint(ColorHigh),
                    DataLabelsPaint = MakePaint(SKColors.DarkRed, 10),
                    DataLabelsPosition = LiveChartsCore.Measure.DataLabelsPosition.Top
                },
                new LineSeries<double>
                {
                    Values = data.Select(d => d.ScanCount > 0 ? Math.Round((double)d.RiskIndex / d.ScanCount, 0) : 0d).ToArray(),
                    Name = "平均风险指数",
                    Stroke = new SolidColorPaint(new SKColor(142, 68, 173), 3),
                    Fill = new SolidColorPaint(new SKColor(142, 68, 173, 60)),
                    GeometrySize = 6,
                    ScalesYAt = 1
                }
            };

            if (PortVsVulnChart != null)
            {
                PortVsVulnChart.Series = series;
                PortVsVulnChart.XAxes = new[] { MakeAxis(labels, rotate: rotate) };
                PortVsVulnChart.YAxes = new[]
                {
                    MakeAxis(name: "数量（端口/漏洞）"),
                    MakeAxis(name: "风险指数", secondAxis: true)
                };
            }
        }

        private void RefreshPeriodDetailGrid()
        {
            var type = GetSelectedPeriod(out int periods);
            var data = _analyticsService.GenerateTimeSeriesData(_history, type, periods);
            if (PeriodDetailGrid != null) PeriodDetailGrid.ItemsSource = data;
        }
    }
}