using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.NetworkInformation;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Threading;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Documents;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Navigation;
using System.Windows.Shapes;
using OxyPlot;
using OxyPlot.Axes;
using OxyPlot.Series;
using LiveChartsCore;
using LiveChartsCore.SkiaSharpView;
using LiveChartsCore.SkiaSharpView.Painting;
using LiveChartsCore.SkiaSharpView.Painting.Effects;
using LiveChartsCore.SkiaSharpView.Extensions;
using iTextSharp.text;
using iTextSharp.text.pdf;
using LiveChartsCore.SkiaSharpView.VisualElements;
using SkiaSharp;
using NetSecurityScanner.Models;
using NetSecurityScanner.Services;
using NetSecurityScanner.Data;
using NetSecurityScanner.Utils;

namespace NetSecurityScanner
{
    public partial class MainWindow : Window, INotifyPropertyChanged, IDisposable
    {
        private PortScanner _portScanner;
        private VulnerabilityScanner _vulnerabilityScanner;
        private RiskAssessmentService _riskAssessmentService;
        private PortManagementService _portManagementService;
        private JsonDatabaseService _jsonDatabaseService;

        // 筛选相关（保留基础字段）
        private ObservableCollection<PortScanResult> _portScanResults;
        private ObservableCollection<VulnerabilityResult> _vulnerabilityResults;
        private ObservableCollection<RiskAssessmentItem> _riskAssessmentItems;
        private RiskAssessmentResult _riskAssessmentResult;

        private CancellationTokenSource _cancellationTokenSource;
        private DispatcherTimer _systemUptimeTimer;
        private DateTime? _lastScanTime;

        // 系统性能监控
        private PerformanceCounter _cpuCounter;
        private PerformanceCounter _ramCounter;
        private DispatcherTimer _systemHealthTimer;
        private DateTime _systemStartTime;

        // 性能优化组件（新增）
        private UiUpdateThrottler _uiUpdateThrottler;  // UI更新节流器
        private ScanPerformanceMonitor _scanPerformanceMonitor;  // 扫描性能监控器
        private bool _isPdfGenerating;  // PDF生成状态标志（防止重复点击）
        
        // 常量配置
        private const int UI_UPDATE_INTERVAL_MS = 500;  // UI更新间隔（毫秒）
        private const int MAX_DISPLAY_RESULTS = 1000;   // DataGrid最大显示数量

        // 风险评估图表
        private PlotModel _riskDistributionModel;
        public PlotModel RiskDistributionModel
        {
            get { return _riskDistributionModel; }
            set
            {
                _riskDistributionModel = value;
                OnPropertyChanged("RiskDistributionModel");
            }
        }


        public MainWindow()
        {
            try
            {
                Log("开始MainWindow构造函数");
                InitializeComponent();
                Log("InitializeComponent完成");
                
                InitializeServices();
                Log("InitializeServices完成");
                
                _portScanResults = new ObservableCollection<PortScanResult>();
                _vulnerabilityResults = new ObservableCollection<VulnerabilityResult>();
                _riskAssessmentItems = new ObservableCollection<RiskAssessmentItem>();
                _riskAssessmentResult = new RiskAssessmentResult();
                
                // 为端口扫描结果添加PropertyChanged事件监听
                PortScanResultsDataGrid.ItemsSource = _portScanResults;
                PortScanResultsDataGrid.ItemContainerGenerator.StatusChanged += PortScanResultsDataGrid_ItemContainerGenerator_StatusChanged;
                
                VulnerabilityResultsDataGrid.ItemsSource = _vulnerabilityResults;
                
                // 设置新的风险评估UI元素数据源
                VulnerabilityDetailsDataGrid.ItemsSource = _riskAssessmentResult.VulnerabilityDetails;
                OpenPortsDataGrid.ItemsSource = _riskAssessmentResult.OpenPorts;
                
                // 设置数据上下文，支持图表绑定
                this.DataContext = this;
                
                // 初始化系统启动时间
                _systemStartTime = DateTime.Now;
                _systemUptimeTimer = new DispatcherTimer();
                _systemUptimeTimer.Interval = TimeSpan.FromSeconds(1);
                _systemUptimeTimer.Tick += SystemUptimeTimer_Tick;
                _systemUptimeTimer.Start();
                
                // 设置状态栏版本号
                StatusVersionText.Text = $"NetSecurityScanner v{VersionHelper.GetVersion()}";
                
                // 初始化系统性能监控
                InitializeSystemPerformanceCounters();
                
                // 初始化性能优化组件（新增）
                InitializePerformanceOptimizers();
                
                // 确保窗口可见
                this.Loaded += MainWindow_Loaded;
                Log("MainWindow构造函数完成");
            }
            catch (Exception ex)
            {
                Log($"MainWindow初始化失败: {ex.Message}");
                Log($"异常堆栈: {ex.StackTrace}");
                if (ex.InnerException != null)
                {
                    Log($"内部异常: {ex.InnerException.Message}");
                    Log($"内部异常堆栈: {ex.InnerException.StackTrace}");
                }
                MessageBox.Show($"初始化失败: {ex.Message}", "错误", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        private void MainWindow_Loaded(object sender, RoutedEventArgs e)
        {
            try
            {
                Log("MainWindow_Loaded事件触发");
                // 确保窗口在屏幕范围内
                if (this.Left < 0) this.Left = 0;
                if (this.Top < 0) this.Top = 0;
                if (this.Left > SystemParameters.VirtualScreenWidth - this.Width)
                    this.Left = SystemParameters.VirtualScreenWidth - this.Width;
                if (this.Top > SystemParameters.VirtualScreenHeight - this.Height)
                    this.Top = SystemParameters.VirtualScreenHeight - this.Height;
                
                // 初始化扫描历史记录（在后台线程中执行，但UI更新会在UI线程中进行）
                _ = Task.Run(async () =>
                {
                    try
                    {
                        await RefreshScanHistoryAsync();
                    }
                    catch (Exception ex)
                    {
                        await Dispatcher.InvokeAsync(() => Log($"后台刷新扫描历史记录失败: {ex.Message}"));
                    }
                });
                
                // 延迟初始化图表以避免BeginInit冲突
                Dispatcher.BeginInvoke(new Action(async () =>
                {
                    try
                    {
                        await InitializeCharts();
                        
                        // 启动系统健康状态更新计时器
                        StartSystemHealthUpdates();
                    }
                    catch (Exception chartEx)
                    {
                        Log($"图表初始化失败: {chartEx.Message}");
                    }
                }));
                
                Log("MainWindow_Loaded事件处理完成");
            }
            catch (Exception ex)
            {
                Log($"MainWindow_Loaded处理失败: {ex.Message}");
                Log($"异常堆栈: {ex.StackTrace}");
                if (ex.InnerException != null)
                {
                    Log($"内部异常: {ex.InnerException.Message}");
                    Log($"内部异常堆栈: {ex.InnerException.StackTrace}");
                }
                MessageBox.Show($"窗口加载失败: {ex.Message}", "错误", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }
        
        // 初始化图表
        private async Task InitializeCharts()
        {
            try
            {
                Log("开始初始化图表");
                
                // 初始化风险分布图表
                InitializeRiskDistributionChart();
                
                Log("图表初始化完成");
            }
            catch (Exception ex)
            {
                Log($"图表初始化失败: {ex.Message}");
                Log($"异常堆栈: {ex.StackTrace}");
            }
        }
        
        /// <summary>
        /// 初始化性能优化组件（UI节流器、性能监控器等）
        /// </summary>
        private void InitializePerformanceOptimizers()
        {
            try
            {
                Log("开始初始化性能优化组件");
                
                // 1. 初始化UI更新节流器
                _uiUpdateThrottler = new UiUpdateThrottler(this.Dispatcher, UI_UPDATE_INTERVAL_MS);
                Log($"UI节流器初始化成功，更新间隔: {UI_UPDATE_INTERVAL_MS}ms");
                
                // 2. 初始化扫描性能监控器
                _scanPerformanceMonitor = new ScanPerformanceMonitor();
                Log("扫描性能监控器初始化成功");
                
                // 3. 初始化PDF生成状态标志
                _isPdfGenerating = false;
                
                Log("性能优化组件初始化完成");
            }
            catch (Exception ex)
            {
                Log($"性能优化组件初始化失败: {ex.Message}");
                Log($"异常堆栈: {ex.StackTrace}");
                // 即使初始化失败也不影响程序运行，使用降级模式
            }
        }
        
        /// <summary>
        /// 初始化风险分布图表
        /// </summary>
        private void InitializeRiskDistributionChart()
        {
            try
            {
                RiskDistributionModel = new PlotModel { Title = "风险分布" };
                
                // 添加类别轴和值轴
                RiskDistributionModel.Axes.Add(new CategoryAxis { Position = AxisPosition.Left, Title = "风险等级" });
                RiskDistributionModel.Axes.Add(new LinearAxis { Position = AxisPosition.Bottom, Title = "数量", Minimum = 0 });
                
                // 添加空的柱状图系列
                var series = new BarSeries { Title = "漏洞数量", FillColor = OxyColors.SkyBlue };
                RiskDistributionModel.Series.Add(series);
            }
            catch (Exception ex)
            {
                Log($"初始化风险分布图表失败: {ex.Message}");
            }
        }
        
        /// <summary>
        /// 更新风险分布图表
        /// </summary>
        private void UpdateRiskDistributionChart()
        {
            try
            {
                if (RiskDistributionModel == null)
                {
                    InitializeRiskDistributionChart();
                }
                
                // 清空现有数据
                RiskDistributionModel.Series.Clear();
                
                // 创建新的柱状图系列
                var series = new BarSeries { Title = "漏洞数量" };
                
                // 根据风险等级添加数据点
                foreach (var riskCategory in _riskAssessmentResult.RiskDistribution)
                {
                    // 根据风险等级设置不同颜色
                    OxyColor color = riskCategory.Category switch
                    {
                        "高" => OxyColors.Red,
                        "中" => OxyColors.Orange,
                        "低" => OxyColors.Yellow,
                        "无风险" => OxyColors.Green,
                        _ => OxyColors.SkyBlue
                    };
                    
                    series.Items.Add(new BarItem { Value = riskCategory.Count, Color = color });
                }
                
                RiskDistributionModel.Series.Add(series);
                
                // 更新图表
                RiskDistributionModel.InvalidatePlot(true);
            }
            catch (Exception ex)
            {
                Log($"更新风险分布图表失败: {ex.Message}");
            }
        }
        
        /// <summary>
        /// 更新风险分布饼图 (LiveCharts)
        /// </summary>
        private void UpdateRiskDistributionPieChart()
        {
            try
            {
                if (_riskAssessmentResult == null || _riskAssessmentResult.RiskDistribution == null)
                    return;
                
                var data = _riskAssessmentResult.RiskDistribution
                    .Where(r => r.Count > 0)
                    .ToList();
                
                if (!data.Any())
                    return;
                
                var pieSeries = new List<PieSeries<int>>();
                
                // 中文字体配置
                var fontFamily = "Microsoft YaHei";
                var paint = new SolidColorPaint(new SKColor(0x33, 0x33, 0x33)) { FontFamily = fontFamily };
                
                foreach (var risk in data)
                {
                    var color = risk.Category switch
                    {
                        "严重" => new SKColor(0xFF, 0x41, 0x6C),
                        "高" => new SKColor(0xFF, 0x6B, 0x4A),
                        "中" => new SKColor(0xFF, 0xA5, 0x02),
                        "低" => new SKColor(0x2E, 0xD5, 0x73),
                        "无风险" => new SKColor(0x70, 0xA1, 0xFF),
                        _ => new SKColor(0xC0, 0xC0, 0xC0)
                    };
                    
                    pieSeries.Add(new PieSeries<int>
                    {
                        Name = risk.Category,
                        Values = new[] { risk.Count },
                        Fill = new SolidColorPaint(color),
                        DataLabelsPaint = new SolidColorPaint(new SKColor(0xFF, 0xFF, 0xFF)) { FontFamily = fontFamily },
                        DataLabelsSize = 14,
                        DataLabelsPosition = LiveChartsCore.Measure.PolarLabelsPosition.Middle,
                        InnerRadius = 50
                    });
                }
                
                RiskDistributionPieChart.Series = pieSeries;
                
                // 配置图例字体
                RiskDistributionPieChart.LegendTextPaint = paint;
            }
            catch (Exception ex)
            {
                Log($"更新风险分布饼图失败: {ex.Message}");
            }
        }
        
        /// <summary>
        /// 更新风险分布柱状图 (LiveCharts)
        /// </summary>
        private void UpdateRiskDistributionBarChart()
        {
            try
            {
                if (_riskAssessmentResult == null || _riskAssessmentResult.RiskDistribution == null)
                    return;
                
                var data = _riskAssessmentResult.RiskDistribution
                    .Where(r => r.Count > 0)
                    .ToList();
                
                if (!data.Any())
                    return;
                
                var columnSeries = new List<ColumnSeries<int>>();
                var labels = new List<string>();
                
                // 中文字体配置
                var fontFamily = "Microsoft YaHei";
                
                foreach (var risk in data)
                {
                    var color = risk.Category switch
                    {
                        "严重" => new SKColor(0xFF, 0x41, 0x6C),
                        "高" => new SKColor(0xFF, 0x6B, 0x4A),
                        "中" => new SKColor(0xFF, 0xA5, 0x02),
                        "低" => new SKColor(0x2E, 0xD5, 0x73),
                        "无风险" => new SKColor(0x70, 0xA1, 0xFF),
                        _ => new SKColor(0xC0, 0xC0, 0xC0)
                    };
                    
                    labels.Add(risk.Category);
                    columnSeries.Add(new ColumnSeries<int>
                    {
                        Name = risk.Category,
                        Values = new[] { risk.Count },
                        Fill = new SolidColorPaint(color) { FontFamily = fontFamily },
                        MaxBarWidth = 60
                    });
                }
                
                RiskDistributionBarChart.Series = columnSeries;
                RiskDistributionBarChart.XAxes = new LiveChartsCore.SkiaSharpView.Axis[]
                {
                    new LiveChartsCore.SkiaSharpView.Axis
                    {
                        Labels = labels,
                        LabelsRotation = 0,
                        SeparatorsPaint = new SolidColorPaint(new SKColor(0xE0, 0xE0, 0xE0)),
                        TextSize = 12,
                        LabelsPaint = new SolidColorPaint(new SKColor(0x33, 0x33, 0x33)) { FontFamily = fontFamily }
                    }
                };
                RiskDistributionBarChart.YAxes = new LiveChartsCore.SkiaSharpView.Axis[]
                {
                    new LiveChartsCore.SkiaSharpView.Axis
                    {
                        MinStep = 1,
                        SeparatorsPaint = new SolidColorPaint(new SKColor(0xE0, 0xE0, 0xE0)),
                        TextSize = 12,
                        LabelsPaint = new SolidColorPaint(new SKColor(0x33, 0x33, 0x33)) { FontFamily = fontFamily }
                    }
                };
            }
            catch (Exception ex)
            {
                Log($"更新风险分布柱状图失败: {ex.Message}");
            }
        }
        
        /// <summary>
        /// 更新风险评估UI
        /// </summary>
        private void UpdateRiskAssessmentUI()
        {
            try
            {
                if (_riskAssessmentResult == null)
                    return;
                
                // 更新风险概览面板
                UpdateRiskOverviewPanel();
                
                // 更新风险分布图表 (OxyPlot)
                UpdateRiskDistributionChart();
                
                // 更新风险分布图表 (LiveCharts)
                UpdateRiskDistributionPieChart();
                UpdateRiskDistributionBarChart();
                
                // 更新数据网格
                // 设置开放端口数据源
                if (OpenPortsDataGrid != null && _riskAssessmentResult.OpenPorts != null)
                {
                    OpenPortsDataGrid.ItemsSource = null;
                    OpenPortsDataGrid.ItemsSource = _riskAssessmentResult.OpenPorts;
                }
                
                // 设置漏洞详情数据源
                if (VulnerabilityDetailsDataGrid != null && _riskAssessmentResult.VulnerabilityDetails != null)
                {
                    VulnerabilityDetailsDataGrid.ItemsSource = null;
                    VulnerabilityDetailsDataGrid.ItemsSource = _riskAssessmentResult.VulnerabilityDetails;
                }
                
                // 更新安全建议
                SecurityAdviceText.Text = _riskAssessmentResult.SecurityAdvice;
                
                // 更新生成端口关闭脚本按钮状态
                UpdateGeneratePortBatFromAiButton();
            }
            catch (Exception ex)
            {
                Log($"更新风险评估UI失败: {ex.Message}");
            }
        }
        
        /// <summary>
        /// 更新风险概览面板
        /// </summary>
        private void UpdateRiskOverviewPanel()
        {
            try
            {
                if (_riskAssessmentResult == null)
                    return;
                
                // 更新总体风险等级和分数
                OverallRiskText.Text = _riskAssessmentResult.OverallRiskLevel;
                RiskScoreText.Text = $"{_riskAssessmentResult.TotalRiskScore:F1} 分";
                
                // 根据风险等级设置颜色
                switch (_riskAssessmentResult.OverallRiskLevel)
                {
                    case "严重":
                    case "高":
                        OverallRiskText.Foreground = Brushes.Red;
                        break;
                    case "中":
                        OverallRiskText.Foreground = Brushes.Orange;
                        break;
                    case "低":
                        OverallRiskText.Foreground = Brushes.YellowGreen;
                        break;
                    default:
                        OverallRiskText.Foreground = Brushes.Green;
                        break;
                }
                
                // 更新目标IP和评估时间
                TargetIpText.Text = _riskAssessmentResult.TargetIp;
                AssessmentTimeText.Text = $"评估时间: {_riskAssessmentResult.AssessmentTime:yyyy-MM-dd HH:mm:ss}";
                AssessmentDateText.Text = $"评估日期: {_riskAssessmentResult.AssessmentTime:yyyy-MM-dd}";
                
                // 更新漏洞总数和开放端口数
                TotalVulnerabilitiesText.Text = _riskAssessmentResult.Statistics.TotalVulnerabilities.ToString();
                OpenPortsCountText.Text = _riskAssessmentResult.OpenPorts.Count.ToString();
                SensitivePortsText.Text = $"{_riskAssessmentResult.SensitiveOpenPorts.Count} 个敏感端口";
                
                // 更新高风险漏洞数量
                int highRiskCount = _riskAssessmentResult.RiskDistribution.Where(r => r.Category == "高" || r.Category == "严重").Sum(r => r.Count);
                if (this.Dispatcher.CheckAccess())
                {
                    HighRiskCountText.Text = highRiskCount.ToString();
                }
                else
                {
                    this.Dispatcher.Invoke(() => HighRiskCountText.Text = highRiskCount.ToString());
                }
            }
            catch (Exception ex)
            {
                Log($"更新风险概览面板失败: {ex.Message}");
            }
        }
        
        /// <summary>
        /// 手动触发AI风险分析
        /// </summary>
        private async void RefreshAiAnalysis_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                await StartAiRiskAssessmentAsync();
            }
            catch (Exception ex)
            {
                Log($"AI风险评估操作失败: {ex.Message}");
                // 确保在UI线程上显示错误信息
                if (this.Dispatcher.CheckAccess())
                {
                    MessageBox.Show($"AI风险评估失败: {ex.Message}", "错误", MessageBoxButton.OK, MessageBoxImage.Error);
                }
                else
                {
                    this.Dispatcher.Invoke(() =>
                    {
                        MessageBox.Show($"AI风险评估失败: {ex.Message}", "错误", MessageBoxButton.OK, MessageBoxImage.Error);
                    });
                }
            }
        }
        
        /// <summary>
        /// 开始AI风险评估
        /// </summary>
        private async Task StartAiRiskAssessmentAsync()
        {
            try
            {
                // 更新AI分析状态
                UpdateAiAnalysisStatus("AI分析中...", 0, true);
                
                // 模拟AI分析过程
                for (int i = 0; i <= 100; i += 10)
                {
                    await Task.Delay(200);
                    UpdateAiAnalysisStatus("AI分析中...", i, true);
                }
                
                // 更新AI分析状态为完成
                UpdateAiAnalysisStatus("AI分析完成", 100, false);
                
                // 更新AI分析子状态
                if (this.Dispatcher.CheckAccess())
                {
                    AiAnalysisSubStatusText.Text = "已完成风险评估，正在生成报告...";
                }
                else
                {
                    this.Dispatcher.Invoke(() =>
                    {
                        AiAnalysisSubStatusText.Text = "已完成风险评估，正在生成报告...";
                    });
                }
                
                // 执行实际的风险评估逻辑
                var portResultsCopy = new List<PortScanResult>();
                var vulnResultsCopy = new List<VulnerabilityResult>();
                                
                // 在UI线程上复制数据以确保线程安全
                if (this.Dispatcher.CheckAccess())
                {
                    portResultsCopy.AddRange(_portScanResults);
                    vulnResultsCopy.AddRange(_vulnerabilityResults);
                }
                else
                {
                    await this.Dispatcher.InvokeAsync(() =>
                    {
                        portResultsCopy.AddRange(_portScanResults);
                        vulnResultsCopy.AddRange(_vulnerabilityResults);
                    });
                }
                                
                if (portResultsCopy.Any() || vulnResultsCopy.Any())
                {
                    var newRiskAssessmentItems = _riskAssessmentService.AssessRisk(vulnResultsCopy, portResultsCopy);
                                    
                    // 在UI线程上更新UI元素
                    if (this.Dispatcher.CheckAccess())
                    {
                        _riskAssessmentItems.Clear();
                        foreach(var item in newRiskAssessmentItems)
                        {
                            _riskAssessmentItems.Add(item);
                        }
                        _riskAssessmentResult = _riskAssessmentService.AssessRiskExpert(vulnResultsCopy, portResultsCopy, TargetIpTextBox.Text.Trim());
                        UpdateRiskAssessmentUI();
                    }
                    else
                    {
                        await this.Dispatcher.InvokeAsync(() =>
                        {
                            _riskAssessmentItems.Clear();
                            foreach(var item in newRiskAssessmentItems)
                            {
                                _riskAssessmentItems.Add(item);
                            }
                            _riskAssessmentResult = _riskAssessmentService.AssessRiskExpert(vulnResultsCopy, portResultsCopy, TargetIpTextBox.Text.Trim());
                            UpdateRiskAssessmentUI();
                        });
                    }
                                    
                    // 更新AI分析子状态
                    if (this.Dispatcher.CheckAccess())
                    {
                        AiAnalysisSubStatusText.Text = "报告生成完成";
                    }
                    else
                    {
                        this.Dispatcher.Invoke(() =>
                        {
                            AiAnalysisSubStatusText.Text = "报告生成完成";
                        });
                    }
                }
                else
                {
                    // 如果没有扫描结果
                    UpdateAiAnalysisStatus("AI分析就绪", 0, false);
                    if (this.Dispatcher.CheckAccess())
                    {
                        AiAnalysisSubStatusText.Text = "请先执行端口扫描或漏洞扫描";
                    }
                    else
                    {
                        this.Dispatcher.Invoke(() =>
                        {
                            AiAnalysisSubStatusText.Text = "请先执行端口扫描或漏洞扫描";
                        });
                    }
                }
            }
            catch (Exception ex)
            {
                Log($"AI风险评估失败: {ex.Message}");
                UpdateAiAnalysisStatus("AI分析失败", 0, false);
                if (this.Dispatcher.CheckAccess())
                {
                    AiAnalysisSubStatusText.Text = ex.Message;
                }
                else
                {
                    this.Dispatcher.Invoke(() =>
                    {
                        AiAnalysisSubStatusText.Text = ex.Message;
                    });
                }
            }
        }
        
        /// <summary>
        /// 更新AI分析状态
        /// </summary>
        private void UpdateAiAnalysisStatus(string status, int progress, bool showProgress)
        {
            if (this.Dispatcher.CheckAccess())
            {
                AiAnalysisStatusText.Text = status;
                if (showProgress)
                {
                    AiAnalysisProgressBar.Visibility = Visibility.Visible;
                    AiAnalysisProgressBar.Value = progress;
                }
                else
                {
                    AiAnalysisProgressBar.Visibility = Visibility.Collapsed;
                }
            }
            else
            {
                this.Dispatcher.Invoke(() =>
                {
                    AiAnalysisStatusText.Text = status;
                    if (showProgress)
                    {
                        AiAnalysisProgressBar.Visibility = Visibility.Visible;
                        AiAnalysisProgressBar.Value = progress;
                    }
                    else
                    {
                        AiAnalysisProgressBar.Visibility = Visibility.Collapsed;
                    }
                });
            }
        }
        

        



        private void Log(string message)
        {
            try
            {
                string logPath = System.IO.Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "logs");
                System.IO.Directory.CreateDirectory(logPath);
                string logFile = System.IO.Path.Combine(logPath, $"app_{DateTime.Now:yyyyMMdd}.log");
                System.IO.File.AppendAllText(logFile, $"[{DateTime.Now:HH:mm:ss.fff}] {message}{Environment.NewLine}");
            }
            catch (Exception)
            {
                // 如果日志写入失败，忽略错误
            }
        }

        private void InitializeServices()
        {
            try
            {
                Log("开始初始化服务");
                // 初始化基础服务
                _portScanner = new PortScanner();
                Log("PortScanner初始化完成");
                
                _riskAssessmentService = new RiskAssessmentService();
                Log("RiskAssessmentService初始化完成");
                
                _portManagementService = new PortManagementService();
                Log("PortManagementService初始化完成");
                
                // 初始化依赖基础服务的服务
                _vulnerabilityScanner = new VulnerabilityScanner();
                Log("VulnerabilityScanner初始化完成");
                
                // 初始化JSON数据库服务（主要使用的数据库服务）
                _jsonDatabaseService = new JsonDatabaseService();
                Log("JsonDatabaseService初始化完成");
                
                // 注意：已跳过DatabaseService初始化，因为应用程序主要使用JsonDatabaseService
                // _databaseService = new DatabaseService();
                // Log("DatabaseService初始化完成");
            }
            catch (Exception ex)
            {
                Log($"服务初始化失败: {ex.Message}");
                Log($"异常堆栈: {ex.StackTrace}");
                if (ex.InnerException != null)
                {
                    Log($"内部异常: {ex.InnerException.Message}");
                    Log($"内部异常堆栈: {ex.InnerException.StackTrace}");
                }
                throw new Exception($"服务初始化失败: {ex.Message}", ex);
            }
        }

        public event PropertyChangedEventHandler? PropertyChanged;

        protected virtual void OnPropertyChanged(string propertyName)
        {
            PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));
        }

        private async void StartPortScan_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                await StartPortScanAsync();
            }
            catch (Exception ex)
            {
                Log($"端口扫描操作失败: {ex.Message}");
                // 确保在UI线程上显示错误信息
                if (this.Dispatcher.CheckAccess())
                {
                    MessageBox.Show($"端口扫描失败: {ex.Message}", "错误", MessageBoxButton.OK, MessageBoxImage.Error);
                }
                else
                {
                    this.Dispatcher.Invoke(() =>
                    {
                        MessageBox.Show($"端口扫描失败: {ex.Message}", "错误", MessageBoxButton.OK, MessageBoxImage.Error);
                    });
                }
            }
        }
        
        private async Task StartPortScanAsync()
        {
            string targetIp = TargetIpTextBox.Text.Trim();
            if (!IsValidIpAddress(targetIp))
            {
                MessageBox.Show("请输入有效的IP地址", "输入错误", MessageBoxButton.OK, MessageBoxImage.Warning);
                return;
            }
        
            List<int> portsToScan;
            if (AutoScanCheckBox.IsChecked == true)
            {
                // 扫描常用端口
                portsToScan = new List<int> { 21, 22, 23, 25, 53, 80, 110, 143, 443, 465, 993, 995, 1433, 3306, 3389, 5432, 8080, 8443 };
                PortRangeTextBox.Text = "常用端口";
            }
            else
            {
                string portRange = PortRangeTextBox.Text.Trim();
                if (string.IsNullOrEmpty(portRange))
                {
                    MessageBox.Show("请输入端口范围", "输入错误", MessageBoxButton.OK, MessageBoxImage.Warning);
                    return;
                }
                portsToScan = ParsePortRange(portRange);
                if (portsToScan == null || !portsToScan.Any())
                {
                    MessageBox.Show("端口范围格式错误", "输入错误", MessageBoxButton.OK, MessageBoxImage.Warning);
                    return;
                }
            }
        
            _cancellationTokenSource = new CancellationTokenSource();
                    
            try
            {
                // 清除之前的扫描结果
                if (this.Dispatcher.CheckAccess())
                {
                    _portScanResults.Clear();
                }
                else
                {
                    this.Dispatcher.Invoke(() =>
                    {
                        _portScanResults.Clear();
                    });
                }
                        
                // 更新按钮状态和扫描状态
                UpdateScanButtonStates(true);
                UpdateScanStatus("端口扫描准备中...", 0);
        
                var progress = new ThreadSafeProgress<int>(this, value =>
                {
                    UpdateScanStatus("端口扫描中...", value);
                });
        
                List<PortScanResult> results;
                string scanType = (ScanTypeComboBox.SelectedItem as ComboBoxItem)?.Content.ToString() ?? "TCP";
                        
                if (scanType == "TCP")
                {
                    results = await _portScanner.ScanTcpPortsAsync(targetIp, portsToScan, progress, _cancellationTokenSource.Token);
                }
                else
                {
                    results = await _portScanner.ScanUdpPortsAsync(targetIp, portsToScan, progress, _cancellationTokenSource.Token);
                }
                        
                // 只添加开放的端口到结果列表中
                var openPorts = results.Where(r => r.Status == "开放").ToList();
        
                // 在UI线程上更新UI元素
                if (this.Dispatcher.CheckAccess())
                {
                    // 清空现有结果
                    _portScanResults.Clear();
                    // 添加新结果
                    foreach (var result in openPorts)
                    {
                        _portScanResults.Add(result);
                    }
                            
                    // 更新生成按钮状态
                    UpdateGenerateButtons();
                }
                else
                {
                    this.Dispatcher.Invoke(() =>
                    {
                        // 清空现有结果
                        _portScanResults.Clear();
                        // 添加新结果
                        foreach (var result in openPorts)
                        {
                            _portScanResults.Add(result);
                        }
                                
                        // 更新生成按钮状态
                        UpdateGenerateButtons();
                    });
                }
        
                int openPortsCount = results.Count(r => r.Status == "开放");
                        
                // 保存完整扫描结果到JSON数据库
                var scanTime = DateTime.Now;
                _lastScanTime = scanTime;
                var completeScanResult = new CompleteScanResult
                {
                    TargetIp = targetIp,
                    ScanType = scanType + "端口扫描",
                    ScanTime = scanTime,
                    OpenPortsCount = openPortsCount,
                    VulnerabilitiesCount = 0,
                    RiskLevel = "未评估",
                    PortScanResults = openPorts,
                    VulnerabilityResults = new List<VulnerabilityResult>(),
                    RiskAssessment = new RiskAssessmentSummary
                    {
                        RiskLevel = "未评估",
                        SecurityAdvice = "请进行漏洞扫描以获取更完整的风险评估"
                    }
                };
                await _jsonDatabaseService.SaveScanResultAsync(completeScanResult);
                        
                // 扫描完成，更新状态
                UpdateScanStatus($"{scanType}端口扫描完成：发现 {openPortsCount} 个开放端口", 100, false);
                UpdateScanButtonStates(false);
            }
            finally
            {
                // 确保取消令牌被释放
                _cancellationTokenSource?.Dispose();
                        
                // 自动触发AI风险评估
                if (_portScanResults.Count > 0) // 只有当发现开放端口时才触发
                {
                    _ = Task.Run(async () =>
                    {
                        try
                        {
                            await StartAiRiskAssessmentAsync();
                        }
                        catch (Exception ex)
                        {
                            await Dispatcher.InvokeAsync(() => Log($"AI风险评估过程中发生错误: {ex.Message}"));
                        }
                    });
                }
            }
        }

        private async void StartVulnScan_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                await StartVulnScanAsync();
            }
            catch (Exception ex)
            {
                Log($"漏洞扫描操作失败: {ex.Message}");
                // 确保在UI线程上显示错误信息
                if (this.Dispatcher.CheckAccess())
                {
                    MessageBox.Show($"漏洞扫描失败: {ex.Message}", "错误", MessageBoxButton.OK, MessageBoxImage.Error);
                }
                else
                {
                    this.Dispatcher.Invoke(() =>
                    {
                        MessageBox.Show($"漏洞扫描失败: {ex.Message}", "错误", MessageBoxButton.OK, MessageBoxImage.Error);
                    });
                }
            }
        }
        
        private async Task StartVulnScanAsync()
        {
            string targetIp = VulnTargetTextBox.Text.Trim();
            if (!IsValidIpAddress(targetIp))
            {
                MessageBox.Show("请输入有效的IP地址", "输入错误", MessageBoxButton.OK, MessageBoxImage.Warning);
                return;
            }
                
            _cancellationTokenSource = new CancellationTokenSource();
                            
            try
            {
                // 清除之前的扫描结果
                if (this.Dispatcher.CheckAccess())
                {
                    _vulnerabilityResults.Clear();
                }
                else
                {
                    this.Dispatcher.Invoke(() =>
                    {
                        _vulnerabilityResults.Clear();
                    });
                }
                                
                // 更新按钮状态和扫描状态
                UpdateScanButtonStates(true);
                UpdateScanStatus("漏洞扫描准备中...", 0);
                        
                // 更新漏洞扫描专用进度条
                if (this.Dispatcher.CheckAccess())
                {
                    VulnScanProgressText.Text = "开始扫描";
                    VulnScanProgressPercent.Text = "0%";
                    VulnScanProgressBar.Value = 0;
                    VulnScanCurrentStage.Text = "正在准备扫描...";
                }
                else
                {
                    this.Dispatcher.Invoke(() =>
                    {
                        VulnScanProgressText.Text = "开始扫描";
                        VulnScanProgressPercent.Text = "0%";
                        VulnScanProgressBar.Value = 0;
                        VulnScanCurrentStage.Text = "正在准备扫描...";
                    });
                }
                
                // 创建漏洞扫描进度报告器
                var vulnProgress = new Progress<(string stage, int progress)>(progressTuple =>
                {
                    var (stage, progressValue) = progressTuple;
                            
                    if (this.Dispatcher.CheckAccess())
                    {
                        VulnScanProgressText.Text = stage;
                        VulnScanProgressPercent.Text = $"{progressValue}%";
                        VulnScanProgressBar.Value = progressValue;
                        VulnScanCurrentStage.Text = $"当前阶段: {stage}";
                    }
                    else
                    {
                        this.Dispatcher.Invoke(() =>
                        {
                            VulnScanProgressText.Text = stage;
                            VulnScanProgressPercent.Text = $"{progressValue}%";
                            VulnScanProgressBar.Value = progressValue;
                            VulnScanCurrentStage.Text = $"当前阶段: {stage}";
                        });
                    }
                });
                
                List<VulnerabilityResult> results;
                // 转换 PortScanResult 到 PortInfo
                var portInfos = _portScanResults.Select(p => new PortInfo
                {
                    PortNumber = p.PortNumber,
                    Service = p.Service,
                    Host = targetIp,
                    Status = p.Status,
                    Version = p.ServiceVersion
                }).ToList();

                if (portInfos.Any())
                {
                    // 使用现有的端口扫描结果进行漏洞扫描
                    results = await _vulnerabilityScanner.ScanAsync(targetIp, portInfos, "standard", vulnProgress, _cancellationTokenSource.Token);
                }
                else
                {
                    // 直接进行漏洞扫描
                    results = await _vulnerabilityScanner.ScanAsync(targetIp, new List<PortInfo>(), "standard", vulnProgress, _cancellationTokenSource.Token);
                }
                
                                
                // 在UI线程上更新UI元素
                if (this.Dispatcher.CheckAccess())
                {
                    // 清空现有结果
                    _vulnerabilityResults.Clear();
                    // 添加新结果
                    foreach (var result in results)
                    {
                        _vulnerabilityResults.Add(result);
                    }
                            
                    // 更新风险评估（传递开放端口列表以获得更准确的评估）
                    _riskAssessmentItems.Clear();
                    var assessmentItems = _riskAssessmentService.AssessRisk(results, _portScanResults.ToList());
                    foreach (var item in assessmentItems)
                    {
                        _riskAssessmentItems.Add(item);
                    }
                            
                    // 更新专家级风险评估结果
                    _riskAssessmentResult = _riskAssessmentService.AssessRiskExpert(results, _portScanResults.ToList(), targetIp);
                    UpdateRiskAssessmentUI();
                }
                else
                {
                    this.Dispatcher.Invoke(() =>
                    {
                        // 清空现有结果
                        _vulnerabilityResults.Clear();
                        // 添加新结果
                        foreach (var result in results)
                        {
                            _vulnerabilityResults.Add(result);
                        }
                                
                        // 更新风险评估（传递开放端口列表以获得更准确的评估）
                        _riskAssessmentItems.Clear();
                        var assessmentItems = _riskAssessmentService.AssessRisk(results, _portScanResults.ToList());
                        foreach (var item in assessmentItems)
                        {
                            _riskAssessmentItems.Add(item);
                        }
                                
                        // 更新专家级风险评估结果
                        _riskAssessmentResult = _riskAssessmentService.AssessRiskExpert(results, _portScanResults.ToList(), targetIp);
                        UpdateRiskAssessmentUI();
                    });
                }
                                
                // 计算总体风险等级
                string overallRisk = _riskAssessmentService.CalculateOverallRisk(results);
                                
                // 保存完整扫描结果到JSON数据库
                var scanTime = DateTime.Now;
                _lastScanTime = scanTime;
                var completeScanResult = new CompleteScanResult
                {
                    TargetIp = targetIp,
                    ScanType = "漏洞扫描",
                    ScanTime = scanTime,
                    OpenPortsCount = _portScanResults.Count(p => p.Status == "开放" || p.Status == "开放或过滤"),
                    VulnerabilitiesCount = results.Count,
                    RiskLevel = overallRisk,
                    PortScanResults = _portScanResults.ToList(),
                    VulnerabilityResults = results,
                    RiskAssessment = new RiskAssessmentSummary
                    {
                        RiskLevel = overallRisk,
                        SecurityAdvice = _riskAssessmentService.GenerateSecurityAdvice(results)
                    }
                };
                await _jsonDatabaseService.SaveScanResultAsync(completeScanResult);
                
                // 扫描完成，更新状态
                UpdateScanStatus($"漏洞扫描完成：发现 {results.Count} 个漏洞", 100, false);
                        
                // 更新漏洞扫描进度条为完成状态
                if (this.Dispatcher.CheckAccess())
                {
                    VulnScanProgressText.Text = "扫描完成";
                    VulnScanProgressPercent.Text = "100%";
                    VulnScanProgressBar.Value = 100;
                    VulnScanCurrentStage.Text = $"发现 {results.Count} 个漏洞";
                }
                else
                {
                    this.Dispatcher.Invoke(() =>
                    {
                        VulnScanProgressText.Text = "扫描完成";
                        VulnScanProgressPercent.Text = "100%";
                        VulnScanProgressBar.Value = 100;
                        VulnScanCurrentStage.Text = $"发现 {results.Count} 个漏洞";
                    });
                }
                        
                UpdateScanButtonStates(false);
            }
            finally
            {
                // 确保取消令牌被释放
                _cancellationTokenSource?.Dispose();
                                
                // 自动触发AI风险评估，使用更安全的方式
                if (Application.Current != null && Application.Current.Dispatcher != null)
                {
                    _ = Task.Run(async () =>
                    {
                        try
                        {
                            await Dispatcher.InvokeAsync(async () =>
                            {
                                await StartAiRiskAssessmentAsync();
                            });
                        }
                        catch (Exception ex)
                        {
                            await Dispatcher.InvokeAsync(() => Log($"AI风险评估过程中发生错误: {ex.Message}"));
                        }
                    });
                }
            }
        }

        private void UpdateAiRiskAssessment(string targetIp, List<PortScanResult> portResults, List<VulnerabilityResult> vulnResults)
        {
            _riskAssessmentItems.Clear();
            var assessmentItems = _riskAssessmentService.AssessRisk(vulnResults, portResults);
            foreach (var item in assessmentItems)
            {
                _riskAssessmentItems.Add(item);
            }

            _riskAssessmentResult = _riskAssessmentService.AssessRiskExpert(vulnResults, portResults, targetIp);
            UpdateRiskAssessmentUI();
        }

        private async void StartScan_Click(object sender, RoutedEventArgs e)
        {
            var dialog = new NetSecurityScanner.Views.ComprehensiveScanDialog();
            dialog.Owner = this;
            
            if (dialog.ShowDialog() != true)
            {
                return;
            }

            var targetIp = dialog.TargetIp;
            var portRange = dialog.PortRange;
            var enableTcp = dialog.EnableTcp;
            var enableUdp = dialog.EnableUdp;
            var enableVulnScan = dialog.EnableVulnerabilityScan;
            var saveToHistory = dialog.SaveToHistory;

            await ExecuteComprehensiveScanAsync(targetIp, portRange, enableTcp, enableUdp, enableVulnScan, saveToHistory);
        }

        private async Task ExecuteComprehensiveScanAsync(string targetIp, string portRange, bool enableTcp, bool enableUdp, bool enableVulnScan, bool saveToHistory)
        {
            var scanId = $"COMPREHENSIVE_{DateTime.Now:yyyyMMdd_HHmmss}";
            var stopwatch = System.Diagnostics.Stopwatch.StartNew();
            var allPortResults = new System.Collections.Concurrent.ConcurrentBag<PortScanResult>();
            var allVulnResults = new System.Collections.Concurrent.ConcurrentBag<VulnerabilityResult>();
            string scanTypeText = "";
            string riskLevel = "无风险";

            try
            {
                UpdateScanButtonStates(true);
                _cancellationTokenSource = new CancellationTokenSource();
                var token = _cancellationTokenSource.Token;

                if (enableTcp && enableUdp) scanTypeText = "TCP+UDP综合扫描";
                else if (enableTcp) scanTypeText = "TCP综合扫描";
                else scanTypeText = "UDP综合扫描";

                if (saveToHistory)
                {
                    await _jsonDatabaseService.SaveScanHistoryAsync(new ScanHistoryItem
                    {
                        ScanId = scanId,
                        TargetIp = targetIp,
                        ScanType = scanTypeText,
                        ScanTime = DateTime.Now,
                        OpenPortsCount = 0,
                        VulnerabilitiesCount = 0,
                        RiskLevel = "扫描中...",
                        PortScanResults = new List<PortScanResult>(),
                        VulnerabilityResults = new List<VulnerabilityResult>()
                    });
                }

                var ports = ParsePortRange(portRange);
                if (ports.Count == 0)
                {
                    MessageBox.Show("端口范围格式错误", "提示", MessageBoxButton.OK, MessageBoxImage.Warning);
                    return;
                }

                Dispatcher.Invoke(() =>
                {
                    TargetIpTextBox.Text = targetIp;
                    PortRangeTextBox.Text = portRange;
                    _portScanResults.Clear();
                    _vulnerabilityResults.Clear();
                    MainTabControl.SelectedIndex = 0;
                });

                if (enableTcp)
                {
                    UpdateScanStatus("正在执行TCP端口扫描...", 5);
                    Log($"[综合扫描] 开始TCP端口扫描: {targetIp}, 端口范围: {portRange}");

                    var tcpProgress = new Progress<int>(p =>
                    {
                        Dispatcher.Invoke(() => UpdateScanStatus($"TCP端口扫描进度: {p}%", 5 + p * 10));
                    });

                    var tcpResults = await _portScanner.ScanTcpPortsAsync(targetIp, ports, tcpProgress, token);
                    foreach (var r in tcpResults) allPortResults.Add(r);

                    Log($"[综合扫描] TCP端口扫描完成，发现 {tcpResults.Count(x => x.Status == "开放")} 个开放端口");
                }

                if (token.IsCancellationRequested) return;

                if (enableUdp)
                {
                    UpdateScanStatus("正在执行UDP端口扫描...", 55);
                    Log($"[综合扫描] 开始UDP端口扫描: {targetIp}, 端口范围: {portRange}");

                    var udpProgress = new Progress<int>(p =>
                    {
                        Dispatcher.Invoke(() => UpdateScanStatus($"UDP端口扫描进度: {p}%", 55 + p * 10));
                    });

                    var udpResults = await _portScanner.ScanUdpPortsAsync(targetIp, ports, udpProgress, token);
                    foreach (var r in udpResults) allPortResults.Add(r);

                    Log($"[综合扫描] UDP端口扫描完成，发现 {udpResults.Count(x => x.Status == "开放")} 个开放端口");
                }

                if (token.IsCancellationRequested) return;

                var openPorts = allPortResults.Where(x => x.Status == "开放").ToList();
                UpdateScanStatus($"端口扫描完成，共发现 {openPorts.Count} 个开放端口，正在更新UI...", 85);

                Dispatcher.Invoke(() =>
                {
                    foreach (var r in allPortResults.OrderBy(x => x.PortNumber))
                    {
                        _portScanResults.Add(r);
                    }
                    ScanProgressText.Text = $"端口扫描完成 - 发现 {openPorts.Count} 个开放端口";
                });

                if (token.IsCancellationRequested) return;

                if (enableVulnScan && openPorts.Count > 0)
                {
                    UpdateScanStatus("正在执行漏洞扫描...", 90);
                    Log($"[综合扫描] 开始漏洞扫描，基于 {openPorts.Count} 个开放端口");

                    var vulnResults = await _vulnerabilityScanner.ScanVulnerabilitiesAsync(
                        targetIp, openPorts, token);
                    
                    foreach (var v in vulnResults) allVulnResults.Add(v);

                    Log($"[综合扫描] 漏洞扫描完成，发现 {vulnResults.Count} 个漏洞");

                    Dispatcher.Invoke(() =>
                    {
                        foreach (var v in allVulnResults)
                        {
                            _vulnerabilityResults.Add(v);
                        }
                    });
                }

                stopwatch.Stop();

                var openPortCount = allPortResults.Count(x => x.Status == "开放");
                var vulnCount = allVulnResults.Count();
                riskLevel = vulnCount > 0 ? 
                    (allVulnResults.Any(x => x.RiskLevel == "严重" || x.RiskLevel == "严重风险") ? "严重风险" :
                     allVulnResults.Any(x => x.RiskLevel == "高" || x.RiskLevel == "高风险") ? "高风险" :
                     allVulnResults.Any(x => x.RiskLevel == "中" || x.RiskLevel == "中风险") ? "中风险" : "低风险") : "无风险";

                Dispatcher.Invoke(() =>
                {
                    UpdateScanStatus($"综合扫描完成! 耗时: {stopwatch.Elapsed.TotalSeconds:F1}秒", 100);
                    ScanProgressText.Text = $"扫描完成 - 耗时: {stopwatch.Elapsed.TotalSeconds:F1}秒 | 开放端口: {openPortCount} | 漏洞: {vulnCount} | 风险: {riskLevel}";

                    UpdateAiRiskAssessment(targetIp, allPortResults.ToList(), allVulnResults.ToList());

                    MessageBox.Show(
                        $"综合扫描完成!\n\n" +
                        $"目标: {targetIp}\n" +
                        $"扫描类型: {scanTypeText}\n" +
                        $"开放端口: {openPortCount} 个\n" +
                        $"发现漏洞: {vulnCount} 个\n" +
                        $"风险等级: {riskLevel}\n" +
                        $"耗时: {stopwatch.Elapsed.TotalSeconds:F1}秒",
                        "扫描完成", MessageBoxButton.OK, MessageBoxImage.Information);
                });

                if (saveToHistory)
                {
                    await _jsonDatabaseService.UpdateScanHistoryAsync(scanId, new ScanHistoryItem
                    {
                        ScanId = scanId,
                        TargetIp = targetIp,
                        ScanType = scanTypeText,
                        ScanTime = DateTime.Now,
                        OpenPortsCount = openPortCount,
                        VulnerabilitiesCount = vulnCount,
                        RiskLevel = riskLevel,
                        PortScanResults = allPortResults.ToList(),
                        VulnerabilityResults = allVulnResults.ToList(),
                        Duration = stopwatch.Elapsed.TotalSeconds
                    });

                    await RefreshScanHistoryAsync();
                }
            }
            catch (OperationCanceledException)
            {
                Log("[综合扫描] 扫描已取消");
                UpdateScanStatus("扫描已取消", 0);
            }
            catch (Exception ex)
            {
                Log($"[综合扫描] 扫描失败: {ex.Message}");
                MessageBox.Show($"扫描失败: {ex.Message}", "错误", MessageBoxButton.OK, MessageBoxImage.Error);
            }
            finally
            {
                UpdateScanButtonStates(false);
                stopwatch.Stop();
            }
        }

        /// <summary>
        /// 更新扫描按钮状态
        /// </summary>
        /// <param name="isScanning">是否正在扫描</param>
        private void UpdateScanButtonStates(bool isScanning)
        {
            if (this.Dispatcher.CheckAccess())
            {
                // 更新端口扫描按钮状态
                if (StartPortScanButton != null)
                    StartPortScanButton.IsEnabled = !isScanning;
                if (StopPortScanButton != null)
                    StopPortScanButton.IsEnabled = isScanning;
                
                // 更新漏洞扫描按钮状态
                if (StartVulnScanButton != null)
                    StartVulnScanButton.IsEnabled = !isScanning;
                if (StopVulnScanButton != null)
                    StopVulnScanButton.IsEnabled = isScanning;
            }
            else
            {
                this.Dispatcher.Invoke(() =>
                {
                    // 更新端口扫描按钮状态
                    if (StartPortScanButton != null)
                        StartPortScanButton.IsEnabled = !isScanning;
                    if (StopPortScanButton != null)
                        StopPortScanButton.IsEnabled = isScanning;
                    
                    // 更新漏洞扫描按钮状态
                    if (StartVulnScanButton != null)
                        StartVulnScanButton.IsEnabled = !isScanning;
                    if (StopVulnScanButton != null)
                        StopVulnScanButton.IsEnabled = isScanning;
                });
            }
        }
        
        /// <summary>
        /// 更新扫描状态显示
        /// </summary>
        /// <param name="statusText">状态文本</param>
        /// <param name="progressValue">进度值（0-100）</param>
        /// <param name="showProgress">是否显示进度条</param>
        private void UpdateScanStatus(string statusText, int progressValue = 0, bool showProgress = true)
        {
            if (this.Dispatcher.CheckAccess())
            {
                StatusTextBlock.Text = statusText;
                if (showProgress)
                {
                    ScanProgressBar.Visibility = Visibility.Visible;
                    ScanProgressBar.Value = progressValue;
                    ScanProgressText.Text = $"{statusText} {progressValue}%";
                }
                else
                {
                    ScanProgressBar.Visibility = Visibility.Collapsed;
                    ScanProgressText.Text = statusText;
                }
            }
            else
            {
                this.Dispatcher.Invoke(() =>
                {
                    StatusTextBlock.Text = statusText;
                    if (showProgress)
                    {
                        ScanProgressBar.Visibility = Visibility.Visible;
                        ScanProgressBar.Value = progressValue;
                        ScanProgressText.Text = $"{statusText} {progressValue}%";
                    }
                    else
                    {
                        ScanProgressBar.Visibility = Visibility.Collapsed;
                        ScanProgressText.Text = statusText;
                    }
                });
            }
        }
        
        private void StopScan_Click(object sender, RoutedEventArgs e)
        {
            _cancellationTokenSource?.Cancel();
            UpdateScanStatus("扫描已停止", 0, false);
            UpdateScanButtonStates(false);
        }

        private void SelectAllPorts_Click(object sender, RoutedEventArgs e)
        {
            // 在UI线程上更新UI元素
            if (this.Dispatcher.CheckAccess())
            {
                foreach (var result in _portScanResults)
                {
                    result.IsSelected = true;
                }
                UpdateGenerateButtons();
            }
            else
            {
                this.Dispatcher.Invoke(() =>
                {
                    foreach (var result in _portScanResults)
                    {
                        result.IsSelected = true;
                    }
                    UpdateGenerateButtons();
                });
            }
        }

        private void UnselectAllPorts_Click(object sender, RoutedEventArgs e)
        {
            // 在UI线程上更新UI元素
            if (this.Dispatcher.CheckAccess())
            {
                foreach (var result in _portScanResults)
                {
                    result.IsSelected = false;
                }
                UpdateGenerateButtons();
            }
            else
            {
                this.Dispatcher.Invoke(() =>
                {
                    foreach (var result in _portScanResults)
                    {
                        result.IsSelected = false;
                    }
                    UpdateGenerateButtons();
                });
            }
        }

        private void GeneratePortBat_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                var selectedPorts = _portScanResults.Where(r => r.IsSelected).ToList();
                if (!selectedPorts.Any())
                {
                    MessageBox.Show("请先勾选要关闭的端口", "提示", MessageBoxButton.OK, MessageBoxImage.Information);
                    return;
                }

                var portList = string.Join(", ", selectedPorts.Select(p => p.PortNumber));
                var result = MessageBox.Show(
                    $"即将为以下端口生成关闭脚本：\n{portList}\n\n是否使用高级选项？\n" +
                    "【是】高级选项：包含防火墙规则备份、入站+出站双向拦截、规则验证\n" +
                    "【否】标准选项：仅添加入站拦截规则",
                    "端口关闭脚本选项",
                    MessageBoxButton.YesNo,
                    MessageBoxImage.Question
                );

                string batContent;
                if (result == MessageBoxResult.Yes)
                {
                    batContent = _portManagementService.GenerateAdvancedPortClosureScript(selectedPorts.Select(p => p.PortNumber).ToList());
                }
                else
                {
                    batContent = _portManagementService.GeneratePortClosureScript(selectedPorts.Select(p => p.PortNumber).ToList());
                }

                string fileName = $"关闭端口脚本_{DateTime.Now:yyyyMMdd_HHmmss}.bat";
                string filePath = _portManagementService.SaveScriptToFile(batContent, fileName);

                MessageBox.Show(
                    $"端口关闭脚本已成功生成！\n\n" +
                    $"保存位置：{filePath}\n" +
                    $"包含端口：{portList}\n\n" +
                    "使用说明：\n" +
                    "1. 右键点击此BAT文件\n" +
                    "2. 选择\"以管理员身份运行\"\n" +
                    "3. 脚本将自动添加防火墙规则关闭端口",
                    "脚本生成成功",
                    MessageBoxButton.OK,
                    MessageBoxImage.Information
                );
                StatusTextBlock.Text = $"已生成端口关闭脚本：{filePath}";
                Log($"端口关闭脚本已生成：{filePath}");
            }
            catch (Exception ex)
            {
                MessageBox.Show($"生成端口关闭脚本失败: {ex.Message}", "错误", MessageBoxButton.OK, MessageBoxImage.Error);
                StatusTextBlock.Text = "生成端口关闭脚本失败";
            }
        }

        /// <summary>
        /// OpenPortsDataGrid选择变化事件
        /// </summary>
        private void OpenPortsDataGrid_SelectionChanged(object sender, SelectionChangedEventArgs e)
        {
            UpdateGeneratePortBatFromAiButton();
        }

        /// <summary>
        /// 端口扫描结果表格选择变化事件
        /// </summary>
        private void PortScanResultsDataGrid_SelectionChanged(object sender, SelectionChangedEventArgs e)
        {
            UpdateGeneratePortBatButton();
        }

        /// <summary>
        /// 更新端口扫描界面中的生成端口关闭脚本按钮状态
        /// </summary>
        private void UpdateGeneratePortBatButton()
        {
            if (this.Dispatcher.CheckAccess())
            {
                bool hasSelectedPorts = _portScanResults?.Any(p => p.IsSelected) == true;
                if (GeneratePortBatButton != null)
                {
                    GeneratePortBatButton.IsEnabled = hasSelectedPorts;
                }
            }
            else
            {
                this.Dispatcher.Invoke(() =>
                {
                    bool hasSelectedPorts = _portScanResults?.Any(p => p.IsSelected) == true;
                    if (GeneratePortBatButton != null)
                    {
                        GeneratePortBatButton.IsEnabled = hasSelectedPorts;
                    }
                });
            }
        }

        /// <summary>
        /// 更新AI风险评估界面中的生成端口关闭脚本按钮状态
        /// </summary>
        private void UpdateGeneratePortBatFromAiButton()
        {
            if (this.Dispatcher.CheckAccess())
            {
                bool hasSelectedPorts = _riskAssessmentResult?.OpenPorts?.Any(p => p.IsSelected) == true;
                if (GeneratePortBatFromAiButton != null)
                {
                    GeneratePortBatFromAiButton.IsEnabled = hasSelectedPorts;
                }
            }
            else
            {
                this.Dispatcher.Invoke(() =>
                {
                    bool hasSelectedPorts = _riskAssessmentResult?.OpenPorts?.Any(p => p.IsSelected) == true;
                    if (GeneratePortBatFromAiButton != null)
                    {
                        GeneratePortBatFromAiButton.IsEnabled = hasSelectedPorts;
                    }
                });
            }
        }

        /// <summary>
        /// 从AI风险评估界面生成端口关闭脚本
        /// </summary>
        private void GeneratePortBatFromAi_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                if (_riskAssessmentResult == null || _riskAssessmentResult.OpenPorts == null)
                {
                    MessageBox.Show("没有可用的端口数据", "提示", MessageBoxButton.OK, MessageBoxImage.Information);
                    return;
                }

                var selectedPorts = _riskAssessmentResult.OpenPorts.Where(p => p.IsSelected).ToList();
                if (!selectedPorts.Any())
                {
                    MessageBox.Show("请先选择要关闭的端口", "提示", MessageBoxButton.OK, MessageBoxImage.Information);
                    return;
                }

                // 提供高级选项
                var result = MessageBox.Show(
                    "是否使用高级选项生成端口关闭脚本？\n高级选项将包含防火墙规则备份功能。",
                    "端口关闭脚本选项",
                    MessageBoxButton.YesNo,
                    MessageBoxImage.Question
                );

                string batContent;
                if (result == MessageBoxResult.Yes)
                {
                    batContent = _portManagementService.GenerateAdvancedPortClosureScript(selectedPorts.Select(p => p.PortNumber).ToList());
                }
                else
                {
                    batContent = _portManagementService.GeneratePortClosureScript(selectedPorts.Select(p => p.PortNumber).ToList());
                }

                string filePath = _portManagementService.SaveScriptToFile(batContent, $"PortClosureScript_{DateTime.Now:yyyyMMdd_HHmmss}.bat");

                MessageBox.Show($"端口关闭脚本已生成：\n{filePath}\n\n请以管理员权限运行此脚本来关闭选定的端口。", "脚本生成成功", MessageBoxButton.OK, MessageBoxImage.Information);
                StatusTextBlock.Text = $"已生成端口关闭脚本：{filePath}";
            }
            catch (Exception ex)
            {
                MessageBox.Show($"生成端口关闭脚本失败: {ex.Message}", "错误", MessageBoxButton.OK, MessageBoxImage.Error);
                StatusTextBlock.Text = "生成端口关闭脚本失败";
            }
        }

        private void GenerateBat_Click(object sender, RoutedEventArgs e)
        {
            GeneratePortBat_Click(sender, e);
        }

        private void ExportReport_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                Log("开始导出报告");
                
                // 创建格式选择对话框
                var formatDialog = new Window
                {
                    Title = "选择报告格式",
                    Width = 300,
                    Height = 200,
                    WindowStartupLocation = WindowStartupLocation.CenterScreen,
                    ResizeMode = ResizeMode.NoResize,
                    WindowStyle = WindowStyle.ToolWindow
                };

                var stackPanel = new StackPanel { Margin = new Thickness(20) };
                
                var label = new Label { Content = "请选择报告格式：", Margin = new Thickness(0, 0, 0, 10) };
                stackPanel.Children.Add(label);

                var formatComboBox = new ComboBox { Width = 250, Margin = new Thickness(0, 0, 0, 20) };
                formatComboBox.Items.Add(new ComboBoxItem { Content = "文本文件 (.txt)", Tag = ReportFormat.Txt });
                formatComboBox.Items.Add(new ComboBoxItem { Content = "CSV文件 (.csv)", Tag = ReportFormat.Csv });
                formatComboBox.Items.Add(new ComboBoxItem { Content = "HTML文件 (.html)", Tag = ReportFormat.Html });
                formatComboBox.Items.Add(new ComboBoxItem { Content = "Word文件 (.docx)", Tag = ReportFormat.Word });
                formatComboBox.Items.Add(new ComboBoxItem { Content = "PDF文件 (.pdf)", Tag = ReportFormat.Pdf });
                formatComboBox.SelectedIndex = 0;
                stackPanel.Children.Add(formatComboBox);

                var buttonPanel = new StackPanel { Orientation = Orientation.Horizontal, HorizontalAlignment = System.Windows.HorizontalAlignment.Center };
                
                var okButton = new Button { Content = "确定", Width = 80, Margin = new Thickness(5) };
                var cancelButton = new Button { Content = "取消", Width = 80, Margin = new Thickness(5) };
                
                buttonPanel.Children.Add(okButton);
                buttonPanel.Children.Add(cancelButton);
                stackPanel.Children.Add(buttonPanel);

                formatDialog.Content = stackPanel;

                ReportFormat selectedFormat = ReportFormat.Txt;
                bool? dialogResult = false;

                okButton.Click += (s, args) =>
                {
                    selectedFormat = (ReportFormat)((ComboBoxItem)formatComboBox.SelectedItem).Tag;
                    dialogResult = true;
                    formatDialog.Close();
                };

                cancelButton.Click += (s, args) =>
                {
                    dialogResult = false;
                    formatDialog.Close();
                };

                formatDialog.ShowDialog();

                if (dialogResult == true)
                {
                    Log($"选择的报告格式：{selectedFormat}");
                    
                    // 确保报告数据可用
                    if (_portScanResults == null || _vulnerabilityResults == null || _riskAssessmentItems == null)
                    {
                        throw new InvalidOperationException("报告数据不可用，请先执行扫描");
                    }
                    
                    // 根据选择的格式生成报告
                    Log("开始生成报告内容");
                    string currentTargetIp = TargetIpTextBox.Text.Trim();
                    if (string.IsNullOrEmpty(currentTargetIp))
                    {
                        currentTargetIp = VulnTargetTextBox.Text.Trim();
                    }
                    var report = ReportGenerator.GenerateReport(_portScanResults.ToList(), _vulnerabilityResults.ToList(), _riskAssessmentItems.ToList(), currentTargetIp, selectedFormat);
                    Log("报告内容生成完成");
                    
                    // 确定文件扩展名
                string extension = selectedFormat switch
                {
                    ReportFormat.Csv => ".csv",
                    ReportFormat.Html => ".html",
                    ReportFormat.Word => ".docx",
                    ReportFormat.Pdf => ".pdf",
                    _ => ".txt"
                };

                string filePath;

                if (selectedFormat == ReportFormat.Pdf)
                {
                    // 使用专业级PDF报告生成器（优化：后台线程执行，避免UI阻塞）
                    Log("开始生成专业级PDF安全扫描报告");
                    
                    // 数据为空检查
                    if (_portScanResults == null || !_portScanResults.Any())
                    {
                        throw new InvalidOperationException("当前无端口扫描结果数据，请先执行扫描后再导出PDF报告");
                    }
                    
                    // 防止重复点击
                    if (_isPdfGenerating)
                    {
                        MessageBox.Show("正在生成PDF报告，请稍候...", "提示", MessageBoxButton.OK, MessageBoxImage.Information);
                        return;
                    }
                    
                    _isPdfGenerating = true;
                    StatusTextBlock.Text = "正在生成PDF报告（后台处理中）...";
                    
                    // 复制数据到本地变量（避免跨线程访问UI集合）
                    var portData = _portScanResults.ToList();
                    var vulnData = _vulnerabilityResults?.ToList() ?? new List<VulnerabilityResult>();
                    var riskData = _riskAssessmentItems?.ToList() ?? new List<RiskAssessmentItem>();
                    var targetIpCopy = currentTargetIp;
                    
                    // 在后台线程生成PDF（避免阻塞UI）
                    _ = Task.Run(() =>
                    {
                        try
                        {
                            Log("PDF生成任务已启动（后台线程）");
                            
                            // 调用PDF生成方法
                            string generatedPath = GenerateProfessionalPdfReport(
                                portData,
                                vulnData,
                                riskData,
                                targetIpCopy
                            );
                            
                            // 在UI线程显示结果
                            Dispatcher.BeginInvoke((Action)(() =>
                            {
                                try
                                {
                                    filePath = generatedPath;
                                    Log($"PDF报告生成成功：{filePath}");
                                    
                                    MessageBox.Show($"PDF报告已成功导出：\n{filePath}\n\n您可以在上述位置找到生成的报告文件。", "导出成功", MessageBoxButton.OK, MessageBoxImage.Information);
                                    StatusTextBlock.Text = $"PDF报告已导出：{filePath}";
                                    // PDF报告生成完成
                                    Log("PDF报告生成完成");
                                }
                                catch (Exception uiEx)
                                {
                                    Log($"更新UI失败: {uiEx.Message}");
                                }
                                finally
                                {
                                    _isPdfGenerating = false;
                                }
                            }));
                        }
                        catch (Exception pdfEx)
                        {
                            Log($"PDF生成失败: {pdfEx.Message}");
                            Debug.WriteLine($"[PDF] 后台生成异常: {pdfEx.StackTrace}");
                            
                            // 在UI线程显示错误
                            Dispatcher.BeginInvoke((Action)(() =>
                            {
                                MessageBox.Show($"PDF报告生成失败:\n{pdfEx.Message}", "错误", MessageBoxButton.OK, MessageBoxImage.Error);
                                StatusTextBlock.Text = "PDF报告生成失败";
                                _isPdfGenerating = false;
                            }));
                        }
                    });
                    
                    // 注意：这里不等待Task完成，立即返回让UI保持响应
                    // filePath将在后台任务完成后被设置
                    return;  // 提前返回，后续代码在回调中执行
                }
                else
                {
                    // 其他格式保持原有逻辑
                    Log($"开始保存报告到文件，扩展名为：{extension}");
                    filePath = _jsonDatabaseService.SaveReportToFile(report, extension);
                }
                    
                    Log($"报告保存成功：{filePath}");

                    MessageBox.Show($"报告已成功导出：\n{filePath}\n\n您可以在上述位置找到生成的报告文件。", "导出成功", MessageBoxButton.OK, MessageBoxImage.Information);
                    StatusTextBlock.Text = $"报告已导出：{filePath}";
                }
                else
                {
                    Log("用户取消了报告导出");
                }
            }
            catch (ArgumentException ex)
            {
                Log($"参数错误：{ex.Message}\n{ex.StackTrace}");
                MessageBox.Show($"报告生成失败：{ex.Message}\n\n请检查输入参数是否正确。", "参数错误", MessageBoxButton.OK, MessageBoxImage.Error);
                StatusTextBlock.Text = "报告生成失败：参数错误";
            }
            catch (InvalidOperationException ex)
            {
                Log($"操作错误：{ex.Message}\n{ex.StackTrace}");
                MessageBox.Show($"报告生成失败：{ex.Message}\n\n请先执行扫描操作，确保有可用的扫描结果。", "操作错误", MessageBoxButton.OK, MessageBoxImage.Error);
                StatusTextBlock.Text = "报告生成失败：操作错误";
            }
            catch (IOException ex)
            {
                Log($"文件操作错误：{ex.Message}\n{ex.StackTrace}");
                MessageBox.Show($"报告保存失败：{ex.Message}\n\n请检查文件路径是否正确，或文件是否被占用。", "文件操作错误", MessageBoxButton.OK, MessageBoxImage.Error);
                StatusTextBlock.Text = "报告保存失败：文件操作错误";
            }
            catch (Exception ex)
            {
                Log($"导出报告失败: {ex.Message}\n{ex.StackTrace}");
                if (ex.InnerException != null)
                {
                    Log($"内部异常: {ex.InnerException.Message}\n{ex.InnerException.StackTrace}");
                }
                MessageBox.Show($"导出报告失败: {ex.Message}\n\n详细错误信息已记录到日志文件中。", "错误", MessageBoxButton.OK, MessageBoxImage.Error);
                StatusTextBlock.Text = "报告导出失败";
            }
        }

        /// <summary>
        /// 使用iTextSharp生成真正的PDF格式报告文件（兼容性包装，建议使用 GenerateProfessionalPdfReport）
        /// </summary>
        /// <param name="markdownContent">报告的Markdown格式内容</param>
        /// <returns>生成的PDF文件完整路径</returns>
        [Obsolete("此方法已过时，请使用 GenerateProfessionalPdfReport 方法以获得专业级报告")]
        private string GenerateRealPdfReport(string markdownContent)
        {
            MessageBox.Show(
                "提示：当前使用的是旧版 PDF 生成接口。\n" +
                "建议使用新的专业级报告生成功能以获得更好的报告质量。\n" +
                "如需使用新接口，请调用 GenerateProfessionalPdfReport 方法。",
                "PDF 报告生成",
                MessageBoxButton.OK,
                MessageBoxImage.Information);

            var reportDir = System.IO.Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "Reports");
            if (!System.IO.Directory.Exists(reportDir))
                System.IO.Directory.CreateDirectory(reportDir);

            var fileName = $"SecurityScanReport_{DateTime.Now:yyyyMMdd_HHmmss}.pdf";
            var filePath = System.IO.Path.Combine(reportDir, fileName);
            var tempPath = filePath + ".tmp";

            try
            {
                if (File.Exists(tempPath)) File.Delete(tempPath);
                if (File.Exists(filePath)) File.Delete(filePath);

                using (var fs = new FileStream(tempPath, FileMode.Create, FileAccess.Write, FileShare.None))
                {
                    var doc = new Document(iTextSharp.text.PageSize.A4, 50, 50, 50, 50);
                    var writer = PdfWriter.GetInstance(doc, fs);
                    writer.CloseStream = false;

                    doc.Open();

                    BaseFont baseFont = null;
                    string[] fontPaths = { @"C:\Windows\Fonts\msyh.ttc", @"C:\Windows\Fonts\simhei.ttf", @"C:\Windows\Fonts\simsun.ttc", @"C:\Windows\Fonts\simsun.ttf" };
                    foreach (var fp in fontPaths)
                    {
                        try { baseFont = BaseFont.CreateFont(fp + ",0", BaseFont.IDENTITY_H, BaseFont.EMBEDDED); break; }
                        catch { }
                    }
                    if (baseFont == null)
                        try { baseFont = BaseFont.CreateFont(BaseFont.HELVETICA, BaseFont.CP1252, false); }
                        catch { baseFont = null; }

                    var titleFont = baseFont != null ? new Font(baseFont, 20, Font.BOLD, new BaseColor(44, 62, 80)) : new Font(Font.FontFamily.HELVETICA, 20, Font.BOLD, new BaseColor(44, 62, 80));
                    var headingFont = baseFont != null ? new Font(baseFont, 13, Font.BOLD, new BaseColor(33, 37, 41)) : new Font(Font.FontFamily.HELVETICA, 13, Font.BOLD, new BaseColor(33, 37, 41));
                    var normalFont = baseFont != null ? new Font(baseFont, 10, Font.NORMAL, BaseColor.BLACK) : new Font(Font.FontFamily.HELVETICA, 10, Font.NORMAL, BaseColor.BLACK);
                    var smallFont = baseFont != null ? new Font(baseFont, 9, Font.NORMAL, BaseColor.GRAY) : new Font(Font.FontFamily.HELVETICA, 9, Font.NORMAL, BaseColor.GRAY);

                    var lines = markdownContent.Split(new[] { "\r\n", "\n" }, StringSplitOptions.None);
                    foreach (var rawLine in lines)
                    {
                        var line = rawLine.Trim();
                        if (string.IsNullOrEmpty(line)) { doc.Add(new iTextSharp.text.Paragraph(" ", normalFont)); continue; }
                        if (line.StartsWith("# ")) { var p = new iTextSharp.text.Paragraph(line.Substring(2).Trim(), titleFont) { Alignment = iTextSharp.text.Element.ALIGN_CENTER, SpacingBefore = 12, SpacingAfter = 8 }; doc.Add(p); continue; }
                        if (line.StartsWith("## ")) { var p = new iTextSharp.text.Paragraph(line.Substring(3).Trim(), headingFont) { SpacingBefore = 8, SpacingAfter = 5 }; doc.Add(p); continue; }
                        if (line.StartsWith("---")) continue;
                        if (line.StartsWith("**") && line.EndsWith("**")) { var p = new iTextSharp.text.Paragraph(line.Trim('*').Trim(), headingFont) { SpacingBefore = 3, SpacingAfter = 2 }; doc.Add(p); continue; }

                        var cleanLine = line.Replace("|", "  ").Trim();
                        var p2 = new iTextSharp.text.Paragraph(cleanLine, normalFont) { SpacingAfter = 3, FirstLineIndent = 12 };
                        doc.Add(p2);
                    }

                    doc.Close();
                    writer.Close();
                    fs.Close();

                    File.Move(tempPath, filePath, true);
                    Log($"PDF报告生成成功：{filePath}");
                    return filePath;
                }
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"[PDF生成] 失败: {ex.Message}");
                try { if (File.Exists(tempPath)) File.Delete(tempPath); } catch { }
                throw new Exception($"PDF报告生成失败: {ex.Message}\n建议使用 GenerateProfessionalPdfReport 方法生成专业级报告。");
            }
        }

        

        #region Professional PDF Report Generation

        private string GenerateProfessionalPdfReport(List<PortScanResult> portScanResults, List<VulnerabilityResult> vulnerabilityResults, List<RiskAssessmentItem> riskAssessmentItems, string targetIp)
        {
            return Services.ProfessionalPdfReportGenerator.GenerateReport(portScanResults, vulnerabilityResults, riskAssessmentItems, targetIp);
        }

        #endregion
        private void Exit_Click(object sender, RoutedEventArgs e)
        {
            Close();
        }

        private string GetAppVersion()
        {
            return VersionHelper.GetVersion();
        }

        private void About_Click(object sender, RoutedEventArgs e)
        {
            var version = GetAppVersion();
            MessageBox.Show($"网络安全扫描工具 v{version}\n\n功能：\n- 端口扫描\n- 漏洞检测\n- 风险评估\n- 端口管理\n- 扫描历史记录\n\n仅供学习和测试使用", "关于", MessageBoxButton.OK, MessageBoxImage.Information);
        }

        private void WebPathTracer_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                var window = new Views.WebPathTracerWindow();
                window.Owner = this;
                window.Show();
                Log("打开网页后缀追踪工具");
            }
            catch (Exception ex)
            {
                Log($"打开网页后缀追踪工具失败: {ex.Message}");
                MessageBox.Show($"打开网页后缀追踪工具失败: {ex.Message}", "错误", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }
        
        #region 扫描历史记录相关方法
        
        private async void RefreshScanHistory_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                await RefreshScanHistoryAsync();
            }
            catch (Exception ex)
            {
                Log($"刷新扫描历史记录失败: {ex.Message}");
                // 确保在UI线程上显示错误信息
                if (this.Dispatcher.CheckAccess())
                {
                    MessageBox.Show($"刷新扫描历史记录失败: {ex.Message}", "错误", MessageBoxButton.OK, MessageBoxImage.Error);
                }
                else
                {
                    this.Dispatcher.Invoke(() =>
                    {
                        MessageBox.Show($"刷新扫描历史记录失败: {ex.Message}", "错误", MessageBoxButton.OK, MessageBoxImage.Error);
                    });
                }
            }
        }
        
        private async void ClearScanHistory_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                var result = MessageBox.Show("确定要清空所有扫描历史记录吗？此操作不可恢复。", "警告", MessageBoxButton.YesNo, MessageBoxImage.Warning);
                if (result == MessageBoxResult.Yes)
                {
                    // 清空所有历史记录
                    bool success = await _jsonDatabaseService.ClearAllScanHistoryAsync();
                    if (success)
                    {
                        // 刷新历史记录显示
                        await RefreshScanHistoryAsync();
                        StatusTextBlock.Text = "扫描历史记录已清空";
                    }
                    else
                    {
                        MessageBox.Show("清空扫描历史记录失败", "错误", MessageBoxButton.OK, MessageBoxImage.Error);
                        StatusTextBlock.Text = "清空扫描历史记录失败";
                    }
                }
            }
            catch (Exception ex)
            {
                MessageBox.Show($"清空扫描历史记录失败: {ex.Message}", "错误", MessageBoxButton.OK, MessageBoxImage.Error);
                StatusTextBlock.Text = "清空扫描历史记录失败";
            }
        }
        
        private async void DeleteScanHistory_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                var button = sender as Button;
                if (button != null)
                {
                    var scanId = button.Tag.ToString();
                    // 删除指定ScanId的扫描历史记录
                    await _jsonDatabaseService.DeleteScanResultAsync(scanId);
                    
                    // 刷新历史记录显示
                    await RefreshScanHistoryAsync();
                    StatusTextBlock.Text = $"扫描历史记录已删除";
                }
            }
            catch (Exception ex)
            {
                MessageBox.Show($"删除扫描历史记录失败: {ex.Message}", "错误", MessageBoxButton.OK, MessageBoxImage.Error);
                StatusTextBlock.Text = "删除扫描历史记录失败";
            }
        }
        
        private async void ViewScanHistory_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                var button = sender as Button;
                if (button != null)
                {
                    var scanId = button.Tag.ToString();
                    await ViewScanResultDetails(scanId);
                }
            }
            catch (Exception ex)
            {
                MessageBox.Show($"查看扫描历史记录失败: {ex.Message}", "错误", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }
        
        private async void ScanHistoryDataGrid_MouseDoubleClick(object sender, MouseButtonEventArgs e)
        {
            try
            {
                var dataGrid = sender as DataGrid;
                if (dataGrid != null && dataGrid.SelectedItem != null)
                {
                    var scanHistoryItem = dataGrid.SelectedItem as ScanHistoryItem;
                    if (scanHistoryItem != null)
                    {
                        await ViewScanResultDetails(scanHistoryItem.ScanId);
                    }
                }
            }
            catch (Exception ex)
            {
                MessageBox.Show($"查看扫描历史记录失败: {ex.Message}", "错误", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }
        
        private void UpdateVulnerabilityDatabase_Click(object sender, RoutedEventArgs e)
        {
            var updateWindow = new Views.VulnerabilityDatabaseUpdateWindow();
            updateWindow.Owner = this;
            updateWindow.ShowDialog();
            
            RefreshDatabaseStatus();
        }

        private void RefreshDatabaseStatus()
        {
            try
            {
                string dbPath = System.IO.Path.Combine(System.Environment.GetFolderPath(System.Environment.SpecialFolder.LocalApplicationData), "NetSecurityScanner", "vulnerability_database.json");
                if (System.IO.File.Exists(dbPath))
                {
                    var json = System.IO.File.ReadAllText(dbPath);
                    var db = System.Text.Json.JsonSerializer.Deserialize<Services.StaticVulnerabilityDatabase>(json);
                    if (db?.Vulnerabilities != null)
                    {
                        StatusTextBlock.Text = $"漏洞库: {db.Vulnerabilities.Count} 条记录";
                    }
                }
            }
            catch
            {
            }
        }

        private async Task ViewScanResultDetails(string scanId)
        {
            try
            {
                var completeResult = await _jsonDatabaseService.GetScanResultByIdAsync(scanId);
                if (completeResult != null)
                {
                    // 创建并显示扫描结果详情窗口
                    var detailsWindow = new Window
                    {
                        Title = $"扫描结果详情 - {completeResult.ScanId}",
                        Width = 800,
                        Height = 600,
                        WindowStartupLocation = WindowStartupLocation.CenterScreen,
                        ResizeMode = ResizeMode.CanResize
                    };
                    
                    var scrollViewer = new ScrollViewer();
                    var stackPanel = new StackPanel { Margin = new Thickness(20) };
                    
                    // 扫描基本信息
                    stackPanel.Children.Add(new Label { Content = "扫描基本信息", FontWeight = System.Windows.FontWeights.Bold, FontSize = 16, Margin = new Thickness(0, 0, 0, 10) });
                    stackPanel.Children.Add(new TextBlock { Text = $"扫描ID: {completeResult.ScanId}", Margin = new Thickness(0, 0, 0, 5) });
                    stackPanel.Children.Add(new TextBlock { Text = $"目标IP: {completeResult.TargetIp}", Margin = new Thickness(0, 0, 0, 5) });
                    stackPanel.Children.Add(new TextBlock { Text = $"扫描类型: {completeResult.ScanType}", Margin = new Thickness(0, 0, 0, 5) });
                    stackPanel.Children.Add(new TextBlock { Text = $"扫描时间: {completeResult.ScanTime}", Margin = new Thickness(0, 0, 0, 5) });
                    stackPanel.Children.Add(new TextBlock { Text = $"风险等级: {completeResult.RiskLevel}", Margin = new Thickness(0, 0, 0, 15) });
                    
                    // 端口扫描结果
                    if (completeResult.PortScanResults != null && completeResult.PortScanResults.Any())
                    {
                        stackPanel.Children.Add(new Label { Content = "端口扫描结果", FontWeight = System.Windows.FontWeights.Bold, FontSize = 14, Margin = new Thickness(0, 0, 0, 10) });
                        
                        var portDataGrid = new DataGrid
                        {
                            AutoGenerateColumns = false,
                            CanUserAddRows = false,
                            Margin = new Thickness(0, 0, 0, 15),
                            AlternatingRowBackground = new SolidColorBrush(Color.FromRgb(245, 245, 245)),
                            ItemsSource = completeResult.PortScanResults
                        };
                        
                        portDataGrid.Columns.Add(new DataGridTextColumn { Header = "端口号", Binding = new Binding("PortNumber"), Width = new DataGridLength(1, DataGridLengthUnitType.Star) });
                        portDataGrid.Columns.Add(new DataGridTextColumn { Header = "状态", Binding = new Binding("Status"), Width = new DataGridLength(1, DataGridLengthUnitType.Star) });
                        portDataGrid.Columns.Add(new DataGridTextColumn { Header = "服务", Binding = new Binding("Service"), Width = new DataGridLength(1, DataGridLengthUnitType.Star) });
                        portDataGrid.Columns.Add(new DataGridTextColumn { Header = "服务版本", Binding = new Binding("ServiceVersion"), Width = new DataGridLength(2, DataGridLengthUnitType.Star) });
                        
                        stackPanel.Children.Add(portDataGrid);
                    }
                    
                    // 漏洞扫描结果
                    if (completeResult.VulnerabilityResults != null && completeResult.VulnerabilityResults.Any())
                    {
                        stackPanel.Children.Add(new Label { Content = "漏洞扫描结果", FontWeight = System.Windows.FontWeights.Bold, FontSize = 14, Margin = new Thickness(0, 0, 0, 10) });
                        
                        var vulnDataGrid = new DataGrid
                        {
                            AutoGenerateColumns = false,
                            CanUserAddRows = false,
                            Margin = new Thickness(0, 0, 0, 15),
                            AlternatingRowBackground = new SolidColorBrush(Color.FromRgb(245, 245, 245)),
                            ItemsSource = completeResult.VulnerabilityResults
                        };
                        
                        vulnDataGrid.Columns.Add(new DataGridTextColumn { Header = "漏洞名称", Binding = new Binding("Name"), Width = new DataGridLength(2, DataGridLengthUnitType.Star) });
                        vulnDataGrid.Columns.Add(new DataGridTextColumn { Header = "风险等级", Binding = new Binding("RiskLevel"), Width = new DataGridLength(1, DataGridLengthUnitType.Star) });
                        vulnDataGrid.Columns.Add(new DataGridTextColumn { Header = "描述", Binding = new Binding("Description"), Width = new DataGridLength(3, DataGridLengthUnitType.Star), ElementStyle = new Style(typeof(TextBlock)) { Setters = { new Setter(TextBlock.TextWrappingProperty, TextWrapping.Wrap) } } });
                        
                        stackPanel.Children.Add(vulnDataGrid);
                    }
                    
                    // 风险评估
                    if (completeResult.RiskAssessment != null)
                    {
                        stackPanel.Children.Add(new Label { Content = "风险评估", FontWeight = System.Windows.FontWeights.Bold, FontSize = 14, Margin = new Thickness(0, 0, 0, 10) });
                        
                        stackPanel.Children.Add(new TextBlock { Text = $"总体风险: {completeResult.RiskAssessment.RiskLevel}", Margin = new Thickness(0, 0, 0, 5) });
                        
                        if (!string.IsNullOrEmpty(completeResult.RiskAssessment.SecurityAdvice))
                        {
                            stackPanel.Children.Add(new Label { Content = "安全建议", FontWeight = System.Windows.FontWeights.Bold, Margin = new Thickness(0, 10, 0, 5) });
                            stackPanel.Children.Add(new TextBlock { Text = completeResult.RiskAssessment.SecurityAdvice, TextWrapping = TextWrapping.Wrap, Margin = new Thickness(0, 0, 0, 15) });
                        }
                    }
                    
                    scrollViewer.Content = stackPanel;
                    detailsWindow.Content = scrollViewer;
                    detailsWindow.ShowDialog();
                }
                else
                {
                    MessageBox.Show("无法找到指定的扫描结果", "错误", MessageBoxButton.OK, MessageBoxImage.Error);
                }
            }
            catch (Exception ex)
            {
                MessageBox.Show($"查看扫描结果详情失败: {ex.Message}", "错误", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }
        
        private async void SearchTextBox_TextChanged(object sender, TextChangedEventArgs e)
        {
            try
            {
                // 搜索功能：用户输入时自动搜索
                await SearchScanHistory();
            }
            catch (Exception ex)
            {
                Log($"搜索扫描历史记录失败: {ex.Message}");
                // 确保在UI线程上显示错误信息
                if (this.Dispatcher.CheckAccess())
                {
                    MessageBox.Show($"搜索扫描历史记录失败: {ex.Message}", "错误", MessageBoxButton.OK, MessageBoxImage.Error);
                }
                else
                {
                    this.Dispatcher.Invoke(() =>
                    {
                        MessageBox.Show($"搜索扫描历史记录失败: {ex.Message}", "错误", MessageBoxButton.OK, MessageBoxImage.Error);
                    });
                }
            }
        }
        
        private async void SearchScanHistory_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                // 手动搜索按钮
                await SearchScanHistory();
            }
            catch (Exception ex)
            {
                Log($"手动搜索扫描历史记录失败: {ex.Message}");
                // 确保在UI线程上显示错误信息
                if (this.Dispatcher.CheckAccess())
                {
                    MessageBox.Show($"手动搜索扫描历史记录失败: {ex.Message}", "错误", MessageBoxButton.OK, MessageBoxImage.Error);
                }
                else
                {
                    this.Dispatcher.Invoke(() =>
                    {
                        MessageBox.Show($"手动搜索扫描历史记录失败: {ex.Message}", "错误", MessageBoxButton.OK, MessageBoxImage.Error);
                    });
                }
            }
        }
        
        private async void RiskLevelFilterComboBox_SelectionChanged(object sender, SelectionChangedEventArgs e)
        {
            try
            {
                // 风险等级过滤
                await FilterScanHistory();
            }
            catch (Exception ex)
            {
                Log($"风险等级过滤失败: {ex.Message}");
                // 确保在UI线程上显示错误信息
                if (this.Dispatcher.CheckAccess())
                {
                    MessageBox.Show($"风险等级过滤失败: {ex.Message}", "错误", MessageBoxButton.OK, MessageBoxImage.Error);
                }
                else
                {
                    this.Dispatcher.Invoke(() =>
                    {
                        MessageBox.Show($"风险等级过滤失败: {ex.Message}", "错误", MessageBoxButton.OK, MessageBoxImage.Error);
                    });
                }
            }
        }
        
        private async void ScanTypeFilterComboBox_SelectionChanged(object sender, SelectionChangedEventArgs e)
        {
            try
            {
                // 扫描类型过滤
                await FilterScanHistory();
            }
            catch (Exception ex)
            {
                Log($"扫描类型过滤失败: {ex.Message}");
                // 确保在UI线程上显示错误信息
                if (this.Dispatcher.CheckAccess())
                {
                    MessageBox.Show($"扫描类型过滤失败: {ex.Message}", "错误", MessageBoxButton.OK, MessageBoxImage.Error);
                }
                else
                {
                    this.Dispatcher.Invoke(() =>
                    {
                        MessageBox.Show($"扫描类型过滤失败: {ex.Message}", "错误", MessageBoxButton.OK, MessageBoxImage.Error);
                    });
                }
            }
        }
        
        private async void ResetFilters_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                // 重置所有过滤条件
                SearchTextBox.Text = string.Empty;
                RiskLevelFilterComboBox.SelectedIndex = 0;
                ScanTypeFilterComboBox.SelectedIndex = 0;
                await RefreshScanHistoryAsync();
            }
            catch (Exception ex)
            {
                Log($"重置过滤条件失败: {ex.Message}");
                // 确保在UI线程上显示错误信息
                if (this.Dispatcher.CheckAccess())
                {
                    MessageBox.Show($"重置过滤条件失败: {ex.Message}", "错误", MessageBoxButton.OK, MessageBoxImage.Error);
                }
                else
                {
                    this.Dispatcher.Invoke(() =>
                    {
                        MessageBox.Show($"重置过滤条件失败: {ex.Message}", "错误", MessageBoxButton.OK, MessageBoxImage.Error);
                    });
                }
            }
        }
        
        private async Task SearchScanHistory()
        {
            try
            {
                string searchTerm = SearchTextBox.Text.Trim();
                if (string.IsNullOrEmpty(searchTerm))
                {
                    await FilterScanHistory();
                }
                else
                {
                    var histories = await _jsonDatabaseService.SearchScanHistoryAsync(searchTerm);
                    UpdateScanHistoryDisplay(histories);
                    StatusTextBlock.Text = $"搜索完成，找到 {histories.Count} 条记录";
                }
            }
            catch (Exception ex)
            {
                MessageBox.Show($"搜索扫描历史记录失败: {ex.Message}", "错误", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }
        
        private async Task FilterScanHistory()
        {
            try
            {
                // 检查UI组件和服务是否已初始化
                if (RiskLevelFilterComboBox == null || ScanTypeFilterComboBox == null || _jsonDatabaseService == null)
                {
                    // 如果组件或服务未初始化，则延迟执行
                    await Task.Delay(100);
                    if (RiskLevelFilterComboBox == null || ScanTypeFilterComboBox == null || _jsonDatabaseService == null)
                        return; // 如果延迟后仍未初始化，则返回
                }
                
                // 获取过滤条件
                string riskLevel = (RiskLevelFilterComboBox.SelectedItem as ComboBoxItem)?.Content.ToString();
                string scanType = (ScanTypeFilterComboBox.SelectedItem as ComboBoxItem)?.Content.ToString();
                
                // 如果选择的是"全部"，则传递null
                riskLevel = riskLevel == "全部" ? null : riskLevel;
                scanType = scanType == "全部" ? null : scanType;
                
                // 应用过滤
                var histories = await _jsonDatabaseService.GetScanHistoryAsync(null, scanType, null, null, riskLevel);
                
                // 在UI线程中更新UI元素
                await Dispatcher.BeginInvoke(new Action(() =>
                {
                    UpdateScanHistoryDisplay(histories);
                }));
            }
            catch (Exception ex)
            {
                Log($"过滤扫描历史记录失败: {ex.Message}");
                // 在UI线程中显示错误消息
                await Dispatcher.BeginInvoke(new Action(() =>
                {
                    MessageBox.Show($"过滤扫描历史记录失败: {ex.Message}", "错误", MessageBoxButton.OK, MessageBoxImage.Error);
                }));
            }
        }
        
        private void UpdateScanHistoryDisplay(List<ScanHistoryItem> histories)
        {
            // 更新DataGrid的ItemsSource
            ScanHistoryDataGrid.ItemsSource = histories;

            // 更新统计信息
            ScanHistoryStats.Text = $"共 {histories.Count} 条记录";
            
            // 更新生成报告按钮的可用性
            GenerateReportFromHistoryButton.IsEnabled = histories.Any();
        }
        
        /// <summary>
        /// 获取选中的扫描历史记录项
        /// </summary>
        /// <returns>选中的扫描历史记录项列表</returns>
        private List<ScanHistoryItem> GetSelectedScanHistoryItems()
        {
            var histories = ScanHistoryDataGrid.ItemsSource as List<ScanHistoryItem>;
            if (histories == null)
                return new List<ScanHistoryItem>();
            
            return histories.Where(item => item.IsSelected).ToList();
        }
        
        /// <summary>
        /// 从扫描历史记录生成报告
        /// </summary>
        private async void GenerateReportFromHistory_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                // 获取选中的历史记录
                var selectedItems = GetSelectedScanHistoryItems();
                if (!selectedItems.Any())
                {
                    MessageBox.Show("请先选择要生成报告的历史记录", "提示", MessageBoxButton.OK, MessageBoxImage.Information);
                    return;
                }
                
                // 创建格式选择对话框
                var formatDialog = new Window
                {
                    Title = "选择报告格式",
                    Width = 300,
                    Height = 200,
                    WindowStartupLocation = WindowStartupLocation.CenterScreen,
                    ResizeMode = ResizeMode.NoResize,
                    WindowStyle = WindowStyle.ToolWindow
                };

                var stackPanel = new StackPanel { Margin = new Thickness(20) };
                
                var label = new Label { Content = "请选择报告格式：", Margin = new Thickness(0, 0, 0, 10) };
                stackPanel.Children.Add(label);

                var formatComboBox = new ComboBox { Width = 250, Margin = new Thickness(0, 0, 0, 20) };
                formatComboBox.Items.Add(new ComboBoxItem { Content = "文本文件 (.txt)", Tag = ReportFormat.Txt });
                formatComboBox.Items.Add(new ComboBoxItem { Content = "CSV文件 (.csv)", Tag = ReportFormat.Csv });
                formatComboBox.Items.Add(new ComboBoxItem { Content = "HTML文件 (.html)", Tag = ReportFormat.Html });
                formatComboBox.Items.Add(new ComboBoxItem { Content = "Word文件 (.docx)", Tag = ReportFormat.Word });
                formatComboBox.Items.Add(new ComboBoxItem { Content = "PDF文件 (.pdf)", Tag = ReportFormat.Pdf });
                formatComboBox.SelectedIndex = 0;
                stackPanel.Children.Add(formatComboBox);

                var buttonPanel = new StackPanel { Orientation = Orientation.Horizontal, HorizontalAlignment = System.Windows.HorizontalAlignment.Center };
                
                var okButton = new Button { Content = "确定", Width = 80, Margin = new Thickness(5) };
                var cancelButton = new Button { Content = "取消", Width = 80, Margin = new Thickness(5) };
                
                buttonPanel.Children.Add(okButton);
                buttonPanel.Children.Add(cancelButton);
                stackPanel.Children.Add(buttonPanel);

                formatDialog.Content = stackPanel;

                ReportFormat selectedFormat = ReportFormat.Txt;
                bool? dialogResult = false;

                okButton.Click += (s, args) =>
                {
                    selectedFormat = (ReportFormat)((ComboBoxItem)formatComboBox.SelectedItem).Tag;
                    dialogResult = true;
                    formatDialog.Close();
                };

                cancelButton.Click += (s, args) =>
                {
                    dialogResult = false;
                    formatDialog.Close();
                };

                formatDialog.ShowDialog();

                if (dialogResult == true)
                {
                    // 加载所有选中的完整扫描结果
                    List<CompleteScanResult> completeResults = new List<CompleteScanResult>();
                    foreach (var item in selectedItems)
                    {
                        var result = await _jsonDatabaseService.GetScanResultByIdAsync(item.ScanId);
                        if (result != null)
                        {
                            completeResults.Add(result);
                        }
                    }
                    
                    if (!completeResults.Any())
                    {
                        MessageBox.Show("无法获取选中的扫描结果", "错误", MessageBoxButton.OK, MessageBoxImage.Error);
                        return;
                    }
                    
                    // 合并扫描结果
                    List<PortScanResult> allPortResults = new List<PortScanResult>();
                    List<VulnerabilityResult> allVulnerabilityResults = new List<VulnerabilityResult>();
                    List<RiskAssessmentItem> allRiskAssessmentItems = new List<RiskAssessmentItem>();
                                        
                    foreach (var result in completeResults)
                    {
                        if (result.PortScanResults != null)
                        {
                            allPortResults.AddRange(result.PortScanResults);
                        }
                        if (result.VulnerabilityResults != null)
                        {
                            allVulnerabilityResults.AddRange(result.VulnerabilityResults);
                        }
                                            
                        // 如果完整扫描结果中有风险评估数据，也要合并
                        if (result.RiskAssessment != null)
                        {
                            // 从风险评估摘要创建风险评估项目
                            allRiskAssessmentItems.Add(new RiskAssessmentItem 
                            { 
                                Item = "总体风险等级", 
                                Value = result.RiskAssessment.RiskLevel, 
                                Status = result.RiskAssessment.RiskLevel 
                            });
                            allRiskAssessmentItems.Add(new RiskAssessmentItem 
                            { 
                                Item = "安全建议", 
                                Value = result.RiskAssessment.SecurityAdvice, 
                                Status = "建议" 
                            });
                        }
                    }
                    
                    // 生成报告
                    // 获取目标IP地址
                    string targetIp = completeResults.First().TargetIp;
                    if (completeResults.Count > 1)
                    {
                        // 如果有多个目标IP，合并显示
                        var uniqueIps = completeResults.Select(r => r.TargetIp).Distinct();
                        targetIp = string.Join(", ", uniqueIps);
                    }
                    
                    var report = ReportGenerator.GenerateReport(allPortResults, allVulnerabilityResults, allRiskAssessmentItems, targetIp, selectedFormat);
                                        
                    // 确定文件扩展名
                    string extension = selectedFormat switch
                    {
                        ReportFormat.Csv => ".csv",
                        ReportFormat.Html => ".html",
                        ReportFormat.Word => ".docx",
                        ReportFormat.Pdf => ".pdf",
                        _ => ".txt"
                    };
                                        
                    // 保存报告
                    string filePath;
                    if (selectedFormat == ReportFormat.Pdf)
                    {
                        // 使用基于44.docx格式的 HistoryReportGenerator 生成专业报告
                        // 替换原有的 GenerateProfessionalPdfReport 调用，以支持更专业的报告格式
                        Log("从历史记录生成符合44.docx格式的专业PDF安全扫描报告");

                        try
                        {
                            string pdfPath;

                            if (completeResults.Count == 1)
                            {
                                // 单条历史记录 - 使用专用方法生成单条记录报告
                                pdfPath = HistoryReportGenerator.GenerateFromHistoryRecord(completeResults[0]);
                            }
                            else if (completeResults.Count > 1)
                            {
                                // 多条历史记录 - 合并生成综合报告
                                pdfPath = HistoryReportGenerator.GenerateFromMultipleRecords(completeResults);
                            }
                            else
                            {
                                throw new InvalidOperationException("未选择任何历史记录");
                            }

                            // 检查生成结果
                            if (string.IsNullOrEmpty(pdfPath))
                            {
                                MessageBox.Show("PDF报告生成失败，可能原因：选中的历史记录中无有效扫描数据。",
                                                "生成失败", MessageBoxButton.OK, MessageBoxImage.Warning);
                                return;
                            }

                            filePath = pdfPath;
                            Log($"历史记录PDF报告已成功生成: {filePath}");
                        }
                        catch (Exception ex)
                        {
                            Log($"从历史记录生成PDF报告时出错: {ex.Message}");
                            MessageBox.Show($"生成PDF报告失败: {ex.Message}\n\n{ex.StackTrace}",
                                            "错误", MessageBoxButton.OK, MessageBoxImage.Error);
                            return;
                        }
                    }
                    else
                    {
                        filePath = _jsonDatabaseService.SaveReportToFile(report, extension);
                    }
                    
                    // 显示成功消息
                    MessageBox.Show($"报告已成功生成：\n{filePath}\n\n您可以在上述位置找到生成的报告文件。", "生成成功", MessageBoxButton.OK, MessageBoxImage.Information);
                    StatusTextBlock.Text = $"报告已生成：{filePath}";
                }
            }
            catch (Exception ex)
            {
                Log($"生成报告失败: {ex.Message}");
                // 确保在UI线程上显示错误信息
                if (this.Dispatcher.CheckAccess())
                {
                    MessageBox.Show($"生成报告失败: {ex.Message}", "错误", MessageBoxButton.OK, MessageBoxImage.Error);
                    StatusTextBlock.Text = "生成报告失败";
                }
                else
                {
                    this.Dispatcher.Invoke(() =>
                    {
                        MessageBox.Show($"生成报告失败: {ex.Message}", "错误", MessageBoxButton.OK, MessageBoxImage.Error);
                        StatusTextBlock.Text = "生成报告失败";
                    });
                }
            }
        }
        #endregion
        
        #region 辅助方法
        
        /// <summary>
        /// 刷新扫描历史记录
        /// </summary>
        private async Task RefreshScanHistoryAsync()
        {
            try
            {
                var histories = await _jsonDatabaseService.GetScanHistoryAsync();

                // 在UI线程中更新UI元素
                await Dispatcher.BeginInvoke(new Action(() =>
                {
                    UpdateScanHistoryDisplay(histories);
                    StatusTextBlock.Text = "扫描历史记录已刷新";
                }));
            }
            catch (Exception ex)
            {
                Log($"刷新扫描历史记录失败: {ex.Message}");
                // 在UI线程中显示错误消息
                await Dispatcher.BeginInvoke(new Action(() =>
                {
                    MessageBox.Show($"刷新扫描历史记录失败: {ex.Message}", "错误", MessageBoxButton.OK, MessageBoxImage.Error);
                }));
            }
        }
        
        /// <summary>
        /// 更新生成按钮状态
        /// </summary>
        private void UpdateGenerateButtons()
        {
            // 检查是否有选中的端口
            bool hasSelectedPorts = _portScanResults.Any(r => r.IsSelected);
            // 检查是否有开放的端口
            bool hasOpenPorts = _portScanResults.Any(r => r.Status == "开放" || r.Status == "开放或过滤");
            
            // 更新按钮状态
            GeneratePortBatButton.IsEnabled = hasSelectedPorts;
        }
        

        
        /// <summary>
        /// 验证IP地址格式
        /// </summary>
        /// <param name="ipAddress">IP地址字符串</param>
        /// <returns>是否为有效IP地址</returns>
        private bool IsValidIpAddress(string ipAddress)
        {
            if (string.IsNullOrEmpty(ipAddress))
                return false;
            
            return IPAddress.TryParse(ipAddress, out _);
        }
        
        /// <summary>
        /// 解析端口范围字符串
        /// </summary>
        /// <param name="portRange">端口范围字符串，如"1-100, 8080"</param>
        /// <returns>端口列表</returns>
        private List<int> ParsePortRange(string portRange)
        {
            var ports = new List<int>();
            
            if (string.IsNullOrEmpty(portRange))
                return ports;
            
            var ranges = portRange.Split(',', StringSplitOptions.RemoveEmptyEntries);
            
            foreach (var range in ranges)
            {
                var trimmedRange = range.Trim();
                
                if (trimmedRange.Contains("-"))
                {
                    // 处理范围格式，如"1-100"
                    var parts = trimmedRange.Split('-', StringSplitOptions.RemoveEmptyEntries);
                    if (parts.Length == 2 && int.TryParse(parts[0], out int start) && int.TryParse(parts[1], out int end))
                    {
                        if (start <= end && start >= 0 && end <= 65535)
                        {
                            ports.AddRange(Enumerable.Range(start, end - start + 1));
                        }
                    }
                }
                else
                {
                    // 处理单个端口，如"8080"
                    if (int.TryParse(trimmedRange, out int port) && port >= 0 && port <= 65535)
                    {
                        ports.Add(port);
                    }
                }
            }
            
            return ports.Distinct().OrderBy(p => p).ToList();
        }
        
        #endregion
        
        #region 事件处理程序
        
        /// <summary>
        /// 端口扫描结果DataGrid的ItemContainerGenerator状态变化事件处理程序
        /// </summary>
        private void PortScanResultsDataGrid_ItemContainerGenerator_StatusChanged(object? sender, EventArgs e)
        {
            // 这里可以添加ItemContainerGenerator状态变化的处理逻辑
        }
        
        /// <summary>
        /// 系统运行时间计时器Tick事件处理程序
        /// </summary>
        private void SystemUptimeTimer_Tick(object? sender, EventArgs e)
        {
            try
            {
                // 计算系统运行时间
                TimeSpan uptime = DateTime.Now - _systemStartTime;
                if (SystemUptimeText != null)
                {
                    SystemUptimeText.Text = $"运行时间: {uptime.Hours:D2}:{uptime.Minutes:D2}:{uptime.Seconds:D2}";
                }
            }
            catch (Exception ex)
            {
                Log($"更新系统运行时间失败: {ex.Message}");
            }
        }
        
        /// <summary>
        /// 初始化系统性能计数器
        /// </summary>
        private void InitializeSystemPerformanceCounters()
        {
            try
            {
                _cpuCounter = new PerformanceCounter();
                _cpuCounter.CategoryName = "Processor";
                _cpuCounter.CounterName = "% Processor Time";
                _cpuCounter.InstanceName = "_Total";
                
                _ramCounter = new PerformanceCounter();
                _ramCounter.CategoryName = "Memory";
                _ramCounter.CounterName = "% Committed Bytes In Use";
                
                // 首次调用GetNextValue()可能会返回0，所以预热一下
                var cpuUsage = _cpuCounter.NextValue();
                var ramUsage = _ramCounter.NextValue();
            }
            catch (Exception ex)
            {
                Log($"初始化性能计数器失败: {ex.Message}");
            }
        }
        
        /// <summary>
        /// 启动系统健康状态更新
        /// </summary>
        private void StartSystemHealthUpdates()
        {
            _systemHealthTimer = new DispatcherTimer();
            _systemHealthTimer.Interval = TimeSpan.FromSeconds(5); // 每5秒更新一次
            _systemHealthTimer.Tick += SystemHealthTimer_Tick;
            _systemHealthTimer.Start();
            
            // 立即更新一次
            UpdateSystemHealthStatus();
        }
        
        /// <summary>
        /// 系统健康状态计时器Tick事件处理程序
        /// </summary>
        private void SystemHealthTimer_Tick(object? sender, EventArgs e)
        {
            UpdateSystemHealthStatus();
        }
        
        /// <summary>
        /// 更新系统健康状态显示
        /// </summary>
        private void UpdateSystemHealthStatus()
        {
            try
            {
                // 获取CPU使用率
                float cpuUsage = 0;
                if (_cpuCounter != null)
                {
                    cpuUsage = _cpuCounter.NextValue();
                }
                
                // 获取内存使用率
                float ramUsage = 0;
                if (_ramCounter != null)
                {
                    ramUsage = _ramCounter.NextValue();
                }
                
                // 获取磁盘使用率
                DriveInfo[] drives = DriveInfo.GetDrives();
                float maxDiskUsage = 0;
                foreach (DriveInfo drive in drives.Where(d => d.IsReady && d.DriveType == DriveType.Fixed))
                {
                    try
                    {
                        double totalSize = drive.TotalSize;
                        double freeSpace = drive.TotalFreeSpace;
                        double usedSpace = totalSize - freeSpace;
                        float diskUsage = (float)(usedSpace / totalSize * 100);
                        if (diskUsage > maxDiskUsage)
                        {
                            maxDiskUsage = diskUsage;
                        }
                    }
                    catch (Exception)
                    {
                        // 忽略无法访问的驱动器
                    }
                }
                
                // 获取网络连接数（简化实现）
                int networkConnections = GetActiveTcpConnectionsCount();
                
                // 更新UI界面
                if (this.Dispatcher.CheckAccess())
                {
                    CpuUsageTextBlock.Text = $"CPU: {cpuUsage:F1}%";
                    RamUsageTextBlock.Text = $"内存: {ramUsage:F1}%";
                    DiskUsageTextBlock.Text = $"磁盘: {maxDiskUsage:F1}%";
                    NetworkConnectionsTextBlock.Text = $"网络连接: {networkConnections}";
                }
                else
                {
                    this.Dispatcher.Invoke(() =>
                    {
                        CpuUsageTextBlock.Text = $"CPU: {cpuUsage:F1}%";
                        RamUsageTextBlock.Text = $"内存: {ramUsage:F1}%";
                        DiskUsageTextBlock.Text = $"磁盘: {maxDiskUsage:F1}%";
                        NetworkConnectionsTextBlock.Text = $"网络连接: {networkConnections}";
                    });
                }
            }
            catch (Exception ex)
            {
                Log($"更新系统健康状态失败: {ex.Message}");
            }
        }
        
        /// <summary>
        /// 获取活动TCP连接数
        /// </summary>
        /// <returns>活动TCP连接数</returns>
        private int GetActiveTcpConnectionsCount()
        {
            try
            {
                var connections = IPGlobalProperties.GetIPGlobalProperties().GetActiveTcpConnections();
                return connections.Length;
            }
            catch (Exception ex)
            {
                Log($"获取TCP连接数失败: {ex.Message}");
                return 0; // 返回0表示无法获取
            }
        }
        
        #endregion
        
        #region Window Events
        
        private void Window_Closing(object sender, CancelEventArgs e)
        {
            try
            {
                Log("开始执行窗口关闭清理");
                
                // 取消正在进行的扫描任务
                if (_cancellationTokenSource != null)
                {
                    try
                    {
                        _cancellationTokenSource.Cancel();
                    }
                    catch (ObjectDisposedException)
                    {
                        // 已经被释放，忽略
                    }
                }
                
                // 等待当前任务完成
                Task.Delay(1000).Wait();
                
                // 清理资源
                Dispose();
                
                Log("窗口关闭清理完成");
            }
            catch (Exception ex)
            {
                Log($"窗口关闭清理过程中发生错误: {ex.Message}");
            }
        }
        
        #endregion
        
        #region IDisposable Implementation
        
        private bool _disposed = false;
        
        protected virtual void Dispose(bool disposing)
        {
            if (!_disposed && disposing)
            {
                try
                {
                    // 停止所有正在运行的任务
                    _cancellationTokenSource?.Cancel();
                    
                    // 等待一小段时间让任务取消完成
                    System.Threading.Thread.Sleep(100);
                    
                    if (_cancellationTokenSource != null)
                    {
                        try
                        {
                            _cancellationTokenSource.Dispose();
                        }
                        catch (ObjectDisposedException) { }
                        _cancellationTokenSource = null;
                    }
                    
                    // 释放漏洞扫描器
                    _vulnerabilityScanner?.Dispose();
                                        
                    // 停止计时器
                    _systemUptimeTimer?.Stop();
                    if (_systemUptimeTimer != null)
                    {
                        _systemUptimeTimer.Tick -= SystemUptimeTimer_Tick;
                    }
                    _systemUptimeTimer = null;

                    _systemHealthTimer?.Stop();
                    if (_systemHealthTimer != null)
                    {
                        _systemHealthTimer.Tick -= SystemHealthTimer_Tick;
                    }
                    _systemHealthTimer = null;
                                    
                    // 清理性能计数器
                    _cpuCounter?.Dispose();
                    _cpuCounter = null;
                    _ramCounter?.Dispose();
                    _ramCounter = null;
                    
                    // 释放性能优化组件（新增）
                    try
                    {
                        _uiUpdateThrottler?.Dispose();
                        Log("UI节流器已释放");
                    }
                    catch (Exception ex)
                    {
                        Log($"释放UI节流器失败: {ex.Message}");
                    }
                    finally
                    {
                        _uiUpdateThrottler = null;
                    }
                    
                    try
                    {
                        _scanPerformanceMonitor?.StopMonitoring();
                        _scanPerformanceMonitor?.Dispose();
                        
                        // 输出性能报告（如果进行过扫描）
                        if (_scanPerformanceMonitor != null && _scanPerformanceMonitor.PortsScanned > 0)
                        {
                            var report = _scanPerformanceMonitor.GenerateReport();
                            Log($"=== 扫描性能报告 ===\n{report}");
                            Debug.WriteLine(report);
                        }
                    }
                    catch (Exception ex)
                    {
                        Log($"释放扫描性能监控器失败: {ex.Message}");
                    }
                    finally
                    {
                        _scanPerformanceMonitor = null;
                    }
                    
                    // 清理大集合数据，释放内存
                    try
                    {
                        _portScanResults?.Clear();
                        _vulnerabilityResults?.Clear();
                        _riskAssessmentItems?.Clear();
                        Log("已清理扫描结果集合");
                    }
                    catch (Exception ex)
                    {
                        Log($"清理集合数据失败: {ex.Message}");
                    }
                    
                    // 强制垃圾回收（可选，在程序退出时执行）
                    GC.Collect(2, GCCollectionMode.Forced);
                    GC.WaitForPendingFinalizers();
                    GC.Collect(2, GCCollectionMode.Forced);
                }
                catch (Exception ex)
                {
                    Log($"资源清理过程中发生错误: {ex.Message}");
                    Debug.WriteLine($"[Dispose] 资源清理异常: {ex.Message}");
                }
            }
            _disposed = true;
        }
        
        public void Dispose()
        {
            Dispose(true);
            GC.SuppressFinalize(this);
        }
        
        #endregion
        
        #region Vulnerability Context Menu Handlers
        
        private void CopyVulnerabilityDetails_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                var selectedItem = VulnerabilityResultsDataGrid.SelectedItem as VulnerabilityResult;
                if (selectedItem != null)
                {
                    string details = $"漏洞名称: {selectedItem.Name}\n" +
                                  $"风险等级: {selectedItem.RiskLevel}\n" +
                                  $"端口: {selectedItem.Port}\n" +
                                  $"服务: {selectedItem.Service}\n" +
                                  $"CVE编号: {selectedItem.CveId}\n" +
                                  $"描述: {selectedItem.Description}\n" +
                                  $"解决方案: {selectedItem.Solution}\n" +
                                  $"参考链接: {selectedItem.References}";
                    
                    Clipboard.SetText(details);
                    MessageBox.Show("漏洞详情已复制到剪贴板", "提示", MessageBoxButton.OK, MessageBoxImage.Information);
                }
                else
                {
                    MessageBox.Show("请先选择一个漏洞条目", "提示", MessageBoxButton.OK, MessageBoxImage.Warning);
                }
            }
            catch (Exception ex)
            {
                Log($"复制漏洞详情时发生错误: {ex.Message}");
                MessageBox.Show("复制漏洞详情时发生错误", "错误", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }
        
        private void ExportSelectedVulnerabilities_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                var selectedItem = VulnerabilityResultsDataGrid.SelectedItem as VulnerabilityResult;
                if (selectedItem != null)
                {
                    // 导出单个选中的漏洞
                    var results = new List<VulnerabilityResult> { selectedItem };
                    ExportVulnerabilitiesToFile(results, "导出选中漏洞", "SelectedVulnerabilities");
                }
                else
                {
                    MessageBox.Show("请先选择一个漏洞条目", "提示", MessageBoxButton.OK, MessageBoxImage.Warning);
                }
            }
            catch (Exception ex)
            {
                Log($"导出漏洞时发生错误: {ex.Message}");
                MessageBox.Show("导出漏洞时发生错误", "错误", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }
        
        private void ViewCveDetails_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                var selectedItem = VulnerabilityResultsDataGrid.SelectedItem as VulnerabilityResult;
                if (selectedItem != null && !string.IsNullOrEmpty(selectedItem.CveId))
                {
                    string cveUrl = $"https://nvd.nist.gov/vuln/detail/{selectedItem.CveId}";
                    System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo
                    {
                        FileName = cveUrl,
                        UseShellExecute = true
                    });
                }
                else
                {
                    MessageBox.Show("所选漏洞没有有效的CVE编号或未选择任何条目", "提示", MessageBoxButton.OK, MessageBoxImage.Warning);
                }
            }
            catch (Exception ex)
            {
                Log($"打开CVE详情时发生错误: {ex.Message}");
                MessageBox.Show("打开CVE详情时发生错误", "错误", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }
        
        private void CopyCveId_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                var selectedItem = VulnerabilityResultsDataGrid.SelectedItem as VulnerabilityResult;
                if (selectedItem != null && !string.IsNullOrEmpty(selectedItem.CveId))
                {
                    Clipboard.SetText(selectedItem.CveId);
                    MessageBox.Show("CVE编号已复制到剪贴板", "提示", MessageBoxButton.OK, MessageBoxImage.Information);
                }
                else
                {
                    MessageBox.Show("所选漏洞没有有效的CVE编号或未选择任何条目", "提示", MessageBoxButton.OK, MessageBoxImage.Warning);
                }
            }
            catch (Exception ex)
            {
                Log($"复制CVE编号时发生错误: {ex.Message}");
                MessageBox.Show("复制CVE编号时发生错误", "错误", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }
        
        private void MarkAsResolved_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                var selectedItem = VulnerabilityResultsDataGrid.SelectedItem as VulnerabilityResult;
                if (selectedItem != null)
                {
                    selectedItem.Solution += " [已标记为已处理]";
                    
                    // 持久化漏洞结果到JSON文件
                    try
                    {
                        var jsonPath = System.IO.Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "vulnerability_results.json");
                        var json = System.Text.Json.JsonSerializer.Serialize(_vulnerabilityResults, new System.Text.Json.JsonSerializerOptions { WriteIndented = true });
                        System.IO.File.WriteAllText(jsonPath, json);
                    }
                    catch (Exception saveEx)
                    {
                        System.Diagnostics.Debug.WriteLine($"保存漏洞结果失败: {saveEx.Message}");
                    }
                    
                    MessageBox.Show("漏洞已标记为已处理", "提示", MessageBoxButton.OK, MessageBoxImage.Information);
                }
                else
                {
                    MessageBox.Show("请先选择一个漏洞条目", "提示", MessageBoxButton.OK, MessageBoxImage.Warning);
                }
            }
            catch (Exception ex)
            {
                Log($"标记漏洞为已处理时发生错误: {ex.Message}");
                MessageBox.Show("标记漏洞为已处理时发生错误", "错误", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }
        
        private void AddRemark_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                var selectedItem = VulnerabilityResultsDataGrid.SelectedItem as VulnerabilityResult;
                if (selectedItem != null)
                {
                    // 创建简单的输入对话框
                    var inputDialog = new InputDialog("添加备注", "请输入备注信息：");
                    if (inputDialog.ShowDialog() == true)
                    {
                        string remark = inputDialog.Answer;
                        if (!string.IsNullOrEmpty(remark))
                        {
                            selectedItem.Description += $" [备注: {remark}]";
                            
                            // 持久化漏洞结果到JSON文件
                            try
                            {
                                var jsonPath = System.IO.Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "vulnerability_results.json");
                                var json = System.Text.Json.JsonSerializer.Serialize(_vulnerabilityResults, new System.Text.Json.JsonSerializerOptions { WriteIndented = true });
                                System.IO.File.WriteAllText(jsonPath, json);
                            }
                            catch (Exception saveEx)
                            {
                                System.Diagnostics.Debug.WriteLine($"保存漏洞结果失败: {saveEx.Message}");
                            }
                            
                            MessageBox.Show("备注已添加", "提示", MessageBoxButton.OK, MessageBoxImage.Information);
                        }
                    }
                }
                else
                {
                    MessageBox.Show("请先选择一个漏洞条目", "提示", MessageBoxButton.OK, MessageBoxImage.Warning);
                }
            }
            catch (Exception ex)
            {
                Log($"添加备注时发生错误: {ex.Message}");
                MessageBox.Show("添加备注时发生错误", "错误", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }
        
        /// <summary>
        /// 导出漏洞到文件
        /// </summary>
        private void ExportVulnerabilitiesToFile(List<VulnerabilityResult> results, string dialogTitle, string defaultFileName)
        {
            var saveFileDialog = new Microsoft.Win32.SaveFileDialog
            {
                Filter = "CSV文件|*.csv|文本文件|*.txt|所有文件|*.*",
                Title = dialogTitle,
                FileName = $"{defaultFileName}_{DateTime.Now:yyyyMMdd_HHmmss}"
            };
            
            if (saveFileDialog.ShowDialog() == true)
            {
                try
                {
                    string fileExtension = System.IO.Path.GetExtension(saveFileDialog.FileName).ToLower();
                    
                    if (fileExtension == ".csv")
                    {
                        // 导出为CSV格式
                        StringBuilder csvContent = new StringBuilder();
                        csvContent.AppendLine("序号,漏洞名称,风险等级,端口,服务,CVE编号,检测方法,描述,解决方案,参考链接");
                        
                        foreach (var result in results)
                        {
                            csvContent.AppendLine($"{result.Id},\"{result.Name}\",\"{result.RiskLevel}\",{result.Port},\"{result.Service}\",\"{result.CveId}\",\"{result.DetectionMethod}\",\"{result.Description}\",\"{result.Solution}\",\"{result.References}\"");
                        }
                        
                        File.WriteAllText(saveFileDialog.FileName, csvContent.ToString(), Encoding.UTF8);
                    }
                    else
                    {
                        // 导出为文本格式
                        StringBuilder txtContent = new StringBuilder();
                        txtContent.AppendLine($"漏洞扫描结果报告 - {DateTime.Now:yyyy-MM-dd HH:mm:ss}");
                        txtContent.AppendLine(new string('=', 80));
                        txtContent.AppendLine();
                        
                        foreach (var result in results)
                        {
                            txtContent.AppendLine($"【漏洞 {result.Id}】");
                            txtContent.AppendLine($"漏洞名称: {result.Name}");
                            txtContent.AppendLine($"风险等级: {result.RiskLevel}");
                            txtContent.AppendLine($"端口: {result.Port}");
                            txtContent.AppendLine($"服务: {result.Service}");
                            txtContent.AppendLine($"CVE编号: {result.CveId}");
                            txtContent.AppendLine($"检测方法: {result.DetectionMethod}");
                            txtContent.AppendLine($"描述: {result.Description}");
                            txtContent.AppendLine($"解决方案: {result.Solution}");
                            txtContent.AppendLine($"参考链接: {result.References}");
                            txtContent.AppendLine(new string('-', 80));
                            txtContent.AppendLine();
                        }
                        
                        File.WriteAllText(saveFileDialog.FileName, txtContent.ToString(), Encoding.UTF8);
                    }
                    
                    MessageBox.Show($"漏洞数据已成功导出到: {saveFileDialog.FileName}", "导出成功", 
                        MessageBoxButton.OK, MessageBoxImage.Information);
                }
                catch (Exception ex)
                {
                    Log($"导出文件时发生错误: {ex.Message}");
                    MessageBox.Show($"导出文件时发生错误: {ex.Message}", "导出失败", 
                        MessageBoxButton.OK, MessageBoxImage.Error);
                }
            }
        }
        /// <summary>
        /// 获取端口扫描结果（供 AI 风险评估窗口使用）
        /// </summary>
        public List<PortScanResult> GetPortScanResults()
        {
            return _portScanResults?.ToList() ?? new List<PortScanResult>();
        }

        /// <summary>
        /// 获取漏洞扫描结果（供 AI 风险评估窗口使用）
        /// </summary>
        public List<VulnerabilityResult> GetVulnerabilityResults()
        {
            return _vulnerabilityResults?.ToList() ?? new List<VulnerabilityResult>();
        }

        /// <summary>
        /// 打开AI风险评估窗口
        /// </summary>
        private void AIRiskAssessment_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                // 检查是否有扫描结果
                if (_portScanResults == null || !_portScanResults.Any())
                {
                    MessageBox.Show("请先执行端口扫描或漏洞扫描，然后再进行 AI 风险评估。", "提示", MessageBoxButton.OK, MessageBoxImage.Information);
                    return;
                }

                // 获取目标 IP
                var targetIp = !string.IsNullOrWhiteSpace(TargetIpTextBox.Text) ? TargetIpTextBox.Text.Trim() : _portScanResults.FirstOrDefault()?.TargetIp ?? "Unknown";
                
                // 显示提示
                MessageBox.Show($"正在对目标 IP: {targetIp} 进行 AI 风险评估...", "AI 风险评估", MessageBoxButton.OK, MessageBoxImage.Information);

                // 复制扫描结果
                var portList = _portScanResults.ToList();
                var vulnList = _vulnerabilityResults?.ToList() ?? new List<VulnerabilityResult>();

                // 打开 AI 风险评估窗口，传递 MainWindow 引用以便重新分析时获取最新数据
                var aiRiskWindow = new Views.AIRiskAssessmentWindow(portList, vulnList, this);
                aiRiskWindow.ShowDialog();
            }
            catch (Exception ex)
            {
                Log($"打开 AI 风险评估窗口失败：{ex.Message}");
                MessageBox.Show($"打开 AI 风险评估窗口失败：{ex.Message}", "错误", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        
        #endregion

    
    #region 菜单项事件处理方法
    
    private void PortScan_Click(object sender, RoutedEventArgs e)
    {
        MainTabControl.SelectedIndex = 0;
    }
    
    private void VulnerabilityScan_Click(object sender, RoutedEventArgs e)
    {
        MainTabControl.SelectedIndex = 1;
    }
    
    private void BatchScan_Click(object sender, RoutedEventArgs e)
    {
        try
        {
            var batchScanWindow = new Views.BatchScanWindow();
            batchScanWindow.ShowDialog();
        }
        catch (Exception ex)
        {
            MessageBox.Show($"打开批量扫描窗口失败：{ex.Message}", "错误", MessageBoxButton.OK, MessageBoxImage.Error);
        }
    }
    
    private void ExpertMode_Click(object sender, RoutedEventArgs e)
    {
        try
        {
            var expertWindow = new Views.ExpertModeWindow();
            expertWindow.ShowDialog();
        }
        catch (Exception ex)
        {
            MessageBox.Show($"打开专家模式失败：{ex.Message}", "错误", MessageBoxButton.OK, MessageBoxImage.Error);
        }
    }
    
    private void StatisticsDashboard_Click(object sender, RoutedEventArgs e)
    {
        try
        {
            var statsWindow = new Views.StatisticsDashboardWindow();
            statsWindow.ShowDialog();
        }
        catch (Exception ex)
        {
            MessageBox.Show($"打开统计仪表板失败：{ex.Message}", "错误", MessageBoxButton.OK, MessageBoxImage.Error);
        }
    }
    
    private void Visualization_Click(object sender, RoutedEventArgs e)
    {
        try
        {
            var visualizationWindow = new Views.ScanVisualizationWindow();
            visualizationWindow.ShowDialog();
        }
        catch (Exception ex)
        {
            MessageBox.Show($"打开可视化图表失败：{ex.Message}", "错误", MessageBoxButton.OK, MessageBoxImage.Error);
        }
    }
    
    private void NetworkTopology_Click(object sender, RoutedEventArgs e)
    {
        try
        {
            var topologyWindow = new Views.NetworkTopologyWindow();
            topologyWindow.ShowDialog();
        }
        catch (Exception ex)
        {
            MessageBox.Show($"打开网络拓扑失败：{ex.Message}", "错误", MessageBoxButton.OK, MessageBoxImage.Error);
        }
    }
    
    private void ViewAttackPaths_Click(object sender, RoutedEventArgs e)
    {
        try
        {
            if (_portScanResults == null && _vulnerabilityResults == null)
            {
                MessageBox.Show("请先执行端口扫描或漏洞扫描，然后再进行攻击路径分析。", "提示", MessageBoxButton.OK, MessageBoxImage.Information);
                return;
            }

            var portList = _portScanResults?.Where(p => p.Status == "开放" || p.Status == "开放或过滤").ToList() ?? new List<PortScanResult>();
            var vulnList = _vulnerabilityResults?.ToList() ?? new List<VulnerabilityResult>();

            var attackPaths = _riskAssessmentService.GenerateAttackPathsForAnalysis(vulnList, portList);

            var attackPathWindow = new Views.AttackPathAnalysisWindow(attackPaths);
            attackPathWindow.Owner = this;
            attackPathWindow.ShowDialog();
        }
        catch (Exception ex)
        {
            MessageBox.Show($"打开攻击路径分析窗口失败：{ex.Message}", "错误", MessageBoxButton.OK, MessageBoxImage.Error);
        }
    }
    
    private void AttackLogQuery_Click(object sender, RoutedEventArgs e)
    {
        try
        {
            var attackLogWindow = new Views.AttackLogWindow();
            attackLogWindow.Owner = this;
            attackLogWindow.ShowDialog();
        }
        catch (Exception ex)
        {
            MessageBox.Show($"打开攻击日志查询窗口失败：{ex.Message}", "错误", MessageBoxButton.OK, MessageBoxImage.Error);
        }
    }
    
    private void ComplianceCheck_Click(object sender, RoutedEventArgs e)
    {
        try
        {
            var complianceWindow = new Views.ComplianceCheckWindow();
            complianceWindow.ShowDialog();
        }
        catch (Exception ex)
        {
            MessageBox.Show($"打开合规检查窗口失败：{ex.Message}", "错误", MessageBoxButton.OK, MessageBoxImage.Error);
        }
    }
    
    private void VulnerabilityKnowledgeBase_Click(object sender, RoutedEventArgs e)
    {
        try
        {
            var knowledgeBaseWindow = new Views.VulnerabilityKnowledgeBaseWindow { Owner = this };
            knowledgeBaseWindow.ShowDialog();
        }
        catch (Exception ex)
        {
            MessageBox.Show($"打开漏洞知识库窗口失败: {ex.Message}", "错误", MessageBoxButton.OK, MessageBoxImage.Error);
        }
    }
    
    private void PluginManager_Click(object sender, RoutedEventArgs e)
    {
        try
        {
            var window = new Views.PluginManagerWindow { Owner = this };
            window.ShowDialog();
        }
        catch (Exception ex)
        {
            MessageBox.Show($"打开插件管理窗口失败: {ex.Message}", "错误", MessageBoxButton.OK, MessageBoxImage.Error);
        }
    }
    
    private void AssetManagement_Click(object sender, RoutedEventArgs e)
    {
        try
        {
            var window = new Views.AssetManagementWindow { Owner = this };
            window.ShowDialog();
        }
        catch (Exception ex)
        {
            MessageBox.Show($"打开资产管理窗口失败: {ex.Message}", "错误", MessageBoxButton.OK, MessageBoxImage.Error);
        }
    }
    
    #endregion

}
}