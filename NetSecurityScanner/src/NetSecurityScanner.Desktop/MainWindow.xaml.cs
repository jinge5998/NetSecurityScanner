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
using iTextSharp.text;
using iTextSharp.text.pdf;
using LiveChartsCore;
using LiveChartsCore.SkiaSharpView;
using LiveChartsCore.SkiaSharpView.Painting;
using NetSecurityScanner.Models;
using NetSecurityScanner.Services;
using NetSecurityScanner.Data;
using NetSecurityScanner.Utils;
using NetSecurityScanner.Views;
using SkiaSharp;

namespace NetSecurityScanner
{
    public partial class MainWindow : Window, INotifyPropertyChanged, IDisposable
    {
        private PortScanner _portScanner;
        private VulnerabilityScanner _vulnerabilityScanner;
        private RiskAssessmentService _riskAssessmentService;
        private PortManagementService _portManagementService;
        private JsonDatabaseService _jsonDatabaseService;

        // AI 风险评估
        private AIRiskAssessmentService _aiRiskAssessmentService;
        private AIRiskAssessmentReportV5 _currentAiReport;

        // 筛选相关（保留基础字段）
        private ObservableCollection<PortScanResult> _portScanResults;
        private ObservableCollection<VulnerabilityResult> _vulnerabilityResults;
        private ObservableCollection<RiskAssessmentItem> _riskAssessmentItems;

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
#pragma warning disable CS0414
        private bool _isPdfGenerating;  // PDF生成状态标志（防止重复点击）
#pragma warning restore CS0414

        // 常量配置
        private const int UI_UPDATE_INTERVAL_MS = 500;  // UI更新间隔（毫秒）
        private const int MAX_DISPLAY_RESULTS = 1000;   // DataGrid最大显示数量


        public MainWindow()
        {
            try
            {
                Log("开始MainWindow构造函数");
                System.Diagnostics.Debug.WriteLine($"[AI Risk Font] Application started; CJK font resolved: {CjkFontResolver.ResolvedFamilyName}");
                InitializeComponent();
                Log("InitializeComponent完成");

                // v1.0.1.0 状态栏版本号改为读取程序集版本（不再硬编码 v1.0）
                try
                {
                    var v = System.Reflection.Assembly.GetExecutingAssembly().GetName().Version;
                    if (StatusVersionText != null && v != null)
                    {
                        StatusVersionText.Text = $"NetSecurityScanner v{v}";
                    }
                }
                catch { /* 静默，回退到 XAML 中的默认值 */ }

                UpdateLicenseStatusBar();

                var _licenseTimer = new System.Windows.Threading.DispatcherTimer();
                _licenseTimer.Interval = TimeSpan.FromSeconds(30);
                _licenseTimer.Tick += LicenseTimer_Tick;
                _licenseTimer.Start();

                InitializeServices();
                Log("InitializeServices完成");

                _portScanResults = new ObservableCollection<PortScanResult>();
                _vulnerabilityResults = new ObservableCollection<VulnerabilityResult>();
                _riskAssessmentItems = new ObservableCollection<RiskAssessmentItem>();

                // 为端口扫描结果添加PropertyChanged事件监听
                PortScanResultsDataGrid.ItemsSource = _portScanResults;
                PortScanResultsDataGrid.ItemContainerGenerator.StatusChanged += PortScanResultsDataGrid_ItemContainerGenerator_StatusChanged;

                VulnerabilityResultsDataGrid.ItemsSource = _vulnerabilityResults;

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

                // 预热插件加载（异步，不阻塞 UI）
                _ = Task.Run(async () =>
                {
                    try
                    {
                        await PluginOrchestrator.Instance.InitializeAsync();

                        // v6：异步初始化 PluginGovernor（依赖已加载的 PluginManager + Orchestrator）
                        try
                        {
                            // 从 Orchestrator 拉取一个临时 PluginManager 用于 Governor 的 HealthMonitor
                            // HealthMonitor 在每次执行时通过 BeginSample/EndSample 主动喂数据，不依赖 enumerate
                            var pm = new Plugins.PluginManager();
                            await pm.LoadAllPluginsAsync();
                            await PluginGovernor.Instance.InitializeAsync(pm, PluginOrchestrator.Instance);
                            Log("PluginGovernor 初始化完成");
                        }
                        catch (Exception gx)
                        {
                            System.Diagnostics.Debug.WriteLine($"[PluginGovernor] 初始化失败: {gx.Message}");
                        }
                    }
                    catch (Exception ex) { System.Diagnostics.Debug.WriteLine($"[PluginOrchestrator] 初始化失败: {ex.Message}"); }
                });
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

                // 初始化 AI 风险评估仪表盘为空状态
                ShowAiRiskEmptyState();

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

                _aiRiskAssessmentService = new AIRiskAssessmentService();
                Log("AIRiskAssessmentService初始化完成");
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

                // 触发 AI 风险评估（异步，不阻塞 UI）
                _ = RunAiRiskAssessmentAsync(targetIp);
            }
            finally
            {
                // 确保取消令牌被释放
                _cancellationTokenSource?.Dispose();
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

                // 触发 AI 风险评估（异步，不阻塞 UI）
                _ = RunAiRiskAssessmentAsync(targetIp);
            }
            finally
            {
                // 确保取消令牌被释放
                _cancellationTokenSource?.Dispose();
            }
        }

        private void PluginScanButton_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                var win = new PluginQuickInvokeWindow { Owner = this };
                win.ShowDialog();
            }
            catch (Exception ex)
            {
                MessageBox.Show($"打开插件扫描窗口失败: {ex.Message}", "错误", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        private async void StartScan_Click(object sender, RoutedEventArgs e)
        {
            // v1.0.1.3: 业务逻辑全部下沉到 ComprehensiveScanService，UI 层只做协调
            var dlg = new NetSecurityScanner.Desktop.Views.ComprehensiveScanDialog { Owner = this };
            if (dlg.ShowDialog() != true) return;
            var options = dlg.BuildOptions();

            var liveWin = new NetSecurityScanner.Views.ScanProgressLiveWindow { Owner = this };
            liveWin.SetTarget(options.TargetIp);
            liveWin.Show();

            try
            {
                var service = new NetSecurityScanner.Services.ComprehensiveScanService(
                    _portScanner, _vulnerabilityScanner, _riskAssessmentService,
                    _jsonDatabaseService, null, msg => Log(msg));
                var result = await service.ExecuteAsync(options, liveWin.Progress, liveWin.CancellationToken);
                liveWin.Close();

                if (result.Cancelled)
                {
                    UpdateScanStatus("扫描已取消", 0);
                    Log("[综合扫描] 用户已取消");
                    return;
                }

                UpdateScanStatus($"扫描完成 - 耗时 {result.ScanDurationSeconds:F1}s | 端口 {result.OpenPortsCount} | 漏洞 {result.VulnerabilitiesCount} | 风险 {result.RiskLevel}", 100);
                if (options.SaveToHistory) await RefreshScanHistoryAsync();

                // 触发 AI 风险评估（异步，不阻塞 UI）
                if (!string.IsNullOrWhiteSpace(result.TargetIp))
                {
                    _ = RunAiRiskAssessmentAsync(result.TargetIp);
                }

                new NetSecurityScanner.Views.ComprehensiveScanResultWindow(result) { Owner = this }.ShowDialog();
            }
            catch (Exception ex)
            {
                liveWin.Close();
                Log($"[综合扫描] 失败: {ex.Message}");
                MessageBox.Show($"扫描失败: {ex.Message}", "错误", MessageBoxButton.OK, MessageBoxImage.Error);
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

        private void GenerateBat_Click(object sender, RoutedEventArgs e)
        {
            GeneratePortBat_Click(sender, e);
        }

        private void ExportReport_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                Log("开始导出报告");

                if (_portScanResults == null || _vulnerabilityResults == null || _riskAssessmentItems == null)
                {
                    throw new InvalidOperationException("报告数据不可用，请先执行扫描");
                }

                string currentTargetIp = TargetIpTextBox.Text.Trim();
                if (string.IsNullOrEmpty(currentTargetIp))
                    currentTargetIp = VulnTargetTextBox.Text.Trim();

                var completeResult = new CompleteScanResult
                {
                    TargetIp = currentTargetIp,
                    ScanTime = DateTime.Now,
                    PortScanResults = _portScanResults.ToList(),
                    VulnerabilityResults = _vulnerabilityResults.ToList(),
                    RiskAssessment = new RiskAssessmentSummary
                    {
                        RiskLevel = CalculateOverallRiskFromVulns(_vulnerabilityResults.ToList()),
                        RiskScore = 0,
                        TotalVulnerabilities = _vulnerabilityResults.Count,
                        HighRiskCount = _vulnerabilityResults.Count(v => IsCriticalLevel(v?.RiskLevel) || IsHighLevel(v?.RiskLevel)),
                        MediumRiskCount = _vulnerabilityResults.Count(v => IsMediumLevel(v?.RiskLevel)),
                        LowRiskCount = _vulnerabilityResults.Count(v => IsLowLevel(v?.RiskLevel))
                    }
                };

                var completeResults = new List<CompleteScanResult> { completeResult };
                ExportReportWithDialog(completeResults);
            }
            catch (InvalidOperationException ex)
            {
                Log($"操作错误：{ex.Message}");
                MessageBox.Show(ex.Message, "操作错误", MessageBoxButton.OK, MessageBoxImage.Warning);
            }
            catch (Exception ex)
            {
                Log($"导出报告失败: {ex.Message}");
                MessageBox.Show($"导出报告失败: {ex.Message}", "错误", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        private async void ExportReportWithDialog(List<CompleteScanResult> completeResults)
        {
            try
            {
                var (selectedFormat, dialogResult) = ShowReportFormatDialog();
                if (dialogResult != true) return;

                string targetIp = completeResults.First().TargetIp ?? "未知目标";
                if (completeResults.Count > 1)
                    targetIp = string.Join(", ", completeResults.Select(r => r.TargetIp).Distinct());

                var filePath = ShowSaveFileDialog(selectedFormat, targetIp);
                if (string.IsNullOrEmpty(filePath)) return;

                var directoryPath = System.IO.Path.GetDirectoryName(filePath);
                if (!string.IsNullOrEmpty(directoryPath) && !Directory.Exists(directoryPath))
                    Directory.CreateDirectory(directoryPath);

                Log($"正在生成{selectedFormat switch { ReportFormat.Word => "Word", ReportFormat.Html => "HTML", ReportFormat.Csv => "CSV", _ => "文本" }}格式报告...");
                StatusTextBlock.Text = "正在生成报告，请稍候...";

                string generatedFilePath = string.Empty;

                if (selectedFormat == ReportFormat.Word)
                    generatedFilePath = await GenerateWordReport(completeResults, filePath);
                else if (selectedFormat == ReportFormat.Html)
                    generatedFilePath = await GenerateHtmlReport(completeResults, filePath);
                else if (selectedFormat == ReportFormat.Csv)
                    generatedFilePath = await GenerateCsvReport(completeResults, filePath);
                else
                    generatedFilePath = await GenerateTxtReport(completeResults, filePath);

                if (!string.IsNullOrEmpty(generatedFilePath) && File.Exists(generatedFilePath))
                {
                    var fileInfo = new FileInfo(generatedFilePath);
                    var sizeStr = fileInfo.Length > 1024 * 1024
                        ? $"{fileInfo.Length / (1024.0 * 1024.0):F2} MB"
                        : $"{fileInfo.Length / 1024.0:F1} KB";

                    var formatName = selectedFormat switch
                    {
                        ReportFormat.Word => "Word",
                        ReportFormat.Html => "HTML",
                        ReportFormat.Csv => "CSV",
                        _ => "文本"
                    };

                    var resultMessage = $"报告已成功生成！\n\n" +
                                       $"格式：{formatName}\n" +
                                       $"保存位置：{generatedFilePath}\n" +
                                       $"文件大小：{sizeStr}\n" +
                                       $"生成时间：{DateTime.Now:yyyy-MM-dd HH:mm:ss}\n\n" +
                                       $"是否立即打开查看？";

                    var openResult = MessageBox.Show(resultMessage, "报告生成成功", MessageBoxButton.YesNo, MessageBoxImage.Information);
                    StatusTextBlock.Text = $"报告已生成：{generatedFilePath}";
                    Log($"报告生成成功: {generatedFilePath} ({sizeStr})");

                    if (openResult == MessageBoxResult.Yes)
                    {
                        try
                        {
                            System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo
                            {
                                FileName = generatedFilePath,
                                UseShellExecute = true
                            });
                        }
                        catch (Exception openEx)
                        {
                            Debug.WriteLine($"[ReportExport] 打开文件失败: {openEx.Message}");
                        }
                    }
                }
                else
                {
                    MessageBox.Show("报告生成失败，可能原因：选中的记录中无有效扫描数据。",
                                    "生成失败", MessageBoxButton.OK, MessageBoxImage.Warning);
                    StatusTextBlock.Text = "报告生成失败";
                }
            }
            catch (Exception ex)
            {
                Log($"生成报告失败: {ex.Message}");
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

        private (ReportFormat format, bool? result) ShowReportFormatDialog()
        {
            var formatDialog = new Window
            {
                Title = "导出安全评估报告",
                Width = 480,
                Height = 420,
                WindowStartupLocation = WindowStartupLocation.CenterScreen,
                ResizeMode = ResizeMode.NoResize,
                WindowStyle = WindowStyle.ToolWindow,
                Background = new System.Windows.Media.SolidColorBrush(System.Windows.Media.Color.FromRgb(250, 250, 252))
            };

            var mainStack = new StackPanel { Margin = new Thickness(28) };

            var headerBorder = new Border
            {
                Background = new System.Windows.Media.SolidColorBrush(System.Windows.Media.Color.FromRgb(26, 54, 93)),
                CornerRadius = new CornerRadius(6),
                Padding = new Thickness(16, 12, 16, 12),
                Margin = new Thickness(0, 0, 0, 18)
            };
            var headerStack = new StackPanel();
            var headerTitle = new TextBlock
            {
                Text = "导出安全评估报告",
                FontSize = 17,
                FontWeight = System.Windows.FontWeights.Bold,
                Foreground = System.Windows.Media.Brushes.White
            };
            var headerDesc = new TextBlock
            {
                Text = "选择报告格式，然后指定保存位置即可生成报告",
                FontSize = 11,
                Foreground = new System.Windows.Media.SolidColorBrush(System.Windows.Media.Color.FromRgb(180, 200, 230)),
                Margin = new Thickness(0, 4, 0, 0)
            };
            headerStack.Children.Add(headerTitle);
            headerStack.Children.Add(headerDesc);
            headerBorder.Child = headerStack;
            mainStack.Children.Add(headerBorder);

            var formatLabel = new TextBlock
            {
                Text = "选择报告格式：",
                FontSize = 12,
                FontWeight = System.Windows.FontWeights.SemiBold,
                Margin = new Thickness(0, 0, 0, 8),
                Foreground = new System.Windows.Media.SolidColorBrush(System.Windows.Media.Color.FromRgb(55, 65, 81))
            };
            mainStack.Children.Add(formatLabel);

            var formatItems = new[]
            {
                new { Icon = "📝", Name = "Word文件 (.docx)", Desc = "可编辑文档格式，方便二次修改和协作（推荐）", Tag = ReportFormat.Word },
                new { Icon = "🌐", Name = "HTML文件 (.html)", Desc = "网页格式报告，可直接在浏览器中查看，支持图表展示", Tag = ReportFormat.Html },
                new { Icon = "📊", Name = "CSV文件 (.csv)", Desc = "数据表格格式，适合导入Excel进行数据分析", Tag = ReportFormat.Csv },
                new { Icon = "📃", Name = "文本文件 (.txt)", Desc = "纯文本格式，体积小、兼容性好", Tag = ReportFormat.Txt }
            };

            var formatComboBox = new ComboBox
            {
                Width = 410,
                Height = 34,
                FontSize = 12,
                Margin = new Thickness(0, 0, 0, 4),
                HorizontalAlignment = System.Windows.HorizontalAlignment.Left
            };

            foreach (var item in formatItems)
            {
                formatComboBox.Items.Add(new ComboBoxItem
                {
                    Content = $"{item.Icon} {item.Name}  — {item.Desc}",
                    Tag = item.Tag
                });
            }
            formatComboBox.SelectedIndex = 0;
            mainStack.Children.Add(formatComboBox);

            var tipBorder = new Border
            {
                Background = new System.Windows.Media.SolidColorBrush(System.Windows.Media.Color.FromRgb(239, 246, 255)),
                CornerRadius = new CornerRadius(4),
                Padding = new Thickness(12, 8, 12, 8),
                Margin = new Thickness(0, 6, 0, 20),
                BorderBrush = new System.Windows.Media.SolidColorBrush(System.Windows.Media.Color.FromRgb(191, 219, 254)),
                BorderThickness = new Thickness(1)
            };
            var tipText = new TextBlock
            {
                Text = "提示：PDF格式支持专业排版、图表和彩色展示，推荐使用。Word格式可编辑，适合二次修改。所有格式均支持自定义保存位置。",
                FontSize = 10,
                Foreground = new System.Windows.Media.SolidColorBrush(System.Windows.Media.Color.FromRgb(37, 99, 235)),
                TextWrapping = TextWrapping.Wrap
            };
            tipBorder.Child = tipText;
            mainStack.Children.Add(tipBorder);

            var buttonPanel = new StackPanel
            {
                Orientation = Orientation.Horizontal,
                HorizontalAlignment = System.Windows.HorizontalAlignment.Right
            };

            var nextButton = new Button
            {
                Content = "下一步 → 选择保存位置",
                Width = 180,
                Height = 36,
                Margin = new Thickness(5, 0, 0, 0),
                FontWeight = System.Windows.FontWeights.SemiBold
            };
            var cancelButton = new Button
            {
                Content = "取消",
                Width = 80,
                Height = 36,
                Margin = new Thickness(5, 0, 0, 0)
            };

            buttonPanel.Children.Add(cancelButton);
            buttonPanel.Children.Add(nextButton);
            mainStack.Children.Add(buttonPanel);

            formatDialog.Content = mainStack;

            ReportFormat selectedFormat = ReportFormat.Word;
            bool? dialogResult = false;

            nextButton.Click += (s, args) =>
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
            return (selectedFormat, dialogResult);
        }

        private string ShowSaveFileDialog(ReportFormat selectedFormat, string targetIp)
        {
            var safeTargetIp = targetIp.Replace(".", "_").Replace(",", "_").Replace(" ", "").Trim();
            if (safeTargetIp.Length > 30) safeTargetIp = safeTargetIp.Substring(0, 30);

            var timestamp = DateTime.Now.ToString("yyyyMMdd_HHmmss");
            var defaultFileName = $"SecurityReport_{safeTargetIp}_{timestamp}";

            string filter;
            string defaultExt;
            switch (selectedFormat)
            {
                case ReportFormat.Word:
                    filter = "Word文件 (*.docx)|*.docx";
                    defaultExt = "docx";
                    break;
                case ReportFormat.Html:
                    filter = "HTML文件 (*.html)|*.html";
                    defaultExt = "html";
                    break;
                case ReportFormat.Csv:
                    filter = "CSV文件 (*.csv)|*.csv";
                    defaultExt = "csv";
                    break;
                default:
                    filter = "文本文件 (*.txt)|*.txt";
                    defaultExt = "txt";
                    break;
            }

            var formatName = selectedFormat switch
            {
                ReportFormat.Word => "Word格式",
                ReportFormat.Html => "HTML格式",
                ReportFormat.Csv => "CSV格式",
                _ => "文本格式"
            };

            var saveDialog = new Microsoft.Win32.SaveFileDialog
            {
                Title = $"保存安全评估报告 — {formatName}",
                Filter = filter,
                DefaultExt = defaultExt,
                FileName = $"{defaultFileName}.{defaultExt}"
            };

            var desktopPath = Environment.GetFolderPath(Environment.SpecialFolder.Desktop);
            if (Directory.Exists(desktopPath))
                saveDialog.InitialDirectory = desktopPath;

            if (saveDialog.ShowDialog() == true)
                return saveDialog.FileName;

            return null;
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

        private void LicenseManager_Click(object sender, RoutedEventArgs e)
        {
            var dialog = new LicenseDialog { Owner = this };
            dialog.ShowDialog();
            UpdateLicenseStatusBar();
        }

        private void UpdateLicenseStatusBar()
        {
            var licenseService = new LicenseService();
            var status = licenseService.GetLicenseStatus();

            if (status.IsLicensed && status.LicenseInfo != null)
            {
                LicenseStatusBarText.Text = $"授权状态：{status.LicenseInfo.DisplayName}";
                LicenseStatusBarText.Foreground = new System.Windows.Media.SolidColorBrush(
                    System.Windows.Media.Color.FromRgb(0x27, 0xAE, 0x60));
            }
            else
            {
                LicenseStatusBarText.Text = "授权状态：未授权";
                LicenseStatusBarText.Foreground = new System.Windows.Media.SolidColorBrush(
                    System.Windows.Media.Color.FromRgb(0x95, 0xA5, 0xA6));
            }
        }

        private void LicenseTimer_Tick(object? sender, EventArgs e)
        {
            var licenseService = new NetSecurityScanner.Services.LicenseService();
            if (!licenseService.IsLicensed())
            {
                var dialog = new NetSecurityScanner.Views.LicenseDialog { Owner = this };
                var result = dialog.ShowDialog();
                if (result != true)
                {
                    Application.Current.Shutdown();
                }
                else
                {
                    UpdateLicenseStatusBar();
                }
            }
            else
            {
                UpdateLicenseStatusBar();
            }
        }

        private void About_Click(object sender, RoutedEventArgs e)
        {
            var version = GetAppVersion();
            MessageBox.Show($"网络安全扫描工具 v{version}\n\n功能：\n- 端口扫描\n- 漏洞检测\n- 风险评估\n- 端口管理\n- 批量扫描\n- APP 安全扫描\n- 摄像头安全扫描\n- Agent 安全扫描\n- 扫描历史记录\n- 统计仪表盘\n- 可视化分析\n- 网络拓扑\n- 攻击路径分析\n- 攻击日志查询\n- 合规检查\n- 漏洞知识库\n- Web 路径追踪\n- 插件管理\n- 资产管理\n\n仅供学习和测试使用", "关于", MessageBoxButton.OK, MessageBoxImage.Information);
        }

        private async void CheckForUpdates_Click(object sender, RoutedEventArgs e)
        {
            await CheckForUpdatesAsync(forceCheck: true);
        }

        private async Task CheckForUpdatesAsync(bool forceCheck = false)
        {
            try
            {
                var settingsService = new SettingsService();
                var updateSettings = await settingsService.GetUpdateSettingsAsync();

                if (!forceCheck && updateSettings.LastCheckTime.HasValue)
                {
                    var hoursSinceLastCheck = (DateTime.Now - updateSettings.LastCheckTime.Value).TotalHours;
                    if (hoursSinceLastCheck < updateSettings.NotifyIntervalHours)
                    {
                        return;
                    }
                }

                var currentVersion = VersionHelper.GetVersion();

                using var updateChecker = new UpdateCheckService();
                var updateInfo = await updateChecker.CheckForUpdateAsync(currentVersion, updateSettings);

                updateSettings.LastCheckTime = DateTime.Now;
                await settingsService.SaveUpdateSettingsAsync(updateSettings);

                if (updateInfo == null)
                {
                    if (forceCheck)
                    {
                        MessageBox.Show("当前已是最新版本，无需更新。", "检查更新", MessageBoxButton.OK, MessageBoxImage.Information);
                    }
                    return;
                }

                if (updateInfo.Version == updateSettings.SkippedVersion)
                {
                    if (forceCheck)
                    {
                        var result = MessageBox.Show($"检测到新版本 {updateInfo.Version}（您之前已跳过），是否查看更新？", "检查更新", MessageBoxButton.YesNo, MessageBoxImage.Question);
                        if (result != MessageBoxResult.Yes)
                            return;
                    }
                    else
                    {
                        return;
                    }
                }

                var updateDialog = new Views.UpdateDialog(updateInfo, updateSettings) { Owner = this };
                updateDialog.ShowDialog();
            }
            catch (Exception ex)
            {
                if (forceCheck)
                {
                    MessageBox.Show($"检查更新失败：{ex.Message}", "错误", MessageBoxButton.OK, MessageBoxImage.Error);
                }
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
                var selectedItems = GetSelectedScanHistoryItems();
                if (!selectedItems.Any())
                {
                    MessageBox.Show("请先选择要生成报告的历史记录", "提示", MessageBoxButton.OK, MessageBoxImage.Information);
                    return;
                }

                List<CompleteScanResult> completeResults = new List<CompleteScanResult>();
                foreach (var item in selectedItems)
                {
                    var result = await _jsonDatabaseService.GetScanResultByIdAsync(item.ScanId);
                    if (result != null) completeResults.Add(result);
                }

                if (!completeResults.Any())
                {
                    MessageBox.Show("无法获取选中的扫描结果", "错误", MessageBoxButton.OK, MessageBoxImage.Error);
                    return;
                }

                ExportReportWithDialog(completeResults);
                return;
            }
            catch (Exception ex)
            {
                Log($"生成报告失败: {ex.Message}");
                MessageBox.Show($"生成报告失败: {ex.Message}", "错误", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        private async Task<string> GeneratePdfReport(List<CompleteScanResult> completeResults, string savePath)
        {
            return await Task.Run(() =>
            {
                try
                {
                    string pdfPath;
                    if (completeResults.Count == 1)
                    {
                        pdfPath = HistoryReportGenerator.GenerateFromHistoryRecordToPath(completeResults[0], savePath);
                    }
                    else
                    {
                        pdfPath = HistoryReportGenerator.GenerateFromMultipleRecordsToPath(completeResults, savePath);
                    }
                    return pdfPath;
                }
                catch (Exception ex)
                {
                    Debug.WriteLine($"[PDF导出] 失败: {ex.Message}");
                    this.Dispatcher.Invoke(() =>
                    {
                        MessageBox.Show($"生成PDF报告失败:\n{ex.Message}", "导出错误", MessageBoxButton.OK, MessageBoxImage.Error);
                    });
                    return string.Empty;
                }
            });
        }

        private async Task<string> GenerateWordReport(List<CompleteScanResult> completeResults, string savePath)
        {
            return await Task.Run(() =>
            {
                try
                {
                    string wordPath;
                    if (completeResults.Count == 1)
                    {
                        wordPath = HistoryWordReportGenerator.GenerateFromHistoryRecordToPath(completeResults[0], savePath);
                    }
                    else
                    {
                        wordPath = HistoryWordReportGenerator.GenerateFromMultipleRecordsToPath(completeResults, savePath);
                    }
                    return wordPath;
                }
                catch (Exception ex)
                {
                    Debug.WriteLine($"[Word导出] 失败: {ex.Message}");
                    this.Dispatcher.Invoke(() =>
                    {
                        MessageBox.Show($"生成Word报告失败:\n{ex.Message}", "导出错误", MessageBoxButton.OK, MessageBoxImage.Error);
                    });
                    return string.Empty;
                }
            });
        }

        private async Task<string> GenerateHtmlReport(List<CompleteScanResult> completeResults, string savePath)
        {
            return await Task.Run(() =>
            {
                try
                {
                    var allPorts = completeResults.SelectMany(r => r.PortScanResults ?? new List<PortScanResult>()).ToList();
                    var allVulns = completeResults.SelectMany(r => r.VulnerabilityResults ?? new List<VulnerabilityResult>()).ToList();
                    var targetIp = string.Join(", ", completeResults.Select(r => r.TargetIp).Distinct());
                    var openPorts = allPorts.Where(p => p?.Status == "开放" || p?.Status?.ToLower() == "open").ToList();
                    var highRiskCount = allVulns.Count(v => IsCriticalLevel(v?.RiskLevel) || IsHighLevel(v?.RiskLevel));
                    var overallRisk = CalculateOverallRiskFromVulns(allVulns);
                    var medRiskCount = allVulns.Count(v => IsMediumLevel(v?.RiskLevel));
                    var lowRiskCount = allVulns.Count(v => IsLowLevel(v?.RiskLevel));
                    var highPct = allVulns.Any() ? (int)((double)highRiskCount / allVulns.Count * 100) : 0;

                    var riskColor = overallRisk == "严重" ? "#991b1b" : overallRisk == "高" ? "#c2410c" : overallRisk == "中" ? "#d97706" : "#059669";

                    var sb = new System.Text.StringBuilder();
                    sb.AppendLine("<!DOCTYPE html>");
                    sb.AppendLine("<html lang='zh-CN'><head><meta charset='UTF-8'>");
                    sb.AppendLine("<meta name='viewport' content='width=device-width, initial-scale=1.0'>");
                    sb.AppendLine("<title>网络安全漏洞扫描评估报告</title>");
                    sb.AppendLine("<style>");
                    sb.AppendLine("* { box-sizing: border-box; margin: 0; padding: 0; }");
                    sb.AppendLine("body { font-family: 'Microsoft YaHei', 'Segoe UI', sans-serif; background: #f1f5f9; color: #334155; line-height: 1.6; }");
                    sb.AppendLine(".container { max-width: 1100px; margin: 0 auto; background: white; box-shadow: 0 1px 3px rgba(0,0,0,0.1); }");
                    sb.AppendLine(".cover { background: linear-gradient(135deg, #1a365d 0%, #2563eb 100%); color: white; padding: 60px 50px; text-align: center; }");
                    sb.AppendLine(".cover h1 { font-size: 28px; margin-bottom: 8px; letter-spacing: 2px; }");
                    sb.AppendLine(".cover h2 { font-size: 14px; font-weight: normal; opacity: 0.8; margin-bottom: 30px; }");
                    sb.AppendLine(".cover-info { display: inline-block; text-align: left; background: rgba(255,255,255,0.1); border-radius: 8px; padding: 20px 30px; margin-top: 20px; }");
                    sb.AppendLine(".cover-info p { margin: 4px 0; font-size: 13px; }");
                    sb.AppendLine(".cover-info strong { display: inline-block; width: 90px; }");
                    sb.AppendLine(".stats-row { display: flex; justify-content: center; gap: 20px; padding: 30px 50px; background: #f8fafc; border-bottom: 1px solid #e2e8f0; }");
                    sb.AppendLine(".stat-card { background: white; border: 1px solid #e2e8f0; border-radius: 8px; padding: 20px 30px; text-align: center; min-width: 160px; }");
                    sb.AppendLine(".stat-card .value { font-size: 28px; font-weight: bold; }");
                    sb.AppendLine(".stat-card .label { font-size: 12px; color: #94a3b8; margin-top: 4px; }");
                    sb.AppendLine(".content { padding: 40px 50px; }");
                    sb.AppendLine("h2 { color: #1a365d; font-size: 20px; margin: 35px 0 15px; padding-bottom: 8px; border-bottom: 2px solid #1a365d; }");
                    sb.AppendLine("h3 { color: #2563eb; font-size: 15px; margin: 25px 0 10px; padding-left: 12px; border-left: 4px solid #2563eb; }");
                    sb.AppendLine("p { margin: 8px 0; }");
                    sb.AppendLine("table { border-collapse: collapse; width: 100%; margin: 15px 0; font-size: 13px; }");
                    sb.AppendLine("th { background: #1e293b; color: white; padding: 10px 14px; text-align: left; font-weight: 600; }");
                    sb.AppendLine("td { border: 1px solid #e2e8f0; padding: 8px 14px; }");
                    sb.AppendLine("tr:nth-child(even) { background: #f8fafc; }");
                    sb.AppendLine("tr:hover { background: #f1f5f9; }");
                    sb.AppendLine(".risk-critical { color: #991b1b; font-weight: bold; background: #fef2f2; padding: 2px 8px; border-radius: 3px; }");
                    sb.AppendLine(".risk-high { color: #c2410c; font-weight: bold; background: #fff7ed; padding: 2px 8px; border-radius: 3px; }");
                    sb.AppendLine(".risk-medium { color: #d97706; font-weight: bold; background: #fefce8; padding: 2px 8px; border-radius: 3px; }");
                    sb.AppendLine(".risk-low { color: #059669; font-weight: bold; background: #ecfdf5; padding: 2px 8px; border-radius: 3px; }");
                    sb.AppendLine(".vuln-card { border: 1px solid #e2e8f0; border-radius: 8px; margin: 12px 0; overflow: hidden; }");
                    sb.AppendLine(".vuln-card .card-header { padding: 12px 18px; color: white; font-weight: bold; font-size: 14px; }");
                    sb.AppendLine(".vuln-card .card-body { padding: 15px 18px; }");
                    sb.AppendLine(".vuln-card .card-body p { margin: 6px 0; font-size: 13px; }");
                    sb.AppendLine(".vuln-card .card-body .section-title { font-weight: bold; color: #1e293b; margin-top: 10px; }");
                    sb.AppendLine(".priority-table td:first-child { font-weight: bold; }");
                    sb.AppendLine(".hardening-item { background: #f8fafc; border-left: 3px solid #2563eb; padding: 12px 18px; margin: 8px 0; border-radius: 0 6px 6px 0; }");
                    sb.AppendLine(".hardening-item strong { color: #1a365d; }");
                    sb.AppendLine(".threat-item { background: #fef2f2; border-left: 3px solid #dc2626; padding: 12px 18px; margin: 8px 0; border-radius: 0 6px 6px 0; }");
                    sb.AppendLine(".threat-item strong { color: #991b1b; }");
                    sb.AppendLine(".gap-item { background: #fefce8; border-left: 3px solid #d97706; padding: 12px 18px; margin: 8px 0; border-radius: 0 6px 6px 0; }");
                    sb.AppendLine(".gap-item strong { color: #92400e; }");
                    sb.AppendLine(".footer { background: #1e293b; color: #94a3b8; padding: 20px 50px; font-size: 11px; text-align: center; }");
                    sb.AppendLine(".bar-container { background: #e2e8f0; border-radius: 4px; height: 20px; margin: 4px 0; overflow: hidden; }");
                    sb.AppendLine(".bar-fill { height: 100%; border-radius: 4px; display: flex; align-items: center; padding-left: 8px; color: white; font-size: 11px; font-weight: bold; }");
                    sb.AppendLine(".cvss-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 4px 20px; margin: 8px 0; padding: 12px; background: #f8fafc; border-radius: 6px; border: 1px solid #e2e8f0; }");
                    sb.AppendLine(".cvss-grid .cvss-item { font-size: 13px; padding: 3px 0; display: flex; justify-content: space-between; }");
                    sb.AppendLine(".cvss-grid .cvss-label { color: #64748b; }");
                    sb.AppendLine(".cvss-grid .cvss-value { font-weight: 600; color: #1e293b; }");
                    sb.AppendLine(".cvss-total { font-size: 15px; font-weight: bold; text-align: center; padding: 8px; margin-top: 6px; border-radius: 0 0 6px 6px; }");
                    sb.AppendLine(".impact-analyze { background: #fefce8; border-left: 3px solid #eab308; padding: 10px 14px; margin: 8px 0; border-radius: 0 6px 6px 0; font-size: 13px; }");
                    sb.AppendLine(".impact-critical { background: #fef2f2; border-left-color: #dc2626; }");
                    sb.AppendLine(".section-info { font-size: 12px; color: #64748b; margin-bottom: 5px; }");
                    sb.AppendLine(".chart-container { background: #f8fafc; border: 1px solid #e2e8f0; border-radius: 8px; padding: 20px; margin: 20px 0; }");
                    sb.AppendLine(".chart-container h4 { color: #1a365d; margin: 0 0 12px 0; font-size: 14px; }");
                    sb.AppendLine(".ref-link { color: #2563eb; word-break: break-all; font-size: 12px; }");
                    sb.AppendLine("</style></head><body>");
                    sb.AppendLine("<div class='container'>");

                    sb.AppendLine("<div class='cover'>");
                    sb.AppendLine("<h1>网络安全漏洞扫描评估报告</h1>");
                    sb.AppendLine("<h2>Network Security Vulnerability Assessment Report</h2>");
                    var scanTypeDesc = BuildScanTypeDescription(completeResults);
                    var activeFeatures = GetActiveScanFeatures(completeResults);
                    var hasPortScanFeature = activeFeatures.Contains("TCP端口扫描");
                    var hasVulnScanFeature = activeFeatures.Contains("漏洞扫描");
                    var hasExpertMode = activeFeatures.Contains("专家模式");

                    sb.AppendLine("<div class='cover-info'>");
                    sb.AppendLine($"<p><strong>报告编号：</strong>RPT-{DateTime.Now:yyyyMMdd}-{Guid.NewGuid():N}".Substring(0, 40) + "</p>");
                    sb.AppendLine($"<p><strong>目标系统：</strong>{targetIp}</p>");
                    sb.AppendLine($"<p><strong>扫描时间：</strong>{DateTime.Now:yyyy-MM-dd HH:mm:ss}</p>");
                    sb.AppendLine($"<p><strong>扫描类型：</strong>{scanTypeDesc}</p>");
                    if (hasExpertMode)
                        sb.AppendLine($"<p><strong>扫描模式：</strong>专家深度扫描（Expert Mode）</p>");
                    sb.AppendLine($"<p><strong>生成时间：</strong>{DateTime.Now:yyyy-MM-dd HH:mm:ss}</p>");
                    sb.AppendLine("</div></div>");

                    sb.AppendLine("<div class='stats-row'>");
                    sb.AppendLine($"<div class='stat-card'><div class='value' style='color:{riskColor}'>{overallRisk}</div><div class='label'>风险等级</div></div>");
                    sb.AppendLine($"<div class='stat-card'><div class='value' style='color:#2563eb'>{openPorts.Count}</div><div class='label'>开放端口</div></div>");
                    sb.AppendLine($"<div class='stat-card'><div class='value' style='color:#dc2626'>{allVulns.Count}</div><div class='label'>漏洞总数</div></div>");
                    sb.AppendLine($"<div class='stat-card'><div class='value' style='color:#f59e0b'>{highPct}%</div><div class='label'>高危占比</div></div>");
                    sb.AppendLine("</div>");

                    sb.AppendLine("<div class='content'>");

                    sb.AppendLine("<h2 style='color:#1a365d;border-bottom:2px solid #3b82f6;padding-bottom:6px;'>扫描配置信息</h2>");
                    sb.AppendLine("<table><tr><th>扫描项目</th><th>状态</th><th>数据来源</th></tr>");
                    sb.AppendLine($"<tr><td><strong>TCP端口扫描</strong></td><td style='color:{(hasPortScanFeature ? "#059669" : "#94a3b8")};font-weight:bold'>{(hasPortScanFeature ? "✓ 已执行" : "✗ 未执行")}</td><td>{(hasPortScanFeature ? $"{openPorts.Count}个开放端口" : "-")}</td></tr>");
                    sb.AppendLine($"<tr><td><strong>漏洞扫描</strong></td><td style='color:{(hasVulnScanFeature ? "#059669" : "#94a3b8")};font-weight:bold'>{(hasVulnScanFeature ? "✓ 已执行" : "✗ 未执行")}</td><td>{(hasVulnScanFeature ? $"{allVulns.Count}个漏洞" : "-")}</td></tr>");
                    sb.AppendLine($"<tr><td><strong>专家模式</strong></td><td style='color:{(hasExpertMode ? "#059669" : "#94a3b8")};font-weight:bold'>{(hasExpertMode ? "✓ 已启用" : "✗ 未启用")}</td><td>{(hasExpertMode ? "深度检测+合规评估" : "-")}</td></tr>");
                    sb.AppendLine("</table>");
                    sb.AppendLine("<p style='font-size:12px;color:#64748b;margin-top:6px;'>以上扫描项目根据选择的扫描历史记录自动合并填充至报告中。</p>");

                    sb.AppendLine("<h2>一、执行摘要</h2>");
                    sb.AppendLine("<p>本节提供本次安全扫描的核心发现和统计概览，帮助快速了解目标系统的整体安全态势。</p>");

                    sb.AppendLine("<h3>1.1 核心统计数据</h3>");
                    sb.AppendLine("<table><tr><th>统计项</th><th>数值</th></tr>");
                    sb.AppendLine($"<tr><td>总体风险等级</td><td><span style='color:{riskColor};font-weight:bold'>{overallRisk}</span></td></tr>");
                    sb.AppendLine($"<tr><td>开放端口数</td><td>{openPorts.Count}/{allPorts.Count}</td></tr>");
                    sb.AppendLine($"<tr><td>漏洞总数</td><td>{allVulns.Count}</td></tr>");
                    sb.AppendLine($"<tr><td>严重/高危漏洞</td><td>{highRiskCount}</td></tr>");
                    sb.AppendLine($"<tr><td>中危漏洞</td><td>{medRiskCount}</td></tr>");
                    sb.AppendLine($"<tr><td>低危漏洞</td><td>{lowRiskCount}</td></tr>");
                    sb.AppendLine("</table>");

                    var securityScore = CalculateSecurityScoreFromVulns(allVulns, openPorts);
                    sb.AppendLine("<h3>1.2 安全评分仪表盘</h3>");
                    sb.AppendLine("<div class='chart-container'>");
                    sb.AppendLine("<div style='display:flex;align-items:center;justify-content:center;gap:30px;flex-wrap:wrap;'>");
                    sb.AppendLine("<div style='text-align:center;'>");
                    sb.AppendLine("<svg width='220' height='160' viewBox='0 0 220 160'>");
                    sb.AppendLine("<path d='M40,130 A90,90 0 0,1 180,130' fill='none' stroke='#e2e8f0' stroke-width='18' stroke-linecap='round'/>");
                    var gaugeSweep = Math.Min(180, (double)securityScore / 100 * 180);
                    var gaugeColor = overallRisk == "严重" ? "#991b1b" : overallRisk == "高" ? "#c2410c" : overallRisk == "中" ? "#d97706" : "#059669";
                    var radSweep = gaugeSweep * Math.PI / 180;
                    var endX = 110 + 90 * Math.Cos(radSweep);
                    var endY = 130 - 90 * Math.Sin(radSweep);
                    var largeArcFlag = gaugeSweep > 90 ? 1 : 0;
                    sb.AppendLine($"<path d='M40,130 A90,90 0 {largeArcFlag},1 {endX:F1},{endY:F1}' fill='none' stroke='{gaugeColor}' stroke-width='18' stroke-linecap='round'/>");
                    sb.AppendLine($"<text x='110' y='115' text-anchor='middle' font-size='28' font-weight='bold' fill='{gaugeColor}'>{securityScore}</text>");
                    sb.AppendLine("<text x='110' y='140' text-anchor='middle' font-size='11' fill='#64748b'>安全评分 / 100</text>");
                    sb.AppendLine("</svg>");
                    sb.AppendLine("</div>");
                    sb.AppendLine("<div style='text-align:center;'>");
                    sb.AppendLine($"<div style='font-size:32px;font-weight:bold;color:{gaugeColor}'>{overallRisk}</div>");
                    sb.AppendLine("<div style='font-size:12px;color:#64748b;margin-top:4px'>总体风险等级</div>");
                    sb.AppendLine($"<div style='margin-top:8px;font-size:13px;color:#334155'>{GetSecurityRatingDescriptionForScore(securityScore)}</div>");
                    sb.AppendLine("</div>");
                    sb.AppendLine("</div>");
                    sb.AppendLine("</div>");

                    var svcGroups = openPorts.Where(p => !string.IsNullOrEmpty(p?.Service))
                        .GroupBy(p => p.Service).OrderByDescending(g => g.Count()).Take(6).ToList();
                    if (svcGroups.Any())
                    {
                        sb.AppendLine("<h3>1.3 服务分布图表</h3>");
                        sb.AppendLine("<div class='chart-container'>");
                        sb.AppendLine("<h4>开放端口服务分布</h4>");
                        var svcMaxVal = svcGroups.Max(g => g.Count());
                        sb.AppendLine("<div style='display:flex;align-items:flex-end;gap:16px;height:160px;padding:0 10px;'>");
                        var svcColors = new[] { "#3b82f6", "#10b981", "#f59e0b", "#ef4444", "#8b5cf6", "#06b6d4" };
                        int si = 0;
                        foreach (var g in svcGroups)
                        {
                            var barH = (int)((double)g.Count() / svcMaxVal * 130);
                            var color = svcColors[si % svcColors.Length];
                            sb.AppendLine($"<div style='flex:1;display:flex;flex-direction:column;align-items:center;justify-content:flex-end;'>");
                            sb.AppendLine($"<div style='font-size:11px;font-weight:bold;color:{color};margin-bottom:4px;'>{g.Count()}</div>");
                            sb.AppendLine($"<div style='width:100%;max-width:50px;height:{barH}px;background:{color};border-radius:4px 4px 0 0;'></div>");
                            var svcLabel = g.Key.Length > 8 ? g.Key.Substring(0, 7) + ".." : g.Key;
                            sb.AppendLine($"<div style='font-size:10px;color:#64748b;margin-top:4px;white-space:nowrap;'>{svcLabel}</div>");
                            sb.AppendLine("</div>");
                            si++;
                        }
                        sb.AppendLine("</div></div>");
                    }

                    if (allVulns.Any())
                    {
                        sb.AppendLine("<h3>1.4 Top 5 高危漏洞</h3>");
                        sb.AppendLine("<table><tr><th>#</th><th>漏洞名称</th><th>风险等级</th><th>CVE编号</th></tr>");
                        int idx = 1;
                        foreach (var v in allVulns.OrderByDescending(v => GetRiskPriorityFromLevel(v?.RiskLevel)).Take(5))
                        {
                            var riskClass = IsCriticalLevel(v?.RiskLevel) ? "risk-critical" : IsHighLevel(v?.RiskLevel) ? "risk-high" : IsMediumLevel(v?.RiskLevel) ? "risk-medium" : "risk-low";
                            sb.AppendLine($"<tr><td>{idx}</td><td>{v.Name ?? "未知"}</td><td class='{riskClass}'>{v.RiskLevel ?? "未分类"}</td><td>{v.CveId ?? "-"}</td></tr>");
                            idx++;
                        }
                        sb.AppendLine("</table>");
                    }

                    if (allPorts.Any())
                    {
                        sb.AppendLine("<h2>二、端口扫描结果</h2>");
                        sb.AppendLine("<p>本节列出所有检测到的开放端口及其对应的服务信息。</p>");
                        sb.AppendLine("<table><tr><th>端口号</th><th>协议</th><th>服务名称</th><th>版本</th><th>状态</th></tr>");
                        foreach (var p in openPorts.OrderBy(p => p.PortNumber))
                        {
                            sb.AppendLine($"<tr><td>{p.PortNumber}</td><td>TCP</td><td>{p.Service ?? "-"}</td><td>{p.ServiceVersion ?? "-"}</td><td>{p.Status}</td></tr>");
                        }
                        sb.AppendLine("</table>");
                    }

                    if (allVulns.Any())
                    {
                        sb.AppendLine("<h2>三、漏洞详情分析</h2>");
                        sb.AppendLine("<p>本节详细列出所有检测到的安全漏洞，按风险等级从高到低排列。</p>");

                        sb.AppendLine("<h3>3.1 漏洞概览表</h3>");
                        sb.AppendLine("<table><tr><th>序号</th><th>CVE编号</th><th>漏洞名称</th><th>风险等级</th><th>端口</th><th>服务</th><th>CVSS评分</th></tr>");
                        int idx = 1;
                        foreach (var v in allVulns.OrderByDescending(v => GetRiskPriorityFromLevel(v?.RiskLevel)))
                        {
                            var riskClass = IsCriticalLevel(v?.RiskLevel) ? "risk-critical" : IsHighLevel(v?.RiskLevel) ? "risk-high" : IsMediumLevel(v?.RiskLevel) ? "risk-medium" : "risk-low";
                            var cvss = EstimateCvssScoreForLevel(v?.RiskLevel);
                            sb.AppendLine($"<tr><td>{idx}</td><td>{v.CveId ?? "-"}</td><td>{v.Name ?? "未知"}</td><td class='{riskClass}'>{v.RiskLevel ?? "未分类"}</td><td>{(v.Port.HasValue ? v.Port.Value.ToString() : "-")}</td><td>{v.Service ?? "-"}</td><td>{cvss:F1}</td></tr>");
                            idx++;
                        }
                        sb.AppendLine("</table>");

                        sb.AppendLine("<h3>3.2 漏洞详细信息（前10个）</h3>");
                        int dIdx = 1;
                        foreach (var v in allVulns.OrderByDescending(v => GetRiskPriorityFromLevel(v?.RiskLevel)).Take(10))
                        {
                            var riskLevel = string.IsNullOrWhiteSpace(v?.RiskLevel) ? "未分类" : v.RiskLevel;
                            var headerBg = IsCriticalLevel(riskLevel) ? "#991b1b" : IsHighLevel(riskLevel) ? "#c2410c" : IsMediumLevel(riskLevel) ? "#d97706" : "#059669";
                            var cvss = EstimateCvssScoreForLevel(riskLevel);
                            var isCritical = IsCriticalLevel(riskLevel);
                            var isHigh = IsHighLevel(riskLevel);
                            var attackVector = v.Port.HasValue ? "网络(N)" : "本地(L)";
                            var complexity = isCritical || isHigh ? "低" : "中";
                            var privileges = isCritical || isHigh ? "无(N)" : "低(L)";
                            var userInteraction = "无(N)";
                            var scope = isCritical ? "改变(C)" : "未改变(U)";
                            var confidentiality = isCritical || isHigh ? "高(H)" : "低(L)";
                            var integrity = isCritical || isHigh ? "高(H)" : "低(L)";
                            var availability = isCritical ? "高(H)" : isHigh ? "高(H)" : "低(L)";

                            sb.AppendLine("<div class='vuln-card'>");
                            var cvePart = string.IsNullOrWhiteSpace(v.CveId) ? "" : $"({v.CveId})";
                            sb.AppendLine($"<div class='card-header' style='background:{headerBg}'>[{dIdx}] {v.Name ?? "未知漏洞"} {cvePart} [{riskLevel}]</div>");
                            sb.AppendLine("<div class='card-body'>");
                            sb.AppendLine($"<p class='section-title'>【漏洞概述】</p>");
                            var desc = v.Description;
                            if (string.IsNullOrWhiteSpace(desc) || desc == "-")
                                desc = $"该漏洞影响 {(string.IsNullOrWhiteSpace(v.Service) ? "系统" : v.Service)}服务" + (v.Port.HasValue ? $"（端口 {v.Port.Value}）" : "");
                            sb.AppendLine($"<p>{desc}</p>");

                            sb.AppendLine($"<p class='section-title'>【CVSS评分详情】</p>");
                            sb.AppendLine("<div class='cvss-grid'>");
                            sb.AppendLine($"<div class='cvss-item'><span class='cvss-label'>攻击向量(AV)</span><span class='cvss-value'>{attackVector}</span></div>");
                            sb.AppendLine($"<div class='cvss-item'><span class='cvss-label'>攻击复杂度(AC)</span><span class='cvss-value'>{complexity}</span></div>");
                            sb.AppendLine($"<div class='cvss-item'><span class='cvss-label'>权限要求(PR)</span><span class='cvss-value'>{privileges}</span></div>");
                            sb.AppendLine($"<div class='cvss-item'><span class='cvss-label'>用户交互(UI)</span><span class='cvss-value'>{userInteraction}</span></div>");
                            sb.AppendLine($"<div class='cvss-item'><span class='cvss-label'>影响范围(S)</span><span class='cvss-value'>{scope}</span></div>");
                            sb.AppendLine($"<div class='cvss-item'><span class='cvss-label'>机密性(C)</span><span class='cvss-value'>{confidentiality}</span></div>");
                            sb.AppendLine($"<div class='cvss-item'><span class='cvss-label'>完整性(I)</span><span class='cvss-value'>{integrity}</span></div>");
                            sb.AppendLine($"<div class='cvss-item'><span class='cvss-label'>可用性(A)</span><span class='cvss-value'>{availability}</span></div>");
                            sb.AppendLine("</div>");
                            sb.AppendLine($"<div class='cvss-total' style='background:{headerBg};color:white'>综合评分：{cvss:F1}/10.0 ({riskLevel})</div>");

                            sb.AppendLine($"<p class='section-title'>【基本信息】</p>");
                            sb.AppendLine($"<p>CVSS评分：{cvss:F1} ({riskLevel}) | 影响端口：{(v.Port.HasValue ? $"TCP/{v.Port.Value}" : "N/A")} | 服务：{v.Service ?? "-"}</p>");

                            if (!string.IsNullOrWhiteSpace(v.DetectionMethod) && v.DetectionMethod != "-")
                            {
                                sb.AppendLine($"<p class='section-title'>【检测方法】</p>");
                                sb.AppendLine($"<p>{v.DetectionMethod}</p>");
                            }

                            sb.AppendLine($"<p class='section-title'>【影响范围分析】</p>");
                            var impactClass = isCritical || isHigh ? "impact-analyze impact-critical" : "impact-analyze";
                            if (isCritical || isHigh)
                                sb.AppendLine($"<div class='{impactClass}'>该漏洞可导致远程代码执行或权限提升，攻击者可能完全控制受影响的系统。影响范围包括：系统完整性破坏、敏感数据泄露、服务中断等严重后果。</div>");
                            else if (IsMediumLevel(riskLevel))
                                sb.AppendLine($"<div class='{impactClass}'>该漏洞可导致信息泄露或服务降级，攻击者可能获取部分系统信息或造成服务影响。建议尽快修复。</div>");
                            else
                                sb.AppendLine($"<div class='{impactClass}'>该漏洞风险较低，主要影响信息收集或带来有限的安全隐患。建议纳入常规修复计划。</div>");

                            sb.AppendLine($"<p class='section-title'>【修复方案】</p>");
                            var solution = v.Solution ?? "请参考官方安全公告获取补丁信息";
                            foreach (var line in solution.Split('\n').Where(l => !string.IsNullOrWhiteSpace(l)).Take(5))
                                sb.AppendLine($"<p>  • {line.Trim()}</p>");

                            if (!string.IsNullOrWhiteSpace(v.References))
                            {
                                sb.AppendLine($"<p class='section-title'>【参考链接】</p>");
                                sb.AppendLine($"<p class='ref-link'><a href='{v.References}' target='_blank'>{v.References}</a></p>");
                            }

                            sb.AppendLine("</div></div>");
                            dIdx++;
                        }
                    }

                    sb.AppendLine("<h2>四、风险评估汇总</h2>");
                    sb.AppendLine("<p>本节对本次扫描发现的各类风险进行综合评估和分析。</p>");

                    sb.AppendLine("<h3>4.1 风险分布</h3>");
                    if (allVulns.Any())
                    {
                        var total = allVulns.Count;
                        var categories = new[]
                        {
                            new { Label = "严重", Count = allVulns.Count(v => IsCriticalLevel(v.RiskLevel)), Color = "#991b1b" },
                            new { Label = "高危", Count = allVulns.Count(v => IsHighLevel(v.RiskLevel)), Color = "#c2410c" },
                            new { Label = "中危", Count = allVulns.Count(v => IsMediumLevel(v.RiskLevel)), Color = "#d97706" },
                            new { Label = "低危", Count = allVulns.Count(v => IsLowLevel(v.RiskLevel)), Color = "#059669" }
                        };
                        var validCats = categories.Where(c => c.Count > 0).ToList();
                        if (validCats.Any())
                        {
                            sb.AppendLine("<div style='display:flex;gap:30px;align-items:center;margin:20px 0;padding:20px;background:#f8fafc;border-radius:8px;border:1px solid #e2e8f0;'>");
                            sb.AppendLine("<div style='flex:0 0 200px;text-align:center;'>");
                            sb.AppendLine("<svg width='200' height='200' viewBox='0 0 200 200'>");
                            float startAngle = -90;
                            foreach (var cat in validCats)
                            {
                                var sweepAngle = (float)cat.Count / total * 360;
                                var startRad = startAngle * (float)Math.PI / 180;
                                var endRad = (startAngle + sweepAngle) * (float)Math.PI / 180;
                                var largeArc = sweepAngle > 180 ? 1 : 0;
                                var r = 80f;
                                var cx = 100f; var cy = 100f;
                                var x1 = cx + r * (float)Math.Cos(startRad);
                                var y1 = cy + r * (float)Math.Sin(startRad);
                                var x2 = cx + r * (float)Math.Cos(endRad);
                                var y2 = cy + r * (float)Math.Sin(endRad);
                                sb.AppendLine($"<path d='M{cx},{cy} L{x1:F1},{y1:F1} A{r},{r} 0 {largeArc},1 {x2:F1},{y2:F1} Z' fill='{cat.Color}' stroke='white' stroke-width='2'/>");
                                if (sweepAngle > 20)
                                {
                                    var midRad = (startAngle + sweepAngle / 2) * (float)Math.PI / 180;
                                    var lx = cx + (r * 0.55f) * (float)Math.Cos(midRad);
                                    var ly = cy + (r * 0.55f) * (float)Math.Sin(midRad);
                                    var pct = (double)cat.Count / total * 100;
                                    sb.AppendLine($"<text x='{lx:F1}' y='{ly:F1}' text-anchor='middle' dominant-baseline='central' fill='white' font-size='11' font-weight='bold'>{pct:F0}%</text>");
                                }
                                startAngle += sweepAngle;
                            }
                            sb.AppendLine("<circle cx='100' cy='100' r='30' fill='white'/>");
                            sb.AppendLine($"<text x='100' y='100' text-anchor='middle' dominant-baseline='central' fill='#1e293b' font-size='14' font-weight='bold'>{total}</text>");
                            sb.AppendLine("</svg>");
                            sb.AppendLine("</div>");
                            sb.AppendLine("<div style='flex:1;'>");
                            sb.AppendLine("<h4 style='margin:0 0 12px;color:#1a365d;'>漏洞风险分布</h4>");
                            foreach (var cat in validCats)
                            {
                                var pct = (double)cat.Count / total * 100;
                                sb.AppendLine($"<div style='margin:6px 0;display:flex;align-items:center;gap:8px;'><span style='display:inline-block;width:14px;height:14px;border-radius:3px;background:{cat.Color};'></span><strong>{cat.Label}：</strong>{cat.Count}个 ({pct:F1}%)</div>");
                            }
                            sb.AppendLine($"<div style='margin-top:12px;padding-top:8px;border-top:1px solid #e2e8f0;color:#1a365d;font-weight:bold;'>总计：{total}个漏洞</div>");
                            sb.AppendLine("</div></div>");
                        }
                        sb.AppendLine("<h4 style='margin:15px 0 8px;color:#1a365d;'>风险等级进度条</h4>");
                        foreach (var cat in categories)
                        {
                            if (cat.Count <= 0) continue;
                            var pct = (double)cat.Count / total * 100;
                            sb.AppendLine($"<p>{cat.Label}: {cat.Count}个 ({pct:F1}%)</p>");
                            sb.AppendLine($"<div class='bar-container'><div class='bar-fill' style='width:{pct}%;background:{cat.Color}'>{pct:F1}%</div></div>");
                        }
                    }

                    sb.AppendLine("<h3>4.2 安全建议概述</h3>");
                    var suggestions = new[]
                    {
                        "立即修复所有严重和高危级别的漏洞，尤其是远程代码执行类漏洞",
                        "关闭不必要的服务和端口，减少攻击面",
                        "及时更新系统和应用软件至最新版本",
                        "实施强密码策略和多因素认证(MFA)",
                        "配置防火墙规则限制网络访问",
                        "定期进行安全扫描和渗透测试",
                        "建立安全事件应急响应流程"
                    };
                    foreach (var s in suggestions)
                        sb.AppendLine($"<p>• {s}</p>");

                    sb.AppendLine("<h2>五、修复建议与安全加固</h2>");

                    sb.AppendLine("<h3>5.1 修复优先级矩阵</h3>");
                    sb.AppendLine("<table class='priority-table'><tr><th>优先级</th><th>处理时限</th><th>适用范围</th><th>建议措施</th></tr>");
                    sb.AppendLine("<tr><td style='color:#dc2626'>P1-紧急</td><td>24小时内</td><td>严重/远程执行类</td><td>立即隔离受影响系统</td></tr>");
                    sb.AppendLine("<tr><td style='color:#f59e0b'>P2-高</td><td>7天内</td><td>高危/权限提升类</td><td>尽快安排维护窗口</td></tr>");
                    sb.AppendLine("<tr><td style='color:#eab308'>P3-中</td><td>30天内</td><td>中危/信息泄露类</td><td>纳入常规更新计划</td></tr>");
                    sb.AppendLine("<tr><td style='color:#22c55e'>P4-低</td><td>下个周期</td><td>低危/信息类</td><td>持续监控</td></tr>");
                    sb.AppendLine("</table>");

                    sb.AppendLine("<h3>5.2 通用安全加固建议</h3>");
                    var hardeningCategories = new[]
                    {
                        ("网络层面", "配置防火墙规则，仅开放必要的业务端口；实施网络分段隔离；启用入侵检测/防御系统(IDS/IPS)；定期审计网络访问日志。"),
                        ("系统层面", "及时安装操作系统安全更新；禁用不必要的服务和账户；配置强密码策略（长度>=12位，含大小写字母、数字、特殊字符）；启用账户锁定策略防止暴力破解。"),
                        ("应用层面", "保持应用程序及依赖库为最新版本；实施安全的编码实践（输入验证、参数化查询）；定期进行代码安全审查和渗透测试；配置安全的HTTP头部（CSP、X-Frame-Options等）。"),
                        ("身份认证", "实施多因素认证(MFA)；采用基于角色的访问控制(RBAC)；定期清理过期账户和冗余权限；监控异常登录行为并及时告警。"),
                        ("数据保护", "加密敏感数据存储和传输（TLS 1.2+）；实施数据分类和分级保护策略；建立定期数据备份和灾难恢复机制；制定数据泄露应急响应预案。"),
                        ("监控审计", "部署集中化日志管理系统(SIEM)；设置安全事件实时告警阈值；定期进行安全基线检查和合规审计；保留审计日志至少180天以满足合规要求。")
                    };
                    int cIdx = 1;
                    foreach (var cat in hardeningCategories)
                    {
                        sb.AppendLine($"<div class='hardening-item'><strong>{cIdx}. {cat.Item1}：</strong>{cat.Item2}</div>");
                        cIdx++;
                    }

                    sb.AppendLine("</div>");

                    sb.AppendLine("<h2>六、威胁情报分析</h2>");
                    sb.AppendLine("<p>本节基于当前扫描结果和已知威胁情报数据，对目标系统面临的潜在威胁进行深度分析。</p>");

                    sb.AppendLine("<h3>6.1 活跃威胁向量</h3>");
                    if (openPorts.Any(p => p.PortNumber == 21 || p.PortNumber == 20))
                        sb.AppendLine("<div class='threat-item'><strong>⚠ FTP服务暴露</strong> — 攻击者可利用匿名登录或弱口令获取文件访问权限，可能导致敏感数据泄露</div>");
                    if (openPorts.Any(p => p.PortNumber == 22))
                        sb.AppendLine("<div class='threat-item'><strong>⚠ SSH服务暴露</strong> — 面临暴力破解和未授权访问风险，弱密码或默认密钥可被利用获取系统控制权</div>");
                    if (openPorts.Any(p => p.PortNumber == 23))
                        sb.AppendLine("<div class='threat-item'><strong>⚠ Telnet服务暴露</strong> — 明文传输协议，凭据和会话数据可被中间人攻击截获</div>");
                    if (openPorts.Any(p => p.PortNumber == 445 || p.PortNumber == 139))
                        sb.AppendLine("<div class='threat-item'><strong>⚠ SMB服务暴露</strong> — 勒索软件主要传播通道，存在远程代码执行风险(如EternalBlue)</div>");
                    if (openPorts.Any(p => p.PortNumber == 3389))
                        sb.AppendLine("<div class='threat-item'><strong>⚠ RDP远程桌面暴露</strong> — 暴力破解和蓝屏漏洞(BSOD)利用风险，是勒索软件常见入口</div>");
                    if (openPorts.Any(p => p.PortNumber == 80 || p.PortNumber == 443 || p.PortNumber == 8080))
                        sb.AppendLine("<div class='threat-item'><strong>⚠ Web服务暴露</strong> — 面临SQL注入、XSS、目录遍历等Web应用层攻击风险</div>");
                    if (openPorts.Any(p => p.PortNumber == 3306 || p.PortNumber == 1433 || p.PortNumber == 5432 || p.PortNumber == 27017))
                        sb.AppendLine("<div class='threat-item'><strong>⚠ 数据库端口暴露</strong> — 数据库服务直接暴露在网络上，面临数据泄露和未授权访问风险</div>");
                    if (highRiskCount > 0)
                        sb.AppendLine($"<div class='threat-item'><strong>⚠ 已知高危漏洞</strong> — 发现{highRiskCount}个高危漏洞，攻击者可利用自动化工具进行批量扫描和利用</div>");
                    sb.AppendLine("<div class='threat-item'><strong>⚠ 弱密码和默认凭据攻击</strong> — 攻击者使用字典攻击和凭据填充尝试获取系统访问权限</div>");
                    sb.AppendLine("<div class='threat-item'><strong>⚠ 拒绝服务攻击(DoS/DDoS)</strong> — 开放服务可能成为拒绝服务攻击的目标</div>");

                    sb.AppendLine("<h3>6.2 行业威胁趋势</h3>");
                    sb.AppendLine("<table><tr><th>威胁趋势</th><th>分析描述</th><th>严重度</th></tr>");
                    sb.AppendLine("<tr><td><strong>勒索软件攻击持续增长</strong></td><td>针对关键基础设施的勒索软件采用双重勒索策略（加密+数据泄露），赎金要求不断攀升</td><td style='color:#991b1b;font-weight:bold'>严重</td></tr>");
                    sb.AppendLine("<tr><td><strong>供应链攻击日益复杂</strong></td><td>攻击者通过入侵可信软件供应商分发恶意代码，SolarWinds事件后成为主要威胁</td><td style='color:#c2410c;font-weight:bold'>高</td></tr>");
                    sb.AppendLine("<tr><td><strong>零日漏洞利用速度加快</strong></td><td>从漏洞公开到被大规模利用的时间窗口持续缩短，数小时内即可完成武器化</td><td style='color:#c2410c;font-weight:bold'>高</td></tr>");
                    sb.AppendLine("<tr><td><strong>云服务成为新攻击重点</strong></td><td>云环境配置错误和API安全漏洞成为攻击者主要入口</td><td style='color:#d97706;font-weight:bold'>中</td></tr>");
                    sb.AppendLine("<tr><td><strong>AI驱动的网络攻击</strong></td><td>攻击者利用AI技术生成钓鱼邮件、自动化漏洞发现和规避检测</td><td style='color:#d97706;font-weight:bold'>中</td></tr>");
                    sb.AppendLine("</table>");

                    sb.AppendLine("<h3>6.3 攻击面评估</h3>");
                    sb.AppendLine("<p>基于扫描结果对目标系统攻击面进行多维度评估：</p>");
                    sb.AppendLine("<table><tr><th>评估维度</th><th>当前状态</th><th>风险等级</th></tr>");
                    var hasHighRiskPort = openPorts.Any(p => p.PortNumber == 445 || p.PortNumber == 135 || p.PortNumber == 3389 || p.PortNumber == 23);
                    sb.AppendLine($"<tr><td><strong>外部可达端口数</strong></td><td>{openPorts.Count}个开放端口{(hasHighRiskPort ? "（含高危端口）" : "（未发现高危端口）")}</td><td style='color:{(hasHighRiskPort ? "#dc2626" : "#059669")};font-weight:bold'>{(hasHighRiskPort ? "高" : "低")}</td></tr>");
                    sb.AppendLine($"<tr><td><strong>已知漏洞数量</strong></td><td>{allVulns.Count}个漏洞{(highRiskCount > 0 ? $"（含{highRiskCount}个高危）" : "")}</td><td style='color:{(highRiskCount > 0 ? "#dc2626" : "#059669")};font-weight:bold'>{(highRiskCount > 0 ? "高" : "低")}</td></tr>");
                    var hasWebPort = openPorts.Any(p => p.PortNumber == 80 || p.PortNumber == 443 || p.PortNumber == 8080);
                    sb.AppendLine($"<tr><td><strong>服务暴露面</strong></td><td>{(hasWebPort ? "Web服务对外暴露" : "无Web服务对外暴露")}</td><td style='color:{(hasWebPort ? "#d97706" : "#059669")};font-weight:bold'>{(hasWebPort ? "中" : "低")}</td></tr>");
                    var hasAuthVuln = allVulns.Any(v => (v?.Name?.ToLower().Contains("auth") == true || v?.Name?.ToLower().Contains("认证") == true || v?.Name?.ToLower().Contains("login") == true));
                    sb.AppendLine($"<tr><td><strong>身份认证风险</strong></td><td>{(hasAuthVuln ? "存在认证相关漏洞" : "未发现认证相关漏洞")}</td><td style='color:{(hasAuthVuln ? "#dc2626" : "#059669")};font-weight:bold'>{(hasAuthVuln ? "高" : "低")}</td></tr>");
                    var hasDataLeak = allVulns.Any(v => (v?.Name?.ToLower().Contains("disclosure") == true || v?.Name?.ToLower().Contains("泄露") == true || v?.Name?.ToLower().Contains("leak") == true));
                    sb.AppendLine($"<tr><td><strong>数据泄露风险</strong></td><td>{(hasDataLeak ? "存在信息泄露风险" : "未发现数据泄露风险")}</td><td style='color:{(hasDataLeak ? "#d97706" : "#059669")};font-weight:bold'>{(hasDataLeak ? "中" : "低")}</td></tr>");
                    sb.AppendLine("</table>");

                    sb.AppendLine("<h2>七、合规参考</h2>");
                    sb.AppendLine("<p>本节根据当前扫描结果，对照主要信息安全合规标准评估目标系统的合规状态。</p>");

                    sb.AppendLine("<h3>7.1 合规标准对照评估</h3>");
                    sb.AppendLine("<table><tr><th>合规标准</th><th>相关要求</th><th>评估范围</th><th>符合性状态</th></tr>");
                    sb.AppendLine($"<tr><td><strong>等保2.0</strong></td><td>安全通信网络、安全区域边界、安全计算环境</td><td>网络安全等级保护基本要求</td><td style='color:{(highRiskCount > 0 ? "#d97706" : "#059669")};font-weight:bold'>{(highRiskCount > 0 ? "部分符合" : "基本符合")}</td></tr>");
                    sb.AppendLine($"<tr><td><strong>ISO 27001</strong></td><td>A.12漏洞管理、A.13通信安全、A.14系统开发安全</td><td>信息安全管理体系要求</td><td style='color:{(highRiskCount > 3 ? "#dc2626" : "#d97706")};font-weight:bold'>{(highRiskCount > 3 ? "不符合" : "部分符合")}</td></tr>");
                    sb.AppendLine("<tr><td><strong>GDPR</strong></td><td>第32条-数据处理者安全措施、第25条-数据保护设计</td><td>通用数据保护条例</td><td style='color:#64748b;font-weight:bold'>需要评估</td></tr>");
                    sb.AppendLine($"<tr><td><strong>PCI DSS</strong></td><td>Req.6安全系统开发、Req.11安全测试、Req.2安全配置</td><td>支付卡行业数据安全标准</td><td style='color:{(highRiskCount > 0 ? "#dc2626" : "#64748b")};font-weight:bold'>{(highRiskCount > 0 ? "不符合" : "需要评估")}</td></tr>");
                    sb.AppendLine($"<tr><td><strong>CIS Controls</strong></td><td>控制3数据保护、控制5安全配置、控制7漏洞管理</td><td>CIS关键安全控制措施</td><td style='color:{(highRiskCount > 0 ? "#d97706" : "#059669")};font-weight:bold'>{(highRiskCount > 0 ? "部分符合" : "基本符合")}</td></tr>");
                    sb.AppendLine("</table>");

                    sb.AppendLine("<h3>7.2 合规差距分析</h3>");
                    if (highRiskCount > 0)
                        sb.AppendLine($"<div class='gap-item'><strong>1.</strong> 发现{highRiskCount}个高危漏洞，不符合等保2.0漏洞管理要求和ISO 27001 A.12漏洞管理控制</div>");
                    if (openPorts.Any(p => p.PortNumber == 445 || p.PortNumber == 135))
                        sb.AppendLine("<div class='gap-item'><strong>2.</strong> SMB/RPC等高危端口对外开放，不符合等保2.0安全区域边界要求和CIS控制5安全配置</div>");
                    if (openPorts.Any(p => p.PortNumber == 3389))
                        sb.AppendLine("<div class='gap-item'><strong>3.</strong> RDP远程桌面端口暴露，不符合PCI DSS Req.1网络分段要求</div>");
                    if (highRiskCount == 0 && !openPorts.Any(p => p.PortNumber == 445 || p.PortNumber == 135 || p.PortNumber == 3389))
                        sb.AppendLine("<div class='gap-item'>当前扫描结果未发现明显合规差距，建议持续监控并定期进行合规审计</div>");

                    sb.AppendLine("<h3>7.3 合规改进建议</h3>");
                    sb.AppendLine("<p>针对上述合规差距，建议按以下优先级进行改进：</p>");
                    sb.AppendLine("<table><tr><th>序号</th><th>改进措施</th><th>关联标准</th><th>优先级</th><th>具体建议</th></tr>");
                    sb.AppendLine("<tr><td>1</td><td><strong>建立安全基线配置标准</strong></td><td>等保2.0/ISO 27001</td><td style='color:#dc2626;font-weight:bold'>高</td><td>制定并实施系统安全配置基线，定期进行基线检查和偏差修正</td></tr>");
                    sb.AppendLine("<tr><td>2</td><td><strong>实施漏洞管理流程</strong></td><td>CIS Controls/PCI DSS</td><td style='color:#dc2626;font-weight:bold'>高</td><td>建立漏洞扫描、评估、修复的闭环管理流程，确保高危漏洞在规定时限内修复</td></tr>");
                    sb.AppendLine("<tr><td>3</td><td><strong>加强访问控制机制</strong></td><td>等保2.0/GDPR</td><td style='color:#dc2626;font-weight:bold'>高</td><td>实施最小权限原则，部署多因素认证，定期审计账户权限</td></tr>");
                    sb.AppendLine("<tr><td>4</td><td><strong>完善日志审计体系</strong></td><td>等保2.0/ISO 27001</td><td style='color:#d97706;font-weight:bold'>中</td><td>部署集中化日志管理平台，确保关键操作可追溯，日志保留不少于6个月</td></tr>");
                    sb.AppendLine("<tr><td>5</td><td><strong>数据加密与保护</strong></td><td>GDPR/PCI DSS</td><td style='color:#d97706;font-weight:bold'>中</td><td>对敏感数据实施传输加密（TLS 1.2+）和存储加密，建立数据分类分级制度</td></tr>");
                    sb.AppendLine("<tr><td>6</td><td><strong>安全意识培训</strong></td><td>ISO 27001/CIS Controls</td><td style='color:#059669;font-weight:bold'>低</td><td>定期开展安全意识培训和考核，建立安全事件报告机制</td></tr>");
                    sb.AppendLine("</table>");

                    sb.AppendLine("<h2>八、结论与建议</h2>");

                    sb.AppendLine("<h3>8.1 总体安全评级</h3>");
                    var riskBgColor = overallRisk == "严重" ? "#fef2f2" : overallRisk == "高" ? "#fff7ed" : overallRisk == "中" ? "#fefce8" : "#ecfdf5";
                    var riskBorderColor = overallRisk == "严重" ? "#991b1b" : overallRisk == "高" ? "#c2410c" : overallRisk == "中" ? "#d97706" : "#059669";
                    sb.AppendLine($"<div style='text-align:center;padding:30px;margin:20px auto;max-width:500px;background:{riskBgColor};border:2px solid {riskBorderColor};border-radius:12px;'>");
                    sb.AppendLine($"<div style='font-size:14px;color:#64748b;'>总体安全评级</div>");
                    sb.AppendLine($"<div style='font-size:36px;font-weight:bold;color:{riskBorderColor};margin:10px 0;'>{overallRisk}风险</div>");
                    sb.AppendLine($"<div style='font-size:18px;font-weight:bold;color:#1a365d;margin:4px 0;'>安全评分：{securityScore}/100</div>");
                    sb.AppendLine($"<div style='font-size:12px;color:#64748b;margin-top:6px;'>{GetSecurityRatingDescriptionForScore(securityScore)}</div>");
                    sb.AppendLine($"<div style='font-size:12px;color:#64748b;margin-top:8px;padding-top:8px;border-top:1px solid #e2e8f0;'>目标系统：{targetIp} | 漏洞总数：{allVulns.Count} | 开放端口：{openPorts.Count}</div>");
                    sb.AppendLine("</div>");

                    var portNumbers = openPorts.Select(p => p.PortNumber).ToHashSet();
                    var hasHighRisk = allVulns.Any(v => IsCriticalLevel(v?.RiskLevel) || IsHighLevel(v?.RiskLevel));
                    var radarData = new (string Standard, int Score)[]
                    {
                        ("等保2.0", hasHighRisk ? 45 : 75),
                        ("ISO 27001", hasHighRisk ? 50 : 80),
                        ("GDPR", portNumbers.Any(p => p == 445 || p == 3389 || p == 3306) ? 40 : 85),
                        ("PCI DSS", hasHighRisk ? 55 : 80),
                        ("CIS Controls", hasHighRisk ? 50 : 75)
                    };

                    sb.AppendLine("<h3>8.2 合规雷达图</h3>");
                    sb.AppendLine("<div class='chart-container'>");
                    sb.AppendLine("<div style='display:flex;justify-content:center;padding:10px 0;'>");
                    sb.AppendLine("<svg width='340' height='340' viewBox='0 0 340 340'>");
                    int radarCx = 170, radarCy = 165, radarR = 120;
                    int radarN = radarData.Length;
                    for (int level = 1; level <= 4; level++)
                    {
                        int r = radarR * level / 4;
                        var pts = new List<string>();
                        for (int i = 0; i < radarN; i++)
                        {
                            double angle = -Math.PI / 2 + 2 * Math.PI * i / radarN;
                            var px = radarCx + (float)(r * Math.Cos(angle));
                            var py = radarCy + (float)(r * Math.Sin(angle));
                            pts.Add($"{px:F1},{py:F1}");
                        }
                        sb.AppendLine($"<polygon points='{string.Join(" ", pts)}' fill='none' stroke='#cbd5e1' stroke-width='0.5' stroke-dasharray='3,3'/>");
                    }
                    for (int i = 0; i < radarN; i++)
                    {
                        double angle = -Math.PI / 2 + 2 * Math.PI * i / radarN;
                        var axisEndX = radarCx + (float)(radarR * Math.Cos(angle));
                        var axisEndY = radarCy + (float)(radarR * Math.Sin(angle));
                        sb.AppendLine($"<line x1='{radarCx}' y1='{radarCy}' x2='{axisEndX:F1}' y2='{axisEndY:F1}' stroke='#cbd5e1' stroke-width='0.5'/>");
                    }
                    var dataPts = new List<string>();
                    for (int i = 0; i < radarN; i++)
                    {
                        double angle = -Math.PI / 2 + 2 * Math.PI * i / radarN;
                        float r = radarR * radarData[i].Score / 100f;
                        var px = radarCx + (float)(r * Math.Cos(angle));
                        var py = radarCy + (float)(r * Math.Sin(angle));
                        dataPts.Add($"{px:F1},{py:F1}");
                    }
                    sb.AppendLine($"<polygon points='{string.Join(" ", dataPts)}' fill='rgba(59,130,246,0.25)' stroke='#2563eb' stroke-width='2'/>");
                    for (int i = 0; i < radarN; i++)
                    {
                        var ptParts = dataPts[i].Split(',');
                        sb.AppendLine($"<circle cx='{ptParts[0]}' cy='{ptParts[1]}' r='4' fill='#1d4ed8' stroke='white' stroke-width='2'/>");
                    }
                    for (int i = 0; i < radarN; i++)
                    {
                        double angle = -Math.PI / 2 + 2 * Math.PI * i / radarN;
                        float lx = radarCx + (float)((radarR + 28) * Math.Cos(angle));
                        float ly = radarCy + (float)((radarR + 28) * Math.Sin(angle));
                        sb.AppendLine($"<text x='{lx:F1}' y='{ly:F1}' text-anchor='middle' dominant-baseline='central' font-size='11' fill='#334155' font-weight='500'>{radarData[i].Standard}</text>");
                    }
                    sb.AppendLine("</svg>");
                    sb.AppendLine("</div></div>");

                    sb.AppendLine("<h3>8.3 核心结论</h3>");
                    if (highRiskCount > 0)
                    {
                        sb.AppendLine($"<p>本次扫描针对目标系统 <strong>{targetIp}</strong> 进行了全面的网络安全评估，共发现 <strong>{allVulns.Count}</strong> 个安全漏洞（其中高危 {highRiskCount} 个、中危 {medRiskCount} 个、低危 {lowRiskCount} 个）和 {openPorts.Count} 个开放端口。发现的高危漏洞需要立即采取修复措施，建议按照本报告提供的修复优先级矩阵制定详细的修复计划。</p>");
                    }
                    else if (allVulns.Any())
                    {
                        sb.AppendLine($"<p>本次扫描针对目标系统 <strong>{targetIp}</strong> 进行了全面的网络安全评估，共发现 <strong>{allVulns.Count}</strong> 个安全漏洞（中危 {medRiskCount} 个、低危 {lowRiskCount} 个）和 {openPorts.Count} 个开放端口。当前未发现高危漏洞，但建议对中低危漏洞进行持续关注和计划修复。</p>");
                    }
                    else
                    {
                        sb.AppendLine($"<p>本次扫描针对目标系统 <strong>{targetIp}</strong> 进行了全面的网络安全评估，未发现安全漏洞。发现 {openPorts.Count} 个开放端口，建议持续监控并定期进行安全评估。</p>");
                    }

                    sb.AppendLine("<div style='margin-top:12px;'>");
                    var criticalCount = allVulns.Count(v => IsCriticalLevel(v?.RiskLevel));
                    if (criticalCount > 0)
                        sb.AppendLine($"<div class='threat-item'><strong>1.</strong> 本次扫描发现{criticalCount}个严重漏洞，存在被远程攻击的高风险，攻击者可利用这些漏洞获取系统控制权。</div>");
                    if (highRiskCount > 0)
                        sb.AppendLine($"<div class='threat-item'><strong>{(criticalCount > 0 ? "2" : "1")}.</strong> 共发现{highRiskCount}个高危漏洞，涉及多个服务端口，需优先处理以降低被攻击风险。</div>");
                    var hasSensitivePorts = portNumbers.Any(p => p == 445 || p == 135 || p == 3389);
                    if (hasSensitivePorts)
                        sb.AppendLine("<div class='threat-item'><strong>3.</strong> 系统暴露了SMB/RPC/RDP等高危端口，这些端口是勒索软件和蠕虫病毒的主要传播通道。</div>");
                    var hasDbPorts = portNumbers.Any(p => p == 3306 || p == 1433 || p == 5432 || p == 6379);
                    if (hasDbPorts)
                        sb.AppendLine("<div class='threat-item'><strong>4.</strong> 数据库或缓存服务端口对外暴露，存在数据泄露和未授权访问风险。</div>");
                    if (openPorts.Count > 15)
                        sb.AppendLine($"<div class='threat-item'><strong>5.</strong> 开放端口数量较多（{openPorts.Count}个），攻击面较大，建议关闭不必要的端口和服务。</div>");
                    sb.AppendLine("<div class='hardening-item'><strong>建议：</strong>建立常态化安全扫描机制，定期评估系统安全状况，及时发现和修复新增安全风险。</div>");
                    sb.AppendLine("</div>");

                    sb.AppendLine("<h3>8.4 长期安全建议</h3>");
                    sb.AppendLine("<p>以下为按优先级分类的长期安全改进建议：</p>");

                    sb.AppendLine("<h4 style='color:#dc2626;margin-top:16px;'>P1 - 紧急（1-7天内完成）</h4>");
                    sb.AppendLine("<table><tr><th>#</th><th>类别</th><th>建议措施</th></tr>");
                    sb.AppendLine("<tr><td style='color:#dc2626;font-weight:bold'>1</td><td><strong>漏洞修复</strong></td><td>修复所有严重和高危漏洞，消除远程代码执行风险</td></tr>");
                    sb.AppendLine("<tr><td style='color:#dc2626;font-weight:bold'>2</td><td><strong>端口安全</strong></td><td>关闭所有非必要的高危端口（如135、445、3389等），配置严格的防火墙规则</td></tr>");
                    sb.AppendLine("<tr><td style='color:#dc2626;font-weight:bold'>3</td><td><strong>数据库隔离</strong></td><td>对暴露的数据库端口实施网络隔离，仅允许授权IP访问</td></tr>");
                    sb.AppendLine("<tr><td style='color:#dc2626;font-weight:bold'>4</td><td><strong>加密通信</strong></td><td>启用所有对外服务的安全加密通信（TLS 1.2+）</td></tr>");
                    sb.AppendLine("<tr><td style='color:#dc2626;font-weight:bold'>5</td><td><strong>多因素认证</strong></td><td>实施多因素认证(MFA)，覆盖所有远程访问和特权账户</td></tr>");
                    sb.AppendLine("</table>");

                    sb.AppendLine("<h4 style='color:#d97706;margin-top:16px;'>P2 - 重要（1-3个月内完成）</h4>");
                    sb.AppendLine("<table><tr><th>#</th><th>类别</th><th>建议措施</th></tr>");
                    sb.AppendLine("<tr><td style='color:#d97706;font-weight:bold'>1</td><td><strong>漏洞管理</strong></td><td>建立漏洞管理闭环流程，实现扫描-评估-修复-验证的标准化</td></tr>");
                    sb.AppendLine("<tr><td style='color:#d97706;font-weight:bold'>2</td><td><strong>安全监控</strong></td><td>部署集中化日志管理系统(SIEM)，实现安全事件实时监控和告警</td></tr>");
                    sb.AppendLine("<tr><td style='color:#d97706;font-weight:bold'>3</td><td><strong>网络分段</strong></td><td>实施网络分段和微隔离，限制横向移动攻击路径</td></tr>");
                    sb.AppendLine("<tr><td style='color:#d97706;font-weight:bold'>4</td><td><strong>安全基线</strong></td><td>制定安全配置基线标准，定期进行基线检查和偏差修正</td></tr>");
                    sb.AppendLine("<tr><td style='color:#d97706;font-weight:bold'>5</td><td><strong>安全培训</strong></td><td>建立安全意识培训体系，定期开展全员安全培训</td></tr>");
                    sb.AppendLine("</table>");

                    sb.AppendLine("<h4 style='color:#059669;margin-top:16px;'>P3 - 改善（3-6个月内完成）</h4>");
                    sb.AppendLine("<table><tr><th>#</th><th>类别</th><th>建议措施</th></tr>");
                    sb.AppendLine("<tr><td style='color:#059669;font-weight:bold'>1</td><td><strong>合规建设</strong></td><td>推进等保2.0合规建设，完成差距整改和测评</td></tr>");
                    sb.AppendLine("<tr><td style='color:#059669;font-weight:bold'>2</td><td><strong>体系认证</strong></td><td>实施ISO 27001信息安全管理体系认证</td></tr>");
                    sb.AppendLine("<tr><td style='color:#059669;font-weight:bold'>3</td><td><strong>威胁情报</strong></td><td>建立威胁情报平台，实现安全威胁的主动防御</td></tr>");
                    sb.AppendLine("<tr><td style='color:#059669;font-weight:bold'>4</td><td><strong>编排自动化</strong></td><td>建设安全编排自动化与响应(SOAR)能力</td></tr>");
                    sb.AppendLine("<tr><td style='color:#059669;font-weight:bold'>5</td><td><strong>数据分级</strong></td><td>制定数据分类分级保护策略，满足GDPR/PCI DSS合规要求</td></tr>");
                    sb.AppendLine("</table>");

                    sb.AppendLine("<div class='footer'>");
                    sb.AppendLine($"NetSecurityScanner v{GetAppVersion()} | 报告生成时间：{DateTime.Now:yyyy-MM-dd HH:mm:ss}<br>");
                    sb.AppendLine("免责声明：本报告由自动化安全扫描工具生成，结果仅供参考。对于关键安全问题，建议进行人工验证和深度安全分析。");
                    sb.AppendLine("</div>");

                    sb.AppendLine("</div>");
                    sb.AppendLine("</body></html>");

                    File.WriteAllText(savePath, sb.ToString(), System.Text.Encoding.UTF8);
                    return savePath;
                }
                catch (Exception ex)
                {
                    Debug.WriteLine($"[HTML导出] 失败: {ex.Message}");
                    return string.Empty;
                }
            });
        }

        private async Task<string> GenerateCsvReport(List<CompleteScanResult> completeResults, string savePath)
        {
            return await Task.Run(() =>
            {
                try
                {
                    var allPorts = completeResults.SelectMany(r => r.PortScanResults ?? new List<PortScanResult>()).ToList();
                    var allVulns = completeResults.SelectMany(r => r.VulnerabilityResults ?? new List<VulnerabilityResult>()).ToList();
                    var targetIp = string.Join(", ", completeResults.Select(r => r.TargetIp).Distinct());
                    var openPorts = allPorts.Where(p => p?.Status == "开放" || p?.Status?.ToLower() == "open").ToList();
                    var highRiskCount = allVulns.Count(v => IsCriticalLevel(v?.RiskLevel) || IsHighLevel(v?.RiskLevel));

                    var sb = new System.Text.StringBuilder();

                    sb.AppendLine("网络安全漏洞扫描评估报告 - CSV数据导出");
                    sb.AppendLine($"报告生成时间,{DateTime.Now:yyyy-MM-dd HH:mm:ss}");
                    sb.AppendLine($"目标系统,{EscapeCsvField(targetIp)}");
                    sb.AppendLine($"扫描类型,{EscapeCsvField(BuildScanTypeDescription(completeResults))}");
                    sb.AppendLine($"风险等级,{CalculateOverallRiskFromVulns(allVulns)}");
                    sb.AppendLine($"开放端口数,{openPorts.Count}");
                    sb.AppendLine($"漏洞总数,{allVulns.Count}");
                    sb.AppendLine();

                    if (openPorts.Any())
                    {
                        sb.AppendLine("=== 端口扫描结果 ===");
                        sb.AppendLine("端口号,协议,服务名称,版本,状态,响应时间");
                        foreach (var p in openPorts.OrderBy(p => p.PortNumber))
                        {
                            sb.AppendLine($"{p.PortNumber},TCP,{EscapeCsvField(p.Service ?? "-")},{EscapeCsvField(p.ServiceVersion ?? "-")},{EscapeCsvField(p.Status ?? "未知")},{EscapeCsvField(p.ResponseTime ?? "-")}");
                        }
                        sb.AppendLine();
                    }

                    if (allVulns.Any())
                    {
                        sb.AppendLine("=== 漏洞详情 ===");
                        sb.AppendLine("序号,CVE编号,漏洞名称,风险等级,端口,服务,CVSS评分,描述,检测方法,修复方案,参考链接");
                        int idx = 1;
                        foreach (var v in allVulns.OrderByDescending(v => GetRiskPriorityFromLevel(v?.RiskLevel)))
                        {
                            var cvss = EstimateCvssScoreForLevel(v?.RiskLevel);
                            var port = v.Port.HasValue ? v.Port.Value.ToString() : "-";
                            sb.AppendLine($"{idx},{EscapeCsvField(v.CveId ?? "-")},{EscapeCsvField(v.Name ?? "未知")},{EscapeCsvField(v.RiskLevel ?? "未分类")},{port},{EscapeCsvField(v.Service ?? "-")},{cvss:F1},{EscapeCsvField(v.Description ?? "-")},{EscapeCsvField(v.DetectionMethod ?? "-")},{EscapeCsvField(v.Solution ?? "-")},{EscapeCsvField(v.References ?? "-")}");
                            idx++;
                        }
                        sb.AppendLine();
                    }

                    sb.AppendLine("=== 修复优先级矩阵 ===");
                    sb.AppendLine("优先级,处理时限,适用范围,建议措施");
                    sb.AppendLine("P1-紧急,24小时内,严重/远程执行类,立即隔离受影响系统");
                    sb.AppendLine("P2-高,7天内,高危/权限提升类,尽快安排维护窗口");
                    sb.AppendLine("P3-中,30天内,中危/信息泄露类,纳入常规更新计划");
                    sb.AppendLine("P4-低,下个周期,低危/信息类,持续监控");
                    sb.AppendLine();

                    sb.AppendLine("=== 威胁情报分析 ===");
                    sb.AppendLine("威胁向量,风险等级,描述");
                    if (openPorts.Any(p => p.PortNumber == 445 || p.PortNumber == 139))
                        sb.AppendLine("SMB服务暴露,高危,勒索软件主要传播通道");
                    if (openPorts.Any(p => p.PortNumber == 3389))
                        sb.AppendLine("RDP远程桌面暴露,高危,暴力破解和蓝屏漏洞利用风险");
                    if (openPorts.Any(p => p.PortNumber == 80 || p.PortNumber == 443 || p.PortNumber == 8080))
                        sb.AppendLine("Web服务暴露,中危,SQL注入/XSS/目录遍历等攻击风险");
                    if (highRiskCount > 0)
                        sb.AppendLine($"已知高危漏洞,高危,发现{highRiskCount}个高危漏洞可被自动化利用");
                    sb.AppendLine("弱密码攻击,中危,字典攻击和凭据填充风险");
                    sb.AppendLine("拒绝服务攻击,中危,DoS/DDoS风险");
                    sb.AppendLine();

                    sb.AppendLine("=== 合规参考 ===");
                    sb.AppendLine("合规标准,相关要求,符合性状态");
                    sb.AppendLine($"等保2.0,安全通信网络/安全区域边界/安全计算环境,{(highRiskCount > 0 ? "部分符合" : "基本符合")}");
                    sb.AppendLine($"ISO 27001,A.12漏洞管理/A.13通信安全/A.14系统开发安全,{(highRiskCount > 3 ? "不符合" : "部分符合")}");
                    sb.AppendLine("GDPR,第32条-数据处理者安全措施/第25条-数据保护设计,需要评估");
                    sb.AppendLine($"PCI DSS,Req.6安全系统开发/Req.11安全测试/Req.2安全配置,{(highRiskCount > 0 ? "不符合" : "需要评估")}");
                    sb.AppendLine($"CIS Controls,控制3数据保护/控制5安全配置/控制7漏洞管理,{(highRiskCount > 0 ? "部分符合" : "基本符合")}");

                    File.WriteAllText(savePath, sb.ToString(), System.Text.Encoding.UTF8);
                    return savePath;
                }
                catch (Exception ex)
                {
                    Debug.WriteLine($"[CSV导出] 失败: {ex.Message}");
                    return string.Empty;
                }
            });
        }

        private static string EscapeCsvField(string field)
        {
            if (string.IsNullOrEmpty(field)) return "";
            if (field.Contains(",") || field.Contains("\"") || field.Contains("\n") || field.Contains("\r"))
                return $"\"{field.Replace("\"", "\"\"")}\"";
            return field;
        }

        private async Task<string> GenerateTxtReport(List<CompleteScanResult> completeResults, string savePath)
        {
            return await Task.Run(() =>
            {
                try
                {
                    var allPorts = completeResults.SelectMany(r => r.PortScanResults ?? new List<PortScanResult>()).ToList();
                    var allVulns = completeResults.SelectMany(r => r.VulnerabilityResults ?? new List<VulnerabilityResult>()).ToList();
                    var targetIp = string.Join(", ", completeResults.Select(r => r.TargetIp).Distinct());
                    var openPorts = allPorts.Where(p => p?.Status == "开放" || p?.Status?.ToLower() == "open").ToList();
                    var overallRisk = CalculateOverallRiskFromVulns(allVulns);
                    var highRiskCount = allVulns.Count(v => IsCriticalLevel(v?.RiskLevel) || IsHighLevel(v?.RiskLevel));
                    var medRiskCount = allVulns.Count(v => IsMediumLevel(v?.RiskLevel));
                    var lowRiskCount = allVulns.Count(v => IsLowLevel(v?.RiskLevel));

                    var sb = new System.Text.StringBuilder();
                    sb.AppendLine("═══════════════════════════════════════════════════════════════");
                    sb.AppendLine("                    网络安全漏洞扫描评估报告");
                    sb.AppendLine("            Network Security Vulnerability Assessment Report");
                    sb.AppendLine("═══════════════════════════════════════════════════════════════");
                    sb.AppendLine();
                    sb.AppendLine($"  报告编号：RPT-{DateTime.Now:yyyyMMdd}-{Guid.NewGuid():N}".Substring(0, 40));
                    sb.AppendLine($"  目标系统：{targetIp}");
                    sb.AppendLine($"  扫描时间：{DateTime.Now:yyyy-MM-dd HH:mm:ss}");
                    sb.AppendLine($"  扫描模式：{BuildScanTypeDescription(completeResults)}");
                    sb.AppendLine($"  生成时间：{DateTime.Now:yyyy-MM-dd HH:mm:ss}");
                    sb.AppendLine();

                    sb.AppendLine("───────────────────────────────────────────────────────────────");
                    sb.AppendLine("一、核心统计");
                    sb.AppendLine("───────────────────────────────────────────────────────────────");
                    sb.AppendLine($"  风险等级：{overallRisk}");
                    sb.AppendLine($"  开放端口：{openPorts.Count}个 / 扫描端口：{allPorts.Count}个");
                    sb.AppendLine($"  漏洞总数：{allVulns.Count}个");
                    sb.AppendLine($"  严重/高危：{highRiskCount}个");
                    sb.AppendLine($"  中危漏洞：{medRiskCount}个");
                    sb.AppendLine($"  低危漏洞：{lowRiskCount}个");
                    var highPct = allVulns.Any() ? (int)((double)highRiskCount / allVulns.Count * 100) : 0;
                    sb.AppendLine($"  高危占比：{highPct}%");
                    sb.AppendLine();

                    if (allVulns.Any())
                    {
                        sb.AppendLine("───────────────────────────────────────────────────────────────");
                        sb.AppendLine("  Top 5 高危漏洞");
                        sb.AppendLine("───────────────────────────────────────────────────────────────");
                        int tIdx = 1;
                        foreach (var v in allVulns.OrderByDescending(v => GetRiskPriorityFromLevel(v?.RiskLevel)).Take(5))
                        {
                            sb.AppendLine($"  {tIdx}. [{v.RiskLevel ?? "未分类"}] {v.Name ?? "未知漏洞"} ({v.CveId ?? "-"})");
                            tIdx++;
                        }
                        sb.AppendLine();
                    }

                    if (openPorts.Any())
                    {
                        sb.AppendLine("───────────────────────────────────────────────────────────────");
                        sb.AppendLine("二、端口扫描结果");
                        sb.AppendLine("───────────────────────────────────────────────────────────────");
                        sb.AppendLine($"  {"端口号",-8}{"协议",-6}{"服务名称",-16}{"版本",-24}{"状态",-10}");
                        sb.AppendLine("  " + new string('-', 60));
                        foreach (var p in openPorts.OrderBy(p => p.PortNumber))
                        {
                            var svc = (p.Service ?? "未知").PadRight(14).Substring(0, Math.Min(14, (p.Service ?? "未知").Length));
                            var ver = (p.ServiceVersion ?? "-").PadRight(22).Substring(0, Math.Min(22, (p.ServiceVersion ?? "-").Length));
                            sb.AppendLine($"  {p.PortNumber,-8}{"TCP",-6}{svc,-16}{ver,-24}{p.Status ?? "未知",-10}");
                        }
                        sb.AppendLine();
                    }

                    if (allVulns.Any())
                    {
                        sb.AppendLine("───────────────────────────────────────────────────────────────");
                        sb.AppendLine("三、漏洞详情");
                        sb.AppendLine("───────────────────────────────────────────────────────────────");
                        int idx = 1;
                        foreach (var v in allVulns.OrderByDescending(v => GetRiskPriorityFromLevel(v?.RiskLevel)))
                        {
                            var cvss = EstimateCvssScoreForLevel(v?.RiskLevel);
                            sb.AppendLine($"  [{idx}] {v.Name ?? "未知漏洞"}");
                            sb.AppendLine($"      CVE编号：{v.CveId ?? "-"}");
                            sb.AppendLine($"      风险等级：{v.RiskLevel ?? "未分类"} (CVSS: {cvss:F1})");
                            sb.AppendLine($"      影响端口：{(v.Port.HasValue ? v.Port.Value.ToString() : "-")}");
                            sb.AppendLine($"      服务：{v.Service ?? "-"}");
                            sb.AppendLine($"      描述：{v.Description ?? "-"}");
                            if (!string.IsNullOrWhiteSpace(v.DetectionMethod))
                                sb.AppendLine($"      检测方法：{v.DetectionMethod}");
                            sb.AppendLine($"      修复方案：{v.Solution ?? "请参考官方安全公告"}");
                            if (!string.IsNullOrWhiteSpace(v.References))
                                sb.AppendLine($"      参考链接：{v.References}");
                            sb.AppendLine();
                            idx++;
                        }
                    }

                    sb.AppendLine("───────────────────────────────────────────────────────────────");
                    sb.AppendLine("四、风险评估");
                    sb.AppendLine("───────────────────────────────────────────────────────────────");
                    sb.AppendLine($"  整体风险评级：{overallRisk}");
                    sb.AppendLine($"  漏洞总量：{allVulns.Count}");
                    sb.AppendLine($"  高危漏洞数：{highRiskCount}");
                    sb.AppendLine($"  开放端口数：{openPorts.Count}");
                    sb.AppendLine();
                    sb.AppendLine("  安全建议：");
                    var suggestions = new[]
                    {
                        "立即修复所有严重和高危级别的漏洞",
                        "关闭不必要的服务和端口，减少攻击面",
                        "及时更新系统和应用软件至最新版本",
                        "实施强密码策略和多因素认证(MFA)",
                        "配置防火墙规则限制网络访问",
                        "定期进行安全扫描和渗透测试"
                    };
                    foreach (var s in suggestions)
                        sb.AppendLine($"    * {s}");
                    sb.AppendLine();

                    sb.AppendLine("───────────────────────────────────────────────────────────────");
                    sb.AppendLine("五、修复建议");
                    sb.AppendLine("───────────────────────────────────────────────────────────────");
                    sb.AppendLine("  修复优先级矩阵：");
                    sb.AppendLine("    P1-紧急 | 24小时内 | 严重/远程执行类 | 立即隔离受影响系统");
                    sb.AppendLine("    P2-高   | 7天内   | 高危/权限提升类 | 尽快安排维护窗口");
                    sb.AppendLine("    P3-中   | 30天内  | 中危/信息泄露类 | 纳入常规更新计划");
                    sb.AppendLine("    P4-低   | 下个周期 | 低危/信息类    | 持续监控");
                    sb.AppendLine();

                    sb.AppendLine("  通用安全加固建议：");
                    var categories = new[]
                    {
                        ("1. 网络层面", "配置防火墙规则，仅开放必要的业务端口；实施网络分段隔离；启用IDS/IPS。"),
                        ("2. 系统层面", "及时安装操作系统安全更新；禁用不必要的服务和账户；配置强密码策略。"),
                        ("3. 应用层面", "保持应用程序及依赖库为最新版本；实施安全的编码实践；定期进行代码安全审查。"),
                        ("4. 身份认证", "实施多因素认证(MFA)；采用基于角色的访问控制(RBAC)；定期清理过期账户。"),
                        ("5. 数据保护", "加密敏感数据存储和传输（TLS 1.2+）；建立定期数据备份和灾难恢复机制。"),
                        ("6. 监控审计", "部署集中化日志管理系统(SIEM)；设置安全事件实时告警阈值；定期进行合规审计。")
                    };
                    foreach (var cat in categories)
                        sb.AppendLine($"    {cat.Item1}：{cat.Item2}");
                    sb.AppendLine();

                    sb.AppendLine("───────────────────────────────────────────────────────────────");
                    sb.AppendLine("六、威胁情报分析");
                    sb.AppendLine("───────────────────────────────────────────────────────────────");
                    sb.AppendLine("  活跃威胁向量：");
                    if (openPorts.Any(p => p.PortNumber == 445 || p.PortNumber == 139))
                        sb.AppendLine("    ⚠ SMB服务暴露 — 勒索软件主要传播通道，存在远程代码执行风险");
                    if (openPorts.Any(p => p.PortNumber == 3389))
                        sb.AppendLine("    ⚠ RDP远程桌面暴露 — 暴力破解和蓝屏漏洞利用风险");
                    if (openPorts.Any(p => p.PortNumber == 80 || p.PortNumber == 443 || p.PortNumber == 8080))
                        sb.AppendLine("    ⚠ Web服务暴露 — SQL注入/XSS/目录遍历等攻击风险");
                    if (highRiskCount > 0)
                        sb.AppendLine($"    ⚠ 已知高危漏洞 — 发现{highRiskCount}个高危漏洞可被自动化利用");
                    sb.AppendLine("    ⚠ 弱密码和默认凭据攻击 — 字典攻击和凭据填充风险");
                    sb.AppendLine("    ⚠ 拒绝服务攻击(DoS/DDoS) — 开放服务可能成为攻击目标");
                    sb.AppendLine();
                    sb.AppendLine("  行业威胁趋势：");
                    sb.AppendLine("    1. 勒索软件攻击持续增长，采用双重勒索策略");
                    sb.AppendLine("    2. 供应链攻击日益复杂，影响范围扩大");
                    sb.AppendLine("    3. 零日漏洞利用速度加快，数小时内完成武器化");
                    sb.AppendLine("    4. 云服务成为新攻击重点");
                    sb.AppendLine("    5. AI驱动的网络攻击兴起");
                    sb.AppendLine();

                    sb.AppendLine("───────────────────────────────────────────────────────────────");
                    sb.AppendLine("七、合规参考");
                    sb.AppendLine("───────────────────────────────────────────────────────────────");
                    sb.AppendLine($"  等保2.0    ：{(highRiskCount > 0 ? "部分符合" : "基本符合")} — 安全通信网络/安全区域边界/安全计算环境");
                    sb.AppendLine($"  ISO 27001  ：{(highRiskCount > 3 ? "不符合" : "部分符合")} — A.12漏洞管理/A.13通信安全/A.14系统开发安全");
                    sb.AppendLine($"  GDPR       ：需要评估 — 第32条-数据处理者安全措施/第25条-数据保护设计");
                    sb.AppendLine($"  PCI DSS    ：{(highRiskCount > 0 ? "不符合" : "需要评估")} — Req.6安全系统开发/Req.11安全测试/Req.2安全配置");
                    sb.AppendLine($"  CIS Controls：{(highRiskCount > 0 ? "部分符合" : "基本符合")} — 控制3数据保护/控制5安全配置/控制7漏洞管理");
                    sb.AppendLine();

                    sb.AppendLine("───────────────────────────────────────────────────────────────");
                    sb.AppendLine("八、结论与建议");
                    sb.AppendLine("───────────────────────────────────────────────────────────────");
                    sb.AppendLine($"  总体安全评级：{overallRisk}风险");
                    sb.AppendLine($"  目标系统：{targetIp} | 漏洞总数：{allVulns.Count} | 开放端口：{openPorts.Count}");
                    sb.AppendLine();
                    sb.AppendLine("  长期安全建议：");
                    sb.AppendLine("    [P1] 建立定期漏洞扫描机制，每周至少全面扫描一次");
                    sb.AppendLine("    [P1] 实施漏洞管理全流程，确保从发现到修复的闭环跟踪");
                    sb.AppendLine("    [P2] 部署入侵检测和防御系统(IDS/IPS)");
                    sb.AppendLine("    [P2] 建立安全事件应急响应计划");
                    sb.AppendLine("    [P2] 加强员工安全意识培训");
                    sb.AppendLine("    [P3] 实施最小权限原则，定期审查用户权限");
                    sb.AppendLine("    [P3] 保持系统和应用程序的及时更新");
                    sb.AppendLine("    [P3] 定期备份关键数据，验证可恢复性");
                    sb.AppendLine();

                    sb.AppendLine("═══════════════════════════════════════════════════════════════");
                    sb.AppendLine("免责声明：本报告由 NetSecurityScanner 安全扫描工具自动生成，结果仅供参考。");
                    sb.AppendLine("对于关键安全问题，建议进行人工验证和深度安全分析。");
                    sb.AppendLine("═══════════════════════════════════════════════════════════════");

                    File.WriteAllText(savePath, sb.ToString(), System.Text.Encoding.UTF8);
                    return savePath;
                }
                catch (Exception ex)
                {
                    Debug.WriteLine($"[TXT导出] 失败: {ex.Message}");
                    return string.Empty;
                }
            });
        }

        private static string CalculateOverallRiskFromVulns(List<VulnerabilityResult> vulns)
        {
            if (vulns == null || !vulns.Any()) return "信息";
            if (vulns.Any(v => IsCriticalLevel(v?.RiskLevel))) return "严重";
            if (vulns.Any(v => IsHighLevel(v?.RiskLevel))) return "高";
            if (vulns.Any(v => IsMediumLevel(v?.RiskLevel))) return "中";
            return "低";
        }

        private static int GetRiskPriorityFromLevel(string riskLevel)
        {
            if (string.IsNullOrWhiteSpace(riskLevel)) return 0;
            if (IsCriticalLevel(riskLevel)) return 5;
            if (IsHighLevel(riskLevel)) return 4;
            if (IsMediumLevel(riskLevel)) return 3;
            if (IsLowLevel(riskLevel)) return 2;
            return 1;
        }

        private static bool IsCriticalLevel(string riskLevel)
        {
            if (string.IsNullOrWhiteSpace(riskLevel)) return false;
            var l = riskLevel.Trim().ToLower();
            return l.Contains("严重") || l == "critical";
        }

        private static bool IsHighLevel(string riskLevel)
        {
            if (string.IsNullOrWhiteSpace(riskLevel)) return false;
            var l = riskLevel.Trim().ToLower();
            return (l.Contains("高") && !l.Contains("严重")) || l == "high";
        }

        private static bool IsMediumLevel(string riskLevel)
        {
            if (string.IsNullOrWhiteSpace(riskLevel)) return false;
            var l = riskLevel.Trim().ToLower();
            return l.Contains("中") || l == "medium";
        }

        private static bool IsLowLevel(string riskLevel)
        {
            if (string.IsNullOrWhiteSpace(riskLevel)) return false;
            var l = riskLevel.Trim().ToLower();
            return l.Contains("低") || l == "low";
        }

        private static double EstimateCvssScoreForLevel(string riskLevel)
        {
            if (string.IsNullOrEmpty(riskLevel)) return 0.0;
            if (IsCriticalLevel(riskLevel)) return 9.5;
            if (IsHighLevel(riskLevel)) return 7.5;
            if (IsMediumLevel(riskLevel)) return 5.5;
            if (IsLowLevel(riskLevel)) return 3.0;
            return 1.0;
        }

        private static int CalculateSecurityScoreFromVulns(List<VulnerabilityResult> vulns, List<PortScanResult> openPorts)
        {
            int score = 100;
            var criticalCount = vulns.Count(v => IsCriticalLevel(v?.RiskLevel));
            var highCount = vulns.Count(v => IsHighLevel(v?.RiskLevel));
            var mediumCount = vulns.Count(v => IsMediumLevel(v?.RiskLevel));
            var lowCount = vulns.Count(v => IsLowLevel(v?.RiskLevel));
            score -= criticalCount * 15;
            score -= highCount * 8;
            score -= mediumCount * 3;
            score -= lowCount * 1;
            var portNumbers = openPorts.Select(p => p?.PortNumber ?? 0).ToHashSet();
            if (portNumbers.Contains(445) || portNumbers.Contains(135)) score -= 10;
            if (portNumbers.Contains(3389)) score -= 8;
            if (portNumbers.Contains(23)) score -= 10;
            if (portNumbers.Contains(3306) || portNumbers.Contains(1433) || portNumbers.Contains(5432)) score -= 5;
            if (openPorts.Count > 20) score -= 5;
            else if (openPorts.Count > 10) score -= 3;
            return Math.Max(0, Math.Min(100, score));
        }

        private static string GetSecurityRatingDescriptionForScore(int score)
        {
            if (score >= 90) return "系统安全状况优秀，仅存在少量低风险问题，建议持续保持安全监控。";
            if (score >= 75) return "系统安全状况良好，存在部分中等风险问题，建议按计划进行安全加固。";
            if (score >= 60) return "系统安全状况一般，存在多个安全风险，建议尽快制定并执行安全改进计划。";
            if (score >= 40) return "系统安全状况较差，存在高危安全风险，建议立即采取紧急修复措施。";
            return "系统安全状况严重，存在严重安全漏洞和重大风险，建议立即启动应急响应。";
        }

        private static string BuildScanTypeDescription(List<CompleteScanResult> results)
        {
            if (results == null || !results.Any())
                return "综合扫描";

            var scanTypes = results
                .Select(r => r?.ScanType)
                .Where(s => !string.IsNullOrWhiteSpace(s))
                .Distinct()
                .ToList();

            if (!scanTypes.Any())
                return "综合扫描";

            var normalized = new List<string>();
            foreach (var st in scanTypes)
            {
                if (st.Contains("专家模式"))
                    normalized.Add("专家模式");
                else if (st.Contains("漏洞"))
                    normalized.Add("漏洞扫描");
                else if (st.Contains("TCP"))
                    normalized.Add("TCP端口扫描");
                else if (st.Contains("UDP"))
                    normalized.Add("UDP端口扫描");
                else
                    normalized.Add(st);
            }

            var distinct = normalized.Distinct().ToList();
            return string.Join(" + ", distinct);
        }

        private static List<string> GetActiveScanFeatures(List<CompleteScanResult> results)
        {
            var features = new List<string>();
            if (results == null || !results.Any()) return features;

            var scanTypes = results
                .Select(r => r?.ScanType)
                .Where(s => !string.IsNullOrWhiteSpace(s))
                .Distinct()
                .ToList();

            bool hasPortScan = scanTypes.Any(s => s.Contains("TCP") || s.Contains("UDP") || s.Contains("端口"));
            bool hasVulnScan = scanTypes.Any(s => s.Contains("漏洞"));
            bool hasExpertMode = scanTypes.Any(s => s.Contains("专家模式"));

            if (hasExpertMode) features.Add("专家模式");
            if (hasPortScan) features.Add("TCP端口扫描");
            if (hasVulnScan) features.Add("漏洞扫描");

            return features;
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

        private async void Window_Closing(object sender, CancelEventArgs e)
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
                await Task.Delay(500);

                // v7：优雅释放 PluginGovernor（关闭 Kestrel / 沙箱 / 链路 flush）
                try
                {
                    await PluginGovernor.Instance.ShutdownAsync();
                }
                catch (Exception gx)
                {
                    System.Diagnostics.Debug.WriteLine($"[MainWindow] PluginGovernor 关闭失败: {gx.Message}");
                }

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
        /// v5-T4.1: 漏洞结果 DataGrid 右键"🔌 用插件深挖"。
        /// 从选中漏洞行提取目标 IP 与端口，调用 PluginOrchestrator 深挖。
        /// </summary>
        private async void DeepScanWithPlugins_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                var selectedItem = VulnerabilityResultsDataGrid.SelectedItem as VulnerabilityResult;
                if (selectedItem == null)
                {
                    MessageBox.Show("请先选择一条漏洞记录", "提示", MessageBoxButton.OK, MessageBoxImage.Warning);
                    return;
                }

                var targetIp = !string.IsNullOrEmpty(selectedItem.Target)
                    ? selectedItem.Target
                    : TargetIpTextBox?.Text?.Trim();

                if (string.IsNullOrEmpty(targetIp))
                {
                    MessageBox.Show("无法获取目标 IP", "提示", MessageBoxButton.OK, MessageBoxImage.Warning);
                    return;
                }

                var ports = new List<int>();
                if (selectedItem.Port.HasValue && selectedItem.Port.Value > 0) ports.Add(selectedItem.Port.Value);
                var portsDisplay = ports.Count > 0 ? string.Join(",", ports) : "默认";

                var confirm = MessageBox.Show(
                    $"将使用所有适用插件重新扫描 {targetIp} (端口: {portsDisplay})，是否继续？",
                    "插件深挖",
                    MessageBoxButton.YesNo,
                    MessageBoxImage.Question);
                if (confirm != MessageBoxResult.Yes) return;

                Mouse.OverrideCursor = Cursors.Wait;
                var results = await PluginOrchestrator.Instance.ScanTargetAsync(targetIp, ports);
                Mouse.OverrideCursor = null;

                if (results.Count > 0)
                {
                    foreach (var r in results) _vulnerabilityResults.Add(r);
                    MessageBox.Show($"深挖完成：新增 {results.Count} 个漏洞", "完成", MessageBoxButton.OK, MessageBoxImage.Information);
                }
                else
                {
                    MessageBox.Show("深挖完成：未发现新漏洞", "完成", MessageBoxButton.OK, MessageBoxImage.Information);
                }
            }
            catch (Exception ex)
            {
                Mouse.OverrideCursor = null;
                Log($"插件深挖失败: {ex.Message}");
                MessageBox.Show($"深挖失败: {ex.Message}", "错误", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        /// <summary>
        /// v5-T4.3: 扫描历史 DataGrid 右键"🔌 用插件深挖"。
        /// 从选中历史记录提取 IP 与端口，调用 PluginOrchestrator.DeepScanAsync。
        /// </summary>
        private async void DeepScanHistoryWithPlugins_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                var selectedItem = ScanHistoryDataGrid.SelectedItem as ScanHistoryItem;
                if (selectedItem == null)
                {
                    MessageBox.Show("请先选择一条历史记录", "提示", MessageBoxButton.OK, MessageBoxImage.Warning);
                    return;
                }

                var targetIp = selectedItem.TargetIp;
                if (string.IsNullOrEmpty(targetIp))
                {
                    MessageBox.Show("无法获取目标 IP", "提示", MessageBoxButton.OK, MessageBoxImage.Warning);
                    return;
                }

                var confirm = MessageBox.Show(
                    $"将使用所有适用插件深挖 {targetIp} 的历史扫描结果，是否继续？",
                    "插件深挖",
                    MessageBoxButton.YesNo,
                    MessageBoxImage.Question);
                if (confirm != MessageBoxResult.Yes) return;

                Mouse.OverrideCursor = Cursors.Wait;
                var results = await PluginOrchestrator.Instance.DeepScanAsync(selectedItem);
                Mouse.OverrideCursor = null;

                MessageBox.Show(
                    results.Count > 0
                        ? $"深挖完成：发现 {results.Count} 个漏洞"
                        : "深挖完成：未发现新漏洞",
                    "完成",
                    MessageBoxButton.OK,
                    MessageBoxImage.Information);
            }
            catch (Exception ex)
            {
                Mouse.OverrideCursor = null;
                Log($"历史深挖失败: {ex.Message}");
                MessageBox.Show($"深挖失败: {ex.Message}", "错误", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        /// <summary>
        /// v5-T4: 右键 "用插件深挖"。从 DataGridRow 反查 DataGrid 与选中行，
        /// 提取漏洞所属目标的 IP 与端口，通过 PluginOrchestrator.ScanTargetAsync
        /// 触发多插件联合扫描并提示结果。
        /// </summary>
        private async void DeepScanMenuItem_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                if (sender is not System.Windows.Controls.MenuItem menuItem) return;
                if (menuItem.DataContext is not DataGridRow row) return;

                var dataGrid = FindVisualParent<DataGrid>(menuItem);
                if (dataGrid == null || dataGrid.SelectedItem == null) return;
                var selectedItem = dataGrid.SelectedItem;

                string? targetIp = null;
                var ports = new System.Collections.Generic.List<int>();
                var type = selectedItem.GetType();
                var ipProp = type.GetProperty("TargetIp")
                    ?? type.GetProperty("Target")
                    ?? type.GetProperty("Ip")
                    ?? type.GetProperty("IPAddress")
                    ?? type.GetProperty("Host");
                if (ipProp != null) targetIp = ipProp.GetValue(selectedItem)?.ToString();

                var portsProp = type.GetProperty("OpenPorts");
                if (portsProp?.GetValue(selectedItem) is string portsStr && !string.IsNullOrEmpty(portsStr))
                {
                    ports = portsStr.Split(',', StringSplitOptions.RemoveEmptyEntries)
                        .Select(int.Parse)
                        .ToList();
                }
                else
                {
                    var portProp = type.GetProperty("Port") ?? type.GetProperty("PortNumber");
                    if (portProp != null)
                    {
                        var portVal = portProp.GetValue(selectedItem);
                        if (portVal != null) ports.Add(Convert.ToInt32(portVal));
                    }
                }

                if (string.IsNullOrEmpty(targetIp))
                {
                    MessageBox.Show("无法获取目标 IP", "提示", MessageBoxButton.OK, MessageBoxImage.Warning);
                    return;
                }

                var portsDisplay = ports.Count > 0 ? string.Join(",", ports) : "默认";
                var confirm = MessageBox.Show(
                    $"将使用所有适用插件重新扫描 {targetIp} (端口: {portsDisplay})，是否继续？",
                    "插件深挖",
                    MessageBoxButton.YesNo,
                    MessageBoxImage.Question);
                if (confirm != MessageBoxResult.Yes) return;

                Mouse.OverrideCursor = Cursors.Wait;
                var results = await PluginOrchestrator.Instance.ScanTargetAsync(targetIp, ports);
                Mouse.OverrideCursor = null;

                MessageBox.Show(
                    $"深挖完成：发现 {results.Count} 个漏洞",
                    "完成",
                    MessageBoxButton.OK,
                    MessageBoxImage.Information);
            }
            catch (Exception ex)
            {
                Mouse.OverrideCursor = null;
                System.Diagnostics.Debug.WriteLine($"[DeepScanMenuItem] 异常: {ex}");
                MessageBox.Show($"深挖失败: {ex.Message}", "错误", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        /// <summary>
        /// 在可视化树中向上查找指定类型的父元素。
        /// </summary>
        private static T? FindVisualParent<T>(DependencyObject child) where T : DependencyObject
        {
            var parent = System.Windows.Media.VisualTreeHelper.GetParent(child);
            while (parent != null && parent is not T)
                parent = System.Windows.Media.VisualTreeHelper.GetParent(parent);
            return parent as T;
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
                MessageBox.Show($"打开专家模式失败：{ex.Message}\n\n{ex.InnerException?.Message}\n\n{ex.StackTrace}", "错误", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        private void AppScan_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                var appScannerWindow = new Views.AppScannerWindow { Owner = this };
                appScannerWindow.Show();
            }
            catch (Exception ex)
            {
                MessageBox.Show($"打开APP扫描窗口失败：{ex.Message}", "错误", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        private void AgentSecurityScan_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                var agentScannerWindow = new Views.AgentSecurityScannerWindow { Owner = this };
                agentScannerWindow.Show();
            }
            catch (Exception ex)
            {
                MessageBox.Show($"打开Agent安全扫描窗口失败：{ex.Message}", "错误", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        /// <summary>
        /// 1.0.1.0 补齐：扫描 → 摄像头安全扫描（之前 MainWindow 缺少入口菜单）
        /// </summary>
        private void CameraSecurityScan_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                var cameraWindow = new Views.CameraSecurityScannerWindow { Owner = this };
                cameraWindow.Show();
            }
            catch (Exception ex)
            {
                MessageBox.Show($"打开摄像头安全扫描窗口失败：{ex.Message}", "错误", MessageBoxButton.OK, MessageBoxImage.Error);
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

        private void WebPathTracer_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                var tracerWindow = new Views.WebPathTracerWindow { Owner = this };
                tracerWindow.Show();
            }
            catch (Exception ex)
            {
                MessageBox.Show($"打开网页路径追踪窗口失败: {ex.Message}", "错误", MessageBoxButton.OK, MessageBoxImage.Error);
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
                // v1.0.1.2：未登录时弹登录窗
                if (SessionContext.Instance.Current == null)
                {
                    var login = new LoginWindow { Owner = this };
                    if (login.ShowDialog() != true)
                    {
                        return;
                    }
                }

                // v1.0.1.2：登录后无 Asset:View 权限则阻止进入
                var current = SessionContext.Instance.Current;
                if (current == null ||
                    (!current.IsAdmin &&
                     (current.Permissions == null || !current.Permissions.Contains(Permission.AssetView))))
                {
                    MessageBox.Show("无资产管理查看权限", "权限不足", MessageBoxButton.OK, MessageBoxImage.Warning);
                    return;
                }

                var window = new Views.AssetManagementWindow { Owner = this };
                window.ShowDialog();
            }
            catch (Exception ex)
            {
                MessageBox.Show($"打开资产管理窗口失败: {ex.Message}", "错误", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        #endregion

        #region AI 风险评估仪表盘（v2 SOC 风格）

        /// <summary>
        /// 图表中文文本字体：通过 <see cref="CjkFontResolver"/> 解析，
        /// LiveChartsCore 2.x 使用 SkiaSharp 渲染文本，WPF FontFamily 不会被自动继承，
        /// 因此需要显式为所有 SolidColorPaint 指定 Typeface，否则中文字符会显示为方块。
        /// </summary>
        private static readonly SKTypeface _chineseTypeface = CjkFontResolver.Resolved;

        /// <summary>
        /// 创建带中文字体的纯色 Paint（用于图表文字、填充、描边）。
        /// 同时设置 SKTypeface、FontFamily、IsAntialias 三项，避免 LiveChartsCore
        /// 内部重建字体时丢失中文字体。
        /// </summary>
        private static SolidColorPaint CjkPaint(SKColor color, float? strokeThickness = null)
        {
            var paint = new SolidColorPaint(color)
            {
                SKTypeface = _chineseTypeface,
                IsAntialias = true
            };
            // 显式设置 FontFamily 字段，避免 LiveChartsCore 内部重建字体时丢失。
            if (!string.IsNullOrEmpty(_chineseTypeface?.FamilyName))
            {
                paint.FontFamily = _chineseTypeface!.FamilyName;
            }
            if (strokeThickness.HasValue)
            {
                paint.StrokeThickness = strokeThickness.Value;
            }
            return paint;
        }

        /// <summary>
        /// 创建带中文字体的纯色 Paint 重载，允许外部传入 typeface（用于动态切换）。
        /// </summary>
        private static SolidColorPaint CjkPaint(SKColor color, float strokeThickness, SKTypeface? typeface)
        {
            var tf = typeface ?? _chineseTypeface;
            var paint = new SolidColorPaint(color)
            {
                SKTypeface = tf,
                IsAntialias = true
            };
            if (!string.IsNullOrEmpty(tf?.FamilyName))
            {
                paint.FontFamily = tf!.FamilyName;
            }
            paint.StrokeThickness = strokeThickness;
            return paint;
        }

        /// <summary>
        /// 为图表设置 Tooltip 文本与背景的 Paint，使用中文字体避免 CJK 显示为方块。
        /// 兼容 CartesianChart / PieChart / PolarChart（均继承自 LiveChartsCore.SkiaSharpView.WPF.Chart）。
        /// </summary>
        private static void ApplyTooltipPaint(LiveChartsCore.SkiaSharpView.WPF.Chart chart)
        {
            if (chart == null) return;
            var text = CjkPaint(SKColor.Parse("#0F172A"));
            var bg = new SolidColorPaint(new SKColor(255, 255, 255, 230))
            {
                SKTypeface = _chineseTypeface,
                IsAntialias = true
            };
            if (!string.IsNullOrEmpty(_chineseTypeface?.FamilyName))
            {
                bg.FontFamily = _chineseTypeface!.FamilyName;
            }
            try
            {
                chart.TooltipTextPaint = text;
                chart.TooltipBackgroundPaint = bg;
            }
            catch
            {
                // 反射兜底：极少数 Chart 子类的 Paint 属性可能不可写
                var ttp = chart.GetType().GetProperty("TooltipTextPaint");
                if (ttp != null && ttp.CanWrite) ttp.SetValue(chart, text);
                var tbp = chart.GetType().GetProperty("TooltipBackgroundPaint");
                if (tbp != null && tbp.CanWrite) tbp.SetValue(chart, bg);
            }
        }

        /// <summary>
        /// "重新分析" 按钮点击处理。
        /// </summary>
        private async void RefreshAiRiskDashboard_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                var ip = TryGetCurrentTargetIp();
                await RunAiRiskAssessmentAsync(ip);
            }
            catch (Exception ex)
            {
                Log($"AI 风险评估重新分析失败: {ex.Message}");
                UpdateAiRiskDashboardStatus($"分析失败：{ex.Message}", 0, false);
                MessageBox.Show($"AI 风险评估失败: {ex.Message}", "错误", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        /// <summary>
        /// 异步执行 AI 风险评估并更新仪表盘。
        /// </summary>
        /// <param name="ip">可选的目标 IP；为空则尝试从当前 MainWindow 中提取。</param>
        private async Task RunAiRiskAssessmentAsync(string ip = null)
        {
            try
            {
                if (_aiRiskAssessmentService == null)
                {
                    _aiRiskAssessmentService = new AIRiskAssessmentService();
                }

                var targetIp = string.IsNullOrWhiteSpace(ip) ? TryGetCurrentTargetIp() : ip;
                var ports = _portScanResults?.ToList() ?? new List<PortScanResult>();
                var vulns = _vulnerabilityResults?.ToList() ?? new List<VulnerabilityResult>();

                if (ports.Count == 0 && vulns.Count == 0)
                {
                    // 没有扫描数据，保持空状态
                    ShowAiRiskEmptyState();
                    return;
                }

                UpdateAiRiskDashboardStatus("分析中...", 30, true);

                // 在后台线程上调用 V5 引擎，避免阻塞 UI
                var report = await Task.Run(() => _aiRiskAssessmentService.AssessRiskV5Async(ports, vulns, targetIp));

                // 报告返回后切回 UI 线程
                _currentAiReport = report;
                if (this.Dispatcher.CheckAccess())
                {
                    UpdateAiRiskDashboard(report);
                }
                else
                {
                    await this.Dispatcher.InvokeAsync(() => UpdateAiRiskDashboard(report));
                }

                UpdateAiRiskDashboardStatus("分析完成", 100, false);
            }
            catch (Exception ex)
            {
                Log($"AI 风险评估执行失败: {ex.Message}");
                UpdateAiRiskDashboardStatus($"分析失败：{ex.Message}", 0, false);
                // 失败时不抛，避免后台 Task 引发未观察异常
            }
        }

        /// <summary>
        /// 将评估报告渲染到所有仪表盘控件。
        /// </summary>
        private void UpdateAiRiskDashboard(AIRiskAssessmentReportV5 report)
        {
            if (report == null)
            {
                ShowAiRiskEmptyState();
                return;
            }

            // 显示数据区，隐藏空状态
            if (AiRiskDistributionPanel != null) AiRiskDistributionPanel.Visibility = Visibility.Visible;
            if (AiRiskEmptyStatePanel != null) AiRiskEmptyStatePanel.Visibility = Visibility.Collapsed;

            // 主评分
            var score = Math.Max(0, Math.Min(10, report.OverallRiskScore));
            if (AiRiskMainScoreText != null) AiRiskMainScoreText.Text = score.ToString("0.0");

            // 风险等级颜色 + 文字
            var (levelText, levelColor, badgeBgHex) = MapRiskLevel(report.OverallRiskLevel);
            if (AiRiskLevelText != null) AiRiskLevelText.Text = levelText;
            if (AiRiskLevelText != null) AiRiskLevelText.Foreground = new SolidColorBrush((Color)ColorConverter.ConvertFromString(levelColor));
            if (AiRiskMainScoreText != null) AiRiskMainScoreText.Foreground = new SolidColorBrush((Color)ColorConverter.ConvertFromString(levelColor));
            if (AiRiskLevelBadge != null) AiRiskLevelBadge.Background = new SolidColorBrush((Color)ColorConverter.ConvertFromString(badgeBgHex));

            // 目标 IP
            if (AiRiskTargetIpText != null)
                AiRiskTargetIpText.Text = string.IsNullOrWhiteSpace(report.TargetIp) ? "--" : report.TargetIp;

            // 评估时间
            if (AiRiskAssessmentTimeText != null)
                AiRiskAssessmentTimeText.Text = report.AssessmentTime == default
                    ? DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss")
                    : report.AssessmentTime.ToString("yyyy-MM-dd HH:mm:ss");

            // 置信度 / 安全态势 / 就绪度
            if (AiRiskConfidenceText != null) AiRiskConfidenceText.Text = (report.ConfidenceScore * 100).ToString("0.0") + "%";
            if (AiRiskPostureText != null) AiRiskPostureText.Text = (report.SecurityPostureScore).ToString("0.0") + " / 100";
            if (AiRiskReadinessText != null) AiRiskReadinessText.Text = (report.ReadinessScore).ToString("0.0") + " / 100";

            // 四宫格指标
            var openPortCount = report.PortStatistics?.OpenPortsCount ?? 0;
            if (AiRiskOpenPortsCountText != null) AiRiskOpenPortsCountText.Text = openPortCount.ToString();

            var vulnCount = report.VulnerabilityCount > 0
                ? report.VulnerabilityCount
                : (report.RiskItems?.Count ?? 0);
            if (AiRiskVulnCountText != null) AiRiskVulnCountText.Text = vulnCount.ToString();

            var highCveCount = (report.CvssBreakdown?.TotalHighCves ?? 0) + (report.CvssBreakdown?.TotalCriticalCves ?? 0);
            if (AiRiskHighRiskCountText != null) AiRiskHighRiskCountText.Text = highCveCount.ToString();

            // CVE 关联数：取 CvssBreakdown 各类之和
            var cveTotal = (report.CvssBreakdown?.TotalCriticalCves ?? 0)
                           + (report.CvssBreakdown?.TotalHighCves ?? 0)
                           + (report.CvssBreakdown?.TotalMediumCves ?? 0)
                           + (report.CvssBreakdown?.TotalLowCves ?? 0);
            if (AiRiskCveCountText != null) AiRiskCveCountText.Text = cveTotal.ToString();

            // 趋势条：根据各项占最大项的比例（最高 100%）
            // 取各项最大可能值的 80% 作为可视化基准（避免空数据时全部 0%）
            SetBarProgress(AiRiskOpenPortsBar, Math.Min(100, openPortCount * 4.0));        // 25 个端口满量程
            SetBarProgress(AiRiskVulnCountBar, Math.Min(100, vulnCount * 8.0));              // 12 个漏洞满量程
            SetBarProgress(AiRiskHighRiskBar, Math.Min(100, highCveCount * 12.0));          // 8 个高危满量程
            SetBarProgress(AiRiskCveCountBar, Math.Min(100, cveTotal * 6.0));                // 16 个 CVE 满量程

            // 风险等级统计
            int critical = 0, high = 0, medium = 0, low = 0;
            if (report.RiskItems != null)
            {
                foreach (var item in report.RiskItems)
                {
                    switch (item.Level)
                    {
                        case RiskLevelV5.Critical:
                        case RiskLevelV5.Extreme:
                            critical++;
                            break;
                        case RiskLevelV5.High:
                            high++;
                            break;
                        case RiskLevelV5.Medium:
                            medium++;
                            break;
                        case RiskLevelV5.Low:
                        case RiskLevelV5.Safe:
                            low++;
                            break;
                    }
                }
            }
            else
            {
                critical = report.CvssBreakdown?.TotalCriticalCves ?? 0;
                high = report.CvssBreakdown?.TotalHighCves ?? 0;
                medium = report.CvssBreakdown?.TotalMediumCves ?? 0;
                low = report.CvssBreakdown?.TotalLowCves ?? 0;
            }

            if (AiRiskCriticalCountText != null) AiRiskCriticalCountText.Text = critical.ToString();
            if (AiRiskHighCountText != null) AiRiskHighCountText.Text = high.ToString();
            if (AiRiskMediumCountText != null) AiRiskMediumCountText.Text = medium.ToString();
            if (AiRiskLowCountText != null) AiRiskLowCountText.Text = low.ToString();

            var maxDist = Math.Max(1, Math.Max(Math.Max(critical, high), Math.Max(medium, low)));
            SetBarProgress(AiRiskCriticalBar, critical * 100.0 / maxDist);
            SetBarProgress(AiRiskHighBar, high * 100.0 / maxDist);
            SetBarProgress(AiRiskMediumBar, medium * 100.0 / maxDist);
            SetBarProgress(AiRiskLowBar, low * 100.0 / maxDist);

            // 状态文字副标题
            if (AiRiskStatusSubText != null)
            {
                AiRiskStatusSubText.Text = $"目标 {report.TargetIp} · 已分析 {report.RiskItems?.Count ?? 0} 项风险 · 置信度 {(report.ConfidenceScore * 100):0.0}%";
            }

            // 填充所有图表
            try { BuildCveSeverityChart(report); } catch (Exception ex) { System.Diagnostics.Debug.WriteLine($"[AI] CVE 柱状图: {ex.Message}"); }
            try { BuildServiceTypeChart(report); } catch (Exception ex) { System.Diagnostics.Debug.WriteLine($"[AI] 服务饼图: {ex.Message}"); }
            try { BuildDimensionalChart(report); } catch (Exception ex) { System.Diagnostics.Debug.WriteLine($"[AI] 维度雷达: {ex.Message}"); }
            try { BuildRemediationChart(report); } catch (Exception ex) { System.Diagnostics.Debug.WriteLine($"[AI] 修复柱状图: {ex.Message}"); }
            try { BuildCategoryChart(report); } catch (Exception ex) { System.Diagnostics.Debug.WriteLine($"[AI] 类别饼图: {ex.Message}"); }
            try { BuildKillChainChart(report); } catch (Exception ex) { System.Diagnostics.Debug.WriteLine($"[AI] 杀伤链雷达: {ex.Message}"); }
            try { BuildGaugeChart(report); } catch (Exception ex) { System.Diagnostics.Debug.WriteLine($"[AI] 仪表盘: {ex.Message}"); }
            try { BuildKeyFindingsList(report); } catch (Exception ex) { System.Diagnostics.Debug.WriteLine($"[AI] 关键发现: {ex.Message}"); }
        }

        /// <summary>
        /// 构建 CVE 严重度分布柱状图（X = 严重/高危/中危/低危，Y = 数量）
        /// </summary>
        private void BuildCveSeverityChart(AIRiskAssessmentReportV5 report)
        {
            if (AiRiskCveSeverityChart == null) return;
            var cvss = report.CvssBreakdown ?? new CvssBreakdownV5();
            double[] values = new[]
            {
            Math.Max(0.0, cvss.TotalCriticalCves),
            Math.Max(0.0, cvss.TotalHighCves),
            Math.Max(0.0, cvss.TotalMediumCves),
            Math.Max(0.0, cvss.TotalLowCves)
        };
            var series = new ISeries[]
            {
            new ColumnSeries<double>
            {
                Name = "CVE 数",
                Values = values,
                Fill = CjkPaint(SKColor.Parse("#2563EB")),
                Stroke = null,
                MaxBarWidth = 40
            }
            };
            AiRiskCveSeverityChart.Series = series;
            AiRiskCveSeverityChart.XAxes = new[]
            {
            new Axis
            {
                Labels = new[] { "严重", "高危", "中危", "低危" },
                LabelsPaint = CjkPaint(SKColor.Parse("#64748B")),
                TextSize = 12
            }
        };
            AiRiskCveSeverityChart.YAxes = new[]
            {
            new Axis
            {
                MinStep = 1,
                LabelsPaint = CjkPaint(SKColor.Parse("#94A3B8")),
                TextSize = 11,
                ShowSeparatorLines = true,
                SeparatorsPaint = CjkPaint(SKColor.Parse("#E2E8F0"), 1)
            }
        };
            ApplyTooltipPaint(AiRiskCveSeverityChart);
        }

        /// <summary>
        /// 构建服务类型分布饼图（ServiceTypeDistribution）
        /// </summary>
        private void BuildServiceTypeChart(AIRiskAssessmentReportV5 report)
        {
            if (AiRiskServiceTypeChart == null) return;
            var dist = report.PortStatistics?.ServiceTypeDistribution ?? new Dictionary<string, int>();
            var colors = new[]
            {
            SKColor.Parse("#2563EB"), SKColor.Parse("#10B981"), SKColor.Parse("#F59E0B"),
            SKColor.Parse("#EF4444"), SKColor.Parse("#8B5CF6"), SKColor.Parse("#EC4899"),
            SKColor.Parse("#14B8A6"), SKColor.Parse("#F97316"), SKColor.Parse("#6366F1")
        };
            var seriesList = new List<ISeries>();
            if (dist.Count == 0)
            {
                // 数据为 0 时仍显示一个空扇区
                seriesList.Add(new PieSeries<double> { Values = new[] { 0.0001 }, Name = "暂无数据", Fill = CjkPaint(SKColor.Parse("#CBD5E1")) });
            }
            else
            {
                int idx = 0;
                foreach (var kv in dist.OrderByDescending(kv => kv.Value).Take(9))
                {
                    var color = colors[idx % colors.Length];
                    seriesList.Add(new PieSeries<double>
                    {
                        Values = new[] { (double)kv.Value },
                        Name = string.IsNullOrEmpty(kv.Key) ? "未知" : kv.Key,
                        Fill = CjkPaint(color),
                        Stroke = CjkPaint(SKColors.White, 1)
                    });
                    idx++;
                }
            }
            AiRiskServiceTypeChart.Series = seriesList.ToArray();
            AiRiskServiceTypeChart.LegendTextPaint = CjkPaint(SKColor.Parse("#0F172A"));
            ApplyTooltipPaint(AiRiskServiceTypeChart);
        }

        /// <summary>
        /// 构建 10 维评分雷达图
        /// </summary>
        private void BuildDimensionalChart(AIRiskAssessmentReportV5 report)
        {
            if (AiRiskDimensionalChart == null) return;
            var ds = report.DimensionalScores ?? new DimensionalScoresV5();
            double[] values = new[]
            {
            ClampScore(ds.NetworkExposure),
            ClampScore(ds.ServiceVulnerability),
            ClampScore(ds.VulnerabilitySeverity),
            ClampScore(ds.ConfigurationRisk),
            ClampScore(ds.AccessControl),
            ClampScore(ds.DataExposure),
            ClampScore(ds.AuthenticationStrength),
            ClampScore(ds.EncryptionPosture),
            ClampScore(ds.PatchingCadence),
            ClampScore(ds.ComplianceGap)
        };
            var series = new ISeries[]
            {
            new PolarLineSeries<double>
            {
                Values = values,
                Name = "评分",
                Fill = CjkPaint(SKColor.Parse("#2563EB").WithAlpha(40)),
                Stroke = CjkPaint(SKColor.Parse("#2563EB"), 2),
                GeometryFill = CjkPaint(SKColor.Parse("#2563EB")),
                GeometryStroke = CjkPaint(SKColors.White, 1),
                GeometrySize = 8,
                IsClosed = true
            }
            };
            AiRiskDimensionalChart.Series = series;
            // LiveChartsCore 2.0.0-rc2 的 PolarChart 没有可设置的 OuterRadius 属性（只有 InnerRadius 与 Relative* 构造器）。
            // 因此仅通过 Axes 布局来避免标签被裁剪。任务 14 标注的 OuterRadius 在该版本中不存在，已跳过。
            AiRiskDimensionalChart.AngleAxes = new[]
            {
            new PolarAxis
            {
                Labels = new[] { "网络暴露", "服务漏洞", "漏洞严重度", "配置风险", "访问控制", "数据暴露", "认证强度", "加密态势", "补丁节奏", "合规差距" },
                LabelsPaint = CjkPaint(SKColor.Parse("#64748B")),
                TextSize = 13
            }
        };
            AiRiskDimensionalChart.RadiusAxes = new[]
            {
            new PolarAxis
            {
                MinLimit = 0,
                MaxLimit = 10,
                ForceStepToMin = true,
                MinStep = 2,
                LabelsPaint = CjkPaint(SKColor.Parse("#94A3B8")),
                TextSize = 10,
                ShowSeparatorLines = true,
                SeparatorsPaint = CjkPaint(SKColor.Parse("#E2E8F0"), 1)
            }
        };
            ApplyTooltipPaint(AiRiskDimensionalChart);
        }

        /// <summary>
        /// 构建修复优先级柱状图（P0-P4）
        /// </summary>
        private void BuildRemediationChart(AIRiskAssessmentReportV5 report)
        {
            if (AiRiskRemediationChart == null) return;
            var plan = report.RemediationPlan ?? new RemediationPlanV5();
            double[] values = new[]
            {
            Math.Max(0.0, plan.P0ImmediateCount),
            Math.Max(0.0, plan.P1UrgentCount),
            Math.Max(0.0, plan.P2HighCount),
            Math.Max(0.0, plan.P3NormalCount),
            Math.Max(0.0, plan.P4LowCount)
        };
            var colors = new[]
            {
            SKColor.Parse("#DC2626"),
            SKColor.Parse("#EA580C"),
            SKColor.Parse("#D97706"),
            SKColor.Parse("#65A30D"),
            SKColor.Parse("#16A34A")
        };
            var seriesList = new List<ISeries>();
            for (int i = 0; i < values.Length; i++)
            {
                seriesList.Add(new ColumnSeries<double>
                {
                    Name = $"P{i}",
                    Values = new[] { values[i] },
                    Fill = CjkPaint(colors[i]),
                    Stroke = null,
                    MaxBarWidth = 32
                });
            }
            AiRiskRemediationChart.Series = seriesList.ToArray();
            AiRiskRemediationChart.XAxes = new[]
            {
            new Axis
            {
                Labels = new[] { "P0 立即", "P1 紧急", "P2 高", "P3 中", "P4 低" },
                LabelsPaint = CjkPaint(SKColor.Parse("#64748B")),
                TextSize = 12,
                LabelsRotation = -25
            }
        };
            AiRiskRemediationChart.YAxes = new[]
            {
            new Axis
            {
                MinStep = 1,
                LabelsPaint = CjkPaint(SKColor.Parse("#94A3B8")),
                TextSize = 11,
                ShowSeparatorLines = true,
                SeparatorsPaint = CjkPaint(SKColor.Parse("#E2E8F0"), 1)
            }
        };
            ApplyTooltipPaint(AiRiskRemediationChart);
        }

        /// <summary>
        /// 构建风险类别分布饼图（按 RiskItem.Category 聚合）
        /// </summary>
        private void BuildCategoryChart(AIRiskAssessmentReportV5 report)
        {
            if (AiRiskCategoryChart == null) return;
            var group = (report.RiskItems ?? new List<AIRiskItemV5>())
                .GroupBy(it => it.Category)
                .OrderByDescending(g => g.Count())
                .ToList();
            var colors = new[]
            {
            SKColor.Parse("#2563EB"), SKColor.Parse("#10B981"), SKColor.Parse("#F59E0B"),
            SKColor.Parse("#EF4444"), SKColor.Parse("#8B5CF6"), SKColor.Parse("#EC4899"),
            SKColor.Parse("#14B8A6"), SKColor.Parse("#F97316"), SKColor.Parse("#6366F1")
        };
            var seriesList = new List<ISeries>();
            if (group.Count == 0)
            {
                seriesList.Add(new PieSeries<double> { Values = new[] { 0.0001 }, Name = "暂无数据", Fill = CjkPaint(SKColor.Parse("#CBD5E1")) });
            }
            else
            {
                int idx = 0;
                foreach (var g in group.Take(9))
                {
                    var color = colors[idx % colors.Length];
                    seriesList.Add(new PieSeries<double>
                    {
                        Values = new[] { (double)g.Count() },
                        Name = MapCategoryName(g.Key),
                        Fill = CjkPaint(color),
                        Stroke = CjkPaint(SKColors.White, 1)
                    });
                    idx++;
                }
            }
            AiRiskCategoryChart.Series = seriesList.ToArray();
            AiRiskCategoryChart.LegendTextPaint = CjkPaint(SKColor.Parse("#0F172A"));
            ApplyTooltipPaint(AiRiskCategoryChart);
        }

        /// <summary>
        /// 构建杀伤链覆盖度雷达图（KillChain）
        /// </summary>
        private void BuildKillChainChart(AIRiskAssessmentReportV5 report)
        {
            if (AiRiskKillChainChart == null) return;
            var kc = report.AttackChainAnalysis?.KillChain ?? new List<KillChainPhaseV5>();
            // 选取 8 个核心阶段（Reconnaissance, InitialAccess, Execution, PrivilegeEscalation, CredentialAccess, Discovery, LateralMovement, Impact）
            var phaseOrder = new[]
            {
            AttackPhaseV5.Reconnaissance, AttackPhaseV5.InitialAccess, AttackPhaseV5.Execution,
            AttackPhaseV5.PrivilegeEscalation, AttackPhaseV5.CredentialAccess, AttackPhaseV5.Discovery,
            AttackPhaseV5.LateralMovement, AttackPhaseV5.Impact
        };
            var phaseLabels = new[] { "侦察", "初始访问", "执行", "提权", "凭据访问", "发现", "横向移动", "影响" };
            // 构造 values：未覆盖的阶段用 0；覆盖度归一化到 0-10
            var values = new double[phaseOrder.Length];
            var phaseMap = kc.ToDictionary(p => p.Phase, p => p);
            for (int i = 0; i < phaseOrder.Length; i++)
            {
                if (phaseMap.TryGetValue(phaseOrder[i], out var phase))
                {
                    // likelihood 0-1 → 0-10
                    values[i] = Math.Max(0, Math.Min(10, phase.Likelihood * 10));
                }
                else
                {
                    values[i] = 0;
                }
            }
            var series = new ISeries[]
            {
            new PolarLineSeries<double>
            {
                Values = values,
                Name = "覆盖度",
                Fill = CjkPaint(SKColor.Parse("#EA580C").WithAlpha(40)),
                Stroke = CjkPaint(SKColor.Parse("#EA580C"), 2),
                GeometryFill = CjkPaint(SKColor.Parse("#EA580C")),
                GeometryStroke = CjkPaint(SKColors.White, 1),
                GeometrySize = 7,
                IsClosed = true
            }
            };
            AiRiskKillChainChart.Series = series;
            // LiveChartsCore 2.0.0-rc2 的 PolarChart 没有可设置的 OuterRadius 属性（只有 InnerRadius 与 Relative* 构造器）。
            // 因此仅通过 Axes 布局来避免标签被裁剪。任务 14 标注的 OuterRadius 在该版本中不存在，已跳过。
            AiRiskKillChainChart.AngleAxes = new[]
            {
            new PolarAxis
            {
                Labels = phaseLabels,
                LabelsPaint = CjkPaint(SKColor.Parse("#64748B")),
                TextSize = 13
            }
        };
            AiRiskKillChainChart.RadiusAxes = new[]
            {
            new PolarAxis
            {
                MinLimit = 0,
                MaxLimit = 10,
                ForceStepToMin = true,
                MinStep = 2,
                LabelsPaint = CjkPaint(SKColor.Parse("#94A3B8")),
                TextSize = 10,
                ShowSeparatorLines = true,
                SeparatorsPaint = CjkPaint(SKColor.Parse("#E2E8F0"), 1)
            }
        };
            ApplyTooltipPaint(AiRiskKillChainChart);
        }

        /// <summary>
        /// 构建综合风险评分小仪表盘（PieChart 模拟 Gauge）
        /// </summary>
        private void BuildGaugeChart(AIRiskAssessmentReportV5 report)
        {
            if (AiRiskGaugeChart == null) return;
            var score = Math.Max(0, Math.Min(10, report.OverallRiskScore));
            // 仪表盘 = 实际值 + 剩余（10-score）
            double actual = score;
            double remaining = Math.Max(0, 10 - score);
            var (levelText, levelColor, _) = MapRiskLevel(report.OverallRiskLevel);
            SKColor mainColor = SKColor.Parse(levelColor);
            var series = new ISeries[]
            {
            new PieSeries<double>
            {
                Values = new[] { actual },
                Name = "已用",
                Fill = CjkPaint(mainColor),
                Stroke = null,
                InnerRadius = 28,
                Pushout = 0,
                MaxRadialColumnWidth = 18
            },
            new PieSeries<double>
            {
                Values = new[] { remaining },
                Name = "剩余",
                Fill = CjkPaint(SKColor.Parse("#E2E8F0")),
                Stroke = null,
                InnerRadius = 28,
                Pushout = 0,
                MaxRadialColumnWidth = 18
            }
            };
            AiRiskGaugeChart.Series = series;
            AiRiskGaugeChart.InitialRotation = 135;
            AiRiskGaugeChart.MaxAngle = 270;
            ApplyTooltipPaint(AiRiskGaugeChart);
        }

        /// <summary>
        /// 填充关键发现列表（最多 8 条）
        /// </summary>
        private void BuildKeyFindingsList(AIRiskAssessmentReportV5 report)
        {
            if (AiRiskKeyFindingsList == null) return;
            var items = new List<string>();
            if (report.KeyFindingsSummary != null && report.KeyFindingsSummary.Count > 0)
            {
                items.AddRange(report.KeyFindingsSummary.Where(s => !string.IsNullOrWhiteSpace(s)).Take(8));
            }
            // 退化逻辑：基于 TopRiskScenarios / NarrativeThreatOverview
            if (items.Count == 0)
            {
                var top = report.AttackChainAnalysis?.TopRiskScenarios;
                if (top != null && top.Count > 0)
                {
                    items.AddRange(top.Where(s => !string.IsNullOrWhiteSpace(s)).Take(8));
                }
            }
            if (items.Count == 0 && !string.IsNullOrWhiteSpace(report.ExecutiveSummary))
            {
                items.Add(report.ExecutiveSummary);
            }
            if (items.Count == 0)
            {
                items.Add("暂无关键发现");
            }
            AiRiskKeyFindingsList.ItemsSource = items;
        }

        /// <summary>
        /// 将任意评分裁剪到 0-10。
        /// </summary>
        private static double ClampScore(double v)
        {
            if (double.IsNaN(v) || double.IsInfinity(v)) return 0;
            return Math.Max(0, Math.Min(10, v));
        }

        /// <summary>
        /// 将 RiskItemCategoryV5 翻译为中文。
        /// </summary>
        private static string MapCategoryName(RiskItemCategoryV5 c)
        {
            switch (c)
            {
                case RiskItemCategoryV5.PortExposure: return "端口暴露";
                case RiskItemCategoryV5.ServiceVulnerability: return "服务漏洞";
                case RiskItemCategoryV5.CveVulnerability: return "CVE 漏洞";
                case RiskItemCategoryV5.ConfigurationRisk: return "配置风险";
                case RiskItemCategoryV5.AccessControl: return "访问控制";
                case RiskItemCategoryV5.DataExposure: return "数据暴露";
                case RiskItemCategoryV5.AttackVector: return "攻击向量";
                case RiskItemCategoryV5.RiskPattern: return "风险模式";
                case RiskItemCategoryV5.Compliance: return "合规";
                default: return c.ToString();
            }
        }

        /// <summary>
        /// 更新状态条文字 + 进度 + 按钮可用性。
        /// </summary>
        private void UpdateAiRiskDashboardStatus(string status, int progress, bool isRunning)
        {
            if (this.Dispatcher.CheckAccess())
            {
                if (AiRiskStatusText != null) AiRiskStatusText.Text = status ?? string.Empty;
                if (AiRiskProgressBar != null) AiRiskProgressBar.Value = Math.Max(0, Math.Min(100, progress));
                if (AiRiskRefreshButton != null) AiRiskRefreshButton.IsEnabled = !isRunning;
            }
            else
            {
                this.Dispatcher.Invoke(() =>
                {
                    if (AiRiskStatusText != null) AiRiskStatusText.Text = status ?? string.Empty;
                    if (AiRiskProgressBar != null) AiRiskProgressBar.Value = Math.Max(0, Math.Min(100, progress));
                    if (AiRiskRefreshButton != null) AiRiskRefreshButton.IsEnabled = !isRunning;
                });
            }
        }

        /// <summary>
        /// 显示空状态提示，隐藏所有数据卡片。
        /// </summary>
        private void ShowAiRiskEmptyState()
        {
            if (this.Dispatcher.CheckAccess())
            {
                ShowAiRiskEmptyStateCore();
            }
            else
            {
                this.Dispatcher.Invoke(ShowAiRiskEmptyStateCore);
            }
        }

        private void ShowAiRiskEmptyStateCore()
        {
            // 隐藏数据区
            if (AiRiskDistributionPanel != null) AiRiskDistributionPanel.Visibility = Visibility.Collapsed;

            // 显示空状态
            if (AiRiskEmptyStatePanel != null) AiRiskEmptyStatePanel.Visibility = Visibility.Visible;

            // 重置状态条
            if (AiRiskStatusText != null) AiRiskStatusText.Text = "就绪";
            if (AiRiskStatusSubText != null) AiRiskStatusSubText.Text = "等待扫描数据";
            if (AiRiskProgressBar != null) AiRiskProgressBar.Value = 0;
            if (AiRiskRefreshButton != null) AiRiskRefreshButton.IsEnabled = false;

            // 重置主评分区
            if (AiRiskMainScoreText != null) AiRiskMainScoreText.Text = "0.0";
            if (AiRiskMainScoreText != null) AiRiskMainScoreText.Foreground = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#16A34A"));
            if (AiRiskLevelText != null) AiRiskLevelText.Text = "无风险";
            if (AiRiskLevelText != null) AiRiskLevelText.Foreground = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#16A34A"));
            if (AiRiskLevelBadge != null) AiRiskLevelBadge.Background = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#F0FDF4"));
            if (AiRiskTargetIpText != null) AiRiskTargetIpText.Text = "--";
            if (AiRiskAssessmentTimeText != null) AiRiskAssessmentTimeText.Text = "--";
            if (AiRiskConfidenceText != null) AiRiskConfidenceText.Text = "--";
            if (AiRiskPostureText != null) AiRiskPostureText.Text = "--";
            if (AiRiskReadinessText != null) AiRiskReadinessText.Text = "--";

            // 重置四宫格
            if (AiRiskOpenPortsCountText != null) AiRiskOpenPortsCountText.Text = "0";
            if (AiRiskVulnCountText != null) AiRiskVulnCountText.Text = "0";
            if (AiRiskHighRiskCountText != null) AiRiskHighRiskCountText.Text = "0";
            if (AiRiskCveCountText != null) AiRiskCveCountText.Text = "0";
            SetBarProgress(AiRiskOpenPortsBar, 0);
            SetBarProgress(AiRiskVulnCountBar, 0);
            SetBarProgress(AiRiskHighRiskBar, 0);
            SetBarProgress(AiRiskCveCountBar, 0);

            // 重置分布条
            if (AiRiskCriticalCountText != null) AiRiskCriticalCountText.Text = "0";
            if (AiRiskHighCountText != null) AiRiskHighCountText.Text = "0";
            if (AiRiskMediumCountText != null) AiRiskMediumCountText.Text = "0";
            if (AiRiskLowCountText != null) AiRiskLowCountText.Text = "0";
            SetBarProgress(AiRiskCriticalBar, 0);
            SetBarProgress(AiRiskHighBar, 0);
            SetBarProgress(AiRiskMediumBar, 0);
            SetBarProgress(AiRiskLowBar, 0);

            // 清空所有图表
            try { if (AiRiskCveSeverityChart != null) AiRiskCveSeverityChart.Series = new ISeries[0]; } catch { }
            try { if (AiRiskServiceTypeChart != null) AiRiskServiceTypeChart.Series = new ISeries[0]; } catch { }
            try { if (AiRiskDimensionalChart != null) AiRiskDimensionalChart.Series = new ISeries[0]; } catch { }
            try { if (AiRiskRemediationChart != null) AiRiskRemediationChart.Series = new ISeries[0]; } catch { }
            try { if (AiRiskCategoryChart != null) AiRiskCategoryChart.Series = new ISeries[0]; } catch { }
            try { if (AiRiskKillChainChart != null) AiRiskKillChainChart.Series = new ISeries[0]; } catch { }
            try { if (AiRiskGaugeChart != null) AiRiskGaugeChart.Series = new ISeries[0]; } catch { }
            try { if (AiRiskKeyFindingsList != null) AiRiskKeyFindingsList.ItemsSource = null; } catch { }
        }

        /// <summary>
        /// 将任意非负数值以"占 100"的方式写入 ProgressBar。
        /// </summary>
        private void SetBarProgress(ProgressBar bar, double value)
        {
            if (bar == null) return;
            if (this.Dispatcher.CheckAccess())
            {
                bar.Value = Math.Max(0, Math.Min(100, value));
            }
            else
            {
                this.Dispatcher.Invoke(() => bar.Value = Math.Max(0, Math.Min(100, value)));
            }
        }

        /// <summary>
        /// 将 RiskLevelV5 映射为中文文字 + 主色 + 徽章背景。
        /// </summary>
        private static (string Text, string ColorHex, string BadgeBgHex) MapRiskLevel(RiskLevelV5 level)
        {
            switch (level)
            {
                case RiskLevelV5.Safe: return ("无风险", "#16A34A", "#F0FDF4");
                case RiskLevelV5.Low: return ("低风险", "#65A30D", "#F7FEE7");
                case RiskLevelV5.Medium: return ("中风险", "#D97706", "#FFFBEB");
                case RiskLevelV5.High: return ("高风险", "#EA580C", "#FFF7ED");
                case RiskLevelV5.Critical: return ("严重风险", "#DC2626", "#FEF2F2");
                case RiskLevelV5.Extreme: return ("极严重", "#DC2626", "#FEF2F2");
                default: return ("无风险", "#16A34A", "#F0FDF4");
            }
        }

        /// <summary>
        /// 尝试从主窗口当前输入控件中获取目标 IP；找不到则返回 null。
        /// </summary>
        private string TryGetCurrentTargetIp()
        {
            try
            {
                var tb = this.FindName("TargetIpTextBox") as TextBox;
                if (tb != null && !string.IsNullOrWhiteSpace(tb.Text)) return tb.Text.Trim();

                // 兜底：使用最近一次扫描结果中的 IP
                if (_portScanResults != null && _portScanResults.Count > 0)
                {
                    var ip = _portScanResults[0].TargetIp;
                    if (!string.IsNullOrWhiteSpace(ip)) return ip;
                }
                if (_vulnerabilityResults != null && _vulnerabilityResults.Count > 0)
                {
                    var ip = _vulnerabilityResults[0].Target;
                    if (!string.IsNullOrWhiteSpace(ip)) return ip;
                }
            }
            catch
            {
                // 静默，返回 null
            }
            return null;
        }

        #endregion

    }
}