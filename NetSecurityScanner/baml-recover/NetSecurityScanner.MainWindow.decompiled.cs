using System;
using System.CodeDom.Compiler;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.NetworkInformation;
using System.Reflection;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Input;
using System.Windows.Markup;
using System.Windows.Media;
using System.Windows.Threading;
using LiveChartsCore;
using LiveChartsCore.Drawing;
using LiveChartsCore.Kernel.Sketches;
using LiveChartsCore.Measure;
using LiveChartsCore.SkiaSharpView;
using LiveChartsCore.SkiaSharpView.Drawing;
using LiveChartsCore.SkiaSharpView.Drawing.Geometries;
using LiveChartsCore.SkiaSharpView.Painting;
using LiveChartsCore.SkiaSharpView.WPF;
using Microsoft.Win32;
using NetSecurityScanner.Desktop.Views;
using NetSecurityScanner.Models;
using NetSecurityScanner.Plugins;
using NetSecurityScanner.Services;
using NetSecurityScanner.Utils;
using NetSecurityScanner.Views;
using OxyPlot;
using OxyPlot.Axes;
using OxyPlot.Series;
using SkiaSharp;
using iTextSharp.text;
using iTextSharp.text.pdf;

namespace NetSecurityScanner;

public class MainWindow : Window, INotifyPropertyChanged, IDisposable, IComponentConnector, IStyleConnector
{
	private PortScanner _portScanner;

	private VulnerabilityScanner _vulnerabilityScanner;

	private RiskAssessmentService _riskAssessmentService;

	private PortManagementService _portManagementService;

	private JsonDatabaseService _jsonDatabaseService;

	private ObservableCollection<PortScanResult> _portScanResults;

	private ObservableCollection<VulnerabilityResult> _vulnerabilityResults;

	private ObservableCollection<RiskAssessmentItem> _riskAssessmentItems;

	private RiskAssessmentResult _riskAssessmentResult;

	private CancellationTokenSource _cancellationTokenSource;

	private DispatcherTimer _systemUptimeTimer;

	private DateTime? _lastScanTime;

	private PerformanceCounter _cpuCounter;

	private PerformanceCounter _ramCounter;

	private DispatcherTimer _systemHealthTimer;

	private DateTime _systemStartTime;

	private UiUpdateThrottler _uiUpdateThrottler;

	private ScanPerformanceMonitor _scanPerformanceMonitor;

	private bool _isPdfGenerating;

	private const int UI_UPDATE_INTERVAL_MS = 500;

	private const int MAX_DISPLAY_RESULTS = 1000;

	private PlotModel _riskDistributionModel;

	private bool _disposed;

	internal MenuItem PluginScanMenuItem;

	internal TabControl MainTabControl;

	internal TextBox TargetIpTextBox;

	internal TextBox PortRangeTextBox;

	internal ComboBox ScanTypeComboBox;

	internal Button StartPortScanButton;

	internal Button StopPortScanButton;

	internal CheckBox AutoScanCheckBox;

	internal DataGrid PortScanResultsDataGrid;

	internal Button GeneratePortBatButton;

	internal TextBlock ScanProgressText;

	internal ProgressBar ScanProgressBar;

	internal TextBox VulnTargetTextBox;

	internal Button StartVulnScanButton;

	internal Button StopVulnScanButton;

	internal TextBlock VulnScanProgressText;

	internal TextBlock VulnScanProgressPercent;

	internal ProgressBar VulnScanProgressBar;

	internal TextBlock VulnScanCurrentStage;

	internal DataGrid VulnerabilityResultsDataGrid;

	internal TextBlock AssessmentDateText;

	internal ProgressBar AiAnalysisProgressBar;

	internal TextBlock AiAnalysisStatusText;

	internal Button RefreshAiAnalysisButton;

	internal TextBlock AiAnalysisSubStatusText;

	internal TextBlock OverallRiskText;

	internal TextBlock RiskScoreText;

	internal Border RiskProgressBar;

	internal TextBlock TargetIpText;

	internal TextBlock AssessmentTimeText;

	internal TextBlock TotalVulnerabilitiesText;

	internal TextBlock HighRiskCountText;

	internal TextBlock OpenPortsCountText;

	internal TextBlock SensitivePortsText;

	internal PieChart RiskDistributionPieChart;

	internal CartesianChart RiskDistributionBarChart;

	internal DataGrid VulnerabilityDetailsDataGrid;

	internal Button GeneratePortBatFromAiButton;

	internal DataGrid OpenPortsDataGrid;

	internal TextBlock SecurityAdviceText;

	internal TextBlock RiskAssessmentSummaryText;

	internal TextBox SearchTextBox;

	internal ComboBox RiskLevelFilterComboBox;

	internal ComboBox ScanTypeFilterComboBox;

	internal Button GenerateReportFromHistoryButton;

	internal DataGrid ScanHistoryDataGrid;

	internal TextBlock ScanHistoryStats;

	internal TextBlock ScanHistorySummary;

	internal TextBlock LicenseStatusBarText;

	internal TextBlock StatusTextBlock;

	internal TextBlock SystemUptimeText;

	internal TextBlock CpuUsageTextBlock;

	internal TextBlock RamUsageTextBlock;

	internal TextBlock DiskUsageTextBlock;

	internal TextBlock NetworkConnectionsTextBlock;

	internal TextBlock SystemHealthText;

	internal TextBlock StatusVersionText;

	private bool _contentLoaded;

	public PlotModel RiskDistributionModel
	{
		get
		{
			return _riskDistributionModel;
		}
		set
		{
			_riskDistributionModel = value;
			OnPropertyChanged("RiskDistributionModel");
		}
	}

	public event PropertyChangedEventHandler? PropertyChanged;

	public MainWindow()
	{
		//IL_007d: Unknown result type (might be due to invalid IL or missing references)
		//IL_0082: Unknown result type (might be due to invalid IL or missing references)
		//IL_0096: Unknown result type (might be due to invalid IL or missing references)
		//IL_00e0: Unknown result type (might be due to invalid IL or missing references)
		//IL_00ea: Expected O, but got Unknown
		//IL_0167: Unknown result type (might be due to invalid IL or missing references)
		//IL_0171: Expected O, but got Unknown
		try
		{
			Log("开始MainWindow构造函数");
			InitializeComponent();
			Log("InitializeComponent完成");
			try
			{
				Version version = Assembly.GetExecutingAssembly().GetName().Version;
				if (StatusVersionText != null && version != null)
				{
					StatusVersionText.Text = $"NetSecurityScanner v{version}";
				}
			}
			catch
			{
			}
			UpdateLicenseStatusBar();
			DispatcherTimer val = new DispatcherTimer
			{
				Interval = TimeSpan.FromSeconds(30.0)
			};
			val.Tick += LicenseTimer_Tick;
			val.Start();
			InitializeServices();
			Log("InitializeServices完成");
			_portScanResults = new ObservableCollection<PortScanResult>();
			_vulnerabilityResults = new ObservableCollection<VulnerabilityResult>();
			_riskAssessmentItems = new ObservableCollection<RiskAssessmentItem>();
			_riskAssessmentResult = new RiskAssessmentResult();
			PortScanResultsDataGrid.ItemsSource = _portScanResults;
			PortScanResultsDataGrid.ItemContainerGenerator.StatusChanged += PortScanResultsDataGrid_ItemContainerGenerator_StatusChanged;
			VulnerabilityResultsDataGrid.ItemsSource = _vulnerabilityResults;
			VulnerabilityDetailsDataGrid.ItemsSource = _riskAssessmentResult.VulnerabilityDetails;
			OpenPortsDataGrid.ItemsSource = _riskAssessmentResult.OpenPorts;
			base.DataContext = this;
			_systemStartTime = DateTime.Now;
			_systemUptimeTimer = new DispatcherTimer();
			_systemUptimeTimer.Interval = TimeSpan.FromSeconds(1.0);
			_systemUptimeTimer.Tick += SystemUptimeTimer_Tick;
			_systemUptimeTimer.Start();
			StatusVersionText.Text = "NetSecurityScanner v" + VersionHelper.GetVersion();
			InitializeSystemPerformanceCounters();
			InitializePerformanceOptimizers();
			base.Loaded += MainWindow_Loaded;
			Log("MainWindow构造函数完成");
			Task.Run(async delegate
			{
				_ = 2;
				try
				{
					await PluginOrchestrator.Instance.InitializeAsync(default(CancellationToken));
					try
					{
						PluginManager pm = new PluginManager();
						await pm.LoadAllPluginsAsync();
						await PluginGovernor.Instance.InitializeAsync(pm, PluginOrchestrator.Instance, "1.0.1.0");
						Log("PluginGovernor 初始化完成");
					}
					catch (Exception)
					{
					}
				}
				catch (Exception)
				{
				}
			});
		}
		catch (Exception ex)
		{
			Log("MainWindow初始化失败: " + ex.Message);
			Log("异常堆栈: " + ex.StackTrace);
			if (ex.InnerException != null)
			{
				Log("内部异常: " + ex.InnerException.Message);
				Log("内部异常堆栈: " + ex.InnerException.StackTrace);
			}
			MessageBox.Show("初始化失败: " + ex.Message, "错误", MessageBoxButton.OK, MessageBoxImage.Hand);
		}
	}

	private void MainWindow_Loaded(object sender, RoutedEventArgs e)
	{
		try
		{
			Log("MainWindow_Loaded事件触发");
			if (base.Left < 0.0)
			{
				base.Left = 0.0;
			}
			if (base.Top < 0.0)
			{
				base.Top = 0.0;
			}
			if (base.Left > SystemParameters.VirtualScreenWidth - base.Width)
			{
				base.Left = SystemParameters.VirtualScreenWidth - base.Width;
			}
			if (base.Top > SystemParameters.VirtualScreenHeight - base.Height)
			{
				base.Top = SystemParameters.VirtualScreenHeight - base.Height;
			}
			Task.Run(async delegate
			{
				try
				{
					await RefreshScanHistoryAsync();
				}
				catch (Exception ex4)
				{
					Exception ex3 = ex4;
					await ((DispatcherObject)this).Dispatcher.InvokeAsync((Action)delegate
					{
						Log("后台刷新扫描历史记录失败: " + ex3.Message);
					});
				}
			});
			((DispatcherObject)this).Dispatcher.BeginInvoke((Delegate)(Action)async delegate
			{
				try
				{
					await InitializeCharts();
					StartSystemHealthUpdates();
				}
				catch (Exception ex2)
				{
					Log("图表初始化失败: " + ex2.Message);
				}
			}, Array.Empty<object>());
			Log("MainWindow_Loaded事件处理完成");
		}
		catch (Exception ex)
		{
			Log("MainWindow_Loaded处理失败: " + ex.Message);
			Log("异常堆栈: " + ex.StackTrace);
			if (ex.InnerException != null)
			{
				Log("内部异常: " + ex.InnerException.Message);
				Log("内部异常堆栈: " + ex.InnerException.StackTrace);
			}
			MessageBox.Show("窗口加载失败: " + ex.Message, "错误", MessageBoxButton.OK, MessageBoxImage.Hand);
		}
	}

	private async Task InitializeCharts()
	{
		try
		{
			Log("开始初始化图表");
			InitializeRiskDistributionChart();
			Log("图表初始化完成");
		}
		catch (Exception ex)
		{
			Log("图表初始化失败: " + ex.Message);
			Log("异常堆栈: " + ex.StackTrace);
		}
	}

	private void InitializePerformanceOptimizers()
	{
		//IL_005c: Unknown result type (might be due to invalid IL or missing references)
		//IL_0066: Expected O, but got Unknown
		try
		{
			Log("开始初始化性能优化组件");
			_uiUpdateThrottler = new UiUpdateThrottler(((DispatcherObject)this).Dispatcher);
			Log($"UI节流器初始化成功，更新间隔: {500}ms");
			_scanPerformanceMonitor = new ScanPerformanceMonitor();
			Log("扫描性能监控器初始化成功");
			_isPdfGenerating = false;
			Log("性能优化组件初始化完成");
		}
		catch (Exception ex)
		{
			Log("性能优化组件初始化失败: " + ex.Message);
			Log("异常堆栈: " + ex.StackTrace);
		}
	}

	private void InitializeRiskDistributionChart()
	{
		//IL_0001: Unknown result type (might be due to invalid IL or missing references)
		//IL_0006: Unknown result type (might be due to invalid IL or missing references)
		//IL_0016: Expected O, but got Unknown
		//IL_0021: Unknown result type (might be due to invalid IL or missing references)
		//IL_0026: Unknown result type (might be due to invalid IL or missing references)
		//IL_002d: Unknown result type (might be due to invalid IL or missing references)
		//IL_003d: Expected O, but got Unknown
		//IL_0048: Unknown result type (might be due to invalid IL or missing references)
		//IL_004d: Unknown result type (might be due to invalid IL or missing references)
		//IL_0054: Unknown result type (might be due to invalid IL or missing references)
		//IL_005f: Unknown result type (might be due to invalid IL or missing references)
		//IL_0073: Expected O, but got Unknown
		//IL_0073: Unknown result type (might be due to invalid IL or missing references)
		//IL_0078: Unknown result type (might be due to invalid IL or missing references)
		//IL_0083: Unknown result type (might be due to invalid IL or missing references)
		//IL_0084: Unknown result type (might be due to invalid IL or missing references)
		//IL_008f: Expected O, but got Unknown
		try
		{
			RiskDistributionModel = new PlotModel
			{
				Title = "风险分布"
			};
			RiskDistributionModel.Axes.Add((Axis)new CategoryAxis
			{
				Position = (AxisPosition)1,
				Title = "风险等级"
			});
			RiskDistributionModel.Axes.Add((Axis)new LinearAxis
			{
				Position = (AxisPosition)4,
				Title = "数量",
				Minimum = 0.0
			});
			BarSeries val = new BarSeries
			{
				Title = "漏洞数量",
				FillColor = OxyColors.SkyBlue
			};
			RiskDistributionModel.Series.Add((Series)(object)val);
		}
		catch (Exception ex)
		{
			Log("初始化风险分布图表失败: " + ex.Message);
		}
	}

	private void UpdateRiskDistributionChart()
	{
		//IL_001e: Unknown result type (might be due to invalid IL or missing references)
		//IL_0023: Unknown result type (might be due to invalid IL or missing references)
		//IL_002f: Expected O, but got Unknown
		//IL_008f: Unknown result type (might be due to invalid IL or missing references)
		//IL_0094: Unknown result type (might be due to invalid IL or missing references)
		//IL_00ba: Unknown result type (might be due to invalid IL or missing references)
		//IL_00bc: Unknown result type (might be due to invalid IL or missing references)
		//IL_00c3: Unknown result type (might be due to invalid IL or missing references)
		//IL_00c8: Unknown result type (might be due to invalid IL or missing references)
		//IL_00d5: Unknown result type (might be due to invalid IL or missing references)
		//IL_00d6: Unknown result type (might be due to invalid IL or missing references)
		//IL_00e1: Expected O, but got Unknown
		//IL_0098: Unknown result type (might be due to invalid IL or missing references)
		//IL_009d: Unknown result type (might be due to invalid IL or missing references)
		//IL_00a1: Unknown result type (might be due to invalid IL or missing references)
		//IL_00a6: Unknown result type (might be due to invalid IL or missing references)
		//IL_00aa: Unknown result type (might be due to invalid IL or missing references)
		//IL_00af: Unknown result type (might be due to invalid IL or missing references)
		//IL_00b3: Unknown result type (might be due to invalid IL or missing references)
		//IL_00b8: Unknown result type (might be due to invalid IL or missing references)
		try
		{
			if (RiskDistributionModel == null)
			{
				InitializeRiskDistributionChart();
			}
			RiskDistributionModel.Series.Clear();
			BarSeries val = new BarSeries
			{
				Title = "漏洞数量"
			};
			foreach (RiskCategory item in _riskAssessmentResult.RiskDistribution)
			{
				OxyColor color = (OxyColor)(item.Category switch
				{
					"高" => OxyColors.Red, 
					"中" => OxyColors.Orange, 
					"低" => OxyColors.Yellow, 
					"无风险" => OxyColors.Green, 
					_ => OxyColors.SkyBlue, 
				});
				((BarSeriesBase<BarItem>)(object)val).Items.Add(new BarItem
				{
					Value = item.Count,
					Color = color
				});
			}
			RiskDistributionModel.Series.Add((Series)(object)val);
			RiskDistributionModel.InvalidatePlot(true);
		}
		catch (Exception ex)
		{
			Log("更新风险分布图表失败: " + ex.Message);
		}
	}

	private void UpdateRiskDistributionPieChart()
	{
		//IL_006e: Unknown result type (might be due to invalid IL or missing references)
		//IL_0073: Unknown result type (might be due to invalid IL or missing references)
		//IL_0078: Unknown result type (might be due to invalid IL or missing references)
		//IL_0080: Expected O, but got Unknown
		//IL_00f0: Unknown result type (might be due to invalid IL or missing references)
		//IL_00f5: Unknown result type (might be due to invalid IL or missing references)
		//IL_015c: Unknown result type (might be due to invalid IL or missing references)
		//IL_015e: Unknown result type (might be due to invalid IL or missing references)
		//IL_018f: Unknown result type (might be due to invalid IL or missing references)
		//IL_0191: Unknown result type (might be due to invalid IL or missing references)
		//IL_019b: Expected O, but got Unknown
		//IL_01ac: Unknown result type (might be due to invalid IL or missing references)
		//IL_01b1: Unknown result type (might be due to invalid IL or missing references)
		//IL_01b6: Unknown result type (might be due to invalid IL or missing references)
		//IL_01c2: Expected O, but got Unknown
		//IL_0102: Unknown result type (might be due to invalid IL or missing references)
		//IL_0107: Unknown result type (might be due to invalid IL or missing references)
		//IL_0116: Unknown result type (might be due to invalid IL or missing references)
		//IL_011b: Unknown result type (might be due to invalid IL or missing references)
		//IL_0128: Unknown result type (might be due to invalid IL or missing references)
		//IL_012d: Unknown result type (might be due to invalid IL or missing references)
		//IL_013d: Unknown result type (might be due to invalid IL or missing references)
		//IL_0142: Unknown result type (might be due to invalid IL or missing references)
		//IL_0155: Unknown result type (might be due to invalid IL or missing references)
		//IL_015a: Unknown result type (might be due to invalid IL or missing references)
		try
		{
			if (_riskAssessmentResult == null || _riskAssessmentResult.RiskDistribution == null)
			{
				return;
			}
			List<RiskCategory> list = _riskAssessmentResult.RiskDistribution.Where((RiskCategory r) => r.Count > 0).ToList();
			if (!list.Any())
			{
				return;
			}
			List<PieSeries<int>> list2 = new List<PieSeries<int>>();
			string fontFamily = "Microsoft YaHei";
			SolidColorPaint legendTextPaint = new SolidColorPaint(new SKColor((byte)51, (byte)51, (byte)51))
			{
				FontFamily = fontFamily
			};
			foreach (RiskCategory item in list)
			{
				SKColor val = (SKColor)(item.Category switch
				{
					"严重" => new SKColor(byte.MaxValue, (byte)65, (byte)108), 
					"高" => new SKColor(byte.MaxValue, (byte)107, (byte)74), 
					"中" => new SKColor(byte.MaxValue, (byte)165, (byte)2), 
					"低" => new SKColor((byte)46, (byte)213, (byte)115), 
					"无风险" => new SKColor((byte)112, (byte)161, byte.MaxValue), 
					_ => new SKColor((byte)192, (byte)192, (byte)192), 
				});
				list2.Add(new PieSeries<int>
				{
					Name = item.Category,
					Values = new int[1] { item.Count },
					Fill = (IPaint<SkiaSharpDrawingContext>)new SolidColorPaint(val),
					DataLabelsPaint = (IPaint<SkiaSharpDrawingContext>)new SolidColorPaint(new SKColor(byte.MaxValue, byte.MaxValue, byte.MaxValue))
					{
						FontFamily = fontFamily
					},
					DataLabelsSize = 14.0,
					DataLabelsPosition = (PolarLabelsPosition)3,
					InnerRadius = 50.0
				});
			}
			RiskDistributionPieChart.Series = (IEnumerable<ISeries>)list2;
			((Chart)RiskDistributionPieChart).LegendTextPaint = (IPaint<SkiaSharpDrawingContext>)(object)legendTextPaint;
		}
		catch (Exception ex)
		{
			Log("更新风险分布饼图失败: " + ex.Message);
		}
	}

	private void UpdateRiskDistributionBarChart()
	{
		//IL_00de: Unknown result type (might be due to invalid IL or missing references)
		//IL_00e3: Unknown result type (might be due to invalid IL or missing references)
		//IL_01ea: Unknown result type (might be due to invalid IL or missing references)
		//IL_01ef: Unknown result type (might be due to invalid IL or missing references)
		//IL_01f6: Expected O, but got Unknown
		//IL_01f6: Unknown result type (might be due to invalid IL or missing references)
		//IL_0205: Expected O, but got Unknown
		//IL_0205: Unknown result type (might be due to invalid IL or missing references)
		//IL_0215: Unknown result type (might be due to invalid IL or missing references)
		//IL_021a: Unknown result type (might be due to invalid IL or missing references)
		//IL_0224: Expected O, but got Unknown
		//IL_0224: Expected O, but got Unknown
		//IL_0224: Unknown result type (might be due to invalid IL or missing references)
		//IL_0233: Expected O, but got Unknown
		//IL_0233: Unknown result type (might be due to invalid IL or missing references)
		//IL_023a: Unknown result type (might be due to invalid IL or missing references)
		//IL_023f: Unknown result type (might be due to invalid IL or missing references)
		//IL_0244: Unknown result type (might be due to invalid IL or missing references)
		//IL_0250: Expected O, but got Unknown
		//IL_0250: Expected O, but got Unknown
		//IL_0251: Expected O, but got Unknown
		//IL_0264: Unknown result type (might be due to invalid IL or missing references)
		//IL_0269: Unknown result type (might be due to invalid IL or missing references)
		//IL_0278: Expected O, but got Unknown
		//IL_0278: Unknown result type (might be due to invalid IL or missing references)
		//IL_0288: Unknown result type (might be due to invalid IL or missing references)
		//IL_028d: Unknown result type (might be due to invalid IL or missing references)
		//IL_0297: Expected O, but got Unknown
		//IL_0297: Expected O, but got Unknown
		//IL_0297: Unknown result type (might be due to invalid IL or missing references)
		//IL_02a6: Expected O, but got Unknown
		//IL_02a6: Unknown result type (might be due to invalid IL or missing references)
		//IL_02ad: Unknown result type (might be due to invalid IL or missing references)
		//IL_02b2: Unknown result type (might be due to invalid IL or missing references)
		//IL_02b7: Unknown result type (might be due to invalid IL or missing references)
		//IL_02c3: Expected O, but got Unknown
		//IL_02c3: Expected O, but got Unknown
		//IL_02c4: Expected O, but got Unknown
		//IL_014a: Unknown result type (might be due to invalid IL or missing references)
		//IL_014c: Unknown result type (might be due to invalid IL or missing references)
		//IL_018a: Unknown result type (might be due to invalid IL or missing references)
		//IL_018c: Unknown result type (might be due to invalid IL or missing references)
		//IL_0191: Unknown result type (might be due to invalid IL or missing references)
		//IL_019d: Expected O, but got Unknown
		//IL_00f0: Unknown result type (might be due to invalid IL or missing references)
		//IL_00f5: Unknown result type (might be due to invalid IL or missing references)
		//IL_0104: Unknown result type (might be due to invalid IL or missing references)
		//IL_0109: Unknown result type (might be due to invalid IL or missing references)
		//IL_0116: Unknown result type (might be due to invalid IL or missing references)
		//IL_011b: Unknown result type (might be due to invalid IL or missing references)
		//IL_012b: Unknown result type (might be due to invalid IL or missing references)
		//IL_0130: Unknown result type (might be due to invalid IL or missing references)
		//IL_0143: Unknown result type (might be due to invalid IL or missing references)
		//IL_0148: Unknown result type (might be due to invalid IL or missing references)
		try
		{
			if (_riskAssessmentResult == null || _riskAssessmentResult.RiskDistribution == null)
			{
				return;
			}
			List<RiskCategory> list = _riskAssessmentResult.RiskDistribution.Where((RiskCategory r) => r.Count > 0).ToList();
			if (!list.Any())
			{
				return;
			}
			List<ColumnSeries<int>> list2 = new List<ColumnSeries<int>>();
			List<string> list3 = new List<string>();
			string fontFamily = "Microsoft YaHei";
			foreach (RiskCategory item in list)
			{
				SKColor val = (SKColor)(item.Category switch
				{
					"严重" => new SKColor(byte.MaxValue, (byte)65, (byte)108), 
					"高" => new SKColor(byte.MaxValue, (byte)107, (byte)74), 
					"中" => new SKColor(byte.MaxValue, (byte)165, (byte)2), 
					"低" => new SKColor((byte)46, (byte)213, (byte)115), 
					"无风险" => new SKColor((byte)112, (byte)161, byte.MaxValue), 
					_ => new SKColor((byte)192, (byte)192, (byte)192), 
				});
				list3.Add(item.Category);
				list2.Add(new ColumnSeries<int>
				{
					Name = item.Category,
					Values = new int[1] { item.Count },
					Fill = (IPaint<SkiaSharpDrawingContext>)new SolidColorPaint(val)
					{
						FontFamily = fontFamily
					},
					MaxBarWidth = 60.0
				});
			}
			RiskDistributionBarChart.Series = (IEnumerable<ISeries>)list2;
			CartesianChart riskDistributionBarChart = RiskDistributionBarChart;
			Axis[] array = new Axis[1];
			Axis val2 = new Axis();
			((CoreAxis<SkiaSharpDrawingContext, LabelGeometry, LineGeometry>)val2).Labels = list3;
			((CoreAxis<SkiaSharpDrawingContext, LabelGeometry, LineGeometry>)val2).LabelsRotation = 0.0;
			((CoreAxis<SkiaSharpDrawingContext, LabelGeometry, LineGeometry>)val2).SeparatorsPaint = (IPaint<SkiaSharpDrawingContext>)new SolidColorPaint(new SKColor((byte)224, (byte)224, (byte)224));
			((CoreAxis<SkiaSharpDrawingContext, LabelGeometry, LineGeometry>)val2).TextSize = 12.0;
			((CoreAxis<SkiaSharpDrawingContext, LabelGeometry, LineGeometry>)val2).LabelsPaint = (IPaint<SkiaSharpDrawingContext>)new SolidColorPaint(new SKColor((byte)51, (byte)51, (byte)51))
			{
				FontFamily = fontFamily
			};
			array[0] = val2;
			riskDistributionBarChart.XAxes = (IEnumerable<ICartesianAxis>)(object)array;
			CartesianChart riskDistributionBarChart2 = RiskDistributionBarChart;
			Axis[] array2 = new Axis[1];
			Axis val3 = new Axis();
			((CoreAxis<SkiaSharpDrawingContext, LabelGeometry, LineGeometry>)val3).MinStep = 1.0;
			((CoreAxis<SkiaSharpDrawingContext, LabelGeometry, LineGeometry>)val3).SeparatorsPaint = (IPaint<SkiaSharpDrawingContext>)new SolidColorPaint(new SKColor((byte)224, (byte)224, (byte)224));
			((CoreAxis<SkiaSharpDrawingContext, LabelGeometry, LineGeometry>)val3).TextSize = 12.0;
			((CoreAxis<SkiaSharpDrawingContext, LabelGeometry, LineGeometry>)val3).LabelsPaint = (IPaint<SkiaSharpDrawingContext>)new SolidColorPaint(new SKColor((byte)51, (byte)51, (byte)51))
			{
				FontFamily = fontFamily
			};
			array2[0] = val3;
			riskDistributionBarChart2.YAxes = (IEnumerable<ICartesianAxis>)(object)array2;
		}
		catch (Exception ex)
		{
			Log("更新风险分布柱状图失败: " + ex.Message);
		}
	}

	private void UpdateRiskAssessmentUI()
	{
		try
		{
			if (_riskAssessmentResult != null)
			{
				UpdateRiskOverviewPanel();
				UpdateRiskDistributionChart();
				UpdateRiskDistributionPieChart();
				UpdateRiskDistributionBarChart();
				if (OpenPortsDataGrid != null && _riskAssessmentResult.OpenPorts != null)
				{
					OpenPortsDataGrid.ItemsSource = null;
					OpenPortsDataGrid.ItemsSource = _riskAssessmentResult.OpenPorts;
				}
				if (VulnerabilityDetailsDataGrid != null && _riskAssessmentResult.VulnerabilityDetails != null)
				{
					VulnerabilityDetailsDataGrid.ItemsSource = null;
					VulnerabilityDetailsDataGrid.ItemsSource = _riskAssessmentResult.VulnerabilityDetails;
				}
				SecurityAdviceText.Text = _riskAssessmentResult.SecurityAdvice;
				UpdateGeneratePortBatFromAiButton();
			}
		}
		catch (Exception ex)
		{
			Log("更新风险评估UI失败: " + ex.Message);
		}
	}

	private void UpdateRiskOverviewPanel()
	{
		try
		{
			if (_riskAssessmentResult == null)
			{
				return;
			}
			OverallRiskText.Text = _riskAssessmentResult.OverallRiskLevel;
			RiskScoreText.Text = $"{_riskAssessmentResult.TotalRiskScore:F1} 分";
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
			TargetIpText.Text = _riskAssessmentResult.TargetIp;
			AssessmentTimeText.Text = $"评估时间: {_riskAssessmentResult.AssessmentTime:yyyy-MM-dd HH:mm:ss}";
			AssessmentDateText.Text = $"评估日期: {_riskAssessmentResult.AssessmentTime:yyyy-MM-dd}";
			TotalVulnerabilitiesText.Text = _riskAssessmentResult.Statistics.TotalVulnerabilities.ToString();
			OpenPortsCountText.Text = _riskAssessmentResult.OpenPorts.Count.ToString();
			SensitivePortsText.Text = $"{_riskAssessmentResult.SensitiveOpenPorts.Count} 个敏感端口";
			int highRiskCount = _riskAssessmentResult.RiskDistribution.Where((RiskCategory r) => r.Category == "高" || r.Category == "严重").Sum((RiskCategory r) => r.Count);
			if (((DispatcherObject)this).Dispatcher.CheckAccess())
			{
				HighRiskCountText.Text = highRiskCount.ToString();
				return;
			}
			((DispatcherObject)this).Dispatcher.Invoke<string>((Func<string>)(() => HighRiskCountText.Text = highRiskCount.ToString()));
		}
		catch (Exception ex)
		{
			Log("更新风险概览面板失败: " + ex.Message);
		}
	}

	private async void RefreshAiAnalysis_Click(object sender, RoutedEventArgs e)
	{
		try
		{
			await StartAiRiskAssessmentAsync();
		}
		catch (Exception ex2)
		{
			Exception ex3 = ex2;
			Exception ex = ex3;
			Log("AI风险评估操作失败: " + ex.Message);
			if (((DispatcherObject)this).Dispatcher.CheckAccess())
			{
				MessageBox.Show("AI风险评估失败: " + ex.Message, "错误", MessageBoxButton.OK, MessageBoxImage.Hand);
				return;
			}
			((DispatcherObject)this).Dispatcher.Invoke((Action)delegate
			{
				MessageBox.Show("AI风险评估失败: " + ex.Message, "错误", MessageBoxButton.OK, MessageBoxImage.Hand);
			});
		}
	}

	private async Task StartAiRiskAssessmentAsync()
	{
		_ = 2;
		try
		{
			UpdateAiAnalysisStatus("AI分析中...", 0, showProgress: true);
			for (int i = 0; i <= 100; i += 10)
			{
				await Task.Delay(200);
				UpdateAiAnalysisStatus("AI分析中...", i, showProgress: true);
			}
			UpdateAiAnalysisStatus("AI分析完成", 100, showProgress: false);
			if (((DispatcherObject)this).Dispatcher.CheckAccess())
			{
				AiAnalysisSubStatusText.Text = "已完成风险评估，正在生成报告...";
			}
			else
			{
				((DispatcherObject)this).Dispatcher.Invoke((Action)delegate
				{
					AiAnalysisSubStatusText.Text = "已完成风险评估，正在生成报告...";
				});
			}
			List<PortScanResult> portResultsCopy = new List<PortScanResult>();
			List<VulnerabilityResult> vulnResultsCopy = new List<VulnerabilityResult>();
			if (!((DispatcherObject)this).Dispatcher.CheckAccess())
			{
				await ((DispatcherObject)this).Dispatcher.InvokeAsync((Action)delegate
				{
					portResultsCopy.AddRange(_portScanResults);
					vulnResultsCopy.AddRange(_vulnerabilityResults);
				});
			}
			else
			{
				portResultsCopy.AddRange(_portScanResults);
				vulnResultsCopy.AddRange(_vulnerabilityResults);
			}
			if (portResultsCopy.Any() || vulnResultsCopy.Any())
			{
				List<RiskAssessmentItem> newRiskAssessmentItems = _riskAssessmentService.AssessRisk(vulnResultsCopy, portResultsCopy);
				if (!((DispatcherObject)this).Dispatcher.CheckAccess())
				{
					await ((DispatcherObject)this).Dispatcher.InvokeAsync((Action)delegate
					{
						_riskAssessmentItems.Clear();
						foreach (RiskAssessmentItem item in newRiskAssessmentItems)
						{
							_riskAssessmentItems.Add(item);
						}
						_riskAssessmentResult = _riskAssessmentService.AssessRiskExpert(vulnResultsCopy, portResultsCopy, TargetIpTextBox.Text.Trim());
						UpdateRiskAssessmentUI();
					});
				}
				else
				{
					_riskAssessmentItems.Clear();
					foreach (RiskAssessmentItem item2 in newRiskAssessmentItems)
					{
						_riskAssessmentItems.Add(item2);
					}
					_riskAssessmentResult = _riskAssessmentService.AssessRiskExpert(vulnResultsCopy, portResultsCopy, TargetIpTextBox.Text.Trim());
					UpdateRiskAssessmentUI();
				}
				if (((DispatcherObject)this).Dispatcher.CheckAccess())
				{
					AiAnalysisSubStatusText.Text = "报告生成完成";
					return;
				}
				((DispatcherObject)this).Dispatcher.Invoke((Action)delegate
				{
					AiAnalysisSubStatusText.Text = "报告生成完成";
				});
				return;
			}
			UpdateAiAnalysisStatus("AI分析就绪", 0, showProgress: false);
			if (((DispatcherObject)this).Dispatcher.CheckAccess())
			{
				AiAnalysisSubStatusText.Text = "请先执行端口扫描或漏洞扫描";
				return;
			}
			((DispatcherObject)this).Dispatcher.Invoke((Action)delegate
			{
				AiAnalysisSubStatusText.Text = "请先执行端口扫描或漏洞扫描";
			});
		}
		catch (Exception ex2)
		{
			Exception ex3 = ex2;
			Exception ex = ex3;
			Log("AI风险评估失败: " + ex.Message);
			UpdateAiAnalysisStatus("AI分析失败", 0, showProgress: false);
			if (((DispatcherObject)this).Dispatcher.CheckAccess())
			{
				AiAnalysisSubStatusText.Text = ex.Message;
				return;
			}
			((DispatcherObject)this).Dispatcher.Invoke((Action)delegate
			{
				AiAnalysisSubStatusText.Text = ex.Message;
			});
		}
	}

	private void UpdateAiAnalysisStatus(string status, int progress, bool showProgress)
	{
		string status2 = status;
		if (((DispatcherObject)this).Dispatcher.CheckAccess())
		{
			AiAnalysisStatusText.Text = status2;
			if (showProgress)
			{
				AiAnalysisProgressBar.Visibility = Visibility.Visible;
				AiAnalysisProgressBar.Value = progress;
			}
			else
			{
				AiAnalysisProgressBar.Visibility = Visibility.Collapsed;
			}
			return;
		}
		((DispatcherObject)this).Dispatcher.Invoke((Action)delegate
		{
			AiAnalysisStatusText.Text = status2;
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

	private void Log(string message)
	{
		try
		{
			string text = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "logs");
			Directory.CreateDirectory(text);
			File.AppendAllText(Path.Combine(text, $"app_{DateTime.Now:yyyyMMdd}.log"), $"[{DateTime.Now:HH:mm:ss.fff}] {message}{Environment.NewLine}");
		}
		catch (Exception)
		{
		}
	}

	private void InitializeServices()
	{
		//IL_000c: Unknown result type (might be due to invalid IL or missing references)
		//IL_0016: Expected O, but got Unknown
		//IL_0022: Unknown result type (might be due to invalid IL or missing references)
		//IL_002c: Expected O, but got Unknown
		//IL_0038: Unknown result type (might be due to invalid IL or missing references)
		//IL_0042: Expected O, but got Unknown
		//IL_004e: Unknown result type (might be due to invalid IL or missing references)
		//IL_0058: Expected O, but got Unknown
		//IL_0064: Unknown result type (might be due to invalid IL or missing references)
		//IL_006e: Expected O, but got Unknown
		try
		{
			Log("开始初始化服务");
			_portScanner = new PortScanner();
			Log("PortScanner初始化完成");
			_riskAssessmentService = new RiskAssessmentService();
			Log("RiskAssessmentService初始化完成");
			_portManagementService = new PortManagementService();
			Log("PortManagementService初始化完成");
			_vulnerabilityScanner = new VulnerabilityScanner();
			Log("VulnerabilityScanner初始化完成");
			_jsonDatabaseService = new JsonDatabaseService();
			Log("JsonDatabaseService初始化完成");
		}
		catch (Exception ex)
		{
			Log("服务初始化失败: " + ex.Message);
			Log("异常堆栈: " + ex.StackTrace);
			if (ex.InnerException != null)
			{
				Log("内部异常: " + ex.InnerException.Message);
				Log("内部异常堆栈: " + ex.InnerException.StackTrace);
			}
			throw new Exception("服务初始化失败: " + ex.Message, ex);
		}
	}

	protected virtual void OnPropertyChanged(string propertyName)
	{
		this.PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));
	}

	private async void StartPortScan_Click(object sender, RoutedEventArgs e)
	{
		try
		{
			await StartPortScanAsync();
		}
		catch (Exception ex2)
		{
			Exception ex3 = ex2;
			Exception ex = ex3;
			Log("端口扫描操作失败: " + ex.Message);
			if (((DispatcherObject)this).Dispatcher.CheckAccess())
			{
				MessageBox.Show("端口扫描失败: " + ex.Message, "错误", MessageBoxButton.OK, MessageBoxImage.Hand);
				return;
			}
			((DispatcherObject)this).Dispatcher.Invoke((Action)delegate
			{
				MessageBox.Show("端口扫描失败: " + ex.Message, "错误", MessageBoxButton.OK, MessageBoxImage.Hand);
			});
		}
	}

	private async Task StartPortScanAsync()
	{
		string targetIp = TargetIpTextBox.Text.Trim();
		if (!IsValidIpAddress(targetIp))
		{
			MessageBox.Show("请输入有效的IP地址", "输入错误", MessageBoxButton.OK, MessageBoxImage.Exclamation);
			return;
		}
		List<int> list;
		if (AutoScanCheckBox.IsChecked == true)
		{
			list = new List<int>
			{
				21, 22, 23, 25, 53, 80, 110, 143, 443, 465,
				993, 995, 1433, 3306, 3389, 5432, 8080, 8443
			};
			PortRangeTextBox.Text = "常用端口";
		}
		else
		{
			string text = PortRangeTextBox.Text.Trim();
			if (string.IsNullOrEmpty(text))
			{
				MessageBox.Show("请输入端口范围", "输入错误", MessageBoxButton.OK, MessageBoxImage.Exclamation);
				return;
			}
			list = ParsePortRange(text);
			if (list == null || !list.Any())
			{
				MessageBox.Show("端口范围格式错误", "输入错误", MessageBoxButton.OK, MessageBoxImage.Exclamation);
				return;
			}
		}
		_cancellationTokenSource = new CancellationTokenSource();
		try
		{
			if (((DispatcherObject)this).Dispatcher.CheckAccess())
			{
				_portScanResults.Clear();
			}
			else
			{
				((DispatcherObject)this).Dispatcher.Invoke((Action)delegate
				{
					_portScanResults.Clear();
				});
			}
			UpdateScanButtonStates(isScanning: true);
			UpdateScanStatus("端口扫描准备中...");
			ThreadSafeProgress<int> threadSafeProgress = new ThreadSafeProgress<int>(this, delegate(int value)
			{
				UpdateScanStatus("端口扫描中...", value);
			});
			string scanType = (ScanTypeComboBox.SelectedItem as ComboBoxItem)?.Content.ToString() ?? "TCP";
			List<PortScanResult> source = ((!(scanType == "TCP")) ? (await _portScanner.ScanUdpPortsAsync(targetIp, list, (IProgress<int>)threadSafeProgress, _cancellationTokenSource.Token, (ScanPolicy)null)) : (await _portScanner.ScanTcpPortsAsync(targetIp, list, (IProgress<int>)threadSafeProgress, _cancellationTokenSource.Token, (ScanPolicy)null)));
			List<PortScanResult> openPorts = source.Where((PortScanResult r) => r.Status == "开放").ToList();
			if (((DispatcherObject)this).Dispatcher.CheckAccess())
			{
				_portScanResults.Clear();
				foreach (PortScanResult item in openPorts)
				{
					_portScanResults.Add(item);
				}
				UpdateGenerateButtons();
			}
			else
			{
				((DispatcherObject)this).Dispatcher.Invoke((Action)delegate
				{
					_portScanResults.Clear();
					foreach (PortScanResult item2 in openPorts)
					{
						_portScanResults.Add(item2);
					}
					UpdateGenerateButtons();
				});
			}
			int openPortsCount = source.Count((PortScanResult r) => r.Status == "开放");
			DateTime now = DateTime.Now;
			_lastScanTime = now;
			CompleteScanResult val = new CompleteScanResult
			{
				TargetIp = targetIp,
				ScanType = scanType + "端口扫描",
				ScanTime = now,
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
			await _jsonDatabaseService.SaveScanResultAsync(val);
			UpdateScanStatus($"{scanType}端口扫描完成：发现 {openPortsCount} 个开放端口", 100, showProgress: false);
			UpdateScanButtonStates(isScanning: false);
		}
		finally
		{
			_cancellationTokenSource?.Dispose();
			if (_portScanResults.Count > 0)
			{
				Task.Run(async delegate
				{
					try
					{
						await StartAiRiskAssessmentAsync();
					}
					catch (Exception ex2)
					{
						Exception ex = ex2;
						await ((DispatcherObject)this).Dispatcher.InvokeAsync((Action)delegate
						{
							Log("AI风险评估过程中发生错误: " + ex.Message);
						});
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
		catch (Exception ex2)
		{
			Exception ex3 = ex2;
			Exception ex = ex3;
			Log("漏洞扫描操作失败: " + ex.Message);
			if (((DispatcherObject)this).Dispatcher.CheckAccess())
			{
				MessageBox.Show("漏洞扫描失败: " + ex.Message, "错误", MessageBoxButton.OK, MessageBoxImage.Hand);
				return;
			}
			((DispatcherObject)this).Dispatcher.Invoke((Action)delegate
			{
				MessageBox.Show("漏洞扫描失败: " + ex.Message, "错误", MessageBoxButton.OK, MessageBoxImage.Hand);
			});
		}
	}

	private async Task StartVulnScanAsync()
	{
		string targetIp = VulnTargetTextBox.Text.Trim();
		if (!IsValidIpAddress(targetIp))
		{
			MessageBox.Show("请输入有效的IP地址", "输入错误", MessageBoxButton.OK, MessageBoxImage.Exclamation);
			return;
		}
		_cancellationTokenSource = new CancellationTokenSource();
		try
		{
			if (((DispatcherObject)this).Dispatcher.CheckAccess())
			{
				_vulnerabilityResults.Clear();
			}
			else
			{
				((DispatcherObject)this).Dispatcher.Invoke((Action)delegate
				{
					_vulnerabilityResults.Clear();
				});
			}
			UpdateScanButtonStates(isScanning: true);
			UpdateScanStatus("漏洞扫描准备中...");
			if (((DispatcherObject)this).Dispatcher.CheckAccess())
			{
				VulnScanProgressText.Text = "开始扫描";
				VulnScanProgressPercent.Text = "0%";
				VulnScanProgressBar.Value = 0.0;
				VulnScanCurrentStage.Text = "正在准备扫描...";
			}
			else
			{
				((DispatcherObject)this).Dispatcher.Invoke((Action)delegate
				{
					VulnScanProgressText.Text = "开始扫描";
					VulnScanProgressPercent.Text = "0%";
					VulnScanProgressBar.Value = 0.0;
					VulnScanCurrentStage.Text = "正在准备扫描...";
				});
			}
			Progress<(string, int)> progress = new Progress<(string, int)>(delegate((string stage, int progress) progressTuple)
			{
				var (stage, progressValue) = progressTuple;
				if (((DispatcherObject)this).Dispatcher.CheckAccess())
				{
					VulnScanProgressText.Text = stage;
					VulnScanProgressPercent.Text = $"{progressValue}%";
					VulnScanProgressBar.Value = progressValue;
					VulnScanCurrentStage.Text = "当前阶段: " + stage;
				}
				else
				{
					((DispatcherObject)this).Dispatcher.Invoke((Action)delegate
					{
						VulnScanProgressText.Text = stage;
						VulnScanProgressPercent.Text = $"{progressValue}%";
						VulnScanProgressBar.Value = progressValue;
						VulnScanCurrentStage.Text = "当前阶段: " + stage;
					});
				}
			});
			List<PortInfo> list = ((IEnumerable<PortScanResult>)_portScanResults).Select((Func<PortScanResult, PortInfo>)((PortScanResult p) => new PortInfo
			{
				PortNumber = p.PortNumber,
				Service = p.Service,
				Host = targetIp,
				Status = p.Status,
				Version = p.ServiceVersion
			})).ToList();
			List<VulnerabilityResult> results;
			if (list.Any())
			{
				results = await _vulnerabilityScanner.ScanAsync(targetIp, list, "standard", (IProgress<ValueTuple<string, int>>)progress, _cancellationTokenSource.Token);
			}
			else
			{
				results = await _vulnerabilityScanner.ScanAsync(targetIp, new List<PortInfo>(), "standard", (IProgress<ValueTuple<string, int>>)progress, _cancellationTokenSource.Token);
			}
			if (((DispatcherObject)this).Dispatcher.CheckAccess())
			{
				_vulnerabilityResults.Clear();
				foreach (VulnerabilityResult item in results)
				{
					_vulnerabilityResults.Add(item);
				}
				_riskAssessmentItems.Clear();
				foreach (RiskAssessmentItem item2 in _riskAssessmentService.AssessRisk(results, _portScanResults.ToList()))
				{
					_riskAssessmentItems.Add(item2);
				}
				_riskAssessmentResult = _riskAssessmentService.AssessRiskExpert(results, _portScanResults.ToList(), targetIp);
				UpdateRiskAssessmentUI();
			}
			else
			{
				((DispatcherObject)this).Dispatcher.Invoke((Action)delegate
				{
					_vulnerabilityResults.Clear();
					foreach (VulnerabilityResult item3 in results)
					{
						_vulnerabilityResults.Add(item3);
					}
					_riskAssessmentItems.Clear();
					foreach (RiskAssessmentItem item4 in _riskAssessmentService.AssessRisk(results, _portScanResults.ToList()))
					{
						_riskAssessmentItems.Add(item4);
					}
					_riskAssessmentResult = _riskAssessmentService.AssessRiskExpert(results, _portScanResults.ToList(), targetIp);
					UpdateRiskAssessmentUI();
				});
			}
			string riskLevel = _riskAssessmentService.CalculateOverallRisk(results);
			DateTime now = DateTime.Now;
			_lastScanTime = now;
			CompleteScanResult val = new CompleteScanResult
			{
				TargetIp = targetIp,
				ScanType = "漏洞扫描",
				ScanTime = now,
				OpenPortsCount = _portScanResults.Count((PortScanResult p) => p.Status == "开放" || p.Status == "开放或过滤"),
				VulnerabilitiesCount = results.Count,
				RiskLevel = riskLevel,
				PortScanResults = _portScanResults.ToList(),
				VulnerabilityResults = results,
				RiskAssessment = new RiskAssessmentSummary
				{
					RiskLevel = riskLevel,
					SecurityAdvice = _riskAssessmentService.GenerateSecurityAdvice(results, (List<PortScanResult>)null)
				}
			};
			await _jsonDatabaseService.SaveScanResultAsync(val);
			UpdateScanStatus($"漏洞扫描完成：发现 {results.Count} 个漏洞", 100, showProgress: false);
			if (((DispatcherObject)this).Dispatcher.CheckAccess())
			{
				VulnScanProgressText.Text = "扫描完成";
				VulnScanProgressPercent.Text = "100%";
				VulnScanProgressBar.Value = 100.0;
				VulnScanCurrentStage.Text = $"发现 {results.Count} 个漏洞";
			}
			else
			{
				((DispatcherObject)this).Dispatcher.Invoke((Action)delegate
				{
					VulnScanProgressText.Text = "扫描完成";
					VulnScanProgressPercent.Text = "100%";
					VulnScanProgressBar.Value = 100.0;
					VulnScanCurrentStage.Text = $"发现 {results.Count} 个漏洞";
				});
			}
			UpdateScanButtonStates(isScanning: false);
		}
		finally
		{
			_cancellationTokenSource?.Dispose();
			if (Application.Current != null && ((DispatcherObject)Application.Current).Dispatcher != null)
			{
				Task.Run(async delegate
				{
					try
					{
						await ((DispatcherObject)this).Dispatcher.InvokeAsync<Task>((Func<Task>)async delegate
						{
							await StartAiRiskAssessmentAsync();
						});
					}
					catch (Exception ex2)
					{
						Exception ex = ex2;
						await ((DispatcherObject)this).Dispatcher.InvokeAsync((Action)delegate
						{
							Log("AI风险评估过程中发生错误: " + ex.Message);
						});
					}
				});
			}
		}
	}

	private void PluginScanButton_Click(object sender, RoutedEventArgs e)
	{
		try
		{
			PluginQuickInvokeWindow pluginQuickInvokeWindow = new PluginQuickInvokeWindow();
			pluginQuickInvokeWindow.Owner = this;
			pluginQuickInvokeWindow.ShowDialog();
		}
		catch (Exception ex)
		{
			MessageBox.Show("打开插件扫描窗口失败: " + ex.Message, "错误", MessageBoxButton.OK, MessageBoxImage.Hand);
		}
	}

	private async void StartScan_Click(object sender, RoutedEventArgs e)
	{
		ComprehensiveScanDialog comprehensiveScanDialog = new ComprehensiveScanDialog
		{
			Owner = this
		};
		if (comprehensiveScanDialog.ShowDialog() != true)
		{
			return;
		}
		ComprehensiveScanOptions options = comprehensiveScanDialog.BuildOptions();
		ScanProgressLiveWindow liveWin = new ScanProgressLiveWindow
		{
			Owner = this
		};
		liveWin.SetTarget(options.TargetIp);
		liveWin.Show();
		try
		{
			ComprehensiveScanResult result = await new ComprehensiveScanService(_portScanner, _vulnerabilityScanner, _riskAssessmentService, _jsonDatabaseService, (PluginOrchestrator)null, (Action<string>)delegate(string msg)
			{
				Log(msg);
			}).ExecuteAsync(options, liveWin.Progress, liveWin.CancellationToken);
			liveWin.Close();
			if (result.Cancelled)
			{
				UpdateScanStatus("扫描已取消");
				Log("[综合扫描] 用户已取消");
				return;
			}
			UpdateScanStatus($"扫描完成 - 耗时 {result.ScanDurationSeconds:F1}s | 端口 {result.OpenPortsCount} | 漏洞 {result.VulnerabilitiesCount} | 风险 {result.RiskLevel}", 100);
			if (options.SaveToHistory)
			{
				await RefreshScanHistoryAsync();
			}
			ComprehensiveScanResultWindow comprehensiveScanResultWindow = new ComprehensiveScanResultWindow(result);
			comprehensiveScanResultWindow.Owner = this;
			comprehensiveScanResultWindow.ShowDialog();
		}
		catch (Exception ex)
		{
			liveWin.Close();
			Log("[综合扫描] 失败: " + ex.Message);
			MessageBox.Show("扫描失败: " + ex.Message, "错误", MessageBoxButton.OK, MessageBoxImage.Hand);
		}
	}

	private void UpdateAiRiskAssessment(string targetIp, List<PortScanResult> portResults, List<VulnerabilityResult> vulnResults)
	{
		_riskAssessmentItems.Clear();
		foreach (RiskAssessmentItem item in _riskAssessmentService.AssessRisk(vulnResults, portResults))
		{
			_riskAssessmentItems.Add(item);
		}
		_riskAssessmentResult = _riskAssessmentService.AssessRiskExpert(vulnResults, portResults, targetIp);
		UpdateRiskAssessmentUI();
	}

	private void UpdateScanButtonStates(bool isScanning)
	{
		if (((DispatcherObject)this).Dispatcher.CheckAccess())
		{
			if (StartPortScanButton != null)
			{
				StartPortScanButton.IsEnabled = !isScanning;
			}
			if (StopPortScanButton != null)
			{
				StopPortScanButton.IsEnabled = isScanning;
			}
			if (StartVulnScanButton != null)
			{
				StartVulnScanButton.IsEnabled = !isScanning;
			}
			if (StopVulnScanButton != null)
			{
				StopVulnScanButton.IsEnabled = isScanning;
			}
			return;
		}
		((DispatcherObject)this).Dispatcher.Invoke((Action)delegate
		{
			if (StartPortScanButton != null)
			{
				StartPortScanButton.IsEnabled = !isScanning;
			}
			if (StopPortScanButton != null)
			{
				StopPortScanButton.IsEnabled = isScanning;
			}
			if (StartVulnScanButton != null)
			{
				StartVulnScanButton.IsEnabled = !isScanning;
			}
			if (StopVulnScanButton != null)
			{
				StopVulnScanButton.IsEnabled = isScanning;
			}
		});
	}

	private void UpdateScanStatus(string statusText, int progressValue = 0, bool showProgress = true)
	{
		string statusText2 = statusText;
		if (((DispatcherObject)this).Dispatcher.CheckAccess())
		{
			StatusTextBlock.Text = statusText2;
			if (showProgress)
			{
				ScanProgressBar.Visibility = Visibility.Visible;
				ScanProgressBar.Value = progressValue;
				ScanProgressText.Text = $"{statusText2} {progressValue}%";
			}
			else
			{
				ScanProgressBar.Visibility = Visibility.Collapsed;
				ScanProgressText.Text = statusText2;
			}
			return;
		}
		((DispatcherObject)this).Dispatcher.Invoke((Action)delegate
		{
			StatusTextBlock.Text = statusText2;
			if (showProgress)
			{
				ScanProgressBar.Visibility = Visibility.Visible;
				ScanProgressBar.Value = progressValue;
				ScanProgressText.Text = $"{statusText2} {progressValue}%";
			}
			else
			{
				ScanProgressBar.Visibility = Visibility.Collapsed;
				ScanProgressText.Text = statusText2;
			}
		});
	}

	private void StopScan_Click(object sender, RoutedEventArgs e)
	{
		_cancellationTokenSource?.Cancel();
		UpdateScanStatus("扫描已停止", 0, showProgress: false);
		UpdateScanButtonStates(isScanning: false);
	}

	private void SelectAllPorts_Click(object sender, RoutedEventArgs e)
	{
		if (((DispatcherObject)this).Dispatcher.CheckAccess())
		{
			foreach (PortScanResult portScanResult in _portScanResults)
			{
				portScanResult.IsSelected = true;
			}
			UpdateGenerateButtons();
			return;
		}
		((DispatcherObject)this).Dispatcher.Invoke((Action)delegate
		{
			foreach (PortScanResult portScanResult2 in _portScanResults)
			{
				portScanResult2.IsSelected = true;
			}
			UpdateGenerateButtons();
		});
	}

	private void UnselectAllPorts_Click(object sender, RoutedEventArgs e)
	{
		if (((DispatcherObject)this).Dispatcher.CheckAccess())
		{
			foreach (PortScanResult portScanResult in _portScanResults)
			{
				portScanResult.IsSelected = false;
			}
			UpdateGenerateButtons();
			return;
		}
		((DispatcherObject)this).Dispatcher.Invoke((Action)delegate
		{
			foreach (PortScanResult portScanResult2 in _portScanResults)
			{
				portScanResult2.IsSelected = false;
			}
			UpdateGenerateButtons();
		});
	}

	private void GeneratePortBat_Click(object sender, RoutedEventArgs e)
	{
		try
		{
			List<PortScanResult> source = _portScanResults.Where((PortScanResult r) => r.IsSelected).ToList();
			if (!source.Any())
			{
				MessageBox.Show("请先勾选要关闭的端口", "提示", MessageBoxButton.OK, MessageBoxImage.Asterisk);
				return;
			}
			string text = string.Join(", ", source.Select((PortScanResult p) => p.PortNumber));
			string text2 = ((MessageBox.Show("即将为以下端口生成关闭脚本：\n" + text + "\n\n是否使用高级选项？\n【是】高级选项：包含防火墙规则备份、入站+出站双向拦截、规则验证\n【否】标准选项：仅添加入站拦截规则", "端口关闭脚本选项", MessageBoxButton.YesNo, MessageBoxImage.Question) != MessageBoxResult.Yes) ? _portManagementService.GeneratePortClosureScript(source.Select((PortScanResult p) => p.PortNumber).ToList()) : _portManagementService.GenerateAdvancedPortClosureScript(source.Select((PortScanResult p) => p.PortNumber).ToList()));
			string text3 = $"关闭端口脚本_{DateTime.Now:yyyyMMdd_HHmmss}.bat";
			string text4 = _portManagementService.SaveScriptToFile(text2, text3);
			MessageBox.Show("端口关闭脚本已成功生成！\n\n保存位置：" + text4 + "\n包含端口：" + text + "\n\n使用说明：\n1. 右键点击此BAT文件\n2. 选择\"以管理员身份运行\"\n3. 脚本将自动添加防火墙规则关闭端口", "脚本生成成功", MessageBoxButton.OK, MessageBoxImage.Asterisk);
			StatusTextBlock.Text = "已生成端口关闭脚本：" + text4;
			Log("端口关闭脚本已生成：" + text4);
		}
		catch (Exception ex)
		{
			MessageBox.Show("生成端口关闭脚本失败: " + ex.Message, "错误", MessageBoxButton.OK, MessageBoxImage.Hand);
			StatusTextBlock.Text = "生成端口关闭脚本失败";
		}
	}

	private void OpenPortsDataGrid_SelectionChanged(object sender, SelectionChangedEventArgs e)
	{
		UpdateGeneratePortBatFromAiButton();
	}

	private void PortScanResultsDataGrid_SelectionChanged(object sender, SelectionChangedEventArgs e)
	{
		UpdateGeneratePortBatButton();
	}

	private void UpdateGeneratePortBatButton()
	{
		if (((DispatcherObject)this).Dispatcher.CheckAccess())
		{
			bool isEnabled = _portScanResults?.Any((PortScanResult p) => p.IsSelected) ?? false;
			if (GeneratePortBatButton != null)
			{
				GeneratePortBatButton.IsEnabled = isEnabled;
			}
			return;
		}
		((DispatcherObject)this).Dispatcher.Invoke((Action)delegate
		{
			bool isEnabled2 = _portScanResults?.Any((PortScanResult p) => p.IsSelected) ?? false;
			if (GeneratePortBatButton != null)
			{
				GeneratePortBatButton.IsEnabled = isEnabled2;
			}
		});
	}

	private void UpdateGeneratePortBatFromAiButton()
	{
		if (((DispatcherObject)this).Dispatcher.CheckAccess())
		{
			RiskAssessmentResult riskAssessmentResult = _riskAssessmentResult;
			bool isEnabled = riskAssessmentResult != null && riskAssessmentResult.OpenPorts?.Any((PortScanResult p) => p.IsSelected) == true;
			if (GeneratePortBatFromAiButton != null)
			{
				GeneratePortBatFromAiButton.IsEnabled = isEnabled;
			}
			return;
		}
		((DispatcherObject)this).Dispatcher.Invoke((Action)delegate
		{
			RiskAssessmentResult riskAssessmentResult2 = _riskAssessmentResult;
			bool isEnabled2 = riskAssessmentResult2 != null && riskAssessmentResult2.OpenPorts?.Any((PortScanResult p) => p.IsSelected) == true;
			if (GeneratePortBatFromAiButton != null)
			{
				GeneratePortBatFromAiButton.IsEnabled = isEnabled2;
			}
		});
	}

	private void GeneratePortBatFromAi_Click(object sender, RoutedEventArgs e)
	{
		try
		{
			if (_riskAssessmentResult == null || _riskAssessmentResult.OpenPorts == null)
			{
				MessageBox.Show("没有可用的端口数据", "提示", MessageBoxButton.OK, MessageBoxImage.Asterisk);
				return;
			}
			List<PortScanResult> source = _riskAssessmentResult.OpenPorts.Where((PortScanResult p) => p.IsSelected).ToList();
			if (!source.Any())
			{
				MessageBox.Show("请先选择要关闭的端口", "提示", MessageBoxButton.OK, MessageBoxImage.Asterisk);
				return;
			}
			string text = ((MessageBox.Show("是否使用高级选项生成端口关闭脚本？\n高级选项将包含防火墙规则备份功能。", "端口关闭脚本选项", MessageBoxButton.YesNo, MessageBoxImage.Question) != MessageBoxResult.Yes) ? _portManagementService.GeneratePortClosureScript(source.Select((PortScanResult p) => p.PortNumber).ToList()) : _portManagementService.GenerateAdvancedPortClosureScript(source.Select((PortScanResult p) => p.PortNumber).ToList()));
			string text2 = _portManagementService.SaveScriptToFile(text, $"PortClosureScript_{DateTime.Now:yyyyMMdd_HHmmss}.bat");
			MessageBox.Show("端口关闭脚本已生成：\n" + text2 + "\n\n请以管理员权限运行此脚本来关闭选定的端口。", "脚本生成成功", MessageBoxButton.OK, MessageBoxImage.Asterisk);
			StatusTextBlock.Text = "已生成端口关闭脚本：" + text2;
		}
		catch (Exception ex)
		{
			MessageBox.Show("生成端口关闭脚本失败: " + ex.Message, "错误", MessageBoxButton.OK, MessageBoxImage.Hand);
			StatusTextBlock.Text = "生成端口关闭脚本失败";
		}
	}

	private void GenerateBat_Click(object sender, RoutedEventArgs e)
	{
		GeneratePortBat_Click(sender, e);
	}

	private void ExportReport_Click(object sender, RoutedEventArgs e)
	{
		//IL_0058: Unknown result type (might be due to invalid IL or missing references)
		//IL_005d: Unknown result type (might be due to invalid IL or missing references)
		//IL_0064: Unknown result type (might be due to invalid IL or missing references)
		//IL_006f: Unknown result type (might be due to invalid IL or missing references)
		//IL_0080: Unknown result type (might be due to invalid IL or missing references)
		//IL_0091: Unknown result type (might be due to invalid IL or missing references)
		//IL_0092: Unknown result type (might be due to invalid IL or missing references)
		//IL_0097: Unknown result type (might be due to invalid IL or missing references)
		//IL_00ad: Unknown result type (might be due to invalid IL or missing references)
		//IL_00b4: Unknown result type (might be due to invalid IL or missing references)
		//IL_00c5: Unknown result type (might be due to invalid IL or missing references)
		//IL_00f5: Unknown result type (might be due to invalid IL or missing references)
		//IL_0125: Unknown result type (might be due to invalid IL or missing references)
		//IL_015a: Expected O, but got Unknown
		//IL_015b: Expected O, but got Unknown
		try
		{
			Log("开始导出报告");
			if (_portScanResults == null || _vulnerabilityResults == null || _riskAssessmentItems == null)
			{
				throw new InvalidOperationException("报告数据不可用，请先执行扫描");
			}
			string text = TargetIpTextBox.Text.Trim();
			if (string.IsNullOrEmpty(text))
			{
				text = VulnTargetTextBox.Text.Trim();
			}
			CompleteScanResult item = new CompleteScanResult
			{
				TargetIp = text,
				ScanTime = DateTime.Now,
				PortScanResults = _portScanResults.ToList(),
				VulnerabilityResults = _vulnerabilityResults.ToList(),
				RiskAssessment = new RiskAssessmentSummary
				{
					RiskLevel = CalculateOverallRiskFromVulns(_vulnerabilityResults.ToList()),
					RiskScore = 0,
					TotalVulnerabilities = _vulnerabilityResults.Count,
					HighRiskCount = _vulnerabilityResults.Count((VulnerabilityResult v) => IsCriticalLevel((v != null) ? v.RiskLevel : null) || IsHighLevel((v != null) ? v.RiskLevel : null)),
					MediumRiskCount = _vulnerabilityResults.Count((VulnerabilityResult v) => IsMediumLevel((v != null) ? v.RiskLevel : null)),
					LowRiskCount = _vulnerabilityResults.Count((VulnerabilityResult v) => IsLowLevel((v != null) ? v.RiskLevel : null))
				}
			};
			List<CompleteScanResult> completeResults = new List<CompleteScanResult> { item };
			ExportReportWithDialog(completeResults);
		}
		catch (InvalidOperationException ex)
		{
			Log("操作错误：" + ex.Message);
			MessageBox.Show(ex.Message, "操作错误", MessageBoxButton.OK, MessageBoxImage.Exclamation);
		}
		catch (Exception ex2)
		{
			Log("导出报告失败: " + ex2.Message);
			MessageBox.Show("导出报告失败: " + ex2.Message, "错误", MessageBoxButton.OK, MessageBoxImage.Hand);
		}
	}

	private async void ExportReportWithDialog(List<CompleteScanResult> completeResults)
	{
		try
		{
			(ReportFormat, bool?) tuple = ShowReportFormatDialog();
			var (selectedFormat, _) = tuple;
			if (tuple.Item2 != true)
			{
				return;
			}
			string targetIp = completeResults.First().TargetIp ?? "未知目标";
			if (completeResults.Count > 1)
			{
				targetIp = string.Join(", ", completeResults.Select((CompleteScanResult r) => r.TargetIp).Distinct());
			}
			string text = ShowSaveFileDialog(selectedFormat, targetIp);
			if (string.IsNullOrEmpty(text))
			{
				return;
			}
			string directoryName = Path.GetDirectoryName(text);
			if (!string.IsNullOrEmpty(directoryName) && !Directory.Exists(directoryName))
			{
				Directory.CreateDirectory(directoryName);
			}
			Log("正在生成" + (selectedFormat - 1) switch
			{
				2 => "Word", 
				1 => "HTML", 
				0 => "CSV", 
				_ => "文本", 
			} + "格式报告...");
			StatusTextBlock.Text = "正在生成报告，请稍候...";
			_ = string.Empty;
			string text2 = (((int)selectedFormat == 3) ? (await GenerateWordReport(completeResults, text)) : (((int)selectedFormat == 2) ? (await GenerateHtmlReport(completeResults, text)) : (((int)selectedFormat != 1) ? (await GenerateTxtReport(completeResults, text)) : (await GenerateCsvReport(completeResults, text)))));
			if (!string.IsNullOrEmpty(text2) && File.Exists(text2))
			{
				FileInfo fileInfo = new FileInfo(text2);
				string value = ((fileInfo.Length > 1048576) ? $"{(double)fileInfo.Length / 1048576.0:F2} MB" : $"{(double)fileInfo.Length / 1024.0:F1} KB");
				string value2 = (selectedFormat - 1) switch
				{
					2 => "Word", 
					1 => "HTML", 
					0 => "CSV", 
					_ => "文本", 
				};
				MessageBoxResult num = MessageBox.Show($"报告已成功生成！\n\n格式：{value2}\n保存位置：{text2}\n文件大小：{value}\n生成时间：{DateTime.Now:yyyy-MM-dd HH:mm:ss}\n\n是否立即打开查看？", "报告生成成功", MessageBoxButton.YesNo, MessageBoxImage.Asterisk);
				StatusTextBlock.Text = "报告已生成：" + text2;
				Log($"报告生成成功: {text2} ({value})");
				if (num == MessageBoxResult.Yes)
				{
					try
					{
						Process.Start(new ProcessStartInfo
						{
							FileName = text2,
							UseShellExecute = true
						});
						return;
					}
					catch (Exception)
					{
						return;
					}
				}
			}
			else
			{
				MessageBox.Show("报告生成失败，可能原因：选中的记录中无有效扫描数据。", "生成失败", MessageBoxButton.OK, MessageBoxImage.Exclamation);
				StatusTextBlock.Text = "报告生成失败";
			}
		}
		catch (Exception ex3)
		{
			Exception ex = ex3;
			Log("生成报告失败: " + ex.Message);
			if (((DispatcherObject)this).Dispatcher.CheckAccess())
			{
				MessageBox.Show("生成报告失败: " + ex.Message, "错误", MessageBoxButton.OK, MessageBoxImage.Hand);
				StatusTextBlock.Text = "生成报告失败";
				return;
			}
			((DispatcherObject)this).Dispatcher.Invoke((Action)delegate
			{
				MessageBox.Show("生成报告失败: " + ex.Message, "错误", MessageBoxButton.OK, MessageBoxImage.Hand);
				StatusTextBlock.Text = "生成报告失败";
			});
		}
	}

	private (ReportFormat format, bool? result) ShowReportFormatDialog()
	{
		//IL_03c1: Unknown result type (might be due to invalid IL or missing references)
		//IL_0640: Unknown result type (might be due to invalid IL or missing references)
		//IL_0684: Unknown result type (might be due to invalid IL or missing references)
		Window formatDialog = new Window
		{
			Title = "导出安全评估报告",
			Width = 480.0,
			Height = 420.0,
			WindowStartupLocation = WindowStartupLocation.CenterScreen,
			ResizeMode = ResizeMode.NoResize,
			WindowStyle = WindowStyle.ToolWindow,
			Background = new SolidColorBrush(Color.FromRgb(250, 250, 252))
		};
		StackPanel stackPanel = new StackPanel
		{
			Margin = new Thickness(28.0)
		};
		Border border = new Border
		{
			Background = new SolidColorBrush(Color.FromRgb(26, 54, 93)),
			CornerRadius = new CornerRadius(6.0),
			Padding = new Thickness(16.0, 12.0, 16.0, 12.0),
			Margin = new Thickness(0.0, 0.0, 0.0, 18.0)
		};
		StackPanel stackPanel2 = new StackPanel();
		TextBlock element = new TextBlock
		{
			Text = "导出安全评估报告",
			FontSize = 17.0,
			FontWeight = FontWeights.Bold,
			Foreground = Brushes.White
		};
		TextBlock element2 = new TextBlock
		{
			Text = "选择报告格式，然后指定保存位置即可生成报告",
			FontSize = 11.0,
			Foreground = new SolidColorBrush(Color.FromRgb(180, 200, 230)),
			Margin = new Thickness(0.0, 4.0, 0.0, 0.0)
		};
		stackPanel2.Children.Add(element);
		stackPanel2.Children.Add(element2);
		border.Child = stackPanel2;
		stackPanel.Children.Add(border);
		TextBlock element3 = new TextBlock
		{
			Text = "选择报告格式：",
			FontSize = 12.0,
			FontWeight = FontWeights.SemiBold,
			Margin = new Thickness(0.0, 0.0, 0.0, 8.0),
			Foreground = new SolidColorBrush(Color.FromRgb(55, 65, 81))
		};
		stackPanel.Children.Add(element3);
		var obj = new[]
		{
			new
			{
				Icon = "\ud83d\udcdd",
				Name = "Word文件 (.docx)",
				Desc = "可编辑文档格式，方便二次修改和协作（推荐）",
				Tag = (ReportFormat)3
			},
			new
			{
				Icon = "\ud83c\udf10",
				Name = "HTML文件 (.html)",
				Desc = "网页格式报告，可直接在浏览器中查看，支持图表展示",
				Tag = (ReportFormat)2
			},
			new
			{
				Icon = "\ud83d\udcca",
				Name = "CSV文件 (.csv)",
				Desc = "数据表格格式，适合导入Excel进行数据分析",
				Tag = (ReportFormat)1
			},
			new
			{
				Icon = "\ud83d\udcc3",
				Name = "文本文件 (.txt)",
				Desc = "纯文本格式，体积小、兼容性好",
				Tag = (ReportFormat)0
			}
		};
		ComboBox formatComboBox = new ComboBox
		{
			Width = 410.0,
			Height = 34.0,
			FontSize = 12.0,
			Margin = new Thickness(0.0, 0.0, 0.0, 4.0),
			HorizontalAlignment = HorizontalAlignment.Left
		};
		var array = obj;
		foreach (var anon in array)
		{
			formatComboBox.Items.Add(new ComboBoxItem
			{
				Content = $"{anon.Icon} {anon.Name}  — {anon.Desc}",
				Tag = anon.Tag
			});
		}
		formatComboBox.SelectedIndex = 0;
		stackPanel.Children.Add(formatComboBox);
		Border border2 = new Border
		{
			Background = new SolidColorBrush(Color.FromRgb(239, 246, byte.MaxValue)),
			CornerRadius = new CornerRadius(4.0),
			Padding = new Thickness(12.0, 8.0, 12.0, 8.0),
			Margin = new Thickness(0.0, 6.0, 0.0, 20.0),
			BorderBrush = new SolidColorBrush(Color.FromRgb(191, 219, 254)),
			BorderThickness = new Thickness(1.0)
		};
		TextBlock child = new TextBlock
		{
			Text = "提示：PDF格式支持专业排版、图表和彩色展示，推荐使用。Word格式可编辑，适合二次修改。所有格式均支持自定义保存位置。",
			FontSize = 10.0,
			Foreground = new SolidColorBrush(Color.FromRgb(37, 99, 235)),
			TextWrapping = TextWrapping.Wrap
		};
		border2.Child = child;
		stackPanel.Children.Add(border2);
		StackPanel stackPanel3 = new StackPanel
		{
			Orientation = Orientation.Horizontal,
			HorizontalAlignment = HorizontalAlignment.Right
		};
		Button button = new Button
		{
			Content = "下一步 → 选择保存位置",
			Width = 180.0,
			Height = 36.0,
			Margin = new Thickness(5.0, 0.0, 0.0, 0.0),
			FontWeight = FontWeights.SemiBold
		};
		Button button2 = new Button
		{
			Content = "取消",
			Width = 80.0,
			Height = 36.0,
			Margin = new Thickness(5.0, 0.0, 0.0, 0.0)
		};
		stackPanel3.Children.Add(button2);
		stackPanel3.Children.Add(button);
		stackPanel.Children.Add(stackPanel3);
		formatDialog.Content = stackPanel;
		ReportFormat selectedFormat = (ReportFormat)3;
		bool? dialogResult = false;
		button.Click += delegate
		{
			//IL_0016: Unknown result type (might be due to invalid IL or missing references)
			//IL_001b: Unknown result type (might be due to invalid IL or missing references)
			selectedFormat = (ReportFormat)((ComboBoxItem)formatComboBox.SelectedItem).Tag;
			dialogResult = true;
			formatDialog.Close();
		};
		button2.Click += delegate
		{
			dialogResult = false;
			formatDialog.Close();
		};
		formatDialog.ShowDialog();
		return (format: selectedFormat, result: dialogResult);
	}

	private string ShowSaveFileDialog(ReportFormat selectedFormat, string targetIp)
	{
		//IL_006e: Unknown result type (might be due to invalid IL or missing references)
		//IL_0070: Unknown result type (might be due to invalid IL or missing references)
		//IL_0082: Expected I4, but got Unknown
		//IL_00be: Unknown result type (might be due to invalid IL or missing references)
		//IL_00c0: Unknown result type (might be due to invalid IL or missing references)
		//IL_00d2: Expected I4, but got Unknown
		string text = targetIp.Replace(".", "_").Replace(",", "_").Replace(" ", "")
			.Trim();
		if (text.Length > 30)
		{
			text = text.Substring(0, 30);
		}
		string text2 = DateTime.Now.ToString("yyyyMMdd_HHmmss");
		string text3 = "SecurityReport_" + text + "_" + text2;
		string filter;
		string text4;
		switch (selectedFormat - 1)
		{
		case 2:
			filter = "Word文件 (*.docx)|*.docx";
			text4 = "docx";
			break;
		case 1:
			filter = "HTML文件 (*.html)|*.html";
			text4 = "html";
			break;
		case 0:
			filter = "CSV文件 (*.csv)|*.csv";
			text4 = "csv";
			break;
		default:
			filter = "文本文件 (*.txt)|*.txt";
			text4 = "txt";
			break;
		}
		string text5 = (selectedFormat - 1) switch
		{
			2 => "Word格式", 
			1 => "HTML格式", 
			0 => "CSV格式", 
			_ => "文本格式", 
		};
		SaveFileDialog saveFileDialog = new SaveFileDialog
		{
			Title = "保存安全评估报告 — " + text5,
			Filter = filter,
			DefaultExt = text4,
			FileName = text3 + "." + text4
		};
		string folderPath = Environment.GetFolderPath(Environment.SpecialFolder.Desktop);
		if (Directory.Exists(folderPath))
		{
			saveFileDialog.InitialDirectory = folderPath;
		}
		if (saveFileDialog.ShowDialog() == true)
		{
			return saveFileDialog.FileName;
		}
		return null;
	}

	[Obsolete("此方法已过时，请使用 GenerateProfessionalPdfReport 方法以获得专业级报告")]
	private string GenerateRealPdfReport(string markdownContent)
	{
		//IL_0193: Unknown result type (might be due to invalid IL or missing references)
		//IL_019d: Expected O, but got Unknown
		//IL_0198: Unknown result type (might be due to invalid IL or missing references)
		//IL_0179: Unknown result type (might be due to invalid IL or missing references)
		//IL_0183: Expected O, but got Unknown
		//IL_017e: Unknown result type (might be due to invalid IL or missing references)
		//IL_019f: Expected O, but got Unknown
		//IL_01ca: Unknown result type (might be due to invalid IL or missing references)
		//IL_01d4: Expected O, but got Unknown
		//IL_01cf: Unknown result type (might be due to invalid IL or missing references)
		//IL_01b0: Unknown result type (might be due to invalid IL or missing references)
		//IL_01ba: Expected O, but got Unknown
		//IL_01b5: Unknown result type (might be due to invalid IL or missing references)
		//IL_00c6: Unknown result type (might be due to invalid IL or missing references)
		//IL_00cd: Expected O, but got Unknown
		//IL_01d6: Expected O, but got Unknown
		//IL_01fa: Unknown result type (might be due to invalid IL or missing references)
		//IL_01e6: Unknown result type (might be due to invalid IL or missing references)
		//IL_0201: Expected O, but got Unknown
		//IL_0226: Unknown result type (might be due to invalid IL or missing references)
		//IL_0211: Unknown result type (might be due to invalid IL or missing references)
		//IL_0271: Unknown result type (might be due to invalid IL or missing references)
		//IL_027b: Expected O, but got Unknown
		//IL_029e: Unknown result type (might be due to invalid IL or missing references)
		//IL_02a3: Unknown result type (might be due to invalid IL or missing references)
		//IL_02aa: Unknown result type (might be due to invalid IL or missing references)
		//IL_02b5: Unknown result type (might be due to invalid IL or missing references)
		//IL_02c2: Expected O, but got Unknown
		//IL_02ee: Unknown result type (might be due to invalid IL or missing references)
		//IL_02f3: Unknown result type (might be due to invalid IL or missing references)
		//IL_02fe: Unknown result type (might be due to invalid IL or missing references)
		//IL_030b: Expected O, but got Unknown
		//IL_0398: Unknown result type (might be due to invalid IL or missing references)
		//IL_039d: Unknown result type (might be due to invalid IL or missing references)
		//IL_03a8: Unknown result type (might be due to invalid IL or missing references)
		//IL_03b5: Expected O, but got Unknown
		//IL_0357: Unknown result type (might be due to invalid IL or missing references)
		//IL_035c: Unknown result type (might be due to invalid IL or missing references)
		//IL_0367: Unknown result type (might be due to invalid IL or missing references)
		//IL_0374: Expected O, but got Unknown
		MessageBox.Show("提示：当前使用的是旧版 PDF 生成接口。\n建议使用新的专业级报告生成功能以获得更好的报告质量。\n如需使用新接口，请调用 GenerateProfessionalPdfReport 方法。", "PDF 报告生成", MessageBoxButton.OK, MessageBoxImage.Asterisk);
		string text = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "Reports");
		if (!Directory.Exists(text))
		{
			Directory.CreateDirectory(text);
		}
		string path = $"SecurityScanReport_{DateTime.Now:yyyyMMdd_HHmmss}.pdf";
		string text2 = Path.Combine(text, path);
		string text3 = text2 + ".tmp";
		try
		{
			if (File.Exists(text3))
			{
				File.Delete(text3);
			}
			if (File.Exists(text2))
			{
				File.Delete(text2);
			}
			using FileStream fileStream = new FileStream(text3, FileMode.Create, FileAccess.Write, FileShare.None);
			Document val = new Document(PageSize.A4, 50f, 50f, 50f, 50f);
			PdfWriter instance = PdfWriter.GetInstance(val, (Stream)fileStream);
			((DocWriter)instance).CloseStream = false;
			val.Open();
			BaseFont val2 = null;
			string[] array = new string[4] { "C:\\Windows\\Fonts\\msyh.ttc", "C:\\Windows\\Fonts\\simhei.ttf", "C:\\Windows\\Fonts\\simsun.ttc", "C:\\Windows\\Fonts\\simsun.ttf" };
			foreach (string text4 in array)
			{
				try
				{
					val2 = BaseFont.CreateFont(text4 + ",0", "Identity-H", true);
				}
				catch
				{
					continue;
				}
				break;
			}
			if (val2 == null)
			{
				try
				{
					val2 = BaseFont.CreateFont("Helvetica", "Cp1252", false);
				}
				catch
				{
					val2 = null;
				}
			}
			Font val3 = ((val2 != null) ? new Font(val2, 20f, 1, new BaseColor(44, 62, 80)) : new Font((FontFamily)1, 20f, 1, new BaseColor(44, 62, 80)));
			Font val4 = ((val2 != null) ? new Font(val2, 13f, 1, new BaseColor(33, 37, 41)) : new Font((FontFamily)1, 13f, 1, new BaseColor(33, 37, 41)));
			Font val5 = ((val2 != null) ? new Font(val2, 10f, 0, BaseColor.BLACK) : new Font((FontFamily)1, 10f, 0, BaseColor.BLACK));
			if (val2 == null)
			{
				new Font((FontFamily)1, 9f, 0, BaseColor.GRAY);
			}
			else
			{
				new Font(val2, 9f, 0, BaseColor.GRAY);
			}
			array = markdownContent.Split(new string[2] { "\r\n", "\n" }, StringSplitOptions.None);
			for (int i = 0; i < array.Length; i++)
			{
				string text5 = array[i].Trim();
				if (string.IsNullOrEmpty(text5))
				{
					val.Add((IElement)new Paragraph(" ", val5));
				}
				else if (text5.StartsWith("# "))
				{
					Paragraph val6 = new Paragraph(text5.Substring(2).Trim(), val3)
					{
						Alignment = 1,
						SpacingBefore = 12f,
						SpacingAfter = 8f
					};
					val.Add((IElement)(object)val6);
				}
				else if (text5.StartsWith("## "))
				{
					Paragraph val7 = new Paragraph(text5.Substring(3).Trim(), val4)
					{
						SpacingBefore = 8f,
						SpacingAfter = 5f
					};
					val.Add((IElement)(object)val7);
				}
				else if (!text5.StartsWith("---"))
				{
					if (text5.StartsWith("**") && text5.EndsWith("**"))
					{
						Paragraph val8 = new Paragraph(text5.Trim('*').Trim(), val4)
						{
							SpacingBefore = 3f,
							SpacingAfter = 2f
						};
						val.Add((IElement)(object)val8);
					}
					else
					{
						Paragraph val9 = new Paragraph(text5.Replace("|", "  ").Trim(), val5)
						{
							SpacingAfter = 3f,
							FirstLineIndent = 12f
						};
						val.Add((IElement)(object)val9);
					}
				}
			}
			val.Close();
			((DocWriter)instance).Close();
			fileStream.Close();
			File.Move(text3, text2, overwrite: true);
			Log("PDF报告生成成功：" + text2);
			return text2;
		}
		catch (Exception ex)
		{
			try
			{
				if (File.Exists(text3))
				{
					File.Delete(text3);
				}
			}
			catch
			{
			}
			throw new Exception("PDF报告生成失败: " + ex.Message + "\n建议使用 GenerateProfessionalPdfReport 方法生成专业级报告。");
		}
	}

	private string GenerateProfessionalPdfReport(List<PortScanResult> portScanResults, List<VulnerabilityResult> vulnerabilityResults, List<RiskAssessmentItem> riskAssessmentItems, string targetIp)
	{
		return ProfessionalPdfReportGenerator.GenerateReport(portScanResults, vulnerabilityResults, riskAssessmentItems, targetIp);
	}

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
		LicenseDialog licenseDialog = new LicenseDialog();
		licenseDialog.Owner = this;
		licenseDialog.ShowDialog();
		UpdateLicenseStatusBar();
	}

	private void UpdateLicenseStatusBar()
	{
		//IL_0000: Unknown result type (might be due to invalid IL or missing references)
		LicenseStatus licenseStatus = new LicenseService().GetLicenseStatus();
		if (licenseStatus.IsLicensed && licenseStatus.LicenseInfo != null)
		{
			LicenseStatusBarText.Text = "授权状态：" + licenseStatus.LicenseInfo.DisplayName;
			LicenseStatusBarText.Foreground = new SolidColorBrush(Color.FromRgb(39, 174, 96));
		}
		else
		{
			LicenseStatusBarText.Text = "授权状态：未授权";
			LicenseStatusBarText.Foreground = new SolidColorBrush(Color.FromRgb(149, 165, 166));
		}
	}

	private void LicenseTimer_Tick(object? sender, EventArgs e)
	{
		//IL_0000: Unknown result type (might be due to invalid IL or missing references)
		if (!new LicenseService().IsLicensed())
		{
			if (new LicenseDialog
			{
				Owner = this
			}.ShowDialog() != true)
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
		string appVersion = GetAppVersion();
		MessageBox.Show("网络安全扫描工具 v" + appVersion + "\n\n功能：\n- 端口扫描\n- 漏洞检测\n- 风险评估\n- 端口管理\n- 扫描历史记录\n\n仅供学习和测试使用", "关于", MessageBoxButton.OK, MessageBoxImage.Asterisk);
	}

	private async void CheckForUpdates_Click(object sender, RoutedEventArgs e)
	{
		await CheckForUpdatesAsync(forceCheck: true);
	}

	private async Task CheckForUpdatesAsync(bool forceCheck = false)
	{
		_ = 2;
		try
		{
			SettingsService settingsService = new SettingsService();
			UpdateSettings updateSettings = await settingsService.GetUpdateSettingsAsync();
			if (!forceCheck && updateSettings.LastCheckTime.HasValue && (DateTime.Now - updateSettings.LastCheckTime.Value).TotalHours < (double)updateSettings.NotifyIntervalHours)
			{
				return;
			}
			string version = VersionHelper.GetVersion();
			UpdateCheckService updateChecker = new UpdateCheckService((string)null);
			try
			{
				UpdateInfo updateInfo = await updateChecker.CheckForUpdateAsync(version, updateSettings);
				updateSettings.LastCheckTime = DateTime.Now;
				await settingsService.SaveUpdateSettingsAsync(updateSettings);
				if (updateInfo == null)
				{
					if (forceCheck)
					{
						MessageBox.Show("当前已是最新版本，无需更新。", "检查更新", MessageBoxButton.OK, MessageBoxImage.Asterisk);
					}
					return;
				}
				if (updateInfo.Version == updateSettings.SkippedVersion && (!forceCheck || MessageBox.Show("检测到新版本 " + updateInfo.Version + "（您之前已跳过），是否查看更新？", "检查更新", MessageBoxButton.YesNo, MessageBoxImage.Question) != MessageBoxResult.Yes))
				{
					return;
				}
				UpdateDialog updateDialog = new UpdateDialog(updateInfo, updateSettings);
				updateDialog.Owner = this;
				updateDialog.ShowDialog();
			}
			finally
			{
				((IDisposable)updateChecker)?.Dispose();
			}
		}
		catch (Exception ex)
		{
			if (forceCheck)
			{
				MessageBox.Show("检查更新失败：" + ex.Message, "错误", MessageBoxButton.OK, MessageBoxImage.Hand);
			}
		}
	}

	private async void RefreshScanHistory_Click(object sender, RoutedEventArgs e)
	{
		try
		{
			await RefreshScanHistoryAsync();
		}
		catch (Exception ex2)
		{
			Exception ex3 = ex2;
			Exception ex = ex3;
			Log("刷新扫描历史记录失败: " + ex.Message);
			if (((DispatcherObject)this).Dispatcher.CheckAccess())
			{
				MessageBox.Show("刷新扫描历史记录失败: " + ex.Message, "错误", MessageBoxButton.OK, MessageBoxImage.Hand);
				return;
			}
			((DispatcherObject)this).Dispatcher.Invoke((Action)delegate
			{
				MessageBox.Show("刷新扫描历史记录失败: " + ex.Message, "错误", MessageBoxButton.OK, MessageBoxImage.Hand);
			});
		}
	}

	private async void ClearScanHistory_Click(object sender, RoutedEventArgs e)
	{
		_ = 1;
		try
		{
			if (MessageBox.Show("确定要清空所有扫描历史记录吗？此操作不可恢复。", "警告", MessageBoxButton.YesNo, MessageBoxImage.Exclamation) == MessageBoxResult.Yes)
			{
				if (await _jsonDatabaseService.ClearAllScanHistoryAsync())
				{
					await RefreshScanHistoryAsync();
					StatusTextBlock.Text = "扫描历史记录已清空";
				}
				else
				{
					MessageBox.Show("清空扫描历史记录失败", "错误", MessageBoxButton.OK, MessageBoxImage.Hand);
					StatusTextBlock.Text = "清空扫描历史记录失败";
				}
			}
		}
		catch (Exception ex)
		{
			MessageBox.Show("清空扫描历史记录失败: " + ex.Message, "错误", MessageBoxButton.OK, MessageBoxImage.Hand);
			StatusTextBlock.Text = "清空扫描历史记录失败";
		}
	}

	private async void DeleteScanHistory_Click(object sender, RoutedEventArgs e)
	{
		_ = 1;
		try
		{
			if (sender is Button button)
			{
				string text = button.Tag.ToString();
				await _jsonDatabaseService.DeleteScanResultAsync(text);
				await RefreshScanHistoryAsync();
				StatusTextBlock.Text = "扫描历史记录已删除";
			}
		}
		catch (Exception ex)
		{
			MessageBox.Show("删除扫描历史记录失败: " + ex.Message, "错误", MessageBoxButton.OK, MessageBoxImage.Hand);
			StatusTextBlock.Text = "删除扫描历史记录失败";
		}
	}

	private async void ViewScanHistory_Click(object sender, RoutedEventArgs e)
	{
		try
		{
			if (sender is Button button)
			{
				string scanId = button.Tag.ToString();
				await ViewScanResultDetails(scanId);
			}
		}
		catch (Exception ex)
		{
			MessageBox.Show("查看扫描历史记录失败: " + ex.Message, "错误", MessageBoxButton.OK, MessageBoxImage.Hand);
		}
	}

	private async void ScanHistoryDataGrid_MouseDoubleClick(object sender, MouseButtonEventArgs e)
	{
		try
		{
			if (sender is DataGrid { SelectedItem: not null } dataGrid)
			{
				object selectedItem = dataGrid.SelectedItem;
				ScanHistoryItem val = (ScanHistoryItem)((selectedItem is ScanHistoryItem) ? selectedItem : null);
				if (val != null)
				{
					await ViewScanResultDetails(val.ScanId);
				}
			}
		}
		catch (Exception ex)
		{
			MessageBox.Show("查看扫描历史记录失败: " + ex.Message, "错误", MessageBoxButton.OK, MessageBoxImage.Hand);
		}
	}

	private void UpdateVulnerabilityDatabase_Click(object sender, RoutedEventArgs e)
	{
		VulnerabilityDatabaseUpdateWindow vulnerabilityDatabaseUpdateWindow = new VulnerabilityDatabaseUpdateWindow();
		vulnerabilityDatabaseUpdateWindow.Owner = this;
		vulnerabilityDatabaseUpdateWindow.ShowDialog();
		RefreshDatabaseStatus();
	}

	private void RefreshDatabaseStatus()
	{
		try
		{
			string path = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "NetSecurityScanner", "vulnerability_database.json");
			if (File.Exists(path))
			{
				StaticVulnerabilityDatabase val = JsonSerializer.Deserialize<StaticVulnerabilityDatabase>(File.ReadAllText(path));
				if (((val != null) ? val.Vulnerabilities : null) != null)
				{
					StatusTextBlock.Text = $"漏洞库: {val.Vulnerabilities.Count} 条记录";
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
			CompleteScanResult val = await _jsonDatabaseService.GetScanResultByIdAsync(scanId);
			if (val != null)
			{
				Window obj = new Window
				{
					Title = "扫描结果详情 - " + val.ScanId,
					Width = 800.0,
					Height = 600.0,
					WindowStartupLocation = WindowStartupLocation.CenterScreen,
					ResizeMode = ResizeMode.CanResize
				};
				ScrollViewer scrollViewer = new ScrollViewer();
				StackPanel stackPanel = new StackPanel
				{
					Margin = new Thickness(20.0)
				};
				stackPanel.Children.Add(new Label
				{
					Content = "扫描基本信息",
					FontWeight = FontWeights.Bold,
					FontSize = 16.0,
					Margin = new Thickness(0.0, 0.0, 0.0, 10.0)
				});
				stackPanel.Children.Add(new TextBlock
				{
					Text = "扫描ID: " + val.ScanId,
					Margin = new Thickness(0.0, 0.0, 0.0, 5.0)
				});
				stackPanel.Children.Add(new TextBlock
				{
					Text = "目标IP: " + val.TargetIp,
					Margin = new Thickness(0.0, 0.0, 0.0, 5.0)
				});
				stackPanel.Children.Add(new TextBlock
				{
					Text = "扫描类型: " + val.ScanType,
					Margin = new Thickness(0.0, 0.0, 0.0, 5.0)
				});
				stackPanel.Children.Add(new TextBlock
				{
					Text = $"扫描时间: {val.ScanTime}",
					Margin = new Thickness(0.0, 0.0, 0.0, 5.0)
				});
				stackPanel.Children.Add(new TextBlock
				{
					Text = "风险等级: " + val.RiskLevel,
					Margin = new Thickness(0.0, 0.0, 0.0, 15.0)
				});
				if (val.PortScanResults != null && val.PortScanResults.Any())
				{
					stackPanel.Children.Add(new Label
					{
						Content = "端口扫描结果",
						FontWeight = FontWeights.Bold,
						FontSize = 14.0,
						Margin = new Thickness(0.0, 0.0, 0.0, 10.0)
					});
					DataGrid dataGrid = new DataGrid
					{
						AutoGenerateColumns = false,
						CanUserAddRows = false,
						Margin = new Thickness(0.0, 0.0, 0.0, 15.0),
						AlternatingRowBackground = new SolidColorBrush(Color.FromRgb(245, 245, 245)),
						ItemsSource = val.PortScanResults
					};
					dataGrid.Columns.Add(new DataGridTextColumn
					{
						Header = "端口号",
						Binding = new Binding("PortNumber"),
						Width = new DataGridLength(1.0, DataGridLengthUnitType.Star)
					});
					dataGrid.Columns.Add(new DataGridTextColumn
					{
						Header = "状态",
						Binding = new Binding("Status"),
						Width = new DataGridLength(1.0, DataGridLengthUnitType.Star)
					});
					dataGrid.Columns.Add(new DataGridTextColumn
					{
						Header = "服务",
						Binding = new Binding("Service"),
						Width = new DataGridLength(1.0, DataGridLengthUnitType.Star)
					});
					dataGrid.Columns.Add(new DataGridTextColumn
					{
						Header = "服务版本",
						Binding = new Binding("ServiceVersion"),
						Width = new DataGridLength(2.0, DataGridLengthUnitType.Star)
					});
					stackPanel.Children.Add(dataGrid);
				}
				if (val.VulnerabilityResults != null && val.VulnerabilityResults.Any())
				{
					stackPanel.Children.Add(new Label
					{
						Content = "漏洞扫描结果",
						FontWeight = FontWeights.Bold,
						FontSize = 14.0,
						Margin = new Thickness(0.0, 0.0, 0.0, 10.0)
					});
					DataGrid dataGrid2 = new DataGrid
					{
						AutoGenerateColumns = false,
						CanUserAddRows = false,
						Margin = new Thickness(0.0, 0.0, 0.0, 15.0),
						AlternatingRowBackground = new SolidColorBrush(Color.FromRgb(245, 245, 245)),
						ItemsSource = val.VulnerabilityResults
					};
					dataGrid2.Columns.Add(new DataGridTextColumn
					{
						Header = "漏洞名称",
						Binding = new Binding("Name"),
						Width = new DataGridLength(2.0, DataGridLengthUnitType.Star)
					});
					dataGrid2.Columns.Add(new DataGridTextColumn
					{
						Header = "风险等级",
						Binding = new Binding("RiskLevel"),
						Width = new DataGridLength(1.0, DataGridLengthUnitType.Star)
					});
					dataGrid2.Columns.Add(new DataGridTextColumn
					{
						Header = "描述",
						Binding = new Binding("Description"),
						Width = new DataGridLength(3.0, DataGridLengthUnitType.Star),
						ElementStyle = new Style(typeof(TextBlock))
						{
							Setters = { (SetterBase)new Setter(TextBlock.TextWrappingProperty, TextWrapping.Wrap) }
						}
					});
					stackPanel.Children.Add(dataGrid2);
				}
				if (val.RiskAssessment != null)
				{
					stackPanel.Children.Add(new Label
					{
						Content = "风险评估",
						FontWeight = FontWeights.Bold,
						FontSize = 14.0,
						Margin = new Thickness(0.0, 0.0, 0.0, 10.0)
					});
					stackPanel.Children.Add(new TextBlock
					{
						Text = "总体风险: " + val.RiskAssessment.RiskLevel,
						Margin = new Thickness(0.0, 0.0, 0.0, 5.0)
					});
					if (!string.IsNullOrEmpty(val.RiskAssessment.SecurityAdvice))
					{
						stackPanel.Children.Add(new Label
						{
							Content = "安全建议",
							FontWeight = FontWeights.Bold,
							Margin = new Thickness(0.0, 10.0, 0.0, 5.0)
						});
						stackPanel.Children.Add(new TextBlock
						{
							Text = val.RiskAssessment.SecurityAdvice,
							TextWrapping = TextWrapping.Wrap,
							Margin = new Thickness(0.0, 0.0, 0.0, 15.0)
						});
					}
				}
				scrollViewer.Content = stackPanel;
				obj.Content = scrollViewer;
				obj.ShowDialog();
			}
			else
			{
				MessageBox.Show("无法找到指定的扫描结果", "错误", MessageBoxButton.OK, MessageBoxImage.Hand);
			}
		}
		catch (Exception ex)
		{
			MessageBox.Show("查看扫描结果详情失败: " + ex.Message, "错误", MessageBoxButton.OK, MessageBoxImage.Hand);
		}
	}

	private async void SearchTextBox_TextChanged(object sender, TextChangedEventArgs e)
	{
		try
		{
			await SearchScanHistory();
		}
		catch (Exception ex2)
		{
			Exception ex3 = ex2;
			Exception ex = ex3;
			Log("搜索扫描历史记录失败: " + ex.Message);
			if (((DispatcherObject)this).Dispatcher.CheckAccess())
			{
				MessageBox.Show("搜索扫描历史记录失败: " + ex.Message, "错误", MessageBoxButton.OK, MessageBoxImage.Hand);
				return;
			}
			((DispatcherObject)this).Dispatcher.Invoke((Action)delegate
			{
				MessageBox.Show("搜索扫描历史记录失败: " + ex.Message, "错误", MessageBoxButton.OK, MessageBoxImage.Hand);
			});
		}
	}

	private async void SearchScanHistory_Click(object sender, RoutedEventArgs e)
	{
		try
		{
			await SearchScanHistory();
		}
		catch (Exception ex2)
		{
			Exception ex3 = ex2;
			Exception ex = ex3;
			Log("手动搜索扫描历史记录失败: " + ex.Message);
			if (((DispatcherObject)this).Dispatcher.CheckAccess())
			{
				MessageBox.Show("手动搜索扫描历史记录失败: " + ex.Message, "错误", MessageBoxButton.OK, MessageBoxImage.Hand);
				return;
			}
			((DispatcherObject)this).Dispatcher.Invoke((Action)delegate
			{
				MessageBox.Show("手动搜索扫描历史记录失败: " + ex.Message, "错误", MessageBoxButton.OK, MessageBoxImage.Hand);
			});
		}
	}

	private async void RiskLevelFilterComboBox_SelectionChanged(object sender, SelectionChangedEventArgs e)
	{
		try
		{
			await FilterScanHistory();
		}
		catch (Exception ex2)
		{
			Exception ex3 = ex2;
			Exception ex = ex3;
			Log("风险等级过滤失败: " + ex.Message);
			if (((DispatcherObject)this).Dispatcher.CheckAccess())
			{
				MessageBox.Show("风险等级过滤失败: " + ex.Message, "错误", MessageBoxButton.OK, MessageBoxImage.Hand);
				return;
			}
			((DispatcherObject)this).Dispatcher.Invoke((Action)delegate
			{
				MessageBox.Show("风险等级过滤失败: " + ex.Message, "错误", MessageBoxButton.OK, MessageBoxImage.Hand);
			});
		}
	}

	private async void ScanTypeFilterComboBox_SelectionChanged(object sender, SelectionChangedEventArgs e)
	{
		try
		{
			await FilterScanHistory();
		}
		catch (Exception ex2)
		{
			Exception ex3 = ex2;
			Exception ex = ex3;
			Log("扫描类型过滤失败: " + ex.Message);
			if (((DispatcherObject)this).Dispatcher.CheckAccess())
			{
				MessageBox.Show("扫描类型过滤失败: " + ex.Message, "错误", MessageBoxButton.OK, MessageBoxImage.Hand);
				return;
			}
			((DispatcherObject)this).Dispatcher.Invoke((Action)delegate
			{
				MessageBox.Show("扫描类型过滤失败: " + ex.Message, "错误", MessageBoxButton.OK, MessageBoxImage.Hand);
			});
		}
	}

	private async void ResetFilters_Click(object sender, RoutedEventArgs e)
	{
		try
		{
			SearchTextBox.Text = string.Empty;
			RiskLevelFilterComboBox.SelectedIndex = 0;
			ScanTypeFilterComboBox.SelectedIndex = 0;
			await RefreshScanHistoryAsync();
		}
		catch (Exception ex2)
		{
			Exception ex3 = ex2;
			Exception ex = ex3;
			Log("重置过滤条件失败: " + ex.Message);
			if (((DispatcherObject)this).Dispatcher.CheckAccess())
			{
				MessageBox.Show("重置过滤条件失败: " + ex.Message, "错误", MessageBoxButton.OK, MessageBoxImage.Hand);
				return;
			}
			((DispatcherObject)this).Dispatcher.Invoke((Action)delegate
			{
				MessageBox.Show("重置过滤条件失败: " + ex.Message, "错误", MessageBoxButton.OK, MessageBoxImage.Hand);
			});
		}
	}

	private async Task SearchScanHistory()
	{
		_ = 1;
		try
		{
			string text = SearchTextBox.Text.Trim();
			if (string.IsNullOrEmpty(text))
			{
				await FilterScanHistory();
				return;
			}
			List<ScanHistoryItem> list = await _jsonDatabaseService.SearchScanHistoryAsync(text);
			UpdateScanHistoryDisplay(list);
			StatusTextBlock.Text = $"搜索完成，找到 {list.Count} 条记录";
		}
		catch (Exception ex)
		{
			MessageBox.Show("搜索扫描历史记录失败: " + ex.Message, "错误", MessageBoxButton.OK, MessageBoxImage.Hand);
		}
	}

	private async Task FilterScanHistory()
	{
		try
		{
			if (RiskLevelFilterComboBox == null || ScanTypeFilterComboBox == null || _jsonDatabaseService == null)
			{
				await Task.Delay(100);
				if (RiskLevelFilterComboBox == null || ScanTypeFilterComboBox == null || _jsonDatabaseService == null)
				{
					return;
				}
			}
			string text = (RiskLevelFilterComboBox.SelectedItem as ComboBoxItem)?.Content.ToString();
			string text2 = (ScanTypeFilterComboBox.SelectedItem as ComboBoxItem)?.Content.ToString();
			text = ((text == "全部") ? null : text);
			text2 = ((text2 == "全部") ? null : text2);
			List<ScanHistoryItem> histories = await _jsonDatabaseService.GetScanHistoryAsync((string)null, text2, (DateTime?)null, (DateTime?)null, text);
			await ((DispatcherObject)this).Dispatcher.BeginInvoke((Delegate)(Action)delegate
			{
				UpdateScanHistoryDisplay(histories);
			}, Array.Empty<object>());
		}
		catch (Exception ex2)
		{
			Exception ex = ex2;
			Log("过滤扫描历史记录失败: " + ex.Message);
			await ((DispatcherObject)this).Dispatcher.BeginInvoke((Delegate)(Action)delegate
			{
				MessageBox.Show("过滤扫描历史记录失败: " + ex.Message, "错误", MessageBoxButton.OK, MessageBoxImage.Hand);
			}, Array.Empty<object>());
		}
	}

	private void UpdateScanHistoryDisplay(List<ScanHistoryItem> histories)
	{
		ScanHistoryDataGrid.ItemsSource = histories;
		ScanHistoryStats.Text = $"共 {histories.Count} 条记录";
		GenerateReportFromHistoryButton.IsEnabled = histories.Any();
	}

	private List<ScanHistoryItem> GetSelectedScanHistoryItems()
	{
		if (!(ScanHistoryDataGrid.ItemsSource is List<ScanHistoryItem> source))
		{
			return new List<ScanHistoryItem>();
		}
		return source.Where((ScanHistoryItem item) => item.IsSelected).ToList();
	}

	private async void GenerateReportFromHistory_Click(object sender, RoutedEventArgs e)
	{
		try
		{
			List<ScanHistoryItem> selectedScanHistoryItems = GetSelectedScanHistoryItems();
			if (!selectedScanHistoryItems.Any())
			{
				MessageBox.Show("请先选择要生成报告的历史记录", "提示", MessageBoxButton.OK, MessageBoxImage.Asterisk);
				return;
			}
			List<CompleteScanResult> completeResults = new List<CompleteScanResult>();
			foreach (ScanHistoryItem item in selectedScanHistoryItems)
			{
				CompleteScanResult val = await _jsonDatabaseService.GetScanResultByIdAsync(item.ScanId);
				if (val != null)
				{
					completeResults.Add(val);
				}
			}
			if (!completeResults.Any())
			{
				MessageBox.Show("无法获取选中的扫描结果", "错误", MessageBoxButton.OK, MessageBoxImage.Hand);
			}
			else
			{
				ExportReportWithDialog(completeResults);
			}
		}
		catch (Exception ex)
		{
			Log("生成报告失败: " + ex.Message);
			MessageBox.Show("生成报告失败: " + ex.Message, "错误", MessageBoxButton.OK, MessageBoxImage.Hand);
		}
	}

	private async Task<string> GeneratePdfReport(List<CompleteScanResult> completeResults, string savePath)
	{
		List<CompleteScanResult> completeResults2 = completeResults;
		string savePath2 = savePath;
		return await Task.Run(delegate
		{
			try
			{
				return (completeResults2.Count != 1) ? HistoryReportGenerator.GenerateFromMultipleRecordsToPath(completeResults2, savePath2) : HistoryReportGenerator.GenerateFromHistoryRecordToPath(completeResults2[0], savePath2);
			}
			catch (Exception ex2)
			{
				Exception ex3 = ex2;
				Exception ex = ex3;
				((DispatcherObject)this).Dispatcher.Invoke((Action)delegate
				{
					MessageBox.Show("生成PDF报告失败:\n" + ex.Message, "导出错误", MessageBoxButton.OK, MessageBoxImage.Hand);
				});
				return string.Empty;
			}
		});
	}

	private async Task<string> GenerateWordReport(List<CompleteScanResult> completeResults, string savePath)
	{
		List<CompleteScanResult> completeResults2 = completeResults;
		string savePath2 = savePath;
		return await Task.Run(delegate
		{
			try
			{
				return (completeResults2.Count != 1) ? HistoryWordReportGenerator.GenerateFromMultipleRecordsToPath(completeResults2, savePath2) : HistoryWordReportGenerator.GenerateFromHistoryRecordToPath(completeResults2[0], savePath2);
			}
			catch (Exception ex2)
			{
				Exception ex3 = ex2;
				Exception ex = ex3;
				((DispatcherObject)this).Dispatcher.Invoke((Action)delegate
				{
					MessageBox.Show("生成Word报告失败:\n" + ex.Message, "导出错误", MessageBoxButton.OK, MessageBoxImage.Hand);
				});
				return string.Empty;
			}
		});
	}

	private async Task<string> GenerateHtmlReport(List<CompleteScanResult> completeResults, string savePath)
	{
		List<CompleteScanResult> completeResults2 = completeResults;
		string savePath2 = savePath;
		return await Task.Run(delegate
		{
			try
			{
				List<PortScanResult> list = completeResults2.SelectMany((CompleteScanResult r) => r.PortScanResults ?? new List<PortScanResult>()).ToList();
				List<VulnerabilityResult> list2 = completeResults2.SelectMany((CompleteScanResult r) => r.VulnerabilityResults ?? new List<VulnerabilityResult>()).ToList();
				string value = string.Join(", ", completeResults2.Select((CompleteScanResult r) => r.TargetIp).Distinct());
				List<PortScanResult> list3 = list.Where((PortScanResult p) => ((p != null) ? p.Status : null) == "开放" || ((p == null) ? null : p.Status?.ToLower()) == "open").ToList();
				int num = list2.Count((VulnerabilityResult v) => IsCriticalLevel((v != null) ? v.RiskLevel : null) || IsHighLevel((v != null) ? v.RiskLevel : null));
				string text = CalculateOverallRiskFromVulns(list2);
				int value2 = list2.Count((VulnerabilityResult v) => IsMediumLevel((v != null) ? v.RiskLevel : null));
				int value3 = list2.Count((VulnerabilityResult v) => IsLowLevel((v != null) ? v.RiskLevel : null));
				int value4 = (list2.Any() ? ((int)((double)num / (double)list2.Count * 100.0)) : 0);
				string value5 = text switch
				{
					"中" => "#d97706", 
					"高" => "#c2410c", 
					"严重" => "#991b1b", 
					_ => "#059669", 
				};
				StringBuilder stringBuilder = new StringBuilder();
				stringBuilder.AppendLine("<!DOCTYPE html>");
				stringBuilder.AppendLine("<html lang='zh-CN'><head><meta charset='UTF-8'>");
				stringBuilder.AppendLine("<meta name='viewport' content='width=device-width, initial-scale=1.0'>");
				stringBuilder.AppendLine("<title>网络安全漏洞扫描评估报告</title>");
				stringBuilder.AppendLine("<style>");
				stringBuilder.AppendLine("* { box-sizing: border-box; margin: 0; padding: 0; }");
				stringBuilder.AppendLine("body { font-family: 'Microsoft YaHei', 'Segoe UI', sans-serif; background: #f1f5f9; color: #334155; line-height: 1.6; }");
				stringBuilder.AppendLine(".container { max-width: 1100px; margin: 0 auto; background: white; box-shadow: 0 1px 3px rgba(0,0,0,0.1); }");
				stringBuilder.AppendLine(".cover { background: linear-gradient(135deg, #1a365d 0%, #2563eb 100%); color: white; padding: 60px 50px; text-align: center; }");
				stringBuilder.AppendLine(".cover h1 { font-size: 28px; margin-bottom: 8px; letter-spacing: 2px; }");
				stringBuilder.AppendLine(".cover h2 { font-size: 14px; font-weight: normal; opacity: 0.8; margin-bottom: 30px; }");
				stringBuilder.AppendLine(".cover-info { display: inline-block; text-align: left; background: rgba(255,255,255,0.1); border-radius: 8px; padding: 20px 30px; margin-top: 20px; }");
				stringBuilder.AppendLine(".cover-info p { margin: 4px 0; font-size: 13px; }");
				stringBuilder.AppendLine(".cover-info strong { display: inline-block; width: 90px; }");
				stringBuilder.AppendLine(".stats-row { display: flex; justify-content: center; gap: 20px; padding: 30px 50px; background: #f8fafc; border-bottom: 1px solid #e2e8f0; }");
				stringBuilder.AppendLine(".stat-card { background: white; border: 1px solid #e2e8f0; border-radius: 8px; padding: 20px 30px; text-align: center; min-width: 160px; }");
				stringBuilder.AppendLine(".stat-card .value { font-size: 28px; font-weight: bold; }");
				stringBuilder.AppendLine(".stat-card .label { font-size: 12px; color: #94a3b8; margin-top: 4px; }");
				stringBuilder.AppendLine(".content { padding: 40px 50px; }");
				stringBuilder.AppendLine("h2 { color: #1a365d; font-size: 20px; margin: 35px 0 15px; padding-bottom: 8px; border-bottom: 2px solid #1a365d; }");
				stringBuilder.AppendLine("h3 { color: #2563eb; font-size: 15px; margin: 25px 0 10px; padding-left: 12px; border-left: 4px solid #2563eb; }");
				stringBuilder.AppendLine("p { margin: 8px 0; }");
				stringBuilder.AppendLine("table { border-collapse: collapse; width: 100%; margin: 15px 0; font-size: 13px; }");
				stringBuilder.AppendLine("th { background: #1e293b; color: white; padding: 10px 14px; text-align: left; font-weight: 600; }");
				stringBuilder.AppendLine("td { border: 1px solid #e2e8f0; padding: 8px 14px; }");
				stringBuilder.AppendLine("tr:nth-child(even) { background: #f8fafc; }");
				stringBuilder.AppendLine("tr:hover { background: #f1f5f9; }");
				stringBuilder.AppendLine(".risk-critical { color: #991b1b; font-weight: bold; background: #fef2f2; padding: 2px 8px; border-radius: 3px; }");
				stringBuilder.AppendLine(".risk-high { color: #c2410c; font-weight: bold; background: #fff7ed; padding: 2px 8px; border-radius: 3px; }");
				stringBuilder.AppendLine(".risk-medium { color: #d97706; font-weight: bold; background: #fefce8; padding: 2px 8px; border-radius: 3px; }");
				stringBuilder.AppendLine(".risk-low { color: #059669; font-weight: bold; background: #ecfdf5; padding: 2px 8px; border-radius: 3px; }");
				stringBuilder.AppendLine(".vuln-card { border: 1px solid #e2e8f0; border-radius: 8px; margin: 12px 0; overflow: hidden; }");
				stringBuilder.AppendLine(".vuln-card .card-header { padding: 12px 18px; color: white; font-weight: bold; font-size: 14px; }");
				stringBuilder.AppendLine(".vuln-card .card-body { padding: 15px 18px; }");
				stringBuilder.AppendLine(".vuln-card .card-body p { margin: 6px 0; font-size: 13px; }");
				stringBuilder.AppendLine(".vuln-card .card-body .section-title { font-weight: bold; color: #1e293b; margin-top: 10px; }");
				stringBuilder.AppendLine(".priority-table td:first-child { font-weight: bold; }");
				stringBuilder.AppendLine(".hardening-item { background: #f8fafc; border-left: 3px solid #2563eb; padding: 12px 18px; margin: 8px 0; border-radius: 0 6px 6px 0; }");
				stringBuilder.AppendLine(".hardening-item strong { color: #1a365d; }");
				stringBuilder.AppendLine(".threat-item { background: #fef2f2; border-left: 3px solid #dc2626; padding: 12px 18px; margin: 8px 0; border-radius: 0 6px 6px 0; }");
				stringBuilder.AppendLine(".threat-item strong { color: #991b1b; }");
				stringBuilder.AppendLine(".gap-item { background: #fefce8; border-left: 3px solid #d97706; padding: 12px 18px; margin: 8px 0; border-radius: 0 6px 6px 0; }");
				stringBuilder.AppendLine(".gap-item strong { color: #92400e; }");
				stringBuilder.AppendLine(".footer { background: #1e293b; color: #94a3b8; padding: 20px 50px; font-size: 11px; text-align: center; }");
				stringBuilder.AppendLine(".bar-container { background: #e2e8f0; border-radius: 4px; height: 20px; margin: 4px 0; overflow: hidden; }");
				stringBuilder.AppendLine(".bar-fill { height: 100%; border-radius: 4px; display: flex; align-items: center; padding-left: 8px; color: white; font-size: 11px; font-weight: bold; }");
				stringBuilder.AppendLine(".cvss-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 4px 20px; margin: 8px 0; padding: 12px; background: #f8fafc; border-radius: 6px; border: 1px solid #e2e8f0; }");
				stringBuilder.AppendLine(".cvss-grid .cvss-item { font-size: 13px; padding: 3px 0; display: flex; justify-content: space-between; }");
				stringBuilder.AppendLine(".cvss-grid .cvss-label { color: #64748b; }");
				stringBuilder.AppendLine(".cvss-grid .cvss-value { font-weight: 600; color: #1e293b; }");
				stringBuilder.AppendLine(".cvss-total { font-size: 15px; font-weight: bold; text-align: center; padding: 8px; margin-top: 6px; border-radius: 0 0 6px 6px; }");
				stringBuilder.AppendLine(".impact-analyze { background: #fefce8; border-left: 3px solid #eab308; padding: 10px 14px; margin: 8px 0; border-radius: 0 6px 6px 0; font-size: 13px; }");
				stringBuilder.AppendLine(".impact-critical { background: #fef2f2; border-left-color: #dc2626; }");
				stringBuilder.AppendLine(".section-info { font-size: 12px; color: #64748b; margin-bottom: 5px; }");
				stringBuilder.AppendLine(".chart-container { background: #f8fafc; border: 1px solid #e2e8f0; border-radius: 8px; padding: 20px; margin: 20px 0; }");
				stringBuilder.AppendLine(".chart-container h4 { color: #1a365d; margin: 0 0 12px 0; font-size: 14px; }");
				stringBuilder.AppendLine(".ref-link { color: #2563eb; word-break: break-all; font-size: 12px; }");
				stringBuilder.AppendLine("</style></head><body>");
				stringBuilder.AppendLine("<div class='container'>");
				stringBuilder.AppendLine("<div class='cover'>");
				stringBuilder.AppendLine("<h1>网络安全漏洞扫描评估报告</h1>");
				stringBuilder.AppendLine("<h2>Network Security Vulnerability Assessment Report</h2>");
				string value6 = BuildScanTypeDescription(completeResults2);
				List<string> activeScanFeatures = GetActiveScanFeatures(completeResults2);
				bool flag = activeScanFeatures.Contains("TCP端口扫描");
				bool flag2 = activeScanFeatures.Contains("漏洞扫描");
				bool flag3 = activeScanFeatures.Contains("专家模式");
				stringBuilder.AppendLine("<div class='cover-info'>");
				stringBuilder.AppendLine($"<p><strong>报告编号：</strong>RPT-{DateTime.Now:yyyyMMdd}-{Guid.NewGuid():N}".Substring(0, 40) + "</p>");
				StringBuilder stringBuilder2 = stringBuilder;
				StringBuilder stringBuilder3 = stringBuilder2;
				StringBuilder.AppendInterpolatedStringHandler handler = new StringBuilder.AppendInterpolatedStringHandler(29, 1, stringBuilder2);
				handler.AppendLiteral("<p><strong>目标系统：</strong>");
				handler.AppendFormatted(value);
				handler.AppendLiteral("</p>");
				stringBuilder3.AppendLine(ref handler);
				stringBuilder2 = stringBuilder;
				StringBuilder stringBuilder4 = stringBuilder2;
				handler = new StringBuilder.AppendInterpolatedStringHandler(29, 1, stringBuilder2);
				handler.AppendLiteral("<p><strong>扫描时间：</strong>");
				handler.AppendFormatted(DateTime.Now, "yyyy-MM-dd HH:mm:ss");
				handler.AppendLiteral("</p>");
				stringBuilder4.AppendLine(ref handler);
				stringBuilder2 = stringBuilder;
				StringBuilder stringBuilder5 = stringBuilder2;
				handler = new StringBuilder.AppendInterpolatedStringHandler(29, 1, stringBuilder2);
				handler.AppendLiteral("<p><strong>扫描类型：</strong>");
				handler.AppendFormatted(value6);
				handler.AppendLiteral("</p>");
				stringBuilder5.AppendLine(ref handler);
				if (flag3)
				{
					stringBuilder.AppendLine("<p><strong>扫描模式：</strong>专家深度扫描（Expert Mode）</p>");
				}
				stringBuilder2 = stringBuilder;
				StringBuilder stringBuilder6 = stringBuilder2;
				handler = new StringBuilder.AppendInterpolatedStringHandler(29, 1, stringBuilder2);
				handler.AppendLiteral("<p><strong>生成时间：</strong>");
				handler.AppendFormatted(DateTime.Now, "yyyy-MM-dd HH:mm:ss");
				handler.AppendLiteral("</p>");
				stringBuilder6.AppendLine(ref handler);
				stringBuilder.AppendLine("</div></div>");
				stringBuilder.AppendLine("<div class='stats-row'>");
				stringBuilder2 = stringBuilder;
				StringBuilder stringBuilder7 = stringBuilder2;
				handler = new StringBuilder.AppendInterpolatedStringHandler(98, 2, stringBuilder2);
				handler.AppendLiteral("<div class='stat-card'><div class='value' style='color:");
				handler.AppendFormatted(value5);
				handler.AppendLiteral("'>");
				handler.AppendFormatted(text);
				handler.AppendLiteral("</div><div class='label'>风险等级</div></div>");
				stringBuilder7.AppendLine(ref handler);
				stringBuilder2 = stringBuilder;
				StringBuilder stringBuilder8 = stringBuilder2;
				handler = new StringBuilder.AppendInterpolatedStringHandler(105, 1, stringBuilder2);
				handler.AppendLiteral("<div class='stat-card'><div class='value' style='color:#2563eb'>");
				handler.AppendFormatted(list3.Count);
				handler.AppendLiteral("</div><div class='label'>开放端口</div></div>");
				stringBuilder8.AppendLine(ref handler);
				stringBuilder2 = stringBuilder;
				StringBuilder stringBuilder9 = stringBuilder2;
				handler = new StringBuilder.AppendInterpolatedStringHandler(105, 1, stringBuilder2);
				handler.AppendLiteral("<div class='stat-card'><div class='value' style='color:#dc2626'>");
				handler.AppendFormatted(list2.Count);
				handler.AppendLiteral("</div><div class='label'>漏洞总数</div></div>");
				stringBuilder9.AppendLine(ref handler);
				stringBuilder2 = stringBuilder;
				StringBuilder stringBuilder10 = stringBuilder2;
				handler = new StringBuilder.AppendInterpolatedStringHandler(106, 1, stringBuilder2);
				handler.AppendLiteral("<div class='stat-card'><div class='value' style='color:#f59e0b'>");
				handler.AppendFormatted(value4);
				handler.AppendLiteral("%</div><div class='label'>高危占比</div></div>");
				stringBuilder10.AppendLine(ref handler);
				stringBuilder.AppendLine("</div>");
				stringBuilder.AppendLine("<div class='content'>");
				stringBuilder.AppendLine("<h2 style='color:#1a365d;border-bottom:2px solid #3b82f6;padding-bottom:6px;'>扫描配置信息</h2>");
				stringBuilder.AppendLine("<table><tr><th>扫描项目</th><th>状态</th><th>数据来源</th></tr>");
				stringBuilder2 = stringBuilder;
				StringBuilder stringBuilder11 = stringBuilder2;
				handler = new StringBuilder.AppendInterpolatedStringHandler(92, 3, stringBuilder2);
				handler.AppendLiteral("<tr><td><strong>TCP端口扫描</strong></td><td style='color:");
				handler.AppendFormatted(flag ? "#059669" : "#94a3b8");
				handler.AppendLiteral(";font-weight:bold'>");
				handler.AppendFormatted(flag ? "✓ 已执行" : "✗ 未执行");
				handler.AppendLiteral("</td><td>");
				handler.AppendFormatted(flag ? $"{list3.Count}个开放端口" : "-");
				handler.AppendLiteral("</td></tr>");
				stringBuilder11.AppendLine(ref handler);
				stringBuilder2 = stringBuilder;
				StringBuilder stringBuilder12 = stringBuilder2;
				handler = new StringBuilder.AppendInterpolatedStringHandler(89, 3, stringBuilder2);
				handler.AppendLiteral("<tr><td><strong>漏洞扫描</strong></td><td style='color:");
				handler.AppendFormatted(flag2 ? "#059669" : "#94a3b8");
				handler.AppendLiteral(";font-weight:bold'>");
				handler.AppendFormatted(flag2 ? "✓ 已执行" : "✗ 未执行");
				handler.AppendLiteral("</td><td>");
				handler.AppendFormatted(flag2 ? $"{list2.Count}个漏洞" : "-");
				handler.AppendLiteral("</td></tr>");
				stringBuilder12.AppendLine(ref handler);
				stringBuilder2 = stringBuilder;
				StringBuilder stringBuilder13 = stringBuilder2;
				handler = new StringBuilder.AppendInterpolatedStringHandler(89, 3, stringBuilder2);
				handler.AppendLiteral("<tr><td><strong>专家模式</strong></td><td style='color:");
				handler.AppendFormatted(flag3 ? "#059669" : "#94a3b8");
				handler.AppendLiteral(";font-weight:bold'>");
				handler.AppendFormatted(flag3 ? "✓ 已启用" : "✗ 未启用");
				handler.AppendLiteral("</td><td>");
				handler.AppendFormatted(flag3 ? "深度检测+合规评估" : "-");
				handler.AppendLiteral("</td></tr>");
				stringBuilder13.AppendLine(ref handler);
				stringBuilder.AppendLine("</table>");
				stringBuilder.AppendLine("<p style='font-size:12px;color:#64748b;margin-top:6px;'>以上扫描项目根据选择的扫描历史记录自动合并填充至报告中。</p>");
				stringBuilder.AppendLine("<h2>一、执行摘要</h2>");
				stringBuilder.AppendLine("<p>本节提供本次安全扫描的核心发现和统计概览，帮助快速了解目标系统的整体安全态势。</p>");
				stringBuilder.AppendLine("<h3>1.1 核心统计数据</h3>");
				stringBuilder.AppendLine("<table><tr><th>统计项</th><th>数值</th></tr>");
				stringBuilder2 = stringBuilder;
				StringBuilder stringBuilder14 = stringBuilder2;
				handler = new StringBuilder.AppendInterpolatedStringHandler(78, 2, stringBuilder2);
				handler.AppendLiteral("<tr><td>总体风险等级</td><td><span style='color:");
				handler.AppendFormatted(value5);
				handler.AppendLiteral(";font-weight:bold'>");
				handler.AppendFormatted(text);
				handler.AppendLiteral("</span></td></tr>");
				stringBuilder14.AppendLine(ref handler);
				stringBuilder2 = stringBuilder;
				StringBuilder stringBuilder15 = stringBuilder2;
				handler = new StringBuilder.AppendInterpolatedStringHandler(33, 2, stringBuilder2);
				handler.AppendLiteral("<tr><td>开放端口数</td><td>");
				handler.AppendFormatted(list3.Count);
				handler.AppendLiteral("/");
				handler.AppendFormatted(list.Count);
				handler.AppendLiteral("</td></tr>");
				stringBuilder15.AppendLine(ref handler);
				stringBuilder2 = stringBuilder;
				StringBuilder stringBuilder16 = stringBuilder2;
				handler = new StringBuilder.AppendInterpolatedStringHandler(31, 1, stringBuilder2);
				handler.AppendLiteral("<tr><td>漏洞总数</td><td>");
				handler.AppendFormatted(list2.Count);
				handler.AppendLiteral("</td></tr>");
				stringBuilder16.AppendLine(ref handler);
				stringBuilder2 = stringBuilder;
				StringBuilder stringBuilder17 = stringBuilder2;
				handler = new StringBuilder.AppendInterpolatedStringHandler(34, 1, stringBuilder2);
				handler.AppendLiteral("<tr><td>严重/高危漏洞</td><td>");
				handler.AppendFormatted(num);
				handler.AppendLiteral("</td></tr>");
				stringBuilder17.AppendLine(ref handler);
				stringBuilder2 = stringBuilder;
				StringBuilder stringBuilder18 = stringBuilder2;
				handler = new StringBuilder.AppendInterpolatedStringHandler(31, 1, stringBuilder2);
				handler.AppendLiteral("<tr><td>中危漏洞</td><td>");
				handler.AppendFormatted(value2);
				handler.AppendLiteral("</td></tr>");
				stringBuilder18.AppendLine(ref handler);
				stringBuilder2 = stringBuilder;
				StringBuilder stringBuilder19 = stringBuilder2;
				handler = new StringBuilder.AppendInterpolatedStringHandler(31, 1, stringBuilder2);
				handler.AppendLiteral("<tr><td>低危漏洞</td><td>");
				handler.AppendFormatted(value3);
				handler.AppendLiteral("</td></tr>");
				stringBuilder19.AppendLine(ref handler);
				stringBuilder.AppendLine("</table>");
				int num2 = CalculateSecurityScoreFromVulns(list2, list3);
				stringBuilder.AppendLine("<h3>1.2 安全评分仪表盘</h3>");
				stringBuilder.AppendLine("<div class='chart-container'>");
				stringBuilder.AppendLine("<div style='display:flex;align-items:center;justify-content:center;gap:30px;flex-wrap:wrap;'>");
				stringBuilder.AppendLine("<div style='text-align:center;'>");
				stringBuilder.AppendLine("<svg width='220' height='160' viewBox='0 0 220 160'>");
				stringBuilder.AppendLine("<path d='M40,130 A90,90 0 0,1 180,130' fill='none' stroke='#e2e8f0' stroke-width='18' stroke-linecap='round'/>");
				double num3 = Math.Min(180.0, (double)num2 / 100.0 * 180.0);
				string value7 = text switch
				{
					"中" => "#d97706", 
					"高" => "#c2410c", 
					"严重" => "#991b1b", 
					_ => "#059669", 
				};
				double num4 = num3 * Math.PI / 180.0;
				double value8 = 110.0 + 90.0 * Math.Cos(num4);
				double value9 = 130.0 - 90.0 * Math.Sin(num4);
				int value10 = ((num3 > 90.0) ? 1 : 0);
				stringBuilder2 = stringBuilder;
				StringBuilder stringBuilder20 = stringBuilder2;
				handler = new StringBuilder.AppendInterpolatedStringHandler(96, 4, stringBuilder2);
				handler.AppendLiteral("<path d='M40,130 A90,90 0 ");
				handler.AppendFormatted(value10);
				handler.AppendLiteral(",1 ");
				handler.AppendFormatted(value8, "F1");
				handler.AppendLiteral(",");
				handler.AppendFormatted(value9, "F1");
				handler.AppendLiteral("' fill='none' stroke='");
				handler.AppendFormatted(value7);
				handler.AppendLiteral("' stroke-width='18' stroke-linecap='round'/>");
				stringBuilder20.AppendLine(ref handler);
				stringBuilder2 = stringBuilder;
				StringBuilder stringBuilder21 = stringBuilder2;
				handler = new StringBuilder.AppendInterpolatedStringHandler(92, 2, stringBuilder2);
				handler.AppendLiteral("<text x='110' y='115' text-anchor='middle' font-size='28' font-weight='bold' fill='");
				handler.AppendFormatted(value7);
				handler.AppendLiteral("'>");
				handler.AppendFormatted(num2);
				handler.AppendLiteral("</text>");
				stringBuilder21.AppendLine(ref handler);
				stringBuilder.AppendLine("<text x='110' y='140' text-anchor='middle' font-size='11' fill='#64748b'>安全评分 / 100</text>");
				stringBuilder.AppendLine("</svg>");
				stringBuilder.AppendLine("</div>");
				stringBuilder.AppendLine("<div style='text-align:center;'>");
				stringBuilder2 = stringBuilder;
				StringBuilder stringBuilder22 = stringBuilder2;
				handler = new StringBuilder.AppendInterpolatedStringHandler(58, 2, stringBuilder2);
				handler.AppendLiteral("<div style='font-size:32px;font-weight:bold;color:");
				handler.AppendFormatted(value7);
				handler.AppendLiteral("'>");
				handler.AppendFormatted(text);
				handler.AppendLiteral("</div>");
				stringBuilder22.AppendLine(ref handler);
				stringBuilder.AppendLine("<div style='font-size:12px;color:#64748b;margin-top:4px'>总体风险等级</div>");
				stringBuilder2 = stringBuilder;
				StringBuilder stringBuilder23 = stringBuilder2;
				handler = new StringBuilder.AppendInterpolatedStringHandler(63, 1, stringBuilder2);
				handler.AppendLiteral("<div style='margin-top:8px;font-size:13px;color:#334155'>");
				handler.AppendFormatted(GetSecurityRatingDescriptionForScore(num2));
				handler.AppendLiteral("</div>");
				stringBuilder23.AppendLine(ref handler);
				stringBuilder.AppendLine("</div>");
				stringBuilder.AppendLine("</div>");
				stringBuilder.AppendLine("</div>");
				List<IGrouping<string, PortScanResult>> list4 = (from p in list3
					where !string.IsNullOrEmpty((p != null) ? p.Service : null)
					group p by p.Service into g
					orderby g.Count() descending
					select g).Take(6).ToList();
				if (list4.Any())
				{
					stringBuilder.AppendLine("<h3>1.3 服务分布图表</h3>");
					stringBuilder.AppendLine("<div class='chart-container'>");
					stringBuilder.AppendLine("<h4>开放端口服务分布</h4>");
					int num5 = list4.Max((IGrouping<string, PortScanResult> g) => g.Count());
					stringBuilder.AppendLine("<div style='display:flex;align-items:flex-end;gap:16px;height:160px;padding:0 10px;'>");
					string[] array = new string[6] { "#3b82f6", "#10b981", "#f59e0b", "#ef4444", "#8b5cf6", "#06b6d4" };
					int num6 = 0;
					foreach (IGrouping<string, PortScanResult> item in list4)
					{
						int value11 = (int)((double)item.Count() / (double)num5 * 130.0);
						string value12 = array[num6 % array.Length];
						stringBuilder.AppendLine("<div style='flex:1;display:flex;flex-direction:column;align-items:center;justify-content:flex-end;'>");
						stringBuilder2 = stringBuilder;
						StringBuilder stringBuilder24 = stringBuilder2;
						handler = new StringBuilder.AppendInterpolatedStringHandler(77, 2, stringBuilder2);
						handler.AppendLiteral("<div style='font-size:11px;font-weight:bold;color:");
						handler.AppendFormatted(value12);
						handler.AppendLiteral(";margin-bottom:4px;'>");
						handler.AppendFormatted(item.Count());
						handler.AppendLiteral("</div>");
						stringBuilder24.AppendLine(ref handler);
						stringBuilder2 = stringBuilder;
						StringBuilder stringBuilder25 = stringBuilder2;
						handler = new StringBuilder.AppendInterpolatedStringHandler(94, 2, stringBuilder2);
						handler.AppendLiteral("<div style='width:100%;max-width:50px;height:");
						handler.AppendFormatted(value11);
						handler.AppendLiteral("px;background:");
						handler.AppendFormatted(value12);
						handler.AppendLiteral(";border-radius:4px 4px 0 0;'></div>");
						stringBuilder25.AppendLine(ref handler);
						string value13 = ((item.Key.Length > 8) ? (item.Key.Substring(0, 7) + "..") : item.Key);
						stringBuilder2 = stringBuilder;
						StringBuilder stringBuilder26 = stringBuilder2;
						handler = new StringBuilder.AppendInterpolatedStringHandler(83, 1, stringBuilder2);
						handler.AppendLiteral("<div style='font-size:10px;color:#64748b;margin-top:4px;white-space:nowrap;'>");
						handler.AppendFormatted(value13);
						handler.AppendLiteral("</div>");
						stringBuilder26.AppendLine(ref handler);
						stringBuilder.AppendLine("</div>");
						num6++;
					}
					stringBuilder.AppendLine("</div></div>");
				}
				if (list2.Any())
				{
					stringBuilder.AppendLine("<h3>1.4 Top 5 高危漏洞</h3>");
					stringBuilder.AppendLine("<table><tr><th>#</th><th>漏洞名称</th><th>风险等级</th><th>CVE编号</th></tr>");
					int num7 = 1;
					foreach (VulnerabilityResult item2 in list2.OrderByDescending((VulnerabilityResult v) => GetRiskPriorityFromLevel((v != null) ? v.RiskLevel : null)).Take(5))
					{
						string value14 = (IsCriticalLevel((item2 != null) ? item2.RiskLevel : null) ? "risk-critical" : (IsHighLevel((item2 != null) ? item2.RiskLevel : null) ? "risk-high" : (IsMediumLevel((item2 != null) ? item2.RiskLevel : null) ? "risk-medium" : "risk-low")));
						stringBuilder2 = stringBuilder;
						StringBuilder stringBuilder27 = stringBuilder2;
						handler = new StringBuilder.AppendInterpolatedStringHandler(54, 5, stringBuilder2);
						handler.AppendLiteral("<tr><td>");
						handler.AppendFormatted(num7);
						handler.AppendLiteral("</td><td>");
						handler.AppendFormatted(item2.Name ?? "未知");
						handler.AppendLiteral("</td><td class='");
						handler.AppendFormatted(value14);
						handler.AppendLiteral("'>");
						handler.AppendFormatted(item2.RiskLevel ?? "未分类");
						handler.AppendLiteral("</td><td>");
						handler.AppendFormatted(item2.CveId ?? "-");
						handler.AppendLiteral("</td></tr>");
						stringBuilder27.AppendLine(ref handler);
						num7++;
					}
					stringBuilder.AppendLine("</table>");
				}
				if (list.Any())
				{
					stringBuilder.AppendLine("<h2>二、端口扫描结果</h2>");
					stringBuilder.AppendLine("<p>本节列出所有检测到的开放端口及其对应的服务信息。</p>");
					stringBuilder.AppendLine("<table><tr><th>端口号</th><th>协议</th><th>服务名称</th><th>版本</th><th>状态</th></tr>");
					foreach (PortScanResult item3 in list3.OrderBy((PortScanResult p) => p.PortNumber))
					{
						stringBuilder2 = stringBuilder;
						StringBuilder stringBuilder28 = stringBuilder2;
						handler = new StringBuilder.AppendInterpolatedStringHandler(57, 4, stringBuilder2);
						handler.AppendLiteral("<tr><td>");
						handler.AppendFormatted(item3.PortNumber);
						handler.AppendLiteral("</td><td>TCP</td><td>");
						handler.AppendFormatted(item3.Service ?? "-");
						handler.AppendLiteral("</td><td>");
						handler.AppendFormatted(item3.ServiceVersion ?? "-");
						handler.AppendLiteral("</td><td>");
						handler.AppendFormatted(item3.Status);
						handler.AppendLiteral("</td></tr>");
						stringBuilder28.AppendLine(ref handler);
					}
					stringBuilder.AppendLine("</table>");
				}
				if (list2.Any())
				{
					stringBuilder.AppendLine("<h2>三、漏洞详情分析</h2>");
					stringBuilder.AppendLine("<p>本节详细列出所有检测到的安全漏洞，按风险等级从高到低排列。</p>");
					stringBuilder.AppendLine("<h3>3.1 漏洞概览表</h3>");
					stringBuilder.AppendLine("<table><tr><th>序号</th><th>CVE编号</th><th>漏洞名称</th><th>风险等级</th><th>端口</th><th>服务</th><th>CVSS评分</th></tr>");
					int num8 = 1;
					foreach (VulnerabilityResult item4 in list2.OrderByDescending((VulnerabilityResult v) => GetRiskPriorityFromLevel((v != null) ? v.RiskLevel : null)))
					{
						string value15 = (IsCriticalLevel((item4 != null) ? item4.RiskLevel : null) ? "risk-critical" : (IsHighLevel((item4 != null) ? item4.RiskLevel : null) ? "risk-high" : (IsMediumLevel((item4 != null) ? item4.RiskLevel : null) ? "risk-medium" : "risk-low")));
						double value16 = EstimateCvssScoreForLevel((item4 != null) ? item4.RiskLevel : null);
						stringBuilder2 = stringBuilder;
						StringBuilder stringBuilder29 = stringBuilder2;
						handler = new StringBuilder.AppendInterpolatedStringHandler(81, 8, stringBuilder2);
						handler.AppendLiteral("<tr><td>");
						handler.AppendFormatted(num8);
						handler.AppendLiteral("</td><td>");
						handler.AppendFormatted(item4.CveId ?? "-");
						handler.AppendLiteral("</td><td>");
						handler.AppendFormatted(item4.Name ?? "未知");
						handler.AppendLiteral("</td><td class='");
						handler.AppendFormatted(value15);
						handler.AppendLiteral("'>");
						handler.AppendFormatted(item4.RiskLevel ?? "未分类");
						handler.AppendLiteral("</td><td>");
						handler.AppendFormatted(item4.Port.HasValue ? item4.Port.Value.ToString() : "-");
						handler.AppendLiteral("</td><td>");
						handler.AppendFormatted(item4.Service ?? "-");
						handler.AppendLiteral("</td><td>");
						handler.AppendFormatted(value16, "F1");
						handler.AppendLiteral("</td></tr>");
						stringBuilder29.AppendLine(ref handler);
						num8++;
					}
					stringBuilder.AppendLine("</table>");
					stringBuilder.AppendLine("<h3>3.2 漏洞详细信息（前10个）</h3>");
					int num9 = 1;
					foreach (VulnerabilityResult item5 in list2.OrderByDescending((VulnerabilityResult v) => GetRiskPriorityFromLevel((v != null) ? v.RiskLevel : null)).Take(10))
					{
						string text2 = (string.IsNullOrWhiteSpace((item5 != null) ? item5.RiskLevel : null) ? "未分类" : item5.RiskLevel);
						string value17 = (IsCriticalLevel(text2) ? "#991b1b" : (IsHighLevel(text2) ? "#c2410c" : (IsMediumLevel(text2) ? "#d97706" : "#059669")));
						double value18 = EstimateCvssScoreForLevel(text2);
						bool num10 = IsCriticalLevel(text2);
						bool flag4 = IsHighLevel(text2);
						string value19 = (item5.Port.HasValue ? "网络(N)" : "本地(L)");
						string value20 = ((num10 || flag4) ? "低" : "中");
						string value21 = ((num10 || flag4) ? "无(N)" : "低(L)");
						string value22 = "无(N)";
						string value23 = (num10 ? "改变(C)" : "未改变(U)");
						string value24 = ((num10 || flag4) ? "高(H)" : "低(L)");
						string value25 = ((num10 || flag4) ? "高(H)" : "低(L)");
						string value26 = (num10 ? "高(H)" : (flag4 ? "高(H)" : "低(L)"));
						stringBuilder.AppendLine("<div class='vuln-card'>");
						string value27 = (string.IsNullOrWhiteSpace(item5.CveId) ? "" : ("(" + item5.CveId + ")"));
						stringBuilder2 = stringBuilder;
						StringBuilder stringBuilder30 = stringBuilder2;
						handler = new StringBuilder.AppendInterpolatedStringHandler(58, 5, stringBuilder2);
						handler.AppendLiteral("<div class='card-header' style='background:");
						handler.AppendFormatted(value17);
						handler.AppendLiteral("'>[");
						handler.AppendFormatted(num9);
						handler.AppendLiteral("] ");
						handler.AppendFormatted(item5.Name ?? "未知漏洞");
						handler.AppendLiteral(" ");
						handler.AppendFormatted(value27);
						handler.AppendLiteral(" [");
						handler.AppendFormatted(text2);
						handler.AppendLiteral("]</div>");
						stringBuilder30.AppendLine(ref handler);
						stringBuilder.AppendLine("<div class='card-body'>");
						stringBuilder.AppendLine("<p class='section-title'>【漏洞概述】</p>");
						string text3 = item5.Description;
						if (string.IsNullOrWhiteSpace(text3) || text3 == "-")
						{
							text3 = "该漏洞影响 " + (string.IsNullOrWhiteSpace(item5.Service) ? "系统" : item5.Service) + "服务" + (item5.Port.HasValue ? $"（端口 {item5.Port.Value}）" : "");
						}
						stringBuilder2 = stringBuilder;
						StringBuilder stringBuilder31 = stringBuilder2;
						handler = new StringBuilder.AppendInterpolatedStringHandler(7, 1, stringBuilder2);
						handler.AppendLiteral("<p>");
						handler.AppendFormatted(text3);
						handler.AppendLiteral("</p>");
						stringBuilder31.AppendLine(ref handler);
						stringBuilder.AppendLine("<p class='section-title'>【CVSS评分详情】</p>");
						stringBuilder.AppendLine("<div class='cvss-grid'>");
						stringBuilder2 = stringBuilder;
						StringBuilder stringBuilder32 = stringBuilder2;
						handler = new StringBuilder.AppendInterpolatedStringHandler(101, 1, stringBuilder2);
						handler.AppendLiteral("<div class='cvss-item'><span class='cvss-label'>攻击向量(AV)</span><span class='cvss-value'>");
						handler.AppendFormatted(value19);
						handler.AppendLiteral("</span></div>");
						stringBuilder32.AppendLine(ref handler);
						stringBuilder2 = stringBuilder;
						StringBuilder stringBuilder33 = stringBuilder2;
						handler = new StringBuilder.AppendInterpolatedStringHandler(102, 1, stringBuilder2);
						handler.AppendLiteral("<div class='cvss-item'><span class='cvss-label'>攻击复杂度(AC)</span><span class='cvss-value'>");
						handler.AppendFormatted(value20);
						handler.AppendLiteral("</span></div>");
						stringBuilder33.AppendLine(ref handler);
						stringBuilder2 = stringBuilder;
						StringBuilder stringBuilder34 = stringBuilder2;
						handler = new StringBuilder.AppendInterpolatedStringHandler(101, 1, stringBuilder2);
						handler.AppendLiteral("<div class='cvss-item'><span class='cvss-label'>权限要求(PR)</span><span class='cvss-value'>");
						handler.AppendFormatted(value21);
						handler.AppendLiteral("</span></div>");
						stringBuilder34.AppendLine(ref handler);
						stringBuilder2 = stringBuilder;
						StringBuilder stringBuilder35 = stringBuilder2;
						handler = new StringBuilder.AppendInterpolatedStringHandler(101, 1, stringBuilder2);
						handler.AppendLiteral("<div class='cvss-item'><span class='cvss-label'>用户交互(UI)</span><span class='cvss-value'>");
						handler.AppendFormatted(value22);
						handler.AppendLiteral("</span></div>");
						stringBuilder35.AppendLine(ref handler);
						stringBuilder2 = stringBuilder;
						StringBuilder stringBuilder36 = stringBuilder2;
						handler = new StringBuilder.AppendInterpolatedStringHandler(100, 1, stringBuilder2);
						handler.AppendLiteral("<div class='cvss-item'><span class='cvss-label'>影响范围(S)</span><span class='cvss-value'>");
						handler.AppendFormatted(value23);
						handler.AppendLiteral("</span></div>");
						stringBuilder36.AppendLine(ref handler);
						stringBuilder2 = stringBuilder;
						StringBuilder stringBuilder37 = stringBuilder2;
						handler = new StringBuilder.AppendInterpolatedStringHandler(99, 1, stringBuilder2);
						handler.AppendLiteral("<div class='cvss-item'><span class='cvss-label'>机密性(C)</span><span class='cvss-value'>");
						handler.AppendFormatted(value24);
						handler.AppendLiteral("</span></div>");
						stringBuilder37.AppendLine(ref handler);
						stringBuilder2 = stringBuilder;
						StringBuilder stringBuilder38 = stringBuilder2;
						handler = new StringBuilder.AppendInterpolatedStringHandler(99, 1, stringBuilder2);
						handler.AppendLiteral("<div class='cvss-item'><span class='cvss-label'>完整性(I)</span><span class='cvss-value'>");
						handler.AppendFormatted(value25);
						handler.AppendLiteral("</span></div>");
						stringBuilder38.AppendLine(ref handler);
						stringBuilder2 = stringBuilder;
						StringBuilder stringBuilder39 = stringBuilder2;
						handler = new StringBuilder.AppendInterpolatedStringHandler(99, 1, stringBuilder2);
						handler.AppendLiteral("<div class='cvss-item'><span class='cvss-label'>可用性(A)</span><span class='cvss-value'>");
						handler.AppendFormatted(value26);
						handler.AppendLiteral("</span></div>");
						stringBuilder39.AppendLine(ref handler);
						stringBuilder.AppendLine("</div>");
						stringBuilder2 = stringBuilder;
						StringBuilder stringBuilder40 = stringBuilder2;
						handler = new StringBuilder.AppendInterpolatedStringHandler(75, 3, stringBuilder2);
						handler.AppendLiteral("<div class='cvss-total' style='background:");
						handler.AppendFormatted(value17);
						handler.AppendLiteral(";color:white'>综合评分：");
						handler.AppendFormatted(value18, "F1");
						handler.AppendLiteral("/10.0 (");
						handler.AppendFormatted(text2);
						handler.AppendLiteral(")</div>");
						stringBuilder40.AppendLine(ref handler);
						stringBuilder.AppendLine("<p class='section-title'>【基本信息】</p>");
						stringBuilder2 = stringBuilder;
						StringBuilder stringBuilder41 = stringBuilder2;
						handler = new StringBuilder.AppendInterpolatedStringHandler(31, 4, stringBuilder2);
						handler.AppendLiteral("<p>CVSS评分：");
						handler.AppendFormatted(value18, "F1");
						handler.AppendLiteral(" (");
						handler.AppendFormatted(text2);
						handler.AppendLiteral(") | 影响端口：");
						handler.AppendFormatted(item5.Port.HasValue ? $"TCP/{item5.Port.Value}" : "N/A");
						handler.AppendLiteral(" | 服务：");
						handler.AppendFormatted(item5.Service ?? "-");
						handler.AppendLiteral("</p>");
						stringBuilder41.AppendLine(ref handler);
						if (!string.IsNullOrWhiteSpace(item5.DetectionMethod) && item5.DetectionMethod != "-")
						{
							stringBuilder.AppendLine("<p class='section-title'>【检测方法】</p>");
							stringBuilder2 = stringBuilder;
							StringBuilder stringBuilder42 = stringBuilder2;
							handler = new StringBuilder.AppendInterpolatedStringHandler(7, 1, stringBuilder2);
							handler.AppendLiteral("<p>");
							handler.AppendFormatted(item5.DetectionMethod);
							handler.AppendLiteral("</p>");
							stringBuilder42.AppendLine(ref handler);
						}
						stringBuilder.AppendLine("<p class='section-title'>【影响范围分析】</p>");
						string value28 = ((num10 || flag4) ? "impact-analyze impact-critical" : "impact-analyze");
						if (num10 || flag4)
						{
							stringBuilder2 = stringBuilder;
							StringBuilder stringBuilder43 = stringBuilder2;
							handler = new StringBuilder.AppendInterpolatedStringHandler(86, 1, stringBuilder2);
							handler.AppendLiteral("<div class='");
							handler.AppendFormatted(value28);
							handler.AppendLiteral("'>该漏洞可导致远程代码执行或权限提升，攻击者可能完全控制受影响的系统。影响范围包括：系统完整性破坏、敏感数据泄露、服务中断等严重后果。</div>");
							stringBuilder43.AppendLine(ref handler);
						}
						else if (IsMediumLevel(text2))
						{
							stringBuilder2 = stringBuilder;
							StringBuilder stringBuilder44 = stringBuilder2;
							handler = new StringBuilder.AppendInterpolatedStringHandler(64, 1, stringBuilder2);
							handler.AppendLiteral("<div class='");
							handler.AppendFormatted(value28);
							handler.AppendLiteral("'>该漏洞可导致信息泄露或服务降级，攻击者可能获取部分系统信息或造成服务影响。建议尽快修复。</div>");
							stringBuilder44.AppendLine(ref handler);
						}
						else
						{
							stringBuilder2 = stringBuilder;
							StringBuilder stringBuilder45 = stringBuilder2;
							handler = new StringBuilder.AppendInterpolatedStringHandler(58, 1, stringBuilder2);
							handler.AppendLiteral("<div class='");
							handler.AppendFormatted(value28);
							handler.AppendLiteral("'>该漏洞风险较低，主要影响信息收集或带来有限的安全隐患。建议纳入常规修复计划。</div>");
							stringBuilder45.AppendLine(ref handler);
						}
						stringBuilder.AppendLine("<p class='section-title'>【修复方案】</p>");
						foreach (string item6 in (from l in (item5.Solution ?? "请参考官方安全公告获取补丁信息").Split('\n')
							where !string.IsNullOrWhiteSpace(l)
							select l).Take(5))
						{
							stringBuilder2 = stringBuilder;
							StringBuilder stringBuilder46 = stringBuilder2;
							handler = new StringBuilder.AppendInterpolatedStringHandler(11, 1, stringBuilder2);
							handler.AppendLiteral("<p>  • ");
							handler.AppendFormatted(item6.Trim());
							handler.AppendLiteral("</p>");
							stringBuilder46.AppendLine(ref handler);
						}
						if (!string.IsNullOrWhiteSpace(item5.References))
						{
							stringBuilder.AppendLine("<p class='section-title'>【参考链接】</p>");
							stringBuilder2 = stringBuilder;
							StringBuilder stringBuilder47 = stringBuilder2;
							handler = new StringBuilder.AppendInterpolatedStringHandler(55, 2, stringBuilder2);
							handler.AppendLiteral("<p class='ref-link'><a href='");
							handler.AppendFormatted(item5.References);
							handler.AppendLiteral("' target='_blank'>");
							handler.AppendFormatted(item5.References);
							handler.AppendLiteral("</a></p>");
							stringBuilder47.AppendLine(ref handler);
						}
						stringBuilder.AppendLine("</div></div>");
						num9++;
					}
				}
				stringBuilder.AppendLine("<h2>四、风险评估汇总</h2>");
				stringBuilder.AppendLine("<p>本节对本次扫描发现的各类风险进行综合评估和分析。</p>");
				stringBuilder.AppendLine("<h3>4.1 风险分布</h3>");
				if (list2.Any())
				{
					int count = list2.Count;
					var array2 = new[]
					{
						new
						{
							Label = "严重",
							Count = list2.Count((VulnerabilityResult v) => IsCriticalLevel(v.RiskLevel)),
							Color = "#991b1b"
						},
						new
						{
							Label = "高危",
							Count = list2.Count((VulnerabilityResult v) => IsHighLevel(v.RiskLevel)),
							Color = "#c2410c"
						},
						new
						{
							Label = "中危",
							Count = list2.Count((VulnerabilityResult v) => IsMediumLevel(v.RiskLevel)),
							Color = "#d97706"
						},
						new
						{
							Label = "低危",
							Count = list2.Count((VulnerabilityResult v) => IsLowLevel(v.RiskLevel)),
							Color = "#059669"
						}
					};
					var list5 = array2.Where(c => c.Count > 0).ToList();
					if (list5.Any())
					{
						stringBuilder.AppendLine("<div style='display:flex;gap:30px;align-items:center;margin:20px 0;padding:20px;background:#f8fafc;border-radius:8px;border:1px solid #e2e8f0;'>");
						stringBuilder.AppendLine("<div style='flex:0 0 200px;text-align:center;'>");
						stringBuilder.AppendLine("<svg width='200' height='200' viewBox='0 0 200 200'>");
						float num11 = -90f;
						foreach (var item7 in list5)
						{
							float num12 = (float)item7.Count / (float)count * 360f;
							float num13 = num11 * (float)Math.PI / 180f;
							float num14 = (num11 + num12) * (float)Math.PI / 180f;
							int value29 = ((num12 > 180f) ? 1 : 0);
							float num15 = 80f;
							float num16 = 100f;
							float num17 = 100f;
							float value30 = num16 + num15 * (float)Math.Cos(num13);
							float value31 = num17 + num15 * (float)Math.Sin(num13);
							float value32 = num16 + num15 * (float)Math.Cos(num14);
							float value33 = num17 + num15 * (float)Math.Sin(num14);
							stringBuilder2 = stringBuilder;
							StringBuilder stringBuilder48 = stringBuilder2;
							handler = new StringBuilder.AppendInterpolatedStringHandler(69, 10, stringBuilder2);
							handler.AppendLiteral("<path d='M");
							handler.AppendFormatted(num16);
							handler.AppendLiteral(",");
							handler.AppendFormatted(num17);
							handler.AppendLiteral(" L");
							handler.AppendFormatted(value30, "F1");
							handler.AppendLiteral(",");
							handler.AppendFormatted(value31, "F1");
							handler.AppendLiteral(" A");
							handler.AppendFormatted(num15);
							handler.AppendLiteral(",");
							handler.AppendFormatted(num15);
							handler.AppendLiteral(" 0 ");
							handler.AppendFormatted(value29);
							handler.AppendLiteral(",1 ");
							handler.AppendFormatted(value32, "F1");
							handler.AppendLiteral(",");
							handler.AppendFormatted(value33, "F1");
							handler.AppendLiteral(" Z' fill='");
							handler.AppendFormatted(item7.Color);
							handler.AppendLiteral("' stroke='white' stroke-width='2'/>");
							stringBuilder48.AppendLine(ref handler);
							if (num12 > 20f)
							{
								float num18 = (num11 + num12 / 2f) * (float)Math.PI / 180f;
								float value34 = num16 + num15 * 0.55f * (float)Math.Cos(num18);
								float value35 = num17 + num15 * 0.55f * (float)Math.Sin(num18);
								double value36 = (double)item7.Count / (double)count * 100.0;
								stringBuilder2 = stringBuilder;
								StringBuilder stringBuilder49 = stringBuilder2;
								handler = new StringBuilder.AppendInterpolatedStringHandler(120, 3, stringBuilder2);
								handler.AppendLiteral("<text x='");
								handler.AppendFormatted(value34, "F1");
								handler.AppendLiteral("' y='");
								handler.AppendFormatted(value35, "F1");
								handler.AppendLiteral("' text-anchor='middle' dominant-baseline='central' fill='white' font-size='11' font-weight='bold'>");
								handler.AppendFormatted(value36, "F0");
								handler.AppendLiteral("%</text>");
								stringBuilder49.AppendLine(ref handler);
							}
							num11 += num12;
						}
						stringBuilder.AppendLine("<circle cx='100' cy='100' r='30' fill='white'/>");
						stringBuilder2 = stringBuilder;
						StringBuilder stringBuilder50 = stringBuilder2;
						handler = new StringBuilder.AppendInterpolatedStringHandler(127, 1, stringBuilder2);
						handler.AppendLiteral("<text x='100' y='100' text-anchor='middle' dominant-baseline='central' fill='#1e293b' font-size='14' font-weight='bold'>");
						handler.AppendFormatted(count);
						handler.AppendLiteral("</text>");
						stringBuilder50.AppendLine(ref handler);
						stringBuilder.AppendLine("</svg>");
						stringBuilder.AppendLine("</div>");
						stringBuilder.AppendLine("<div style='flex:1;'>");
						stringBuilder.AppendLine("<h4 style='margin:0 0 12px;color:#1a365d;'>漏洞风险分布</h4>");
						foreach (var item8 in list5)
						{
							double value37 = (double)item8.Count / (double)count * 100.0;
							stringBuilder2 = stringBuilder;
							StringBuilder stringBuilder51 = stringBuilder2;
							handler = new StringBuilder.AppendInterpolatedStringHandler(192, 4, stringBuilder2);
							handler.AppendLiteral("<div style='margin:6px 0;display:flex;align-items:center;gap:8px;'><span style='display:inline-block;width:14px;height:14px;border-radius:3px;background:");
							handler.AppendFormatted(item8.Color);
							handler.AppendLiteral(";'></span><strong>");
							handler.AppendFormatted(item8.Label);
							handler.AppendLiteral("：</strong>");
							handler.AppendFormatted(item8.Count);
							handler.AppendLiteral("个 (");
							handler.AppendFormatted(value37, "F1");
							handler.AppendLiteral("%)</div>");
							stringBuilder51.AppendLine(ref handler);
						}
						stringBuilder2 = stringBuilder;
						StringBuilder stringBuilder52 = stringBuilder2;
						handler = new StringBuilder.AppendInterpolatedStringHandler(118, 1, stringBuilder2);
						handler.AppendLiteral("<div style='margin-top:12px;padding-top:8px;border-top:1px solid #e2e8f0;color:#1a365d;font-weight:bold;'>总计：");
						handler.AppendFormatted(count);
						handler.AppendLiteral("个漏洞</div>");
						stringBuilder52.AppendLine(ref handler);
						stringBuilder.AppendLine("</div></div>");
					}
					stringBuilder.AppendLine("<h4 style='margin:15px 0 8px;color:#1a365d;'>风险等级进度条</h4>");
					var array3 = array2;
					foreach (var anon in array3)
					{
						if (anon.Count > 0)
						{
							double value38 = (double)anon.Count / (double)count * 100.0;
							stringBuilder2 = stringBuilder;
							StringBuilder stringBuilder53 = stringBuilder2;
							handler = new StringBuilder.AppendInterpolatedStringHandler(14, 3, stringBuilder2);
							handler.AppendLiteral("<p>");
							handler.AppendFormatted(anon.Label);
							handler.AppendLiteral(": ");
							handler.AppendFormatted(anon.Count);
							handler.AppendLiteral("个 (");
							handler.AppendFormatted(value38, "F1");
							handler.AppendLiteral("%)</p>");
							stringBuilder53.AppendLine(ref handler);
							stringBuilder2 = stringBuilder;
							StringBuilder stringBuilder54 = stringBuilder2;
							handler = new StringBuilder.AppendInterpolatedStringHandler(90, 3, stringBuilder2);
							handler.AppendLiteral("<div class='bar-container'><div class='bar-fill' style='width:");
							handler.AppendFormatted(value38);
							handler.AppendLiteral("%;background:");
							handler.AppendFormatted(anon.Color);
							handler.AppendLiteral("'>");
							handler.AppendFormatted(value38, "F1");
							handler.AppendLiteral("%</div></div>");
							stringBuilder54.AppendLine(ref handler);
						}
					}
				}
				stringBuilder.AppendLine("<h3>4.2 安全建议概述</h3>");
				string[] array4 = new string[7] { "立即修复所有严重和高危级别的漏洞，尤其是远程代码执行类漏洞", "关闭不必要的服务和端口，减少攻击面", "及时更新系统和应用软件至最新版本", "实施强密码策略和多因素认证(MFA)", "配置防火墙规则限制网络访问", "定期进行安全扫描和渗透测试", "建立安全事件应急响应流程" };
				foreach (string value39 in array4)
				{
					stringBuilder2 = stringBuilder;
					StringBuilder stringBuilder55 = stringBuilder2;
					handler = new StringBuilder.AppendInterpolatedStringHandler(9, 1, stringBuilder2);
					handler.AppendLiteral("<p>• ");
					handler.AppendFormatted(value39);
					handler.AppendLiteral("</p>");
					stringBuilder55.AppendLine(ref handler);
				}
				stringBuilder.AppendLine("<h2>五、修复建议与安全加固</h2>");
				stringBuilder.AppendLine("<h3>5.1 修复优先级矩阵</h3>");
				stringBuilder.AppendLine("<table class='priority-table'><tr><th>优先级</th><th>处理时限</th><th>适用范围</th><th>建议措施</th></tr>");
				stringBuilder.AppendLine("<tr><td style='color:#dc2626'>P1-紧急</td><td>24小时内</td><td>严重/远程执行类</td><td>立即隔离受影响系统</td></tr>");
				stringBuilder.AppendLine("<tr><td style='color:#f59e0b'>P2-高</td><td>7天内</td><td>高危/权限提升类</td><td>尽快安排维护窗口</td></tr>");
				stringBuilder.AppendLine("<tr><td style='color:#eab308'>P3-中</td><td>30天内</td><td>中危/信息泄露类</td><td>纳入常规更新计划</td></tr>");
				stringBuilder.AppendLine("<tr><td style='color:#22c55e'>P4-低</td><td>下个周期</td><td>低危/信息类</td><td>持续监控</td></tr>");
				stringBuilder.AppendLine("</table>");
				stringBuilder.AppendLine("<h3>5.2 通用安全加固建议</h3>");
				(string, string)[] obj = new(string, string)[6]
				{
					("网络层面", "配置防火墙规则，仅开放必要的业务端口；实施网络分段隔离；启用入侵检测/防御系统(IDS/IPS)；定期审计网络访问日志。"),
					("系统层面", "及时安装操作系统安全更新；禁用不必要的服务和账户；配置强密码策略（长度>=12位，含大小写字母、数字、特殊字符）；启用账户锁定策略防止暴力破解。"),
					("应用层面", "保持应用程序及依赖库为最新版本；实施安全的编码实践（输入验证、参数化查询）；定期进行代码安全审查和渗透测试；配置安全的HTTP头部（CSP、X-Frame-Options等）。"),
					("身份认证", "实施多因素认证(MFA)；采用基于角色的访问控制(RBAC)；定期清理过期账户和冗余权限；监控异常登录行为并及时告警。"),
					("数据保护", "加密敏感数据存储和传输（TLS 1.2+）；实施数据分类和分级保护策略；建立定期数据备份和灾难恢复机制；制定数据泄露应急响应预案。"),
					("监控审计", "部署集中化日志管理系统(SIEM)；设置安全事件实时告警阈值；定期进行安全基线检查和合规审计；保留审计日志至少180天以满足合规要求。")
				};
				int num19 = 1;
				(string, string)[] array5 = obj;
				for (int i = 0; i < array5.Length; i++)
				{
					(string, string) tuple = array5[i];
					stringBuilder2 = stringBuilder;
					StringBuilder stringBuilder56 = stringBuilder2;
					handler = new StringBuilder.AppendInterpolatedStringHandler(54, 3, stringBuilder2);
					handler.AppendLiteral("<div class='hardening-item'><strong>");
					handler.AppendFormatted(num19);
					handler.AppendLiteral(". ");
					handler.AppendFormatted(tuple.Item1);
					handler.AppendLiteral("：</strong>");
					handler.AppendFormatted(tuple.Item2);
					handler.AppendLiteral("</div>");
					stringBuilder56.AppendLine(ref handler);
					num19++;
				}
				stringBuilder.AppendLine("</div>");
				stringBuilder.AppendLine("<h2>六、威胁情报分析</h2>");
				stringBuilder.AppendLine("<p>本节基于当前扫描结果和已知威胁情报数据，对目标系统面临的潜在威胁进行深度分析。</p>");
				stringBuilder.AppendLine("<h3>6.1 活跃威胁向量</h3>");
				if (list3.Any((PortScanResult p) => p.PortNumber == 21 || p.PortNumber == 20))
				{
					stringBuilder.AppendLine("<div class='threat-item'><strong>⚠ FTP服务暴露</strong> — 攻击者可利用匿名登录或弱口令获取文件访问权限，可能导致敏感数据泄露</div>");
				}
				if (list3.Any((PortScanResult p) => p.PortNumber == 22))
				{
					stringBuilder.AppendLine("<div class='threat-item'><strong>⚠ SSH服务暴露</strong> — 面临暴力破解和未授权访问风险，弱密码或默认密钥可被利用获取系统控制权</div>");
				}
				if (list3.Any((PortScanResult p) => p.PortNumber == 23))
				{
					stringBuilder.AppendLine("<div class='threat-item'><strong>⚠ Telnet服务暴露</strong> — 明文传输协议，凭据和会话数据可被中间人攻击截获</div>");
				}
				if (list3.Any((PortScanResult p) => p.PortNumber == 445 || p.PortNumber == 139))
				{
					stringBuilder.AppendLine("<div class='threat-item'><strong>⚠ SMB服务暴露</strong> — 勒索软件主要传播通道，存在远程代码执行风险(如EternalBlue)</div>");
				}
				if (list3.Any((PortScanResult p) => p.PortNumber == 3389))
				{
					stringBuilder.AppendLine("<div class='threat-item'><strong>⚠ RDP远程桌面暴露</strong> — 暴力破解和蓝屏漏洞(BSOD)利用风险，是勒索软件常见入口</div>");
				}
				if (list3.Any((PortScanResult p) => p.PortNumber == 80 || p.PortNumber == 443 || p.PortNumber == 8080))
				{
					stringBuilder.AppendLine("<div class='threat-item'><strong>⚠ Web服务暴露</strong> — 面临SQL注入、XSS、目录遍历等Web应用层攻击风险</div>");
				}
				if (list3.Any((PortScanResult p) => p.PortNumber == 3306 || p.PortNumber == 1433 || p.PortNumber == 5432 || p.PortNumber == 27017))
				{
					stringBuilder.AppendLine("<div class='threat-item'><strong>⚠ 数据库端口暴露</strong> — 数据库服务直接暴露在网络上，面临数据泄露和未授权访问风险</div>");
				}
				if (num > 0)
				{
					stringBuilder2 = stringBuilder;
					StringBuilder stringBuilder57 = stringBuilder2;
					handler = new StringBuilder.AppendInterpolatedStringHandler(87, 1, stringBuilder2);
					handler.AppendLiteral("<div class='threat-item'><strong>⚠ 已知高危漏洞</strong> — 发现");
					handler.AppendFormatted(num);
					handler.AppendLiteral("个高危漏洞，攻击者可利用自动化工具进行批量扫描和利用</div>");
					stringBuilder57.AppendLine(ref handler);
				}
				stringBuilder.AppendLine("<div class='threat-item'><strong>⚠ 弱密码和默认凭据攻击</strong> — 攻击者使用字典攻击和凭据填充尝试获取系统访问权限</div>");
				stringBuilder.AppendLine("<div class='threat-item'><strong>⚠ 拒绝服务攻击(DoS/DDoS)</strong> — 开放服务可能成为拒绝服务攻击的目标</div>");
				stringBuilder.AppendLine("<h3>6.2 行业威胁趋势</h3>");
				stringBuilder.AppendLine("<table><tr><th>威胁趋势</th><th>分析描述</th><th>严重度</th></tr>");
				stringBuilder.AppendLine("<tr><td><strong>勒索软件攻击持续增长</strong></td><td>针对关键基础设施的勒索软件采用双重勒索策略（加密+数据泄露），赎金要求不断攀升</td><td style='color:#991b1b;font-weight:bold'>严重</td></tr>");
				stringBuilder.AppendLine("<tr><td><strong>供应链攻击日益复杂</strong></td><td>攻击者通过入侵可信软件供应商分发恶意代码，SolarWinds事件后成为主要威胁</td><td style='color:#c2410c;font-weight:bold'>高</td></tr>");
				stringBuilder.AppendLine("<tr><td><strong>零日漏洞利用速度加快</strong></td><td>从漏洞公开到被大规模利用的时间窗口持续缩短，数小时内即可完成武器化</td><td style='color:#c2410c;font-weight:bold'>高</td></tr>");
				stringBuilder.AppendLine("<tr><td><strong>云服务成为新攻击重点</strong></td><td>云环境配置错误和API安全漏洞成为攻击者主要入口</td><td style='color:#d97706;font-weight:bold'>中</td></tr>");
				stringBuilder.AppendLine("<tr><td><strong>AI驱动的网络攻击</strong></td><td>攻击者利用AI技术生成钓鱼邮件、自动化漏洞发现和规避检测</td><td style='color:#d97706;font-weight:bold'>中</td></tr>");
				stringBuilder.AppendLine("</table>");
				stringBuilder.AppendLine("<h3>6.3 攻击面评估</h3>");
				stringBuilder.AppendLine("<p>基于扫描结果对目标系统攻击面进行多维度评估：</p>");
				stringBuilder.AppendLine("<table><tr><th>评估维度</th><th>当前状态</th><th>风险等级</th></tr>");
				bool flag5 = list3.Any((PortScanResult p) => p.PortNumber == 445 || p.PortNumber == 135 || p.PortNumber == 3389 || p.PortNumber == 23);
				stringBuilder2 = stringBuilder;
				StringBuilder stringBuilder58 = stringBuilder2;
				handler = new StringBuilder.AppendInterpolatedStringHandler(97, 4, stringBuilder2);
				handler.AppendLiteral("<tr><td><strong>外部可达端口数</strong></td><td>");
				handler.AppendFormatted(list3.Count);
				handler.AppendLiteral("个开放端口");
				handler.AppendFormatted(flag5 ? "（含高危端口）" : "（未发现高危端口）");
				handler.AppendLiteral("</td><td style='color:");
				handler.AppendFormatted(flag5 ? "#dc2626" : "#059669");
				handler.AppendLiteral(";font-weight:bold'>");
				handler.AppendFormatted(flag5 ? "高" : "低");
				handler.AppendLiteral("</td></tr>");
				stringBuilder58.AppendLine(ref handler);
				stringBuilder2 = stringBuilder;
				StringBuilder stringBuilder59 = stringBuilder2;
				handler = new StringBuilder.AppendInterpolatedStringHandler(94, 4, stringBuilder2);
				handler.AppendLiteral("<tr><td><strong>已知漏洞数量</strong></td><td>");
				handler.AppendFormatted(list2.Count);
				handler.AppendLiteral("个漏洞");
				handler.AppendFormatted((num > 0) ? $"（含{num}个高危）" : "");
				handler.AppendLiteral("</td><td style='color:");
				handler.AppendFormatted((num > 0) ? "#dc2626" : "#059669");
				handler.AppendLiteral(";font-weight:bold'>");
				handler.AppendFormatted((num > 0) ? "高" : "低");
				handler.AppendLiteral("</td></tr>");
				stringBuilder59.AppendLine(ref handler);
				bool flag6 = list3.Any((PortScanResult p) => p.PortNumber == 80 || p.PortNumber == 443 || p.PortNumber == 8080);
				stringBuilder2 = stringBuilder;
				StringBuilder stringBuilder60 = stringBuilder2;
				handler = new StringBuilder.AppendInterpolatedStringHandler(90, 3, stringBuilder2);
				handler.AppendLiteral("<tr><td><strong>服务暴露面</strong></td><td>");
				handler.AppendFormatted(flag6 ? "Web服务对外暴露" : "无Web服务对外暴露");
				handler.AppendLiteral("</td><td style='color:");
				handler.AppendFormatted(flag6 ? "#d97706" : "#059669");
				handler.AppendLiteral(";font-weight:bold'>");
				handler.AppendFormatted(flag6 ? "中" : "低");
				handler.AppendLiteral("</td></tr>");
				stringBuilder60.AppendLine(ref handler);
				bool flag7 = list2.Any((VulnerabilityResult v) => (v != null && v.Name?.ToLower().Contains("auth") == true) || (v != null && v.Name?.ToLower().Contains("认证") == true) || (v != null && v.Name?.ToLower().Contains("login") == true));
				stringBuilder2 = stringBuilder;
				StringBuilder stringBuilder61 = stringBuilder2;
				handler = new StringBuilder.AppendInterpolatedStringHandler(91, 3, stringBuilder2);
				handler.AppendLiteral("<tr><td><strong>身份认证风险</strong></td><td>");
				handler.AppendFormatted(flag7 ? "存在认证相关漏洞" : "未发现认证相关漏洞");
				handler.AppendLiteral("</td><td style='color:");
				handler.AppendFormatted(flag7 ? "#dc2626" : "#059669");
				handler.AppendLiteral(";font-weight:bold'>");
				handler.AppendFormatted(flag7 ? "高" : "低");
				handler.AppendLiteral("</td></tr>");
				stringBuilder61.AppendLine(ref handler);
				bool flag8 = list2.Any((VulnerabilityResult v) => (v != null && v.Name?.ToLower().Contains("disclosure") == true) || (v != null && v.Name?.ToLower().Contains("泄露") == true) || (v != null && v.Name?.ToLower().Contains("leak") == true));
				stringBuilder2 = stringBuilder;
				StringBuilder stringBuilder62 = stringBuilder2;
				handler = new StringBuilder.AppendInterpolatedStringHandler(91, 3, stringBuilder2);
				handler.AppendLiteral("<tr><td><strong>数据泄露风险</strong></td><td>");
				handler.AppendFormatted(flag8 ? "存在信息泄露风险" : "未发现数据泄露风险");
				handler.AppendLiteral("</td><td style='color:");
				handler.AppendFormatted(flag8 ? "#d97706" : "#059669");
				handler.AppendLiteral(";font-weight:bold'>");
				handler.AppendFormatted(flag8 ? "中" : "低");
				handler.AppendLiteral("</td></tr>");
				stringBuilder62.AppendLine(ref handler);
				stringBuilder.AppendLine("</table>");
				stringBuilder.AppendLine("<h2>七、合规参考</h2>");
				stringBuilder.AppendLine("<p>本节根据当前扫描结果，对照主要信息安全合规标准评估目标系统的合规状态。</p>");
				stringBuilder.AppendLine("<h3>7.1 合规标准对照评估</h3>");
				stringBuilder.AppendLine("<table><tr><th>合规标准</th><th>相关要求</th><th>评估范围</th><th>符合性状态</th></tr>");
				stringBuilder2 = stringBuilder;
				StringBuilder stringBuilder63 = stringBuilder2;
				handler = new StringBuilder.AppendInterpolatedStringHandler(131, 2, stringBuilder2);
				handler.AppendLiteral("<tr><td><strong>等保2.0</strong></td><td>安全通信网络、安全区域边界、安全计算环境</td><td>网络安全等级保护基本要求</td><td style='color:");
				handler.AppendFormatted((num > 0) ? "#d97706" : "#059669");
				handler.AppendLiteral(";font-weight:bold'>");
				handler.AppendFormatted((num > 0) ? "部分符合" : "基本符合");
				handler.AppendLiteral("</td></tr>");
				stringBuilder63.AppendLine(ref handler);
				stringBuilder2 = stringBuilder;
				StringBuilder stringBuilder64 = stringBuilder2;
				handler = new StringBuilder.AppendInterpolatedStringHandler(141, 2, stringBuilder2);
				handler.AppendLiteral("<tr><td><strong>ISO 27001</strong></td><td>A.12漏洞管理、A.13通信安全、A.14系统开发安全</td><td>信息安全管理体系要求</td><td style='color:");
				handler.AppendFormatted((num > 3) ? "#dc2626" : "#d97706");
				handler.AppendLiteral(";font-weight:bold'>");
				handler.AppendFormatted((num > 3) ? "不符合" : "部分符合");
				handler.AppendLiteral("</td></tr>");
				stringBuilder64.AppendLine(ref handler);
				stringBuilder.AppendLine("<tr><td><strong>GDPR</strong></td><td>第32条-数据处理者安全措施、第25条-数据保护设计</td><td>通用数据保护条例</td><td style='color:#64748b;font-weight:bold'>需要评估</td></tr>");
				stringBuilder2 = stringBuilder;
				StringBuilder stringBuilder65 = stringBuilder2;
				handler = new StringBuilder.AppendInterpolatedStringHandler(144, 2, stringBuilder2);
				handler.AppendLiteral("<tr><td><strong>PCI DSS</strong></td><td>Req.6安全系统开发、Req.11安全测试、Req.2安全配置</td><td>支付卡行业数据安全标准</td><td style='color:");
				handler.AppendFormatted((num > 0) ? "#dc2626" : "#64748b");
				handler.AppendLiteral(";font-weight:bold'>");
				handler.AppendFormatted((num > 0) ? "不符合" : "需要评估");
				handler.AppendLiteral("</td></tr>");
				stringBuilder65.AppendLine(ref handler);
				stringBuilder2 = stringBuilder;
				StringBuilder stringBuilder66 = stringBuilder2;
				handler = new StringBuilder.AppendInterpolatedStringHandler(140, 2, stringBuilder2);
				handler.AppendLiteral("<tr><td><strong>CIS Controls</strong></td><td>控制3数据保护、控制5安全配置、控制7漏洞管理</td><td>CIS关键安全控制措施</td><td style='color:");
				handler.AppendFormatted((num > 0) ? "#d97706" : "#059669");
				handler.AppendLiteral(";font-weight:bold'>");
				handler.AppendFormatted((num > 0) ? "部分符合" : "基本符合");
				handler.AppendLiteral("</td></tr>");
				stringBuilder66.AppendLine(ref handler);
				stringBuilder.AppendLine("</table>");
				stringBuilder.AppendLine("<h3>7.2 合规差距分析</h3>");
				if (num > 0)
				{
					stringBuilder2 = stringBuilder;
					StringBuilder stringBuilder67 = stringBuilder2;
					handler = new StringBuilder.AppendInterpolatedStringHandler(91, 1, stringBuilder2);
					handler.AppendLiteral("<div class='gap-item'><strong>1.</strong> 发现");
					handler.AppendFormatted(num);
					handler.AppendLiteral("个高危漏洞，不符合等保2.0漏洞管理要求和ISO 27001 A.12漏洞管理控制</div>");
					stringBuilder67.AppendLine(ref handler);
				}
				if (list3.Any((PortScanResult p) => p.PortNumber == 445 || p.PortNumber == 135))
				{
					stringBuilder.AppendLine("<div class='gap-item'><strong>2.</strong> SMB/RPC等高危端口对外开放，不符合等保2.0安全区域边界要求和CIS控制5安全配置</div>");
				}
				if (list3.Any((PortScanResult p) => p.PortNumber == 3389))
				{
					stringBuilder.AppendLine("<div class='gap-item'><strong>3.</strong> RDP远程桌面端口暴露，不符合PCI DSS Req.1网络分段要求</div>");
				}
				if (num == 0 && !list3.Any((PortScanResult p) => p.PortNumber == 445 || p.PortNumber == 135 || p.PortNumber == 3389))
				{
					stringBuilder.AppendLine("<div class='gap-item'>当前扫描结果未发现明显合规差距，建议持续监控并定期进行合规审计</div>");
				}
				stringBuilder.AppendLine("<h3>7.3 合规改进建议</h3>");
				stringBuilder.AppendLine("<p>针对上述合规差距，建议按以下优先级进行改进：</p>");
				stringBuilder.AppendLine("<table><tr><th>序号</th><th>改进措施</th><th>关联标准</th><th>优先级</th><th>具体建议</th></tr>");
				stringBuilder.AppendLine("<tr><td>1</td><td><strong>建立安全基线配置标准</strong></td><td>等保2.0/ISO 27001</td><td style='color:#dc2626;font-weight:bold'>高</td><td>制定并实施系统安全配置基线，定期进行基线检查和偏差修正</td></tr>");
				stringBuilder.AppendLine("<tr><td>2</td><td><strong>实施漏洞管理流程</strong></td><td>CIS Controls/PCI DSS</td><td style='color:#dc2626;font-weight:bold'>高</td><td>建立漏洞扫描、评估、修复的闭环管理流程，确保高危漏洞在规定时限内修复</td></tr>");
				stringBuilder.AppendLine("<tr><td>3</td><td><strong>加强访问控制机制</strong></td><td>等保2.0/GDPR</td><td style='color:#dc2626;font-weight:bold'>高</td><td>实施最小权限原则，部署多因素认证，定期审计账户权限</td></tr>");
				stringBuilder.AppendLine("<tr><td>4</td><td><strong>完善日志审计体系</strong></td><td>等保2.0/ISO 27001</td><td style='color:#d97706;font-weight:bold'>中</td><td>部署集中化日志管理平台，确保关键操作可追溯，日志保留不少于6个月</td></tr>");
				stringBuilder.AppendLine("<tr><td>5</td><td><strong>数据加密与保护</strong></td><td>GDPR/PCI DSS</td><td style='color:#d97706;font-weight:bold'>中</td><td>对敏感数据实施传输加密（TLS 1.2+）和存储加密，建立数据分类分级制度</td></tr>");
				stringBuilder.AppendLine("<tr><td>6</td><td><strong>安全意识培训</strong></td><td>ISO 27001/CIS Controls</td><td style='color:#059669;font-weight:bold'>低</td><td>定期开展安全意识培训和考核，建立安全事件报告机制</td></tr>");
				stringBuilder.AppendLine("</table>");
				stringBuilder.AppendLine("<h2>八、结论与建议</h2>");
				stringBuilder.AppendLine("<h3>8.1 总体安全评级</h3>");
				string value40 = text switch
				{
					"中" => "#fefce8", 
					"高" => "#fff7ed", 
					"严重" => "#fef2f2", 
					_ => "#ecfdf5", 
				};
				string value41 = text switch
				{
					"中" => "#d97706", 
					"高" => "#c2410c", 
					"严重" => "#991b1b", 
					_ => "#059669", 
				};
				stringBuilder2 = stringBuilder;
				StringBuilder stringBuilder68 = stringBuilder2;
				handler = new StringBuilder.AppendInterpolatedStringHandler(127, 2, stringBuilder2);
				handler.AppendLiteral("<div style='text-align:center;padding:30px;margin:20px auto;max-width:500px;background:");
				handler.AppendFormatted(value40);
				handler.AppendLiteral(";border:2px solid ");
				handler.AppendFormatted(value41);
				handler.AppendLiteral(";border-radius:12px;'>");
				stringBuilder68.AppendLine(ref handler);
				stringBuilder.AppendLine("<div style='font-size:14px;color:#64748b;'>总体安全评级</div>");
				stringBuilder2 = stringBuilder;
				StringBuilder stringBuilder69 = stringBuilder2;
				handler = new StringBuilder.AppendInterpolatedStringHandler(75, 2, stringBuilder2);
				handler.AppendLiteral("<div style='font-size:36px;font-weight:bold;color:");
				handler.AppendFormatted(value41);
				handler.AppendLiteral(";margin:10px 0;'>");
				handler.AppendFormatted(text);
				handler.AppendLiteral("风险</div>");
				stringBuilder69.AppendLine(ref handler);
				stringBuilder2 = stringBuilder;
				StringBuilder stringBuilder70 = stringBuilder2;
				handler = new StringBuilder.AppendInterpolatedStringHandler(88, 1, stringBuilder2);
				handler.AppendLiteral("<div style='font-size:18px;font-weight:bold;color:#1a365d;margin:4px 0;'>安全评分：");
				handler.AppendFormatted(num2);
				handler.AppendLiteral("/100</div>");
				stringBuilder70.AppendLine(ref handler);
				stringBuilder2 = stringBuilder;
				StringBuilder stringBuilder71 = stringBuilder2;
				handler = new StringBuilder.AppendInterpolatedStringHandler(64, 1, stringBuilder2);
				handler.AppendLiteral("<div style='font-size:12px;color:#64748b;margin-top:6px;'>");
				handler.AppendFormatted(GetSecurityRatingDescriptionForScore(num2));
				handler.AppendLiteral("</div>");
				stringBuilder71.AppendLine(ref handler);
				stringBuilder2 = stringBuilder;
				StringBuilder stringBuilder72 = stringBuilder2;
				handler = new StringBuilder.AppendInterpolatedStringHandler(130, 3, stringBuilder2);
				handler.AppendLiteral("<div style='font-size:12px;color:#64748b;margin-top:8px;padding-top:8px;border-top:1px solid #e2e8f0;'>目标系统：");
				handler.AppendFormatted(value);
				handler.AppendLiteral(" | 漏洞总数：");
				handler.AppendFormatted(list2.Count);
				handler.AppendLiteral(" | 开放端口：");
				handler.AppendFormatted(list3.Count);
				handler.AppendLiteral("</div>");
				stringBuilder72.AppendLine(ref handler);
				stringBuilder.AppendLine("</div>");
				HashSet<int> source = list3.Select((PortScanResult p) => p.PortNumber).ToHashSet();
				bool flag9 = list2.Any((VulnerabilityResult v) => IsCriticalLevel((v != null) ? v.RiskLevel : null) || IsHighLevel((v != null) ? v.RiskLevel : null));
				(string, int)[] array6 = new(string, int)[5]
				{
					("等保2.0", flag9 ? 45 : 75),
					("ISO 27001", flag9 ? 50 : 80),
					("GDPR", source.Any((int p) => p == 445 || p == 3389 || p == 3306) ? 40 : 85),
					("PCI DSS", flag9 ? 55 : 80),
					("CIS Controls", flag9 ? 50 : 75)
				};
				stringBuilder.AppendLine("<h3>8.2 合规雷达图</h3>");
				stringBuilder.AppendLine("<div class='chart-container'>");
				stringBuilder.AppendLine("<div style='display:flex;justify-content:center;padding:10px 0;'>");
				stringBuilder.AppendLine("<svg width='340' height='340' viewBox='0 0 340 340'>");
				int num20 = 170;
				int num21 = 165;
				int num22 = 120;
				int num23 = array6.Length;
				for (int j = 1; j <= 4; j++)
				{
					int num24 = num22 * j / 4;
					List<string> list6 = new List<string>();
					for (int k = 0; k < num23; k++)
					{
						double num25 = -Math.PI / 2.0 + Math.PI * 2.0 * (double)k / (double)num23;
						float value42 = (float)num20 + (float)((double)num24 * Math.Cos(num25));
						float value43 = (float)num21 + (float)((double)num24 * Math.Sin(num25));
						list6.Add($"{value42:F1},{value43:F1}");
					}
					stringBuilder2 = stringBuilder;
					StringBuilder stringBuilder73 = stringBuilder2;
					handler = new StringBuilder.AppendInterpolatedStringHandler(91, 1, stringBuilder2);
					handler.AppendLiteral("<polygon points='");
					handler.AppendFormatted(string.Join(" ", list6));
					handler.AppendLiteral("' fill='none' stroke='#cbd5e1' stroke-width='0.5' stroke-dasharray='3,3'/>");
					stringBuilder73.AppendLine(ref handler);
				}
				for (int m = 0; m < num23; m++)
				{
					double num26 = -Math.PI / 2.0 + Math.PI * 2.0 * (double)m / (double)num23;
					float value44 = (float)num20 + (float)((double)num22 * Math.Cos(num26));
					float value45 = (float)num21 + (float)((double)num22 * Math.Sin(num26));
					stringBuilder2 = stringBuilder;
					StringBuilder stringBuilder74 = stringBuilder2;
					handler = new StringBuilder.AppendInterpolatedStringHandler(67, 4, stringBuilder2);
					handler.AppendLiteral("<line x1='");
					handler.AppendFormatted(num20);
					handler.AppendLiteral("' y1='");
					handler.AppendFormatted(num21);
					handler.AppendLiteral("' x2='");
					handler.AppendFormatted(value44, "F1");
					handler.AppendLiteral("' y2='");
					handler.AppendFormatted(value45, "F1");
					handler.AppendLiteral("' stroke='#cbd5e1' stroke-width='0.5'/>");
					stringBuilder74.AppendLine(ref handler);
				}
				List<string> list7 = new List<string>();
				for (int n = 0; n < num23; n++)
				{
					double num27 = -Math.PI / 2.0 + Math.PI * 2.0 * (double)n / (double)num23;
					float num28 = (float)(num22 * array6[n].Item2) / 100f;
					float value46 = (float)num20 + (float)((double)num28 * Math.Cos(num27));
					float value47 = (float)num21 + (float)((double)num28 * Math.Sin(num27));
					list7.Add($"{value46:F1},{value47:F1}");
				}
				stringBuilder2 = stringBuilder;
				StringBuilder stringBuilder75 = stringBuilder2;
				handler = new StringBuilder.AppendInterpolatedStringHandler(83, 1, stringBuilder2);
				handler.AppendLiteral("<polygon points='");
				handler.AppendFormatted(string.Join(" ", list7));
				handler.AppendLiteral("' fill='rgba(59,130,246,0.25)' stroke='#2563eb' stroke-width='2'/>");
				stringBuilder75.AppendLine(ref handler);
				for (int num29 = 0; num29 < num23; num29++)
				{
					string[] array7 = list7[num29].Split(',');
					stringBuilder2 = stringBuilder;
					StringBuilder stringBuilder76 = stringBuilder2;
					handler = new StringBuilder.AppendInterpolatedStringHandler(74, 2, stringBuilder2);
					handler.AppendLiteral("<circle cx='");
					handler.AppendFormatted(array7[0]);
					handler.AppendLiteral("' cy='");
					handler.AppendFormatted(array7[1]);
					handler.AppendLiteral("' r='4' fill='#1d4ed8' stroke='white' stroke-width='2'/>");
					stringBuilder76.AppendLine(ref handler);
				}
				for (int num30 = 0; num30 < num23; num30++)
				{
					double num31 = -Math.PI / 2.0 + Math.PI * 2.0 * (double)num30 / (double)num23;
					float value48 = (float)num20 + (float)((double)(num22 + 28) * Math.Cos(num31));
					float value49 = (float)num21 + (float)((double)(num22 + 28) * Math.Sin(num31));
					stringBuilder2 = stringBuilder;
					StringBuilder stringBuilder77 = stringBuilder2;
					handler = new StringBuilder.AppendInterpolatedStringHandler(120, 3, stringBuilder2);
					handler.AppendLiteral("<text x='");
					handler.AppendFormatted(value48, "F1");
					handler.AppendLiteral("' y='");
					handler.AppendFormatted(value49, "F1");
					handler.AppendLiteral("' text-anchor='middle' dominant-baseline='central' font-size='11' fill='#334155' font-weight='500'>");
					handler.AppendFormatted(array6[num30].Item1);
					handler.AppendLiteral("</text>");
					stringBuilder77.AppendLine(ref handler);
				}
				stringBuilder.AppendLine("</svg>");
				stringBuilder.AppendLine("</div></div>");
				stringBuilder.AppendLine("<h3>8.3 核心结论</h3>");
				if (num > 0)
				{
					stringBuilder2 = stringBuilder;
					StringBuilder stringBuilder78 = stringBuilder2;
					handler = new StringBuilder.AppendInterpolatedStringHandler(151, 6, stringBuilder2);
					handler.AppendLiteral("<p>本次扫描针对目标系统 <strong>");
					handler.AppendFormatted(value);
					handler.AppendLiteral("</strong> 进行了全面的网络安全评估，共发现 <strong>");
					handler.AppendFormatted(list2.Count);
					handler.AppendLiteral("</strong> 个安全漏洞（其中高危 ");
					handler.AppendFormatted(num);
					handler.AppendLiteral(" 个、中危 ");
					handler.AppendFormatted(value2);
					handler.AppendLiteral(" 个、低危 ");
					handler.AppendFormatted(value3);
					handler.AppendLiteral(" 个）和 ");
					handler.AppendFormatted(list3.Count);
					handler.AppendLiteral(" 个开放端口。发现的高危漏洞需要立即采取修复措施，建议按照本报告提供的修复优先级矩阵制定详细的修复计划。</p>");
					stringBuilder78.AppendLine(ref handler);
				}
				else if (list2.Any())
				{
					stringBuilder2 = stringBuilder;
					StringBuilder stringBuilder79 = stringBuilder2;
					handler = new StringBuilder.AppendInterpolatedStringHandler(129, 5, stringBuilder2);
					handler.AppendLiteral("<p>本次扫描针对目标系统 <strong>");
					handler.AppendFormatted(value);
					handler.AppendLiteral("</strong> 进行了全面的网络安全评估，共发现 <strong>");
					handler.AppendFormatted(list2.Count);
					handler.AppendLiteral("</strong> 个安全漏洞（中危 ");
					handler.AppendFormatted(value2);
					handler.AppendLiteral(" 个、低危 ");
					handler.AppendFormatted(value3);
					handler.AppendLiteral(" 个）和 ");
					handler.AppendFormatted(list3.Count);
					handler.AppendLiteral(" 个开放端口。当前未发现高危漏洞，但建议对中低危漏洞进行持续关注和计划修复。</p>");
					stringBuilder79.AppendLine(ref handler);
				}
				else
				{
					stringBuilder2 = stringBuilder;
					StringBuilder stringBuilder80 = stringBuilder2;
					handler = new StringBuilder.AppendInterpolatedStringHandler(83, 2, stringBuilder2);
					handler.AppendLiteral("<p>本次扫描针对目标系统 <strong>");
					handler.AppendFormatted(value);
					handler.AppendLiteral("</strong> 进行了全面的网络安全评估，未发现安全漏洞。发现 ");
					handler.AppendFormatted(list3.Count);
					handler.AppendLiteral(" 个开放端口，建议持续监控并定期进行安全评估。</p>");
					stringBuilder80.AppendLine(ref handler);
				}
				stringBuilder.AppendLine("<div style='margin-top:12px;'>");
				int num32 = list2.Count((VulnerabilityResult v) => IsCriticalLevel((v != null) ? v.RiskLevel : null));
				if (num32 > 0)
				{
					stringBuilder2 = stringBuilder;
					StringBuilder stringBuilder81 = stringBuilder2;
					handler = new StringBuilder.AppendInterpolatedStringHandler(93, 1, stringBuilder2);
					handler.AppendLiteral("<div class='threat-item'><strong>1.</strong> 本次扫描发现");
					handler.AppendFormatted(num32);
					handler.AppendLiteral("个严重漏洞，存在被远程攻击的高风险，攻击者可利用这些漏洞获取系统控制权。</div>");
					stringBuilder81.AppendLine(ref handler);
				}
				if (num > 0)
				{
					stringBuilder2 = stringBuilder;
					StringBuilder stringBuilder82 = stringBuilder2;
					handler = new StringBuilder.AppendInterpolatedStringHandler(82, 2, stringBuilder2);
					handler.AppendLiteral("<div class='threat-item'><strong>");
					handler.AppendFormatted((num32 > 0) ? "2" : "1");
					handler.AppendLiteral(".</strong> 共发现");
					handler.AppendFormatted(num);
					handler.AppendLiteral("个高危漏洞，涉及多个服务端口，需优先处理以降低被攻击风险。</div>");
					stringBuilder82.AppendLine(ref handler);
				}
				if (source.Any((int p) => p == 445 || p == 135 || p == 3389))
				{
					stringBuilder.AppendLine("<div class='threat-item'><strong>3.</strong> 系统暴露了SMB/RPC/RDP等高危端口，这些端口是勒索软件和蠕虫病毒的主要传播通道。</div>");
				}
				if (source.Any((int p) => p == 3306 || p == 1433 || p == 5432 || p == 6379))
				{
					stringBuilder.AppendLine("<div class='threat-item'><strong>4.</strong> 数据库或缓存服务端口对外暴露，存在数据泄露和未授权访问风险。</div>");
				}
				if (list3.Count > 15)
				{
					stringBuilder2 = stringBuilder;
					StringBuilder stringBuilder83 = stringBuilder2;
					handler = new StringBuilder.AppendInterpolatedStringHandler(83, 1, stringBuilder2);
					handler.AppendLiteral("<div class='threat-item'><strong>5.</strong> 开放端口数量较多（");
					handler.AppendFormatted(list3.Count);
					handler.AppendLiteral("个），攻击面较大，建议关闭不必要的端口和服务。</div>");
					stringBuilder83.AppendLine(ref handler);
				}
				stringBuilder.AppendLine("<div class='hardening-item'><strong>建议：</strong>建立常态化安全扫描机制，定期评估系统安全状况，及时发现和修复新增安全风险。</div>");
				stringBuilder.AppendLine("</div>");
				stringBuilder.AppendLine("<h3>8.4 长期安全建议</h3>");
				stringBuilder.AppendLine("<p>以下为按优先级分类的长期安全改进建议：</p>");
				stringBuilder.AppendLine("<h4 style='color:#dc2626;margin-top:16px;'>P1 - 紧急（1-7天内完成）</h4>");
				stringBuilder.AppendLine("<table><tr><th>#</th><th>类别</th><th>建议措施</th></tr>");
				stringBuilder.AppendLine("<tr><td style='color:#dc2626;font-weight:bold'>1</td><td><strong>漏洞修复</strong></td><td>修复所有严重和高危漏洞，消除远程代码执行风险</td></tr>");
				stringBuilder.AppendLine("<tr><td style='color:#dc2626;font-weight:bold'>2</td><td><strong>端口安全</strong></td><td>关闭所有非必要的高危端口（如135、445、3389等），配置严格的防火墙规则</td></tr>");
				stringBuilder.AppendLine("<tr><td style='color:#dc2626;font-weight:bold'>3</td><td><strong>数据库隔离</strong></td><td>对暴露的数据库端口实施网络隔离，仅允许授权IP访问</td></tr>");
				stringBuilder.AppendLine("<tr><td style='color:#dc2626;font-weight:bold'>4</td><td><strong>加密通信</strong></td><td>启用所有对外服务的安全加密通信（TLS 1.2+）</td></tr>");
				stringBuilder.AppendLine("<tr><td style='color:#dc2626;font-weight:bold'>5</td><td><strong>多因素认证</strong></td><td>实施多因素认证(MFA)，覆盖所有远程访问和特权账户</td></tr>");
				stringBuilder.AppendLine("</table>");
				stringBuilder.AppendLine("<h4 style='color:#d97706;margin-top:16px;'>P2 - 重要（1-3个月内完成）</h4>");
				stringBuilder.AppendLine("<table><tr><th>#</th><th>类别</th><th>建议措施</th></tr>");
				stringBuilder.AppendLine("<tr><td style='color:#d97706;font-weight:bold'>1</td><td><strong>漏洞管理</strong></td><td>建立漏洞管理闭环流程，实现扫描-评估-修复-验证的标准化</td></tr>");
				stringBuilder.AppendLine("<tr><td style='color:#d97706;font-weight:bold'>2</td><td><strong>安全监控</strong></td><td>部署集中化日志管理系统(SIEM)，实现安全事件实时监控和告警</td></tr>");
				stringBuilder.AppendLine("<tr><td style='color:#d97706;font-weight:bold'>3</td><td><strong>网络分段</strong></td><td>实施网络分段和微隔离，限制横向移动攻击路径</td></tr>");
				stringBuilder.AppendLine("<tr><td style='color:#d97706;font-weight:bold'>4</td><td><strong>安全基线</strong></td><td>制定安全配置基线标准，定期进行基线检查和偏差修正</td></tr>");
				stringBuilder.AppendLine("<tr><td style='color:#d97706;font-weight:bold'>5</td><td><strong>安全培训</strong></td><td>建立安全意识培训体系，定期开展全员安全培训</td></tr>");
				stringBuilder.AppendLine("</table>");
				stringBuilder.AppendLine("<h4 style='color:#059669;margin-top:16px;'>P3 - 改善（3-6个月内完成）</h4>");
				stringBuilder.AppendLine("<table><tr><th>#</th><th>类别</th><th>建议措施</th></tr>");
				stringBuilder.AppendLine("<tr><td style='color:#059669;font-weight:bold'>1</td><td><strong>合规建设</strong></td><td>推进等保2.0合规建设，完成差距整改和测评</td></tr>");
				stringBuilder.AppendLine("<tr><td style='color:#059669;font-weight:bold'>2</td><td><strong>体系认证</strong></td><td>实施ISO 27001信息安全管理体系认证</td></tr>");
				stringBuilder.AppendLine("<tr><td style='color:#059669;font-weight:bold'>3</td><td><strong>威胁情报</strong></td><td>建立威胁情报平台，实现安全威胁的主动防御</td></tr>");
				stringBuilder.AppendLine("<tr><td style='color:#059669;font-weight:bold'>4</td><td><strong>编排自动化</strong></td><td>建设安全编排自动化与响应(SOAR)能力</td></tr>");
				stringBuilder.AppendLine("<tr><td style='color:#059669;font-weight:bold'>5</td><td><strong>数据分级</strong></td><td>制定数据分类分级保护策略，满足GDPR/PCI DSS合规要求</td></tr>");
				stringBuilder.AppendLine("</table>");
				stringBuilder.AppendLine("<div class='footer'>");
				stringBuilder2 = stringBuilder;
				StringBuilder stringBuilder84 = stringBuilder2;
				handler = new StringBuilder.AppendInterpolatedStringHandler(34, 2, stringBuilder2);
				handler.AppendLiteral("NetSecurityScanner v");
				handler.AppendFormatted(GetAppVersion());
				handler.AppendLiteral(" | 报告生成时间：");
				handler.AppendFormatted(DateTime.Now, "yyyy-MM-dd HH:mm:ss");
				handler.AppendLiteral("<br>");
				stringBuilder84.AppendLine(ref handler);
				stringBuilder.AppendLine("免责声明：本报告由自动化安全扫描工具生成，结果仅供参考。对于关键安全问题，建议进行人工验证和深度安全分析。");
				stringBuilder.AppendLine("</div>");
				stringBuilder.AppendLine("</div>");
				stringBuilder.AppendLine("</body></html>");
				File.WriteAllText(savePath2, stringBuilder.ToString(), Encoding.UTF8);
				return savePath2;
			}
			catch (Exception)
			{
				return string.Empty;
			}
		});
	}

	private async Task<string> GenerateCsvReport(List<CompleteScanResult> completeResults, string savePath)
	{
		List<CompleteScanResult> completeResults2 = completeResults;
		string savePath2 = savePath;
		return await Task.Run(delegate
		{
			try
			{
				List<PortScanResult> source = completeResults2.SelectMany((CompleteScanResult r) => r.PortScanResults ?? new List<PortScanResult>()).ToList();
				List<VulnerabilityResult> list = completeResults2.SelectMany((CompleteScanResult r) => r.VulnerabilityResults ?? new List<VulnerabilityResult>()).ToList();
				string field = string.Join(", ", completeResults2.Select((CompleteScanResult r) => r.TargetIp).Distinct());
				List<PortScanResult> list2 = source.Where((PortScanResult p) => ((p != null) ? p.Status : null) == "开放" || ((p == null) ? null : p.Status?.ToLower()) == "open").ToList();
				int num = list.Count((VulnerabilityResult v) => IsCriticalLevel((v != null) ? v.RiskLevel : null) || IsHighLevel((v != null) ? v.RiskLevel : null));
				StringBuilder stringBuilder = new StringBuilder();
				stringBuilder.AppendLine("网络安全漏洞扫描评估报告 - CSV数据导出");
				StringBuilder stringBuilder2 = stringBuilder;
				StringBuilder stringBuilder3 = stringBuilder2;
				StringBuilder.AppendInterpolatedStringHandler handler = new StringBuilder.AppendInterpolatedStringHandler(7, 1, stringBuilder2);
				handler.AppendLiteral("报告生成时间,");
				handler.AppendFormatted(DateTime.Now, "yyyy-MM-dd HH:mm:ss");
				stringBuilder3.AppendLine(ref handler);
				stringBuilder2 = stringBuilder;
				StringBuilder stringBuilder4 = stringBuilder2;
				handler = new StringBuilder.AppendInterpolatedStringHandler(5, 1, stringBuilder2);
				handler.AppendLiteral("目标系统,");
				handler.AppendFormatted(EscapeCsvField(field));
				stringBuilder4.AppendLine(ref handler);
				stringBuilder2 = stringBuilder;
				StringBuilder stringBuilder5 = stringBuilder2;
				handler = new StringBuilder.AppendInterpolatedStringHandler(5, 1, stringBuilder2);
				handler.AppendLiteral("扫描类型,");
				handler.AppendFormatted(EscapeCsvField(BuildScanTypeDescription(completeResults2)));
				stringBuilder5.AppendLine(ref handler);
				stringBuilder2 = stringBuilder;
				StringBuilder stringBuilder6 = stringBuilder2;
				handler = new StringBuilder.AppendInterpolatedStringHandler(5, 1, stringBuilder2);
				handler.AppendLiteral("风险等级,");
				handler.AppendFormatted(CalculateOverallRiskFromVulns(list));
				stringBuilder6.AppendLine(ref handler);
				stringBuilder2 = stringBuilder;
				StringBuilder stringBuilder7 = stringBuilder2;
				handler = new StringBuilder.AppendInterpolatedStringHandler(6, 1, stringBuilder2);
				handler.AppendLiteral("开放端口数,");
				handler.AppendFormatted(list2.Count);
				stringBuilder7.AppendLine(ref handler);
				stringBuilder2 = stringBuilder;
				StringBuilder stringBuilder8 = stringBuilder2;
				handler = new StringBuilder.AppendInterpolatedStringHandler(5, 1, stringBuilder2);
				handler.AppendLiteral("漏洞总数,");
				handler.AppendFormatted(list.Count);
				stringBuilder8.AppendLine(ref handler);
				stringBuilder.AppendLine();
				if (list2.Any())
				{
					stringBuilder.AppendLine("=== 端口扫描结果 ===");
					stringBuilder.AppendLine("端口号,协议,服务名称,版本,状态,响应时间");
					foreach (PortScanResult item in list2.OrderBy((PortScanResult p) => p.PortNumber))
					{
						stringBuilder2 = stringBuilder;
						StringBuilder stringBuilder9 = stringBuilder2;
						handler = new StringBuilder.AppendInterpolatedStringHandler(8, 5, stringBuilder2);
						handler.AppendFormatted(item.PortNumber);
						handler.AppendLiteral(",TCP,");
						handler.AppendFormatted(EscapeCsvField(item.Service ?? "-"));
						handler.AppendLiteral(",");
						handler.AppendFormatted(EscapeCsvField(item.ServiceVersion ?? "-"));
						handler.AppendLiteral(",");
						handler.AppendFormatted(EscapeCsvField(item.Status ?? "未知"));
						handler.AppendLiteral(",");
						handler.AppendFormatted(EscapeCsvField(item.ResponseTime ?? "-"));
						stringBuilder9.AppendLine(ref handler);
					}
					stringBuilder.AppendLine();
				}
				if (list.Any())
				{
					stringBuilder.AppendLine("=== 漏洞详情 ===");
					stringBuilder.AppendLine("序号,CVE编号,漏洞名称,风险等级,端口,服务,CVSS评分,描述,检测方法,修复方案,参考链接");
					int num2 = 1;
					foreach (VulnerabilityResult item2 in list.OrderByDescending((VulnerabilityResult v) => GetRiskPriorityFromLevel((v != null) ? v.RiskLevel : null)))
					{
						double value = EstimateCvssScoreForLevel((item2 != null) ? item2.RiskLevel : null);
						string value2 = (item2.Port.HasValue ? item2.Port.Value.ToString() : "-");
						stringBuilder2 = stringBuilder;
						StringBuilder stringBuilder10 = stringBuilder2;
						handler = new StringBuilder.AppendInterpolatedStringHandler(10, 11, stringBuilder2);
						handler.AppendFormatted(num2);
						handler.AppendLiteral(",");
						handler.AppendFormatted(EscapeCsvField(item2.CveId ?? "-"));
						handler.AppendLiteral(",");
						handler.AppendFormatted(EscapeCsvField(item2.Name ?? "未知"));
						handler.AppendLiteral(",");
						handler.AppendFormatted(EscapeCsvField(item2.RiskLevel ?? "未分类"));
						handler.AppendLiteral(",");
						handler.AppendFormatted(value2);
						handler.AppendLiteral(",");
						handler.AppendFormatted(EscapeCsvField(item2.Service ?? "-"));
						handler.AppendLiteral(",");
						handler.AppendFormatted(value, "F1");
						handler.AppendLiteral(",");
						handler.AppendFormatted(EscapeCsvField(item2.Description ?? "-"));
						handler.AppendLiteral(",");
						handler.AppendFormatted(EscapeCsvField(item2.DetectionMethod ?? "-"));
						handler.AppendLiteral(",");
						handler.AppendFormatted(EscapeCsvField(item2.Solution ?? "-"));
						handler.AppendLiteral(",");
						handler.AppendFormatted(EscapeCsvField(item2.References ?? "-"));
						stringBuilder10.AppendLine(ref handler);
						num2++;
					}
					stringBuilder.AppendLine();
				}
				stringBuilder.AppendLine("=== 修复优先级矩阵 ===");
				stringBuilder.AppendLine("优先级,处理时限,适用范围,建议措施");
				stringBuilder.AppendLine("P1-紧急,24小时内,严重/远程执行类,立即隔离受影响系统");
				stringBuilder.AppendLine("P2-高,7天内,高危/权限提升类,尽快安排维护窗口");
				stringBuilder.AppendLine("P3-中,30天内,中危/信息泄露类,纳入常规更新计划");
				stringBuilder.AppendLine("P4-低,下个周期,低危/信息类,持续监控");
				stringBuilder.AppendLine();
				stringBuilder.AppendLine("=== 威胁情报分析 ===");
				stringBuilder.AppendLine("威胁向量,风险等级,描述");
				if (list2.Any((PortScanResult p) => p.PortNumber == 445 || p.PortNumber == 139))
				{
					stringBuilder.AppendLine("SMB服务暴露,高危,勒索软件主要传播通道");
				}
				if (list2.Any((PortScanResult p) => p.PortNumber == 3389))
				{
					stringBuilder.AppendLine("RDP远程桌面暴露,高危,暴力破解和蓝屏漏洞利用风险");
				}
				if (list2.Any((PortScanResult p) => p.PortNumber == 80 || p.PortNumber == 443 || p.PortNumber == 8080))
				{
					stringBuilder.AppendLine("Web服务暴露,中危,SQL注入/XSS/目录遍历等攻击风险");
				}
				if (num > 0)
				{
					stringBuilder2 = stringBuilder;
					StringBuilder stringBuilder11 = stringBuilder2;
					handler = new StringBuilder.AppendInterpolatedStringHandler(24, 1, stringBuilder2);
					handler.AppendLiteral("已知高危漏洞,高危,发现");
					handler.AppendFormatted(num);
					handler.AppendLiteral("个高危漏洞可被自动化利用");
					stringBuilder11.AppendLine(ref handler);
				}
				stringBuilder.AppendLine("弱密码攻击,中危,字典攻击和凭据填充风险");
				stringBuilder.AppendLine("拒绝服务攻击,中危,DoS/DDoS风险");
				stringBuilder.AppendLine();
				stringBuilder.AppendLine("=== 合规参考 ===");
				stringBuilder.AppendLine("合规标准,相关要求,符合性状态");
				stringBuilder2 = stringBuilder;
				StringBuilder stringBuilder12 = stringBuilder2;
				handler = new StringBuilder.AppendInterpolatedStringHandler(27, 1, stringBuilder2);
				handler.AppendLiteral("等保2.0,安全通信网络/安全区域边界/安全计算环境,");
				handler.AppendFormatted((num > 0) ? "部分符合" : "基本符合");
				stringBuilder12.AppendLine(ref handler);
				stringBuilder2 = stringBuilder;
				StringBuilder stringBuilder13 = stringBuilder2;
				handler = new StringBuilder.AppendInterpolatedStringHandler(39, 1, stringBuilder2);
				handler.AppendLiteral("ISO 27001,A.12漏洞管理/A.13通信安全/A.14系统开发安全,");
				handler.AppendFormatted((num > 3) ? "不符合" : "部分符合");
				stringBuilder13.AppendLine(ref handler);
				stringBuilder.AppendLine("GDPR,第32条-数据处理者安全措施/第25条-数据保护设计,需要评估");
				stringBuilder2 = stringBuilder;
				StringBuilder stringBuilder14 = stringBuilder2;
				handler = new StringBuilder.AppendInterpolatedStringHandler(41, 1, stringBuilder2);
				handler.AppendLiteral("PCI DSS,Req.6安全系统开发/Req.11安全测试/Req.2安全配置,");
				handler.AppendFormatted((num > 0) ? "不符合" : "需要评估");
				stringBuilder14.AppendLine(ref handler);
				stringBuilder2 = stringBuilder;
				StringBuilder stringBuilder15 = stringBuilder2;
				handler = new StringBuilder.AppendInterpolatedStringHandler(37, 1, stringBuilder2);
				handler.AppendLiteral("CIS Controls,控制3数据保护/控制5安全配置/控制7漏洞管理,");
				handler.AppendFormatted((num > 0) ? "部分符合" : "基本符合");
				stringBuilder15.AppendLine(ref handler);
				File.WriteAllText(savePath2, stringBuilder.ToString(), Encoding.UTF8);
				return savePath2;
			}
			catch (Exception)
			{
				return string.Empty;
			}
		});
	}

	private static string EscapeCsvField(string field)
	{
		if (string.IsNullOrEmpty(field))
		{
			return "";
		}
		if (field.Contains(",") || field.Contains("\"") || field.Contains("\n") || field.Contains("\r"))
		{
			return "\"" + field.Replace("\"", "\"\"") + "\"";
		}
		return field;
	}

	private async Task<string> GenerateTxtReport(List<CompleteScanResult> completeResults, string savePath)
	{
		List<CompleteScanResult> completeResults2 = completeResults;
		string savePath2 = savePath;
		return await Task.Run(delegate
		{
			try
			{
				List<PortScanResult> list = completeResults2.SelectMany((CompleteScanResult r) => r.PortScanResults ?? new List<PortScanResult>()).ToList();
				List<VulnerabilityResult> list2 = completeResults2.SelectMany((CompleteScanResult r) => r.VulnerabilityResults ?? new List<VulnerabilityResult>()).ToList();
				string value = string.Join(", ", completeResults2.Select((CompleteScanResult r) => r.TargetIp).Distinct());
				List<PortScanResult> list3 = list.Where((PortScanResult p) => ((p != null) ? p.Status : null) == "开放" || ((p == null) ? null : p.Status?.ToLower()) == "open").ToList();
				string value2 = CalculateOverallRiskFromVulns(list2);
				int num = list2.Count((VulnerabilityResult v) => IsCriticalLevel((v != null) ? v.RiskLevel : null) || IsHighLevel((v != null) ? v.RiskLevel : null));
				int value3 = list2.Count((VulnerabilityResult v) => IsMediumLevel((v != null) ? v.RiskLevel : null));
				int value4 = list2.Count((VulnerabilityResult v) => IsLowLevel((v != null) ? v.RiskLevel : null));
				StringBuilder stringBuilder = new StringBuilder();
				stringBuilder.AppendLine("═══════════════════════════════════════════════════════════════");
				stringBuilder.AppendLine("                    网络安全漏洞扫描评估报告");
				stringBuilder.AppendLine("            Network Security Vulnerability Assessment Report");
				stringBuilder.AppendLine("═══════════════════════════════════════════════════════════════");
				stringBuilder.AppendLine();
				stringBuilder.AppendLine($"  报告编号：RPT-{DateTime.Now:yyyyMMdd}-{Guid.NewGuid():N}".Substring(0, 40));
				StringBuilder stringBuilder2 = stringBuilder;
				StringBuilder stringBuilder3 = stringBuilder2;
				StringBuilder.AppendInterpolatedStringHandler handler = new StringBuilder.AppendInterpolatedStringHandler(7, 1, stringBuilder2);
				handler.AppendLiteral("  目标系统：");
				handler.AppendFormatted(value);
				stringBuilder3.AppendLine(ref handler);
				stringBuilder2 = stringBuilder;
				StringBuilder stringBuilder4 = stringBuilder2;
				handler = new StringBuilder.AppendInterpolatedStringHandler(7, 1, stringBuilder2);
				handler.AppendLiteral("  扫描时间：");
				handler.AppendFormatted(DateTime.Now, "yyyy-MM-dd HH:mm:ss");
				stringBuilder4.AppendLine(ref handler);
				stringBuilder2 = stringBuilder;
				StringBuilder stringBuilder5 = stringBuilder2;
				handler = new StringBuilder.AppendInterpolatedStringHandler(7, 1, stringBuilder2);
				handler.AppendLiteral("  扫描模式：");
				handler.AppendFormatted(BuildScanTypeDescription(completeResults2));
				stringBuilder5.AppendLine(ref handler);
				stringBuilder2 = stringBuilder;
				StringBuilder stringBuilder6 = stringBuilder2;
				handler = new StringBuilder.AppendInterpolatedStringHandler(7, 1, stringBuilder2);
				handler.AppendLiteral("  生成时间：");
				handler.AppendFormatted(DateTime.Now, "yyyy-MM-dd HH:mm:ss");
				stringBuilder6.AppendLine(ref handler);
				stringBuilder.AppendLine();
				stringBuilder.AppendLine("───────────────────────────────────────────────────────────────");
				stringBuilder.AppendLine("一、核心统计");
				stringBuilder.AppendLine("───────────────────────────────────────────────────────────────");
				stringBuilder2 = stringBuilder;
				StringBuilder stringBuilder7 = stringBuilder2;
				handler = new StringBuilder.AppendInterpolatedStringHandler(7, 1, stringBuilder2);
				handler.AppendLiteral("  风险等级：");
				handler.AppendFormatted(value2);
				stringBuilder7.AppendLine(ref handler);
				stringBuilder2 = stringBuilder;
				StringBuilder stringBuilder8 = stringBuilder2;
				handler = new StringBuilder.AppendInterpolatedStringHandler(17, 2, stringBuilder2);
				handler.AppendLiteral("  开放端口：");
				handler.AppendFormatted(list3.Count);
				handler.AppendLiteral("个 / 扫描端口：");
				handler.AppendFormatted(list.Count);
				handler.AppendLiteral("个");
				stringBuilder8.AppendLine(ref handler);
				stringBuilder2 = stringBuilder;
				StringBuilder stringBuilder9 = stringBuilder2;
				handler = new StringBuilder.AppendInterpolatedStringHandler(8, 1, stringBuilder2);
				handler.AppendLiteral("  漏洞总数：");
				handler.AppendFormatted(list2.Count);
				handler.AppendLiteral("个");
				stringBuilder9.AppendLine(ref handler);
				stringBuilder2 = stringBuilder;
				StringBuilder stringBuilder10 = stringBuilder2;
				handler = new StringBuilder.AppendInterpolatedStringHandler(9, 1, stringBuilder2);
				handler.AppendLiteral("  严重/高危：");
				handler.AppendFormatted(num);
				handler.AppendLiteral("个");
				stringBuilder10.AppendLine(ref handler);
				stringBuilder2 = stringBuilder;
				StringBuilder stringBuilder11 = stringBuilder2;
				handler = new StringBuilder.AppendInterpolatedStringHandler(8, 1, stringBuilder2);
				handler.AppendLiteral("  中危漏洞：");
				handler.AppendFormatted(value3);
				handler.AppendLiteral("个");
				stringBuilder11.AppendLine(ref handler);
				stringBuilder2 = stringBuilder;
				StringBuilder stringBuilder12 = stringBuilder2;
				handler = new StringBuilder.AppendInterpolatedStringHandler(8, 1, stringBuilder2);
				handler.AppendLiteral("  低危漏洞：");
				handler.AppendFormatted(value4);
				handler.AppendLiteral("个");
				stringBuilder12.AppendLine(ref handler);
				int value5 = (list2.Any() ? ((int)((double)num / (double)list2.Count * 100.0)) : 0);
				stringBuilder2 = stringBuilder;
				StringBuilder stringBuilder13 = stringBuilder2;
				handler = new StringBuilder.AppendInterpolatedStringHandler(8, 1, stringBuilder2);
				handler.AppendLiteral("  高危占比：");
				handler.AppendFormatted(value5);
				handler.AppendLiteral("%");
				stringBuilder13.AppendLine(ref handler);
				stringBuilder.AppendLine();
				if (list2.Any())
				{
					stringBuilder.AppendLine("───────────────────────────────────────────────────────────────");
					stringBuilder.AppendLine("  Top 5 高危漏洞");
					stringBuilder.AppendLine("───────────────────────────────────────────────────────────────");
					int num2 = 1;
					foreach (VulnerabilityResult item in list2.OrderByDescending((VulnerabilityResult v) => GetRiskPriorityFromLevel((v != null) ? v.RiskLevel : null)).Take(5))
					{
						stringBuilder2 = stringBuilder;
						StringBuilder stringBuilder14 = stringBuilder2;
						handler = new StringBuilder.AppendInterpolatedStringHandler(10, 4, stringBuilder2);
						handler.AppendLiteral("  ");
						handler.AppendFormatted(num2);
						handler.AppendLiteral(". [");
						handler.AppendFormatted(item.RiskLevel ?? "未分类");
						handler.AppendLiteral("] ");
						handler.AppendFormatted(item.Name ?? "未知漏洞");
						handler.AppendLiteral(" (");
						handler.AppendFormatted(item.CveId ?? "-");
						handler.AppendLiteral(")");
						stringBuilder14.AppendLine(ref handler);
						num2++;
					}
					stringBuilder.AppendLine();
				}
				if (list3.Any())
				{
					stringBuilder.AppendLine("───────────────────────────────────────────────────────────────");
					stringBuilder.AppendLine("二、端口扫描结果");
					stringBuilder.AppendLine("───────────────────────────────────────────────────────────────");
					stringBuilder2 = stringBuilder;
					StringBuilder stringBuilder15 = stringBuilder2;
					handler = new StringBuilder.AppendInterpolatedStringHandler(2, 5, stringBuilder2);
					handler.AppendLiteral("  ");
					handler.AppendFormatted<string>("端口号", -8);
					handler.AppendFormatted<string>("协议", -6);
					handler.AppendFormatted<string>("服务名称", -16);
					handler.AppendFormatted<string>("版本", -24);
					handler.AppendFormatted<string>("状态", -10);
					stringBuilder15.AppendLine(ref handler);
					stringBuilder.AppendLine("  " + new string('-', 60));
					foreach (PortScanResult item2 in list3.OrderBy((PortScanResult p) => p.PortNumber))
					{
						string value6 = (item2.Service ?? "未知").PadRight(14).Substring(0, Math.Min(14, (item2.Service ?? "未知").Length));
						string value7 = (item2.ServiceVersion ?? "-").PadRight(22).Substring(0, Math.Min(22, (item2.ServiceVersion ?? "-").Length));
						stringBuilder2 = stringBuilder;
						StringBuilder stringBuilder16 = stringBuilder2;
						handler = new StringBuilder.AppendInterpolatedStringHandler(2, 5, stringBuilder2);
						handler.AppendLiteral("  ");
						handler.AppendFormatted(item2.PortNumber, -8);
						handler.AppendFormatted<string>("TCP", -6);
						handler.AppendFormatted<string>(value6, -16);
						handler.AppendFormatted<string>(value7, -24);
						handler.AppendFormatted<string>(item2.Status ?? "未知", -10);
						stringBuilder16.AppendLine(ref handler);
					}
					stringBuilder.AppendLine();
				}
				if (list2.Any())
				{
					stringBuilder.AppendLine("───────────────────────────────────────────────────────────────");
					stringBuilder.AppendLine("三、漏洞详情");
					stringBuilder.AppendLine("───────────────────────────────────────────────────────────────");
					int num3 = 1;
					foreach (VulnerabilityResult item3 in list2.OrderByDescending((VulnerabilityResult v) => GetRiskPriorityFromLevel((v != null) ? v.RiskLevel : null)))
					{
						double value8 = EstimateCvssScoreForLevel((item3 != null) ? item3.RiskLevel : null);
						stringBuilder2 = stringBuilder;
						StringBuilder stringBuilder17 = stringBuilder2;
						handler = new StringBuilder.AppendInterpolatedStringHandler(5, 2, stringBuilder2);
						handler.AppendLiteral("  [");
						handler.AppendFormatted(num3);
						handler.AppendLiteral("] ");
						handler.AppendFormatted(item3.Name ?? "未知漏洞");
						stringBuilder17.AppendLine(ref handler);
						stringBuilder2 = stringBuilder;
						StringBuilder stringBuilder18 = stringBuilder2;
						handler = new StringBuilder.AppendInterpolatedStringHandler(12, 1, stringBuilder2);
						handler.AppendLiteral("      CVE编号：");
						handler.AppendFormatted(item3.CveId ?? "-");
						stringBuilder18.AppendLine(ref handler);
						stringBuilder2 = stringBuilder;
						StringBuilder stringBuilder19 = stringBuilder2;
						handler = new StringBuilder.AppendInterpolatedStringHandler(20, 2, stringBuilder2);
						handler.AppendLiteral("      风险等级：");
						handler.AppendFormatted(item3.RiskLevel ?? "未分类");
						handler.AppendLiteral(" (CVSS: ");
						handler.AppendFormatted(value8, "F1");
						handler.AppendLiteral(")");
						stringBuilder19.AppendLine(ref handler);
						stringBuilder2 = stringBuilder;
						StringBuilder stringBuilder20 = stringBuilder2;
						handler = new StringBuilder.AppendInterpolatedStringHandler(11, 1, stringBuilder2);
						handler.AppendLiteral("      影响端口：");
						handler.AppendFormatted(item3.Port.HasValue ? item3.Port.Value.ToString() : "-");
						stringBuilder20.AppendLine(ref handler);
						stringBuilder2 = stringBuilder;
						StringBuilder stringBuilder21 = stringBuilder2;
						handler = new StringBuilder.AppendInterpolatedStringHandler(9, 1, stringBuilder2);
						handler.AppendLiteral("      服务：");
						handler.AppendFormatted(item3.Service ?? "-");
						stringBuilder21.AppendLine(ref handler);
						stringBuilder2 = stringBuilder;
						StringBuilder stringBuilder22 = stringBuilder2;
						handler = new StringBuilder.AppendInterpolatedStringHandler(9, 1, stringBuilder2);
						handler.AppendLiteral("      描述：");
						handler.AppendFormatted(item3.Description ?? "-");
						stringBuilder22.AppendLine(ref handler);
						if (!string.IsNullOrWhiteSpace(item3.DetectionMethod))
						{
							stringBuilder2 = stringBuilder;
							StringBuilder stringBuilder23 = stringBuilder2;
							handler = new StringBuilder.AppendInterpolatedStringHandler(11, 1, stringBuilder2);
							handler.AppendLiteral("      检测方法：");
							handler.AppendFormatted(item3.DetectionMethod);
							stringBuilder23.AppendLine(ref handler);
						}
						stringBuilder2 = stringBuilder;
						StringBuilder stringBuilder24 = stringBuilder2;
						handler = new StringBuilder.AppendInterpolatedStringHandler(11, 1, stringBuilder2);
						handler.AppendLiteral("      修复方案：");
						handler.AppendFormatted(item3.Solution ?? "请参考官方安全公告");
						stringBuilder24.AppendLine(ref handler);
						if (!string.IsNullOrWhiteSpace(item3.References))
						{
							stringBuilder2 = stringBuilder;
							StringBuilder stringBuilder25 = stringBuilder2;
							handler = new StringBuilder.AppendInterpolatedStringHandler(11, 1, stringBuilder2);
							handler.AppendLiteral("      参考链接：");
							handler.AppendFormatted(item3.References);
							stringBuilder25.AppendLine(ref handler);
						}
						stringBuilder.AppendLine();
						num3++;
					}
				}
				stringBuilder.AppendLine("───────────────────────────────────────────────────────────────");
				stringBuilder.AppendLine("四、风险评估");
				stringBuilder.AppendLine("───────────────────────────────────────────────────────────────");
				stringBuilder2 = stringBuilder;
				StringBuilder stringBuilder26 = stringBuilder2;
				handler = new StringBuilder.AppendInterpolatedStringHandler(9, 1, stringBuilder2);
				handler.AppendLiteral("  整体风险评级：");
				handler.AppendFormatted(value2);
				stringBuilder26.AppendLine(ref handler);
				stringBuilder2 = stringBuilder;
				StringBuilder stringBuilder27 = stringBuilder2;
				handler = new StringBuilder.AppendInterpolatedStringHandler(7, 1, stringBuilder2);
				handler.AppendLiteral("  漏洞总量：");
				handler.AppendFormatted(list2.Count);
				stringBuilder27.AppendLine(ref handler);
				stringBuilder2 = stringBuilder;
				StringBuilder stringBuilder28 = stringBuilder2;
				handler = new StringBuilder.AppendInterpolatedStringHandler(8, 1, stringBuilder2);
				handler.AppendLiteral("  高危漏洞数：");
				handler.AppendFormatted(num);
				stringBuilder28.AppendLine(ref handler);
				stringBuilder2 = stringBuilder;
				StringBuilder stringBuilder29 = stringBuilder2;
				handler = new StringBuilder.AppendInterpolatedStringHandler(8, 1, stringBuilder2);
				handler.AppendLiteral("  开放端口数：");
				handler.AppendFormatted(list3.Count);
				stringBuilder29.AppendLine(ref handler);
				stringBuilder.AppendLine();
				stringBuilder.AppendLine("  安全建议：");
				string[] array = new string[6] { "立即修复所有严重和高危级别的漏洞", "关闭不必要的服务和端口，减少攻击面", "及时更新系统和应用软件至最新版本", "实施强密码策略和多因素认证(MFA)", "配置防火墙规则限制网络访问", "定期进行安全扫描和渗透测试" };
				foreach (string value9 in array)
				{
					stringBuilder2 = stringBuilder;
					StringBuilder stringBuilder30 = stringBuilder2;
					handler = new StringBuilder.AppendInterpolatedStringHandler(6, 1, stringBuilder2);
					handler.AppendLiteral("    * ");
					handler.AppendFormatted(value9);
					stringBuilder30.AppendLine(ref handler);
				}
				stringBuilder.AppendLine();
				stringBuilder.AppendLine("───────────────────────────────────────────────────────────────");
				stringBuilder.AppendLine("五、修复建议");
				stringBuilder.AppendLine("───────────────────────────────────────────────────────────────");
				stringBuilder.AppendLine("  修复优先级矩阵：");
				stringBuilder.AppendLine("    P1-紧急 | 24小时内 | 严重/远程执行类 | 立即隔离受影响系统");
				stringBuilder.AppendLine("    P2-高   | 7天内   | 高危/权限提升类 | 尽快安排维护窗口");
				stringBuilder.AppendLine("    P3-中   | 30天内  | 中危/信息泄露类 | 纳入常规更新计划");
				stringBuilder.AppendLine("    P4-低   | 下个周期 | 低危/信息类    | 持续监控");
				stringBuilder.AppendLine();
				stringBuilder.AppendLine("  通用安全加固建议：");
				(string, string)[] array2 = new(string, string)[6]
				{
					("1. 网络层面", "配置防火墙规则，仅开放必要的业务端口；实施网络分段隔离；启用IDS/IPS。"),
					("2. 系统层面", "及时安装操作系统安全更新；禁用不必要的服务和账户；配置强密码策略。"),
					("3. 应用层面", "保持应用程序及依赖库为最新版本；实施安全的编码实践；定期进行代码安全审查。"),
					("4. 身份认证", "实施多因素认证(MFA)；采用基于角色的访问控制(RBAC)；定期清理过期账户。"),
					("5. 数据保护", "加密敏感数据存储和传输（TLS 1.2+）；建立定期数据备份和灾难恢复机制。"),
					("6. 监控审计", "部署集中化日志管理系统(SIEM)；设置安全事件实时告警阈值；定期进行合规审计。")
				};
				for (int i = 0; i < array2.Length; i++)
				{
					(string, string) tuple = array2[i];
					stringBuilder2 = stringBuilder;
					StringBuilder stringBuilder31 = stringBuilder2;
					handler = new StringBuilder.AppendInterpolatedStringHandler(5, 2, stringBuilder2);
					handler.AppendLiteral("    ");
					handler.AppendFormatted(tuple.Item1);
					handler.AppendLiteral("：");
					handler.AppendFormatted(tuple.Item2);
					stringBuilder31.AppendLine(ref handler);
				}
				stringBuilder.AppendLine();
				stringBuilder.AppendLine("───────────────────────────────────────────────────────────────");
				stringBuilder.AppendLine("六、威胁情报分析");
				stringBuilder.AppendLine("───────────────────────────────────────────────────────────────");
				stringBuilder.AppendLine("  活跃威胁向量：");
				if (list3.Any((PortScanResult p) => p.PortNumber == 445 || p.PortNumber == 139))
				{
					stringBuilder.AppendLine("    ⚠ SMB服务暴露 — 勒索软件主要传播通道，存在远程代码执行风险");
				}
				if (list3.Any((PortScanResult p) => p.PortNumber == 3389))
				{
					stringBuilder.AppendLine("    ⚠ RDP远程桌面暴露 — 暴力破解和蓝屏漏洞利用风险");
				}
				if (list3.Any((PortScanResult p) => p.PortNumber == 80 || p.PortNumber == 443 || p.PortNumber == 8080))
				{
					stringBuilder.AppendLine("    ⚠ Web服务暴露 — SQL注入/XSS/目录遍历等攻击风险");
				}
				if (num > 0)
				{
					stringBuilder2 = stringBuilder;
					StringBuilder stringBuilder32 = stringBuilder2;
					handler = new StringBuilder.AppendInterpolatedStringHandler(29, 1, stringBuilder2);
					handler.AppendLiteral("    ⚠ 已知高危漏洞 — 发现");
					handler.AppendFormatted(num);
					handler.AppendLiteral("个高危漏洞可被自动化利用");
					stringBuilder32.AppendLine(ref handler);
				}
				stringBuilder.AppendLine("    ⚠ 弱密码和默认凭据攻击 — 字典攻击和凭据填充风险");
				stringBuilder.AppendLine("    ⚠ 拒绝服务攻击(DoS/DDoS) — 开放服务可能成为攻击目标");
				stringBuilder.AppendLine();
				stringBuilder.AppendLine("  行业威胁趋势：");
				stringBuilder.AppendLine("    1. 勒索软件攻击持续增长，采用双重勒索策略");
				stringBuilder.AppendLine("    2. 供应链攻击日益复杂，影响范围扩大");
				stringBuilder.AppendLine("    3. 零日漏洞利用速度加快，数小时内完成武器化");
				stringBuilder.AppendLine("    4. 云服务成为新攻击重点");
				stringBuilder.AppendLine("    5. AI驱动的网络攻击兴起");
				stringBuilder.AppendLine();
				stringBuilder.AppendLine("───────────────────────────────────────────────────────────────");
				stringBuilder.AppendLine("七、合规参考");
				stringBuilder.AppendLine("───────────────────────────────────────────────────────────────");
				stringBuilder2 = stringBuilder;
				StringBuilder stringBuilder33 = stringBuilder2;
				handler = new StringBuilder.AppendInterpolatedStringHandler(35, 1, stringBuilder2);
				handler.AppendLiteral("  等保2.0    ：");
				handler.AppendFormatted((num > 0) ? "部分符合" : "基本符合");
				handler.AppendLiteral(" — 安全通信网络/安全区域边界/安全计算环境");
				stringBuilder33.AppendLine(ref handler);
				stringBuilder2 = stringBuilder;
				StringBuilder stringBuilder34 = stringBuilder2;
				handler = new StringBuilder.AppendInterpolatedStringHandler(45, 1, stringBuilder2);
				handler.AppendLiteral("  ISO 27001  ：");
				handler.AppendFormatted((num > 3) ? "不符合" : "部分符合");
				handler.AppendLiteral(" — A.12漏洞管理/A.13通信安全/A.14系统开发安全");
				stringBuilder34.AppendLine(ref handler);
				stringBuilder.AppendLine("  GDPR       ：需要评估 — 第32条-数据处理者安全措施/第25条-数据保护设计");
				stringBuilder2 = stringBuilder;
				StringBuilder stringBuilder35 = stringBuilder2;
				handler = new StringBuilder.AppendInterpolatedStringHandler(49, 1, stringBuilder2);
				handler.AppendLiteral("  PCI DSS    ：");
				handler.AppendFormatted((num > 0) ? "不符合" : "需要评估");
				handler.AppendLiteral(" — Req.6安全系统开发/Req.11安全测试/Req.2安全配置");
				stringBuilder35.AppendLine(ref handler);
				stringBuilder2 = stringBuilder;
				StringBuilder stringBuilder36 = stringBuilder2;
				handler = new StringBuilder.AppendInterpolatedStringHandler(41, 1, stringBuilder2);
				handler.AppendLiteral("  CIS Controls：");
				handler.AppendFormatted((num > 0) ? "部分符合" : "基本符合");
				handler.AppendLiteral(" — 控制3数据保护/控制5安全配置/控制7漏洞管理");
				stringBuilder36.AppendLine(ref handler);
				stringBuilder.AppendLine();
				stringBuilder.AppendLine("───────────────────────────────────────────────────────────────");
				stringBuilder.AppendLine("八、结论与建议");
				stringBuilder.AppendLine("───────────────────────────────────────────────────────────────");
				stringBuilder2 = stringBuilder;
				StringBuilder stringBuilder37 = stringBuilder2;
				handler = new StringBuilder.AppendInterpolatedStringHandler(11, 1, stringBuilder2);
				handler.AppendLiteral("  总体安全评级：");
				handler.AppendFormatted(value2);
				handler.AppendLiteral("风险");
				stringBuilder37.AppendLine(ref handler);
				stringBuilder2 = stringBuilder;
				StringBuilder stringBuilder38 = stringBuilder2;
				handler = new StringBuilder.AppendInterpolatedStringHandler(23, 3, stringBuilder2);
				handler.AppendLiteral("  目标系统：");
				handler.AppendFormatted(value);
				handler.AppendLiteral(" | 漏洞总数：");
				handler.AppendFormatted(list2.Count);
				handler.AppendLiteral(" | 开放端口：");
				handler.AppendFormatted(list3.Count);
				stringBuilder38.AppendLine(ref handler);
				stringBuilder.AppendLine();
				stringBuilder.AppendLine("  长期安全建议：");
				stringBuilder.AppendLine("    [P1] 建立定期漏洞扫描机制，每周至少全面扫描一次");
				stringBuilder.AppendLine("    [P1] 实施漏洞管理全流程，确保从发现到修复的闭环跟踪");
				stringBuilder.AppendLine("    [P2] 部署入侵检测和防御系统(IDS/IPS)");
				stringBuilder.AppendLine("    [P2] 建立安全事件应急响应计划");
				stringBuilder.AppendLine("    [P2] 加强员工安全意识培训");
				stringBuilder.AppendLine("    [P3] 实施最小权限原则，定期审查用户权限");
				stringBuilder.AppendLine("    [P3] 保持系统和应用程序的及时更新");
				stringBuilder.AppendLine("    [P3] 定期备份关键数据，验证可恢复性");
				stringBuilder.AppendLine();
				stringBuilder.AppendLine("═══════════════════════════════════════════════════════════════");
				stringBuilder.AppendLine("免责声明：本报告由 NetSecurityScanner 安全扫描工具自动生成，结果仅供参考。");
				stringBuilder.AppendLine("对于关键安全问题，建议进行人工验证和深度安全分析。");
				stringBuilder.AppendLine("═══════════════════════════════════════════════════════════════");
				File.WriteAllText(savePath2, stringBuilder.ToString(), Encoding.UTF8);
				return savePath2;
			}
			catch (Exception)
			{
				return string.Empty;
			}
		});
	}

	private static string CalculateOverallRiskFromVulns(List<VulnerabilityResult> vulns)
	{
		if (vulns == null || !vulns.Any())
		{
			return "信息";
		}
		if (vulns.Any((VulnerabilityResult v) => IsCriticalLevel((v != null) ? v.RiskLevel : null)))
		{
			return "严重";
		}
		if (vulns.Any((VulnerabilityResult v) => IsHighLevel((v != null) ? v.RiskLevel : null)))
		{
			return "高";
		}
		if (vulns.Any((VulnerabilityResult v) => IsMediumLevel((v != null) ? v.RiskLevel : null)))
		{
			return "中";
		}
		return "低";
	}

	private static int GetRiskPriorityFromLevel(string riskLevel)
	{
		if (string.IsNullOrWhiteSpace(riskLevel))
		{
			return 0;
		}
		if (IsCriticalLevel(riskLevel))
		{
			return 5;
		}
		if (IsHighLevel(riskLevel))
		{
			return 4;
		}
		if (IsMediumLevel(riskLevel))
		{
			return 3;
		}
		if (IsLowLevel(riskLevel))
		{
			return 2;
		}
		return 1;
	}

	private static bool IsCriticalLevel(string riskLevel)
	{
		if (string.IsNullOrWhiteSpace(riskLevel))
		{
			return false;
		}
		string text = riskLevel.Trim().ToLower();
		if (!text.Contains("严重"))
		{
			return text == "critical";
		}
		return true;
	}

	private static bool IsHighLevel(string riskLevel)
	{
		if (string.IsNullOrWhiteSpace(riskLevel))
		{
			return false;
		}
		string text = riskLevel.Trim().ToLower();
		if (!text.Contains("高") || text.Contains("严重"))
		{
			return text == "high";
		}
		return true;
	}

	private static bool IsMediumLevel(string riskLevel)
	{
		if (string.IsNullOrWhiteSpace(riskLevel))
		{
			return false;
		}
		string text = riskLevel.Trim().ToLower();
		if (!text.Contains("中"))
		{
			return text == "medium";
		}
		return true;
	}

	private static bool IsLowLevel(string riskLevel)
	{
		if (string.IsNullOrWhiteSpace(riskLevel))
		{
			return false;
		}
		string text = riskLevel.Trim().ToLower();
		if (!text.Contains("低"))
		{
			return text == "low";
		}
		return true;
	}

	private static double EstimateCvssScoreForLevel(string riskLevel)
	{
		if (string.IsNullOrEmpty(riskLevel))
		{
			return 0.0;
		}
		if (IsCriticalLevel(riskLevel))
		{
			return 9.5;
		}
		if (IsHighLevel(riskLevel))
		{
			return 7.5;
		}
		if (IsMediumLevel(riskLevel))
		{
			return 5.5;
		}
		if (IsLowLevel(riskLevel))
		{
			return 3.0;
		}
		return 1.0;
	}

	private static int CalculateSecurityScoreFromVulns(List<VulnerabilityResult> vulns, List<PortScanResult> openPorts)
	{
		int num = 100;
		int num2 = vulns.Count((VulnerabilityResult v) => IsCriticalLevel((v != null) ? v.RiskLevel : null));
		int num3 = vulns.Count((VulnerabilityResult v) => IsHighLevel((v != null) ? v.RiskLevel : null));
		int num4 = vulns.Count((VulnerabilityResult v) => IsMediumLevel((v != null) ? v.RiskLevel : null));
		int num5 = vulns.Count((VulnerabilityResult v) => IsLowLevel((v != null) ? v.RiskLevel : null));
		num -= num2 * 15;
		num -= num3 * 8;
		num -= num4 * 3;
		num -= num5;
		HashSet<int> hashSet = openPorts.Select((PortScanResult p) => (p != null) ? p.PortNumber : 0).ToHashSet();
		if (hashSet.Contains(445) || hashSet.Contains(135))
		{
			num -= 10;
		}
		if (hashSet.Contains(3389))
		{
			num -= 8;
		}
		if (hashSet.Contains(23))
		{
			num -= 10;
		}
		if (hashSet.Contains(3306) || hashSet.Contains(1433) || hashSet.Contains(5432))
		{
			num -= 5;
		}
		if (openPorts.Count > 20)
		{
			num -= 5;
		}
		else if (openPorts.Count > 10)
		{
			num -= 3;
		}
		return Math.Max(0, Math.Min(100, num));
	}

	private static string GetSecurityRatingDescriptionForScore(int score)
	{
		if (score >= 90)
		{
			return "系统安全状况优秀，仅存在少量低风险问题，建议持续保持安全监控。";
		}
		if (score >= 75)
		{
			return "系统安全状况良好，存在部分中等风险问题，建议按计划进行安全加固。";
		}
		if (score >= 60)
		{
			return "系统安全状况一般，存在多个安全风险，建议尽快制定并执行安全改进计划。";
		}
		if (score >= 40)
		{
			return "系统安全状况较差，存在高危安全风险，建议立即采取紧急修复措施。";
		}
		return "系统安全状况严重，存在严重安全漏洞和重大风险，建议立即启动应急响应。";
	}

	private static string BuildScanTypeDescription(List<CompleteScanResult> results)
	{
		if (results == null || !results.Any())
		{
			return "综合扫描";
		}
		List<string> list = (from r in results
			select (r == null) ? null : r.ScanType into s
			where !string.IsNullOrWhiteSpace(s)
			select s).Distinct().ToList();
		if (!list.Any())
		{
			return "综合扫描";
		}
		List<string> list2 = new List<string>();
		foreach (string item in list)
		{
			if (item.Contains("专家模式"))
			{
				list2.Add("专家模式");
			}
			else if (item.Contains("漏洞"))
			{
				list2.Add("漏洞扫描");
			}
			else if (item.Contains("TCP"))
			{
				list2.Add("TCP端口扫描");
			}
			else if (item.Contains("UDP"))
			{
				list2.Add("UDP端口扫描");
			}
			else
			{
				list2.Add(item);
			}
		}
		List<string> values = list2.Distinct().ToList();
		return string.Join(" + ", values);
	}

	private static List<string> GetActiveScanFeatures(List<CompleteScanResult> results)
	{
		List<string> list = new List<string>();
		if (results == null || !results.Any())
		{
			return list;
		}
		List<string> source = (from r in results
			select (r == null) ? null : r.ScanType into s
			where !string.IsNullOrWhiteSpace(s)
			select s).Distinct().ToList();
		bool flag = source.Any((string s) => s.Contains("TCP") || s.Contains("UDP") || s.Contains("端口"));
		bool flag2 = source.Any((string s) => s.Contains("漏洞"));
		if (source.Any((string s) => s.Contains("专家模式")))
		{
			list.Add("专家模式");
		}
		if (flag)
		{
			list.Add("TCP端口扫描");
		}
		if (flag2)
		{
			list.Add("漏洞扫描");
		}
		return list;
	}

	private async Task RefreshScanHistoryAsync()
	{
		try
		{
			List<ScanHistoryItem> histories = await _jsonDatabaseService.GetScanHistoryAsync();
			await ((DispatcherObject)this).Dispatcher.BeginInvoke((Delegate)(Action)delegate
			{
				UpdateScanHistoryDisplay(histories);
				StatusTextBlock.Text = "扫描历史记录已刷新";
			}, Array.Empty<object>());
		}
		catch (Exception ex2)
		{
			Exception ex = ex2;
			Log("刷新扫描历史记录失败: " + ex.Message);
			await ((DispatcherObject)this).Dispatcher.BeginInvoke((Delegate)(Action)delegate
			{
				MessageBox.Show("刷新扫描历史记录失败: " + ex.Message, "错误", MessageBoxButton.OK, MessageBoxImage.Hand);
			}, Array.Empty<object>());
		}
	}

	private void UpdateGenerateButtons()
	{
		bool isEnabled = _portScanResults.Any((PortScanResult r) => r.IsSelected);
		_portScanResults.Any((PortScanResult r) => r.Status == "开放" || r.Status == "开放或过滤");
		GeneratePortBatButton.IsEnabled = isEnabled;
	}

	private bool IsValidIpAddress(string ipAddress)
	{
		if (string.IsNullOrEmpty(ipAddress))
		{
			return false;
		}
		IPAddress address;
		return IPAddress.TryParse(ipAddress, out address);
	}

	private List<int> ParsePortRange(string portRange)
	{
		List<int> list = new List<int>();
		if (string.IsNullOrEmpty(portRange))
		{
			return list;
		}
		string[] array = portRange.Split(',', StringSplitOptions.RemoveEmptyEntries);
		for (int i = 0; i < array.Length; i++)
		{
			string text = array[i].Trim();
			int result3;
			if (text.Contains("-"))
			{
				string[] array2 = text.Split('-', StringSplitOptions.RemoveEmptyEntries);
				if (array2.Length == 2 && int.TryParse(array2[0], out var result) && int.TryParse(array2[1], out var result2) && result <= result2 && result >= 0 && result2 <= 65535)
				{
					list.AddRange(Enumerable.Range(result, result2 - result + 1));
				}
			}
			else if (int.TryParse(text, out result3) && result3 >= 0 && result3 <= 65535)
			{
				list.Add(result3);
			}
		}
		return (from p in list.Distinct()
			orderby p
			select p).ToList();
	}

	private void PortScanResultsDataGrid_ItemContainerGenerator_StatusChanged(object? sender, EventArgs e)
	{
	}

	private void SystemUptimeTimer_Tick(object? sender, EventArgs e)
	{
		try
		{
			TimeSpan timeSpan = DateTime.Now - _systemStartTime;
			if (SystemUptimeText != null)
			{
				SystemUptimeText.Text = $"运行时间: {timeSpan.Hours:D2}:{timeSpan.Minutes:D2}:{timeSpan.Seconds:D2}";
			}
		}
		catch (Exception ex)
		{
			Log("更新系统运行时间失败: " + ex.Message);
		}
	}

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
			_cpuCounter.NextValue();
			_ramCounter.NextValue();
		}
		catch (Exception ex)
		{
			Log("初始化性能计数器失败: " + ex.Message);
		}
	}

	private void StartSystemHealthUpdates()
	{
		//IL_0001: Unknown result type (might be due to invalid IL or missing references)
		//IL_000b: Expected O, but got Unknown
		_systemHealthTimer = new DispatcherTimer();
		_systemHealthTimer.Interval = TimeSpan.FromSeconds(5.0);
		_systemHealthTimer.Tick += SystemHealthTimer_Tick;
		_systemHealthTimer.Start();
		UpdateSystemHealthStatus();
	}

	private void SystemHealthTimer_Tick(object? sender, EventArgs e)
	{
		UpdateSystemHealthStatus();
	}

	private void UpdateSystemHealthStatus()
	{
		try
		{
			float cpuUsage = 0f;
			if (_cpuCounter != null)
			{
				cpuUsage = _cpuCounter.NextValue();
			}
			float ramUsage = 0f;
			if (_ramCounter != null)
			{
				ramUsage = _ramCounter.NextValue();
			}
			DriveInfo[] drives = DriveInfo.GetDrives();
			float maxDiskUsage = 0f;
			foreach (DriveInfo item in drives.Where((DriveInfo d) => d.IsReady && d.DriveType == DriveType.Fixed))
			{
				try
				{
					double num = item.TotalSize;
					double num2 = item.TotalFreeSpace;
					float num3 = (float)((num - num2) / num * 100.0);
					if (num3 > maxDiskUsage)
					{
						maxDiskUsage = num3;
					}
				}
				catch (Exception)
				{
				}
			}
			int networkConnections = GetActiveTcpConnectionsCount();
			if (((DispatcherObject)this).Dispatcher.CheckAccess())
			{
				CpuUsageTextBlock.Text = $"CPU: {cpuUsage:F1}%";
				RamUsageTextBlock.Text = $"内存: {ramUsage:F1}%";
				DiskUsageTextBlock.Text = $"磁盘: {maxDiskUsage:F1}%";
				NetworkConnectionsTextBlock.Text = $"网络连接: {networkConnections}";
				return;
			}
			((DispatcherObject)this).Dispatcher.Invoke((Action)delegate
			{
				CpuUsageTextBlock.Text = $"CPU: {cpuUsage:F1}%";
				RamUsageTextBlock.Text = $"内存: {ramUsage:F1}%";
				DiskUsageTextBlock.Text = $"磁盘: {maxDiskUsage:F1}%";
				NetworkConnectionsTextBlock.Text = $"网络连接: {networkConnections}";
			});
		}
		catch (Exception ex2)
		{
			Log("更新系统健康状态失败: " + ex2.Message);
		}
	}

	private int GetActiveTcpConnectionsCount()
	{
		try
		{
			return IPGlobalProperties.GetIPGlobalProperties().GetActiveTcpConnections().Length;
		}
		catch (Exception ex)
		{
			Log("获取TCP连接数失败: " + ex.Message);
			return 0;
		}
	}

	private async void Window_Closing(object sender, CancelEventArgs e)
	{
		_ = 1;
		try
		{
			Log("开始执行窗口关闭清理");
			if (_cancellationTokenSource != null)
			{
				try
				{
					_cancellationTokenSource.Cancel();
				}
				catch (ObjectDisposedException)
				{
				}
			}
			await Task.Delay(500);
			try
			{
				await PluginGovernor.Instance.ShutdownAsync();
			}
			catch (Exception)
			{
			}
			Dispose();
			Log("窗口关闭清理完成");
		}
		catch (Exception ex3)
		{
			Log("窗口关闭清理过程中发生错误: " + ex3.Message);
		}
	}

	protected virtual void Dispose(bool disposing)
	{
		if (!_disposed && disposing)
		{
			try
			{
				_cancellationTokenSource?.Cancel();
				Thread.Sleep(100);
				if (_cancellationTokenSource != null)
				{
					try
					{
						_cancellationTokenSource.Dispose();
					}
					catch (ObjectDisposedException)
					{
					}
					_cancellationTokenSource = null;
				}
				VulnerabilityScanner vulnerabilityScanner = _vulnerabilityScanner;
				if (vulnerabilityScanner != null)
				{
					vulnerabilityScanner.Dispose();
				}
				DispatcherTimer systemUptimeTimer = _systemUptimeTimer;
				if (systemUptimeTimer != null)
				{
					systemUptimeTimer.Stop();
				}
				if (_systemUptimeTimer != null)
				{
					_systemUptimeTimer.Tick -= SystemUptimeTimer_Tick;
				}
				_systemUptimeTimer = null;
				DispatcherTimer systemHealthTimer = _systemHealthTimer;
				if (systemHealthTimer != null)
				{
					systemHealthTimer.Stop();
				}
				if (_systemHealthTimer != null)
				{
					_systemHealthTimer.Tick -= SystemHealthTimer_Tick;
				}
				_systemHealthTimer = null;
				_cpuCounter?.Dispose();
				_cpuCounter = null;
				_ramCounter?.Dispose();
				_ramCounter = null;
				try
				{
					_uiUpdateThrottler?.Dispose();
					Log("UI节流器已释放");
				}
				catch (Exception ex2)
				{
					Log("释放UI节流器失败: " + ex2.Message);
				}
				finally
				{
					_uiUpdateThrottler = null;
				}
				try
				{
					ScanPerformanceMonitor scanPerformanceMonitor = _scanPerformanceMonitor;
					if (scanPerformanceMonitor != null)
					{
						scanPerformanceMonitor.StopMonitoring();
					}
					ScanPerformanceMonitor scanPerformanceMonitor2 = _scanPerformanceMonitor;
					if (scanPerformanceMonitor2 != null)
					{
						scanPerformanceMonitor2.Dispose();
					}
					if (_scanPerformanceMonitor != null && _scanPerformanceMonitor.PortsScanned > 0)
					{
						ScanPerformanceReport value = _scanPerformanceMonitor.GenerateReport();
						Log($"=== 扫描性能报告 ===\n{value}");
					}
				}
				catch (Exception ex3)
				{
					Log("释放扫描性能监控器失败: " + ex3.Message);
				}
				finally
				{
					_scanPerformanceMonitor = null;
				}
				try
				{
					_portScanResults?.Clear();
					_vulnerabilityResults?.Clear();
					_riskAssessmentItems?.Clear();
					Log("已清理扫描结果集合");
				}
				catch (Exception ex4)
				{
					Log("清理集合数据失败: " + ex4.Message);
				}
				GC.Collect(2, GCCollectionMode.Forced);
				GC.WaitForPendingFinalizers();
				GC.Collect(2, GCCollectionMode.Forced);
			}
			catch (Exception ex5)
			{
				Log("资源清理过程中发生错误: " + ex5.Message);
			}
		}
		_disposed = true;
	}

	public void Dispose()
	{
		Dispose(disposing: true);
		GC.SuppressFinalize(this);
	}

	private void CopyVulnerabilityDetails_Click(object sender, RoutedEventArgs e)
	{
		try
		{
			object selectedItem = VulnerabilityResultsDataGrid.SelectedItem;
			VulnerabilityResult val = (VulnerabilityResult)((selectedItem is VulnerabilityResult) ? selectedItem : null);
			if (val != null)
			{
				Clipboard.SetText($"漏洞名称: {val.Name}\n风险等级: {val.RiskLevel}\n端口: {val.Port}\n服务: {val.Service}\nCVE编号: {val.CveId}\n描述: {val.Description}\n解决方案: {val.Solution}\n参考链接: {val.References}");
				MessageBox.Show("漏洞详情已复制到剪贴板", "提示", MessageBoxButton.OK, MessageBoxImage.Asterisk);
			}
			else
			{
				MessageBox.Show("请先选择一个漏洞条目", "提示", MessageBoxButton.OK, MessageBoxImage.Exclamation);
			}
		}
		catch (Exception ex)
		{
			Log("复制漏洞详情时发生错误: " + ex.Message);
			MessageBox.Show("复制漏洞详情时发生错误", "错误", MessageBoxButton.OK, MessageBoxImage.Hand);
		}
	}

	private void ExportSelectedVulnerabilities_Click(object sender, RoutedEventArgs e)
	{
		try
		{
			object selectedItem = VulnerabilityResultsDataGrid.SelectedItem;
			VulnerabilityResult val = (VulnerabilityResult)((selectedItem is VulnerabilityResult) ? selectedItem : null);
			if (val != null)
			{
				List<VulnerabilityResult> results = new List<VulnerabilityResult> { val };
				ExportVulnerabilitiesToFile(results, "导出选中漏洞", "SelectedVulnerabilities");
			}
			else
			{
				MessageBox.Show("请先选择一个漏洞条目", "提示", MessageBoxButton.OK, MessageBoxImage.Exclamation);
			}
		}
		catch (Exception ex)
		{
			Log("导出漏洞时发生错误: " + ex.Message);
			MessageBox.Show("导出漏洞时发生错误", "错误", MessageBoxButton.OK, MessageBoxImage.Hand);
		}
	}

	private void ViewCveDetails_Click(object sender, RoutedEventArgs e)
	{
		try
		{
			object selectedItem = VulnerabilityResultsDataGrid.SelectedItem;
			VulnerabilityResult val = (VulnerabilityResult)((selectedItem is VulnerabilityResult) ? selectedItem : null);
			if (val != null && !string.IsNullOrEmpty(val.CveId))
			{
				string fileName = "https://nvd.nist.gov/vuln/detail/" + val.CveId;
				Process.Start(new ProcessStartInfo
				{
					FileName = fileName,
					UseShellExecute = true
				});
			}
			else
			{
				MessageBox.Show("所选漏洞没有有效的CVE编号或未选择任何条目", "提示", MessageBoxButton.OK, MessageBoxImage.Exclamation);
			}
		}
		catch (Exception ex)
		{
			Log("打开CVE详情时发生错误: " + ex.Message);
			MessageBox.Show("打开CVE详情时发生错误", "错误", MessageBoxButton.OK, MessageBoxImage.Hand);
		}
	}

	private void CopyCveId_Click(object sender, RoutedEventArgs e)
	{
		try
		{
			object selectedItem = VulnerabilityResultsDataGrid.SelectedItem;
			VulnerabilityResult val = (VulnerabilityResult)((selectedItem is VulnerabilityResult) ? selectedItem : null);
			if (val != null && !string.IsNullOrEmpty(val.CveId))
			{
				Clipboard.SetText(val.CveId);
				MessageBox.Show("CVE编号已复制到剪贴板", "提示", MessageBoxButton.OK, MessageBoxImage.Asterisk);
			}
			else
			{
				MessageBox.Show("所选漏洞没有有效的CVE编号或未选择任何条目", "提示", MessageBoxButton.OK, MessageBoxImage.Exclamation);
			}
		}
		catch (Exception ex)
		{
			Log("复制CVE编号时发生错误: " + ex.Message);
			MessageBox.Show("复制CVE编号时发生错误", "错误", MessageBoxButton.OK, MessageBoxImage.Hand);
		}
	}

	private void MarkAsResolved_Click(object sender, RoutedEventArgs e)
	{
		try
		{
			object selectedItem = VulnerabilityResultsDataGrid.SelectedItem;
			VulnerabilityResult val = (VulnerabilityResult)((selectedItem is VulnerabilityResult) ? selectedItem : null);
			if (val != null)
			{
				val.Solution += " [已标记为已处理]";
				try
				{
					string path = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "vulnerability_results.json");
					string contents = JsonSerializer.Serialize(_vulnerabilityResults, new JsonSerializerOptions
					{
						WriteIndented = true
					});
					File.WriteAllText(path, contents);
				}
				catch (Exception)
				{
				}
				MessageBox.Show("漏洞已标记为已处理", "提示", MessageBoxButton.OK, MessageBoxImage.Asterisk);
			}
			else
			{
				MessageBox.Show("请先选择一个漏洞条目", "提示", MessageBoxButton.OK, MessageBoxImage.Exclamation);
			}
		}
		catch (Exception ex2)
		{
			Log("标记漏洞为已处理时发生错误: " + ex2.Message);
			MessageBox.Show("标记漏洞为已处理时发生错误", "错误", MessageBoxButton.OK, MessageBoxImage.Hand);
		}
	}

	private void AddRemark_Click(object sender, RoutedEventArgs e)
	{
		try
		{
			object selectedItem = VulnerabilityResultsDataGrid.SelectedItem;
			VulnerabilityResult val = (VulnerabilityResult)((selectedItem is VulnerabilityResult) ? selectedItem : null);
			if (val != null)
			{
				InputDialog inputDialog = new InputDialog("添加备注", "请输入备注信息：");
				if (inputDialog.ShowDialog() != true)
				{
					return;
				}
				string answer = inputDialog.Answer;
				if (!string.IsNullOrEmpty(answer))
				{
					val.Description = val.Description + " [备注: " + answer + "]";
					try
					{
						string path = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "vulnerability_results.json");
						string contents = JsonSerializer.Serialize(_vulnerabilityResults, new JsonSerializerOptions
						{
							WriteIndented = true
						});
						File.WriteAllText(path, contents);
					}
					catch (Exception)
					{
					}
					MessageBox.Show("备注已添加", "提示", MessageBoxButton.OK, MessageBoxImage.Asterisk);
				}
			}
			else
			{
				MessageBox.Show("请先选择一个漏洞条目", "提示", MessageBoxButton.OK, MessageBoxImage.Exclamation);
			}
		}
		catch (Exception ex2)
		{
			Log("添加备注时发生错误: " + ex2.Message);
			MessageBox.Show("添加备注时发生错误", "错误", MessageBoxButton.OK, MessageBoxImage.Hand);
		}
	}

	private async void DeepScanMenuItem_Click(object sender, RoutedEventArgs e)
	{
		try
		{
			if (!(sender is MenuItem menuItem) || !(menuItem.DataContext is DataGridRow))
			{
				return;
			}
			DataGrid dataGrid = FindVisualParent<DataGrid>((DependencyObject)(object)menuItem);
			if (dataGrid == null || dataGrid.SelectedItem == null)
			{
				return;
			}
			object selectedItem = dataGrid.SelectedItem;
			string text = null;
			List<int> list = new List<int>();
			Type type = selectedItem.GetType();
			PropertyInfo propertyInfo = type.GetProperty("TargetIp") ?? type.GetProperty("Target") ?? type.GetProperty("Ip") ?? type.GetProperty("IPAddress") ?? type.GetProperty("Host");
			if (propertyInfo != null)
			{
				text = propertyInfo.GetValue(selectedItem)?.ToString();
			}
			if (type.GetProperty("OpenPorts")?.GetValue(selectedItem) is string text2 && !string.IsNullOrEmpty(text2))
			{
				list = text2.Split(',', StringSplitOptions.RemoveEmptyEntries).Select(int.Parse).ToList();
			}
			else
			{
				PropertyInfo propertyInfo2 = type.GetProperty("Port") ?? type.GetProperty("PortNumber");
				if (propertyInfo2 != null)
				{
					object value = propertyInfo2.GetValue(selectedItem);
					if (value != null)
					{
						list.Add(Convert.ToInt32(value));
					}
				}
			}
			if (string.IsNullOrEmpty(text))
			{
				MessageBox.Show("无法获取目标 IP", "提示", MessageBoxButton.OK, MessageBoxImage.Exclamation);
				return;
			}
			string value2 = ((list.Count > 0) ? string.Join(",", list) : "默认");
			if (MessageBox.Show($"将使用所有适用插件重新扫描 {text} (端口: {value2})，是否继续？", "插件深挖", MessageBoxButton.YesNo, MessageBoxImage.Question) == MessageBoxResult.Yes)
			{
				Mouse.OverrideCursor = Cursors.Wait;
				List<VulnerabilityResult> list2 = await PluginOrchestrator.Instance.ScanTargetAsync(text, list, (IEnumerable<string>)null, default(CancellationToken), (string)null);
				Mouse.OverrideCursor = null;
				MessageBox.Show($"深挖完成：发现 {list2.Count} 个漏洞", "完成", MessageBoxButton.OK, MessageBoxImage.Asterisk);
			}
		}
		catch (Exception ex)
		{
			Mouse.OverrideCursor = null;
			MessageBox.Show("深挖失败: " + ex.Message, "错误", MessageBoxButton.OK, MessageBoxImage.Hand);
		}
	}

	private static T? FindVisualParent<T>(DependencyObject child) where T : DependencyObject
	{
		DependencyObject parent = VisualTreeHelper.GetParent(child);
		while (parent != null && !(parent is T))
		{
			parent = VisualTreeHelper.GetParent(parent);
		}
		return (T)(object)((parent is T) ? parent : null);
	}

	private void ExportVulnerabilitiesToFile(List<VulnerabilityResult> results, string dialogTitle, string defaultFileName)
	{
		SaveFileDialog saveFileDialog = new SaveFileDialog
		{
			Filter = "CSV文件|*.csv|文本文件|*.txt|所有文件|*.*",
			Title = dialogTitle,
			FileName = $"{defaultFileName}_{DateTime.Now:yyyyMMdd_HHmmss}"
		};
		if (saveFileDialog.ShowDialog() != true)
		{
			return;
		}
		try
		{
			if (Path.GetExtension(saveFileDialog.FileName).ToLower() == ".csv")
			{
				StringBuilder stringBuilder = new StringBuilder();
				stringBuilder.AppendLine("序号,漏洞名称,风险等级,端口,服务,CVE编号,检测方法,描述,解决方案,参考链接");
				foreach (VulnerabilityResult result in results)
				{
					StringBuilder stringBuilder2 = stringBuilder;
					StringBuilder stringBuilder3 = stringBuilder2;
					StringBuilder.AppendInterpolatedStringHandler handler = new StringBuilder.AppendInterpolatedStringHandler(25, 10, stringBuilder2);
					handler.AppendFormatted(result.Id);
					handler.AppendLiteral(",\"");
					handler.AppendFormatted(result.Name);
					handler.AppendLiteral("\",\"");
					handler.AppendFormatted(result.RiskLevel);
					handler.AppendLiteral("\",");
					handler.AppendFormatted(result.Port);
					handler.AppendLiteral(",\"");
					handler.AppendFormatted(result.Service);
					handler.AppendLiteral("\",\"");
					handler.AppendFormatted(result.CveId);
					handler.AppendLiteral("\",\"");
					handler.AppendFormatted(result.DetectionMethod);
					handler.AppendLiteral("\",\"");
					handler.AppendFormatted(result.Description);
					handler.AppendLiteral("\",\"");
					handler.AppendFormatted(result.Solution);
					handler.AppendLiteral("\",\"");
					handler.AppendFormatted(result.References);
					handler.AppendLiteral("\"");
					stringBuilder3.AppendLine(ref handler);
				}
				File.WriteAllText(saveFileDialog.FileName, stringBuilder.ToString(), Encoding.UTF8);
			}
			else
			{
				StringBuilder stringBuilder4 = new StringBuilder();
				StringBuilder stringBuilder2 = stringBuilder4;
				StringBuilder stringBuilder5 = stringBuilder2;
				StringBuilder.AppendInterpolatedStringHandler handler = new StringBuilder.AppendInterpolatedStringHandler(11, 1, stringBuilder2);
				handler.AppendLiteral("漏洞扫描结果报告 - ");
				handler.AppendFormatted(DateTime.Now, "yyyy-MM-dd HH:mm:ss");
				stringBuilder5.AppendLine(ref handler);
				stringBuilder4.AppendLine(new string('=', 80));
				stringBuilder4.AppendLine();
				foreach (VulnerabilityResult result2 in results)
				{
					stringBuilder2 = stringBuilder4;
					StringBuilder stringBuilder6 = stringBuilder2;
					handler = new StringBuilder.AppendInterpolatedStringHandler(5, 1, stringBuilder2);
					handler.AppendLiteral("【漏洞 ");
					handler.AppendFormatted(result2.Id);
					handler.AppendLiteral("】");
					stringBuilder6.AppendLine(ref handler);
					stringBuilder2 = stringBuilder4;
					StringBuilder stringBuilder7 = stringBuilder2;
					handler = new StringBuilder.AppendInterpolatedStringHandler(6, 1, stringBuilder2);
					handler.AppendLiteral("漏洞名称: ");
					handler.AppendFormatted(result2.Name);
					stringBuilder7.AppendLine(ref handler);
					stringBuilder2 = stringBuilder4;
					StringBuilder stringBuilder8 = stringBuilder2;
					handler = new StringBuilder.AppendInterpolatedStringHandler(6, 1, stringBuilder2);
					handler.AppendLiteral("风险等级: ");
					handler.AppendFormatted(result2.RiskLevel);
					stringBuilder8.AppendLine(ref handler);
					stringBuilder2 = stringBuilder4;
					StringBuilder stringBuilder9 = stringBuilder2;
					handler = new StringBuilder.AppendInterpolatedStringHandler(4, 1, stringBuilder2);
					handler.AppendLiteral("端口: ");
					handler.AppendFormatted(result2.Port);
					stringBuilder9.AppendLine(ref handler);
					stringBuilder2 = stringBuilder4;
					StringBuilder stringBuilder10 = stringBuilder2;
					handler = new StringBuilder.AppendInterpolatedStringHandler(4, 1, stringBuilder2);
					handler.AppendLiteral("服务: ");
					handler.AppendFormatted(result2.Service);
					stringBuilder10.AppendLine(ref handler);
					stringBuilder2 = stringBuilder4;
					StringBuilder stringBuilder11 = stringBuilder2;
					handler = new StringBuilder.AppendInterpolatedStringHandler(7, 1, stringBuilder2);
					handler.AppendLiteral("CVE编号: ");
					handler.AppendFormatted(result2.CveId);
					stringBuilder11.AppendLine(ref handler);
					stringBuilder2 = stringBuilder4;
					StringBuilder stringBuilder12 = stringBuilder2;
					handler = new StringBuilder.AppendInterpolatedStringHandler(6, 1, stringBuilder2);
					handler.AppendLiteral("检测方法: ");
					handler.AppendFormatted(result2.DetectionMethod);
					stringBuilder12.AppendLine(ref handler);
					stringBuilder2 = stringBuilder4;
					StringBuilder stringBuilder13 = stringBuilder2;
					handler = new StringBuilder.AppendInterpolatedStringHandler(4, 1, stringBuilder2);
					handler.AppendLiteral("描述: ");
					handler.AppendFormatted(result2.Description);
					stringBuilder13.AppendLine(ref handler);
					stringBuilder2 = stringBuilder4;
					StringBuilder stringBuilder14 = stringBuilder2;
					handler = new StringBuilder.AppendInterpolatedStringHandler(6, 1, stringBuilder2);
					handler.AppendLiteral("解决方案: ");
					handler.AppendFormatted(result2.Solution);
					stringBuilder14.AppendLine(ref handler);
					stringBuilder2 = stringBuilder4;
					StringBuilder stringBuilder15 = stringBuilder2;
					handler = new StringBuilder.AppendInterpolatedStringHandler(6, 1, stringBuilder2);
					handler.AppendLiteral("参考链接: ");
					handler.AppendFormatted(result2.References);
					stringBuilder15.AppendLine(ref handler);
					stringBuilder4.AppendLine(new string('-', 80));
					stringBuilder4.AppendLine();
				}
				File.WriteAllText(saveFileDialog.FileName, stringBuilder4.ToString(), Encoding.UTF8);
			}
			MessageBox.Show("漏洞数据已成功导出到: " + saveFileDialog.FileName, "导出成功", MessageBoxButton.OK, MessageBoxImage.Asterisk);
		}
		catch (Exception ex)
		{
			Log("导出文件时发生错误: " + ex.Message);
			MessageBox.Show("导出文件时发生错误: " + ex.Message, "导出失败", MessageBoxButton.OK, MessageBoxImage.Hand);
		}
	}

	public List<PortScanResult> GetPortScanResults()
	{
		return _portScanResults?.ToList() ?? new List<PortScanResult>();
	}

	public List<VulnerabilityResult> GetVulnerabilityResults()
	{
		return _vulnerabilityResults?.ToList() ?? new List<VulnerabilityResult>();
	}

	private void AIRiskAssessment_Click(object sender, RoutedEventArgs e)
	{
		try
		{
			if (_portScanResults == null || !_portScanResults.Any())
			{
				MessageBox.Show("请先执行端口扫描或漏洞扫描，然后再进行 AI 风险评估。", "提示", MessageBoxButton.OK, MessageBoxImage.Asterisk);
				return;
			}
			object obj2;
			if (string.IsNullOrWhiteSpace(TargetIpTextBox.Text))
			{
				PortScanResult? obj = _portScanResults.FirstOrDefault();
				obj2 = ((obj != null) ? obj.TargetIp : null) ?? "Unknown";
			}
			else
			{
				obj2 = TargetIpTextBox.Text.Trim();
			}
			string text = (string)obj2;
			MessageBox.Show("正在对目标 IP: " + text + " 进行 AI 风险评估...", "AI 风险评估", MessageBoxButton.OK, MessageBoxImage.Asterisk);
			List<PortScanResult> portScanResults = _portScanResults.ToList();
			List<VulnerabilityResult> vulnerabilityResults = _vulnerabilityResults?.ToList() ?? new List<VulnerabilityResult>();
			new AIRiskAssessmentWindow(portScanResults, vulnerabilityResults, this).ShowDialog();
		}
		catch (Exception ex)
		{
			Log("打开 AI 风险评估窗口失败：" + ex.Message);
			MessageBox.Show("打开 AI 风险评估窗口失败：" + ex.Message, "错误", MessageBoxButton.OK, MessageBoxImage.Hand);
		}
	}

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
			new BatchScanWindow().ShowDialog();
		}
		catch (Exception ex)
		{
			MessageBox.Show("打开批量扫描窗口失败：" + ex.Message, "错误", MessageBoxButton.OK, MessageBoxImage.Hand);
		}
	}

	private void ExpertMode_Click(object sender, RoutedEventArgs e)
	{
		try
		{
			new ExpertModeWindow().ShowDialog();
		}
		catch (Exception ex)
		{
			MessageBox.Show($"打开专家模式失败：{ex.Message}\n\n{ex.InnerException?.Message}\n\n{ex.StackTrace}", "错误", MessageBoxButton.OK, MessageBoxImage.Hand);
		}
	}

	private void AppScan_Click(object sender, RoutedEventArgs e)
	{
		try
		{
			AppScannerWindow appScannerWindow = new AppScannerWindow();
			appScannerWindow.Owner = this;
			appScannerWindow.Show();
		}
		catch (Exception ex)
		{
			MessageBox.Show("打开APP扫描窗口失败：" + ex.Message, "错误", MessageBoxButton.OK, MessageBoxImage.Hand);
		}
	}

	private void AgentSecurityScan_Click(object sender, RoutedEventArgs e)
	{
		try
		{
			AgentSecurityScannerWindow agentSecurityScannerWindow = new AgentSecurityScannerWindow();
			agentSecurityScannerWindow.Owner = this;
			agentSecurityScannerWindow.Show();
		}
		catch (Exception ex)
		{
			MessageBox.Show("打开Agent安全扫描窗口失败：" + ex.Message, "错误", MessageBoxButton.OK, MessageBoxImage.Hand);
		}
	}

	private void CameraSecurityScan_Click(object sender, RoutedEventArgs e)
	{
		try
		{
			CameraSecurityScannerWindow cameraSecurityScannerWindow = new CameraSecurityScannerWindow();
			cameraSecurityScannerWindow.Owner = this;
			cameraSecurityScannerWindow.Show();
		}
		catch (Exception ex)
		{
			MessageBox.Show("打开摄像头安全扫描窗口失败：" + ex.Message, "错误", MessageBoxButton.OK, MessageBoxImage.Hand);
		}
	}

	private void StatisticsDashboard_Click(object sender, RoutedEventArgs e)
	{
		try
		{
			new StatisticsDashboardWindow().ShowDialog();
		}
		catch (Exception ex)
		{
			MessageBox.Show("打开统计仪表板失败：" + ex.Message, "错误", MessageBoxButton.OK, MessageBoxImage.Hand);
		}
	}

	private void Visualization_Click(object sender, RoutedEventArgs e)
	{
		try
		{
			new ScanVisualizationWindow().ShowDialog();
		}
		catch (Exception ex)
		{
			MessageBox.Show("打开可视化图表失败：" + ex.Message, "错误", MessageBoxButton.OK, MessageBoxImage.Hand);
		}
	}

	private void NetworkTopology_Click(object sender, RoutedEventArgs e)
	{
		try
		{
			new NetworkTopologyWindow().ShowDialog();
		}
		catch (Exception ex)
		{
			MessageBox.Show("打开网络拓扑失败：" + ex.Message, "错误", MessageBoxButton.OK, MessageBoxImage.Hand);
		}
	}

	private void ViewAttackPaths_Click(object sender, RoutedEventArgs e)
	{
		try
		{
			if (_portScanResults == null && _vulnerabilityResults == null)
			{
				MessageBox.Show("请先执行端口扫描或漏洞扫描，然后再进行攻击路径分析。", "提示", MessageBoxButton.OK, MessageBoxImage.Asterisk);
				return;
			}
			List<PortScanResult> list = _portScanResults?.Where((PortScanResult p) => p.Status == "开放" || p.Status == "开放或过滤").ToList() ?? new List<PortScanResult>();
			List<VulnerabilityResult> list2 = _vulnerabilityResults?.ToList() ?? new List<VulnerabilityResult>();
			AttackPathAnalysisWindow attackPathAnalysisWindow = new AttackPathAnalysisWindow(_riskAssessmentService.GenerateAttackPathsForAnalysis(list2, list));
			attackPathAnalysisWindow.Owner = this;
			attackPathAnalysisWindow.ShowDialog();
		}
		catch (Exception ex)
		{
			MessageBox.Show("打开攻击路径分析窗口失败：" + ex.Message, "错误", MessageBoxButton.OK, MessageBoxImage.Hand);
		}
	}

	private void AttackLogQuery_Click(object sender, RoutedEventArgs e)
	{
		try
		{
			AttackLogWindow attackLogWindow = new AttackLogWindow();
			attackLogWindow.Owner = this;
			attackLogWindow.ShowDialog();
		}
		catch (Exception ex)
		{
			MessageBox.Show("打开攻击日志查询窗口失败：" + ex.Message, "错误", MessageBoxButton.OK, MessageBoxImage.Hand);
		}
	}

	private void ComplianceCheck_Click(object sender, RoutedEventArgs e)
	{
		try
		{
			new ComplianceCheckWindow().ShowDialog();
		}
		catch (Exception ex)
		{
			MessageBox.Show("打开合规检查窗口失败：" + ex.Message, "错误", MessageBoxButton.OK, MessageBoxImage.Hand);
		}
	}

	private void VulnerabilityKnowledgeBase_Click(object sender, RoutedEventArgs e)
	{
		try
		{
			VulnerabilityKnowledgeBaseWindow vulnerabilityKnowledgeBaseWindow = new VulnerabilityKnowledgeBaseWindow();
			vulnerabilityKnowledgeBaseWindow.Owner = this;
			vulnerabilityKnowledgeBaseWindow.ShowDialog();
		}
		catch (Exception ex)
		{
			MessageBox.Show("打开漏洞知识库窗口失败: " + ex.Message, "错误", MessageBoxButton.OK, MessageBoxImage.Hand);
		}
	}

	private void WebPathTracer_Click(object sender, RoutedEventArgs e)
	{
		try
		{
			WebPathTracerWindow webPathTracerWindow = new WebPathTracerWindow();
			webPathTracerWindow.Owner = this;
			webPathTracerWindow.Show();
		}
		catch (Exception ex)
		{
			MessageBox.Show("打开网页路径追踪窗口失败: " + ex.Message, "错误", MessageBoxButton.OK, MessageBoxImage.Hand);
		}
	}

	private void PluginManager_Click(object sender, RoutedEventArgs e)
	{
		try
		{
			PluginManagerWindow pluginManagerWindow = new PluginManagerWindow();
			pluginManagerWindow.Owner = this;
			pluginManagerWindow.ShowDialog();
		}
		catch (Exception ex)
		{
			MessageBox.Show("打开插件管理窗口失败: " + ex.Message, "错误", MessageBoxButton.OK, MessageBoxImage.Hand);
		}
	}

	private void AssetManagement_Click(object sender, RoutedEventArgs e)
	{
		try
		{
			if (SessionContext.Instance.Current != null || new LoginWindow
			{
				Owner = this
			}.ShowDialog() == true)
			{
				User current = SessionContext.Instance.Current;
				if (current == null || (!current.IsAdmin && (current.Permissions == null || !current.Permissions.Contains("Asset:View"))))
				{
					MessageBox.Show("无资产管理查看权限", "权限不足", MessageBoxButton.OK, MessageBoxImage.Exclamation);
					return;
				}
				AssetManagementWindow assetManagementWindow = new AssetManagementWindow();
				assetManagementWindow.Owner = this;
				assetManagementWindow.ShowDialog();
			}
		}
		catch (Exception ex)
		{
			MessageBox.Show("打开资产管理窗口失败: " + ex.Message, "错误", MessageBoxButton.OK, MessageBoxImage.Hand);
		}
	}

	[DebuggerNonUserCode]
	[GeneratedCode("PresentationBuildTasks", "6.0.36.0")]
	public void InitializeComponent()
	{
		if (!_contentLoaded)
		{
			_contentLoaded = true;
			Uri resourceLocator = new Uri("/NetSecurityScanner.Desktop;V1.0.1.5;component/mainwindow.xaml", UriKind.Relative);
			Application.LoadComponent(this, resourceLocator);
		}
	}

	[DebuggerNonUserCode]
	[GeneratedCode("PresentationBuildTasks", "6.0.36.0")]
	[EditorBrowsable(EditorBrowsableState.Never)]
	void IComponentConnector.Connect(int connectionId, object target)
	{
		//IL_0789: Unknown result type (might be due to invalid IL or missing references)
		//IL_0793: Expected O, but got Unknown
		//IL_0796: Unknown result type (might be due to invalid IL or missing references)
		//IL_07a0: Expected O, but got Unknown
		switch (connectionId)
		{
		case 1:
			((MainWindow)target).Closing += Window_Closing;
			break;
		case 2:
			((MenuItem)target).Click += ExportReport_Click;
			break;
		case 3:
			((MenuItem)target).Click += Exit_Click;
			break;
		case 4:
			((MenuItem)target).Click += PortScan_Click;
			break;
		case 5:
			((MenuItem)target).Click += VulnerabilityScan_Click;
			break;
		case 6:
			((MenuItem)target).Click += BatchScan_Click;
			break;
		case 7:
			((MenuItem)target).Click += AppScan_Click;
			break;
		case 8:
			((MenuItem)target).Click += AgentSecurityScan_Click;
			break;
		case 9:
			((MenuItem)target).Click += CameraSecurityScan_Click;
			break;
		case 10:
			((MenuItem)target).Click += StartScan_Click;
			break;
		case 11:
			PluginScanMenuItem = (MenuItem)target;
			PluginScanMenuItem.Click += PluginScanButton_Click;
			break;
		case 12:
			((MenuItem)target).Click += StopScan_Click;
			break;
		case 13:
			((MenuItem)target).Click += ExpertMode_Click;
			break;
		case 14:
			((MenuItem)target).Click += AIRiskAssessment_Click;
			break;
		case 15:
			((MenuItem)target).Click += StatisticsDashboard_Click;
			break;
		case 16:
			((MenuItem)target).Click += Visualization_Click;
			break;
		case 17:
			((MenuItem)target).Click += NetworkTopology_Click;
			break;
		case 18:
			((MenuItem)target).Click += ViewAttackPaths_Click;
			break;
		case 19:
			((MenuItem)target).Click += AttackLogQuery_Click;
			break;
		case 20:
			((MenuItem)target).Click += GenerateBat_Click;
			break;
		case 21:
			((MenuItem)target).Click += UpdateVulnerabilityDatabase_Click;
			break;
		case 22:
			((MenuItem)target).Click += ComplianceCheck_Click;
			break;
		case 23:
			((MenuItem)target).Click += VulnerabilityKnowledgeBase_Click;
			break;
		case 24:
			((MenuItem)target).Click += WebPathTracer_Click;
			break;
		case 25:
			((MenuItem)target).Click += PluginManager_Click;
			break;
		case 26:
			((MenuItem)target).Click += AssetManagement_Click;
			break;
		case 27:
			((MenuItem)target).Click += LicenseManager_Click;
			break;
		case 28:
			((MenuItem)target).Click += CheckForUpdates_Click;
			break;
		case 29:
			((MenuItem)target).Click += About_Click;
			break;
		case 30:
			MainTabControl = (TabControl)target;
			break;
		case 31:
			TargetIpTextBox = (TextBox)target;
			break;
		case 32:
			PortRangeTextBox = (TextBox)target;
			break;
		case 33:
			ScanTypeComboBox = (ComboBox)target;
			break;
		case 34:
			StartPortScanButton = (Button)target;
			StartPortScanButton.Click += StartPortScan_Click;
			break;
		case 35:
			StopPortScanButton = (Button)target;
			StopPortScanButton.Click += StopScan_Click;
			break;
		case 36:
			AutoScanCheckBox = (CheckBox)target;
			break;
		case 37:
			PortScanResultsDataGrid = (DataGrid)target;
			PortScanResultsDataGrid.SelectionChanged += PortScanResultsDataGrid_SelectionChanged;
			break;
		case 38:
			((Button)target).Click += SelectAllPorts_Click;
			break;
		case 39:
			((Button)target).Click += UnselectAllPorts_Click;
			break;
		case 40:
			GeneratePortBatButton = (Button)target;
			GeneratePortBatButton.Click += GeneratePortBat_Click;
			break;
		case 41:
			ScanProgressText = (TextBlock)target;
			break;
		case 42:
			ScanProgressBar = (ProgressBar)target;
			break;
		case 43:
			VulnTargetTextBox = (TextBox)target;
			break;
		case 44:
			StartVulnScanButton = (Button)target;
			StartVulnScanButton.Click += StartVulnScan_Click;
			break;
		case 45:
			StopVulnScanButton = (Button)target;
			StopVulnScanButton.Click += StopScan_Click;
			break;
		case 46:
			VulnScanProgressText = (TextBlock)target;
			break;
		case 47:
			VulnScanProgressPercent = (TextBlock)target;
			break;
		case 48:
			VulnScanProgressBar = (ProgressBar)target;
			break;
		case 49:
			VulnScanCurrentStage = (TextBlock)target;
			break;
		case 50:
			VulnerabilityResultsDataGrid = (DataGrid)target;
			break;
		case 51:
			((MenuItem)target).Click += DeepScanMenuItem_Click;
			break;
		case 52:
			((MenuItem)target).Click += CopyVulnerabilityDetails_Click;
			break;
		case 53:
			((MenuItem)target).Click += ExportSelectedVulnerabilities_Click;
			break;
		case 54:
			((MenuItem)target).Click += ViewCveDetails_Click;
			break;
		case 55:
			((MenuItem)target).Click += CopyCveId_Click;
			break;
		case 56:
			((MenuItem)target).Click += MarkAsResolved_Click;
			break;
		case 57:
			((MenuItem)target).Click += AddRemark_Click;
			break;
		case 58:
			AssessmentDateText = (TextBlock)target;
			break;
		case 59:
			AiAnalysisProgressBar = (ProgressBar)target;
			break;
		case 60:
			AiAnalysisStatusText = (TextBlock)target;
			break;
		case 61:
			RefreshAiAnalysisButton = (Button)target;
			RefreshAiAnalysisButton.Click += RefreshAiAnalysis_Click;
			break;
		case 62:
			AiAnalysisSubStatusText = (TextBlock)target;
			break;
		case 63:
			OverallRiskText = (TextBlock)target;
			break;
		case 64:
			RiskScoreText = (TextBlock)target;
			break;
		case 65:
			RiskProgressBar = (Border)target;
			break;
		case 66:
			TargetIpText = (TextBlock)target;
			break;
		case 67:
			AssessmentTimeText = (TextBlock)target;
			break;
		case 68:
			TotalVulnerabilitiesText = (TextBlock)target;
			break;
		case 69:
			HighRiskCountText = (TextBlock)target;
			break;
		case 70:
			OpenPortsCountText = (TextBlock)target;
			break;
		case 71:
			SensitivePortsText = (TextBlock)target;
			break;
		case 72:
			RiskDistributionPieChart = (PieChart)target;
			break;
		case 73:
			RiskDistributionBarChart = (CartesianChart)target;
			break;
		case 74:
			VulnerabilityDetailsDataGrid = (DataGrid)target;
			break;
		case 75:
			GeneratePortBatFromAiButton = (Button)target;
			GeneratePortBatFromAiButton.Click += GeneratePortBatFromAi_Click;
			break;
		case 76:
			OpenPortsDataGrid = (DataGrid)target;
			OpenPortsDataGrid.SelectionChanged += OpenPortsDataGrid_SelectionChanged;
			break;
		case 77:
			SecurityAdviceText = (TextBlock)target;
			break;
		case 78:
			RiskAssessmentSummaryText = (TextBlock)target;
			break;
		case 79:
			SearchTextBox = (TextBox)target;
			SearchTextBox.TextChanged += SearchTextBox_TextChanged;
			break;
		case 80:
			((Button)target).Click += SearchScanHistory_Click;
			break;
		case 81:
			((Button)target).Click += RefreshScanHistory_Click;
			break;
		case 82:
			((Button)target).Click += ClearScanHistory_Click;
			break;
		case 83:
			RiskLevelFilterComboBox = (ComboBox)target;
			RiskLevelFilterComboBox.SelectionChanged += RiskLevelFilterComboBox_SelectionChanged;
			break;
		case 84:
			ScanTypeFilterComboBox = (ComboBox)target;
			ScanTypeFilterComboBox.SelectionChanged += ScanTypeFilterComboBox_SelectionChanged;
			break;
		case 85:
			((Button)target).Click += ResetFilters_Click;
			break;
		case 86:
			GenerateReportFromHistoryButton = (Button)target;
			GenerateReportFromHistoryButton.Click += GenerateReportFromHistory_Click;
			break;
		case 87:
			ScanHistoryDataGrid = (DataGrid)target;
			ScanHistoryDataGrid.MouseDoubleClick += ScanHistoryDataGrid_MouseDoubleClick;
			break;
		case 90:
			ScanHistoryStats = (TextBlock)target;
			break;
		case 91:
			ScanHistorySummary = (TextBlock)target;
			break;
		case 92:
			LicenseStatusBarText = (TextBlock)target;
			break;
		case 93:
			StatusTextBlock = (TextBlock)target;
			break;
		case 94:
			SystemUptimeText = (TextBlock)target;
			break;
		case 95:
			CpuUsageTextBlock = (TextBlock)target;
			break;
		case 96:
			RamUsageTextBlock = (TextBlock)target;
			break;
		case 97:
			DiskUsageTextBlock = (TextBlock)target;
			break;
		case 98:
			NetworkConnectionsTextBlock = (TextBlock)target;
			break;
		case 99:
			SystemHealthText = (TextBlock)target;
			break;
		case 100:
			StatusVersionText = (TextBlock)target;
			break;
		default:
			_contentLoaded = true;
			break;
		}
	}

	[DebuggerNonUserCode]
	[GeneratedCode("PresentationBuildTasks", "6.0.36.0")]
	[EditorBrowsable(EditorBrowsableState.Never)]
	void IStyleConnector.Connect(int connectionId, object target)
	{
		switch (connectionId)
		{
		case 88:
			((Button)target).Click += ViewScanHistory_Click;
			break;
		case 89:
			((Button)target).Click += DeleteScanHistory_Click;
			break;
		}
	}
}
