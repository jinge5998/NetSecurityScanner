using Microsoft.Win32;
using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Threading;
using NetSecurityScanner.Models;
using NetSecurityScanner.Services;

namespace NetSecurityScanner.Views
{
    public partial class AgentSecurityScannerWindow : Window
    {
        private AgentScanResult? _currentResult;
        private AgentScanOptions _options = new();
        private CancellationTokenSource? _cts;
        private DateTime _scanStartTime;
        private DispatcherTimer? _elapsedTimer;

        // 数据集合（用于DataGrid/ListBox绑定）
        private ObservableCollection<StaticAnalysisItem> _staticAnalysisItems = new();
        private ObservableCollection<BehaviorVulnItem> _behaviorItems = new();
        private ObservableCollection<TopIssueItem> _topIssues = new();

        public AgentSecurityScannerWindow()
        {
            InitializeComponent();

            // 初始化DataGrid数据源
            StaticAnalysisDataGrid.ItemsSource = _staticAnalysisItems;
            BehaviorDataGrid.ItemsSource = _behaviorItems;
            TopIssuesListBox.ItemsSource = _topIssues;

            // 初始化计时器用于显示扫描用时
            _elapsedTimer = new DispatcherTimer
            {
                Interval = TimeSpan.FromSeconds(1)
            };
            _elapsedTimer.Tick += ElapsedTimer_Tick;
        }

        #region 目标模式切换事件

        private void TargetModeChanged(object sender, RoutedEventArgs e)
        {
            var mode = GetTargetMode();
            TargetPathTextBox.Clear();
            TargetPathTextBox.Foreground = Brushes.Gray;

            switch (mode)
            {
                case "File":
                    TargetPathTextBox.Text = "请选择或拖拽文件...";
                    TargetPathTextBox.AcceptsReturn = false;
                    TargetPathTextBox.TextWrapping = TextWrapping.NoWrap;
                    break;
                case "Directory":
                    TargetPathTextBox.Text = "请选择目录路径...";
                    TargetPathTextBox.AcceptsReturn = false;
                    TargetPathTextBox.TextWrapping = TextWrapping.NoWrap;
                    break;
                case "Config":
                    TargetPathTextBox.Text = "请导入配置文件...";
                    TargetPathTextBox.AcceptsReturn = false;
                    TargetPathTextBox.TextWrapping = TextWrapping.NoWrap;
                    break;
                case "Text":
                    TargetPathTextBox.Text = "请粘贴Agent代码或提示词内容...";
                    TargetPathTextBox.AcceptsReturn = true;
                    TargetPathTextBox.TextWrapping = TextWrapping.Wrap;
                    break;
            }
        }

        private string GetTargetMode()
        {
            if (FileModeRadio.IsChecked == true) return "File";
            if (DirectoryModeRadio.IsChecked == true) return "Directory";
            if (ConfigModeRadio.IsChecked == true) return "Config";
            return "Text";
        }

        #endregion

        #region 文本框焦点事件

        private void TargetPathTextBox_GotFocus(object sender, RoutedEventArgs e)
        {
            if (TargetPathTextBox.Foreground == Brushes.Gray)
            {
                TargetPathTextBox.Clear();
                TargetPathTextBox.Foreground = Brushes.Black;
            }
        }

        private void TargetPathTextBox_LostFocus(object sender, RoutedEventArgs e)
        {
            if (string.IsNullOrWhiteSpace(TargetPathTextBox.Text))
            {
                TargetModeChanged(sender, e);
            }
        }

        private void SearchBox_GotFocus(object sender, RoutedEventArgs e)
        {
            var box = sender as TextBox;
            if (box?.Foreground == Brushes.Gray)
            {
                box.Clear();
                box.Foreground = Brushes.Black;
            }
        }

        private void SearchBox_LostFocus(object sender, RoutedEventArgs e)
        {
            var box = sender as TextBox;
            if (string.IsNullOrWhiteSpace(box?.Text))
            {
                box.Text = "搜索...";
                box.Foreground = Brushes.Gray;
            }
        }

        #endregion

        #region 浏览按钮

        private void Browse_Click(object sender, RoutedEventArgs e)
        {
            var mode = GetTargetMode();

            try
            {
                switch (mode)
                {
                    case "File":
                        BrowseFile();
                        break;
                    case "Directory":
                        BrowseDirectory();
                        break;
                    case "Config":
                        BrowseConfigFile();
                        break;
                    default:
                        MessageBox.Show("文本粘贴模式无需浏览文件", "提示", MessageBoxButton.OK, MessageBoxImage.Information);
                        break;
                }
            }
            catch (Exception ex)
            {
                MessageBox.Show($"浏览失败: {ex.Message}", "错误", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        private void BrowseFile()
        {
            var dialog = new OpenFileDialog
            {
                Filter = "Agent文件|*.py;*.js;*.ts;*.yaml;*.yml;*.json|Python文件|*.py|JavaScript文件|*.js;*.ts|配置文件|*.yaml;*.yml;*.json|所有文件|*.*",
                Title = "选择要扫描的Agent文件"
            };

            if (dialog.ShowDialog() == true)
            {
                TargetPathTextBox.Text = dialog.FileName;
                TargetPathTextBox.Foreground = Brushes.Black;
            }
        }

        private void BrowseDirectory()
        {
            using var dialog = new System.Windows.Forms.FolderBrowserDialog
            {
                Description = "选择要扫描的Agent目录",
                UseDescriptionForTitle = true
            };

            if (dialog.ShowDialog() == System.Windows.Forms.DialogResult.OK)
            {
                if (!string.IsNullOrEmpty(dialog.SelectedPath))
                {
                    TargetPathTextBox.Text = dialog.SelectedPath;
                    TargetPathTextBox.Foreground = Brushes.Black;
                }
            }
        }

        private void BrowseConfigFile()
        {
            var dialog = new OpenFileDialog
            {
                Filter = "配置文件|*.json;*.yaml;*.yml;*.xml|JSON文件|*.json|YAML文件|*.yaml;*.yml|XML文件|*.xml",
                Title = "选择Agent配置文件"
            };

            if (dialog.ShowDialog() == true)
            {
                TargetPathTextBox.Text = dialog.FileName;
                TargetPathTextBox.Foreground = Brushes.Black;
            }
        }

        #endregion

        #region 扫描控制

        private async void StartScan_Click(object sender, RoutedEventArgs e)
        {
            var target = TargetPathTextBox.Text.Trim();
            if (string.IsNullOrEmpty(target) || TargetPathTextBox.Foreground == Brushes.Gray)
            {
                MessageBox.Show("请先输入或选择扫描目标", "提示", MessageBoxButton.OK, MessageBoxImage.Warning);
                return;
            }

            // 验证目标有效性
            if (!ValidateTarget(target))
            {
                return;
            }

            // 准备扫描选项
            PrepareScanOptions(target);

            _cts = new CancellationTokenSource();
            _scanStartTime = DateTime.Now;

            // 更新UI状态
            SetScanningUIState(true);

            try
            {
                // 调用真实的AgentSecurityScannerService执行扫描
                await PerformScanAsync(_cts.Token);

                // 显示结果
                if (_currentResult != null)
                {
                    UpdateResultDisplay(_currentResult);
                    ScanStatusText.Text = "状态: 扫描完成";
                    ExportReportButton.IsEnabled = true;
                }
            }
            catch (OperationCanceledException)
            {
                ScanStatusText.Text = "状态: 已取消";
                CurrentPhaseText.Text = "";
            }
            catch (Exception ex)
            {
                ScanStatusText.Text = "状态: 扫描失败";
                MessageBox.Show($"扫描失败: {ex.Message}", "错误", MessageBoxButton.OK, MessageBoxImage.Error);
            }
            finally
            {
                SetScanningUIState(false);
                _elapsedTimer?.Stop();
                UpdateStatusBar();
            }
        }

        private bool ValidateTarget(string target)
        {
            var mode = GetTargetMode();

            if (mode == "Text")
            {
                if (target.Length < 10)
                {
                    MessageBox.Show("输入的内容太短，请提供有效的代码或提示词", "提示", MessageBoxButton.OK, MessageBoxImage.Warning);
                    return false;
                }
                return true;
            }

            if (mode == "File" || mode == "Config")
            {
                if (!File.Exists(target))
                {
                    MessageBox.Show("文件不存在，请检查路径是否正确", "错误", MessageBoxButton.OK, MessageBoxImage.Error);
                    return false;
                }
                return true;
            }

            if (mode == "Directory")
            {
                if (!Directory.Exists(target))
                {
                    MessageBox.Show("目录不存在，请检查路径是否正确", "错误", MessageBoxButton.OK, MessageBoxImage.Error);
                    return false;
                }
                return true;
            }

            return true;
        }

        /// <summary>
        /// 根据界面控件状态构建正式的 AgentScanOptions 对象
        /// </summary>
        private void PrepareScanOptions(string target)
        {
            _options = new AgentScanOptions
            {
                TargetPath = target,
                TargetType = ParseTargetMode(GetTargetMode()),
                EnableStaticAnalysis = StaticAnalysisCheck.IsChecked ?? true,
                EnableIntentAnalysis = IntentAnalysisCheck.IsChecked ?? true,
                EnableBehaviorSandbox = BehaviorSandboxCheck.IsChecked ?? true,
                IncludeDependencyCheck = DependencyCheck.IsChecked ?? true,
                ScanDepth = ParseScanDepth((ScanDepthComboBox.SelectedItem as ComboBoxItem)?.Content.ToString() ?? "标准扫描"),
                MaxFileSizeMB = 10.0,
                AgentTypeAutoDetect = true
            };
        }

        /// <summary>
        /// 调用真实的 AgentSecurityScannerService 执行三阶段安全扫描
        /// </summary>
        private async Task PerformScanAsync(CancellationToken token)
        {
            var service = new AgentSecurityScannerService();

            try
            {
                _currentResult = await service.ScanAsync(
                    _options,
                    new Progress<AgentSecurityScannerService.AgentScanProgressInfo>(p =>
                    {
                        Dispatcher.Invoke(() => UpdateProgressFromService(p));
                    }),
                    token);
            }
            finally
            {
                service.Dispose();
            }
        }

        /// <summary>
        /// 根据服务返回的进度信息更新UI
        /// </summary>
        private void UpdateProgressFromService(AgentSecurityScannerService.AgentScanProgressInfo progress)
        {
            ScanProgressBar.Value = Math.Min(progress.Percentage, 100);
            ScanProgressText.Text = $"{Math.Min(progress.Percentage, 100)}%";
            ScanStatusText.Text = $"状态: {progress.StatusDescription}";
            CurrentPhaseText.Text = string.IsNullOrEmpty(progress.CurrentPhase) ? "" : $"阶段: {progress.CurrentPhase}";

            // 实时更新发现数量
            TotalFoundText.Text = $"已发现: {progress.FindingsCount}";
        }

        private void StopScan_Click(object sender, RoutedEventArgs e)
        {
            _cts?.Cancel();
            StopScanButton.IsEnabled = false;
            StartScanButton.IsEnabled = true;
            ScanStatusText.Text = "状态: 正在停止...";
            CurrentPhaseText.Text = "";
        }

        private void SetScanningUIState(bool isScanning)
        {
            StartScanButton.IsEnabled = !isScanning;
            StopScanButton.IsEnabled = isScanning;
            ExportReportButton.IsEnabled = false;

            if (isScanning)
            {
                _elapsedTimer?.Start();
                ScanProgressBar.Value = 0;
                ScanProgressText.Text = "0%";
                ClearResults();
            }
        }

        private void ElapsedTimer_Tick(object? sender, EventArgs e)
        {
            var elapsed = DateTime.Now - _scanStartTime;
            StatusBarDuration.Text = $"扫描用时: {elapsed:mm\\:ss}";
        }

        #endregion

        #region 导出报告

        private void ExportReport_Click(object sender, RoutedEventArgs e)
        {
            if (_currentResult == null || _currentResult.TotalFindings == 0)
            {
                MessageBox.Show("没有可导出的扫描结果", "提示", MessageBoxButton.OK, MessageBoxImage.Information);
                return;
            }

            var dialog = new SaveFileDialog
            {
                Filter = "Word报告|*.docx|PDF报告|*.pdf|HTML报告|*.html|文本报告|*.txt",
                Title = "导出Agent安全扫描报告",
                FileName = $"Agent安全扫描报告_{DateTime.Now:yyyyMMdd_HHmmss}"
            };

            if (dialog.ShowDialog() == true)
            {
                try
                {
                    ExportFullReport(dialog.FileName);
                    MessageBox.Show("报告导出成功!", "成功", MessageBoxButton.OK, MessageBoxImage.Information);
                    StatusBarLastUpdate.Text = $"最后更新: {DateTime.Now:HH:mm:ss}";
                }
                catch (Exception ex)
                {
                    MessageBox.Show($"导出报告失败: {ex.Message}", "错误", MessageBoxButton.OK, MessageBoxImage.Error);
                }
            }
        }

        private void ExportFullReport(string filePath)
        {
            var sb = new StringBuilder();
            sb.AppendLine("==============================================");
            sb.AppendLine("       Agent 安全扫描报告");
            sb.AppendLine("==============================================");
            sb.AppendLine();
            sb.AppendLine($"扫描时间: {_currentResult!.StartTime:yyyy-MM-dd HH:mm:ss}");
            sb.AppendLine($"目标路径: {_currentResult.TargetPath}");
            sb.AppendLine($"Agent类型: {_currentResult.AgentType}");
            sb.AppendLine($"扫描深度: {_options.ScanDepth}");

            var duration = TimeSpan.FromMilliseconds(_currentResult.DurationMs);
            sb.AppendLine($"总耗时: {duration:mm\\:ss}");
            sb.AppendLine();
            sb.AppendLine("----------------------------------------------");
            sb.AppendLine("漏洞统计:");
            sb.AppendLine($"  总计: {_currentResult.TotalFindings}");
            sb.AppendLine($"  超危(Critical): {_currentResult.CriticalCount}");
            sb.AppendLine($"  高危(High): {_currentResult.HighCount}");
            sb.AppendLine($"  中危(Medium): {_currentResult.MediumCount}");
            sb.AppendLine($"  低危(Low): {_currentResult.LowCount}");
            sb.AppendLine($"  信息(Info): {_currentResult.InfoCount}");
            sb.AppendLine($"  安全评分: {_currentResult.Score}/100");
            sb.AppendLine("----------------------------------------------");
            sb.AppendLine();

            // 写入各Tab详细数据
            sb.AppendLine("[静态分析结果]");
            foreach (var item in _staticAnalysisItems)
            {
                sb.AppendLine($"  - [{item.RiskLevel}] {item.FileLocation}:{item.LineNumber} - {item.Category}");
            }
            sb.AppendLine();

            File.WriteAllText(filePath, sb.ToString(), Encoding.UTF8);
        }

        private void ExportRemediationList_Click(object sender, RoutedEventArgs e)
        {
            var dialog = new SaveFileDialog
            {
                Filter = "Markdown文件|*.md|文本文件|*.txt|CSV文件|*.csv",
                Title = "导出修复清单",
                FileName = $"Agent修复清单_{DateTime.Now:yyyyMMdd}"
            };

            if (dialog.ShowDialog() == true)
            {
                try
                {
                    // 使用正式模型数据生成修复清单
                    if (_currentResult != null && _currentResult.AllVulnerabilities.Count > 0)
                    {
                        var sb = new StringBuilder();
                        sb.AppendLine("# Agent 安全修复清单");
                        sb.AppendLine($"生成时间: {DateTime.Now:yyyy-MM-dd HH:mm:ss}");
                        sb.AppendLine($"扫描目标: {_currentResult.TargetPath}");
                        sb.AppendLine();
                        foreach (var vuln in _currentResult.AllVulnerabilities.OrderByDescending(v => v.RiskLevel))
                        {
                            sb.AppendLine($"## [{vuln.RiskLevel}] {vuln.Title}");
                            sb.AppendLine($"- **分类**: {vuln.Category}");
                            sb.AppendLine($"- **位置**: {vuln.FileLocation}" + (vuln.LineNumber.HasValue ? $":{vuln.LineNumber}" : ""));
                            sb.AppendLine($"- **置信度**: {(vuln.Confidence * 100):F0}%");
                            if (!string.IsNullOrEmpty(vuln.CveId)) sb.AppendLine($"- **CVE**: {vuln.CveId}");
                            if (vuln.CvssScore.HasValue) sb.AppendLine($"- **CVSS**: {vuln.CvssScore:F1}");
                            sb.AppendLine($"- **修复建议**: {vuln.Remediation}");
                            sb.AppendLine();
                        }
                        File.WriteAllText(dialog.FileName, sb.ToString(), Encoding.UTF8);
                    }
                    MessageBox.Show("修复清单导出成功!", "成功", MessageBoxButton.OK, MessageBoxImage.Information);
                }
                catch (Exception ex)
                {
                    MessageBox.Show($"导出失败: {ex.Message}", "错误", MessageBoxButton.OK, MessageBoxImage.Error);
                }
            }
        }

        #endregion

        #region Tab切换与结果显示

        private void ResultTab_SelectionChanged(object sender, SelectionChangedEventArgs e)
        {
            if (_currentResult == null) return;

            var tab = ResultTab.SelectedIndex;
            switch (tab)
            {
                case 0:
                    UpdateDashboard(_currentResult);
                    break;
                case 1:
                    UpdateStaticAnalysisTab(_currentResult.GetVulnerabilitiesByPhase(AgentScanPhase.StaticAnalysis));
                    break;
                case 2:
                    UpdateIntentAnalysisTab(_currentResult.GetVulnerabilitiesByPhase(AgentScanPhase.IntentAnalysis));
                    break;
                case 3:
                    UpdateBehaviorSandboxTab(_currentResult.GetVulnerabilitiesByPhase(AgentScanPhase.BehaviorSandbox));
                    break;
                case 4:
                    UpdateRemediationTab(_currentResult.AllVulnerabilities.ToList());
                    break;
            }
        }

        /// <summary>
        /// 更新结果展示区域 —— 使用正式模型的属性
        /// </summary>
        private void UpdateResultDisplay(AgentScanResult result)
        {
            // 更新进度条区域统计
            TotalFoundText.Text = $"已发现: {result.TotalFindings}";
            CriticalCountText.Text = result.CriticalCount.ToString();
            HighCountText.Text = result.HighCount.ToString();
            MediumCountText.Text = result.MediumCount.ToString();
            LowCountText.Text = result.LowCount.ToString();

            // 更新当前选中的Tab
            ResultTab_SelectionChanged(null, null);
        }

        private void ClearResults()
        {
            _staticAnalysisItems.Clear();
            _behaviorItems.Clear();
            _topIssues.Clear();
            IntentCardsPanel.Children.Clear();
            RemediationListPanel.Children.Clear();

            TotalFoundText.Text = "已发现: 0";
            CriticalCountText.Text = "0";
            HighCountText.Text = "0";
            MediumCountText.Text = "0";
            LowCountText.Text = "0";

            DashboardTotalVulns.Text = "0";
            DashboardCriticalVulns.Text = "0";
            DashboardHighVulns.Text = "0";
            DashboardMediumVulns.Text = "0";
            DashboardLowVulns.Text = "0";
            DashboardSecurityScore.Text = "--";

            SummaryTargetPath.Text = "-";
            SummaryAgentType.Text = "-";
            SummaryDuration.Text = "-";
            SummaryScanTime.Text = "-";

            StaticResultCount.Text = "结果: 0";
            RemediationPendingCount.Text = "0";
            RemediationAcknowledgedCount.Text = "0";

            // 重置攻击面热力图
            LayerPromptInjection.Value = 0;
            LayerRoleHijack.Value = 0;
            LayerContextManipulation.Value = 0;
            LayerToolAbuse.Value = 0;
            LayerDataLeakage.Value = 0;
            LayerSupplyChain.Value = 0;
            LayerPromptCount1.Text = "0";
            LayerPromptCount2.Text = "0";
            LayerPromptCount3.Text = "0";
            LayerPromptCount4.Text = "0";
            LayerPromptCount5.Text = "0";
            LayerPromptCount6.Text = "0";
        }

        #endregion

        #region Tab 1: 概览仪表盘更新

        private void UpdateDashboard(AgentScanResult result)
        {
            DashboardTotalVulns.Text = result.TotalFindings.ToString();
            DashboardCriticalVulns.Text = result.CriticalCount.ToString();
            DashboardHighVulns.Text = result.HighCount.ToString();
            DashboardMediumVulns.Text = result.MediumCount.ToString();
            DashboardLowVulns.Text = result.LowCount.ToString();
            DashboardSecurityScore.Text = result.Score.ToString();

            // 更新攻击面热力图（使用正式模型的 AttackSurfaceSummary）
            UpdateAttackSurfaceLayers(result);

            // 更新Top 10问题列表（使用正式模型数据）
            UpdateTopIssuesList(result);

            // 更新摘要信息
            SummaryTargetPath.Text = Path.GetFileName(result.TargetPath);
            SummaryAgentType.Text = result.AgentType;
            SummaryDuration.Text = TimeSpan.FromMilliseconds(result.DurationMs).ToString(@"mm\:ss");
            SummaryScanTime.Text = result.StartTime.ToString("yyyy-MM-dd HH:mm:ss");

            StatusBarLastUpdate.Text = $"最后更新: {DateTime.Now:HH:mm:ss}";
        }

        /// <summary>
        /// 更新六层攻击面热力图 —— 使用正式模型的 AttackSurfaceSummary 字典
        /// 映射关系: LLM->提示词注入层, Tool->工具滥用层, Memory->上下文操纵层,
        ///           Workflow->角色劫持层, Transport->数据泄露层, External->供应链攻击层
        /// </summary>
        private void UpdateAttackSurfaceLayers(AgentScanResult result)
        {
            var summary = result.AttackSurfaceSummary;
            var maxRisk = Math.Max(result.TotalFindings, 1);

            // 六层攻击面的映射：枚举值 -> ProgressBar / Count TextBlock
            var layerMapping = new[]
            {
                (AgentAttackSurfaceLayer.LLM,    (ProgressBar)LayerPromptInjection,     (TextBlock)LayerPromptCount1),
                (AgentAttackSurfaceLayer.Tool,   (ProgressBar)LayerToolAbuse,          (TextBlock)LayerPromptCount4),
                (AgentAttackSurfaceLayer.Memory, (ProgressBar)LayerContextManipulation, (TextBlock)LayerPromptCount3),
                (AgentAttackSurfaceLayer.Workflow,(ProgressBar)LayerRoleHijack,         (TextBlock)LayerPromptCount2),
                (AgentAttackSurfaceLayer.Transport,(ProgressBar)LayerDataLeakage,       (TextBlock)LayerPromptCount5),
                (AgentAttackSurfaceLayer.External,(ProgressBar)LayerSupplyChain,        (TextBlock)LayerPromptCount6),
            };

            foreach (var (layer, progressBar, countText) in layerMapping)
            {
                int count = summary.TryGetValue(layer, out var c) ? c : 0;
                progressBar.Value = maxRisk > 0 ? (int)(count * 100.0 / maxRisk) : 0;
                countText.Text = count.ToString();
            }
        }

        /// <summary>
        /// 更新Top 10最严重问题列表 —— 从正式模型的 AllVulnerabilities 中按风险等级排序提取
        /// </summary>
        private void UpdateTopIssuesList(AgentScanResult result)
        {
            _topIssues.Clear();

            var topIssues = result.AllVulnerabilities
                .OrderByDescending(v => v.RiskLevel)
                .ThenByDescending(v => v.CvssScore ?? 0)
                .Take(10)
                .ToList();

            int index = 1;
            foreach (var vuln in topIssues)
            {
                _topIssues.Add(new TopIssueItem
                {
                    Index = index++,
                    Title = vuln.Title,
                    LevelText = vuln.RiskLevel.ToString(),
                    LevelColor = new SolidColorBrush((Color)ColorConverter.ConvertFromString(GetRiskLevelColor(vuln.RiskLevel)))
                });
            }
        }

        #endregion

        #region Tab 2: 静态分析结果更新

        /// <summary>
        /// 更新静态分析Tab —— 接收正式模型 List&lt;AgentVulnerability&gt;
        /// </summary>
        private void UpdateStaticAnalysisTab(List<AgentVulnerability>? vulns)
        {
            _staticAnalysisItems.Clear();

            if (vulns == null || vulns.Count == 0) return;

            foreach (var vuln in vulns.Take(50)) // 限制显示数量
            {
                _staticAnalysisItems.Add(new StaticAnalysisItem
                {
                    FileLocation = vuln.FileLocation,
                    LineNumber = vuln.LineNumber ?? 0,
                    Category = vuln.Category,
                    RiskLevel = vuln.RiskLevel.ToString(),
                    Preview = (vuln.Description.Length > 50 ? vuln.Description.Substring(0, 50) + "..." : vuln.Description)
                });
            }

            StaticResultCount.Text = $"结果: {_staticAnalysisItems.Count}";
        }

        private void StaticAnalysisDataGrid_MouseDoubleClick(object sender, MouseButtonEventArgs e)
        {
            ShowVulnerabilityDetail();
        }

        private void StaticViewDetail_Click(object sender, RoutedEventArgs e)
        {
            ShowVulnerabilityDetail();
        }

        private void ShowVulnerabilityDetail()
        {
            if (StaticAnalysisDataGrid.SelectedItem is StaticAnalysisItem item)
            {
                MessageBox.Show(
                    $"文件: {item.FileLocation}\n行号: {item.LineNumber}\n类型: {item.Category}\n等级: {item.RiskLevel}\n\n详情预览: {item.Preview}",
                    "漏洞详情",
                    MessageBoxButton.OK,
                    MessageBoxImage.Information
                );
            }
        }

        #endregion

        #region Tab 3: 意图研判结果更新

        /// <summary>
        /// 更新意图研判Tab —— 接收正式模型 List&lt;AgentVulnerability&gt;
        /// </summary>
        private void UpdateIntentAnalysisTab(List<AgentVulnerability>? vulns)
        {
            IntentCardsPanel.Children.Clear();

            if (vulns == null || vulns.Count == 0) return;

            foreach (var vuln in vulns.Take(20))
            {
                var card = CreateIntentCard(vuln);
                IntentCardsPanel.Children.Add(card);
            }
        }

        /// <summary>
        /// 创建意图研判风险卡片 —— 使用正式模型属性
        /// </summary>
        private Border CreateIntentCard(AgentVulnerability vuln)
        {
            string styleKey = vuln.RiskLevel switch
            {
                AgentRiskLevel.Critical => "RiskCardCritical",
                AgentRiskLevel.High => "RiskCardHigh",
                AgentRiskLevel.Medium => "RiskCardMedium",
                _ => "RiskCardLow"
            };

            var leftBarColor = GetRiskLevelColor(vuln.RiskLevel);

            var card = new Border
            {
                Style = (Style)FindResource(styleKey),
                Margin = new Thickness(5),
                Padding = new Thickness(12)
            };

            var grid = new Grid();
            grid.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto }); // 彩色竖条
            grid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) }); // 内容

            // 左侧彩色竖条
            var colorBar = new Border
            {
                Width = 5,
                CornerRadius = new CornerRadius(2),
                Background = new SolidColorBrush((Color)ColorConverter.ConvertFromString(leftBarColor)),
                Margin = new Thickness(0, 0, 10, 0)
            };
            Grid.SetColumn(colorBar, 0);

            // 右侧内容面板
            var contentPanel = new StackPanel();
            Grid.SetColumn(contentPanel, 1);

            // 标题行：分类标签 + 攻击面层级 + 置信度
            var headerPanel = new StackPanel { Orientation = Orientation.Horizontal, Margin = new Thickness(0, 0, 0, 8) };

            var typeLabel = new Border
            {
                Background = new SolidColorBrush((Color)ColorConverter.ConvertFromString(leftBarColor)),
                CornerRadius = new CornerRadius(3),
                Padding = new Thickness(8, 4, 8, 4),
                Margin = new Thickness(0, 0, 10, 0)
            };
            typeLabel.Child = new TextBlock
            {
                Text = vuln.Category,
                Foreground = Brushes.White,
                FontWeight = FontWeights.Bold,
                FontSize = 11
            };

            headerPanel.Children.Add(typeLabel);

            // 显示攻击面层级标签
            if (vuln.AttackSurfaceLayer != default)
            {
                var layerLabel = new Border
                {
                    Background = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#3498DB")),
                    CornerRadius = new CornerRadius(3),
                    Padding = new Thickness(6, 4, 6, 4),
                    Margin = new Thickness(0, 0, 10, 0)
                };
                layerLabel.Child = new TextBlock
                {
                    Text = vuln.AttackSurfaceLayer.ToString(),
                    Foreground = Brushes.White,
                    FontSize = 10
                };
                headerPanel.Children.Add(layerLabel);
            }

            // 置信度（使用正式模型的 Confidence 属性，范围 0-1）
            var confidencePanel = new StackPanel { Orientation = Orientation.Horizontal, VerticalAlignment = VerticalAlignment.Center };
            confidencePanel.Children.Add(new TextBlock { Text = "置信度: ", FontSize = 11, Foreground = Brushes.Gray });

            var confidencePercent = (int)(vuln.Confidence * 100);
            var confidenceBar = new ProgressBar
            {
                Width = 100,
                Height = 14,
                Minimum = 0,
                Maximum = 100,
                Value = confidencePercent,
                Foreground = confidencePercent >= 80 ? Brushes.Green : confidencePercent >= 60 ? Brushes.Orange : Brushes.Red
            };
            confidencePanel.Children.Add(confidenceBar);
            confidencePanel.Children.Add(new TextBlock { Text = $"{confidencePercent}%", FontSize = 11, Margin = new Thickness(5, 0, 0, 0), FontWeight = FontWeights.Bold });

            headerPanel.Children.Add(confidencePanel);
            contentPanel.Children.Add(headerPanel);

            // 攻击场景描述
            var descText = new TextBlock
            {
                Text = vuln.Description,
                TextWrapping = TextWrapping.Wrap,
                FontSize = 12,
                Foreground = Brushes.DarkGray,
                Margin = new Thickness(0, 0, 0, 8),
                MaxHeight = 60,
                TextTrimming = TextTrimming.CharacterEllipsis
            };
            contentPanel.Children.Add(descText);

            // 修复建议（可折叠）
            if (!string.IsNullOrEmpty(vuln.Remediation))
            {
                var expander = new Expander
                {
                    Header = "查看修复建议",
                    Margin = new Thickness(0, 5, 0, 0),
                    IsExpanded = false
                };
                expander.Content = new TextBlock
                {
                    Text = vuln.Remediation,
                    TextWrapping = TextWrapping.Wrap,
                    FontSize = 11,
                    Foreground = Brushes.DarkGreen,
                    Padding = new Thickness(5)
                };
                contentPanel.Children.Add(expander);
            }

            grid.Children.Add(colorBar);
            grid.Children.Add(contentPanel);
            card.Child = grid;

            return card;
        }

        #endregion

        #region Tab 4: 行为检测结果更新

        /// <summary>
        /// 更新行为检测Tab —— 接收正式模型 List&lt;AgentVulnerability&gt;
        /// </summary>
        private void UpdateBehaviorSandboxTab(List<AgentVulnerability>? vulns)
        {
            _behaviorItems.Clear();

            if (vulns == null || vulns.Count == 0) return;

            foreach (var vuln in vulns)
            {
                var cvssScore = vuln.CvssScore ?? 0.0;
                _behaviorItems.Add(new BehaviorVulnItem
                {
                    CveId = vuln.CveId ?? "N/A",
                    Title = vuln.Title,
                    CvssScore = cvssScore,
                    CvssColor = GetCvssColor(cvssScore),
                    RiskLevel = vuln.RiskLevel.ToString(),
                    AffectedComponent = vuln.FileLocation,
                    Condition = vuln.RawEvidence.Length > 80 ? vuln.RawEvidence.Substring(0, 80) + "..." : vuln.RawEvidence
                });
            }
        }

        private Brush GetCvssColor(double score)
        {
            return score switch
            {
                >= 9.0 => new SolidColorBrush((Color)ColorConverter.ConvertFromString("#C0392B")),
                >= 7.0 => new SolidColorBrush((Color)ColorConverter.ConvertFromString("#E74C3C")),
                >= 4.0 => new SolidColorBrush((Color)ColorConverter.ConvertFromString("#F39C12")),
                >= 0.1 => new SolidColorBrush((Color)ColorConverter.ConvertFromString("#27AE60")),
                _ => new SolidColorBrush((Color)ColorConverter.ConvertFromString("#95A5A6"))
            };
        }

        private void BehaviorDataGrid_SelectionChanged(object sender, SelectionChangedEventArgs e)
        {
            if (BehaviorDataGrid.SelectedItem is BehaviorVulnItem item)
            {
                BehaviorDetailPanel.Visibility = Visibility.Visible;
                BehaviorDetailTitle.Text = item.Title;
                BehaviorDetailDesc.Text = $"CVE编号: {item.CveId}\n影响组件: {item.AffectedComponent}\n利用条件: {item.Condition}\nCVSS评分: {item.CvssScore:F1}\n危害等级: {item.RiskLevel}";

                // 尝试从正式结果中获取更详细的修复建议
                var matchedVuln = _currentResult?.AllVulnerabilities.FirstOrDefault(v =>
                    v.CveId == item.CveId || v.Title == item.Title);
                BehaviorDetailFix.Text = matchedVuln?.Remediation ?? "修复建议: 请参考官方安全公告，及时升级受影响的组件版本。";
                BehaviorDetailRef.Text = !string.IsNullOrEmpty(item.CveId) && item.CveId != "N/A"
                    ? $"参考链接: https://nvd.nist.gov/vuln/detail/{item.CveId}"
                    : "";
            }
            else
            {
                BehaviorDetailPanel.Visibility = Visibility.Collapsed;
            }
        }

        private void CveId_MouseLeftButtonDown(object sender, MouseButtonEventArgs e)
        {
            if (sender is TextBlock tb && !string.IsNullOrEmpty(tb.Text))
            {
                Clipboard.SetText(tb.Text);
                MessageBox.Show($"已复制到剪贴板: {tb.Text}", "复制成功", MessageBoxButton.OK, MessageBoxImage.Information);
            }
        }

        #endregion

        #region Tab 5: 修复建议更新

        /// <summary>
        /// 更新修复建议Tab —— 接收正式模型 List&lt;AgentVulnerability&gt;
        /// </summary>
        private void UpdateRemediationTab(List<AgentVulnerability>? vulns)
        {
            RemediationListPanel.Children.Clear();

            if (vulns == null || vulns.Count == 0) return;

            int pending = 0, acknowledged = 0;

            // 按风险等级优先级排序（使用正式枚举比较）
            var sorted = vulns.OrderByDescending(v => v.RiskLevel).ToList();

            foreach (var vuln in sorted)
            {
                var item = CreateRemediationItem(vuln, ref pending, ref acknowledged);
                RemediationListPanel.Children.Add(item);
            }

            RemediationPendingCount.Text = pending.ToString();
            RemediationAcknowledgedCount.Text = acknowledged.ToString();
        }

        /// <summary>
        /// 创建修复建议项 —— 使用正式模型属性
        /// </summary>
        private Border CreateRemediationItem(AgentVulnerability vuln, ref int pending, ref int acknowledged)
        {
            var priorityColor = GetRiskLevelColor(vuln.RiskLevel);

            pending++;

            var border = new Border
            {
                Background = Brushes.White,
                BorderBrush = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#E9ECEF")),
                BorderThickness = new Thickness(1),
                CornerRadius = new CornerRadius(6),
                Margin = new Thickness(0, 0, 0, 10),
                Padding = new Thickness(15)
            };

            var grid = new Grid();
            grid.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto }); // 优先级标签
            grid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) }); // 内容
            grid.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto }); // 操作按钮

            // 优先级标签
            var priorityBadge = new Border
            {
                Background = new SolidColorBrush((Color)ColorConverter.ConvertFromString(priorityColor)),
                CornerRadius = new CornerRadius(3),
                Padding = new Thickness(10, 6, 10, 6),
                Margin = new Thickness(0, 0, 15, 0),
                VerticalAlignment = VerticalAlignment.Top
            };
            priorityBadge.Child = new TextBlock
            {
                Text = vuln.RiskLevel.ToString(),
                Foreground = Brushes.White,
                FontWeight = FontWeights.Bold,
                FontSize = 11
            };
            Grid.SetColumn(priorityBadge, 0);

            // 内容区
            var contentStack = new StackPanel { VerticalAlignment = VerticalAlignment.Center };
            Grid.SetColumn(contentStack, 1);

            contentStack.Children.Add(new TextBlock
            {
                Text = vuln.Title,
                FontWeight = FontWeights.Bold,
                FontSize = 13,
                Foreground = Brushes.DarkSlateGray,
                Margin = new Thickness(0, 0, 0, 5)
            });

            // 分类和位置信息
            var metaText = new StringBuilder();
            metaText.Append($"分类: {vuln.Category}");
            if (!string.IsNullOrEmpty(vuln.FileLocation))
                metaText.Append($" | 位置: {vuln.FileLocation}" + (vuln.LineNumber.HasValue ? $":{vuln.LineNumber}" : ""));
            if (!string.IsNullOrEmpty(vuln.CveId))
                metaText.Append($" | CVE: {vuln.CveId}");
            if (vuln.CvssScore.HasValue)
                metaText.Append($" | CVSS: {vuln.CvssScore.Value:F1}");
            metaText.Append($" | 置信度: {(vuln.Confidence * 100):F0}%");

            contentStack.Children.Add(new TextBlock
            {
                Text = metaText.ToString(),
                FontSize = 11,
                Foreground = Brushes.Gray,
                Margin = new Thickness(0, 0, 0, 5)
            });

            // 修复步骤
            if (!string.IsNullOrEmpty(vuln.Remediation))
            {
                var stepsText = new TextBlock
                {
                    Text = vuln.Remediation,
                    TextWrapping = TextWrapping.Wrap,
                    FontSize = 12,
                    Foreground = Brushes.Gray,
                    Margin = new Thickness(0, 0, 0, 5)
                };
                contentStack.Children.Add(stepsText);
            }

            // 复制按钮
            var copyBtn = new Button
            {
                Content = "复制",
                Padding = new Thickness(15, 6, 15, 6),
                Background = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#3498DB")),
                Foreground = Brushes.White,
                FontWeight = FontWeights.SemiBold,
                FontSize = 11,
                VerticalAlignment = VerticalAlignment.Center,
                Margin = new Thickness(15, 0, 0, 0),
                Tag = vuln
            };
            copyBtn.Click += CopyRemediation_Click;
            Grid.SetColumn(copyBtn, 2);

            grid.Children.Add(priorityBadge);
            grid.Children.Add(contentStack);
            grid.Children.Add(copyBtn);
            border.Child = grid;

            return border;
        }

        private void CopyRemediation_Click(object sender, RoutedEventArgs e)
        {
            if (sender is Button btn && btn.Tag is AgentVulnerability vuln)
            {
                var text = $"[{vuln.RiskLevel}] {vuln.Title}\n" +
                           $"分类: {vuln.Category} | 位置: {vuln.FileLocation}" + (vuln.LineNumber.HasValue ? $":{vuln.LineNumber}" : "") + "\n" +
                           $"CVSS: {vuln.CvssScore?.ToString("F1") ?? "N/A"} | 置信度: {(vuln.Confidence * 100):F0}%\n" +
                           $"修复步骤:\n{vuln.Remediation}";
                Clipboard.SetText(text);
                MessageBox.Show("修复建议已复制到剪贴板", "复制成功", MessageBoxButton.OK, MessageBoxImage.Information);
            }
        }

        #endregion

        #region 状态栏更新

        private void UpdateStatusBar()
        {
            if (_currentResult != null)
            {
                StatusBarStatus.Text = "状态: 就绪";
                StatusBarDuration.Text = $"扫描用时: {TimeSpan.FromMilliseconds(_currentResult.DurationMs):mm\\:ss}";
                StatusBarLastUpdate.Text = $"最后更新: {DateTime.Now:HH:mm:ss}";
            }
        }

        #endregion

        #region 辅助方法

        /// <summary>将界面模式字符串解析为正式的 AgentTargetType 枚举</summary>
        private static AgentTargetType ParseTargetMode(string mode) => mode switch
        {
            "File" => AgentTargetType.File,
            "Directory" => AgentTargetType.Directory,
            "Config" => AgentTargetType.ConfigText,
            _ => AgentTargetType.Clipboard
        };

        /// <summary>将界面深度字符串解析为正式的 AgentScanDepth 枚举</summary>
        private static AgentScanDepth ParseScanDepth(string depth) => depth switch
        {
            "快速扫描" => AgentScanDepth.Quick,
            "深度扫描" or "全面扫描" => AgentScanDepth.Deep,
            _ => AgentScanDepth.Standard
        };

        /// <summary>根据风险等级获取对应的十六进制颜色字符串</summary>
        private static string GetRiskLevelColor(AgentRiskLevel level) => level switch
        {
            AgentRiskLevel.Critical => "#E74C3C",
            AgentRiskLevel.High => "#E67E22",
            AgentRiskLevel.Medium => "#F39C12",
            AgentRiskLevel.Low => "#27AE60",
            _ => "#95A5A6"
        };

        #endregion
    }

    #region UI绑定数据项类（仅用于DataGrid/ListBox展示，非业务模型）

    /// <summary>
    /// 静态分析DataGrid绑定项 —— 属性名需与XAML中Binding一致
    /// </summary>
    public class StaticAnalysisItem
    {
        public string FileLocation { get; set; } = "";
        public int LineNumber { get; set; }
        public string Category { get; set; } = "";
        public string RiskLevel { get; set; } = "";
        public string Preview { get; set; } = "";
    }

    /// <summary>
    /// 行为检测DataGrid绑定项 —— 属性名需与XAML中Binding一致
    /// </summary>
    public class BehaviorVulnItem
    {
        public string CveId { get; set; } = "";
        public string Title { get; set; } = "";
        public double CvssScore { get; set; }
        public Brush CvssColor { get; set; } = Brushes.Gray;
        public string RiskLevel { get; set; } = "";
        public string AffectedComponent { get; set; } = "";
        public string Condition { get; set; } = "";
    }

    /// <summary>
    /// Top问题列表绑定项
    /// </summary>
    public class TopIssueItem
    {
        public int Index { get; set; }
        public string Title { get; set; } = "";
        public string LevelText { get; set; } = "";
        public Brush LevelColor { get; set; } = Brushes.Gray;
    }

    #endregion
}
