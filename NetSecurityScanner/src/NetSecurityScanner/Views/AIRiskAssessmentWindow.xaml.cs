using LiveChartsCore;
using LiveChartsCore.SkiaSharpView;
using LiveChartsCore.SkiaSharpView.Painting;
using LiveChartsCore.SkiaSharpView.WPF;
using LiveChartsCore.Measure;
using Microsoft.Win32;
using SkiaSharp;
using NetSecurityScanner.Models;
using NetSecurityScanner.Services;
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;

namespace NetSecurityScanner.Views
{
    public partial class AIRiskAssessmentWindow : Window
    {
        private readonly AIRiskAssessmentService _riskService;
        private AIRiskAssessmentReport? _currentReport;
        private List<PortScanResult> _portScanResults;
        private List<VulnerabilityResult> _vulnerabilityResults;
        private MainWindow? _mainWindow;

        public AIRiskAssessmentWindow(List<PortScanResult> portScanResults, List<VulnerabilityResult> vulnerabilityResults = null, MainWindow? mainWindow = null)
        {
            InitializeComponent();
            _riskService = new AIRiskAssessmentService();
            _portScanResults = portScanResults ?? new List<PortScanResult>();
            _vulnerabilityResults = vulnerabilityResults ?? new List<VulnerabilityResult>();
            _mainWindow = mainWindow;

            Loaded += AIRiskAssessmentWindow_Loaded;
        }

        private async void AIRiskAssessmentWindow_Loaded(object sender, RoutedEventArgs e)
        {
            await RunAssessmentAsync();
        }

        private async Task RunAssessmentAsync()
        {
            try
            {
                AssessmentStatusText.Text = "Running AI risk assessment...";
                RefreshAssessmentButton.IsEnabled = false;

                _currentReport = await _riskService.AssessRiskAsync(_portScanResults, _vulnerabilityResults);

                DisplayReport();

                AssessmentStatusText.Text = "Assessment completed";
                LastUpdateText.Text = DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss");
                ExportReportButton.IsEnabled = true;
                CopyReportButton.IsEnabled = true;
            }
            catch (Exception ex)
            {
                AssessmentStatusText.Text = $"Assessment failed: {ex.Message}";
                MessageBox.Show($"Risk assessment failed: {ex.Message}", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
            }
            finally
            {
                RefreshAssessmentButton.IsEnabled = true;
            }
        }

        private void DisplayReport()
        {
            if (_currentReport == null) return;

            var target = _portScanResults.FirstOrDefault()?.TargetIp ?? "Unknown";
            TargetTextBox.Text = target;
            ScanTimeTextBox.Text = _currentReport.AssessmentTime.ToString("yyyy-MM-dd HH:mm:ss");
            RiskScoreText.Text = _currentReport.RiskScore.ToString("F1");

            TotalPortsTextBox.Text = $"Total: {_currentReport.PortStatistics?.TotalPortsScanned ?? 0}";
            OpenPortsTextBox.Text = (_currentReport.PortStatistics?.OpenPortsCount ?? 0).ToString();
            VulnCountText.Text = _currentReport.RiskItems.Count.ToString();
            VulnTrendText.Text = $"{_currentReport.Recommendations.Count} recommendations";

            var riskColor = _currentReport.OverallRiskLevel switch
            {
                RiskLevel.Critical => new SolidColorBrush(Color.FromRgb(255, 65, 108)),
                RiskLevel.High => new SolidColorBrush(Color.FromRgb(245, 87, 108)),
                RiskLevel.Medium => new SolidColorBrush(Color.FromRgb(0, 242, 254)),
                RiskLevel.Low => new SolidColorBrush(Color.FromRgb(67, 233, 123)),
                _ => new SolidColorBrush(Colors.White)
            };

            RiskScoreText.Foreground = riskColor;
            RiskLevelText.Text = _currentReport.OverallRiskLevel.ToString();
            RiskLevelText.Foreground = riskColor;
            RiskLevelBadge.Text = _currentReport.OverallRiskLevel.ToString();
            RiskLevelBadge.Foreground = riskColor;

            RiskLevelDesc.Text = _currentReport.OverallRiskLevel switch
            {
                RiskLevel.Critical => "Immediate action required",
                RiskLevel.High => "High priority issue",
                RiskLevel.Medium => "Monitor closely",
                RiskLevel.Low => "Low priority",
                _ => "Unknown status"
            };

            var criticalCount = _currentReport.RiskItems.Count(r => r.RiskLevel == RiskLevel.Critical);
            var highCount = _currentReport.RiskItems.Count(r => r.RiskLevel == RiskLevel.High);
            var mediumCount = _currentReport.RiskItems.Count(r => r.RiskLevel == RiskLevel.Medium);
            var lowCount = _currentReport.RiskItems.Count(r => r.RiskLevel == RiskLevel.Low);

            CriticalCountText.Text = criticalCount.ToString();
            HighCountText.Text = highCount.ToString();
            MediumCountText.Text = mediumCount.ToString();
            LowCountText.Text = lowCount.ToString();

            RiskItemCount.Text = $"({_currentReport.RiskItems.Count} items)";
            RiskItemsDataGrid.ItemsSource = _currentReport.RiskItems.OrderByDescending(r => r.RiskScore).ToList();

            UpdateRiskGaugeChart(_currentReport.RiskScore);
            UpdateRiskDistributionChart(criticalCount, highCount, mediumCount, lowCount);
            UpdateRadarChart();
            UpdatePortDistributionChart();
        }

        private void UpdateRiskGaugeChart(double score)
        {
            var percentage = score / 10.0;
            var (primaryColor, secondaryColor) = score switch
            {
                >= 8 => (new SKColor(255, 65, 108), new SKColor(255, 75, 43)),
                >= 6 => (new SKColor(245, 87, 108), new SKColor(240, 147, 123)),
                >= 4 => (new SKColor(0, 242, 254), new SKColor(79, 172, 254)),
                _ => (new SKColor(67, 233, 123), new SKColor(56, 249, 215))
            };

            RiskGaugeChart.Series = new ISeries[]
            {
                new PieSeries<double>
                {
                    Values = new[] { percentage },
                    Fill = new SolidColorPaint(primaryColor),
                    Stroke = new SolidColorPaint(new SKColor(255, 255, 255)) { StrokeThickness = 2 },
                    Pushout = 0,
                    InnerRadius = 50
                },
                new PieSeries<double>
                {
                    Values = new[] { 1 - percentage },
                    Fill = new SolidColorPaint(new SKColor(40, 40, 60)),
                    Stroke = null,
                    Pushout = 0,
                    InnerRadius = 50
                }
            };

            RiskGaugeChart.AnimationsSpeed = TimeSpan.FromMilliseconds(800);
        }

        private void UpdateRiskDistributionChart(int critical, int high, int medium, int low)
        {
            var series = new ISeries[]
            {
                new PieSeries<int>
                {
                    Name = "Critical",
                    Values = new[] { critical },
                    Fill = new SolidColorPaint(new SKColor(255, 65, 108)),
                    DataLabelsSize = 13,
                    DataLabelsPaint = new SolidColorPaint(new SKColor(255, 255, 255)),
                    DataLabelsPosition = LiveChartsCore.Measure.PolarLabelsPosition.Middle,
                    DataLabelsFormatter = point => point.Coordinate.PrimaryValue > 0 ? $"{point.Coordinate.PrimaryValue}" : ""
                },
                new PieSeries<int>
                {
                    Name = "High",
                    Values = new[] { high },
                    Fill = new SolidColorPaint(new SKColor(245, 87, 108)),
                    DataLabelsSize = 13,
                    DataLabelsPaint = new SolidColorPaint(new SKColor(255, 255, 255)),
                    DataLabelsPosition = LiveChartsCore.Measure.PolarLabelsPosition.Middle,
                    DataLabelsFormatter = point => point.Coordinate.PrimaryValue > 0 ? $"{point.Coordinate.PrimaryValue}" : ""
                },
                new PieSeries<int>
                {
                    Name = "Medium",
                    Values = new[] { medium },
                    Fill = new SolidColorPaint(new SKColor(0, 242, 254)),
                    DataLabelsSize = 13,
                    DataLabelsPaint = new SolidColorPaint(new SKColor(0, 0, 0)),
                    DataLabelsPosition = LiveChartsCore.Measure.PolarLabelsPosition.Middle,
                    DataLabelsFormatter = point => point.Coordinate.PrimaryValue > 0 ? $"{point.Coordinate.PrimaryValue}" : ""
                },
                new PieSeries<int>
                {
                    Name = "Low",
                    Values = new[] { low },
                    Fill = new SolidColorPaint(new SKColor(67, 233, 123)),
                    DataLabelsSize = 13,
                    DataLabelsPaint = new SolidColorPaint(new SKColor(0, 0, 0)),
                    DataLabelsPosition = LiveChartsCore.Measure.PolarLabelsPosition.Middle,
                    DataLabelsFormatter = point => point.Coordinate.PrimaryValue > 0 ? $"{point.Coordinate.PrimaryValue}" : ""
                }
            };

            RiskDistributionChart.Series = series;
            RiskDistributionChart.LegendPosition = LiveChartsCore.Measure.LegendPosition.Bottom;
        }

        private void UpdateRadarChart()
        {
            var dimensions = new[] { "Network", "Services", "Vulns", "Ports", "Config", "Access" };
            
            var networkRisk = CalculateNetworkRisk();
            var servicesRisk = CalculateServicesRisk();
            var vulnsRisk = CalculateVulnsRisk();
            var portsRisk = CalculatePortsRisk();
            var configRisk = CalculateConfigRisk();
            var accessRisk = CalculateAccessRisk();
            
            var values = new[] { networkRisk, servicesRisk, vulnsRisk, portsRisk, configRisk, accessRisk };

            RadarChart.Series = new ISeries[]
            {
                new PolarLineSeries<double>
                {
                    Name = "Risk Score",
                    Values = values,
                    Fill = new SolidColorPaint(new SKColor(102, 126, 234, 100)),
                    Stroke = new SolidColorPaint(new SKColor(118, 75, 162)) { StrokeThickness = 3 },
                    GeometryFill = new SolidColorPaint(new SKColor(102, 126, 234)),
                    GeometryStroke = new SolidColorPaint(new SKColor(255, 255, 255)) { StrokeThickness = 2 },
                    GeometrySize = 10,
                    LineSmoothness = 0.3
                }
            };
        }
        
        private double CalculateNetworkRisk()
        {
            // 网络风险：根据开放端口数量计算
            var openPorts = _portScanResults.Count(p => p.Status == "开放");
            return Math.Min(10.0, openPorts * 0.5);
        }
        
        private double CalculateServicesRisk()
        {
            // 服务风险：根据识别的服务数量计算
            var services = _portScanResults.Where(p => !string.IsNullOrEmpty(p.Service)).Select(p => p.Service).Distinct().Count();
            return Math.Min(10.0, services * 1.2);
        }
        
        private double CalculateVulnsRisk()
        {
            // 漏洞风险：根据漏洞数量和等级计算
            if (_vulnerabilityResults == null || !_vulnerabilityResults.Any()) return 0;
            var vulnScore = _vulnerabilityResults.Sum(v => v.RiskLevel switch
            {
                "Critical" => 3.0,
                "High" => 2.0,
                "Medium" => 1.0,
                "Low" => 0.5,
                _ => 0.5
            });
            return Math.Min(10.0, vulnScore);
        }
        
        private double CalculatePortsRisk()
        {
            // 端口风险：根据高危端口数量计算
            var highRiskPorts = _portScanResults.Count(p => p.Status == "开放" && 
                (p.PortNumber == 22 || p.PortNumber == 23 || p.PortNumber == 445 || 
                 p.PortNumber == 3389 || p.PortNumber == 3306 || p.PortNumber == 1433));
            return Math.Min(10.0, highRiskPorts * 1.5);
        }
        
        private double CalculateConfigRisk()
        {
            // 配置风险：根据服务版本信息缺失情况计算
            var missingVersion = _portScanResults.Count(p => p.Status == "开放" && string.IsNullOrEmpty(p.ServiceVersion));
            var totalOpen = _portScanResults.Count(p => p.Status == "开放");
            if (totalOpen == 0) return 0;
            return Math.Min(10.0, (missingVersion * 1.0 / totalOpen) * 10);
        }
        
        private double CalculateAccessRisk()
        {
            // 访问风险：根据远程访问端口数量计算
            var accessPorts = _portScanResults.Count(p => p.Status == "开放" && 
                (p.PortNumber == 22 || p.PortNumber == 23 || p.PortNumber == 3389 || p.PortNumber == 5900));
            return Math.Min(10.0, accessPorts * 2.0);
        }

        private void UpdatePortDistributionChart()
        {
            var portRanges = new[] { "1-1024", "1025-5K", "5K-10K", "10K-20K", "20K+" };
            
            var openPorts = portRanges.Select(range => 
            {
                var (min, max) = GetPortRange(range);
                return (double)_portScanResults.Count(p => p.PortNumber >= min && p.PortNumber <= max && p.Status == "开放");
            }).ToArray();
            
            var totalScanned = _portScanResults.Count;
            var closedPorts = portRanges.Select(range => 
            {
                var (min, max) = GetPortRange(range);
                var openInRange = _portScanResults.Count(p => p.PortNumber >= min && p.PortNumber <= max);
                var estimatedTotal = GetEstimatedTotalPorts(min, max);
                return (double)Math.Max(0, estimatedTotal - openInRange);
            }).ToArray();

            PortDistributionChart.Series = new ISeries[]
            {
                new ColumnSeries<double>
                {
                    Name = "Open",
                    Values = openPorts,
                    Fill = new SolidColorPaint(new SKColor(0, 242, 254)),
                    Stroke = null,
                    MaxBarWidth = 30,
                    Padding = 5,
                    Rx = 4,
                    Ry = 4
                },
                new ColumnSeries<double>
                {
                    Name = "Closed",
                    Values = closedPorts,
                    Fill = new SolidColorPaint(new SKColor(102, 126, 234)),
                    Stroke = null,
                    MaxBarWidth = 30,
                    Padding = 5,
                    Rx = 4,
                    Ry = 4
                }
            };

            PortDistributionChart.XAxes = new Axis[]
            {
                new Axis
                {
                    Labels = portRanges,
                    LabelsPaint = new SolidColorPaint(new SKColor(200, 200, 220)),
                    TextSize = 10,
                    LabelsRotation = 0,
                    SeparatorsPaint = new SolidColorPaint(new SKColor(60, 60, 80)) { StrokeThickness = 1 }
                }
            };

            PortDistributionChart.YAxes = new Axis[]
            {
                new Axis
                {
                    MinLimit = 0,
                    LabelsPaint = new SolidColorPaint(new SKColor(139, 139, 154)),
                    TextSize = 9,
                    SeparatorsPaint = new SolidColorPaint(new SKColor(60, 60, 80)) { StrokeThickness = 1 }
                }
            };
        }
        
        private (int min, int max) GetPortRange(string rangeName)
        {
            return rangeName switch
            {
                "1-1024" => (1, 1024),
                "1025-5K" => (1025, 5000),
                "5K-10K" => (5001, 10000),
                "10K-20K" => (10001, 20000),
                "20K+" => (20001, 65535),
                _ => (1, 65535)
            };
        }
        
        private int GetEstimatedTotalPorts(int min, int max)
        {
            // 根据端口段估算扫描的端口总数
            return min switch
            {
                1 => 100,      // 1-1024段：假设扫描了100个端口
                1025 => 50,    // 1025-5000段：假设扫描了50个端口
                5001 => 30,    // 5001-10000段：假设扫描了30个端口
                10001 => 20,   // 10001-20000段：假设扫描了20个端口
                20001 => 10,   // 20001+段：假设扫描了10个端口
                _ => 50
            };
        }

        private void RiskItemsDataGrid_SelectionChanged(object sender, SelectionChangedEventArgs e)
        {
            if (RiskItemsDataGrid.SelectedItem is AIRiskItem riskItem)
            {
                DisplayRecommendation(riskItem);
            }
        }

        private void RiskItemsDataGrid_MouseDoubleClick(object sender, System.Windows.Input.MouseButtonEventArgs e)
        {
            if (RiskItemsDataGrid.SelectedItem is AIRiskItem riskItem)
            {
                ShowRiskItemDetails(riskItem);
            }
        }

        private void RiskItemsDataGrid_Sorting(object sender, DataGridSortingEventArgs e)
        {
            e.Handled = true;
            
            var column = e.Column;
            var direction = column.SortDirection == ListSortDirection.Ascending 
                ? ListSortDirection.Descending 
                : ListSortDirection.Ascending;
            
            column.SortDirection = direction;
            
            if (RiskItemsDataGrid.ItemsSource is List<AIRiskItem> items)
            {
                List<AIRiskItem> sortedList = direction == ListSortDirection.Ascending
                    ? items.OrderBy(r => GetSortValue(r, column.SortMemberPath)).ToList()
                    : items.OrderByDescending(r => GetSortValue(r, column.SortMemberPath)).ToList();
                
                RiskItemsDataGrid.ItemsSource = sortedList;
            }
        }

        private object GetSortValue(AIRiskItem item, string memberPath)
        {
            return memberPath switch
            {
                "RiskLevel" => GetRiskLevelPriority(item.RiskLevel),
                "RiskScore" => item.RiskScore,
                "Target" => item.Target,
                "Title" => item.Title,
                _ => item.RiskScore
            };
        }

        private int GetRiskLevelPriority(RiskLevel level)
        {
            return level switch
            {
                RiskLevel.Critical => 5,
                RiskLevel.High => 4,
                RiskLevel.Medium => 3,
                RiskLevel.Low => 2,
                _ => 1
            };
        }

        private void DisplayRecommendation(AIRiskItem riskItem)
        {
            RecommendationsItemsControl.Items.Clear();

            var recommendation = _currentReport?.Recommendations
                .FirstOrDefault(r => r.Target == riskItem.Target);

            if (recommendation != null)
            {
                var priorityColor = recommendation.Priority switch
                {
                    RecommendationPriority.Immediate => "#ff416c",
                    RecommendationPriority.High => "#f5576c",
                    RecommendationPriority.Medium => "#00f2fe",
                    _ => "#43e97b"
                };

                RecommendationsItemsControl.Items.Add(new Border
                {
                    Background = new SolidColorBrush((Color)ColorConverter.ConvertFromString(priorityColor)),
                    CornerRadius = new CornerRadius(6),
                    Padding = new Thickness(10, 5, 10, 5),
                    Margin = new Thickness(0, 0, 0, 12),
                    HorizontalAlignment = HorizontalAlignment.Left,
                    Child = new TextBlock
                    {
                        Text = $"Priority: {recommendation.Priority}",
                        Foreground = Brushes.White,
                        FontWeight = FontWeights.Bold,
                        FontSize = 12
                    }
                });

                RecommendationsItemsControl.Items.Add(new TextBlock
                {
                    Text = recommendation.Title,
                    FontSize = 16,
                    FontWeight = FontWeights.Bold,
                    Foreground = Brushes.White,
                    Margin = new Thickness(0, 0, 0, 8),
                    TextWrapping = TextWrapping.Wrap
                });

                RecommendationsItemsControl.Items.Add(new TextBlock
                {
                    Text = recommendation.Description,
                    FontSize = 13,
                    Foreground = new SolidColorBrush(Color.FromRgb(200, 200, 200)),
                    Margin = new Thickness(0, 0, 0, 12),
                    TextWrapping = TextWrapping.Wrap
                });

                RecommendationsItemsControl.Items.Add(new TextBlock
                {
                    Text = "Action Steps:",
                    FontSize = 13,
                    FontWeight = FontWeights.Bold,
                    Foreground = Brushes.White,
                    Margin = new Thickness(0, 0, 0, 8)
                });

                int stepNum = 1;
                foreach (var step in recommendation.ActionSteps)
                {
                    RecommendationsItemsControl.Items.Add(new TextBlock
                    {
                        Text = $"{stepNum}. {step}",
                        FontSize = 12,
                        Foreground = new SolidColorBrush(Color.FromRgb(180, 180, 180)),
                        Margin = new Thickness(8, 3, 0, 3),
                        TextWrapping = TextWrapping.Wrap
                    });
                    stepNum++;
                }
            }
            else
            {
                RecommendationsItemsControl.Items.Add(new TextBlock
                {
                    Text = riskItem.Title,
                    FontSize = 16,
                    FontWeight = FontWeights.Bold,
                    Foreground = Brushes.White,
                    Margin = new Thickness(0, 0, 0, 8)
                });

                RecommendationsItemsControl.Items.Add(new TextBlock
                {
                    Text = riskItem.Description,
                    FontSize = 13,
                    Foreground = new SolidColorBrush(Color.FromRgb(200, 200, 200)),
                    Margin = new Thickness(0, 0, 0, 8),
                    TextWrapping = TextWrapping.Wrap
                });
            }
        }

        private void ShowRiskItemDetails(AIRiskItem riskItem)
        {
            var detailWindow = new Window
            {
                Title = $"Risk Details - {riskItem.Title}",
                Width = 550,
                Height = 450,
                WindowStartupLocation = WindowStartupLocation.CenterScreen,
                Background = new SolidColorBrush(Color.FromRgb(26, 31, 53))
            };

            var scrollViewer = new ScrollViewer { Margin = new Thickness(20) };
            var panel = new StackPanel { Orientation = Orientation.Vertical };

            var levelColor = riskItem.RiskLevel switch
            {
                RiskLevel.Critical => "#ff416c",
                RiskLevel.High => "#f5576c",
                RiskLevel.Medium => "#00f2fe",
                _ => "#43e97b"
            };

            panel.Children.Add(new Border
            {
                Background = new SolidColorBrush((Color)ColorConverter.ConvertFromString(levelColor)),
                CornerRadius = new CornerRadius(6),
                Padding = new Thickness(12, 6, 12, 6),
                Margin = new Thickness(0, 0, 0, 15),
                HorizontalAlignment = HorizontalAlignment.Left,
                Child = new TextBlock
                {
                    Text = $"Risk Level: {riskItem.RiskLevel}",
                    Foreground = Brushes.White,
                    FontWeight = FontWeights.Bold,
                    FontSize = 14
                }
            });

            panel.Children.Add(new TextBlock
            {
                Text = riskItem.Title,
                FontSize = 20,
                FontWeight = FontWeights.Bold,
                Foreground = Brushes.White,
                Margin = new Thickness(0, 0, 0, 12),
                TextWrapping = TextWrapping.Wrap
            });

            panel.Children.Add(new TextBlock
            {
                Text = $"Target: {riskItem.Target}",
                FontSize = 13,
                Foreground = new SolidColorBrush(Color.FromRgb(139, 139, 154)),
                Margin = new Thickness(0, 0, 0, 5)
            });

            panel.Children.Add(new TextBlock
            {
                Text = $"Score: {riskItem.RiskScore:F1}/10",
                FontSize = 13,
                Foreground = Brushes.White,
                Margin = new Thickness(0, 0, 0, 15),
                FontWeight = FontWeights.SemiBold
            });

            panel.Children.Add(new TextBlock
            {
                Text = "Description:",
                FontSize = 14,
                FontWeight = FontWeights.Bold,
                Foreground = Brushes.White,
                Margin = new Thickness(0, 0, 0, 8)
            });

            panel.Children.Add(new TextBlock
            {
                Text = riskItem.Description,
                FontSize = 13,
                Foreground = new SolidColorBrush(Color.FromRgb(200, 200, 200)),
                Margin = new Thickness(0, 0, 0, 15),
                TextWrapping = TextWrapping.Wrap
            });

            if (riskItem.Details?.Any() == true)
            {
                panel.Children.Add(new TextBlock
                {
                    Text = "Details:",
                    FontSize = 14,
                    FontWeight = FontWeights.Bold,
                    Foreground = Brushes.White,
                    Margin = new Thickness(0, 0, 0, 8)
                });

                foreach (var detail in riskItem.Details)
                {
                    var detailPanel = new StackPanel { Orientation = Orientation.Horizontal, Margin = new Thickness(0, 3, 0, 3) };
                    detailPanel.Children.Add(new TextBlock
                    {
                        Text = $"{detail.Key}: ",
                        FontWeight = FontWeights.SemiBold,
                        FontSize = 12,
                        Foreground = new SolidColorBrush(Color.FromRgb(139, 139, 154)),
                        Width = 80
                    });
                    detailPanel.Children.Add(new TextBlock
                    {
                        Text = detail.Value,
                        FontSize = 12,
                        Foreground = Brushes.White,
                        TextWrapping = TextWrapping.Wrap
                    });
                    panel.Children.Add(detailPanel);
                }
            }

            scrollViewer.Content = panel;
            detailWindow.Content = scrollViewer;
            detailWindow.ShowDialog();
        }

        private async void RefreshAssessmentButton_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                AssessmentStatusText.Text = "正在重新分析...";
                RefreshAssessmentButton.IsEnabled = false;

                if (_mainWindow != null)
                {
                    _portScanResults = _mainWindow.GetPortScanResults();
                    _vulnerabilityResults = _mainWindow.GetVulnerabilityResults();
                }

                if (_portScanResults == null || !_portScanResults.Any())
                {
                    MessageBox.Show("没有扫描数据可供分析。", "提示", MessageBoxButton.OK, MessageBoxImage.Warning);
                    return;
                }

                _currentReport = await _riskService.AssessRiskAsync(_portScanResults, _vulnerabilityResults);
                DisplayReport();

                AssessmentStatusText.Text = "分析完成";
                LastUpdateText.Text = DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss");
                MessageBox.Show("重新分析完成！", "提示", MessageBoxButton.OK, MessageBoxImage.Information);
            }
            catch (Exception ex)
            {
                AssessmentStatusText.Text = $"分析失败：{ex.Message}";
                MessageBox.Show($"重新分析失败：{ex.Message}", "错误", MessageBoxButton.OK, MessageBoxImage.Error);
            }
            finally
            {
                RefreshAssessmentButton.IsEnabled = true;
            }
        }

        private async Task SaveScanHistoryAsync()
        {
            try
            {
                if (_currentReport == null) return;

                var historyService = new ScanHistoryService();
                var target = _portScanResults.FirstOrDefault()?.TargetIp ?? "Unknown";
                
                // 创建扫描配置
                var config = new ScanConfiguration
                {
                    Mode = ScanMode.Standard,
                    PortRange = "1-1000",
                    TargetPorts = _portScanResults.Select(p => p.PortNumber).ToArray()
                };

                // 保存扫描历史（简化版本）
                await Task.CompletedTask;
            }
            catch (Exception ex)
            {
                // 记录日志但不影响主流程
                System.Diagnostics.Debug.WriteLine($"保存扫描历史失败：{ex.Message}");
            }
        }

        private void CopyReportButton_Click(object sender, RoutedEventArgs e)
        {
            if (_currentReport == null) return;

            try
            {
                var sb = new StringBuilder();
                sb.AppendLine("=".PadRight(70, '='));
                sb.AppendLine("                    AI Risk Assessment Report");
                sb.AppendLine("=".PadRight(70, '='));
                sb.AppendLine();
                sb.AppendLine($"Assessment Time  : {_currentReport.AssessmentTime:yyyy-MM-dd HH:mm:ss}");
                sb.AppendLine($"Target           : {_portScanResults.FirstOrDefault()?.TargetIp ?? "Unknown"}");
                sb.AppendLine($"Risk Score       : {_currentReport.RiskScore:F1} / 10.0");
                sb.AppendLine($"Overall Risk     : {_currentReport.OverallRiskLevel}");
                sb.AppendLine($"Open Ports       : {_currentReport.PortStatistics.OpenPortsCount}");
                sb.AppendLine();
                sb.AppendLine("Risk Distribution:");
                sb.AppendLine($"  🔴 Critical : {_currentReport.RiskItems.Count(r => r.RiskLevel == RiskLevel.Critical)}");
                sb.AppendLine($"  🟠 High     : {_currentReport.RiskItems.Count(r => r.RiskLevel == RiskLevel.High)}");
                sb.AppendLine($"  🔵 Medium  : {_currentReport.RiskItems.Count(r => r.RiskLevel == RiskLevel.Medium)}");
                sb.AppendLine($"  🟢 Low     : {_currentReport.RiskItems.Count(r => r.RiskLevel == RiskLevel.Low)}");
                sb.AppendLine();
                
                if (_currentReport.PortStatistics.RiskPatterns.Any())
                {
                    sb.AppendLine("Identified Risk Patterns:");
                    foreach (var pattern in _currentReport.PortStatistics.RiskPatterns)
                    {
                        sb.AppendLine($"  • {pattern}");
                    }
                    sb.AppendLine();
                }
                
                sb.AppendLine("-".PadRight(70, '-'));
                sb.AppendLine("Top 10 Risk Items (by score):");
                sb.AppendLine("-".PadRight(70, '-'));
                
                foreach (var item in _currentReport.RiskItems.OrderByDescending(r => r.RiskScore).Take(10))
                {
                    var icon = item.RiskLevel switch
                    {
                        RiskLevel.Critical => "🔴",
                        RiskLevel.High => "🟠",
                        RiskLevel.Medium => "🔵",
                        _ => "🟢"
                    };
                    sb.AppendLine();
                    sb.AppendLine($"  {icon} [{item.RiskLevel}] {item.Title}");
                    sb.AppendLine($"     Target: {item.Target} | Score: {item.RiskScore:F1}");
                    sb.AppendLine($"     {item.Description}");
                }
                
                sb.AppendLine();
                sb.AppendLine("=".PadRight(70, '='));
                sb.AppendLine($"Generated: {DateTime.Now:yyyy-MM-dd HH:mm:ss}");

                Clipboard.SetText(sb.ToString());
                MessageBox.Show("Detailed report copied to clipboard!", "Success", MessageBoxButton.OK, MessageBoxImage.Information);
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Copy failed: {ex.Message}", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        private async void ExportReportButton_Click(object sender, RoutedEventArgs e)
        {
            if (_currentReport == null) return;

            try
            {
                var dialog = new SaveFileDialog
                {
                    Filter = "JSON File|*.json|HTML File|*.html|Text File|*.txt",
                    FileName = $"AI_Risk_Assessment_{DateTime.Now:yyyyMMdd_HHmmss}",
                    Title = "Export AI Risk Assessment Report"
                };

                if (dialog.ShowDialog() != true) return;

                string filePath = dialog.FileName;
                string extension = Path.GetExtension(filePath).ToLower();

                switch (extension)
                {
                    case ".json":
                        await ExportToJsonAsync(filePath);
                        break;
                    case ".html":
                        await ExportToHtmlAsync(filePath);
                        break;
                    case ".txt":
                        await ExportToTextAsync(filePath);
                        break;
                }

                MessageBox.Show($"Report exported to:\n{filePath}", "Success", MessageBoxButton.OK, MessageBoxImage.Information);
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Export failed: {ex.Message}", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        private async Task ExportToJsonAsync(string filePath)
        {
            var json = JsonSerializer.Serialize(_currentReport, new JsonSerializerOptions { WriteIndented = true });
            await File.WriteAllTextAsync(filePath, json);
        }

        private async Task ExportToHtmlAsync(string filePath)
        {
            var html = GenerateHtmlReport();
            await File.WriteAllTextAsync(filePath, html);
        }

        private async Task ExportToTextAsync(string filePath)
        {
            var sb = new StringBuilder();
            
            // Header
            sb.AppendLine("=".PadRight(70, '='));
            sb.AppendLine("                    AI Risk Assessment Report");
            sb.AppendLine("           Deep Learning Based Network Security Risk Analysis");
            sb.AppendLine("=".PadRight(70, '='));
            sb.AppendLine();
            
            // Basic Information
            sb.AppendLine("📋 Assessment Information");
            sb.AppendLine("-".PadRight(70, '-'));
            sb.AppendLine($"  Assessment Time    : {_currentReport!.AssessmentTime:yyyy-MM-dd HH:mm:ss}");
            sb.AppendLine($"  Target IP          : {_portScanResults.FirstOrDefault()?.TargetIp ?? "Unknown"}");
            sb.AppendLine($"  Risk Score         : {_currentReport.RiskScore:F1} / 10.0");
            sb.AppendLine($"  Overall Risk Level : {_currentReport.OverallRiskLevel}");
            sb.AppendLine($"  Open Ports         : {_currentReport.PortStatistics.OpenPortsCount}");
            sb.AppendLine($"  Total Scanned      : {_currentReport.PortStatistics.TotalPortsScanned}");
            sb.AppendLine();
            
            // Risk Statistics
            sb.AppendLine("📊 Risk Distribution");
            sb.AppendLine("-".PadRight(70, '-'));
            var criticalCount = _currentReport.RiskItems.Count(r => r.RiskLevel == RiskLevel.Critical);
            var highCount = _currentReport.RiskItems.Count(r => r.RiskLevel == RiskLevel.High);
            var mediumCount = _currentReport.RiskItems.Count(r => r.RiskLevel == RiskLevel.Medium);
            var lowCount = _currentReport.RiskItems.Count(r => r.RiskLevel == RiskLevel.Low);
            
            sb.AppendLine($"  🔴 Critical : {criticalCount,-5} ({criticalCount * 100.0 / _currentReport.RiskItems.Count:F1}%)");
            sb.AppendLine($"  🟠 High     : {highCount,-5} ({highCount * 100.0 / _currentReport.RiskItems.Count:F1}%)");
            sb.AppendLine($"  🔵 Medium  : {mediumCount,-5} ({mediumCount * 100.0 / _currentReport.RiskItems.Count:F1}%)");
            sb.AppendLine($"  🟢 Low     : {lowCount,-5} ({lowCount * 100.0 / _currentReport.RiskItems.Count:F1}%)");
            sb.AppendLine();
            
            // Risk Patterns
            if (_currentReport.PortStatistics.RiskPatterns.Any())
            {
                sb.AppendLine("⚠️  Identified Risk Patterns");
                sb.AppendLine("-".PadRight(70, '-'));
                foreach (var pattern in _currentReport.PortStatistics.RiskPatterns)
                {
                    sb.AppendLine($"  • {pattern}");
                }
                sb.AppendLine();
            }
            
            // Risk Items Detail
            sb.AppendLine("🔍 Risk Items Detail");
            sb.AppendLine("-".PadRight(70, '-'));
            sb.AppendLine();
            
            var sortedItems = _currentReport.RiskItems.OrderByDescending(r => r.RiskScore).ToList();
            for (int i = 0; i < sortedItems.Count; i++)
            {
                var item = sortedItems[i];
                var levelIcon = item.RiskLevel switch
                {
                    RiskLevel.Critical => "🔴",
                    RiskLevel.High => "🟠",
                    RiskLevel.Medium => "🔵",
                    _ => "🟢"
                };
                
                sb.AppendLine($"  {i + 1}. {levelIcon} [{item.RiskLevel}] {item.Title}");
                sb.AppendLine($"     Target    : {item.Target}");
                sb.AppendLine($"     Risk Score: {item.RiskScore:F1} / 10.0");
                sb.AppendLine($"     CVSS      : {item.CVSSScore:F1}");
                sb.AppendLine($"     Description: {item.Description}");
                
                if (item.Details?.Any() == true)
                {
                    sb.AppendLine($"     Technical Details:");
                    foreach (var detail in item.Details)
                    {
                        sb.AppendLine($"       - {detail.Key}: {detail.Value}");
                    }
                }
                
                if (item.RelatedVulnerabilities?.Any() == true)
                {
                    sb.AppendLine($"     Related Vulnerabilities:");
                    foreach (var vuln in item.RelatedVulnerabilities)
                    {
                        sb.AppendLine($"       [{vuln.Severity}] {vuln.Name}");
                        sb.AppendLine($"         CVE: {vuln.CVE}");
                        sb.AppendLine($"         {vuln.Description}");
                    }
                }
                
                sb.AppendLine();
            }
            
            // Recommendations
            if (_currentReport.Recommendations.Any())
            {
                sb.AppendLine("💡 Recommendations");
                sb.AppendLine("-".PadRight(70, '-'));
                sb.AppendLine();
                
                foreach (var rec in _currentReport.Recommendations)
                {
                    var priorityIcon = rec.Priority switch
                    {
                        RecommendationPriority.Immediate => "🚨",
                        RecommendationPriority.High => "⚡",
                        RecommendationPriority.Medium => "📌",
                        _ => "📋"
                    };
                    
                    sb.AppendLine($"  {priorityIcon} [{rec.Priority}] {rec.Title}");
                    sb.AppendLine($"     Target: {rec.Target}");
                    sb.AppendLine($"     {rec.Description}");
                    sb.AppendLine($"     Action Steps:");
                    for (int i = 0; i < rec.ActionSteps.Count; i++)
                    {
                        sb.AppendLine($"       {i + 1}. {rec.ActionSteps[i]}");
                    }
                    sb.AppendLine();
                }
            }
            
            // Summary
            sb.AppendLine();
            sb.AppendLine("=".PadRight(70, '='));
            sb.AppendLine("                          End of Report");
            sb.AppendLine("=".PadRight(70, '='));
            sb.AppendLine($"Generated by NetSecurityScanner AI Risk Assessment System");
            sb.AppendLine($"Report Time: {DateTime.Now:yyyy-MM-dd HH:mm:ss}");

            await File.WriteAllTextAsync(filePath, sb.ToString(), Encoding.UTF8);
        }

        private string GenerateHtmlReport()
        {
            var sb = new StringBuilder();
            sb.AppendLine("<!DOCTYPE html>");
            sb.AppendLine("<html><head><meta charset='utf-8'/><title>AI Risk Assessment Report</title>");
            sb.AppendLine("<style>");
            sb.AppendLine("body{font-family:Segoe UI,sans-serif;margin:40px;background:#0a0e14;color:#e0e0e0;}");
            sb.AppendLine(".container{max-width:1200px;margin:0 auto;background:#1a1f35;padding:40px;border-radius:15px;}");
            sb.AppendLine("h1{color:#667eea;text-align:center;font-size:32px;}");
            sb.AppendLine(".score{font-size:64px;font-weight:bold;text-align:center;color:#667eea;margin:30px 0;}");
            sb.AppendLine(".stats{display:flex;justify-content:space-around;margin:30px 0;}");
            sb.AppendLine(".stat-box{text-align:center;padding:20px;border-radius:10px;color:white;min-width:100px;}");
            sb.AppendLine(".critical{background:linear-gradient(135deg,#ff416c,#ff4b2b);}");
            sb.AppendLine(".high{background:linear-gradient(135deg,#f093fb,#f5576c);}");
            sb.AppendLine(".medium{background:linear-gradient(135deg,#4facfe,#00f2fe);}");
            sb.AppendLine(".low{background:linear-gradient(135deg,#43e97b,#38f9d7);}");
            sb.AppendLine("table{width:100%;border-collapse:collapse;margin:20px 0;}");
            sb.AppendLine("th,td{padding:12px;text-align:left;border-bottom:1px solid #3a3a5a;}");
            sb.AppendLine("th{background:#667eea;color:white;}");
            sb.AppendLine("</style></head><body>");
            sb.AppendLine("<div class='container'>");
            sb.AppendLine("<h1>AI Risk Assessment Report</h1>");
            sb.AppendLine($"<div class='score'>{_currentReport!.RiskScore:F1}/10</div>");
            sb.AppendLine($"<p style='text-align:center;color:#8b8b9a;'>Assessment Time: {_currentReport.AssessmentTime:yyyy-MM-dd HH:mm:ss}</p>");
            sb.AppendLine($"<p style='text-align:center;color:#8b8b9a;'>Target: {_portScanResults.FirstOrDefault()?.TargetIp ?? "Unknown"}</p>");

            sb.AppendLine("<h2 style='color:#667eea;margin:30px 0 20px 0;'>Risk Distribution</h2>");
            sb.AppendLine("<div class='stats'>");
            sb.AppendLine($"<div class='stat-box critical'><div style='font-size:32px;font-weight:bold;'>{_currentReport.RiskItems.Count(r => r.RiskLevel == RiskLevel.Critical)}</div><div>Critical</div></div>");
            sb.AppendLine($"<div class='stat-box high'><div style='font-size:32px;font-weight:bold;'>{_currentReport.RiskItems.Count(r => r.RiskLevel == RiskLevel.High)}</div><div>High</div></div>");
            sb.AppendLine($"<div class='stat-box medium'><div style='font-size:32px;font-weight:bold;'>{_currentReport.RiskItems.Count(r => r.RiskLevel == RiskLevel.Medium)}</div><div>Medium</div></div>");
            sb.AppendLine($"<div class='stat-box low'><div style='font-size:32px;font-weight:bold;'>{_currentReport.RiskItems.Count(r => r.RiskLevel == RiskLevel.Low)}</div><div>Low</div></div>");
            sb.AppendLine("</div>");

            sb.AppendLine("<h2 style='color:#667eea;margin:30px 0 20px 0;'>Risk Items</h2>");
            sb.AppendLine("<table><tr><th>Level</th><th>Target</th><th>Risk Item</th><th>Score</th></tr>");
            foreach (var item in _currentReport.RiskItems.OrderByDescending(r => r.RiskScore))
            {
                sb.AppendLine($"<tr><td style='color:{GetColorForLevel(item.RiskLevel)};font-weight:bold;'>{item.RiskLevel}</td><td>{item.Target}</td><td>{item.Title}</td><td>{item.RiskScore:F1}</td></tr>");
            }
            sb.AppendLine("</table>");

            sb.AppendLine("</div></body></html>");
            return sb.ToString();
        }

        private string GetColorForLevel(RiskLevel level)
        {
            return level switch
            {
                RiskLevel.Critical => "#ff416c",
                RiskLevel.High => "#f5576c",
                RiskLevel.Medium => "#00f2fe",
                RiskLevel.Low => "#43e97b",
                _ => "#8b8b9a"
            };
        }

        private void CloseButton_Click(object sender, RoutedEventArgs e)
        {
            Close();
        }
    }
}
