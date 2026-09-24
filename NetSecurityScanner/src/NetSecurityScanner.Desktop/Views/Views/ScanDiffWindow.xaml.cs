using NetSecurityScanner.Models;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;

namespace NetSecurityScanner.Views
{
    public partial class ScanDiffWindow : Window
    {
        public ScanDiffWindow(CompleteScanResult scan1, CompleteScanResult scan2)
        {
            InitializeComponent();
            BuildVisualTree(scan1, scan2);
        }

        private void BuildVisualTree(CompleteScanResult scan1, CompleteScanResult scan2)
        {
            var rootGrid = (Grid)this.Content;
            rootGrid.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
            rootGrid.RowDefinitions.Add(new RowDefinition { Height = new GridLength(1, GridUnitType.Star) });

            // Header bar
            var headerBorder = new Border
            {
                Background = new SolidColorBrush(Color.FromRgb(0x2C, 0x3E, 0x50)),
                Padding = new Thickness(15, 10, 15, 10),
                CornerRadius = new CornerRadius(0)
            };
            var headerText = new TextBlock
            {
                Text = "📊 扫描差异对比",
                FontSize = 18,
                FontWeight = FontWeights.Bold,
                Foreground = Brushes.White
            };
            headerBorder.Child = headerText;
            Grid.SetRow(headerBorder, 0);
            rootGrid.Children.Add(headerBorder);

            // Main scroll viewer
            var scrollViewer = new ScrollViewer
            {
                VerticalScrollBarVisibility = ScrollBarVisibility.Auto,
                Margin = new Thickness(15)
            };
            Grid.SetRow(scrollViewer, 1);
            rootGrid.Children.Add(scrollViewer);

            var mainStack = new StackPanel();

            // Scan info comparison
            var infoBorder = new Border
            {
                BorderBrush = new SolidColorBrush(Color.FromRgb(0xBD, 0xC3, 0xC7)),
                BorderThickness = new Thickness(1),
                CornerRadius = new CornerRadius(6),
                Background = Brushes.White,
                Margin = new Thickness(0, 0, 0, 10)
            };
            var infoStack = new StackPanel { Margin = new Thickness(15) };
            infoStack.Children.Add(new TextBlock
            {
                Text = "扫描基本信息",
                FontWeight = FontWeights.Bold,
                FontSize = 14,
                Foreground = new SolidColorBrush(Color.FromRgb(0x2C, 0x3E, 0x50)),
                Margin = new Thickness(0, 0, 0, 10)
            });

            var infoGrid = new Grid();
            infoGrid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
            infoGrid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });

            // Left panel: Scan A
            var leftInfoStack = new StackPanel { Margin = new Thickness(0, 0, 5, 0) };
            leftInfoStack.Children.Add(new TextBlock
            {
                Text = "扫描 A",
                FontWeight = FontWeights.Bold,
                FontSize = 13,
                Foreground = new SolidColorBrush(Color.FromRgb(0x34, 0x98, 0xDB)),
                Margin = new Thickness(0, 0, 0, 5)
            });
            leftInfoStack.Children.Add(new TextBlock
            {
                Text = $"目标: {scan1.TargetIp}",
                FontSize = 12,
                Margin = new Thickness(0, 0, 0, 3)
            });
            leftInfoStack.Children.Add(new TextBlock
            {
                Text = $"时间: {scan1.ScanTime:yyyy-MM-dd HH:mm:ss}",
                FontSize = 12,
                Margin = new Thickness(0, 0, 0, 3)
            });
            leftInfoStack.Children.Add(new TextBlock
            {
                Text = $"类型: {scan1.ScanType}",
                FontSize = 12,
                Margin = new Thickness(0, 0, 0, 3)
            });
            leftInfoStack.Children.Add(new TextBlock
            {
                Text = $"开放端口: {scan1.OpenPortsCount}  漏洞数: {scan1.VulnerabilitiesCount}",
                FontSize = 12
            });
            Grid.SetColumn(leftInfoStack, 0);
            infoGrid.Children.Add(leftInfoStack);

            // Right panel: Scan B
            var rightInfoStack = new StackPanel { Margin = new Thickness(5, 0, 0, 0) };
            rightInfoStack.Children.Add(new TextBlock
            {
                Text = "扫描 B",
                FontWeight = FontWeights.Bold,
                FontSize = 13,
                Foreground = new SolidColorBrush(Color.FromRgb(0xE7, 0x4C, 0x3C)),
                Margin = new Thickness(0, 0, 0, 5)
            });
            rightInfoStack.Children.Add(new TextBlock
            {
                Text = $"目标: {scan2.TargetIp}",
                FontSize = 12,
                Margin = new Thickness(0, 0, 0, 3)
            });
            rightInfoStack.Children.Add(new TextBlock
            {
                Text = $"时间: {scan2.ScanTime:yyyy-MM-dd HH:mm:ss}",
                FontSize = 12,
                Margin = new Thickness(0, 0, 0, 3)
            });
            rightInfoStack.Children.Add(new TextBlock
            {
                Text = $"类型: {scan2.ScanType}",
                FontSize = 12,
                Margin = new Thickness(0, 0, 0, 3)
            });
            rightInfoStack.Children.Add(new TextBlock
            {
                Text = $"开放端口: {scan2.OpenPortsCount}  漏洞数: {scan2.VulnerabilitiesCount}",
                FontSize = 12
            });
            Grid.SetColumn(rightInfoStack, 1);
            infoGrid.Children.Add(rightInfoStack);

            infoStack.Children.Add(infoGrid);
            infoBorder.Child = infoStack;
            mainStack.Children.Add(infoBorder);

            // Compute diffs
            var ports1 = scan1.PortScanResults?.Where(p => p.Status == "开放").Select(p => p.PortNumber).ToHashSet() ?? new HashSet<int>();
            var ports2 = scan2.PortScanResults?.Where(p => p.Status == "开放").Select(p => p.PortNumber).ToHashSet() ?? new HashSet<int>();
            var newOpenPorts = ports2.Except(ports1).OrderBy(p => p).ToList();
            var closedPorts = ports1.Except(ports2).OrderBy(p => p).ToList();

            var vulns1 = scan1.VulnerabilityResults?.Select(v => v.CveId ?? v.Name).ToHashSet() ?? new HashSet<string>();
            var vulns2 = scan2.VulnerabilityResults?.Select(v => v.CveId ?? v.Name).ToHashSet() ?? new HashSet<string>();
            var newVulns = scan2.VulnerabilityResults?.Where(v => !vulns1.Contains(v.CveId ?? v.Name)).ToList() ?? new List<VulnerabilityResult>();
            var fixedVulns = scan1.VulnerabilityResults?.Where(v => !vulns2.Contains(v.CveId ?? v.Name)).ToList() ?? new List<VulnerabilityResult>();

            // Port diff section
            var portBorder = new Border
            {
                BorderBrush = new SolidColorBrush(Color.FromRgb(0xBD, 0xC3, 0xC7)),
                BorderThickness = new Thickness(1),
                CornerRadius = new CornerRadius(6),
                Background = Brushes.White,
                Margin = new Thickness(0, 0, 0, 10)
            };
            var portStack = new StackPanel { Margin = new Thickness(15) };
            portStack.Children.Add(new TextBlock
            {
                Text = "🔌 端口差异",
                FontWeight = FontWeights.Bold,
                FontSize = 14,
                Foreground = new SolidColorBrush(Color.FromRgb(0x2C, 0x3E, 0x50)),
                Margin = new Thickness(0, 0, 0, 10)
            });

            var portGrid = new Grid();
            portGrid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
            portGrid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });

            // New open ports (green)
            var newPortsStack = new StackPanel { Margin = new Thickness(0, 0, 5, 0) };
            newPortsStack.Children.Add(new TextBlock
            {
                Text = $"新增开放端口 ({newOpenPorts.Count})",
                FontWeight = FontWeights.SemiBold,
                FontSize = 12,
                Foreground = new SolidColorBrush(Color.FromRgb(0x27, 0xAE, 0x60)),
                Margin = new Thickness(0, 0, 0, 5)
            });
            var newPortsList = new ListBox { Height = 120 };
            foreach (var port in newOpenPorts)
            {
                var service = scan2.PortScanResults?.FirstOrDefault(p => p.PortNumber == port && p.Status == "开放")?.Service ?? "";
                newPortsList.Items.Add(CreatePortItem(port, service, true));
            }
            if (newOpenPorts.Count == 0)
                newPortsList.Items.Add(new TextBlock { Text = "无新增开放端口", Foreground = new SolidColorBrush(Color.FromRgb(0x95, 0xA5, 0xA6)), FontSize = 11 });
            newPortsStack.Children.Add(newPortsList);
            Grid.SetColumn(newPortsStack, 0);
            portGrid.Children.Add(newPortsStack);

            // Closed ports (red)
            var closedPortsStack = new StackPanel { Margin = new Thickness(5, 0, 0, 0) };
            closedPortsStack.Children.Add(new TextBlock
            {
                Text = $"已关闭端口 ({closedPorts.Count})",
                FontWeight = FontWeights.SemiBold,
                FontSize = 12,
                Foreground = new SolidColorBrush(Color.FromRgb(0xE7, 0x4C, 0x3C)),
                Margin = new Thickness(0, 0, 0, 5)
            });
            var closedPortsList = new ListBox { Height = 120 };
            foreach (var port in closedPorts)
            {
                var service = scan1.PortScanResults?.FirstOrDefault(p => p.PortNumber == port && p.Status == "开放")?.Service ?? "";
                closedPortsList.Items.Add(CreatePortItem(port, service, false));
            }
            if (closedPorts.Count == 0)
                closedPortsList.Items.Add(new TextBlock { Text = "无已关闭端口", Foreground = new SolidColorBrush(Color.FromRgb(0x95, 0xA5, 0xA6)), FontSize = 11 });
            closedPortsStack.Children.Add(closedPortsList);
            Grid.SetColumn(closedPortsStack, 1);
            portGrid.Children.Add(closedPortsStack);

            portStack.Children.Add(portGrid);
            portBorder.Child = portStack;
            mainStack.Children.Add(portBorder);

            // Vulnerability diff section
            var vulnBorder = new Border
            {
                BorderBrush = new SolidColorBrush(Color.FromRgb(0xBD, 0xC3, 0xC7)),
                BorderThickness = new Thickness(1),
                CornerRadius = new CornerRadius(6),
                Background = Brushes.White
            };
            var vulnStack = new StackPanel { Margin = new Thickness(15) };
            vulnStack.Children.Add(new TextBlock
            {
                Text = "⚠️ 漏洞差异",
                FontWeight = FontWeights.Bold,
                FontSize = 14,
                Foreground = new SolidColorBrush(Color.FromRgb(0x2C, 0x3E, 0x50)),
                Margin = new Thickness(0, 0, 0, 10)
            });

            var vulnGrid = new Grid();
            vulnGrid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
            vulnGrid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });

            // New vulnerabilities (red)
            var newVulnsStack = new StackPanel { Margin = new Thickness(0, 0, 5, 0) };
            newVulnsStack.Children.Add(new TextBlock
            {
                Text = $"新增漏洞 ({newVulns.Count})",
                FontWeight = FontWeights.SemiBold,
                FontSize = 12,
                Foreground = new SolidColorBrush(Color.FromRgb(0xE7, 0x4C, 0x3C)),
                Margin = new Thickness(0, 0, 0, 5)
            });
            var newVulnsList = new ListBox { Height = 150 };
            foreach (var vuln in newVulns)
            {
                newVulnsList.Items.Add(CreateVulnItem(vuln, false));
            }
            if (newVulns.Count == 0)
                newVulnsList.Items.Add(new TextBlock { Text = "无新增漏洞", Foreground = new SolidColorBrush(Color.FromRgb(0x95, 0xA5, 0xA6)), FontSize = 11 });
            newVulnsStack.Children.Add(newVulnsList);
            Grid.SetColumn(newVulnsStack, 0);
            vulnGrid.Children.Add(newVulnsStack);

            // Fixed vulnerabilities (green)
            var fixedVulnsStack = new StackPanel { Margin = new Thickness(5, 0, 0, 0) };
            fixedVulnsStack.Children.Add(new TextBlock
            {
                Text = $"已修复漏洞 ({fixedVulns.Count})",
                FontWeight = FontWeights.SemiBold,
                FontSize = 12,
                Foreground = new SolidColorBrush(Color.FromRgb(0x27, 0xAE, 0x60)),
                Margin = new Thickness(0, 0, 0, 5)
            });
            var fixedVulnsList = new ListBox { Height = 150 };
            foreach (var vuln in fixedVulns)
            {
                fixedVulnsList.Items.Add(CreateVulnItem(vuln, true));
            }
            if (fixedVulns.Count == 0)
                fixedVulnsList.Items.Add(new TextBlock { Text = "无已修复漏洞", Foreground = new SolidColorBrush(Color.FromRgb(0x95, 0xA5, 0xA6)), FontSize = 11 });
            fixedVulnsStack.Children.Add(fixedVulnsList);
            Grid.SetColumn(fixedVulnsStack, 1);
            vulnGrid.Children.Add(fixedVulnsStack);

            vulnStack.Children.Add(vulnGrid);
            vulnBorder.Child = vulnStack;
            mainStack.Children.Add(vulnBorder);

            scrollViewer.Content = mainStack;
        }

        private StackPanel CreatePortItem(int port, string service, bool isNew)
        {
            var panel = new StackPanel { Orientation = Orientation.Horizontal };
            var portText = new TextBlock
            {
                Text = $"端口 {port}",
                FontWeight = FontWeights.SemiBold,
                FontSize = 12,
                Foreground = isNew
                    ? new SolidColorBrush(Color.FromRgb(0x27, 0xAE, 0x60))
                    : new SolidColorBrush(Color.FromRgb(0xE7, 0x4C, 0x3C)),
                Margin = new Thickness(0, 0, 8, 0)
            };
            panel.Children.Add(portText);
            if (!string.IsNullOrEmpty(service))
            {
                panel.Children.Add(new TextBlock
                {
                    Text = $"({service})",
                    FontSize = 11,
                    Foreground = new SolidColorBrush(Color.FromRgb(0x7F, 0x8C, 0x8D))
                });
            }
            return panel;
        }

        private StackPanel CreateVulnItem(VulnerabilityResult vuln, bool isFixed)
        {
            var panel = new StackPanel();
            var headerPanel = new StackPanel { Orientation = Orientation.Horizontal };
            var nameText = new TextBlock
            {
                Text = vuln.Name,
                FontWeight = FontWeights.SemiBold,
                FontSize = 12,
                Foreground = isFixed
                    ? new SolidColorBrush(Color.FromRgb(0x27, 0xAE, 0x60))
                    : new SolidColorBrush(Color.FromRgb(0xE7, 0x4C, 0x3C)),
                Margin = new Thickness(0, 0, 8, 0)
            };
            headerPanel.Children.Add(nameText);
            if (!string.IsNullOrEmpty(vuln.CveId))
            {
                headerPanel.Children.Add(new TextBlock
                {
                    Text = vuln.CveId,
                    FontSize = 11,
                    Foreground = new SolidColorBrush(Color.FromRgb(0x7F, 0x8C, 0x8D))
                });
            }
            panel.Children.Add(headerPanel);
            var detail = "";
            if (vuln.Port.HasValue) detail += $"端口: {vuln.Port}  ";
            if (!string.IsNullOrEmpty(vuln.RiskLevel)) detail += $"风险: {vuln.RiskLevel}";
            if (!string.IsNullOrEmpty(detail))
            {
                panel.Children.Add(new TextBlock
                {
                    Text = detail,
                    FontSize = 11,
                    Foreground = new SolidColorBrush(Color.FromRgb(0x95, 0xA5, 0xA6)),
                    Margin = new Thickness(0, 2, 0, 0)
                });
            }
            return panel;
        }
    }
}
