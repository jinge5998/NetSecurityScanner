using Microsoft.Win32;
using NetSecurityScanner.Services;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Shapes;
using IoPath = System.IO.Path;

namespace NetSecurityScanner.Views
{
    public partial class NetworkTopologyWindow : Window
    {
        private readonly NetworkTopologyService _topologyService;
        private List<NetworkDevice> _discoveredDevices;
        private CancellationTokenSource? _cancellationTokenSource;
        
        private Dictionary<string, TopologyNode> _topologyNodes = new();
        private List<TopologyEdge> _topologyEdges = new();
        private TopologyNode? _draggingNode;
        private Point _dragOffset;
        private double _zoomLevel = 1.0;

        public NetworkTopologyWindow()
        {
            InitializeComponent();
            _topologyService = new NetworkTopologyService();
            _discoveredDevices = new List<NetworkDevice>();
        }

        private async void StartDiscoveryButton_Click(object sender, RoutedEventArgs e)
        {
            var networkRange = NetworkRangeTextBox.Text.Trim();
            if (string.IsNullOrEmpty(networkRange))
            {
                MessageBox.Show("请输入网络范围", "提示", MessageBoxButton.OK, MessageBoxImage.Information);
                return;
            }

            StartDiscoveryButton.IsEnabled = false;
            StopDiscoveryButton.IsEnabled = true;
            DiscoveryProgressBar.Visibility = Visibility.Visible;
            StatusTextBlock.Text = "正在扫描网络...";
            _cancellationTokenSource = new CancellationTokenSource();
            _discoveredDevices = new List<NetworkDevice>();

            TopologyCanvas.Children.Clear();
            _topologyNodes.Clear();
            _topologyEdges.Clear();

            try
            {
                var progress = new Progress<string>(message =>
                {
                    StatusTextBlock.Text = message;
                });

                var allDevices = await _topologyService.DiscoverNetworkAsync(
                    networkRange, 
                    progress, 
                    _cancellationTokenSource.Token);

                _discoveredDevices = allDevices;
                DisplayResults();
                UpdateStatistics();
                BuildAndRenderTopology();
                UpdateSubnetInfoPanel();
                
                StatusTextBlock.Text = $"扫描完成，发现 {_discoveredDevices.Count} 个设备";
                ExportButton.IsEnabled = true;
            }
            catch (OperationCanceledException)
            {
                StatusTextBlock.Text = "扫描已取消";
                if (_discoveredDevices.Count > 0)
                {
                    DisplayResults();
                    UpdateStatistics();
                    BuildAndRenderTopology();
                    UpdateSubnetInfoPanel();
                    ExportButton.IsEnabled = true;
                }
            }
            catch (Exception ex)
            {
                StatusTextBlock.Text = $"扫描失败: {ex.Message}";
                MessageBox.Show($"扫描失败: {ex.Message}", "错误", MessageBoxButton.OK, MessageBoxImage.Error);
            }
            finally
            {
                StartDiscoveryButton.IsEnabled = true;
                StopDiscoveryButton.IsEnabled = false;
                DiscoveryProgressBar.Visibility = Visibility.Collapsed;
            }
        }

        private void StopDiscoveryButton_Click(object sender, RoutedEventArgs e)
        {
            _cancellationTokenSource?.Cancel();
            StatusTextBlock.Text = "正在停止扫描...";
        }

        private void DisplayResults()
        {
            // 准备显示数据
            var displayData = _discoveredDevices.Select(d => new DeviceDisplayInfo
            {
                IPAddress = d.IPAddress,
                Hostname = d.Hostname,
                DeviceType = d.DeviceType.ToString(),
                MacAddress = d.MacAddress ?? "N/A",
                OpenPortsCount = d.OpenPorts.Count,
                Status = d.Status.ToString(),
                OriginalDevice = d
            }).ToList();

            DevicesDataGrid.ItemsSource = displayData;
            DeviceCountTextBlock.Text = $"({_discoveredDevices.Count})";
        }

        private void UpdateStatistics()
        {
            var stats = _topologyService.GetNetworkStatistics(_discoveredDevices);
            
            TotalDevicesText.Text = stats.TotalDevices.ToString();
            OnlineDevicesText.Text = stats.OnlineDevices.ToString();
            TotalPortsText.Text = stats.TotalOpenPorts.ToString();
            SubnetCountText.Text = stats.SubnetDistribution.Count.ToString();

            if (RelationshipCountText != null)
                RelationshipCountText.Text = _topologyEdges.Count.ToString();
        }

        private void UpdateSubnetInfoPanel()
        {
            if (_discoveredDevices == null || _discoveredDevices.Count == 0)
            {
                if (SubnetInfoPanel != null)
                    SubnetInfoPanel.Visibility = Visibility.Collapsed;
                return;
            }

            SubnetListPanel.Children.Clear();

            var subnets = _discoveredDevices.GroupBy(d => GetSubnet(d.IPAddress)).ToList();
            if (subnets.Count <= 1)
            {
                SubnetInfoPanel.Visibility = Visibility.Collapsed;
                return;
            }

            SubnetInfoPanel.Visibility = Visibility.Visible;

            var subnetColors = new[]
            {
                Color.FromRgb(0xE8, 0xF8, 0xF5), Color.FromRgb(0xEB, 0xF5, 0xFB),
                Color.FromRgb(0xFD, 0xF2, 0xE9), Color.FromRgb(0xF4, 0xEC, 0xF7),
                Color.FromRgb(0xE8, 0xDA, 0xEF), Color.FromRgb(0xD5, 0xF5, 0xE3),
                Color.FromRgb(0xFE, 0xF9, 0xE7), Color.FromRgb(0xF9, 0xEB, 0xEA)
            };

            int colorIndex = 0;
            foreach (var subnet in subnets)
            {
                var itemPanel = new StackPanel { Margin = new Thickness(0, 5, 0, 5) };

                var headerPanel = new StackPanel { Orientation = Orientation.Horizontal };
                headerPanel.Children.Add(new Ellipse
                {
                    Width = 10, Height = 10,
                    Fill = new SolidColorBrush(subnetColors[colorIndex % subnetColors.Length]),
                    Margin = new Thickness(0, 0, 6, 0)
                });
                headerPanel.Children.Add(new TextBlock
                {
                    Text = subnet.Key,
                    FontWeight = FontWeights.SemiBold,
                    FontSize = 11
                });
                headerPanel.Children.Add(new TextBlock
                {
                    Text = $" ({subnet.Count()})",
                    Foreground = new SolidColorBrush(Color.FromRgb(0x7F, 0x8C, 0x8D)),
                    FontSize = 10
                });
                itemPanel.Children.Add(headerPanel);
                SubnetListPanel.Children.Add(itemPanel);
                colorIndex++;
            }
        }

        private void DevicesDataGrid_SelectionChanged(object sender, SelectionChangedEventArgs e)
        {
            if (DevicesDataGrid.SelectedItem is DeviceDisplayInfo info)
            {
                DisplayDeviceDetails(info.OriginalDevice);
            }
        }

        private void DisplayDeviceDetails(NetworkDevice device)
        {
            DeviceDetailPanel.Children.Clear();

            // 设备名称
            DeviceDetailPanel.Children.Add(new TextBlock
            {
                Text = device.Hostname,
                FontSize = 20,
                FontWeight = FontWeights.Bold,
                Margin = new Thickness(0, 0, 0, 10)
            });

            // 基本信息
            AddDetailItem("IP地址:", device.IPAddress);
            AddDetailItem("MAC地址:", device.MacAddress ?? "N/A");
            AddDetailItem("设备类型:", device.DeviceType.ToString());
            AddDetailItem("操作系统:", device.OperatingSystem ?? "Unknown");
            AddDetailItem("子网:", device.Subnet ?? "N/A");
            AddDetailItem("网关:", device.Gateway ?? "N/A");
            AddDetailItem("发现时间:", device.DiscoveryTime.ToString("yyyy-MM-dd HH:mm:ss"));

            // 开放端口
            if (device.OpenPorts.Any())
            {
                DeviceDetailPanel.Children.Add(new TextBlock
                {
                    Text = "开放端口:",
                    FontWeight = FontWeights.Bold,
                    Margin = new Thickness(0, 15, 0, 5)
                });

                var portsText = string.Join(", ", device.OpenPorts);
                DeviceDetailPanel.Children.Add(new TextBlock
                {
                    Text = portsText,
                    TextWrapping = TextWrapping.Wrap,
                    Foreground = Brushes.DarkBlue
                });
            }

            // 服务信息
            if (!string.IsNullOrEmpty(device.ServiceInfo))
            {
                AddDetailItem("服务信息:", device.ServiceInfo);
            }

            // 依赖关系
            if (device.Dependencies.Any())
            {
                DeviceDetailPanel.Children.Add(new TextBlock
                {
                    Text = "依赖设备:",
                    FontWeight = FontWeights.Bold,
                    Margin = new Thickness(0, 15, 0, 5)
                });

                foreach (var dep in device.Dependencies)
                {
                    DeviceDetailPanel.Children.Add(new TextBlock
                    {
                        Text = $"  • {dep}",
                        Foreground = Brushes.Gray
                    });
                }
            }
        }

        private void AddDetailItem(string label, string value)
        {
            var panel = new StackPanel { Orientation = Orientation.Horizontal, Margin = new Thickness(0, 3, 0, 3) };
            panel.Children.Add(new TextBlock { Text = label, FontWeight = FontWeights.SemiBold, Width = 100 });
            panel.Children.Add(new TextBlock { Text = value, TextWrapping = TextWrapping.Wrap });
            DeviceDetailPanel.Children.Add(panel);
        }

        private async void RefreshLayoutButton_Click(object sender, RoutedEventArgs e)
        {
            if (_discoveredDevices == null || _discoveredDevices.Count == 0)
            {
                MessageBox.Show("请先进行网络扫描", "提示", MessageBoxButton.OK, MessageBoxImage.Information);
                return;
            }
            StatusTextBlock.Text = "正在刷新布局...";
            await Task.Run(() => BuildAndRenderTopology());
            await Task.Yield();
            StatusTextBlock.Text = $"布局已刷新，{_topologyNodes.Count} 个节点，{_topologyEdges.Count} 条连线";
        }

        private void ZoomInButton_Click(object sender, RoutedEventArgs e)
        {
            _zoomLevel = Math.Min(_zoomLevel + 0.2, 3.0);
            TopologyScaleTransform.ScaleX = _zoomLevel;
            TopologyScaleTransform.ScaleY = _zoomLevel;
        }

        private void ZoomOutButton_Click(object sender, RoutedEventArgs e)
        {
            _zoomLevel = Math.Max(_zoomLevel - 0.2, 0.2);
            TopologyScaleTransform.ScaleX = _zoomLevel;
            TopologyScaleTransform.ScaleY = _zoomLevel;
        }

        private void ResetViewButton_Click(object sender, RoutedEventArgs e)
        {
            _zoomLevel = 1.0;
            TopologyScaleTransform.ScaleX = 1.0;
            TopologyScaleTransform.ScaleY = 1.0;
            TopologyTranslateTransform.X = 0;
            TopologyTranslateTransform.Y = 0;
            TopologyScrollViewer.ScrollToHome();
            if (_discoveredDevices != null && _discoveredDevices.Count > 0)
            {
                BuildAndRenderTopology();
            }
        }

        private void BuildAndRenderTopology()
        {
            if (_discoveredDevices == null || _discoveredDevices.Count == 0)
                return;

            TopologyCanvas.Children.Clear();
            _topologyNodes.Clear();
            _topologyEdges.Clear();

            double canvasWidth = TopologyCanvas.Width;
            double canvasHeight = TopologyCanvas.Height;
            double centerX = canvasWidth / 2;
            double centerY = canvasHeight / 2;

            if (_discoveredDevices.Count == 1)
            {
                var device = _discoveredDevices[0];
                _topologyNodes[device.IPAddress] = new TopologyNode
                {
                    Device = device,
                    X = centerX,
                    Y = centerY,
                    Vx = 0,
                    Vy = 0
                };
            }
            else
            {
                double radius = Math.Min(canvasWidth, canvasHeight) * 0.35;
                for (int i = 0; i < _discoveredDevices.Count; i++)
                {
                    var device = _discoveredDevices[i];
                    double angle = 2 * Math.PI * i / _discoveredDevices.Count - Math.PI / 2;
                    _topologyNodes[device.IPAddress] = new TopologyNode
                    {
                        Device = device,
                        X = centerX + radius * Math.Cos(angle),
                        Y = centerY + radius * Math.Sin(angle),
                        Vx = 0,
                        Vy = 0
                    };
                }
            }

            var relationshipSet = new HashSet<string>();

            foreach (var device in _discoveredDevices)
            {
                if (!string.IsNullOrEmpty(device.Gateway))
                {
                    string pair = device.IPAddress.CompareTo(device.Gateway) < 0 ? $"{device.IPAddress}-{device.Gateway}" : $"{device.Gateway}-{device.IPAddress}";
                    if (!relationshipSet.Contains(pair))
                    {
                        relationshipSet.Add(pair);
                        _topologyEdges.Add(new TopologyEdge
                        {
                            Source = device.IPAddress,
                            Target = device.Gateway,
                            RelationshipType = "网关"
                        });
                    }
                }

                foreach (var dep in device.Dependencies)
                {
                    string pair = device.IPAddress.CompareTo(dep) < 0 ? $"{device.IPAddress}-{dep}" : $"{dep}-{device.IPAddress}";
                    if (!relationshipSet.Contains(pair))
                    {
                        relationshipSet.Add(pair);
                        _topologyEdges.Add(new TopologyEdge
                        {
                            Source = device.IPAddress,
                            Target = dep,
                            RelationshipType = GetDependencyType(device, dep)
                        });
                    }
                }
            }

            RunForceDirectedLayout(100);
            DrawSubnetBackgrounds();
            DrawTopology();
            UpdateSubnetInfoPanel();
        }

        private void DrawSubnetBackgrounds()
        {
            var subnets = _discoveredDevices.GroupBy(d => GetSubnet(d.IPAddress)).ToList();
            if (subnets.Count <= 1) return;

            var subnetColors = new[]
            {
                Color.FromArgb(0x15, 0x00, 0xB8, 0x94),
                Color.FromArgb(0x15, 0x09, 0x84, 0xE3),
                Color.FromArgb(0x15, 0xE1, 0x70, 0x55),
                Color.FromArgb(0x15, 0x6C, 0x5C, 0xE7),
                Color.FromArgb(0x15, 0xF3, 0x9C, 0x12),
                Color.FromArgb(0x15, 0xE7, 0x4C, 0x3C),
                Color.FromArgb(0x15, 0x34, 0x98, 0xDB),
                Color.FromArgb(0x15, 0x2E, 0xCC, 0x71)
            };

            int colorIndex = 0;
            foreach (var subnet in subnets)
            {
                var subnetIps = subnet.Select(d => d.IPAddress).ToHashSet();
                double minX = double.MaxValue, maxX = double.MinValue;
                double minY = double.MaxValue, maxY = double.MinValue;

                foreach (var node in _topologyNodes.Values)
                {
                    if (subnetIps.Contains(node.Device.IPAddress))
                    {
                        if (node.X < minX) minX = node.X;
                        if (node.X > maxX) maxX = node.X;
                        if (node.Y < minY) minY = node.Y;
                        if (node.Y > maxY) maxY = node.Y;
                    }
                }

                if (minX == double.MaxValue) continue;

                double padding = 50;
                var rect = new System.Windows.Shapes.Rectangle
                {
                    Width = maxX - minX + padding * 2,
                    Height = maxY - minY + padding * 2,
                    Fill = new SolidColorBrush(subnetColors[colorIndex % subnetColors.Length]),
                    RadiusX = 15,
                    RadiusY = 15
                };

                Canvas.SetLeft(rect, minX - padding);
                Canvas.SetTop(rect, minY - padding);
                Canvas.SetZIndex(rect, -10);

                TopologyCanvas.Children.Add(rect);
                colorIndex++;
            }
        }

        private void RunForceDirectedLayout(int maxIterations)
        {
            var nodes = _topologyNodes.Values.ToList();
            int nodeCount = nodes.Count;
            if (nodeCount < 2) return;

            double k = Math.Sqrt((TopologyCanvas.Width * TopologyCanvas.Height) / nodeCount) * 0.8;
            double kSquared = k * k;
            double maxMove = 50.0;

            for (int iter = 0; iter < maxIterations; iter++)
            {
                double temperature = maxMove * (1.0 - (double)iter / maxIterations);

                for (int i = 0; i < nodeCount; i++)
                {
                    nodes[i].Fx = 0;
                    nodes[i].Fy = 0;
                }

                for (int i = 0; i < nodeCount; i++)
                {
                    for (int j = i + 1; j < nodeCount; j++)
                    {
                        double dx = nodes[i].X - nodes[j].X;
                        double dy = nodes[i].Y - nodes[j].Y;
                        double distSquared = dx * dx + dy * dy;
                        if (distSquared < 0.01) distSquared = 0.01;
                        double dist = Math.Sqrt(distSquared);
                        double force = kSquared / distSquared;

                        double fx = force * dx / dist;
                        double fy = force * dy / dist;
                        nodes[i].Fx += fx;
                        nodes[i].Fy += fy;
                        nodes[j].Fx -= fx;
                        nodes[j].Fy -= fy;
                    }
                }

                foreach (var edge in _topologyEdges)
                {
                    if (!_topologyNodes.ContainsKey(edge.Source) || !_topologyNodes.ContainsKey(edge.Target))
                        continue;

                    var source = _topologyNodes[edge.Source];
                    var target = _topologyNodes[edge.Target];
                    double dx = target.X - source.X;
                    double dy = target.Y - source.Y;
                    double dist = Math.Sqrt(dx * dx + dy * dy);
                    if (dist < 0.01) dist = 0.01;

                    double distSquared = dist * dist;
                    double force = (distSquared - kSquared) / (k * dist);
                    source.Fx += force * dx;
                    source.Fy += force * dy;
                    target.Fx -= force * dx;
                    target.Fy -= force * dy;
                }

                double centerX = TopologyCanvas.Width / 2;
                double centerY = TopologyCanvas.Height / 2;
                foreach (var node in nodes)
                {
                    double dx = node.X - centerX;
                    double dy = node.Y - centerY;
                    node.Fx -= dx * 0.01;
                    node.Fy -= dy * 0.01;
                }

                foreach (var node in nodes)
                {
                    double moveX = Math.Min(Math.Abs(node.Fx), temperature) * Math.Sign(node.Fx);
                    double moveY = Math.Min(Math.Abs(node.Fy), temperature) * Math.Sign(node.Fy);

                    if (node == _draggingNode) continue;

                    node.X += moveX;
                    node.Y += moveY;

                    node.X = Math.Max(80, Math.Min(TopologyCanvas.Width - 80, node.X));
                    node.Y = Math.Max(60, Math.Min(TopologyCanvas.Height - 60, node.Y));
                }
            }
        }

        private void DrawTopology()
        {
            DrawEdges();
            DrawNodes();

            NodeCountTextBlock.Text = _topologyNodes.Count.ToString();
            EdgeCountTextBlock.Text = _topologyEdges.Count.ToString();

            if (RelationshipCountText != null)
                RelationshipCountText.Text = _topologyEdges.Count.ToString();
        }

        private void DrawEdges()
        {
            foreach (var edge in _topologyEdges)
            {
                if (!_topologyNodes.ContainsKey(edge.Source) || !_topologyNodes.ContainsKey(edge.Target))
                    continue;

                var source = _topologyNodes[edge.Source];
                var target = _topologyNodes[edge.Target];

                var line = new Line
                {
                    X1 = source.X,
                    Y1 = source.Y,
                    X2 = target.X,
                    Y2 = target.Y,
                    Stroke = new SolidColorBrush(Color.FromArgb(0xAA, 0x34, 0x98, 0xDB)),
                    StrokeThickness = 2,
                    Tag = edge
                };
                TopologyCanvas.Children.Add(line);

                double midX = (source.X + target.X) / 2;
                double midY = (source.Y + target.Y) / 2;
                var label = new TextBlock
                {
                    Text = edge.RelationshipType,
                    FontSize = 10,
                    Foreground = new SolidColorBrush(Color.FromRgb(0x7F, 0x8C, 0x8D)),
                    Background = new SolidColorBrush(Color.FromArgb(0xE0, 0xFF, 0xFF, 0xFF))
                };
                Canvas.SetLeft(label, midX - 20);
                Canvas.SetTop(label, midY - 8);
                TopologyCanvas.Children.Add(label);
            }
        }

        private void DrawNodes()
        {
            foreach (var node in _topologyNodes.Values)
            {
                double nodeSize = 60;
                var mainColor = GetDeviceColor(node.Device.DeviceType);

                var border = new Border
                {
                    Width = nodeSize,
                    Height = nodeSize,
                    Background = new SolidColorBrush(mainColor),
                    CornerRadius = new CornerRadius(10),
                    BorderBrush = new SolidColorBrush(Colors.White),
                    BorderThickness = new Thickness(2),
                    Tag = node
                };

                var shadowEffect = new System.Windows.Media.Effects.DropShadowEffect
                {
                    Color = Color.FromArgb(0x40, 0x00, 0x00, 0x00),
                    BlurRadius = 8,
                    ShadowDepth = 3,
                    Direction = 315
                };
                border.Effect = shadowEffect;

                var contentPanel = new StackPanel
                {
                    HorizontalAlignment = HorizontalAlignment.Center,
                    VerticalAlignment = VerticalAlignment.Center,
                    Margin = new Thickness(5)
                };

                var iconText = new TextBlock
                {
                    Text = GetDeviceIcon(node.Device.DeviceType),
                    FontSize = 22,
                    HorizontalAlignment = HorizontalAlignment.Center,
                    Foreground = new SolidColorBrush(Colors.White)
                };
                contentPanel.Children.Add(iconText);

                var ipText = new TextBlock
                {
                    Text = node.Device.IPAddress,
                    FontSize = 9,
                    HorizontalAlignment = HorizontalAlignment.Center,
                    Foreground = new SolidColorBrush(Colors.White),
                    TextTrimming = TextTrimming.CharacterEllipsis,
                    MaxWidth = nodeSize - 10
                };
                contentPanel.Children.Add(ipText);

                border.Child = contentPanel;
                Canvas.SetLeft(border, node.X - nodeSize / 2);
                Canvas.SetTop(border, node.Y - nodeSize / 2);

                border.MouseLeftButtonDown += Node_MouseLeftButtonDown;
                border.MouseMove += Node_MouseMove;
                border.MouseLeftButtonUp += Node_MouseLeftButtonUp;
                border.InputBindings.Add(new MouseBinding(
                    new RelayCommand(() => Node_MouseDoubleClickHandler(node)),
                    new MouseGesture(MouseAction.LeftDoubleClick)));

                TopologyCanvas.Children.Add(border);
            }
        }

        private Color GetDeviceColor(DeviceType deviceType)
        {
            return deviceType switch
            {
                DeviceType.Router => Color.FromRgb(0xE6, 0x7E, 0x22),
                DeviceType.Switch => Color.FromRgb(0x34, 0x98, 0xDB),
                DeviceType.Windows => Color.FromRgb(0x00, 0x78, 0xD4),
                DeviceType.Linux => Color.FromRgb(0x00, 0xB8, 0x94),
                DeviceType.WebServer => Color.FromRgb(0xE7, 0x4C, 0x3C),
                DeviceType.Database => Color.FromRgb(0x9B, 0x59, 0xB6),
                DeviceType.MailServer => Color.FromRgb(0x2E, 0xCC, 0x71),
                DeviceType.DNS => Color.FromRgb(0xF3, 0x9C, 0x12),
                DeviceType.Printer => Color.FromRgb(0x95, 0xA5, 0xA6),
                DeviceType.VNC => Color.FromRgb(0xE8, 0x43, 0x93),
                DeviceType.Other => Color.FromRgb(0x34, 0x49, 0x5E),
                _ => Color.FromRgb(0x34, 0x98, 0xDB)
            };
        }

        private string GetDeviceIcon(DeviceType deviceType)
        {
            return deviceType switch
            {
                DeviceType.Router => "🌐",
                DeviceType.Switch => "🔀",
                DeviceType.Windows => "🖥️",
                DeviceType.Linux => "🐧",
                DeviceType.WebServer => "🌍",
                DeviceType.Database => "💾",
                DeviceType.MailServer => "📧",
                DeviceType.DNS => "🔤",
                DeviceType.Printer => "�️",
                DeviceType.VNC => "🖱️",
                DeviceType.Other => "�",
                _ => "💻"
            };
        }

        private string GetDependencyType(NetworkDevice device, string targetIp)
        {
            var targetDevice = _discoveredDevices.FirstOrDefault(d => d.IPAddress == targetIp);
            if (targetDevice == null) return "依赖";

            if (targetDevice.OpenPorts.Contains(53)) return "DNS";
            if (targetDevice.DeviceType == DeviceType.Database) return "数据库";
            if (targetDevice.DeviceType == DeviceType.MailServer) return "邮件";
            if (targetDevice.DeviceType == DeviceType.DNS) return "DNS";
            if (targetDevice.DeviceType == DeviceType.WebServer) return "HTTP";
            if (targetDevice.OpenPorts.Contains(443)) return "HTTPS";
            if (targetDevice.OpenPorts.Contains(80)) return "HTTP";
            if (targetDevice.OpenPorts.Contains(22)) return "SSH";
            if (targetDevice.OpenPorts.Contains(3389)) return "RDP";
            if (device.Gateway == targetIp) return "网关";
            return "依赖";
        }

        private void Node_MouseLeftButtonDown(object sender, MouseButtonEventArgs e)
        {
            if (sender is Border border && border.Tag is TopologyNode node)
            {
                _draggingNode = node;
                _dragOffset = e.GetPosition(TopologyCanvas);
                _dragOffset = new Point(_dragOffset.X - node.X, _dragOffset.Y - node.Y);
                border.CaptureMouse();
                e.Handled = true;
            }
        }

        private void Node_MouseMove(object sender, MouseEventArgs e)
        {
            if (_draggingNode != null && sender is Border border)
            {
                Point newPos = e.GetPosition(TopologyCanvas);
                _draggingNode.X = newPos.X - _dragOffset.X;
                _draggingNode.Y = newPos.Y - _dragOffset.Y;

                Canvas.SetLeft(border, _draggingNode.X - 30);
                Canvas.SetTop(border, _draggingNode.Y - 30);

                RedrawEdges();
                e.Handled = true;
            }
        }

        private void Node_MouseLeftButtonUp(object sender, MouseButtonEventArgs e)
        {
            if (sender is Border border)
            {
                _draggingNode = null;
                border.ReleaseMouseCapture();
                e.Handled = true;
            }
        }

        private void Node_MouseDoubleClick(object sender, MouseButtonEventArgs e)
        {
            if (sender is Border border && border.Tag is TopologyNode node)
            {
                DisplayDeviceDetails(node.Device);
                e.Handled = true;
            }
        }

        private void Node_MouseDoubleClickHandler(TopologyNode node)
        {
            DisplayDeviceDetails(node.Device);
        }

        private void RedrawEdges()
        {
            var edgesToRemove = TopologyCanvas.Children.OfType<Line>().ToList();
            var labelsToRemove = TopologyCanvas.Children.OfType<TextBlock>().ToList();

            foreach (var child in edgesToRemove.Concat<UIElement>(labelsToRemove))
            {
                TopologyCanvas.Children.Remove(child);
            }

            DrawEdges();
        }

        private async void ExportButton_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                if (_discoveredDevices == null || _discoveredDevices.Count == 0)
                {
                    MessageBox.Show("没有可导出的数据", "提示", MessageBoxButton.OK, MessageBoxImage.Information);
                    return;
                }

                var dialog = new SaveFileDialog
                {
                    Filter = "JSON文件|*.json|CSV文件|*.csv",
                    FileName = $"网络拓扑_{DateTime.Now:yyyyMMdd_HHmmss}",
                    Title = "导出网络拓扑"
                };

                if (dialog.ShowDialog() != true) return;

                string filePath = dialog.FileName;
                string extension = IoPath.GetExtension(filePath).ToLower();

                if (extension == ".json")
                {
                    await ExportToJsonAsync(filePath);
                }
                else if (extension == ".csv")
                {
                    await ExportToCsvAsync(filePath);
                }

                MessageBox.Show($"网络拓扑已导出到:\n{filePath}", "导出成功", MessageBoxButton.OK, MessageBoxImage.Information);
            }
            catch (Exception ex)
            {
                MessageBox.Show($"导出失败: {ex.Message}", "错误", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        private async void ExportImageButton_Click(object sender, RoutedEventArgs e)
        {
            await ExportTopologyAsImageAsync();
        }

        private async void AnalysisReportButton_Click(object sender, RoutedEventArgs e)
        {
            if (_discoveredDevices == null || _discoveredDevices.Count == 0)
            {
                MessageBox.Show("请先进行网络扫描", "提示", MessageBoxButton.OK, MessageBoxImage.Information);
                return;
            }
            await GenerateTopologyAnalysisReportAsync();
        }

        private void SearchTextBox_TextChanged(object sender, TextChangedEventArgs e)
        {
            string searchText = SearchTextBox?.Text?.Trim().ToLower() ?? "";

            if (string.IsNullOrEmpty(searchText))
            {
                foreach (var uiElement in TopologyCanvas.Children.OfType<Border>())
                {
                    uiElement.Opacity = 1.0;
                }
                foreach (var line in TopologyCanvas.Children.OfType<Line>())
                {
                    line.Opacity = 1.0;
                }
                return;
            }

            foreach (var uiElement in TopologyCanvas.Children.OfType<Border>())
            {
                if (uiElement.Tag is TopologyNode node)
                {
                    bool match = node.Device.IPAddress.ToLower().Contains(searchText) ||
                                 node.Device.Hostname.ToLower().Contains(searchText) ||
                                 node.Device.MacAddress.ToLower().Contains(searchText) ||
                                 node.Device.DeviceType.ToString().ToLower().Contains(searchText);
                    uiElement.Opacity = match ? 1.0 : 0.15;
                }
                else
                {
                    uiElement.Opacity = 1.0;
                }
            }

            foreach (var line in TopologyCanvas.Children.OfType<Line>())
            {
                line.Opacity = 0.3;
            }
        }

        private TopologyNode? _contextMenuNode;

        private void TopologyCanvas_MouseRightButtonDown(object sender, MouseButtonEventArgs e)
        {
            var position = e.GetPosition(TopologyCanvas);
            _contextMenuNode = null;

            foreach (var uiElement in TopologyCanvas.Children.OfType<Border>())
            {
                if (uiElement.Tag is TopologyNode node)
                {
                    var left = Canvas.GetLeft(uiElement);
                    var top = Canvas.GetTop(uiElement);
                    var rect = new System.Windows.Rect(left, top, uiElement.Width, uiElement.Height);
                    if (rect.Contains(position))
                    {
                        _contextMenuNode = node;
                        break;
                    }
                }
            }

            if (_contextMenuNode != null)
            {
                TopologyContextMenu.IsOpen = true;
                e.Handled = true;
            }
        }

        private void ContextMenuViewDetail_Click(object sender, RoutedEventArgs e)
        {
            if (_contextMenuNode != null)
            {
                DisplayDeviceDetails(_contextMenuNode.Device);
            }
        }

        private void ContextMenuHighlight_Click(object sender, RoutedEventArgs e)
        {
            if (_contextMenuNode == null) return;

            var connectedIps = new HashSet<string> { _contextMenuNode.Device.IPAddress };

            foreach (var edge in _topologyEdges)
            {
                if (edge.Source == _contextMenuNode.Device.IPAddress) connectedIps.Add(edge.Target);
                if (edge.Target == _contextMenuNode.Device.IPAddress) connectedIps.Add(edge.Source);
            }

            foreach (var uiElement in TopologyCanvas.Children.OfType<Border>())
            {
                if (uiElement.Tag is TopologyNode node)
                {
                    if (connectedIps.Contains(node.Device.IPAddress))
                    {
                        uiElement.Opacity = 1.0;
                        uiElement.BorderBrush = new SolidColorBrush(Colors.Gold);
                        uiElement.BorderThickness = new Thickness(3);
                    }
                    else
                    {
                        uiElement.Opacity = 0.3;
                    }
                }
            }

            foreach (var line in TopologyCanvas.Children.OfType<Line>())
            {
                if (line.Tag is TopologyEdge edge)
                {
                    if (edge.Source == _contextMenuNode.Device.IPAddress || edge.Target == _contextMenuNode.Device.IPAddress)
                    {
                        line.Opacity = 1.0;
                        line.StrokeThickness = 3;
                        line.Stroke = new SolidColorBrush(Color.FromRgb(0xE7, 0x4C, 0x3C));
                    }
                    else
                    {
                        line.Opacity = 0.1;
                    }
                }
            }
        }

        private Dictionary<string, bool> _hiddenNodes = new();

        private void ContextMenuHide_Click(object sender, RoutedEventArgs e)
        {
            if (_contextMenuNode == null) return;

            string ip = _contextMenuNode.Device.IPAddress;
            if (_hiddenNodes.ContainsKey(ip) && _hiddenNodes[ip])
            {
                _hiddenNodes[ip] = false;
            }
            else
            {
                _hiddenNodes[ip] = true;
            }

            foreach (var uiElement in TopologyCanvas.Children.OfType<Border>())
            {
                if (uiElement.Tag is TopologyNode node && node.Device.IPAddress == ip)
                {
                    uiElement.Visibility = _hiddenNodes[ip] ? Visibility.Collapsed : Visibility.Visible;
                }
            }

            foreach (var line in TopologyCanvas.Children.OfType<Line>())
            {
                if (line.Tag is TopologyEdge edge)
                {
                    bool sourceHidden = _hiddenNodes.ContainsKey(edge.Source) && _hiddenNodes[edge.Source];
                    bool targetHidden = _hiddenNodes.ContainsKey(edge.Target) && _hiddenNodes[edge.Target];
                    line.Visibility = (sourceHidden || targetHidden) ? Visibility.Collapsed : Visibility.Visible;
                }
            }
        }

        private void ContextMenuFitScreen_Click(object sender, RoutedEventArgs e)
        {
            ResetViewButton_Click(sender, e);
        }

        private async void ContextMenuExportImage_Click(object sender, RoutedEventArgs e)
        {
            await ExportTopologyAsImageAsync();
        }

        private async Task ExportTopologyAsImageAsync()
        {
            try
            {
                var dialog = new SaveFileDialog
                {
                    Filter = "PNG图片|*.png|JPEG图片|*.jpg",
                    FileName = $"网络拓扑图_{DateTime.Now:yyyyMMdd_HHmmss}",
                    Title = "导出拓扑图为图片"
                };

                if (dialog.ShowDialog() != true) return;

                double originalWidth = TopologyCanvas.Width;
                double originalHeight = TopologyCanvas.Height;

                double maxX = 0, maxY = 0;
                foreach (var uiElement in TopologyCanvas.Children.OfType<Border>())
                {
                    double x = Canvas.GetLeft(uiElement) + uiElement.Width;
                    double y = Canvas.GetTop(uiElement) + uiElement.Height;
                    if (x > maxX) maxX = x;
                    if (y > maxY) maxY = y;
                }

                double padding = 50;
                TopologyCanvas.Width = maxX + padding * 2;
                TopologyCanvas.Height = maxY + padding * 2;

                var rtb = new System.Windows.Media.Imaging.RenderTargetBitmap(
                    (int)TopologyCanvas.Width,
                    (int)TopologyCanvas.Height,
                    96, 96,
                    System.Windows.Media.PixelFormats.Pbgra32);

                TopologyCanvas.Measure(new System.Windows.Size(TopologyCanvas.Width, TopologyCanvas.Height));
                TopologyCanvas.Arrange(new System.Windows.Rect(0, 0, TopologyCanvas.Width, TopologyCanvas.Height));

                rtb.Render(TopologyCanvas);

                System.Windows.Media.Imaging.BitmapEncoder encoder;
                if (dialog.FileName.EndsWith(".png", StringComparison.OrdinalIgnoreCase))
                {
                    encoder = new System.Windows.Media.Imaging.PngBitmapEncoder();
                }
                else
                {
                    encoder = new System.Windows.Media.Imaging.JpegBitmapEncoder { QualityLevel = 95 };
                }

                encoder.Frames.Add(System.Windows.Media.Imaging.BitmapFrame.Create(rtb));

                using var stream = System.IO.File.Create(dialog.FileName);
                encoder.Save(stream);

                TopologyCanvas.Width = originalWidth;
                TopologyCanvas.Height = originalHeight;

                MessageBox.Show($"拓扑图已导出到:\n{dialog.FileName}", "导出成功", MessageBoxButton.OK, MessageBoxImage.Information);
            }
            catch (Exception ex)
            {
                MessageBox.Show($"导出图片失败: {ex.Message}", "错误", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        private async Task GenerateTopologyAnalysisReportAsync()
        {
            try
            {
                var content = new System.Text.StringBuilder();
                content.AppendLine("=====================================");
                content.AppendLine("网络拓扑分析报告");
                content.AppendLine($"生成时间: {DateTime.Now:yyyy-MM-dd HH:mm:ss}");
                content.AppendLine($"扫描范围: {NetworkRangeTextBox.Text}");
                content.AppendLine("=====================================");
                content.AppendLine();

                content.AppendLine("【网络概览】");
                content.AppendLine($"总设备数: {_discoveredDevices.Count}");
                content.AppendLine($"在线设备: {_discoveredDevices.Count(d => d.Status == DeviceStatus.Online)}");
                content.AppendLine($"开放端口总数: {_discoveredDevices.Sum(d => d.OpenPorts.Count)}");
                content.AppendLine($"设备关系数: {_topologyEdges.Count}");

                var subnets = _discoveredDevices.GroupBy(d => GetSubnet(d.IPAddress)).ToList();
                content.AppendLine($"子网数: {subnets.Count}");
                content.AppendLine();

                content.AppendLine("【设备类型分布】");
                var typeGroups = _discoveredDevices.GroupBy(d => d.DeviceType);
                foreach (var group in typeGroups)
                {
                    content.AppendLine($"  {group.Key}: {group.Count()} 台");
                }
                content.AppendLine();

                content.AppendLine("【子网详情】");
                foreach (var subnet in subnets)
                {
                    content.AppendLine($"\n  子网: {subnet.Key}");
                    content.AppendLine($"  设备数: {subnet.Count()}");
                    foreach (var device in subnet.OrderBy(d => d.IPAddress))
                    {
                        content.AppendLine($"    {device.IPAddress} - {device.Hostname} - {device.DeviceType} (端口: {string.Join(", ", device.OpenPorts)})");
                    }
                }
                content.AppendLine();

                content.AppendLine("【网络连接关系】");
                foreach (var edge in _topologyEdges)
                {
                    var sourceDevice = _discoveredDevices.FirstOrDefault(d => d.IPAddress == edge.Source);
                    var targetDevice = _discoveredDevices.FirstOrDefault(d => d.IPAddress == edge.Target);
                    content.AppendLine($"  {sourceDevice?.Hostname ?? edge.Source} ({edge.Source}) --[{edge.RelationshipType}]--> {targetDevice?.Hostname ?? edge.Target} ({edge.Target})");
                }
                content.AppendLine();

                content.AppendLine("【安全风险建议】");
                foreach (var device in _discoveredDevices.Where(d => d.OpenPorts.Count > 5))
                {
                    content.AppendLine($"  ⚠️ {device.IPAddress}: 开放端口过多({device.OpenPorts.Count}个)，建议审查不必要的服务");
                }
                foreach (var device in _discoveredDevices.Where(d => d.OpenPorts.Contains(23)))
                {
                    content.AppendLine($"  ⚠️ {device.IPAddress}: 开放Telnet端口(23)，建议改用SSH");
                }
                foreach (var device in _discoveredDevices.Where(d => d.OpenPorts.Contains(21)))
                {
                    content.AppendLine($"  ⚠️ {device.IPAddress}: 开放FTP端口(21)，建议改用SFTP");
                }

                var dialog = new SaveFileDialog
                {
                    Filter = "文本文件|*.txt",
                    FileName = $"网络拓扑分析报告_{DateTime.Now:yyyyMMdd_HHmmss}.txt",
                    Title = "保存分析报告"
                };

                if (dialog.ShowDialog() != true) return;

                await System.IO.File.WriteAllTextAsync(dialog.FileName, content.ToString(), Encoding.UTF8);
                MessageBox.Show($"分析报告已保存到:\n{dialog.FileName}", "导出成功", MessageBoxButton.OK, MessageBoxImage.Information);
            }
            catch (Exception ex)
            {
                MessageBox.Show($"生成报告失败: {ex.Message}", "错误", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        private string GetSubnet(string ipAddress)
        {
            var parts = ipAddress.Split('.');
            if (parts.Length == 4)
            {
                return $"{parts[0]}.{parts[1]}.{parts[2]}.0/24";
            }
            return "未知子网";
        }

        private async Task ExportToJsonAsync(string filePath)
        {
            var json = JsonSerializer.Serialize(_discoveredDevices, new JsonSerializerOptions
            {
                WriteIndented = true
            });
            await File.WriteAllTextAsync(filePath, json);
        }

        private async Task ExportToCsvAsync(string filePath)
        {
            var sb = new StringBuilder();
            sb.AppendLine("IP地址,主机名,设备类型,MAC地址,开放端口,子网,网关,发现时间");

            foreach (var device in _discoveredDevices)
            {
                var ports = string.Join(";", device.OpenPorts);
                sb.AppendLine($"{device.IPAddress},{device.Hostname},{device.DeviceType},{device.MacAddress},{ports},{device.Subnet},{device.Gateway},{device.DiscoveryTime:yyyy-MM-dd HH:mm:ss}");
            }

            await File.WriteAllTextAsync(filePath, sb.ToString());
        }

        private void CloseButton_Click(object sender, RoutedEventArgs e)
        {
            _cancellationTokenSource?.Cancel();
            Close();
        }
    }

    public class DeviceDisplayInfo
    {
        public string IPAddress { get; set; } = "";
        public string Hostname { get; set; } = "";
        public string DeviceType { get; set; } = "";
        public string MacAddress { get; set; } = "";
        public int OpenPortsCount { get; set; }
        public string Status { get; set; } = "";
        public NetworkDevice OriginalDevice { get; set; } = null!;
    }

    public class TopologyNode
    {
        public NetworkDevice Device { get; set; } = null!;
        public double X { get; set; }
        public double Y { get; set; }
        public double Vx { get; set; }
        public double Vy { get; set; }
        public double Fx { get; set; }
        public double Fy { get; set; }
    }

    public class TopologyEdge
    {
        public string Source { get; set; } = "";
        public string Target { get; set; } = "";
        public string RelationshipType { get; set; } = "";
    }

    public class RelayCommand : ICommand
    {
        private readonly Action _execute;
        private readonly Func<bool>? _canExecute;

        public RelayCommand(Action execute, Func<bool>? canExecute = null)
        {
            _execute = execute ?? throw new ArgumentNullException(nameof(execute));
            _canExecute = canExecute;
        }

        public bool CanExecute(object? parameter) => _canExecute?.Invoke() ?? true;
        public void Execute(object? parameter) => _execute();
#pragma warning disable CS0067 // 从不使用事件 CanExecuteChanged，但它是 ICommand 接口必需的
        public event EventHandler? CanExecuteChanged;
#pragma warning restore CS0067
    }
}
