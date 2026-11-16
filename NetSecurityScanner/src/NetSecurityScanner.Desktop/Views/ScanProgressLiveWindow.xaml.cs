using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using System.Windows.Threading;
using NetSecurityScanner.Models;

namespace NetSecurityScanner.Views
{
    public partial class ScanProgressLiveWindow : Window
    {
        private readonly CancellationTokenSource _cts = new();
        private readonly Progress<ScanPhaseProgress> _progressAdapter;
        private readonly Dictionary<ScanPhase, Border> _phaseChipMap = new();
        private readonly List<int> _allDiscoveredPorts = new();
        private DateTime _startTime = DateTime.Now;
        private string _target = string.Empty;
        private ScanPhase? _currentPhase;

        /// <summary>ComprehensiveScanService 用的进度回调（线程安全，捕获到 UI 线程）</summary>
        public IProgress<ScanPhaseProgress> Progress => _progressAdapter;

        /// <summary>ComprehensiveScanService 用的取消令牌</summary>
        public CancellationToken CancellationToken => _cts.Token;

        public ScanProgressLiveWindow()
        {
            InitializeComponent();
            _progressAdapter = new Progress<ScanPhaseProgress>(OnProgressReport);
            InitPhaseStepper();
            Loaded += (s, e) => _startTime = DateTime.Now;
            Closed += (s, e) =>
            {
                try { if (!_cts.IsCancellationRequested) _cts.Cancel(); } catch (ObjectDisposedException) { /* CTS 已释放 */ }
                _cts.Dispose();
            };
        }

        /// <summary>由 MainWindow.StartScan_Click 在 Show() 前注入目标</summary>
        public void SetTarget(string target)
        {
            _target = target ?? string.Empty;
            TargetText.Text = string.IsNullOrEmpty(_target) ? "" : $"目标: {_target}";
        }

        private void InitPhaseStepper()
        {
            PhaseStepper.Items.Clear();
            _phaseChipMap.Clear();

            var phases = new (ScanPhase Phase, string Icon, string Name)[]
            {
                (ScanPhase.HostDiscovery, "🔍", "存活"),
                (ScanPhase.TcpPortScan, "🔌", "TCP"),
                (ScanPhase.UdpPortScan, "📡", "UDP"),
                (ScanPhase.ServiceDetection, "🧬", "服务"),
                (ScanPhase.VulnerabilityScan, "🛡️", "漏洞"),
                (ScanPhase.PluginScan, "🧩", "插件"),
            };

            foreach (var (phase, icon, name) in phases)
            {
                var border = BuildPhaseChip(icon, name, isActive: false, isDone: false);
                _phaseChipMap[phase] = border;
                PhaseStepper.Items.Add(border);
            }
        }

        private Border BuildPhaseChip(string icon, string name, bool isActive, bool isDone)
        {
            var border = new Border
            {
                CornerRadius = new CornerRadius(12),
                Padding = new Thickness(10, 5, 10, 5),
                Margin = new Thickness(0, 0, 6, 0),
                BorderThickness = new Thickness(1),
                Background = new SolidColorBrush(Color.FromRgb(0xEC, 0xEF, 0xF1)),
                BorderBrush = new SolidColorBrush(Color.FromRgb(0xD0, 0xD7, 0xDE))
            };
            ApplyPhaseStyle(border, isActive, isDone);

            var sp = new StackPanel { Orientation = Orientation.Horizontal };
            sp.Children.Add(new TextBlock
            {
                Text = isDone ? "✅" : icon,
                FontSize = 12,
                VerticalAlignment = VerticalAlignment.Center
            });
            sp.Children.Add(new TextBlock
            {
                Text = " " + name,
                FontSize = 12,
                FontWeight = isActive ? FontWeights.Bold : FontWeights.Normal,
                Foreground = isActive ? Brushes.White
                            : isDone ? new SolidColorBrush(Color.FromRgb(0x27, 0xAE, 0x60))
                            : new SolidColorBrush(Color.FromRgb(0x7F, 0x8C, 0x8D)),
                VerticalAlignment = VerticalAlignment.Center
            });
            border.Child = sp;
            return border;
        }

        private static void ApplyPhaseStyle(Border border, bool isActive, bool isDone)
        {
            if (isActive)
            {
                border.Background = new SolidColorBrush(Color.FromRgb(0x34, 0x98, 0xDB));
                border.BorderBrush = new SolidColorBrush(Color.FromRgb(0x29, 0x80, 0xB9));
            }
            else if (isDone)
            {
                border.Background = new SolidColorBrush(Color.FromRgb(0xE8, 0xF8, 0xF5));
                border.BorderBrush = new SolidColorBrush(Color.FromRgb(0x27, 0xAE, 0x60));
            }
            else
            {
                border.Background = new SolidColorBrush(Color.FromRgb(0xEC, 0xEF, 0xF1));
                border.BorderBrush = new SolidColorBrush(Color.FromRgb(0xD0, 0xD7, 0xDE));
            }
        }

        private void OnProgressReport(ScanPhaseProgress p)
        {
            // Progress<T> 自动捕获 SynchronizationContext，本应在 UI 线程
            if (!Dispatcher.CheckAccess())
            {
                Dispatcher.Invoke(() => OnProgressReport(p));
                return;
            }
            ApplyProgress(p);
        }

        private void ApplyProgress(ScanPhaseProgress p)
        {
            _currentPhase = p.Phase;

            // 主进度条
            MainProgressBar.Value = p.Progress;
            PercentText.Text = $"{p.Progress}%";
            StatusText.Text = p.Message ?? string.Empty;

            // 子进度条
            SubProgressBar.Value = p.SubProgress;
            CurrentPhaseText.Text = $"▶ {p.PhaseName}";
            CurrentItemText.Text = string.IsNullOrEmpty(p.CurrentItem) ? "" : p.CurrentItem;

            // 已用时间
            var elapsed = TimeSpan.FromMilliseconds(p.ElapsedMs);
            ElapsedText.Text = $"已用 {(int)elapsed.TotalMinutes}:{elapsed.Seconds:D2}";

            // 剩余时间估算
            if (p.EstimatedRemainingMs > 0)
            {
                var remaining = TimeSpan.FromMilliseconds(p.EstimatedRemainingMs);
                RemainingText.Text = $"剩余 ~{(int)remaining.TotalMinutes}:{remaining.Seconds:D2}";
            }
            else
            {
                RemainingText.Text = "剩余 --:--";
            }

            // 阶段步骤条
            UpdatePhaseStepper(p.Phase);

            // 已发现端口列表
            if (p.DiscoveredPorts != null && p.DiscoveredPorts.Count > 0)
            {
                foreach (var port in p.DiscoveredPorts)
                {
                    if (!_allDiscoveredPorts.Contains(port))
                    {
                        _allDiscoveredPorts.Add(port);
                    }
                }
                RefreshPortList();
            }
        }

        private void UpdatePhaseStepper(ScanPhase current)
        {
            var order = new[] {
                ScanPhase.HostDiscovery,
                ScanPhase.TcpPortScan,
                ScanPhase.UdpPortScan,
                ScanPhase.ServiceDetection,
                ScanPhase.VulnerabilityScan,
                ScanPhase.PluginScan,
            };
            int currentIdx = Array.IndexOf(order, current);

            foreach (var (phase, border) in _phaseChipMap)
            {
                int idx = Array.IndexOf(order, phase);
                bool isActive = phase == current;
                bool isDone = idx < currentIdx;
                ApplyPhaseStyle(border, isActive, isDone);
                // 重置 chip 内部文本
                if (border.Child is StackPanel sp && sp.Children.Count >= 2)
                {
                    if (sp.Children[0] is TextBlock iconTb)
                    {
                        var (icon, _, _) = GetPhaseInfo(phase);
                        iconTb.Text = isDone ? "✅" : icon;
                    }
                    if (sp.Children[1] is TextBlock nameTb)
                    {
                        nameTb.FontWeight = isActive ? FontWeights.Bold : FontWeights.Normal;
                        nameTb.Foreground = isActive ? Brushes.White
                            : isDone ? new SolidColorBrush(Color.FromRgb(0x27, 0xAE, 0x60))
                            : new SolidColorBrush(Color.FromRgb(0x7F, 0x8C, 0x8D));
                    }
                }
            }
        }

        private static (string Icon, string Name, ScanPhase _) GetPhaseInfo(ScanPhase phase) => phase switch
        {
            ScanPhase.HostDiscovery => ("🔍", "存活", ScanPhase.HostDiscovery),
            ScanPhase.TcpPortScan => ("🔌", "TCP", ScanPhase.TcpPortScan),
            ScanPhase.UdpPortScan => ("📡", "UDP", ScanPhase.UdpPortScan),
            ScanPhase.ServiceDetection => ("🧬", "服务", ScanPhase.ServiceDetection),
            ScanPhase.VulnerabilityScan => ("🛡️", "漏洞", ScanPhase.VulnerabilityScan),
            ScanPhase.PluginScan => ("🧩", "插件", ScanPhase.PluginScan),
            _ => ("⏳", "处理", phase)
        };

        private void RefreshPortList()
        {
            PortCountText.Text = $"{_allDiscoveredPorts.Count} 个";
            DiscoveredPortsList.ItemsSource = null;
            DiscoveredPortsList.ItemsSource = _allDiscoveredPorts.OrderBy(p => p).Select(p => $"  •  {p}").ToList();
        }

        private void CancelButton_Click(object sender, RoutedEventArgs e)
        {
            try { _cts.Cancel(); } catch { }
            CancelButton.IsEnabled = false;
            CancelButton.Content = "⏳ 正在取消...";
        }
    }
}