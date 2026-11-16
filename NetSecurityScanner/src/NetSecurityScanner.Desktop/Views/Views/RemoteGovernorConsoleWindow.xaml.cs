using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Input;
using System.Windows.Media;
using NetSecurityScanner.Models;
using NetSecurityScanner.Services;

namespace NetSecurityScanner.Views
{
    /// <summary>
    /// 远程管控台（v7 - RemoteGovernorConsoleWindow）
    /// 职责：
    ///   1. 展示 Remote API 入口 URL（基址 + 健康检查/状态/插件/策略/告警/追踪接口）
    ///   2. 一键生成临时 JWT（1h / 2h / 8h / 24h TTL）
    ///   3. 复制 JWT 到剪贴板（STA + Win32 退避重试，与 LicenseDialog 同源）
    ///   4. 打开默认浏览器到 BaseUrl（健康检查页）
    ///   5. 最近 10 条 Remote API 审计记录（基于 PluginSecurityService 审计日志过滤）
    /// </summary>
    public partial class RemoteGovernorConsoleWindow : Window
    {
        private readonly PluginGovernor _governor;

        // ====== 顶部：API URL ======
        private TextBlock _apiUrlTextBlock;
        private TextBlock _apiStatusTextBlock;
        private Button _openBrowserButton;

        // ====== 中部：JWT 生成 ======
        private TextBox _userTextBox;
        private TextBox _jwtOutputTextBox;
        private TextBlock _jwtTtlTextBlock;
        private TextBlock _jwtGeneratedAtTextBlock;
        private Button _copyJwtButton;
        private string _currentJwt = string.Empty;

        // ====== 底部：审计记录 ======
        private DataGrid _auditGrid;
        private TextBlock _auditSummaryTextBlock;
        private Button _refreshAuditButton;

        public RemoteGovernorConsoleWindow()
        {
            Title = "远程管控台";
            Width = 700;
            Height = 550;
            WindowStartupLocation = WindowStartupLocation.CenterOwner;
            Background = Brushes.White;
            MinWidth = 660;
            MinHeight = 480;
            ResizeMode = ResizeMode.CanResize;

            _governor = PluginGovernor.Instance;

            BuildUI();

            KeyDown += (s, e) =>
            {
                if (e.Key == Key.F5) _ = ReloadAuditAsync();
                else if (e.Key == Key.Escape) Close();
            };

            Loaded += async (s, e) =>
            {
                try
                {
                    await ReloadAuditAsync();
                }
                catch (Exception ex)
                {
                    System.Diagnostics.Debug.WriteLine($"[RemoteGovernorConsole] 加载失败: {ex.Message}");
                }
            };

            Closed += (s, e) => { /* 单例 Governor 不关闭 */ };
        }

        // ================ UI 构建（纯 C#）================
        private void BuildUI()
        {
            var root = new DockPanel();

            // 顶部 Header
            var header = BuildHeader();
            DockPanel.SetDock(header, Dock.Top);
            root.Children.Add(header);

            // 底部状态栏
            var status = BuildStatusBar();
            DockPanel.SetDock(status, Dock.Bottom);
            root.Children.Add(status);

            // 中部 Grid：API 信息 / JWT 生成 / 审计记录
            var center = new Grid { Margin = new Thickness(10) };
            center.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
            center.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
            center.RowDefinitions.Add(new RowDefinition { Height = new GridLength(1, GridUnitType.Star) });

            // Row 0: API URL
            var apiSection = BuildApiSection();
            Grid.SetRow(apiSection, 0);
            center.Children.Add(apiSection);

            // Row 1: JWT 生成
            var jwtSection = BuildJwtSection();
            Grid.SetRow(jwtSection, 1);
            center.Children.Add(jwtSection);

            // Row 2: 审计记录
            var auditSection = BuildAuditSection();
            Grid.SetRow(auditSection, 2);
            center.Children.Add(auditSection);

            root.Children.Add(center);

            Content = root;
        }

        private Border BuildHeader()
        {
            var border = new Border
            {
                Background = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#2C3E50")),
                Padding = new Thickness(15, 10, 15, 10)
            };
            var panel = new StackPanel { Orientation = Orientation.Horizontal };
            panel.Children.Add(new TextBlock
            {
                Text = "🌐  远程管控台",
                Foreground = Brushes.White,
                FontWeight = FontWeights.Bold,
                FontSize = 16,
                VerticalAlignment = VerticalAlignment.Center
            });

            _apiStatusTextBlock = new TextBlock
            {
                Text = "● --",
                Foreground = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#95A5A6")),
                FontWeight = FontWeights.SemiBold,
                VerticalAlignment = VerticalAlignment.Center,
                Margin = new Thickness(15, 0, 0, 0)
            };
            panel.Children.Add(_apiStatusTextBlock);

            border.Child = panel;
            return border;
        }

        private Border BuildStatusBar()
        {
            var border = new Border
            {
                Background = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#ECF0F1")),
                Padding = new Thickness(15, 6, 15, 6)
            };
            var panel = new StackPanel { Orientation = Orientation.Horizontal, HorizontalAlignment = HorizontalAlignment.Right };

            var closeBtn = new Button
            {
                Content = "关闭",
                Width = 80,
                Height = 28,
                Cursor = Cursors.Hand
            };
            closeBtn.Click += (s, e) => Close();
            panel.Children.Add(closeBtn);

            border.Child = panel;
            return border;
        }

        // ---------- Row 0: API 信息 ----------
        private Border BuildApiSection()
        {
            var border = new Border
            {
                Background = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#ECF0F1")),
                CornerRadius = new CornerRadius(6),
                Padding = new Thickness(12, 10, 12, 10),
                Margin = new Thickness(0, 0, 0, 8)
            };
            var stack = new StackPanel();

            var titleRow = new StackPanel { Orientation = Orientation.Horizontal };
            titleRow.Children.Add(new TextBlock
            {
                Text = "API 入口 URL",
                FontWeight = FontWeights.Bold,
                Foreground = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#2C3E50")),
                VerticalAlignment = VerticalAlignment.Center
            });
            titleRow.Children.Add(new TextBlock
            {
                Text = "  （HttpListener 仅监听本地回环，可结合 SSH 端口转发对外暴露）",
                FontSize = 11,
                Foreground = Brushes.Gray,
                VerticalAlignment = VerticalAlignment.Center
            });
            stack.Children.Add(titleRow);

            var urlRow = new StackPanel { Orientation = Orientation.Horizontal, Margin = new Thickness(0, 6, 0, 0) };
            _apiUrlTextBlock = new TextBlock
            {
                Text = SafeBaseUrl(),
                FontFamily = new FontFamily("Consolas"),
                FontSize = 13,
                Foreground = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#3498DB")),
                VerticalAlignment = VerticalAlignment.Center,
                TextWrapping = TextWrapping.Wrap
            };
            urlRow.Children.Add(_apiUrlTextBlock);

            _openBrowserButton = new Button
            {
                Content = "🌍 打开浏览器",
                Width = 120,
                Height = 26,
                Margin = new Thickness(15, 0, 0, 0),
                Background = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#3498DB")),
                Foreground = Brushes.White,
                BorderThickness = new Thickness(0),
                Cursor = Cursors.Hand
            };
            _openBrowserButton.Click += OpenBrowserButton_Click;
            urlRow.Children.Add(_openBrowserButton);

            stack.Children.Add(urlRow);

            // 提示
            stack.Children.Add(new TextBlock
            {
                Text = "可用端点：/api/v7/health, /governor/status, /plugins, /security/policy, /plugins/{id}/quarantine|release, /traces/{id}, /alerts/recent",
                FontSize = 10,
                Foreground = Brushes.Gray,
                Margin = new Thickness(0, 6, 0, 0),
                TextWrapping = TextWrapping.Wrap
            });

            border.Child = stack;
            return border;
        }

        // ---------- Row 1: JWT 生成 ----------
        private Border BuildJwtSection()
        {
            var border = new Border
            {
                Background = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#ECF0F1")),
                CornerRadius = new CornerRadius(6),
                Padding = new Thickness(12, 10, 12, 10),
                Margin = new Thickness(0, 0, 0, 8)
            };
            var stack = new StackPanel();

            stack.Children.Add(new TextBlock
            {
                Text = "生成临时 JWT（HS256）",
                FontWeight = FontWeights.Bold,
                Foreground = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#2C3E50"))
            });

            // 用户名输入 + TTL 按钮
            var row1 = new StackPanel { Orientation = Orientation.Horizontal, Margin = new Thickness(0, 8, 0, 0) };
            row1.Children.Add(new TextBlock
            {
                Text = "用户:",
                VerticalAlignment = VerticalAlignment.Center,
                Margin = new Thickness(0, 0, 5, 0)
            });
            _userTextBox = new TextBox
            {
                Text = SessionContext.Instance.Current?.Username ?? "admin",
                Width = 140,
                Height = 26,
                VerticalContentAlignment = VerticalAlignment.Center,
                Margin = new Thickness(0, 0, 15, 0)
            };
            row1.Children.Add(_userTextBox);

            row1.Children.Add(new TextBlock
            {
                Text = "有效期:",
                VerticalAlignment = VerticalAlignment.Center,
                Margin = new Thickness(0, 0, 5, 0)
            });

            // 4 个 TTL 按钮
            var ttls = new (string Label, TimeSpan Span)[] {
                ("1h", TimeSpan.FromHours(1)),
                ("2h", TimeSpan.FromHours(2)),
                ("8h", TimeSpan.FromHours(8)),
                ("24h", TimeSpan.FromHours(24)),
            };
            foreach (var (label, span) in ttls)
            {
                var btn = new Button
                {
                    Content = label,
                    Width = 46,
                    Height = 26,
                    Margin = new Thickness(0, 0, 5, 0),
                    Background = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#3498DB")),
                    Foreground = Brushes.White,
                    BorderThickness = new Thickness(0),
                    Cursor = Cursors.Hand,
                    Tag = span
                };
                btn.Click += GenerateJwtButton_Click;
                row1.Children.Add(btn);
            }

            stack.Children.Add(row1);

            // JWT 输出
            var row2 = new StackPanel { Orientation = Orientation.Horizontal, Margin = new Thickness(0, 8, 0, 0) };
            _jwtOutputTextBox = new TextBox
            {
                IsReadOnly = true,
                FontFamily = new FontFamily("Consolas"),
                FontSize = 11,
                Height = 28,
                VerticalContentAlignment = VerticalAlignment.Center,
                Text = "（点击上方 TTL 按钮生成 JWT）",
                Foreground = Brushes.Gray,
                Background = Brushes.White
            };
            row2.Children.Add(_jwtOutputTextBox);

            _copyJwtButton = new Button
            {
                Content = "📋 复制 JWT",
                Width = 110,
                Height = 28,
                Margin = new Thickness(8, 0, 0, 0),
                Background = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#27AE60")),
                Foreground = Brushes.White,
                BorderThickness = new Thickness(0),
                Cursor = Cursors.Hand,
                IsEnabled = false
            };
            _copyJwtButton.Click += CopyJwtButton_Click;
            row2.Children.Add(_copyJwtButton);

            stack.Children.Add(row2);

            // TTL / 生成时间提示
            var row3 = new StackPanel { Orientation = Orientation.Horizontal, Margin = new Thickness(0, 4, 0, 0) };
            _jwtTtlTextBlock = new TextBlock
            {
                Text = "TTL: --",
                FontSize = 11,
                Foreground = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#2C3E50")),
                VerticalAlignment = VerticalAlignment.Center
            };
            row3.Children.Add(_jwtTtlTextBlock);
            row3.Children.Add(new TextBlock
            {
                Text = "    ",
                VerticalAlignment = VerticalAlignment.Center
            });
            _jwtGeneratedAtTextBlock = new TextBlock
            {
                Text = "",
                FontSize = 11,
                Foreground = Brushes.Gray,
                VerticalAlignment = VerticalAlignment.Center
            };
            row3.Children.Add(_jwtGeneratedAtTextBlock);
            stack.Children.Add(row3);

            // 用法提示
            stack.Children.Add(new TextBlock
            {
                Text = "使用方式：curl -H \"Authorization: Bearer <token>\" http://127.0.0.1:9530/api/v7/governor/status",
                FontSize = 10,
                Foreground = Brushes.Gray,
                FontFamily = new FontFamily("Consolas"),
                Margin = new Thickness(0, 6, 0, 0),
                TextWrapping = TextWrapping.Wrap
            });

            border.Child = stack;
            return border;
        }

        // ---------- Row 2: 审计记录 ----------
        private Border BuildAuditSection()
        {
            var border = new Border
            {
                Background = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#ECF0F1")),
                CornerRadius = new CornerRadius(6),
                Padding = new Thickness(12, 10, 12, 10)
            };
            var dock = new DockPanel();

            // 标题栏
            var titleBar = new StackPanel { Orientation = Orientation.Horizontal, Margin = new Thickness(0, 0, 0, 6) };
            titleBar.Children.Add(new TextBlock
            {
                Text = "最近 10 条 RemoteApi 审计记录",
                FontWeight = FontWeights.Bold,
                Foreground = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#2C3E50")),
                VerticalAlignment = VerticalAlignment.Center
            });

            _auditSummaryTextBlock = new TextBlock
            {
                Text = "（共 0 条）",
                FontSize = 11,
                Foreground = Brushes.Gray,
                VerticalAlignment = VerticalAlignment.Center,
                Margin = new Thickness(10, 0, 0, 0)
            };
            titleBar.Children.Add(_auditSummaryTextBlock);

            _refreshAuditButton = new Button
            {
                Content = "🔄 刷新",
                Width = 80,
                Height = 24,
                Margin = new Thickness(10, 0, 0, 0),
                Background = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#3498DB")),
                Foreground = Brushes.White,
                BorderThickness = new Thickness(0),
                Cursor = Cursors.Hand,
                HorizontalAlignment = HorizontalAlignment.Right
            };
            _refreshAuditButton.Click += async (s, e) => await ReloadAuditAsync();
            titleBar.Children.Add(_refreshAuditButton);

            DockPanel.SetDock(titleBar, Dock.Top);
            dock.Children.Add(titleBar);

            // DataGrid
            _auditGrid = new DataGrid
            {
                AutoGenerateColumns = false,
                IsReadOnly = true,
                CanUserAddRows = false,
                CanUserDeleteRows = false,
                HeadersVisibility = DataGridHeadersVisibility.Column,
                RowHeight = 24,
                GridLinesVisibility = DataGridGridLinesVisibility.Horizontal,
                Background = Brushes.White,
                BorderBrush = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#BDC3C7")),
                BorderThickness = new Thickness(1)
            };
            _auditGrid.Columns.Add(new DataGridTextColumn { Header = "时间", Binding = new Binding("Timestamp") { StringFormat = "yyyy-MM-dd HH:mm:ss" }, Width = new DataGridLength(140) });
            _auditGrid.Columns.Add(new DataGridTextColumn { Header = "动作", Binding = new Binding("Action"), Width = new DataGridLength(170) });
            _auditGrid.Columns.Add(new DataGridTextColumn { Header = "结果", Binding = new Binding("Result"), Width = new DataGridLength(70) });
            _auditGrid.Columns.Add(new DataGridTextColumn { Header = "操作人", Binding = new Binding("Operator"), Width = new DataGridLength(80) });
            _auditGrid.Columns.Add(new DataGridTextColumn { Header = "详情", Binding = new Binding("Detail"), Width = new DataGridLength(1, DataGridLengthUnitType.Star) });
            dock.Children.Add(_auditGrid);

            border.Child = dock;
            return border;
        }

        // ================ 事件处理 ================
        private void GenerateJwtButton_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                if (_governor?.RemoteApi == null)
                {
                    MessageBox.Show("PluginGovernor 尚未初始化，无法生成 JWT。", "错误", MessageBoxButton.OK, MessageBoxImage.Error);
                    return;
                }
                if (sender is not Button btn || btn.Tag is not TimeSpan ttl) return;
                var user = string.IsNullOrWhiteSpace(_userTextBox.Text) ? "admin" : _userTextBox.Text.Trim();

                var jwt = _governor.RemoteApi.GenerateTempJwt(user, ttl);
                _currentJwt = jwt;
                _jwtOutputTextBox.Text = jwt;
                _jwtOutputTextBox.Foreground = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#2C3E50"));
                _jwtTtlTextBlock.Text = $"TTL: {ttl.TotalHours:0.#}h";
                _jwtGeneratedAtTextBlock.Text = $"生成时间: {DateTime.Now:yyyy-MM-dd HH:mm:ss}    过期: {DateTime.Now.Add(ttl):yyyy-MM-dd HH:mm:ss}";
                _copyJwtButton.IsEnabled = true;
            }
            catch (Exception ex)
            {
                MessageBox.Show($"生成 JWT 失败: {ex.Message}", "错误", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        private void CopyJwtButton_Click(object sender, RoutedEventArgs e)
        {
            if (string.IsNullOrEmpty(_currentJwt))
            {
                MessageBox.Show("请先生成 JWT。", "提示", MessageBoxButton.OK, MessageBoxImage.Information);
                return;
            }

            if (!TrySetClipboardText(_currentJwt, out var ex))
            {
                MessageBox.Show(
                    $"复制到剪贴板失败：{ex?.Message}\n\n请手动复制以下 JWT：\n{_currentJwt}",
                    "复制失败",
                    MessageBoxButton.OK,
                    MessageBoxImage.Warning);
                return;
            }

            var original = _copyJwtButton.Content;
            _copyJwtButton.Content = "✅ 已复制";
            _copyJwtButton.Background = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#27AE60"));

            var timer = new System.Windows.Threading.DispatcherTimer { Interval = TimeSpan.FromSeconds(2) };
            timer.Tick += (s, args) =>
            {
                _copyJwtButton.Content = original;
                _copyJwtButton.Background = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#27AE60"));
                timer.Stop();
            };
            timer.Start();
        }

        private void OpenBrowserButton_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                var url = SafeBaseUrl();
                if (string.IsNullOrEmpty(url))
                {
                    MessageBox.Show("BaseUrl 不可用。", "错误", MessageBoxButton.OK, MessageBoxImage.Error);
                    return;
                }
                // 默认浏览器打开（health 端点）
                Process.Start(new ProcessStartInfo
                {
                    FileName = url.TrimEnd('/') + "/api/v7/health",
                    UseShellExecute = true
                });
            }
            catch (Exception ex)
            {
                MessageBox.Show($"打开浏览器失败: {ex.Message}", "错误", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        // ================ 数据加载 ================
        private async Task ReloadAuditAsync()
        {
            try
            {
                if (_governor?.Security == null)
                {
                    UpdateApiStatus("Governor 未初始化", "#E74C3C");
                    return;
                }
                var api = _governor.RemoteApi;
                if (api != null && api.IsRunning)
                {
                    UpdateApiStatus("● 运行中", "#27AE60");
                    _apiUrlTextBlock.Text = api.BaseUrl;
                }
                else
                {
                    UpdateApiStatus("● 未启动", "#E74C3C");
                    _apiUrlTextBlock.Text = SafeBaseUrl();
                }

                // 拉取今日 + 昨日审计（合并后过滤），最多 10 条 RemoteApi 相关
                var all = new List<PluginAuditEntry>();
                try { all.AddRange(_governor.Security.GetAuditEntries(DateTime.Today)); } catch { }
                try { all.AddRange(_governor.Security.GetAuditEntries(DateTime.Today.AddDays(-1))); } catch { }

                var remoteEntries = all
                    .Where(e => !string.IsNullOrEmpty(e.Action) && e.Action.IndexOf("RemoteApi", StringComparison.OrdinalIgnoreCase) >= 0)
                    .OrderByDescending(e => e.Timestamp)
                    .Take(10)
                    .ToList();

                _auditGrid.ItemsSource = remoteEntries;
                _auditSummaryTextBlock.Text = $"（共 {remoteEntries.Count} 条）";
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"[RemoteGovernorConsole] 刷新审计失败: {ex.Message}");
            }
            await Task.CompletedTask;
        }

        private void UpdateApiStatus(string text, string colorHex)
        {
            _apiStatusTextBlock.Text = text;
            _apiStatusTextBlock.Foreground = new SolidColorBrush((Color)ColorConverter.ConvertFromString(colorHex));
        }

        private string SafeBaseUrl()
        {
            try
            {
                var api = _governor?.RemoteApi;
                if (api == null) return "http://127.0.0.1:9530";
                return api.BaseUrl ?? "http://127.0.0.1:9530";
            }
            catch
            {
                return "http://127.0.0.1:9530";
            }
        }

        // ===================== Win32 剪贴板原生 API（与 LicenseDialog 同源）=====================
        private const uint CF_UNICODETEXT = 13;

        [DllImport("user32.dll", SetLastError = true)]
        private static extern bool OpenClipboard(IntPtr hWndNewOwner);

        [DllImport("user32.dll", SetLastError = true)]
        private static extern bool CloseClipboard();

        [DllImport("user32.dll", SetLastError = true)]
        private static extern bool EmptyClipboard();

        [DllImport("user32.dll", SetLastError = true)]
        private static extern IntPtr SetClipboardData(uint uFormat, IntPtr hMem);

        /// <summary>
        /// 健壮地设置剪贴板文本：
        /// 1) 在专用 STA 线程上跑 Win32 OpenClipboard/SetClipboardData，避免阻塞 UI；
        /// 2) OpenClipboard 失败时按 0/30/60/120 ms 退避重试 4 次；
        /// 3) 全部失败返回异常。
        /// </summary>
        private static bool TrySetClipboardText(string text, out Exception? lastError)
        {
            lastError = null;
            if (text == null) text = string.Empty;

            var win32Ok = false;
            Exception? win32Error = null;
            var staThread = new Thread(() =>
            {
                try
                {
                    win32Ok = SetClipboardTextWin32(text, out var ex);
                    if (!win32Ok) win32Error = ex;
                }
                catch (Exception ex)
                {
                    win32Error = ex;
                }
            });
            staThread.SetApartmentState(ApartmentState.STA);
            staThread.IsBackground = true;
            staThread.Start();
            staThread.Join();

            if (win32Ok) return true;
            lastError = win32Error;
            return false;
        }

        private static bool SetClipboardTextWin32(string text, out Exception? lastError)
        {
            lastError = null;
            IntPtr hGlobal = IntPtr.Zero;
            try
            {
                // UTF-16 LE + 终止 NUL
                byte[] bytes = Encoding.Unicode.GetBytes(text + "\0");
                hGlobal = Marshal.AllocHGlobal(bytes.Length); // 用托管安全的 AllocHGlobal，等同 GMEM_MOVEABLE 句柄
                if (hGlobal == IntPtr.Zero)
                {
                    lastError = new InvalidOperationException("AllocHGlobal 失败");
                    return false;
                }
                Marshal.Copy(bytes, 0, hGlobal, bytes.Length);

                int[] delaysMs = { 0, 30, 60, 120 };
                bool opened = false;
                int lastErr = 0;
                for (int i = 0; i < delaysMs.Length; i++)
                {
                    if (delaysMs[i] > 0) Thread.Sleep(delaysMs[i]);
                    if (OpenClipboard(IntPtr.Zero))
                    {
                        opened = true;
                        break;
                    }
                    lastErr = Marshal.GetLastWin32Error();
                }
                if (!opened)
                {
                    lastError = new InvalidOperationException(
                        $"OpenClipboard 失败 (Win32 错误码={lastErr}, 0x{lastErr:X})");
                    return false;
                }

                try
                {
                    EmptyClipboard();
                    if (SetClipboardData(CF_UNICODETEXT, hGlobal) == IntPtr.Zero)
                    {
                        lastError = new InvalidOperationException(
                            $"SetClipboardData 失败 (Win32 错误码={Marshal.GetLastWin32Error()})");
                        return false;
                    }
                    // 句柄所有权已转移给系统
                    hGlobal = IntPtr.Zero;
                    return true;
                }
                finally
                {
                    CloseClipboard();
                }
            }
            catch (Exception ex)
            {
                lastError = ex;
                return false;
            }
            finally
            {
                if (hGlobal != IntPtr.Zero)
                {
                    // 系统未接管，释放
                    try { Marshal.FreeHGlobal(hGlobal); } catch { }
                }
            }
        }
    }
}
