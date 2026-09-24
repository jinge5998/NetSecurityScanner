using System;
using System.Media;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Animation;
using System.Windows.Threading;

namespace NetSecurityScanner.Services
{
    /// <summary>
    /// 操作反馈和通知服务 - P0优先级：操作反馈动画
    /// 提供成功/错误/加载状态的可视化反馈
    /// </summary>
    public class NotificationService
    {
        private readonly DispatcherTimer _autoHideTimer;
        private Window? _ownerWindow;
        
        // 通知面板控件引用（在MainWindow中设置）
        public Grid? NotificationPanel { get; set; }
        public TextBlock? NotificationText { get; set; }
        public ProgressBar? LoadingProgressBar { get; set; }

        public NotificationService()
        {
            _autoHideTimer = new DispatcherTimer();
            _autoHideTimer.Interval = TimeSpan.FromSeconds(2);
            _autoHideTimer.Tick += AutoHideTimer_Tick;
        }

        /// <summary>
        /// 设置宿主窗口（用于显示通知）
        /// </summary>
        public void SetOwnerWindow(Window window)
        {
            _ownerWindow = window;
        }

        #region 成功/错误提示

        /// <summary>
        /// 显示成功提示（绿色，2秒后自动消失）
        /// </summary>
        public void ShowSuccess(string message, int autoHideSeconds = 2)
        {
            ShowNotification(message, NotificationType.Success, autoHideSeconds);
        }

        /// <summary>
        /// 显示错误提示（红色，需手动关闭）
        /// </summary>
        public void ShowError(string message)
        {
            ShowNotification(message, NotificationType.Error, 0); // 不自动隐藏
        }

        /// <summary>
        /// 显示警告提示（橙色）
        /// </summary>
        public void ShowWarning(string message, int autoHideSeconds = 3)
        {
            ShowNotification(message, NotificationType.Warning, autoHideSeconds);
        }

        /// <summary>
        /// 显示信息提示（蓝色）
        /// </summary>
        public void ShowInfo(string message, int autoHideSeconds = 2)
        {
            ShowNotification(message, NotificationType.Info, autoHideSeconds);
        }

        /// <summary>
        /// 显示加载状态（带进度条或转圈动画）
        /// </summary>
        public void ShowLoading(string message = "处理中...")
        {
            ShowNotification(message, NotificationType.Loading, 0);
        }

        /// <summary>
        /// 更新加载消息
        /// </summary>
        public void UpdateLoadingMessage(string message)
        {
            if (_ownerWindow != null && NotificationText != null)
            {
                _ownerWindow.Dispatcher.Invoke(() =>
                {
                    NotificationText.Text = message;
                });
            }
        }

        /// <summary>
        /// 隐藏通知
        /// </summary>
        public void HideNotification()
        {
            _autoHideTimer.Stop();
            
            if (_ownerWindow != null && NotificationPanel != null)
            {
                _ownerWindow.Dispatcher.Invoke(() =>
                {
                    var fadeOut = new DoubleAnimation
                    {
                        To = 0,
                        Duration = TimeSpan.FromMilliseconds(300),
                        EasingFunction = new QuadraticEase { EasingMode = EasingMode.EaseIn }
                    };

                    fadeOut.Completed += (s, e) =>
                    {
                        if (NotificationPanel != null)
                        {
                            NotificationPanel.Visibility = Visibility.Collapsed;
                            NotificationPanel.Opacity = 1;
                        }
                    };

                    NotificationPanel.BeginAnimation(UIElement.OpacityProperty, fadeOut);
                });
            }
        }

        #endregion

        #region 私有实现

        private enum NotificationType
        {
            Success,
            Error,
            Warning,
            Info,
            Loading
        }

        private void ShowNotification(string message, NotificationType type, int autoHideSeconds)
        {
            if (_ownerWindow == null || NotificationPanel == null || NotificationText == null)
            {
                // 如果UI元素未设置，使用MessageBox作为后备方案
                ShowFallbackNotification(message, type);
                return;
            }

            _ownerWindow.Dispatcher.Invoke(() =>
            {
                // 停止之前的自动隐藏计时器
                _autoHideTimer.Stop();

                // 设置通知内容和样式
                NotificationText.Text = message;
                
                // 根据类型设置颜色和图标
                var backgroundColor = type switch
                {
                    NotificationType.Success => new SolidColorBrush(Color.FromArgb(230, 46, 204, 113)),   // 绿色
                    NotificationType.Error => new SolidColorBrush(Color.FromArgb(230, 231, 76, 60)),     // 红色
                    NotificationType.Warning => new SolidColorBrush(Color.FromArgb(230, 243, 156, 18)),  // 橙色
                    NotificationType.Info => new SolidColorBrush(Color.FromArgb(230, 52, 152, 219)),     // 蓝色
                    NotificationType.Loading => new SolidColorBrush(Color.FromArgb(230, 52, 73, 94)),    // 深灰色
                    _ => new SolidColorBrush(Color.FromArgb(230, 149, 165, 166))                         // 灰色
                };

                NotificationPanel.Background = backgroundColor;
                NotificationText.Foreground = Brushes.White;

                // 显示/隐藏进度条
                if (LoadingProgressBar != null)
                {
                    LoadingProgressBar.Visibility = type == NotificationType.Loading 
                        ? Visibility.Visible 
                        : Visibility.Collapsed;
                    
                    if (type == NotificationType.Loading)
                    {
                        // 启动进度条动画
                        LoadingProgressBar.IsIndeterminate = true;
                    }
                }

                // 显示通知面板并播放淡入动画
                NotificationPanel.Visibility = Visibility.Visible;
                NotificationPanel.Opacity = 0;

                var fadeIn = new DoubleAnimation
                {
                    To = 1,
                    Duration = TimeSpan.FromMilliseconds(300),
                    EasingFunction = new QuadraticEase { EasingMode = EasingMode.EaseOut }
                };

                NotificationPanel.BeginAnimation(UIElement.OpacityProperty, fadeIn);

                // 播放提示音（仅对成功和错误）
                PlayNotificationSound(type);

                // 设置自动隐藏（如果需要）
                if (autoHideSeconds > 0)
                {
                    _autoHideTimer.Interval = TimeSpan.FromSeconds(autoHideSeconds);
                    _autoHideTimer.Start();
                }
            });
        }

        private void AutoHideTimer_Tick(object? sender, EventArgs e)
        {
            _autoHideTimer.Stop();
            HideNotification();
        }

        private void ShowFallbackNotification(string message, NotificationType type)
        {
            var imageIcon = type switch
            {
                NotificationType.Success => MessageBoxImage.Information,
                NotificationType.Error => MessageBoxImage.Error,
                NotificationType.Warning => MessageBoxImage.Warning,
                _ => MessageBoxImage.None
            };

            // 在UI线程上显示MessageBox
            Application.Current.Dispatcher.Invoke(() =>
            {
                MessageBox.Show(message, GetNotificationTitle(type), MessageBoxButton.OK, imageIcon);
            });
        }

        private string GetNotificationTitle(NotificationType type)
        {
            return type switch
            {
                NotificationType.Success => "✓ 操作成功",
                NotificationType.Error => "✗ 操作失败",
                NotificationType.Warning => "⚠ 警告",
                NotificationType.Info => "ℹ 信息",
                NotificationType.Loading => "⏳ 处理中...",
                _ => "提示"
            };
        }

        private void PlayNotificationSound(NotificationType type)
        {
            try
            {
                switch (type)
                {
                    case NotificationType.Success:
                        SystemSounds.Asterisk.Play();
                        break;
                    case NotificationType.Error:
                        SystemSounds.Hand.Play();
                        break;
                    case NotificationType.Warning:
                        SystemSounds.Exclamation.Play();
                        break;
                    default:
                        // 其他类型不播放声音
                        break;
                }
            }
            catch
            {
                // 忽略声音播放错误
            }
        }

        #endregion

        #region 确认对话框

        /// <summary>
        /// 显示确认对话框（带二次确认功能）
        /// </summary>
        public bool ShowConfirmation(string message, string title = "确认操作")
        {
            return Application.Current.Dispatcher.Invoke(() =>
            {
                var result = MessageBox.Show(
                    _ownerWindow ?? Application.Current.MainWindow,
                    message,
                    title,
                    MessageBoxButton.YesNo,
                    MessageBoxImage.Question);

                return result == MessageBoxResult.Yes;
            });
        }

        /// <summary>
        /// 显示危险操作确认对话框（需要输入确认文字）
        /// </summary>
        public bool ShowDangerousConfirmation(string actionDescription, string confirmText = "DELETE")
        {
            return Application.Current.Dispatcher.Invoke(() =>
            {
                // 创建自定义输入对话框窗口
                var dialog = new Window
                {
                    Title = "⚠️ 危险操作确认",
                    Width = 400,
                    Height = 250,
                    WindowStartupLocation = WindowStartupLocation.CenterOwner,
                    Owner = _ownerWindow ?? Application.Current.MainWindow,
                    ResizeMode = ResizeMode.NoResize,
                    WindowStyle = WindowStyle.SingleBorderWindow
                };

                var grid = new Grid();
                grid.Margin = new Thickness(20);
                
                grid.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto }); // 标题
                grid.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto }); // 警告文字
                grid.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto }); // 输入框标签
                grid.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto }); // 输入框
                grid.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto }); // 按钮

                // 警告标题
                var warningText = new TextBlock
                {
                    Text = "⚠️ 此操作不可撤销！",
                    FontSize = 16,
                    FontWeight = FontWeights.Bold,
                    Foreground = Brushes.Red,
                    Margin = new Thickness(0, 0, 0, 10)
                };
                Grid.SetRow(warningText, 0);
                grid.Children.Add(warningText);

                // 操作描述
                var descText = new TextBlock
                {
                    Text = actionDescription,
                    TextWrapping = TextWrapping.Wrap,
                    Margin = new Thickness(0, 0, 0, 15),
                    Foreground = Brushes.DarkRed
                };
                Grid.SetRow(descText, 1);
                grid.Children.Add(descText);

                // 输入框标签
                var inputLabel = new TextBlock
                {
                    Text = $"请输入 \"{confirmText}\" 以确认此操作:",
                    Margin = new Thickness(0, 0, 0, 5)
                };
                Grid.SetRow(inputLabel, 2);
                grid.Children.Add(inputLabel);

                // 输入框
                var inputTextBox = new TextBox
                    {
                        Margin = new Thickness(0, 0, 0, 15),
                        Height = 25
                    };
                Grid.SetRow(inputTextBox, 3);
                grid.Children.Add(inputTextBox);

                // 按钮面板
                var buttonPanel = new StackPanel
                {
                    Orientation = Orientation.Horizontal,
                    HorizontalAlignment = HorizontalAlignment.Right
                };
                Grid.SetRow(buttonPanel, 4);
                grid.Children.Add(buttonPanel);

                var cancelButton = new Button
                {
                    Content = "取消",
                    Width = 80,
                    Height = 25,
                    Margin = new Thickness(10, 0, 0, 0),
                    Background = Brushes.LightGray
                };
                cancelButton.Click += (s, e) => { dialog.DialogResult = false; dialog.Close(); };
                buttonPanel.Children.Add(cancelButton);

                var confirmButton = new Button
                {
                    Content = "确认删除",
                    Width = 80,
                    Height = 25,
                    Background = Brushes.Red,
                    Foreground = Brushes.White
                };
                confirmButton.Click += (s, e) =>
                {
                    if (inputTextBox.Text.Trim().Equals(confirmText, StringComparison.OrdinalIgnoreCase))
                    {
                        dialog.DialogResult = true;
                        dialog.Close();
                    }
                    else
                    {
                        MessageBox.Show("输入的确认文字不匹配！", "错误", 
                            MessageBoxButton.OK, MessageBoxImage.Error);
                    }
                };
                buttonPanel.Children.Add(confirmButton);

                dialog.Content = grid;
                inputTextBox.Focus();

                return dialog.ShowDialog() == true;
            });
        }

        #endregion

        #region 系统托盘通知

        /// <summary>
        /// 显示系统托盘气泡通知
        /// </summary>
        public async Task ShowBalloonTipAsync(string title, string message, BalloonTipIcon icon = BalloonTipIcon.Info)
        {
            // 注意：WPF本身不直接支持系统托盘气泡通知
            // 这里使用简单的替代方案：显示一个非模态的通知窗口
            
            await Task.Run(() =>
            {
                Application.Current.Dispatcher.Invoke(() =>
                {
                    var notificationWindow = new Window
                    {
                        Title = title,
                        Width = 350,
                        Height = 120,
                        WindowStartupLocation = WindowStartupLocation.Manual,
                        Topmost = true,
                        ShowInTaskbar = false,
                        AllowsTransparency = true,
                        WindowStyle = WindowStyle.None,
                        Background = Brushes.Transparent,
                        ResizeMode = ResizeMode.NoResize
                    };

                    // 定位到屏幕右下角
                    var workingArea = SystemParameters.WorkArea;
                    notificationWindow.Left = workingArea.Right - 370;
                    notificationWindow.Top = workingArea.Bottom - 140;

                    var border = new Border
                    {
                        CornerRadius = new CornerRadius(8),
                        Background = new SolidColorBrush(Color.FromArgb(240, 44, 62, 80)),
                        Padding = new Thickness(15),
                        BorderBrush = Brushes.White,
                        BorderThickness = new Thickness(1)
                    };

                    var stackPanel = new StackPanel();

                    var titleText = new TextBlock
                    {
                        Text = title,
                        FontSize = 14,
                        FontWeight = FontWeights.Bold,
                        Foreground = Brushes.White,
                        Margin = new Thickness(0, 0, 0, 5)
                    };
                    stackPanel.Children.Add(titleText);

                    var messageText = new TextBlock
                    {
                        Text = message,
                        FontSize = 12,
                        Foreground = Brushes.White,
                        TextWrapping = TextWrapping.Wrap,
                        MaxHeight = 60
                    };
                    stackPanel.Children.Add(messageText);

                    var closeButton = new Button
                    {
                        Content = "×",
                        Width = 20,
                        Height = 20,
                        HorizontalAlignment = HorizontalAlignment.Right,
                        VerticalAlignment = VerticalAlignment.Top,
                        Background = Brushes.Transparent,
                        Foreground = Brushes.White,
                        FontSize = 14,
                        FontWeight = FontWeights.Bold,
                        Cursor = Cursors.Hand,
                        Margin = new Thickness(0, -5, -5, 0)
                    };
                    closeButton.Click += (s, e) => notificationWindow.Close();

                    var mainGrid = new Grid();
                    mainGrid.Children.Add(border);
                    mainGrid.Children.Add(closeButton);
                    border.Child = stackPanel;
                    notificationWindow.Content = mainGrid;

                    // 显示窗口
                    notificationWindow.Show();

                    // 自动淡出并关闭
                    var fadeOutTimer = new DispatcherTimer
                    {
                        Interval = TimeSpan.FromSeconds(5)
                    };
                    fadeOutTimer.Tick += (s, e) =>
                    {
                        fadeOutTimer.Stop();
                        
                        var fadeOutAnimation = new DoubleAnimation
                        {
                            To = 0,
                            Duration = TimeSpan.FromMilliseconds(1000)
                        };
                        fadeOutAnimation.Completed += (sender, args) => notificationWindow.Close();
                        notificationWindow.BeginAnimation(Window.OpacityProperty, fadeOutAnimation);
                    };
                    fadeOutTimer.Start();
                });
            });
        }

        /// <summary>
        /// 气泡通知图标类型
        /// </summary>
        public enum BalloonTipIcon
        {
            None,
            Info,
            Warning,
            Error
        }

        #endregion

        #region 进度报告辅助方法

        /// <summary>
        /// 格式化扫描进度信息
        /// </summary>
        public static string FormatScanProgress(int current, int total, string stage = "")
        {
            double percentage = total > 0 ? (double)current / total * 100 : 0;
            var sb = new System.Text.StringBuilder();
            
            if (!string.IsNullOrEmpty(stage))
            {
                sb.Append($"{stage} - ");
            }
            
            sb.Append($"已扫描: {current}/{total} ({percentage:F1}%)");
            
            return sb.ToString();
        }

        /// <summary>
        /// 格式化发现的漏洞统计
        /// </summary>
        public static string FormatVulnerabilityStats(int criticalCount, int highCount, int mediumCount, int lowCount)
        {
            var total = criticalCount + highCount + mediumCount + lowCount;
            var sb = new System.Text.StringBuilder();
            
            sb.AppendLine($"共发现 {total} 个漏洞:");
            sb.AppendLine($"  • 严重: {criticalCount}");
            sb.AppendLine($"  • 高危: {highCount}");
            sb.AppendLine($"  • 中危: {mediumCount}");
            sb.AppendLine($"  • 低危: {lowCount}");

            return sb.ToString();
        }

        #endregion
    }
}
