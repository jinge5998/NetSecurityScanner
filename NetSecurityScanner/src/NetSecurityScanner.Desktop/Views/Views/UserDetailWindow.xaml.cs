using System;
using System.Linq;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using NetSecurityScanner.Models;
using NetSecurityScanner.Services;

namespace NetSecurityScanner.Views
{
    public partial class UserDetailWindow : Window
    {
        private readonly AuthService _authService;
        private readonly string _targetUsername;

        public UserDetailWindow(string targetUsername)
        {
            InitializeComponent();
            _authService = new AuthService();
            _targetUsername = targetUsername;
            Loaded += UserDetailWindow_Loaded;
        }

        private void UserDetailWindow_Loaded(object sender, RoutedEventArgs e)
        {
            try
            {
                // 重新 new 一个 AuthService 从磁盘加载最新数据
                var freshAuth = new AuthService();
                var user = freshAuth.GetAllUsers().FirstOrDefault(u =>
                    string.Equals(u.Username, _targetUsername, StringComparison.OrdinalIgnoreCase));
                if (user == null)
                {
                    MessageBox.Show($"未找到用户 [{_targetUsername}]", "错误",
                        MessageBoxButton.OK, MessageBoxImage.Error);
                    Close();
                    return;
                }

                HeaderText.Text = $"{user.DisplayName} ({user.Username})";

                AddSection("📋 基本信息", new (string label, string value)[]
                {
                    ("用户名", user.Username),
                    ("显示名称", user.DisplayName ?? "—"),
                    ("角色", user.IsAdmin ? "👑 超级管理员" : "👤 普通用户"),
                    ("状态", user.Status switch
                    {
                        UserStatus.Pending => "⏳ 待审核",
                        UserStatus.Active => "✅ 正常",
                        UserStatus.Disabled => "🚫 已禁用",
                        _ => "❓ 未知"
                    }),
                    ("创建时间", user.CreatedAt.ToString("yyyy-MM-dd HH:mm:ss")),
                });

                AddSection("🔐 登录信息", new (string label, string value)[]
                {
                    ("最后登录", user.LastLoginAt.HasValue
                        ? user.LastLoginAt.Value.ToString("yyyy-MM-dd HH:mm:ss")
                        : "—"),
                    ("失败次数", user.FailedAttempts.ToString()),
                    ("锁定到期", user.LockoutUntil.HasValue
                        ? user.LockoutUntil.Value.ToString("yyyy-MM-dd HH:mm:ss")
                        : "—"),
                });

                if (user.IsAdmin)
                {
                    AddSection("🔑 权限", new (string label, string value)[]
                    {
                        ("权限范围", "✅ 全部 10 项权限（管理员内置）"),
                    });
                }
                else
                {
                    var perms = user.Permissions ?? new System.Collections.Generic.List<string>();
                    var permsDisplay = perms.Count == 0
                        ? "⚠️ 尚未授予任何权限"
                        : string.Join("\n• ", new[] { "" }.Concat(perms));
                    AddSection("🔑 权限", new (string label, string value)[]
                    {
                        ("已授予", permsDisplay.TrimStart('\n').TrimStart(' ')),
                    });
                }

                AddSection("📝 审计追踪", new (string label, string value)[]
                {
                    ("审核人", user.ApprovedBy ?? "—"),
                    ("审核时间", user.ApprovedAt.HasValue
                        ? user.ApprovedAt.Value.ToString("yyyy-MM-dd HH:mm:ss")
                        : "—"),
                    ("最后修改人", user.LastModifiedBy ?? "—"),
                    ("最后修改时间", user.LastModifiedAt.HasValue
                        ? user.LastModifiedAt.Value.ToString("yyyy-MM-dd HH:mm:ss")
                        : "—"),
                });
            }
            catch (Exception ex)
            {
                MessageBox.Show($"加载用户详情失败：{ex.Message}", "错误",
                    MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        private void AddSection(string title, (string label, string value)[] rows)
        {
            // 分组标题
            var titleBlock = new TextBlock
            {
                Text = title,
                FontSize = 14,
                FontWeight = FontWeights.Bold,
                Foreground = new SolidColorBrush(Color.FromRgb(0x2d, 0x34, 0x36)),
                Margin = new Thickness(0, 12, 0, 8)
            };
            DetailPanel.Children.Add(titleBlock);

            // 卡片
            var card = new Border
            {
                Background = Brushes.White,
                CornerRadius = new CornerRadius(6),
                BorderBrush = new SolidColorBrush(Color.FromRgb(0xdf, 0xe6, 0xe9)),
                BorderThickness = new Thickness(1),
                Padding = new Thickness(14, 10, 14, 10),
                Margin = new Thickness(0, 0, 0, 0)
            };

            var stack = new StackPanel();
            foreach (var (label, value) in rows)
            {
                var grid = new Grid();
                grid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(110) });
                grid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });

                var labelBlock = new TextBlock
                {
                    Text = label,
                    Foreground = new SolidColorBrush(Color.FromRgb(0x63, 0x6e, 0x72)),
                    FontWeight = FontWeights.SemiBold
                };
                Grid.SetColumn(labelBlock, 0);
                grid.Children.Add(labelBlock);

                var valueBlock = new TextBlock
                {
                    Text = value,
                    Foreground = new SolidColorBrush(Color.FromRgb(0x2d, 0x34, 0x36)),
                    TextWrapping = TextWrapping.Wrap,
                    FontFamily = new System.Windows.Media.FontFamily("Consolas, Courier New")
                };
                Grid.SetColumn(valueBlock, 1);
                grid.Children.Add(valueBlock);

                stack.Children.Add(grid);
            }
            card.Child = stack;
            DetailPanel.Children.Add(card);
        }

        private void CloseButton_Click(object sender, RoutedEventArgs e)
        {
            Close();
        }
    }
}
