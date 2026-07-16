using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using System.Windows.Media;
using NetSecurityScanner.Models;
using NetSecurityScanner.Services;

namespace NetSecurityScanner.Views
{
    public partial class UserManagementWindow : Window
    {
        private readonly AuthService _authService;
        private List<UserDisplayItem> _allUsers = new();

        public UserManagementWindow()
        {
            InitializeComponent();
            _authService = new AuthService();
            Loaded += UserManagementWindow_Loaded;
        }

        private void UserManagementWindow_Loaded(object sender, RoutedEventArgs e)
        {
            var currentUser = SessionContext.Instance.Current;
            string viewer = currentUser == null ? "未登录" : $"{currentUser.DisplayName} ({currentUser.Username})";
            bool isAdmin = currentUser?.IsAdmin == true;
            InfoText.Text = $"查看者: {viewer}  ·  共 {LoadAllUsers()} 个账号{(isAdmin ? "  ·  可双击行编辑权限" : string.Empty)}";
            if (!isAdmin)
            {
                HintText.Visibility = Visibility.Collapsed;
            }
            ApplyFilter();
        }

        private int LoadAllUsers()
        {
            try
            {
                // 重新 new 一个 AuthService 从磁盘加载最新数据
                var freshAuth = new AuthService();
                _allUsers = new List<UserDisplayItem>();
                foreach (var u in freshAuth.GetAllUsers())
                {
                    _allUsers.Add(UserDisplayItem.FromUser(u));
                }
                return _allUsers.Count;
            }
            catch (Exception ex)
            {
                MessageBox.Show($"加载账号列表失败：{ex.Message}", "错误",
                    MessageBoxButton.OK, MessageBoxImage.Error);
                return 0;
            }
        }

        private void ApplyFilter()
        {
            string keyword = SearchTextBox?.Text?.Trim() ?? "";
            string statusFilter = (StatusFilterCombo?.SelectedItem as ComboBoxItem)?.Content?.ToString() ?? "全部";

            IEnumerable<UserDisplayItem> query = _allUsers;

            // 关键字搜索：用户名/显示名
            if (!string.IsNullOrEmpty(keyword))
                query = query.Where(u =>
                    (u.Username ?? "").Contains(keyword, StringComparison.OrdinalIgnoreCase) ||
                    (u.DisplayName ?? "").Contains(keyword, StringComparison.OrdinalIgnoreCase));

            // 状态筛选
            if (statusFilter != "全部")
            {
                UserStatus? wantStatus = statusFilter switch
                {
                    "⏳ 待审" => UserStatus.Pending,
                    "✅ 正常" => UserStatus.Active,
                    "🚫 禁用" => UserStatus.Disabled,
                    _ => null
                };
                if (wantStatus.HasValue)
                    query = query.Where(u => u.Status == wantStatus.Value);
            }

            var filtered = query.ToList();
            UsersDataGrid.ItemsSource = filtered;
            FilterStatusText.Text = keyword == "" && statusFilter == "全部"
                ? ""
                : $"筛选后 {filtered.Count} / {_allUsers.Count}";
        }

        private void SearchTextBox_TextChanged(object sender, TextChangedEventArgs e)
        {
            if (IsLoaded) ApplyFilter();
        }

        private void StatusFilter_Changed(object sender, SelectionChangedEventArgs e)
        {
            if (IsLoaded) ApplyFilter();
        }

        private void RefreshButton_Click(object sender, RoutedEventArgs e)
        {
            LoadAllUsers();
            ApplyFilter();
        }

        private void UsersDataGrid_SelectionChanged(object sender, SelectionChangedEventArgs e)
        {
            if (ViewDetailButton != null)
            {
                ViewDetailButton.IsEnabled = UsersDataGrid.SelectedItem is UserDisplayItem;
            }
        }

        private void ViewDetailButton_Click(object sender, RoutedEventArgs e)
        {
            if (UsersDataGrid.SelectedItem is not UserDisplayItem target) return;
            var detail = new UserDetailWindow(target.Username) { Owner = this };
            detail.ShowDialog();
        }

        private void UsersDataGrid_MouseDoubleClick(object sender, MouseButtonEventArgs e)
        {
            // 非 admin 不能编辑
            var current = SessionContext.Instance.Current;
            if (current == null || !current.IsAdmin) return;

            if (UsersDataGrid.SelectedItem is not UserDisplayItem target) return;

            // admin 行不允许编辑
            if (target.IsAdmin)
            {
                MessageBox.Show("超级管理员的权限不允许修改。", "提示",
                    MessageBoxButton.OK, MessageBoxImage.Information);
                return;
            }

            // 仅 Active 状态允许编辑（Pending 走审核流程，Disabled 走重新启用）
            if (target.Status != UserStatus.Active)
            {
                MessageBox.Show($"用户 [{target.Username}] 当前状态为 {target.StatusText}，不能直接编辑权限。\nPending 请通过「用户审核」处理；Disabled 请先重新启用。",
                    "提示", MessageBoxButton.OK, MessageBoxImage.Information);
                return;
            }

            try
            {
                var editor = new UserPermissionEditWindow(target.Username) { Owner = this };
                if (editor.ShowDialog() == true)
                {
                    UserManagementWindow_Loaded(this, new RoutedEventArgs());
                }
            }
            catch (Exception ex)
            {
                MessageBox.Show($"打开权限编辑窗口失败：{ex.Message}", "错误",
                    MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        private void CloseButton_Click(object sender, RoutedEventArgs e)
        {
            Close();
        }
    }

    /// <summary>
    /// DataGrid 显示项（含状态徽章、权限摘要等）。
    /// </summary>
    public class UserDisplayItem : INotifyPropertyChanged
    {
        public string Username { get; set; } = "";
        public string DisplayName { get; set; } = "";
        public DateTime CreatedAt { get; set; }
        public DateTime? LastLoginAt { get; set; }
        public int FailedAttempts { get; set; }
        public DateTime? LockoutUntil { get; set; }
        public bool IsAdmin { get; set; }
        public UserStatus Status { get; set; }
        public List<string> Permissions { get; set; } = new();
        public string? ApprovedBy { get; set; }
        public DateTime? ApprovedAt { get; set; }
        public string? LastModifiedBy { get; set; }
        public DateTime? LastModifiedAt { get; set; }

        public string LastLoginAtDisplay => LastLoginAt.HasValue
            ? LastLoginAt.Value.ToString("yyyy-MM-dd HH:mm")
            : "—";

        public int StatusSortKey => (int)Status;
        public int PermissionCount => IsAdmin ? 10 : (Permissions?.Count ?? 0);

        public string StatusText
        {
            get
            {
                if (LockoutUntil.HasValue && LockoutUntil.Value > DateTime.Now)
                    return "🔒 锁定";
                return Status switch
                {
                    UserStatus.Pending => "⏳ 待审",
                    UserStatus.Active => "✅ 正常",
                    UserStatus.Disabled => "🚫 禁用",
                    _ => "❓ 未知"
                };
            }
        }

        public Brush StatusBackground
        {
            get
            {
                if (LockoutUntil.HasValue && LockoutUntil.Value > DateTime.Now)
                    return new SolidColorBrush(Color.FromRgb(0x95, 0xA5, 0xA6));
                return Status switch
                {
                    UserStatus.Pending => new SolidColorBrush(Color.FromRgb(0xF3, 0x9C, 0x12)),
                    UserStatus.Active => new SolidColorBrush(Color.FromRgb(0x27, 0xAE, 0x60)),
                    UserStatus.Disabled => new SolidColorBrush(Color.FromRgb(0x95, 0xA5, 0xA6)),
                    _ => new SolidColorBrush(Color.FromRgb(0xBD, 0xC3, 0xC7))
                };
            }
        }

        public string RoleText
        {
            get
            {
                if (IsAdmin) return "👑 管理员";
                if (Status == UserStatus.Pending) return "—";
                return "👤 用户";
            }
        }

        public string PermissionSummary
        {
            get
            {
                if (IsAdmin) return "✅ 全部权限";
                if (Status == UserStatus.Pending) return "—（待审核）";
                if (Permissions == null || Permissions.Count == 0) return "⚠️ 无权限";
                return $"🔑 {Permissions.Count} 项：{string.Join("、", Permissions.Take(3))}{(Permissions.Count > 3 ? "…" : "")}";
            }
        }

        public string PermissionDetail
        {
            get
            {
                if (IsAdmin) return "超级管理员：拥有全部 10 项权限";
                if (Permissions == null || Permissions.Count == 0) return "尚未授予任何权限";
                return string.Join("\n", Permissions);
            }
        }

        public static UserDisplayItem FromUser(User u) => new()
        {
            Username = u.Username,
            DisplayName = u.DisplayName,
            CreatedAt = u.CreatedAt,
            LastLoginAt = u.LastLoginAt,
            FailedAttempts = u.FailedAttempts,
            LockoutUntil = u.LockoutUntil,
            IsAdmin = u.IsAdmin,
            Status = u.Status,
            Permissions = new List<string>(u.Permissions ?? new List<string>()),
            ApprovedBy = u.ApprovedBy,
            ApprovedAt = u.ApprovedAt,
            LastModifiedBy = u.LastModifiedBy,
            LastModifiedAt = u.LastModifiedAt
        };

        public event PropertyChangedEventHandler? PropertyChanged;
        private void OnPropertyChanged([CallerMemberName] string? n = null)
            => PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(n));
    }
}
