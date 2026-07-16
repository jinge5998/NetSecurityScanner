using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Windows;
using System.Windows.Controls;
using NetSecurityScanner.Models;
using NetSecurityScanner.Services;

namespace NetSecurityScanner.Views
{
    public partial class UserApprovalWindow : Window
    {
        private readonly AuthService _authService;
        private List<User> _pendingUsers = new();
        private List<PendingUserItem> _allDisplayUsers = new();  // 原始全量(搜索前的列表)
        public ObservableCollection<PermissionItem> PermissionItems { get; } = new();
        public ObservableCollection<PendingUserItem> DisplayUsers { get; } = new();

        public UserApprovalWindow()
        {
            InitializeComponent();
            _authService = new AuthService();
            PendingUsersDataGrid.ItemsSource = DisplayUsers;
            PermissionsItemsControl.ItemsSource = PermissionItems;
            Loaded += UserApprovalWindow_Loaded;
            Unloaded += UserApprovalWindow_Unloaded;
        }

        private System.Windows.Threading.DispatcherTimer? _autoRefreshTimer;

        private void UserApprovalWindow_Unloaded(object sender, RoutedEventArgs e)
        {
            // 窗口关闭时停止自动刷新,释放 timer
            if (_autoRefreshTimer != null)
            {
                _autoRefreshTimer.Stop();
                _autoRefreshTimer = null;
            }
        }

        private void UserApprovalWindow_Loaded(object sender, RoutedEventArgs e)
        {
            var currentUser = SessionContext.Instance.Current;
            if (currentUser == null || !currentUser.IsAdmin)
            {
                MessageBox.Show("此功能仅限管理员使用。", "权限不足",
                    MessageBoxButton.OK, MessageBoxImage.Warning);
                Close();
                return;
            }

            InfoText.Text = $"审核者: {currentUser.DisplayName} ({currentUser.Username})";

            // 初始化权限复选框（默认勾选资产查看 + 资产编辑）
            PermissionItems.Clear();
            foreach (var (perm, idx) in Permission.AllPermissions.Select((p, i) => (p, i)))
            {
                PermissionItems.Add(new PermissionItem
                {
                    Key = perm,
                    Label = Permission.AllPermissionLabels[idx],
                    IsChecked = perm == Permission.AssetView || perm == Permission.AssetEdit
                });
            }

            LoadPendingUsers();

            // 启动 3 秒间隔的自动刷新 timer,确保打开期间能看到 RegisterWindow 等其他窗口注册的新用户
            _autoRefreshTimer = new System.Windows.Threading.DispatcherTimer
            {
                Interval = TimeSpan.FromSeconds(3)
            };
            _autoRefreshTimer.Tick += (_, _) => LoadPendingUsers();
            _autoRefreshTimer.Start();
        }

        private void LoadPendingUsers()
        {
            try
            {
                // 关键：每次刷新都 new 一个新的 AuthService，重新从磁盘加载 users.json
                // 避免窗口长期打开时，其他窗口（如 RegisterWindow）注册的新用户看不到

                // 保存当前选中状态(Username),刷新后恢复,避免 3 秒自动刷新时 DataGrid 选中行被清空导致 Approve 按钮变灰
                var prevSelectedUsername = (PendingUsersDataGrid.SelectedItem as PendingUserItem)?.Username;

                var freshAuth = new AuthService();
                _pendingUsers = freshAuth.GetPendingUsers();

                // 重新生成全量列表(保留 DisplayUsers 中的 IsSelected 状态)
                var prevSelected = DisplayUsers.Where(u => u.IsSelected).Select(u => u.Username).ToHashSet();
                _allDisplayUsers = _pendingUsers.Select(PendingUserItem.FromUser).ToList();
                foreach (var item in _allDisplayUsers)
                {
                    if (prevSelected.Contains(item.Username))
                        item.IsSelected = true;
                }

                // 应用搜索过滤
                ApplySearchFilter();

                // 状态层
                EmptyHint.Visibility = _allDisplayUsers.Count == 0
                    ? Visibility.Visible
                    : Visibility.Collapsed;

                // 恢复选中行:根据 Username 找到新对象,设回 SelectedItem
                if (!string.IsNullOrEmpty(prevSelectedUsername))
                {
                    var match = DisplayUsers.FirstOrDefault(u => u.Username == prevSelectedUsername);
                    if (match != null)
                    {
                        PendingUsersDataGrid.SelectedItem = match;
                        // 滚动到可见
                        PendingUsersDataGrid.ScrollIntoView(match);
                    }
                }

                UpdateInfoText();
                UpdateButtonsState();
            }
            catch (Exception ex)
            {
                MessageBox.Show($"加载待审核用户失败：{ex.Message}", "错误",
                    MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        private void ApplySearchFilter()
        {
            DisplayUsers.Clear();
            var keyword = SearchTextBox?.Text?.Trim() ?? "";
            IEnumerable<PendingUserItem> filtered = _allDisplayUsers;
            if (!string.IsNullOrEmpty(keyword))
            {
                var kw = keyword.ToLower();
                filtered = _allDisplayUsers.Where(u =>
                    (u.Username?.ToLower().Contains(kw) ?? false) ||
                    (u.DisplayName?.ToLower().Contains(kw) ?? false) ||
                    (u.Email?.ToLower().Contains(kw) ?? false) ||
                    (u.Phone?.Contains(kw) ?? false));
            }
            foreach (var u in filtered)
                DisplayUsers.Add(u);
        }

        private void SearchTextBox_TextChanged(object sender, TextChangedEventArgs e)
        {
            ApplySearchFilter();
            UpdateInfoText();
            UpdateButtonsState();
        }

        private void UpdateInfoText()
        {
            if (InfoText == null) return;
            var current = SessionContext.Instance.Current;
            int checkedCount = DisplayUsers.Count(u => u.IsSelected);
            string baseText = current == null ? ""
                : $"审核者: {current.DisplayName} ({current.Username})  ·  待审 {DisplayUsers.Count}/{_allDisplayUsers.Count} 人";
            string extra = checkedCount > 0 ? $"  ·  已勾选 {checkedCount}" : "";
            string searchInfo = !string.IsNullOrEmpty(SearchTextBox?.Text)
                ? $"  ·  🔍 过滤中"
                : "";
            InfoText.Text = baseText + extra + searchInfo;
        }

        private void UpdateButtonsState()
        {
            int checkedCount = DisplayUsers.Count(u => u.IsSelected);
            BatchApproveButton.IsEnabled = checkedCount > 0;
            BatchRejectButton.IsEnabled = checkedCount > 0;

            // 单个批准/拒绝按钮:依赖"行被选中"或"至少一个被勾选"
            // 双保险:即使 3 秒自动刷新时 DataGrid 选中行短暂丢失,只要有勾选,按钮仍可用
            var single = PendingUsersDataGrid.SelectedItem as PendingUserItem;
            bool hasAny = single != null || checkedCount > 0;
            ApproveButton.IsEnabled = hasAny;
            RejectButton.IsEnabled = hasAny;

            if (single != null)
                SelectedUserText.Text = $"为 [{single.Username} ({single.DisplayName})] 分配权限";
            else if (checkedCount > 0)
                SelectedUserText.Text = $"已勾选 {checkedCount} 个用户（点击「批量批准」/「批量拒绝」应用当前权限）";
            else
                SelectedUserText.Text = "请在左侧选择或勾选待审用户";
        }

        private void PendingUsersDataGrid_SelectionChanged(object sender, SelectionChangedEventArgs e)
        {
            UpdateButtonsState();
        }

        private void RefreshButton_Click(object sender, RoutedEventArgs e)
        {
            LoadPendingUsers();
            StatusBarText.Text = $"🔄 已刷新于 {DateTime.Now:HH:mm:ss}";
        }

        private void CloseButton_Click(object sender, RoutedEventArgs e)
        {
            Close();
        }

        private List<string> CollectCheckedPermissions()
        {
            return PermissionItems.Where(p => p.IsChecked).Select(p => p.Key).ToList();
        }

        private string GetRemark()
        {
            var remark = RemarkTextBox?.Text?.Trim();
            return string.IsNullOrEmpty(remark) ? "（无）" : remark;
        }

        // ========== 单个审核 ==========
        private async void ApproveButton_Click(object sender, RoutedEventArgs e)
        {
            // 优先用选中行;否则用第一个 IsChecked 的用户(双保险:3 秒自动刷新时选中行可能短暂丢失)
            var single = PendingUsersDataGrid.SelectedItem as PendingUserItem
                         ?? DisplayUsers.FirstOrDefault(u => u.IsSelected);
            if (single == null)
            {
                MessageBox.Show("请先选中一行或勾选一个用户。", "提示",
                    MessageBoxButton.OK, MessageBoxImage.Information);
                return;
            }
            var perms = CollectCheckedPermissions();
            if (perms.Count == 0)
            {
                MessageBox.Show("请至少勾选一项权限。", "提示", MessageBoxButton.OK, MessageBoxImage.Warning);
                return;
            }
            ApproveButton.IsEnabled = false;
            try
            {
                var current = SessionContext.Instance.Current;
                var ok = await _authService.ApproveUserAsync(current.Username, single.Username, perms);
                if (ok)
                {
                    StatusBarText.Text = $"✅ 已批准 [{single.Username}]  ·  {DateTime.Now:HH:mm:ss}";
                    RemarkTextBox.Clear();
                    LoadPendingUsers();
                }
                else
                {
                    MessageBox.Show("批准失败。", "错误", MessageBoxButton.OK, MessageBoxImage.Error);
                }
            }
            catch (Exception ex)
            {
                MessageBox.Show($"批准失败：{ex.Message}", "错误", MessageBoxButton.OK, MessageBoxImage.Error);
            }
            ApproveButton.IsEnabled = true;
        }

        private async void RejectButton_Click(object sender, RoutedEventArgs e)
        {
            var single = PendingUsersDataGrid.SelectedItem as PendingUserItem
                         ?? DisplayUsers.FirstOrDefault(u => u.IsSelected);
            if (single == null) return;
            var ok = MessageBox.Show(
                $"确定拒绝 [{single.Username} ({single.DisplayName})] 的注册申请吗？\n该用户将被禁用。",
                "确认拒绝", MessageBoxButton.YesNo, MessageBoxImage.Question);
            if (ok != MessageBoxResult.Yes) return;

            RejectButton.IsEnabled = false;
            try
            {
                var current = SessionContext.Instance.Current;
                var r = await _authService.RejectUserAsync(current.Username, single.Username);
                if (r)
                {
                    StatusBarText.Text = $"🚫 已拒绝 [{single.Username}]  ·  {DateTime.Now:HH:mm:ss}";
                    LoadPendingUsers();
                }
                else
                {
                    MessageBox.Show("拒绝失败。", "错误", MessageBoxButton.OK, MessageBoxImage.Error);
                }
            }
            catch (Exception ex)
            {
                MessageBox.Show($"拒绝失败：{ex.Message}", "错误", MessageBoxButton.OK, MessageBoxImage.Error);
            }
            RejectButton.IsEnabled = true;
        }

        // ========== 批量审核 ==========
        private async void BatchApproveButton_Click(object sender, RoutedEventArgs e)
        {
            var targets = DisplayUsers.Where(u => u.IsSelected).ToList();
            if (targets.Count == 0) return;
            var perms = CollectCheckedPermissions();
            if (perms.Count == 0)
            {
                MessageBox.Show("请至少勾选一项权限。", "提示", MessageBoxButton.OK, MessageBoxImage.Warning);
                return;
            }
            var ok = MessageBox.Show(
                $"确定批量批准 {targets.Count} 个用户并授予 {perms.Count} 项权限？\n\n将使用：{string.Join(", ", perms)}",
                "确认批量批准", MessageBoxButton.YesNo, MessageBoxImage.Question);
            if (ok != MessageBoxResult.Yes) return;

            BatchApproveButton.IsEnabled = false;
            try
            {
                var current = SessionContext.Instance.Current;
                var usernames = targets.Select(t => t.Username).ToList();
                int cnt = await _authService.BatchApproveAsync(current.Username, usernames, perms);
                StatusBarText.Text = $"✅ 批量批准 {cnt}/{targets.Count} 个用户  ·  {DateTime.Now:HH:mm:ss}";
                RemarkTextBox.Clear();
                LoadPendingUsers();
            }
            catch (Exception ex)
            {
                MessageBox.Show($"批量批准失败：{ex.Message}", "错误", MessageBoxButton.OK, MessageBoxImage.Error);
            }
            BatchApproveButton.IsEnabled = true;
        }

        private async void BatchRejectButton_Click(object sender, RoutedEventArgs e)
        {
            var targets = DisplayUsers.Where(u => u.IsSelected).ToList();
            if (targets.Count == 0) return;
            var ok = MessageBox.Show(
                $"确定批量拒绝 {targets.Count} 个用户？这些用户将被禁用。",
                "确认批量拒绝", MessageBoxButton.YesNo, MessageBoxImage.Warning);
            if (ok != MessageBoxResult.Yes) return;

            BatchRejectButton.IsEnabled = false;
            try
            {
                var current = SessionContext.Instance.Current;
                var usernames = targets.Select(t => t.Username).ToList();
                int cnt = await _authService.BatchRejectAsync(current.Username, usernames);
                StatusBarText.Text = $"🚫 批量拒绝 {cnt}/{targets.Count} 个用户  ·  {DateTime.Now:HH:mm:ss}";
                LoadPendingUsers();
            }
            catch (Exception ex)
            {
                MessageBox.Show($"批量拒绝失败：{ex.Message}", "错误", MessageBoxButton.OK, MessageBoxImage.Error);
            }
            BatchRejectButton.IsEnabled = true;
        }

        // ========== 权限模板 ==========
        private void ApplyTemplate(IReadOnlyList<string> perms)
        {
            var permSet = new HashSet<string>(perms);
            foreach (var p in PermissionItems)
                p.IsChecked = permSet.Contains(p.Key);
        }

        private void TemplateViewerButton_Click(object sender, RoutedEventArgs e)
        {
            ApplyTemplate(Permission.Templates.All[Permission.Templates.Viewer].Permissions);
            StatusBarText.Text = $"📦 已应用模板：{Permission.Templates.All[Permission.Templates.Viewer].Label}";
        }

        private void TemplateOperatorButton_Click(object sender, RoutedEventArgs e)
        {
            ApplyTemplate(Permission.Templates.All[Permission.Templates.Operator].Permissions);
            StatusBarText.Text = $"📦 已应用模板：{Permission.Templates.All[Permission.Templates.Operator].Label}";
        }

        private void TemplateAssetManagerButton_Click(object sender, RoutedEventArgs e)
        {
            ApplyTemplate(Permission.Templates.All[Permission.Templates.AssetManager].Permissions);
            StatusBarText.Text = $"📦 已应用模板：{Permission.Templates.All[Permission.Templates.AssetManager].Label}";
        }

        private void ViewAuditLogButton_Click(object sender, RoutedEventArgs e)
        {
            var w = new AuditLogWindow { Owner = this };
            w.ShowDialog();
        }

        /// <summary>
        /// 导出当前过滤后的待审用户为 CSV。
        /// 用 SaveFileDialog 让用户选保存路径。导出范围 = DisplayUsers(尊重当前搜索过滤)。
        /// </summary>
        private void ExportCsvButton_Click(object sender, RoutedEventArgs e)
        {
            if (DisplayUsers.Count == 0)
            {
                MessageBox.Show("当前列表为空,无可导出数据。", "导出 CSV",
                    MessageBoxButton.OK, MessageBoxImage.Information);
                return;
            }

            var dlg = new Microsoft.Win32.SaveFileDialog
            {
                Title = "导出待审用户为 CSV",
                FileName = $"pending_users_{DateTime.Now:yyyyMMdd_HHmmss}.csv",
                DefaultExt = ".csv",
                Filter = "CSV 文件 (*.csv)|*.csv|所有文件 (*.*)|*.*"
            };
            if (dlg.ShowDialog(this) != true) return;

            try
            {
                var sb = new System.Text.StringBuilder();
                // 表头
                sb.AppendLine("用户名,显示名,邮箱,手机,申请说明,创建时间,等待时长(分钟)");
                foreach (var item in DisplayUsers)
                {
                    var minutes = item.CreatedAt > DateTime.MinValue
                        ? ((int)(DateTime.Now - item.CreatedAt).TotalMinutes).ToString()
                        : "";
                    sb.AppendLine(string.Join(",",
                        CsvEscape(item.Username),
                        CsvEscape(item.DisplayName),
                        CsvEscape(item.Email),
                        CsvEscape(item.Phone),
                        CsvEscape(item.ReasonShort),
                        item.CreatedAt == DateTime.MinValue ? "" : item.CreatedAt.ToString("yyyy-MM-dd HH:mm:ss"),
                        minutes));
                }
                // UTF-8 with BOM:让 Excel 正确识别中文
                System.IO.File.WriteAllText(dlg.FileName, "\uFEFF" + sb.ToString(), new System.Text.UTF8Encoding(true));
                MessageBox.Show($"✅ 已导出 {DisplayUsers.Count} 个用户到\n{dlg.FileName}", "导出成功",
                    MessageBoxButton.OK, MessageBoxImage.Information);
                StatusBarText.Text = $"📊 已导出 CSV: {DisplayUsers.Count} 行 → {System.IO.Path.GetFileName(dlg.FileName)}";
            }
            catch (Exception ex)
            {
                MessageBox.Show($"导出失败: {ex.Message}", "错误",
                    MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        private static string CsvEscape(string? value)
        {
            if (string.IsNullOrEmpty(value)) return "";
            // CSV 转义:含逗号/引号/换行的字段用双引号包裹,内部双引号 → ""
            if (value.Contains(',') || value.Contains('"') || value.Contains('\n') || value.Contains('\r'))
                return "\"" + value.Replace("\"", "\"\"") + "\"";
            return value;
        }

        // ========== 批量勾选助手 ==========
        private void SelectAllButton_Click(object sender, RoutedEventArgs e)
        {
            foreach (var u in DisplayUsers) u.IsSelected = true;
            UpdateInfoText();
            UpdateButtonsState();
            StatusBarText.Text = $"☑ 已全选 {DisplayUsers.Count} 个用户（按当前过滤）";
        }

        private void InvertSelectionButton_Click(object sender, RoutedEventArgs e)
        {
            foreach (var u in DisplayUsers) u.IsSelected = !u.IsSelected;
            UpdateInfoText();
            UpdateButtonsState();
            int n = DisplayUsers.Count(u => u.IsSelected);
            StatusBarText.Text = $"🔄 已反选 → 选中 {n} 个";
        }

        private void ClearSelectionButton_Click(object sender, RoutedEventArgs e)
        {
            foreach (var u in DisplayUsers) u.IsSelected = false;
            UpdateInfoText();
            UpdateButtonsState();
            StatusBarText.Text = "⬜ 已清空勾选";
        }
    }

    /// <summary>
    /// DataGrid 行项（含 IsSelected 用于批量勾选）。
    /// </summary>
    public class PendingUserItem : INotifyPropertyChanged
    {
        public string Username { get; set; } = "";
        public string DisplayName { get; set; } = "";
        public string Email { get; set; } = "";
        public string Phone { get; set; } = "";
        public string Reason { get; set; } = "";
        public DateTime CreatedAt { get; set; }

        private bool _isSelected;
        public bool IsSelected
        {
            get => _isSelected;
            set
            {
                if (_isSelected == value) return;
                _isSelected = value;
                OnPropertyChanged();
            }
        }

        public string WaitDurationDisplay
        {
            get
            {
                var span = DateTime.Now - CreatedAt;
                if (span.TotalMinutes < 1) return "刚刚";
                if (span.TotalHours < 1) return $"{(int)span.TotalMinutes} 分钟";
                if (span.TotalDays < 1) return $"{(int)span.TotalHours} 小时";
                return $"{(int)span.TotalDays} 天";
            }
        }

        /// <summary>
        /// 申请说明列显示用：空时显示"—"，过长截断为 30 字 + "…"
        /// </summary>
        public string ReasonShort
        {
            get
            {
                if (string.IsNullOrWhiteSpace(Reason)) return "—";
                var s = Reason.Replace("\r", " ").Replace("\n", " ").Trim();
                return s.Length > 30 ? s.Substring(0, 30) + "…" : s;
            }
        }

        public static PendingUserItem FromUser(User u) => new()
        {
            Username = u.Username,
            DisplayName = u.DisplayName ?? "",
            Email = u.Email ?? "—",
            Phone = u.Phone ?? "—",
            Reason = u.Reason ?? "",
            CreatedAt = u.CreatedAt
        };

        public event PropertyChangedEventHandler? PropertyChanged;
        private void OnPropertyChanged([CallerMemberName] string? n = null)
            => PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(n));
    }

    /// <summary>
    /// 权限勾选项。
    /// </summary>
    public class PermissionItem : INotifyPropertyChanged
    {
        private bool _isChecked;
        public string Key { get; set; } = "";
        public string Label { get; set; } = "";
        public bool IsChecked
        {
            get => _isChecked;
            set
            {
                if (_isChecked == value) return;
                _isChecked = value;
                OnPropertyChanged();
            }
        }

        public event PropertyChangedEventHandler? PropertyChanged;
        private void OnPropertyChanged([CallerMemberName] string? n = null)
            => PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(n));
    }
}
