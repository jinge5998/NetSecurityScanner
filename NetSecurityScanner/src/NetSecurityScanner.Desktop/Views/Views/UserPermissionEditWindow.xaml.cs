using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Windows;
using NetSecurityScanner.Services;

namespace NetSecurityScanner.Views
{
    public partial class UserPermissionEditWindow : Window
    {
        private readonly AuthService _authService;
        private readonly string _targetUsername;
        public ObservableCollection<PermissionCheckItem> PermissionItems { get; } = new();

        public UserPermissionEditWindow(string targetUsername)
        {
            InitializeComponent();
            _authService = new AuthService();
            _targetUsername = targetUsername;
            Loaded += UserPermissionEditWindow_Loaded;
        }

        private void UserPermissionEditWindow_Loaded(object sender, RoutedEventArgs e)
        {
            // 仅 admin 可用
            var current = SessionContext.Instance.Current;
            if (current == null || !current.IsAdmin)
            {
                MessageBox.Show("此功能仅限管理员使用。", "权限不足",
                    MessageBoxButton.OK, MessageBoxImage.Warning);
                Close();
                return;
            }

            // 重新 new 一个 AuthService 从磁盘加载最新数据
            var freshAuth = new AuthService();
            var allUsers = freshAuth.GetAllUsers();
            var target = allUsers.FirstOrDefault(u =>
                string.Equals(u.Username, _targetUsername, StringComparison.OrdinalIgnoreCase));
            if (target == null)
            {
                MessageBox.Show($"未找到用户 [{_targetUsername}]。", "错误",
                    MessageBoxButton.OK, MessageBoxImage.Error);
                Close();
                return;
            }

            HeaderText.Text = $"正在为 [{target.DisplayName} ({target.Username})] 配置权限";
            var currentPerms = new HashSet<string>(target.Permissions ?? new List<string>(),
                StringComparer.OrdinalIgnoreCase);

            // 填充 10 个权限位
            for (int i = 0; i < Permission.AllPermissions.Count; i++)
            {
                var key = Permission.AllPermissions[i];
                PermissionItems.Add(new PermissionCheckItem
                {
                    Key = key,
                    Label = Permission.AllPermissionLabels[i],
                    IsChecked = currentPerms.Contains(key)
                });
            }
            PermissionsItemsControl.ItemsSource = PermissionItems;
            UpdateSelectedCount();
        }

        private void UpdateSelectedCount()
        {
            int count = PermissionItems.Count(p => p.IsChecked);
            SelectedCountText.Text = $"已选 {count} / {PermissionItems.Count} 项";
        }

        private void PermissionCheck_Changed(object sender, RoutedEventArgs e)
        {
            UpdateSelectedCount();
        }

        private void SelectAllButton_Click(object sender, RoutedEventArgs e)
        {
            foreach (var p in PermissionItems) p.IsChecked = true;
            UpdateSelectedCount();
        }

        private void SelectNoneButton_Click(object sender, RoutedEventArgs e)
        {
            foreach (var p in PermissionItems) p.IsChecked = false;
            UpdateSelectedCount();
        }

        private void SelectViewOnlyButton_Click(object sender, RoutedEventArgs e)
        {
            foreach (var p in PermissionItems)
                p.IsChecked = (p.Key == Permission.AssetView);
            UpdateSelectedCount();
        }

        private async void SaveButton_Click(object sender, RoutedEventArgs e)
        {
            var current = SessionContext.Instance.Current;
            if (current == null || !current.IsAdmin) return;

            // 至少保留 Asset:View（与后端策略一致）
            var perms = PermissionItems.Where(p => p.IsChecked).Select(p => p.Key).ToList();
            if (!perms.Contains(Permission.AssetView))
            {
                var ok = MessageBox.Show("当前未勾选「资产查看」。用户将无法看到任何资产。\n是否继续保存？",
                    "确认", MessageBoxButton.YesNo, MessageBoxImage.Question);
                if (ok != MessageBoxResult.Yes) return;
            }

            SaveButton.IsEnabled = false;
            try
            {
                var result = await _authService.SetUserPermissionsAsync(current.Username, _targetUsername, perms);
                if (result)
                {
                    MessageBox.Show($"已保存 [{_targetUsername}] 的权限，共 {perms.Count} 项。", "成功",
                        MessageBoxButton.OK, MessageBoxImage.Information);
                    DialogResult = true;
                    Close();
                }
                else
                {
                    MessageBox.Show("保存失败，请检查目标用户状态。", "错误",
                        MessageBoxButton.OK, MessageBoxImage.Error);
                    SaveButton.IsEnabled = true;
                }
            }
            catch (Exception ex)
            {
                MessageBox.Show($"保存失败：{ex.Message}", "错误",
                    MessageBoxButton.OK, MessageBoxImage.Error);
                SaveButton.IsEnabled = true;
            }
        }

        private void CancelButton_Click(object sender, RoutedEventArgs e)
        {
            DialogResult = false;
            Close();
        }
    }

    /// <summary>
    /// 权限勾选项（含 Key 标签 + 中文 Label + IsChecked）。
    /// </summary>
    public class PermissionCheckItem : INotifyPropertyChanged
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
