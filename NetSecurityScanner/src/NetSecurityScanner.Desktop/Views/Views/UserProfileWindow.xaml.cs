using System;
using System.Windows;
using System.Windows.Media;
using NetSecurityScanner.Services;

namespace NetSecurityScanner.Views
{
    public partial class UserProfileWindow : Window
    {
        private readonly AuthService _authService;
        private readonly string _username;

        public UserProfileWindow()
        {
            InitializeComponent();
            _authService = new AuthService();
            _username = SessionContext.Instance.Current?.Username ?? "";

            CurrentUserText.Text = $"当前账号: {_username}";
            if (SessionContext.Instance.Current != null)
                DisplayNameTextBox.Text = SessionContext.Instance.Current.DisplayName;

            ValidateInputs();
        }

        private void Input_TextChanged(object sender, RoutedEventArgs e)
        {
            ValidateInputs();
        }

        private void ValidateInputs()
        {
            var displayName = DisplayNameTextBox.Text?.Trim() ?? "";
            var oldPwd = OldPasswordBox.Password ?? "";
            var newPwd = NewPasswordBox.Password ?? "";
            var confirm = ConfirmPasswordBox.Password ?? "";

            // 显示名校验
            DisplayNameErrorText.Text = string.IsNullOrWhiteSpace(displayName)
                ? "显示名称不能为空"
                : displayName.Length > 32
                    ? "显示名称不能超过 32 字符"
                    : "";

            // 旧密码必须填
            OldPasswordErrorText.Text = string.IsNullOrEmpty(oldPwd) ? "请输入当前密码" : "";

            // 新密码校验（可选，若填了则必须合规）
            bool wantChangePwd = !string.IsNullOrEmpty(newPwd);
            NewPasswordErrorText.Text = wantChangePwd && newPwd.Length < 6 ? "新密码至少 6 位" : "";
            ConfirmPasswordErrorText.Text = wantChangePwd && newPwd != confirm ? "两次输入的密码不一致" : "";

            // 保存按钮：显示名合规 + 旧密码已填 + (新密码为空 或 新密码合规)
            SaveButton.IsEnabled =
                !string.IsNullOrWhiteSpace(displayName) &&
                displayName.Length <= 32 &&
                !string.IsNullOrEmpty(oldPwd) &&
                (!wantChangePwd || (newPwd.Length >= 6 && newPwd == confirm));
        }

        private async void SaveButton_Click(object sender, RoutedEventArgs e)
        {
            SaveButton.IsEnabled = false;
            try
            {
                var newDisplayName = DisplayNameTextBox.Text.Trim();
                var oldPwd = OldPasswordBox.Password;
                var newPwd = NewPasswordBox.Password;

                // 1. 更新显示名
                bool nameOk = await _authService.UpdateDisplayNameAsync(_username, newDisplayName);
                if (!nameOk)
                {
                    MessageBox.Show("修改显示名失败。", "错误", MessageBoxButton.OK, MessageBoxImage.Error);
                    SaveButton.IsEnabled = true;
                    return;
                }

                // 2. 如果填了新密码，则改密
                if (!string.IsNullOrEmpty(newPwd))
                {
                    var pwdResult = await _authService.ChangePasswordAsync(_username, oldPwd, newPwd);
                    if (!pwdResult.IsSuccess)
                    {
                        MessageBox.Show($"密码修改失败：{pwdResult.Message}", "错误", MessageBoxButton.OK, MessageBoxImage.Error);
                        SaveButton.IsEnabled = true;
                        return;
                    }
                }

                MessageBox.Show("个人资料保存成功！", "成功", MessageBoxButton.OK, MessageBoxImage.Information);
                DialogResult = true;
                Close();
            }
            catch (Exception ex)
            {
                MessageBox.Show($"保存失败：{ex.Message}", "错误", MessageBoxButton.OK, MessageBoxImage.Error);
                SaveButton.IsEnabled = true;
            }
        }

        private void CancelButton_Click(object sender, RoutedEventArgs e)
        {
            DialogResult = false;
            Close();
        }
    }
}
