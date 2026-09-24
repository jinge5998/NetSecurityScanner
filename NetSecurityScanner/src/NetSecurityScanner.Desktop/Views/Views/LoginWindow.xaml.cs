using System;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Input;
using NetSecurityScanner.Services;

namespace NetSecurityScanner.Views
{
    public partial class LoginWindow : Window
    {
        private readonly AuthService _authService;
        private bool _isSubmitting;

        public LoginWindow()
        {
            InitializeComponent();
            _authService = new AuthService();
            UsernameTextBox.Focus();
        }

        private void CancelButton_Click(object sender, RoutedEventArgs e)
        {
            DialogResult = false;
            Close();
        }

        private async void LoginButton_Click(object sender, RoutedEventArgs e)
        {
            await SubmitLoginAsync();
        }

        private async void Input_KeyDown(object sender, KeyEventArgs e)
        {
            if (e.Key == Key.Enter)
            {
                await SubmitLoginAsync();
            }
        }

        private async Task SubmitLoginAsync()
        {
            if (_isSubmitting) return;
            var username = UsernameTextBox.Text?.Trim() ?? "";
            var password = PasswordBox.Password ?? "";

            if (string.IsNullOrEmpty(username))
            {
                UsernameErrorText.Text = "请输入用户名";
                UsernameTextBox.Focus();
                return;
            }
            if (string.IsNullOrEmpty(password))
            {
                PasswordErrorText.Text = "请输入密码";
                PasswordBox.Focus();
                return;
            }

            _isSubmitting = true;
            LoginButton.IsEnabled = false;
            try
            {
                var result = await _authService.LoginAsync(username, password, RememberMeCheckBox.IsChecked == true);
                if (result.IsSuccess)
                {
                    DialogResult = true;
                    Close();
                }
                else
                {
                    PasswordErrorText.Text = result.Message;
                    PasswordBox.SelectAll();
                    PasswordBox.Focus();
                }
            }
            catch (Exception ex)
            {
                MessageBox.Show($"登录失败：{ex.Message}", "错误", MessageBoxButton.OK, MessageBoxImage.Error);
            }
            finally
            {
                _isSubmitting = false;
                LoginButton.IsEnabled = true;
            }
        }

        private void Input_TextChanged(object sender, RoutedEventArgs e)
        {
            UsernameErrorText.Text = "";
            PasswordErrorText.Text = "";
        }

        private void RegisterLinkButton_Click(object sender, RoutedEventArgs e)
        {
            var register = new RegisterWindow { Owner = this };
            var ok = register.ShowDialog();
            if (ok == true)
            {
                // 注册成功，焦点回到用户名
                UsernameTextBox.Focus();
            }
        }
    }
}
