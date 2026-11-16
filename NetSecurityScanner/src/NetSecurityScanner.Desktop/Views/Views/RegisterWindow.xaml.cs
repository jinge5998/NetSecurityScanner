using System;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using NetSecurityScanner.Models;
using NetSecurityScanner.Services;

namespace NetSecurityScanner.Views
{
    public partial class RegisterWindow : Window
    {
        private readonly AuthService _authService;

        // 实时校验标志
        private bool _usernameAvailable = false;
        private bool _emailAvailable = true;
        private bool _phoneAvailable = true;

        public RegisterWindow()
        {
            InitializeComponent();
            _authService = new AuthService();
            UsernameTextBox.Focus();
            // 初始时让按钮状态基于格式校验结果（默认空输入 → 按钮 disabled）
            UpdateRegisterButton();
        }

        private void CancelButton_Click(object sender, RoutedEventArgs e)
        {
            DialogResult = false;
            Close();
        }

        // ========== 实时校验回调 ==========
        private async void UsernameTextBox_TextChanged(object sender, TextChangedEventArgs e)
        {
            string username = UsernameTextBox.Text?.Trim() ?? "";
            if (string.IsNullOrEmpty(username))
            {
                UsernameStatusText.Text = "";
                UsernameErrorText.Text = "";
                _usernameAvailable = false;
                UpdateRegisterButton();
                return;
            }
            if (!AuthService.IsValidUsername(username))
            {
                UsernameStatusText.Text = "❌ 格式错";
                UsernameStatusText.Foreground = Brushes.Red;
                UsernameErrorText.Text = "• 用户名必须为 3-32 位字母/数字/下划线";
                _usernameAvailable = false;
                UpdateRegisterButton();
                return;
            }
            // 异步查重（不阻塞 UI）
            try
            {
                bool ok = await Task.Run(() => _authService.IsUsernameAvailable(username));
                if (username != UsernameTextBox.Text?.Trim()) return; // 用户已改
                if (ok)
                {
                    UsernameStatusText.Text = "✅ 可用";
                    UsernameStatusText.Foreground = Brushes.Green;
                    UsernameErrorText.Text = "";
                    _usernameAvailable = true;
                }
                else
                {
                    UsernameStatusText.Text = "❌ 已占用";
                    UsernameStatusText.Foreground = Brushes.Red;
                    UsernameErrorText.Text = "• 该用户名已被占用";
                    _usernameAvailable = false;
                }
            }
            catch { /* 静默 */ }
            UpdateRegisterButton();
        }

        private async void EmailTextBox_TextChanged(object sender, TextChangedEventArgs e)
        {
            string email = EmailTextBox.Text?.Trim() ?? "";
            if (string.IsNullOrEmpty(email))
            {
                EmailStatusText.Text = "";
                EmailErrorText.Text = "";
                _emailAvailable = true;
                UpdateRegisterButton();
                return;
            }
            if (!AuthService.IsValidEmail(email))
            {
                EmailStatusText.Text = "❌ 格式错";
                EmailStatusText.Foreground = Brushes.Red;
                EmailErrorText.Text = "• 邮箱格式不正确";
                _emailAvailable = false;
                UpdateRegisterButton();
                return;
            }
            try
            {
                bool ok = await Task.Run(() => _authService.IsEmailAvailable(email));
                if (email != EmailTextBox.Text?.Trim()) return;
                if (ok)
                {
                    EmailStatusText.Text = "✅ 可用";
                    EmailStatusText.Foreground = Brushes.Green;
                    EmailErrorText.Text = "";
                    _emailAvailable = true;
                }
                else
                {
                    EmailStatusText.Text = "❌ 已注册";
                    EmailStatusText.Foreground = Brushes.Red;
                    EmailErrorText.Text = "• 该邮箱已被注册";
                    _emailAvailable = false;
                }
            }
            catch { }
            UpdateRegisterButton();
        }

        private async void PhoneTextBox_TextChanged(object sender, TextChangedEventArgs e)
        {
            string phone = PhoneTextBox.Text?.Trim() ?? "";
            if (string.IsNullOrEmpty(phone))
            {
                PhoneStatusText.Text = "";
                PhoneErrorText.Text = "";
                _phoneAvailable = true;
                UpdateRegisterButton();
                return;
            }
            if (!AuthService.IsValidPhone(phone))
            {
                PhoneStatusText.Text = "❌ 格式错";
                PhoneStatusText.Foreground = Brushes.Red;
                PhoneErrorText.Text = "• 手机号必须为 11 位数字且 1 开头";
                _phoneAvailable = false;
                UpdateRegisterButton();
                return;
            }
            try
            {
                bool ok = await Task.Run(() => _authService.IsPhoneAvailable(phone));
                if (phone != PhoneTextBox.Text?.Trim()) return;
                if (ok)
                {
                    PhoneStatusText.Text = "✅ 可用";
                    PhoneStatusText.Foreground = Brushes.Green;
                    PhoneErrorText.Text = "";
                    _phoneAvailable = true;
                }
                else
                {
                    PhoneStatusText.Text = "❌ 已注册";
                    PhoneStatusText.Foreground = Brushes.Red;
                    PhoneErrorText.Text = "• 该手机号已被注册";
                    _phoneAvailable = false;
                }
            }
            catch { }
            UpdateRegisterButton();
        }

        private void ReasonTextBox_TextChanged(object sender, TextChangedEventArgs e)
        {
            int len = ReasonTextBox.Text?.Length ?? 0;
            ReasonCountText.Text = len > 200
                ? $"❌ 超出限制 {len}/200"
                : $"📝 {len}/200 字符";
            ReasonCountText.Foreground = len > 200 ? Brushes.Red : Brushes.Gray;
            UpdateRegisterButton();
        }

        /// <summary>
        /// 生成 12 位随机强密码（含大小写字母 + 数字 + 特殊字符），自动填入密码框 + 确认密码框。
        /// 同步触发 PasswordChanged → 刷新强度条。
        /// </summary>
        private void GeneratePasswordButton_Click(object sender, RoutedEventArgs e)
        {
            const string upper = "ABCDEFGHJKLMNPQRSTUVWXYZ";  // 去掉 I,O
            const string lower = "abcdefghijkmnopqrstuvwxyz";  // 去掉 l
            const string digits = "23456789";                   // 去掉 0,1
            const string special = "!@#$%^&*";
            var all = upper + lower + digits + special;
            var rnd = new Random();
            var sb = new System.Text.StringBuilder(12);
            // 保证至少每种 1 个
            sb.Append(upper[rnd.Next(upper.Length)]);
            sb.Append(lower[rnd.Next(lower.Length)]);
            sb.Append(digits[rnd.Next(digits.Length)]);
            sb.Append(special[rnd.Next(special.Length)]);
            for (int i = 4; i < 12; i++)
                sb.Append(all[rnd.Next(all.Length)]);
            // 打乱顺序
            var chars = sb.ToString().ToCharArray();
            for (int i = chars.Length - 1; i > 0; i--)
            {
                int j = rnd.Next(i + 1);
                (chars[i], chars[j]) = (chars[j], chars[i]);
            }
            var pwd = new string(chars);
            PasswordBox.Password = pwd;
            ConfirmPasswordBox.Password = pwd;
            PasswordErrorText.Text = "🎲 已生成强密码，请记牢后提交";
            PasswordErrorText.Foreground = Brushes.Green;
            // 自动 focus 申请说明(可选)或保持当前焦点
        }

        private void PasswordBox_PasswordChanged(object sender, RoutedEventArgs e)
        {
            string pwd = PasswordBox.Password ?? "";
            int score = AuthService.CalcPasswordStrength(pwd);
            PasswordStrengthBar.Value = score;
            int level = AuthService.CalcPasswordStrengthLevel(pwd);
            switch (level)
            {
                case 0:
                    PasswordStrengthText.Text = "弱";
                    PasswordStrengthText.Foreground = Brushes.Red;
                    PasswordStrengthBar.Foreground = Brushes.Red;
                    break;
                case 1:
                    PasswordStrengthText.Text = "中";
                    PasswordStrengthText.Foreground = Brushes.Orange;
                    PasswordStrengthBar.Foreground = Brushes.Orange;
                    break;
                case 2:
                    PasswordStrengthText.Text = "强";
                    PasswordStrengthText.Foreground = Brushes.Green;
                    PasswordStrengthBar.Foreground = Brushes.Green;
                    break;
            }

            // 长度校验
            if (string.IsNullOrEmpty(pwd))
            {
                PasswordErrorText.Text = "";
            }
            else if (pwd.Length < 6)
            {
                PasswordErrorText.Text = $"• 至少 6 位（当前 {pwd.Length}）";
            }
            else
            {
                PasswordErrorText.Text = ""; // 弱密码不阻止，仅强度提示
            }

            // 同步刷新确认密码状态
            ValidateConfirmPassword();
            UpdateRegisterButton();
        }

        private void ConfirmPasswordBox_PasswordChanged(object sender, RoutedEventArgs e)
        {
            ValidateConfirmPassword();
            UpdateRegisterButton();
        }

        private void ValidateConfirmPassword()
        {
            string pwd = PasswordBox.Password ?? "";
            string confirm = ConfirmPasswordBox.Password ?? "";
            if (string.IsNullOrEmpty(confirm))
            {
                ConfirmPasswordErrorText.Text = "";
            }
            else if (!string.Equals(pwd, confirm))
            {
                ConfirmPasswordErrorText.Text = "• 两次密码不一致";
            }
            else
            {
                ConfirmPasswordErrorText.Text = "";
            }
        }

        private void UpdateRegisterButton()
        {
            string username = UsernameTextBox.Text?.Trim() ?? "";
            string email = EmailTextBox.Text?.Trim() ?? "";
            string phone = PhoneTextBox.Text?.Trim() ?? "";
            string pwd = PasswordBox.Password ?? "";
            string confirm = ConfirmPasswordBox.Password ?? "";

            // 按钮只依赖"同步可判"的格式校验，不等待异步查重
            // 异步查重（用户名/邮箱/手机是否已存在）移到 RegisterButton_Click 内做
            // 这样用户输入完成后按钮立即可点，不会因异步延迟而误以为"点击无反应"
            bool formatOk =
                AuthService.IsValidUsername(username) &&
                AuthService.IsValidEmail(email) &&
                AuthService.IsValidPhone(phone) &&
                pwd.Length >= 6 &&
                string.Equals(pwd, confirm) &&
                (ReasonTextBox.Text?.Length ?? 0) <= 200;

            RegisterButton.IsEnabled = formatOk;
        }

        private async void RegisterButton_Click(object sender, RoutedEventArgs e)
        {
            // 诊断日志：确认点击事件触发
            try
            {
                var diagDir = System.IO.Path.Combine(NetSecurityScanner.Utils.DataPaths.DataRoot, "logs");
                System.IO.Directory.CreateDirectory(diagDir);
                var diagFile = System.IO.Path.Combine(diagDir, "auth_diag.log");
                System.IO.File.AppendAllText(diagFile, $"[{DateTime.Now:HH:mm:ss.fff}] RegisterButton_Click: Triggered IsEnabled={RegisterButton.IsEnabled} Username='{UsernameTextBox.Text?.Trim() ?? ""}'\n");
            }
            catch { }

            string username = UsernameTextBox.Text?.Trim() ?? "";
            string displayName = DisplayNameTextBox.Text?.Trim() ?? "";
            string email = EmailTextBox.Text?.Trim() ?? "";
            string phone = PhoneTextBox.Text?.Trim() ?? "";
            string reason = ReasonTextBox.Text?.Trim() ?? "";
            string password = PasswordBox.Password ?? "";

            // 提交前最后一次整体校验
            if (!_usernameAvailable)
            {
                MessageBox.Show("用户名不可用，请换一个。", "注册失败", MessageBoxButton.OK, MessageBoxImage.Warning);
                UsernameTextBox.Focus();
                return;
            }
            if (!_emailAvailable || !_phoneAvailable)
            {
                MessageBox.Show("邮箱或手机号不可用，请检查。", "注册失败", MessageBoxButton.OK, MessageBoxImage.Warning);
                return;
            }

            RegisterButton.IsEnabled = false;
            try
            {
                var result = await _authService.RegisterAsync(
                    username, password,
                    string.IsNullOrEmpty(displayName) ? null : displayName,
                    string.IsNullOrEmpty(email) ? null : email,
                    string.IsNullOrEmpty(phone) ? null : phone,
                    string.IsNullOrEmpty(reason) ? null : reason);

                if (result.Success)
                {
                    // 检查当前 SessionContext:如果是 admin,弹窗里加"立即打开待审核"按钮一键跳转
                    var currentSession = SessionContext.Instance.Current;
                    bool isAdmin = currentSession?.IsAdmin == true;
                    var dlgResult = MessageBox.Show(
                        $"注册成功！\n\n账号 [{username}] 已创建，状态为「待审核」。\n请等待管理员审核通过后再登录。" +
                        (isAdmin ? "\n\n👉 点击「是」立即打开「用户审核」窗口查看" : ""),
                        "注册成功",
                        isAdmin ? MessageBoxButton.YesNo : MessageBoxButton.OK,
                        MessageBoxImage.Information);

                    // admin 点"是" → 主动调起 UserApprovalWindow
                    if (isAdmin && dlgResult == MessageBoxResult.Yes)
                    {
                        try
                        {
                            var owner = Window.GetWindow(this);
                            var approvalWin = new UserApprovalWindow { Owner = owner };
                            approvalWin.ShowDialog();
                        }
                        catch (Exception ex)
                        {
                            MessageBox.Show($"打开用户审核窗口失败: {ex.Message}", "错误",
                                MessageBoxButton.OK, MessageBoxImage.Error);
                        }
                    }
                    DialogResult = true;
                    Close();
                }
                else
                {
                    MessageBox.Show(result.Message, "注册失败", MessageBoxButton.OK, MessageBoxImage.Warning);
                    // 聚焦到错误字段
                    if (result.ErrorCode == RegisterError.UsernameTaken) UsernameTextBox.Focus();
                    else if (result.ErrorCode == RegisterError.EmailTaken) EmailTextBox.Focus();
                    else if (result.ErrorCode == RegisterError.PhoneTaken) PhoneTextBox.Focus();
                    else if (result.ErrorCode == RegisterError.InvalidPassword) PasswordBox.Focus();
                    RegisterButton.IsEnabled = true;
                    UpdateRegisterButton();
                }
            }
            catch (Exception ex)
            {
                MessageBox.Show($"注册失败：{ex.Message}", "错误", MessageBoxButton.OK, MessageBoxImage.Error);
                RegisterButton.IsEnabled = true;
            }
        }
    }
}
