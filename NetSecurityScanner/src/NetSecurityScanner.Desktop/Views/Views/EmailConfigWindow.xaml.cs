using System;
using System.IO;
using System.Text.Json;
using System.Threading.Tasks;
using System.Windows;

namespace NetSecurityScanner.Views
{
    public partial class EmailConfigWindow : Window
    {
        private readonly string _configPath;

        public EmailConfigWindow()
        {
            InitializeComponent();
            _configPath = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
                "NetSecurityScanner",
                "email_config.json"
            );
            Loaded += EmailConfigWindow_Loaded;
        }

        private void EmailConfigWindow_Loaded(object sender, RoutedEventArgs e)
        {
            LoadConfig();
        }

        private void LoadConfig()
        {
            try
            {
                if (File.Exists(_configPath))
                {
                    var json = File.ReadAllText(_configPath);
                    var config = JsonSerializer.Deserialize<EmailConfig>(json);
                    if (config != null)
                    {
                        SmtpServerTextBox.Text = config.SmtpServer ?? "";
                        SmtpPortTextBox.Text = config.SmtpPort.ToString();
                        EnableSslCheckBox.IsChecked = config.EnableSsl;
                        FromEmailTextBox.Text = config.FromEmail ?? "";
                        FromNameTextBox.Text = config.FromName ?? "网络安全扫描器";
                        UsernameTextBox.Text = config.Username ?? "";
                        PasswordBox.Password = config.Password ?? "";
                    }
                }
            }
            catch (Exception ex)
            {
                MessageBox.Show($"加载配置失败: {ex.Message}", "错误", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        private void QQEmailTemplate_Click(object sender, RoutedEventArgs e)
        {
            SmtpServerTextBox.Text = "smtp.qq.com";
            SmtpPortTextBox.Text = "587";
            EnableSslCheckBox.IsChecked = true;
        }

        private void NeteaseEmailTemplate_Click(object sender, RoutedEventArgs e)
        {
            SmtpServerTextBox.Text = "smtp.163.com";
            SmtpPortTextBox.Text = "25";
            EnableSslCheckBox.IsChecked = true;
        }

        private void GmailTemplate_Click(object sender, RoutedEventArgs e)
        {
            SmtpServerTextBox.Text = "smtp.gmail.com";
            SmtpPortTextBox.Text = "587";
            EnableSslCheckBox.IsChecked = true;
        }

        private void OutlookTemplate_Click(object sender, RoutedEventArgs e)
        {
            SmtpServerTextBox.Text = "smtp.office365.com";
            SmtpPortTextBox.Text = "587";
            EnableSslCheckBox.IsChecked = true;
        }

        private async void TestConnectionButton_Click(object sender, RoutedEventArgs e)
        {
            var config = GetConfigFromUI();
            if (config == null) return;

            var testEmail = TestRecipientTextBox.Text.Trim();
            if (string.IsNullOrEmpty(testEmail))
            {
                MessageBox.Show("请输入测试收件人邮箱", "提示", MessageBoxButton.OK, MessageBoxImage.Information);
                return;
            }

            try
            {
                TestConnectionButton.IsEnabled = false;
                TestConnectionButton.Content = "发送中...";

                var emailService = new Services.EmailNotificationService(
                    config.SmtpServer,
                    config.SmtpPort,
                    config.Username,
                    config.Password,
                    config.FromEmail
                );

                await emailService.SendScanNotificationAsync(testEmail, "测试邮件", 0, 0);

                MessageBox.Show("测试邮件发送成功！", "成功", MessageBoxButton.OK, MessageBoxImage.Information);
            }
            catch (Exception ex)
            {
                MessageBox.Show($"测试邮件发送失败: {ex.Message}", "错误", MessageBoxButton.OK, MessageBoxImage.Error);
            }
            finally
            {
                TestConnectionButton.IsEnabled = true;
                TestConnectionButton.Content = "🧪 测试连接";
            }
        }

        private void SaveConfigButton_Click(object sender, RoutedEventArgs e)
        {
            var config = GetConfigFromUI();
            if (config == null) return;

            try
            {
                var directory = Path.GetDirectoryName(_configPath);
                if (!Directory.Exists(directory))
                {
                    Directory.CreateDirectory(directory);
                }

                var json = JsonSerializer.Serialize(config, new JsonSerializerOptions
                {
                    WriteIndented = true
                });

                File.WriteAllText(_configPath, json);

                MessageBox.Show("邮件配置已保存", "成功", MessageBoxButton.OK, MessageBoxImage.Information);
                DialogResult = true;
                Close();
            }
            catch (Exception ex)
            {
                MessageBox.Show($"保存配置失败: {ex.Message}", "错误", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        private void CancelButton_Click(object sender, RoutedEventArgs e)
        {
            DialogResult = false;
            Close();
        }

        private EmailConfig? GetConfigFromUI()
        {
            if (string.IsNullOrWhiteSpace(SmtpServerTextBox.Text))
            {
                MessageBox.Show("请输入SMTP服务器地址", "提示", MessageBoxButton.OK, MessageBoxImage.Warning);
                return null;
            }

            if (!int.TryParse(SmtpPortTextBox.Text, out int port))
            {
                MessageBox.Show("请输入有效的端口号", "提示", MessageBoxButton.OK, MessageBoxImage.Warning);
                return null;
            }

            return new EmailConfig
            {
                SmtpServer = SmtpServerTextBox.Text.Trim(),
                SmtpPort = port,
                EnableSsl = EnableSslCheckBox.IsChecked ?? true,
                FromEmail = FromEmailTextBox.Text.Trim(),
                FromName = FromNameTextBox.Text.Trim(),
                Username = UsernameTextBox.Text.Trim(),
                Password = PasswordBox.Password
            };
        }
    }

    public class EmailConfig
    {
        public string SmtpServer { get; set; } = "";
        public int SmtpPort { get; set; } = 587;
        public bool EnableSsl { get; set; } = true;
        public string FromEmail { get; set; } = "";
        public string FromName { get; set; } = "网络安全扫描器";
        public string Username { get; set; } = "";
        public string Password { get; set; } = "";
    }
}
