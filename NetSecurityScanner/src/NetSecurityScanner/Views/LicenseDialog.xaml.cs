using System;
using System.Windows;
using NetSecurityScanner.Services;
using NetSecurityScanner.Models;

namespace NetSecurityScanner.Views
{
    public partial class LicenseDialog : Window
    {
        public LicenseDialog()
        {
            InitializeComponent();
            UpdateStatusDisplay();
        }

        private void UpdateStatusDisplay()
        {
            var licenseService = new LicenseService();
            var status = licenseService.GetLicenseStatus();

            StatusTextBlock.Text = status.StatusText;
            if (status.IsLicensed && !status.IsExpired)
            {
                StatusTextBlock.Foreground = new System.Windows.Media.SolidColorBrush(
                    System.Windows.Media.Color.FromRgb(0x27, 0xAE, 0x60));
            }
            else if (status.IsExpired)
            {
                StatusTextBlock.Foreground = new System.Windows.Media.SolidColorBrush(
                    System.Windows.Media.Color.FromRgb(0xE7, 0x4C, 0x3C));
            }
            else
            {
                StatusTextBlock.Foreground = new System.Windows.Media.SolidColorBrush(
                    System.Windows.Media.Color.FromRgb(0x95, 0xA5, 0xA6));
            }

            LicenseTypeTextBlock.Text = status.LicenseInfo != null
                ? $"授权类型：{status.LicenseInfo.DisplayName}"
                : "授权类型：无";

            ExpiryTextBlock.Text = status.LicenseInfo != null && status.LicenseInfo.ExpiryTime.HasValue
                ? $"到期时间：{status.LicenseInfo.ExpiryTime.Value:yyyy-MM-dd HH:mm:ss}"
                : status.LicenseInfo != null && status.LicenseInfo.IsPermanent
                    ? "到期时间：永久"
                    : "到期时间：-";

            MachineIdTextBox.Text = status.MachineId;
        }

        private void ActivateButton_Click(object sender, RoutedEventArgs e)
        {
            string code = LicenseCodeTextBox.Text.Trim();
            if (string.IsNullOrEmpty(code))
            {
                MessageBox.Show("请输入授权码", "提示", MessageBoxButton.OK, MessageBoxImage.Warning);
                return;
            }

            ActivateButton.IsEnabled = false;

            try
            {
                var licenseService = new LicenseService();
                bool success = licenseService.ActivateLicense(code);

                if (success)
                {
                    MessageBox.Show("授权激活成功！", "成功", MessageBoxButton.OK, MessageBoxImage.Information);
                    UpdateStatusDisplay();
                    DialogResult = true;
                }
                else
                {
                    licenseService.ValidateLicenseCode(code, out _, out string errorMessage);
                    MessageBox.Show(errorMessage, "激活失败", MessageBoxButton.OK, MessageBoxImage.Error);
                }
            }
            finally
            {
                ActivateButton.IsEnabled = true;
            }
        }

        private void CloseButton_Click(object sender, RoutedEventArgs e)
        {
            Close();
        }

        private void CopyMachineIdButton_Click(object sender, RoutedEventArgs e)
        {
            var licenseService = new LicenseService();
            string machineId = licenseService.GetCurrentMachineId();
            Clipboard.SetText(machineId);

            CopyMachineIdButton.Content = "✅ 已复制";
            CopyMachineIdButton.Background = new System.Windows.Media.SolidColorBrush(
                System.Windows.Media.Color.FromRgb(0x27, 0xAE, 0x60));

            var timer = new System.Windows.Threading.DispatcherTimer { Interval = TimeSpan.FromSeconds(2) };
            timer.Tick += (s, args) =>
            {
                CopyMachineIdButton.Content = "📋 复制机器码";
                CopyMachineIdButton.Background = new System.Windows.Media.SolidColorBrush(
                    System.Windows.Media.Color.FromRgb(0x34, 0x98, 0xDB));
                timer.Stop();
            };
            timer.Start();
        }
    }
}
