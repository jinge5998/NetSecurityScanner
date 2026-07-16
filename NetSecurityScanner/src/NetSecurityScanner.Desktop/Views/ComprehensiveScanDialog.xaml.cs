using System.Net;
using System.Text.RegularExpressions;
using System.Windows;

namespace NetSecurityScanner.Desktop.Views
{
    public partial class ComprehensiveScanDialog : Window
    {
        public string TargetIp => TargetIpTextBox.Text.Trim();
        public string PortRange => PortRangeTextBox.Text.Trim();
        public bool EnableTcp => TcpCheckBox.IsChecked == true;
        public bool EnableUdp => UdpCheckBox.IsChecked == true;
        public bool EnableVulnerabilityScan => VulnerabilityScanCheckBox.IsChecked == true;
        public bool SaveToHistory => SaveToHistoryCheckBox.IsChecked == true;

        public ComprehensiveScanDialog()
        {
            InitializeComponent();
            TargetIpTextBox.TextChanged += (s, e) => ClearError(IpErrorTextBlock);
            PortRangeTextBox.TextChanged += (s, e) => ClearError(PortErrorTextBlock);
            TcpCheckBox.Checked += (s, e) => ClearError(ProtocolErrorTextBlock);
            UdpCheckBox.Checked += (s, e) => ClearError(ProtocolErrorTextBlock);
        }

        private void StartButton_Click(object sender, RoutedEventArgs e)
        {
            ClearError(IpErrorTextBlock);
            ClearError(PortErrorTextBlock);
            ClearError(ProtocolErrorTextBlock);

            var target = TargetIp;
            if (string.IsNullOrEmpty(target))
            {
                ShowError(IpErrorTextBlock, "请输入目标IP地址或域名");
                return;
            }

            if (!IsValidTarget(target))
            {
                ShowError(IpErrorTextBlock, "格式无效。请输入有效的 IPv4 地址（如 192.168.1.1）或域名（如 example.com）");
                return;
            }

            var portRange = PortRange;
            if (string.IsNullOrEmpty(portRange))
            {
                ShowError(PortErrorTextBlock, "请输入端口范围");
                return;
            }

            if (!IsValidPortRange(portRange))
            {
                ShowError(PortErrorTextBlock, "端口格式无效。支持范围（1-1000）、列表（22,80,443）或混合（1-100,443,8080）");
                return;
            }

            if (!EnableTcp && !EnableUdp)
            {
                ShowError(ProtocolErrorTextBlock, "请至少选择一种扫描协议（TCP 或 UDP）");
                return;
            }

            DialogResult = true;
            Close();
        }

        private bool IsValidTarget(string target)
        {
            if (IPAddress.TryParse(target, out _))
                return true;

            var domainPattern = @"^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*\.[a-zA-Z]{2,}$";
            return Regex.IsMatch(target, domainPattern);
        }

        private bool IsValidPortRange(string input)
        {
            var parts = input.Split(',');
            foreach (var part in parts)
            {
                var trimmed = part.Trim();
                if (trimmed.Contains('-'))
                {
                    var rangeParts = trimmed.Split('-');
                    if (rangeParts.Length != 2)
                        return false;
                    if (!int.TryParse(rangeParts[0].Trim(), out int start) || !int.TryParse(rangeParts[1].Trim(), out int end))
                        return false;
                    if (start < 1 || end > 65535 || start > end)
                        return false;
                }
                else
                {
                    if (!int.TryParse(trimmed, out int port))
                        return false;
                    if (port < 1 || port > 65535)
                        return false;
                }
            }
            return true;
        }

        private void ShowError(System.Windows.Controls.TextBlock errorBlock, string message)
        {
            errorBlock.Text = message;
            errorBlock.Visibility = Visibility.Visible;
        }

        private void ClearError(System.Windows.Controls.TextBlock errorBlock)
        {
            errorBlock.Text = "";
            errorBlock.Visibility = Visibility.Collapsed;
        }
    }
}
