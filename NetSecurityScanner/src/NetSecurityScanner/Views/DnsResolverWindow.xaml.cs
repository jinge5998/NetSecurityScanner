using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Windows;
using System.Windows.Controls;

namespace NetSecurityScanner.Views
{
    public partial class DnsResolverWindow : Window
    {
        public DnsResolverWindow()
        {
            InitializeComponent();
        }

        public class DnsResult
        {
            public string Address { get; set; }
            public string Type { get; set; }
            public string AddressFamily { get; set; }
        }

        private async void ResolveButton_Click(object sender, RoutedEventArgs e)
        {
            string domain = DomainTextBox.Text.Trim();
            
            if (string.IsNullOrEmpty(domain))
            {
                MessageBox.Show("请输入要解析的域名", "输入错误", MessageBoxButton.OK, MessageBoxImage.Warning);
                return;
            }

            ResolveButton.IsEnabled = false;
            ResolveButton.Content = "解析中...";
            ResultsDataGrid.ItemsSource = null;
            EmptyMessage.Visibility = Visibility.Collapsed;
            ResultCountText.Text = "正在解析...";

            try
            {
                var addresses = await Dns.GetHostAddressesAsync(domain);
                var results = addresses.Select(ip => new DnsResult
                {
                    Address = ip.ToString(),
                    Type = ip.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork ? "IPv4" : "IPv6",
                    AddressFamily = ip.AddressFamily.ToString()
                }).ToList();

                ResultsDataGrid.ItemsSource = results;
                ResultCountText.Text = $"{results.Count} 个IP地址";

                if (results.Count == 0)
                {
                    EmptyMessage.Text = "未找到该域名的IP地址";
                    EmptyMessage.Visibility = Visibility.Visible;
                    CopyAllButton.IsEnabled = false;
                }
                else
                {
                    CopyAllButton.IsEnabled = true;
                }
            }
            catch (Exception ex)
            {
                MessageBox.Show($"域名解析失败: {ex.Message}", "解析错误", MessageBoxButton.OK, MessageBoxImage.Error);
                EmptyMessage.Text = "解析失败，请检查域名是否正确";
                EmptyMessage.Visibility = Visibility.Visible;
                ResultCountText.Text = "0 个IP地址";
                CopyAllButton.IsEnabled = false;
            }
            finally
            {
                ResolveButton.IsEnabled = true;
                ResolveButton.Content = "解析";
            }
        }

        private void CopySingle_Click(object sender, RoutedEventArgs e)
        {
            if (sender is Button button && button.Tag is string address)
            {
                Clipboard.SetText(address);
                MessageBox.Show($"已复制: {address}", "复制成功", MessageBoxButton.OK, MessageBoxImage.Information);
            }
        }

        private void CopyAllButton_Click(object sender, RoutedEventArgs e)
        {
            if (ResultsDataGrid.ItemsSource is IEnumerable<DnsResult> results)
            {
                var addresses = string.Join(Environment.NewLine, results.Select(r => r.Address));
                Clipboard.SetText(addresses);
                MessageBox.Show($"已复制 {results.Count()} 个IP地址到剪贴板", "复制成功", MessageBoxButton.OK, MessageBoxImage.Information);
            }
        }

        private void CloseButton_Click(object sender, RoutedEventArgs e)
        {
            Close();
        }
    }
}
