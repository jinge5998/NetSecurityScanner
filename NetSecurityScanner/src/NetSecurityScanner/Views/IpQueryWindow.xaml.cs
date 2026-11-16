using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using System.Windows.Media;
using Microsoft.Win32;

namespace NetSecurityScanner.Views
{
    public partial class IpQueryWindow : Window
    {
        private readonly IpInfoService _ipInfoService;
        private readonly List<HistoryRecord> _historyRecords = new();
        private readonly List<DnsResult> _currentDnsResults = new();
        private int _pingSequence = 0;
        private int _recordIndex = 0;

        public IpQueryWindow()
        {
            InitializeComponent();
            _ipInfoService = new IpInfoService();
        }

        #region 事件处理

        private void QueryTextBox_KeyDown(object sender, KeyEventArgs e)
        {
            if (e.Key == Key.Enter)
            {
                Query_Click(sender, e);
            }
        }

        private async void Query_Click(object sender, RoutedEventArgs e)
        {
            string query = QueryTextBox.Text.Trim();
            if (string.IsNullOrEmpty(query))
            {
                MessageBox.Show("请输入域名或IP地址（多个用逗号或换行分隔）", "提示",
                    MessageBoxButton.OK, MessageBoxImage.Warning);
                return;
            }

            ShowLoading(true, "正在查询中...");
            StatusText.Text = "正在查询...";

            try
            {
                var queries = ParseQueries(query);
                var results = new List<DnsResult>();
                int index = 1;
                var totalStart = DateTime.Now;

                foreach (var q in queries)
                {
                    var stopwatch = Stopwatch.StartNew();
                    try
                    {
                        bool isIp = IsIpAddress(q);
                        if (isIp)
                        {
                            results.Add(new DnsResult
                            {
                                Index = index++,
                                Source = q,
                                IpAddress = q,
                                AddressType = GetIpType(q),
                                AddressFamily = GetAddressFamily(q),
                                DurationMs = (int)stopwatch.ElapsedMilliseconds,
                                Status = "✓ 成功"
                            });
                        }
                        else
                        {
                            var addresses = await Dns.GetHostAddressesAsync(q);
                            bool first = true;
                            foreach (var addr in addresses)
                            {
                                results.Add(new DnsResult
                                {
                                    Index = first ? index : 0,
                                    Source = first ? q : "",
                                    IpAddress = addr.ToString(),
                                    AddressType = GetIpType(addr.ToString()),
                                    AddressFamily = GetAddressFamily(addr.ToString()),
                                    DurationMs = (int)stopwatch.ElapsedMilliseconds,
                                    Status = "✓ 成功"
                                });
                                first = false;
                            }
                            if (!addresses.Any())
                            {
                                results.Add(new DnsResult
                                {
                                    Index = index++,
                                    Source = q,
                                    IpAddress = "-",
                                    DurationMs = (int)stopwatch.ElapsedMilliseconds,
                                    Status = "✗ 无结果"
                                });
                            }
                            else
                            {
                                index++;
                            }
                        }

                        if (IpLocationCheckBox.IsChecked == true && results.LastOrDefault(r => r.Source == q) is { } lastResult)
                        {
                            var ip = lastResult.IpAddress;
                            if (IsIpAddress(ip) && !ip.StartsWith("127."))
                            {
                                await QueryIpInfoAsync(ip);
                            }
                        }
                    }
                    catch (Exception ex)
                    {
                        results.Add(new DnsResult
                        {
                            Index = index++,
                            Source = q,
                            IpAddress = "-",
                            DurationMs = (int)stopwatch.ElapsedMilliseconds,
                            Status = $"✗ 失败: {ex.Message.Substring(0, Math.Min(20, ex.Message.Length))}"
                        });
                    }
                }

                var totalDuration = (int)(DateTime.Now - totalStart).TotalMilliseconds;
                DnsResultsGrid.ItemsSource = results;
                DnsCountText.Text = results.Count.ToString();
                DnsDurationText.Text = totalDuration.ToString();
                _currentDnsResults.Clear();
                _currentDnsResults.AddRange(results);

                AddHistory(query, "DNS解析", $"共解析 {results.Count} 条结果，耗时 {totalDuration}ms");

                if (ReverseDnsCheckBox.IsChecked == true && results.Any())
                {
                    await PerformReverseDnsAsync(results);
                }

                if (PingTestCheckBox.IsChecked == true && results.Any())
                {
                    var firstIp = results.FirstOrDefault(r => IsIpAddress(r.IpAddress) && !r.IpAddress.StartsWith("127."));
                    if (firstIp != null)
                    {
                        ResultTabs.SelectedIndex = 3;
                        await PerformPingAsync(firstIp.IpAddress, 4);
                    }
                }

                if (results.Count == 1 && IsIpAddress(results[0].IpAddress))
                {
                    await QueryIpInfoAsync(results[0].IpAddress);
                }

                StatusText.Text = $"✓ 查询完成，共 {results.Count} 条结果";
            }
            catch (Exception ex)
            {
                StatusText.Text = $"✗ 查询失败: {ex.Message}";
                MessageBox.Show($"查询失败: {ex.Message}", "错误", MessageBoxButton.OK, MessageBoxImage.Error);
            }
            finally
            {
                ShowLoading(false);
            }
        }

        private async void Ping_Click(object sender, RoutedEventArgs e)
        {
            string target = QueryTextBox.Text.Trim();
            if (string.IsNullOrEmpty(target))
            {
                MessageBox.Show("请输入要Ping的目标", "提示", MessageBoxButton.OK, MessageBoxImage.Warning);
                return;
            }

            try
            {
                if (!IsIpAddress(target))
                {
                    var addresses = await Dns.GetHostAddressesAsync(target);
                    target = addresses.FirstOrDefault()?.ToString() ?? target;
                }
            }
            catch
            {
                // 继续使用原值
            }

            ResultTabs.SelectedIndex = 3;
            await PerformPingAsync(target, 4);
        }

        private async Task PerformPingAsync(string target, int count)
        {
            ShowLoading(true, $"正在Ping {target}...");
            StatusText.Text = $"正在Ping {target}...";

            try
            {
                PingTargetText.Text = target;
                var results = new List<PingResult>();
                var rtts = new List<long>();
                int lost = 0;

                using var ping = new Ping();
                for (int i = 1; i <= count; i++)
                {
                    try
                    {
                        var reply = await ping.SendPingAsync(target, 3000);
                        var result = new PingResult
                        {
                            Index = i,
                            Bytes = 32,
                            Address = reply.Address?.ToString() ?? target,
                            Sequence = $"{i} TTL={reply.Options?.Ttl ?? 0}",
                            RttMs = reply.RoundtripTime,
                            Status = reply.Status == IPStatus.Success ? "✓ 成功" : $"✗ {reply.Status}"
                        };
                        results.Add(result);
                        if (reply.Status == IPStatus.Success)
                            rtts.Add(reply.RoundtripTime);
                        else
                            lost++;
                    }
                    catch (Exception ex)
                    {
                        results.Add(new PingResult
                        {
                            Index = i,
                            Bytes = 32,
                            Address = target,
                            Sequence = $"{i}",
                            RttMs = -1,
                            Status = $"✗ {ex.Message.Substring(0, Math.Min(20, ex.Message.Length))}"
                        });
                        lost++;
                    }
                }

                PingResultsGrid.ItemsSource = results;
                if (rtts.Any())
                {
                    PingAvgText.Text = $"{rtts.Average():F0}";
                }
                else
                {
                    PingAvgText.Text = "-";
                }
                PingLossText.Text = $"{(lost * 100.0 / count):F0}%";

                AddHistory(target, "Ping测试", $"发送{count}次，丢包{lost}次，平均延迟{(rtts.Any() ? rtts.Average().ToString("F0") : "-")}ms");
                StatusText.Text = $"✓ Ping完成，{count}次，丢包{lost}次";
            }
            catch (Exception ex)
            {
                StatusText.Text = $"✗ Ping失败: {ex.Message}";
                MessageBox.Show($"Ping失败: {ex.Message}", "错误", MessageBoxButton.OK, MessageBoxImage.Error);
            }
            finally
            {
                ShowLoading(false);
            }
        }

        private async void ScanIpRange_Click(object sender, RoutedEventArgs e)
        {
            string range = IpRangeTextBox.Text.Trim();
            if (string.IsNullOrEmpty(range))
            {
                MessageBox.Show("请输入IP段（如 192.168.1.0/24）", "提示",
                    MessageBoxButton.OK, MessageBoxImage.Warning);
                return;
            }

            ShowLoading(true, "正在扫描IP段...");
            StatusText.Text = "正在扫描IP段...";

            try
            {
                var ips = ParseIpRange(range);
                if (ips.Count > 1000)
                {
                    var confirm = MessageBox.Show(
                        $"IP段包含 {ips.Count} 个地址，扫描可能需要较长时间。\n是否继续？",
                        "确认", MessageBoxButton.YesNo, MessageBoxImage.Question);
                    if (confirm != MessageBoxResult.Yes) return;
                }

                var results = new List<DnsResult>();
                int index = 1;
                var totalStart = DateTime.Now;

                foreach (var ip in ips)
                {
                    var stopwatch = Stopwatch.StartNew();
                    try
                    {
                        using var ping = new Ping();
                        var reply = await ping.SendPingAsync(ip, 1000);
                        if (reply.Status == IPStatus.Success)
                        {
                            try
                            {
                                var hostEntry = await Dns.GetHostEntryAsync(ip);
                                results.Add(new DnsResult
                                {
                                    Index = index++,
                                    Source = hostEntry.HostName,
                                    IpAddress = ip,
                                    AddressType = "IPv4",
                                    AddressFamily = "IPv4",
                                    DurationMs = (int)reply.RoundtripTime,
                                    Status = "✓ 在线"
                                });
                            }
                            catch
                            {
                                results.Add(new DnsResult
                                {
                                    Index = index++,
                                    Source = "-",
                                    IpAddress = ip,
                                    AddressType = "IPv4",
                                    AddressFamily = "IPv4",
                                    DurationMs = (int)reply.RoundtripTime,
                                    Status = "✓ 在线"
                                });
                            }
                        }
                    }
                    catch
                    {
                        // 跳过无响应IP
                    }
                }

                var totalDuration = (int)(DateTime.Now - totalStart).TotalMilliseconds;
                DnsResultsGrid.ItemsSource = results;
                DnsCountText.Text = results.Count.ToString();
                DnsDurationText.Text = totalDuration.ToString();
                _currentDnsResults.Clear();
                _currentDnsResults.AddRange(results);

                AddHistory(range, "IP段扫描", $"扫描{ips.Count}个地址，发现{results.Count}个在线，耗时{totalDuration}ms");
                StatusText.Text = $"✓ 扫描完成，{results.Count}/{ips.Count} 在线";
            }
            catch (Exception ex)
            {
                StatusText.Text = $"✗ 扫描失败: {ex.Message}";
                MessageBox.Show($"扫描失败: {ex.Message}", "错误", MessageBoxButton.OK, MessageBoxImage.Error);
            }
            finally
            {
                ShowLoading(false);
            }
        }

        private async void BatchResolve_Click(object sender, RoutedEventArgs e)
        {
            var dlg = new BatchInputDialog("批量解析", "请输入要批量解析的域名或IP（每行一个）：");
            if (dlg.ShowDialog() == true && !string.IsNullOrWhiteSpace(dlg.InputText))
            {
                QueryTextBox.Text = dlg.InputText;
                await Task.Delay(100);
                Query_Click(sender, e);
            }
        }

        private void ExportResults_Click(object sender, RoutedEventArgs e)
        {
            if (!_currentDnsResults.Any())
            {
                MessageBox.Show("没有可导出的结果", "提示", MessageBoxButton.OK, MessageBoxImage.Warning);
                return;
            }

            var dlg = new SaveFileDialog
            {
                Filter = "CSV文件 (*.csv)|*.csv|文本文件 (*.txt)|*.txt",
                FileName = $"IP查询结果_{DateTime.Now:yyyyMMdd_HHmmss}.csv"
            };

            if (dlg.ShowDialog() == true)
            {
                try
                {
                    var sb = new StringBuilder();
                    sb.AppendLine("序号,源,IP地址,类型,地址族,耗时(ms),状态");
                    foreach (var r in _currentDnsResults)
                    {
                        sb.AppendLine($"{r.Index},{r.Source},{r.IpAddress},{r.AddressType},{r.AddressFamily},{r.DurationMs},{r.Status}");
                    }
                    File.WriteAllText(dlg.FileName, sb.ToString(), Encoding.UTF8);
                    MessageBox.Show($"结果已导出到: {dlg.FileName}", "成功",
                        MessageBoxButton.OK, MessageBoxImage.Information);
                    AddHistory(dlg.FileName, "导出结果", $"导出{_currentDnsResults.Count}条记录");
                }
                catch (Exception ex)
                {
                    MessageBox.Show($"导出失败: {ex.Message}", "错误",
                        MessageBoxButton.OK, MessageBoxImage.Error);
                }
            }
        }

        private void Clear_Click(object sender, RoutedEventArgs e)
        {
            QueryTextBox.Text = string.Empty;
            DnsResultsGrid.ItemsSource = null;
            DnsCountText.Text = "0";
            DnsDurationText.Text = "0";
            PingResultsGrid.ItemsSource = null;
            PingAvgText.Text = "0";
            PingLossText.Text = "0%";
            PingTargetText.Text = "-";
            WhoisResultText.Text = "点击查询按钮获取Whois信息...";
            ClearLocationPanel();
            ClearDetailsPanel();
            _currentDnsResults.Clear();
            StatusText.Text = "就绪";
        }

        private async void QueryIpDetail_Click(object sender, RoutedEventArgs e)
        {
            if (sender is Button btn && btn.DataContext is DnsResult selected)
            {
                if (!IsIpAddress(selected.IpAddress)) return;
                QueryTextBox.Text = selected.IpAddress;
                ResultTabs.SelectedIndex = 1;
                await QueryIpInfoAsync(selected.IpAddress);

                AddHistory(selected.IpAddress, "IP详情", $"{selected.IpAddress} - {selected.AddressType}");

                WhoisResultText.Text = $"正在进行Whois查询...\n\n目标: {selected.IpAddress}\n时间: {DateTime.Now}\n\n请稍候...";
                try
                {
                    var whois = await _ipInfoService.GetWhoisAsync(selected.IpAddress);
                    WhoisResultText.Text = whois;
                }
                catch (Exception ex)
                {
                    WhoisResultText.Text = $"Whois查询失败: {ex.Message}\n\n提示：Whois查询需要稳定的网络连接到 whois.iana.org";
                }
            }
        }

        private async void PingIp_Click(object sender, RoutedEventArgs e)
        {
            if (sender is Button btn && btn.DataContext is DnsResult selected)
            {
                if (!IsIpAddress(selected.IpAddress)) return;
                ResultTabs.SelectedIndex = 3;
                await PerformPingAsync(selected.IpAddress, 4);
            }
        }

        private void CopyIp_Click(object sender, RoutedEventArgs e)
        {
            if (sender is Button btn && btn.DataContext is DnsResult selected)
            {
                try
                {
                    Clipboard.SetText(selected.IpAddress);
                    StatusText.Text = $"✓ 已复制: {selected.IpAddress}";
                }
                catch (Exception ex)
                {
                    MessageBox.Show($"复制失败: {ex.Message}", "错误", MessageBoxButton.OK, MessageBoxImage.Error);
                }
            }
        }

        private void OpenMap_Click(object sender, RoutedEventArgs e)
        {
            if (string.IsNullOrEmpty(LocationCoordsText.Text) || LocationCoordsText.Text == "未知")
            {
                MessageBox.Show("无经纬度信息", "提示", MessageBoxButton.OK, MessageBoxImage.Warning);
                return;
            }

            try
            {
                var url = $"https://www.openstreetmap.org/?mlat={LocationCoordsText.Text.Split(',')[0].Trim()}&mlon={LocationCoordsText.Text.Split(',')[1].Trim()}&zoom=10";
                Process.Start(new ProcessStartInfo(url) { UseShellExecute = true });
            }
            catch (Exception ex)
            {
                MessageBox.Show($"打开地图失败: {ex.Message}", "错误", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        #endregion

        #region 私有方法

        private List<string> ParseQueries(string input)
        {
            return input.Split(new[] { ',', '\n', '\r', ';', ' ' }, StringSplitOptions.RemoveEmptyEntries)
                .Select(s => s.Trim())
                .Where(s => !string.IsNullOrEmpty(s))
                .Distinct()
                .ToList();
        }

        private List<string> ParseIpRange(string range)
        {
            var result = new List<string>();
            try
            {
                if (range.Contains("/"))
                {
                    var parts = range.Split('/');
                    if (parts.Length == 2 && int.TryParse(parts[1], out int cidr))
                    {
                        if (!System.Net.IPAddress.TryParse(parts[0], out var baseIp))
                            throw new ArgumentException("无效的IP地址");

                        var ipBytes = baseIp.GetAddressBytes();
                        if (ipBytes.Length != 4)
                            throw new ArgumentException("仅支持IPv4网段");

                        uint ipNum = ((uint)ipBytes[0] << 24) | ((uint)ipBytes[1] << 16) | ((uint)ipBytes[2] << 8) | ipBytes[3];
                        uint mask = cidr == 0 ? 0 : 0xFFFFFFFF << (32 - cidr);
                        uint network = ipNum & mask;
                        uint broadcast = network | ~mask;

                        for (uint i = network; i <= broadcast && result.Count < 65536; i++)
                        {
                            result.Add($"{i >> 24}.{(i >> 16) & 0xFF}.{(i >> 8) & 0xFF}.{i & 0xFF}");
                        }
                    }
                }
                else if (range.Contains("-"))
                {
                    var parts = range.Split('-');
                    if (parts.Length == 2 && System.Net.IPAddress.TryParse(parts[0], out var startIp)
                        && System.Net.IPAddress.TryParse(parts[1], out var endIp))
                    {
                        var startBytes = startIp.GetAddressBytes();
                        var endBytes = endIp.GetAddressBytes();
                        uint start = ((uint)startBytes[0] << 24) | ((uint)startBytes[1] << 16) | ((uint)startBytes[2] << 8) | startBytes[3];
                        uint end = ((uint)endBytes[0] << 24) | ((uint)endBytes[1] << 16) | ((uint)endBytes[2] << 8) | endBytes[3];

                        for (uint i = start; i <= end && result.Count < 65536; i++)
                        {
                            result.Add($"{i >> 24}.{(i >> 16) & 0xFF}.{(i >> 8) & 0xFF}.{i & 0xFF}");
                        }
                    }
                }
                else
                {
                    result.Add(range);
                }
            }
            catch (Exception ex)
            {
                throw new ArgumentException($"解析IP段失败: {ex.Message}");
            }
            return result;
        }

        private async Task QueryIpInfoAsync(string ip)
        {
            try
            {
                var ipInfo = await _ipInfoService.GetIpInfoAsync(ip);
                if (IpLocationCheckBox.IsChecked == true)
                {
                    ShowIpLocation(ipInfo);
                }
                if (IpDetailsCheckBox.IsChecked == true)
                {
                    ShowIpDetails(ipInfo);
                }
            }
            catch (Exception ex)
            {
                MessageBox.Show($"IP信息查询失败: {ex.Message}", "错误", MessageBoxButton.OK, MessageBoxImage.Warning);
            }
        }

        private async Task PerformReverseDnsAsync(List<DnsResult> results)
        {
            foreach (var r in results.Where(x => IsIpAddress(x.IpAddress) && !x.IpAddress.StartsWith("127.")).Take(10))
            {
                try
                {
                    var hostEntry = await Dns.GetHostEntryAsync(r.IpAddress);
                    r.Status = $"✓ {hostEntry.HostName}";
                }
                catch
                {
                    // 跳过反向解析失败
                }
            }
            DnsResultsGrid.Items.Refresh();
        }

        private void ShowIpLocation(IpInfoResult ipInfo)
        {
            IpLocationPanel.Visibility = Visibility.Visible;
            LocationIpText.Text = ipInfo.Query;
            LocationCountryFlag.Text = GetCountryFlag(ipInfo.CountryCode);
            LocationCountryText.Text = $"{ipInfo.Country} ({ipInfo.CountryCode})";
            LocationRegionText.Text = string.IsNullOrEmpty(ipInfo.Region) ? "未知" : ipInfo.Region;
            LocationCityText.Text = string.IsNullOrEmpty(ipInfo.City) ? "未知" : ipInfo.City;
            LocationZipText.Text = string.IsNullOrEmpty(ipInfo.Zip) ? "未知" : ipInfo.Zip;
            LocationIspText.Text = string.IsNullOrEmpty(ipInfo.Isp) ? "未知" : ipInfo.Isp;
            LocationCoordsText.Text = string.IsNullOrEmpty(ipInfo.Latitude) ? "未知" : $"{ipInfo.Latitude}, {ipInfo.Longitude}";
        }

        private void ShowIpDetails(IpInfoResult ipInfo)
        {
            IpDetailsPanel.Visibility = Visibility.Visible;
            DetailAsnText.Text = string.IsNullOrEmpty(ipInfo.Asn) ? "未知" : ipInfo.Asn;
            DetailOrgText.Text = string.IsNullOrEmpty(ipInfo.Org) ? "未知" : ipInfo.Org;
            DetailNetworkText.Text = string.IsNullOrEmpty(ipInfo.Network) ? ipInfo.As : ipInfo.Network;
            DetailHostnameText.Text = string.IsNullOrEmpty(ipInfo.Hostname) ? "未知" : ipInfo.Hostname;
            DetailTimezoneText.Text = string.IsNullOrEmpty(ipInfo.Timezone) ? "未知" : ipInfo.Timezone;
            DetailRegionCodeText.Text = string.IsNullOrEmpty(ipInfo.RegionCode) ? "未知" : ipInfo.RegionCode;
            DetailCurrencyText.Text = string.IsNullOrEmpty(ipInfo.Currency) ? "未知" : ipInfo.Currency;
            DetailLanguageText.Text = string.IsNullOrEmpty(ipInfo.Language) ? "未知" : ipInfo.Language;
            DetailSecurityText.Text = string.IsNullOrEmpty(ipInfo.Proxy) ? "未知" :
                (ipInfo.Proxy == "true" ? "⚠️ 代理/ VPN" : "✅ 正常");
            DetailSourceText.Text = "ip-api.com (免费API)";
        }

        private void ClearLocationPanel()
        {
            LocationIpText.Text = "-";
            LocationCountryFlag.Text = "🏳️";
            LocationCountryText.Text = "-";
            LocationRegionText.Text = "-";
            LocationCityText.Text = "-";
            LocationZipText.Text = "-";
            LocationIspText.Text = "-";
            LocationCoordsText.Text = "-";
        }

        private void ClearDetailsPanel()
        {
            DetailAsnText.Text = "-";
            DetailOrgText.Text = "-";
            DetailNetworkText.Text = "-";
            DetailHostnameText.Text = "-";
            DetailTimezoneText.Text = "-";
            DetailRegionCodeText.Text = "-";
            DetailCurrencyText.Text = "-";
            DetailLanguageText.Text = "-";
            DetailSecurityText.Text = "-";
            DetailSourceText.Text = "-";
        }

        private void AddHistory(string query, string type, string result)
        {
            _historyRecords.Insert(0, new HistoryRecord
            {
                Time = DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss"),
                Query = query,
                Type = type,
                Result = result
            });
            HistoryGrid.ItemsSource = null;
            HistoryGrid.ItemsSource = _historyRecords.Take(100).ToList();
        }

        private bool IsIpAddress(string input)
        {
            return System.Net.IPAddress.TryParse(input, out _);
        }

        private string GetIpType(string ip)
        {
            if (System.Net.IPAddress.TryParse(ip, out var address))
            {
                return address.AddressFamily == AddressFamily.InterNetworkV6 ? "IPv6" : "IPv4";
            }
            return "未知";
        }

        private string GetAddressFamily(string ip)
        {
            if (System.Net.IPAddress.TryParse(ip, out var address))
            {
                return address.AddressFamily switch
                {
                    AddressFamily.InterNetwork => "IPv4",
                    AddressFamily.InterNetworkV6 => "IPv6",
                    _ => "其他"
                };
            }
            return "未知";
        }

        private string GetCountryFlag(string countryCode)
        {
            if (string.IsNullOrEmpty(countryCode) || countryCode.Length != 2)
                return "🏳️";
            return char.ConvertFromUtf32(0x1F1E6 + (countryCode[0] - 'A'))
                 + char.ConvertFromUtf32(0x1F1E6 + (countryCode[1] - 'A'));
        }

        private void ShowLoading(bool show, string text = "正在查询...")
        {
            LoadingOverlay.Visibility = show ? Visibility.Visible : Visibility.Collapsed;
            LoadingText.Text = text;
        }

        #endregion
    }

    #region 数据模型

    public class DnsResult
    {
        public int Index { get; set; }
        public string Source { get; set; } = string.Empty;
        public string IpAddress { get; set; } = string.Empty;
        public string AddressType { get; set; } = string.Empty;
        public string AddressFamily { get; set; } = string.Empty;
        public int DurationMs { get; set; }
        public string Status { get; set; } = string.Empty;
    }

    public class PingResult
    {
        public int Index { get; set; }
        public int Bytes { get; set; }
        public string Address { get; set; } = string.Empty;
        public string Sequence { get; set; } = string.Empty;
        public long RttMs { get; set; }
        public string Status { get; set; } = string.Empty;
    }

    public class HistoryRecord
    {
        public string Time { get; set; } = string.Empty;
        public string Query { get; set; } = string.Empty;
        public string Type { get; set; } = string.Empty;
        public string Result { get; set; } = string.Empty;
    }

    public class IpInfoResult
    {
        public string Query { get; set; } = string.Empty;
        public string Status { get; set; } = string.Empty;
        public string Country { get; set; } = string.Empty;
        public string CountryCode { get; set; } = string.Empty;
        public string Region { get; set; } = string.Empty;
        public string RegionCode { get; set; } = string.Empty;
        public string RegionName { get; set; } = string.Empty;
        public string City { get; set; } = string.Empty;
        public string Zip { get; set; } = string.Empty;
        public string Latitude { get; set; } = string.Empty;
        public string Longitude { get; set; } = string.Empty;
        public string Timezone { get; set; } = string.Empty;
        public string Isp { get; set; } = string.Empty;
        public string Org { get; set; } = string.Empty;
        public string As { get; set; } = string.Empty;
        public string Asn => As;
        public string Network { get; set; } = string.Empty;
        public string Hostname { get; set; } = string.Empty;
        public string Currency { get; set; } = string.Empty;
        public string Language { get; set; } = string.Empty;
        public string Proxy { get; set; } = string.Empty;
    }

    public class IpInfoService
    {
        private const string ApiUrl = "http://ip-api.com/json/";
        private const string WhoisUrl = "https://whois.iana.org/";

        public async Task<IpInfoResult> GetIpInfoAsync(string ip)
        {
            try
            {
                using var client = new HttpClient();
                client.Timeout = TimeSpan.FromSeconds(10);
                client.DefaultRequestHeaders.Add("User-Agent", "NetSecurityScanner/1.0");

                var response = await client.GetStringAsync($"{ApiUrl}{ip}?lang=zh-CN");
                var result = System.Text.Json.JsonSerializer.Deserialize<IpApiResponse>(response,
                    new System.Text.Json.JsonSerializerOptions { PropertyNameCaseInsensitive = true });

                if (result != null && result.Status == "success")
                {
                    var ipInfo = new IpInfoResult
                    {
                        Query = result.Query ?? ip,
                        Status = result.Status ?? "fail",
                        Country = result.Country ?? "未知",
                        CountryCode = result.CountryCode ?? "",
                        Region = result.RegionName ?? "未知",
                        RegionName = result.RegionName ?? "未知",
                        RegionCode = result.Region ?? "",
                        City = result.City ?? "未知",
                        Zip = result.Zip ?? "",
                        Latitude = result.Lat?.ToString() ?? "",
                        Longitude = result.Lon?.ToString() ?? "",
                        Timezone = result.Timezone ?? "未知",
                        Isp = result.Isp ?? "未知",
                        Org = result.Org ?? "未知",
                        As = result.As ?? "未知",
                        Proxy = result.Proxy ?? "false",
                        Currency = GetCurrencyByCountry(result.CountryCode ?? ""),
                        Language = GetLanguageByCountry(result.CountryCode ?? "")
                    };

                    try
                    {
                        var hostEntry = await Dns.GetHostEntryAsync(ip);
                        ipInfo.Hostname = hostEntry.HostName ?? "未知";
                    }
                    catch
                    {
                        ipInfo.Hostname = "未知";
                    }

                    return ipInfo;
                }

                return new IpInfoResult { Query = ip, Status = "fail" };
            }
            catch
            {
                return new IpInfoResult { Query = ip, Status = "error" };
            }
        }

        public async Task<string> GetWhoisAsync(string ip)
        {
            try
            {
                using var client = new HttpClient();
                client.Timeout = TimeSpan.FromSeconds(15);
                client.DefaultRequestHeaders.Add("User-Agent", "NetSecurityScanner/1.0");

                var response = await client.GetStringAsync($"{WhoisUrl}?q={ip}");
                return FormatWhoisResponse(response, ip);
            }
            catch (Exception ex)
            {
                return $"Whois查询失败: {ex.Message}\n\n提示：Whois查询需要稳定的网络连接到 whois.iana.org\n您可以手动访问: https://whois.iana.org/ 查询 {ip}";
            }
        }

        private string FormatWhoisResponse(string raw, string ip)
        {
            var sb = new StringBuilder();
            sb.AppendLine($"========== Whois 查询结果 ==========");
            sb.AppendLine($"查询目标: {ip}");
            sb.AppendLine($"查询时间: {DateTime.Now:yyyy-MM-dd HH:mm:ss}");
            sb.AppendLine($"====================================");
            sb.AppendLine();

            var lines = raw.Split('\n');
            int lineCount = 0;
            foreach (var line in lines)
            {
                if (lineCount++ > 80) break;
                if (line.Contains(":"))
                {
                    var idx = line.IndexOf(':');
                    if (idx > 0 && idx < 30)
                    {
                        sb.AppendLine($"  {line.Substring(0, idx).Trim(),-25}: {line.Substring(idx + 1).Trim()}");
                    }
                    else
                    {
                        sb.AppendLine($"  {line.Trim()}");
                    }
                }
                else
                {
                    sb.AppendLine(line.Trim());
                }
            }

            return sb.ToString();
        }

        private string GetCurrencyByCountry(string countryCode)
        {
            var map = new Dictionary<string, string>
            {
                { "CN", "人民币 (CNY ¥)" }, { "US", "美元 (USD $)" }, { "HK", "港币 (HKD HK$)" },
                { "TW", "新台币 (TWD NT$)" }, { "JP", "日元 (JPY ¥)" }, { "KR", "韩元 (KRW ₩)" },
                { "GB", "英镑 (GBP £)" }, { "DE", "欧元 (EUR €)" }, { "FR", "欧元 (EUR €)" },
                { "RU", "卢布 (RUB ₽)" }, { "IN", "印度卢比 (INR ₹)" }, { "AU", "澳元 (AUD A$)" },
                { "CA", "加元 (CAD C$)" }, { "SG", "新加坡元 (SGD S$)" }
            };
            return map.TryGetValue(countryCode.ToUpper(), out var c) ? c : "未知";
        }

        private string GetLanguageByCountry(string countryCode)
        {
            var map = new Dictionary<string, string>
            {
                { "CN", "中文 (简体)" }, { "US", "英语" }, { "GB", "英语" },
                { "HK", "中文 (繁體) / English" }, { "TW", "中文 (繁體)" },
                { "JP", "日本語" }, { "KR", "한국어" }, { "DE", "Deutsch" },
                { "FR", "Français" }, { "RU", "Русский" }, { "ES", "Español" },
                { "PT", "Português" }, { "IT", "Italiano" }, { "AR", "العربية" }
            };
            return map.TryGetValue(countryCode.ToUpper(), out var l) ? l : "未知";
        }

        private class IpApiResponse
        {
            public string? Status { get; set; }
            public string? Query { get; set; }
            public string? Country { get; set; }
            public string? CountryCode { get; set; }
            public string? Region { get; set; }
            public string? RegionName { get; set; }
            public string? City { get; set; }
            public string? Zip { get; set; }
            public double? Lat { get; set; }
            public double? Lon { get; set; }
            public string? Timezone { get; set; }
            public string? Isp { get; set; }
            public string? Org { get; set; }
            public string? As { get; set; }
            public string? Proxy { get; set; }
        }
    }

    #endregion
}
