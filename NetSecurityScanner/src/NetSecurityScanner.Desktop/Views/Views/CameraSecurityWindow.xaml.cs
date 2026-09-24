using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Data;
using System.Windows.Media;
using Microsoft.Extensions.Logging;
using NetSecurityScanner.Core.Models;
using NetSecurityScanner.Core.Services;

namespace NetSecurityScanner.Views
{
    public partial class CameraSecurityWindow : Window
    {
        private CancellationTokenSource? _cts;
        private CameraScanResult? _lastResult;

        public CameraSecurityWindow()
        {
            InitializeComponent();
        }

        private void AppendLog(string msg)
        {
            Dispatcher.Invoke(() =>
            {
                TxtLog.AppendText($"[{DateTime.Now:HH:mm:ss}] {msg}\n");
                TxtLog.ScrollToEnd();
            });
        }

        private void BtnStart_Click(object sender, RoutedEventArgs e)
        {
            var ip = TxtTargetIp.Text?.Trim() ?? "";
            if (string.IsNullOrWhiteSpace(ip))
            {
                MessageBox.Show("请输入目标 IP 地址", "提示", MessageBoxButton.OK, MessageBoxImage.Warning);
                return;
            }

            TxtLog.Clear();
            ListFindings.ItemsSource = null;
            ResetUI();

            _cts = new CancellationTokenSource();
            BtnStart.IsEnabled = false;
            BtnStop.Visibility = Visibility.Visible;
            ProgressBar.Visibility = Visibility.Visible;

            _ = RunScanAsync(ip, _cts.Token);
        }

        private void BtnStop_Click(object sender, RoutedEventArgs e)
        {
            _cts?.Cancel();
            AppendLog("[*] 扫描已请求停止...");
        }

        private async Task RunScanAsync(string ip, CancellationToken ct)
        {
            var logger = new EmptyLogger<CameraSecurityScanner>();
            using var scanner = new CameraSecurityScanner(logger);

            var progress = new Progress<string>(msg => AppendLog(msg));

            try
            {
                var result = await scanner.ScanAsync(ip, ct, progress);
                _lastResult = result;
                Dispatcher.Invoke(() => DisplayResult(result));
            }
            catch (OperationCanceledException)
            {
                AppendLog("[!] 扫描已取消");
            }
            catch (Exception ex)
            {
                AppendLog($"[×] 扫描异常: {ex.Message}");
            }
            finally
            {
                Dispatcher.Invoke(() =>
                {
                    BtnStart.IsEnabled = true;
                    BtnStop.Visibility = Visibility.Collapsed;
                    ProgressBar.Visibility = Visibility.Collapsed;
                    BtnExport.IsEnabled = _lastResult != null && _lastResult.Findings.Any();
                });
            }
        }

        private void DisplayResult(CameraScanResult r)
        {
            var t = r.Target;
            LblIp.Text = t.IpAddress;
            LblVendor.Text = string.IsNullOrEmpty(t.DetectedVendor) ? "未识别" : t.DetectedVendor;
            LblFirmware.Text = string.IsNullOrEmpty(t.FirmwareVersion) ? "未知" : t.FirmwareVersion;
            LblPorts.Text = t.OpenPorts.Any() ? string.Join(", ", t.OpenPorts.Select(p => $"{p} ({t.PortServices.GetValueOrDefault(p, "?")})")) : "无";
            LblHttpServer.Text = string.IsNullOrEmpty(t.HttpServerHeader) ? "—" : t.HttpServerHeader;
            LblReachable.Text = t.IsReachable ? "可达 ✓" : "不可达";
            LblReachable.Foreground = t.IsReachable ? Brushes.Green : Brushes.Gray;

            LblCritical.Text = r.CriticalCount.ToString();
            LblHigh.Text = r.HighRiskCount.ToString();
            LblMedium.Text = r.MediumRiskCount.ToString();
            LblLow.Text = r.LowRiskCount.ToString();
            LblScore.Text = r.RiskScore;
            LblScore.Foreground = r.OverallRiskLevel switch
            {
                "Critical" => new SolidColorBrush(Color.FromRgb(0xE7, 0x4C, 0x3C)),
                "High" => new SolidColorBrush(Color.FromRgb(0xE6, 0x7E, 0x22)),
                "Medium" => new SolidColorBrush(Color.FromRgb(0xF1, 0xC4, 0x0F)),
                _ => new SolidColorBrush(Color.FromRgb(0x27, 0xAE, 0x60))
            };

            ListFindings.ItemsSource = r.Findings.OrderByDescending(f => f.CvssScore).ToList();
        }

        private void ResetUI()
        {
            LblIp.Text = "—"; LblVendor.Text = "—"; LblFirmware.Text = "—";
            LblPorts.Text = "—"; LblHttpServer.Text = "—"; LblReachable.Text = "—";
            LblCritical.Text = "0"; LblHigh.Text = "0"; LblMedium.Text = "0"; LblLow.Text = "0";
            LblScore.Text = "—";
        }

        private void BtnExport_Click(object sender, RoutedEventArgs e)
        {
            if (_lastResult == null) return;
            try
            {
                var dir = Path.Combine(AppContext.BaseDirectory, "Reports");
                Directory.CreateDirectory(dir);
                var file = Path.Combine(dir, $"CameraScan_{_lastResult.Target.IpAddress}_{DateTime.Now:yyyyMMdd_HHmmss}.txt");

                using var sw = new StreamWriter(file);
                sw.WriteLine("╔══════════════════════════════════════════════════╗");
                sw.WriteLine("║          摄像头安全扫描报告                       ║");
                sw.WriteLine("╚══════════════════════════════════════════════════╝");
                sw.WriteLine();
                sw.WriteLine($"扫描时间:   {_lastResult.ScanTime:yyyy-MM-dd HH:mm:ss}");
                sw.WriteLine($"目标 IP:    {_lastResult.Target.IpAddress}");
                sw.WriteLine($"总体风险:   {_lastResult.OverallRiskLevel}");
                sw.WriteLine($"风险评分:   {_lastResult.RiskScore}/100");
                sw.WriteLine();
                sw.WriteLine("── 设备信息 ──────────────────────────────────────");
                sw.WriteLine($"  品牌:       {_lastResult.Target.DetectedVendor}");
                sw.WriteLine($"  固件版本:   {_lastResult.Target.FirmwareVersion}");
                sw.WriteLine($"  硬件型号:   {_lastResult.Target.HardwareVersion}");
                sw.WriteLine($"  开放端口:   {string.Join(", ", _lastResult.Target.OpenPorts)}");
                sw.WriteLine($"  HTTP Server:{_lastResult.Target.HttpServerHeader}");
                sw.WriteLine();
                sw.WriteLine($"── 发现漏洞 ({_lastResult.Findings.Count}) ──────────────────────────────");
                sw.WriteLine($"  Critical: {_lastResult.CriticalCount}  High: {_lastResult.HighRiskCount}  Medium: {_lastResult.MediumRiskCount}  Low: {_lastResult.LowRiskCount}");
                sw.WriteLine();
                foreach (var f in _lastResult.Findings.OrderByDescending(x => x.CvssScore))
                {
                    sw.WriteLine($"  ┌─ [{f.Severity}] {f.CveId} ─────────────────────");
                    sw.WriteLine($"  │ 名称: {f.Name}");
                    if (!string.IsNullOrEmpty(f.Description))
                        sw.WriteLine($"  │ 描述: {f.Description}");
                    sw.WriteLine($"  │ CVSS: {f.CvssScore:F1}  检测方式: {f.DetectionMethod}");
                    if (!string.IsNullOrEmpty(f.Evidence))
                        sw.WriteLine($"  │ 证据: {f.Evidence}");
                    if (!string.IsNullOrEmpty(f.Remedy))
                        sw.WriteLine($"  │ 修复: {f.Remedy}");
                    sw.WriteLine($"  └────────────────────────────────────");
                    sw.WriteLine();
                }

                MessageBox.Show($"报告已导出到:\n{file}", "导出成功", MessageBoxButton.OK, MessageBoxImage.Information);
            }
            catch (Exception ex)
            {
                MessageBox.Show($"导出失败: {ex.Message}", "错误", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }
    }

    public class SeverityToBrushConverter : IValueConverter
    {
        public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
        {
            if (value is string s)
            {
                return s switch
                {
                    "Critical" => new SolidColorBrush(Color.FromRgb(0xE7, 0x4C, 0x3C)),
                    "High" => new SolidColorBrush(Color.FromRgb(0xE6, 0x7E, 0x22)),
                    "Medium" => new SolidColorBrush(Color.FromRgb(0xF1, 0xC4, 0x0F)),
                    "Low" => new SolidColorBrush(Color.FromRgb(0x27, 0xAE, 0x60)),
                    _ => Brushes.Gray
                };
            }
            return Brushes.Gray;
        }

        public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture)
            => throw new NotImplementedException();
    }

    internal class EmptyLogger<T> : Microsoft.Extensions.Logging.ILogger<T>
    {
        public void Log<TState>(Microsoft.Extensions.Logging.LogLevel logLevel, Microsoft.Extensions.Logging.EventId eventId, TState state, Exception? exception, Func<TState, Exception?, string> formatter) { }
        public bool IsEnabled(Microsoft.Extensions.Logging.LogLevel logLevel) => false;
        public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;
    }
}