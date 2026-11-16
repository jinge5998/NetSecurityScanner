using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Media;
using Microsoft.Extensions.Logging;
using Microsoft.Win32;
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
            ScanProgressBar.Value = 0;
            LblProgressPercent.Text = "0%";

            _ = RunScanAsync(ip, _cts.Token);
        }

        private void BtnStop_Click(object sender, RoutedEventArgs e)
        {
            _cts?.Cancel();
            AppendLog("[*] 扫描已请求停止...");
        }

        /// <summary>
        /// 弱口令爆破属于高敏感操作（最多 200 次登录尝试），勾选时强制弹授权确认，拒绝则回退为未勾选。
        /// </summary>
        private void ChkWeakPassword_Checked(object sender, RoutedEventArgs e)
        {
            var result = MessageBox.Show(
                "弱口令爆破检测会向目标设备发起多次登录尝试（上限 200 次）。\n\n请确认：\n1. 你已获得目标网络/设备所有者的书面授权；\n2. 该操作符合所在地区法律法规。\n\n未经授权的爆破行为可能构成违法。是否确认启用？",
                "授权确认 - 弱口令爆破检测",
                MessageBoxButton.YesNo,
                MessageBoxImage.Warning);
            if (result != MessageBoxResult.Yes)
            {
                ChkWeakPassword.IsChecked = false;
            }
            else
            {
                AppendLog("[!] 用户已确认授权，启用弱口令爆破检测");
            }
        }

        /// <summary>
        /// 从 UI 构建扫描选项：品牌下拉框映射 ForcedVendor，扫描模式决定 PoC 开关，弱口令由勾选框独立控制。
        /// </summary>
        private CameraScanOptions BuildOptionsFromUi()
        {
            var vendorTag = (CmbVendor.SelectedItem as ComboBoxItem)?.Tag?.ToString();
            var isQuick = (CmbScanMode.SelectedItem as ComboBoxItem)?.Tag?.ToString() == "Quick";
            var weakPwdEnabled = ChkWeakPassword.IsChecked == true;

            var options = isQuick
                ? CameraScanOptions.CreateQuick()
                : CameraScanOptions.CreateFull(weakPwdEnabled);

            if (!string.IsNullOrEmpty(vendorTag))
            {
                options.ForcedVendor = vendorTag;
            }
            if (weakPwdEnabled)
            {
                // 用户在快速模式下显式勾选弱口令时，仍尊重其已授权的选择
                options.EnableWeakPasswordScan = true;
            }
            return options;
        }

        private async Task RunScanAsync(string ip, CancellationToken ct)
        {
            var logger = new EmptyLogger<CameraSecurityScanner>();
            using var scanner = new CameraSecurityScanner(logger);

            var progress = new Progress<string>(msg => AppendLog(msg));
            var percentProgress = new Progress<int>(p => Dispatcher.Invoke(() =>
            {
                ScanProgressBar.Value = p;
                LblProgressPercent.Text = $"{p}%";
            }));
            var options = BuildOptionsFromUi();

            try
            {
                var result = await scanner.ScanAsync(ip, ct, progress, options, percentProgress);
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

        private async void BtnExport_Click(object sender, RoutedEventArgs e)
        {
            if (_lastResult == null) return;

            var dialog = new SaveFileDialog
            {
                Filter = "文本文件|*.txt|HTML文件|*.html|JSON文件|*.json",
                FileName = $"CameraScan_{_lastResult.Target.IpAddress}_{DateTime.Now:yyyyMMdd_HHmmss}",
                Title = $"导出 {_lastResult.Target.IpAddress} 的摄像头安全报告"
            };
            if (dialog.ShowDialog() != true) return;

            try
            {
                var ext = Path.GetExtension(dialog.FileName).ToLowerInvariant();
                string content = ext switch
                {
                    ".html" => GenerateHtmlReport(_lastResult),
                    ".json" => GenerateJsonReport(_lastResult),
                    _ => GenerateTextReport(_lastResult)
                };
                // JSON/HTML 无 BOM；TXT 带 BOM 方便记事本识别中文
                var withBom = ext == ".txt";
                await File.WriteAllTextAsync(dialog.FileName, content, new UTF8Encoding(withBom));
                MessageBox.Show($"报告已导出到:\n{dialog.FileName}", "导出成功", MessageBoxButton.OK, MessageBoxImage.Information);
            }
            catch (Exception ex)
            {
                MessageBox.Show($"导出失败: {ex.Message}", "错误", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        private static string GenerateTextReport(CameraScanResult r)
        {
            var sb = new StringBuilder();
            sb.AppendLine("╔══════════════════════════════════════════════════╗");
            sb.AppendLine("║          摄像头安全扫描报告                       ║");
            sb.AppendLine("╚══════════════════════════════════════════════════╝");
            sb.AppendLine();
            sb.AppendLine($"扫描时间:   {r.ScanTime:yyyy-MM-dd HH:mm:ss}");
            sb.AppendLine($"目标 IP:    {r.Target.IpAddress}");
            sb.AppendLine($"总体风险:   {r.OverallRiskLevel}");
            sb.AppendLine($"风险评分:   {r.RiskScore}/100");
            sb.AppendLine();
            sb.AppendLine("── 设备信息 ──────────────────────────────────────");
            sb.AppendLine($"  品牌:       {r.Target.DetectedVendor}");
            sb.AppendLine($"  固件版本:   {r.Target.FirmwareVersion}");
            sb.AppendLine($"  硬件型号:   {r.Target.HardwareVersion}");
            sb.AppendLine($"  开放端口:   {string.Join(", ", r.Target.OpenPorts)}");
            sb.AppendLine($"  HTTP Server:{r.Target.HttpServerHeader}");
            sb.AppendLine();
            sb.AppendLine($"── 发现漏洞 ({r.Findings.Count}) ──────────────────────────────");
            sb.AppendLine($"  Critical: {r.CriticalCount}  High: {r.HighRiskCount}  Medium: {r.MediumRiskCount}  Low: {r.LowRiskCount}");
            sb.AppendLine();
            foreach (var f in r.Findings.OrderByDescending(x => x.CvssScore))
            {
                sb.AppendLine($"  ┌─ [{f.Severity}] {f.CveId} ─────────────────────");
                sb.AppendLine($"  │ 名称: {f.Name}");
                if (!string.IsNullOrEmpty(f.Description))
                    sb.AppendLine($"  │ 描述: {f.Description}");
                sb.AppendLine($"  │ CVSS: {f.CvssScore:F1}  检测方式: {f.DetectionMethod}");
                if (!string.IsNullOrEmpty(f.Evidence))
                    sb.AppendLine($"  │ 证据: {f.Evidence}");
                if (!string.IsNullOrEmpty(f.Remedy))
                    sb.AppendLine($"  │ 修复: {f.Remedy}");
                sb.AppendLine($"  └────────────────────────────────────");
                sb.AppendLine();
            }
            return sb.ToString();
        }

        private static string GenerateHtmlReport(CameraScanResult r)
        {
            static string Esc(string? s) => System.Net.WebUtility.HtmlEncode(s ?? "");
            static string Sevc(string sev) => sev switch
            {
                "Critical" => "#e74c3c",
                "High" => "#e67e22",
                "Medium" => "#f1c40f",
                "Low" => "#27ae60",
                _ => "#95a5a6"
            };

            var sb = new StringBuilder();
            sb.AppendLine("<!DOCTYPE html><html><head><meta charset='UTF-8'><title>摄像头安全扫描报告</title>");
            sb.AppendLine("<style>body{font-family:'Microsoft YaHei UI',Arial,sans-serif;margin:40px;background:#f5f6fa;color:#2c3e50}");
            sb.AppendLine(".header{background:#2c3e50;color:white;padding:24px;border-radius:8px}");
            sb.AppendLine(".card{background:white;border:1px solid #e0e3eb;border-radius:8px;padding:20px;margin:16px 0}");
            sb.AppendLine("table{width:100%;border-collapse:collapse}th{background:#34495e;color:white;padding:10px;text-align:left}");
            sb.AppendLine("td{padding:8px;border-bottom:1px solid #eaecef;vertical-align:top}");
            sb.AppendLine(".badge{color:white;padding:2px 10px;border-radius:3px;font-size:12px;font-weight:bold;white-space:nowrap}");
            sb.AppendLine("</style></head><body>");
            sb.AppendLine($"<div class='header'><h1>摄像头安全扫描报告</h1><p>目标: {Esc(r.Target.IpAddress)} &nbsp;|&nbsp; 扫描时间: {r.ScanTime:yyyy-MM-dd HH:mm:ss}</p></div>");

            sb.AppendLine("<div class='card'><h2>设备信息</h2><table><tbody>");
            sb.AppendLine($"<tr><th style='width:140px'>品牌</th><td>{Esc(r.Target.DetectedVendor)}</td></tr>");
            sb.AppendLine($"<tr><th>固件版本</th><td>{Esc(r.Target.FirmwareVersion)}</td></tr>");
            sb.AppendLine($"<tr><th>硬件型号</th><td>{Esc(r.Target.HardwareVersion)}</td></tr>");
            sb.AppendLine($"<tr><th>开放端口</th><td>{Esc(string.Join(", ", r.Target.OpenPorts))}</td></tr>");
            sb.AppendLine($"<tr><th>HTTP Server</th><td>{Esc(r.Target.HttpServerHeader)}</td></tr>");
            sb.AppendLine("</tbody></table></div>");

            sb.AppendLine("<div class='card'><h2>风险概览</h2>");
            sb.AppendLine($"<p><strong>总体风险:</strong> {Esc(r.OverallRiskLevel)} &nbsp; <strong>风险评分:</strong> {Esc(r.RiskScore)}/100</p>");
            sb.AppendLine($"<p><span class='badge' style='background:#e74c3c'>Critical {r.CriticalCount}</span> ");
            sb.AppendLine($"<span class='badge' style='background:#e67e22'>High {r.HighRiskCount}</span> ");
            sb.AppendLine($"<span class='badge' style='background:#f1c40f'>Medium {r.MediumRiskCount}</span> ");
            sb.AppendLine($"<span class='badge' style='background:#27ae60'>Low {r.LowRiskCount}</span></p></div>");

            sb.AppendLine($"<div class='card'><h2>发现的漏洞 ({r.Findings.Count})</h2>");
            sb.AppendLine("<table><thead><tr><th>严重度</th><th>漏洞名称</th><th>CVE</th><th>CVSS</th><th>检测方式</th><th>描述 / 证据 / 修复建议</th></tr></thead><tbody>");
            foreach (var f in r.Findings.OrderByDescending(x => x.CvssScore))
            {
                sb.AppendLine("<tr>");
                sb.AppendLine($"<td><span class='badge' style='background:{Sevc(f.Severity)}'>{Esc(f.Severity)}</span></td>");
                sb.AppendLine($"<td>{Esc(f.Name)}</td>");
                sb.AppendLine($"<td style='font-family:Consolas,monospace'>{Esc(f.CveId)}</td>");
                sb.AppendLine($"<td><strong>{f.CvssScore:F1}</strong></td>");
                sb.AppendLine($"<td>{Esc(f.DetectionMethod)}</td>");
                sb.AppendLine("<td>");
                if (!string.IsNullOrEmpty(f.Description))
                    sb.AppendLine($"<div><strong>描述:</strong> {Esc(f.Description)}</div>");
                if (!string.IsNullOrEmpty(f.Evidence))
                    sb.AppendLine($"<div style='color:#7f8c8d'><strong>证据:</strong> {Esc(f.Evidence)}</div>");
                if (!string.IsNullOrEmpty(f.Remedy))
                    sb.AppendLine($"<div style='color:#27ae60'><strong>修复:</strong> {Esc(f.Remedy)}</div>");
                sb.AppendLine("</td></tr>");
            }
            sb.AppendLine("</tbody></table></div>");
            sb.AppendLine("<p style='text-align:center;color:#7f8c8d;margin-top:32px'>由 NetSecurityScanner 生成</p></body></html>");
            return sb.ToString();
        }

        private static string GenerateJsonReport(CameraScanResult r)
        {
            var report = new
            {
                generatedAt = DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss"),
                scanTime = r.ScanTime.ToString("yyyy-MM-dd HH:mm:ss"),
                target = new
                {
                    ip = r.Target.IpAddress,
                    reachable = r.Target.IsReachable,
                    vendor = r.Target.DetectedVendor,
                    firmwareVersion = r.Target.FirmwareVersion,
                    hardwareVersion = r.Target.HardwareVersion,
                    httpServerHeader = r.Target.HttpServerHeader,
                    openPorts = r.Target.OpenPorts,
                    portServices = r.Target.PortServices
                },
                summary = new
                {
                    overallRiskLevel = r.OverallRiskLevel,
                    riskScore = r.RiskScore,
                    totalFindings = r.Findings.Count,
                    critical = r.CriticalCount,
                    high = r.HighRiskCount,
                    medium = r.MediumRiskCount,
                    low = r.LowRiskCount
                },
                findings = r.Findings.OrderByDescending(x => x.CvssScore).Select(f => new
                {
                    severity = f.Severity,
                    cveId = f.CveId,
                    name = f.Name,
                    cvssScore = f.CvssScore,
                    detectionMethod = f.DetectionMethod,
                    description = f.Description,
                    evidence = f.Evidence,
                    remedy = f.Remedy
                })
            };

            return System.Text.Json.JsonSerializer.Serialize(report, new System.Text.Json.JsonSerializerOptions
            {
                WriteIndented = true,
                Encoder = System.Text.Encodings.Web.JavaScriptEncoder.UnsafeRelaxedJsonEscaping
            });
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