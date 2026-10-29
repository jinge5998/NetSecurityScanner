using Microsoft.Win32;
using NetSecurityScanner.Core.Models;
using NetSecurityScanner.Core.Services;
using NetSecurityScanner.Models;
using NetSecurityScanner.Utils;
using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;

namespace NetSecurityScanner.Views
{
    /// <summary>
    /// 摄像头批量扫描窗口：支持 IP 段/CIDR/文件/列表四种目标输入，SemaphoreSlim 并发队列扫描，
    /// 实时汇总统计，双击行打开单目标详情，导出 HTML/JSON/CSV 汇总报告。
    /// </summary>
    public partial class CameraBatchScanWindow : Window
    {
        private readonly ObservableCollection<CameraBatchScanItem> _items = new();
        private List<string> _parsedTargets = new();
        private CancellationTokenSource? _cts;
        private int _completedCount;
        private int _failedCount;
        private int _totalFindings;
        private int _totalCritical;

        public CameraBatchScanWindow()
        {
            InitializeComponent();
            GridResults.ItemsSource = _items;
            ConcurrencySlider.ValueChanged += (s, e) => TxtConcurrencyValue.Text = ConcurrencySlider.Value.ToString("F0");
        }

        private void CmbTargetType_SelectionChanged(object sender, SelectionChangedEventArgs e)
        {
            if (CmbTargetType?.SelectedItem is not ComboBoxItem selectedItem) return;
            string tag = selectedItem.Tag?.ToString() ?? "";
            TxtTargetHint.Text = tag switch
            {
                "Range" => "提示：输入 IP 段，如 192.168.1.1-192.168.1.254",
                "CIDR" => "提示：输入 CIDR 格式，如 192.168.1.0/24",
                "File" => "提示：点击'导入目标文件'按钮选择文件",
                "List" => "提示：每行输入一个 IP 地址",
                _ => "提示：输入目标值"
            };
            BtnImportFile.Visibility = tag == "File" ? Visibility.Visible : Visibility.Collapsed;
        }

        private void BtnImportFile_Click(object sender, RoutedEventArgs e)
        {
            var dialog = new OpenFileDialog { Filter = "文本文件|*.txt|所有文件|*.*", Title = "选择目标列表文件" };
            if (dialog.ShowDialog() == true)
            {
                TxtTargetValue.Text = dialog.FileName;
            }
        }

        private void BtnParseTargets_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                string targetValue = TxtTargetValue.Text.Trim();
                if (string.IsNullOrEmpty(targetValue))
                {
                    MessageBox.Show("请输入目标值", "提示", MessageBoxButton.OK, MessageBoxImage.Information);
                    return;
                }

                if (CmbTargetType.SelectedItem is not ComboBoxItem selectedItem) return;
                string tag = selectedItem.Tag?.ToString() ?? "";
                TargetType targetType = tag switch
                {
                    "Range" => TargetType.Range,
                    "CIDR" => TargetType.CIDR,
                    "File" => TargetType.ListFile,
                    _ => TargetType.Single
                };

                // IP 列表（每行一个）与单目标共用 Single 解析逻辑，与批量扫描窗口保持一致
                _parsedTargets = TargetParser.ParseTargets(targetValue, targetType);
                if (_parsedTargets.Any())
                {
                    _items.Clear();
                    foreach (var ip in _parsedTargets)
                    {
                        _items.Add(new CameraBatchScanItem { IpAddress = ip, Status = "等待中" });
                    }
                    TxtParsedCount.Text = $"已解析: {_parsedTargets.Count} 个目标";
                    TxtTotalTargets.Text = $"总目标: {_parsedTargets.Count}";
                    MessageBox.Show($"成功解析 {_parsedTargets.Count} 个扫描目标", "解析成功", MessageBoxButton.OK, MessageBoxImage.Information);
                }
                else
                {
                    TxtParsedCount.Text = "已解析: 0 个目标";
                    MessageBox.Show("未能解析到有效的扫描目标", "解析失败", MessageBoxButton.OK, MessageBoxImage.Warning);
                }
            }
            catch (Exception ex)
            {
                MessageBox.Show($"解析目标失败: {ex.Message}", "错误", MessageBoxButton.OK, MessageBoxImage.Error);
            }
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
        }

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
                options.EnableWeakPasswordScan = true;
            }
            return options;
        }

        private async void BtnStart_Click(object sender, RoutedEventArgs e)
        {
            if (!_parsedTargets.Any())
            {
                MessageBox.Show("请先解析扫描目标", "提示", MessageBoxButton.OK, MessageBoxImage.Information);
                return;
            }
            await RunBatchScanAsync();
        }

        private void BtnStop_Click(object sender, RoutedEventArgs e)
        {
            _cts?.Cancel();
        }

        private async Task RunBatchScanAsync()
        {
            int total = _parsedTargets.Count;
            _completedCount = 0;
            _failedCount = 0;
            _totalFindings = 0;
            _totalCritical = 0;
            OverallProgressBar.Value = 0;
            UpdateSummary(total);

            _cts = new CancellationTokenSource();
            var token = _cts.Token;
            var options = BuildOptionsFromUi();
            int concurrency = Math.Max(1, (int)ConcurrencySlider.Value);
            using var semaphore = new SemaphoreSlim(concurrency);

            BtnStart.IsEnabled = false;
            BtnStop.IsEnabled = true;
            BtnExport.IsEnabled = false;

            var tasks = _parsedTargets.Select(async ip =>
            {
                try
                {
                    await semaphore.WaitAsync(token);
                }
                catch (OperationCanceledException)
                {
                    return;
                }

                var item = _items.FirstOrDefault(i => i.IpAddress.Equals(ip, StringComparison.OrdinalIgnoreCase));
                if (item == null)
                {
                    semaphore.Release();
                    return;
                }

                var sw = Stopwatch.StartNew();
                try
                {
                    Dispatcher.Invoke(() => item.Status = "扫描中");
                    var logger = new EmptyLogger<CameraSecurityScanner>();
                    using var scanner = new CameraSecurityScanner(logger);
                    var result = await scanner.ScanAsync(ip, token, null, options, null);
                    sw.Stop();

                    item.Result = result;
                    Dispatcher.Invoke(() =>
                    {
                        item.Status = "完成";
                        item.Vendor = string.IsNullOrEmpty(result.Target.DetectedVendor) ? "未识别" : result.Target.DetectedVendor;
                        item.OpenPortsCount = result.Target.OpenPorts.Count;
                        item.FindingsCount = result.Findings.Count;
                        item.CriticalCount = result.CriticalCount;
                        item.HighCount = result.HighRiskCount;
                        item.RiskScore = result.RiskScore;
                        item.DurationText = sw.Elapsed.ToString(@"mm\:ss");
                        _completedCount++;
                        _totalFindings += result.Findings.Count;
                        _totalCritical += result.CriticalCount;
                        UpdateSummary(total);
                        UpdateOverallProgress(total);
                    });
                }
                catch (OperationCanceledException)
                {
                    Dispatcher.Invoke(() => item.Status = "已取消");
                }
                catch (Exception ex)
                {
                    sw.Stop();
                    Dispatcher.Invoke(() =>
                    {
                        item.Status = "失败";
                        item.ErrorMessage = ex.Message;
                        item.DurationText = sw.Elapsed.ToString(@"mm\:ss");
                        _failedCount++;
                        UpdateSummary(total);
                        UpdateOverallProgress(total);
                    });
                }
                finally
                {
                    semaphore.Release();
                }
            });

            try
            {
                await Task.WhenAll(tasks);
            }
            catch (OperationCanceledException)
            {
                // 用户取消：部分任务已在上层标记为"已取消"
            }

            Dispatcher.Invoke(() =>
            {
                BtnStart.IsEnabled = true;
                BtnStop.IsEnabled = false;
                BtnExport.IsEnabled = _items.Any(i => i.Result != null);
            });
        }

        private void UpdateSummary(int total)
        {
            TxtTotalTargets.Text = $"总目标: {total}";
            TxtCompleted.Text = $"已完成: {_completedCount}";
            TxtFailed.Text = $"失败: {_failedCount}";
            TxtTotalFindings.Text = $"总漏洞: {_totalFindings}";
            TxtTotalCritical.Text = $"Critical: {_totalCritical}";
        }

        private void UpdateOverallProgress(int total)
        {
            OverallProgressBar.Value = total == 0 ? 0 : (_completedCount + _failedCount) * 100.0 / total;
        }

        /// <summary>
        /// 双击行打开单目标详情窗口（携带已扫描结果，无需重扫）。
        /// </summary>
        private void GridResults_MouseDoubleClick(object sender, MouseButtonEventArgs e)
        {
            if (GridResults.SelectedItem is CameraBatchScanItem item)
            {
                var detail = new CameraSecurityWindow(item.IpAddress, item.Result) { Owner = this };
                detail.Show();
            }
        }

        private async void BtnExport_Click(object sender, RoutedEventArgs e)
        {
            var results = _items.Where(i => i.Result != null).ToList();
            if (!results.Any())
            {
                MessageBox.Show("没有可导出的扫描结果", "提示", MessageBoxButton.OK, MessageBoxImage.Information);
                return;
            }

            var dialog = new SaveFileDialog
            {
                Filter = "HTML文件|*.html|JSON文件|*.json|CSV文件|*.csv",
                FileName = $"CameraBatchScan_{DateTime.Now:yyyyMMdd_HHmmss}",
                Title = "导出摄像头批量扫描汇总报告"
            };
            if (dialog.ShowDialog() != true) return;

            try
            {
                var ext = Path.GetExtension(dialog.FileName).ToLowerInvariant();
                string content = ext switch
                {
                    ".html" => GenerateHtmlSummary(results),
                    ".json" => GenerateJsonSummary(results),
                    _ => GenerateCsvSummary(results)
                };
                // JSON/HTML 无 BOM；CSV 带 BOM 方便 Excel 识别中文
                var withBom = ext == ".csv";
                await File.WriteAllTextAsync(dialog.FileName, content, new UTF8Encoding(withBom));
                MessageBox.Show($"汇总报告已导出到:\n{dialog.FileName}", "导出成功", MessageBoxButton.OK, MessageBoxImage.Information);
            }
            catch (Exception ex)
            {
                MessageBox.Show($"导出失败: {ex.Message}", "错误", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        private string GenerateCsvSummary(List<CameraBatchScanItem> results)
        {
            static string Csv(string? s)
            {
                s ??= "";
                return s.Contains(',') || s.Contains('"') || s.Contains('\n')
                    ? "\"" + s.Replace("\"", "\"\"") + "\""
                    : s;
            }

            var sb = new StringBuilder();
            sb.AppendLine("IP,品牌,开放端口数,漏洞数,Critical,High,风险评分,耗时,扫描时间");
            foreach (var item in results)
            {
                var r = item.Result!;
                sb.AppendLine(string.Join(",",
                    Csv(item.IpAddress),
                    Csv(r.Target.DetectedVendor),
                    r.Target.OpenPorts.Count,
                    r.Findings.Count,
                    r.CriticalCount,
                    r.HighRiskCount,
                    Csv(r.RiskScore),
                    Csv(item.DurationText),
                    Csv(r.ScanTime.ToString("yyyy-MM-dd HH:mm:ss"))));
            }
            return sb.ToString();
        }

        private string GenerateHtmlSummary(List<CameraBatchScanItem> results)
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

            var totalFindings = results.Sum(i => i.Result!.Findings.Count);
            var totalCritical = results.Sum(i => i.Result!.CriticalCount);
            var totalHigh = results.Sum(i => i.Result!.HighRiskCount);

            var sb = new StringBuilder();
            sb.AppendLine("<!DOCTYPE html><html><head><meta charset='UTF-8'><title>摄像头批量扫描汇总报告</title>");
            sb.AppendLine("<style>body{font-family:'Microsoft YaHei UI',Arial,sans-serif;margin:40px;background:#f5f6fa;color:#2c3e50}");
            sb.AppendLine(".header{background:#2c3e50;color:white;padding:24px;border-radius:8px}");
            sb.AppendLine(".card{background:white;border:1px solid #e0e3eb;border-radius:8px;padding:20px;margin:16px 0}");
            sb.AppendLine("table{width:100%;border-collapse:collapse}th{background:#34495e;color:white;padding:10px;text-align:left}");
            sb.AppendLine("td{padding:8px;border-bottom:1px solid #eaecef;vertical-align:top}");
            sb.AppendLine(".badge{color:white;padding:2px 10px;border-radius:3px;font-size:12px;font-weight:bold;white-space:nowrap}");
            sb.AppendLine("</style></head><body>");
            sb.AppendLine($"<div class='header'><h1>摄像头批量扫描汇总报告</h1><p>生成时间: {DateTime.Now:yyyy-MM-dd HH:mm:ss} &nbsp;|&nbsp; 扫描目标: {results.Count} 台</p></div>");

            sb.AppendLine("<div class='card'><h2>总体概览</h2>");
            sb.AppendLine($"<p><span class='badge' style='background:#34495e'>总漏洞 {totalFindings}</span> ");
            sb.AppendLine($"<span class='badge' style='background:#e74c3c'>Critical {totalCritical}</span> ");
            sb.AppendLine($"<span class='badge' style='background:#e67e22'>High {totalHigh}</span></p>");
            sb.AppendLine("<table><thead><tr><th>IP</th><th>品牌</th><th>开放端口</th><th>漏洞数</th><th>Critical</th><th>High</th><th>风险评分</th><th>耗时</th></tr></thead><tbody>");
            foreach (var item in results)
            {
                var r = item.Result!;
                sb.AppendLine("<tr>");
                sb.AppendLine($"<td><strong>{Esc(item.IpAddress)}</strong></td>");
                sb.AppendLine($"<td>{Esc(string.IsNullOrEmpty(r.Target.DetectedVendor) ? "未识别" : r.Target.DetectedVendor)}</td>");
                sb.AppendLine($"<td>{r.Target.OpenPorts.Count}</td>");
                sb.AppendLine($"<td>{r.Findings.Count}</td>");
                sb.AppendLine($"<td>{(r.CriticalCount > 0 ? $"<span class='badge' style='background:#e74c3c'>{r.CriticalCount}</span>" : "0")}</td>");
                sb.AppendLine($"<td>{(r.HighRiskCount > 0 ? $"<span class='badge' style='background:#e67e22'>{r.HighRiskCount}</span>" : "0")}</td>");
                sb.AppendLine($"<td><strong>{Esc(r.RiskScore)}/100</strong></td>");
                sb.AppendLine($"<td>{Esc(item.DurationText)}</td>");
                sb.AppendLine("</tr>");
            }
            sb.AppendLine("</tbody></table></div>");

            foreach (var item in results)
            {
                var r = item.Result!;
                if (!r.Findings.Any()) continue;
                sb.AppendLine($"<div class='card'><h2>{Esc(item.IpAddress)} 漏洞详情 ({r.Findings.Count})</h2>");
                sb.AppendLine("<table><thead><tr><th>严重度</th><th>漏洞名称</th><th>CVE</th><th>CVSS</th><th>检测方式</th><th>修复建议</th></tr></thead><tbody>");
                foreach (var f in r.Findings.OrderByDescending(x => x.CvssScore))
                {
                    sb.AppendLine("<tr>");
                    sb.AppendLine($"<td><span class='badge' style='background:{Sevc(f.Severity)}'>{Esc(f.Severity)}</span></td>");
                    sb.AppendLine($"<td>{Esc(f.Name)}</td>");
                    sb.AppendLine($"<td style='font-family:Consolas,monospace'>{Esc(f.CveId)}</td>");
                    sb.AppendLine($"<td><strong>{f.CvssScore:F1}</strong></td>");
                    sb.AppendLine($"<td>{Esc(f.DetectionMethod)}</td>");
                    sb.AppendLine($"<td>{Esc(f.Remedy)}</td>");
                    sb.AppendLine("</tr>");
                }
                sb.AppendLine("</tbody></table></div>");
            }

            sb.AppendLine("<p style='text-align:center;color:#7f8c8d;margin-top:32px'>由 NetSecurityScanner 生成</p></body></html>");
            return sb.ToString();
        }

        private string GenerateJsonSummary(List<CameraBatchScanItem> results)
        {
            var report = new
            {
                generatedAt = DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss"),
                summary = new
                {
                    totalTargets = results.Count,
                    completed = _completedCount,
                    failed = _failedCount,
                    totalFindings = results.Sum(i => i.Result!.Findings.Count),
                    critical = results.Sum(i => i.Result!.CriticalCount),
                    high = results.Sum(i => i.Result!.HighRiskCount),
                    medium = results.Sum(i => i.Result!.MediumRiskCount),
                    low = results.Sum(i => i.Result!.LowRiskCount)
                },
                targets = results.Select(i =>
                {
                    var r = i.Result!;
                    return new
                    {
                        ip = r.Target.IpAddress,
                        reachable = r.Target.IsReachable,
                        vendor = r.Target.DetectedVendor,
                        firmwareVersion = r.Target.FirmwareVersion,
                        httpServerHeader = r.Target.HttpServerHeader,
                        openPorts = r.Target.OpenPorts,
                        overallRiskLevel = r.OverallRiskLevel,
                        riskScore = r.RiskScore,
                        scanTime = r.ScanTime.ToString("yyyy-MM-dd HH:mm:ss"),
                        duration = i.DurationText,
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
                })
            };

            return System.Text.Json.JsonSerializer.Serialize(report, new System.Text.Json.JsonSerializerOptions
            {
                WriteIndented = true,
                Encoder = System.Text.Encodings.Web.JavaScriptEncoder.UnsafeRelaxedJsonEscaping
            });
        }

        protected override void OnClosing(System.ComponentModel.CancelEventArgs e)
        {
            _cts?.Cancel();
            base.OnClosing(e);
        }
    }
}
