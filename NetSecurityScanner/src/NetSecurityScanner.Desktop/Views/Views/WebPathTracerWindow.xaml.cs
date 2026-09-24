using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using System.Windows.Media;
using Microsoft.Win32;
using Newtonsoft.Json;
using NetSecurityScanner.Services;

namespace NetSecurityScanner.Views
{
    public partial class WebPathTracerWindow : Window
    {
        private WebPathTracerService? _tracer;
        private CancellationTokenSource? _cts;
        private Stopwatch? _stopwatch;
        private WebPathTraceResult? _lastResult;

        public WebPathTracerWindow()
        {
            InitializeComponent();
            ConcurrencySlider.ValueChanged += (s, e) => ConcurrencyValueText.Text = ((int)ConcurrencySlider.Value).ToString();
            CrawlDepthSlider.ValueChanged += (s, e) => CrawlDepthValueText.Text = ((int)CrawlDepthSlider.Value).ToString();
            DetectChromeStatus();
        }

        private void DetectChromeStatus()
        {
            var version = DetectChromeVersion();
            if (version != null)
            {
                ChromeStatusText.Text = $"Chrome状态: ✅ 已检测到Chrome {version}";
                ChromeStatusText.Foreground = new SolidColorBrush(Color.FromRgb(0x27, 0xAE, 0x60));
            }
            else
            {
                ChromeStatusText.Text = "Chrome状态: ❌ 未检测到Chrome";
                ChromeStatusText.Foreground = new SolidColorBrush(Color.FromRgb(0xE7, 0x4C, 0x3C));
            }
        }

        private static string? DetectChromeVersion()
        {
            try
            {
                using var key = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\chrome.exe");
                if (key?.GetValue("") is string path && File.Exists(path))
                {
                    var vi = FileVersionInfo.GetVersionInfo(path);
                    return vi.FileVersion;
                }
            }
            catch { }
            try
            {
                using var key = Registry.CurrentUser.OpenSubKey(@"SOFTWARE\Google\Chrome\BLBeacon");
                if (key?.GetValue("version") is string version)
                    return version;
            }
            catch { }
            try
            {
                using var key = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Google\Chrome\BLBeacon");
                if (key?.GetValue("version") is string version)
                    return version;
            }
            catch { }
            try
            {
                using var key = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\WOW6432Node\Google\Chrome\BLBeacon");
                if (key?.GetValue("version") is string version)
                    return version;
            }
            catch { }
            return null;
        }

        private TraceMode GetSelectedMode()
        {
            if (ModeQuickRadio.IsChecked == true) return TraceMode.Quick;
            if (ModeDeepRadio.IsChecked == true) return TraceMode.Deep;
            return TraceMode.Standard;
        }

        private async void StartTrace_Click(object sender, RoutedEventArgs e)
        {
            var targetUrl = TargetUrlTextBox.Text.Trim();
            if (string.IsNullOrEmpty(targetUrl) || targetUrl == "http://")
            {
                MessageBox.Show("请输入有效的目标URL", "提示", MessageBoxButton.OK, MessageBoxImage.Warning);
                return;
            }

            if (!Uri.TryCreate(targetUrl, UriKind.Absolute, out var uri)
                || (uri.Scheme != "http" && uri.Scheme != "https"))
            {
                if (!targetUrl.StartsWith("http://") && !targetUrl.StartsWith("https://"))
                {
                    targetUrl = "http://" + targetUrl;
                    if (!Uri.TryCreate(targetUrl, UriKind.Absolute, out uri))
                    {
                        MessageBox.Show("URL格式无效，请输入正确的URL（如 http://example.com）", "提示", MessageBoxButton.OK, MessageBoxImage.Warning);
                        return;
                    }
                }
                else
                {
                    MessageBox.Show("URL格式无效，请输入正确的URL（如 http://example.com）", "提示", MessageBoxButton.OK, MessageBoxImage.Warning);
                    return;
                }
            }

            TargetUrlTextBox.Text = targetUrl;

            _cts = new CancellationTokenSource();
            _stopwatch = Stopwatch.StartNew();
            _lastResult = null;
            StartTraceButton.IsEnabled = false;
            StopTraceButton.IsEnabled = true;
            LogTextBox.Clear();
            StatusText.Text = "正在追踪...";
            PathCountText.Text = "发现: 0条路径";
            ElapsedTimeText.Text = "耗时: 0s";
            ScanProgressBar.Value = 0;

            var mode = GetSelectedMode();
            _tracer = new WebPathTracerService
            {
                EnableSelenium = EnableSeleniumCheckBox.IsChecked == true,
                EnableBrute = EnableBruteCheckBox.IsChecked == true,
                EnableCrawl = EnableCrawlCheckBox.IsChecked == true,
                SameDomainOnly = SameDomainOnlyCheckBox.IsChecked == true,
                Mode = mode,
                BruteConcurrency = (int)ConcurrencySlider.Value,
                MaxCrawlDepth = (int)CrawlDepthSlider.Value
            };
            _tracer.OnLog += log => Dispatcher.Invoke(() =>
            {
                LogTextBox.AppendText(log + Environment.NewLine);
                LogTextBox.ScrollToEnd();

                if (log.Contains("第一层")) ScanProgressBar.Value = 8;
                else if (log.Contains("技术栈识别")) ScanProgressBar.Value = 12;
                else if (log.Contains("开放重定向")) ScanProgressBar.Value = 16;
                else if (log.Contains("后缀智能探测") || log.Contains("后缀探测")) ScanProgressBar.Value = 20;
                else if (log.Contains("第二层")) ScanProgressBar.Value = 30;
                else if (log.Contains("递进追踪")) ScanProgressBar.Value = 40;
                else if (log.Contains("第三层")) ScanProgressBar.Value = 50;
                else if (log.Contains("目录爆破")) ScanProgressBar.Value = 60;
                else if (log.Contains("根据技术栈")) ScanProgressBar.Value = 65;
                else if (log.Contains("合并后缀探测")) ScanProgressBar.Value = 68;
                else if (log.Contains("第四层")) ScanProgressBar.Value = 75;
                else if (log.Contains("注入") && log.Contains("Cookie")) ScanProgressBar.Value = 78;
                else if (log.Contains("深度爬取")) ScanProgressBar.Value = 82;
                else if (log.Contains("注入") && log.Contains("Layer2")) ScanProgressBar.Value = 85;
                else if (log.Contains("验证")) ScanProgressBar.Value = 90;
                else if (log.Contains("追踪链摘要")) ScanProgressBar.Value = 95;
            });

            _ = UpdateElapsedTimeAsync();

            try
            {
                var result = await _tracer.TraceAsync(targetUrl, _cts.Token);
                _lastResult = result;
                _stopwatch.Stop();

                // SSL证书分析（在主任务完成后异步执行）
                SslCertificateInfo? sslResult = null;
                if (result.Layer1Results != null && targetUrl.StartsWith("https", StringComparison.OrdinalIgnoreCase))
                {
                    var tracer = new WebPathTracerService();
                    sslResult = await tracer.AnalyzeSslCertificate(targetUrl);
                }

                Dispatcher.Invoke(() =>
                {
                    ScanProgressBar.Value = 100;

                    ShowLayer1Result(result.Layer1Results, result.PathChain.Select(p => new PathStep { Url = p.Url, StatusCode = p.StatusCode, LocationHeader = p.LocationHeader }).ToList());
                    ShowLayer2Result(result.Layer2Results);
                    ShowLayer3Result(result.Layer3Results);
                    ShowLayer4Result(result.Layer4Results);
                    ShowBruteResult(result.BruteResults);
                    ShowPathSegmentResult(result.PathSegmentResults);
                    ShowSensitivePathResult(result.SensitivePaths, result);
                    ShowCrawlResult(result.CrawlResults);
                    ShowFinalResult(result);

                    _lastTraceResult = result;
                    ExportMarkdownButton.Visibility = Visibility.Visible;
                    ExportJson.Visibility = Visibility.Visible;

                    PathCountText.Text = $"发现: {result.AllDiscoveredPaths.Count}条路径";
                    ElapsedTimeText.Text = $"耗时: {_stopwatch.ElapsedMilliseconds / 1000}s";

                    // 显示SSL证书结果
                    if (sslResult != null)
                    {
                        _lastSslCertificate = sslResult;
                        ShowSslCertificateResult(sslResult);
                    }

                    // 安全审计
                    if (result.Layer1Results != null)
                    {
                        var tracer = new WebPathTracerService();
                        var auditResult = tracer.AuditSecurityHeaders(result.Layer1Results);
                        ShowSecurityAuditResult(auditResult);

                        if (result.Layer1Results.TechStack?.DetectedTechs.Count > 0)
                        {
                            ShowVulnerabilityInfo(result.Layer1Results.TechStack.DetectedTechs, tracer);
                        }
                    }

                    if (result.FoundPath)
                    {
                        StatusText.Text = "✅ 追踪完成 - 发现路径";
                    }
                    else
                    {
                        StatusText.Text = "追踪完成 - 未发现路径";
                    }
                });
            }
            catch (OperationCanceledException)
            {
                _stopwatch?.Stop();
                Dispatcher.Invoke(() =>
                {
                    StatusText.Text = "追踪已取消";
                    ScanProgressBar.Value = 0;
                });
            }
            catch (Exception ex)
            {
                _stopwatch?.Stop();
                Dispatcher.Invoke(() =>
                {
                    StatusText.Text = $"追踪失败: {ex.Message}";
                    ScanProgressBar.Value = 0;
                    MessageBox.Show($"追踪失败: {ex.Message}", "错误", MessageBoxButton.OK, MessageBoxImage.Error);
                });
            }
            finally
            {
                Dispatcher.Invoke(() =>
                {
                    StartTraceButton.IsEnabled = true;
                    StopTraceButton.IsEnabled = false;
                });
            }
        }

        private async Task UpdateElapsedTimeAsync()
        {
            while (_stopwatch != null && _stopwatch.IsRunning)
            {
                await Task.Delay(1000);
                if (_stopwatch.IsRunning)
                {
                    Dispatcher.Invoke(() =>
                    {
                        ElapsedTimeText.Text = $"耗时: {_stopwatch.ElapsedMilliseconds / 1000}s";
                    });
                }
            }
        }

        private void StopTrace_Click(object sender, RoutedEventArgs e)
        {
            _cts?.Cancel();
            StatusText.Text = "正在取消...";
        }

        private async void ScanPorts_Click(object sender, RoutedEventArgs e)
        {
            var targetUrl = TargetUrlTextBox.Text.Trim();
            if (string.IsNullOrEmpty(targetUrl) || !Uri.IsWellFormedUriString(targetUrl, UriKind.Absolute))
            {
                MessageBox.Show("请输入有效的目标URL", "提示", MessageBoxButton.OK, MessageBoxImage.Warning);
                return;
            }

            ScanPortsButton.IsEnabled = false;
            ScanPortsButton.Content = "🔌 扫描中...";
            PortScanPanel.Children.Clear();
            PortScanPanel.Children.Add(new TextBlock { Text = "正在扫描端口...", Foreground = Brushes.Gray, FontSize = 14 });

            await Task.Run(async () =>
            {
                var tracer = new WebPathTracerService();
                var portResult = await tracer.ScanCommonPorts(targetUrl);
                Dispatcher.Invoke(() => ShowPortScanResult(portResult));
            });

            ScanPortsButton.IsEnabled = true;
            ScanPortsButton.Content = "🔌 端口扫描";
        }

        private void ShowPortScanResult(WebPortScanResult result)
        {
            PortScanPanel.Children.Clear();

            PortScanPanel.Children.Add(new TextBlock
            {
                Text = $"🔌 端口扫描结果 - {result.Host}",
                FontSize = 16,
                FontWeight = FontWeights.Bold,
                Foreground = new SolidColorBrush(Color.FromRgb(0x2C, 0x3E, 0x50)),
                Margin = new Thickness(0, 0, 0, 15)
            });

            PortScanPanel.Children.Add(CreateInfoRow("扫描主机:", result.Host));
            PortScanPanel.Children.Add(CreateInfoRow("扫描端口数:", result.TotalScanned.ToString()));
            PortScanPanel.Children.Add(CreateInfoRow("开放端口:", result.OpenPorts.Count.ToString()));
            PortScanPanel.Children.Add(CreateInfoRow("扫描耗时:", $"{result.ScanDuration.TotalSeconds:F2}秒"));

            if (result.OpenPorts.Count > 0)
            {
                PortScanPanel.Children.Add(new TextBlock
                {
                    Text = $"开放端口列表 ({result.OpenPorts.Count}):",
                    FontWeight = FontWeights.Bold,
                    Foreground = Brushes.Red,
                    Margin = new Thickness(0, 15, 0, 10)
                });

                foreach (var port in result.OpenPorts)
                {
                    var portColor = port.Port == 22 ? Colors.Orange
                        : port.Port == 3306 || port.Port == 5432 || port.Port == 6379 || port.Port == 27017 ? Colors.Red
                        : Colors.Teal;

                    var border = new Border
                    {
                        Background = new SolidColorBrush(Color.FromArgb(0x10, (byte)portColor.R, (byte)portColor.G, (byte)portColor.B)),
                        BorderBrush = new SolidColorBrush(portColor),
                        BorderThickness = new Thickness(1),
                        CornerRadius = new CornerRadius(3),
                        Margin = new Thickness(0, 3, 0, 3),
                        Padding = new Thickness(8)
                    };

                    var stackPanel = new StackPanel();
                    stackPanel.Children.Add(new TextBlock
                    {
                        Text = $"🔓 端口 {port.Port} - {port.Service}",
                        FontWeight = FontWeights.Bold,
                        Foreground = new SolidColorBrush(portColor)
                    });
                    stackPanel.Children.Add(new TextBlock
                    {
                        Text = $"响应时间: {port.ResponseTime.TotalMilliseconds:F0}ms",
                        Foreground = Brushes.Gray,
                        FontSize = 11
                    });

                    border.Child = stackPanel;
                    PortScanPanel.Children.Add(border);
                }
            }
            else
            {
                PortScanPanel.Children.Add(new TextBlock
                {
                    Text = "✅ 未发现开放端口",
                    Foreground = Brushes.Green,
                    FontWeight = FontWeights.Bold,
                    Margin = new Thickness(0, 20, 0, 0)
                });
            }
        }

        private void ExportMarkdown_Click(object sender, RoutedEventArgs e)
        {
            if (_lastTraceResult == null)
            {
                MessageBox.Show("请先执行路径追踪", "提示", MessageBoxButton.OK, MessageBoxImage.Warning);
                return;
            }

            var tracer = new WebPathTracerService();
            var report = tracer.GenerateReport(_lastTraceResult, _stopwatch.Elapsed);
            var markdown = tracer.ExportReportAsMarkdown(report);

            var dialog = new Microsoft.Win32.SaveFileDialog
            {
                Filter = "Markdown文件|*.md",
                FileName = $"WebPathTrace_{DateTime.Now:yyyyMMdd_HHmmss}.md",
                InitialDirectory = Environment.GetFolderPath(Environment.SpecialFolder.Desktop)
            };

            if (dialog.ShowDialog() == true)
            {
                System.IO.File.WriteAllText(dialog.FileName, markdown, System.Text.Encoding.UTF8);
                MessageBox.Show($"报告已导出到:\n{dialog.FileName}", "导出成功", MessageBoxButton.OK, MessageBoxImage.Information);
            }
        }

        private void ExportJson_Click(object sender, RoutedEventArgs e)
        {
            if (_lastTraceResult == null)
            {
                MessageBox.Show("请先执行路径追踪", "提示", MessageBoxButton.OK, MessageBoxImage.Warning);
                return;
            }

            var tracer = new WebPathTracerService();
            var report = tracer.GenerateReport(_lastTraceResult, _stopwatch.Elapsed);
            var json = tracer.ExportReportAsJson(report);

            var dialog = new Microsoft.Win32.SaveFileDialog
            {
                Filter = "JSON文件|*.json",
                FileName = $"WebPathTrace_{DateTime.Now:yyyyMMdd_HHmmss}.json",
                InitialDirectory = Environment.GetFolderPath(Environment.SpecialFolder.Desktop)
            };

            if (dialog.ShowDialog() == true)
            {
                System.IO.File.WriteAllText(dialog.FileName, json, System.Text.Encoding.UTF8);
                MessageBox.Show($"报告已导出到:\n{dialog.FileName}", "导出成功", MessageBoxButton.OK, MessageBoxImage.Information);
            }
        }

        private WebPathTraceResult? _lastTraceResult;
        private SslCertificateInfo? _lastSslCertificate;

        private void ShowLayer1Result(Layer1Result? result, List<PathStep> redirectChain)
        {
            Layer1Panel.Children.Clear();
            if (result == null)
            {
                Layer1Panel.Children.Add(new TextBlock { Text = "未执行", Foreground = Brushes.Gray });
                return;
            }

            if (result.Error != null)
            {
                Layer1Panel.Children.Add(CreateResultBox("❌ HTTP请求失败", result.Error, Colors.Red));
                return;
            }

            Layer1Panel.Children.Add(CreateInfoRow("HTTP状态码:", result.StatusCode.ToString()));

            if (result.TechStack != null && result.TechStack.DetectedTechs.Count > 0)
            {
                Layer1Panel.Children.Add(new TextBlock
                {
                    Text = $"🔧 技术栈识别:",
                    FontWeight = FontWeights.Bold,
                    Foreground = new SolidColorBrush(Color.FromRgb(0x8E, 0x44, 0xAD)),
                    Margin = new Thickness(0, 10, 0, 3)
                });
                if (!string.IsNullOrEmpty(result.TechStack.Server))
                    Layer1Panel.Children.Add(CreateInfoRow("  Server:", result.TechStack.Server));
                if (!string.IsNullOrEmpty(result.TechStack.XPoweredBy))
                    Layer1Panel.Children.Add(CreateInfoRow("  X-Powered-By:", result.TechStack.XPoweredBy));
                if (!string.IsNullOrEmpty(result.TechStack.BackendLanguage))
                    Layer1Panel.Children.Add(CreateInfoRow("  后端语言:", result.TechStack.BackendLanguage));
                if (!string.IsNullOrEmpty(result.TechStack.Framework))
                    Layer1Panel.Children.Add(CreateInfoRow("  框架:", result.TechStack.Framework));
                if (!string.IsNullOrEmpty(result.TechStack.Cms))
                    Layer1Panel.Children.Add(CreateInfoRow("  CMS:", result.TechStack.Cms));
                Layer1Panel.Children.Add(new TextBlock
                {
                    Text = $"  识别结果: {string.Join(", ", result.TechStack.DetectedTechs)}",
                    TextWrapping = TextWrapping.Wrap,
                    Foreground = new SolidColorBrush(Color.FromRgb(0x8E, 0x44, 0xAD)),
                    Margin = new Thickness(0, 2, 0, 5)
                });
            }

            if (result.SetCookies.Count > 0)
            {
                Layer1Panel.Children.Add(new TextBlock
                {
                    Text = $"🍪 Cookie信息 ({result.SetCookies.Count}个):",
                    FontWeight = FontWeights.Bold,
                    Foreground = new SolidColorBrush(Color.FromRgb(0xE6, 0x7E, 0x22)),
                    Margin = new Thickness(0, 10, 0, 3)
                });
                foreach (var cookie in result.SetCookies)
                {
                    var flags = new List<string>();
                    if (cookie.HttpOnly) flags.Add("HttpOnly");
                    if (cookie.Secure) flags.Add("Secure");
                    if (cookie.IsSession) flags.Add("Session");
                    var flagStr = flags.Count > 0 ? $" [{string.Join(",", flags)}]" : "";
                    Layer1Panel.Children.Add(new TextBlock
                    {
                        Text = $"  {cookie.Name}{flagStr}",
                        TextWrapping = TextWrapping.Wrap,
                        Foreground = new SolidColorBrush(Color.FromRgb(0xE6, 0x7E, 0x22)),
                        Margin = new Thickness(0, 1, 0, 1)
                    });
                }
            }

            if (result.OpenRedirects.Count > 0)
            {
                Layer1Panel.Children.Add(new TextBlock
                {
                    Text = $"⚠️ 开放重定向漏洞 ({result.OpenRedirects.Count}个):",
                    FontWeight = FontWeights.Bold,
                    Foreground = Brushes.Red,
                    Margin = new Thickness(0, 10, 0, 3)
                });
                foreach (var or in result.OpenRedirects)
                {
                    if (or.IsVulnerable)
                    {
                        Layer1Panel.Children.Add(CreateResultBox($"参数: {or.Parameter}", $"测试URL: {or.TestUrl}\n跳转到: {or.RedirectedTo}", Colors.Red));
                    }
                }
            }

            if (result.WafInfo != null && result.WafInfo.IsBehindWaf)
            {
                Layer1Panel.Children.Add(new TextBlock
                {
                    Text = $"🛡️ WAF/防火墙检测:",
                    FontWeight = FontWeights.Bold,
                    Foreground = new SolidColorBrush(Color.FromRgb(0xE6, 0x7E, 0x22)),
                    Margin = new Thickness(0, 10, 0, 3)
                });
                Layer1Panel.Children.Add(new TextBlock
                {
                    Text = $"  检测到: {result.WafInfo.WafName}",
                    TextWrapping = TextWrapping.Wrap,
                    Foreground = new SolidColorBrush(Color.FromRgb(0xE6, 0x7E, 0x22)),
                    Margin = new Thickness(0, 2, 0, 2)
                });
                Layer1Panel.Children.Add(new TextBlock
                {
                    Text = $"  依据: {result.WafInfo.DetectionMethod}",
                    TextWrapping = TextWrapping.Wrap,
                    Foreground = Brushes.Gray,
                    Margin = new Thickness(0, 0, 0, 2)
                });
                foreach (var ind in result.WafInfo.Indicators.Take(3))
                {
                    Layer1Panel.Children.Add(new TextBlock
                    {
                        Text = $"    → {ind}",
                        TextWrapping = TextWrapping.Wrap,
                        Foreground = Brushes.Gray,
                        FontSize = 11
                    });
                }
            }

            if (result.DiscoveredApis.Count > 0)
            {
                Layer1Panel.Children.Add(new TextBlock
                {
                    Text = $"🔗 API端点发现 ({result.DiscoveredApis.Count}个):",
                    FontWeight = FontWeights.Bold,
                    Foreground = new SolidColorBrush(Color.FromRgb(0x1A, 0x7A, 0x9C)),
                    Margin = new Thickness(0, 10, 0, 3)
                });
                foreach (var api in result.DiscoveredApis.Take(10))
                {
                    var typeColor = api.Type switch
                    {
                        "GraphQL" => new SolidColorBrush(Color.FromRgb(0xE0, 0x35, 0x98)),
                        "OpenAPI/Swagger" => new SolidColorBrush(Color.FromRgb(0x6B, 0xCF, 0x7F)),
                        "REST API" => new SolidColorBrush(Color.FromRgb(0x1A, 0x7A, 0x9C)),
                        "Spring Actuator" => new SolidColorBrush(Color.FromRgb(0x4C, 0xAF, 0x50)),
                        "API Client" => new SolidColorBrush(Color.FromRgb(0xFF, 0x98, 0x00)),
                        _ => Brushes.Gray
                    };
                    Layer1Panel.Children.Add(new TextBlock
                    {
                        Text = $"  [{api.Type}] {api.Url}",
                        TextWrapping = TextWrapping.Wrap,
                        Foreground = typeColor,
                        Margin = new Thickness(0, 1, 0, 1)
                    });
                }
            }

            if (result.DiscoveredSubdomains.Count > 0)
            {
                Layer1Panel.Children.Add(new TextBlock
                {
                    Text = $"🌐 子域名发现 ({result.DiscoveredSubdomains.Count}个):",
                    FontWeight = FontWeights.Bold,
                    Foreground = new SolidColorBrush(Color.FromRgb(0x2E, 0x86, 0xAB)),
                    Margin = new Thickness(0, 10, 0, 3)
                });
                foreach (var sub in result.DiscoveredSubdomains.Take(10))
                {
                    Layer1Panel.Children.Add(CreateInfoRow("  →", sub));
                }
            }

            if (result.ParamVulnerabilityHints.Count > 0)
            {
                Layer1Panel.Children.Add(new TextBlock
                {
                    Text = $"⚠️ 参数漏洞风险提示 ({result.ParamVulnerabilityHints.Count}个):",
                    FontWeight = FontWeights.Bold,
                    Foreground = new SolidColorBrush(Colors.OrangeRed),
                    Margin = new Thickness(0, 10, 0, 3)
                });
                foreach (var hint in result.ParamVulnerabilityHints.Take(5))
                {
                    Layer1Panel.Children.Add(new TextBlock
                    {
                        Text = $"  → {hint}",
                        TextWrapping = TextWrapping.Wrap,
                        Foreground = new SolidColorBrush(Colors.OrangeRed),
                        Margin = new Thickness(0, 1, 0, 1)
                    });
                }
            }

            // 页面内容分析
            if (result.PageContent != null)
            {
                var page = result.PageContent;
                Layer1Panel.Children.Add(new TextBlock
                {
                    Text = "📄 页面内容分析:",
                    FontWeight = FontWeights.Bold,
                    Foreground = new SolidColorBrush(Color.FromRgb(0x2C, 0x3E, 0x50)),
                    Margin = new Thickness(0, 15, 0, 10)
                });

                if (!string.IsNullOrEmpty(page.Title))
                {
                    Layer1Panel.Children.Add(CreateInfoRow("  标题:", page.Title));
                }

                if (!string.IsNullOrEmpty(page.Description))
                {
                    Layer1Panel.Children.Add(CreateInfoRow("  描述:", page.Description));
                }

                if (page.Keywords.Count > 0)
                {
                    Layer1Panel.Children.Add(CreateInfoRow("  关键词:", string.Join(", ", page.Keywords)));
                }

                if (!string.IsNullOrEmpty(page.CmsDetected))
                {
                    var cmsBorder = new Border
                    {
                        Background = new SolidColorBrush(Color.FromRgb(0xE8, 0xF8, 0xF5)),
                        BorderBrush = new SolidColorBrush(Color.FromRgb(0x1A, 0xBC, 0x9C)),
                        BorderThickness = new Thickness(1),
                        CornerRadius = new CornerRadius(3),
                        Padding = new Thickness(5),
                        Margin = new Thickness(0, 3, 0, 3)
                    };
                    cmsBorder.Child = new TextBlock
                    {
                        Text = $"  🔧 CMS: {page.CmsDetected}",
                        FontWeight = FontWeights.Bold,
                        Foreground = new SolidColorBrush(Color.FromRgb(0x1A, 0xBC, 0x9C))
                    };
                    Layer1Panel.Children.Add(cmsBorder);
                }

                if (!string.IsNullOrEmpty(page.FrameworkDetected))
                {
                    var fwBorder = new Border
                    {
                        Background = new SolidColorBrush(Color.FromRgb(0xEB, 0xF5, 0xFB)),
                        BorderBrush = new SolidColorBrush(Color.FromRgb(0x34, 0x98, 0xDB)),
                        BorderThickness = new Thickness(1),
                        CornerRadius = new CornerRadius(3),
                        Padding = new Thickness(5),
                        Margin = new Thickness(0, 3, 0, 3)
                    };
                    fwBorder.Child = new TextBlock
                    {
                        Text = $"  🔧 前端框架: {page.FrameworkDetected}",
                        FontWeight = FontWeights.Bold,
                        Foreground = new SolidColorBrush(Color.FromRgb(0x34, 0x98, 0xDB))
                    };
                    Layer1Panel.Children.Add(fwBorder);
                }

                var statsPanel = new StackPanel { Orientation = Orientation.Horizontal, Margin = new Thickness(0, 5, 0, 0) };
                statsPanel.Children.Add(CreateStatBox("🔗", page.LinkCount.ToString(), "链接"));
                statsPanel.Children.Add(CreateStatBox("🖼️", page.ImageCount.ToString(), "图片"));
                statsPanel.Children.Add(CreateStatBox("📝", page.FormCount.ToString(), "表单"));
                statsPanel.Children.Add(CreateStatBox("📜", page.ScriptCount.ToString(), "脚本"));
                statsPanel.Children.Add(CreateStatBox("🎨", page.StyleCount.ToString(), "样式"));
                Layer1Panel.Children.Add(statsPanel);
            }

            if (result.FoundUrl != null)
            {
                Layer1Panel.Children.Add(CreateResultBox("✅ 发现跳转URL", result.FoundUrl, Colors.Green));
            }

            if (result.LinkHeaderUrl != null)
            {
                Layer1Panel.Children.Add(CreateResultBox("Link头跳转", result.LinkHeaderUrl, Colors.Teal));
            }

            if (result.XRedirectUrl != null)
            {
                Layer1Panel.Children.Add(CreateResultBox("X-Redirect头跳转", result.XRedirectUrl, Colors.Purple));
            }

            if (result.MissingSecurityHeaders.Count > 0)
            {
                Layer1Panel.Children.Add(new TextBlock
                {
                    Text = $"⚠️ 缺少安全头 ({result.MissingSecurityHeaders.Count}):",
                    FontWeight = FontWeights.Bold,
                    Foreground = Brushes.OrangeRed,
                    Margin = new Thickness(0, 15, 0, 5)
                });
                foreach (var header in result.MissingSecurityHeaders)
                {
                    Layer1Panel.Children.Add(new TextBlock
                    {
                        Text = $"  ❌ {header}",
                        Foreground = Brushes.OrangeRed,
                        Margin = new Thickness(0, 1, 0, 1)
                    });
                }
            }

            if (result.SecurityHeaders.Count > 0)
            {
                Layer1Panel.Children.Add(new TextBlock
                {
                    Text = $"已设置安全头 ({result.SecurityHeaders.Count}):",
                    FontWeight = FontWeights.Bold,
                    Foreground = new SolidColorBrush(Color.FromRgb(0x27, 0xAE, 0x60)),
                    Margin = new Thickness(0, 10, 0, 5)
                });
                foreach (var header in result.SecurityHeaders)
                {
                    Layer1Panel.Children.Add(new TextBlock
                    {
                        Text = $"  ✅ {header}",
                        Foreground = new SolidColorBrush(Color.FromRgb(0x27, 0xAE, 0x60)),
                        Margin = new Thickness(0, 1, 0, 1)
                    });
                }
            }

            if (redirectChain.Count > 0)
            {
                Layer1Panel.Children.Add(new TextBlock
                {
                    Text = $"重定向链 ({redirectChain.Count} 步):",
                    FontWeight = FontWeights.Bold,
                    FontSize = 14,
                    Foreground = new SolidColorBrush(Color.FromRgb(0x2C, 0x3E, 0x50)),
                    Margin = new Thickness(0, 15, 0, 10)
                });
                for (int i = 0; i < redirectChain.Count; i++)
                {
                    Layer1Panel.Children.Add(CreateRedirectChainItem(redirectChain[i], i + 1));
                }
            }

            if (result.Headers.Count > 0)
            {
                Layer1Panel.Children.Add(new TextBlock
                {
                    Text = "响应头:",
                    FontWeight = FontWeights.Bold,
                    Margin = new Thickness(0, 15, 0, 5)
                });
                foreach (var header in result.Headers.Take(20))
                {
                    Layer1Panel.Children.Add(CreateInfoRow($"  {header.Key}:", header.Value));
                }
            }
        }

        private void ShowLayer2Result(Layer2Result? result)
        {
            Layer2Panel.Children.Clear();
            if (result == null)
            {
                Layer2Panel.Children.Add(new TextBlock { Text = "未执行", Foreground = Brushes.Gray });
                return;
            }

            if (result.Error != null)
            {
                Layer2Panel.Children.Add(CreateResultBox("❌ HTML分析失败", result.Error, Colors.Red));
                return;
            }

            if (result.MetaRefreshUrl != null)
            {
                Layer2Panel.Children.Add(CreateResultBox("Meta Refresh跳转", result.MetaRefreshUrl, Colors.Orange));
            }

            if (result.JsRedirectUrl != null)
            {
                Layer2Panel.Children.Add(CreateResultBox("JavaScript跳转", result.JsRedirectUrl, Colors.Blue));
            }

            if (result.JsRedirectUrls.Count > 0)
            {
                Layer2Panel.Children.Add(new TextBlock
                {
                    Text = $"JS跳转URL ({result.JsRedirectUrls.Count}):",
                    FontWeight = FontWeights.Bold,
                    Foreground = Brushes.Blue,
                    Margin = new Thickness(0, 10, 0, 5)
                });
                foreach (var url in result.JsRedirectUrls)
                {
                    Layer2Panel.Children.Add(CreateInfoRow("  →", url));
                }
            }

            if (result.SpaRouteUrls.Count > 0)
            {
                Layer2Panel.Children.Add(new TextBlock
                {
                    Text = $"SPA路由 ({result.SpaRouteUrls.Count}):",
                    FontWeight = FontWeights.Bold,
                    Foreground = Brushes.Purple,
                    Margin = new Thickness(0, 10, 0, 5)
                });
                foreach (var url in result.SpaRouteUrls)
                {
                    Layer2Panel.Children.Add(CreateInfoRow("  →", url));
                }
            }

            if (result.DecodedUrls.Count > 0)
            {
                Layer2Panel.Children.Add(new TextBlock
                {
                    Text = $"Base64解码URL ({result.DecodedUrls.Count}):",
                    FontWeight = FontWeights.Bold,
                    Foreground = Brushes.Teal,
                    Margin = new Thickness(0, 10, 0, 5)
                });
                foreach (var url in result.DecodedUrls)
                {
                    Layer2Panel.Children.Add(CreateInfoRow("  →", url));
                }
            }

            if (result.FoundLoginLinks.Count > 0)
            {
                Layer2Panel.Children.Add(new TextBlock
                {
                    Text = $"登录链接 ({result.FoundLoginLinks.Count}):",
                    FontWeight = FontWeights.Bold,
                    Foreground = Brushes.OrangeRed,
                    Margin = new Thickness(0, 10, 0, 5)
                });
                foreach (var link in result.FoundLoginLinks)
                {
                    Layer2Panel.Children.Add(CreateResultBox("🔗 登录链接", link, Colors.OrangeRed));
                }
            }

            if (result.AllLinks.Count > 0)
            {
                var grouped = result.AllLinks.GroupBy(l => l.Category).OrderByDescending(g => g.Count()).ToList();
                Layer2Panel.Children.Add(new TextBlock
                {
                    Text = $"📋 页面链接分类 ({result.AllLinks.Count}个):",
                    FontWeight = FontWeights.Bold,
                    Foreground = new SolidColorBrush(Color.FromRgb(0x2C, 0x3E, 0x50)),
                    Margin = new Thickness(0, 15, 0, 5)
                });
                foreach (var group in grouped)
                {
                    var categoryColor = group.Key switch
                    {
                        "login" => Colors.OrangeRed,
                        "admin" => Colors.Purple,
                        "api" => Colors.Teal,
                        "form" => Colors.Blue,
                        "register" => Colors.DeepPink,
                        _ => Colors.Gray
                    };
                    Layer2Panel.Children.Add(new TextBlock
                    {
                        Text = $"  {group.Key} ({group.Count()}个):",
                        FontWeight = FontWeights.Bold,
                        Foreground = new SolidColorBrush(categoryColor),
                        Margin = new Thickness(0, 5, 0, 2)
                    });
                    foreach (var link in group.Take(10))
                    {
                        var displayText = !string.IsNullOrEmpty(link.Text) ? $" [{link.Text}]" : "";
                        Layer2Panel.Children.Add(CreateInfoRow("    →", $"{link.Url}{displayText}"));
                    }
                    if (group.Count() > 10)
                    {
                        Layer2Panel.Children.Add(new TextBlock
                        {
                            Text = $"    ... 还有 {group.Count() - 10} 个",
                            Foreground = Brushes.Gray,
                            Margin = new Thickness(0, 1, 0, 3)
                        });
                    }
                }
            }

            if (result.ExternalResources.Count > 0)
            {
                Layer2Panel.Children.Add(new TextBlock
                {
                    Text = $"📦 外部资源 ({result.ExternalResources.Count}个):",
                    FontWeight = FontWeights.Bold,
                    Foreground = Brushes.Gray,
                    Margin = new Thickness(0, 10, 0, 5)
                });
                foreach (var res in result.ExternalResources.Take(20))
                {
                    Layer2Panel.Children.Add(new TextBlock
                    {
                        Text = $"  {res}",
                        TextWrapping = TextWrapping.Wrap,
                        Foreground = Brushes.Gray,
                        FontSize = 11,
                        Margin = new Thickness(0, 1, 0, 1)
                    });
                }
                if (result.ExternalResources.Count > 20)
                {
                    Layer2Panel.Children.Add(new TextBlock
                    {
                        Text = $"  ... 还有 {result.ExternalResources.Count - 20} 个",
                        Foreground = Brushes.Gray,
                        Margin = new Thickness(0, 1, 0, 3)
                    });
                }
            }

            if (result.InlineEventHandlers.Count > 0)
            {
                Layer2Panel.Children.Add(new TextBlock
                {
                    Text = $"⚡ 内联事件处理 ({result.InlineEventHandlers.Count}个):",
                    FontWeight = FontWeights.Bold,
                    Foreground = Brushes.Orange,
                    Margin = new Thickness(0, 10, 0, 5)
                });
                foreach (var handler in result.InlineEventHandlers.Take(10))
                {
                    Layer2Panel.Children.Add(new TextBlock
                    {
                        Text = $"  {handler}",
                        TextWrapping = TextWrapping.Wrap,
                        Foreground = Brushes.Orange,
                        FontSize = 11,
                        Margin = new Thickness(0, 1, 0, 1)
                    });
                }
            }

            if (result.FoundUrl == null && result.MetaRefreshUrl == null && result.JsRedirectUrl == null
                && result.JsRedirectUrls.Count == 0 && result.SpaRouteUrls.Count == 0
                && result.FoundLoginLinks.Count == 0 && result.DecodedUrls.Count == 0
                && result.AllLinks.Count == 0)
            {
                Layer2Panel.Children.Add(new TextBlock
                {
                    Text = "HTML源码中未发现明显跳转或登录链接",
                    Foreground = Brushes.Gray,
                    Margin = new Thickness(0, 10, 0, 0)
                });
            }
        }

        private void ShowLayer3Result(Layer3Result? result)
        {
            Layer3Panel.Children.Clear();
            if (result == null)
            {
                Layer3Panel.Children.Add(new TextBlock { Text = "未执行", Foreground = Brushes.Gray });
                return;
            }

            if (result.FoundUrls.Count > 0)
            {
                Layer3Panel.Children.Add(new TextBlock
                {
                    Text = $"发现 {result.FoundUrls.Count} 个敏感文件:",
                    FontWeight = FontWeights.Bold,
                    Margin = new Thickness(0, 0, 0, 10)
                });
                foreach (var url in result.FoundUrls)
                {
                    Layer3Panel.Children.Add(CreateResultBox("📄", url, Colors.Red));
                }
            }
            else
            {
                Layer3Panel.Children.Add(new TextBlock { Text = "未发现敏感文件", Foreground = Brushes.Gray });
            }

            if (result.DisallowPaths.Count > 0)
            {
                Layer3Panel.Children.Add(new TextBlock
                {
                    Text = $"robots.txt Disallow 路径 ({result.DisallowPaths.Count}):",
                    FontWeight = FontWeights.Bold,
                    Margin = new Thickness(0, 15, 0, 5)
                });
                foreach (var path in result.DisallowPaths)
                {
                    Layer3Panel.Children.Add(CreateInfoRow("  🚫", path));
                }
            }

            if (result.AllowPaths.Count > 0)
            {
                Layer3Panel.Children.Add(new TextBlock
                {
                    Text = $"robots.txt Allow 路径 ({result.AllowPaths.Count}):",
                    FontWeight = FontWeights.Bold,
                    Margin = new Thickness(0, 15, 0, 5)
                });
                foreach (var path in result.AllowPaths)
                {
                    Layer3Panel.Children.Add(CreateInfoRow("  ✅", path));
                }
            }

            if (result.SitemapUrls.Count > 0)
            {
                Layer3Panel.Children.Add(new TextBlock
                {
                    Text = $"Sitemap URL ({result.SitemapUrls.Count}):",
                    FontWeight = FontWeights.Bold,
                    Margin = new Thickness(0, 15, 0, 5)
                });
                foreach (var url in result.SitemapUrls)
                {
                    Layer3Panel.Children.Add(CreateInfoRow("  🗺", url));
                }
            }
        }

        private void ShowLayer4Result(Layer4Result? result)
        {
            Layer4Panel.Children.Clear();
            if (result == null)
            {
                var msg = EnableSeleniumCheckBox.IsChecked == true ? "未执行" : "Selenium检测已跳过(未启用)";
                Layer4Panel.Children.Add(new TextBlock { Text = msg, Foreground = Brushes.Gray });
                return;
            }

            if (result.Error != null)
            {
                Layer4Panel.Children.Add(CreateResultBox("❌ Selenium检测失败", result.Error, Colors.Red));
                Layer4Panel.Children.Add(new TextBlock
                {
                    Text = "提示: 请确保已安装Chrome浏览器。如无法使用Selenium，可取消勾选[Selenium动态检测]。",
                    Foreground = Brushes.OrangeRed,
                    TextWrapping = TextWrapping.Wrap,
                    Margin = new Thickness(0, 10, 0, 0)
                });
                return;
            }

            Layer4Panel.Children.Add(new TextBlock
            {
                Text = "Selenium动态检测结果",
                FontSize = 16,
                FontWeight = FontWeights.Bold,
                Foreground = new SolidColorBrush(Color.FromRgb(0x2C, 0x3E, 0x50)),
                Margin = new Thickness(0, 0, 0, 15)
            });

            Layer4Panel.Children.Add(CreateInfoRow("初始URL:", result.InitialUrl));
            Layer4Panel.Children.Add(CreateInfoRow("最终URL:", result.FinalUrl ?? "无变化"));

            if (result.UrlChanged)
            {
                Layer4Panel.Children.Add(CreateResultBox("✅ 检测到URL变化!", result.FinalUrl ?? "", Colors.Green));

                if (result.RedirectChain.Count > 0)
                {
                    Layer4Panel.Children.Add(new TextBlock
                    {
                        Text = "跳转链:",
                        FontWeight = FontWeights.Bold,
                        Margin = new Thickness(0, 10, 0, 5)
                    });
                    for (int i = 0; i < result.RedirectChain.Count; i++)
                    {
                        Layer4Panel.Children.Add(CreateInfoRow($"  {i + 1}.", result.RedirectChain[i]));
                    }
                }
            }
            else
            {
                Layer4Panel.Children.Add(new TextBlock
                {
                    Text = "URL未发生变化(页面可能无动态跳转)",
                    Foreground = Brushes.Gray,
                    Margin = new Thickness(0, 5, 0, 0)
                });
            }

            if (result.FoundForms.Count > 0)
            {
                Layer4Panel.Children.Add(new TextBlock
                {
                    Text = $"发现 {result.FoundForms.Count} 个表单:",
                    FontWeight = FontWeights.Bold,
                    Foreground = Brushes.Orange,
                    Margin = new Thickness(0, 15, 0, 5)
                });
                foreach (var form in result.FoundForms)
                {
                    Layer4Panel.Children.Add(CreateResultBox("📝 表单", form, Colors.Orange));
                }
            }

            if (result.FoundIframes.Count > 0)
            {
                Layer4Panel.Children.Add(new TextBlock
                {
                    Text = $"发现 {result.FoundIframes.Count} 个iframe:",
                    FontWeight = FontWeights.Bold,
                    Foreground = Brushes.Blue,
                    Margin = new Thickness(0, 15, 0, 5)
                });
                foreach (var iframe in result.FoundIframes)
                {
                    Layer4Panel.Children.Add(CreateResultBox("🖼 iframe", iframe, Colors.Blue));
                }
            }

            if (result.FoundDynamicLinks.Count > 0)
            {
                Layer4Panel.Children.Add(new TextBlock
                {
                    Text = $"发现 {result.FoundDynamicLinks.Count} 个动态链接:",
                    FontWeight = FontWeights.Bold,
                    Foreground = Brushes.Purple,
                    Margin = new Thickness(0, 15, 0, 5)
                });
                foreach (var link in result.FoundDynamicLinks)
                {
                    Layer4Panel.Children.Add(CreateResultBox("🔗 动态链接", link, Colors.Purple));
                }
            }

            if (result.FoundAjaxCalls.Count > 0)
            {
                Layer4Panel.Children.Add(new TextBlock
                {
                    Text = $"发现 {result.FoundAjaxCalls.Count} 个AJAX请求:",
                    FontWeight = FontWeights.Bold,
                    Foreground = Brushes.Teal,
                    Margin = new Thickness(0, 15, 0, 5)
                });
                foreach (var ajax in result.FoundAjaxCalls)
                {
                    Layer4Panel.Children.Add(CreateInfoRow("  →", ajax));
                }
            }

            if (result.ConsoleLogs.Count > 0)
            {
                Layer4Panel.Children.Add(new TextBlock
                {
                    Text = $"浏览器控制台日志 ({result.ConsoleLogs.Count} 条):",
                    FontWeight = FontWeights.Bold,
                    Foreground = Brushes.Gray,
                    Margin = new Thickness(0, 15, 0, 5)
                });
                foreach (var log in result.ConsoleLogs.Take(20))
                {
                    Layer4Panel.Children.Add(new TextBlock
                    {
                        Text = $"  {log}",
                        TextWrapping = TextWrapping.Wrap,
                        FontFamily = new FontFamily("Consolas"),
                        FontSize = 10,
                        Foreground = Brushes.Gray
                    });
                }
            }

            if (!string.IsNullOrEmpty(result.ScreenshotPath) && File.Exists(result.ScreenshotPath))
            {
                Layer4Panel.Children.Add(new TextBlock
                {
                    Text = $"📷 页面截图:",
                    FontWeight = FontWeights.Bold,
                    Foreground = new SolidColorBrush(Color.FromRgb(0x6B, 0xCF, 0x7F)),
                    Margin = new Thickness(0, 15, 0, 5)
                });
                try
                {
                    var img = new System.Windows.Media.Imaging.BitmapImage();
                    img.BeginInit();
                    img.CacheOption = System.Windows.Media.Imaging.BitmapCacheOption.OnLoad;
                    img.UriSource = new Uri(result.ScreenshotPath);
                    img.EndInit();
                    img.Freeze();

                    var image = new Image
                    {
                        Source = img,
                        MaxWidth = 800,
                        MaxHeight = 450,
                        Stretch = Stretch.Uniform,
                        Margin = new Thickness(0, 5, 0, 5),
                        Cursor = Cursors.Hand
                    };
                    var tooltip = new ToolTip { Content = result.ScreenshotPath };
                    image.ToolTip = tooltip;

                    Layer4Panel.Children.Add(image);
                    Layer4Panel.Children.Add(new TextBlock
                    {
                        Text = $"路径: {result.ScreenshotPath}",
                        TextWrapping = TextWrapping.Wrap,
                        Foreground = Brushes.Gray,
                        FontSize = 11,
                        Margin = new Thickness(0, 2, 0, 5)
                    });
                }
                catch
                {
                    Layer4Panel.Children.Add(new TextBlock
                    {
                        Text = $"截图加载失败: {result.ScreenshotPath}",
                        Foreground = Brushes.Gray,
                        Margin = new Thickness(0, 2, 0, 5)
                    });
                }
            }

            if (result.FoundForms.Count == 0 && result.FoundIframes.Count == 0 && result.FoundDynamicLinks.Count == 0 && result.FoundAjaxCalls.Count == 0 && string.IsNullOrEmpty(result.ScreenshotPath))
            {
                Layer4Panel.Children.Add(new TextBlock
                {
                    Text = "Selenium动态检测未发现额外跳转、表单或隐藏路径",
                    Foreground = Brushes.Gray,
                    Margin = new Thickness(0, 15, 0, 0)
                });
            }
        }

        private void ShowBruteResult(DirectoryBruteResult? result)
        {
            BrutePanel.Children.Clear();
            if (result == null)
            {
                BrutePanel.Children.Add(new TextBlock { Text = "未执行(仅在标准/深度模式下运行)", Foreground = Brushes.Gray });
                return;
            }

            BrutePanel.Children.Add(new TextBlock
            {
                Text = "目录爆破结果",
                FontSize = 16,
                FontWeight = FontWeights.Bold,
                Foreground = new SolidColorBrush(Color.FromRgb(0x2C, 0x3E, 0x50)),
                Margin = new Thickness(0, 0, 0, 15)
            });

            BrutePanel.Children.Add(CreateInfoRow("测试总数:", result.TotalTested.ToString()));
            BrutePanel.Children.Add(CreateInfoRow("发现路径:", result.FoundPaths.Count.ToString()));

            if (result.HasCustom404)
            {
                BrutePanel.Children.Add(new TextBlock
                {
                    Text = "⚠️ 检测到自定义404页面，已启用内容相似度过滤",
                    Foreground = Brushes.Orange,
                    TextWrapping = TextWrapping.Wrap,
                    Margin = new Thickness(0, 5, 0, 5)
                });
            }

            var highConf = result.FoundPaths.Count(p => p.Confidence >= 70);
            var medConf = result.FoundPaths.Count(p => p.Confidence >= 50 && p.Confidence < 70);
            var lowConf = result.FoundPaths.Count(p => p.Confidence < 50);
            if (highConf > 0 || medConf > 0 || lowConf > 0)
            {
                BrutePanel.Children.Add(new TextBlock
                {
                    Text = $"置信度分布: 高={highConf} 中={medConf} 低(疑似404)={lowConf}",
                    Foreground = Brushes.Gray,
                    Margin = new Thickness(0, 5, 0, 5)
                });
            }

            if (result.ByStatusCode.Count > 0)
            {
                BrutePanel.Children.Add(new TextBlock
                {
                    Text = "按状态码分类:",
                    FontWeight = FontWeights.Bold,
                    Margin = new Thickness(0, 15, 0, 5)
                });
                foreach (var kv in result.ByStatusCode.OrderByDescending(x => x.Key))
                {
                    var color = kv.Key == 200 ? Colors.Green
                        : kv.Key == 403 ? Colors.Orange
                        : kv.Key >= 400 ? Colors.Red
                        : Colors.Blue;
                    BrutePanel.Children.Add(new TextBlock
                    {
                        Text = $"  [{kv.Key}] - {kv.Value.Count} 个路径",
                        FontWeight = FontWeights.Bold,
                        Foreground = new SolidColorBrush(color),
                        Margin = new Thickness(0, 5, 0, 3)
                    });
                    foreach (var path in kv.Value)
                    {
                        BrutePanel.Children.Add(CreateInfoRow("    →", $"{path.Url} ({path.PathType})"));
                    }
                }
            }

            if (result.FoundPaths.Count > 0)
            {
                BrutePanel.Children.Add(new TextBlock
                {
                    Text = "所有发现路径:",
                    FontWeight = FontWeights.Bold,
                    Margin = new Thickness(0, 15, 0, 5)
                });
                foreach (var path in result.FoundPaths)
                {
                    var color = path.StatusCode == 200 ? Colors.Green
                        : path.StatusCode == 403 ? Colors.Orange
                        : Colors.Red;
                    var confLabel = path.Confidence < 50 ? $" [⚠️置信度:{path.Confidence}%]"
                        : path.Confidence < 70 ? $" [置信度:{path.Confidence}%]" : "";
                    var titleInfo = !string.IsNullOrEmpty(path.Title) ? $" \"{path.Title}\"" : "";
                    var lengthInfo = path.ContentLength > 0 ? $" [{path.ContentLength}B]" : "";
                    BrutePanel.Children.Add(CreateResultBox($"[{path.StatusCode}] {path.PathType}{confLabel}", $"{path.Url}{titleInfo}{lengthInfo}", color));
                }
            }
        }

        private void ShowPathSegmentResult(PathSegmentResult? result)
        {
            PathSegmentPanel.Children.Clear();
            if (result == null)
            {
                PathSegmentPanel.Children.Add(new TextBlock { Text = "未执行", Foreground = Brushes.Gray });
                return;
            }

            PathSegmentPanel.Children.Add(new TextBlock
            {
                Text = "路径段分析结果",
                FontSize = 16,
                FontWeight = FontWeights.Bold,
                Foreground = new SolidColorBrush(Color.FromRgb(0x2C, 0x3E, 0x50)),
                Margin = new Thickness(0, 0, 0, 15)
            });

            PathSegmentPanel.Children.Add(CreateInfoRow("基础URL:", result.BaseUrl));
            PathSegmentPanel.Children.Add(CreateInfoRow("路径段数量:", result.Segments.Count.ToString()));

            if (result.Segments.Count > 0)
            {
                PathSegmentPanel.Children.Add(new TextBlock
                {
                    Text = "路径段详情:",
                    FontWeight = FontWeights.Bold,
                    Foreground = new SolidColorBrush(Color.FromRgb(0x2C, 0x3E, 0x50)),
                    Margin = new Thickness(0, 15, 0, 10)
                });

                foreach (var segment in result.Segments)
                {
                    var depthColor = segment.Depth == 1 ? Colors.Green
                        : segment.Depth <= 3 ? Colors.Blue
                        : segment.Depth <= 5 ? Colors.Orange
                        : Colors.Red;

                    var border = new Border
                    {
                        Background = Brushes.WhiteSmoke,
                        BorderBrush = new SolidColorBrush(depthColor),
                        BorderThickness = new Thickness(2),
                        CornerRadius = new CornerRadius(5),
                        Margin = new Thickness(0, 5, 0, 5),
                        Padding = new Thickness(10)
                    };

                    var stackPanel = new StackPanel();
                    stackPanel.Children.Add(new TextBlock
                    {
                        Text = $"深度 {segment.Depth}: {segment.Segment}",
                        FontWeight = FontWeights.Bold,
                        Foreground = new SolidColorBrush(depthColor)
                    });

                    if (!string.IsNullOrEmpty(segment.ParentPath))
                    {
                        stackPanel.Children.Add(new TextBlock
                        {
                            Text = $"父路径: {segment.ParentPath}",
                            Foreground = Brushes.Gray,
                            FontSize = 11,
                            Margin = new Thickness(0, 2, 0, 0)
                        });
                    }

                    border.Child = stackPanel;
                    PathSegmentPanel.Children.Add(border);
                }
            }

            if (result.PathPatterns.Count > 0)
            {
                PathSegmentPanel.Children.Add(new TextBlock
                {
                    Text = $"路径模式 ({result.PathPatterns.Count}):",
                    FontWeight = FontWeights.Bold,
                    Foreground = new SolidColorBrush(Color.FromRgb(0x8E, 0x44, 0xAD)),
                    Margin = new Thickness(0, 15, 0, 10)
                });

                foreach (var pattern in result.PathPatterns)
                {
                    PathSegmentPanel.Children.Add(CreateInfoRow("  →", pattern));
                }
            }

            if (result.FoundPaths.Count > 0)
            {
                PathSegmentPanel.Children.Add(new TextBlock
                {
                    Text = "发现的路径:",
                    FontWeight = FontWeights.Bold,
                    Foreground = new SolidColorBrush(Color.FromRgb(0x27, 0xAE, 0x60)),
                    Margin = new Thickness(0, 15, 0, 10)
                });

                foreach (var path in result.FoundPaths)
                {
                    var color = path.StatusCode == 200 ? Colors.Green
                        : path.StatusCode == 403 ? Colors.Orange
                        : Colors.Red;
                    PathSegmentPanel.Children.Add(CreateResultBox($"[{path.StatusCode}] {path.PathType}", path.Url, color));
                }
            }
        }

        private void ShowSensitivePathResult(List<string> sensitivePaths, WebPathTraceResult result)
        {
            SensitivePathPanel.Children.Clear();

            if (sensitivePaths == null || sensitivePaths.Count == 0)
            {
                SensitivePathPanel.Children.Add(new TextBlock
                {
                    Text = "✅ 未发现敏感路径",
                    FontSize = 16,
                    FontWeight = FontWeights.Bold,
                    Foreground = new SolidColorBrush(Color.FromRgb(0x27, 0xAE, 0x60)),
                    Margin = new Thickness(0, 10, 0, 0)
                });
                return;
            }

            SensitivePathPanel.Children.Add(new TextBlock
            {
                Text = $"敏感路径检测结果",
                FontSize = 16,
                FontWeight = FontWeights.Bold,
                Foreground = new SolidColorBrush(Color.FromRgb(0xE7, 0x4C, 0x3C)),
                Margin = new Thickness(0, 0, 0, 15)
            });

            SensitivePathPanel.Children.Add(CreateInfoRow("发现敏感路径数量:", sensitivePaths.Count.ToString()));

            SensitivePathPanel.Children.Add(new TextBlock
            {
                Text = $"敏感路径列表 ({sensitivePaths.Count}):",
                FontWeight = FontWeights.Bold,
                Foreground = new SolidColorBrush(Color.FromRgb(0xE7, 0x4C, 0x3C)),
                Margin = new Thickness(0, 15, 0, 10)
            });

            foreach (var path in sensitivePaths)
            {
                var riskLevel = ClassifySensitivePath(path);
                var riskColor = riskLevel == "高风险" ? Colors.Red
                    : riskLevel == "中风险" ? Colors.Orange
                    : Colors.Gray;

                SensitivePathPanel.Children.Add(CreateResultBox($"⚠️ {riskLevel}", path, riskColor));
            }

            var groupedPaths = sensitivePaths.GroupBy(p => GetSensitivePathCategory(p)).OrderByDescending(g => g.Count());
            SensitivePathPanel.Children.Add(new TextBlock
            {
                Text = "敏感路径分类统计:",
                FontWeight = FontWeights.Bold,
                Foreground = new SolidColorBrush(Color.FromRgb(0x2C, 0x3E, 0x50)),
                Margin = new Thickness(0, 15, 0, 10)
            });

            foreach (var group in groupedPaths)
            {
                var categoryColor = group.Key switch
                {
                    "管理后台" => Colors.Red,
                    "认证相关" => Colors.Orange,
                    "API接口" => Colors.Teal,
                    "配置文件" => Colors.Purple,
                    "调试信息" => Colors.Blue,
                    _ => Colors.Gray
                };

                SensitivePathPanel.Children.Add(new TextBlock
                {
                    Text = $"  {group.Key}: {group.Count()} 个路径",
                    FontWeight = FontWeights.Bold,
                    Foreground = new SolidColorBrush(categoryColor),
                    Margin = new Thickness(0, 5, 0, 5)
                });

                foreach (var path in group.Take(5))
                {
                    SensitivePathPanel.Children.Add(CreateInfoRow("    →", path));
                }

                if (group.Count() > 5)
                {
                    SensitivePathPanel.Children.Add(new TextBlock
                    {
                        Text = $"    ... 还有 {group.Count() - 5} 个",
                        Foreground = Brushes.Gray,
                        Margin = new Thickness(0, 2, 0, 5)
                    });
                }
            }
        }

        private static string ClassifySensitivePath(string path)
        {
            var lower = path.ToLower();
            if (lower.Contains("admin") || lower.Contains("manage") || lower.Contains("dashboard"))
                return "高风险";
            if (lower.Contains("login") || lower.Contains("auth") || lower.Contains("token"))
                return "高风险";
            if (lower.Contains("config") || lower.Contains("env") || lower.Contains("secret"))
                return "高风险";
            if (lower.Contains("api") || lower.Contains("graphql"))
                return "中风险";
            if (lower.Contains("debug") || lower.Contains("test") || lower.Contains("dev"))
                return "中风险";
            return "低风险";
        }

        private static string GetSensitivePathCategory(string path)
        {
            var lower = path.ToLower();
            if (lower.Contains("admin") || lower.Contains("manage") || lower.Contains("dashboard") || lower.Contains("console"))
                return "管理后台";
            if (lower.Contains("login") || lower.Contains("auth") || lower.Contains("token") || lower.Contains("register"))
                return "认证相关";
            if (lower.Contains("api") || lower.Contains("graphql") || lower.Contains("rest"))
                return "API接口";
            if (lower.Contains("config") || lower.Contains("env") || lower.Contains("secret") || lower.Contains("backup"))
                return "配置文件";
            if (lower.Contains("debug") || lower.Contains("test") || lower.Contains("dev"))
                return "调试信息";
            return "其他";
        }

        private void ShowCrawlResult(DeepCrawlResult? result)
        {
            CrawlPanel.Children.Clear();
            if (result == null)
            {
                CrawlPanel.Children.Add(new TextBlock { Text = "未执行(仅在标准/深度模式下运行)", Foreground = Brushes.Gray });
                return;
            }

            CrawlPanel.Children.Add(new TextBlock
            {
                Text = "深度爬取结果",
                FontSize = 16,
                FontWeight = FontWeights.Bold,
                Foreground = new SolidColorBrush(Color.FromRgb(0x2C, 0x3E, 0x50)),
                Margin = new Thickness(0, 0, 0, 15)
            });

            CrawlPanel.Children.Add(CreateInfoRow("爬取页面数:", result.TotalCrawled.ToString()));
            CrawlPanel.Children.Add(CreateInfoRow("最大深度:", result.MaxDepth.ToString()));
            CrawlPanel.Children.Add(CreateInfoRow("发现路径:", result.FoundPaths.Count.ToString()));

            if (result.CrawledUrls.Count > 0)
            {
                CrawlPanel.Children.Add(new TextBlock
                {
                    Text = $"已爬取URL ({result.CrawledUrls.Count}):",
                    FontWeight = FontWeights.Bold,
                    Margin = new Thickness(0, 15, 0, 5)
                });
                foreach (var url in result.CrawledUrls)
                {
                    CrawlPanel.Children.Add(CreateInfoRow("  🕷", url));
                }
            }

            if (result.FoundPaths.Count > 0)
            {
                CrawlPanel.Children.Add(new TextBlock
                {
                    Text = "发现的链接:",
                    FontWeight = FontWeights.Bold,
                    Margin = new Thickness(0, 15, 0, 5)
                });
                foreach (var path in result.FoundPaths)
                {
                    var color = path.StatusCode == 200 ? Colors.Green
                        : path.StatusCode == 403 ? Colors.Orange
                        : Colors.Red;
                    CrawlPanel.Children.Add(CreateResultBox($"[{path.StatusCode}] {path.PathType}", path.Url, color));
                }
            }
        }

        private void ShowFinalResult(WebPathTraceResult result)
        {
            FinalResultPanel.Children.Clear();

            FinalResultPanel.Children.Add(new TextBlock
            {
                Text = result.FoundPath ? "🎯 追踪成功!" : "❌ 未发现路径",
                FontSize = 20,
                FontWeight = FontWeights.Bold,
                Foreground = result.FoundPath ? Brushes.Green : Brushes.Red,
                Margin = new Thickness(0, 0, 0, 20)
            });

            FinalResultPanel.Children.Add(CreateInfoRow("原始URL:", result.OriginalUrl));
            FinalResultPanel.Children.Add(CreateInfoRow("追踪模式:", result.Mode.ToString()));

            if (result.Layer1Results?.TechStack != null && result.Layer1Results.TechStack.DetectedTechs.Count > 0)
            {
                var tech = result.Layer1Results.TechStack;
                FinalResultPanel.Children.Add(new TextBlock
                {
                    Text = $"🔧 技术栈: {string.Join(", ", tech.DetectedTechs)}",
                    TextWrapping = TextWrapping.Wrap,
                    FontWeight = FontWeights.Bold,
                    Foreground = new SolidColorBrush(Color.FromRgb(0x8E, 0x44, 0xAD)),
                    Margin = new Thickness(0, 5, 0, 5)
                });
            }

            if (result.FinalUrl != null)
            {
                FinalResultPanel.Children.Add(CreateResultBox("最终路径:", result.FinalUrl, Colors.Green));
            }

            FinalResultPanel.Children.Add(new TextBlock
            {
                Text = "各层探测结果:",
                FontWeight = FontWeights.Bold,
                FontSize = 14,
                Foreground = new SolidColorBrush(Color.FromRgb(0x2C, 0x3E, 0x50)),
                Margin = new Thickness(0, 15, 0, 10)
            });

            FinalResultPanel.Children.Add(CreateInfoRow("第一层(HTTP重定向):",
                result.Layer1Results?.FoundUrl != null ? $"✅ 发现 → {result.Layer1Results.FoundUrl}" : "❌ 未发现"));

            FinalResultPanel.Children.Add(CreateInfoRow("第二层(HTML/JS):",
                result.Layer2Results?.FoundUrl != null ? $"✅ 发现 → {result.Layer2Results.FoundUrl}" : "❌ 未发现"));

            FinalResultPanel.Children.Add(CreateInfoRow("第三层(敏感文件):",
                result.Layer3Results?.FoundUrls.Count > 0 ? $"发现 {result.Layer3Results.FoundUrls.Count} 个" : "❌ 未发现"));

            if (result.Layer4Results != null)
            {
                var l4Status = result.Layer4Results.Error != null
                    ? $"⚠️ 失败: {result.Layer4Results.Error}"
                    : result.Layer4Results.UrlChanged
                        ? $"✅ 发现动态跳转 → {result.Layer4Results.FinalUrl}"
                        : "❌ 未发现动态跳转";
                FinalResultPanel.Children.Add(CreateInfoRow("第四层(Selenium动态):", l4Status));
            }
            else
            {
                FinalResultPanel.Children.Add(CreateInfoRow("第四层(Selenium动态):", "⏭ 已跳过"));
            }

            if (result.BruteResults != null)
            {
                FinalResultPanel.Children.Add(CreateInfoRow("目录爆破:",
                    result.BruteResults.FoundPaths.Count > 0 ? $"发现 {result.BruteResults.FoundPaths.Count} 个路径" : "❌ 未发现"));
            }

            if (result.CrawlResults != null)
            {
                FinalResultPanel.Children.Add(CreateInfoRow("深度爬取:",
                    result.CrawlResults.FoundPaths.Count > 0 ? $"发现 {result.CrawlResults.FoundPaths.Count} 个路径" : "❌ 未发现"));
            }

            if (result.AllDiscoveredPaths.Count > 0)
            {
                FinalResultPanel.Children.Add(new TextBlock
                {
                    Text = $"所有发现的路径 ({result.AllDiscoveredPaths.Count}):",
                    FontWeight = FontWeights.Bold,
                    FontSize = 14,
                    Foreground = new SolidColorBrush(Color.FromRgb(0x2C, 0x3E, 0x50)),
                    Margin = new Thickness(0, 15, 0, 10)
                });
                foreach (var path in result.AllDiscoveredPaths)
                {
                    var color = path.PathType == "login" ? Colors.OrangeRed
                        : path.PathType == "admin" ? Colors.Purple
                        : path.PathType == "redirect" ? Colors.Blue
                        : path.PathType == "api" ? Colors.Teal
                        : Colors.Green;
                    FinalResultPanel.Children.Add(CreateResultBox($"[{path.PathType}] [{path.StatusCode}]", path.Url, color));
                }
            }
        }

        private TextBlock CreateInfoRow(string label, string value)
        {
            var tb = new TextBlock
            {
                Text = $"{label} {value}",
                TextWrapping = TextWrapping.Wrap,
                Margin = new Thickness(0, 2, 0, 2)
            };
            if (value.StartsWith("http://") || value.StartsWith("https://"))
            {
                tb.Cursor = Cursors.Hand;
                tb.Foreground = new SolidColorBrush(Color.FromRgb(0x29, 0x80, 0xB9));
                tb.MouseLeftButtonUp += (s, e) =>
                {
                    try
                    {
                        Clipboard.SetText(value);
                        var oldText = tb.Text;
                        tb.Text = $"{label} {value} [已复制!]";
                        tb.FontWeight = FontWeights.Bold;
                        Dispatcher.BeginInvoke(new Action(() =>
                        {
                            tb.Text = oldText;
                            tb.FontWeight = FontWeights.Normal;
                        }), System.Windows.Threading.DispatcherPriority.ApplicationIdle);
                    }
                    catch { }
                };
            }
            return tb;
        }

        private void ShowSecurityAuditResult(SecurityAuditResult audit)
        {
            SecurityAuditPanel.Children.Clear();

            var scoreColor = audit.OverallScore >= 80 ? Colors.Green
                : audit.OverallScore >= 60 ? Colors.Orange
                : Colors.Red;

            SecurityAuditPanel.Children.Add(new TextBlock
            {
                Text = "🔒 安全审计报告",
                FontSize = 16,
                FontWeight = FontWeights.Bold,
                Foreground = new SolidColorBrush(Color.FromRgb(0x2C, 0x3E, 0x50)),
                Margin = new Thickness(0, 0, 0, 15)
            });

            var scoreBorder = new Border
            {
                Background = new SolidColorBrush(Color.FromArgb(0x20, (byte)scoreColor.R, (byte)scoreColor.G, (byte)scoreColor.B)),
                BorderBrush = new SolidColorBrush(scoreColor),
                BorderThickness = new Thickness(2),
                CornerRadius = new CornerRadius(5),
                Padding = new Thickness(15),
                Margin = new Thickness(0, 0, 0, 15)
            };

            var scoreStack = new StackPanel { Orientation = Orientation.Horizontal };
            scoreStack.Children.Add(new TextBlock
            {
                Text = "安全得分: ",
                FontWeight = FontWeights.Bold,
                FontSize = 16
            });
            scoreStack.Children.Add(new TextBlock
            {
                Text = $"{audit.OverallScore}/100",
                FontWeight = FontWeights.Bold,
                FontSize = 20,
                Foreground = new SolidColorBrush(scoreColor)
            });
            scoreBorder.Child = scoreStack;
            SecurityAuditPanel.Children.Add(scoreBorder);

            if (audit.PassedChecks.Count > 0)
            {
                SecurityAuditPanel.Children.Add(new TextBlock
                {
                    Text = $"✅ 通过检查 ({audit.PassedChecks.Count}):",
                    FontWeight = FontWeights.Bold,
                    Foreground = Brushes.Green,
                    Margin = new Thickness(0, 10, 0, 5)
                });
                foreach (var check in audit.PassedChecks)
                {
                    SecurityAuditPanel.Children.Add(new TextBlock
                    {
                        Text = $"  {check}",
                        Foreground = Brushes.Green,
                        Margin = new Thickness(0, 2, 0, 2)
                    });
                }
            }

            if (audit.FailedChecks.Count > 0)
            {
                SecurityAuditPanel.Children.Add(new TextBlock
                {
                    Text = $"❌ 未通过检查 ({audit.FailedChecks.Count}):",
                    FontWeight = FontWeights.Bold,
                    Foreground = Brushes.Red,
                    Margin = new Thickness(0, 15, 0, 5)
                });
                foreach (var check in audit.FailedChecks)
                {
                    SecurityAuditPanel.Children.Add(new TextBlock
                    {
                        Text = $"  {check}",
                        Foreground = Brushes.Red,
                        Margin = new Thickness(0, 2, 0, 2)
                    });
                }
            }

            if (audit.Findings.Count > 0)
            {
                SecurityAuditPanel.Children.Add(new TextBlock
                {
                    Text = $"安全发现 ({audit.Findings.Count}):",
                    FontWeight = FontWeights.Bold,
                    Foreground = new SolidColorBrush(Color.FromRgb(0xE6, 0x7E, 0x22)),
                    Margin = new Thickness(0, 15, 0, 10)
                });

                foreach (var finding in audit.Findings)
                {
                    var severityColor = finding.Severity switch
                    {
                        "Critical" => Colors.Red,
                        "High" => Colors.OrangeRed,
                        "Medium" => Colors.Orange,
                        "Low" => Colors.Gray,
                        _ => Colors.Blue
                    };

                    var findingBorder = new Border
                    {
                        Background = Brushes.White,
                        BorderBrush = new SolidColorBrush(severityColor),
                        BorderThickness = new Thickness(1),
                        CornerRadius = new CornerRadius(3),
                        Padding = new Thickness(10),
                        Margin = new Thickness(0, 5, 0, 5)
                    };

                    var findingStack = new StackPanel();
                    findingStack.Children.Add(new TextBlock
                    {
                        Text = $"[{finding.Severity}] {finding.Title}",
                        FontWeight = FontWeights.Bold,
                        Foreground = new SolidColorBrush(severityColor)
                    });
                    findingStack.Children.Add(new TextBlock
                    {
                        Text = finding.Description,
                        TextWrapping = TextWrapping.Wrap,
                        Foreground = Brushes.DarkGray,
                        Margin = new Thickness(0, 3, 0, 0)
                    });
                    findingStack.Children.Add(new TextBlock
                    {
                        Text = $"建议: {finding.Recommendation}",
                        TextWrapping = TextWrapping.Wrap,
                        Foreground = Brushes.Green,
                        Margin = new Thickness(0, 5, 0, 0),
                        FontSize = 11
                    });

                    findingBorder.Child = findingStack;
                    SecurityAuditPanel.Children.Add(findingBorder);
                }
            }
        }

        private void ShowVulnerabilityInfo(List<string> techs, WebPathTracerService tracer)
        {
            VulnInfoPanel.Children.Clear();

            VulnInfoPanel.Children.Add(new TextBlock
            {
                Text = "📊 技术栈漏洞信息",
                FontSize = 16,
                FontWeight = FontWeights.Bold,
                Foreground = new SolidColorBrush(Color.FromRgb(0x2C, 0x3E, 0x50)),
                Margin = new Thickness(0, 0, 0, 15)
            });

            bool hasVulns = false;

            foreach (var tech in techs)
            {
                var vulnInfo = tracer.GetTechVulnerabilities(tech);
                if (vulnInfo.KnownVulnerabilities.Count == 0) continue;

                hasVulns = true;

                VulnInfoPanel.Children.Add(new TextBlock
                {
                    Text = $"🔧 {tech} 已知漏洞:",
                    FontWeight = FontWeights.Bold,
                    Foreground = new SolidColorBrush(Color.FromRgb(0xE7, 0x4C, 0x3C)),
                    Margin = new Thickness(0, 10, 0, 5)
                });

                foreach (var cve in vulnInfo.KnownVulnerabilities)
                {
                    var cveColor = cve.Severity switch
                    {
                        "Critical" => Colors.Red,
                        "High" => Colors.OrangeRed,
                        "Medium" => Colors.Orange,
                        _ => Colors.Gray
                    };

                    var cveBorder = new Border
                    {
                        Background = new SolidColorBrush(Color.FromArgb(0x08, (byte)cveColor.R, (byte)cveColor.G, (byte)cveColor.B)),
                        BorderBrush = new SolidColorBrush(cveColor),
                        BorderThickness = new Thickness(1),
                        CornerRadius = new CornerRadius(3),
                        Padding = new Thickness(10),
                        Margin = new Thickness(0, 3, 0, 5)
                    };

                    var cveStack = new StackPanel();
                    cveStack.Children.Add(new TextBlock
                    {
                        Text = $"{cve.CveId} [{cve.Severity}] CVSS: {cve.CvssScore:F1}",
                        FontWeight = FontWeights.Bold,
                        Foreground = new SolidColorBrush(cveColor)
                    });
                    cveStack.Children.Add(new TextBlock
                    {
                        Text = cve.Description,
                        TextWrapping = TextWrapping.Wrap,
                        Margin = new Thickness(0, 3, 0, 0)
                    });
                    if (!string.IsNullOrEmpty(cve.FixVersion))
                    {
                        cveStack.Children.Add(new TextBlock
                        {
                            Text = $"修复版本: {cve.FixVersion}",
                            Foreground = Brushes.Green,
                            Margin = new Thickness(0, 3, 0, 0),
                            FontWeight = FontWeights.Bold,
                            FontSize = 11
                        });
                    }

                    cveBorder.Child = cveStack;
                    VulnInfoPanel.Children.Add(cveBorder);
                }
            }

            if (!hasVulns)
            {
                VulnInfoPanel.Children.Add(new TextBlock
                {
                    Text = "✅ 未检测到已知漏洞",
                    Foreground = Brushes.Green,
                    FontWeight = FontWeights.Bold,
                    Margin = new Thickness(0, 20, 0, 0)
                });
            }
        }

        private void ShowSslCertificateResult(SslCertificateInfo? ssl)
        {
            SslCertificatePanel.Children.Clear();

            if (ssl == null)
            {
                SslCertificatePanel.Children.Add(new TextBlock
                {
                    Text = "⚠️ SSL证书分析失败或未执行",
                    Foreground = Brushes.Gray,
                    FontSize = 14,
                    Margin = new Thickness(0, 10, 0, 0)
                });
                return;
            }

            SslCertificatePanel.Children.Add(new TextBlock
            {
                Text = "🔐 SSL/TLS 证书分析报告",
                FontSize = 16,
                FontWeight = FontWeights.Bold,
                Foreground = new SolidColorBrush(Color.FromRgb(0x2C, 0x3E, 0x50)),
                Margin = new Thickness(0, 0, 0, 15)
            });

            var isValidColor = ssl.IsValid ? Colors.Green : Colors.Red;
            SslCertificatePanel.Children.Add(CreateInfoRow("证书状态:", ssl.IsValid ? "✅ 有效" : "❌ 无效/警告"));
            SslCertificatePanel.Children.Add(CreateInfoRow("主题:", ssl.Subject));
            SslCertificatePanel.Children.Add(CreateInfoRow("颁发者:", ssl.Issuer));
            SslCertificatePanel.Children.Add(CreateInfoRow("颁发日期:", ssl.ValidFrom ?? "未知"));
            SslCertificatePanel.Children.Add(CreateInfoRow("到期日期:", ssl.ValidTo ?? "未知"));

            if (ssl.DaysUntilExpiry.HasValue)
            {
                var expiryColor = ssl.DaysUntilExpiry.Value > 30 ? Colors.Green
                    : ssl.DaysUntilExpiry.Value > 7 ? Colors.Orange
                    : Colors.Red;
                
                var expiryBlock = new TextBlock
                {
                    Text = $"剩余天数: {ssl.DaysUntilExpiry.Value}天",
                    Foreground = new SolidColorBrush(expiryColor),
                    FontWeight = FontWeights.Bold,
                    Margin = new Thickness(0, 2, 0, 2)
                };
                SslCertificatePanel.Children.Add(expiryBlock);
            }

            SslCertificatePanel.Children.Add(CreateInfoRow("序列号:", ssl.SerialNumber ?? "未知"));
            SslCertificatePanel.Children.Add(CreateInfoRow("证书版本:", ssl.Version ?? "未知"));
            SslCertificatePanel.Children.Add(CreateInfoRow("签名算法:", ssl.SignatureAlgorithm ?? "未知"));
            SslCertificatePanel.Children.Add(CreateInfoRow("公钥算法:", ssl.PublicKeyAlgorithm ?? "未知"));

            if (ssl.KeySize.HasValue)
            {
                var keyColor = ssl.KeySize.Value >= 2048 ? Colors.Green : Colors.Red;
                SslCertificatePanel.Children.Add(new TextBlock
                {
                    Text = $"密钥长度: {ssl.KeySize.Value}位",
                    Foreground = new SolidColorBrush(keyColor),
                    Margin = new Thickness(0, 2, 0, 2)
                });
            }

            SslCertificatePanel.Children.Add(CreateInfoRow("TLS协议:", ssl.ProtocolVersion ?? "未知"));
            SslCertificatePanel.Children.Add(CreateInfoRow("加密套件:", ssl.CipherSuite ?? "未知"));
            SslCertificatePanel.Children.Add(CreateInfoRow("支持TLS 1.2:", ssl.SupportsTls12 ? "✅ 是" : "❌ 否"));
            SslCertificatePanel.Children.Add(CreateInfoRow("支持TLS 1.3:", ssl.SupportsTls13 ? "✅ 是" : "❌ 否"));

            SslCertificatePanel.Children.Add(new TextBlock
            {
                Text = $"自签名证书: {(ssl.IsSelfSigned ? "⚠️ 是（不受信任）" : "✅ 否（受信任）")}",
                Foreground = ssl.IsSelfSigned ? Brushes.Red : Brushes.Green,
                Margin = new Thickness(0, 2, 0, 2)
            });

            if (ssl.SubjectAlternativeNames.Count > 0)
            {
                SslCertificatePanel.Children.Add(new TextBlock
                {
                    Text = $"🌐 主题备用域名 ({ssl.SubjectAlternativeNames.Count}个):",
                    FontWeight = FontWeights.Bold,
                    Foreground = new SolidColorBrush(Color.FromRgb(0x2C, 0x3E, 0x50)),
                    Margin = new Thickness(0, 10, 0, 5)
                });

                foreach (var san in ssl.SubjectAlternativeNames.Take(10))
                {
                    SslCertificatePanel.Children.Add(new TextBlock
                    {
                        Text = $"  • {san}",
                        Foreground = Brushes.Gray,
                        Margin = new Thickness(0, 1, 0, 1)
                    });
                }
            }

            if (!string.IsNullOrEmpty(ssl.CrlDistributionPoints))
            {
                SslCertificatePanel.Children.Add(CreateInfoRow("CRL吊销检查:", ssl.CrlDistributionPoints));
            }

            if (!string.IsNullOrEmpty(ssl.OcspResponderUrl))
            {
                SslCertificatePanel.Children.Add(CreateInfoRow("OCSP状态:", ssl.OcspResponderUrl));
            }

            if (ssl.Warnings.Count > 0)
            {
                SslCertificatePanel.Children.Add(new TextBlock
                {
                    Text = $"⚠️ 警告信息 ({ssl.Warnings.Count}个):",
                    FontWeight = FontWeights.Bold,
                    Foreground = Brushes.Red,
                    Margin = new Thickness(0, 15, 0, 5)
                });

                foreach (var warning in ssl.Warnings)
                {
                    SslCertificatePanel.Children.Add(new TextBlock
                    {
                        Text = $"  • {warning}",
                        Foreground = Brushes.Red,
                        TextWrapping = TextWrapping.Wrap,
                        Margin = new Thickness(0, 2, 0, 2)
                    });
                }
            }
        }

        private Border CreateStatBox(string icon, string value, string label)
        {
            var border = new Border
            {
                Background = Brushes.White,
                BorderBrush = new SolidColorBrush(Color.FromRgb(0xDD, 0xDD, 0xDD)),
                BorderThickness = new Thickness(1),
                CornerRadius = new CornerRadius(4),
                Padding = new Thickness(8, 4, 8, 4),
                Margin = new Thickness(0, 0, 8, 0)
            };

            var stackPanel = new StackPanel { Orientation = Orientation.Horizontal };
            stackPanel.Children.Add(new TextBlock
            {
                Text = icon,
                FontSize = 14,
                Margin = new Thickness(0, 0, 4, 0)
            });
            stackPanel.Children.Add(new TextBlock
            {
                Text = value,
                FontWeight = FontWeights.Bold,
                Foreground = new SolidColorBrush(Color.FromRgb(0x2C, 0x3E, 0x50)),
                Margin = new Thickness(0, 0, 2, 0)
            });
            stackPanel.Children.Add(new TextBlock
            {
                Text = label,
                Foreground = Brushes.Gray,
                FontSize = 11
            });

            border.Child = stackPanel;
            return border;
        }

        private Border CreateResultBox(string label, string value, Color borderColor)
        {
            var brush = new SolidColorBrush(borderColor);
            var stackPanel = new StackPanel { Margin = new Thickness(10) };
            stackPanel.Children.Add(new TextBlock
            {
                Text = label,
                FontWeight = FontWeights.Bold,
                Foreground = brush
            });
            var valueTb = new TextBlock
            {
                Text = value,
                TextWrapping = TextWrapping.Wrap
            };
            if (value.StartsWith("http://") || value.StartsWith("https://"))
            {
                valueTb.Cursor = Cursors.Hand;
                valueTb.Foreground = new SolidColorBrush(Color.FromRgb(0x29, 0x80, 0xB9));
                valueTb.MouseLeftButtonUp += (s, e) =>
                {
                    try
                    {
                        Clipboard.SetText(value);
                        var oldText = valueTb.Text;
                        valueTb.Text = $"{value} [已复制!]";
                        valueTb.FontWeight = FontWeights.Bold;
                        Dispatcher.BeginInvoke(new Action(() =>
                        {
                            valueTb.Text = oldText;
                            valueTb.FontWeight = FontWeights.Normal;
                        }), System.Windows.Threading.DispatcherPriority.ApplicationIdle);
                    }
                    catch { }
                };
            }
            stackPanel.Children.Add(valueTb);
            return new Border
            {
                Background = Brushes.WhiteSmoke,
                BorderBrush = brush,
                BorderThickness = new Thickness(2),
                CornerRadius = new CornerRadius(5),
                Margin = new Thickness(0, 5, 0, 5),
                Child = stackPanel
            };
        }

        private Border CreateRedirectChainItem(PathStep step, int index)
        {
            var statusColor = step.StatusCode >= 300 && step.StatusCode < 400
                ? Colors.Blue
                : step.StatusCode >= 400
                    ? Colors.Red
                    : Colors.Green;
            var brush = new SolidColorBrush(statusColor);
            var stackPanel = new StackPanel { Margin = new Thickness(10) };
            stackPanel.Children.Add(new TextBlock
            {
                Text = $"步骤 {index}",
                FontWeight = FontWeights.Bold,
                Foreground = brush
            });
            stackPanel.Children.Add(new TextBlock
            {
                Text = $"URL: {step.Url}",
                TextWrapping = TextWrapping.Wrap
            });
            stackPanel.Children.Add(new TextBlock
            {
                Text = $"状态码: {step.StatusCode}"
            });
            if (step.LocationHeader != null)
            {
                stackPanel.Children.Add(new TextBlock
                {
                    Text = $"Location: {step.LocationHeader}",
                    TextWrapping = TextWrapping.Wrap,
                    Foreground = Brushes.Blue
                });
            }
            return new Border
            {
                Background = Brushes.WhiteSmoke,
                BorderBrush = brush,
                BorderThickness = new Thickness(2, 0, 0, 2),
                CornerRadius = new CornerRadius(3),
                Margin = new Thickness(20, 3, 0, 3),
                Child = stackPanel
            };
        }
    }
}
