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
                ChromeStatusText.Text = $"Chrome状态: \u2705 已检测到Chrome {version}";
                ChromeStatusText.Foreground = new SolidColorBrush(Color.FromRgb(0x27, 0xAE, 0x60));
            }
            else
            {
                ChromeStatusText.Text = "Chrome状态: \u274C 未检测到Chrome";
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

                Dispatcher.Invoke(() =>
                {
                    ScanProgressBar.Value = 100;

                    ShowLayer1Result(result.Layer1Results, result.RedirectChain);
                    ShowLayer2Result(result.Layer2Results);
                    ShowLayer3Result(result.Layer3Results);
                    ShowLayer4Result(result.Layer4Results);
                    ShowBruteResult(result.BruteResults);
                    ShowSuffixProbeResult(result.SuffixProbeResults);
                    ShowCrawlResult(result.CrawlResults);
                    ShowFinalResult(result);

                    PathCountText.Text = $"发现: {result.AllDiscoveredPaths.Count}条路径";
                    ElapsedTimeText.Text = $"耗时: {_stopwatch.ElapsedMilliseconds / 1000}s";

                    if (result.FoundPath)
                    {
                        StatusText.Text = "\u2705 追踪完成 - 发现路径";
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

        private void ShowLayer1Result(Layer1Result? result, List<RedirectStep> redirectChain)
        {
            Layer1Panel.Children.Clear();
            if (result == null)
            {
                Layer1Panel.Children.Add(new TextBlock { Text = "未执行", Foreground = Brushes.Gray });
                return;
            }

            if (result.Error != null)
            {
                Layer1Panel.Children.Add(CreateResultBox("\u274C HTTP请求失败", result.Error, Colors.Red));
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

            if (result.FoundUrl != null)
            {
                Layer1Panel.Children.Add(CreateResultBox("\u2705 发现跳转URL", result.FoundUrl, Colors.Green));
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
                Layer2Panel.Children.Add(CreateResultBox("\u274C HTML分析失败", result.Error, Colors.Red));
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
                    Layer2Panel.Children.Add(CreateInfoRow("  \u2192", url));
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
                    Layer2Panel.Children.Add(CreateInfoRow("  \u2192", url));
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
                    Layer2Panel.Children.Add(CreateInfoRow("  \u2192", url));
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
                    Layer2Panel.Children.Add(CreateResultBox("\U0001F517 登录链接", link, Colors.OrangeRed));
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
                    Layer3Panel.Children.Add(CreateResultBox("\U0001F4C4", url, Colors.Red));
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
                    Layer3Panel.Children.Add(CreateInfoRow("  \U0001F6AB", path));
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
                    Layer3Panel.Children.Add(CreateInfoRow("  \u2705", path));
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
                    Layer3Panel.Children.Add(CreateInfoRow("  \U0001F5FA", url));
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
                Layer4Panel.Children.Add(CreateResultBox("\u274C Selenium检测失败", result.Error, Colors.Red));
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
                Layer4Panel.Children.Add(CreateResultBox("\u2705 检测到URL变化!", result.FinalUrl ?? "", Colors.Green));

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
                    Layer4Panel.Children.Add(CreateResultBox("\U0001F4DD 表单", form, Colors.Orange));
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
                    Layer4Panel.Children.Add(CreateResultBox("\U0001F5BC iframe", iframe, Colors.Blue));
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
                    Layer4Panel.Children.Add(CreateResultBox("\U0001F517 动态链接", link, Colors.Purple));
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
                    Layer4Panel.Children.Add(CreateInfoRow("  \u2192", ajax));
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
                        BrutePanel.Children.Add(CreateInfoRow("    \u2192", $"{path.Url} ({path.PathType})"));
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

        private void ShowSuffixProbeResult(SuffixProbeResult? result)
        {
            SuffixProbePanel.Children.Clear();
            if (result == null)
            {
                SuffixProbePanel.Children.Add(new TextBlock { Text = "未执行(仅在标准/深度模式下运行)", Foreground = Brushes.Gray });
                return;
            }

            SuffixProbePanel.Children.Add(new TextBlock
            {
                Text = "后缀智能探测结果",
                FontSize = 16,
                FontWeight = FontWeights.Bold,
                Foreground = new SolidColorBrush(Color.FromRgb(0x2C, 0x3E, 0x50)),
                Margin = new Thickness(0, 0, 0, 15)
            });

            SuffixProbePanel.Children.Add(CreateInfoRow("识别技术栈:", result.DetectedTech));
            SuffixProbePanel.Children.Add(CreateInfoRow("测试后缀数:", result.ProbedSuffixes.Count.ToString()));
            SuffixProbePanel.Children.Add(CreateInfoRow("发现路径:", result.FoundPaths.Count.ToString()));

            if (result.ProbedSuffixes.Count > 0)
            {
                var suffixGroups = result.ProbedSuffixes
                    .Select(s => System.IO.Path.GetExtension(s).TrimStart('.'))
                    .Where(e => !string.IsNullOrEmpty(e))
                    .GroupBy(e => e)
                    .OrderByDescending(g => g.Count())
                    .ToList();

                SuffixProbePanel.Children.Add(new TextBlock
                {
                    Text = $"测试后缀类型 ({suffixGroups.Count}种):",
                    FontWeight = FontWeights.Bold,
                    Margin = new Thickness(0, 10, 0, 5)
                });
                foreach (var group in suffixGroups)
                {
                    SuffixProbePanel.Children.Add(CreateInfoRow($"  .{group.Key}:", $"{group.Count()} 条路径"));
                }
            }

            if (result.FoundPaths.Count > 0)
            {
                SuffixProbePanel.Children.Add(new TextBlock
                {
                    Text = "发现的路径:",
                    FontWeight = FontWeights.Bold,
                    Margin = new Thickness(0, 15, 0, 5)
                });
                foreach (var path in result.FoundPaths)
                {
                    var color = path.Confidence >= 70 ? Colors.Green
                        : path.Confidence >= 50 ? Colors.Orange
                        : Colors.Gray;
                    var confLabel = path.Confidence < 70 ? $" [置信度:{path.Confidence}%]" : "";
                    var titleInfo = !string.IsNullOrEmpty(path.Title) ? $" \"{path.Title}\"" : "";
                    SuffixProbePanel.Children.Add(CreateResultBox($"[{path.StatusCode}] {path.PathType}{confLabel}", $"{path.Url}{titleInfo}", color));
                }
            }
            else
            {
                SuffixProbePanel.Children.Add(new TextBlock
                {
                    Text = "未发现有效后缀路径",
                    Foreground = Brushes.Gray,
                    Margin = new Thickness(0, 10, 0, 0)
                });
            }
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
                    CrawlPanel.Children.Add(CreateInfoRow("  \U0001F577", url));
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
                var techDetails = new List<string>();
                if (!string.IsNullOrEmpty(tech.BackendLanguage)) techDetails.Add($"语言:{tech.BackendLanguage}");
                if (!string.IsNullOrEmpty(tech.Framework)) techDetails.Add($"框架:{tech.Framework}");
                if (!string.IsNullOrEmpty(tech.Cms)) techDetails.Add($"CMS:{tech.Cms}");
                if (!string.IsNullOrEmpty(tech.Server)) techDetails.Add($"服务器:{tech.Server}");
                if (techDetails.Count > 0)
                {
                    FinalResultPanel.Children.Add(new TextBlock
                    {
                        Text = $"  {string.Join(" | ", techDetails)}",
                        TextWrapping = TextWrapping.Wrap,
                        Foreground = new SolidColorBrush(Color.FromRgb(0x8E, 0x44, 0xAD)),
                        Margin = new Thickness(0, 0, 0, 5)
                    });
                }
            }

            if (result.Layer1Results?.SetCookies.Count > 0)
            {
                var cookies = result.Layer1Results.SetCookies;
                var insecureCookies = cookies.Count(c => !c.Secure || !c.HttpOnly);
                var cookieColor = insecureCookies > 0 ? Colors.OrangeRed : Colors.Green;
                FinalResultPanel.Children.Add(new TextBlock
                {
                    Text = $"🍪 Cookie安全: {cookies.Count}个Cookie, {insecureCookies}个缺少Secure/HttpOnly标志",
                    TextWrapping = TextWrapping.Wrap,
                    FontWeight = FontWeights.Bold,
                    Foreground = new SolidColorBrush(cookieColor),
                    Margin = new Thickness(0, 5, 0, 5)
                });
            }

            if (result.Layer1Results?.OpenRedirects.Count > 0)
            {
                var vulnCount = result.Layer1Results.OpenRedirects.Count(o => o.IsVulnerable);
                if (vulnCount > 0)
                {
                    FinalResultPanel.Children.Add(new TextBlock
                    {
                        Text = $"⚠️ 开放重定向漏洞: 发现 {vulnCount} 个可利用参数!",
                        TextWrapping = TextWrapping.Wrap,
                        FontWeight = FontWeights.Bold,
                        Foreground = Brushes.Red,
                        Margin = new Thickness(0, 5, 0, 5)
                    });
                    foreach (var or in result.Layer1Results.OpenRedirects.Where(o => o.IsVulnerable))
                    {
                        FinalResultPanel.Children.Add(CreateInfoRow("  参数:", $"{or.Parameter} → {or.RedirectedTo}"));
                    }
                }
            }

            if (result.Layer1Results?.WafInfo != null && result.Layer1Results.WafInfo.IsBehindWaf)
            {
                FinalResultPanel.Children.Add(new TextBlock
                {
                    Text = $"🛡️ WAF/防火墙: {result.Layer1Results.WafInfo.WafName}",
                    TextWrapping = TextWrapping.Wrap,
                    FontWeight = FontWeights.Bold,
                    Foreground = new SolidColorBrush(Color.FromRgb(0xE6, 0x7E, 0x22)),
                    Margin = new Thickness(0, 5, 0, 5)
                });
            }

            if (result.Layer1Results?.DiscoveredApis.Count > 0)
            {
                FinalResultPanel.Children.Add(new TextBlock
                {
                    Text = $"🔗 API端点: {result.Layer1Results.DiscoveredApis.Count}个",
                    TextWrapping = TextWrapping.Wrap,
                    FontWeight = FontWeights.Bold,
                    Foreground = new SolidColorBrush(Color.FromRgb(0x1A, 0x7A, 0x9C)),
                    Margin = new Thickness(0, 5, 0, 5)
                });
                foreach (var api in result.Layer1Results.DiscoveredApis.Take(5))
                {
                    FinalResultPanel.Children.Add(CreateInfoRow("  →", $"[{api.Type}] {api.Url}"));
                }
            }

            if (result.Layer1Results?.DiscoveredSubdomains.Count > 0)
            {
                FinalResultPanel.Children.Add(new TextBlock
                {
                    Text = $"🌐 子域名: {result.Layer1Results.DiscoveredSubdomains.Count}个",
                    TextWrapping = TextWrapping.Wrap,
                    FontWeight = FontWeights.Bold,
                    Foreground = new SolidColorBrush(Color.FromRgb(0x2E, 0x86, 0xAB)),
                    Margin = new Thickness(0, 5, 0, 5)
                });
                foreach (var sub in result.Layer1Results.DiscoveredSubdomains.Take(5))
                {
                    FinalResultPanel.Children.Add(CreateInfoRow("  →", sub));
                }
            }

            if (result.Layer1Results?.ParamVulnerabilityHints.Count > 0)
            {
                FinalResultPanel.Children.Add(new TextBlock
                {
                    Text = $"⚠️ 参数漏洞风险: {result.Layer1Results.ParamVulnerabilityHints.Count}个提示",
                    TextWrapping = TextWrapping.Wrap,
                    FontWeight = FontWeights.Bold,
                    Foreground = new SolidColorBrush(Colors.OrangeRed),
                    Margin = new Thickness(0, 5, 0, 5)
                });
                foreach (var hint in result.Layer1Results.ParamVulnerabilityHints.Take(3))
                {
                    FinalResultPanel.Children.Add(CreateInfoRow("  →", hint));
                }
            }

            if (result.SuffixProbeResults != null)
            {
                FinalResultPanel.Children.Add(CreateInfoRow("后缀探测:",
                    result.SuffixProbeResults.FoundPaths.Count > 0
                        ? $"技术栈={result.SuffixProbeResults.DetectedTech}, 发现 {result.SuffixProbeResults.FoundPaths.Count} 条路径"
                        : $"技术栈={result.SuffixProbeResults.DetectedTech}, 未发现"));
            }

            if (result.FinalUrl != null)
            {
                FinalResultPanel.Children.Add(CreateResultBox("最终路径:", result.FinalUrl, Colors.Green));
            }

            if (result.TraceChain.Count > 0)
            {
                FinalResultPanel.Children.Add(new TextBlock
                {
                    Text = $"🔗 逐层追踪链 ({result.TraceChain.Count} 步):",
                    FontWeight = FontWeights.Bold,
                    FontSize = 14,
                    Foreground = new SolidColorBrush(Color.FromRgb(0x2C, 0x3E, 0x50)),
                    Margin = new Thickness(0, 15, 0, 10)
                });

                var chainBorder = new Border
                {
                    Background = Brushes.WhiteSmoke,
                    BorderBrush = new SolidColorBrush(Color.FromRgb(0x2C, 0x3E, 0x50)),
                    BorderThickness = new Thickness(2),
                    CornerRadius = new CornerRadius(5),
                    Padding = new Thickness(15),
                    Margin = new Thickness(0, 0, 0, 15)
                };
                var chainPanel = new StackPanel();

                chainPanel.Children.Add(new TextBlock
                {
                    Text = $"  起点: {result.OriginalUrl}",
                    FontFamily = new FontFamily("Consolas"),
                    FontSize = 12,
                    Foreground = Brushes.Gray,
                    Margin = new Thickness(0, 0, 0, 5)
                });

                for (int i = 0; i < result.TraceChain.Count; i++)
                {
                    var step = result.TraceChain[i];
                    var layerColors = new Dictionary<int, Color>
                    {
                        [1] = Colors.Blue,
                        [2] = Colors.Orange,
                        [3] = Colors.Purple,
                        [4] = Colors.Teal
                    };
                    var color = layerColors.TryGetValue(step.Layer, out var c) ? c : Colors.Gray;

                    chainPanel.Children.Add(new TextBlock
                    {
                        Text = $"  ↓ [{step.Layer}层-{step.Method}]",
                        FontFamily = new FontFamily("Consolas"),
                        FontSize = 12,
                        Foreground = new SolidColorBrush(color),
                        FontWeight = FontWeights.Bold,
                        Margin = new Thickness(0, 2, 0, 0)
                    });
                    chainPanel.Children.Add(new TextBlock
                    {
                        Text = $"    → {step.ToUrl}",
                        FontFamily = new FontFamily("Consolas"),
                        FontSize = 12,
                        TextWrapping = TextWrapping.Wrap,
                        Margin = new Thickness(0, 0, 0, 3)
                    });
                }

                chainPanel.Children.Add(new TextBlock
                {
                    Text = $"  终点: {result.FinalUrl ?? "未找到"}",
                    FontFamily = new FontFamily("Consolas"),
                    FontSize = 12,
                    FontWeight = FontWeights.Bold,
                    Foreground = result.FinalUrl != null ? Brushes.Green : Brushes.Red,
                    Margin = new Thickness(0, 5, 0, 0)
                });

                chainBorder.Child = chainPanel;
                FinalResultPanel.Children.Add(chainBorder);
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

            if (result.Layer1Results?.OpenRedirects.Count > 0)
            {
                var vulnCount = result.Layer1Results.OpenRedirects.Count(o => o.IsVulnerable);
                FinalResultPanel.Children.Add(CreateInfoRow("  开放重定向:", vulnCount > 0 ? $"⚠️ 发现 {vulnCount} 个漏洞" : "安全"));
            }

            FinalResultPanel.Children.Add(CreateInfoRow("第二层(HTML/JS):",
                result.Layer2Results?.FoundUrl != null ? $"✅ 发现 → {result.Layer2Results.FoundUrl}" : "❌ 未发现"));

            if (result.Layer2Results?.AllLinks.Count > 0)
            {
                var linkCats = result.Layer2Results.AllLinks.GroupBy(l => l.Category).Select(g => $"{g.Key}={g.Count()}");
                FinalResultPanel.Children.Add(CreateInfoRow("  链接分类:", string.Join(", ", linkCats)));
            }

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

            var exportPanel = new StackPanel { Orientation = Orientation.Horizontal, Margin = new Thickness(0, 20, 0, 0) };

            var exportJsonBtn = new Button
            {
                Content = "\U0001F4C4 导出JSON",
                Padding = new Thickness(15, 8, 15, 8),
                Margin = new Thickness(0, 0, 15, 0),
                Background = new SolidColorBrush(Color.FromRgb(0x27, 0xAE, 0x60)),
                Foreground = Brushes.White,
                FontWeight = FontWeights.Bold
            };
            exportJsonBtn.Click += ExportJson_Click;
            exportPanel.Children.Add(exportJsonBtn);

            var exportTxtBtn = new Button
            {
                Content = "\U0001F4DD 导出TXT",
                Padding = new Thickness(15, 8, 15, 8),
                Margin = new Thickness(0, 0, 15, 0),
                Background = new SolidColorBrush(Color.FromRgb(0x29, 0x80, 0xB9)),
                Foreground = Brushes.White,
                FontWeight = FontWeights.Bold
            };
            exportTxtBtn.Click += ExportTxt_Click;
            exportPanel.Children.Add(exportTxtBtn);

            var exportHtmlBtn = new Button
            {
                Content = "\U0001F310 导出HTML",
                Padding = new Thickness(15, 8, 15, 8),
                Background = new SolidColorBrush(Color.FromRgb(0x8E, 0x44, 0xAD)),
                Foreground = Brushes.White,
                FontWeight = FontWeights.Bold
            };
            exportHtmlBtn.Click += ExportHtml_Click;
            exportPanel.Children.Add(exportHtmlBtn);

            FinalResultPanel.Children.Add(exportPanel);
        }

        private void ExportJson_Click(object sender, RoutedEventArgs e)
        {
            if (_lastResult == null) return;
            var dlg = new SaveFileDialog
            {
                Filter = "JSON文件|*.json",
                FileName = $"WebPathTrace_{DateTime.Now:yyyyMMdd_HHmmss}.json"
            };
            if (dlg.ShowDialog() == true)
            {
                var json = JsonConvert.SerializeObject(_lastResult, Formatting.Indented);
                File.WriteAllText(dlg.FileName, json);
                MessageBox.Show($"已导出到: {dlg.FileName}", "导出成功", MessageBoxButton.OK, MessageBoxImage.Information);
            }
        }

        private void ExportTxt_Click(object sender, RoutedEventArgs e)
        {
            if (_lastResult == null) return;
            var dlg = new SaveFileDialog
            {
                Filter = "文本文件|*.txt",
                FileName = $"WebPathTrace_{DateTime.Now:yyyyMMdd_HHmmss}.txt"
            };
            if (dlg.ShowDialog() == true)
            {
                var sb = new StringBuilder();
                sb.AppendLine($"网页路径追踪报告 - {DateTime.Now:yyyy-MM-dd HH:mm:ss}");
                sb.AppendLine(new string('=', 60));
                sb.AppendLine($"目标URL: {_lastResult.OriginalUrl}");
                sb.AppendLine($"追踪模式: {_lastResult.Mode}");
                sb.AppendLine($"最终URL: {_lastResult.FinalUrl ?? "未发现"}");
                sb.AppendLine();
                sb.AppendLine($"所有发现路径 ({_lastResult.AllDiscoveredPaths.Count}):");
                sb.AppendLine(new string('-', 40));
                foreach (var path in _lastResult.AllDiscoveredPaths)
                {
                    sb.AppendLine($"  [{path.PathType}] [{path.StatusCode}] {path.Url} (来源: {path.Source})");
                }

                if (_lastResult.Layer1Results != null)
                {
                    sb.AppendLine();
                    sb.AppendLine("第一层 - HTTP重定向:");
                    sb.AppendLine(new string('-', 40));
                    sb.AppendLine($"  状态码: {_lastResult.Layer1Results.StatusCode}");
                    sb.AppendLine($"  发现URL: {_lastResult.Layer1Results.FoundUrl ?? "无"}");
                    foreach (var step in _lastResult.Layer1Results.RedirectChain)
                    {
                        sb.AppendLine($"  \u2192 [{step.StatusCode}] {step.Url}");
                    }
                }

                if (_lastResult.Layer2Results != null)
                {
                    sb.AppendLine();
                    sb.AppendLine("第二层 - HTML/JS分析:");
                    sb.AppendLine(new string('-', 40));
                    sb.AppendLine($"  Meta Refresh: {_lastResult.Layer2Results.MetaRefreshUrl ?? "无"}");
                    sb.AppendLine($"  JS跳转: {_lastResult.Layer2Results.JsRedirectUrl ?? "无"}");
                    sb.AppendLine($"  发现URL: {_lastResult.Layer2Results.FoundUrl ?? "无"}");
                    foreach (var link in _lastResult.Layer2Results.FoundLoginLinks)
                    {
                        sb.AppendLine($"  登录链接: {link}");
                    }
                    foreach (var url in _lastResult.Layer2Results.JsRedirectUrls)
                    {
                        sb.AppendLine($"  JS跳转URL: {url}");
                    }
                    foreach (var url in _lastResult.Layer2Results.SpaRouteUrls)
                    {
                        sb.AppendLine($"  SPA路由: {url}");
                    }
                }

                if (_lastResult.Layer3Results != null)
                {
                    sb.AppendLine();
                    sb.AppendLine("第三层 - 敏感文件:");
                    sb.AppendLine(new string('-', 40));
                    foreach (var url in _lastResult.Layer3Results.FoundUrls)
                    {
                        sb.AppendLine($"  文件: {url}");
                    }
                    foreach (var path in _lastResult.Layer3Results.DisallowPaths)
                    {
                        sb.AppendLine($"  Disallow: {path}");
                    }
                    foreach (var path in _lastResult.Layer3Results.AllowPaths)
                    {
                        sb.AppendLine($"  Allow: {path}");
                    }
                }

                if (_lastResult.Layer4Results != null)
                {
                    sb.AppendLine();
                    sb.AppendLine("第四层 - Selenium动态:");
                    sb.AppendLine(new string('-', 40));
                    sb.AppendLine($"  初始URL: {_lastResult.Layer4Results.InitialUrl}");
                    sb.AppendLine($"  最终URL: {_lastResult.Layer4Results.FinalUrl ?? "无变化"}");
                    sb.AppendLine($"  URL变化: {_lastResult.Layer4Results.UrlChanged}");
                    foreach (var form in _lastResult.Layer4Results.FoundForms)
                    {
                        sb.AppendLine($"  表单: {form}");
                    }
                    foreach (var link in _lastResult.Layer4Results.FoundDynamicLinks)
                    {
                        sb.AppendLine($"  动态链接: {link}");
                    }
                }

                if (_lastResult.BruteResults != null)
                {
                    sb.AppendLine();
                    sb.AppendLine("目录爆破:");
                    sb.AppendLine(new string('-', 40));
                    sb.AppendLine($"  测试总数: {_lastResult.BruteResults.TotalTested}");
                    foreach (var path in _lastResult.BruteResults.FoundPaths)
                    {
                        sb.AppendLine($"  [{path.StatusCode}] {path.Url}");
                    }
                }

                if (_lastResult.CrawlResults != null)
                {
                    sb.AppendLine();
                    sb.AppendLine("深度爬取:");
                    sb.AppendLine(new string('-', 40));
                    sb.AppendLine($"  爬取页面数: {_lastResult.CrawlResults.TotalCrawled}");
                    sb.AppendLine($"  最大深度: {_lastResult.CrawlResults.MaxDepth}");
                    foreach (var path in _lastResult.CrawlResults.FoundPaths)
                    {
                        sb.AppendLine($"  [{path.StatusCode}] {path.Url}");
                    }
                }

                File.WriteAllText(dlg.FileName, sb.ToString());
                MessageBox.Show($"已导出到: {dlg.FileName}", "导出成功", MessageBoxButton.OK, MessageBoxImage.Information);
            }
        }

        private void ExportHtml_Click(object sender, RoutedEventArgs e)
        {
            if (_lastResult == null) return;
            var dlg = new SaveFileDialog
            {
                Filter = "HTML文件|*.html",
                FileName = $"WebPathTrace_{DateTime.Now:yyyyMMdd_HHmmss}.html"
            };
            if (dlg.ShowDialog() == true)
            {
                var html = GenerateHtmlReport(_lastResult);
                File.WriteAllText(dlg.FileName, html, Encoding.UTF8);
                MessageBox.Show($"已导出到: {dlg.FileName}", "导出成功", MessageBoxButton.OK, MessageBoxImage.Information);
            }
        }

        private static string GenerateHtmlReport(WebPathTraceResult result)
        {
            var sb = new StringBuilder();
            sb.AppendLine("<!DOCTYPE html>");
            sb.AppendLine("<html lang='zh-CN'><head>");
            sb.AppendLine("<meta charset='UTF-8'>");
            sb.AppendLine("<meta name='viewport' content='width=device-width, initial-scale=1.0'>");
            sb.AppendLine($"<title>网页路径追踪报告 - {result.OriginalUrl}</title>");
            sb.AppendLine("<style>");
            sb.AppendLine("body{font-family:'Segoe UI',Tahoma,Geneva,Verdana,sans-serif;margin:0;padding:20px;background:#f5f6fa;color:#2c3e50;}");
            sb.AppendLine(".container{max-width:1100px;margin:0 auto;}");
            sb.AppendLine("h1{color:#2c3e50;border-bottom:3px solid #3498db;padding-bottom:10px;}");
            sb.AppendLine("h2{color:#2980b9;margin-top:30px;border-left:4px solid #3498db;padding-left:10px;}");
            sb.AppendLine("h3{color:#27ae60;margin-top:20px;}");
            sb.AppendLine(".summary{background:#fff;border-radius:8px;padding:20px;margin:15px 0;box-shadow:0 2px 8px rgba(0,0,0,0.1);}");
            sb.AppendLine(".path-item{background:#fff;border-radius:6px;padding:12px 16px;margin:8px 0;border-left:4px solid #3498db;box-shadow:0 1px 4px rgba(0,0,0,0.08);}");
            sb.AppendLine(".path-item.login{border-left-color:#e74c3c;}");
            sb.AppendLine(".path-item.admin{border-left-color:#9b59b6;}");
            sb.AppendLine(".path-item.redirect{border-left-color:#3498db;}");
            sb.AppendLine(".path-item.api{border-left-color:#1abc9c;}");
            sb.AppendLine(".path-item.file{border-left-color:#f39c12;}");
            sb.AppendLine(".badge{display:inline-block;padding:2px 8px;border-radius:12px;font-size:12px;font-weight:bold;color:#fff;margin-right:6px;}");
            sb.AppendLine(".badge-login{background:#e74c3c;}.badge-admin{background:#9b59b6;}.badge-redirect{background:#3498db;}.badge-api{background:#1abc9c;}.badge-file{background:#f39c12;}");
            sb.AppendLine(".chain-step{background:#ecf0f1;padding:10px 15px;margin:5px 0;border-radius:4px;font-family:Consolas,monospace;font-size:13px;}");
            sb.AppendLine(".chain-arrow{text-align:center;color:#7f8c8d;font-size:18px;margin:3px 0;}");
            sb.AppendLine("a{color:#2980b9;text-decoration:none;}a:hover{text-decoration:underline;}");
            sb.AppendLine(".status-ok{color:#27ae60;}.status-err{color:#e74c3c;}.status-warn{color:#f39c12;}");
            sb.AppendLine("table{width:100%;border-collapse:collapse;margin:10px 0;}");
            sb.AppendLine("th,td{padding:8px 12px;text-align:left;border-bottom:1px solid #ddd;}");
            sb.AppendLine("th{background:#3498db;color:#fff;}");
            sb.AppendLine("tr:hover{background:#f1f2f6;}");
            sb.AppendLine("</style></head><body>");
            sb.AppendLine("<div class='container'>");

            sb.AppendLine($"<h1>🔍 网页路径追踪报告</h1>");
            sb.AppendLine("<div class='summary'>");
            sb.AppendLine($"<p><strong>目标URL:</strong> <a href='{EscapeHtml(result.OriginalUrl)}'>{EscapeHtml(result.OriginalUrl)}</a></p>");
            sb.AppendLine($"<p><strong>追踪模式:</strong> {result.Mode}</p>");
            sb.AppendLine($"<p><strong>最终URL:</strong> {(result.FinalUrl != null ? $"<a href='{EscapeHtml(result.FinalUrl)}'>{EscapeHtml(result.FinalUrl)}</a>" : "未发现")}</p>");
            sb.AppendLine($"<p><strong>发现路径:</strong> {result.AllDiscoveredPaths.Count} 条</p>");
            sb.AppendLine($"<p><strong>追踪结果:</strong> <span class='{(result.FoundPath ? "status-ok" : "status-err")}'>{(result.FoundPath ? "✅ 发现路径" : "❌ 未发现路径")}</span></p>");
            sb.AppendLine("</div>");

            if (result.TraceChain.Count > 0)
            {
                sb.AppendLine("<h2>🔗 逐层追踪链</h2>");
                sb.AppendLine($"<div class='chain-step'>起点: <a href='{EscapeHtml(result.OriginalUrl)}'>{EscapeHtml(result.OriginalUrl)}</a></div>");
                foreach (var step in result.TraceChain)
                {
                    sb.AppendLine("<div class='chain-arrow'>↓</div>");
                    sb.AppendLine($"<div class='chain-step'>[第{step.Layer}层-{EscapeHtml(step.Method)}] → <a href='{EscapeHtml(step.ToUrl)}'>{EscapeHtml(step.ToUrl)}</a></div>");
                }
                if (result.FinalUrl != null)
                {
                    sb.AppendLine("<div class='chain-arrow'>↓</div>");
                    sb.AppendLine($"<div class='chain-step'><strong>终点: <a href='{EscapeHtml(result.FinalUrl)}'>{EscapeHtml(result.FinalUrl)}</a></strong></div>");
                }
            }

            if (result.AllDiscoveredPaths.Count > 0)
            {
                sb.AppendLine("<h2>📋 所有发现的路径</h2>");
                sb.AppendLine("<table><tr><th>类型</th><th>状态码</th><th>URL</th><th>来源</th></tr>");
                foreach (var path in result.AllDiscoveredPaths)
                {
                    sb.AppendLine($"<tr><td><span class='badge badge-{path.PathType}'>{EscapeHtml(path.PathType)}</span></td><td>{path.StatusCode}</td><td><a href='{EscapeHtml(path.Url)}'>{EscapeHtml(path.Url)}</a></td><td>{EscapeHtml(path.Source)}</td></tr>");
                }
                sb.AppendLine("</table>");
            }

            if (result.Layer1Results != null)
            {
                sb.AppendLine("<h2>1️⃣ 第一层 - HTTP重定向</h2>");
                sb.AppendLine("<div class='summary'>");
                sb.AppendLine($"<p><strong>状态码:</strong> {result.Layer1Results.StatusCode}</p>");
                if (result.Layer1Results.FoundUrl != null)
                    sb.AppendLine($"<p><strong>发现URL:</strong> <a href='{EscapeHtml(result.Layer1Results.FoundUrl)}'>{EscapeHtml(result.Layer1Results.FoundUrl)}</a></p>");
                if (result.Layer1Results.RedirectChain.Count > 0)
                {
                    sb.AppendLine("<h3>重定向链</h3>");
                    foreach (var step in result.Layer1Results.RedirectChain)
                    {
                        sb.AppendLine($"<div class='chain-step'>[{step.StatusCode}] <a href='{EscapeHtml(step.Url)}'>{EscapeHtml(step.Url)}</a>{(step.LocationHeader != null ? $" → Location: {EscapeHtml(step.LocationHeader)}" : "")}</div>");
                    }
                }
                sb.AppendLine("</div>");
            }

            if (result.Layer2Results != null)
            {
                sb.AppendLine("<h2>2️⃣ 第二层 - HTML/JS分析</h2>");
                sb.AppendLine("<div class='summary'>");
                if (result.Layer2Results.MetaRefreshUrl != null)
                    sb.AppendLine($"<p><strong>Meta Refresh:</strong> <a href='{EscapeHtml(result.Layer2Results.MetaRefreshUrl)}'>{EscapeHtml(result.Layer2Results.MetaRefreshUrl)}</a></p>");
                if (result.Layer2Results.JsRedirectUrl != null)
                    sb.AppendLine($"<p><strong>JS跳转:</strong> <a href='{EscapeHtml(result.Layer2Results.JsRedirectUrl)}'>{EscapeHtml(result.Layer2Results.JsRedirectUrl)}</a></p>");
                if (result.Layer2Results.JsRedirectUrls.Count > 0)
                {
                    sb.AppendLine("<h3>JS跳转URL</h3>");
                    foreach (var url in result.Layer2Results.JsRedirectUrls)
                        sb.AppendLine($"<div class='path-item redirect'><a href='{EscapeHtml(url)}'>{EscapeHtml(url)}</a></div>");
                }
                if (result.Layer2Results.SpaRouteUrls.Count > 0)
                {
                    sb.AppendLine("<h3>SPA路由</h3>");
                    foreach (var url in result.Layer2Results.SpaRouteUrls)
                        sb.AppendLine($"<div class='path-item redirect'><a href='{EscapeHtml(url)}'>{EscapeHtml(url)}</a></div>");
                }
                if (result.Layer2Results.FoundLoginLinks.Count > 0)
                {
                    sb.AppendLine("<h3>登录链接</h3>");
                    foreach (var link in result.Layer2Results.FoundLoginLinks)
                        sb.AppendLine($"<div class='path-item login'><a href='{EscapeHtml(link)}'>{EscapeHtml(link)}</a></div>");
                }
                sb.AppendLine("</div>");
            }

            if (result.Layer3Results != null)
            {
                sb.AppendLine("<h2>3️⃣ 第三层 - 敏感文件</h2>");
                sb.AppendLine("<div class='summary'>");
                if (result.Layer3Results.FoundUrls.Count > 0)
                {
                    sb.AppendLine("<h3>发现的敏感文件</h3>");
                    foreach (var url in result.Layer3Results.FoundUrls)
                        sb.AppendLine($"<div class='path-item file'><a href='{EscapeHtml(url)}'>{EscapeHtml(url)}</a></div>");
                }
                if (result.Layer3Results.DisallowPaths.Count > 0)
                {
                    sb.AppendLine("<h3>robots.txt Disallow</h3>");
                    foreach (var path in result.Layer3Results.DisallowPaths)
                        sb.AppendLine($"<div class='path-item'>{EscapeHtml(path)}</div>");
                }
                sb.AppendLine("</div>");
            }

            if (result.Layer4Results != null)
            {
                sb.AppendLine("<h2>4️⃣ 第四层 - Selenium动态</h2>");
                sb.AppendLine("<div class='summary'>");
                sb.AppendLine($"<p><strong>初始URL:</strong> <a href='{EscapeHtml(result.Layer4Results.InitialUrl)}'>{EscapeHtml(result.Layer4Results.InitialUrl)}</a></p>");
                sb.AppendLine($"<p><strong>最终URL:</strong> {(result.Layer4Results.FinalUrl != null ? $"<a href='{EscapeHtml(result.Layer4Results.FinalUrl)}'>{EscapeHtml(result.Layer4Results.FinalUrl)}</a>" : "无变化")}</p>");
                sb.AppendLine($"<p><strong>URL变化:</strong> <span class='{(result.Layer4Results.UrlChanged ? "status-ok" : "status-warn")}'>{(result.Layer4Results.UrlChanged ? "是" : "否")}</span></p>");
                if (result.Layer4Results.FoundForms.Count > 0)
                {
                    sb.AppendLine("<h3>表单</h3>");
                    foreach (var form in result.Layer4Results.FoundForms)
                        sb.AppendLine($"<div class='path-item'>{EscapeHtml(form)}</div>");
                }
                if (result.Layer4Results.FoundDynamicLinks.Count > 0)
                {
                    sb.AppendLine("<h3>动态链接</h3>");
                    foreach (var link in result.Layer4Results.FoundDynamicLinks)
                        sb.AppendLine($"<div class='path-item login'><a href='{EscapeHtml(link)}'>{EscapeHtml(link)}</a></div>");
                }
                sb.AppendLine("</div>");
            }

            if (result.BruteResults != null)
            {
                sb.AppendLine("<h2>5️⃣ 目录爆破</h2>");
                sb.AppendLine("<div class='summary'>");
                sb.AppendLine($"<p><strong>测试总数:</strong> {result.BruteResults.TotalTested}</p>");
                sb.AppendLine($"<p><strong>发现路径:</strong> {result.BruteResults.FoundPaths.Count}</p>");
                if (result.BruteResults.FoundPaths.Count > 0)
                {
                    sb.AppendLine("<table><tr><th>状态码</th><th>类型</th><th>URL</th></tr>");
                    foreach (var path in result.BruteResults.FoundPaths)
                        sb.AppendLine($"<tr><td>{path.StatusCode}</td><td><span class='badge badge-{path.PathType}'>{EscapeHtml(path.PathType)}</span></td><td><a href='{EscapeHtml(path.Url)}'>{EscapeHtml(path.Url)}</a></td></tr>");
                    sb.AppendLine("</table>");
                }
                sb.AppendLine("</div>");
            }

            if (result.CrawlResults != null)
            {
                sb.AppendLine("<h2>6️⃣ 深度爬取</h2>");
                sb.AppendLine("<div class='summary'>");
                sb.AppendLine($"<p><strong>爬取页面数:</strong> {result.CrawlResults.TotalCrawled}</p>");
                sb.AppendLine($"<p><strong>最大深度:</strong> {result.CrawlResults.MaxDepth}</p>");
                sb.AppendLine($"<p><strong>发现路径:</strong> {result.CrawlResults.FoundPaths.Count}</p>");
                if (result.CrawlResults.FoundPaths.Count > 0)
                {
                    sb.AppendLine("<table><tr><th>状态码</th><th>类型</th><th>URL</th></tr>");
                    foreach (var path in result.CrawlResults.FoundPaths)
                        sb.AppendLine($"<tr><td>{path.StatusCode}</td><td><span class='badge badge-{path.PathType}'>{EscapeHtml(path.PathType)}</span></td><td><a href='{EscapeHtml(path.Url)}'>{EscapeHtml(path.Url)}</a></td></tr>");
                    sb.AppendLine("</table>");
                }
                sb.AppendLine("</div>");
            }

            sb.AppendLine($"<p style='text-align:center;color:#7f8c8d;margin-top:40px;'>生成时间: {DateTime.Now:yyyy-MM-dd HH:mm:ss}</p>");
            sb.AppendLine("</div></body></html>");
            return sb.ToString();
        }

        private static string EscapeHtml(string text)
        {
            if (string.IsNullOrEmpty(text)) return text;
            return text.Replace("&", "&amp;").Replace("<", "&lt;").Replace(">", "&gt;").Replace("\"", "&quot;").Replace("'", "&#39;");
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

        private Border CreateRedirectChainItem(RedirectStep step, int index)
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
