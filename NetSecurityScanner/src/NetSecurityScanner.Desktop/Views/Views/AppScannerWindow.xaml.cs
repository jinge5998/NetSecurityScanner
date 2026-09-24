using Microsoft.Win32;
using NetSecurityScanner.Utils;
using System;
using System.Collections.ObjectModel;
using System.IO;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using NetSecurityScanner.Models;
using NetSecurityScanner.Services;

namespace NetSecurityScanner.Views
{
    public partial class AppScannerWindow : Window
    {
        private AppScannerService? _scanner;
        private CancellationTokenSource? _cts;
        private ObservableCollection<AppVulnerabilityResult> _vulnerabilities;
        private AppScanResult? _lastResult;

        public AppScannerWindow()
        {
            InitializeComponent();
            Title = $"APP安全扫描 v{VersionHelper.GetVersion()}";
            _vulnerabilities = new ObservableCollection<AppVulnerabilityResult>();
            VulnerabilityDataGrid.ItemsSource = _vulnerabilities;
        }

        private void FilePathTextBox_DragOver(object sender, DragEventArgs e)
        {
            if (e.Data.GetDataPresent(DataFormats.FileDrop))
            {
                e.Effects = DragDropEffects.Copy;
            }
        }

        private void FilePathTextBox_Drop(object sender, DragEventArgs e)
        {
            if (e.Data.GetDataPresent(DataFormats.FileDrop))
            {
                var files = (string[])e.Data.GetData(DataFormats.FileDrop);
                if (files.Length > 0)
                {
                    FilePathTextBox.Text = files[0];
                    UpdateFileInfo(files[0]);
                }
            }
        }

        private void SelectFile_Click(object sender, RoutedEventArgs e)
        {
            var dialog = new OpenFileDialog
            {
                Filter = "应用文件|*.apk;*.ipa;*.zip;*.wxapkg|Android APK|*.apk|iOS IPA|*.ipa|小程序|*.zip;*.wxapkg|所有文件|*.*",
                Title = "选择要扫描的应用文件"
            };

            if (dialog.ShowDialog() == true)
            {
                FilePathTextBox.Text = dialog.FileName;
                FilePathTextBox.Foreground = Brushes.Black;
                UpdateFileInfo(dialog.FileName);
            }
        }

        private void UpdateFileInfo(string filePath)
        {
            try
            {
                var fileInfo = new FileInfo(filePath);
                var extension = fileInfo.Extension.ToLower();

                FileTypeText.Text = extension switch
                {
                    ".apk" => "Android APK",
                    ".ipa" => "iOS IPA",
                    ".zip" or ".wxapkg" => "小程序/压缩包",
                    _ => extension.ToUpper()
                };

                FileSizeText.Text = fileInfo.Length switch
                {
                    < 1024 => $"{fileInfo.Length} B",
                    < 1024 * 1024 => $"{fileInfo.Length / 1024.0:F2} KB",
                    < 1024 * 1024 * 1024 => $"{fileInfo.Length / (1024.0 * 1024):F2} MB",
                    _ => $"{fileInfo.Length / (1024.0 * 1024 * 1024):F2} GB"
                };
            }
            catch (Exception ex)
            {
                FileTypeText.Text = "未知";
                FileSizeText.Text = "未知";
                MessageBox.Show($"读取文件信息失败: {ex.Message}", "错误", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        private async void StartScan_Click(object sender, RoutedEventArgs e)
        {
            var filePath = FilePathTextBox.Text;
            if (string.IsNullOrEmpty(filePath) || filePath == "请选择或拖拽APK/IPA/小程序文件...")
            {
                MessageBox.Show("请先选择要扫描的应用文件", "提示", MessageBoxButton.OK, MessageBoxImage.Warning);
                return;
            }

            if (!File.Exists(filePath))
            {
                MessageBox.Show("文件不存在，请重新选择", "错误", MessageBoxButton.OK, MessageBoxImage.Error);
                return;
            }

            _cts = new CancellationTokenSource();
            _scanner = new AppScannerService();
            _scanner.OnProgressChanged += OnProgressChanged;
            _scanner.OnLog += OnLog;

            _vulnerabilities.Clear();
            HighCountText.Text = "0";
            MediumCountText.Text = "0";
            LowCountText.Text = "0";

            ScanStatusText.Text = "状态: 扫描中...";
            ScanLogTextBox.AppendText($"[{DateTime.Now:HH:mm:ss}] 开始扫描: {Path.GetFileName(filePath)}\n");
            ScanProgressBar.Value = 0;
            ScanProgressText.Text = "0%";
            StartScanButton.IsEnabled = false;
            StopScanButton.IsEnabled = true;
            ExportReportButton.IsEnabled = false;

            var scanMode = GetSelectedScanMode();

            try
            {
                _lastResult = await _scanner.ScanAsync(filePath, scanMode, _cts.Token);
                DisplayResults(_lastResult);
                ScanLogTextBox.AppendText($"[{DateTime.Now:HH:mm:ss}] 扫描完成! 发现 {_lastResult.Vulnerabilities.Count} 个漏洞\n");
                ExportReportButton.IsEnabled = true;
            }
            catch (OperationCanceledException)
            {
                ScanLogTextBox.AppendText($"[{DateTime.Now:HH:mm:ss}] 扫描已取消\n");
            }
            catch (Exception ex)
            {
                ScanLogTextBox.AppendText($"[{DateTime.Now:HH:mm:ss}] 扫描失败: {ex.Message}\n");
                MessageBox.Show($"扫描失败: {ex.Message}", "错误", MessageBoxButton.OK, MessageBoxImage.Error);
            }
            finally
            {
                ScanStatusText.Text = "状态: 就绪";
                StartScanButton.IsEnabled = true;
                StopScanButton.IsEnabled = false;
                _scanner.OnProgressChanged -= OnProgressChanged;
                _scanner.OnLog -= OnLog;
            }
        }

        private void StopScan_Click(object sender, RoutedEventArgs e)
        {
            _cts?.Cancel();
            ScanStatusText.Text = "状态: 已停止";
            StartScanButton.IsEnabled = true;
            StopScanButton.IsEnabled = false;
        }

        private void OnProgressChanged(int progress, string message)
        {
            Dispatcher.Invoke(() =>
            {
                ScanProgressBar.Value = progress;
                ScanProgressText.Text = $"{progress}%";
                ScanStatusText.Text = $"状态: {message}";
            });
        }

        private void OnLog(string message)
        {
            Dispatcher.Invoke(() =>
            {
                ScanLogTextBox.AppendText($"[{DateTime.Now:HH:mm:ss}] {message}\n");
                ScanLogTextBox.ScrollToEnd();
            });
        }

        private void DisplayResults(AppScanResult result)
        {
            foreach (var vuln in result.Vulnerabilities)
            {
                _vulnerabilities.Add(vuln);
            }

            var sorted = _vulnerabilities
                .OrderBy(v => v.RiskLevel == RiskLevel.High ? 0 : v.RiskLevel == RiskLevel.Medium ? 1 : 2)
                .ToList();

            _vulnerabilities.Clear();
            foreach (var vuln in sorted)
            {
                _vulnerabilities.Add(vuln);
            }

            HighCountText.Text = result.HighRiskCount.ToString();
            MediumCountText.Text = result.MediumRiskCount.ToString();
            LowCountText.Text = result.LowRiskCount.ToString();
        }

        private ScanMode GetSelectedScanMode()
        {
            return ScanTypeComboBox.SelectedIndex switch
            {
                0 => ScanMode.Lightning,
                1 => ScanMode.Standard,
                2 => ScanMode.Deep,
                _ => ScanMode.Full
            };
        }

        private void ExportReport_Click(object sender, RoutedEventArgs e)
        {
            if (_lastResult == null || _lastResult.Vulnerabilities.Count == 0)
            {
                MessageBox.Show("没有可导出的扫描结果", "提示", MessageBoxButton.OK, MessageBoxImage.Information);
                return;
            }

            var dialog = new SaveFileDialog
            {
                Filter = "Word报告|*.docx|文本报告|*.txt|HTML报告|*.html",
                Title = "导出扫描报告",
                FileName = $"APP扫描报告_{DateTime.Now:yyyyMMdd_HHmmss}"
            };

            if (dialog.ShowDialog() == true)
            {
                try
                {
                    var extension = Path.GetExtension(dialog.FileName).ToLower();
                    ExportReport(dialog.FileName, extension);
                    ScanLogTextBox.AppendText($"[{DateTime.Now:HH:mm:ss}] 报告已导出: {dialog.FileName}\n");
                    MessageBox.Show("报告导出成功", "提示", MessageBoxButton.OK, MessageBoxImage.Information);
                }
                catch (Exception ex)
                {
                    MessageBox.Show($"导出报告失败: {ex.Message}", "错误", MessageBoxButton.OK, MessageBoxImage.Error);
                }
            }
        }

        private void ExportReport(string filePath, string extension)
        {
            if (_lastResult == null) return;

            var sb = new System.Text.StringBuilder();
            sb.AppendLine("========================================");
            sb.AppendLine("       APP安全扫描报告");
            sb.AppendLine("========================================");
            sb.AppendLine();
            sb.AppendLine($"扫描时间: {DateTime.Now:yyyy-MM-dd HH:mm:ss}");
            sb.AppendLine($"扫描文件: {_lastResult.OriginalFilePath}");
            sb.AppendLine($"文件类型: {_lastResult.AppType}");
            sb.AppendLine($"文件大小: {_lastResult.FileSize} 字节");
            sb.AppendLine($"扫描模式: {_lastResult.ScanMode}");
            sb.AppendLine();
            sb.AppendLine("----------------------------------------");
            sb.AppendLine("漏洞统计:");
            sb.AppendLine($"  高危: {_lastResult.HighRiskCount}");
            sb.AppendLine($"  中危: {_lastResult.MediumRiskCount}");
            sb.AppendLine($"  低危: {_lastResult.LowRiskCount}");
            sb.AppendLine($"  总计: {_lastResult.Vulnerabilities.Count}");
            sb.AppendLine("----------------------------------------");
            sb.AppendLine();

            foreach (var vuln in _lastResult.Vulnerabilities)
            {
                sb.AppendLine($"漏洞 #{vuln.Id}");
                sb.AppendLine($"  名称: {vuln.Name}");
                sb.AppendLine($"  风险等级: {vuln.RiskLevel}");
                sb.AppendLine($"  漏洞类型: {vuln.VulnerabilityType}");
                sb.AppendLine($"  所在文件: {vuln.Location}");
                sb.AppendLine($"  CVSS评分: {vuln.CvssScore:F1}");
                sb.AppendLine($"  漏洞描述: {vuln.Description}");
                sb.AppendLine($"  修复建议: {vuln.Suggestion}");
                sb.AppendLine();
            }

            sb.AppendLine("========================================");
            sb.AppendLine("报告生成完毕");
            sb.AppendLine("========================================");

            File.WriteAllText(filePath, sb.ToString(), System.Text.Encoding.UTF8);
        }
    }
}