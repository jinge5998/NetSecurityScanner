using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Windows;
using Microsoft.Win32;
using NetSecurityScanner.LicenseGenerator.Models;
using NetSecurityScanner.LicenseGenerator.Services;

namespace NetSecurityScanner.LicenseGenerator
{
    public partial class MainWindow : Window
    {
        private readonly LicenseRecordService _recordService;
        private List<LicenseRecord> _currentRecords;

        public MainWindow()
        {
            InitializeComponent();
            _recordService = new LicenseRecordService();
            _currentRecords = new List<LicenseRecord>();
        }

        private void GenerateButton_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                var selectedItem = LicenseTypeComboBox.SelectedItem as System.Windows.Controls.ComboBoxItem;
                if (selectedItem == null) return;

                string licenseType = selectedItem.Tag?.ToString() ?? "TRIAL";
                string machineId = MachineIdTextBox.Text.Trim();
                if (string.IsNullOrWhiteSpace(machineId))
                {
                    MessageBox.Show("请输入机器码（必须绑定机器）", "提示", MessageBoxButton.OK, MessageBoxImage.Warning);
                    return;
                }

                if (!int.TryParse(CountTextBox.Text.Trim(), out int count) || count < 1 || count > 100)
                {
                    MessageBox.Show("生成数量必须为1-100之间的整数", "提示", MessageBoxButton.OK, MessageBoxImage.Warning);
                    return;
                }

                var sb = new StringBuilder();
                var records = new List<LicenseRecord>();

                for (int i = 0; i < count; i++)
                {
                    string code = LicenseGeneratorService.GenerateLicenseCode(licenseType, machineId);
                    DateTime issuedTime = DateTime.Now;
                    DateTime? expiryTime = CalculateExpiryTime(licenseType, issuedTime);

                    sb.AppendLine($"--- 授权码 #{i + 1} ---");
                    sb.AppendLine(code);
                    sb.AppendLine();

                    records.Add(new LicenseRecord
                    {
                        LicenseCode = code,
                        LicenseType = licenseType,
                        MachineId = machineId,
                        IssuedTime = issuedTime,
                        ExpiryTime = expiryTime
                    });
                }

                _recordService.AddRecords(records);
                ResultTextBox.Text = sb.ToString();
                StatusTextBlock.Text = $"已成功生成 {count} 个授权码（{selectedItem.Content}），已记录到发放数据库";
            }
            catch (Exception ex)
            {
                MessageBox.Show($"生成失败：{ex.Message}", "错误", MessageBoxButton.OK, MessageBoxImage.Error);
                StatusTextBlock.Text = "生成失败";
            }
        }

        private void ExportButton_Click(object sender, RoutedEventArgs e)
        {
            if (string.IsNullOrWhiteSpace(ResultTextBox.Text))
            {
                MessageBox.Show("没有可导出的授权码", "提示", MessageBoxButton.OK, MessageBoxImage.Warning);
                return;
            }

            var dialog = new SaveFileDialog
            {
                Filter = "文本文件|*.txt",
                DefaultExt = ".txt",
                FileName = $"授权码_{DateTime.Now:yyyyMMdd_HHmmss}"
            };

            if (dialog.ShowDialog() == true)
            {
                try
                {
                    var selectedItem = LicenseTypeComboBox.SelectedItem as System.Windows.Controls.ComboBoxItem;
                    string licenseTypeName = selectedItem?.Content?.ToString() ?? "未知";

                    var sb = new StringBuilder();
                    sb.AppendLine($"生成时间：{DateTime.Now:yyyy-MM-dd HH:mm:ss}");
                    sb.AppendLine($"授权类型：{licenseTypeName}");
                    sb.AppendLine(new string('=', 50));
                    sb.AppendLine();
                    sb.Append(ResultTextBox.Text);

                    File.WriteAllText(dialog.FileName, sb.ToString(), Encoding.UTF8);
                    MessageBox.Show("导出成功", "提示", MessageBoxButton.OK, MessageBoxImage.Information);
                    StatusTextBlock.Text = $"已导出到 {Path.GetFileName(dialog.FileName)}";
                }
                catch (Exception ex)
                {
                    MessageBox.Show($"导出失败：{ex.Message}", "错误", MessageBoxButton.OK, MessageBoxImage.Error);
                }
            }
        }

        private void ClearButton_Click(object sender, RoutedEventArgs e)
        {
            ResultTextBox.Text = string.Empty;
            MachineIdTextBox.Text = string.Empty;
            StatusTextBlock.Text = "就绪";
        }

        private void BatchGenerateButton_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                var selectedItem = BatchLicenseTypeComboBox.SelectedItem as System.Windows.Controls.ComboBoxItem;
                if (selectedItem == null) return;

                string licenseType = selectedItem.Tag?.ToString() ?? "YEAR1";
                string rawText = BatchMachineIdTextBox.Text.Trim();

                if (string.IsNullOrWhiteSpace(rawText))
                {
                    MessageBox.Show("请输入机器码列表", "提示", MessageBoxButton.OK, MessageBoxImage.Warning);
                    return;
                }

                var machineIds = rawText.Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries)
                    .Select(s => s.Trim())
                    .Where(s => !string.IsNullOrWhiteSpace(s))
                    .Distinct()
                    .ToList();

                if (machineIds.Count == 0)
                {
                    MessageBox.Show("未找到有效的机器码", "提示", MessageBoxButton.OK, MessageBoxImage.Warning);
                    return;
                }

                var sb = new StringBuilder();
                var records = new List<LicenseRecord>();

                for (int i = 0; i < machineIds.Count; i++)
                {
                    string mid = machineIds[i];
                    string code = LicenseGeneratorService.GenerateLicenseCode(licenseType, mid);
                    DateTime issuedTime = DateTime.Now;
                    DateTime? expiryTime = CalculateExpiryTime(licenseType, issuedTime);

                    sb.AppendLine($"--- 机器码：{mid} ---");
                    sb.AppendLine(code);
                    sb.AppendLine();

                    records.Add(new LicenseRecord
                    {
                        LicenseCode = code,
                        LicenseType = licenseType,
                        MachineId = mid,
                        IssuedTime = issuedTime,
                        ExpiryTime = expiryTime
                    });
                }

                _recordService.AddRecords(records);
                _currentRecords = records;

                BatchResultTextBox.Text = sb.ToString();
                BatchStatusTextBlock.Text = $"已为 {machineIds.Count} 台机器生成授权码（{selectedItem.Content}），已记录到发放数据库";
            }
            catch (Exception ex)
            {
                MessageBox.Show($"批量生成失败：{ex.Message}", "错误", MessageBoxButton.OK, MessageBoxImage.Error);
                BatchStatusTextBlock.Text = "批量生成失败";
            }
        }

        private void ImportFileButton_Click(object sender, RoutedEventArgs e)
        {
            var dialog = new OpenFileDialog
            {
                Filter = "文本文件|*.txt|所有文件|*.*",
                Title = "导入机器码列表"
            };

            if (dialog.ShowDialog() == true)
            {
                try
                {
                    string content = File.ReadAllText(dialog.FileName, Encoding.UTF8);
                    BatchMachineIdTextBox.Text = content;
                    int count = content.Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries)
                        .Select(s => s.Trim())
                        .Where(s => !string.IsNullOrWhiteSpace(s))
                        .Distinct()
                        .Count();
                    BatchStatusTextBlock.Text = $"已导入 {count} 个机器码";
                }
                catch (Exception ex)
                {
                    MessageBox.Show($"导入失败：{ex.Message}", "错误", MessageBoxButton.OK, MessageBoxImage.Error);
                }
            }
        }

        private void BatchExportButton_Click(object sender, RoutedEventArgs e)
        {
            if (string.IsNullOrWhiteSpace(BatchResultTextBox.Text))
            {
                MessageBox.Show("没有可导出的授权码", "提示", MessageBoxButton.OK, MessageBoxImage.Warning);
                return;
            }

            var dialog = new SaveFileDialog
            {
                Filter = "文本文件|*.txt",
                DefaultExt = ".txt",
                FileName = $"批量授权码_{DateTime.Now:yyyyMMdd_HHmmss}"
            };

            if (dialog.ShowDialog() == true)
            {
                try
                {
                    File.WriteAllText(dialog.FileName, BatchResultTextBox.Text, Encoding.UTF8);
                    MessageBox.Show("导出成功", "提示", MessageBoxButton.OK, MessageBoxImage.Information);
                    BatchStatusTextBlock.Text = $"已导出到 {Path.GetFileName(dialog.FileName)}";
                }
                catch (Exception ex)
                {
                    MessageBox.Show($"导出失败：{ex.Message}", "错误", MessageBoxButton.OK, MessageBoxImage.Error);
                }
            }
        }

        private void BatchClearButton_Click(object sender, RoutedEventArgs e)
        {
            BatchMachineIdTextBox.Text = string.Empty;
            BatchResultTextBox.Text = string.Empty;
            BatchStatusTextBlock.Text = "就绪";
        }

        private void SearchRecordButton_Click(object sender, RoutedEventArgs e)
        {
            string keyword = SearchMachineIdTextBox.Text.Trim();
            var records = _recordService.SearchByMachineId(keyword);
            RecordDataGrid.ItemsSource = records;
            RecordStatusTextBlock.Text = $"共 {records.Count} 条记录";
        }

        private void RefreshRecordButton_Click(object sender, RoutedEventArgs e)
        {
            SearchMachineIdTextBox.Text = string.Empty;
            var records = _recordService.GetAllRecords();
            RecordDataGrid.ItemsSource = records;
            RecordStatusTextBlock.Text = $"共 {records.Count} 条记录";
        }

        private void DeleteRecordButton_Click(object sender, RoutedEventArgs e)
        {
            var selectedItems = RecordDataGrid.SelectedItems.Cast<LicenseRecord>().ToList();
            if (selectedItems.Count == 0)
            {
                MessageBox.Show("请先选择要删除的记录", "提示", MessageBoxButton.OK, MessageBoxImage.Warning);
                return;
            }

            var result = MessageBox.Show($"确定删除选中的 {selectedItems.Count} 条记录？", "确认删除",
                MessageBoxButton.YesNo, MessageBoxImage.Question);

            if (result == MessageBoxResult.Yes)
            {
                foreach (var item in selectedItems)
                {
                    _recordService.DeleteRecord(item.RecordId);
                }
                RefreshRecordButton_Click(sender, e);
            }
        }

        private DateTime? CalculateExpiryTime(string licenseType, DateTime issuedTime)
        {
            return licenseType switch
            {
                "TRIAL" => issuedTime.AddMinutes(5),
                "YEAR1" => issuedTime.AddYears(1),
                "YEAR2" => issuedTime.AddYears(2),
                "PERMANENT" => null,
                _ => issuedTime
            };
        }

        private void PasteMachineIdButton_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                string clipboardText = Clipboard.GetText()?.Trim() ?? "";
                if (!string.IsNullOrEmpty(clipboardText))
                {
                    MachineIdTextBox.Text = clipboardText;
                    StatusTextBlock.Text = "已从剪贴板粘贴机器码";
                }
                else
                {
                    MessageBox.Show("剪贴板为空", "提示", MessageBoxButton.OK, MessageBoxImage.Information);
                }
            }
            catch
            {
                MessageBox.Show("无法读取剪贴板", "提示", MessageBoxButton.OK, MessageBoxImage.Warning);
            }
        }

        private void BatchPasteButton_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                string clipboardText = Clipboard.GetText()?.Trim() ?? "";
                if (!string.IsNullOrEmpty(clipboardText))
                {
                    if (string.IsNullOrEmpty(BatchMachineIdTextBox.Text))
                        BatchMachineIdTextBox.Text = clipboardText;
                    else
                        BatchMachineIdTextBox.Text += "\n" + clipboardText;
                    BatchStatusTextBlock.Text = "已从剪贴板粘贴机器码";
                }
                else
                {
                    MessageBox.Show("剪贴板为空", "提示", MessageBoxButton.OK, MessageBoxImage.Information);
                }
            }
            catch
            {
                MessageBox.Show("无法读取剪贴板", "提示", MessageBoxButton.OK, MessageBoxImage.Warning);
            }
        }
    }
}
