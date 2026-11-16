using NetSecurityScanner.Models;
using NetSecurityScanner.Services;
using System;
using System.Linq;
using System.Windows;
using System.Windows.Controls;

namespace NetSecurityScanner.Views
{
    public partial class ScheduledScanWindow : Window
    {
        private readonly ScheduledScanService _scheduledScanService;

        public ScheduledScanWindow()
        {
            InitializeComponent();
            _scheduledScanService = new ScheduledScanService();
            try
            {
                InitializeTimeComboBoxes();
                LoadScheduledScans();
                SetupEventHandlers();
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"[ScheduledScanWindow] 初始化失败: {ex.Message}");
            }
        }

        private void InitializeTimeComboBoxes()
        {
            if (HourComboBox == null || MinuteComboBox == null) return;

            // 初始化小时选择器 (0-23)
            for (int i = 0; i < 24; i++)
            {
                HourComboBox.Items.Add(i.ToString("D2"));
            }
            HourComboBox.SelectedIndex = 2; // 默认02:00

            // 初始化分钟选择器 (0-59, 每5分钟)
            for (int i = 0; i < 60; i += 5)
            {
                MinuteComboBox.Items.Add(i.ToString("D2"));
            }
            MinuteComboBox.SelectedIndex = 0;
        }

        private void SetupEventHandlers()
        {
            _scheduledScanService.ScanStarted += (s, e) =>
            {
                Dispatcher.Invoke(() =>
                {
                    MessageBox.Show($"定时任务 '{e.Scan.Name}' 开始执行", "扫描开始", MessageBoxButton.OK, MessageBoxImage.Information);
                });
            };

            _scheduledScanService.ScanCompleted += (s, e) =>
            {
                Dispatcher.Invoke(() =>
                {
                    MessageBox.Show(
                        $"定时任务 '{e.Scan.Name}' 执行完成\n" +
                        $"扫描目标: {e.Scan.TargetValue}\n" +
                        $"发现漏洞: {e.Result.TotalVulnerabilities} 个\n" +
                        $"执行时长: {e.Duration.TotalMinutes:F1} 分钟",
                        "扫描完成", MessageBoxButton.OK, MessageBoxImage.Information);
                    LoadScheduledScans();
                });
            };

            _scheduledScanService.ScanFailed += (s, e) =>
            {
                Dispatcher.Invoke(() =>
                {
                    MessageBox.Show($"定时任务 '{e.Scan.Name}' 执行失败: {e.Error}", "扫描失败", MessageBoxButton.OK, MessageBoxImage.Error);
                });
            };
        }

        private void LoadScheduledScans()
        {
            var scans = _scheduledScanService.GetAllScheduledScans();
            ScheduledScansDataGrid.ItemsSource = scans;
        }

        private void TargetTypeComboBox_SelectionChanged(object sender, SelectionChangedEventArgs e)
        {
            if (TargetTypeComboBox.SelectedItem is ComboBoxItem selectedItem)
            {
                string tag = selectedItem.Tag?.ToString();
                if (TargetHintTextBlock != null)
                {
                    TargetHintTextBlock.Text = tag switch
                    {
                        "Single" => "提示：输入单个IP地址，如：192.168.1.1",
                        "Range" => "提示：输入IP段，如：192.168.1.1-192.168.1.254",
                        "CIDR" => "提示：输入CIDR格式，如：192.168.1.0/24",
                        "File" => "提示：输入目标列表文件路径",
                        _ => "提示：输入目标值"
                    };
                }
            }
        }

        private void AddTaskButton_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                var scan = CreateScheduledScanFromUI();
                if (scan == null) return;

                _scheduledScanService.AddScheduledScan(scan);
                LoadScheduledScans();
                ClearInputFields();
                MessageBox.Show("定时任务添加成功", "成功", MessageBoxButton.OK, MessageBoxImage.Information);
            }
            catch (Exception ex)
            {
                MessageBox.Show($"添加任务失败: {ex.Message}", "错误", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        private void UpdateTaskButton_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                if (ScheduledScansDataGrid.SelectedItem is not ScheduledScan selectedScan)
                {
                    MessageBox.Show("请先选择要更新的任务", "提示", MessageBoxButton.OK, MessageBoxImage.Information);
                    return;
                }

                var updatedScan = CreateScheduledScanFromUI();
                if (updatedScan == null) return;

                updatedScan.Id = selectedScan.Id;
                updatedScan.CreatedAt = selectedScan.CreatedAt;
                updatedScan.LastRunTime = selectedScan.LastRunTime;
                updatedScan.RunCount = selectedScan.RunCount;

                _scheduledScanService.UpdateScheduledScan(updatedScan);
                LoadScheduledScans();
                MessageBox.Show("定时任务更新成功", "成功", MessageBoxButton.OK, MessageBoxImage.Information);
            }
            catch (Exception ex)
            {
                MessageBox.Show($"更新任务失败: {ex.Message}", "错误", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        private void DeleteTaskButton_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                if (ScheduledScansDataGrid.SelectedItem is not ScheduledScan selectedScan)
                {
                    MessageBox.Show("请先选择要删除的任务", "提示", MessageBoxButton.OK, MessageBoxImage.Information);
                    return;
                }

                var result = MessageBox.Show($"确定要删除任务 '{selectedScan.Name}' 吗？", "确认删除", MessageBoxButton.YesNo, MessageBoxImage.Question);
                if (result == MessageBoxResult.Yes)
                {
                    _scheduledScanService.DeleteScheduledScan(selectedScan.Id);
                    LoadScheduledScans();
                    ClearInputFields();
                    MessageBox.Show("定时任务删除成功", "成功", MessageBoxButton.OK, MessageBoxImage.Information);
                }
            }
            catch (Exception ex)
            {
                MessageBox.Show($"删除任务失败: {ex.Message}", "错误", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        private ScheduledScan CreateScheduledScanFromUI()
        {
            // 验证输入
            if (string.IsNullOrWhiteSpace(TaskNameTextBox.Text))
            {
                MessageBox.Show("请输入任务名称", "输入错误", MessageBoxButton.OK, MessageBoxImage.Warning);
                return null;
            }

            if (string.IsNullOrWhiteSpace(TargetValueTextBox.Text))
            {
                MessageBox.Show("请输入目标值", "输入错误", MessageBoxButton.OK, MessageBoxImage.Warning);
                return null;
            }

            if (TargetTypeComboBox.SelectedItem is not ComboBoxItem targetTypeItem)
            {
                MessageBox.Show("请选择目标类型", "输入错误", MessageBoxButton.OK, MessageBoxImage.Warning);
                return null;
            }

            if (TaskScanModeComboBox.SelectedItem is not ComboBoxItem scanModeItem)
            {
                MessageBox.Show("请选择扫描模式", "输入错误", MessageBoxButton.OK, MessageBoxImage.Warning);
                return null;
            }

            if (ScheduleTypeComboBox.SelectedItem is not ComboBoxItem scheduleTypeItem)
            {
                MessageBox.Show("请选择调度类型", "输入错误", MessageBoxButton.OK, MessageBoxImage.Warning);
                return null;
            }

            string hourStr = HourComboBox?.SelectedItem?.ToString() ?? "08";
            string minuteStr = MinuteComboBox?.SelectedItem?.ToString() ?? "00";
            string scheduleTime = $"{hourStr}:{minuteStr}";

            return new ScheduledScan
            {
                Name = TaskNameTextBox.Text.Trim(),
                Description = TaskDescriptionTextBox.Text.Trim(),
                TargetType = targetTypeItem.Tag?.ToString(),
                TargetValue = TargetValueTextBox.Text.Trim(),
                ScanMode = scanModeItem.Tag?.ToString(),
                ScheduleType = scheduleTypeItem.Tag?.ToString(),
                ScheduleTime = scheduleTime,
                EnableEmailNotification = EnableEmailCheckBox.IsChecked == true,
                NotificationEmail = NotificationEmailTextBox.Text.Trim(),
                IsEnabled = true
            };
        }

        private void ClearInputFields()
        {
            TaskNameTextBox.Clear();
            TaskDescriptionTextBox.Clear();
            TargetValueTextBox.Clear();
            NotificationEmailTextBox.Clear();
            EnableEmailCheckBox.IsChecked = false;
            TargetTypeComboBox.SelectedIndex = 0;
            TaskScanModeComboBox.SelectedIndex = 1;
            ScheduleTypeComboBox.SelectedIndex = 0;
            HourComboBox.SelectedIndex = 2;
            MinuteComboBox.SelectedIndex = 0;
        }

        private void StartSchedulerButton_Click(object sender, RoutedEventArgs e)
        {
            _scheduledScanService.Start();
            MessageBox.Show("定时扫描调度器已启动", "启动成功", MessageBoxButton.OK, MessageBoxImage.Information);
        }

        private void StopSchedulerButton_Click(object sender, RoutedEventArgs e)
        {
            _scheduledScanService.Stop();
            MessageBox.Show("定时扫描调度器已停止", "停止成功", MessageBoxButton.OK, MessageBoxImage.Information);
        }

        private void CloseButton_Click(object sender, RoutedEventArgs e)
        {
            Close();
        }

        protected override void OnClosing(System.ComponentModel.CancelEventArgs e)
        {
            _scheduledScanService?.Dispose();
            base.OnClosing(e);
        }
    }
}
