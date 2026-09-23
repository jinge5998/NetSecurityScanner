using System;
using System.Collections.Generic;
using System.Linq;
using System.Windows;
using NetSecurityScanner.Models;
using NetSecurityScanner.Services;

namespace NetSecurityScanner.Views
{
    public partial class LocalLibraryManagerWindow : Window
    {
        public enum Action
        {
            None,
            Rollback,
            ClearLibrary
        }

        public Action SelectedAction { get; private set; } = Action.None;
        public string SelectedSnapshot { get; private set; }

        public LocalLibraryManagerWindow(
            List<(string FileName, DateTime Time, int Count)> snapshots,
            VulnerabilityLibraryMeta meta)
        {
            InitializeComponent();
            LoadCurrentInfo(meta);
            LoadSnapshots(snapshots);
        }

        private void LoadCurrentInfo(VulnerabilityLibraryMeta meta)
        {
            try
            {
                if (meta == null)
                {
                    CurrentInfoText.Text = "当前库：未挂接或为空";
                    return;
                }

                var lastSync = meta.LastSyncTime.HasValue ? meta.LastSyncTime.Value.ToString("yyyy-MM-dd HH:mm:ss") : "未同步";
                var sources = meta.Sources != null && meta.Sources.Count > 0
                    ? string.Join(" / ", meta.Sources.Select(kv => $"{kv.Key} {kv.Value}"))
                    : "-";
                var breakdown = meta.SeverityBreakdown != null && meta.SeverityBreakdown.Count > 0
                    ? string.Join(" / ", meta.SeverityBreakdown.Select(kv => $"{kv.Key} {kv.Value}"))
                    : "-";
                CurrentInfoText.Text =
                    $"当前库版本：v{meta.Version}    总数：{meta.TotalCount}    等级分布：{breakdown}\n" +
                    $"来源明细：{sources}    最近同步：{lastSync}    快照数：{meta.SnapshotCount}";
            }
            catch (Exception ex)
            {
                CurrentInfoText.Text = $"加载元数据失败：{ex.Message}";
            }
        }

        private void LoadSnapshots(List<(string FileName, DateTime Time, int Count)> snapshots)
        {
            SnapshotListView.Items.Clear();
            foreach (var s in snapshots)
            {
                SnapshotListView.Items.Add(new
                {
                    FileName = s.FileName,
                    Time = s.Time,
                    Count = s.Count
                });
            }
        }

        private void RollbackButton_Click(object sender, RoutedEventArgs e)
        {
            var item = SnapshotListView.SelectedItem;
            if (item == null)
            {
                MessageBox.Show("请先选择要回滚到的快照", "提示", MessageBoxButton.OK, MessageBoxImage.Information);
                return;
            }

            var fileNameProp = item.GetType().GetProperty("FileName");
            if (fileNameProp == null)
            {
                MessageBox.Show("选中的快照无效", "错误", MessageBoxButton.OK, MessageBoxImage.Error);
                return;
            }

            SelectedSnapshot = fileNameProp.GetValue(item)?.ToString();
            SelectedAction = Action.Rollback;
            DialogResult = true;
            Close();
        }

        private void ClearButton_Click(object sender, RoutedEventArgs e)
        {
            SelectedAction = Action.ClearLibrary;
            DialogResult = true;
            Close();
        }

        private void CancelButton_Click(object sender, RoutedEventArgs e)
        {
            SelectedAction = Action.None;
            DialogResult = false;
            Close();
        }
    }
}
