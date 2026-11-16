using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.Json;
using System.Windows;
using Microsoft.Win32;
using NetSecurityScanner.Models;
using NetSecurityScanner.Services;

namespace NetSecurityScanner.Views
{
    public partial class AuditLogWindow : Window
    {
        private readonly AuthService _authService;
        private List<AuditEntry> _all = new();

        public AuditLogWindow()
        {
            InitializeComponent();
            _authService = new AuthService();
            Loaded += AuditLogWindow_Loaded;
        }

        private void AuditLogWindow_Loaded(object sender, RoutedEventArgs e)
        {
            // 仅 admin 可看
            var current = SessionContext.Instance.Current;
            if (current == null || !current.IsAdmin)
            {
                MessageBox.Show("此功能仅限管理员使用。", "权限不足",
                    MessageBoxButton.OK, MessageBoxImage.Warning);
                Close();
                return;
            }

            // 填充动作筛选下拉
            ActionFilter.Items.Add("全部");
            foreach (var a in new[] { "APPROVE", "REJECT", "SET_PERMS", "DISABLE", "ENABLE", "RESET_PWD", "CLEAR_AUDIT" })
                ActionFilter.Items.Add(a);
            ActionFilter.SelectedIndex = 0;

            LoadAll();
        }

        private void LoadAll()
        {
            try
            {
                // 重新 new 一个 AuthService 从磁盘加载最新数据
                var freshAuth = new AuthService();
                _all = freshAuth.GetAuditEntries(2000);
                InfoText.Text = $"共 {_all.Count} 条审计记录（最近 2000 条）";
                ApplyFilter();
            }
            catch (Exception ex)
            {
                MessageBox.Show($"加载审计日志失败：{ex.Message}", "错误",
                    MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        private void ApplyFilter()
        {
            string action = (ActionFilter.SelectedItem as string) ?? "全部";
            string target = TargetFilter.Text?.Trim() ?? "";
            var query = _all.AsEnumerable();
            if (action != "全部")
                query = query.Where(x => x.Action == action);
            if (!string.IsNullOrEmpty(target))
                query = query.Where(x =>
                    (x.Target ?? "").Contains(target, StringComparison.OrdinalIgnoreCase) ||
                    (x.Actor ?? "").Contains(target, StringComparison.OrdinalIgnoreCase));
            var list = query.ToList();
            AuditGrid.ItemsSource = list;
            StatusText.Text = $"显示 {list.Count} / {_all.Count} 条";
        }

        private void Filter_Changed(object sender, EventArgs e)
        {
            if (IsLoaded) ApplyFilter();
        }

        private void RefreshButton_Click(object sender, RoutedEventArgs e)
        {
            LoadAll();
        }

        private void ExportButton_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                var dlg = new SaveFileDialog
                {
                    Filter = "JSON文件|*.json|CSV文件|*.csv",
                    FileName = $"审计日志_{DateTime.Now:yyyyMMdd_HHmmss}",
                    Title = "导出审计日志"
                };
                if (dlg.ShowDialog() != true) return;

                var filtered = (AuditGrid.ItemsSource as IEnumerable<AuditEntry>)?.ToList() ?? new List<AuditEntry>();
                if (filtered.Count == 0) filtered = _all;
                var ext = Path.GetExtension(dlg.FileName).ToLower();
                if (ext == ".json")
                {
                    var json = JsonSerializer.Serialize(filtered, new JsonSerializerOptions { WriteIndented = true });
                    File.WriteAllText(dlg.FileName, json);
                }
                else
                {
                    var sb = new StringBuilder();
                    sb.AppendLine("时间,操作者,动作,目标,结果,详情");
                    foreach (var a in filtered)
                    {
                        sb.AppendLine($"{a.AtDisplay},{a.Actor},{a.Action},{a.Target},{(a.Success ? "成功" : "失败")},\"{a.Detail.Replace("\"", "\"\"")}\"");
                    }
                    File.WriteAllText(dlg.FileName, sb.ToString());
                }
                MessageBox.Show($"已导出 {filtered.Count} 条审计记录到：\n{dlg.FileName}", "导出成功",
                    MessageBoxButton.OK, MessageBoxImage.Information);
            }
            catch (Exception ex)
            {
                MessageBox.Show($"导出失败：{ex.Message}", "错误",
                    MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        private async void ClearButton_Click(object sender, RoutedEventArgs e)
        {
            var ok = MessageBox.Show(
                $"确定清空全部审计日志吗？\n此操作不可恢复！",
                "确认清空", MessageBoxButton.YesNo, MessageBoxImage.Warning);
            if (ok != MessageBoxResult.Yes) return;

            try
            {
                var current = SessionContext.Instance.Current;
                var r = await _authService.ClearAuditLogAsync(current.Username);
                if (r)
                {
                    LoadAll();
                    MessageBox.Show("审计日志已清空。", "完成", MessageBoxButton.OK, MessageBoxImage.Information);
                }
            }
            catch (Exception ex)
            {
                MessageBox.Show($"清空失败：{ex.Message}", "错误",
                    MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        private void CloseButton_Click(object sender, RoutedEventArgs e)
        {
            Close();
        }
    }
}
