using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Input;
using System.Windows.Media;
using NetSecurityScanner.Models;

namespace NetSecurityScanner.Views
{
    /// <summary>
    /// 权限申请处理弹窗（v7-T6）。
    /// 管理员输入备注后点击"确定"返回 DialogResult=true，并通过 OperatorNote 属性读取备注。
    /// </summary>
    public class PermissionRequestDialog : Window
    {
        private readonly PermissionRequest _request;
        private readonly TextBox _noteBox;

        /// <summary>操作员备注（用于写审计 + 沙箱放行）</summary>
        public string OperatorNote { get; private set; } = "";

        public PermissionRequestDialog(PermissionRequest request)
        {
            _request = request ?? throw new System.ArgumentNullException(nameof(request));

            Title = "权限申请处理";
            Width = 480;
            Height = 380;
            WindowStartupLocation = WindowStartupLocation.CenterOwner;
            ResizeMode = ResizeMode.NoResize;
            Background = Brushes.White;

            var grid = new Grid { Margin = new Thickness(20) };
            grid.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
            grid.RowDefinitions.Add(new RowDefinition { Height = new GridLength(1, GridUnitType.Star) });
            grid.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });

            // ===== 申请信息（只读） =====
            var info = new StackPanel { Margin = new Thickness(0, 0, 0, 12) };
            info.Children.Add(new TextBlock
            {
                Text = "� 权限申请详情",
                FontSize = 15,
                FontWeight = FontWeights.Bold,
                Foreground = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#2C3E50")),
                Margin = new Thickness(0, 0, 0, 8)
            });
            info.Children.Add(BuildInfoRow("PluginId", _request.PluginId));
            info.Children.Add(BuildInfoRow("Permission", _request.Permission));
            info.Children.Add(BuildInfoRow("Reason", _request.Reason));
            info.Children.Add(BuildInfoRow("RequestedAt", _request.RequestedAt.ToString("yyyy-MM-dd HH:mm:ss")));
            Grid.SetRow(info, 0);
            grid.Children.Add(info);

            // ===== 备注 =====
            var notePanel = new DockPanel { Margin = new Thickness(0, 0, 0, 12) };
            notePanel.Children.Add(new TextBlock
            {
                Text = "操作员备注：",
                FontWeight = FontWeights.SemiBold,
                Margin = new Thickness(0, 0, 0, 4)
            });
            DockPanel.SetDock((UIElement)notePanel.Children[0], Dock.Top);
            _noteBox = new TextBox
            {
                Height = 80,
                AcceptsReturn = true,
                TextWrapping = TextWrapping.Wrap,
                VerticalScrollBarVisibility = ScrollBarVisibility.Auto,
                VerticalContentAlignment = VerticalAlignment.Top
            };
            notePanel.Children.Add(_noteBox);
            Grid.SetRow(notePanel, 1);
            grid.Children.Add(notePanel);

            // ===== 按钮 =====
            var btns = new StackPanel
            {
                Orientation = Orientation.Horizontal,
                HorizontalAlignment = HorizontalAlignment.Right
            };
            var okBtn = new Button
            {
                Content = "确定",
                Width = 80,
                Height = 30,
                Margin = new Thickness(0, 0, 8, 0),
                Background = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#27AE60")),
                Foreground = Brushes.White,
                BorderThickness = new Thickness(0),
                Cursor = Cursors.Hand,
                IsDefault = true
            };
            okBtn.Click += (s, e) =>
            {
                OperatorNote = _noteBox.Text?.Trim() ?? "";
                DialogResult = true;
                Close();
            };
            var cancelBtn = new Button
            {
                Content = "取消",
                Width = 80,
                Height = 30,
                Cursor = Cursors.Hand,
                IsCancel = true
            };
            cancelBtn.Click += (s, e) =>
            {
                OperatorNote = "";
                DialogResult = false;
                Close();
            };
            btns.Children.Add(okBtn);
            btns.Children.Add(cancelBtn);
            Grid.SetRow(btns, 2);
            grid.Children.Add(btns);

            Content = grid;
        }

        private static UIElement BuildInfoRow(string label, string value)
        {
            var sp = new StackPanel { Orientation = Orientation.Horizontal, Margin = new Thickness(0, 2, 0, 2) };
            sp.Children.Add(new TextBlock
            {
                Text = label + ":",
                FontWeight = FontWeights.SemiBold,
                Width = 90,
                Foreground = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#7F8C8D"))
            });
            sp.Children.Add(new TextBlock
            {
                Text = string.IsNullOrEmpty(value) ? "(空)" : value,
                TextWrapping = TextWrapping.Wrap,
                Foreground = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#2C3E50"))
            });
            return sp;
        }
    }
}
