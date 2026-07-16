using System.Windows;
using System.Windows.Controls;

namespace NetSecurityScanner.Views
{
  public partial class CameraMonitorDialog : Window
  {
    public int IntervalMinutes { get; private set; } = 30;
    public bool EnableSound { get; private set; }

    public CameraMonitorDialog()
    {
      Title = "配置持续监控";
      Width = 350;
      Height = 220;
      WindowStartupLocation = WindowStartupLocation.CenterOwner;
      ResizeMode = ResizeMode.NoResize;

      var stack = new StackPanel { Margin = new Thickness(15) };

      stack.Children.Add(new TextBlock
      {
        Text = "监控间隔（分钟）:",
        FontWeight = FontWeights.Bold,
        Margin = new Thickness(0, 0, 0, 6)
      });

      var intervalCombo = new ComboBox
      {
        Name = "IntervalCombo",
        Padding = new Thickness(6),
        FontSize = 13
      };
      foreach (var i in new[] { 5, 10, 15, 30, 60, 120 })
        intervalCombo.Items.Add(i);
      intervalCombo.SelectedIndex = 3;
      stack.Children.Add(intervalCombo);

      var soundCheck = new CheckBox
      {
        Content = "启用声音告警",
        Margin = new Thickness(0, 12, 0, 0),
        IsChecked = false
      };
      stack.Children.Add(soundCheck);

      var btnPanel = new StackPanel
      {
        Orientation = Orientation.Horizontal,
        HorizontalAlignment = HorizontalAlignment.Right,
        Margin = new Thickness(0, 20, 0, 0)
      };
      var okBtn = new Button
      {
        Content = "启动",
        Width = 80,
        Height = 30,
        Margin = new Thickness(0, 0, 8, 0),
        IsDefault = true
      };
      okBtn.Click += (s, e) =>
      {
        if (intervalCombo.SelectedItem is int min) IntervalMinutes = min;
        EnableSound = soundCheck.IsChecked == true;
        DialogResult = true;
        Close();
      };
      var cancelBtn = new Button
      {
        Content = "取消",
        Width = 80,
        Height = 30,
        IsCancel = true
      };
      btnPanel.Children.Add(okBtn);
      btnPanel.Children.Add(cancelBtn);
      stack.Children.Add(btnPanel);

      Content = stack;
    }
  }
}
