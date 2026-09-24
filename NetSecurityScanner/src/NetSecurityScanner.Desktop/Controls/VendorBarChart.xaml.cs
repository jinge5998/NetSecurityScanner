using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using System.Windows.Shapes;

namespace NetSecurityScanner.Controls
{
  /// <summary>
  /// 横向柱图（v4-T1 共用控件）。
  /// 用法：
  ///   &lt;ctrl:VendorBarChart Data="{Binding VendorTopN}" /&gt;
  /// 说明：本控件采用纯代码方式构建 UI（避免 XAML 编译问题）。
  /// </summary>
  public class VendorBarChart : UserControl
  {
    public static readonly DependencyProperty DataProperty =
        DependencyProperty.Register(
            nameof(Data),
            typeof(Dictionary<string, int>),
            typeof(VendorBarChart),
            new PropertyMetadata(null, OnDataChanged));

    public Dictionary<string, int>? Data
    {
      get => (Dictionary<string, int>?)GetValue(DataProperty);
      set => SetValue(DataProperty, value);
    }

    private readonly Canvas _chartCanvas;

    public VendorBarChart()
    {
      _chartCanvas = new Canvas { Background = Brushes.White };
      Content = _chartCanvas;
    }

    /// <summary>向后兼容的内部访问点</summary>
    internal Canvas ChartCanvas => _chartCanvas;

    private static void OnDataChanged(DependencyObject d, DependencyPropertyChangedEventArgs e)
    {
      if (d is VendorBarChart chart) chart.Redraw();
    }

    public void Redraw()
    {
      _chartCanvas.Children.Clear();

      var data = Data ?? new Dictionary<string, int>();
      if (data.Count == 0)
      {
        var hint = new TextBlock
        {
          Text = "暂无数据",
          Foreground = new SolidColorBrush(Color.FromRgb(0x94, 0xA3, 0xB8)),
          FontSize = 12,
          Margin = new Thickness(10)
        };
        Canvas.SetLeft(hint, 10);
        Canvas.SetTop(hint, 10);
        _chartCanvas.Children.Add(hint);
        _chartCanvas.Height = 40;
        return;
      }

      const double rowHeight = 26;
      const double gap = 6;
      const double labelWidth = 110;
      const double valueWidth = 50;
      const double padding = 8;
      const double barMin = 50;
      double canvasWidth = Math.Max(300, ActualWidth > 0 ? ActualWidth : 480);

      // 排序
      var sorted = data.OrderByDescending(kv => kv.Value).ToList();
      int maxVal = Math.Max(1, sorted.Max(kv => kv.Value));

      double totalHeight = padding * 2 + sorted.Count * (rowHeight + gap);
      _chartCanvas.Height = totalHeight;
      _chartCanvas.Width = canvasWidth;

      var labelColor = new SolidColorBrush(Color.FromRgb(0x33, 0x41, 0x55));
      var valueColor = new SolidColorBrush(Color.FromRgb(0x1E, 0x29, 0x3B));
      var barColor = new SolidColorBrush(Color.FromRgb(0x25, 0x63, 0xEB));
      var trackColor = new SolidColorBrush(Color.FromRgb(0xE2, 0xE8, 0xF0));

      double availableBarWidth = canvasWidth - labelWidth - valueWidth - padding * 3;

      for (int i = 0; i < sorted.Count; i++)
      {
        var kv = sorted[i];
        double y = padding + i * (rowHeight + gap);

        // 名称
        var label = new TextBlock
        {
          Text = Truncate(kv.Key, 16),
          FontSize = 12,
          Foreground = labelColor,
          Width = labelWidth,
          TextTrimming = TextTrimming.CharacterEllipsis,
          VerticalAlignment = VerticalAlignment.Center,
          TextAlignment = TextAlignment.Right
        };
        Canvas.SetLeft(label, padding);
        Canvas.SetTop(label, y + (rowHeight - 16) / 2);
        _chartCanvas.Children.Add(label);

        // 背景轨道
        var track = new Rectangle
        {
          Width = availableBarWidth,
          Height = 16,
          RadiusX = 3,
          RadiusY = 3,
          Fill = trackColor
        };
        Canvas.SetLeft(track, padding + labelWidth + padding);
        Canvas.SetTop(track, y + (rowHeight - 16) / 2);
        _chartCanvas.Children.Add(track);

        // 柱
        double w = Math.Max(2, availableBarWidth * kv.Value / maxVal);
        if (w < barMin && kv.Value > 0) w = barMin;
        var bar = new Rectangle
        {
          Width = Math.Min(availableBarWidth, w),
          Height = 16,
          RadiusX = 3,
          RadiusY = 3,
          Fill = barColor,
          ToolTip = $"{kv.Key}: {kv.Value}"
        };
        Canvas.SetLeft(bar, padding + labelWidth + padding);
        Canvas.SetTop(bar, y + (rowHeight - 16) / 2);
        _chartCanvas.Children.Add(bar);

        // 数值
        var val = new TextBlock
        {
          Text = kv.Value.ToString(CultureInfo.InvariantCulture),
          FontSize = 12,
          FontWeight = FontWeights.SemiBold,
          Foreground = valueColor,
          Width = valueWidth,
          TextAlignment = TextAlignment.Left
        };
        Canvas.SetLeft(val, padding + labelWidth + padding + availableBarWidth + 6);
        Canvas.SetTop(val, y + (rowHeight - 16) / 2);
        _chartCanvas.Children.Add(val);
      }
    }

    private static string Truncate(string s, int max)
    {
      if (string.IsNullOrEmpty(s)) return string.Empty;
      return s.Length <= max ? s : s.Substring(0, max - 1) + "…";
    }
  }
}
