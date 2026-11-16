using System;
using System.Globalization;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using System.Windows.Shapes;

namespace NetSecurityScanner.Controls
{
  /// <summary>
  /// 半圆仪表盘（v4-T1 共用控件）。
  /// 用法：&lt;ctrl:RiskGauge Value="{Binding OnlinePercent}" Title="在线率" /&gt;
  /// Value 范围 0-100；Title 显示在圆弧下方。
  /// 说明：本控件采用纯代码方式构建 UI（避免 XAML 编译问题）。
  /// </summary>
  public class RiskGauge : UserControl
  {
    public static readonly DependencyProperty ValueProperty =
        DependencyProperty.Register(
            nameof(Value),
            typeof(double),
            typeof(RiskGauge),
            new PropertyMetadata(0.0, OnValueChanged));

    public double Value
    {
      get => (double)GetValue(ValueProperty);
      set => SetValue(ValueProperty, Math.Clamp(value, 0, 100));
    }

    public static readonly DependencyProperty TitleProperty =
        DependencyProperty.Register(
            nameof(Title),
            typeof(string),
            typeof(RiskGauge),
            new PropertyMetadata(string.Empty, OnValueChanged));

    public string Title
    {
      get => (string)GetValue(TitleProperty);
      set => SetValue(TitleProperty, value);
    }

    private readonly Canvas _gaugeCanvas;

    public RiskGauge()
    {
      _gaugeCanvas = new Canvas { Background = Brushes.Transparent, MinHeight = 140 };
      Content = _gaugeCanvas;
      SizeChanged += (s, e) => Redraw();
    }

    /// <summary>向后兼容的内部访问点</summary>
    internal Canvas GaugeCanvas => _gaugeCanvas;

    private static void OnValueChanged(DependencyObject d, DependencyPropertyChangedEventArgs e)
    {
      if (d is RiskGauge g) g.Redraw();
    }

    public void Redraw()
    {
      _gaugeCanvas.Children.Clear();
      double w = ActualWidth > 0 ? ActualWidth : 240;
      double h = ActualHeight > 0 ? ActualHeight : 160;
      _gaugeCanvas.Width = w;
      _gaugeCanvas.Height = h;

      double cx = w / 2;
      double cy = h * 0.85;
      double radius = Math.Min(w * 0.42, h * 0.75);
      if (radius < 30) return;

      // 背景弧（半圆 180°）
      var track = MakeArc(cx, cy, radius, 180, 360, new SolidColorBrush(Color.FromRgb(0xE2, 0xE8, 0xF0)), 14);
      _gaugeCanvas.Children.Add(track);

      // 颜色按值变化
      var fg = new SolidColorBrush(ValueToColor(Value));
      double angle = 180 + (180.0 * Value / 100.0);
      var fill = MakeArc(cx, cy, radius, 180, angle, fg, 14);
      _gaugeCanvas.Children.Add(fill);

      // 中心文字
      var valueText = new TextBlock
      {
        Text = Value.ToString("0", CultureInfo.InvariantCulture),
        FontSize = 28,
        FontWeight = FontWeights.Bold,
        Foreground = fg
      };
      valueText.Measure(new Size(w, h));
      double vw = valueText.DesiredSize.Width;
      Canvas.SetLeft(valueText, cx - vw / 2);
      Canvas.SetTop(valueText, cy - 50);
      _gaugeCanvas.Children.Add(valueText);

      var titleText = new TextBlock
      {
        Text = string.IsNullOrEmpty(Title) ? string.Empty : Title,
        FontSize = 12,
        Foreground = new SolidColorBrush(Color.FromRgb(0x64, 0x74, 0x8B))
      };
      titleText.Measure(new Size(w, h));
      double tw = titleText.DesiredSize.Width;
      Canvas.SetLeft(titleText, cx - tw / 2);
      Canvas.SetTop(titleText, cy - 22);
      _gaugeCanvas.Children.Add(titleText);
    }

    /// <summary>
    /// 绘制一段圆弧。
    /// </summary>
    private static Path MakeArc(double cx, double cy, double r, double startDeg, double endDeg, Brush brush, double thickness)
    {
      double startRad = startDeg * Math.PI / 180;
      double endRad = endDeg * Math.PI / 180;
      double sx = cx + r * Math.Cos(startRad);
      double sy = cy + r * Math.Sin(startRad);
      double ex = cx + r * Math.Cos(endRad);
      double ey = cy + r * Math.Sin(endRad);
      bool isLarge = endDeg - startDeg > 180;

      var figure = new PathFigure { StartPoint = new Point(sx, sy), IsClosed = false };
      figure.Segments.Add(new ArcSegment
      {
        Point = new Point(ex, ey),
        Size = new Size(r, r),
        IsLargeArc = isLarge,
        SweepDirection = SweepDirection.Clockwise
      });
      var geom = new PathGeometry();
      geom.Figures.Add(figure);

      return new Path
      {
        Stroke = brush,
        StrokeThickness = thickness,
        Data = geom,
        StrokeStartLineCap = PenLineCap.Round,
        StrokeEndLineCap = PenLineCap.Round
      };
    }

    private static Color ValueToColor(double v)
    {
      if (v >= 80) return Color.FromRgb(0xEF, 0x44, 0x44);
      if (v >= 60) return Color.FromRgb(0xF5, 0x9E, 0x0B);
      if (v >= 30) return Color.FromRgb(0x3B, 0x82, 0xF6);
      if (v >= 10) return Color.FromRgb(0x10, 0xB9, 0x81);
      return Color.FromRgb(0x64, 0x74, 0x8B);
    }
  }
}
