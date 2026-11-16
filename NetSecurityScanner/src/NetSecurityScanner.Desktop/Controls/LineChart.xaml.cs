using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using System.Windows.Shapes;
using NetSecurityScanner.Models;
using NetSecurityScanner.Core.Models;

namespace NetSecurityScanner.Controls
{
  /// <summary>
  /// 折线图（v4-T5 共用控件）。
  /// 支持两种数据源：
  ///   - Points: IEnumerable&lt;(DateTime X, double Y)&gt;（多线 = 多条 series）
  ///   - Data: List&lt;CameraTrendPoint&gt;（自动绘制 Total/Online/VulnTotal 三条线）
  /// </summary>
  public class LineChart : UserControl
  {
    public static readonly DependencyProperty DataProperty =
        DependencyProperty.Register(
            nameof(Data),
            typeof(List<CameraTrendPoint>),
            typeof(LineChart),
            new PropertyMetadata(null, OnDataChanged));

    public List<CameraTrendPoint>? Data
    {
      get => (List<CameraTrendPoint>?)GetValue(DataProperty);
      set => SetValue(DataProperty, value);
    }

    private List<SeriesDefinition> _series = new();
    private readonly Canvas _chartCanvas;

    public LineChart()
    {
      _chartCanvas = new Canvas { Background = Brushes.White, MinHeight = 160 };
      Content = _chartCanvas;
      SizeChanged += (s, e) => Redraw();
      _chartCanvas.MouseMove += ChartCanvas_MouseMove;
      _chartCanvas.MouseLeave += (s, e) => { _hoverLine.Visibility = Visibility.Collapsed; _hoverLabel.Visibility = Visibility.Collapsed; };
    }

    /// <summary>向后兼容的内部访问点</summary>
    internal Canvas ChartCanvas => _chartCanvas;

    private readonly Line _hoverLine = new()
    {
      Stroke = new SolidColorBrush(Color.FromRgb(0x94, 0xA3, 0xB8)),
      StrokeThickness = 1,
      StrokeDashArray = new DoubleCollection { 2, 2 },
      Visibility = Visibility.Collapsed,
      IsHitTestVisible = false
    };

    private readonly Border _hoverLabel = new()
    {
      Background = new SolidColorBrush(Color.FromArgb(0xEE, 0x1F, 0x29, 0x37)),
      CornerRadius = new CornerRadius(4),
      Padding = new Thickness(6, 3, 6, 3),
      Visibility = Visibility.Collapsed,
      IsHitTestVisible = false
    };

    private readonly TextBlock _hoverLabelText = new()
    {
      Foreground = Brushes.White,
      FontSize = 11
    };

    public void SetSeries(IEnumerable<SeriesDefinition> series)
    {
      _series = series.ToList();
      Redraw();
    }

    private static void OnDataChanged(DependencyObject d, DependencyPropertyChangedEventArgs e)
    {
      if (d is LineChart chart)
      {
        var data = chart.Data;
        if (data != null)
        {
          // 默认三条线
          chart._series = new List<SeriesDefinition>
          {
            new SeriesDefinition { Name = "总数", Color = Color.FromRgb(0x25, 0x63, 0xEB), Values = data.Select(p => (p.Date, (double)p.Total)).ToList() },
            new SeriesDefinition { Name = "在线", Color = Color.FromRgb(0x10, 0xB9, 0x81), Values = data.Select(p => (p.Date, (double)p.Online)).ToList() },
            new SeriesDefinition { Name = "漏洞", Color = Color.FromRgb(0xEF, 0x44, 0x44), Values = data.Select(p => (p.Date, (double)p.VulnTotal)).ToList() }
          };
        }
        else
        {
          chart._series.Clear();
        }
        chart.Redraw();
      }
    }

    public void Redraw()
    {
      ChartCanvas.Children.Clear();
      double w = ActualWidth > 0 ? ActualWidth : 500;
      double h = ActualHeight > 0 ? ActualHeight : 200;
      ChartCanvas.Width = w;
      ChartCanvas.Height = h;

      if (_series.Count == 0 || _series.All(s => s.Values.Count == 0))
      {
        var hint = new TextBlock
        {
          Text = "暂无趋势数据",
          Foreground = new SolidColorBrush(Color.FromRgb(0x94, 0xA3, 0xB8)),
          FontSize = 12
        };
        Canvas.SetLeft(hint, 16);
        Canvas.SetTop(hint, 16);
        ChartCanvas.Children.Add(hint);
        return;
      }

      const double padL = 50;
      const double padR = 16;
      const double padT = 20;
      const double padB = 32;
      double plotW = w - padL - padR;
      double plotH = h - padT - padB;
      if (plotW < 30 || plotH < 30) return;

      // 收集 X（日期）与 Y 最大值
      var allDates = _series.SelectMany(s => s.Values.Select(v => v.Item1)).Distinct().OrderBy(d => d).ToList();
      double maxY = Math.Max(1, _series.SelectMany(s => s.Values).DefaultIfEmpty((DateTime.MinValue, 0.0)).Max(v => v.Item2));
      maxY = NiceCeiling(maxY);

      // 缓存供悬浮跟踪使用
      _xDates = allDates.ToArray();
      _maxY = maxY;
      _padL = padL;
      _padT = padT;
      _plotW = plotW;
      _plotH = plotH;

      // 坐标轴
      var axisBrush = new SolidColorBrush(Color.FromRgb(0xCB, 0xD5, 0xE1));
      // Y 轴
      ChartCanvas.Children.Add(new Line
      {
        X1 = padL,
        Y1 = padT,
        X2 = padL,
        Y2 = padT + plotH,
        Stroke = axisBrush,
        StrokeThickness = 1
      });
      // X 轴
      ChartCanvas.Children.Add(new Line
      {
        X1 = padL,
        Y1 = padT + plotH,
        X2 = padL + plotW,
        Y2 = padT + plotH,
        Stroke = axisBrush,
        StrokeThickness = 1
      });

      var textColor = new SolidColorBrush(Color.FromRgb(0x64, 0x74, 0x8B));
      // Y 网格线 + 刻度
      int yTicks = 4;
      for (int i = 0; i <= yTicks; i++)
      {
        double yVal = maxY * i / yTicks;
        double yPos = padT + plotH - plotH * i / yTicks;
        if (i > 0 && i < yTicks)
        {
          var grid = new Line
          {
            X1 = padL,
            Y1 = yPos,
            X2 = padL + plotW,
            Y2 = yPos,
            Stroke = new SolidColorBrush(Color.FromRgb(0xE2, 0xE8, 0xF0)),
            StrokeThickness = 1,
            StrokeDashArray = new DoubleCollection { 2, 4 }
          };
          ChartCanvas.Children.Add(grid);
        }
        var txt = new TextBlock
        {
          Text = yVal.ToString("0", CultureInfo.InvariantCulture),
          FontSize = 10,
          Foreground = textColor
        };
        Canvas.SetLeft(txt, 4);
        Canvas.SetTop(txt, yPos - 8);
        ChartCanvas.Children.Add(txt);
      }

      // X 标签（最多 6 个）
      int xLabelCount = Math.Min(6, allDates.Count);
      if (xLabelCount == 0) xLabelCount = 1;
      int xStep = Math.Max(1, allDates.Count / xLabelCount);
      for (int i = 0; i < allDates.Count; i += xStep)
      {
        var d = allDates[i];
        double xPos = allDates.Count == 1
            ? padL + plotW / 2
            : padL + plotW * i / (allDates.Count - 1);
        var txt = new TextBlock
        {
          Text = d.ToString("MM-dd"),
          FontSize = 10,
          Foreground = textColor
        };
        Canvas.SetLeft(txt, xPos - 18);
        Canvas.SetTop(txt, padT + plotH + 6);
        ChartCanvas.Children.Add(txt);
      }

      // 绘制每条线
      foreach (var series in _series)
      {
        if (series.Values.Count == 0) continue;
        var brush = new SolidColorBrush(series.Color);
        for (int i = 0; i < series.Values.Count; i++)
        {
          var (dt, val) = series.Values[i];
          if (i == 0) continue;
          var (pdt, pval) = series.Values[i - 1];
          if (pdt == DateTime.MinValue || dt == DateTime.MinValue) continue;
          double x1 = allDates.Count <= 1
              ? padL
              : padL + plotW * allDates.IndexOf(pdt) / Math.Max(1, allDates.Count - 1);
          double y1 = padT + plotH - plotH * pval / maxY;
          double x2 = allDates.Count <= 1
              ? padL + plotW
              : padL + plotW * allDates.IndexOf(dt) / Math.Max(1, allDates.Count - 1);
          double y2 = padT + plotH - plotH * val / maxY;
          ChartCanvas.Children.Add(new Line
          {
            X1 = x1,
            Y1 = y1,
            X2 = x2,
            Y2 = y2,
            Stroke = brush,
            StrokeThickness = 2
          });
        }
        // 数据点
        for (int i = 0; i < series.Values.Count; i++)
        {
          var (dt, val) = series.Values[i];
          if (dt == DateTime.MinValue) continue;
          double xPos = allDates.Count <= 1
              ? padL + plotW / 2
              : padL + plotW * allDates.IndexOf(dt) / Math.Max(1, allDates.Count - 1);
          double yPos = padT + plotH - plotH * val / maxY;
          var dot = new Ellipse
          {
            Width = 5,
            Height = 5,
            Fill = brush,
            ToolTip = $"{series.Name} {dt:MM-dd}: {val:0}"
          };
          Canvas.SetLeft(dot, xPos - 2.5);
          Canvas.SetTop(dot, yPos - 2.5);
          ChartCanvas.Children.Add(dot);
        }
      }

      // 图例（右上角）
      double lx = padL + plotW - 120;
      double ly = padT + 4;
      for (int i = 0; i < _series.Count; i++)
      {
        var s = _series[i];
        var dot = new Rectangle { Width = 10, Height = 4, Fill = new SolidColorBrush(s.Color), RadiusX = 2, RadiusY = 2 };
        Canvas.SetLeft(dot, lx);
        Canvas.SetTop(dot, ly + i * 16 + 4);
        ChartCanvas.Children.Add(dot);
        var txt = new TextBlock { Text = s.Name, FontSize = 10, Foreground = new SolidColorBrush(Color.FromRgb(0x33, 0x41, 0x55)) };
        Canvas.SetLeft(txt, lx + 14);
        Canvas.SetTop(txt, ly + i * 16);
        ChartCanvas.Children.Add(txt);
      }

      // 悬浮 UI 元素 (置于顶层)
      _hoverLabel.Child = _hoverLabelText;
      ChartCanvas.Children.Add(_hoverLine);
      ChartCanvas.Children.Add(_hoverLabel);
    }

    private DateTime[] _xDates = Array.Empty<DateTime>();
    private double _maxY;
    private double _padL, _padT, _plotW, _plotH;

    private void ChartCanvas_MouseMove(object sender, System.Windows.Input.MouseEventArgs e)
    {
      if (_xDates.Length == 0 || _plotW <= 0)
      {
        _hoverLine.Visibility = Visibility.Collapsed;
        _hoverLabel.Visibility = Visibility.Collapsed;
        return;
      }

      var pos = e.GetPosition(ChartCanvas);
      if (pos.X < _padL || pos.X > _padL + _plotW)
      {
        _hoverLine.Visibility = Visibility.Collapsed;
        _hoverLabel.Visibility = Visibility.Collapsed;
        return;
      }

      // 找到最近的 x 索引
      int nearestIdx = 0;
      double bestDist = double.MaxValue;
      for (int i = 0; i < _xDates.Length; i++)
      {
        double xi = _padL + _plotW * i / Math.Max(1, _xDates.Length - 1);
        double dist = Math.Abs(xi - pos.X);
        if (dist < bestDist) { bestDist = dist; nearestIdx = i; }
      }
      var date = _xDates[nearestIdx];
      double xPos = _padL + _plotW * nearestIdx / Math.Max(1, _xDates.Length - 1);

      _hoverLine.X1 = xPos;
      _hoverLine.Y1 = _padT;
      _hoverLine.X2 = xPos;
      _hoverLine.Y2 = _padT + _plotH;
      _hoverLine.Visibility = Visibility.Visible;

      // 构造 tooltip 文本：日期 + 每条线在该日期的值
      var sb = new System.Text.StringBuilder();
      sb.Append(date.ToString("yyyy-MM-dd"));
      foreach (var s in _series)
      {
        var match = s.Values.FirstOrDefault(v => v.Item1 == date);
        if (match.Item1 != DateTime.MinValue)
          sb.Append($"\n{s.Name}: {match.Item2:0}");
      }
      _hoverLabelText.Text = sb.ToString();

      // 测量 label 大小后定位 (放在悬浮线右上角，不超出右边界)
      _hoverLabel.Measure(new Size(double.PositiveInfinity, double.PositiveInfinity));
      double lw = _hoverLabel.DesiredSize.Width;
      double lh = _hoverLabel.DesiredSize.Height;
      double lxPos = Math.Min(xPos + 8, _padL + _plotW - lw);
      double lyPos = _padT + 2;
      Canvas.SetLeft(_hoverLabel, lxPos);
      Canvas.SetTop(_hoverLabel, lyPos);
      _hoverLabel.Visibility = Visibility.Visible;
    }

    private static double NiceCeiling(double v)
    {
      if (v <= 1) return 1;
      double pow = Math.Pow(10, Math.Floor(Math.Log10(v)));
      double norm = v / pow;
      double nice;
      if (norm <= 1) nice = 1;
      else if (norm <= 2) nice = 2;
      else if (norm <= 5) nice = 5;
      else nice = 10;
      return nice * pow;
    }
  }

  public class SeriesDefinition
  {
    public string Name { get; set; } = string.Empty;
    public Color Color { get; set; } = Colors.SteelBlue;
    public List<(DateTime, double)> Values { get; set; } = new();
  }
}