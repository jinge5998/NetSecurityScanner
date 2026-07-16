using System;
using System.Collections.Generic;
using System.Linq;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using NetSecurityScanner.Controls;
using NetSecurityScanner.Core;
using NetSecurityScanner.Models;

namespace NetSecurityScanner.Views
{
  /// <summary>
  /// 摄像头扫描历史趋势窗口（v4-T5）
  /// 说明：使用纯代码方式构建 UI（避免 XAML 编译问题）。
  /// </summary>
  public class CameraTrendWindow : Window
  {
    private readonly CameraTrendService _service = new();
    private List<CameraTrendPoint> _currentPoints = new();

    // 控件引用
    private readonly ComboBox _rangeCombo = new();
    private readonly ComboBox _sessionCombo = new();
    private readonly TextBlock _statusText = new();
    private readonly LineChart _totalChart = new() { MinHeight = 160 };
    private readonly LineChart _onlineChart = new() { MinHeight = 160 };
    private readonly LineChart _vulnChart = new() { MinHeight = 160 };

    public CameraTrendWindow()
    {
      Title = "摄像头扫描历史趋势";
      Width = 900;
      Height = 700;
      WindowStartupLocation = WindowStartupLocation.CenterOwner;
      Background = Brushes.White;

      BuildUi();
      Loaded += (s, e) => Refresh();
    }

    private void BuildUi()
    {
      var root = new Grid { Margin = new Thickness(12) };
      root.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
      root.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
      root.RowDefinitions.Add(new RowDefinition { Height = new GridLength(1, GridUnitType.Star) });
      root.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });

      // 顶部工具栏
      var top = new StackPanel
      {
        Orientation = Orientation.Horizontal,
        Margin = new Thickness(0, 0, 0, 8)
      };
      top.Children.Add(new TextBlock
      {
        Text = "时间范围：",
        VerticalAlignment = VerticalAlignment.Center,
        Margin = new Thickness(0, 0, 6, 0)
      });
      _rangeCombo.MinWidth = 120;
      _rangeCombo.SelectionChanged += RangeCombo_SelectionChanged;
      top.Children.Add(_rangeCombo);
      top.Children.Add(new TextBlock
      {
        Text = "   会话：",
        VerticalAlignment = VerticalAlignment.Center,
        Margin = new Thickness(0, 0, 6, 0)
      });
      _sessionCombo.MinWidth = 240;
      _sessionCombo.SelectionChanged += SessionCombo_SelectionChanged;
      top.Children.Add(_sessionCombo);
      var refreshBtn = new Button
      {
        Content = "刷新",
        MinWidth = 80,
        Margin = new Thickness(8, 0, 0, 0),
        Padding = new Thickness(12, 4, 12, 4),
        Background = new SolidColorBrush(Color.FromRgb(0x25, 0x63, 0xEB)),
        Foreground = Brushes.White,
        BorderThickness = new Thickness(0),
        Cursor = System.Windows.Input.Cursors.Hand
      };
      refreshBtn.Click += Refresh_Click;
      top.Children.Add(refreshBtn);
      Grid.SetRow(top, 0);
      root.Children.Add(top);

      // 三张图表标题
      var headerPanel = new StackPanel
      {
        Orientation = Orientation.Horizontal,
        Margin = new Thickness(0, 0, 0, 6)
      };
      headerPanel.Children.Add(MakeTitleBlock("摄像头总数趋势", 0x25, 0x63, 0xEB));
      headerPanel.Children.Add(MakeTitleBlock("在线数量趋势", 0x10, 0xB9, 0x81));
      headerPanel.Children.Add(MakeTitleBlock("漏洞数量趋势", 0xEF, 0x44, 0x44));
      Grid.SetRow(headerPanel, 1);
      root.Children.Add(headerPanel);

      // 图表区
      var chartPanel = new Grid();
      chartPanel.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
      chartPanel.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(6) });
      chartPanel.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
      chartPanel.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(6) });
      chartPanel.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });

      // 给图表加边框便于展示
      var totalBox = new Border
      {
        BorderBrush = new SolidColorBrush(Color.FromRgb(0xE2, 0xE8, 0xF0)),
        BorderThickness = new Thickness(1),
        CornerRadius = new CornerRadius(4),
        Child = _totalChart,
        Padding = new Thickness(4)
      };
      Grid.SetColumn(totalBox, 0);
      chartPanel.Children.Add(totalBox);

      var onlineBox = new Border
      {
        BorderBrush = new SolidColorBrush(Color.FromRgb(0xE2, 0xE8, 0xF0)),
        BorderThickness = new Thickness(1),
        CornerRadius = new CornerRadius(4),
        Child = _onlineChart,
        Padding = new Thickness(4)
      };
      Grid.SetColumn(onlineBox, 2);
      chartPanel.Children.Add(onlineBox);

      var vulnBox = new Border
      {
        BorderBrush = new SolidColorBrush(Color.FromRgb(0xE2, 0xE8, 0xF0)),
        BorderThickness = new Thickness(1),
        CornerRadius = new CornerRadius(4),
        Child = _vulnChart,
        Padding = new Thickness(4)
      };
      Grid.SetColumn(vulnBox, 4);
      chartPanel.Children.Add(vulnBox);

      Grid.SetRow(chartPanel, 2);
      root.Children.Add(chartPanel);

      // 状态栏
      _statusText.Foreground = new SolidColorBrush(Color.FromRgb(0x64, 0x74, 0x8B));
      _statusText.FontSize = 12;
      _statusText.Margin = new Thickness(0, 8, 0, 0);
      Grid.SetRow(_statusText, 3);
      root.Children.Add(_statusText);

      Content = root;

      // 初始化时间范围下拉
      _rangeCombo.Items.Add(new ComboBoxItem { Content = "最近 7 天", Tag = "7" });
      _rangeCombo.Items.Add(new ComboBoxItem { Content = "最近 30 天", Tag = "30", IsSelected = true });
      _rangeCombo.Items.Add(new ComboBoxItem { Content = "最近 90 天", Tag = "90" });
      _rangeCombo.Items.Add(new ComboBoxItem { Content = "最近 365 天", Tag = "365" });
    }

    private static TextBlock MakeTitleBlock(string text, byte r, byte g, byte b)
    {
      return new TextBlock
      {
        Text = text,
        FontWeight = FontWeights.SemiBold,
        Foreground = new SolidColorBrush(Color.FromRgb(r, g, b)),
        Margin = new Thickness(0, 0, 12, 0),
        VerticalAlignment = VerticalAlignment.Center
      };
    }

    private int GetSelectedDays()
    {
      if (_rangeCombo.SelectedItem is ComboBoxItem item &&
          int.TryParse(item.Tag?.ToString(), out var d))
        return d;
      return 30;
    }

    private void Refresh()
    {
      try
      {
        // 加载会话列表
        var sessions = _service.ListRecentSessions(50);
        _sessionCombo.Items.Clear();
        _sessionCombo.Items.Add(new ComboBoxItem { Content = "（汇总视图）", IsSelected = true, Tag = "" });
        foreach (var s in sessions)
        {
          _sessionCombo.Items.Add(new ComboBoxItem { Content = s.Display, Tag = s.ScanId });
        }
        _sessionCombo.DisplayMemberPath = "Content";

        // 加载趋势
        var days = GetSelectedDays();
        _currentPoints = _service.GetTrend(days);
        RedrawCharts();
        _statusText.Text = $"显示最近 {days} 天，共 {_currentPoints.Count} 个数据点；DB：{_service.DbPath}";
      }
      catch (Exception ex)
      {
        _statusText.Text = $"加载失败: {ex.Message}";
      }
    }

    private void RedrawCharts()
    {
      var pts = _currentPoints ?? new List<CameraTrendPoint>();

      // Total
      _totalChart.SetSeries(new[]
      {
        new SeriesDefinition
        {
          Name = "总数",
          Color = Color.FromRgb(0x25, 0x63, 0xEB),
          Values = pts.Select(p => (p.Date, (double)p.Total)).ToList()
        }
      });

      // Online
      _onlineChart.SetSeries(new[]
      {
        new SeriesDefinition
        {
          Name = "在线",
          Color = Color.FromRgb(0x10, 0xB9, 0x81),
          Values = pts.Select(p => (p.Date, (double)p.Online)).ToList()
        }
      });

      // Vuln
      _vulnChart.SetSeries(new[]
      {
        new SeriesDefinition
        {
          Name = "漏洞",
          Color = Color.FromRgb(0xEF, 0x44, 0x44),
          Values = pts.Select(p => (p.Date, (double)p.VulnTotal)).ToList()
        }
      });
    }

    private void RangeCombo_SelectionChanged(object sender, SelectionChangedEventArgs e) => Refresh();

    private void SessionCombo_SelectionChanged(object sender, SelectionChangedEventArgs e)
    {
      if (_sessionCombo.SelectedItem is not ComboBoxItem item) return;
      var tag = item.Tag?.ToString() ?? string.Empty;
      if (string.IsNullOrEmpty(tag))
      {
        RedrawCharts();
        _statusText.Text = $"汇总视图：{_currentPoints.Count} 个聚合点";
        return;
      }
      var sessions = _service.ListRecentSessions(50);
      var s = sessions.FirstOrDefault(x => x.ScanId == tag);
      if (s == null) return;
      var single = new List<CameraTrendPoint>
      {
        new CameraTrendPoint
        {
          Date = s.ScanTime.Date,
          Total = s.Total,
          Online = s.Online,
          VulnTotal = s.VulnTotal
        }
      };
      _totalChart.SetSeries(new[] {
        new SeriesDefinition { Name = "总数", Color = Color.FromRgb(0x25, 0x63, 0xEB), Values = single.Select(p=>(p.Date,(double)p.Total)).ToList() }
      });
      _onlineChart.SetSeries(new[] {
        new SeriesDefinition { Name = "在线", Color = Color.FromRgb(0x10, 0xB9, 0x81), Values = single.Select(p=>(p.Date,(double)p.Online)).ToList() }
      });
      _vulnChart.SetSeries(new[] {
        new SeriesDefinition { Name = "漏洞", Color = Color.FromRgb(0xEF, 0x44, 0x44), Values = single.Select(p=>(p.Date,(double)p.VulnTotal)).ToList() }
      });
      _statusText.Text = $"单会话视图：{s.Display}";
    }

    private void Refresh_Click(object sender, RoutedEventArgs e) => Refresh();
  }
}
