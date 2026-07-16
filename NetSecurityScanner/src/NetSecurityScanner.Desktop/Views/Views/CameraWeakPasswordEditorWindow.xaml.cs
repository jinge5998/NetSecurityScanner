using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using Microsoft.Win32;
using NetSecurityScanner.Core;

namespace NetSecurityScanner.Views
{
  /// <summary>
  /// 摄像头弱口令字典编辑器（v4-T4）
  /// 说明：使用纯代码方式构建 UI（避免 XAML 编译问题）。
  /// </summary>
  public class CameraWeakPasswordEditorWindow : Window
  {
    private readonly CameraWeakPasswordDictService _service = new();
    private List<PasswordItem> _items = new();

    // 控件引用
    private readonly CheckBox _builtInEnabledCheck = new();
    private readonly TextBlock _builtInCountText = new();
    private readonly TextBlock _customCountText = new();
    private readonly TextBlock _totalCountText = new();
    private readonly ListView _passwordList = new();
    private readonly TextBlock _statusText = new();

    public CameraWeakPasswordEditorWindow()
    {
      Title = "弱口令字典编辑";
      Width = 720;
      Height = 540;
      WindowStartupLocation = WindowStartupLocation.CenterOwner;
      Background = Brushes.White;

      BuildUi();
      Loaded += (s, e) => RefreshList();
    }

    private void BuildUi()
    {
      var root = new Grid { Margin = new Thickness(12) };
      root.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
      root.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
      root.RowDefinitions.Add(new RowDefinition { Height = new GridLength(1, GridUnitType.Star) });
      root.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
      root.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });

      // 顶部：内置开关 + 统计
      var topPanel = new StackPanel
      {
        Orientation = Orientation.Horizontal,
        Margin = new Thickness(0, 0, 0, 8)
      };
      _builtInEnabledCheck.Content = "启用内置字典";
      _builtInEnabledCheck.VerticalAlignment = VerticalAlignment.Center;
      _builtInEnabledCheck.Checked += BuiltInEnabled_Changed;
      _builtInEnabledCheck.Unchecked += BuiltInEnabled_Changed;
      topPanel.Children.Add(_builtInEnabledCheck);
      topPanel.Children.Add(new TextBlock
      {
        Text = "   内置：",
        Foreground = new SolidColorBrush(Color.FromRgb(0x64, 0x74, 0x8B)),
        VerticalAlignment = VerticalAlignment.Center
      });
      _builtInCountText.FontWeight = FontWeights.SemiBold;
      _builtInCountText.VerticalAlignment = VerticalAlignment.Center;
      topPanel.Children.Add(_builtInCountText);
      topPanel.Children.Add(new TextBlock
      {
        Text = "   自定义：",
        Foreground = new SolidColorBrush(Color.FromRgb(0x64, 0x74, 0x8B)),
        VerticalAlignment = VerticalAlignment.Center
      });
      _customCountText.FontWeight = FontWeights.SemiBold;
      _customCountText.VerticalAlignment = VerticalAlignment.Center;
      topPanel.Children.Add(_customCountText);
      topPanel.Children.Add(new TextBlock
      {
        Text = "   总计：",
        Foreground = new SolidColorBrush(Color.FromRgb(0x64, 0x74, 0x8B)),
        VerticalAlignment = VerticalAlignment.Center
      });
      _totalCountText.FontWeight = FontWeights.SemiBold;
      _totalCountText.Foreground = new SolidColorBrush(Color.FromRgb(0x25, 0x63, 0xEB));
      _totalCountText.VerticalAlignment = VerticalAlignment.Center;
      topPanel.Children.Add(_totalCountText);
      Grid.SetRow(topPanel, 0);
      root.Children.Add(topPanel);

      // 表头
      var header = new Border
      {
        Background = new SolidColorBrush(Color.FromRgb(0xF1, 0xF5, 0xF9)),
        BorderBrush = new SolidColorBrush(Color.FromRgb(0xE2, 0xE8, 0xF0)),
        BorderThickness = new Thickness(1, 1, 1, 0),
        Padding = new Thickness(8, 4, 8, 4)
      };
      var headerText = new TextBlock
      {
        Text = "口令列表（内置=蓝色，自定义=绿色；可多选后批量移除）",
        FontWeight = FontWeights.SemiBold,
        Foreground = new SolidColorBrush(Color.FromRgb(0x33, 0x41, 0x55))
      };
      header.Child = headerText;
      Grid.SetRow(header, 1);
      root.Children.Add(header);

      // 列表
      _passwordList.SelectionMode = SelectionMode.Extended;
      _passwordList.BorderBrush = new SolidColorBrush(Color.FromRgb(0xE2, 0xE8, 0xF0));
      _passwordList.BorderThickness = new Thickness(1);
      var gridView = new GridView();
      gridView.Columns.Add(new GridViewColumn
      {
        Header = "序号",
        DisplayMemberBinding = new System.Windows.Data.Binding("Index"),
        Width = 50
      });
      gridView.Columns.Add(new GridViewColumn
      {
        Header = "口令",
        DisplayMemberBinding = new System.Windows.Data.Binding("Value"),
        Width = 280
      });
      gridView.Columns.Add(new GridViewColumn
      {
        Header = "类型",
        DisplayMemberBinding = new System.Windows.Data.Binding("OriginText"),
        Width = 100
      });
      _passwordList.View = gridView;
      Grid.SetRow(_passwordList, 2);
      root.Children.Add(_passwordList);

      // 按钮
      var btnPanel = new StackPanel
      {
        Orientation = Orientation.Horizontal,
        Margin = new Thickness(0, 8, 0, 0)
      };
      btnPanel.Children.Add(MakeButton("添加", "#10B981", Add_Click));
      btnPanel.Children.Add(MakeButton("移除选中", "#EF4444", Remove_Click));
      btnPanel.Children.Add(MakeButton("清空自定义", "#F59E0B", Clear_Click));
      btnPanel.Children.Add(MakeButton("导入 TXT", "#3B82F6", Import_Click));
      btnPanel.Children.Add(MakeButton("导出 TXT", "#6366F1", Export_Click));
      Grid.SetRow(btnPanel, 3);
      root.Children.Add(btnPanel);

      // 状态
      _statusText.Foreground = new SolidColorBrush(Color.FromRgb(0x64, 0x74, 0x8B));
      _statusText.FontSize = 12;
      _statusText.Margin = new Thickness(0, 8, 0, 0);
      Grid.SetRow(_statusText, 4);
      root.Children.Add(_statusText);

      Content = root;
    }

    private static Button MakeButton(string text, string colorHex, RoutedEventHandler handler)
    {
      var b = new Button
      {
        Content = text,
        MinWidth = 90,
        Margin = new Thickness(0, 0, 8, 0),
        Padding = new Thickness(12, 6, 12, 6),
        Background = new SolidColorBrush((Color)System.Windows.Media.ColorConverter.ConvertFromString(colorHex)),
        Foreground = Brushes.White,
        BorderThickness = new Thickness(0),
        Cursor = System.Windows.Input.Cursors.Hand
      };
      b.Click += handler;
      return b;
    }

    private void RefreshList()
    {
      try
      {
        _builtInEnabledCheck.IsChecked = _service.BuiltInEnabled;
        _builtInCountText.Text = _service.BuiltInCount.ToString();
        _customCountText.Text = _service.CustomCount.ToString();
        _totalCountText.Text = _service.Count.ToString();

        var built = _service.BuiltInEnabled
            ? CameraWeakPasswordDictService.BuiltInPasswords.ToList()
            : new List<string>();
        var custom = _service.GetCustom().ToList();

        _items = built.Select(p => new PasswordItem { Value = p, IsCustom = false }).ToList();
        _items.AddRange(custom.Select(p => new PasswordItem { Value = p, IsCustom = true }));
        for (int i = 0; i < _items.Count; i++) _items[i].Index = i + 1;
        _passwordList.ItemsSource = null;
        _passwordList.ItemsSource = _items;
        _statusText.Text = $"当前共 {_items.Count} 条（内置 {built.Count} + 自定义 {custom.Count}）";
      }
      catch (Exception ex)
      {
        _statusText.Text = $"加载失败: {ex.Message}";
      }
    }

    private void BuiltInEnabled_Changed(object sender, RoutedEventArgs e)
    {
      _service.BuiltInEnabled = _builtInEnabledCheck.IsChecked == true;
      RefreshList();
    }

    private void Add_Click(object sender, RoutedEventArgs e)
    {
      var dlg = new PasswordInputDialog();
      if (dlg.ShowDialog() == true && !string.IsNullOrWhiteSpace(dlg.InputPassword))
      {
        if (_service.Add(dlg.InputPassword))
        {
          RefreshList();
          _statusText.Text = "已添加口令";
        }
        else
        {
          _statusText.Text = "已存在或无效，未添加";
        }
      }
    }

    private void Remove_Click(object sender, RoutedEventArgs e)
    {
      var sel = _passwordList.SelectedItems.Cast<PasswordItem>().ToList();
      if (sel.Count == 0)
      {
        MessageBox.Show("请先选择要移除的口令", "提示", MessageBoxButton.OK, MessageBoxImage.Information);
        return;
      }
      var customs = sel.Where(x => x.IsCustom).ToList();
      if (customs.Count == 0)
      {
        MessageBox.Show("内置字典条目不可移除；如需忽略请取消「启用内置字典」", "提示", MessageBoxButton.OK, MessageBoxImage.Information);
        return;
      }
      foreach (var p in customs) _service.Remove(p.Value);
      RefreshList();
      _statusText.Text = $"已移除 {customs.Count} 条自定义口令";
    }

    private void Clear_Click(object sender, RoutedEventArgs e)
    {
      if (_service.CustomCount == 0)
      {
        _statusText.Text = "没有自定义口令可清空";
        return;
      }
      var r = MessageBox.Show("确认清空所有自定义口令？此操作不可恢复。", "清空确认",
          MessageBoxButton.YesNo, MessageBoxImage.Warning);
      if (r == MessageBoxResult.Yes)
      {
        _service.Clear();
        RefreshList();
        _statusText.Text = "已清空自定义口令";
      }
    }

    private void Import_Click(object sender, RoutedEventArgs e)
    {
      var dlg = new OpenFileDialog
      {
        Filter = "文本文件 (*.txt)|*.txt|所有文件 (*.*)|*.*",
        Title = "选择要导入的弱口令文件"
      };
      if (dlg.ShowDialog(this) == true)
      {
        try
        {
          var n = _service.ImportTxt(dlg.FileName);
          RefreshList();
          _statusText.Text = $"已导入，新增 {n} 条";
        }
        catch (Exception ex)
        {
          MessageBox.Show($"导入失败: {ex.Message}", "错误", MessageBoxButton.OK, MessageBoxImage.Error);
        }
      }
    }

    private void Export_Click(object sender, RoutedEventArgs e)
    {
      var dlg = new SaveFileDialog
      {
        Filter = "文本文件 (*.txt)|*.txt",
        Title = "导出弱口令到文件",
        FileName = $"camera_weak_passwords_{DateTime.Now:yyyyMMdd_HHmmss}.txt"
      };
      if (dlg.ShowDialog(this) == true)
      {
        try
        {
          var n = _service.ExportTxt(dlg.FileName);
          _statusText.Text = $"已导出 {n} 条到 {Path.GetFileName(dlg.FileName)}";
        }
        catch (Exception ex)
        {
          MessageBox.Show($"导出失败: {ex.Message}", "错误", MessageBoxButton.OK, MessageBoxImage.Error);
        }
      }
    }
  }

  /// <summary>列表显示条目</summary>
  public class PasswordItem
  {
    public int Index { get; set; }
    public string Value { get; set; } = string.Empty;
    public bool IsCustom { get; set; }
    public string OriginText => IsCustom ? "自定义" : "内置";
    public string OriginColor => IsCustom ? "#10B981" : "#2563EB";
  }

  /// <summary>简单的口令输入弹窗（纯代码 UI）</summary>
  internal class PasswordInputDialog : Window
  {
    public string InputPassword { get; private set; } = string.Empty;

    public PasswordInputDialog()
    {
      Title = "添加弱口令";
      Width = 360;
      Height = 180;
      WindowStartupLocation = WindowStartupLocation.CenterOwner;
      ResizeMode = ResizeMode.NoResize;
      Background = System.Windows.Media.Brushes.White;

      var grid = new System.Windows.Controls.Grid { Margin = new Thickness(15) };
      grid.RowDefinitions.Add(new System.Windows.Controls.RowDefinition { Height = GridLength.Auto });
      grid.RowDefinitions.Add(new System.Windows.Controls.RowDefinition { Height = GridLength.Auto });
      grid.RowDefinitions.Add(new System.Windows.Controls.RowDefinition { Height = new GridLength(1, GridUnitType.Star) });
      grid.RowDefinitions.Add(new System.Windows.Controls.RowDefinition { Height = GridLength.Auto });

      var label = new System.Windows.Controls.TextBlock
      {
        Text = "请输入要添加的弱口令：",
        FontSize = 13,
        Foreground = new System.Windows.Media.SolidColorBrush(System.Windows.Media.Color.FromRgb(0x33, 0x41, 0x55))
      };
      System.Windows.Controls.Grid.SetRow(label, 0);
      grid.Children.Add(label);

      var box = new System.Windows.Controls.TextBox
      {
        Padding = new Thickness(6),
        FontSize = 13,
        FontFamily = new System.Windows.Media.FontFamily("Consolas, Courier New")
      };
      var border = new System.Windows.Controls.Border
      {
        Child = box,
        BorderBrush = new System.Windows.Media.SolidColorBrush(System.Windows.Media.Color.FromRgb(0xCB, 0xD5, 0xE1)),
        BorderThickness = new Thickness(1),
        Margin = new Thickness(0, 6, 0, 0)
      };
      System.Windows.Controls.Grid.SetRow(border, 1);
      grid.Children.Add(border);

      var panel = new System.Windows.Controls.StackPanel
      {
        Orientation = Orientation.Horizontal,
        HorizontalAlignment = HorizontalAlignment.Right
      };
      var ok = new System.Windows.Controls.Button
      {
        Content = "确定",
        MinWidth = 80,
        Margin = new Thickness(0, 0, 8, 0),
        Background = new System.Windows.Media.SolidColorBrush(System.Windows.Media.Color.FromRgb(0x10, 0xB9, 0x81)),
        Foreground = System.Windows.Media.Brushes.White,
        BorderThickness = new Thickness(0),
        Padding = new Thickness(15, 8, 15, 8),
        Cursor = System.Windows.Input.Cursors.Hand,
        IsDefault = true
      };
      ok.Click += (_, _) =>
      {
        InputPassword = box.Text.Trim();
        DialogResult = true;
        Close();
      };
      var cancel = new System.Windows.Controls.Button
      {
        Content = "取消",
        MinWidth = 80,
        Background = new System.Windows.Media.SolidColorBrush(System.Windows.Media.Color.FromRgb(0xCB, 0xD5, 0xE1)),
        Foreground = System.Windows.Media.Brushes.White,
        BorderThickness = new Thickness(0),
        Padding = new Thickness(15, 8, 15, 8),
        Cursor = System.Windows.Input.Cursors.Hand,
        IsCancel = true
      };
      panel.Children.Add(ok);
      panel.Children.Add(cancel);
      System.Windows.Controls.Grid.SetRow(panel, 3);
      grid.Children.Add(panel);

      Content = grid;
      Loaded += (s, e) => box.Focus();
    }
  }
}
