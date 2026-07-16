using System;
using System.Collections.Generic;
using System.Linq;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using NetSecurityScanner.Core;
using NetSecurityScanner.Models;

namespace NetSecurityScanner.Views
{
  /// <summary>
  /// 摄像头标签管理窗口（v4-T2）
  /// </summary>
  public partial class CameraTagManageWindow : Window
  {
    private readonly CameraTagService _tagService = new();
    private List<TagItem> _allTags = new();
    private string? _currentTagId;

    public CameraTagManageWindow()
    {
      InitializeComponent();
      Loaded += (s, e) => RefreshTagList();
    }

    private void RefreshTagList()
    {
      try
      {
        var tags = _tagService.GetAll();
        _allTags = tags.Select(t => new TagItem
        {
          TagId = t.TagId,
          Name = t.Name,
          Color = t.Color,
          Description = t.Description,
          IpCount = _tagService.GetIpsForTag(t.TagId).Count
        }).ToList();
        TagListView.ItemsSource = _allTags;
        StatusText.Text = $"共 {_allTags.Count} 个标签";
      }
      catch (Exception ex)
      {
        StatusText.Text = $"加载失败: {ex.Message}";
      }
    }

    private void TagListView_SelectionChanged(object sender, System.Windows.Controls.SelectionChangedEventArgs e)
    {
      if (TagListView.SelectedItem is TagItem item)
      {
        _currentTagId = item.TagId;
        CurrentTagTitle.Text = $"标签「{item.Name}」下的 IP";
        var ips = _tagService.GetIpsForTag(item.TagId);
        IpListView.ItemsSource = ips.ToList();
        StatusText.Text = $"标签 {item.Name} 已分配 {ips.Count} 个 IP";
      }
      else
      {
        _currentTagId = null;
        CurrentTagTitle.Text = "该标签下的 IP";
        IpListView.ItemsSource = null;
      }
    }

    private void NewTag_Click(object sender, RoutedEventArgs e)
    {
      var dlg = new TagEditDialog();
      if (dlg.ShowDialog() == true && dlg.ResultTag != null)
      {
        _tagService.Add(dlg.ResultTag);
        RefreshTagList();
        StatusText.Text = $"已新建标签 {dlg.ResultTag.Name}";
      }
    }

    private void EditTag_Click(object sender, RoutedEventArgs e)
    {
      if (TagListView.SelectedItem is not TagItem item)
      {
        MessageBox.Show("请先选择要编辑的标签", "提示", MessageBoxButton.OK, MessageBoxImage.Information);
        return;
      }
      var tag = _tagService.GetAll().FirstOrDefault(t => t.TagId == item.TagId);
      if (tag == null) return;
      var dlg = new TagEditDialog(tag);
      if (dlg.ShowDialog() == true && dlg.ResultTag != null)
      {
        _tagService.Update(dlg.ResultTag);
        RefreshTagList();
        StatusText.Text = $"已更新标签 {dlg.ResultTag.Name}";
      }
    }

    private void DeleteTag_Click(object sender, RoutedEventArgs e)
    {
      if (TagListView.SelectedItem is not TagItem item)
      {
        MessageBox.Show("请先选择要删除的标签", "提示", MessageBoxButton.OK, MessageBoxImage.Information);
        return;
      }
      var r = MessageBox.Show(
          $"确认删除标签「{item.Name}」？\n该标签下所有 IP 关联都会被清除。",
          "删除确认", MessageBoxButton.YesNo, MessageBoxImage.Warning);
      if (r == MessageBoxResult.Yes)
      {
        _tagService.Remove(item.TagId);
        RefreshTagList();
        IpListView.ItemsSource = null;
        _currentTagId = null;
        StatusText.Text = $"已删除标签 {item.Name}";
      }
    }

    private void AddIp_Click(object sender, RoutedEventArgs e)
    {
      if (string.IsNullOrWhiteSpace(_currentTagId))
      {
        MessageBox.Show("请先选择标签", "提示", MessageBoxButton.OK, MessageBoxImage.Information);
        return;
      }
      var ip = NewIpTextBox.Text.Trim();
      if (string.IsNullOrEmpty(ip))
      {
        MessageBox.Show("请输入 IP", "提示", MessageBoxButton.OK, MessageBoxImage.Information);
        return;
      }
      _tagService.Assign(ip, _currentTagId);
      NewIpTextBox.Clear();
      RefreshCurrentIps();
      StatusText.Text = $"已为标签分配 IP {ip}";
    }

    private void RemoveIp_Click(object sender, RoutedEventArgs e)
    {
      if (string.IsNullOrWhiteSpace(_currentTagId))
      {
        MessageBox.Show("请先选择标签", "提示", MessageBoxButton.OK, MessageBoxImage.Information);
        return;
      }
      var selected = IpListView.SelectedItems.Cast<string>().ToList();
      if (selected.Count == 0)
      {
        MessageBox.Show("请先选择要移除的 IP", "提示", MessageBoxButton.OK, MessageBoxImage.Information);
        return;
      }
      foreach (var ip in selected)
        _tagService.Unassign(ip, _currentTagId);
      RefreshCurrentIps();
      StatusText.Text = $"已移除 {selected.Count} 个 IP";
    }

    private void RefreshCurrentIps()
    {
      if (string.IsNullOrWhiteSpace(_currentTagId)) return;
      var ips = _tagService.GetIpsForTag(_currentTagId);
      IpListView.ItemsSource = ips.ToList();
      // 刷新左侧 IP 数量
      if (TagListView.SelectedItem is TagItem item) item.IpCount = ips.Count;
    }
  }

  /// <summary>
  /// 列表显示用的轻量 Tag 包装
  /// </summary>
  public class TagItem
  {
    public string TagId { get; set; } = string.Empty;
    public string Name { get; set; } = string.Empty;
    public string Color { get; set; } = "#3498DB";
    public string Description { get; set; } = string.Empty;
    public int IpCount { get; set; }
  }

  /// <summary>
  /// 简单的标签编辑弹窗（新建/编辑共用）
  /// </summary>
  internal class TagEditDialog : Window
  {
    public CameraTag? ResultTag { get; private set; }

    private readonly System.Windows.Controls.TextBox _nameBox = new() { Padding = new Thickness(6) };
    private readonly System.Windows.Controls.TextBox _colorBox = new() { Padding = new Thickness(6), Text = "#3498DB" };
    private readonly System.Windows.Controls.TextBox _descBox = new() { Padding = new Thickness(6) };

    public TagEditDialog(CameraTag? existing = null)
    {
      Title = existing == null ? "新建标签" : "编辑标签";
      Width = 380;
      Height = 260;
      WindowStartupLocation = WindowStartupLocation.CenterOwner;
      ResizeMode = ResizeMode.NoResize;
      Background = System.Windows.Media.Brushes.White;

      var grid = new System.Windows.Controls.Grid { Margin = new Thickness(15) };
      grid.RowDefinitions.Add(new System.Windows.Controls.RowDefinition { Height = GridLength.Auto });
      grid.RowDefinitions.Add(new System.Windows.Controls.RowDefinition { Height = GridLength.Auto });
      grid.RowDefinitions.Add(new System.Windows.Controls.RowDefinition { Height = GridLength.Auto });
      grid.RowDefinitions.Add(new System.Windows.Controls.RowDefinition { Height = GridLength.Auto });
      grid.RowDefinitions.Add(new System.Windows.Controls.RowDefinition { Height = new GridLength(1, GridUnitType.Star) });
      grid.RowDefinitions.Add(new System.Windows.Controls.RowDefinition { Height = GridLength.Auto });

      grid.Children.Add(MakeLabel("名称：", 0)); grid.Children.Add(MakeTextBox(_nameBox, 0));
      grid.Children.Add(MakeLabel("颜色（HEX）：", 1)); grid.Children.Add(MakeTextBox(_colorBox, 1));
      grid.Children.Add(MakeLabel("描述：", 2)); grid.Children.Add(MakeTextBox(_descBox, 2));

      var btnPanel = new System.Windows.Controls.StackPanel
      {
        Orientation = Orientation.Horizontal,
        HorizontalAlignment = HorizontalAlignment.Right
      };
      var ok = new System.Windows.Controls.Button
      {
        Content = "确定",
        MinWidth = 80,
        Margin = new Thickness(0, 0, 8, 0),
        Background = new System.Windows.Media.SolidColorBrush(System.Windows.Media.Color.FromRgb(0x25, 0x63, 0xEB)),
        Foreground = System.Windows.Media.Brushes.White,
        BorderThickness = new Thickness(0),
        Padding = new Thickness(15, 8, 15, 8),
        Cursor = System.Windows.Input.Cursors.Hand,
        IsDefault = true
      };
      ok.Click += (_, _) =>
      {
        if (string.IsNullOrWhiteSpace(_nameBox.Text))
        {
          MessageBox.Show("请输入标签名称", "提示", MessageBoxButton.OK, MessageBoxImage.Information);
          return;
        }
        ResultTag = existing ?? new CameraTag();
        ResultTag.Name = _nameBox.Text.Trim();
        ResultTag.Color = string.IsNullOrWhiteSpace(_colorBox.Text) ? "#3498DB" : _colorBox.Text.Trim();
        ResultTag.Description = _descBox.Text.Trim();
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
      btnPanel.Children.Add(ok);
      btnPanel.Children.Add(cancel);
      System.Windows.Controls.Grid.SetRow(btnPanel, 5);
      grid.Children.Add(btnPanel);

      if (existing != null)
      {
        _nameBox.Text = existing.Name;
        _colorBox.Text = existing.Color;
        _descBox.Text = existing.Description;
      }

      Content = grid;
    }

    private static System.Windows.Controls.TextBlock MakeLabel(string text, int row)
    {
      var lb = new System.Windows.Controls.TextBlock
      {
        Text = text,
        Margin = new Thickness(0, 6, 0, 4),
        Foreground = new System.Windows.Media.SolidColorBrush(System.Windows.Media.Color.FromRgb(0x33, 0x41, 0x55))
      };
      System.Windows.Controls.Grid.SetRow(lb, row * 2);
      return lb;
    }

    private static System.Windows.Controls.Border MakeTextBox(System.Windows.Controls.TextBox box, int row)
    {
      box.BorderBrush = new System.Windows.Media.SolidColorBrush(System.Windows.Media.Color.FromRgb(0xCB, 0xD5, 0xE1));
      var border = new System.Windows.Controls.Border
      {
        Child = box,
        BorderBrush = new System.Windows.Media.SolidColorBrush(System.Windows.Media.Color.FromRgb(0xCB, 0xD5, 0xE1)),
        BorderThickness = new Thickness(1)
      };
      System.Windows.Controls.Grid.SetRow(border, row * 2 + 1);
      return border;
    }
  }
}
