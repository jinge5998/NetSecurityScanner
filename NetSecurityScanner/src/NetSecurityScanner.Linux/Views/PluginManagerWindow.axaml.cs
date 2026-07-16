using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Avalonia;
using Avalonia.Controls;
using Avalonia.Diagnostics;
using Avalonia.Interactivity;
using NetSecurityScanner.Plugins;

namespace NetSecurityScanner.Views;

public partial class PluginManagerWindow : Window
{
    private PluginManager? _pluginManager;
    
    public PluginManagerWindow()
    {
        InitializeComponent();
#if DEBUG
        this.AttachDevTools();
#endif
        Loaded += OnLoaded;
    }
    
    private async void OnLoaded(object? sender, EventArgs e)
    {
        _pluginManager = new PluginManager();
        
        var refreshBtn = this.FindControl<Button>("RefreshButton");
        var closeBtn = this.FindControl<Button>("CloseButton");
        
        if (refreshBtn != null) refreshBtn.Click += Refresh_Click;
        if (closeBtn != null) closeBtn.Click += (_, _) => Close();
        
        await _pluginManager.LoadAllPluginsAsync();
        LoadPlugins();
    }
    
    private void LoadPlugins()
    {
        var grid = this.FindControl<DataGrid>("PluginsDataGrid");
        if (grid == null || _pluginManager == null) return;
        
        var plugins = _pluginManager.Plugins.Values.ToList();
        grid.ItemsSource = plugins.Select(p => new
        {
            Name = p.Name,
            Version = p.Version,
            Description = p.Description,
            Author = p.Author,
            IsEnabled = true
        }).ToList();
    }
    
    private async void Refresh_Click(object? sender, RoutedEventArgs e)
    {
        if (_pluginManager != null)
            await _pluginManager.LoadAllPluginsAsync();
        LoadPlugins();
    }
    
    private async Task ShowMessageAsync(string message, string title)
    {
        var dialog = new Window { Title = title, Width = 420, Height = 180, WindowStartupLocation = WindowStartupLocation.CenterOwner };
        var panel = new StackPanel { Margin = new Thickness(20) };
        panel.Children.Add(new TextBlock { Text = message, TextWrapping = Avalonia.Media.TextWrapping.Wrap });
        var btn = new Button { Content = "确定", HorizontalAlignment = Avalonia.Layout.HorizontalAlignment.Right, Margin = new Thickness(0,15,0,0) };
        btn.Click += (_, _) => dialog.Close();
        panel.Children.Add(btn);
        dialog.Content = panel;
        await dialog.ShowDialog(this);
    }
}
