#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# 读取文件
with open('MainWindow.xaml.cs', 'r', encoding='utf-8') as f:
    content = f.read()

# 注释掉 ApplySettingsToUI 方法体
old_apply = '''    private void ApplySettingsToUI()
    {
        // 应用扫描设置
        MaxConcurrency.Text = _appSettings.MaxConcurrency.ToString();
        ConnectionTimeout.Text = _appSettings.ConnectionTimeout.ToString();
        
        // 设置扫描速度
        foreach (ComboBoxItem item in SystemScanSpeed.Items)
        {
            if (item.Content.ToString() == _appSettings.DefaultScanSpeed)
            {
                SystemScanSpeed.SelectedItem = item;
                break;
            }
        }
        
        // 应用功能开关
        EnableAutoUpdate.IsChecked = _appSettings.EnableAutoUpdate;
        EnableAuditLog.IsChecked = _appSettings.EnableAuditLog;
        EnableProxy.IsChecked = _appSettings.EnableProxy;
        
        // 应用代理设置
        ProxyServer.Text = _appSettings.ProxyServer;
    }'''

new_apply = '''    private void ApplySettingsToUI()
    {
        // 应用扫描设置
        // MaxConcurrency.Text = _appSettings.MaxConcurrency.ToString();
        // ConnectionTimeout.Text = _appSettings.ConnectionTimeout.ToString();
        
        // 设置扫描速度
        // foreach (ComboBoxItem item in SystemScanSpeed.Items)
        // {
        //     if (item.Content.ToString() == _appSettings.DefaultScanSpeed)
        //     {
        //         SystemScanSpeed.SelectedItem = item;
        //         break;
        //     }
        // }
        
        // 应用功能开关
        // EnableAutoUpdate.IsChecked = _appSettings.EnableAutoUpdate;
        // EnableAuditLog.IsChecked = _appSettings.EnableAuditLog;
        // EnableProxy.IsChecked = _appSettings.EnableProxy;
        
        // 应用代理设置
        // ProxyServer.Text = _appSettings.ProxyServer;
    }'''

content = content.replace(old_apply, new_apply)

# 注释掉 CollectSettingsFromUI 方法体
old_collect = '''    private void CollectSettingsFromUI()
    {
        // 收集扫描设置
        if (int.TryParse(MaxConcurrency.Text, out int maxConcurrency))
            _appSettings.MaxConcurrency = maxConcurrency;
        
        if (int.TryParse(ConnectionTimeout.Text, out int connectionTimeout))
            _appSettings.ConnectionTimeout = connectionTimeout;'''

new_collect = '''    private void CollectSettingsFromUI()
    {
        // 收集扫描设置
        // if (int.TryParse(MaxConcurrency.Text, out int maxConcurrency))
        //     _appSettings.MaxConcurrency = maxConcurrency;
        
        // if (int.TryParse(ConnectionTimeout.Text, out int connectionTimeout))
        //     _appSettings.ConnectionTimeout = connectionTimeout;'''

content = content.replace(old_collect, new_collect)

# 保存文件
with open('MainWindow.xaml.cs', 'w', encoding='utf-8', newline='') as f:
    f.write(content)

print("CS file fixed successfully!")
