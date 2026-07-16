#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import re

# 读取文件
with open('MainWindow.xaml', 'r', encoding='utf-8') as f:
    content = f.read()

# 1. 修改漏洞列表的序号列绑定
old_id_column = '''<DataGridTextColumn Header="序号" Binding="{Binding Id}" Width="0.6*" 
                                                SortMemberPath="Id">'''
new_id_column = '''<DataGridTextColumn Header="序号" Binding="{Binding SequenceNumber}" Width="0.5*"
                                                SortMemberPath="SequenceNumber">'''
content = content.replace(old_id_column, new_id_column)

# 2. 在序号列后添加目标IP列
old_name_column = '''</DataGridTextColumn>
                            <DataGridTextColumn Header="漏洞名称" Binding="{Binding Name}" Width="1.8*"'''
new_name_column = '''</DataGridTextColumn>
                            <DataGridTextColumn Header="目标IP" Binding="{Binding Host}" Width="1.0*"
                                                SortMemberPath="Host">
                                <DataGridTextColumn.ElementStyle>
                                    <Style TargetType="TextBlock">
                                        <Setter Property="VerticalAlignment" Value="Center"/>
                                        <Setter Property="HorizontalAlignment" Value="Center"/>
                                    </Style>
                                </DataGridTextColumn.ElementStyle>
                            </DataGridTextColumn>
                            <DataGridTextColumn Header="漏洞名称" Binding="{Binding Name}" Width="1.6*"'''
content = content.replace(old_name_column, new_name_column)

# 3. 添加导出按钮
old_buttons = '''<Button Name="StartVulnScanButton" Content="开始漏洞扫描" Width="120" Height="25" Margin="5" Click="StartVulnScan_Click" Background="#3498DB" Foreground="White"/>
                            <Button Name="StopVulnScanButton" Content="停止扫描" Width="80" Height="25" Margin="5" Click="StopScan_Click" Background="#E74C3C" Foreground="White" IsEnabled="False"/>'''
new_buttons = '''<Button Name="StartVulnScanButton" Content="开始漏洞扫描" Width="120" Height="25" Margin="5" Click="StartVulnScan_Click" Background="#3498DB" Foreground="White"/>
                            <Button Name="StopVulnScanButton" Content="停止扫描" Width="80" Height="25" Margin="5" Click="StopScan_Click" Background="#E74C3C" Foreground="White" IsEnabled="False"/>
                            <Button Name="ExportVulnListButton" Content="导出列表" Width="80" Height="25" Margin="5" Click="ExportVulnerabilityList_Click" Background="#27AE60" Foreground="White"/>'''
content = content.replace(old_buttons, new_buttons)

# 保存文件
with open('MainWindow.xaml', 'w', encoding='utf-8', newline='') as f:
    f.write(content)

print("XAML file updated successfully!")
