#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# 读取MainWindow.xaml
with open('MainWindow.xaml', 'r', encoding='utf-8') as f:
    content = f.read()

# 1. 添加MouseDoubleClick事件
old_datagrid = '''<DataGrid Name="VulnerabilityResultsDataGrid" Grid.Row="1" Margin="5" 
                              AutoGenerateColumns="False" CanUserAddRows="False"
                              GridLinesVisibility="All" HeadersVisibility="Column"
                              AlternatingRowBackground="#F5F5F5" IsReadOnly="True"
                              CanUserSortColumns="True" SelectionMode="Single"
                              CanUserResizeRows="False" RowHeight="35">'''
new_datagrid = '''<DataGrid Name="VulnerabilityResultsDataGrid" Grid.Row="1" Margin="5" 
                              AutoGenerateColumns="False" CanUserAddRows="False"
                              GridLinesVisibility="All" HeadersVisibility="Column"
                              AlternatingRowBackground="#F5F5F5" IsReadOnly="True"
                              CanUserSortColumns="True" SelectionMode="Single"
                              CanUserResizeRows="False" RowHeight="35"
                              MouseDoubleClick="VulnerabilityResultsDataGrid_MouseDoubleClick">'''
content = content.replace(old_datagrid, new_datagrid)

# 2. 添加查看详情菜单项
old_menu = '''<DataGrid.ContextMenu>
                            <ContextMenu>
                                <MenuItem Header="复制漏洞详情" Click="CopyVulnerabilityDetails_Click"/>'''
new_menu = '''<DataGrid.ContextMenu>
                            <ContextMenu>
                                <MenuItem Header="查看详情" Click="ViewVulnerabilityDetails_Click" FontWeight="Bold"/>
                                <Separator/>
                                <MenuItem Header="复制漏洞详情" Click="CopyVulnerabilityDetails_Click"/>'''
content = content.replace(old_menu, new_menu)

# 保存
with open('MainWindow.xaml', 'w', encoding='utf-8', newline='') as f:
    f.write(content)

print("MainWindow.xaml updated")
