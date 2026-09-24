#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# 读取文件
with open('MainWindow.xaml', 'r', encoding='utf-8') as f:
    content = f.read()

# 1. 修改序号列绑定: Id -> SequenceNumber
content = content.replace('Binding="{Binding Id}"', 'Binding="{Binding SequenceNumber}"')
content = content.replace('SortMemberPath="Id"', 'SortMemberPath="SequenceNumber"')

# 2. 修改风险等级绑定: RiskLevel -> Severity
content = content.replace('Binding="{Binding RiskLevel}"', 'Binding="{Binding Severity}"')
content = content.replace('SortMemberPath="RiskLevel"', 'SortMemberPath="Severity"')
content = content.replace('Binding="{Binding RiskLevel}" Value="严重"', 'Binding="{Binding Severity}" Value="严重"')
content = content.replace('Binding="{Binding RiskLevel}" Value="高"', 'Binding="{Binding Severity}" Value="高危"')
content = content.replace('Binding="{Binding RiskLevel}" Value="中"', 'Binding="{Binding Severity}" Value="中危"')
content = content.replace('Binding="{Binding RiskLevel}" Value="低"', 'Binding="{Binding Severity}" Value="低危"')

# 3. 修改服务绑定: Service -> ServiceName
content = content.replace('Binding="{Binding Service}"', 'Binding="{Binding ServiceName}"')
content = content.replace('SortMemberPath="Service"', 'SortMemberPath="ServiceName"')

# 4. 添加导出按钮
old_buttons = '''<Button Name="StartVulnScanButton" Content="开始漏洞扫描" Width="120" Height="25" Margin="5" Click="StartVulnScan_Click" Background="#3498DB" Foreground="White"/>
                            <Button Name="StopVulnScanButton" Content="停止扫描" Width="80" Height="25" Margin="5" Click="StopScan_Click" Background="#E74C3C" Foreground="White" IsEnabled="False"/>'''
new_buttons = '''<Button Name="StartVulnScanButton" Content="开始漏洞扫描" Width="120" Height="25" Margin="5" Click="StartVulnScan_Click" Background="#3498DB" Foreground="White"/>
                            <Button Name="StopVulnScanButton" Content="停止扫描" Width="80" Height="25" Margin="5" Click="StopScan_Click" Background="#E74C3C" Foreground="White" IsEnabled="False"/>
                            <Button Name="ExportVulnListButton" Content="导出列表" Width="80" Height="25" Margin="5" Click="ExportVulnerabilityList_Click" Background="#27AE60" Foreground="White"/>'''
content = content.replace(old_buttons, new_buttons)

# 5. 在序号列后添加目标IP列
old_after_id = '''</DataGridTextColumn>
                            <DataGridTextColumn Header="漏洞名称" Binding="{Binding Name}" Width="1.8*"'''
new_after_id = '''</DataGridTextColumn>
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
content = content.replace(old_after_id, new_after_id)

# 保存文件
with open('MainWindow.xaml', 'w', encoding='utf-8', newline='') as f:
    f.write(content)

print("XAML file updated successfully!")
