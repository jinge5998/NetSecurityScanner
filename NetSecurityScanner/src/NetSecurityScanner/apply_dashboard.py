#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# 读取MainWindow.xaml
with open('MainWindow.xaml', 'r', encoding='utf-8') as f:
    content = f.read()

# 1. 添加仪表盘首页（在端口扫描之前）
dashboard_xaml = '''        <!-- 主内容区域 -->
        <TabControl Grid.Row="1" Margin="10">
            <!-- 仪表盘首页 -->
            <TabItem Header="首页">
                <ScrollViewer VerticalScrollBarVisibility="Auto">
                    <Grid Margin="20">
                        <Grid.RowDefinitions>
                            <RowDefinition Height="Auto"/>
                            <RowDefinition Height="Auto"/>
                            <RowDefinition Height="Auto"/>
                            <RowDefinition Height="Auto"/>
                            <RowDefinition Height="*"/>
                        </Grid.RowDefinitions>
                        
                        <!-- 欢迎标题 -->
                        <Border Grid.Row="0" Background="#3498DB" CornerRadius="10" Padding="30" Margin="0,0,0,20">
                            <StackPanel>
                                <TextBlock Text="欢迎使用网络安全漏洞扫描工具" FontSize="28" FontWeight="Bold" Foreground="White" HorizontalAlignment="Center"/>
                                <TextBlock Text="全面检测系统安全，防范网络威胁" FontSize="14" Foreground="#ECF0F1" HorizontalAlignment="Center" Margin="0,10,0,0"/>
                            </StackPanel>
                        </Border>
                        
                        <!-- 统计卡片区域 -->
                        <UniformGrid Grid.Row="1" Columns="4" Margin="0,0,0,20">
                            <!-- 总扫描次数 -->
                            <Border Background="White" BorderBrush="#E0E0E0" BorderThickness="1" CornerRadius="8" Margin="5" Padding="20">
                                <StackPanel HorizontalAlignment="Center">
                                    <TextBlock Text="&#xE9D9;" FontFamily="Segoe UI Symbol" FontSize="36" Foreground="#3498DB" HorizontalAlignment="Center"/>
                                    <TextBlock Name="DashboardTotalScansText" Text="0" FontSize="32" FontWeight="Bold" Foreground="#2C3E50" HorizontalAlignment="Center" Margin="0,10"/>
                                    <TextBlock Text="总扫描次数" FontSize="14" Foreground="#7F8C8D" HorizontalAlignment="Center"/>
                                </StackPanel>
                            </Border>
                            
                            <!-- 发现漏洞数 -->
                            <Border Background="White" BorderBrush="#E0E0E0" BorderThickness="1" CornerRadius="8" Margin="5" Padding="20">
                                <StackPanel HorizontalAlignment="Center">
                                    <TextBlock Text="&#xE7BA;" FontFamily="Segoe UI Symbol" FontSize="36" Foreground="#E74C3C" HorizontalAlignment="Center"/>
                                    <TextBlock Name="DashboardTotalVulnsText" Text="0" FontSize="32" FontWeight="Bold" Foreground="#2C3E50" HorizontalAlignment="Center" Margin="0,10"/>
                                    <TextBlock Text="发现漏洞数" FontSize="14" Foreground="#7F8C8D" HorizontalAlignment="Center"/>
                                </StackPanel>
                            </Border>
                            
                            <!-- 高危漏洞 -->
                            <Border Background="White" BorderBrush="#E0E0E0" BorderThickness="1" CornerRadius="8" Margin="5" Padding="20">
                                <StackPanel HorizontalAlignment="Center">
                                    <TextBlock Text="&#xE71C;" FontFamily="Segoe UI Symbol" FontSize="36" Foreground="#F39C12" HorizontalAlignment="Center"/>
                                    <TextBlock Name="DashboardHighRiskText" Text="0" FontSize="32" FontWeight="Bold" Foreground="#2C3E50" HorizontalAlignment="Center" Margin="0,10"/>
                                    <TextBlock Text="高危漏洞" FontSize="14" Foreground="#7F8C8D" HorizontalAlignment="Center"/>
                                </StackPanel>
                            </Border>
                            
                            <!-- 已修复漏洞 -->
                            <Border Background="White" BorderBrush="#E0E0E0" BorderThickness="1" CornerRadius="8" Margin="5" Padding="20">
                                <StackPanel HorizontalAlignment="Center">
                                    <TextBlock Text="&#xE930;" FontFamily="Segoe UI Symbol" FontSize="36" Foreground="#27AE60" HorizontalAlignment="Center"/>
                                    <TextBlock Name="DashboardResolvedText" Text="0" FontSize="32" FontWeight="Bold" Foreground="#2C3E50" HorizontalAlignment="Center" Margin="0,10"/>
                                    <TextBlock Text="已修复漏洞" FontSize="14" Foreground="#7F8C8D" HorizontalAlignment="Center"/>
                                </StackPanel>
                            </Border>
                        </UniformGrid>
                        
                        <!-- 快速操作按钮 -->
                        <Border Grid.Row="2" Background="#F8F9FA" BorderBrush="#E9ECEF" BorderThickness="1" CornerRadius="8" Padding="20" Margin="0,0,0,20">
                            <StackPanel>
                                <TextBlock Text="快速操作" FontSize="18" FontWeight="Bold" Foreground="#2C3E50" Margin="0,0,0,15"/>
                                <StackPanel Orientation="Horizontal" HorizontalAlignment="Center">
                                    <Button Name="QuickPortScanButton" Content="端口扫描" Width="120" Height="40" Margin="10" 
                                            Background="#3498DB" Foreground="White" FontSize="14" Click="QuickPortScanButton_Click"/>
                                    <Button Name="QuickVulnScanButton" Content="漏洞扫描" Width="120" Height="40" Margin="10" 
                                            Background="#E74C3C" Foreground="White" FontSize="14" Click="QuickVulnScanButton_Click"/>
                                    <Button Name="QuickReportButton" Content="生成报告" Width="120" Height="40" Margin="10" 
                                            Background="#27AE60" Foreground="White" FontSize="14" Click="QuickGenerateReportButton_Click"/>
                                    <Button Name="QuickHistoryButton" Content="查看历史" Width="120" Height="40" Margin="10" 
                                            Background="#9B59B6" Foreground="White" FontSize="14" Click="QuickViewHistoryButton_Click"/>
                                </StackPanel>
                            </StackPanel>
                        </Border>
                        
                        <!-- 最近扫描记录 -->
                        <Border Grid.Row="3" Background="White" BorderBrush="#E0E0E0" BorderThickness="1" CornerRadius="8" Padding="20" Margin="0,0,0,20">
                            <Grid>
                                <Grid.RowDefinitions>
                                    <RowDefinition Height="Auto"/>
                                    <RowDefinition Height="*"/>
                                </Grid.RowDefinitions>
                                
                                <StackPanel Grid.Row="0" Orientation="Horizontal" Margin="0,0,0,10">
                                    <TextBlock Text="最近扫描记录" FontSize="18" FontWeight="Bold" Foreground="#2C3E50" VerticalAlignment="Center"/>
                                    <Button Name="RefreshDashboardButton" Content="刷新" Width="60" Height="25" Margin="20,0,0,0" 
                                            Background="Transparent" BorderBrush="#3498DB" BorderThickness="1" Foreground="#3498DB"
                                            Click="RefreshDashboardButton_Click"/>
                                </StackPanel>
                                
                                <DataGrid Name="RecentScansDataGrid" Grid.Row="1" AutoGenerateColumns="False" 
                                          CanUserAddRows="False" IsReadOnly="True" GridLinesVisibility="Horizontal"
                                          HeadersVisibility="Column" Height="200">
                                    <DataGrid.Columns>
                                        <DataGridTextColumn Header="时间" Binding="{Binding ScanTime, StringFormat={}{0:yyyy-MM-dd HH:mm}}" Width="140"/>
                                        <DataGridTextColumn Header="目标" Binding="{Binding Target}" Width="150"/>
                                        <DataGridTextColumn Header="类型" Binding="{Binding ScanType}" Width="100"/>
                                        <DataGridTextColumn Header="状态" Binding="{Binding Status}" Width="80"/>
                                        <DataGridTextColumn Header="漏洞数" Binding="{Binding VulnerabilityCount}" Width="80"/>
                                        <DataGridTextColumn Header="耗时" Binding="{Binding Duration}" Width="80"/>
                                    </DataGrid.Columns>
                                </DataGrid>
                            </Grid>
                        </Border>
                        
                        <!-- 系统状态 -->
                        <Border Grid.Row="4" Background="White" BorderBrush="#E0E0E0" BorderThickness="1" CornerRadius="8" Padding="20">
                            <Grid>
                                <Grid.ColumnDefinitions>
                                    <ColumnDefinition Width="*"/>
                                    <ColumnDefinition Width="*"/>
                                </Grid.ColumnDefinitions>
                                
                                <StackPanel Grid.Column="0">
                                    <TextBlock Text="系统状态" FontSize="16" FontWeight="Bold" Foreground="#2C3E50" Margin="0,0,0,10"/>
                                    <StackPanel Orientation="Horizontal" Margin="0,5">
                                        <TextBlock Text="数据库状态：" FontSize="13" Foreground="#7F8C8D"/>
                                        <TextBlock Name="DatabaseStatusText" Text="正常" FontSize="13" Foreground="#27AE60" FontWeight="SemiBold"/>
                                    </StackPanel>
                                    <StackPanel Orientation="Horizontal" Margin="0,5">
                                        <TextBlock Text="漏洞库版本：" FontSize="13" Foreground="#7F8C8D"/>
                                        <TextBlock Name="VulnDbVersionText" Text="2024.02.01" FontSize="13" Foreground="#2C3E50"/>
                                    </StackPanel>
                                    <StackPanel Orientation="Horizontal" Margin="0,5">
                                        <TextBlock Text="最后更新：" FontSize="13" Foreground="#7F8C8D"/>
                                        <TextBlock Name="LastUpdateText" Text="2024-02-01" FontSize="13" Foreground="#2C3E50"/>
                                    </StackPanel>
                                </StackPanel>
                                
                                <StackPanel Grid.Column="1">
                                    <TextBlock Text="扫描能力" FontSize="16" FontWeight="Bold" Foreground="#2C3E50" Margin="0,0,0,10"/>
                                    <StackPanel Orientation="Horizontal" Margin="0,5">
                                        <TextBlock Text="支持端口数：" FontSize="13" Foreground="#7F8C8D"/>
                                        <TextBlock Text="65,535" FontSize="13" Foreground="#2C3E50"/>
                                    </StackPanel>
                                    <StackPanel Orientation="Horizontal" Margin="0,5">
                                        <TextBlock Text="漏洞检测规则：" FontSize="13" Foreground="#7F8C8D"/>
                                        <TextBlock Text="1,200+" FontSize="13" Foreground="#2C3E50"/>
                                    </StackPanel>
                                    <StackPanel Orientation="Horizontal" Margin="0,5">
                                        <TextBlock Text="CVE覆盖：" FontSize="13" Foreground="#7F8C8D"/>
                                        <TextBlock Text="180,000+" FontSize="13" Foreground="#2C3E50"/>
                                    </StackPanel>
                                </StackPanel>
                            </Grid>
                        </Border>
                    </Grid>
                </ScrollViewer>
            </TabItem>
            
            <!-- 端口扫描 -->
            <TabItem Header="端口扫描">'''

content = content.replace(
    '''        <!-- 主内容区域 -->
        <TabControl Grid.Row="1" Margin="10">
                        <!-- 端口扫描 -->
            <TabItem Header="端口扫描">''',
    dashboard_xaml
)

# 保存
with open('MainWindow.xaml', 'w', encoding='utf-8', newline='') as f:
    f.write(content)

print("MainWindow.xaml updated with dashboard")
