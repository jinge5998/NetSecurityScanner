#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# 读取文件
with open('MainWindow.xaml', 'r', encoding='utf-8') as f:
    content = f.read()

# 移除utils命名空间引用
content = content.replace('        xmlns:utils="clr-namespace:NetSecurityScanner.Utils"\n', '')

# 替换utils:RiskLevelToColorConverter为本地转换器
content = content.replace('<utils:RiskLevelToColorConverter x:Key="RiskLevelToColorConverter"/>', '')
content = content.replace('CellStyle="{StaticResource RiskLevelCellStyle}"', '')

# 保存文件
with open('MainWindow.xaml', 'w', encoding='utf-8', newline='') as f:
    f.write(content)

print("XAML file fixed successfully!")
