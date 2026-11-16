#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# 读取文件
with open('MainWindow.xaml', 'r', encoding='utf-8') as f:
    content = f.read()

# 修改SequenceNumber绑定（不需要SortMemberPath，因为是字符串）
content = content.replace('SortMemberPath="SequenceNumber"', 'SortMemberPath="Id"')

# 保存文件
with open('MainWindow.xaml', 'w', encoding='utf-8', newline='') as f:
    f.write(content)

print("XAML binding fixed!")
