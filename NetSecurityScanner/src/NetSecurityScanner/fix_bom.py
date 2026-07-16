#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import os

# 读取文件
with open('MainWindow.xaml', 'rb') as f:
    content = f.read()

# 移除BOM
if content.startswith(b'\xef\xbb\xbf'):
    content = content[3:]
    print("BOM removed")
else:
    print("No BOM found")

# 保存文件
with open('MainWindow.xaml', 'wb') as f:
    f.write(content)

print("File saved")
