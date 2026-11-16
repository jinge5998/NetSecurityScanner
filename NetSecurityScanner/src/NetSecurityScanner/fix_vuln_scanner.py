#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import re

# 读取文件
with open('Services/VulnerabilityScanner.cs', 'r', encoding='utf-8') as f:
    content = f.read()

# 修复第58行的问题 - 将乱码替换为正确的代码
# 查找并替换乱码部分
old_pattern = r'_httpClient\.DefaultRequestHeaders\.Add\("User-Agent", "NetSecurityScanner/1\.0"\);\s*\}\s*//.*并发控制.*\n\s*private readonly SemaphoreSlim _scanSemaphore'
new_text = '''_httpClient.DefaultRequestHeaders.Add("User-Agent", "NetSecurityScanner/1.0");
        }

        // 并发控制 - 增加并发度以提高扫描效率
        private readonly SemaphoreSlim _scanSemaphore'''

content = re.sub(old_pattern, new_text, content)

# 修复其他乱码注释
content = re.sub(r'// 绾跨▼瀹夊叏鐨勬棩蹇楄褰曢攣', '// 线程安全的日志记录锁', content)
content = re.sub(r'// 淇濇姢_vulnerabilityDatabase鐨勫苟鍙戣闂攣', '// 保护_vulnerabilityDatabase的并发访问锁', content)
content = re.sub(r'// 鍒濆骞跺彂搴?0锛屾渶澶?0', '// 初始并发度10，最大20', content)
content = re.sub(r'// 绔彛鎵弿骞跺彂搴?锛屾渶澶?0', '// 端口扫描并发度5，最大10', content)
content = re.sub(r'// Web鎵弿骞跺彂搴?锛屾渶澶?', '// Web扫描并发度3，最大5', content)
content = re.sub(r'// SQL鎵弿骞跺彂搴?锛屾渶澶?', '// SQL扫描并发度3，最大5', content)

# 保存文件
with open('Services/VulnerabilityScanner.cs', 'w', encoding='utf-8', newline='') as f:
    f.write(content)

print("VulnerabilityScanner.cs fixed!")
