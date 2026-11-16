# 更新日志 v1.0.3.4

发布日期：2026-11-16

## 概述

用户安装 nmap 7.993 后要求运行验证。排查过程中发现并修复了 **Nmap 引擎执行链路的
两个致命缺陷**——此前界面上的「用 Nmap 执行」即使检测到 nmap 也无法返回正确结果。
本版本修复后经全链路实测 PASS（真实检出开放端口），并把 nmap 工具随发布包分发。

## 修复明细

### 1. nmap 未接入应用检测路径（环境问题 → 已解决）

用户安装的 nmap 7.993 位于应用上层目录，而 `NmapEngineExecutor.LocateNmap()` 只查
应用目录 / `tools/nmap/` / `C:\Program Files\Nmap` / PATH。已将 nmap 完整文件集
（nmap.exe、数据文件、scripts、nselib、nse_main.lua）复制到发布目录的 `tools/nmap/`，
发布包现已自带 nmap，开箱即用。

### 2. `ScanAsync` 把展示用命令当执行参数（致命 bug）

`NmapCommandBuilder.Build()` 生成的是**给用户复制到终端看的命令**，末尾含
`<target>` 占位符、`-oJ "scan_scan_live.json"`、`--top-ports 1000` 等展示参数；
`ScanAsync` 直接拆词交给 nmap 执行，导致：nmap 把 `<target>` 当真实目标解析失败，
输出格式冲突，整次扫描返回 0 条结果。

**修复**：执行前按白名单剥离占位符与展示用参数（输出格式/端口默认值/排除项），
再以真实端口列表 `-p <ports>`、stdout XML `-oX -`、真实目标重组参数。

### 3. nmap 脚本引擎缺失 `nse_main.lua`

`-sV`（服务版本探测）会触发 NSE 脚本引擎，但复制到 tools 的文件集中漏了根目录的
`nse_main.lua`，nmap 报 `failed to initialize the script engine: could not locate nse_main.lua`
并退出（stderr 可见，stdout 有半截 XML）。已补齐。

## 验证过程与结果

| 步骤 | 结果 |
|---|---|
| nmap 定位 + 版本读取 | ✅ `tools\nmap\nmap.exe`，Nmap version 7.993 |
| 直接 nmap 扫描（对照） | ✅ 4 个端口状态正确 |
| 诊断参数污染 | ✅ 发现 `<target>` 占位符 + 输出参数冲突 |
| 修复后引擎扫描（全链路） | ✅ 4 条结果，临时监听端口正确标为「开放」 |
| 发布产物 | ✅ exe/Core.dll = 1.0.3.4，rust + nmap + 46 条漏洞库就位 |

## 交付物

| 文件/目录 | 说明 |
|---|---|
| `NetSecurityScanner/publish-v1.0.3.4/` | 主程序发布产物（自带 nmap 7.993、rust 引擎、46 条漏洞库） |
