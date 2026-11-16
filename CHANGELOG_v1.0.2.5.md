# 更新日志 v1.0.2.5

发布日期：2026-11-15

## 概述

本版本继续完善专家模式：修复 Rust 引擎路径的服务检测配置缺口、清理漏洞扫描判定死代码、
并为高级选项页补充能力边界说明（消除"勾选了却无效"的能力误导）。

## 主要变更

### 1. Rust 引擎路径接入统一配置映射（修复服务检测配置缺口）

`ExecuteRustScanAsync` 原先手工构造 `ScanProfileConfig`，只填了 8 个字段，
`ServiceIntensity`（服务检测强度）与 `ServiceDetectTimeoutMs`（服务识别超时）被漏掉——
这两项界面对 Rust 引擎路径完全无效；而 `ScanConfigMapper.ToScanProfileConfig` 已含完整映射，
却只在契约测试中被调用，生产路径从未使用。

现改为统一走 `ScanConfigMapper`，服务识别强度（0-9 档）与识别超时对 Rust 通道正确下发。
以后新增可下发字段只需改 Mapper 一处，不会再出现界面与引擎两侧漂移。

### 2. 漏洞扫描判定死代码清理

`ExecuteExpertScanAsync` 中存在恒不可达的 `else if (!config.ScriptScan && !config.ServiceDetection)`
分支（`shouldRunVulnScan = openPorts.Any()` 与前两个分支互补且穷尽），已删除并留注释说明。
行为不变：只要有开放端口就执行漏洞库匹配，`ScriptScan` 勾选与否不影响该判定。

### 3. 高级选项页能力边界说明（消除能力误导）

9 月完善度检查报告指出的系统性缺陷：约 9 个原始套接字类选项（源端口/MTU/分片/错误校验和/
诱饵扫描/Idle 僵尸/源路由）勾选后只影响 Nmap 命令文本生成，对程序自身扫描无任何影响，
且界面此前**零提示**。

现已在「高级选项」页三个分组顶部添加说明框，明确标注哪些选项仅用于生成 Nmap 命令
（供复制到已安装 nmap 的终端执行）、哪些对本程序真实生效：

| 分组 | 仅生成 Nmap 命令 | 本程序真实生效 |
|---|---|---|
| 数据包选项 | 源端口、MTU、数据包分片、错误校验和 | 随机化目标顺序、Stealth 模式 |
| 防火墙/IDS 规避 | 诱饵扫描、Idle 僵尸扫描、源路由 | 仅显示开放端口 |
| 输出控制 | 日志级别（Tooltip 标注） | 输出格式（JSON/HTML/CSV 自动保存） |

原始套接字类选项原理上无法用纯 TCP 连接扫描实现（`NmapCommandBuilder.cs` 注释已说明），
保留命令生成能力作为参考输出是最合理的处置。

### 4. 配置澄清

- `ShowOpenOnly`（仅显示开放端口）：经核实**已真实接线**（勾选即过滤实时结果表），非误报项
- `ServiceDetectTimeout`：v1.0.2.3 迭代已接入内置 C# 引擎的 banner 探测，本版本补齐 Rust 通道

## 质量验证

| 门禁 | 结果 |
|---|---|
| 全解决方案 `dotnet build` | 0 错误 |
| NetSecurityScanner.Core.Tests（含专家模式生效性契约测试 24 条） | **248/248 通过** |
| NetSecurityScanner.Tests | **10/10 通过** |
| 发布产物版本核对 | exe / Core.dll = 1.0.2.5，rust 引擎与 46 条漏洞库就位 |
| 启动冒烟 | `OnStartup completed successfully`，无异常 |

## 升级方式

`publish-v1.0.2.5/` 为最新发布目录，直接运行其中的 `NetSecurityScanner.Desktop.exe`。
配置文件与扫描历史向后兼容，无需迁移。

## 交付物

| 文件/目录 | 说明 |
|---|---|
| `NetSecurityScanner/publish-v1.0.2.5/` | 主程序发布产物（含 rust-scanner-service.exe、46 条漏洞库） |
