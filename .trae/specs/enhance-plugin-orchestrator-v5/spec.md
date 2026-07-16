# 插件库统一调度器 v5 Spec

## Why
v4 已完成核心集成（启用/禁用、统一目录、卸载 DLL、综合扫描调用、4 个内置插件真实网络检测、商店 UI、执行日志、沙箱），但插件调用入口单一：仅在综合扫描完成时由 `MainWindow.xaml.cs:1510` 创建 `new PluginManager()` 一次性调用 `ScanWithPluginsForTargetAsync`。每次扫描都要重新 `LoadAllPluginsAsync`，且用户无法：
- 手动选择目标 + 目标端口 + 适用插件组合运行
- 对历史扫描结果"深挖"（用所有适用插件重新扫）
- 在插件商店"试运行"未安装的插件看效果
- 沙箱结果仅供日志查看，无法"重新执行"

## What Changes
- **新建 `PluginOrchestrator` 单例**：集中持有 `PluginManager`（已加载）、`PluginSandboxService`、`PluginExecutionLogService`，提供 4 个统一入口（手动扫描、深挖、试运行、批量）
- **新建 `PluginQuickInvokeWindow`**：手动扫描窗口（目标 IP + 端口输入 + 插件复选框 + 执行）
- **主窗口接入**：顶部工具栏新增"🔌 插件扫描"按钮，调用 QuickInvokeWindow
- **扫描结果深挖**：综合扫描结果 + 摄像头扫描结果 + 扫描历史的 DataGrid 右键菜单新增"🔌 用插件深挖"
- **商店试运行**：`PluginMarketWindow` 操作列新增"▶ 试运行"按钮（不安装到本地，按 mock 插件的"受影响端口"模拟返回）
- **日志重跑**：`PluginExecutionLogWindow` DataGrid 新增"▶ 重新执行选中"按钮
- **替换综合扫描中 `new PluginManager()`**：改为 `PluginOrchestrator.Instance.ScanTargetAsync`

## Impact
- Affected specs: enhance-plugin-manager-v4
- Affected code:
  - `NetSecurityScanner.Core/Services/PluginOrchestrator.cs`（新）
  - `NetSecurityScanner.Desktop/Views/Views/PluginQuickInvokeWindow.xaml(.cs)`（新）
  - `NetSecurityScanner.Desktop/Views/Views/PluginMarketWindow.xaml(.cs)`（增强：试运行）
  - `NetSecurityScanner.Desktop/Views/Views/PluginExecutionLogWindow.xaml.cs`（增强：重新执行）
  - `NetSecurityScanner.Desktop/Views/Views/PluginManagerWindow.xaml.cs`（增强：右键菜单）
  - `NetSecurityScanner.Desktop/MainWindow.xaml`（增强：插件扫描按钮）
  - `NetSecurityScanner.Desktop/MainWindow.xaml.cs`（替换 :1510 调用 + 新增事件）
  - `NetSecurityScanner.Desktop/Views/Views/CameraSecurityScannerWindow.xaml.cs`（增强：右键深挖）
  - `NetSecurityScanner.Desktop/Views/Views/ScanHistoryWindow.xaml.cs`（增强：右键深挖）

## ADDED Requirements

### Requirement: PluginOrchestrator 统一调度器
新增 `PluginOrchestrator` 单例，启动时调用 `InitializeAsync` 加载全部插件。提供 4 个公开方法。

#### Scenario: 单目标扫描
- **WHEN** 调用 `ScanTargetAsync(ip="192.168.3.92", ports=[80, 443, 554], selectedPluginIds=null)`
- **THEN** 自动选择所有适用插件（`CanScanAsync` 命中），通过沙箱执行（30s 超时 + 3 并发）
- **AND** 每次执行构造 `PluginExecutionEntry` 写入日志
- **AND** 返回 `List<VulnerabilityResult>` 合并结果

#### Scenario: 手动选择插件
- **WHEN** 调用 `ScanTargetAsync(ip, ports, selectedPluginIds=["HttpBannerPlugin", "WebVulnPlugin"])`
- **THEN** 仅运行指定插件，其他插件跳过
- **AND** 日志记录"VulnCount"为实际找到的漏洞数

#### Scenario: 深挖历史目标
- **WHEN** 调用 `DeepScanAsync(scanHistoryItem)`
- **SHALL** 复用历史的 `TargetIp` + `OpenPorts`，调用 `ScanTargetAsync` 跑所有适用插件
- **AND** 在历史项上追加新发现的漏洞（不覆盖原有）

#### Scenario: 试运行商店插件
- **WHEN** 调用 `TryRunAsync(marketPlugin)`
- **SHALL** 根据 `marketPlugin.Category` 模拟返回 0-3 个 `VulnerabilityResult`（Hikvision 弱口令→admin/12345 模拟命中，SSL 评分→返回 "SSL 评分 A+"）
- **AND** 不调用任何真实网络操作，仅 UI 演示

#### Scenario: 批量扫描
- **WHEN** 调用 `ScanBatchAsync(targets=[(ip1, ports1), (ip2, ports2)])`
- **SHALL** 对每个目标依次 `ScanTargetAsync`（避免端口冲突），并支持 `IProgress<int>` 上报

### Requirement: 手动快速调用窗口
新增 `PluginQuickInvokeWindow`，用户可手动输入目标 + 端口 + 勾选插件并执行。

#### Scenario: 打开手动调用窗口
- **WHEN** 主窗口点击"🔌 插件扫描"按钮
- **THEN** 弹出 `PluginQuickInvokeWindow`：
  - 顶部：目标 IP 输入框 + 端口输入框（支持 80,443,554 逗号分隔或 1-1024 范围）
  - 中部：插件多选 CheckBox 列表（默认全选 + 显示每个插件的 CanScan 范围）
  - 底部：进度条 + "▶ 执行" + "取消" + "关闭" 按钮
  - 执行时禁用输入，启用取消；完成后弹出结果数 + 详细列表

### Requirement: 扫描结果深挖入口
所有扫描结果 DataGrid（含综合扫描、摄像头扫描、扫描历史、插件日志）右键菜单新增"🔌 用插件深挖"。

#### Scenario: 右键深挖
- **WHEN** 用户在 DataGrid 右键某行 → 选择"🔌 用插件深挖"
- **THEN** 弹窗确认"将使用所有适用插件重新扫描 {Target} (端口: {ports})"
- **AND** 用户确认后调用 `PluginOrchestrator.DeepScanAsync` 并显示进度
- **AND** 深挖完成后弹窗显示新发现的漏洞数，可点击"查看详情"跳到结果窗口

### Requirement: 商店试运行入口
`PluginMarketWindow` 操作列新增"▶ 试运行"按钮（在"安装"前）。

#### Scenario: 商店试运行
- **WHEN** 用户点击插件"▶ 试运行"按钮
- **THEN** 调用 `PluginOrchestrator.TryRunAsync(marketPlugin)`
- **AND** 在窗口内显示模拟结果（如 Hikvision 弱口令→"模拟命中: admin/12345"）
- **AND** 不修改本地 `Plugins/{id}/` 目录

### Requirement: 日志重新执行
`PluginExecutionLogWindow` DataGrid 新增"▶ 重新执行选中"按钮（顶部工具栏）。

#### Scenario: 重新执行日志条目
- **WHEN** 用户在日志窗口选择某行 → 点击"▶ 重新执行选中"
- **SHALL** 反查日志条目中的 `Target` + `Port` + `PluginId`，调用 `PluginOrchestrator.ScanTargetAsync(target, [port], [pluginId])`
- **AND** 在新窗口/状态栏显示重新执行结果

## MODIFIED Requirements

### Requirement: 综合扫描自动调用插件
`MainWindow.xaml.cs:1510` 处的 `new PluginManager()` 替换为 `PluginOrchestrator.Instance.ScanTargetAsync`，避免每次扫描重复 `LoadAllPlugins`。

## REMOVED Requirements
无
