# 深度测试专家模式 v3 — 修复错误并继续完善 Spec

## Why
专家模式 v3 已完成大量近期增强（端口风险评分、端口预设场景、UDP 协议特定探测、风险信息展示、风险排序等），但运行时仍可能存在历史遗留 bug 与新引入的回归问题。本次需要全面深度测试各 Tab、扫描流程、结果显示、导出功能，识别并修复错误，让现有功能稳定运行。

## What Changes
- **深度测试与错误排查**：覆盖目标配置 / 端口与服务 / 性能调优 / 高级选项 / 实时结果 / Nmap模板 / 定时扫描 / 扫描历史 / 数据可视化 各 Tab
- **修复历史遗留 bug**：端口结果误报、目标解析崩溃、进度报告异常、空集合异常、UI 卡顿等
- **继续完善现有功能**：补全缺失校验、改进错误提示、优化大列表性能、增强用户引导
- **保持兼容**：不破坏已有 v2/v3 已实现功能，优先做"修复+完善"，新功能交由后续 spec

## Impact
- Affected specs: enhance-expert-mode-v2, enhance-expert-mode-v3
- Affected code:
  - `ExpertModeWindow.xaml` / `.xaml.cs` — 主要修改目标
  - `PortScanner.cs` / `PortServiceMapping.cs` / `PortRiskScorer.cs` — 端口扫描核心
  - `VulnerabilityScanner.cs` / `WeakPasswordPlugin.cs` — 漏洞扫描与弱口令
  - `TargetParser.cs` — 目标解析
  - `ReportEngine.cs` / `ExportHelper.cs` — 报告导出

## ADDED Requirements

### Requirement: 深度测试覆盖所有 Tab
系统 SHALL 在本次深度测试中覆盖专家模式全部 8 个 Tab 的功能流：
- 目标配置（解析、导入、导出、去重、预览）
- 端口与服务（端口模式、预设场景、协议检测）
- 性能调优（并发、超时、重试、随机化）
- 高级选项（数据包、IDS 规避、输出控制）
- 实时结果（端口/漏洞 DataGrid、统计、筛选、排序、复制、删除）
- Nmap 模板（8 个 Nmap 按钮 + 6 个预设场景按钮）
- 定时扫描（Cron 解析、任务 CRUD、启停）
- 扫描历史（加载、查看详情、对比、删除）

#### Scenario: 各 Tab 切换无异常
- **WHEN** 用户依次切换所有 Tab
- **THEN** 控件正确显示，无 XAML 解析异常，无 null 引用

#### Scenario: 扫描全流程跑通
- **WHEN** 用户输入目标 → 选择端口 → 点击开始扫描
- **THEN** 扫描进行、进度条更新、结果写入 DataGrid、停止按钮可中断、完成后统计数据正确

### Requirement: 修复已识别的常见错误
系统 SHALL 修复以下常见错误模式：

#### Scenario: 空集合导致 NRE
- **WHEN** 用户没有输入任何目标直接扫描 / 目标解析结果为空
- **THEN** 显示友好提示，不抛出 NullReferenceException

#### Scenario: 端口结果无开放端口
- **WHEN** 扫描完成后没有发现开放端口
- **THEN** DataGrid 仍能正常显示"无结果"状态，统计显示 0

#### Scenario: 导出大文件 OOM
- **WHEN** 扫描结果 > 10 万条
- **THEN** 导出时使用流式写入，不一次性加载全部到内存

#### Scenario: 重复点击开始扫描
- **WHEN** 扫描进行中用户再次点击"开始"
- **THEN** 禁用按钮或提示"扫描进行中"，不并发启动

#### Scenario: 关闭窗口未停止扫描
- **WHEN** 扫描进行中用户关闭窗口
- **THEN** 后台任务被取消，资源释放，无后台线程残留

### Requirement: 完善用户引导与错误提示
系统 SHALL 在以下场景提供更友好的反馈：

#### Scenario: 端口列表为空
- **WHEN** 用户选择自定义端口但未填写
- **THEN** 提示"请填写至少一个端口"

#### Scenario: 目标格式非法
- **WHEN** 用户输入非法 CIDR/范围
- **THEN** 在输入框旁红色提示，不静默失败

#### Scenario: 扫描被取消
- **WHEN** 用户点击"停止"
- **THEN** 立即停止，已扫到的结果保留在 DataGrid

### Requirement: 优化大数据量场景
系统 SHALL 优化以下性能问题：

#### Scenario: DataGrid 10 万行卡顿
- **WHEN** 结果数据 > 1 万行
- **THEN** 启用虚拟化模式 + 分页/筛选，UI 不卡顿

#### Scenario: 大量端口扫描内存占用
- **WHEN** 扫描 1-65535 全端口
- **THEN** 使用分批并发，内存峰值 < 500MB

### Requirement: 风险信息完整展示
系统 SHALL 确保所有扫描结果均带风险信息：

#### Scenario: 端口结果含风险等级
- **WHEN** 任意 TCP/UDP 扫描完成
- **THEN** 每条结果均带 RiskLevel/RiskScore/ServiceCategory/VulnHint

#### Scenario: 风险排序与筛选
- **WHEN** 用户在结果表右键选择"按风险评分降序"或"筛选高危端口"
- **THEN** 排序/筛选立即生效，日志显示操作结果

## MODIFIED Requirements
无（本次为修复 + 完善，不变更既有 spec 行为）

## REMOVED Requirements
无

## 验收标准
- 编译 0 错误
- 全部 8 个 Tab 切换正常
- 单目标 / 多目标 / 全端口扫描流程跑通
- 端口风险评分与预设场景在结果中正确显示
- 风险排序、筛选、复制、删除等右键菜单全部生效
- 定时扫描、扫描历史可正常加载/操作
- 异常路径均有友好提示，不抛出原始异常
