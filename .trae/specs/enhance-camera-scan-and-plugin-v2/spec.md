# 摄像头安全扫描与插件管理 v2 Spec

## Why
现有摄像头扫描功能已支持基本端口/指纹/弱口令，但缺少 **持续监控、告警、模板化扫描策略、摄像头扫描定时任务、扫描会话回放** 等能力；插件管理缺少 **插件签名校验、插件依赖解析、插件热加载** 等企业级特性。需要进一步增强以支撑真实生产环境。

## What Changes
- 摄像头扫描模型增强
- 摄像头扫描服务增强（持续监控、定时任务、扫描会话）
- 摄像头扫描 UI 增强（监控模式、扫描计划、历史回放）
- 插件模型增强（签名、依赖、热加载）
- 插件管理 UI 增强（市场、签名校验、依赖管理）

### v3 增量完善
- 摄像头告警去重 + 真实通知（系统托盘/邮件）
- 监控任务支持 cron 表达式 + 失败退避
- 摄像头扫描基线 (Baseline) 对比
- 摄像头白名单/黑名单机制
- 扫描模板导入/导出
- 修复 PluginSignature 每次创建新 RSA 密钥对的 bug
- 使用 AssemblyLoadContext 实现真正的热卸载
- 插件沙箱权限声明模型
- 插件自动更新检测服务
- 插件依赖循环检测
- 插件版本回滚
- 插件配置 Schema

## Impact
- Affected specs: enhance-plugin-manager-v3（继任）
- Affected code:
  - NetSecurityScanner.Core/Models/Camera*.cs
  - NetSecurityScanner.Core/Services/Camera*.cs
  - NetSecurityScanner.Core/Plugins/PluginManager.cs
  - NetSecurityScanner.Core/Models/Plugin.cs
  - NetSecurityScanner.Desktop/Views/Views/CameraSecurityScannerWindow.xaml(.cs)
  - NetSecurityScanner.Desktop/Views/Views/PluginManagerWindow.xaml(.cs)
  - NetSecurityScanner.Desktop/Views/Views/PluginMarketWindow.xaml(.cs)

## ADDED Requirements

### Requirement: 摄像头持续监控
The system SHALL provide 对指定摄像头列表进行**周期性持续监控**的能力。
#### Scenario: 持续监控
- **WHEN** 用户进入摄像头监控模式，配置监控间隔（5/10/30/60分钟）
- **THEN** 系统按间隔自动执行扫描，状态变化时通过弹窗/通知提示

### Requirement: 摄像头扫描定时任务
The system SHALL provide 摄像头扫描**定时任务**。
#### Scenario: 创建定时任务
- **WHEN** 用户点击"创建定时任务"，填写 cron 表达式
- **THEN** 系统按 cron 周期执行扫描，结果自动保存到扫描历史

### Requirement: 摄像头扫描会话回放
The system SHALL provide 摄像头扫描**会话回放**功能。
#### Scenario: 回放历史会话
- **WHEN** 用户选择历史扫描会话
- **THEN** 系统按时间线逐步回放扫描进度和结果

### Requirement: 摄像头扫描模板
The system SHALL provide 摄像头扫描**模板**。
#### Scenario: 使用模板
- **WHEN** 用户选择"海康威视深度检测"模板
- **THEN** 系统按模板预置的厂商/端口/弱口令列表进行扫描

### Requirement: 摄像头扫描告警
The system SHALL provide 摄像头扫描**告警**机制。
#### Scenario: 状态变化告警
- **WHEN** 摄像头从在线变为离线，或新增高危漏洞
- **THEN** 系统通过系统通知、声音、邮件等方式告警

### Requirement: 插件签名校验
The system SHALL provide 插件**数字签名校验**。
#### Scenario: 安装签名插件
- **WHEN** 用户从市场安装带签名的插件
- **THEN** 系统验证签名后才允许加载，否则拒绝

### Requirement: 插件依赖解析
The system SHALL provide 插件**依赖解析**。
#### Scenario: 安装依赖型插件
- **WHEN** 用户安装依赖 v2 核心 API 的插件
- **THEN** 系统检查依赖版本兼容性，自动提示安装缺失依赖

### Requirement: 插件热加载
The system SHALL provide 插件**热加载**（运行时启用/禁用）。
#### Scenario: 热加载插件
- **WHEN** 用户在运行时点击"启用/禁用"某个插件
- **THEN** 系统无需重启即应用变更，并在 UI 反馈状态

### Requirement: 插件市场增强
The system SHALL provide 插件市场**评分/评论/版本历史**。
#### Scenario: 浏览市场
- **WHEN** 用户浏览插件市场
- **THEN** 系统显示插件评分、评论数、版本历史和升级说明

## MODIFIED Requirements

### Requirement: 摄像头扫描模型
- 现有 9 个模型保持向后兼容
- 新增字段：`SessionId`、`ScheduledTaskId`、`TemplateId`、`MonitoringMode`、`LastCheckedTime`、`AlertLevel`
- 不破坏现有 UI 数据绑定

### Requirement: 插件模型
- 现有 Plugin 模型保持向后兼容
- 新增字段：`Signature`、`Checksum`、`Dependencies`、`MinCoreVersion`、`Author`、`LastUpdated`
- 不破坏现有市场/管理器 UI

## REMOVED Requirements
无

## v3 ADDED Requirements

### Requirement: 摄像头告警去重与真实通知
The system SHALL provide 告警去重（24 小时内同 IP+Type 不重复），并通过系统托盘 `NotifyIcon` 与 `EmailNotificationService` 真实发送通知。
#### Scenario: 连续 5 次离线
- **WHEN** 同一摄像头 1 分钟内离线 5 次
- **THEN** 系统只产生 1 条告警，且 24 小时内不再重复

#### Scenario: 严重级别告警触发邮件
- **WHEN** 摄像头检测到严重漏洞
- **THEN** 系统同时发送系统托盘通知和邮件

### Requirement: 监控任务支持 cron
The system SHALL provide `CameraMonitorTask` 同时支持 `IntervalMinutes` 和 `CronExpression` 两种调度方式，使用自实现简化版 cron 解析。

### Requirement: 监控任务失败退避
The system SHALL provide 监控任务连续失败 N 次时按指数退避（1→2→4→8 分钟），并在 N≥5 时自动禁用任务并产生"任务自动禁用"告警。

### Requirement: 摄像头扫描基线对比
The system SHALL provide `CameraBaseline` 模型，可保存某次扫描结果为基线，后续扫描自动与之对比，标注"新增/消失/变更"。

### Requirement: 摄像头白名单/黑名单
The system SHALL provide 全局白名单（永不告警）和黑名单（强制跳过扫描），持久化到 JSON。

### Requirement: 摄像头扫描模板导入导出
The system SHALL provide 模板导出为 JSON 文件 + 从 JSON 文件导入。

### Requirement: 修复 PluginSignature 密钥 bug
The system SHALL `PluginSignature.SignData/VerifyData` 使用**真实密钥对**：提供 `GenerateKeyPair()` 返回 `(PrivateKeyXml, PublicKeyXml)`，验证时使用传入的 `publicKeyXml`，**严禁**每次创建新 RSACryptoServiceProvider。

### Requirement: 插件 AssemblyLoadContext 真正热卸载
The system SHALL 使用 `AssemblyLoadContext`（自定义可卸载 `IsCollectible = true`）隔离加载，禁用时 `AssemblyLoadContext.Unload()` + GC.Collect，真正释放 DLL 句柄。

### Requirement: 插件沙箱权限声明
The system SHALL `Plugin` 新增 `Permissions`（`PluginPermission` 枚举：Network/FileSystem/Process/UI）、`ConfigurationSchema`（JSON Schema 字符串）、`LicenseType` 字段，加载前强制校验 `Permissions` 在白名单内。

### Requirement: 插件自动更新检测
The system SHALL provide `PluginUpdateService`，启动时和每天定时检查市场服务，对比本地版本与市场版本，生成"可更新插件"列表，UI 一键升级。

### Requirement: 插件依赖循环检测
The system SHALL `PluginDependencyResolver` 增加 `DetectCycle()` 方法，依赖图出现环时抛 `InvalidOperationException` 并指出环路径。

### Requirement: 插件版本回滚
The system SHALL provide `PluginRollbackService`，回滚时把 `VersionHistory` 中上一版本恢复为当前，并保留 `installed.json` 中的备份。

## Task Dependencies
- Task 5（插件市场增强）依赖 Task 1（摄像头扫描模型增强）
- Task 4（摄像头扫描告警）依赖 Task 2（摄像头扫描服务增强）
- Task 3（UI 增强）依赖 Task 1、Task 2
- Task 6（插件签名校验）依赖 Task 1（模型）
- Task 7（插件依赖解析）依赖 Task 6
- Task 8（插件热加载）独立
- Task 9（插件市场增强）独立

### v3 依赖
- v3-T1 告警去重 依赖 v2-T4 告警
- v3-T2 通知集成 依赖 v3-T1
- v3-T3 cron + 退避 依赖 v2-T2 监控服务
- v3-T4 基线 依赖 v2-T2 会话服务
- v3-T5 白/黑名单 独立
- v3-T6 模板导入导出 依赖 v2-T1 模板模型
- v3-T7 修复签名 bug 独立
- v3-T8 AssemblyLoadContext 依赖 v2-T8 热加载
- v3-T9 沙箱权限 独立
- v3-T10 自动更新 依赖 v2-T9 市场
- v3-T11 依赖循环 依赖 v2-T7 依赖解析
- v3-T12 版本回滚 依赖 v2-T9 市场
