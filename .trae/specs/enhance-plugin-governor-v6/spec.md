# 插件管控器 v6 Spec

## Why
v5 已完成插件**统一调度器**（PluginOrchestrator：怎么用、怎么调），但插件的**治理、生命周期、健壮性、自动化**仍存在缺口：

- 第三方插件被加载后无白名单/黑名单/危险操作拦截，存在恶意插件拖垮主程序的风险
- 插件更新要手动操作；旧版本无法回滚；依赖关系不可见
- 异常插件无自动隔离，反复失败/超时仍会被继续调度
- 无定时执行、失败重试、告警通知，运维需要人肉盯着

本 Spec 在 v5 调度器之上补一个**平级**的 `PluginGovernor`（管控器）：聚焦"能不能用 / 什么时候用 / 健不健康 / 安不安全"，不重复 v5 的"怎么用"。

## What Changes
- **新增 `PluginGovernor` 单例**：与 `PluginOrchestrator` 平级，集中管理白名单、版本、依赖、健康度、定时任务、审计日志
- **新增 `PluginSecurityService`**：白/黑名单、权限矩阵、危险操作拦截、审计写入
- **新增 `PluginVersionManager`**：自动检查更新、一键升级（旧版本备份到 `Plugins/backup/{id}_{ver}/`）、回滚、依赖图、依赖自动安装
- **新增 `PluginHealthMonitor`**：实时内存/CPU 采样、连续失败自动隔离、性能排行榜、健康度评分
- **新增 `PluginScheduler`**：Cron 表达式定时任务、指数退避重试、通知（系统托盘/弹窗/日志）、告警规则
- **新增 `PluginGovernorWindow`**：4 标签页（安全治理 / 版本与依赖 / 健康监控 / 调度与告警）
- **改造 `PluginManagerWindow`**：主窗口新增"🛡  管控中心"按钮，打开 `PluginGovernorWindow`
- **审计/事件总线**：所有 install/uninstall/enable/disable/execute/upgrade 操作写入 `data/plugin_audit/{yyyyMMdd}.json`，不可删

**BREAKING**：仅管理员（admin）可访问管控中心；其他角色看到的"🛡  管控中心"按钮置灰。

## Impact
- Affected specs: enhance-plugin-orchestrator-v5（不变，只新增平级模块）
- Affected code:
  - `NetSecurityScanner.Core/Services/PluginGovernor.cs`（新）
  - `NetSecurityScanner.Core/Services/PluginSecurityService.cs`（新）
  - `NetSecurityScanner.Core/Services/PluginVersionManager.cs`（新）
  - `NetSecurityScanner.Core/Services/PluginHealthMonitor.cs`（新）
  - `NetSecurityScanner.Core/Services/PluginScheduler.cs`（新）
  - `NetSecurityScanner.Core/Models/PluginPolicy.cs`（新）
  - `NetSecurityScanner.Core/Models/PluginAuditEntry.cs`（新）
  - `NetSecurityScanner.Core/Models/ScheduledTask.cs`（新）
  - `NetSecurityScanner.Core/Models/AlertRule.cs`（新）
  - `NetSecurityScanner.Core/Models/PluginHealthSnapshot.cs`（新）
  - `NetSecurityScanner.Core/Models/PluginDependencyGraph.cs`（新）
  - `NetSecurityScanner.Core/Plugins/PluginManager.cs`（改造：执行前后埋点健康监控 + 审计）
  - `NetSecurityScanner.Core/Services/PluginExecutionLogService.cs`（改造：执行结果同时写入审计）
  - `NetSecurityScanner.Core/Plugins/PluginHotLoader.cs`（改造：加载前查白名单 + 写审计）
  - `NetSecurityScanner.Desktop/Views/Views/PluginGovernorWindow.xaml(.cs)`（新）
  - `NetSecurityScanner.Desktop/Views/Views/PluginManagerWindow.xaml(.cs)`（增强：新增"🛡 管控中心"按钮）
  - `NetSecurityScanner.Desktop/MainWindow.xaml.cs`（改造：插件扫描调用前先经 Governor 校验）
  - `NetSecurityScanner.Core/Services/PluginOrchestrator.cs`（增强：Governor 集成点）

## ADDED Requirements

### Requirement: PluginGovernor 单例
新增 `PluginGovernor` 单例（与 `PluginOrchestrator` 平级），构造时初始化 4 个子服务（Security / Version / Health / Scheduler），启动时 `InitializeAsync()` 加载策略 + 启动调度器。

#### Scenario: 单例获取
- **WHEN** 任意位置调用 `PluginGovernor.Instance`
- **THEN** 返回唯一实例；多次调用不重复构造
- **AND** 重复 `InitializeAsync()` 只生效一次

#### Scenario: 策略热更新
- **WHEN** 用户在管控中心修改白/黑名单/告警阈值并保存
- **THEN** 立即生效（无需重启），后续 install/enable/execute 即时按新策略校验

### Requirement: 安全治理（白/黑名单 + 权限矩阵 + 审计）
`PluginSecurityService` 提供：
- 持久化 `PluginPolicy.json`（白名单/黑名单/权限矩阵/危险操作拦截规则）
- `IsAllowed(pluginId)` 检查
- `EnforcePermission(pluginId, perm)` 检查权限
- `InterceptDangerousOp(pluginId, op)` 拦截写注册表/删除文件/启动进程等
- `AppendAuditAsync(entry)` 写审计日志（线程安全）

#### Scenario: 黑名单插件被拒绝加载
- **WHEN** `PluginHotLoader.Enable(path, plugin)` 调用
- **THEN** 校验 `plugin.Id` 不在黑名单中
- **AND** 通过则继续；否则抛 `PluginBlockedException("插件 {id} 在黑名单中")`
- **AND** 任何路径都会写一条审计 `PluginBlocked`

#### Scenario: 危险操作被拦截
- **WHEN** 插件调用 `InterceptDangerousOp("WriteRegistry", "HKLM\\...")`
- **THEN** 若策略中"写注册表"未在权限矩阵内 → 抛 `PermissionDeniedException`
- **AND** 审计日志记录 `DangerousOpBlocked` + 上下文

#### Scenario: 审计日志
- **WHEN** install/uninstall/enable/disable/execute/upgrade/policyChange 任何操作发生
- **THEN** 在 `data/plugin_audit/{yyyyMMdd}.json` 追加一条 `PluginAuditEntry`
- **AND** 字段包含：时间戳 / 操作人（当前登录用户）/ pluginId / action / before/after 状态 / 结果 / IP
- **AND** 文件按日滚动，30 天后自动归档到 `archive/`

### Requirement: 版本与依赖管理
`PluginVersionManager` 提供：
- `CheckUpdatesAsync()` 扫描本地插件版本 vs 商店目录（v4 已有 `PluginMarketCatalogService`）
- `UpgradeAsync(pluginId)` 下载新版本并备份旧版到 `Plugins/backup/{id}_{ver}/`
- `RollbackAsync(pluginId, targetVersion)` 从 backup/ 还原
- `ResolveDependencyAsync(pluginId)` 返回依赖图
- `InstallDependencyAsync(pluginId)` 自动从商店拉取缺失依赖

#### Scenario: 启动时检查更新
- **WHEN** `PluginGovernor.InitializeAsync()` 完成
- **THEN** 在后台异步 `CheckUpdatesAsync()`，结果存 `PendingUpdates`
- **AND** 管控中心"版本与依赖"页签显示红点徽章 + 待更新数量

#### Scenario: 一键升级
- **WHEN** 用户点击"升级" → 选择保留旧版本
- **THEN** 把当前 DLL 复制到 `Plugins/backup/{id}_{ver}/`
- **AND** 下载新版本覆盖 `Plugins/{id}/`
- **AND** 写审计 `Upgraded` + 备份路径
- **AND** 若依赖不满足（新插件要求 core ≥ 1.0.2）→ 拒绝升级并提示

#### Scenario: 回滚
- **WHEN** 用户选择 v1.2.0 → 点击"回滚"
- **THEN** 从 `Plugins/backup/{id}_1.0.0/` 还原 DLL
- **AND** 写审计 `RolledBack`

#### Scenario: 依赖图
- **WHEN** 用户在"版本与依赖"页签选某个插件
- **THEN** 显示树形依赖图（已满足=绿，缺失=红，版本过低=黄）
- **AND** 点击缺失节点 → 一键从商店安装

### Requirement: 健康监控
`PluginHealthMonitor` 后台线程每 5 秒采样（仅采集已加载插件）：
- 内存增量（GC.GetTotalMemory - startBaseline）
- CPU 估算（基于执行次数与累计耗时）
- 连续失败次数（重置：成功一次）
- 最近一次异常堆栈
- 健康度评分 = `100 - 失败权重 - 内存权重 - 超时权重`，< 60 触发告警

#### Scenario: 连续失败自动隔离
- **WHEN** 某插件 5 分钟内连续失败 3 次
- **THEN** 标记 `IsQuarantined = true`，从 `PluginManager.LoadedPlugins` 移除
- **AND** 审计 `Quarantined`
- **AND** 弹系统托盘通知 + 写入告警日志

#### Scenario: 内存超限告警
- **WHEN** 插件单次执行内存增量 > 200 MB
- **THEN** 当前执行被取消（CancellationToken）
- **AND** 审计 `MemoryLimitExceeded`
- **AND** 健康度扣 20 分

#### Scenario: 健康度排行榜
- **WHEN** 用户进入"健康监控"页签
- **THEN** 表格按健康度倒序：名称 / 评分 / 内存峰值 / 累计耗时 / 失败次数 / 隔离状态
- **AND** 双击行 → 跳到该插件的详细指标（最近 50 次执行）

### Requirement: 调度与告警
`PluginScheduler`：
- 解析标准 5/6 段 Cron 表达式
- 后台 `Timer` 每分钟唤醒，检查命中任务
- 命中后调用 `PluginOrchestrator.ScanTargetAsync`（或批量）
- 失败按指数退避重试（1s, 2s, 4s, 8s, 16s，最多 5 次）
- 通知：系统托盘 / 弹窗 / 日志（可配）
- 告警规则：连续失败 / 单次超时 / 资源超限 / 健康度 < 阈值

#### Scenario: 创建定时任务
- **WHEN** 用户在"调度与告警"页签 → 新建任务
- **THEN** 填 Cron（如 `0 2 * * *`）+ 目标 IP 段 + 端口 + 插件列表 + 重试策略
- **AND** 保存到 `data/scheduled_tasks.json`
- **AND** 任务立即加入调度队列，下次命中点自动执行

#### Scenario: 失败重试
- **WHEN** 定时任务执行失败
- **THEN** 按 1/2/4/8/16 秒退避重试，最多 5 次
- **AND** 5 次后标记任务 `LastError` + 触发"连续失败"告警（如已配置）

#### Scenario: 告警通知
- **WHEN** 告警规则触发（连续失败 / 内存超限 / 健康度过低）
- **THEN** 根据 `AlertRule.NotificationChannels` 推送：
  - 系统托盘：`NotifyIcon.ShowBalloonTip(告警标题, 内容, Icon.Warning)`
  - 弹窗：`MessageBox`（仅当 Channels 含 "Popup" 且应用在前台）
  - 日志：`logs/alerts/{yyyyMMdd}.log` 追加一行

### Requirement: 管控中心窗口
新增 `PluginGovernorWindow`（4 个 TabControl 标签页）：
1. **安全治理**：白名单列表 / 黑名单列表 / 权限矩阵表 / 审计日志（按日切换） / 危险操作拦截规则
2. **版本与依赖**：本地插件版本表 + 待更新徽章 / 依赖图（TreeView）/ 回滚记录
3. **健康监控**：健康度排行榜（DataGrid）/ 资源使用折线图（LiveCharts2）/ 已隔离插件列表
4. **调度与告警**：定时任务列表 / 新建/编辑任务对话框 / 告警规则配置 / 通知渠道开关

#### Scenario: 打开管控中心
- **WHEN** 非管理员用户点击"🛡  管控中心"按钮
- **THEN** 按钮置灰，鼠标悬停提示"仅管理员可用"

#### Scenario: 仅管理员可见
- **WHEN** 当前登录用户 = "admin"
- **THEN** "🛡  管控中心"按钮可见可点
- **AND** 点击后弹出 `PluginGovernorWindow`

## MODIFIED Requirements

### Requirement: 插件加载前必走 SecurityService
`PluginHotLoader.Enable(path, plugin)` 在 v3 已有的 `Permissions ⊆ Whitelist` 基础上，**先**调 `PluginSecurityService.IsAllowed(plugin.Id)`，**再**做权限白名单校验。

### Requirement: 插件执行埋点健康监控
`PluginManager.ScanWithPluginsForTargetAsync` 在每个插件 `CanScanAsync` + `ScanAsync` 前后埋点：
- 执行前：`HealthMonitor.BeginSample(pluginId)`
- 执行后：`HealthMonitor.EndSample(pluginId, success, exception, elapsedMs)`
- 异常：自动累加 `ConsecutiveFailures`

### Requirement: 审计与执行日志合并写入
`PluginExecutionLogService` 的每次 `LogExecutionAsync(entry)` 调用**同时**触发 `PluginSecurityService.AppendAuditAsync(对应 entry)`，避免两套日志脱节。

### Requirement: 插件扫描调用前 Governor 校验
`PluginOrchestrator.ScanTargetAsync` / `ScanBatchAsync` 调用前先经 `PluginGovernor.ValidateScanRequestAsync(request)` 校验：
- 目标 IP 不在黑名单插件的禁用范围
- 任务不在"已隔离"列表
- 通过后才委托给 `PluginManager`

## REMOVED Requirements
无
