# Tasks

- [x] Task 1: 模型与持久化（白名单/黑名单/权限矩阵/审计/任务/告警/健康快照/依赖图）
  - [x] SubTask 1.1: 新建 `PluginPolicy.cs`（白名单 / 黑名单 / 权限矩阵 / 危险操作拦截规则）
  - [x] SubTask 1.2: 新建 `PluginAuditEntry.cs`（审计日志条目）
  - [x] SubTask 1.3: 新建 `ScheduledTask.cs` + `AlertRule.cs`（调度任务 + 告警规则）
  - [x] SubTask 1.4: 新建 `PluginHealthSnapshot.cs` + `PluginDependencyGraph.cs`（健康快照 + 依赖图）
  - [x] SubTask 1.5: 新建 `data/PluginPolicy.json` 默认模板（白名单空，黑名单空，全部权限默认允许）
  - [x] SubTask 1.6: 审计归档策略：> 30 天自动移到 `data/plugin_audit/archive/`

- [x] Task 2: PluginSecurityService（安全治理）
  - [x] SubTask 2.1: 加载/保存 PluginPolicy.json（线程安全 + 写时原子替换）
  - [x] SubTask 2.2: `IsAllowed(pluginId)` / `EnforcePermission(pluginId, perm)` / `InterceptDangerousOp(pluginId, op)`
  - [x] SubTask 2.3: 异常类型：`PluginBlockedException` / `PermissionDeniedException`
  - [x] SubTask 2.4: `AppendAuditAsync(entry)`：按日滚动 JSON Lines，写入 `data/plugin_audit/{yyyyMMdd}.json`
  - [x] SubTask 2.5: 事件 `OnPolicyChanged`：管控中心保存后所有缓存失效

- [x] Task 3: PluginVersionManager（版本与依赖）
  - [x] SubTask 3.1: 复用 v4 `PluginMarketCatalogService.GetCatalogAsync()` 获取远端版本
  - [x] SubTask 3.2: `CheckUpdatesAsync()`：对比本地 Plugin.Version vs 远端，填充 `PendingUpdates` 字典
  - [x] SubTask 3.3: `UpgradeAsync(pluginId, keepBackup=true)`：备份到 `Plugins/backup/{id}_{ver}/` + 下载覆盖
  - [x] SubTask 3.4: `RollbackAsync(pluginId, targetVersion)`：从 backup/ 还原
  - [x] SubTask 3.5: `ResolveDependencyAsync(pluginId)`：DFS 构造 `PluginDependencyGraph`
  - [x] SubTask 3.6: `InstallDependencyAsync(pluginId)`：缺失依赖自动从商店拉取

- [x] Task 4: PluginHealthMonitor（健康监控）
  - [x] SubTask 4.1: 后台 `Timer` 5 秒采样（仅 LoadedPlugins）
  - [x] SubTask 4.2: `BeginSample(pluginId)` / `EndSample(pluginId, success, ex, elapsedMs)`
  - [x] SubTask 4.3: 连续失败计数（成功重置）+ 5 分钟 3 次失败自动隔离
  - [x] SubTask 4.4: 内存超限检测（> 200 MB 触发熔断）
  - [x] SubTask 4.5: 健康度评分公式 + `GetHealthRankingAsync()` 返回排序列表
  - [x] SubTask 4.6: 隔离/熔断时触发 `OnAlert` 事件 + 写审计

- [x] Task 5: PluginScheduler（调度与告警）
  - [x] SubTask 5.1: Cron 表达式解析（5/6 段：分 时 日 月 周 [年]）
  - [x] SubTask 5.2: 后台 `Timer` 每分钟唤醒 + 命中点执行
  - [x] SubTask 5.3: 指数退避重试（1/2/4/8/16s，最多 5 次）
  - [x] SubTask 5.4: 通知渠道：系统托盘（NotifyIcon）/ 弹窗 / 日志文件
  - [x] SubTask 5.5: 告警规则匹配引擎（连续失败 / 内存超限 / 健康度 < 阈值）
  - [x] SubTask 5.6: 持久化 `data/scheduled_tasks.json` + `data/alert_rules.json`

- [x] Task 6: PluginGovernor 单例（聚合 4 个子服务）
  - [x] SubTask 6.1: `Lazy<PluginGovernor>` 静态实例
  - [x] SubTask 6.2: `InitializeAsync()` 串联 Security/Version/Health/Scheduler 启动
  - [x] SubTask 6.3: `ValidateScanRequestAsync(request)` 校验黑名单 + 隔离列表
  - [x] SubTask 6.4: 公开 `Security` / `VersionManager` / `Health` / `Scheduler` 4 个属性
  - [x] SubTask 6.5: `MainWindow` 启动时 `await PluginGovernor.Instance.InitializeAsync()`

- [x] Task 7: 改造 PluginManager / HotLoader / ExecutionLogService / Orchestrator 集成 Governor
  - [x] SubTask 7.1: `PluginHotLoader.Enable()` 先调 SecurityService.IsAllowed
  - [x] SubTask 7.2: `PluginManager.ScanWithPluginsForTargetAsync` 埋点 HealthMonitor
  - [x] SubTask 7.3: `PluginExecutionLogService.LogExecutionAsync` 同步写审计
  - [x] SubTask 7.4: `PluginOrchestrator.ScanTargetAsync` 调用前 `PluginGovernor.Instance.ValidateScanRequestAsync`

- [x] Task 8: PluginGovernorWindow XAML
  - [x] SubTask 8.1: 主框架 `TabControl` 4 页签：安全治理 / 版本与依赖 / 健康监控 / 调度与告警
  - [x] SubTask 8.2: 安全治理页：白名单 DataGrid / 黑名单 DataGrid / 权限矩阵表 / 审计日志
  - [x] SubTask 8.3: 版本与依赖页：本地版本表（带更新徽章）+ 依赖图 TreeView + 回滚记录
  - [x] SubTask 8.4: 健康监控页：健康度排行 DataGrid + 隔离列表（含解除隔离操作）
  - [x] SubTask 8.5: 调度与告警页：定时任务列表 + 新建/编辑对话框 + 告警规则配置
  - [x] SubTask 8.6: 顶部状态栏：Governor 健康度 / 待更新 / 隔离数 / 调度任务数

- [x] Task 9: 改造 PluginManagerWindow / MainWindow 入口
  - [x] SubTask 9.1: `PluginManagerWindow.xaml` 顶栏新增 "🛡  管控中心" 按钮
  - [x] SubTask 9.2: `PluginManagerWindow.xaml.cs` 仅 admin 可见可点；其他角色置灰 + ToolTip 提示
  - [x] SubTask 9.3: `MainWindow.xaml.cs` 启动时 `await PluginGovernor.Instance.InitializeAsync()`
  - [x] SubTask 9.4: `MainWindow` 关闭时优雅释放 Governor 后台线程

- [x] Task 10: 验证 & 构建
  - [x] SubTask 10.1: `dotnet build -c Release` 0 错误
  - [x] SubTask 10.2: 自测：白名单/黑名单生效、危险操作拦截、连续失败自动隔离、Cron 命中执行、通知到达
  - [x] SubTask 10.3: 重启主程序不重复初始化（Governor 单例 + 幂等）
  - [x] SubTask 10.4: 更新 checklist.md 全部勾选

# Task Dependencies
- [Task 1] 无依赖（基础模型先行）
- [Task 2] 依赖 [Task 1]（用到 PluginPolicy / PluginAuditEntry）
- [Task 3] 依赖 [Task 1]（用到 PluginDependencyGraph）
- [Task 4] 依赖 [Task 1]（用到 PluginHealthSnapshot）
- [Task 5] 依赖 [Task 1]（用到 ScheduledTask / AlertRule）
- [Task 6] 依赖 [Task 2] [Task 3] [Task 4] [Task 5]（聚合 4 个子服务）
- [Task 7] 依赖 [Task 2] [Task 4] [Task 6]（集成 Governor）
- [Task 8] 依赖 [Task 6]（窗口绑定 Governor.Instance）
- [Task 9] 依赖 [Task 6] [Task 8]（入口 + 集成）
- [Task 10] 依赖所有（最终验证）
