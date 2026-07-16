# Tasks

- [ ] Task 1: 摄像头扫描模型增强
  - [ ] SubTask 1.1: CameraScanResult 添加 SessionId/ScheduledTaskId/TemplateId/MonitoringMode/LastCheckedTime/AlertLevel 字段
  - [ ] SubTask 1.2: 创建 CameraScanSession（会话记录）模型
  - [ ] SubTask 1.3: 创建 CameraScanTemplate（扫描模板）模型
  - [ ] SubTask 1.4: 创建 CameraMonitorTask（监控任务）模型
  - [ ] SubTask 1.5: 创建 CameraAlert（告警）模型

- [ ] Task 2: 摄像头扫描服务增强
  - [ ] SubTask 2.1: 创建 CameraScanSessionService（会话持久化）
  - [ ] SubTask 2.2: 创建 CameraMonitorService（持续监控）
  - [ ] SubTask 2.3: 创建 CameraScanTemplateService（模板加载）
  - [ ] SubTask 2.4: 创建 CameraAlertService（告警触发）

- [ ] Task 3: 摄像头扫描 UI 增强
  - [ ] SubTask 3.1: 摄像头扫描窗口增加"持续监控"模式选项卡
  - [ ] SubTask 3.2: 增加"定时任务"配置面板
  - [ ] SubTask 3.3: 增加"扫描模板"下拉
  - [ ] SubTask 3.4: 增加"会话回放"窗口
  - [ ] SubTask 3.5: 增加告警通知面板

- [ ] Task 4: 摄像头扫描告警
  - [ ] SubTask 4.1: 实现状态变化检测（在线→离线、新增漏洞）
  - [ ] SubTask 4.2: 实现系统通知（System.Windows.Forms.NotifyIcon）
  - [ ] SubTask 4.3: 实现声音告警
  - [ ] SubTask 4.4: 告警持久化到 SQLite

- [ ] Task 5: 插件模型增强
  - [ ] SubTask 5.1: Plugin 添加 Signature/Checksum/Dependencies/MinCoreVersion/Author/LastUpdated 字段
  - [ ] SubTask 5.2: 创建 PluginSignature 工具类
  - [ ] SubTask 5.3: 创建 PluginDependency 解析器

- [ ] Task 6: 插件签名校验
  - [ ] SubTask 6.1: 实现 RSA 签名生成/验证
  - [ ] SubTask 6.2: 集成到 PluginManager 加载流程
  - [ ] SubTask 6.3: 签名缺失/失效时拒绝加载并记录

- [ ] Task 7: 插件依赖解析
  - [ ] SubTask 7.1: 实现 SemVer 版本比较
  - [ ] SubTask 7.2: 安装时检查依赖
  - [ ] SubTask 7.3: 缺失依赖时弹出安装向导

- [ ] Task 8: 插件热加载
  - [ ] SubTask 8.1: 实现 AssemblyLoadContext 隔离加载
  - [ ] SubTask 8.2: 运行时启用/禁用（不重启应用）
  - [ ] SubTask 8.3: 状态变更通知 UI

- [ ] Task 9: 插件市场增强
  - [ ] SubTask 9.1: 评分/评论数据模型
  - [ ] SubTask 9.2: 版本历史显示
  - [ ] SubTask 9.3: 一键升级所有插件

- [ ] Task 10: 集成验证
  - [ ] SubTask 10.1: 摄像头持续监控运行 5 分钟无崩溃
  - [ ] SubTask 10.2: 定时任务按 cron 正确触发
  - [ ] SubTask 10.3: 会话回放时间线准确
  - [ ] SubTask 10.4: 插件签名缺失时拒绝加载
  - [ ] SubTask 10.5: 插件热加载不需要重启

# v3 Tasks

- [x] v3-T1: 摄像头告警去重
  - [x] v3-T1.1: `CameraAlertService` 维护 `_recentFingerprints` 字典（key = `${Ip}:${Type}:${Date:yyyyMMddHH}`），24h TTL
  - [x] v3-T1.2: `Raise()` 入口处查重，命中则直接返回 false
  - [x] v3-T1.3: 单元测试：同 IP+Type 5 秒内连续触发 3 次，结果 `_alerts` 数量为 1

- [x] v3-T2: 真实通知集成
  - [x] v3-T2.1: `CameraAlertService` 集成 `System.Windows.Forms.NotifyIcon`（仅 Windows 平台）
  - [x] v3-T2.2: 严重/高 级别告警同时调用 `EmailNotificationService.SendAsync`
  - [x] v3-T2.3: `CameraMonitorService` 暴露 `SoundAlert` 开关，启用时播放 `System.Media.SystemSounds.Hand`

- [x] v3-T3: cron + 失败退避
  - [x] v3-T3.1: 实现 `CronExpression` 工具类，支持 5 字段（分/时/日/月/周）
  - [x] v3-T3.2: `CameraMonitorTask.ScheduleType` = `Interval` 或 `Cron`
  - [x] v3-T3.3: `CameraMonitorService` 维护 `failureCount[TaskId]`，连续失败按 `1,2,4,8` 分钟退避
  - [x] v3-T3.4: `failureCount >= 5` 自动 `Enabled=false` 并触发 `CameraAlertType.UnauthorizedAccess`-style 自动禁用告警

- [x] v3-T4: 扫描基线对比
  - [x] v3-T4.1: 新增 `Models/CameraBaseline.cs`：保存 `SessionId/SnapshotTime/Results[]`
  - [x] v3-T4.2: 新增 `Services/CameraBaselineService.cs`：`SaveBaseline(sessionId)` / `CompareLatest()` 返回 `CameraBaselineDiff`（含 Added/Removed/Changed 列表）
  - [x] v3-T4.3: 摄像头扫描窗口新增"保存为基线"按钮和"与基线对比"开关

- [x] v3-T5: 白名单/黑名单
  - [x] v3-T5.1: 新增 `Models/CameraIpList.cs` + `Services/CameraListService.cs`
  - [x] v3-T5.2: `CameraScannerService.ScanCamerasAsync` 入口过滤黑名单
  - [x] v3-T5.3: `CameraAlertService.CheckStatusChanges` 跳过白名单
  - [x] v3-T5.4: UI 增补"列表管理"窗口

- [x] v3-T6: 模板导入导出
  - [x] v3-T6.1: `CameraScanTemplateService.Export(string id, string filePath)`
  - [x] v3-T6.2: `CameraScanTemplateService.Import(string filePath)` 返回新模板
  - [x] v3-T6.3: 摄像头扫描窗口增加"导出模板"和"导入模板"按钮

- [x] v3-T7: 修复 PluginSignature 密钥 bug
  - [x] v3-T7.1: 新增 `GenerateKeyPair()` 静态方法返回 `(PrivateKeyXml, PublicKeyXml)`
  - [x] v3-T7.2: `SignData/VerifyData` **强制要求**调用方传入密钥，移除默认 `new RSACryptoServiceProvider(2048)` 分支
  - [x] v3-T7.3: 单元测试：生成密钥对 → 签名 → 验证通过；用错误公钥验证失败

- [x] v3-T8: AssemblyLoadContext 真正热卸载
  - [x] v3-T8.1: 新增 `Plugins/CollectibleAssemblyLoadContext.cs`（`IsCollectible = true`）
  - [x] v3-T8.2: `PluginHotLoader.Enable` 使用 `weakRef` 记录上下文
  - [x] v3-T8.3: `PluginHotLoader.Disable` 调 `Unload()` + `GC.Collect()` + `GC.WaitForPendingFinalizers()`
  - [x] v3-T8.4: 单元测试：加载 100 个插件 → 全部禁用 → DLL 句柄已释放

- [x] v3-T9: 插件沙箱权限
  - [x] v3-T9.1: 新增 `Models/PluginPermission.cs` 枚举（None/Network/FileSystem/Process/UI）
  - [x] v3-T9.2: `Plugin` 模型新增 `Permissions`、`ConfigurationSchema`、`LicenseType` 字段
  - [x] v3-T9.3: `PluginHotLoader.Enable` 前比对 `Permissions` ⊆ `PluginPermissionWhitelist`
  - [x] v3-T9.4: `PluginMarketWindow` 增加"权限说明"列

- [x] v3-T10: 插件自动更新检测
  - [x] v3-T10.1: 新增 `Services/PluginUpdateService.cs`：`CheckUpdatesAsync()` 返回可更新 `Plugin[]`
  - [x] v3-T10.2: 应用启动时 + 每天 03:00 定时检查
  - [x] v3-T10.3: 插件市场窗口加"有 N 个可更新"徽章

- [x] v3-T11: 依赖循环检测
  - [x] v3-T11.1: `PluginDependencyResolver.DetectCycle(IEnumerable<Plugin>)` 拓扑排序
  - [x] v3-T11.2: 检测到环时抛 `InvalidOperationException("检测到依赖环: A->B->C->A")`
  - [x] v3-T11.3: 单元测试：A→B→C→A 抛异常；A→B→C 不抛

- [x] v3-T12: 插件版本回滚
  - [x] v3-T12.1: 新增 `Services/PluginRollbackService.cs`
  - [x] v3-T12.2: `Rollback(pluginId)` 把 `VersionHistory[倒数第二条]` 恢复为当前，备份旧版本到 `installed.json.bak`
  - [x] v3-T12.3: 插件市场窗口加"回滚到上一版本"按钮（仅当 `VersionHistory.Count >= 2`）

# Task Dependencies
- Task 5 依赖 Task 1
- Task 4 依赖 Task 2
- Task 3 依赖 Task 1、Task 2
- Task 6 依赖 Task 5
- Task 7 依赖 Task 6

# v3 Task Dependencies
- v3-T2 依赖 v3-T1
- v3-T3 依赖 Task 2
- v3-T4 依赖 Task 2
- v3-T6 依赖 Task 1
- v3-T8 依赖 Task 8
- v3-T10 依赖 Task 9
- v3-T11 依赖 Task 7
- v3-T12 依赖 Task 9
