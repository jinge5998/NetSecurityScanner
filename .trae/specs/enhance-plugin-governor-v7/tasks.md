# Tasks

- [x] Task 1: 模型与持久化（签名/沙箱/链路/权限申请/告警模板）
  - [ ] SubTask 1.1: 新建 `PluginSignature.cs`（签名记录 + 公钥白名单 + RequireSignature 开关）
  - [ ] SubTask 1.2: 新建 `SandboxPolicy.cs`（路径白名单 / 网络出口白名单 / 进程白名单）
  - [ ] SubTask 1.3: 新建 `TraceSpan.cs` + 持久化策略（`data/plugin_traces/{yyyyMMdd}.jsonl`）
  - [ ] SubTask 1.4: 新建 `PermissionRequest.cs`（Status: Pending/Approved/Rejected）
  - [ ] SubTask 1.5: 新建 `AlertTemplate.cs`（8 个内置模板的元数据）
  - [ ] SubTask 1.6: 扩展 `PluginExceptions.cs` 加 `PluginSignatureException` / `SandboxViolationException`
  - [ ] SubTask 1.7: 扩展 `PluginPolicy.cs` 加 `RemoteApiJwtSecret` / `SiemEndpoint` / `SiemApiKey` 字段

- [ ] Task 2: PluginSignatureService（签名校验）
  - [ ] SubTask 2.1: 加载 DLL 同目录的 `.sig` 文件（base64 解码）
  - [ ] SubTask 2.2: 用 `RSA.VerifyHash(SHA256, signature)` 验签
  - [ ] SubTask 2.3: 遍历 `PluginPolicy.TrustedPublicKeys` 找到匹配的公钥
  - [ ] SubTask 2.4: 验签失败 → 抛 `PluginSignatureException` + 审计 `SignatureInvalid` + 计算 SHA-256 指纹
  - [ ] SubTask 2.5: 提供 `SignAsync(dllPath, privateKeyPath)` 工具方法（开发期用，生产期由发布者签）

- [ ] Task 3: PluginSandboxService（沙箱）
  - [ ] SubTask 3.1: 用 `AssemblyLoadContext` 加载插件 + 自定义 `ResolveEventHandler` 拦截
  - [ ] SubTask 3.2: 拦截 `System.IO.File` / `Directory` / `Path`（路径白名单）
  - [ ] SubTask 3.3: 拦截 `System.Net.Http.HttpClient`（域名白名单）
  - [ ] SubTask 3.4: 拦截 `System.Diagnostics.Process.Start`（进程名白名单）
  - [ ] SubTask 3.5: 拦截 `Microsoft.Win32.Registry`（写操作白名单）
  - [ ] SubTask 3.6: 违规时抛 `SandboxViolationException` + 审计 + 取消插件执行
  - [ ] SubTask 3.7: 提供"宽松模式"开关（仅记录不阻断），用于调试

- [ ] Task 4: PluginTelemetryService（调用链）
  - [ ] SubTask 4.1: `BeginTrace()` 生成 TraceId（Guid）+ 创建 RootSpan
  - [ ] SubTask 4.2: `BeginSpan(parentId, name)` / `EndSpan(spanId, status, tags)` API
  - [ ] SubTask 4.3: 在 `PluginManager.ScanWithPluginsForTargetAsync` 埋点 RootSpan + Plugin Span
  - [ ] SubTask 4.4: 在 `PluginOrchestrator.ScanTargetAsync` 透传 TraceId
  - [ ] SubTask 4.5: 异步批量写入 `data/plugin_traces/{yyyyMMdd}.jsonl`（每 5 秒 flush）
  - [ ] SubTask 4.6: `QueryTraceAsync(traceId)` 反查完整链路（内存索引 + 落盘回查）
  - [ ] SubTask 4.7: 与 `PluginHealthMonitor` 联动：Span > 30 秒扣 10 分 + 触发告警

- [ ] Task 5: RemoteGovernorApiService（远程管控 API）
  - [ ] SubTask 5.1: 用 `WebApplication.CreateBuilder` + Kestrel 监听 `127.0.0.1:9530`
  - [ ] SubTask 5.2: 集成 JWT Bearer 中间件（HS256，密钥从 `PluginPolicy.RemoteApiJwtSecret`）
  - [ ] SubTask 5.3: 实现 7 个 REST 接口（GET plugins / GET status / POST policy / POST quarantine / POST release / GET trace / GET alerts）
  - [ ] SubTask 5.4: 所有写操作写审计 + `RemoteApiUnauthorized` 异常处理
  - [ ] SubTask 5.5: 提供 `GenerateTempJwtAsync(user, ttl=2h)` 给本地管控台用
  - [ ] SubTask 5.6: 与 `PluginGovernor` 集成：`InitializeAsync` 时自动启动，关闭时优雅停止

- [ ] Task 6: PermissionRequestService（权限申请工作流）
  - [ ] SubTask 6.1: `RequestPermissionAsync(pluginId, perm, reason)` 提交申请
  - [ ] SubTask 6.2: 持久化到 `data/permission_requests.json`（JSON 数组）
  - [ ] SubTask 6.3: 状态机：Pending → Approved/Rejected（管理员触发）
  - [ ] SubTask 6.4: 批准后自动更新 `PluginPolicy.PermissionMatrix` + 写审计 + 通知
  - [ ] SubTask 6.5: 拒绝后写审计 + 插件再次申请同权限直接拒绝（带冷却 1 小时）
  - [ ] SubTask 6.6: 与 `PluginSandboxService` 联动：批准后沙箱同步放行

- [ ] Task 7: AlertTemplateService（告警模板）
  - [ ] SubTask 7.1: 内置 8 个模板（ConsecutiveFailure / MemoryLimit / Timeout / HealthBelowThreshold / SignatureInvalid / SandboxViolation / TraceTimeout / UnauthorizedRemoteApi）
  - [ ] SubTask 7.2: `ListTemplates()` 返回所有模板元数据
  - [ ] SubTask 7.3: `EnableTemplateAsync(templateId, customThresholds)` 创建 `AlertRule`
  - [ ] SubTask 7.4: 自定义阈值规则标记为 `IsCustomized=true`，不再跟随模板更新
  - [ ] SubTask 7.5: 启用时写审计 `AlertTemplateEnabled`
  - [ ] SubTask 7.6: 与 `PluginScheduler` 集成：启用后告警规则立即生效

- [ ] Task 8: 升级 PluginHealthMonitor（真实 CPU + 调用链超时）
  - [ ] SubTask 8.1: 改 CPU 采样为 `Process.TotalProcessorTime` 差值 / 总时间
  - [ ] SubTask 8.2: 订阅 `PluginTelemetryService.OnTraceTimeout` 事件
  - [ ] SubTask 8.3: 隔离前增加 5 分钟"冷却期"（连续失败 3 次后等 5 分钟再评估）
  - [ ] SubTask 8.4: 新增 `HealthMetric.CpuUsagePercent` 字段
  - [ ] SubTask 8.5: 健康度评分公式更新：失败 30% + 内存 30% + CPU 20% + 超时 20%

- [ ] Task 9: 升级 PluginSecurityService（审计导出 + SIEM）
  - [ ] SubTask 9.1: `ExportAuditCsvAsync(startDate, endDate, outputPath)` 合并 JSON Lines 为 CSV
  - [ ] SubTask 9.2: CSV 含 UTF-8 BOM + 标准列：时间 / 操作人 / pluginId / action / result / detail
  - [ ] SubTask 9.3: `ConfigureSiemUploadAsync(config)` 配置 SYSLOG-UDP / HTTP-JSON
  - [ ] SubTask 9.4: `AppendAuditAsync` 改为本地 + SIEM 双写（异步）
  - [ ] SubTask 9.5: 失败重试 3 次 → 写 dead-letter → 每 30 秒重试 dead-letter
  - [ ] SubTask 9.6: 在 `PluginGovernorWindow` 增"导出审计"按钮 + "SIEM 配置"对话框

- [ ] Task 10: 升级 PluginGovernorWindow（运行时大屏）
  - [ ] SubTask 10.1: 新增第 5 个 Tab "🩺 运行时大屏"
  - [ ] SubTask 10.2: 顶部 4 个 KPI 卡片（健康度/待更新/隔离/任务）+ 5 秒自动刷新
  - [ ] SubTask 10.3: 中部 LiveCharts2 折线图（健康度趋势 / 内存趋势 / 调用链耗时）
  - [ ] SubTask 10.4: 下部事件流 ListView（最近 100 条告警/隔离/签名失败）
  - [ ] SubTask 10.5: 事件行点击 → 跳到对应插件详情
  - [ ] SubTask 10.6: 新增"权限审批"Tab（待审批列表 + 通过/拒绝按钮 + 备注）
  - [ ] SubTask 10.7: 新增"告警模板"Tab（8 个模板卡片 + 启用按钮）

- [ ] Task 11: 新增 RemoteGovernorConsoleWindow（远程管控台 UI）
  - [ ] SubTask 11.1: 显示当前 API URL + 一键生成临时 JWT（带 TTL 选择）
  - [ ] SubTask 11.2: "复制 JWT" 按钮（与 LicenseDialog 同款 STA 线程方案）
  - [ ] SubTask 11.3: "打开浏览器" 按钮（Process.Start 默认浏览器）
  - [ ] SubTask 11.4: 显示最近 10 个 API 调用记录（从审计读）
  - [ ] SubTask 11.5: 在 `PluginManagerWindow` 顶栏新增"🌐 远程管控"按钮（admin only）

- [ ] Task 12: 新增 PermissionRequestDialog（权限申请审批对话框）
  - [ ] SubTask 12.1: 显示插件名 / 申请的权限 / 申请理由 / 申请时间
  - [ ] SubTask 12.2: "批准" 按钮（带备注输入框，必填）
  - [ ] SubTask 12.3: "拒绝" 按钮（带备注输入框）
  - [ ] SubTask 12.4: 提交后回调 `PermissionRequestService.ApproveAsync` / `RejectAsync`
  - [ ] SubTask 12.5: 在系统托盘弹通知（"插件 X 申请权限 Y"）

- [ ] Task 13: 升级 PluginGovernor（聚合 v7 子服务）
  - [ ] SubTask 13.1: 公开 6 个新子服务属性：`Signature` / `Sandbox` / `Telemetry` / `RemoteApi` / `PermissionRequest` / `AlertTemplate`
  - [ ] SubTask 13.2: `InitializeAsync()` 串联新服务启动
  - [ ] SubTask 13.3: `DisposeAsync()` 优雅停止 Kestrel / 沙箱 / 链路批量 flush
  - [ ] SubTask 13.4: 重复 `InitializeAsync()` 幂等保证（沿用 v6 机制）

- [x] Task 14: 改造 PluginHotLoader / PluginManager / Orchestrator
  - [x] SubTask 14.1: `PluginHotLoader.Enable()` 新签名 → 沙箱 → 权限 三段校验
  - [x] SubTask 14.2: `PluginManager.ScanWithPluginsForTargetAsync` 埋点 Telemetry Span
  - [x] SubTask 14.3: `PluginManager` 调 `RequestPermissionAsync` 当插件遇到未授权权限
  - [x] SubTask 14.4: `PluginOrchestrator.ScanTargetAsync` 接收并透传 TraceId
  - [x] SubTask 14.5: `MainWindow.xaml.cs` 关闭时 `await PluginGovernor.Instance.DisposeAsync()`

- [x] Task 10: 升级 PluginGovernorWindow（运行时大屏 + 权限审批 + 告警模板 Tab）
  - [x] SubTask 10.1: 新增第 5 个 Tab "🩺 运行时大屏"
  - [x] SubTask 10.2: 顶部 4 个 KPI 卡片（健康度/待更新/隔离/任务）+ 5 秒自动刷新
  - [x] SubTask 10.3: 中部 Canvas 柱状图（健康度趋势 / 内存 / 插件执行）
  - [x] SubTask 10.4: 下部事件流 ListView（最近 100 条告警/隔离/签名失败）
  - [x] SubTask 10.5: 事件行点击 → 跳到对应插件详情
  - [x] SubTask 10.6: 新增"权限审批"Tab（待审批列表 + 通过/拒绝按钮 + 备注）
  - [x] SubTask 10.7: 新增"告警模板"Tab（8 个模板卡片 + 启用按钮）

- [x] Task 11: 新增 RemoteGovernorConsoleWindow（远程管控台 UI）
  - [x] SubTask 11.1: 显示当前 API URL + 一键生成临时 JWT（带 TTL 选择）
  - [x] SubTask 11.2: "复制 JWT" 按钮（与 LicenseDialog 同款 STA 线程方案）
  - [x] SubTask 11.3: "打开浏览器" 按钮（Process.Start 默认浏览器）
  - [x] SubTask 11.4: 显示最近 10 个 API 调用记录（从审计读）
  - [x] SubTask 11.5: 在 `PluginManagerWindow` 顶栏新增"🌐 远程管控"按钮（admin only）

- [x] Task 12: 新增 PermissionRequestDialog（权限申请审批对话框）
  - [x] SubTask 12.1: 显示插件名 / 申请的权限 / 申请理由 / 申请时间
  - [x] SubTask 12.2: "批准" 按钮（带备注输入框，必填）
  - [x] SubTask 12.3: "拒绝" 按钮（带备注输入框）
  - [x] SubTask 12.4: 提交后回调 `PermissionRequestService.ApproveAsync` / `RejectAsync`
  - [x] SubTask 12.5: 在系统托盘弹通知（"插件 X 申请权限 Y"）

- [x] Task 15: 验证 & 构建
  - [x] SubTask 15.1: `dotnet build -c Release` 0 错误
  - [x] SubTask 15.2: 自测 8 个核心场景：签名失败拦截 / 沙箱越界拦截 / 链路查询 / 远程 API 调用 / 权限申请审批 / 模板启用 / 大屏实时刷新 / 审计 CSV 导出
  - [x] SubTask 15.3: 生成自签名测试用 `.sig` 文件 + 验证完整流程
  - [x] SubTask 15.4: 重启主程序不重复初始化（Governor 幂等）
  - [x] SubTask 15.5: 更新 checklist.md 全部勾选

# Task Dependencies
- [Task 1] 无依赖（基础模型先行）
- [Task 2] 依赖 [Task 1]（用到 PluginSignature）
- [Task 3] 依赖 [Task 1]（用到 SandboxPolicy）
- [Task 4] 依赖 [Task 1]（用到 TraceSpan）
- [Task 5] 依赖 [Task 1] [Task 6]（用到 RemoteApiJwtSecret / PermissionRequest 通知）
- [Task 6] 依赖 [Task 1]（用到 PermissionRequest）
- [Task 7] 依赖 [Task 1]（用到 AlertTemplate）
- [Task 8] 依赖 [Task 4]（订阅 OnTraceTimeout 事件）
- [Task 9] 依赖 [Task 1]（升级 PluginSecurityService 字段）
- [Task 10] 依赖 [Task 2] [Task 3] [Task 4] [Task 6] [Task 7] [Task 9]（Tab 整合所有 v7 能力）
- [Task 11] 依赖 [Task 5]（远程 API 提供 JWT）
- [Task 12] 依赖 [Task 6]（权限申请工作流）
- [Task 13] 依赖 [Task 2] [Task 3] [Task 4] [Task 5] [Task 6] [Task 7]（聚合 6 个新子服务）
- [Task 14] 依赖 [Task 2] [Task 3] [Task 4] [Task 6] [Task 13]（集成改造）
- [Task 15] 依赖所有（最终验证）
