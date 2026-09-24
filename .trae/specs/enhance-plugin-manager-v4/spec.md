# 插件库 v4 完善 Spec

## Why
v3 已完成核心集成（启用/禁用、统一目录、卸载 DLL、综合扫描调用、4 个内置插件真实网络检测），但仍存在以下不足：
- 4 个内置插件仅做基础 Banner / TLS / 弱口令 / HTTP 探测，缺少对已知严重漏洞的深度检测（如 Heartbleed、SQLi 注入、目录爆破、默认路径枚举）
- 没有插件商店（Plugin Market）UI，用户无法浏览/下载第三方插件
- 插件执行没有持久化日志，无法审计、回放、统计成功率/耗时
- 插件没有沙箱隔离，第三方插件崩溃会拖垮主程序；没有超时/资源限制

## What Changes
- **增强 4 个内置插件的扫描深度**：新增针对 CVE 的 PoC 探测（Heartbleed、POODLE、目录爆破、SQL 注入 payload、默认凭据深度枚举等）
- **新增插件商店窗口 `PluginMarketWindow`**：浏览/搜索/安装/卸载第三方插件（使用本地 mock 数据源，可在未来替换为真实后端）
- **新增插件执行日志与统计服务 `PluginExecutionLogService`**：每次插件执行写入 JSON 到 `data/plugin_executions/{date}/`，提供成功率、平均耗时、TOP10 耗时排行
- **新增插件沙箱与资源限制 `PluginSandboxService`**：超时、并发、内存监控、try-catch 包裹防止单插件崩溃
- **PluginManagerWindow 顶部新增"插件商店"按钮**和"执行日志"按钮

## Impact
- Affected specs: enhance-plugin-manager-v3
- Affected code:
  - `NetSecurityScanner.Core/Plugins/DefaultPlugins/PortServicePlugin.cs`（增强）
  - `NetSecurityScanner.Core/Plugins/DefaultPlugins/SslTlsPlugin.cs`（增强）
  - `NetSecurityScanner.Core/Plugins/DefaultPlugins/WeakPasswordPlugin.cs`（增强）
  - `NetSecurityScanner.Core/Plugins/DefaultPlugins/WebVulnPlugin.cs`（增强）
  - `NetSecurityScanner.Core/Plugins/PluginSandboxService.cs`（新）
  - `NetSecurityScanner.Core/Services/PluginExecutionLogService.cs`（新）
  - `NetSecurityScanner.Core/Services/PluginMarketCatalogService.cs`（新：本地 mock 目录）
  - `NetSecurityScanner.Core/Plugins/PluginManager.cs`（集成沙箱与日志）
  - `NetSecurityScanner.Desktop/Views/Views/PluginMarketWindow.xaml(.cs)`（新）
  - `NetSecurityScanner.Desktop/Views/Views/PluginExecutionLogWindow.xaml(.cs)`（新）
  - `NetSecurityScanner.Desktop/Views/Views/PluginManagerWindow.xaml(.cs)`（增强：新增"商店"和"日志"按钮）

## ADDED Requirements

### Requirement: 内置插件深度 PoC 探测
4 个内置插件 SHALL 在原有真实网络探测基础上，**额外**对已知高危 CVE 执行 PoC 探测，发现即报告。

#### Scenario: SslTlsPlugin 检测 Heartbleed
- **WHEN** 目标开放 443 且 TLS 握手成功
- **THEN** 发送 Heartbleed payload (CVE-2014-0160)，若返回超过请求长度的数据 → 报告严重漏洞

#### Scenario: WebVulnPlugin 目录爆破
- **WHEN** 目标开放 80/443/8080
- **THEN** 探测 30+ 常见敏感路径（/admin、/phpinfo.php、/config.php、/.env、/actuator、/manager/html、/.git/HEAD、/wp-admin、/console 等），发现 200 OK 且非通用欢迎页 → 报告

#### Scenario: WeakPasswordPlugin 深度凭据枚举
- **WHEN** 目标开放 FTP/SSH/Telnet/HTTP/RTSP
- **THEN** 探测协议是否支持凭据认证，若支持则用 50+ 常见凭据组合 (admin/admin、admin/12345、root/root、admin/password 等) 尝试 5 轮，每轮超时 2 秒

#### Scenario: PortServicePlugin 增强 Banner
- **WHEN** 目标开放常见服务端口
- **THEN** 不仅抓取 Banner，还解析出服务名/版本号，匹配已知漏洞签名 (如 OpenSSH 7.x → CVE-2018-15473)

### Requirement: 插件商店窗口
新增 `PluginMarketWindow`，展示本地 mock 插件目录（10+ 个示例插件），支持：
- 按分类过滤（漏洞扫描/弱口令/Web 安全/合规检查）
- 关键字搜索
- 一键安装/卸载
- 显示评分、下载量、作者

#### Scenario: 打开插件商店
- **WHEN** 用户在 PluginManagerWindow 点击"插件商店"按钮
- **THEN** 弹出 PluginMarketWindow，列出 10+ 模拟插件
- **AND** 用户点击"安装" → 调用 PluginMarketService.InstallPluginAsync，文件保存到 Plugins/{id}/，并显示进度条
- **AND** 关闭窗口后 PluginManagerWindow 刷新显示新安装的插件

### Requirement: 插件执行日志与统计
所有插件执行结果 SHALL 持久化到 `data/plugin_executions/{yyyyMMdd}/{pluginId}_{timestamp}.json`，包含：插件ID、目标、端口、耗时、状态（成功/失败/超时）、发现漏洞数、错误信息。

`PluginExecutionLogService` 提供：
- `LogExecutionAsync(entry)` 写入单条记录
- `GetStatisticsAsync(lastDays=7)` 返回：总执行数/成功率/平均耗时/失败 TOP5 插件

#### Scenario: 扫描完成后查看日志
- **WHEN** 用户点击 PluginManagerWindow 的"执行日志"按钮
- **THEN** 弹出日志窗口，显示最近 7 天的统计 + 最近 50 条执行记录
- **AND** 异常失败的插件高亮红色

### Requirement: 插件沙箱与资源限制
所有插件执行 SHALL 包裹在 `PluginSandboxService.ExecuteSafelyAsync` 中，包含：
- 单插件超时（默认 30 秒）
- 并发限流（SemaphoreSlim，最多 3 个插件同时执行）
- 全局 try-catch 防止插件崩溃拖垮主程序
- 资源监控（开始时记录时间/内存，结束记录耗时与内存增量）

#### Scenario: 插件卡死被强制终止
- **WHEN** 某个插件执行超过 30 秒
- **THEN** 沙箱服务通过 CancellationToken 取消任务
- **AND** 记录日志为"超时"，标记为失败，不影响其他插件

## MODIFIED Requirements

### Requirement: 插件执行流程
v3 的 `PluginManager.ScanWithPluginsForTargetAsync` SHALL 在每个插件执行前后增加沙箱包裹和日志记录。

## REMOVED Requirements
无
