# 版本说明 v1.0.2.2

> 发布日期：2026-09-03
> 核心内容：修复 v1.0.2.1 深度测试中发现的两个运行时缺陷
> 前置版本：v1.0.2.1（专家模式"扫描不到端口/漏洞"修复，见 `CHANGELOG_v1.0.2.1.md`）

---

## 一、版本标识（唯一性核对）

| 项目 | 版本号 |
|------|--------|
| `NetSecurityScanner.Desktop.csproj` | 1.0.2.2 |
| `NetSecurityScanner.Core.csproj` | 1.0.2.2 |
| `NetSecurityScanner.csproj` | 1.0.2.2 |
| `NetSecurityScanner.Linux.csproj` | 1.0.2.2 |

发布目录：`NetSecurityScanner/publish-v1.0.2.2`（唯一）

产物内嵌版本已核对：

```
NetSecurityScanner.Desktop.exe  FileVersion = 1.0.2.2
NetSecurityScanner.Core.dll     FileVersion = 1.0.2.2
```

启动日志核对：`boot_20260903_123238.log` 显示 `Version: 1.0.2.2`，`OnStartup completed successfully`。

> 版本策略说明：v1.0.2.1 已发布运行并产生运行日志，本次修复改变了产物内容，
> 按"一个版本号唯一对应一组产物"的原则递增为 v1.0.2.2，不回写已发布版本。

---

## 二、修复清单

### 1. Rust 引擎日志无限膨胀（单文件实测 40MB）

**问题**：Rust 扫描引擎以 tracing 的 **INFO 级别逐端口打印日志**，形如：

```
scan_tcp_port: 211.137.75.166 65327 -> filtered
[result] 211.137.75.166:80
    at src\scanner.rs:634
```

C# 端 `RustScannerClient.ReadStreamAsync` 将子进程 stdout **无过滤全量写入**专家模式日志。
全端口扫描（65535 端口）产生 6 万行以上，实测 `logs/expert_scan_*.log` 单文件膨胀到 **40MB**
（两天累计约 80MB），既拖慢扫描又使日志无法检索。

**修复**（C# 端过滤，不改 Rust 端）：

1. 新增 `ShouldSkipRustOutput()`：丢弃 INFO / DEBUG / TRACE 级别的逐端口噪音行、
   tracing 的位置行（`at src\...rs:NNN`）及空行，仅保留 WARN / ERROR 及无级别标记的输出（如 panic）
2. 新增 `AnsiEscapeRegex`：写入前剥离 ANSI 颜色/样式转义序列
   （Rust tracing 默认彩色输出，`\x1B[2;3m` 等序列会污染日志）
3. **保留子进程读取循环本身**：即使全部行被过滤，仍持续读取 stdout，
   这是防止子进程缓冲区写满而阻塞的必要措施，不能因过滤而省略

**效果**：日志量从每端口约 4 行降为 0 行（正常扫描时 WARN/ERROR 极少），
预计全端口扫描的日志体积从 40MB 降至 KB 级。

**涉及文件**：`NetSecurityScanner.Core/Services/RustScannerClient.cs`

---

### 2. DNS 解析未观察异常（UnobservedTaskException）

**问题**：`ResolveHostnameAsync` 用 `Task.WhenAny(dnsTask, timeoutTask)` 实现超时。
超时路径直接 `return "__TIMEOUT__"`，而 `dnsTask` 仍在后台运行——
若它随后因解析失败抛出异常（如"不知道这样的主机"），**异常永远无人接管**，
最终由 finalizer 线程重新抛出，在应用日志中留下：

```
A Task's exception(s) were not observed either by Waiting on the Task or
accessing its Exception property. As a result, the unobserved exception
was rethrown by the finalizer thread. (不知道这样的主机。)
```

实测 `app_20260902.log`、`app_20260903.log` 中均出现多条此类告警。

**修复**：在两个提前返回路径（超时、已取消）调用已有的 `ObserveTaskException(dnsTask)`
通过 `ContinueWith(OnlyOnFaulted)` 消化异常。

**涉及文件**：`NetSecurityScanner.Desktop/Views/Views/ExpertModeWindow.xaml.cs`

---

## 三、运维提示

**旧日志清理**：v1.0.2.1 的发布目录中存在两个失控膨胀的日志文件，建议确认无需保留后删除：

```
publish-v1.0.2.1/logs/expert_scan_20260902.log   (~41 MB)
publish-v1.0.2.1/logs/expert_scan_20260903.log   (~40 MB)
```

v1.0.2.2 已从根源上阻止再次产生此类大文件。

---

## 四、变更文件清单

| 文件 | 变更 |
|------|------|
| `Core/Services/RustScannerClient.cs` | Rust 输出过滤 + ANSI 剥离 |
| `Desktop/Views/Views/ExpertModeWindow.xaml.cs` | DNS 超时路径观察异常 |
| 4 个 `.csproj` | 版本 → 1.0.2.2 |

---

## 五、升级渠道调整（GitHub 主升级、百度辅助）

自 v1.0.2.2 起，应用内升级渠道调整为：

| 优先级 | 渠道 | 说明 |
|--------|------|------|
| **主升级** | GitHub 自动更新 | 应用内"检查更新 → 一键更新"直接从 GitHub Release 下载并安装，自动重启生效 |
| **辅助升级** | 百度网盘 | 仅当 GitHub 无法访问或自动更新失败时使用，Release 说明中附带链接与提取码 |

具体变更：

1. `UpdateCheckService.ParseBaiduDownloadInfo`：百度链接不再覆盖
   `UpdateInfo.DownloadUrl`（主下载地址保持 GitHub 资源），仅当 GitHub 上
   无可用 Windows 更新包时才回退到百度链接
2. `UpdatePackageDownloader`：新增 `DefaultGitHubReleaseUrl` 常量；
   `GetDownloadGuideText` 升级指南改为 GitHub 优先、百度备用的双渠道说明
3. 更新对话框（Desktop 与主 WPF 项目同步）：GitHub 一键更新置顶为推荐方式，
   百度网盘降级为"备用（国内加速）"折叠区

---

## 六、与 v1.0.2.1 的关系

v1.0.2.2 在 v1.0.2.1 全部内容的基础上叠加本文件所述两项修复，其余行为不变。
v1.0.2.1 的修复明细见 `CHANGELOG_v1.0.2.1.md`，测试明细见 `NetSecurityScanner/docs/测试报告-v1.0.2.1.md`。
