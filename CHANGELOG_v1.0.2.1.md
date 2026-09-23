# 版本说明 v1.0.2.1

> 发布日期：2026-09-03
> 测试目标：`211.137.75.166`
> 版本策略：本版本包含专家模式"扫不到端口/漏洞"修复、深度测试中发现的全部缺陷修复，
> 以及漏洞库的数据修正与扩充——**所有修改统一归入 v1.0.2.1 这一个版本号**，不拆分子版本。

---

## 一、版本标识（唯一性核对）

| 项目 | 版本号 |
|------|--------|
| `NetSecurityScanner.Desktop.csproj` | 1.0.2.1 |
| `NetSecurityScanner.Core.csproj` | 1.0.2.1 |
| `NetSecurityScanner.csproj` | 1.0.2.1 |
| `NetSecurityScanner.Linux.csproj` | 1.0.2.1 |

发布目录：`NetSecurityScanner/publish-v1.0.2.1`（全仓库唯一）

产物内嵌版本：

```
NetSecurityScanner.Desktop.exe  FileVersion = 1.0.2.1  ProductVersion = 1.0.2.1
NetSecurityScanner.Core.dll     FileVersion = 1.0.2.1
```

---

## 二、核心修复：扫描不到端口 / 扫描不到漏洞

### 1. 常用端口范围错误（根本原因）

**问题**：「常用端口」模式实现为 `Enumerable.Range(1, 1000)`（端口 1~1000 连续区间），
既不是"常用端口"的语义，也不是文档宣称的 Nmap Top-1000 排名。所有 1000 以上的常见服务端口
（8080/8443/8888/3306/3389/5432/27017 等）全部不扫描；漏洞扫描又以开放端口为唯一输入，
故漏洞结果随之为空。

**修复**：新增 `CommonPorts.GetTop1000Ports()`（知名端口 1~1024 + 高频服务端口，共 1121 个）；
「敏感端口」改为与 `CommonPorts.GetSensitivePorts()` 取并集。

**实测效果**（211.137.75.166）：修复前 3 个端口（21/23/80）→ 修复后 **7 个**
（21/23/80/5000/5001/8098/8443），新发现 4 个开放端口。

### 2. 性能调优参数完全不下发

**问题**：`ExecuteExpertScanAsync` 构造的 `ScanOptions` 是遗留模型，`PortScanner` 只接受
`ScanPolicy`，该变量从未被使用——界面上配置的并发/超时/重试全部被丢弃，
扫描器退回内部默认值（并发 300、超时 500ms），深度扫描会因超时过短漏判慢响应端口。

**修复**：新增 `BuildScanPolicy()` 真正下发参数；并发值做 `>0` 兜底
（`SemaphoreSlim(0)` 会抛异常）；`SmallPortRangeTimeout` 跟随用户配置（防被硬编码 800ms 覆盖）。

### 3. 速率限制不生效

**问题**：`RateLimit`/`PacketRate` 此前仅用于生成 Nmap 命令，实际扫描全速运行。

**修复**：`PortScanner` 实现限流（累计耗时补偿，避免与扫描耗时叠加导致实际速率偏低）。
新增 `EnableRateLimit` 开关且默认关闭——`PortScanRate` 有默认值 100，
若直接依它限流会把所有未显式配置的调用方静默压到 100 端口/秒，属严重回归，故必须显式开启。

### 4. 自适应并发落地（原为死代码）

`AdaptiveConcurrencyController` 已实现但全项目零引用，现接入专家模式（默认关闭，
「性能调优」Tab 提供开关）。控制器内部有 `CPU核数×4` 硬上限（原面向 CPU 密集任务），
UI 与日志中如实提示实际生效上限。

### 5. 漏洞严重误报（三层修复）

**问题**：匹配逻辑 `portMatch || serviceMatch`，且规则把通用服务名与产品名混写
（如 Confluence 漏洞写 `service="http,https,confluence"`）按 OR 匹配。
一台 FTP 服务器（80 端口返回 HTTP 400）被报出 Log4Shell、Confluence、SharePoint、
MOVEit、Struts2 等 12 个严重 RCE。

**修复**：
1. 端口与服务同时定义时要求 **AND**（漏洞是"某端口上的某服务"的问题）
2. **严格服务匹配** `IsServiceMatchStrict`：通用协议名（http/https…）与特定产品名分离，只按产品名匹配
3. 无版本支撑的结果标注「端口/服务指纹推测，未验证，需人工确认」

---

## 三、深度测试中发现的缺陷修复

### 6. Rust 引擎日志无限膨胀（单文件实测 40MB）

**问题**：Rust 端以 tracing **INFO 级别逐端口打印**（`scan_tcp_port: ... -> filtered`、
`[result] ...`），C# 端无过滤全量写入，全端口扫描产生 6 万+ 行（含 ANSI 转义序列），
`expert_scan_*.log` 单文件膨胀至 40MB。

**修复**（C# 端，不改 Rust）：`ShouldSkipRustOutput()` 丢弃 INFO/DEBUG/TRACE 噪音行、
tracing 位置行（`at src\...rs:NNN`）与空行；`AnsiEscapeRegex` 剥离 ANSI 序列。
子进程读取循环保留（防缓冲区写满阻塞子进程）。

### 7. DNS 解析未观察异常（UnobservedTaskException）

**问题**：`ResolveHostnameAsync` 超时返回后 `dnsTask` 仍在后台运行，其解析失败异常
（"不知道这样的主机"）无人接管，由 finalizer 线程重新抛出，应用日志多次出现
`A Task's exception(s) were not observed...` 告警。

**修复**：超时/取消路径调用 `ObserveTaskException(dnsTask)` 消化异常。

### 8. 漏洞库数据缺陷修正与扩充

**数据修正**（消除最后 4 条误报）：Cisco IOS XE（CVE-2023-20198）、MOVEit（CVE-2023-34362）、
Citrix ADC（CVE-2019-19781）、Pulse Secure（CVE-2019-11510）的 `AffectedService`
原先只写 `http,https`（无产品名），导致任何 HTTP 服务都命中。现补上产品名
（cisco/ios-xe、moveit、citrix/netscaler、pulse/pulse-secure）。

**规则扩充**（新增 5 条配置类风险，`CONFIG-*` 编号）：这些风险由协议本身特性决定，
端口开放 + 服务识别即可确认，不存在推测误报：

| 编号 | 风险 | 等级 | 触发条件 |
|---|---|---|---|
| CONFIG-TELNET-PLAINTEXT | Telnet 明文远程管理 | 高危 | 23/telnet |
| CONFIG-FTP-PLAINTEXT | FTP 明文传输 | 中危 | 21/ftp |
| CONFIG-HTTP-PLAINTEXT | HTTP 明文 Web 服务 | 低危 | 80/http |
| CONFIG-RDP-EXPOSED | RDP 直接暴露公网 | 高危 | 3389/rdp |
| CONFIG-SMB-EXPOSED | SMB 端口暴露（勒索入口） | 高危 | 445,139/smb |

此前测试目标开放 23/Telnet 却"该报未报"，本项扩充后可正确检出。

漏洞库总数：31 → **36 条**。

---

## 四、实测汇总（目标 211.137.75.166）

| 指标 | 修复前 | 修复后 |
|---|---|---|
| 开放端口 | 3 | **7**（21/23/80/5000/5001/8098/8443） |
| 漏洞检出 | 0~少量 | **10 条**（7 条 CVE + 3 条配置类风险） |
| 产品专属 CVE 误报 | 12 条 | **0**（含数据修正后彻底消除） |
| 单次全端口扫描日志 | 40 MB | KB 级（过滤生效后） |
| 未观察异常告警 | 多条 | 已消化 |

## 五、已知限制

1. 漏洞库 36 条，覆盖仍有限，后续持续扩充
2. `CONFIG-*` 类结果沿用统一的"未验证"标注（保守处理，虽协议明文本身是确定的）
3. 端口 5000/5001/8098 服务识别为 `unknown`（Rust 引擎未做服务探测）
4. 限速与自适应并发仅对内置 C# 扫描器生效（Rust 走独立进程，启用时日志会提示）
5. 用户实跑全端口扫描发现 62 个开放端口（含 FTP 被动模式高位端口段），属正常现象

## 六、变更文件清单

| 文件 | 变更 |
|------|------|
| `Core/Utils/CommonPorts.cs` | 新增 `GetTop1000Ports()` 与高频端口表 |
| `Core/Services/PortScanner.cs` | 实现速率限制（TCP/UDP） |
| `Core/Models/ScanPolicy.cs` | `RateLimitConfig` 新增 `EnableRateLimit` |
| `Core/Services/VulnerabilityScanner.cs` | 严格服务匹配、AND 语义、未验证标注 |
| `Core/Services/RustScannerClient.cs` | Rust 输出过滤 + ANSI 剥离 |
| `Core/Data/StaticVulnerabilityDatabase.json` | 4 条规则补产品名 + 新增 5 条配置类规则（同步至另两份副本） |
| `Desktop/Views/Views/ExpertModeWindow.xaml.cs` | 端口范围修复、`BuildScanPolicy`、自适应并发接入、DNS 异常观察 |
| `Desktop/Views/Views/ExpertModeWindow.xaml` | 性能调优 Tab 新增「自适应并发」开关 |
| 4 个 `.csproj` | 版本统一 1.0.2.1 |

## 七、运维提示

旧版本运行产生的失控日志可确认后删除：

```
publish-v1.0.2.1/logs/expert_scan_20260902.log   (~41 MB，修复前产生)
publish-v1.0.2.1/logs/expert_scan_20260903.log   (~40 MB，修复前产生)
```

本版本已从根源阻止再次产生此类大文件。

测试明细见 `NetSecurityScanner/docs/测试报告-v1.0.2.1.md`。
