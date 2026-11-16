# 批量扫描 S1：扫描控制与交互 设计规格

- 日期：2026-10-29
- 状态：待评审
- 范围：`扫描 → 批量扫描`（`Views/Views/BatchScanWindow`）子项目 S1
- 后续子项目：S2 结果分析、S3 报告与落地（本文不涉及）

## 1. 背景与目标

现有批量扫描窗口已具备：四种目标输入、闪电/标准/深度三档模式（联动 `ScanProfileConfig` 走 Rust 引擎）、并发与超时调节、状态/威胁双过滤、右键复制/导出单目标/移除、失败重扫、历史写入、HTML/JSON/CSV 导出、双栏详情。

存在的问题：

1. 配置不持久化，每次打开窗口全部重置为默认值。
2. 目标重复与非法值无校验，可能重复扫描或静默失效。
3. 无暂停能力，长任务只能整体停止并丢掉未完成进度。
4. 失败仅有文本信息，无法分类统计与精确重扫。
5. 开始前无规模与耗时提示，误扫大网段时缺乏保护。

本子项目目标：在不改变现有扫描策略与导出格式的前提下，补齐上述五项控制与交互能力，并把结构化状态与失败分类沉淀为可复用的服务与模型，为 S2、S3 提供基础。

## 2. 范围

### 2.1 包含

- 扫描配置持久化（模式、并发、超时、目标类型、过滤条件）
- 目标解析的去重与合法性校验
- 扫描前规模确认与粗略耗时预估
- 阶段 2（漏洞扫描）的暂停 / 继续
- 失败原因枚举分类、列表展示、筛选
- 按失败类别精确重扫

### 2.2 不包含

- 跨会话断点续扫（扫描状态落盘）
- 跨目标漏洞聚合、排序、风险分布（S2）
- 报告模板化、Word/PDF/Excel、图表（S3）
- 扫描策略本身（端口集、PoC、引擎选型）的任何变更

## 3. 术语

| 术语 | 含义 |
|---|---|
| 阶段 1 | Rust 服务单次多目标端口扫描 |
| 阶段 2 | 按并发上限逐目标执行漏洞扫描 |
| 暂停闸门 | 阶段 2 派发任务前的等待点 |
| 失败类别 | `BatchScanFailureCategory` 枚举值 |

## 4. 架构与组件

采用「服务层 + 轻量模型」，窗口只负责绑定与展示。

| 文件 | 类型 | 职责 |
|---|---|---|
| `Models/BatchScanFailureCategory.cs` | 新增 | 失败原因枚举 |
| `Models/BatchScanSettings.cs` | 新增 | 配置持久化载体 |
| `Services/BatchScanSettingsService.cs` | 新增 | 配置读写与降级 |
| `Services/AsyncPauseController.cs` | 新增 | 暂停/继续闸门 |
| `Services/BatchScanOrchestrator.cs` | 新增 | 目标校验、耗时预估、异常分类 |
| `Views/Views/BatchScanWindow.xaml` | 修改 | 新增暂停按钮、失败原因列、解析提示、预估确认 |
| `Views/Views/BatchScanWindow.xaml.cs` | 修改 | 接线新服务，移除内联分类/校验逻辑 |
| `NetSecurityScanner.Core.Tests/BatchScanOrchestratorTests.cs` | 新增 | 纯函数单测 |

### 4.1 接口定义

```csharp
public enum BatchScanFailureCategory
{
    None, Timeout, ConnectionRefused, Unreachable,
    DnsFailure, NoOpenPort, ScanException, Canceled
}

public class BatchScanSettings
{
    public int SchemaVersion { get; set; } = 1;
    public string ScanModeTag { get; set; } = "Standard";
    public int Concurrency { get; set; } = 10;
    public double TimeoutSeconds { get; set; } = 0.3;
    public string TargetTypeTag { get; set; } = "Range";
    public string StatusFilterTag { get; set; } = "All";
    public string ThreatFilterTag { get; set; } = "All";
}

public class BatchScanSettingsService
{
    public BatchScanSettings Load();
    public void Save(BatchScanSettings settings);
}

public class AsyncPauseController
{
    public bool IsPaused { get; }
    public void Pause();
    public void Resume();
    public Task WaitIfPausedAsync(CancellationToken ct);
}

public class TargetParseOutcome
{
    public List<string> Targets { get; init; } = new();
    public int Total { get; init; }     // 原始条目数
    public int Deduped { get; init; }   // 去重数量
    public int Invalid { get; init; }   // 忽略数量
    public string? Error { get; init; } // 非空表示整体拒绝
}

public static class BatchScanOrchestrator
{
    public const int MaxTargets = 65536;
    public const int ConfirmThreshold = 256;

    public static TargetParseOutcome ValidateTargets(IEnumerable<string> raw);
    public static TimeSpan Estimate(int targetCount, int portCount, int concurrency, double timeoutSeconds);
    public static BatchScanFailureCategory Classify(Exception? ex, bool reachedTarget, bool hasOpenPorts, bool canceled);
}
```

`AsyncPauseController` 内部使用 `TaskCompletionSource<bool>` 闸门：`Pause()` 关闭闸门，`Resume()` 完成 TCS 并重建；`WaitIfPausedAsync` 在暂停期间等待并支持取消。

## 5. 数据模型变更

`IpScanItem`（定义于 `BatchScanWindow.xaml.cs`）新增：

```csharp
public BatchScanFailureCategory FailureCategory { get; set; }
public string FailureText { get; set; }   // 人类可读短描述，如"超时"
```

`ThreatLevel` 保持现状；不新增排序字段（排序属 S2）。

## 6. 数据流

1. 窗口构造 → `BatchScanSettingsService.Load()` → 回填模式/并发/超时/目标类型/两个过滤下拉；下拉 `SelectedIndex` 按 Tag 匹配，未匹配则用默认项。
2. 任一配置控件变化 → 标记配置为「脏」，由 500ms 防抖计时器触发一次 `Save()`（避免拖动滑块时高频写盘）；`OnClosing` 立即落盘一次兜底。
3. 解析目标 → `BatchScanOrchestrator.ValidateTargets()` → 成功则填充列表并提示「总计 N / 去重 M / 忽略 K」；返回 `Error` 时弹窗拒绝。
4. 点「开始批量扫描」→ `Estimate()` → 若目标数 > `ConfirmThreshold` 弹二次确认（含目标数、端口数、预估耗时下限）；取消则中止。
5. 阶段 1：Rust 端口扫描。期间暂停按钮 `IsEnabled=false`，状态栏文案「端口扫描阶段不支持暂停」。
6. 阶段 2：每目标在获取信号量前调用 `WaitIfPausedAsync(token)`；异常经 `Classify()` 归类写入 `FailureCategory`。
7. 完成汇总：在现有五个统计标签基础上，新增失败分类分项（按类别计数，仅统计非 `None`）。

## 7. 配置持久化规则

- 路径：`%LOCALAPPDATA%\NetSecurityScanner\batch_scan_settings.json`
- 编码 UTF-8 无 BOM，`WriteIndented=true`，`UnsafeRelaxedJsonEscaping`
- 读取：文件缺失、JSON 非法、字段缺失 → 返回默认实例，不抛异常
- 写入：任何 IO 异常吞掉并 `Debug.WriteLine`，不弹窗、不阻断扫描
- `SchemaVersion` 小于当前值视为旧版，按字段默认值补齐；未知字段忽略

## 8. 目标校验规则

| 输入情况 | 结果 |
|---|---|
| 空输入 / 全为空白 | `Error="请输入目标"` |
| 解析后条目数 > 65536 | `Error="目标数量超过 65536 上限，请缩小扫描范围"` |
| 文件不存在或无读权限 | `Error` 携带文件路径与异常原因 |
| `#` 开头行、空行 | 跳过，计入 `Invalid` |
| 非法 IP / 非法 CIDR / 段起止反向 | 跳过，计入 `Invalid` |
| 重复目标（忽略大小写与首尾空白） | 去重，计入 `Deduped` |
| 去重后为空 | `Error="未解析到有效目标"` |

实现方式：先调用 `TargetParser.ParseTargets` 得到原始列表，再在 `ValidateTargets` 内做 IP 合法性校验（`IPAddress.TryParse`）、去重与计数；不修改 `TargetParser` 本身。

## 9. 耗时预估

```
EstimateSeconds = (targetCount × portCount × timeoutSeconds) / concurrency
                + (targetCount × 3 × timeoutSeconds) / concurrency
```

- 第一项近似阶段 1，第二项近似阶段 2（每目标按 3 次 HTTP 探测计）
- 结果下限 1 秒；UI 标注「粗略下限，实际耗时通常为数倍」
- 公式封闭在 `BatchScanOrchestrator.Estimate`，便于单测与后续调整

## 10. 暂停 / 停止语义

| 动作 | 行为 |
|---|---|
| 暂停 | 闸门关闭；阶段 2 不再派发新目标；已派发目标继续跑完 |
| 继续 | 闸门打开，恢复派发 |
| 停止 | `Cancel()`；已派发任务协作取消，归入 `FailureCategory.Canceled` |
| 关闭窗口 | 先 `Resume()` 再 `Cancel()`，避免等待中的派发线程悬挂 |
| 阶段 1 期间 | 暂停按钮禁用，状态栏提示不支持 |

按钮状态矩阵：

| 状态 | 开始 | 暂停 | 继续 | 停止 | 重扫失败 | 导出 |
|---|---|---|---|---|---|---|
| 空闲 | 可用 | 隐藏 | 隐藏 | 禁用 | 有失败项时可用 | 有结果时可用 |
| 阶段 1 | 禁用 | 禁用 | 隐藏 | 可用 | 禁用 | 禁用 |
| 阶段 2 运行 | 禁用 | 可用 | 隐藏 | 可用 | 禁用 | 禁用 |
| 已暂停 | 禁用 | 隐藏 | 可用 | 可用 | 禁用 | 禁用 |

## 11. 失败分类判定

`Classify(Exception? ex, bool reachedTarget, bool hasOpenPorts, bool canceled)`：

| 条件顺序 | 分类 |
|---|---|
| `canceled == true` 或 `ex is OperationCanceledException` | `Canceled` |
| `ex is TaskCanceledException` 或 `ex is TimeoutException` | `Timeout` |
| `ex is SocketException` 且 `SocketErrorCode == ConnectionRefused` | `ConnectionRefused` |
| `ex is SocketException` 且错误码为 `HostUnreachable` / `NetworkUnreachable` | `Unreachable` |
| `ex is SocketException` 且错误码为 `HostNotFound`，或 `ex` 为域名解析异常 | `DnsFailure` |
| `ex == null && reachedTarget && !hasOpenPorts` | `NoOpenPort` |
| `ex == null && reachedTarget && hasOpenPorts` | `None` |
| 其他 `ex != null` | `ScanException` |

`FailureText` 为对应中文短描述（超时 / 连接被拒 / 主机不可达 / 域名解析失败 / 无开放端口 / 扫描异常 / 已取消），`ScanException` 追加原始 `Message` 便于诊断。

## 12. 按失败类别重扫

- 列表右键菜单新增「重扫本类失败」子菜单，动态生成当前存在的失败类别（去重排序），每项显示「类别名 (N)」
- 选中后：该类目标状态重置为「等待中」、清空 `FailureCategory`/`FailureText`，随后调用现有 `RunBatchScanAsync(目标集合, rescanOnlyFailed: true)`
- 底部「重扫失败目标」按钮保留，语义为全部失败类别

## 13. UI 变更

- 配置面板：无新增控件；解析按钮旁提示文本改为支持「总计 / 去重 / 忽略」三段式
- 列表：新增「失败原因」列（宽度 100，绑定 `FailureText`），并纳入状态过滤下拉（新增「已取消」选项）
- 底部按钮栏：新增「暂停」与「继续」按钮（同一位置切换可见性）
- 状态栏：新增失败分类分项汇总文本

## 14. 错误处理

- 配置读写失败：静默降级，仅 Debug 日志
- 预估弹窗：纯计算，不引入 IO
- 暂停闸门：等待期间响应取消；`Resume()` 在已恢复状态下调用为幂等
- 导出、历史写入：保持现有逻辑不变

## 15. 测试与验收标准

### 15.1 单元测试（`BatchScanOrchestratorTests`）

1. `ValidateTargets`：重复 IP 去重且 `Deduped` 正确
2. `ValidateTargets`：非法 IP 被忽略且 `Invalid` 正确
3. `ValidateTargets`：空输入返回 `Error`
4. `ValidateTargets`：超过 65536 返回 `Error`
5. `ValidateTargets`：`#` 注释行与空行被忽略
6. `Estimate`：`targetCount=1, portCount=1, concurrency=1, timeout=1` 得到 4 秒
7. `Estimate`：并发增大时结果递减，且不小于 1 秒
8. `Classify`：7 类映射逐一断言
9. `AsyncPauseController`：暂停时 `WaitIfPausedAsync` 阻塞，`Resume` 后完成；取消令牌可中断等待

### 15.2 手动验收清单

- [ ] 修改模式/并发/超时/目标类型/过滤 → 关闭并重开窗口，全部还原
- [ ] 输入含重复与非法行的列表 → 提示三段数字准确，列表仅含合法去重项
- [ ] 目标数 300 → 开始前出现二次确认，取消后不扫描
- [ ] 阶段 2 中暂停 → 列表停止新增完成项；继续 → 恢复；停止 → 已派发项变为已取消
- [ ] 阶段 1 期间暂停按钮置灰且状态文案正确
- [ ] 对不可达地址扫描 → 失败原因显示「主机不可达」，右键「重扫本类失败」仅重跑该类
- [ ] 导出三种格式内容与改动前一致（除新增失败原因列）

### 15.3 质量门禁

- `dotnet build src\NetSecurityScanner.Desktop\NetSecurityScanner.Desktop.csproj -c Debug --nologo -v q` 0 错误
- 新增单测全部通过
- 窗口代码行数不高于改动前（逻辑下沉后应净减少）

## 16. 实施约束

- 不修改 `TargetParser`、`CameraSecurityScanner` 等共享组件
- 不改变 Rust 服务调用协议与两阶段结构
- 旧 `NetSecurityScanner.csproj` 的遗留编译错误不在本次修复范围
- 每个改动点独立原子提交，提交信息遵循 `<type>: <描述>`
