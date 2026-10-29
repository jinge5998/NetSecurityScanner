# 批量扫描 S1：扫描控制与交互 实施计划

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 为批量扫描窗口补齐配置记忆、目标校验、扫描前确认、阶段2暂停/继续、失败原因分类与按类别重扫，逻辑下沉到 Core 层服务并可单测。

**Architecture:** 纯逻辑（校验/预估/分类/暂停闸门/配置读写）放入 `NetSecurityScanner.Core`（Models + Services），窗口 `BatchScanWindow` 只做绑定与展示。单元测试放 `NetSecurityScanner.Core.Tests`（xUnit + FluentAssertions）。

**Tech Stack:** C# / .NET 6 / WPF / xUnit / FluentAssertions / System.Text.Json

**Spec:** `docs/superpowers/specs/2026-10-29-batch-scan-control-design.md`

**命令约定：** 所有命令在仓库根目录 `d:\360安全浏览器下载\软件开发备份\网络安全漏洞扫描\NetSecurityScanner` 下执行。

**与规格的差异（实现时以本计划为准）：**
1. `Classify` 判定顺序调整：`TaskCanceledException` 继承自 `OperationCanceledException`，规格表顺序会导致 Timeout 分支不可达。实际顺序：`canceled` 标志 → `TimeoutException` → `TaskCanceledException` → `OperationCanceledException` → `SocketException` → null 分支 → `ScanException`。
2. 阶段1 Rust 只回传开放端口，「不可达」与「无开放端口」无法区分，统一归 `NoOpenPort` 且状态仍为「已完成」（信息标注，不改变统计语义）；`Unreachable/ConnectionRefused/DnsFailure` 在阶段2抛出 `SocketException` 时生效。规格 15.2 第 6 条验收相应改为「无开放端口」。
3. 解析成功后的 MessageBox 弹窗移除，改为 `ParsedTargetCountTextBlock` 三段式文本（总计/去重/忽略），减少一次点击。
4. 「重扫失败目标」按钮扩展为同时覆盖「失败」与「已取消」目标（对应规格 12「全部失败类别」语义）。
5. 新模型/服务放 `NetSecurityScanner.Core`（而非 Desktop），命名空间 `NetSecurityScanner.Core.Models` / `NetSecurityScanner.Core.Services`，以便 Core.Tests 直接引用单测。

---

## 文件结构

| 文件 | 动作 | 职责 |
|---|---|---|
| `src/NetSecurityScanner.Core/Models/BatchScanFailureCategory.cs` | 新建 | 失败原因枚举（8 值） |
| `src/NetSecurityScanner.Core/Models/BatchScanSettings.cs` | 新建 | 配置持久化载体 |
| `src/NetSecurityScanner.Core/Models/TargetParseOutcome.cs` | 新建 | 目标校验结果（Targets/Total/Deduped/Invalid/Error） |
| `src/NetSecurityScanner.Core/Services/BatchScanOrchestrator.cs` | 新建 | ValidateTargets / Estimate / Classify / ToDisplayText |
| `src/NetSecurityScanner.Core/Services/AsyncPauseController.cs` | 新建 | 暂停/继续异步闸门 |
| `src/NetSecurityScanner.Core/Services/BatchScanSettingsService.cs` | 新建 | 配置读写（LOCALAPPDATA，静默降级） |
| `src/NetSecurityScanner.Core.Tests/BatchScanOrchestratorTests.cs` | 新建 | 编排器单测 |
| `src/NetSecurityScanner.Core.Tests/AsyncPauseControllerTests.cs` | 新建 | 暂停闸门单测 |
| `src/NetSecurityScanner.Desktop/Views/Views/BatchScanWindow.xaml` | 修改 | 失败原因列、已取消过滤项、右键子菜单、暂停/继续按钮、失败分项文本 |
| `src/NetSecurityScanner.Desktop/Views/Views/BatchScanWindow.xaml.cs` | 修改 | 全部接线；`IpScanItem` 增加两个字段 |

---

## Task 1: Core 模型三件套（枚举 + 配置 + 解析结果）

**Files:**
- Create: `src/NetSecurityScanner.Core/Models/BatchScanFailureCategory.cs`
- Create: `src/NetSecurityScanner.Core/Models/BatchScanSettings.cs`
- Create: `src/NetSecurityScanner.Core/Models/TargetParseOutcome.cs`

- [ ] **Step 1: 创建失败原因枚举**

`src/NetSecurityScanner.Core/Models/BatchScanFailureCategory.cs`：

```csharp
namespace NetSecurityScanner.Core.Models
{
    /// <summary>
    /// 批量扫描单目标失败/异常原因分类。
    /// </summary>
    public enum BatchScanFailureCategory
    {
        None,
        Timeout,
        ConnectionRefused,
        Unreachable,
        DnsFailure,
        NoOpenPort,
        ScanException,
        Canceled
    }
}
```

- [ ] **Step 2: 创建配置载体**

`src/NetSecurityScanner.Core/Models/BatchScanSettings.cs`：

```csharp
namespace NetSecurityScanner.Core.Models
{
    /// <summary>
    /// 批量扫描窗口持久化配置。不保存目标输入内容，避免误扫。
    /// </summary>
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
}
```

- [ ] **Step 3: 创建解析结果模型**

`src/NetSecurityScanner.Core/Models/TargetParseOutcome.cs`：

```csharp
using System.Collections.Generic;

namespace NetSecurityScanner.Core.Models
{
    /// <summary>
    /// 目标校验结果。Error 非空表示整体拒绝（此时其余字段无意义）。
    /// </summary>
    public class TargetParseOutcome
    {
        public List<string> Targets { get; init; } = new();
        public int Total { get; init; }
        public int Deduped { get; init; }
        public int Invalid { get; init; }
        public string? Error { get; init; }
    }
}
```

- [ ] **Step 4: 构建 Core 验证通过**

Run: `dotnet build "src\NetSecurityScanner.Core\NetSecurityScanner.Core.csproj" -c Debug --nologo -v q`
Expected: 输出含 `已成功生成`，`0 个错误`

- [ ] **Step 5: 提交**

```powershell
git add src/NetSecurityScanner.Core/Models/BatchScanFailureCategory.cs src/NetSecurityScanner.Core/Models/BatchScanSettings.cs src/NetSecurityScanner.Core/Models/TargetParseOutcome.cs
git commit -m "feat: 新增批量扫描失败分类/配置/解析结果模型"
```

---

## Task 2: 编排器骨架 + 失败测试（RED）

**Files:**
- Create: `src/NetSecurityScanner.Core/Services/BatchScanOrchestrator.cs`
- Test: `src/NetSecurityScanner.Core.Tests/BatchScanOrchestratorTests.cs`

- [ ] **Step 1: 写骨架（方法全部抛 NotImplementedException，保证可编译）**

`src/NetSecurityScanner.Core/Services/BatchScanOrchestrator.cs`：

```csharp
using System;
using System.Collections.Generic;
using NetSecurityScanner.Core.Models;

namespace NetSecurityScanner.Core.Services
{
    /// <summary>
    /// 批量扫描编排纯逻辑：目标校验、耗时预估、失败分类。无 IO、无 UI 依赖。
    /// </summary>
    public static class BatchScanOrchestrator
    {
        public const int MaxTargets = 65536;
        public const int ConfirmThreshold = 256;

        public static TargetParseOutcome ValidateTargets(IEnumerable<string> raw)
            => throw new NotImplementedException();

        public static TimeSpan Estimate(int targetCount, int portCount, int concurrency, double timeoutSeconds)
            => throw new NotImplementedException();

        public static BatchScanFailureCategory Classify(Exception? ex, bool reachedTarget, bool hasOpenPorts, bool canceled)
            => throw new NotImplementedException();

        public static string ToDisplayText(BatchScanFailureCategory category)
            => throw new NotImplementedException();
    }
}
```

- [ ] **Step 2: 写完整测试文件**

`src/NetSecurityScanner.Core.Tests/BatchScanOrchestratorTests.cs`：

```csharp
using System;
using System.Collections.Generic;
using System.Net.Sockets;
using System.Threading.Tasks;
using FluentAssertions;
using NetSecurityScanner.Core.Models;
using NetSecurityScanner.Core.Services;
using Xunit;

namespace NetSecurityScanner.Tests
{
    public class BatchScanOrchestratorTests
    {
        #region ValidateTargets

        [Fact]
        public void ValidateTargets_Duplicates_AreRemoved()
        {
            var raw = new List<string> { "192.168.1.1", "192.168.1.1", " 192.168.1.2 ", "192.168.1.2" };

            var outcome = BatchScanOrchestrator.ValidateTargets(raw);

            outcome.Error.Should().BeNull();
            outcome.Targets.Should().Equal("192.168.1.1", "192.168.1.2");
            outcome.Total.Should().Be(4);
            outcome.Deduped.Should().Be(2);
            outcome.Invalid.Should().Be(0);
        }

        [Fact]
        public void ValidateTargets_InvalidEntries_AreSkipped()
        {
            var raw = new List<string> { "192.168.1.1", "not-an-ip", "999.1.1.1", "" };

            var outcome = BatchScanOrchestrator.ValidateTargets(raw);

            outcome.Error.Should().BeNull();
            outcome.Targets.Should().Equal("192.168.1.1");
            outcome.Invalid.Should().Be(3);
        }

        [Fact]
        public void ValidateTargets_EmptyInput_ReturnsError()
        {
            var outcome = BatchScanOrchestrator.ValidateTargets(new List<string>());
            outcome.Error.Should().Be("请输入目标");
        }

        [Fact]
        public void ValidateTargets_AllWhitespace_ReturnsError()
        {
            var outcome = BatchScanOrchestrator.ValidateTargets(new List<string> { " ", "" });
            outcome.Error.Should().Be("请输入目标");
        }

        [Fact]
        public void ValidateTargets_ExceedsMax_ReturnsError()
        {
            var raw = new List<string>();
            for (int i = 0; i < BatchScanOrchestrator.MaxTargets + 1; i++)
            {
                raw.Add($"10.{(i >> 16) & 255}.{(i >> 8) & 255}.{i & 255}");
            }

            var outcome = BatchScanOrchestrator.ValidateTargets(raw);

            outcome.Error.Should().Contain("65536");
        }

        [Fact]
        public void ValidateTargets_CommentAndBlankLines_AreIgnored()
        {
            var raw = new List<string> { "# 内网段", "", "192.168.1.1" };

            var outcome = BatchScanOrchestrator.ValidateTargets(raw);

            outcome.Error.Should().BeNull();
            outcome.Targets.Should().Equal("192.168.1.1");
            outcome.Invalid.Should().Be(2);
        }

        #endregion

        #region Estimate

        [Fact]
        public void Estimate_MinimalInputs_ReturnsFourSeconds()
        {
            BatchScanOrchestrator.Estimate(1, 1, 1, 1.0).Should().Be(TimeSpan.FromSeconds(4));
        }

        [Fact]
        public void Estimate_HigherConcurrency_DecreasesEstimate()
        {
            var low = BatchScanOrchestrator.Estimate(100, 100, 1, 0.3);
            var high = BatchScanOrchestrator.Estimate(100, 100, 50, 0.3);
            high.Should().BeLessThan(low);
        }

        [Fact]
        public void Estimate_NeverBelowOneSecond()
        {
            BatchScanOrchestrator.Estimate(1, 0, 50, 0.1).Should().Be(TimeSpan.FromSeconds(1));
        }

        #endregion

        #region Classify

        [Fact]
        public void Classify_CanceledFlag_ReturnsCanceled()
        {
            BatchScanOrchestrator.Classify(null, true, true, canceled: true)
                .Should().Be(BatchScanFailureCategory.Canceled);
        }

        [Fact]
        public void Classify_OperationCanceled_ReturnsCanceled()
        {
            BatchScanOrchestrator.Classify(new OperationCanceledException(), true, false, canceled: false)
                .Should().Be(BatchScanFailureCategory.Canceled);
        }

        [Fact]
        public void Classify_TaskCanceledWithoutUserCancel_ReturnsTimeout()
        {
            BatchScanOrchestrator.Classify(new TaskCanceledException(), true, true, canceled: false)
                .Should().Be(BatchScanFailureCategory.Timeout);
        }

        [Fact]
        public void Classify_TimeoutException_ReturnsTimeout()
        {
            BatchScanOrchestrator.Classify(new TimeoutException(), true, true, canceled: false)
                .Should().Be(BatchScanFailureCategory.Timeout);
        }

        [Fact]
        public void Classify_ConnectionRefused_ReturnsConnectionRefused()
        {
            var ex = new SocketException((int)SocketError.ConnectionRefused);
            BatchScanOrchestrator.Classify(ex, true, true, canceled: false)
                .Should().Be(BatchScanFailureCategory.ConnectionRefused);
        }

        [Fact]
        public void Classify_HostUnreachable_ReturnsUnreachable()
        {
            var ex = new SocketException((int)SocketError.HostUnreachable);
            BatchScanOrchestrator.Classify(ex, true, true, canceled: false)
                .Should().Be(BatchScanFailureCategory.Unreachable);
        }

        [Fact]
        public void Classify_HostNotFound_ReturnsDnsFailure()
        {
            var ex = new SocketException((int)SocketError.HostNotFound);
            BatchScanOrchestrator.Classify(ex, true, true, canceled: false)
                .Should().Be(BatchScanFailureCategory.DnsFailure);
        }

        [Fact]
        public void Classify_NoOpenPorts_ReturnsNoOpenPort()
        {
            BatchScanOrchestrator.Classify(null, reachedTarget: true, hasOpenPorts: false, canceled: false)
                .Should().Be(BatchScanFailureCategory.NoOpenPort);
        }

        [Fact]
        public void Classify_SuccessWithPorts_ReturnsNone()
        {
            BatchScanOrchestrator.Classify(null, true, true, canceled: false)
                .Should().Be(BatchScanFailureCategory.None);
        }

        [Fact]
        public void Classify_UnknownException_ReturnsScanException()
        {
            BatchScanOrchestrator.Classify(new InvalidOperationException("boom"), true, true, canceled: false)
                .Should().Be(BatchScanFailureCategory.ScanException);
        }

        #endregion

        #region ToDisplayText

        [Theory]
        [InlineData(BatchScanFailureCategory.Timeout, "超时")]
        [InlineData(BatchScanFailureCategory.ConnectionRefused, "连接被拒")]
        [InlineData(BatchScanFailureCategory.Unreachable, "主机不可达")]
        [InlineData(BatchScanFailureCategory.DnsFailure, "域名解析失败")]
        [InlineData(BatchScanFailureCategory.NoOpenPort, "无开放端口")]
        [InlineData(BatchScanFailureCategory.ScanException, "扫描异常")]
        [InlineData(BatchScanFailureCategory.Canceled, "已取消")]
        [InlineData(BatchScanFailureCategory.None, "")]
        public void ToDisplayText_MapsAllValues(BatchScanFailureCategory category, string expected)
        {
            BatchScanOrchestrator.ToDisplayText(category).Should().Be(expected);
        }

        #endregion
    }
}
```

- [ ] **Step 3: 跑测试确认失败**

Run: `dotnet test "src\NetSecurityScanner.Core.Tests\NetSecurityScanner.Core.Tests.csproj" -c Debug --nologo --filter "FullyQualifiedName~BatchScanOrchestratorTests"`
Expected: 全部 21 个用例 FAIL（NotImplementedException）

---

## Task 3: 实现 ValidateTargets（GREEN 部分）

**Files:**
- Modify: `src/NetSecurityScanner.Core/Services/BatchScanOrchestrator.cs`

- [ ] **Step 1: 替换 ValidateTargets 实现**

把 `ValidateTargets` 方法的 `=> throw new NotImplementedException();` 替换为：

```csharp
        public static TargetParseOutcome ValidateTargets(IEnumerable<string> raw)
        {
            if (raw == null) return new TargetParseOutcome { Error = "请输入目标" };

            var list = raw.ToList();
            if (list.Count == 0 || list.All(string.IsNullOrWhiteSpace))
            {
                return new TargetParseOutcome { Error = "请输入目标" };
            }

            int total = list.Count;
            var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            var targets = new List<string>();
            int invalid = 0;

            foreach (var entry in list)
            {
                var t = (entry ?? "").Trim();
                if (t.Length == 0 || t.StartsWith("#")) { invalid++; continue; }
                if (!System.Net.IPAddress.TryParse(t, out _)) { invalid++; continue; }
                if (seen.Add(t)) targets.Add(t);
            }

            if (targets.Count > MaxTargets)
            {
                return new TargetParseOutcome { Error = $"目标数量超过 {MaxTargets} 上限，请缩小扫描范围" };
            }
            if (targets.Count == 0)
            {
                return new TargetParseOutcome { Error = "未解析到有效目标" };
            }

            return new TargetParseOutcome
            {
                Targets = targets,
                Total = total,
                Deduped = total - invalid - targets.Count,
                Invalid = invalid
            };
        }
```

同时在文件顶部 `using` 区确认有 `using System.Linq;`（没有则添加）。

- [ ] **Step 2: 跑 ValidateTargets 相关测试**

Run: `dotnet test "src\NetSecurityScanner.Core.Tests\NetSecurityScanner.Core.Tests.csproj" -c Debug --nologo --filter "FullyQualifiedName~ValidateTargets"`
Expected: 6 个用例 PASS，其余仍 FAIL

---

## Task 4: 实现 Estimate / Classify / ToDisplayText（全 GREEN）+ 提交

**Files:**
- Modify: `src/NetSecurityScanner.Core/Services/BatchScanOrchestrator.cs`

- [ ] **Step 1: 替换剩余三个方法**

```csharp
        public static TimeSpan Estimate(int targetCount, int portCount, int concurrency, double timeoutSeconds)
        {
            if (targetCount <= 0 || concurrency <= 0) return TimeSpan.FromSeconds(1);
            double seconds = (targetCount * (double)portCount * timeoutSeconds) / concurrency
                           + (targetCount * 3.0 * timeoutSeconds) / concurrency;
            return TimeSpan.FromSeconds(Math.Max(1, seconds));
        }

        public static BatchScanFailureCategory Classify(Exception? ex, bool reachedTarget, bool hasOpenPorts, bool canceled)
        {
            // 用户取消以令牌标志为准；TaskCanceledException 继承 OperationCanceledException，必须先判 Timeout 系
            if (canceled) return BatchScanFailureCategory.Canceled;
            if (ex is TimeoutException) return BatchScanFailureCategory.Timeout;
            if (ex is TaskCanceledException) return BatchScanFailureCategory.Timeout;
            if (ex is OperationCanceledException) return BatchScanFailureCategory.Canceled;
            if (ex is SocketException se)
            {
                return se.SocketErrorCode switch
                {
                    SocketError.ConnectionRefused => BatchScanFailureCategory.ConnectionRefused,
                    SocketError.HostUnreachable or SocketError.NetworkUnreachable => BatchScanFailureCategory.Unreachable,
                    SocketError.HostNotFound => BatchScanFailureCategory.DnsFailure,
                    _ => BatchScanFailureCategory.ScanException
                };
            }
            if (ex == null && reachedTarget && !hasOpenPorts) return BatchScanFailureCategory.NoOpenPort;
            if (ex == null && reachedTarget && hasOpenPorts) return BatchScanFailureCategory.None;
            return BatchScanFailureCategory.ScanException;
        }

        public static string ToDisplayText(BatchScanFailureCategory category) => category switch
        {
            BatchScanFailureCategory.Timeout => "超时",
            BatchScanFailureCategory.ConnectionRefused => "连接被拒",
            BatchScanFailureCategory.Unreachable => "主机不可达",
            BatchScanFailureCategory.DnsFailure => "域名解析失败",
            BatchScanFailureCategory.NoOpenPort => "无开放端口",
            BatchScanFailureCategory.ScanException => "扫描异常",
            BatchScanFailureCategory.Canceled => "已取消",
            _ => ""
        };
```

同时确认文件顶部 `using` 区有 `using System.Net.Sockets;` 与 `using System.Threading.Tasks;`（没有则添加）。

- [ ] **Step 2: 跑全部编排器测试**

Run: `dotnet test "src\NetSecurityScanner.Core.Tests\NetSecurityScanner.Core.Tests.csproj" -c Debug --nologo --filter "FullyQualifiedName~BatchScanOrchestratorTests"`
Expected: 21 个用例全部 PASS

- [ ] **Step 3: 提交**

```powershell
git add src/NetSecurityScanner.Core/Services/BatchScanOrchestrator.cs src/NetSecurityScanner.Core.Tests/BatchScanOrchestratorTests.cs
git commit -m "feat: 批量扫描编排器(目标校验/耗时预估/失败分类)与单元测试"
```

---

## Task 5: 异步暂停闸门 + 单测

**Files:**
- Create: `src/NetSecurityScanner.Core/Services/AsyncPauseController.cs`
- Test: `src/NetSecurityScanner.Core.Tests/AsyncPauseControllerTests.cs`

- [ ] **Step 1: 写实现**

`src/NetSecurityScanner.Core/Services/AsyncPauseController.cs`：

```csharp
using System.Threading;
using System.Threading.Tasks;

namespace NetSecurityScanner.Core.Services
{
    /// <summary>
    /// 异步暂停闸门：Pause 后 WaitIfPausedAsync 阻塞，Resume 放行；等待支持取消。
    /// 每次批量扫描运行创建一个实例，运行结束后丢弃。
    /// </summary>
    public class AsyncPauseController
    {
        private readonly object _gate = new();
        private TaskCompletionSource<bool> _tcs = NewTcs();

        public bool IsPaused { get; private set; }

        private static TaskCompletionSource<bool> NewTcs() =>
            new(TaskCreationOptions.RunContinuationsAsynchronously);

        public void Pause()
        {
            lock (_gate) { IsPaused = true; }
        }

        public void Resume()
        {
            lock (_gate)
            {
                IsPaused = false;
                _tcs.TrySetResult(true);
                _tcs = NewTcs();
            }
        }

        public async Task WaitIfPausedAsync(CancellationToken ct)
        {
            Task wait;
            lock (_gate)
            {
                if (!IsPaused) return;
                wait = _tcs.Task;
            }
            // WaitAsync(ct)：按等待者取消，不污染共享 TCS（.NET 6+）
            await wait.WaitAsync(ct).ConfigureAwait(false);
        }
    }
}
```

- [ ] **Step 2: 写测试**

`src/NetSecurityScanner.Core.Tests/AsyncPauseControllerTests.cs`：

```csharp
using System;
using System.Threading;
using System.Threading.Tasks;
using FluentAssertions;
using NetSecurityScanner.Core.Services;
using Xunit;

namespace NetSecurityScanner.Tests
{
    public class AsyncPauseControllerTests
    {
        [Fact]
        public async Task WaitIfPausedAsync_NotPaused_CompletesImmediately()
        {
            var controller = new AsyncPauseController();
            await controller.WaitIfPausedAsync(CancellationToken.None);
        }

        [Fact]
        public async Task WaitIfPausedAsync_Paused_BlocksUntilResume()
        {
            var controller = new AsyncPauseController();
            controller.Pause();

            var waitTask = controller.WaitIfPausedAsync(CancellationToken.None);
            await Task.Delay(100);
            waitTask.IsCompleted.Should().BeFalse();

            controller.Resume();
            await waitTask;
        }

        [Fact]
        public async Task WaitIfPausedAsync_Paused_CancellationThrows()
        {
            var controller = new AsyncPauseController();
            controller.Pause();
            using var cts = new CancellationTokenSource(100);

            Func<Task> act = () => controller.WaitIfPausedAsync(cts.Token);
            await act.Should().ThrowAsync<OperationCanceledException>();
        }

        [Fact]
        public async Task Resume_WhenNotPaused_IsIdempotent()
        {
            var controller = new AsyncPauseController();
            controller.Resume();
            await controller.WaitIfPausedAsync(CancellationToken.None);
        }
    }
}
```

- [ ] **Step 3: 跑测试**

Run: `dotnet test "src\NetSecurityScanner.Core.Tests\NetSecurityScanner.Core.Tests.csproj" -c Debug --nologo --filter "FullyQualifiedName~AsyncPauseControllerTests"`
Expected: 4 个用例 PASS

- [ ] **Step 4: 提交**

```powershell
git add src/NetSecurityScanner.Core/Services/AsyncPauseController.cs src/NetSecurityScanner.Core.Tests/AsyncPauseControllerTests.cs
git commit -m "feat: 新增异步暂停闸门与单元测试"
```

---

## Task 6: 配置持久化服务

**Files:**
- Create: `src/NetSecurityScanner.Core/Services/BatchScanSettingsService.cs`

- [ ] **Step 1: 写实现**

```csharp
using System;
using System.Diagnostics;
using System.IO;
using System.Text.Json;
using NetSecurityScanner.Core.Models;

namespace NetSecurityScanner.Core.Services
{
    /// <summary>
    /// 批量扫描配置持久化：%LOCALAPPDATA%\NetSecurityScanner\batch_scan_settings.json。
    /// 读写失败一律静默降级（返回默认值/跳过保存），不影响扫描主流程。
    /// </summary>
    public class BatchScanSettingsService
    {
        private static readonly string SettingsPath = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "NetSecurityScanner", "batch_scan_settings.json");

        private static readonly JsonSerializerOptions JsonOptions = new()
        {
            WriteIndented = true,
            Encoder = System.Text.Encodings.Web.JavaScriptEncoder.UnsafeRelaxedJsonEscaping
        };

        public BatchScanSettings Load()
        {
            try
            {
                if (!File.Exists(SettingsPath)) return new BatchScanSettings();
                var json = File.ReadAllText(SettingsPath);
                return JsonSerializer.Deserialize<BatchScanSettings>(json) ?? new BatchScanSettings();
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"[BatchScanSettingsService] 读取配置失败: {ex.Message}");
                return new BatchScanSettings();
            }
        }

        public void Save(BatchScanSettings settings)
        {
            try
            {
                Directory.CreateDirectory(Path.GetDirectoryName(SettingsPath)!);
                File.WriteAllText(SettingsPath, JsonSerializer.Serialize(settings, JsonOptions));
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"[BatchScanSettingsService] 保存配置失败: {ex.Message}");
            }
        }
    }
}
```

- [ ] **Step 2: 构建 Core 验证**

Run: `dotnet build "src\NetSecurityScanner.Core\NetSecurityScanner.Core.csproj" -c Debug --nologo -v q`
Expected: `已成功生成`，`0 个错误`

- [ ] **Step 3: 提交**

```powershell
git add src/NetSecurityScanner.Core/Services/BatchScanSettingsService.cs
git commit -m "feat: 新增批量扫描配置持久化服务"
```

---

## Task 7: IpScanItem 增加失败分类字段

**Files:**
- Modify: `src/NetSecurityScanner.Desktop/Views/Views/BatchScanWindow.xaml.cs`（约 L921-951 的 `IpScanItem` 类）

- [ ] **Step 1: 添加私有字段**

old_string（在 `IpScanItem` 类字段区）：

```csharp
        private string _threatLevel = "None";
        private string _errorMessage = "";
```

new_string：

```csharp
        private string _threatLevel = "None";
        private string _errorMessage = "";
        private BatchScanFailureCategory _failureCategory = BatchScanFailureCategory.None;
        private string _failureText = "";
```

- [ ] **Step 2: 添加公开属性**

old_string：

```csharp
        public string ErrorMessage { get => _errorMessage; set { _errorMessage = value; OnPropertyChanged(nameof(ErrorMessage)); } }
        public List<PortScanResult> PortResults { get; set; } = new List<PortScanResult>();
```

new_string：

```csharp
        public string ErrorMessage { get => _errorMessage; set { _errorMessage = value; OnPropertyChanged(nameof(ErrorMessage)); } }
        public BatchScanFailureCategory FailureCategory { get => _failureCategory; set { _failureCategory = value; OnPropertyChanged(nameof(FailureCategory)); } }
        public string FailureText { get => _failureText; set { _failureText = value; OnPropertyChanged(nameof(FailureText)); } }
        public List<PortScanResult> PortResults { get; set; } = new List<PortScanResult>();
```

（文件顶部已有 `using NetSecurityScanner.Core.Models;`，无需新增 using。）

- [ ] **Step 3: 构建 Desktop 验证**

Run: `dotnet build "src\NetSecurityScanner.Desktop\NetSecurityScanner.Desktop.csproj" -c Debug --nologo -v q`
Expected: `已成功生成`，`0 个错误`

- [ ] **Step 4: 提交**

```powershell
git add src/NetSecurityScanner.Desktop/Views/Views/BatchScanWindow.xaml.cs
git commit -m "feat: IpScanItem增加失败分类字段"
```

---

## Task 8: 窗口 XAML（列/过滤项/菜单/按钮/状态栏）

**Files:**
- Modify: `src/NetSecurityScanner.Desktop/Views/Views/BatchScanWindow.xaml`

- [ ] **Step 1: 状态栏新增失败分项文本**

old_string：

```xml
                    <TextBlock Name="CurrentScanningTargetTextBlock" Text="当前: -" FontSize="12" Foreground="#7F8C8D"/>
                </StackPanel>
```

new_string：

```xml
                    <TextBlock Name="CurrentScanningTargetTextBlock" Text="当前: -" FontSize="12" Foreground="#7F8C8D"/>
                    <TextBlock Name="FailureBreakdownTextBlock" Text="" FontSize="12" Foreground="#E74C3C" Margin="20,0,0,0"/>
                </StackPanel>
```

- [ ] **Step 2: 状态过滤新增「已取消」**

old_string：

```xml
                                <ComboBoxItem Content="失败" Tag="失败"/>
                            </ComboBox>
                            <TextBlock Text="威胁:" VerticalAlignment="Center" FontSize="11" Foreground="#7F8C8D"/>
```

new_string：

```xml
                                <ComboBoxItem Content="失败" Tag="失败"/>
                                <ComboBoxItem Content="已取消" Tag="已取消"/>
                            </ComboBox>
                            <TextBlock Text="威胁:" VerticalAlignment="Center" FontSize="11" Foreground="#7F8C8D"/>
```

- [ ] **Step 3: 右键菜单新增「重扫本类失败」**

old_string：

```xml
                                    <Separator/>
                                    <MenuItem Header="从列表移除" Click="RemoveTargetMenuItem_Click"/>
```

new_string：

```xml
                                    <Separator/>
                                    <MenuItem Name="RescanCategoryMenuItem" Header="重扫本类失败" SubmenuOpened="RescanCategoryMenuItem_SubmenuOpened"/>
                                    <Separator/>
                                    <MenuItem Header="从列表移除" Click="RemoveTargetMenuItem_Click"/>
```

- [ ] **Step 4: 列表项模板新增失败原因列**

old_string：

```xml
                                            <Grid.ColumnDefinitions>
                                                <ColumnDefinition Width="20"/>
                                                <ColumnDefinition Width="*"/>
                                                <ColumnDefinition Width="50"/>
                                                <ColumnDefinition Width="60"/>
                                            </Grid.ColumnDefinitions>
                                            <TextBlock Grid.Column="0" Text="{Binding StatusIcon}" FontSize="14" Foreground="{Binding ThreatLevel, Converter={StaticResource ThreatLevelToForegroundConverter}}"/>
                                            <TextBlock Grid.Column="1" Text="{Binding IpAddress}" FontWeight="SemiBold" VerticalAlignment="Center" Foreground="{Binding ThreatLevel, Converter={StaticResource ThreatLevelToForegroundConverter}}"/>
                                            <TextBlock Grid.Column="2" Text="{Binding ProgressText}" FontSize="11" Foreground="{Binding ThreatLevel, Converter={StaticResource ThreatLevelToForegroundConverter}}" VerticalAlignment="Center" HorizontalAlignment="Center"/>
                                            <TextBlock Grid.Column="3" Text="{Binding DurationText}" FontSize="11" Foreground="{Binding ThreatLevel, Converter={StaticResource ThreatLevelToForegroundConverter}}" VerticalAlignment="Center" HorizontalAlignment="Right"/>
```

new_string：

```xml
                                            <Grid.ColumnDefinitions>
                                                <ColumnDefinition Width="20"/>
                                                <ColumnDefinition Width="*"/>
                                                <ColumnDefinition Width="50"/>
                                                <ColumnDefinition Width="60"/>
                                                <ColumnDefinition Width="90"/>
                                            </Grid.ColumnDefinitions>
                                            <TextBlock Grid.Column="0" Text="{Binding StatusIcon}" FontSize="14" Foreground="{Binding ThreatLevel, Converter={StaticResource ThreatLevelToForegroundConverter}}"/>
                                            <TextBlock Grid.Column="1" Text="{Binding IpAddress}" FontWeight="SemiBold" VerticalAlignment="Center" Foreground="{Binding ThreatLevel, Converter={StaticResource ThreatLevelToForegroundConverter}}"/>
                                            <TextBlock Grid.Column="2" Text="{Binding ProgressText}" FontSize="11" Foreground="{Binding ThreatLevel, Converter={StaticResource ThreatLevelToForegroundConverter}}" VerticalAlignment="Center" HorizontalAlignment="Center"/>
                                            <TextBlock Grid.Column="3" Text="{Binding DurationText}" FontSize="11" Foreground="{Binding ThreatLevel, Converter={StaticResource ThreatLevelToForegroundConverter}}" VerticalAlignment="Center" HorizontalAlignment="Right"/>
                                            <TextBlock Grid.Column="4" Text="{Binding FailureText}" FontSize="11" Foreground="#E74C3C" VerticalAlignment="Center" HorizontalAlignment="Center" ToolTip="{Binding ErrorMessage}"/>
```

- [ ] **Step 5: 底部按钮栏新增暂停/继续**

old_string：

```xml
            <Button Name="StartBatchScanButton" Content="开始批量扫描" Width="140" Height="40" Margin="5" Background="#27AE60" Foreground="White" FontWeight="Bold" FontSize="14" Click="StartBatchScanButton_Click"/>
            <Button Name="RescanFailedButton" Content="重扫失败目标" Width="120" Height="40" Margin="5" Background="#E67E22" Foreground="White" FontWeight="Bold" IsEnabled="False" Click="RescanFailedButton_Click"/>
```

new_string：

```xml
            <Button Name="StartBatchScanButton" Content="开始批量扫描" Width="140" Height="40" Margin="5" Background="#27AE60" Foreground="White" FontWeight="Bold" FontSize="14" Click="StartBatchScanButton_Click"/>
            <Button Name="PauseBatchScanButton" Content="暂停" Width="100" Height="40" Margin="5" Background="#F39C12" Foreground="White" FontWeight="Bold" Visibility="Collapsed" Click="PauseBatchScanButton_Click"/>
            <Button Name="ResumeBatchScanButton" Content="继续" Width="100" Height="40" Margin="5" Background="#16A085" Foreground="White" FontWeight="Bold" Visibility="Collapsed" Click="ResumeBatchScanButton_Click"/>
            <Button Name="RescanFailedButton" Content="重扫失败目标" Width="120" Height="40" Margin="5" Background="#E67E22" Foreground="White" FontWeight="Bold" IsEnabled="False" Click="RescanFailedButton_Click"/>
```

- [ ] **Step 6: 构建 Desktop 验证（XAML 编译）**

Run: `dotnet build "src\NetSecurityScanner.Desktop\NetSecurityScanner.Desktop.csproj" -c Debug --nologo -v q`
Expected: `已成功生成`，`0 个错误`（此时 Click 处理器尚未存在会报错——若报 `RescanCategoryMenuItem_SubmenuOpened`/`PauseBatchScanButton_Click`/`ResumeBatchScanButton_Click` 不存在，属预期，继续 Task 9-13 后再验证；或先补三个空方法再提交）

**注意：** WPF 编译会校验事件处理器存在性。本任务先补上三个空壳方法保证可编译（Task 12/13 填充实现）：

在 `BatchScanWindow.xaml.cs` 的 `StopBatchScanButton_Click` 方法后插入：

```csharp
        private void PauseBatchScanButton_Click(object sender, RoutedEventArgs e)
        {
        }

        private void ResumeBatchScanButton_Click(object sender, RoutedEventArgs e)
        {
        }

        private void RescanCategoryMenuItem_SubmenuOpened(object sender, RoutedEventArgs e)
        {
        }
```

- [ ] **Step 7: 再次构建并提交**

Run: `dotnet build "src\NetSecurityScanner.Desktop\NetSecurityScanner.Desktop.csproj" -c Debug --nologo -v q`
Expected: `已成功生成`，`0 个错误`

```powershell
git add src/NetSecurityScanner.Desktop/Views/Views/BatchScanWindow.xaml src/NetSecurityScanner.Desktop/Views/Views/BatchScanWindow.xaml.cs
git commit -m "feat: 批量扫描窗口UI(失败原因列/已取消过滤/暂停按钮/分类重扫菜单)"
```

---

## Task 9: 窗口接线——配置记忆（加载/防抖保存）

**Files:**
- Modify: `src/NetSecurityScanner.Desktop/Views/Views/BatchScanWindow.xaml.cs`

- [ ] **Step 1: 新增 using**

old_string：

```csharp
using NetSecurityScanner.Core.Models;
using NetSecurityScanner.Models;
```

new_string：

```csharp
using NetSecurityScanner.Core.Models;
using NetSecurityScanner.Core.Services;
using NetSecurityScanner.Models;
```

- [ ] **Step 2: 新增字段**

old_string：

```csharp
        private int _completedCount;
        private int _failedCount;
        private int _totalVulns;
        private int _totalCritical;
```

new_string：

```csharp
        private int _completedCount;
        private int _failedCount;
        private int _canceledCount;
        private int _totalVulns;
        private int _totalCritical;
        private readonly BatchScanSettingsService _settingsService = new();
        private DispatcherTimer _settingsSaveTimer;
        private bool _loadingSettings;
        private AsyncPauseController _pauseController;
```

- [ ] **Step 3: 构造函数——创建防抖计时器**

old_string：

```csharp
            _elapsedTimer = new DispatcherTimer { Interval = TimeSpan.FromSeconds(1) };
```

new_string：

```csharp
            _settingsSaveTimer = new DispatcherTimer { Interval = TimeSpan.FromMilliseconds(500) };
            _settingsSaveTimer.Tick += (s, e) =>
            {
                _settingsSaveTimer.Stop();
                _settingsService.Save(CaptureSettingsFromUi());
            };

            _elapsedTimer = new DispatcherTimer { Interval = TimeSpan.FromSeconds(1) };
```

- [ ] **Step 4: 构造函数末尾——加载并应用配置**

old_string：

```csharp
            BatchTargetTypeComboBox.SelectedIndex = 0;
        }
```

new_string：

```csharp
            LoadAndApplySettings();
        }
```

（`LoadAndApplySettings` 内部按 Tag 选中下拉项，未匹配时回退到第 0 项，覆盖原 `SelectedIndex = 0` 的语义。）

- [ ] **Step 5: 新增配置读写方法**

在 `BatchTargetTypeComboBox_SelectionChanged` 方法前插入：

```csharp
        /// <summary>
        /// 配置变化时调用：500ms 防抖后统一落盘，避免拖动滑块时高频写盘。
        /// InitializeComponent 期间（计时器尚未创建）与配置回填期间不触发。
        /// </summary>
        private void MarkSettingsDirty()
        {
            if (_loadingSettings || _settingsSaveTimer == null) return;
            _settingsSaveTimer.Stop();
            _settingsSaveTimer.Start();
        }

        private BatchScanSettings CaptureSettingsFromUi() => new()
        {
            ScanModeTag = (BatchScanModeComboBox.SelectedItem as ComboBoxItem)?.Tag?.ToString() ?? "Standard",
            Concurrency = (int)ConcurrencySlider.Value,
            TimeoutSeconds = Math.Round(TimeoutSlider.Value, 1),
            TargetTypeTag = (BatchTargetTypeComboBox.SelectedItem as ComboBoxItem)?.Tag?.ToString() ?? "Range",
            StatusFilterTag = (StatusFilterComboBox.SelectedItem as ComboBoxItem)?.Tag?.ToString() ?? "All",
            ThreatFilterTag = (ThreatFilterComboBox.SelectedItem as ComboBoxItem)?.Tag?.ToString() ?? "All"
        };

        /// <summary>
        /// 启动时还原配置。先设下拉框（其 SelectionChanged 会联动超时默认值），后设滑块以保留已存值。
        /// </summary>
        private void LoadAndApplySettings()
        {
            var settings = _settingsService.Load();
            _loadingSettings = true;
            try
            {
                SelectComboItemByTag(BatchScanModeComboBox, settings.ScanModeTag);
                SelectComboItemByTag(BatchTargetTypeComboBox, settings.TargetTypeTag);
                SelectComboItemByTag(StatusFilterComboBox, settings.StatusFilterTag);
                SelectComboItemByTag(ThreatFilterComboBox, settings.ThreatFilterTag);
                ConcurrencySlider.Value = Math.Clamp(settings.Concurrency, (int)ConcurrencySlider.Minimum, (int)ConcurrencySlider.Maximum);
                TimeoutSlider.Value = Math.Clamp(settings.TimeoutSeconds, TimeoutSlider.Minimum, TimeoutSlider.Maximum);
            }
            finally
            {
                _loadingSettings = false;
            }
        }

        private static void SelectComboItemByTag(ComboBox combo, string tag)
        {
            foreach (var item in combo.Items)
            {
                if (item is ComboBoxItem cbi && string.Equals(cbi.Tag?.ToString(), tag, StringComparison.OrdinalIgnoreCase))
                {
                    combo.SelectedItem = cbi;
                    return;
                }
            }
            if (combo.Items.Count > 0) combo.SelectedIndex = 0;
        }
```

- [ ] **Step 6: 各控件事件接入 MarkSettingsDirty**

6a. old_string：

```csharp
            ConcurrencySlider.ValueChanged += (s, e) => ConcurrencyValueTextBlock.Text = ConcurrencySlider.Value.ToString("F0");
            TimeoutSlider.ValueChanged += (s, e) => TimeoutValueTextBlock.Text = $"{TimeoutSlider.Value:F1}s";
```

new_string：

```csharp
            ConcurrencySlider.ValueChanged += (s, e) => { ConcurrencyValueTextBlock.Text = ConcurrencySlider.Value.ToString("F0"); MarkSettingsDirty(); };
            TimeoutSlider.ValueChanged += (s, e) => { TimeoutValueTextBlock.Text = $"{TimeoutSlider.Value:F1}s"; MarkSettingsDirty(); };
```

6b. old_string：

```csharp
        private void BatchTargetTypeComboBox_SelectionChanged(object sender, SelectionChangedEventArgs e)
        {
            if (BatchTargetTypeComboBox?.SelectedItem is ComboBoxItem selectedItem)
```

new_string：

```csharp
        private void BatchTargetTypeComboBox_SelectionChanged(object sender, SelectionChangedEventArgs e)
        {
            MarkSettingsDirty();
            if (BatchTargetTypeComboBox?.SelectedItem is ComboBoxItem selectedItem)
```

6c. old_string：

```csharp
        private void BatchScanModeComboBox_SelectionChanged(object sender, SelectionChangedEventArgs e)
        {
            if (TimeoutSlider == null) return;
```

new_string：

```csharp
        private void BatchScanModeComboBox_SelectionChanged(object sender, SelectionChangedEventArgs e)
        {
            if (TimeoutSlider == null) return;
            MarkSettingsDirty();
```

6d. old_string：

```csharp
        private void FilterComboBox_SelectionChanged(object sender, SelectionChangedEventArgs e)
        {
            _ipItemsView?.Refresh();
        }
```

new_string：

```csharp
        private void FilterComboBox_SelectionChanged(object sender, SelectionChangedEventArgs e)
        {
            _ipItemsView?.Refresh();
            MarkSettingsDirty();
        }
```

- [ ] **Step 7: 关闭窗口时兜底保存 + 释放暂停闸门**

old_string：

```csharp
        protected override void OnClosing(System.ComponentModel.CancelEventArgs e)
        {
            _cancellationTokenSource?.Cancel();
            _elapsedTimer.Stop();
            base.OnClosing(e);
        }
```

new_string：

```csharp
        protected override void OnClosing(System.ComponentModel.CancelEventArgs e)
        {
            _settingsSaveTimer.Stop();
            _settingsService.Save(CaptureSettingsFromUi());
            _pauseController?.Resume();
            _cancellationTokenSource?.Cancel();
            _elapsedTimer.Stop();
            base.OnClosing(e);
        }
```

- [ ] **Step 8: 构建 + 提交**

Run: `dotnet build "src\NetSecurityScanner.Desktop\NetSecurityScanner.Desktop.csproj" -c Debug --nologo -v q`
Expected: `已成功生成`，`0 个错误`

```powershell
git add src/NetSecurityScanner.Desktop/Views/Views/BatchScanWindow.xaml.cs
git commit -m "feat: 批量扫描配置记忆(启动加载/500ms防抖保存/关闭落盘)"
```

---

## Task 10: 窗口接线——目标解析校验

**Files:**
- Modify: `src/NetSecurityScanner.Desktop/Views/Views/BatchScanWindow.xaml.cs`

- [ ] **Step 1: 替换解析结果处理段**

old_string（`ParseTargetsButton_Click` 内 `_parsedTargets = TargetParser.ParseTargets(...)` 之后的全部 if/else）：

```csharp
                _parsedTargets = TargetParser.ParseTargets(targetValue, targetType);
                if (_parsedTargets.Any())
                {
                    _ipItems.Clear();
                    foreach (var ip in _parsedTargets)
                    {
                        _ipItems.Add(new IpScanItem { IpAddress = ip, Status = "等待中", StatusIcon = "...", ProgressText = "0%", DurationText = "00:00" });
                    }
                    ParsedTargetCountTextBlock.Text = $"已解析: {_parsedTargets.Count} 个目标";
                    ParsedTargetCountTextBlock.Foreground = System.Windows.Media.Brushes.Green;
                    TotalTargetsTextBlock.Text = $"总目标: {_parsedTargets.Count}";
                    MessageBox.Show($"成功解析 {_parsedTargets.Count} 个扫描目标", "解析成功", MessageBoxButton.OK, MessageBoxImage.Information);
                }
                else
                {
                    ParsedTargetCountTextBlock.Text = "已解析: 0 个目标";
                    ParsedTargetCountTextBlock.Foreground = System.Windows.Media.Brushes.Red;
                    MessageBox.Show("未能解析到有效的扫描目标", "解析失败", MessageBoxButton.OK, MessageBoxImage.Warning);
                }
```

new_string：

```csharp
                _parsedTargets = TargetParser.ParseTargets(targetValue, targetType);
                var outcome = BatchScanOrchestrator.ValidateTargets(_parsedTargets);
                if (outcome.Error != null)
                {
                    ParsedTargetCountTextBlock.Text = "已解析: 0 个目标";
                    ParsedTargetCountTextBlock.Foreground = System.Windows.Media.Brushes.Red;
                    MessageBox.Show(outcome.Error, "解析失败", MessageBoxButton.OK, MessageBoxImage.Warning);
                    return;
                }

                _parsedTargets = outcome.Targets;
                _ipItems.Clear();
                foreach (var ip in _parsedTargets)
                {
                    _ipItems.Add(new IpScanItem { IpAddress = ip, Status = "等待中", StatusIcon = "...", ProgressText = "0%", DurationText = "00:00" });
                }
                ParsedTargetCountTextBlock.Text = $"已解析: {_parsedTargets.Count} 个目标 (总计 {outcome.Total} / 去重 {outcome.Deduped} / 忽略 {outcome.Invalid})";
                ParsedTargetCountTextBlock.Foreground = System.Windows.Media.Brushes.Green;
                TotalTargetsTextBlock.Text = $"总目标: {_parsedTargets.Count}";
```

- [ ] **Step 2: 构建 + 提交**

Run: `dotnet build "src\NetSecurityScanner.Desktop\NetSecurityScanner.Desktop.csproj" -c Debug --nologo -v q`
Expected: `已成功生成`，`0 个错误`

```powershell
git add src/NetSecurityScanner.Desktop/Views/Views/BatchScanWindow.xaml.cs
git commit -m "feat: 目标解析接入去重与合法性校验(三段式提示)"
```

---

## Task 11: 窗口接线——扫描前预估与确认

**Files:**
- Modify: `src/NetSecurityScanner.Desktop/Views/Views/BatchScanWindow.xaml.cs`

- [ ] **Step 1: 替换开始按钮处理器**

old_string：

```csharp
        private async void StartBatchScanButton_Click(object sender, RoutedEventArgs e)
        {
            await RunBatchScanAsync(_parsedTargets, rescanOnlyFailed: false);
        }
```

new_string：

```csharp
        private async void StartBatchScanButton_Click(object sender, RoutedEventArgs e)
        {
            if (_parsedTargets == null || !_parsedTargets.Any())
            {
                MessageBox.Show("请先解析扫描目标", "提示", MessageBoxButton.OK, MessageBoxImage.Information);
                return;
            }

            BuildScanConfigFromUi();
            if (_parsedTargets.Count > BatchScanOrchestrator.ConfirmThreshold)
            {
                var estimate = BatchScanOrchestrator.Estimate(
                    _parsedTargets.Count, _scanPorts.Count, (int)ConcurrencySlider.Value, TimeoutSlider.Value);
                var confirm = MessageBox.Show(
                    $"目标数: {_parsedTargets.Count}\n端口数: {_scanPorts.Count}\n并发数: {(int)ConcurrencySlider.Value}\n预估耗时下限: {estimate:hh\\:mm\\:ss}（粗略下限，实际通常为数倍）\n\n确认开始批量扫描？",
                    "确认批量扫描", MessageBoxButton.YesNo, MessageBoxImage.Question);
                if (confirm != MessageBoxResult.Yes) return;
            }

            await RunBatchScanAsync(_parsedTargets, rescanOnlyFailed: false);
        }
```

- [ ] **Step 2: 构建 + 提交**

Run: `dotnet build "src\NetSecurityScanner.Desktop\NetSecurityScanner.Desktop.csproj" -c Debug --nologo -v q`
Expected: `已成功生成`，`0 个错误`

```powershell
git add src/NetSecurityScanner.Desktop/Views/Views/BatchScanWindow.xaml.cs
git commit -m "feat: 扫描前规模确认与耗时下限预估(>256目标弹窗)"
```

---

## Task 12: 窗口接线——暂停/继续 + 失败分类 + 统计

**Files:**
- Modify: `src/NetSecurityScanner.Desktop/Views/Views/BatchScanWindow.xaml.cs`

- [ ] **Step 1: 扫描启动段接入暂停闸门与按钮状态**

old_string：

```csharp
            _completedCount = 0;
            _failedCount = 0;
            _totalVulns = 0;
            _totalCritical = 0;
            _currentRunCount = targets.Count;
            _portResultsByIp.Clear();
            _cancellationTokenSource = new CancellationTokenSource();
            var token = _cancellationTokenSource.Token;

            StartBatchScanButton.IsEnabled = false;
            RescanFailedButton.IsEnabled = false;
            StopBatchScanButton.IsEnabled = true;
            ExportBatchReportButton.IsEnabled = false;
```

new_string：

```csharp
            _completedCount = 0;
            _failedCount = 0;
            _canceledCount = 0;
            _totalVulns = 0;
            _totalCritical = 0;
            _currentRunCount = targets.Count;
            _portResultsByIp.Clear();
            _cancellationTokenSource = new CancellationTokenSource();
            _pauseController = new AsyncPauseController();
            var token = _cancellationTokenSource.Token;

            StartBatchScanButton.IsEnabled = false;
            RescanFailedButton.IsEnabled = false;
            StopBatchScanButton.IsEnabled = true;
            ExportBatchReportButton.IsEnabled = false;
            PauseBatchScanButton.Visibility = Visibility.Visible;
            PauseBatchScanButton.IsEnabled = false; // 阶段1为单次流式调用，不支持暂停
            ResumeBatchScanButton.Visibility = Visibility.Collapsed;
```

- [ ] **Step 2: 阶段2 开始前启用暂停按钮**

old_string：

```csharp
                BatchScanStatusTextBlock.Text = $"阶段2/2: 漏洞扫描 ({targetsWithPorts.Count} 个目标有开放端口)...";
```

new_string：

```csharp
                BatchScanStatusTextBlock.Text = $"阶段2/2: 漏洞扫描 ({targetsWithPorts.Count} 个目标有开放端口)...";
                PauseBatchScanButton.IsEnabled = true;
```

- [ ] **Step 3: finally 段复位暂停状态与重扫条件**

old_string：

```csharp
                StartBatchScanButton.IsEnabled = true;
                StopBatchScanButton.IsEnabled = false;
                RescanFailedButton.IsEnabled = _ipItems.Any(i => i.Status == "失败");
                ExportBatchReportButton.IsEnabled = true;
```

new_string：

```csharp
                _pauseController?.Resume(); // 防止仍有派发线程悬挂在闸门
                _pauseController = null;
                PauseBatchScanButton.Visibility = Visibility.Collapsed;
                ResumeBatchScanButton.Visibility = Visibility.Collapsed;

                StartBatchScanButton.IsEnabled = true;
                StopBatchScanButton.IsEnabled = false;
                RescanFailedButton.IsEnabled = _ipItems.Any(i => i.Status == "失败" || i.Status == "已取消");
                ExportBatchReportButton.IsEnabled = true;
```

- [ ] **Step 4: 完成弹窗增加已取消统计**

old_string：

```csharp
                MessageBox.Show(
                    $"批量扫描完成！\n\n总目标: {targets.Count}\n已完成: {_completedCount}\n失败: {_failedCount}\n总漏洞: {_totalVulns}\n严重漏洞: {_totalCritical}\n耗时: {_totalStopwatch.Elapsed:hh\\:mm\\:ss}",
                    "扫描完成", MessageBoxButton.OK, MessageBoxImage.Information);
```

new_string：

```csharp
                MessageBox.Show(
                    $"批量扫描完成！\n\n总目标: {targets.Count}\n已完成: {_completedCount}\n失败: {_failedCount}\n已取消: {_canceledCount}\n总漏洞: {_totalVulns}\n严重漏洞: {_totalCritical}\n耗时: {_totalStopwatch.Elapsed:hh\\:mm\\:ss}",
                    "扫描完成", MessageBoxButton.OK, MessageBoxImage.Information);
```

- [ ] **Step 5: 单目标扫描方法接入暂停闸门 + openPorts 提前声明**

old_string：

```csharp
            await semaphore.WaitAsync(token);
            var itemStopwatch = new Stopwatch();

            try
            {
                _portResultsByIp.TryGetValue(ip, out var openPorts);
                openPorts = openPorts ?? new List<PortScanResult>();
```

new_string：

```csharp
            await semaphore.WaitAsync(token);
            if (_pauseController != null)
            {
                await _pauseController.WaitIfPausedAsync(token);
            }
            var itemStopwatch = new Stopwatch();
            List<PortScanResult> openPorts = new List<PortScanResult>();

            try
            {
                _portResultsByIp.TryGetValue(ip, out var foundPorts);
                openPorts = foundPorts ?? new List<PortScanResult>();
```

- [ ] **Step 6: 成功分支标注「无开放端口」**

old_string：

```csharp
                    else
                        _ipItems[index].ThreatLevel = "None";

                    Interlocked.Increment(ref _completedCount);
```

new_string：

```csharp
                    else
                        _ipItems[index].ThreatLevel = "None";

                    if (openPorts.Count == 0)
                    {
                        // 信息标注：不改变统计语义，仅说明无漏洞的原因
                        _ipItems[index].FailureCategory = BatchScanFailureCategory.NoOpenPort;
                        _ipItems[index].FailureText = BatchScanOrchestrator.ToDisplayText(BatchScanFailureCategory.NoOpenPort);
                    }

                    Interlocked.Increment(ref _completedCount);
```

- [ ] **Step 7: 取消分支归类为「已取消」**

old_string：

```csharp
            catch (OperationCanceledException) { throw; }
```

new_string：

```csharp
            catch (OperationCanceledException)
            {
                itemStopwatch.Stop();
                _ = Dispatcher.BeginInvoke(() =>
                {
                    _ipItems[index].Status = "已取消";
                    _ipItems[index].StatusIcon = "⊘";
                    _ipItems[index].DurationText = itemStopwatch.Elapsed.ToString(@"mm\:ss");
                    _ipItems[index].FailureCategory = BatchScanFailureCategory.Canceled;
                    _ipItems[index].FailureText = BatchScanOrchestrator.ToDisplayText(BatchScanFailureCategory.Canceled);

                    Interlocked.Increment(ref _canceledCount);
                    UpdateGlobalStatistics();
                    UpdateProgressBar();
                });
                throw;
            }
```

- [ ] **Step 8: 失败分支接入分类**

old_string：

```csharp
            catch (Exception ex)
            {
                itemStopwatch.Stop();
                _ = Dispatcher.BeginInvoke(() =>
                {
                    _ipItems[index].Status = "失败";
                    _ipItems[index].StatusIcon = "X";
                    _ipItems[index].ProgressText = "失败";
                    _ipItems[index].DurationText = itemStopwatch.Elapsed.ToString(@"mm\:ss");
                    _ipItems[index].ErrorMessage = ex.Message;
```

new_string：

```csharp
            catch (Exception ex)
            {
                itemStopwatch.Stop();
                var category = BatchScanOrchestrator.Classify(ex, reachedTarget: true, hasOpenPorts: openPorts.Count > 0, canceled: token.IsCancellationRequested);
                _ = Dispatcher.BeginInvoke(() =>
                {
                    _ipItems[index].Status = "失败";
                    _ipItems[index].StatusIcon = "X";
                    _ipItems[index].ProgressText = "失败";
                    _ipItems[index].DurationText = itemStopwatch.Elapsed.ToString(@"mm\:ss");
                    _ipItems[index].ErrorMessage = ex.Message;
                    _ipItems[index].FailureCategory = category;
                    _ipItems[index].FailureText = category == BatchScanFailureCategory.ScanException
                        ? $"{BatchScanOrchestrator.ToDisplayText(category)}: {ex.Message}"
                        : BatchScanOrchestrator.ToDisplayText(category);
```

- [ ] **Step 9: 进度统计计入已取消**

old_string：

```csharp
            int done = _completedCount + _failedCount;
```

new_string：

```csharp
            int done = _completedCount + _failedCount + _canceledCount;
```

- [ ] **Step 10: 全局统计追加失败分类分项**

old_string：

```csharp
        private void UpdateGlobalStatistics()
        {
            CompletedTargetsTextBlock.Text = $"已完成: {_completedCount}";
            FailedTargetsTextBlock.Text = $"失败: {_failedCount}";
            TotalVulnerabilitiesTextBlock.Text = $"总漏洞: {_totalVulns}";
            TotalCriticalTextBlock.Text = $"严重: {_totalCritical}";
        }
```

new_string：

```csharp
        private void UpdateGlobalStatistics()
        {
            CompletedTargetsTextBlock.Text = $"已完成: {_completedCount}";
            FailedTargetsTextBlock.Text = $"失败: {_failedCount}";
            TotalVulnerabilitiesTextBlock.Text = $"总漏洞: {_totalVulns}";
            TotalCriticalTextBlock.Text = $"严重: {_totalCritical}";

            var breakdown = _ipItems
                .Where(i => i.FailureCategory != BatchScanFailureCategory.None)
                .GroupBy(i => i.FailureCategory)
                .OrderBy(g => g.Key)
                .Select(g => $"{BatchScanOrchestrator.ToDisplayText(g.Key)}: {g.Count()}")
                .ToList();
            FailureBreakdownTextBlock.Text = breakdown.Count > 0 ? string.Join("   ", breakdown) : "";
        }
```

- [ ] **Step 11: 填充暂停/继续处理器（替换 Task 8 的空壳）**

old_string：

```csharp
        private void PauseBatchScanButton_Click(object sender, RoutedEventArgs e)
        {
        }

        private void ResumeBatchScanButton_Click(object sender, RoutedEventArgs e)
        {
        }
```

new_string：

```csharp
        private void PauseBatchScanButton_Click(object sender, RoutedEventArgs e)
        {
            if (_pauseController == null) return;
            _pauseController.Pause();
            PauseBatchScanButton.Visibility = Visibility.Collapsed;
            ResumeBatchScanButton.Visibility = Visibility.Visible;
            BatchScanStatusTextBlock.Text = "已暂停（进行中的目标将继续完成）";
        }

        private void ResumeBatchScanButton_Click(object sender, RoutedEventArgs e)
        {
            if (_pauseController == null) return;
            _pauseController.Resume();
            ResumeBatchScanButton.Visibility = Visibility.Collapsed;
            PauseBatchScanButton.Visibility = Visibility.Visible;
            BatchScanStatusTextBlock.Text = "继续扫描...";
        }
```

- [ ] **Step 12: 构建 + 提交**

Run: `dotnet build "src\NetSecurityScanner.Desktop\NetSecurityScanner.Desktop.csproj" -c Debug --nologo -v q`
Expected: `已成功生成`，`0 个错误`

```powershell
git add src/NetSecurityScanner.Desktop/Views/Views/BatchScanWindow.xaml.cs
git commit -m "feat: 阶段2暂停继续与失败分类接入扫描流水线"
```

---

## Task 13: 窗口接线——按失败类别重扫

**Files:**
- Modify: `src/NetSecurityScanner.Desktop/Views/Views/BatchScanWindow.xaml.cs`

- [ ] **Step 1: 重构「重扫失败目标」并抽出重置方法**

old_string：

```csharp
        private async void RescanFailedButton_Click(object sender, RoutedEventArgs e)
        {
            var failedTargets = _ipItems.Where(i => i.Status == "失败").Select(i => i.IpAddress).ToList();
            if (!failedTargets.Any())
            {
                MessageBox.Show("当前没有失败的扫描目标", "提示", MessageBoxButton.OK, MessageBoxImage.Information);
                return;
            }

            foreach (var ip in failedTargets)
            {
                var item = _ipItems.FirstOrDefault(i => i.IpAddress.Equals(ip, StringComparison.OrdinalIgnoreCase));
                if (item != null)
                {
                    item.Status = "等待中";
                    item.StatusIcon = "...";
                    item.ProgressText = "0%";
                    item.DurationText = "00:00";
                    item.ErrorMessage = "";
                }
            }

            await RunBatchScanAsync(failedTargets, rescanOnlyFailed: true);
        }
```

new_string：

```csharp
        private async void RescanFailedButton_Click(object sender, RoutedEventArgs e)
        {
            var failedTargets = _ipItems
                .Where(i => i.Status == "失败" || i.Status == "已取消")
                .Select(i => i.IpAddress)
                .ToList();
            if (!failedTargets.Any())
            {
                MessageBox.Show("当前没有失败或已取消的扫描目标", "提示", MessageBoxButton.OK, MessageBoxImage.Information);
                return;
            }

            ResetItemsForRescan(failedTargets);
            await RunBatchScanAsync(failedTargets, rescanOnlyFailed: true);
        }

        /// <summary>
        /// 将指定目标重置为「等待中」并清空失败分类，供重扫前调用。
        /// </summary>
        private void ResetItemsForRescan(IEnumerable<string> ips)
        {
            foreach (var ip in ips)
            {
                var item = _ipItems.FirstOrDefault(i => i.IpAddress.Equals(ip, StringComparison.OrdinalIgnoreCase));
                if (item != null)
                {
                    item.Status = "等待中";
                    item.StatusIcon = "...";
                    item.ProgressText = "0%";
                    item.DurationText = "00:00";
                    item.ErrorMessage = "";
                    item.FailureCategory = BatchScanFailureCategory.None;
                    item.FailureText = "";
                }
            }
        }
```

- [ ] **Step 2: 填充按类别重扫菜单（替换 Task 8 的空壳）**

old_string：

```csharp
        private void RescanCategoryMenuItem_SubmenuOpened(object sender, RoutedEventArgs e)
        {
        }
```

new_string：

```csharp
        private void RescanCategoryMenuItem_SubmenuOpened(object sender, RoutedEventArgs e)
        {
            RescanCategoryMenuItem.Items.Clear();
            var groups = _ipItems
                .Where(i => (i.Status == "失败" || i.Status == "已取消") && i.FailureCategory != BatchScanFailureCategory.None)
                .GroupBy(i => i.FailureCategory)
                .OrderBy(g => g.Key)
                .ToList();

            foreach (var group in groups)
            {
                var menuItem = new MenuItem
                {
                    Header = $"{BatchScanOrchestrator.ToDisplayText(group.Key)} ({group.Count()})",
                    Tag = group.Key
                };
                menuItem.Click += RescanCategoryItem_Click;
                RescanCategoryMenuItem.Items.Add(menuItem);
            }
            RescanCategoryMenuItem.IsEnabled = RescanCategoryMenuItem.Items.Count > 0;
        }

        private async void RescanCategoryItem_Click(object sender, RoutedEventArgs e)
        {
            if ((sender as MenuItem)?.Tag is not BatchScanFailureCategory category) return;

            var targets = _ipItems
                .Where(i => (i.Status == "失败" || i.Status == "已取消") && i.FailureCategory == category)
                .Select(i => i.IpAddress)
                .ToList();
            if (!targets.Any()) return;

            ResetItemsForRescan(targets);
            await RunBatchScanAsync(targets, rescanOnlyFailed: true);
        }
```

- [ ] **Step 3: 构建 + 提交**

Run: `dotnet build "src\NetSecurityScanner.Desktop\NetSecurityScanner.Desktop.csproj" -c Debug --nologo -v q`
Expected: `已成功生成`，`0 个错误`

```powershell
git add src/NetSecurityScanner.Desktop/Views/Views/BatchScanWindow.xaml.cs
git commit -m "feat: 按失败类别精确重扫(右键动态子菜单)"
```

---

## Task 14: 全量验证与手动验收

- [ ] **Step 1: 全量单测**

Run: `dotnet test "src\NetSecurityScanner.Core.Tests\NetSecurityScanner.Core.Tests.csproj" -c Debug --nologo -v q`
Expected: `已通过!`，总计 273（248 基线 + 21 编排器 + 4 暂停闸门），失败 0

- [ ] **Step 2: Desktop 构建**

Run: `dotnet build "src\NetSecurityScanner.Desktop\NetSecurityScanner.Desktop.csproj" -c Debug --nologo -v q`
Expected: `已成功生成`，`0 个错误`

- [ ] **Step 3: 手动验收清单（运行程序逐项核对）**

Run: `dotnet run --project "src\NetSecurityScanner.Desktop\NetSecurityScanner.Desktop.csproj" -c Debug --no-build --nologo`

- [ ] 修改模式/并发/超时/目标类型/过滤 → 关闭并重开窗口，全部还原
- [ ] 手动列表输入 `192.168.1.1`、`192.168.1.1`、`bad-ip`、`# 注释`、空行 → 提示「已解析: 1 个目标 (总计 5 / 去重 1 / 忽略 3)」
- [ ] 目标数 > 256（如 `10.0.0.1-10.0.1.44`）→ 开始前出现含预估耗时的确认弹窗，点「否」不扫描
- [ ] 正常小网段扫描，阶段2 点「暂停」→ 列表停止新增完成项，状态栏显示已暂停；点「继续」→ 恢复
- [ ] 阶段1 期间「暂停」按钮置灰
- [ ] 扫描中点「停止」→ 未完成项变为「已取消」，失败分项显示「已取消: N」，状态过滤选「已取消」可筛出
- [ ] 对无开放端口目标（如本机未开端口 IP）→ 状态「已完成」，失败原因列显示「无开放端口」
- [ ] 右键「重扫本类失败」→ 子菜单列出类别与数量，点击后仅该类目标重置并重跑
- [ ] 导出 HTML/CSV/JSON 内容与改动前结构一致（失败原因仅体现在列表与状态栏，不改导出格式）

- [ ] **Step 4: 确认工作区状态**

Run: `git status --short; git log --oneline -12`
Expected: 工作区干净；12 个原子提交按 Task 1-13 顺序排列
