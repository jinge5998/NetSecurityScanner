# 批量扫描 S2：结果分析面板与列表排序 实施计划

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 为批量扫描窗口新增内嵌「整体分析」页签（威胁分布条带/TOP 漏洞榜/TOP 风险主机/端口分布，实时节流刷新+双向钻取），并为结果列表增加可点击排序表头（排序状态记忆）。

**Architecture:** 聚合逻辑下沉 `NetSecurityScanner.Core`（`BatchScanAnalyticsService` 静态纯函数 + DTO + `IpNumericComparer`），窗口 `BatchScanWindow` 只做投影、绑定与交互。单测放 `NetSecurityScanner.Core.Tests`（xUnit + FluentAssertions）。

**Tech Stack:** C# / .NET 6 / WPF / xUnit / FluentAssertions

**Spec:** `docs/superpowers/specs/2026-10-30-batch-scan-analytics-design.md`

**命令约定：** 所有命令在仓库根目录 `d:\360安全浏览器下载\软件开发备份\网络安全漏洞扫描\NetSecurityScanner` 下执行。

**已核对的现有代码事实（实现时以此为锚）：**
- `BatchScanWindow.xaml.cs`：`UpdateGlobalStatistics()` 在 L726；`MarkSettingsDirty()` L102（500ms 防抖入口）；`CaptureSettingsFromUi()` L109；`LoadAndApplySettings()` L122；扫描完成点 L382（`BatchScanStatusTextBlock.Text = "扫描完成"`）；`IpListView_SelectionChanged` L750；`IpScanItem` 类 L1131-1165（含 `PortResults: List<PortScanResult>`、`VulnResults: List<VulnerabilityResult>`）；`DurationText` 赋值三处：L635、L676、L695，重置处 L299；`_ipItemsView` 为 `ListCollectionView` 且 `Filter = IpItemFilter`。
- `BatchScanWindow.xaml`：IP 列表卡片 Grid 行定义在 L144-147（Auto/Auto/*）；过滤行 L151-170；`IpListView` L171-202（`Grid.Row="2"`），行模板列 L186-197（20/*/50/60/90）；`DetailTabControl` L225，含「开放端口」L226、「漏洞列表」L237 两个 TabItem。
- Core 模型命名空间注意：`VulnerabilityResult`/`PortScanResult` 在 `NetSecurityScanner.Models`（属性：VulnerabilityResult.Name/RiskLevel/Port(int?)/Service/CveId；PortScanResult.PortNumber/Service）；S1 新模型在 `NetSecurityScanner.Core.Models`。新文件统一用 `NetSecurityScanner.Core.Models`，引用漏洞模型时 `using NetSecurityScanner.Models;`。
- `ThreatLevelToForegroundConverter` 已存在（.cs L1191），可直接在行模板复用。

---

## 文件结构

| 文件 | 动作 | 职责 |
|---|---|---|
| `src/NetSecurityScanner.Core/Models/BatchScanAnalysisDtos.cs` | 新建 | 分析输入/输出 DTO（6 个类） |
| `src/NetSecurityScanner.Core/Services/IpNumericComparer.cs` | 新建 | IPv4 数值比较器（单例） |
| `src/NetSecurityScanner.Core/Services/BatchScanAnalyticsService.cs` | 新建 | Analyze 聚合 + ThreatWeight/RiskWeight |
| `src/NetSecurityScanner.Core.Tests/BatchScanAnalyticsServiceTests.cs` | 新建 | 12 组聚合单测 |
| `src/NetSecurityScanner.Core.Tests/IpNumericComparerTests.cs` | 新建 | 3 组比较器单测 |
| `src/NetSecurityScanner.Core/Models/BatchScanSettings.cs` | 修改 | 增加 SortField/SortDescending |
| `src/NetSecurityScanner.Desktop/Views/Views/BatchScanWindow.xaml` | 修改 | 排序表头行、行模板漏洞列、分析页签 |
| `src/NetSecurityScanner.Desktop/Views/Views/BatchScanWindow.xaml.cs` | 修改 | 排序逻辑、分析刷新节流、钻取、DurationSeconds |

---

## Task 1: Core DTO + IP 数值比较器

**Files:**
- Create: `src/NetSecurityScanner.Core/Models/BatchScanAnalysisDtos.cs`
- Create: `src/NetSecurityScanner.Core/Services/IpNumericComparer.cs`

- [ ] **Step 1: 创建分析 DTO**

`src/NetSecurityScanner.Core/Models/BatchScanAnalysisDtos.cs`：

```csharp
using System;
using System.Collections.Generic;
using NetSecurityScanner.Models;

namespace NetSecurityScanner.Core.Models
{
    /// <summary>主机开放端口事实（分析投影用）。</summary>
    public class PortFact
    {
        public int Port { get; init; }
        public string Service { get; init; } = "";
    }

    /// <summary>单台主机的分析输入（由窗口从 IpScanItem 投影）。</summary>
    public class HostAnalysisInput
    {
        public string IpAddress { get; init; } = "";
        public string Status { get; init; } = "";
        public string ThreatLevel { get; init; } = "None";
        public int OpenPortsCount { get; init; }
        public int VulnCount { get; init; }
        public int CriticalCount { get; init; }
        public int HighCount { get; init; }
        public IReadOnlyList<PortFact> Ports { get; init; } = Array.Empty<PortFact>();
        public IReadOnlyList<VulnerabilityResult> Vulns { get; init; } = Array.Empty<VulnerabilityResult>();
    }

    /// <summary>分布条目：某级别的数量与占比。</summary>
    public class RiskDistributionItem
    {
        public string Level { get; set; } = "";
        public int Count { get; set; }
        public double Ratio { get; set; }
    }

    /// <summary>TOP 漏洞条目：按 Name+Port+Service 聚合。</summary>
    public class TopVulnerabilityItem
    {
        public string Name { get; set; } = "";
        public int? Port { get; set; }
        public string Service { get; set; } = "";
        public string CveId { get; set; } = "";
        public string HighestRisk { get; set; } = "";
        public int AffectedHostCount { get; set; }
        public IReadOnlyList<string> AffectedHosts { get; set; } = Array.Empty<string>();
    }

    /// <summary>TOP 风险主机条目。</summary>
    public class TopHostItem
    {
        public string IpAddress { get; set; } = "";
        public string ThreatLevel { get; set; } = "None";
        public int VulnCount { get; set; }
        public int CriticalCount { get; set; }
        public int HighCount { get; set; }
        public int OpenPortsCount { get; set; }
    }

    /// <summary>端口/服务分布条目。</summary>
    public class PortDistributionItem
    {
        public int Port { get; set; }
        public string Service { get; set; } = "";
        public int HostCount { get; set; }
    }

    /// <summary>分析结果总载体。</summary>
    public class BatchScanAnalysisResult
    {
        public List<RiskDistributionItem> HostThreatDistribution { get; set; } = new();
        public List<RiskDistributionItem> VulnRiskDistribution { get; set; } = new();
        public List<TopVulnerabilityItem> TopVulnerabilities { get; set; } = new();
        public List<TopHostItem> TopHosts { get; set; } = new();
        public List<PortDistributionItem> PortDistribution { get; set; } = new();
    }
}
```

- [ ] **Step 2: 创建 IPv4 数值比较器**

`src/NetSecurityScanner.Core/Services/IpNumericComparer.cs`：

```csharp
using System;
using System.Collections.Generic;

namespace NetSecurityScanner.Core.Services
{
    /// <summary>
    /// IPv4 四段数值比较器（升序）。无法解析为合法 IPv4 的值排在最后；
    /// 两者均非法时按字典序，保证排序稳定。
    /// </summary>
    public sealed class IpNumericComparer : IComparer<string>
    {
        public static readonly IpNumericComparer Instance = new();

        private IpNumericComparer() { }

        public int Compare(string? x, string? y)
        {
            bool xOk = TryKey(x, out long kx);
            bool yOk = TryKey(y, out long ky);
            if (xOk && yOk) return kx.CompareTo(ky);
            if (xOk) return -1;
            if (yOk) return 1;
            return string.CompareOrdinal(x, y);
        }

        private static bool TryKey(string? ip, out long key)
        {
            key = 0;
            if (string.IsNullOrWhiteSpace(ip)) return false;
            var parts = ip.Split('.');
            if (parts.Length != 4) return false;
            for (int i = 0; i < 4; i++)
            {
                if (!int.TryParse(parts[i], out int seg) || seg < 0 || seg > 255) return false;
                key = (key << 8) | (uint)seg;
            }
            return true;
        }
    }
}
```

- [ ] **Step 3: 构建 Core 验证通过**

Run: `dotnet build "src\NetSecurityScanner.Core\NetSecurityScanner.Core.csproj" -c Debug --nologo -v q`
Expected: 输出含 `已成功生成`，`0 个错误`

- [ ] **Step 4: 提交**

```powershell
git add src/NetSecurityScanner.Core/Models/BatchScanAnalysisDtos.cs src/NetSecurityScanner.Core/Services/IpNumericComparer.cs
git commit -m "feat: 新增批量扫描分析 DTO 与 IPv4 数值比较器"
```

---

## Task 2: 分析服务骨架 + 全部失败测试（RED）

**Files:**
- Create: `src/NetSecurityScanner.Core/Services/BatchScanAnalyticsService.cs`
- Test: `src/NetSecurityScanner.Core.Tests/BatchScanAnalyticsServiceTests.cs`
- Test: `src/NetSecurityScanner.Core.Tests/IpNumericComparerTests.cs`

- [ ] **Step 1: 写骨架（方法全部抛 NotImplementedException，保证可编译）**

`src/NetSecurityScanner.Core/Services/BatchScanAnalyticsService.cs`：

```csharp
using System;
using System.Collections.Generic;
using NetSecurityScanner.Core.Models;

namespace NetSecurityScanner.Core.Services
{
    /// <summary>
    /// 批量扫描结果分析纯逻辑：威胁分布、TOP 漏洞/主机、端口分布。无 IO、无 UI 依赖。
    /// </summary>
    public static class BatchScanAnalyticsService
    {
        public const string StatusCompleted = "已完成";

        public static int ThreatWeight(string threatLevel)
            => throw new NotImplementedException();

        public static int RiskWeight(string riskLevel)
            => throw new NotImplementedException();

        public static BatchScanAnalysisResult Analyze(IReadOnlyList<HostAnalysisInput> hosts, int topN = 10)
            => throw new NotImplementedException();
    }
}
```

- [ ] **Step 2: 写分析服务测试文件**

`src/NetSecurityScanner.Core.Tests/BatchScanAnalyticsServiceTests.cs`：

```csharp
using System;
using System.Collections.Generic;
using FluentAssertions;
using NetSecurityScanner.Core.Models;
using NetSecurityScanner.Core.Services;
using NetSecurityScanner.Models;
using Xunit;

namespace NetSecurityScanner.Tests
{
    public class BatchScanAnalyticsServiceTests
    {
        private static HostAnalysisInput Host(string ip, string status = "已完成", string threat = "None",
            int vulns = 0, int critical = 0, int high = 0, int ports = 0,
            IReadOnlyList<VulnerabilityResult>? vulnList = null,
            IReadOnlyList<PortFact>? portList = null) => new()
        {
            IpAddress = ip,
            Status = status,
            ThreatLevel = threat,
            VulnCount = vulns,
            CriticalCount = critical,
            HighCount = high,
            OpenPortsCount = ports,
            Vulns = vulnList ?? Array.Empty<VulnerabilityResult>(),
            Ports = portList ?? Array.Empty<PortFact>()
        };

        private static VulnerabilityResult Vuln(string name, string risk, int? port = null, string service = "", string cve = "")
            => new() { Name = name, RiskLevel = risk, Port = port, Service = service, CveId = cve };

        [Fact]
        public void Analyze_EmptyInput_ReturnsEmptyResult()
        {
            var result = BatchScanAnalyticsService.Analyze(new List<HostAnalysisInput>());

            result.HostThreatDistribution.Should().BeEmpty();
            result.VulnRiskDistribution.Should().BeEmpty();
            result.TopVulnerabilities.Should().BeEmpty();
            result.TopHosts.Should().BeEmpty();
            result.PortDistribution.Should().BeEmpty();
        }

        [Fact]
        public void Analyze_OnlyCompletedHosts_AreCounted()
        {
            var hosts = new List<HostAnalysisInput>
            {
                Host("10.0.0.1", status: "已完成", threat: "High", vulns: 2),
                Host("10.0.0.2", status: "扫描中", threat: "Critical", vulns: 9),
                Host("10.0.0.3", status: "失败", threat: "Critical", vulns: 9),
                Host("10.0.0.4", status: "已取消", threat: "Critical", vulns: 9)
            };

            var result = BatchScanAnalyticsService.Analyze(hosts);

            result.HostThreatDistribution.Should().ContainSingle();
            result.HostThreatDistribution[0].Level.Should().Be("High");
            result.HostThreatDistribution[0].Count.Should().Be(1);
            result.TopHosts.Should().ContainSingle(h => h.IpAddress == "10.0.0.1");
        }

        [Fact]
        public void Analyze_HostThreatDistribution_CountsAndRatios()
        {
            var hosts = new List<HostAnalysisInput>
            {
                Host("10.0.0.1", threat: "Critical"),
                Host("10.0.0.2", threat: "High"),
                Host("10.0.0.3", threat: "High"),
                Host("10.0.0.4", threat: "None")
            };

            var result = BatchScanAnalyticsService.Analyze(hosts);

            result.HostThreatDistribution.Should().HaveCount(3);
            result.HostThreatDistribution[0].Level.Should().Be("Critical");
            result.HostThreatDistribution[0].Count.Should().Be(1);
            result.HostThreatDistribution[0].Ratio.Should().BeApproximately(0.25, 0.001);
            result.HostThreatDistribution[1].Level.Should().Be("High");
            result.HostThreatDistribution[1].Count.Should().Be(2);
            result.HostThreatDistribution[1].Ratio.Should().BeApproximately(0.5, 0.001);
            result.HostThreatDistribution[2].Level.Should().Be("None");
        }

        [Fact]
        public void Analyze_VulnRiskDistribution_CountsByRiskLevel()
        {
            var hosts = new List<HostAnalysisInput>
            {
                Host("10.0.0.1", vulnList: new List<VulnerabilityResult>
                {
                    Vuln("v1", "严重"), Vuln("v2", "高危"), Vuln("v3", "高危")
                }),
                Host("10.0.0.2", vulnList: new List<VulnerabilityResult> { Vuln("v4", "低危") })
            };

            var result = BatchScanAnalyticsService.Analyze(hosts);

            result.VulnRiskDistribution.Should().HaveCount(3);
            result.VulnRiskDistribution[0].Level.Should().Be("严重");
            result.VulnRiskDistribution[0].Count.Should().Be(1);
            result.VulnRiskDistribution[0].Ratio.Should().BeApproximately(0.25, 0.001);
            result.VulnRiskDistribution[1].Level.Should().Be("高危");
            result.VulnRiskDistribution[1].Count.Should().Be(2);
            result.VulnRiskDistribution[2].Level.Should().Be("低危");
        }

        [Fact]
        public void TopVulnerabilities_OrderedByAffectedHostCountDesc()
        {
            var hosts = new List<HostAnalysisInput>
            {
                Host("10.0.0.1", vulnList: new List<VulnerabilityResult> { Vuln("A", "高危", 80), Vuln("B", "低危", 22) }),
                Host("10.0.0.2", vulnList: new List<VulnerabilityResult> { Vuln("A", "高危", 80) }),
                Host("10.0.0.3", vulnList: new List<VulnerabilityResult> { Vuln("A", "高危", 80) })
            };

            var result = BatchScanAnalyticsService.Analyze(hosts);

            result.TopVulnerabilities.Should().HaveCount(2);
            result.TopVulnerabilities[0].Name.Should().Be("A");
            result.TopVulnerabilities[0].AffectedHostCount.Should().Be(3);
            result.TopVulnerabilities[1].Name.Should().Be("B");
            result.TopVulnerabilities[1].AffectedHostCount.Should().Be(1);
        }

        [Fact]
        public void TopVulnerabilities_SameNameDifferentPort_AreSeparateEntries()
        {
            var hosts = new List<HostAnalysisInput>
            {
                Host("10.0.0.1", vulnList: new List<VulnerabilityResult> { Vuln("WeakTLS", "高危", 443), Vuln("WeakTLS", "高危", 8443) })
            };

            var result = BatchScanAnalyticsService.Analyze(hosts);

            result.TopVulnerabilities.Should().HaveCount(2);
            result.TopVulnerabilities.Should().OnlyContain(t => t.Name == "WeakTLS");
            result.TopVulnerabilities.Select(t => t.Port).Should().BeEquivalentTo(new int?[] { 443, 8443 });
        }

        [Fact]
        public void TopVulnerabilities_HighestRisk_AndAffectedHosts()
        {
            var hosts = new List<HostAnalysisInput>
            {
                Host("10.0.0.2", vulnList: new List<VulnerabilityResult> { Vuln("RCE", "高危", 445, "smb", "CVE-2024-0001") }),
                Host("10.0.0.10", vulnList: new List<VulnerabilityResult> { Vuln("RCE", "严重", 445, "smb", "CVE-2024-0001") })
            };

            var result = BatchScanAnalyticsService.Analyze(hosts);

            var top = result.TopVulnerabilities.Should().ContainSingle().Subject;
            top.HighestRisk.Should().Be("严重");
            top.CveId.Should().Be("CVE-2024-0001");
            top.Service.Should().Be("smb");
            top.AffectedHostCount.Should().Be(2);
            top.AffectedHosts.Should().Equal("10.0.0.2", "10.0.0.10");
        }

        [Fact]
        public void TopVulnerabilities_TopN_Truncates()
        {
            var vulnList = new List<VulnerabilityResult>();
            for (int i = 0; i < 15; i++) vulnList.Add(Vuln($"V{i:D2}", "高危", 1000 + i));
            var hosts = new List<HostAnalysisInput> { Host("10.0.0.1", vulnList: vulnList) };

            var result = BatchScanAnalyticsService.Analyze(hosts, topN: 10);

            result.TopVulnerabilities.Should().HaveCount(10);
        }

        [Fact]
        public void TopHosts_OrderedByThreatThenVulnThenPorts()
        {
            var hosts = new List<HostAnalysisInput>
            {
                Host("10.0.0.1", threat: "Medium", vulns: 5, ports: 2),
                Host("10.0.0.2", threat: "High", vulns: 1, ports: 1),
                Host("10.0.0.3", threat: "Medium", vulns: 5, ports: 9),
                Host("10.0.0.4", threat: "Medium", vulns: 8, ports: 1)
            };

            var result = BatchScanAnalyticsService.Analyze(hosts);

            result.TopHosts.Select(h => h.IpAddress).Should().Equal("10.0.0.2", "10.0.0.4", "10.0.0.3", "10.0.0.1");
        }

        [Fact]
        public void TopHosts_TopN_Truncates()
        {
            var hosts = new List<HostAnalysisInput>();
            for (int i = 1; i <= 12; i++) hosts.Add(Host($"10.0.0.{i}", threat: "Low", vulns: i));

            var result = BatchScanAnalyticsService.Analyze(hosts, topN: 10);

            result.TopHosts.Should().HaveCount(10);
            result.TopHosts[0].IpAddress.Should().Be("10.0.0.12");
        }

        [Fact]
        public void PortDistribution_CountsDistinctHosts_MajorityService()
        {
            var hosts = new List<HostAnalysisInput>
            {
                Host("10.0.0.1", portList: new List<PortFact> { new() { Port = 80, Service = "http" }, new() { Port = 22, Service = "ssh" } }),
                Host("10.0.0.2", portList: new List<PortFact> { new() { Port = 80, Service = "http" }, new() { Port = 80, Service = "http-alt" } }),
                Host("10.0.0.3", portList: new List<PortFact> { new() { Port = 443, Service = "https" } })
            };

            var result = BatchScanAnalyticsService.Analyze(hosts);

            result.PortDistribution.Should().HaveCount(3);
            result.PortDistribution[0].Port.Should().Be(80);
            result.PortDistribution[0].HostCount.Should().Be(2);
            result.PortDistribution[0].Service.Should().Be("http");
            result.PortDistribution.Select(p => p.Port).Should().Contain(new[] { 22, 443 });
        }

        [Fact]
        public void Weights_ChineseAndEnglish_MapCorrectly()
        {
            BatchScanAnalyticsService.ThreatWeight("Critical").Should().Be(4);
            BatchScanAnalyticsService.ThreatWeight("High").Should().Be(3);
            BatchScanAnalyticsService.ThreatWeight("Medium").Should().Be(2);
            BatchScanAnalyticsService.ThreatWeight("Low").Should().Be(1);
            BatchScanAnalyticsService.ThreatWeight("None").Should().Be(0);
            BatchScanAnalyticsService.ThreatWeight("其他").Should().Be(0);

            BatchScanAnalyticsService.RiskWeight("严重").Should().Be(4);
            BatchScanAnalyticsService.RiskWeight("Critical").Should().Be(4);
            BatchScanAnalyticsService.RiskWeight("高危").Should().Be(3);
            BatchScanAnalyticsService.RiskWeight("High").Should().Be(3);
            BatchScanAnalyticsService.RiskWeight("中危").Should().Be(2);
            BatchScanAnalyticsService.RiskWeight("低危").Should().Be(1);
            BatchScanAnalyticsService.RiskWeight("").Should().Be(0);
        }
    }
}
```

- [ ] **Step 3: 写比较器测试文件**

`src/NetSecurityScanner.Core.Tests/IpNumericComparerTests.cs`：

```csharp
using System.Collections.Generic;
using FluentAssertions;
using NetSecurityScanner.Core.Services;
using Xunit;

namespace NetSecurityScanner.Tests
{
    public class IpNumericComparerTests
    {
        [Fact]
        public void Compare_OrdersFourOctetsNumerically()
        {
            var ips = new List<string> { "10.0.0.10", "192.168.1.1", "10.0.0.2", "10.0.0.1" };

            ips.Sort(IpNumericComparer.Instance);

            ips.Should().Equal("10.0.0.1", "10.0.0.2", "10.0.0.10", "192.168.1.1");
        }

        [Fact]
        public void Compare_InvalidValues_SortLast()
        {
            var ips = new List<string> { "bad-ip", "10.0.0.1", "", "999.1.1.1", "10.0.0.2" };

            ips.Sort(IpNumericComparer.Instance);

            ips.Should().StartWith(new[] { "10.0.0.1", "10.0.0.2" });
            ips.GetRange(2, 3).Should().BeEquivalentTo(new[] { "bad-ip", "", "999.1.1.1" });
        }

        [Fact]
        public void Compare_Equal_ReturnsZero()
        {
            IpNumericComparer.Instance.Compare("10.0.0.1", "10.0.0.1").Should().Be(0);
        }
    }
}
```

- [ ] **Step 4: 运行新测试确认 RED**

Run: `dotnet test src\NetSecurityScanner.Core.Tests\NetSecurityScanner.Core.Tests.csproj -c Debug --nologo --filter "FullyQualifiedName~BatchScanAnalyticsServiceTests|FullyQualifiedName~IpNumericComparerTests"`
Expected: 15 个测试，其中 12 个 BatchScanAnalyticsServiceTests 全部 FAIL（NotImplementedException），3 个 IpNumericComparerTests 全部 PASS（比较器已实现）

**不提交**（RED 状态随 Task 3 一起提交）。

---

## Task 3: 实现 Analyze 与权重映射（全 GREEN）+ 提交

**Files:**
- Modify: `src/NetSecurityScanner.Core/Services/BatchScanAnalyticsService.cs`

- [ ] **Step 1: 用完整实现替换骨架（整个文件内容如下）**

```csharp
using System;
using System.Collections.Generic;
using System.Linq;
using NetSecurityScanner.Core.Models;

namespace NetSecurityScanner.Core.Services
{
    /// <summary>
    /// 批量扫描结果分析纯逻辑：威胁分布、TOP 漏洞/主机、端口分布。无 IO、无 UI 依赖。
    /// 仅统计 Status == "已完成" 的主机。
    /// </summary>
    public static class BatchScanAnalyticsService
    {
        public const string StatusCompleted = "已完成";

        /// <summary>主机威胁等级权重：Critical=4 … None=0，未知按 0。</summary>
        public static int ThreatWeight(string threatLevel) => threatLevel switch
        {
            "Critical" => 4,
            "High" => 3,
            "Medium" => 2,
            "Low" => 1,
            _ => 0
        };

        /// <summary>漏洞风险等级权重：严重=4/高危=3/中危=2/低危=1，兼容英文，未知按 0。</summary>
        public static int RiskWeight(string riskLevel) => riskLevel switch
        {
            "严重" or "Critical" => 4,
            "高危" or "High" => 3,
            "中危" or "Medium" => 2,
            "低危" or "Low" => 1,
            _ => 0
        };

        public static BatchScanAnalysisResult Analyze(IReadOnlyList<HostAnalysisInput> hosts, int topN = 10)
        {
            var completed = hosts.Where(h => h.Status == StatusCompleted).ToList();
            var result = new BatchScanAnalysisResult();

            // 主机威胁分布（按 ThreatLevel 权重降序）
            result.HostThreatDistribution = completed
                .GroupBy(h => h.ThreatLevel)
                .Select(g => new RiskDistributionItem
                {
                    Level = g.Key,
                    Count = g.Count(),
                    Ratio = completed.Count == 0 ? 0 : (double)g.Count() / completed.Count
                })
                .OrderByDescending(i => ThreatWeight(i.Level))
                .ToList();

            // 漏洞风险分布（按 RiskLevel 权重降序）
            var allVulns = completed.SelectMany(h => h.Vulns).ToList();
            result.VulnRiskDistribution = allVulns
                .GroupBy(v => v.RiskLevel)
                .Select(g => new RiskDistributionItem
                {
                    Level = g.Key,
                    Count = g.Count(),
                    Ratio = allVulns.Count == 0 ? 0 : (double)g.Count() / allVulns.Count
                })
                .OrderByDescending(i => RiskWeight(i.Level))
                .ToList();

            // TOP 漏洞榜：Name+Port+Service 分组
            result.TopVulnerabilities = completed
                .SelectMany(h => h.Vulns.Select(v => new { h.IpAddress, Vuln = v }))
                .GroupBy(x => (x.Vuln.Name, x.Vuln.Port, x.Vuln.Service))
                .Select(g =>
                {
                    var affected = g.Select(x => x.IpAddress).Distinct()
                        .OrderBy(ip => ip, IpNumericComparer.Instance).ToList();
                    return new TopVulnerabilityItem
                    {
                        Name = g.Key.Name,
                        Port = g.Key.Port,
                        Service = g.Key.Service,
                        CveId = g.Select(x => x.Vuln.CveId).FirstOrDefault(c => !string.IsNullOrEmpty(c)) ?? "",
                        HighestRisk = g.Select(x => x.Vuln.RiskLevel).OrderByDescending(RiskWeight).FirstOrDefault() ?? "",
                        AffectedHostCount = affected.Count,
                        AffectedHosts = affected
                    };
                })
                .OrderByDescending(t => t.AffectedHostCount)
                .ThenByDescending(t => RiskWeight(t.HighestRisk))
                .ThenBy(t => t.Name, StringComparer.Ordinal)
                .Take(topN)
                .ToList();

            // TOP 风险主机
            result.TopHosts = completed
                .OrderByDescending(h => ThreatWeight(h.ThreatLevel))
                .ThenByDescending(h => h.VulnCount)
                .ThenByDescending(h => h.OpenPortsCount)
                .ThenBy(h => h.IpAddress, IpNumericComparer.Instance)
                .Take(topN)
                .Select(h => new TopHostItem
                {
                    IpAddress = h.IpAddress,
                    ThreatLevel = h.ThreatLevel,
                    VulnCount = h.VulnCount,
                    CriticalCount = h.CriticalCount,
                    HighCount = h.HighCount,
                    OpenPortsCount = h.OpenPortsCount
                })
                .ToList();

            // 端口/服务分布：按开放主机数降序，服务名取组内多数值
            result.PortDistribution = completed
                .SelectMany(h => h.Ports.Select(p => new { h.IpAddress, p.Port, p.Service }))
                .GroupBy(x => x.Port)
                .Select(g => new PortDistributionItem
                {
                    Port = g.Key,
                    Service = g.Where(x => !string.IsNullOrEmpty(x.Service))
                        .GroupBy(x => x.Service)
                        .OrderByDescending(s => s.Count())
                        .Select(s => s.Key)
                        .FirstOrDefault() ?? "",
                    HostCount = g.Select(x => x.IpAddress).Distinct().Count()
                })
                .OrderByDescending(p => p.HostCount)
                .ThenBy(p => p.Port)
                .Take(topN)
                .ToList();

            return result;
        }
    }
}
```

- [ ] **Step 2: 运行新测试确认全 GREEN**

Run: `dotnet test src\NetSecurityScanner.Core.Tests\NetSecurityScanner.Core.Tests.csproj -c Debug --nologo --filter "FullyQualifiedName~BatchScanAnalyticsServiceTests|FullyQualifiedName~IpNumericComparerTests"`
Expected: `通过: 15`，`失败: 0`

- [ ] **Step 3: 运行全量测试确认无回归**

Run: `dotnet test src\NetSecurityScanner.Core.Tests\NetSecurityScanner.Core.Tests.csproj -c Debug --nologo`
Expected: `通过: 294`，`失败: 0`（279 存量 + 15 新增）

- [ ] **Step 4: 提交**

```powershell
git add src/NetSecurityScanner.Core/Services/BatchScanAnalyticsService.cs src/NetSecurityScanner.Core.Tests/BatchScanAnalyticsServiceTests.cs src/NetSecurityScanner.Core.Tests/IpNumericComparerTests.cs
git commit -m "feat: 实现批量扫描结果分析服务（分布/TOP榜/端口分布）+15单测"
```

---

## Task 4: Desktop 数据准备（DurationSeconds + 排序记忆字段）

**Files:**
- Modify: `src/NetSecurityScanner.Core/Models/BatchScanSettings.cs`
- Modify: `src/NetSecurityScanner.Desktop/Views/Views/BatchScanWindow.xaml.cs`

- [ ] **Step 1: BatchScanSettings 增加排序字段**

在 `src/NetSecurityScanner.Core/Models/BatchScanSettings.cs` 的 `public string ThreatFilterTag { get; set; } = "All";` 行后追加两行：

```csharp
        public string SortField { get; set; } = "";
        public bool SortDescending { get; set; }
```

- [ ] **Step 2: IpScanItem 增加 DurationSeconds**

`BatchScanWindow.xaml.cs` 的 `IpScanItem` 类中，在 `public List<PortScanResult> PortResults { get; set; } = new List<PortScanResult>();` 行前插入一行：

```csharp
        public double DurationSeconds { get; set; }
```

（纯数值排序键，不需 PropertyChanged 通知；与 DurationText 同步赋值。）

- [ ] **Step 3: 四处同步赋值**

a. 重置处（L299 附近），将：
```csharp
                    item.DurationText = "00:00";
```
改为：
```csharp
                    item.DurationText = "00:00";
                    item.DurationSeconds = 0;
```

b. 三处扫描计时赋值（L635、L676、L695 附近），每处将：
```csharp
                    _ipItems[index].DurationText = itemStopwatch.Elapsed.ToString(@"mm\:ss");
```
改为：
```csharp
                    _ipItems[index].DurationText = itemStopwatch.Elapsed.ToString(@"mm\:ss");
                    _ipItems[index].DurationSeconds = itemStopwatch.Elapsed.TotalSeconds;
```

- [ ] **Step 4: CaptureSettingsFromUi / LoadAndApplySettings 接线**

`CaptureSettingsFromUi()`（L109-117）末尾 `ThreatFilterTag = ...` 行后追加两行：

```csharp
            ,
            SortField = _sortField,
            SortDescending = _sortDescending
```

（注意给上一行补逗号；`_sortField`/`_sortDescending` 字段由 Task 6 定义，本任务先加私有字段，见 Step 5。）

`LoadAndApplySettings()` 的 `try` 块末尾（`TimeoutSlider.Value = ...` 行之后）追加：

```csharp
                _sortField = settings.SortField ?? "";
                _sortDescending = settings.SortDescending;
```

- [ ] **Step 5: 声明排序状态字段**

在 `_settingsSaveTimer` 字段声明（L41 附近）后追加：

```csharp
        private string _sortField = "";
        private bool _sortDescending;
```

- [ ] **Step 6: 构建 Desktop 验证通过**

Run: `dotnet build src\NetSecurityScanner.Desktop\NetSecurityScanner.Desktop.csproj -c Debug --nologo -v q`
Expected: `0 个错误`（若 MSB3027/MSB3021 DLL 占用，结束运行中的 NetSecurityScanner.Desktop 进程后重试）

- [ ] **Step 7: 提交**

```powershell
git add src/NetSecurityScanner.Core/Models/BatchScanSettings.cs src/NetSecurityScanner.Desktop/Views/Views/BatchScanWindow.xaml.cs
git commit -m "feat: IpScanItem 增加耗时数值字段，批量扫描配置增加排序记忆字段"
```

---

## Task 5: XAML 排序表头 + 行模板漏洞列

**Files:**
- Modify: `src/NetSecurityScanner.Desktop/Views/Views/BatchScanWindow.xaml`

- [ ] **Step 1: Window.Resources 增加表头按钮样式**

在 `Window.Resources` 内（既有资源之后）追加：

```xml
        <Style x:Key="SortHeaderStyle" TargetType="Button">
            <Setter Property="Background" Value="Transparent"/>
            <Setter Property="BorderThickness" Value="0"/>
            <Setter Property="FontSize" Value="11"/>
            <Setter Property="FontWeight" Value="SemiBold"/>
            <Setter Property="Foreground" Value="#7F8C8D"/>
            <Setter Property="Cursor" Value="Hand"/>
            <Setter Property="Padding" Value="2,0"/>
            <Setter Property="Height" Value="20"/>
            <Setter Property="HorizontalContentAlignment" Value="Center"/>
            <Setter Property="VerticalContentAlignment" Value="Center"/>
            <Style.Triggers>
                <Trigger Property="IsMouseOver" Value="True">
                    <Setter Property="Foreground" Value="#2C3E50"/>
                </Trigger>
            </Style.Triggers>
        </Style>
        <Style x:Key="IpChipStyle" TargetType="Button">
            <Setter Property="Background" Value="#ECF0F1"/>
            <Setter Property="BorderBrush" Value="#BDC3C7"/>
            <Setter Property="BorderThickness" Value="1"/>
            <Setter Property="FontSize" Value="11"/>
            <Setter Property="Padding" Value="6,2"/>
            <Setter Property="Margin" Value="2"/>
            <Setter Property="Cursor" Value="Hand"/>
            <Setter Property="Template">
                <Setter.Value>
                    <ControlTemplate TargetType="Button">
                        <Border Background="{TemplateBinding Background}" BorderBrush="{TemplateBinding BorderBrush}"
                                BorderThickness="{TemplateBinding BorderThickness}" CornerRadius="3" Padding="{TemplateBinding Padding}">
                            <ContentPresenter HorizontalAlignment="Center" VerticalAlignment="Center"/>
                        </Border>
                    </ControlTemplate>
                </Setter.Value>
            </Setter>
            <Style.Triggers>
                <Trigger Property="IsMouseOver" Value="True">
                    <Setter Property="Background" Value="#D5DBDB"/>
                </Trigger>
            </Style.Triggers>
        </Style>
```

- [ ] **Step 2: IP 列表卡片 Grid 改 4 行并插入排序表头**

将（L144-147）：

```xml
                        <Grid.RowDefinitions>
                            <RowDefinition Height="Auto"/>
                            <RowDefinition Height="Auto"/>
                            <RowDefinition Height="*"/>
                        </Grid.RowDefinitions>
```

改为：

```xml
                        <Grid.RowDefinitions>
                            <RowDefinition Height="Auto"/>
                            <RowDefinition Height="Auto"/>
                            <RowDefinition Height="Auto"/>
                            <RowDefinition Height="*"/>
                        </Grid.RowDefinitions>
```

在过滤行 `</StackPanel>`（L170）之后、`<ListView Grid.Row="2" Name="IpListView"` 之前插入：

```xml
                        <Grid Grid.Row="2" Margin="7,0,7,2">
                            <Grid.ColumnDefinitions>
                                <ColumnDefinition Width="20"/>
                                <ColumnDefinition Width="*"/>
                                <ColumnDefinition Width="56"/>
                                <ColumnDefinition Width="50"/>
                                <ColumnDefinition Width="60"/>
                                <ColumnDefinition Width="90"/>
                            </Grid.ColumnDefinitions>
                            <Button Grid.Column="0" Style="{StaticResource SortHeaderStyle}" Tag="Threat" Click="SortHeader_Click" Content="状态"/>
                            <Button Grid.Column="1" Style="{StaticResource SortHeaderStyle}" Tag="Ip" Click="SortHeader_Click" Content="IP地址" HorizontalContentAlignment="Left"/>
                            <Button Grid.Column="2" Style="{StaticResource SortHeaderStyle}" Tag="Vuln" Click="SortHeader_Click" Content="漏洞"/>
                            <Button Grid.Column="3" Style="{StaticResource SortHeaderStyle}" Tag="Progress" Click="SortHeader_Click" Content="进度"/>
                            <Button Grid.Column="4" Style="{StaticResource SortHeaderStyle}" Tag="Duration" Click="SortHeader_Click" Content="耗时"/>
                            <Button Grid.Column="5" Style="{StaticResource SortHeaderStyle}" Tag="Failure" Click="SortHeader_Click" Content="失败原因"/>
                        </Grid>
```

并将 `IpListView` 改为 `Grid.Row="3"`（即 `<ListView Grid.Row="2" Name="IpListView"` 改为 `<ListView Grid.Row="3" Name="IpListView"`）。

- [ ] **Step 3: 行模板增加「漏洞」列**

将行模板中的列定义（L186-192）：

```xml
                                            <Grid.ColumnDefinitions>
                                                <ColumnDefinition Width="20"/>
                                                <ColumnDefinition Width="*"/>
                                                <ColumnDefinition Width="50"/>
                                                <ColumnDefinition Width="60"/>
                                                <ColumnDefinition Width="90"/>
                                            </Grid.ColumnDefinitions>
```

改为：

```xml
                                            <Grid.ColumnDefinitions>
                                                <ColumnDefinition Width="20"/>
                                                <ColumnDefinition Width="*"/>
                                                <ColumnDefinition Width="56"/>
                                                <ColumnDefinition Width="50"/>
                                                <ColumnDefinition Width="60"/>
                                                <ColumnDefinition Width="90"/>
                                            </Grid.ColumnDefinitions>
```

将（L195-197）：

```xml
                                            <TextBlock Grid.Column="2" Text="{Binding ProgressText}" FontSize="11" Foreground="{Binding ThreatLevel, Converter={StaticResource ThreatLevelToForegroundConverter}}" VerticalAlignment="Center" HorizontalAlignment="Center"/>
                                            <TextBlock Grid.Column="3" Text="{Binding DurationText}" FontSize="11" Foreground="{Binding ThreatLevel, Converter={StaticResource ThreatLevelToForegroundConverter}}" VerticalAlignment="Center" HorizontalAlignment="Right"/>
                                            <TextBlock Grid.Column="4" Text="{Binding FailureText}" FontSize="11" Foreground="#E74C3C" VerticalAlignment="Center" HorizontalAlignment="Center" ToolTip="{Binding ErrorMessage}"/>
```

改为：

```xml
                                            <TextBlock Grid.Column="2" Text="{Binding VulnCount}" FontSize="11" Foreground="{Binding ThreatLevel, Converter={StaticResource ThreatLevelToForegroundConverter}}" VerticalAlignment="Center" HorizontalAlignment="Center">
                                                <TextBlock.ToolTip>
                                                    <ToolTip>
                                                        <StackPanel>
                                                            <TextBlock Text="{Binding CriticalCount, StringFormat='严重: {0}'}"/>
                                                            <TextBlock Text="{Binding HighCount, StringFormat='高危: {0}'}"/>
                                                        </StackPanel>
                                                    </ToolTip>
                                                </TextBlock.ToolTip>
                                            </TextBlock>
                                            <TextBlock Grid.Column="3" Text="{Binding ProgressText}" FontSize="11" Foreground="{Binding ThreatLevel, Converter={StaticResource ThreatLevelToForegroundConverter}}" VerticalAlignment="Center" HorizontalAlignment="Center"/>
                                            <TextBlock Grid.Column="4" Text="{Binding DurationText}" FontSize="11" Foreground="{Binding ThreatLevel, Converter={StaticResource ThreatLevelToForegroundConverter}}" VerticalAlignment="Center" HorizontalAlignment="Right"/>
                                            <TextBlock Grid.Column="5" Text="{Binding FailureText}" FontSize="11" Foreground="#E74C3C" VerticalAlignment="Center" HorizontalAlignment="Center" ToolTip="{Binding ErrorMessage}"/>
```

- [ ] **Step 4: 构建 Desktop 验证通过**

Run: `dotnet build src\NetSecurityScanner.Desktop\NetSecurityScanner.Desktop.csproj -c Debug --nologo -v q`
Expected: `0 个错误`（SortHeader_Click 尚未实现会出现 CS1061 错误——属预期，Task 6 补齐；本任务只验证 XAML 结构，可先注释 6 个 `Click="SortHeader_Click"` 属性验证构建后再恢复，或直接进入 Task 6 后统一构建）

**推荐：本任务与 Task 6 连续执行，Task 6 末尾统一构建后一起提交。**

---

## Task 6: 排序逻辑（Comparer + 表头交互 + 状态恢复）

**Files:**
- Modify: `src/NetSecurityScanner.Desktop/Views/Views/BatchScanWindow.xaml.cs`

- [ ] **Step 1: 实现 IpItemSortComparer**

在 `IpScanItem` 类定义之后（文件尾部，L1165 `}` 之后）新增：

```csharp
    /// <summary>
    /// 批量扫描结果列表排序比较器。字段键：Threat/Ip/Vuln/Progress/Duration/Failure。
    /// </summary>
    public class IpItemSortComparer : System.Collections.IComparer
    {
        private readonly string _field;
        private readonly bool _descending;

        public IpItemSortComparer(string field, bool descending)
        {
            _field = field;
            _descending = descending;
        }

        private static int StatusWeight(string status) => status switch
        {
            "扫描中" => 4,
            "等待中" => 3,
            "已完成" => 2,
            "失败" => 1,
            _ => 0 // 已取消及其他
        };

        public int Compare(object? x, object? y)
        {
            if (x is not IpScanItem a || y is not IpScanItem b) return 0;
            int result = _field switch
            {
                "Threat" => BatchScanAnalyticsService.ThreatWeight(a.ThreatLevel)
                                .CompareTo(BatchScanAnalyticsService.ThreatWeight(b.ThreatLevel)),
                "Ip" => IpNumericComparer.Instance.Compare(a.IpAddress, b.IpAddress),
                "Vuln" => a.VulnCount.CompareTo(b.VulnCount) != 0 ? a.VulnCount.CompareTo(b.VulnCount)
                        : a.CriticalCount.CompareTo(b.CriticalCount) != 0 ? a.CriticalCount.CompareTo(b.CriticalCount)
                        : a.HighCount.CompareTo(b.HighCount),
                "Progress" => StatusWeight(a.Status).CompareTo(StatusWeight(b.Status)),
                "Duration" => a.DurationSeconds.CompareTo(b.DurationSeconds),
                "Failure" => ((int)a.FailureCategory).CompareTo((int)b.FailureCategory),
                _ => 0
            };
            // 次级排序统一按 IP 数值升序，保证结果稳定
            if (result == 0 && _field != "Ip")
                result = IpNumericComparer.Instance.Compare(a.IpAddress, b.IpAddress);
            return _descending ? -result : result;
        }
    }
```

（文件顶部需有 `using NetSecurityScanner.Core.Services;`，若无则添加。）

- [ ] **Step 2: 表头交互与排序应用**

在 `FilterComboBox_SelectionChanged` 方法附近新增：

```csharp
        private static readonly Dictionary<string, string> SortHeaderBaseTexts = new()
        {
            ["Threat"] = "状态",
            ["Ip"] = "IP地址",
            ["Vuln"] = "漏洞",
            ["Progress"] = "进度",
            ["Duration"] = "耗时",
            ["Failure"] = "失败原因"
        };

        private void SortHeader_Click(object sender, RoutedEventArgs e)
        {
            if (sender is not Button btn || btn.Tag is not string field) return;
            if (_sortField == field)
            {
                _sortDescending = !_sortDescending;
            }
            else
            {
                _sortField = field;
                _sortDescending = field != "Ip"; // IP 首击升序，其余首击降序
            }
            ApplySort();
            MarkSettingsDirty();
        }

        private void ApplySort()
        {
            _ipItemsView.CustomSort = string.IsNullOrEmpty(_sortField)
                ? null
                : new IpItemSortComparer(_sortField, _sortDescending);
            _ipItemsView.Refresh();
            UpdateSortHeaderIndicators();
        }

        private void UpdateSortHeaderIndicators()
        {
            foreach (var btn in FindVisualChildren<Button>(IpListViewHeaderGrid))
            {
                if (btn.Tag is not string field || !SortHeaderBaseTexts.TryGetValue(field, out var baseText)) continue;
                btn.Content = field == _sortField
                    ? baseText + (_sortDescending ? " ▼" : " ▲")
                    : baseText;
            }
        }

        private static IEnumerable<T> FindVisualChildren<T>(System.Windows.DependencyObject parent) where T : System.Windows.DependencyObject
        {
            int count = System.Windows.Media.VisualTreeHelper.GetChildrenCount(parent);
            for (int i = 0; i < count; i++)
            {
                var child = System.Windows.Media.VisualTreeHelper.GetChild(parent, i);
                if (child is T t) yield return t;
                foreach (var nested in FindVisualChildren<T>(child)) yield return nested;
            }
        }
```

（文件顶部需有 `using System.Collections.Generic;` 与 `using System.Windows.Controls;`，一般已存在。）

- [ ] **Step 3: XAML 表头 Grid 命名**

将 Task 5 插入的表头 Grid 标签 `<Grid Grid.Row="2" Margin="7,0,7,2">` 改为 `<Grid Grid.Row="2" Name="IpListViewHeaderGrid" Margin="7,0,7,2">`。

- [ ] **Step 4: 启动时恢复排序**

`LoadAndApplySettings()` 的 `finally` 块之后（即整个 try/finally 结束后）追加：

```csharp
            if (!string.IsNullOrEmpty(_sortField))
            {
                ApplySort();
            }
```

- [ ] **Step 5: 构建 Desktop 验证通过**

Run: `dotnet build src\NetSecurityScanner.Desktop\NetSecurityScanner.Desktop.csproj -c Debug --nologo -v q`
Expected: `0 个错误`

- [ ] **Step 6: 提交（含 Task 5 的 XAML）**

```powershell
git add src/NetSecurityScanner.Desktop/Views/Views/BatchScanWindow.xaml src/NetSecurityScanner.Desktop/Views/Views/BatchScanWindow.xaml.cs
git commit -m "feat: 批量扫描结果列表支持列头点击排序并记忆排序状态"
```

---

## Task 7: XAML 分析页签（整体分析）

**Files:**
- Modify: `src/NetSecurityScanner.Desktop/Views/Views/BatchScanWindow.xaml`

- [ ] **Step 1: DetailTabControl 插入首个页签**

将 `<TabControl Grid.Row="1" Name="DetailTabControl" Margin="5">`（L225）与其后 `<TabItem Header="开放端口">` 之间，插入完整新页签：

```xml
                        <TabItem Header="📊 整体分析">
                            <ScrollViewer VerticalScrollBarVisibility="Auto">
                                <StackPanel Margin="8">
                                    <TextBlock Name="AnalysisEmptyTextBlock" Text="暂无分析数据（完成扫描后自动生成）"
                                               Foreground="#95A5A6" FontSize="12" HorizontalAlignment="Center" Margin="0,30,0,0"/>
                                    <StackPanel Name="AnalysisContentPanel" Visibility="Collapsed">
                                        <TextBlock Text="主机威胁分布" FontWeight="SemiBold" FontSize="12"/>
                                        <Grid Name="HostThreatBarGrid" Height="18" Margin="0,4,0,2"/>
                                        <WrapPanel Name="HostThreatLegendPanel"/>

                                        <TextBlock Text="漏洞等级分布" FontWeight="SemiBold" FontSize="12" Margin="0,10,0,0"/>
                                        <Grid Name="VulnRiskBarGrid" Height="18" Margin="0,4,0,2"/>
                                        <WrapPanel Name="VulnRiskLegendPanel"/>

                                        <TextBlock Text="TOP 漏洞榜" FontWeight="SemiBold" FontSize="12" Margin="0,12,0,4"/>
                                        <ListView Name="TopVulnListView" SelectionMode="Single" MaxHeight="180" FontSize="11"
                                                  SelectionChanged="TopVulnListView_SelectionChanged">
                                            <ListView.ItemTemplate>
                                                <DataTemplate>
                                                    <Grid>
                                                        <Grid.ColumnDefinitions>
                                                            <ColumnDefinition Width="*"/>
                                                            <ColumnDefinition Width="50"/>
                                                            <ColumnDefinition Width="50"/>
                                                            <ColumnDefinition Width="56"/>
                                                        </Grid.ColumnDefinitions>
                                                        <TextBlock Grid.Column="0" Text="{Binding Name}" VerticalAlignment="Center"
                                                                   ToolTip="{Binding CveId, StringFormat='CVE: {0}'}"/>
                                                        <TextBlock Grid.Column="1" Text="{Binding Port}" VerticalAlignment="Center" HorizontalAlignment="Center" Foreground="#7F8C8D"/>
                                                        <TextBlock Grid.Column="2" Text="{Binding HighestRisk}" VerticalAlignment="Center" HorizontalAlignment="Center"
                                                                   Foreground="{Binding HighestRisk, Converter={StaticResource RiskLevelToForegroundConverter}}" FontWeight="SemiBold"/>
                                                        <TextBlock Grid.Column="3" Text="{Binding AffectedHostCount, StringFormat='{0} 台'}" VerticalAlignment="Center" HorizontalAlignment="Center"/>
                                                    </Grid>
                                                </DataTemplate>
                                            </ListView.ItemTemplate>
                                        </ListView>

                                        <Border Name="AffectedHostsPanel" Visibility="Collapsed" Margin="0,4,0,8" Padding="6"
                                                Background="#F8F9FA" CornerRadius="3" BorderBrush="#BDC3C7" BorderThickness="1">
                                            <StackPanel>
                                                <Grid>
                                                    <TextBlock Name="AffectedHostsTitleTextBlock" Text="受影响主机 (0)" FontWeight="SemiBold" FontSize="11"/>
                                                    <Button HorizontalAlignment="Right" Content="✕" Width="18" Height="18" FontSize="10"
                                                            Padding="0" Click="CloseAffectedHostsPanel_Click" Style="{StaticResource SortHeaderStyle}"/>
                                                </Grid>
                                                <WrapPanel Name="AffectedHostsWrapPanel" Margin="0,4,0,0"/>
                                            </StackPanel>
                                        </Border>

                                        <TextBlock Text="TOP 风险主机" FontWeight="SemiBold" FontSize="12" Margin="0,10,0,4"/>
                                        <ListView Name="TopHostListView" SelectionMode="Single" MaxHeight="160" FontSize="11"
                                                  SelectionChanged="TopHostListView_SelectionChanged">
                                            <ListView.ItemTemplate>
                                                <DataTemplate>
                                                    <Grid>
                                                        <Grid.ColumnDefinitions>
                                                            <ColumnDefinition Width="110"/>
                                                            <ColumnDefinition Width="50"/>
                                                            <ColumnDefinition Width="56"/>
                                                            <ColumnDefinition Width="56"/>
                                                            <ColumnDefinition Width="*"/>
                                                        </Grid.ColumnDefinitions>
                                                        <TextBlock Grid.Column="0" Text="{Binding IpAddress}" FontWeight="SemiBold" VerticalAlignment="Center"
                                                                   Foreground="{Binding ThreatLevel, Converter={StaticResource ThreatLevelToForegroundConverter}}"/>
                                                        <TextBlock Grid.Column="1" Text="{Binding ThreatLevel}" VerticalAlignment="Center" HorizontalAlignment="Center"
                                                                   Foreground="{Binding ThreatLevel, Converter={StaticResource ThreatLevelToForegroundConverter}}"/>
                                                        <TextBlock Grid.Column="2" Text="{Binding VulnCount, StringFormat='漏洞 {0}'}" VerticalAlignment="Center"/>
                                                        <TextBlock Grid.Column="3" Text="{Binding HighCount, StringFormat='高危 {0}'}" VerticalAlignment="Center" Foreground="#C2410C"/>
                                                        <TextBlock Grid.Column="4" Text="{Binding OpenPortsCount, StringFormat='端口 {0}'}" VerticalAlignment="Center" Foreground="#7F8C8D"/>
                                                    </Grid>
                                                </DataTemplate>
                                            </ListView.ItemTemplate>
                                        </ListView>

                                        <TextBlock Text="端口/服务分布" FontWeight="SemiBold" FontSize="12" Margin="0,10,0,4"/>
                                        <ListView Name="PortDistListView" MaxHeight="160" FontSize="11">
                                            <ListView.ItemTemplate>
                                                <DataTemplate>
                                                    <Grid>
                                                        <Grid.ColumnDefinitions>
                                                            <ColumnDefinition Width="56"/>
                                                            <ColumnDefinition Width="90"/>
                                                            <ColumnDefinition Width="*"/>
                                                            <ColumnDefinition Width="56"/>
                                                        </Grid.ColumnDefinitions>
                                                        <TextBlock Grid.Column="0" Text="{Binding Port}" FontWeight="SemiBold" VerticalAlignment="Center"/>
                                                        <TextBlock Grid.Column="1" Text="{Binding Service}" VerticalAlignment="Center" Foreground="#7F8C8D"/>
                                                        <Border Grid.Column="2" Height="10" VerticalAlignment="Center" Margin="4,0"
                                                                Background="#3498DB" HorizontalAlignment="Left"
                                                                Width="{Binding HostCount, Converter={StaticResource PortCountToBarWidthConverter}}"/>
                                                        <TextBlock Grid.Column="3" Text="{Binding HostCount, StringFormat='{0} 台'}" VerticalAlignment="Center" HorizontalAlignment="Right"/>
                                                    </Grid>
                                                </DataTemplate>
                                            </ListView.ItemTemplate>
                                        </ListView>

                                        <TextBlock Name="AnalysisStatusTextBlock" Text="" Foreground="#E67E22" FontSize="11" Margin="0,8,0,0"/>
                                    </StackPanel>
                                </StackPanel>
                            </ScrollViewer>
                        </TabItem>
```

- [ ] **Step 2: 说明**

`RiskLevelToForegroundConverter` 与 `PortCountToBarWidthConverter` 在 Task 8 Step 2 中实现；本任务只做 XAML，构建放到 Task 8 末尾统一验证（中间态构建会报转换器缺失，属预期）。

**不提交**（随 Task 8 一起提交）。

---

## Task 8: 分析接线（转换器 + 刷新节流 + 面板更新）

**Files:**
- Modify: `src/NetSecurityScanner.Desktop/Views/Views/BatchScanWindow.xaml.cs`

- [ ] **Step 1: 节流字段**

在 `_sortDescending` 字段声明后追加：

```csharp
        private DateTime _lastAnalysisRefreshUtc = DateTime.MinValue;
        private const double AnalysisThrottleMs = 300;
        private string? _selectedTopVulnKey;
```

- [ ] **Step 2: 新增两个值转换器**

在 `ThreatLevelToForegroundConverter` 类之后（文件尾部）新增：

```csharp
    /// <summary>漏洞风险等级（中文）→ 前景色。</summary>
    public class RiskLevelToForegroundConverter : System.Windows.Data.IValueConverter
    {
        public object Convert(object value, Type targetType, object parameter, System.Globalization.CultureInfo culture)
        {
            var brush = (value as string) switch
            {
                "严重" or "Critical" => "#991B1B",
                "高危" or "High" => "#C2410C",
                "中危" or "Medium" => "#D97706",
                "低危" or "Low" => "#059669",
                _ => "#7F8C8D"
            };
            return new System.Windows.Media.SolidColorBrush(
                (System.Windows.Media.Color)System.Windows.Media.ColorConverter.ConvertFromString(brush));
        }

        public object ConvertBack(object value, Type targetType, object parameter, System.Globalization.CultureInfo culture)
            => throw new NotImplementedException();
    }

    /// <summary>端口主机数 → 迷你比例条宽度（1 台=14px，上限 140px）。</summary>
    public class PortCountToBarWidthConverter : System.Windows.Data.IValueConverter
    {
        public object Convert(object value, Type targetType, object parameter, System.Globalization.CultureInfo culture)
        {
            if (value is int n && n > 0) return (double)Math.Min(n * 14, 140);
            return 2.0;
        }

        public object ConvertBack(object value, Type targetType, object parameter, System.Globalization.CultureInfo culture)
            => throw new NotImplementedException();
    }
```

- [ ] **Step 3: XAML 注册两个转换器资源**

`BatchScanWindow.xaml` 的 `Window.Resources` 内（既有转换器资源声明处）追加两行：

```xml
        <local:RiskLevelToForegroundConverter x:Key="RiskLevelToForegroundConverter"/>
        <local:PortCountToBarWidthConverter x:Key="PortCountToBarWidthConverter"/>
```

（`local` 命名空间与既有转换器声明所用前缀一致；若既有声明用的是别的前缀，沿用该前缀。）

- [ ] **Step 4: 面板更新与节流方法**

在 `UpdateGlobalStatistics()` 方法之后新增：

```csharp
        /// <summary>
        /// 分析面板节流刷新：距上次刷新不足 300ms 时跳过；force 用于扫描启动/结束等关键点。
        /// </summary>
        private void RefreshAnalysisThrottled(bool force = false)
        {
            if (!force && (DateTime.UtcNow - _lastAnalysisRefreshUtc).TotalMilliseconds < AnalysisThrottleMs) return;
            _lastAnalysisRefreshUtc = DateTime.UtcNow;
            UpdateAnalysisPanel();
        }

        private void UpdateAnalysisPanel()
        {
            // 记住当前选中的 TOP 漏洞，刷新后恢复，避免扫描中高频刷新打断钻取
            _selectedTopVulnKey = (TopVulnListView.SelectedItem as TopVulnerabilityItem) is { } sel
                ? $"{sel.Name}|{sel.Port}|{sel.Service}"
                : null;

            var inputs = _ipItems.Select(item => new HostAnalysisInput
            {
                IpAddress = item.IpAddress,
                Status = item.Status,
                ThreatLevel = item.ThreatLevel,
                OpenPortsCount = item.OpenPortsCount,
                VulnCount = item.VulnCount,
                CriticalCount = item.CriticalCount,
                HighCount = item.HighCount,
                Ports = item.PortResults?.Select(p => new PortFact { Port = p.PortNumber, Service = p.Service }).ToList()
                        ?? (IReadOnlyList<PortFact>)Array.Empty<PortFact>(),
                Vulns = item.VulnResults ?? (IReadOnlyList<VulnerabilityResult>)Array.Empty<VulnerabilityResult>()
            }).ToList();

            var result = BatchScanAnalyticsService.Analyze(inputs);

            bool hasData = result.HostThreatDistribution.Count > 0 || result.VulnRiskDistribution.Count > 0;
            AnalysisEmptyTextBlock.Visibility = hasData ? Visibility.Collapsed : Visibility.Visible;
            AnalysisContentPanel.Visibility = hasData ? Visibility.Visible : Visibility.Collapsed;
            if (!hasData)
            {
                TopVulnListView.ItemsSource = null;
                TopHostListView.ItemsSource = null;
                PortDistListView.ItemsSource = null;
                AffectedHostsPanel.Visibility = Visibility.Collapsed;
                return;
            }

            BuildBar(HostThreatBarGrid, HostThreatLegendPanel, result.HostThreatDistribution, isHostBar: true);
            BuildBar(VulnRiskBarGrid, VulnRiskLegendPanel, result.VulnRiskDistribution, isHostBar: false);
            TopVulnListView.ItemsSource = result.TopVulnerabilities;
            TopHostListView.ItemsSource = result.TopHosts;
            PortDistListView.ItemsSource = result.PortDistribution;

            // 恢复 TOP 漏洞选中（触发 SelectionChanged，自动重建受影响主机面板）
            if (_selectedTopVulnKey != null)
            {
                TopVulnListView.SelectedItem = result.TopVulnerabilities
                    .FirstOrDefault(t => $"{t.Name}|{t.Port}|{t.Service}" == _selectedTopVulnKey);
            }
        }

        private static readonly Dictionary<string, string> ThreatBarColors = new()
        {
            ["Critical"] = "#991B1B",
            ["High"] = "#C2410C",
            ["Medium"] = "#D97706",
            ["Low"] = "#059669",
            ["None"] = "#95A5A6"
        };

        private static readonly Dictionary<string, string> RiskBarColors = new()
        {
            ["严重"] = "#991B1B",
            ["高危"] = "#C2410C",
            ["中危"] = "#D97706",
            ["低危"] = "#059669"
        };

        private static string ThreatDisplayName(string level) => level switch
        {
            "Critical" => "严重",
            "High" => "高危",
            "Medium" => "中危",
            "Low" => "低危",
            _ => "无威胁"
        };

        /// <summary>原生条带图：按占比生成 Grid 比例列色块 + 图例。</summary>
        private void BuildBar(Grid barGrid, WrapPanel legendPanel, List<RiskDistributionItem> items, bool isHostBar)
        {
            barGrid.Children.Clear();
            barGrid.ColumnDefinitions.Clear();
            legendPanel.Children.Clear();
            var colors = isHostBar ? ThreatBarColors : RiskBarColors;

            int col = 0;
            foreach (var item in items)
            {
                var display = isHostBar ? ThreatDisplayName(item.Level) : item.Level;
                var colorHex = colors.TryGetValue(item.Level, out var c) ? c : "#7F8C8D";
                var brush = new System.Windows.Media.SolidColorBrush(
                    (System.Windows.Media.Color)System.Windows.Media.ColorConverter.ConvertFromString(colorHex));

                if (item.Count > 0)
                {
                    barGrid.ColumnDefinitions.Add(new ColumnDefinition
                    {
                        Width = new GridLength(Math.Max(item.Ratio, 0.001), GridUnitType.Star)
                    });
                    var border = new Border
                    {
                        Background = brush,
                        ToolTip = $"{display}: {item.Count} ({item.Ratio:P0})"
                    };
                    Grid.SetColumn(border, col++);
                    barGrid.Children.Add(border);
                }

                var legend = new TextBlock { FontSize = 10, Margin = new Thickness(0, 2, 10, 0), Foreground = System.Windows.Media.Brushes.DimGray };
                legend.Inlines.Add(new System.Windows.Documents.Run("■ ") { Foreground = brush });
                legend.Inlines.Add(new System.Windows.Documents.Run($"{display} {item.Count} ({item.Ratio:P0})"));
                legendPanel.Children.Add(legend);
            }
        }

        /// <summary>新一轮扫描启动时清空分析面板（与列表清空同点调用）。</summary>
        private void ResetAnalysisPanel()
        {
            AnalysisEmptyTextBlock.Visibility = Visibility.Visible;
            AnalysisContentPanel.Visibility = Visibility.Collapsed;
            TopVulnListView.ItemsSource = null;
            TopHostListView.ItemsSource = null;
            PortDistListView.ItemsSource = null;
            HostThreatBarGrid.Children.Clear();
            HostThreatBarGrid.ColumnDefinitions.Clear();
            HostThreatLegendPanel.Children.Clear();
            VulnRiskBarGrid.Children.Clear();
            VulnRiskBarGrid.ColumnDefinitions.Clear();
            VulnRiskLegendPanel.Children.Clear();
            AffectedHostsPanel.Visibility = Visibility.Collapsed;
            AnalysisStatusTextBlock.Text = "";
            _selectedTopVulnKey = null;
            _lastAnalysisRefreshUtc = DateTime.MinValue;
        }
```

（需确保文件顶部有 `using NetSecurityScanner.Core.Models;`，若无则添加。）

- [ ] **Step 5: 挂接刷新点**

a. `UpdateGlobalStatistics()` 方法体末尾追加一行：

```csharp
            RefreshAnalysisThrottled();
```

b. 扫描启动清空点：在 `StartBatchScanButton_Click` 中清空 `_ipItems` 的代码附近（列表 Clear 之后）追加一行：

```csharp
            ResetAnalysisPanel();
```

c. 扫描完成点（L382 附近，`BatchScanStatusTextBlock.Text = "扫描完成";` 行之后）追加一行：

```csharp
            RefreshAnalysisThrottled(force: true);
```

- [ ] **Step 6: 构建 Desktop 验证通过**

Run: `dotnet build src\NetSecurityScanner.Desktop\NetSecurityScanner.Desktop.csproj -c Debug --nologo -v q`
Expected: `0 个错误`（TopVulnListView_SelectionChanged 等三个事件处理器尚未实现会出现 CS1061——属预期，Task 9 补齐后统一构建提交）

**推荐：本任务与 Task 9 连续执行，Task 9 末尾统一构建后一起提交。**

---

## Task 9: 钻取交互（三个事件处理器 + 统一定位）

**Files:**
- Modify: `src/NetSecurityScanner.Desktop/Views/Views/BatchScanWindow.xaml.cs`

- [ ] **Step 1: 实现钻取处理器**

在 `UpdateAnalysisPanel()` 之后新增：

```csharp
        private void TopVulnListView_SelectionChanged(object sender, SelectionChangedEventArgs e)
        {
            if (TopVulnListView.SelectedItem is TopVulnerabilityItem item)
            {
                AffectedHostsTitleTextBlock.Text = $"受影响主机 ({item.AffectedHostCount})";
                AffectedHostsWrapPanel.Children.Clear();
                foreach (var ip in item.AffectedHosts)
                {
                    var btn = new Button { Content = ip, Tag = ip, Style = (Style)FindResource("IpChipStyle") };
                    btn.Click += AffectedHostChip_Click;
                    AffectedHostsWrapPanel.Children.Add(btn);
                }
                AffectedHostsPanel.Visibility = Visibility.Visible;
            }
            else
            {
                AffectedHostsPanel.Visibility = Visibility.Collapsed;
            }
        }

        private void AffectedHostChip_Click(object sender, RoutedEventArgs e)
        {
            if (sender is Button btn && btn.Tag is string ip)
            {
                LocateHostInList(ip);
            }
        }

        private void TopHostListView_SelectionChanged(object sender, SelectionChangedEventArgs e)
        {
            if (TopHostListView.SelectedItem is TopHostItem item)
            {
                LocateHostInList(item.IpAddress);
                // 清空选择，允许重复点击同一行再次定位
                TopHostListView.SelectedItem = null;
            }
        }

        private void CloseAffectedHostsPanel_Click(object sender, RoutedEventArgs e)
        {
            AffectedHostsPanel.Visibility = Visibility.Collapsed;
            TopVulnListView.SelectedItem = null;
        }

        /// <summary>
        /// 在左侧结果列表中定位指定 IP：被过滤隐藏时先重置过滤为"全部"并提示。
        /// 不切换右侧详情页签。
        /// </summary>
        private void LocateHostInList(string ip)
        {
            var item = _ipItems.FirstOrDefault(x => x.IpAddress == ip);
            if (item == null) return;

            if (!_ipItemsView.Contains(item))
            {
                StatusFilterComboBox.SelectedIndex = 0;
                ThreatFilterComboBox.SelectedIndex = 0;
                AnalysisStatusTextBlock.Text = $"已清除过滤条件以定位 {ip}";
            }

            IpListView.SelectedItem = item;
            IpListView.ScrollIntoView(item);
            IpListView.Focus();
        }
```

- [ ] **Step 2: 构建 Desktop 验证通过**

Run: `dotnet build src\NetSecurityScanner.Desktop\NetSecurityScanner.Desktop.csproj -c Debug --nologo -v q`
Expected: `0 个错误`

- [ ] **Step 3: 提交（含 Task 7/8 的 XAML 与接线）**

```powershell
git add src/NetSecurityScanner.Desktop/Views/Views/BatchScanWindow.xaml src/NetSecurityScanner.Desktop/Views/Views/BatchScanWindow.xaml.cs
git commit -m "feat: 批量扫描新增整体分析页签（分布条带/TOP榜/端口分布）与双向钻取"
```

---

## Task 10: 全量验证与手动验收

**Files:** 无（仅验证）

- [ ] **Step 1: 全量单测**

Run: `dotnet test src\NetSecurityScanner.Core.Tests\NetSecurityScanner.Core.Tests.csproj -c Debug --nologo`
Expected: `通过: 294`，`失败: 0`

- [ ] **Step 2: Desktop 构建**

Run: `dotnet build src\NetSecurityScanner.Desktop\NetSecurityScanner.Desktop.csproj -c Debug --nologo -v q`
Expected: `0 个错误`

- [ ] **Step 3: 提交序列核对**

Run: `git log --oneline -8`
Expected: 自上而下为 Task 9、Task 6、Task 4、Task 3、Task 1 五个新提交（顺序执行时 Task 1 最早）

- [ ] **Step 4: 手动验收清单（需用户参与）**

运行 `dotnet run --project src\NetSecurityScanner.Desktop -c Debug`，逐项核对：

1. 扫描产生漏洞后，「📊 整体分析」页签四块内容实时出现并随扫描增长；无数据时显示空态提示
2. 两条条带图比例、图例数字与列表明细一致；悬停色块显示 ToolTip
3. TOP 漏洞选中 → 受影响主机面板展开，IP 标签数量与「N 台」一致；CVE ToolTip 显示
4. 点受影响主机 IP → 左侧列表定位选中该行；若该行被过滤隐藏，自动清除两个过滤下拉并显示提示
5. 点 TOP 主机行 → 直接定位；可重复点击同一行
6. 点击各排序表头：首击方向正确（IP 升序、其余降序）、再击反转、▲/▼ 指示正确、与状态/威胁过滤组合正常、IP 按数值序（10.0.0.2 在 10.0.0.10 前）
7. 关闭重开窗口：排序字段与方向还原
8. 扫描中高频刷新时 UI 不卡顿、TOP 漏洞选中不被刷新打断；新扫描启动后面板清空归零

---

## 自查记录

- 规格 11 节全部映射到任务：§4→T1-3，§5→T7-8，§6→T4-6，§7→T9，§8→T8，§9→T2-3，§10→T10
- 类型一致性：`HostAnalysisInput`/`PortFact`/`TopVulnerabilityItem` 等名称在 Core、测试、窗口三处一致；`IpNumericComparer.Instance` 在 Core 与 Desktop 比较器间复用
- 中间态构建错误（T5 的 SortHeader_Click、T8 的三个事件处理器与转换器）已在对应任务中显式标注为预期并给出连续执行建议
