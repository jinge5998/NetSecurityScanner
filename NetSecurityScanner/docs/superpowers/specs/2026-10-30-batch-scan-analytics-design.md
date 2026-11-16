# 批量扫描 S2：结果分析面板与列表排序 设计规格

**状态**：已确认（方案 A，6 节设计逐节批准）
**前置**：S1《2026-10-29-batch-scan-control-design.md》已实施（分支 feature/batch-camera-scan-enhance）
**实施计划**：`docs/superpowers/plans/2026-10-30-batch-scan-analytics-plan.md`（writing-plans 生成）

---

## 1. 背景与目标

S1 已完成批量扫描的扫描控制与交互（配置记忆、目标校验、预估确认、暂停/继续、失败分类、按类别重扫）。S2 解决「扫完之后看不懂结果」的问题：

- 为批量扫描窗口增加**内嵌结果分析面板**：威胁分布条带图、TOP 漏洞榜、TOP 风险主机榜、端口/服务分布
- 结果列表支持**列头点击排序**，排序状态纳入配置记忆
- 分析面板与列表**双向钻取**：TOP 漏洞 → 受影响主机列表 → 定位结果列表行；TOP 主机 → 定位行

## 2. 关键决策（已与用户确认）

| 决策点 | 结论 |
|---|---|
| 数据范围 | 仅当前窗口会话结果，不做跨次持久化与趋势对比 |
| 面板形态 | 内嵌分析面板（非独立窗口），位于右侧详情 TabControl 新增页签「📊 整体分析」 |
| 统计维度 | 风险分布图 + TOP 风险主机 + TOP 漏洞榜 + 端口/服务分布 |
| 图表实现 | WPF 原生条带图（Border/Grid 比例列），零第三方图表库 |
| 参与统计范围 | 仅 `Status == "已完成"` 的主机；扫描中/失败/已取消不进入分析 |
| 排序 | 结果列表新增可点击排序表头，状态写入 BatchScanSettings 记忆 |
| 钻取 | 双向：TOP 漏洞→受影响主机→定位行；TOP 主机→定位行 |
| 刷新时机 | 扫描中实时刷新，挂 `UpdateGlobalStatistics()` 调用点做 300ms 节流 |
| 架构 | 方案 A：聚合逻辑下沉 Core 纯函数可单测，窗口只绑定展示 |

## 3. 架构

延续 S1 分层：`NetSecurityScanner.Core` 新增 `BatchScanAnalyticsService`（静态纯函数）+ 分析 DTO；窗口 `BatchScanWindow` 负责投影 `IpScanItem` → `HostAnalysisInput`、绑定展示、钻取与排序。Core 不依赖 Desktop 类型，单测放 `NetSecurityScanner.Core.Tests`。

## 4. Core 层数据模型与服务

### 4.1 新文件

- `src/NetSecurityScanner.Core/Models/BatchScanAnalysisDtos.cs`：全部分析 DTO
- `src/NetSecurityScanner.Core/Services/BatchScanAnalyticsService.cs`：聚合服务
- `src/NetSecurityScanner.Core/Services/IpNumericComparer.cs`：IPv4 数值比较器（排序复用）

### 4.2 数据模型

```csharp
public class HostAnalysisInput
{
    public string IpAddress { get; init; } = "";
    public string Status { get; init; } = "";          // 仅"已完成"参与统计
    public string ThreatLevel { get; init; } = "None"; // Critical/High/Medium/Low/None
    public int OpenPortsCount { get; init; }
    public int VulnCount { get; init; }
    public int CriticalCount { get; init; }
    public int HighCount { get; init; }
    public IReadOnlyList<PortFact> Ports { get; init; } = Array.Empty<PortFact>();
    public IReadOnlyList<VulnerabilityResult> Vulns { get; init; } = Array.Empty<VulnerabilityResult>();
}

public class PortFact { public int Port; public string Service = ""; }

public class RiskDistributionItem { public string Level; public int Count; public double Ratio; }
public class TopVulnerabilityItem { public string Name; public int? Port; public string Service; public string CveId; public string HighestRisk; public int AffectedHostCount; public IReadOnlyList<string> AffectedHosts; }
public class TopHostItem { public string IpAddress; public string ThreatLevel; public int VulnCount; public int CriticalCount; public int HighCount; public int OpenPortsCount; }
public class PortDistributionItem { public int Port; public string Service; public int HostCount; }
public class BatchScanAnalysisResult
{
    public List<RiskDistributionItem> HostThreatDistribution;   // 按主机 ThreatLevel 5 级
    public List<RiskDistributionItem> VulnRiskDistribution;     // 按漏洞 RiskLevel 4 级
    public List<TopVulnerabilityItem> TopVulnerabilities;
    public List<TopHostItem> TopHosts;
    public List<PortDistributionItem> PortDistribution;
}
```

### 4.3 聚合规则

- 仅统计 `Status == "已完成"` 的主机
- 主机威胁分布：按 ThreatLevel 分 5 级统计主机数+占比；漏洞风险分布：按 RiskLevel（严重/高危/中危/低危）统计漏洞条数+占比
- TOP 漏洞榜：按 `Name+Port+Service` 分组；排序 = 影响主机数 ↓ → 最高风险 ↓ → 名称；`AffectedHosts` 保留全部 IP
- TOP 主机榜：排序 = `ThreatWeight` ↓ → VulnCount ↓ → OpenPortsCount ↓，取 topN（默认 10）
- 端口分布：按开放主机数 ↓，取 topN；服务名取组内多数值
- `ThreatWeight`：Critical=4/High=3/Medium=2/Low=1/None=0；`RiskWeight`：严重=4/高危=3/中危=2/低危=1，兼容英文取值

## 5. UI：分析面板（右侧详情 TabControl 新增页签「📊 整体分析」）

ScrollViewer 纵向四块：

1. **威胁概览条带**：条带 A「主机威胁分布」+ 条带 B「漏洞等级分布」。高 18px，Grid 比例列按占比横排色块：严重 `#991b1b` / 高 `#c2410c` / 中 `#d97706` / 低 `#059669` / 无 `#95a5a6`；每条带下方图例 `■ 严重 12 (24%)`
2. **TOP 漏洞榜** ListView：漏洞名称 │ 端口 │ 最高级别色块 │ 影响主机数；选中 → 下方展开受影响主机面板
3. **TOP 风险主机** ListView：IP │ 威胁 │ 漏洞 │ 高危 │ 端口数
4. **端口/服务分布** ListView：端口 │ 服务 │ 主机数 + 迷你比例条

空态：无已完成主机时显示「暂无分析数据（完成扫描后自动生成）」。

## 6. UI：结果列表排序

### 6.1 表头行

IP 列表卡片 Grid 改 4 行（Auto/Auto/Auto/*），过滤行与 `IpListView` 之间插入排序表头（`IpListView` 移至 Grid.Row=3）。6 列与行模板对齐：状态(20) │ IP地址(*) │ 漏洞(56) │ 进度(50) │ 耗时(60) │ 失败原因(90)，均为扁平 `Button`（Tag=字段名，Click 走同一处理器），激活表头显示 ▲/▼。

### 6.2 行模板

新增「漏洞」列（IP 与进度之间）：`TextBlock Text="{Binding VulnCount}"`，前景色复用 `ThreatLevelToForegroundConverter`；ToolTip 显示「严重 X / 高危 Y」。后续列序号顺延。

### 6.3 排序逻辑

- `_ipItemsView.CustomSort` 挂单个 `IComparer<IpScanItem>`（与现有 `Filter = IpItemFilter` 组合）
- 字段比较键与首击方向：

| Tag | 比较键 | 首击 |
|---|---|---|
| Threat | `ThreatWeight(ThreatLevel)` → VulnCount | 降 |
| Ip | IPv4 四段数值（`IpNumericComparer`），非法/空排最后 | 升 |
| Vuln | VulnCount → CriticalCount → HighCount | 降 |
| Progress | 状态权重（扫描中>等待中>已完成>失败>已取消） | 降 |
| Duration | `DurationSeconds`（IpScanItem 新增数值属性，计时处与 DurationText 同步赋值） | 降 |
| Failure | FailureCategory 枚举值 | 降 |

- 同字段再点切换升降；排序状态（`SortField`/`SortDescending`）写入 `BatchScanSettings`，随 S1 防抖保存路径记忆与恢复
- 重扫/清空列表时排序状态保留

## 7. UI：钻取交互

- **TOP 漏洞榜**：`SelectionChanged` → 展开「受影响主机」面板（标题 `受影响主机 (N)` + WrapPanel IP 标签按钮 + ✕ 关闭）；点 IP 标签 → `LocateHostInList(ip)`
- **TOP 主机榜**：`SelectionChanged` → 直接 `LocateHostInList(ip)`
- **统一定位**：

```csharp
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

- 定位不切换右侧详情页签；选中行系统高亮即可，不加闪烁动画
- 端口分布无钻取
- 新一轮扫描启动时：清空榜单、条带归零、折叠受影响主机面板（与列表清空同点）

## 8. 刷新节流

- 挂点：`UpdateGlobalStatistics()` 末尾调 `RefreshAnalysisThrottled()`；300ms 节流（`_lastAnalysisRefreshUtc`）
- 扫描启动、停止、重扫结束时强制执行一次（绕过节流）
- 流程：投影 → `Analyze` → 更新三个榜单 ItemsSource + 条带比例列宽 + 图例文本
- 性能：单次 <50ms（N=65536），节流上限约 3 次/秒

## 9. 测试策略

**Core.Tests 新增**：

`BatchScanAnalyticsServiceTests`（8 组）：
1. 空输入 → 空结果
2. 仅统计已完成（扫描中/失败/已取消被排除）
3. 主机威胁分布计数与占比
4. 漏洞风险分布计数
5. TOP 漏洞：影响主机数排序、分组去重、组内最高风险、AffectedHosts 完整
6. TOP 主机：三级排序规则、topN 截断
7. 端口分布聚合与服务名多数值
8. ThreatWeight/RiskWeight 中英文兼容

`IpNumericComparerTests`（3 组）：四段数值升序、非法/空值排最后、相等返回 0。

## 10. 手动验收清单

1. 扫描产生漏洞后，分析页签四块内容实时出现并随扫描增长
2. 条带图比例、图例数字与漏洞明细一致
3. TOP 漏洞选中 → 受影响主机面板展开，IP 数量与「影响主机数」一致
4. 点受影响主机 IP → 左侧列表定位选中该行；被过滤时自动清除过滤并提示
5. 点 TOP 主机行 → 直接定位
6. 点击各排序表头：首击方向正确、再击反转、▲/▼ 指示正确、与过滤组合正常
7. 关闭重开窗口：排序字段与方向还原（配置记忆）
8. 扫描中高频刷新时 UI 不卡顿；新扫描启动后面板清空归零

## 11. 非目标（YAGNI）

- 跨次扫描历史持久化、趋势对比
- 分析报告导出（HTML/CSV 导出结构不变）
- 第三方图表库、动画高亮
- 端口分布钻取、威胁等级筛选联动
