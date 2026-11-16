# 规格：专家模式「实时端口/漏洞结果表为空」修复

- 日期：2026-10-30
- 状态：已批准，已实施（待手动 UI 验证）
- 关联缺陷：专家模式扫描实际扫到端口（日志 1122 条结果、4 个开放端口），但「实时端口扫描结果」DataGrid 显示为空；漏洞表同样不刷新。

## 1. 根因

`ExpertModeWindow` 中两个实时结果表的数据源是 `BulkObservableCollection<T>`：

- `_allPortScanResults`（L113）
- `_allVulnResults`（L114）
- 扫描开始时绑定：`RealTimePortResultsDataGrid.ItemsSource = _allPortScanResults`（L1132-1133）
- 扫描结果通过 `AddRange`（Reset 通知）写入，UI 线程安全，无异常（日志无「写入实时端口结果失败」）

但以下动作把 `ItemsSource` 替换成**一次性 `List<T>` 快照**，从此与实时集合断开：

| 动作 | 位置 | 现状 |
|---|---|---|
| 筛选开放端口 | L4287-4289 | `ItemsSource = null; ItemsSource = filtered;` |
| 筛选高危端口 | L4308-4309 | 同上 |
| 筛选高危漏洞 | L4435-4436 | 同上 |
| 筛选中危漏洞 | L4456-4457 | 同上 |
| 端口深度漏洞扫描后 | L4544 | `ItemsSource = snapshot;` |

后果：

1. 若在扫描出结果**之前**点过任一筛选（此时快照为空），扫描结束后 1122 条结果全部进不了表格 → 表格永久为空（用户所见现象）。
2. 若扫描后点筛选，快照不会随后续增量更新。
3. 深度扫描后漏洞表同样冻结，且再扫描时 `AddRange` 无法反映。

界面无「当前处于筛选状态」标识，重置按钮存在但用户无从得知需要点击。

## 2. 修复目标（AC）

- **AC1**：任意筛选/深度扫描动作之后，实时结果仍能随扫描增量刷新，`ItemsSource` 始终是同一个视图对象。
- **AC2**：新一次扫描开始时自动清除遗留筛选，并在扫描日志明确提示（避免"上次筛选把新结果筛成 0 条"）。
- **AC3**：筛选语义不变：开放端口 = `Status == "开放"`；高危端口 = `RiskScore >= 15`；高危漏洞 = `RiskLevel ∈ {高危, 严重}`；中危漏洞 = `RiskLevel == "中危"`。
- **AC4**：「重置筛选」按钮清除筛选并恢复全部行，日志显示当前总数。
- **AC5**：表格列头排序、右键排序/删除/复制、双击钻取等既有交互不回退。
- **AC6**：`dotnet build` 0 错误；`Core.Tests` 全量仍为 279 通过（本次不改 Core）。

## 3. 方案（单一数据视图）

用 `ListCollectionView` 包裹实时集合作为**唯一** `ItemsSource`；筛选改为设置 `Filter` 谓词 + `Refresh()`，排序仍沿用既有 `AddRangeReset`（视图会自动响应 Reset）。不再有任何 `ItemsSource = List<T>` 赋值。

### 3.1 新增字段（文件：`src\NetSecurityScanner.Desktop\Views\Views\ExpertModeWindow.xaml.cs`，L113-140 字段区）

```csharp
// 实时结果表的唯一数据视图：筛选只改 Filter 谓词，绝不替换 ItemsSource。
// 历史缺陷：筛选时把 ItemsSource 换成 List 快照，导致后续扫描结果无法显示（表恒为空）。
private ListCollectionView? _portResultsView;
private ListCollectionView? _vulnResultsView;
```

### 3.2 构造期初始化并绑定（L159-160 之后）

```csharp
_allPortScanResults = new BulkObservableCollection<PortScanResult>();
_allVulnResults = new BulkObservableCollection<VulnerabilityResult>();

_portResultsView = new ListCollectionView(_allPortScanResults);
_vulnResultsView = new ListCollectionView(_allVulnResults);
RealTimePortResultsDataGrid.ItemsSource = _portResultsView;
RealTimeVulnResultsDataGrid.ItemsSource = _vulnResultsView;
```

（`InitializeComponent()` 在此前已调用，控件实例可用。）

### 3.3 扫描开始：清除筛选 + 绑定视图（L1132-1133）

```csharp
if (_portResultsView?.Filter != null)
{
    _portResultsView.Filter = null;
    _portResultsView.Refresh();
    AppendLog("ℹ️ 新扫描开始：已自动清除上次的端口结果筛选");
}
if (_vulnResultsView?.Filter != null)
{
    _vulnResultsView.Filter = null;
    _vulnResultsView.Refresh();
}
RealTimePortResultsDataGrid.ItemsSource = _portResultsView;
RealTimeVulnResultsDataGrid.ItemsSource = _vulnResultsView;
```

### 3.4 端口筛选（L4276-4316）

```csharp
private void FilterOpenPorts_Click(object sender, RoutedEventArgs e)
{
    if (_portResultsView == null) return;
    try
    {
        _portResultsView.Filter = o => o is PortScanResult r && r.Status == "开放";
        _portResultsView.Refresh();
        AppendLog($"已筛选开放端口，共 {_portResultsView.Cast<PortScanResult>().Count()} 个（后续结果仍实时更新）");
    }
    catch (Exception ex) { AppendLog($"筛选失败: {ex.Message}"); }
}

private void FilterHighRiskPorts_Click(object sender, RoutedEventArgs e)
{
    if (_portResultsView == null) return;
    try
    {
        _portResultsView.Filter = o => o is PortScanResult r && r.RiskScore >= 15;
        _portResultsView.Refresh();
        AppendLog($"已筛选高危/严重端口，共 {_portResultsView.Cast<PortScanResult>().Count()} 个（后续结果仍实时更新）");
    }
    catch (Exception ex) { AppendLog($"高危筛选失败: {ex.Message}"); }
}
```

（`_resultsLock` 用于保护集合读写的既有做法保留其必要场景：`ToDisplayText` 导出等在后台线程读取集合处；筛选改为视图 Filter 后不再需要快照拷贝。）

### 3.5 端口重置（L4032-4046）

```csharp
_portResultsView.Filter = null;
_portResultsView.Refresh();
AppendLog($"已重置端口结果筛选，当前显示全部 {_allPortScanResults.Count} 条");
```

### 3.6 漏洞筛选 / 重置（L4424-4464、L4048+）

```csharp
_vulnResultsView.Filter = o => o is VulnerabilityResult v && (v.RiskLevel == "高危" || v.RiskLevel == "严重");
// 中危：v.RiskLevel == "中危"
// 重置：_vulnResultsView.Filter = null; _vulnResultsView.Refresh();
```

### 3.7 深度扫描不再换数据源（L4542-4547）

```csharp
Dispatcher.Invoke(() =>
{
    // 直接复用既有视图：新增漏洞由集合 Reset/Add 通知驱动，无需替换 ItemsSource
    _vulnResultsView.Refresh();
    if (VulnerabilitiesStat != null) VulnerabilitiesStat.Text = _allVulnResults.Count.ToString();
});
```

## 4. 不做的事（明确边界）

- 不改 `BulkObservableCollection`、不改 `RustScannerClient`、不改 Core、不改 XAML 布局。
- 不新增「筛选生效」徽标控件（用日志提示，避免 XAML 改动扩大回归面）。
- 不改扫描流程（TCP/UDP 拆分修复已独立提交 `3b57a83`）。

## 5. 验证

1. 构建：`dotnet build src\NetSecurityScanner.Desktop\NetSecurityScanner.Desktop.csproj -c Debug --nologo -v q` → 0 错误。
2. 回归单测：`dotnet test src\NetSecurityScanner.Core.Tests\NetSecurityScanner.Core.Tests.csproj --nologo -v q` → 279 通过。
3. 手动（复现原缺陷再验证已修）：
   - a) 打开专家模式 → 表格为空时点「筛选开放端口」→ 开始扫描 `211.137.75.166`（1122 端口）→ 扫描完成应能实时看到 1122 行、开放端口行存在；日志出现「已自动清除上次的端口结果筛选」。
   - b) 扫描完成后点「筛选开放端口」→ 仅显示开放行；点「重置筛选」→ 恢复全部行。
   - c) 双击某个开放端口行做深度扫描 → 漏洞表追加显示，且已存在的行仍在（不再是快照断链）。
   - d) 列头排序 / 右键「按风险评分降序」/「删除选中行」仍正常。
