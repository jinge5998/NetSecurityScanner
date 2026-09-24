# 综合扫描完善 Spec

## Why
当前 `MainWindow.xaml.cs:1319-1548` 的 `ExecuteComprehensiveScanAsync` 长达 230+ 行,在一个 UI 事件处理器中混杂了"参数解析 + TCP扫描 + UDP扫描 + 漏洞扫描 + 插件扫描 + 风险汇总 + 历史保存 + UI 更新" 8 件事,违反 SRP,无法被 CLI / Web API / 自动化测试复用。`ComprehensiveScanDialog` 也只支持自定义端口范围 + 3 个复选框,缺乏**扫描预设**、**并发扫描**、**主机存活探测**、**结果可视化**、**导出/对比**等关键能力。本 spec 将这 5 大方向一次性补齐。

## What Changes

### 1. 新建可重用服务层 (`NetSecurityScanner.Core`)
- 新增 `ComprehensiveScanService` (Core/Services/) — 唯一对外的综合扫描编排入口
- 新增 `ComprehensiveScanOptions` / `ComprehensiveScanResult` / `ScanPhase` / `ScanPhaseProgress` 4 个数据模型
- 新增 `ScanPresetRegistry` 静态预设(`Quick=Top100`/`Standard=1-1000`/`Deep=1-65535`/`Web=80,443,8080,8443`/`Db=1433,1521,3306,5432,6379,27017`)
- `ComprehensiveScanService.ExecuteAsync(options, IProgress<ScanPhaseProgress>, CancellationToken)` 按"存活探测→端口扫描(TCP+UDP 并发)→服务识别→漏洞扫描→插件扫描→风险汇总" 6 阶段串行编排,任一阶段异常不阻断后续阶段

### 2. UI 体验提升
- `ComprehensiveScanDialog.xaml` 重构为左右分栏:左侧配置(目标/预设/端口/并发数/超时/线程/重试次数/插件开关),右侧实时预览(端口数估算、扫描耗时估算、最近一次扫描摘要)
- 新增 `ComprehensiveScanResultWindow.xaml`(.cs) — 富文本结果窗口,按"概览/端口/漏洞/服务/插件/风险" 5 个 Tab 展示,替代完成时 `MessageBox`
- 新增 `ScanProgressLiveWindow.xaml`(.cs) — 实时进度窗,显示阶段(存活探测/TCP/UDP/服务/漏洞/插件)、进度条、当前已发现端口列表、当前线程数、已用时间/剩余时间
- `MainWindow.xaml.cs` 的 `StartScan_Click` 改为只负责"弹对话框→调服务→弹结果窗",业务逻辑全部下沉到服务层

### 3. 代码结构重构
- `MainWindow.xaml.cs` 中 `ExecuteComprehensiveScanAsync` 的 230+ 行实现整体删除,替换为 ~30 行的"UI 协调器"
- 私有帮助方法 `UpdateScanStatus` / `UpdateScanButtonStates` 保留 UI 工具,移除业务耦合
- 把 `ParsePortRange` 字符串解析逻辑从 `MainWindow` 抽出,放到 `ScanPresetRegistry.ParsePortList(string)`,作为唯一权威端口解析器

### 4. 结果分析与导出
- `ComprehensiveScanResultWindow` 内置"导出"按钮:复用现有 `ScanExportService.ExportToJson/ExportToCsv`
- 新增"对比历史"按钮:取 `JsonDatabaseService.GetScanHistoryAsync` 中同一 `TargetIp` 的最近一次扫描,调 `ScanComparisonService.CompareScans`,结果以"新增/消失/持续"三段式展示
- 内置"按端口/按风险/按服务"三种筛选
- 内置"复制为 Markdown"按钮,一键复制富文本摘要到剪贴板

### 5. 扫描能力增强
- **扫描预设**:`Quick`/`Standard`/`Deep`/`Web`/`Database`/`Custom` 6 个内置预设 + 用户自定义持久化
- **并发 TCP+UDP 扫描**:`ComprehensiveScanService` 内部用 `Task.WhenAll` 并发跑两个扫描器,共享同一 `CancellationToken`
- **主机存活探测**:阶段 1 用 ICMP ping(如失败回退 TCP 80/443 connect),失败时仍允许继续但风险标记为"目标不可达,结果可能不完整"
- **超时与重试**:每个阶段可配置超时(默认端口 5s、漏洞 30s、插件 60s),单端口失败重试 1 次
- **服务版本识别**:已存在于 `PortScanner.ScanTcpPortsAsync` 内部,服务层只做汇总,不重新实现
- **插件扫描**:用现有 `PluginOrchestrator.Instance.ScanTargetAsync`,失败不阻断主流程

## Impact
- **新增文件**:
  - `NetSecurityScanner/src/NetSecurityScanner.Core/Services/ComprehensiveScanService.cs`
  - `NetSecurityScanner/src/NetSecurityScanner.Core/Models/ComprehensiveScanOptions.cs`
  - `NetSecurityScanner/src/NetSecurityScanner.Core/Models/ComprehensiveScanResult.cs`
  - `NetSecurityScanner/src/NetSecurityScanner.Core/Models/ScanPhaseProgress.cs`
  - `NetSecurityScanner/src/NetSecurityScanner.Core/Services/ScanPresetRegistry.cs`
  - `NetSecurityScanner/src/NetSecurityScanner.Desktop/Views/ComprehensiveScanResultWindow.xaml(.cs)`
  - `NetSecurityScanner/src/NetSecurityScanner.Desktop/Views/ScanProgressLiveWindow.xaml(.cs)`
- **修改文件**:
  - `NetSecurityScanner/src/NetSecurityScanner.Desktop/Views/ComprehensiveScanDialog.xaml(.cs)` — 大改 UI + 引入预设
  - `NetSecurityScanner/src/NetSecurityScanner.Desktop/MainWindow.xaml.cs` — `StartScan_Click` + 删除 `ExecuteComprehensiveScanAsync`
- **影响 UI**:扫描菜单"开始综合扫描" → ComprehensiveScanDialog → ScanProgressLiveWindow → ComprehensiveScanResultWindow
- **依赖服务**(全部已存在,无需新写):`PortScanner` / `VulnerabilityScanner` / `PluginOrchestrator` / `RiskAssessmentService` / `ScanComparisonService` / `ScanExportService` / `ScanPresetService` / `JsonDatabaseService`

## ADDED Requirements

### Requirement: ComprehensiveScanService 可重用编排入口
系统 SHALL 提供 `NetSecurityScanner.Services.ComprehensiveScanService.ExecuteAsync(ComprehensiveScanOptions, IProgress<ScanPhaseProgress>, CancellationToken)`,作为唯一对外编排入口,按"存活探测→TCP+UDP 并发→服务识别→漏洞扫描→插件扫描→风险汇总" 6 阶段串行执行,任一阶段异常被 try/catch 隔离,不阻断后续阶段,最终 `ComprehensiveScanResult` 仍返回。

#### Scenario: 完整流程成功
- **WHEN** 调用方传入 `TargetIp=192.168.1.1`, `Preset=Standard`, `EnableTcp=true`, `EnableUdp=true`, `EnableVulnScan=true`, `EnablePluginScan=true`
- **THEN** 6 阶段全部跑完,返回 `ComprehensiveScanResult.OpenPortsCount / VulnerabilitiesCount / PluginResultsCount / RiskLevel / Phases` 字段全部填充,`Phases` 列表里每项 `Phase / Status=Success / DurationMs`

#### Scenario: 漏洞扫描阶段异常
- **WHEN** 漏洞扫描阶段内部抛异常
- **THEN** `Phases["VulnerabilityScan"].Status=Failed`, `ErrorMessage` 记录异常文本,后续"插件扫描"和"风险汇总"继续执行,最终 `ComprehensiveScanResult` 仍返回(标志位 `HasVulnerabilityScanError=true`)

### Requirement: 综合扫描预设(ScanPresetRegistry)
系统 SHALL 提供 6 个内置预设,加载时无需读文件:
- `Quick`: Top-100 常用端口(22, 21, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995, 1723, 3306, 3389, 5900, 8080 等)
- `Standard`: 1-1000
- `Deep`: 1-65535(默认 200 线程)
- `Web`: 80, 443, 8000, 8008, 8080, 8081, 8443, 8888, 9090, 9200
- `Database`: 1433, 1521, 3306, 5432, 6379, 9042, 9200, 11211, 27017
- `Custom`: 用户输入

`ScanPresetRegistry.ParsePortList(string)` 接受 `1-1000,443,8080-8090` 混合格式,返回去重排序后的 `List<int>`,非法输入抛 `ArgumentException`(与 `MainWindow` 中现有 `ParsePortRange` 行为一致)。

#### Scenario: 选择 Standard 预设
- **WHEN** 用户在对话框选择 `Standard`
- **THEN** 端口范围输入框自动填 `1-1000`,右侧预览显示"1000 个端口,预计耗时 ~30 秒"

#### Scenario: 自定义端口格式
- **WHEN** 用户输入 `1-100,443,8080-8090`
- **THEN** `ParsePortList` 返回 103 个端口(含 443, 100 个范围端口, 2 个范围端口)

### Requirement: 主机存活探测
系统 SHALL 在端口扫描前先做存活探测,使用 ICMP ping;若 ICMP 被防火墙拦截则回退到 TCP connect 80/443 探测。探测失败不阻断扫描,但 `ComprehensiveScanResult.HostAlive=false` 且最终 `ScanSummary` 包含"目标不可达,结果可能不完整"提示。

#### Scenario: 目标存活
- **WHEN** 目标 192.168.1.1 在 3 秒内响应 ICMP
- **THEN** `HostAlive=true`,正常进入端口扫描

#### Scenario: 目标不可达
- **WHEN** 目标 8.8.8.8 防火墙拦截 ICMP 且 80/443 不通
- **THEN** `HostAlive=false`, `Phase["HostDiscovery"].Status=Failed`,但端口扫描仍继续(给用户机会看到端口扫描结果)

### Requirement: 并发 TCP+UDP 端口扫描
系统 SHALL 用 `Task.WhenAll` 同时启动 TCP 和 UDP 扫描器,共享 `CancellationToken`,各自独立的 `IProgress<int>` 合并到 `ScanPhaseProgress`(TCP 占 50%, UDP 占 50%,合并后 0-100%)。任一扫描器抛异常,只标记该 Phase 失败,另一个继续。

#### Scenario: 同时执行
- **WHEN** 用户勾选 TCP+UDP,选择 Standard 预设
- **THEN** 两个扫描器同时启动,进度条从 0 走到 100,期间任何时刻两个扫描器都在工作

#### Scenario: UDP 扫描器超时
- **WHEN** UDP 扫描在 5 分钟后超时
- **THEN** `Phase["UdpPortScan"].Status=Failed`, TCP 扫描结果仍保留,最终 `ComprehensiveScanResult.TcpOpenPorts` 正常,`UdpOpenPorts` 为空

### Requirement: 实时进度窗口
系统 SHALL 在扫描开始时弹出 `ScanProgressLiveWindow`,显示:
- 6 个阶段步骤条(存活探测/TCP/UDP/服务/漏洞/插件),当前阶段高亮,已完成阶段打勾
- 主进度条(0-100%) + 阶段内进度
- 当前已发现开放端口列表(实时追加)
- 已用时间 / 估算剩余时间
- "取消扫描"按钮(调 `CancellationTokenSource.Cancel`)

#### Scenario: 扫描进行中
- **WHEN** 扫描已运行 30 秒,完成了 TCP 扫描(进度 40%),正在进行 UDP 扫描
- **THEN** 窗口显示:阶段 1/2 已完成(打勾),当前阶段 UDP 进度 50%,主进度条 70%,已用时间 0:30,已发现开放端口 12 个

#### Scenario: 用户取消
- **WHEN** 用户点击"取消扫描"
- **THEN** 进度窗口立即关闭,`OperationCanceledException` 被 `ComprehensiveScanService` 捕获,`MainWindow.StartScan_Click` 收到 `Cancelled=true` 后弹"扫描已取消"提示,不弹结果窗口

### Requirement: 富文本结果窗口
系统 SHALL 扫描完成后弹 `ComprehensiveScanResultWindow`,包含 5 个 Tab:
- **概览**:目标/扫描类型/耗时/开放端口数/漏洞数/风险等级/各阶段耗时
- **端口**:DataGrid 显示 `Port / Protocol / Status / Service / Version`
- **漏洞**:DataGrid 显示 `VulnerabilityName / Severity / CVE / Description / Port / Remediation`,带按风险筛选
- **服务**:按服务聚合(`Service / Count / Ports / Versions`)
- **插件**:DataGrid 显示 `PluginName / Port / Severity / Title / Output`(如有)
底部工具栏:"📤 导出 JSON/CSV"、"📊 对比历史"、"📋 复制为 Markdown"、"❌ 关闭"。

#### Scenario: 完整结果展示
- **WHEN** 综合扫描完成且 `Result.OpenPorts.Count > 0`
- **THEN** 概览 Tab 显示完整统计;端口 Tab 列出所有开放端口;漏洞 Tab 按风险排序,严重在前;导出按钮可用

#### Scenario: 无开放端口
- **WHEN** 扫描完成且 `Result.OpenPorts.Count == 0`
- **THEN** 概览显示"无开放端口,跳过漏洞/插件扫描",各 Tab 仍可切换(显示空态文案),风险等级为"无风险"

### Requirement: 导出与对比
系统 SHALL 在结果窗口提供:
- "导出 JSON" 按钮 → `ScanExportService.ExportToJson(Result)` 并 `SaveFileDialog`
- "导出 CSV" 按钮 → `ScanExportService.ExportToCsv(Result)` 并 `SaveFileDialog`
- "对比历史" 按钮 → 查 `JsonDatabaseService.GetScanHistoryAsync` 中同 `TargetIp` 最近一条,调 `ScanComparisonService.CompareScans`,结果弹对比窗口
- "复制为 Markdown" 按钮 → 把"概览 Tab"内容格式化为 Markdown 文本写入剪贴板

#### Scenario: 导出 JSON
- **WHEN** 用户点击"导出 JSON"并选择路径 `D:\scan.json`
- **THEN** 文件写入完成,弹"已导出到 D:\scan.json"提示

#### Scenario: 对比历史无历史
- **WHEN** 同 `TargetIp` 历史为空
- **THEN** 弹提示"暂无历史扫描可对比",不弹对比窗口

### Requirement: MainWindow 瘦身
系统 SHALL 把 `MainWindow.xaml.cs:1299-1548` 的 `StartScan_Click` 重写为:
```csharp
private async void StartScan_Click(object sender, RoutedEventArgs e)
{
    var dlg = new ComprehensiveScanDialog { Owner = this };
    if (dlg.ShowDialog() != true) return;
    var options = dlg.BuildOptions();

    var liveWin = new ScanProgressLiveWindow { Owner = this };
    liveWin.Show();

    try
    {
        var result = await new ComprehensiveScanService().ExecuteAsync(
            options, liveWin.Progress, liveWin.CancellationToken);
        liveWin.Close();
        if (result.Cancelled) return;
        new ComprehensiveScanResultWindow(result) { Owner = this }.ShowDialog();
    }
    catch (Exception ex) { liveWin.Close(); MessageBox.Show(...); }
}
```
原 `ExecuteComprehensiveScanAsync` 整体删除。

#### Scenario: 替代原 230 行实现
- **WHEN** 用户点击"开始综合扫描"
- **THEN** `StartScan_Click` 总行数 ≤ 30,所有业务逻辑在 `ComprehensiveScanService` 内

## MODIFIED Requirements

### Requirement: ComprehensiveScanDialog 增强
原实现:仅 4 个输入框(IP/端口/TCP/UDP/漏洞)+ 2 个复选框。
新实现:
- 左侧:目标 IP、**预设下拉框**(Quick/Standard/Deep/Web/Database/Custom)、端口输入框、并发数(`Concurrency`, 默认 200)、超时秒数(`TimeoutSeconds`, 默认 5)、TCP/UDP/漏洞/插件 4 个开关、是否保存历史
- 右侧:实时预览(端口数估算/扫描时长估算/最近一次同目标扫描摘要)
- 验证规则:IP 不可空 + 端口格式合法 + 至少一个协议 + 选择 Custom 时端口不可空

### Requirement: 端口解析权威化
原 `MainWindow.xaml.cs` 私有 `ParsePortRange` 方法被删除(如有);新代码统一调 `ScanPresetRegistry.ParsePortList(string)`,行为完全兼容(支持 `1-1000`、`22,80,443`、`1-100,443,8080-8090` 三种格式)。

## REMOVED Requirements

### Requirement: 删除 MainWindow.ExecuteComprehensiveScanAsync
**Reason**: 已下沉到 `ComprehensiveScanService`,UI 层不再需要 230 行的编排逻辑。
**Migration**: 替换为 `StartScan_Click` 内 ~30 行的 UI 协调器,业务 100% 由 `ComprehensiveScanService` 承担。
