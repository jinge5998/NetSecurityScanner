# 任务清单：专家模式实时结果表为空修复

对应规格：[spec.md](./spec.md)

- [x] **T1 视图字段与首次绑定**
  - 文件：[ExpertModeWindow.xaml.cs](file:///d:/360安全浏览器下载/软件开发备份/网络安全漏洞扫描/NetSecurityScanner/src/NetSecurityScanner.Desktop/Views/Views/ExpertModeWindow.xaml.cs)
  - 改动：字段区新增 `_portResultsView` / `_vulnResultsView`（`ListCollectionView?`）；构造函数中创建两个视图并首次绑定 `ItemsSource`。
  - 验证：编译通过；窗口打开时表头正常。
  - 状态：completed

- [x] **T2 扫描开始自动清除筛选**
  - 改动：`ExecuteExpertScanAsync` 初始化块改为绑定视图，并清除两个视图的 `Filter`，日志「新扫描开始：已自动清除上次的端口结果筛选」。
  - 验证：AC2。
  - 状态：completed

- [x] **T3 端口筛选改为视图 Filter**
  - 改动：`FilterOpenPorts_Click` / `FilterHighRiskPorts_Click` 改为设置 `_portResultsView.Filter` + `Refresh()`，日志带当前条数；已删除 `ItemsSource = null; ItemsSource = filtered;`。
  - 验证：AC1、AC3。
  - 状态：completed

- [x] **T4 端口重置改为清空 Filter**
  - 改动：`ResetPortFilterButton_Click` 改为 `Filter = null` + `Refresh()`。
  - 验证：AC4。
  - 状态：completed

- [x] **T5 漏洞筛选/重置改为视图 Filter**
  - 改动：`FilterHighRisk_Click`、`FilterMediumRisk_Click`、`ResetVulnFilterButton_Click` 改为视图 Filter。
  - 验证：AC1、AC3、AC4。
  - 状态：completed

- [x] **T6 深度扫描不再替换 ItemsSource**
  - 改动：`DeepScanPort_Click` 删除快照赋值，改为写入集合 + `_vulnResultsView.Refresh()` + 更新统计。
  - 验证：AC1。
  - 状态：completed

- [ ] **T7 构建、回归与手动验证**
  - [x] `dotnet build src\NetSecurityScanner.Desktop\NetSecurityScanner.Desktop.csproj -c Debug --nologo -v q` → **已成功生成，0 错误**
  - [x] `dotnet test src\NetSecurityScanner.Core.Tests\NetSecurityScanner.Core.Tests.csproj --nologo -v q` → **279 通过 / 0 失败 / 0 跳过**
  - [ ] 手动 UI 验证（需用户操作，步骤见 spec.md 第 5 节 a/b/c/d）
  - [x] 原子提交 `fix: 专家模式实时结果表改用单一集合视图，修复筛选后表格恒为空`
  - 状态：in_progress（仅剩手动 UI 验证）

## 完成标准

T1-T7 全部完成，且 spec.md 第 5 节手动验证 4 项通过后，按《Trae 双模式规范》进入 Work 模式代码审查。
