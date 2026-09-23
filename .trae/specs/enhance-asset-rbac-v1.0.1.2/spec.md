# 资产模块细粒度权限控制 & v1.0.1.2 升级 Spec

## Why
现有 `add-asset-user-authentication` spec 实现了注册/登录/会话/管理员审批,但 `AssetManagementWindow` 完全没有集成 `SessionContext` 和 `User.Permissions` —— 所有按钮始终启用,任何登录用户都能增删改资产,服务层也未拦截 `UnauthorizedAccessException`。同时需要把程序版本从 v1.0.1.1 升到 v1.0.1.2,并完善资产管理(统计、过滤、详情等)。

## What Changes
- 版本号从 v1.0.1.1 升到 v1.0.1.2(`NetSecurityScanner.Desktop.csproj` 的 `AssemblyVersion/FileVersion/Version`、底部状态栏)。
- `AssetManagementService` 的 `AddAssetAsync / UpdateAssetAsync / DeleteAssetAsync / ImportFromScanResultsAsync` 增加 `operatorName` 参数,服务层按 `User.Permissions` + `IsAdmin` 校验:缺失权限时抛 `UnauthorizedAccessException`;`AssetChangeLog.ChangedBy` 改为实际用户名。
- 新增 `AssetManagementService` 的 `GetAssets / GetAsset / Search` 等只读方法不要求权限,任何登录用户(或匿名但能看到本地数据)可调用。
- `AssetManagementWindow` 顶部增加"登录状态栏"区域:显示当前用户/角色徽章(管理员/操作员/查看者)、登录/登出按钮。
- `AssetManagementWindow` 工具栏按钮的 `IsEnabled` 与 `SessionContext.Current.Permissions` 实时联动,遵循以下矩阵:
  - **添加**:有 `Asset:Add` 或 `IsAdmin` 即可
  - **编辑**:有 `Asset:Edit` 或 `IsAdmin`
  - **删除**:有 `Asset:Delete` 或 `IsAdmin`(普通用户永远禁用)
  - **导入**:有 `Asset:Import` 或 `IsAdmin`
  - **导出**:有 `Asset:View`(查看即可导出)
  - **搜索/刷新/查看列表**:有 `Asset:View`
- `AssetManagementWindow` 打开时若 `SessionContext.Current == null`,弹出 `LoginWindow`,登录成功后再渲染数据;若 `SessionContext.Current.IsAdmin || Permissions contains Asset:View == false` 则直接关闭并提示"无权限"。
- 主窗口 `MainWindow` 顶部菜单的"资产管理"入口在 v1.0.1.2 之前已要求登录;v1.0.1.2 进一步要求"必须至少有 `Asset:View` 权限才能进入资产管理窗口"。
- **完善资产管理**:
  - 资产列表 DataGrid 增加"操作系统/位置/MAC地址/创建时间/最后修改/创建人/修改人"列(超出宽度时支持横向滚动)。
  - 统计面板增加"离线/维护中"两个数字 + 类型分布柱状图(用 `ProgressBar` 简易实现)。
  - 工具栏新增"按类型筛选"下拉框(全部/Server/Workstation/NetworkDevice/SecurityDevice/Database/Application/Other)+"按状态筛选"(全部/在线/离线/维护中/已退役)。
  - 双击资产行打开详情窗口 `AssetDetailWindow`(只读视图 + 完整字段)。
  - "最近变更"列表改为"查看完整变更日志"按钮,打开 `AssetChangeLogWindow` 显示所有 `AssetChangeLog` 记录(含 ChangedBy / OldValue / NewValue)。
- 资产详情窗口和资产变更日志窗口作为本次新增。

## Impact
- Affected specs:
  - 关联 `add-asset-user-authentication`(已完成的登录/会话基建被复用)
  - 关联 `add-role-permission-approval`(复用 `User.Permissions` + `Permission.Asset*` 权限位)
- Affected code:
  - 修改 `NetSecurityScanner/src/NetSecurityScanner.Desktop/NetSecurityScanner.Desktop.csproj`(版本号)
  - 修改 `NetSecurityScanner/src/NetSecurityScanner.Core/Services/AssetManagementService.cs`(operatorName 参数 + 权限校验 + ChangedBy 真实用户)
  - 修改 `NetSecurityScanner/src/NetSecurityScanner.Desktop/Views/Views/AssetManagementWindow.xaml`(登录状态栏、筛选、列扩展)
  - 修改 `NetSecurityScanner/src/NetSecurityScanner.Desktop/Views/Views/AssetManagementWindow.xaml.cs`(权限联动、登录拦截、双击详情)
  - 修改 `NetSecurityScanner/src/NetSecurityScanner.Desktop/Views/Views/MainWindow.xaml.cs`(资产管理入口的权限校验)
  - 新增 `NetSecurityScanner/src/NetSecurityScanner.Desktop/Views/Views/AssetDetailWindow.xaml(.cs)`
  - 新增 `NetSecurityScanner/src/NetSecurityScanner.Desktop/Views/Views/AssetChangeLogWindow.xaml(.cs)`

## ADDED Requirements

### Requirement: 版本号升级到 v1.0.1.2
系统 SHALL 在 v1.0.1.2 发布时将 `NetSecurityScanner.Desktop.csproj` 的 `AssemblyVersion / FileVersion / Version` 统一更新为 `1.0.1.2`,主窗口底部状态栏显示"v1.0.1.2"。

#### Scenario: 编译后版本号正确
- **WHEN** 开发者执行 `dotnet build -c Release` 构建项目
- **THEN** 生成的 `NetSecurityScanner.Desktop.dll` 的 FileVersion 为 1.0.1.2,主窗口右下角显示"v1.0.1.2"

### Requirement: 资产服务层权限校验
系统 SHALL 在 `AssetManagementService` 的写操作方法入口校验 `operatorName` 的有效性,并在 `SessionContext` 中查找该用户的 `Permissions`,缺失 `Asset:Add / Edit / Delete / Import` 对应权限时拒绝调用并抛 `UnauthorizedAccessException`。

#### Scenario: 无权限用户调用 AddAssetAsync
- **WHEN** 调用者 `SessionContext.Current` 为 null,或用户 `IsAdmin == false` 且 `Permissions` 不含 `Asset:Add`
- **THEN** `AddAssetAsync` 抛 `UnauthorizedAccessException("需要 Asset:Add 权限")`,不写 `assets.json`,不写变更日志

#### Scenario: 管理员调用 AddAssetAsync
- **WHEN** `SessionContext.Current.IsAdmin == true`
- **THEN** 资产成功添加,`AssetChangeLog.ChangedBy` 记录为管理员用户名

#### Scenario: 写操作记录真实操作人
- **WHEN** 任意有权限用户成功 `Add/Update/Delete/Import`
- **THEN** `AssetChangeLog.ChangedBy` 等于 `SessionContext.Current.Username`,不再是硬编码 "System"

### Requirement: 资产管理窗口登录态 UI
系统 SHALL 在 `AssetManagementWindow` 顶部显示当前登录用户的角色徽章和登录/登出按钮,并依据权限联动工具栏按钮可用性。

#### Scenario: 未登录用户打开资产管理
- **WHEN** 用户点击主窗口"工具 → 资产管理",但 `SessionContext.Current == null`
- **THEN** 弹出 `LoginWindow`,登录成功后回到资产管理窗口,继续按权限渲染按钮;若取消登录则不进入资产管理窗口

#### Scenario: 管理员登录后
- **WHEN** 管理员(任一 `IsAdmin == true` 用户)进入资产管理窗口
- **THEN** 顶部显示"👑 管理员:admin",所有按钮(添加/编辑/删除/导入/导出/搜索/刷新)均可用

#### Scenario: 仅查看权限用户
- **WHEN** 普通用户 `Permissions == [Asset:View]` 进入资产管理
- **THEN** 顶部显示"👁 查看者:alice",工具栏只显示"搜索/刷新/导出/关闭",添加/编辑/删除/导入按钮置灰且 ToolTip 提示"权限不足"

#### Scenario: 操作员(可增改不可删)
- **WHEN** 普通用户 `Permissions == [Asset:View, Asset:Add, Asset:Edit]` 进入资产管理
- **THEN** 顶部显示"🛠 操作员:bob",添加/编辑按钮可用,删除/导入按钮置灰

#### Scenario: 切换登录态后按钮实时刷新
- **WHEN** 用户在资产管理窗口内点击"登出"再"登录"为另一个账号
- **THEN** 按钮可用性按新用户的权限立即刷新(通过订阅 `SessionContext.Changed` 事件)

### Requirement: 资产管理筛选与详情
系统 SHALL 提供按类型/状态筛选资产、双击查看详情、查看完整变更日志的能力。

#### Scenario: 按类型筛选
- **WHEN** 用户在工具栏"类型"下拉选择"Server"
- **THEN** DataGrid 仅显示 `AssetType == "Server"` 的资产,统计面板的"总资产"数同步更新为筛选后数量

#### Scenario: 按状态筛选
- **WHEN** 用户在工具栏"状态"下拉选择"离线"
- **THEN** DataGrid 仅显示 `Status == Offline` 的资产

#### Scenario: 双击打开资产详情
- **WHEN** 用户在 DataGrid 中双击某行
- **THEN** 弹出 `AssetDetailWindow`,只读展示该资产的全部字段(名称/IP/MAC/类型/OS/部门/负责人/位置/状态/描述/Tags/创建时间/最后修改/创建人/修改人),窗口标题"资产详情 - {Name}"

#### Scenario: 查看完整变更日志
- **WHEN** 用户点击"查看完整变更日志"按钮
- **THEN** 弹出 `AssetChangeLogWindow`,按 `ChangedAt` 倒序列出所有 `AssetChangeLog`,列:时间 / 操作类型 / 资产 / 字段 / 旧值 / 新值 / 操作人;窗口提供"按资产筛选"下拉框

### Requirement: 统计面板扩展
系统 SHALL 在统计面板除"总资产/在线"外增加"离线/维护中"计数,并展示按类型分布的简易柱状图。

#### Scenario: 离线/维护中计数显示
- **WHEN** 资产数据加载完成
- **THEN** 统计面板的 2x2 网格分别显示"总资产/在线/离线/维护中"四个数字,数字取自 `AssetStatistics.OfflineAssets / MaintenanceAssets`

#### Scenario: 类型分布柱状图
- **WHEN** 资产数据加载完成
- **THEN** 统计面板下方按 `AssetTypeDistribution` 字典渲染水平 `ProgressBar` 列表,每条进度条按最大类型的占比填充,标签显示"类型: 数量 (百分比%)"

## MODIFIED Requirements
无(本规格为新增功能,不动其他 spec 的需求)。

## REMOVED Requirements
无。

## 安全设计要点
- 双重防护:`AssetManagementWindow` UI 禁用 + `AssetManagementService` 服务层 `UnauthorizedAccessException`。
- 权限位统一在 `Permission.Asset*` 常量中,UI 与服务层共用同一字符串,避免硬编码不一致。
- 资产详情/变更日志窗口为只读,无任何写操作入口。
- 操作日志 `ChangedBy` 取自 `SessionContext.Current.Username`,匿名调用方(无会话)的服务层调用会先被拦截。
