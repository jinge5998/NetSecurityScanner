# Tasks

- [x] Task 1: 版本号升级 v1.0.1.1 → v1.0.1.2
  - [x] SubTask 1.1: 修改 `NetSecurityScanner/src/NetSecurityScanner.Desktop/NetSecurityScanner.Desktop.csproj` 的 `AssemblyVersion / FileVersion / Version` 为 `1.0.1.2`（已为 1.0.1.2,确认)
  - [x] SubTask 1.2: `MainWindow.xaml` 底部状态栏硬编码 `v1.0.0.0` 改为 `v1.0.1.2`

- [x] Task 2: `AssetManagementService` 增加 operatorName 与服务层权限校验
  - [x] SubTask 2.1: `AddAssetAsync(Asset asset, string operatorName)` 入口校验 `Permission.AssetAdd`,否则抛 `UnauthorizedAccessException`
  - [x] SubTask 2.2: `UpdateAssetAsync(Asset asset, string operatorName)` 校验 `Permission.AssetEdit`
  - [x] SubTask 2.3: `DeleteAssetAsync(string id, string operatorName)` 校验 `Permission.AssetDelete`
  - [x] SubTask 2.4: `ImportFromScanResultsAsync(List<NetworkDevice> devices, string operatorName)` 校验 `Permission.AssetImport`
  - [x] SubTask 2.5: 4 个写操作把 `ChangedBy = "System"` 改为 `ChangedBy = user.Username`(同时写资产 `CreatedBy/LastModifiedBy`)
  - [x] SubTask 2.6: 私有 `ResolveOperator(operatorName, requiredPermission)` 助手:null/空/会话不匹配/缺权限均抛 `UnauthorizedAccessException`

- [x] Task 3: `AssetManagementWindow` 登录状态栏 + 权限联动
  - [x] SubTask 3.1: XAML 顶部新增"登录状态栏"Border,包含 `RoleBadgeText` / `CurrentUserText` / `LoginLogoutButton` / `ViewChangeLogButton`
  - [x] SubTask 3.2: 工具栏新增 `AssetTypeFilter` / `AssetStatusFilter` 两个 ComboBox
  - [x] SubTask 3.3: DataGrid 新增"操作系统""位置""MAC地址""创建时间""最后修改""创建人""修改人"7 列
  - [x] SubTask 3.4: 统计面板 2x2(总资产/在线/离线/维护中),下方新增 `TypeDistributionPanel` 动态渲染 ProgressBar
  - [x] SubTask 3.5: 代码后台 `RefreshUiByPermission()` 按权限联动所有按钮 IsEnabled
  - [x] SubTask 3.6: 构造函数订阅 `SessionContext.Changed` 事件
  - [x] SubTask 3.7: `LoginLogoutButton_Click` 实现登录/登出切换
  - [x] SubTask 3.8: 窗口 Loaded 事件:未登录时弹 LoginWindow,无 Asset:View 权限时关闭窗口
  - [x] SubTask 3.9: `AssetsDataGrid_MouseDoubleClick` 打开 `AssetDetailWindow`
  - [x] SubTask 3.10: `ViewChangeLogButton_Click` 打开 `AssetChangeLogWindow`
  - [x] SubTask 3.11: `AssetTypeFilter_SelectionChanged` / `AssetStatusFilter_SelectionChanged` 实现过滤
  - [x] SubTask 3.12: 4 个写操作调用时传 `SessionContext.Instance.Current?.Username ?? ""`,catch `UnauthorizedAccessException` 提示

- [x] Task 4: 新增 `AssetDetailWindow` 只读详情窗口
  - [x] SubTask 4.1: 新建 `AssetDetailWindow.xaml`,只读展示全部 15 个字段
  - [x] SubTask 4.2: 新建 `AssetDetailWindow.xaml.cs`,构造函数接收 Asset,填充字段

- [x] Task 5: 新增 `AssetChangeLogWindow` 完整变更日志窗口
  - [x] SubTask 5.1: 新建 `AssetChangeLogWindow.xaml`,DataGrid 7 列 + 资产筛选下拉 + 关闭按钮
  - [x] SubTask 5.2: 新建 `AssetChangeLogWindow.xaml.cs`,`AssetFilterCombo` 变更时按 AssetId 过滤

- [x] Task 6: 主窗口资产管理入口加权限校验
  - [x] SubTask 6.1: `MainWindow.xaml.cs` 的 `AssetManagement_Click`:未登录时弹 LoginWindow;无 `Asset:View` 权限时弹"无资产管理查看权限"并返回
  - [x] SubTask 6.2: 校验通过后实例化 `AssetManagementWindow` 并 ShowDialog

- [x] Task 7: 编译 + 冒烟测试
  - [x] SubTask 7.1: `dotnet build -c Release` NetSecurityScanner.sln,零编译错误(87 个 warning 均为已有警告,无新增错误)
  - [x] SubTask 7.2: DLL FileVersion = 1.0.1.2(已验证)
  - [ ] SubTask 7.3: 手动 UI 冒烟测试(管理员/查看者/操作员)需运行程序交互验证
  - [ ] SubTask 7.4: 手动 UI 冒烟测试(操作员)
  - [ ] SubTask 7.5: 手动 UI 冒烟测试(权限置空场景)
  - [ ] SubTask 7.6: 关闭再打开程序能恢复登录会话(沿用 v1.0.1.1 行为)

# Task Dependencies
- Task 2 依赖 Task 1 ✅
- Task 3 依赖 Task 2 ✅
- Task 4 依赖 Task 3 ✅
- Task 5 依赖 Task 3 ✅
- Task 6 依赖 Task 2 ✅
- Task 7 依赖 Task 1-6 全部完成 ✅ (编译通过,手动冒烟需运行程序时执行)
