# Checklist

## 版本
- [x] `NetSecurityScanner.Desktop.csproj` 的 `AssemblyVersion / FileVersion / Version` 均为 `1.0.1.2`
- [x] 主窗口底部状态栏显示 "v1.0.1.2"
- [x] `dotnet build -c Release` 成功,dll 元数据 FileVersion=1.0.1.2

## 服务层权限校验
- [x] `AssetManagementService.AddAssetAsync` 接受 `operatorName` 参数,无权限时抛 `UnauthorizedAccessException`
- [x] `AssetManagementService.UpdateAssetAsync` 接受 `operatorName` 参数,无权限时抛 `UnauthorizedAccessException`
- [x] `AssetManagementService.DeleteAssetAsync` 接受 `operatorName` 参数,无权限时抛 `UnauthorizedAccessException`
- [x] `AssetManagementService.ImportFromScanResultsAsync` 接受 `operatorName` 参数,无权限时抛 `UnauthorizedAccessException`
- [x] 所有写操作的 `AssetChangeLog.ChangedBy` 记录为实际登录用户名(不再是硬编码 "System")
- [x] `ResolveOperator(operatorName)` 私有助手对 null/空/会话不匹配情况都抛 `UnauthorizedAccessException`
- [x] 资产对象同时记录 `CreatedBy` / `LastModifiedBy` 字段

## 资产管理窗口 UI
- [x] 顶部显示角色徽章(管理员/操作员/查看者/未登录)和当前用户名
- [x] 顶部"登录/登出"按钮按登录态切换文本(🔑 登录 / 🚪 登出)
- [x] 顶部"查看完整变更日志"按钮可点击
- [x] 工具栏新增"按类型筛选""按状态筛选"两个下拉框
- [x] DataGrid 新增"操作系统/位置/MAC地址/创建时间/最后修改/创建人/修改人"7 列
- [x] 统计面板 2x2 显示"总资产/在线/离线/维护中"4 个数字
- [x] 统计面板下方显示按类型分布的 `ProgressBar` 柱状图
- [x] 双击资产行打开 `AssetDetailWindow` 详情窗口
- [x] "查看完整变更日志"按钮打开 `AssetChangeLogWindow`

## 权限联动
- [x] 未登录:添加/编辑/删除/导入/导出 全部置灰(工具栏 ToolTip 提示"权限不足/请先登录")
- [x] 管理员:全部按钮可用
- [x] 仅 Asset:View 权限:仅搜索/刷新/导出可用
- [x] Asset:View+Add+Edit 权限:添加/编辑可用,删除/导入置灰
- [x] 登出/登录切换后按钮可用性立即刷新(`SessionContext.Changed` 事件)

## 主窗口入口
- [x] 未登录时点击"资产管理"弹出 `LoginWindow`,登录成功才进入
- [x] 登录后无 `Asset:View` 权限时显示"无资产管理查看权限"并阻止进入
- [x] 通过权限校验后正常显示资产管理窗口

## 资产详情窗口
- [x] 标题"资产详情 - {Name}"
- [x] 完整字段只读展示:Name/IP/MAC/AssetType/OperatingSystem/Owner/Department/Location/Status/Description/Tags/CreatedAt/LastModified/CreatedBy/LastModifiedBy
- [x] 关闭按钮可用

## 变更日志窗口
- [x] DataGrid 显示 ChangedAt/ChangeType/AssetId/FieldName/OldValue/NewValue/ChangedBy
- [x] 顶部"按资产筛选"下拉框可过滤
- [x] 关闭按钮可用

## 编译与运行
- [x] `dotnet build -c Release` NetSecurityScanner.sln 零错误
- [ ] 管理员登录后可完成增/改/删/导入/导出全流程(需运行程序交互验证)
- [ ] 仅查看用户登录后无写操作权限(需运行程序交互验证)
- [ ] 操作员登录后可增/改但不可删/导入(需运行程序交互验证)
- [x] 关闭再打开程序能恢复登录会话(沿用 v1.0.1.1 行为,AuthService.TryRestoreSession 逻辑未变)
- [x] 主窗口显示版本号 v1.0.1.2(XAML 静态字符串已更新;同时 `MainWindow.xaml.cs` 第 144 行通过 `VersionHelper.GetVersion()` 动态读取程序集版本,值也为 1.0.1.2)
