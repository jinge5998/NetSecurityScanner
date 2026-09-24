# Tasks

- [ ] Task 1: 数据模型与权限常量
  - [ ] SubTask 1.1: 修改 `Models/User.cs`，新增 `IsAdmin (bool)`、`Status (UserStatus: Pending/Active/Disabled)`、`ApprovedBy/ApprovedAt/ApprovedPermissions`、`Permissions (List<string>)` 字段；新增 `UserStatus` 枚举
  - [ ] SubTask 1.2: 新建 `Services/Permission.cs`，定义权限位字符串常量（`Asset:View/Add/Edit/Delete/Import/Export`、`User:View/Manage`、`Scan:Run`、`Report:Export`）与 `AllPermissions` 列表

- [ ] Task 2: 权限服务
  - [ ] SubTask 2.1: 新建 `Services/PermissionService.cs`，实现 `HasPermission(User? user, string permission)` 静态方法：admin 短路返回 true；普通用户检查 `Permissions` 列表
  - [ ] SubTask 2.2: 实现 `EnsurePermission(user, perm)` 抛出 `UnauthorizedAccessException`

- [ ] Task 3: `AuthService` 扩展
  - [ ] SubTask 3.1: 修改 `RegisterAsync`：新用户默认 `Status=Pending`、`Permissions=[]`、`IsAdmin=false`
  - [ ] SubTask 3.2: 修改 `LoginAsync`：登录前检查 `Status != Active` 直接返回失败
  - [ ] SubTask 3.3: 新增管理员方法：`ApproveUserAsync(adminName, targetUsername, permissions)`、`RejectUserAsync(adminName, targetUsername)`、`SetUserPermissionsAsync(adminName, targetUsername, permissions)`、`DisableUserAsync(adminName, targetUsername)`、`GetPendingUsers()`
  - [ ] SubTask 3.4: 所有管理员方法入口校验当前操作者 `IsAdmin=true`

- [ ] Task 4: `AssetManagementService` 叠加权限校验
  - [ ] SubTask 4.1: `AddAssetAsync` 增加 `Asset:Add` 权限校验
  - [ ] SubTask 4.2: `UpdateAssetAsync` 增加 `Asset:Edit` 权限校验
  - [ ] SubTask 4.3: `DeleteAssetAsync` 增加 `Asset:Delete` 权限校验
  - [ ] SubTask 4.4: `ImportFromScanResultsAsync` 增加 `Asset:Import` 权限校验
  - [ ] SubTask 4.5: `ExportAsync`（若存在）增加 `Asset:Export` 权限校验

- [ ] Task 5: admin 自动初始化
  - [ ] SubTask 5.1: `App.OnStartup` 在已有 `MigrateLegacyAssets` 之前调用 `EnsureDefaultAdmin()`：检测 `users.json` 与 admin 账号，缺失则创建 `admin/123456`
  - [ ] SubTask 5.2: 创建后立即 `TryRestoreSession`（让 admin 免登录即可用）

- [ ] Task 6: 用户审核窗口
  - [ ] SubTask 6.1: 新建 `Views/Views/UserApprovalWindow.xaml(.cs)`：上半部分列出 `Pending` 用户（用户名、注册时间、显示名），下半部分是权限复选框列表
  - [ ] SubTask 6.2: "批准"按钮调用 `AuthService.ApproveUserAsync`，权限默认为 `Asset:View + Asset:Edit`
  - [ ] SubTask 6.3: "拒绝"按钮调用 `AuthService.RejectUserAsync`

- [ ] Task 7: 改造账号管理窗口
  - [ ] SubTask 7.1: DataGrid 新增"状态"、"权限"两列；"状态"用颜色徽章（Pending 橙色、Active 绿色、Disabled 灰色）
  - [ ] SubTask 7.2: 双击行事件：admin 用户双击 Active 行 → 弹出 `UserPermissionEditWindow`（仅 admin 可打开）；非 admin 或双击 admin 行 → 不响应
  - [ ] SubTask 7.3: 新建 `UserPermissionEditWindow.xaml(.cs)`：按权限位显示复选框，保存调用 `AuthService.SetUserPermissionsAsync`

- [ ] Task 8: 主窗口菜单
  - [ ] SubTask 8.1: 「工具」菜单新增"用户审核"菜单项，仅 admin 可见（`Visibility` 绑定 `SessionContext.Current.IsAdmin`）
  - [ ] SubTask 8.2: 点击事件直接打开 `UserApprovalWindow`

- [ ] Task 9: 资产管理窗口
  - [ ] SubTask 9.1: 顶部新增"⏳ 我的状态"徽章（仅登录后可见，Pending 显示橙色警告）
  - [ ] SubTask 9.2: 改造 `UpdatePermissionControls`：按钮可用性按权限位判断（`Asset:Add/Edit/Delete/Import/Export`），未登录时全部禁用
  - [ ] SubTask 9.3: Pending 用户打开资产管理窗口时弹出"账号待审核"提示并关闭窗口

- [ ] Task 10: 编译与冒烟测试
  - [ ] SubTask 10.1: 编译 Core + Desktop，0 错误
  - [ ] SubTask 10.2: 端到端测试：首次启动自动创建 admin → admin 登录 → 注册普通用户 → 普通用户登录被拒 → admin 审核通过 → 普通用户按权限操作资产 → admin 调整权限立即生效 → 普通用户被禁用后无法登录

# Task Dependencies
- Task 2 依赖 Task 1
- Task 3 依赖 Task 1、Task 2
- Task 4 依赖 Task 2
- Task 5 依赖 Task 3
- Task 6 依赖 Task 3
- Task 7 依赖 Task 3
- Task 8 依赖 Task 6
- Task 9 依赖 Task 3、Task 4
- Task 10 依赖所有上述 Task
