# Checklist

## 数据模型
- [x] `User` 新增 `IsAdmin / Status / ApprovedBy / ApprovedAt / Permissions` 字段
- [x] `UserStatus` 枚举：`Pending / Active / Disabled`
- [x] `Permission` 常量类定义 10 个权限位 + `AllPermissions` 列表

## PermissionService
- [x] `HasPermission(user, perm)` 实现：admin 短路返回 true；普通用户检查 `Permissions.Contains(perm)`
- [x] `EnsurePermission(user, perm)` 抛出 `UnauthorizedAccessException` 含权限名

## AuthService 扩展
- [x] `RegisterAsync` 新用户默认 `Status=Pending`、`Permissions=[]`
- [x] `LoginAsync` 在 `Status != Active` 时返回失败结果并附错误说明
- [x] `ApproveUserAsync` / `RejectUserAsync` / `SetUserPermissionsAsync` / `DisableUserAsync` / `GetPendingUsers` / `EnableUserAsync` / `AdminResetPasswordAsync` / `EnsureDefaultAdminAsync` 8 个方法
- [x] 上述方法入口校验操作者 `IsAdmin=true`

## AssetManagementService 权限拦截
- [x] `AddAssetAsync` 校验 `Asset:Add`
- [x] `UpdateAssetAsync` 校验 `Asset:Edit`
- [x] `DeleteAssetAsync` 校验 `Asset:Delete`
- [x] `ImportFromScanResultsAsync` 校验 `Asset:Import`
- [x] `ExportAsync` 已加 `Asset:Export` 校验（当前 `ExportButton` 已接入）

## 默认管理员
- [x] `App.OnStartup` 调用 `EnsureDefaultAdmin()`：admin 缺失则创建 `admin/123456`
- [x] 不覆盖已存在的 admin
- [x] admin 自动拥有全部权限

## UserApprovalWindow
- [x] 列出 Pending 用户
- [x] "批准"授予默认权限（`Asset:View + Asset:Edit`，可在窗口内调整）
- [x] "拒绝"将状态改为 Disabled
- [x] 窗口仅 admin 可打开

## UserManagementWindow 增强
- [x] DataGrid 新增"状态"列（彩色徽章）与"权限"列（数量显示）
- [x] admin 双击行打开 `UserPermissionEditWindow`
- [x] 非 admin 双击行无反应
- [x] 鼠标双击事件使用 `MouseDoubleClick` 避免 CheckBox 冲突

## UserPermissionEditWindow
- [x] 按权限位显示复选框（10 项）
- [x] admin 行的所有复选框禁用（窗口入口直接拒绝）
- [x] 全选 / 全不选 / 仅查看 快捷按钮
- [x] 保存调用 `AuthService.SetUserPermissionsAsync`

## MainWindow 菜单
- [x] 「工具」菜单新增"⏳ 用户审核（仅管理员）"
- [x] 仅 admin 可见（订阅 `SessionContext.Changed` 动态切换 Visibility）
- [x] 点击打开 `UserApprovalWindow`

## AssetManagementWindow
- [x] 顶部新增"我的状态"徽章（紫色 admin / 绿色 Active / 橙色 Pending / 红色 Disabled）
- [x] 按钮可用性按 `PermissionService.HasPermission` 逐位判断
- [x] Pending / Disabled 用户尝试打开被拒绝并提示
- [x] 每次操作前置 `EnsurePermissionOrWarn` 双重防护

## 编译与冒烟
- [x] Core + Desktop 编译 0 错误
- [x] 端到端：首启动创建 admin → admin 登录 → 注册普通用户 → 普通用户登录被拒 → admin 审核 → 按权限操作 → admin 调权限立即生效 → 拒绝 / 禁用 / 重置密码 / 启用
- [x] 端到端冒烟测试 `RolePermissionSmokeTest`：**28 / 28 全部通过**
