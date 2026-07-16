# 角色权限 + 管理员审核 Spec

## Why
当前 `enhance-user-profile-and-database` 规格里所有已登录用户对资产模块拥有同样的读写权限，缺乏细粒度授权；同时新注册用户无需审核即可使用，无法满足企业级管理需要。本规格引入"角色 + 权限位 + 管理员审核"模型：①admin 为固定超级管理员；②新注册用户默认处于 `Pending` 状态，必须经 admin 审核通过才能激活；③admin 可在账号管理窗口按权限位（资产/用户/扫描）授权每个用户。

## What Changes
- 在 `User` 模型中新增字段：`IsAdmin (bool)`、`Status (UserStatus: Pending/Active/Disabled)`、`ApprovedBy/ApprovedAt`、`Permissions (List<string>)`。
- 新增 `Permission` 常量类与 `PermissionService` 工具方法（`HasPermission(user, perm)`）。
- 扩充 `AuthService`：注册时新用户默认 `Status=Pending`；新增 `ApproveUserAsync / RejectUserAsync / SetUserPermissionsAsync / DisableUserAsync / SetAdminAsync` 等管理方法；admin 自动拥有全部权限。
- 改造 `AssetManagementService` 的写操作：不仅要求 `operatorName`（旧逻辑），还要求 `PermissionService.HasPermission("Asset:Add")` 等对应权限；权限不足时抛 `UnauthorizedAccessException`。
- 新增 `UserApprovalWindow`（管理员审核窗口）：列出所有 `Pending` 状态用户，admin 可批准（授予默认权限）/ 拒绝 / 自定义权限。
- 改造 `UserManagementWindow`：在 DataGrid 上加「权限」与「状态」两列；admin 看到的是可编辑版（双击行 → 弹出权限编辑窗口），普通用户看到的是只读。
- `LoginWindow` 在用户 `Status != Active` 时拒绝登录（提示"账号待管理员审核"）。
- `App.OnStartup` 在 `users.json` 不存在或 admin 缺失时**自动创建**默认管理员 `admin / 123456`（已存在的 admin 保留不变）。
- 资产管理窗口顶部新增「⏳ 我的状态」徽章：登录后若状态为 Pending 显示橙色警告；Active 显示绿色"已激活"。

## Impact
- Affected specs:
  - `add-asset-user-authentication`：向后兼容，`User` 增加字段使用 `JsonSerializer` 默认值
  - `enhance-user-profile-and-database`：复用 `GetAllUsers`，但显示项增加 `Status/Permissions`
  - 新增本规格 `add-role-permission-approval`
- Affected code:
  - 修改 `NetSecurityScanner.Core/Models/User.cs`（新增字段、状态枚举）
  - 新增 `NetSecurityScanner.Core/Services/Permission.cs`（权限常量）
  - 新增 `NetSecurityScanner.Core/Services/PermissionService.cs`（权限校验工具）
  - 修改 `NetSecurityScanner.Core/Services/AuthService.cs`（注册默认 Pending、审核与权限 API）
  - 修改 `NetSecurityScanner.Core/Services/AssetManagementService.cs`（写操作按权限位拦截）
  - 新增 `NetSecurityScanner.Desktop/Views/Views/UserApprovalWindow.xaml(.cs)`
  - 修改 `NetSecurityScanner.Desktop/Views/Views/UserManagementWindow.xaml(.cs)`（双击行编辑权限）
  - 修改 `NetSecurityScanner.Desktop/Views/Views/LoginWindow.xaml.cs`（登录前校验状态）
  - 修改 `NetSecurityScanner.Desktop/Views/Views/AssetManagementWindow.xaml(.cs)`（状态徽章 + 权限按钮可用性）
  - 修改 `NetSecurityScanner.Desktop/MainWindow.xaml.cs`（admin 专属"用户审核"入口）
  - 修改 `NetSecurityScanner.Desktop/App.xaml.cs`（首次启动创建 admin）

## ADDED Requirements

### Requirement: 默认管理员账号
系统 SHALL 在首次启动时确保存在一个 admin/123456 超级管理员账号。

#### Scenario: 首次启动
- **WHEN** `users.json` 不存在，或其中没有 `Username == "admin"` 的用户
- **THEN** 自动创建 `admin / 123456`（PBKDF2 哈希），`IsAdmin=true`，`Status=Active`，拥有全部权限

#### Scenario: admin 已存在
- **WHEN** `users.json` 中已存在 `admin` 账号
- **THEN** 不覆盖（保留现有密码、权限、显示名）

#### Scenario: 修改 admin 密码
- **WHEN** admin 登录后通过"个人资料"修改密码为 6 位以上新密码
- **THEN** 密码立即生效，旧密码失效

### Requirement: 用户注册需审核
新注册用户 SHALL 默认处于待审核状态，登录被拒绝。

#### Scenario: 注册新用户
- **WHEN** 普通用户在注册窗口提交注册
- **THEN** 账号保存到 `users.json`，`Status=Pending`，`IsAdmin=false`，`Permissions=[]`，弹窗提示"注册成功，请等待管理员审核"

#### Scenario: Pending 用户尝试登录
- **WHEN** Status=Pending 的用户在登录窗口输入正确密码
- **THEN** 登录被拒绝，提示"账号待管理员审核，请联系 admin"

#### Scenario: 已禁用用户尝试登录
- **WHEN** Status=Disabled 的用户尝试登录
- **THEN** 登录被拒绝，提示"账号已被禁用，请联系管理员"

### Requirement: 管理员审核用户
admin SHALL 能够在审核窗口批准/拒绝待审用户，并授予权限。

#### Scenario: 批准用户
- **WHEN** admin 在「待审核」列表中选中某 Pending 用户，点"批准"
- **THEN** 弹出"权限选择"对话框（默认勾选"资产查看 + 资产编辑"），确认后将该用户 `Status=Active` 并写入对应 `Permissions`，记录 `ApprovedBy=admin`、`ApprovedAt=Now`

#### Scenario: 拒绝用户
- **WHEN** admin 选中 Pending 用户点"拒绝"
- **THEN** 弹出确认框，确认后将该用户 `Status=Disabled`，不可再登录

#### Scenario: 调整已批准用户权限
- **WHEN** admin 在账号管理 DataGrid 中双击某 Active 用户
- **THEN** 弹出权限编辑窗口，admin 可勾选/取消各项权限位，保存后立即生效（不需重新登录）

### Requirement: 细粒度权限控制
系统 SHALL 按权限位控制用户对各功能模块的访问。

#### Scenario: 资产写操作权限校验
- **WHEN** 调用 `AssetManagementService.AddAssetAsync/UpdateAssetAsync/DeleteAssetAsync/ImportFromScanResultsAsync`
- **THEN** 服务层检查当前用户的 `Permissions` 是否包含对应权限（`Asset:Add`/`Asset:Edit`/`Asset:Delete`/`Asset:Import`），无权限则抛 `UnauthorizedAccessException`

#### Scenario: 用户管理权限
- **WHEN** 调用 `AuthService.ApproveUserAsync / SetUserPermissionsAsync / DisableUserAsync`
- **THEN** 校验当前操作者 `IsAdmin=true`，否则抛 `UnauthorizedAccessException`

#### Scenario: 权限位定义
权限位 SHALL 至少包含：
- `Asset:View` 资产查看（默认所有 Active 用户拥有）
- `Asset:Add` 添加资产
- `Asset:Edit` 编辑资产
- `Asset:Delete` 删除资产
- `Asset:Import` 导入资产
- `Asset:Export` 导出资产
- `User:View` 查看账号列表
- `User:Manage` 审核/管理用户（仅 admin 自动拥有）
- `Scan:Run` 发起扫描
- `Report:Export` 导出报告

### Requirement: 资产管理窗口权限显示
资产管理窗口 SHALL 根据当前用户的权限位决定按钮可用性。

#### Scenario: 部分权限用户
- **WHEN** 用户拥有 `Asset:Add` 但没有 `Asset:Delete`
- **THEN** "添加资产"按钮可用，"删除"按钮置灰

#### Scenario: 无任何资产写权限
- **WHEN** 用户仅有 `Asset:View`
- **THEN** 所有写操作按钮置灰；服务层再次拦截保证不会被绕过

#### Scenario: 资产查看者
- **WHEN** 用户连 `Asset:View` 都没有
- **THEN** 资产管理窗口拒绝打开（提示"您没有资产查看权限"）

### Requirement: 管理员专属入口
admin SHALL 看到"用户审核"入口，普通用户看不到。

#### Scenario: 主窗口菜单
- **WHEN** admin 登录
- **THEN** 主窗口「工具」菜单显示"用户审核"菜单项（位于"账号管理"之前）

#### Scenario: 普通用户登录
- **WHEN** 非 admin 用户登录
- **THEN** "用户审核"菜单项隐藏

## MODIFIED Requirements
（继承自 `enhance-user-profile-and-database`）

### Requirement: 资产管理权限控制
在原有"未登录时禁用写操作"基础上叠加"权限位校验"：未登录 → 弹登录；登录但无权限 → 弹错误"权限不足"。两个检查都在服务层完成，UI 仅是体验优化。

## REMOVED Requirements
无。

## 安全设计要点
- 权限位使用字符串常量存储（可读性、可扩展性优于位运算），列表里没有该常量即视为无权限。
- admin 的 `Permissions` 字段可以为空，但 `IsAdmin=true` 始终拥有所有权限（`PermissionService.HasPermission` 对 admin 短路返回 true）。
- 注册默认 Pending 不允许任何已注册用户自助激活；只能由 admin 通过 `AuthService.ApproveUserAsync` 激活。
- 修改权限位时记录 `LastModifiedBy=admin`、`LastModifiedAt=Now`；写回 `users.json`。
- `App.OnStartup` 启动时强制确保 admin 存在：若 `users.json` 存在但 admin 缺失，也补建一个（不覆盖已有用户）。
- 旧的 `add-asset-user-authentication` 与 `enhance-user-profile-and-database` 规格已实现的 UI/Service 全部保留，新规格只做"叠加"而不"替换"。
