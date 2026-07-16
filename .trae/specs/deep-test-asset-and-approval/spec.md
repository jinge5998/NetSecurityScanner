# 资产登记 + 账号注册审批 深度测试 Spec

## Why
资产登记（[AssetManagementWindow](file:///d:/360安全浏览器下载/软件开发备份/网络安全漏洞扫描/NetSecurityScanner/src/NetSecurityScanner.Desktop/Views/Views/AssetManagementWindow.xaml)）和账号注册审批（[UserApprovalWindow](file:///d:/360安全浏览器下载/软件开发备份/网络安全漏洞扫描/NetSecurityScanner/src/NetSecurityScanner.Desktop/Views/Views/UserApprovalWindow.xaml)）是用户日常使用的核心流程，需要一个独立、深入的测试规范来覆盖：
- 端到端流程（注册 → 审批 → 登录 → 资产操作 → 权限回收）
- 边界与异常（重复注册、密码不匹配、并发、空数据、Pending/Disabled 用户越权）
- 审计追踪（每一步操作是否可被追溯）
- WPF 实际可交互性（按钮、复选框、菜单是否真的可点）

## What Changes
- **新增** 自动化深度测试控制台 `DeepAssetApprovalTest`，覆盖 5 大场景、共 50+ 用例
- **新增** 测试 fixture：可重置 `users.json` / `audit_log.json` / `assets.json` 的临时目录辅助
- **新增** WPF 行为校验脚本 `WpfInteractionProbe.ps1`，检查窗口/按钮可见性
- **修改** 现有 `RolePermissionSmokeTest` 不影响；新测试独立运行

## Impact
- Affected specs: [add-asset-user-authentication](../add-asset-user-authentication/spec.md)、[add-role-permission-approval](../add-role-permission-approval/spec.md)
- Affected code:
  - `NetSecurityScanner/src/NetSecurityScanner.Core/Services/AuthService.cs`（注册/登录/审批/审计）
  - `NetSecurityScanner/src/NetSecurityScanner.Core/Services/AssetManagementService.cs`（增/改/删/导入/导出）
  - `NetSecurityScanner/src/NetSecurityScanner.Core/Services/PermissionService.cs`（权限位）
  - `NetSecurityScanner/src/NetSecurityScanner.Desktop/Views/Views/RegisterWindow.xaml(.cs)`（注册 UI）
  - `NetSecurityScanner/src/NetSecurityScanner.Desktop/Views/Views/UserApprovalWindow.xaml(.cs)`（审核 UI）
  - `NetSecurityScanner/src/NetSecurityScanner.Desktop/Views/Views/UserManagementWindow.xaml(.cs)`（用户管理）
  - `NetSecurityScanner/src/NetSecurityScanner.Desktop/Views/Views/AssetManagementWindow.xaml(.cs)`（资产管理）
  - `NetSecurityScanner/src/NetSecurityScanner.Desktop/Views/Views/AuditLogWindow.xaml(.cs)`（审计查看）
  - `NetSecurityScanner/src/NetSecurityScanner.Desktop/MainWindow.xaml(.cs)`（主窗口菜单 + 状态栏）

## ADDED Requirements

### Requirement: 端到端资产登记流程深度测试
The system SHALL permit a user with appropriate permissions to add, edit, delete, import, and export assets; operations SHALL be rejected with a clear message for users lacking the permission bit.

#### Scenario: 全权限用户可执行所有资产操作
- **WHEN** an Active user holding all 10 permission bits calls `AddAssetAsync` / `UpdateAssetAsync` / `DeleteAssetAsync` / `ImportFromScanResultsAsync` / `ExportAsync`
- **THEN** each method returns success and persists changes to `assets/<username>/assets.json`

#### Scenario: 无权限用户被拒
- **WHEN** an Active user with only `Asset:View` calls `DeleteAssetAsync`
- **THEN** the call throws `UnauthorizedAccessException` mentioning `Asset:Delete`

#### Scenario: Pending / Disabled 用户被拒
- **WHEN** a Pending or Disabled user attempts any asset mutation
- **THEN** the call throws `UnauthorizedAccessException`

### Requirement: 注册流程深度测试
The system SHALL validate user registration input and create a Pending user that requires admin approval.

#### Scenario: 重复用户名注册失败
- **WHEN** `RegisterAsync` is called with an existing username
- **THEN** the call returns a failure result with "用户名已存在"

#### Scenario: 密码哈希独立
- **WHEN** two users register with the same password
- **THEN** their `PasswordHash` and `Salt` differ (proving per-user salt)

#### Scenario: 注册后状态 = Pending
- **WHEN** registration succeeds
- **THEN** the new user has `Status=Pending`, `Permissions=[]`, `IsAdmin=false`

### Requirement: 审批流程深度测试
The system SHALL allow admin to approve / reject pending users and to batch-process them, and every action SHALL be recorded in the audit log.

#### Scenario: 单个审批
- **WHEN** admin calls `ApproveUserAsync` with 3 permissions
- **THEN** target user becomes Active, `Permissions` contains exactly those 3, audit log has 1 APPROVE + 1 SET_PERMS entry

#### Scenario: 批量审批
- **WHEN** admin calls `BatchApproveAsync([u1, u2, u3], perms)`
- **THEN** all 3 users become Active with those permissions, audit log has 3 APPROVE entries (and 3 SET_PERMS)

#### Scenario: 拒绝用户变 Disabled
- **WHEN** admin calls `RejectUserAsync` on a Pending user
- **THEN** user status becomes Disabled, `ApprovedBy` set, audit log has 1 REJECT entry

#### Scenario: 非 admin 调用审批方法失败
- **WHEN** a non-admin user calls `ApproveUserAsync` / `RejectUserAsync` / `BatchApproveAsync` / `SetUserPermissionsAsync` / `DisableUserAsync` / `EnableUserAsync` / `AdminResetPasswordAsync` / `GetPendingUsers`
- **THEN** the call throws `UnauthorizedAccessException`

### Requirement: 权限模板深度测试
The system SHALL provide 3 permission templates (Viewer / Operator / AssetManager) and applying them SHALL overwrite the user's `Permissions` list exactly.

#### Scenario: 套用 Viewer 模板
- **WHEN** admin applies the Viewer template
- **THEN** user `Permissions` becomes exactly `[Asset:View]`

#### Scenario: 套用 AssetManager 模板
- **WHEN** admin applies the AssetManager template
- **THEN** user `Permissions` contains 8 specific permission bits (no `User:View` / `User:Manage`)

#### Scenario: 模板不会自动出现 User 权限
- **WHEN** any of the 3 templates is applied
- **THEN** the resulting permission list does NOT include `User:View` or `User:Manage` (those are admin-only)

### Requirement: 审计日志深度测试
The system SHALL persist every admin write action to `audit_log.json` and expose query/export methods.

#### Scenario: 每条记录字段完整
- **WHEN** any of the 7 actions (APPROVE / REJECT / SET_PERMS / DISABLE / ENABLE / RESET_PWD / CLEAR_AUDIT) is executed
- **THEN** an entry with `Id / At / Actor / Action / Target / Detail / Success / Ip` is appended

#### Scenario: 审计可查询、可清空
- **WHEN** admin opens AuditLogWindow and clicks "Clear"
- **THEN** all entries are removed; subsequent queries return only the CLEAR_AUDIT entry itself

#### Scenario: 失败注册也写审计
- **WHEN** `RegisterAsync` fails (e.g. weak password)
- **THEN** an audit entry with `Success=false` is written

### Requirement: WPF 可交互性测试
The WPF UI SHALL render all critical controls in the expected state and react to user input.

#### Scenario: 审核窗口模板按钮可点
- **WHEN** admin opens UserApprovalWindow and clicks the "📋 资产管理员" template button
- **THEN** the corresponding 8 permission checkboxes become checked

#### Scenario: 状态栏待审提醒
- **WHEN** admin MainWindow loads with N>0 pending users
- **THEN** the status bar shows "⏳ 有 N 个待审用户（点击审核）" and clicking it opens UserApprovalWindow

#### Scenario: 审计日志窗口可筛选
- **WHEN** admin selects action filter "REJECT" in AuditLogWindow
- **THEN** the grid only shows entries with `Action=REJECT`

### Requirement: 数据隔离深度测试
Assets SHALL be stored per-user and SHALL NOT leak across users.

#### Scenario: 用户 A 看不到用户 B 资产
- **WHEN** user A and user B both call `ListAssetsAsync` after registering and adding assets
- **THEN** A's list contains only A's assets, B's list contains only B's assets

#### Scenario: 用户不能删他人资产
- **WHEN** user A attempts to delete an asset that belongs to user B
- **THEN** the call throws or returns empty result (depending on permission model)
