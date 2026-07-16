# 资产管理-用户资料与每用户独立数据库 Spec

## Why
现有 `add-asset-user-authentication` 规格解决了"谁登录谁操作"的鉴权问题，但仍存在明显短板：①用户没有自助修改密码/昵称的入口；②无法查看已注册账号的清单；③所有用户共享同一份 `assets.json`，缺乏隔离。本规格在保持原有登录鉴权流程不变的前提下，补齐"自助资料管理 + 账号审计 + 多租户数据隔离"三项能力。

## What Changes
- 新增 `UserProfileWindow`（自助资料窗口）：当前登录用户可修改显示名与密码。
- 新增 `UserManagementWindow`（账号管理窗口）：以只读 DataGrid 列出所有用户（用户名、显示名、创建时间、最后登录时间、失败次数、是否锁定），登录用户可访问。
- `AuthService` 新增方法：`ChangePasswordAsync(username, oldPassword, newPassword)` 与 `UpdateDisplayNameAsync(username, newDisplayName)`。
- `AssetManagementService` 改造为**多租户**：每个登录用户拥有独立的资产文件 `assets/<username>/assets.json`；服务初始化时根据 `SessionContext.Current.Username` 选择数据目录。
- 资产变更日志的 `ChangedBy` 仍记录操作用户（每用户独立日志，与资产同目录）。
- `App.OnStartup` 在 `users.json` 缺失时不再阻止启动；为每个登录用户首次访问资产模块时自动创建 `assets/<username>/` 目录。
- 资产管理窗口顶部新增「👤 个人资料」与「👥 账号管理」两个按钮（仅登录后可见）。
- 旧版单一 `assets.json` 在首次启动新版本时**自动迁移**到默认用户 `default` 的目录下，避免数据丢失。

## Impact
- Affected specs:
  - `add-asset-user-authentication`（向后兼容，方法签名不变，行为升级）
  - 新增本规格 `enhance-user-profile-and-database`
- Affected code:
  - 修改 `NetSecurityScanner.Core/Services/AuthService.cs`
  - 修改 `NetSecurityScanner.Core/Services/AssetManagementService.cs`
  - 新增 `NetSecurityScanner.Desktop/Views/Views/UserProfileWindow.xaml(.cs)`
  - 新增 `NetSecurityScanner.Desktop/Views/Views/UserManagementWindow.xaml(.cs)`
  - 修改 `NetSecurityScanner.Desktop/Views/Views/AssetManagementWindow.xaml(.cs)`
  - 修改 `NetSecurityScanner.Desktop/MainWindow.xaml.cs`（账号管理入口）
  - 修改 `NetSecurityScanner.Desktop/App.xaml.cs`（旧数据迁移）

## ADDED Requirements

### Requirement: 修改密码
登录用户 SHALL 能够通过个人资料窗口修改自己的密码。

#### Scenario: 成功修改
- **WHEN** 登录用户在个人资料窗口输入正确的旧密码与合法的新密码（≥6 位）并确认两次新密码一致
- **THEN** `AuthService.ChangePasswordAsync` 用新盐 + PBKDF2 重写 `PasswordHash` 与 `Salt`，保存 `users.json`，提示「密码修改成功」，旧密码立即失效

#### Scenario: 旧密码错误
- **WHEN** 用户输入的旧密码与当前不匹配
- **THEN** 弹出错误「旧密码错误」，不修改任何数据

#### Scenario: 新密码不合规
- **WHEN** 新密码长度 < 6 位或两次输入不一致
- **THEN** 禁用「保存」按钮并在对应字段下方显示红色错误

### Requirement: 修改个人资料（显示名）
登录用户 SHALL 能够修改自己的显示名。

#### Scenario: 成功修改
- **WHEN** 用户在个人资料窗口修改显示名（1-32 字符）并保存
- **THEN** `AuthService.UpdateDisplayNameAsync` 更新 `User.DisplayName` 并写回 `users.json`；如果当前用户正持有会话，则同步更新 `SessionContext.Current.DisplayName`，资产管理窗口顶部用户名立即刷新

#### Scenario: 输入校验失败
- **WHEN** 显示名为空或超过 32 字符
- **THEN** 禁用「保存」按钮并提示校验失败

### Requirement: 账号管理与查看
登录用户 SHALL 能够查看所有已注册账号的元数据（只读）。

#### Scenario: 查看账号列表
- **WHEN** 登录用户在主窗口「工具 → 账号管理」或资产管理窗口「👥 账号管理」打开账号管理窗口
- **THEN** DataGrid 显示所有 `User` 字段：用户名、显示名、创建时间、最后登录时间、累计失败次数、是否被锁定；`PasswordHash` 与 `Salt` 永不显示

#### Scenario: 未登录访问
- **WHEN** 未登录用户尝试打开账号管理窗口
- **THEN** 弹出登录窗口，登录成功后自动进入账号管理

### Requirement: 每用户独立资产数据库
系统 SHALL 为每个登录用户提供独立的资产与变更日志存储。

#### Scenario: 登录后首次打开资产管理
- **WHEN** 用户 alice 首次登录后打开资产管理窗口
- **THEN** 自动创建 `assets/alice/assets.json`（若不存在），所有增/改/删/导入仅作用于该文件

#### Scenario: 切换登录用户
- **WHEN** 用户登出后用 bob 账号重新登录并打开资产管理
- **THEN** 看到的是 `assets/bob/assets.json` 的内容，与 alice 完全隔离

#### Scenario: 旧版数据迁移
- **WHEN** 程序检测到根目录下存在旧版 `assets.json` 且 `assets/default/` 不存在
- **THEN** 启动时把旧 `assets.json` 复制为 `assets/default/assets.json`（仅一次），之后保留原文件供用户手动清理

#### Scenario: 用户目录隔离
- **WHEN** alice 调用 `AssetManagementService.GetAllAssets()`
- **THEN** 永远只能读到 `assets/alice/assets.json` 里的数据，不存在跨用户读取的可能

## MODIFIED Requirements
（继承自 `add-asset-user-authentication`）

### Requirement: 资产管理权限控制
保留原规格中"未登录时禁用写操作"的逻辑；本规格在用户已登录的前提下新增"每用户独立数据库"的隔离要求，写入路径不可跨用户。

## REMOVED Requirements
无。

## 安全设计要点
- `UserProfileWindow` 必须在每次进入时强制要求输入**旧密码**才能改密码（即使当前用户已经登录），防止离开座位时被他人改密。
- 账号管理窗口为只读；不允许通过 UI 增删用户或重置密码。
- 每用户数据库路径不可由用户输入控制（避免路径穿越 `../`），用户名经 `AuthService.IsValidUsername` 校验后才用于拼路径。
- 修改密码成功后**立即使现有会话重新加载**（`SessionContext.Instance.Current` 指向新的 User 对象），确保 UI 显示名/时间字段一致。
- 旧 `assets.json` 迁移采用"复制而非移动"，避免迁移失败造成数据丢失；用户可手动删除原文件。
