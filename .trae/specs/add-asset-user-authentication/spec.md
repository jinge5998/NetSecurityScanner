# 资产管理-用户注册登录与权限控制 Spec

## Why
当前资产管理模块（AssetManagementWindow / AssetManagementService）完全开放，所有用户都能添加、编辑、删除资产，且 `ChangedBy` 字段被硬编码为 "System"，无法追踪操作责任人。引入注册登录与会话状态，将资产变更权限与登录账号绑定，既能保护数据安全，也能为后续审计和多人协作打基础。

## What Changes
- 新增 `User` 用户模型、`AuthService` 认证服务、`SessionContext` 当前会话上下文。
- 新增 `LoginWindow` / `RegisterWindow` 两个 WPF 窗口，提供注册与登录 UI。
- 改造 `AssetManagementService` 的增/改/删接口，要求传入当前操作用户；对未登录调用方抛出 `UnauthorizedAccessException`。
- 改造 `AssetManagementWindow`：未登录时禁用「添加、编辑、删除、导入」按钮；并在窗口顶部显示当前登录用户与「登录/登出」入口。
- `MainWindow` 顶部菜单的「资产管理」入口在打开资产管理窗口前先确认登录状态（未登录时弹出登录框，登录成功后再进入）。
- 资产变更日志 `AssetChangeLog.ChangedBy` 由调用方传入的用户名填充，取代硬编码 "System"。
- 用户凭证以 `users.json` 形式本地持久化，密码使用 PBKDF2 (Rfc2898DeriveBytes) 加盐哈希存储（复用现有 `CryptoHelper.DeriveKey`）。
- **BREAKING**：`AssetManagementService.AddAssetAsync / UpdateAssetAsync / DeleteAssetAsync` 的方法签名增加可选参数 `operatorName`（旧调用方仍可工作，但默认为 "Anonymous" 且会被服务层拒绝写入）。

## Impact
- Affected specs:
  - `enhance-network-topology`（资产模块相关）— 无直接破坏
  - 新增本规格 `add-asset-user-authentication`
- Affected code:
  - 新增 `NetSecurityScanner.Core/Models/User.cs`
  - 新增 `NetSecurityScanner.Core/Services/AuthService.cs`
  - 新增 `NetSecurityScanner.Core/Services/SessionContext.cs`
  - 新增 `NetSecurityScanner.Desktop/Views/Views/LoginWindow.xaml(.cs)`
  - 新增 `NetSecurityScanner.Desktop/Views/Views/RegisterWindow.xaml(.cs)`
  - 修改 `NetSecurityScanner.Core/Services/AssetManagementService.cs`
  - 修改 `NetSecurityScanner.Desktop/Views/Views/AssetManagementWindow.xaml(.cs)`
  - 修改 `NetSecurityScanner.Desktop/MainWindow.xaml.cs`（资产管理入口）

## ADDED Requirements

### Requirement: 用户注册
系统 SHALL 提供本地用户注册功能，允许用户通过用户名与密码创建账号。

#### Scenario: 成功注册
- **WHEN** 用户在注册窗口输入合法的用户名（3-32 位，字母/数字/下划线）和密码（≥6 位）并点击「注册」
- **THEN** 系统在 `users.json` 中创建新用户，密码经 PBKDF2 加盐哈希后保存，提示「注册成功」并跳转到登录窗口

#### Scenario: 用户名重复
- **WHEN** 用户输入已存在的用户名
- **THEN** 系统弹出错误提示「该用户名已被占用」，不写入数据

#### Scenario: 输入校验失败
- **WHEN** 用户名或密码不符合规则
- **THEN** 系统在对应字段下方显示红色错误提示，禁用「注册」按钮

### Requirement: 用户登录
系统 SHALL 提供本地用户登录功能，验证用户名与密码后建立会话。

#### Scenario: 登录成功
- **WHEN** 用户输入正确的用户名与密码并点击「登录」
- **THEN** `SessionContext` 保存当前登录用户（用户名 + 显示名 + 登录时间），登录窗口关闭，资产管理窗口的受限按钮变为可用

#### Scenario: 密码错误
- **WHEN** 用户输入错误密码
- **THEN** 系统提示「用户名或密码错误」，不暴露具体错误原因，连续 5 次错误锁定 60 秒

#### Scenario: 会话持久化
- **WHEN** 用户勾选「记住登录状态」并登录成功
- **THEN** 会话信息加密保存到 `session.json`，下次启动程序时自动恢复登录状态

### Requirement: 用户登出
系统 SHALL 提供登出功能，清除当前会话。

#### Scenario: 主动登出
- **WHEN** 登录用户在资产管理窗口点击「登出」
- **THEN** `SessionContext` 清除当前用户，删除 `session.json`（如果存在），界面按钮回到未登录态

### Requirement: 资产管理权限控制
系统 SHALL 根据登录状态控制资产模块的增删改权限。

#### Scenario: 未登录用户访问
- **WHEN** 未登录用户打开资产管理窗口
- **THEN** 「添加资产」「编辑」「删除」「导入」按钮置灰（IsEnabled=false），仅可查看、搜索、刷新、导出

#### Scenario: 未登录用户尝试绕过 UI
- **WHEN** 任何代码路径在 `SessionContext` 为空时调用 `AssetManagementService.AddAssetAsync/UpdateAssetAsync/DeleteAssetAsync`
- **THEN** 服务层抛出 `UnauthorizedAccessException`，不写入 `assets.json`

#### Scenario: 登录用户操作
- **WHEN** 已登录用户执行添加/编辑/删除
- **THEN** 操作成功执行，变更日志 `ChangedBy` 字段记录为当前登录用户名

### Requirement: 登录入口
系统 SHALL 在主窗口与资产管理窗口提供登录入口。

#### Scenario: 主窗口打开资产管理
- **WHEN** 用户在主窗口点击「工具 → 资产管理」
- **THEN** 若未登录则弹出登录窗口（登录后自动进入资产管理）；若已登录则直接打开资产管理窗口

#### Scenario: 资产管理窗口内登录
- **WHEN** 未登录用户通过主窗口进入资产管理（应被拦截到登录窗口）后仍处于资产管理窗口
- **THEN** 窗口顶部显示「🔒 未登录」徽章和「登录」按钮，点击后弹出登录窗口

## MODIFIED Requirements
无（本规格为全新功能模块，不修改已有功能规格）。

## REMOVED Requirements
无。

## 安全设计要点
- 密码哈希：`PBKDF2-SHA256, 100000 iterations, 16-byte salt`，盐值随机并随哈希一并存储。
- 用户文件 `users.json` 存储于程序目录，文件权限建议由操作系统控制（Windows 普通用户隔离）。
- 会话文件 `session.json` 使用 `CryptoHelper.AesEncrypt` 加密，密钥派生自机器指纹 `MachineFingerprint`。
- 登录失败计数与锁定时间仅存内存，重启后清零（避免本地暴力破解）。
- 服务层校验与会话状态校验双重防护：UI 禁用仅是体验优化，真正权限拦截在 `AssetManagementService` 内部完成。
