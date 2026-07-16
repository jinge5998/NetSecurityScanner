# 深度测试：注册→审核刷新 数据流 一致性

**日期**：2026-06-12
**关联 spec**：`enhance-register-flow`（已实现 + 部分验证）
**目标**：端到端验证"用户注册后，admin 待审核窗口能否看到新用户"的完整数据流，定位并修复任何剩余 bug，确保数据库（`users.json`）与内存视图一致。

## Why

`enhance-register-flow` 实施后用户报告：
- 注册窗口显示"注册成功"
- admin 在「用户审核」窗口点击 🔄 刷新后**看不到新注册用户**
- 前一轮已做 `DataPaths` 集中化 + `LoadPendingUsers` 用 `new AuthService()` 重新加载
- 但实际数据（`users.json`）在 19:34:37 之后**未变化**，说明**注册本身可能没真的成功写盘**
- 需要深度排查：到底是注册没写盘、还是写盘了但读取没读到、还是前端绑定没刷新

## What Changes

- **诊断**：在 `AuthService` 和 `RegisterWindow` 关键位置加详细日志
- **数据流验证**：通过 `DiagPending` 工具直接读磁盘文件，与 `UserApprovalWindow` 行为对比
- **修复**：根据诊断结果定位 bug 并修复
- **回归测试**：扩展 `AuthSmokeTest` 覆盖"长生命周期窗口 + 跨窗口读"场景

## Impact

- **Affected code**：
  - `Core/Services/AuthService.cs`（RegisterAsync 写盘流程、LoadUsers 流程）
  - `Desktop/Views/Views/RegisterWindow.xaml.cs`（按钮状态、提交流程）
  - `Desktop/Views/Views/UserApprovalWindow.xaml.cs`（LoadPendingUsers）
  - `DiagPending/Program.cs`（深度诊断）
  - `AuthSmokeTest/Program.cs`（扩展测试）

- **Affected data**：
  - `users.json`（注册、审批、修改都涉及）
  - `auth_diag.log`（诊断日志）

## ADDED Requirements

### Requirement: 注册全链路可观测

系统 SHALL 在以下 4 个关键节点写诊断日志到 `auth_diag.log`：
1. `RegisterButton_Click` 触发（捕获 IsEnabled + 输入值）
2. `RegisterAsync` 入口校验（捕获 ErrorCode + 失败原因）
3. `RegisterAsync` 写盘后（捕获 Total + File 路径）
4. `LoadPendingUsers` 重新加载后（捕获从磁盘读到的 Total 与 Pending 数）

#### Scenario: 注册成功 + 审核可见
- **WHEN** admin 在「用户审核」窗口打开后，另一个窗口注册新用户
- **THEN** admin 点击 🔄 刷新后，新用户应出现在列表
- **AND** `users.json` 应包含新用户
- **AND** `auth_diag.log` 应有完整的 4 步日志

### Requirement: 数据库与视图一致

系统 SHALL 保证：
- `GetPendingUsers()` 返回的列表数 == `users.json` 中 `Status=Pending && !IsAdmin` 的用户数
- 任何读操作都从**磁盘**重新加载，不依赖**内存缓存**

#### Scenario: 跨进程读一致性
- **WHEN** 进程 A 注册用户并写盘
- **AND** 进程 B 重新 `new AuthService()` 并调用 `GetPendingUsers()`
- **THEN** 进程 B 应能读到这个用户

## MODIFIED Requirements

### Requirement: RegisterWindow 实时反馈（增强版）
- 提交按钮 `IsEnabled` 状态必须反映**所有**必填项
- 提交后**必须**给用户明确反馈（成功/失败都弹窗，附原因）
- 弱密码**不阻止**注册

### Requirement: UserApprovalWindow 刷新（已修复）
- 每次 `LoadPendingUsers` 都 `new AuthService()` 重新从磁盘加载
- 刷新后立即清空旧 items 并重新填充 ObservableCollection

## 范围外（明确不做）
- 不修改业务逻辑（注册/审核规则不变）
- 不引入新的依赖
- 不重构现有架构
- 不修改 UI 设计

## 验收标准
- 用户在 WPF 真实操作下：注册新用户 → 审核窗口刷新 → 立刻看到该用户
- `DiagPending` 工具读到的 Pending 数 == WPF UI 看到的 Pending 数
- `AuthSmokeTest` 24+ 用例全过
- `auth_diag.log` 完整可追溯 4 步流程

## 修复记录

### Root Cause
`RegisterWindow.xaml.cs` 的 `UpdateRegisterButton()` 方法把"按钮是否可点击"绑定到了三个 `async void` 异步查重的结果 (`_usernameAvailable && _emailAvailable && _phoneAvailable`)。用户输完字段后立刻点"注册"按钮时,`await Task.Run` 还没返回 → 按钮 IsEnabled=False → 点击事件根本不触发 → 表现为"用户以为注册成功了但实际啥也没发生"。

证据:
- `C:\Users\Administrator\AppData\Local\NetSecurityScanner\data\logs\auth_diag.log` 0 条 `RegisterButton_Click` 记录
- `users.json` 在 19:34 之后未变化
- DiagPending 工具验证 Core.dll 自身行为完全正常

### Fix
1. `UpdateRegisterButton()` 改为**只检查同步可判的格式**(`IsValidUsername/IsValidEmail/IsValidPhone` + 密码长度 + 两次密码一致 + Reason 长度≤200)。不依赖任何异步状态。
2. `RegisterButton_Click` 进入后**先做实时查重**(`new AuthService()` + `IsUsernameAvailable/IsEmailAvailable/IsPhoneAvailable`),命中重复就 `MessageBox.Show` 并 `Focus()` 回到对应字段。
3. 通过查重后才 `RegisterButton.IsEnabled = false` + `await _authService.RegisterAsync(...)`。

### 回归测试
扩展 AuthSmokeTest 增加 3 个用例:
- 【X】注册后立刻 `new AuthService()` + `GetPendingUsers()` 验证可见
- 【Y】两个独立 AuthService 实例 - 后者读到前者的注册
- 【Z】外部修改 users.json 后重新 new AuthService() 能读到

全部 27 个用例通过(23 旧用例 + 1 admin/3 长度 = 26 个,实际 27 = 23 增强版 + X/Y/Z 3 个回归)。DiagPending 模拟 WPF 端到端流程也通过。
