# Tasks

- [x] Task 1: 建立用户数据模型与认证服务
  - [x] SubTask 1.1: 新建 `Models/User.cs`，定义 `User` 类（Id、Username、DisplayName、PasswordHash、Salt、CreatedAt、LastLoginAt、FailedAttempts、LockoutUntil）和 `UserStore` 持久化模型
  - [x] SubTask 1.2: 新建 `Services/AuthService.cs`，实现 `RegisterAsync` / `LoginAsync` / `Logout` / `IsLoggedIn` / `GetCurrentUser` 方法，使用 `CryptoHelper.DeriveKey` 进行 PBKDF2 哈希，登录失败 5 次锁定 60 秒
  - [x] SubTask 1.3: 新建 `Services/SessionContext.cs`，使用单例模式保存当前登录用户，对外暴露 `Current` 属性与 `Changed` 事件（用于 UI 自动刷新按钮状态）

- [x] Task 2: 实现注册与登录窗口
  - [x] SubTask 2.1: 新建 `Views/Views/RegisterWindow.xaml` 与 `.xaml.cs`：包含用户名、密码、确认密码输入框，实时校验，注册成功返回 DialogResult=true
  - [x] SubTask 2.2: 新建 `Views/Views/LoginWindow.xaml` 与 `.xaml.cs`：包含用户名、密码、记住登录状态复选框，登录成功返回 DialogResult=true 并保存当前用户到 SessionContext
  - [x] SubTask 2.3: 登录窗口提供「注册新账号」链接，点击后关闭登录窗口并打开注册窗口

- [x] Task 3: 改造 `AssetManagementService` 加入权限校验
  - [x] SubTask 3.1: 修改 `AddAssetAsync / UpdateAssetAsync / DeleteAssetAsync` 方法签名，增加可选参数 `operatorName`（保持向后兼容）
  - [x] SubTask 3.2: 在服务层方法入口检查 `operatorName` 是否为 null/空/"Anonymous"，是则抛出 `UnauthorizedAccessException`
  - [x] SubTask 3.3: 将 `AddChangeLogAsync` 调用处的 `ChangedBy = "System"` 改为 `ChangedBy = operatorName`

- [x] Task 4: 改造 `AssetManagementWindow` 实现登录态 UI
  - [x] SubTask 4.1: 在 XAML 顶部新增状态栏区域，显示当前登录用户或「🔒 未登录」+「登录」按钮
  - [x] SubTask 4.2: 在 `AssetManagementWindow_Loaded` 与 `SessionContext.Changed` 事件中刷新按钮可用性：未登录时禁用 Add/Edit/Delete/Import；已登录时全部启用
  - [x] SubTask 4.3: 三个调用点（AddAssetButton_Click、EditAssetButton_Click、DeleteAssetButton_Click、ImportButton_Click）将当前登录用户名作为 `operatorName` 传入服务层
  - [x] SubTask 4.4: 新增「登出」按钮（仅登录后可见），点击后调用 `AuthService.Logout` 并刷新 UI

- [x] Task 5: 改造主窗口资产管理入口
  - [x] SubTask 5.1: 在 `MainWindow.xaml.cs` 的 `AssetManagement_Click` 中先检查 `SessionContext.Current`，未登录则弹出 `LoginWindow`，登录成功后再打开 `AssetManagementWindow`

- [x] Task 6: 会话持久化（记住登录状态）
  - [x] SubTask 6.1: `AuthService.LoginAsync` 接收 `rememberMe` 参数，登录成功且勾选时将 `SessionContext.Current` 加密写入 `session.json`（使用 `CryptoHelper.AesEncrypt` + `MachineFingerprint` 派生密钥）
  - [x] SubTask 6.2: `App.OnStartup` 启动时尝试加载 `session.json` 并自动恢复登录状态

- [x] Task 7: 编译与冒烟测试
  - [x] SubTask 7.1: 编译 `NetSecurityScanner.Core` 与 `NetSecurityScanner.Desktop`，修复所有编译错误
  - [x] SubTask 7.2: 运行程序验证：注册 → 登录 → 添加资产 → 编辑 → 删除 → 登出 → 重新登录后操作正常
  - [x] SubTask 7.3: 验证未登录时直接调用服务层会被拒绝（可通过临时测试按钮或断点验证）

# Task Dependencies
- Task 2 依赖 Task 1（需要 User 模型与 AuthService）
- Task 3 依赖 Task 1（需要 SessionContext 获取当前用户，但解耦后只需 operatorName 参数）
- Task 4 依赖 Task 2、Task 3
- Task 5 依赖 Task 2
- Task 6 依赖 Task 1
- Task 7 依赖 Task 1-6 全部完成
