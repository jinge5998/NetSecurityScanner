# Checklist

## 数据层
- [x] `Models/User.cs` 已创建，包含 `Id/Username/DisplayName/PasswordHash/Salt/CreatedAt/LastLoginAt/FailedAttempts/LockoutUntil` 字段
- [x] `Services/AuthService.cs` 已实现 `RegisterAsync` / `LoginAsync` / `Logout` 方法
- [x] 密码使用 PBKDF2-SHA256（100000 轮）+ 16 字节随机盐 存储
- [x] `users.json` 写入程序运行目录，结构清晰可读

## 会话层
- [x] `Services/SessionContext.cs` 单例实现，暴露 `Current` 属性与 `Changed` 事件
- [x] 「记住登录状态」时使用 `CryptoHelper.AesEncrypt` + `MachineFingerprint` 加密保存到 `session.json`
- [x] `App.OnStartup` 启动时自动恢复登录状态

## UI 层
- [x] `RegisterWindow` 包含用户名/密码/确认密码字段，实时校验规则
- [x] `LoginWindow` 包含用户名/密码/记住登录状态字段，提供「注册新账号」入口
- [x] `AssetManagementWindow` 顶部显示登录状态徽章与登录/登出按钮
- [x] 未登录时「添加资产/编辑/删除/导入」按钮置灰
- [x] 已登录时所有按钮可用
- [x] `MainWindow` 的「资产管理」菜单在未登录时先弹出登录窗口

## 服务层权限拦截
- [x] `AssetManagementService.AddAssetAsync/UpdateAssetAsync/DeleteAssetAsync` 在 `operatorName` 为空时抛出 `UnauthorizedAccessException`
- [x] `AssetChangeLog.ChangedBy` 字段记录为实际登录用户名，不再是硬编码 "System"

## 安全与体验
- [x] 连续 5 次密码错误锁定 60 秒
- [x] 密码错误提示统一为「用户名或密码错误」，不区分两种情况
- [x] 用户名重复注册时给出明确错误提示

## 编译与运行
- [x] `NetSecurityScanner.Core` 编译通过
- [x] `NetSecurityScanner.Desktop` 编译通过
- [x] 完整流程测试通过：注册 → 登录 → 添加 → 编辑 → 删除 → 登出 → 重新登录
- [x] 未登录状态下尝试操作资产被服务层拒绝
