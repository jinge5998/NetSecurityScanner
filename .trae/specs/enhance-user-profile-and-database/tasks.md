# Tasks

- [x] Task 1: 扩展 `AuthService` 支持修改密码与显示名
  - [x] SubTask 1.1: 在 `AuthService` 中新增 `ChangePasswordAsync(string username, string oldPassword, string newPassword)`，先校验旧密码，再生成新盐与哈希后写回 `users.json`；当前会话用户名匹配时同步刷新 `SessionContext.Instance.Current`
  - [x] SubTask 1.2: 在 `AuthService` 中新增 `UpdateDisplayNameAsync(string username, string newDisplayName)`，校验 1-32 字符后写回；当前会话匹配时同步刷新 `SessionContext`
  - [x] SubTask 1.3: 新增 `GetAllUsers()` 方法返回 `User` 列表（密码字段已脱敏为 null），供账号管理窗口绑定

- [x] Task 2: 把 `AssetManagementService` 改造为多租户
  - [x] SubTask 2.1: 在服务构造函数中接收当前登录用户名（或从 `SessionContext.Instance.Current.Username` 读取），按 `assets/<username>/assets.json` 路径加载
  - [x] SubTask 2.2: 路径拼接前对用户名执行 `AuthService.IsValidUsername` 校验，防止路径穿越
  - [x] SubTask 2.3: 保存路径同步使用 `assets/<username>/assets.json`；`assets/<username>/` 目录不存在时自动创建
  - [x] SubTask 2.4: 变更日志与 `assets.json` 写入同一目录

- [x] Task 3: 实现 `UserProfileWindow`（个人资料窗口）
  - [x] SubTask 3.1: 新建 `Views/Views/UserProfileWindow.xaml` 与 `.xaml.cs`：包含「显示名」「旧密码」「新密码」「确认新密码」字段，保存按钮根据校验结果启用/禁用
  - [x] SubTask 3.2: 保存逻辑：先调用 `AuthService.UpdateDisplayNameAsync`，再调用 `AuthService.ChangePasswordAsync`（用户若未填写新密码区域则跳过改密步骤），成功后提示并关闭
  - [x] SubTask 3.3: 任何失败（用户名不存在、旧密码错误、密码不合规）需在窗口内联显示红色错误提示

- [x] Task 4: 实现 `UserManagementWindow`（账号管理窗口）
  - [x] SubTask 4.1: 新建 `Views/Views/UserManagementWindow.xaml` 与 `.xaml.cs`：只读 DataGrid 列展示 用户名 / 显示名 / 创建时间 / 最后登录时间 / 失败次数 / 是否锁定；窗口标题带登录用户上下文
  - [x] SubTask 4.2: 窗口打开时调用 `AuthService.GetAllUsers()` 加载数据，关闭窗口时自动释放资源

- [x] Task 5: 改造 `AssetManagementWindow` 暴露新入口
  - [x] SubTask 5.1: XAML 顶部状态栏新增「👤 个人资料」与「👥 账号管理」两个按钮，仅在已登录时显示
  - [x] SubTask 5.2: 点击事件分别打开 `UserProfileWindow` 与 `UserManagementWindow`，并订阅 `SessionContext.Changed` 事件在显示名变化时刷新顶部账号文本

- [x] Task 6: 改造 `MainWindow` 添加账号管理入口
  - [x] SubTask 6.1: 在 `MainWindow.xaml` 「工具」菜单下新增「账号管理」菜单项（位置紧邻「资产管理」）
  - [x] SubTask 6.2: 点击事件先校验登录状态，未登录时弹出登录框，登录成功后打开账号管理窗口

- [x] Task 7: 旧 `assets.json` 自动迁移
  - [x] SubTask 7.1: 在 `App.OnStartup` 调用 `AuthService.TryRestoreSession` 之后，检测 `assets.json` 与 `assets/default/assets.json` 是否同时缺失，若是则将旧文件复制为 `assets/default/assets.json`（仅一次；用文件存在性判断避免重复）
  - [x] SubTask 7.2: 迁移时使用 try/catch 静默失败，避免阻塞主程序启动

- [x] Task 8: 编译与冒烟测试
  - [x] SubTask 8.1: 编译 `NetSecurityScanner.Core` 与 `NetSecurityScanner.Desktop`，修复所有编译错误
  - [x] SubTask 8.2: 编写并运行冒烟脚本验证：注册 → 登录 → 改昵称 → 改密码 → 重新登录 → 资产管理数据按用户名隔离 → 账号管理只读 → 旧 assets.json 迁移到 assets/default/

# Task Dependencies
- Task 2 依赖 Task 1（需要 `GetAllUsers` 等方法）
- Task 3 依赖 Task 1（需要 ChangePasswordAsync / UpdateDisplayNameAsync）
- Task 4 依赖 Task 1（需要 GetAllUsers）
- Task 5 依赖 Task 2、Task 3、Task 4
- Task 6 依赖 Task 4
- Task 7 独立
- Task 8 依赖所有上述 Task
