# Checklist

## AuthService 扩展
- [x] `ChangePasswordAsync` 校验旧密码、生成新盐与 PBKDF2 哈希并写回 `users.json`
- [x] `UpdateDisplayNameAsync` 校验 1-32 字符长度后写回
- [x] 当前会话用户名匹配时 `SessionContext.Current` 同步刷新
- [x] `GetAllUsers()` 返回 `User` 列表（`PasswordHash` / `Salt` 字段为 null）

## AssetManagementService 多租户改造
- [x] 构造函数根据 `SessionContext.Current.Username` 决定 `assets/<username>/assets.json`
- [x] 用户名在拼路径前先经 `IsValidUsername` 校验
- [x] 目录不存在时自动创建
- [x] 资产与变更日志写入同一目录
- [x] 跨用户数据完全隔离（一个用户无法读取另一个用户的数据）

## UserProfileWindow（个人资料）
- [x] 含显示名、旧密码、新密码、确认新密码字段
- [x] 「保存」按钮根据校验结果启用/禁用
- [x] 改密成功或失败都有内联提示
- [x] 旧密码错误、新密码不合规、两次输入不一致均被拦截

## UserManagementWindow（账号管理）
- [x] 只读 DataGrid 展示：用户名 / 显示名 / 创建时间 / 最后登录时间 / 失败次数 / 是否锁定
- [x] `PasswordHash` 与 `Salt` 字段不出现在 UI
- [x] 未登录用户访问会被拦截到登录窗口

## AssetManagementWindow 入口
- [x] 顶部新增「👤 个人资料」与「👥 账号管理」按钮（仅登录后可见）
- [x] 点击事件分别打开对应窗口
- [x] `SessionContext.Changed` 事件触发时刷新顶部账号文本

## MainWindow 入口
- [x] 「工具」菜单新增「账号管理」菜单项
- [x] 未登录时弹出登录窗口，登录成功后打开账号管理

## 旧数据迁移
- [x] `App.OnStartup` 检测到根目录 `assets.json` 且 `assets/default/assets.json` 不存在时复制一次
- [x] 迁移失败不阻塞主程序启动

## 编译与冒烟
- [x] `NetSecurityScanner.Core` 编译通过
- [x] `NetSecurityScanner.Desktop` 编译通过
- [x] 完整流程测试：注册 → 登录 → 改昵称 → 改密码 → 重新登录 → 资产管理按用户隔离 → 账号管理只读 → 旧 assets.json 自动迁移
