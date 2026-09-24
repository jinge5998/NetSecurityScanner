# 验收清单

## 数据流验证
- [ ] `users.json` 与 WPF 待审核窗口显示的待审用户数一致
- [ ] 新注册用户能在 1 秒内通过刷新出现在待审核窗口
- [ ] `auth_diag.log` 记录完整的 4 步流程（Click → RegisterAsync → WriteDisk → LoadPendingUsers）

## 数据库一致性
- [ ] `DiagPending` 工具读到的 Pending 数 == `users.json` 中 `Status=Pending && !IsAdmin` 数
- [ ] 写盘路径就是读盘路径（`%LOCALAPPDATA%\NetSecurityScanner\data\users.json`）

## 测试
- [ ] `AuthSmokeTest` 27+ 用例全过
- [ ] 跨进程读一致性测试通过

## 用户体验
- [ ] 注册窗口：所有字段都填且合法时按钮才可点击
- [ ] 注册窗口：提交后立即给成功/失败反馈 + 失败原因
- [ ] 待审核窗口：🔄 刷新按钮立即重新加载
- [ ] 状态栏：登录后显示"⏳ 有 N 个待审用户"，N 与实际一致

## 代码质量
- [ ] 关键写操作都有 try/catch + 诊断日志
- [ ] 关键读操作都从磁盘重新加载，不依赖内存缓存
- [ ] 无新增硬编码路径（仍走 `DataPaths`）
