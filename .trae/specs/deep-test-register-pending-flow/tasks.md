# 任务清单

## 阶段 1：诊断与现状调查
- [ ] Task 1.1: 读取当前 `users.json` 完整内容并汇总用户状态
  - 用 `Read` 工具读取
  - 列出所有用户的 Username / Status / IsAdmin / CreatedAt
- [ ] Task 1.2: 读取 `auth_diag.log` 完整内容并定位最新注册行为
  - 找最新一次 `RegisterAsync: SUCCESS` 或 `SAVE_FAILED` 记录
  - 找最新一次 `RegisterButton_Click` 记录
- [ ] Task 1.3: 用 `DiagPending` 工具运行实际读盘流程并对比结果
  - 跑 `dotnet run --project src/DiagPending/DiagPending.csproj`
  - 看 Total / Pending 数是否与 `users.json` 一致

## 阶段 2：定位 Root Cause
- [ ] Task 2.1: 分析"用户看到注册成功 + users.json 没变"的矛盾
  - 可能性 A：RegisterButton_Click 没触发（按钮 IsEnabled=False）
  - 可能性 B：RegisterAsync 内部失败但被错误地返回 Success
  - 可能性 C：写盘路径错误（写到了别处）
  - 可能性 D：MessageBox.Show 弹的是别的消息，用户误以为是"注册成功"
- [ ] Task 2.2: 根据 `auth_diag.log` 证据确定具体原因
  - 如果只有 LoginAsync 记录无 RegisterAsync 记录 → 按钮没触发
  - 如果有 RegisterAsync: SAVE_FAILED → 写盘异常
  - 如果有 RegisterAsync: SUCCESS 但 users.json 没新用户 → 路径错

## 阶段 3：修复 Bug
- [ ] Task 3.1: 根据 2.2 结论修复代码
  - 如果是按钮 IsEnabled 问题：修 `UpdateRegisterButton()` 逻辑
  - 如果是写盘问题：修 `SaveUsersAsync` 路径或加锁
  - 如果是路径问题：修 `DataPaths` 或 `_usersFilePath` 赋值
- [ ] Task 3.2: 重新构建 WPF：`dotnet build src/NetSecurityScanner.Desktop/NetSecurityScanner.Desktop.csproj -c Release --no-incremental`
- [ ] Task 3.3: 重启 WPF 让用户重试

## 阶段 4：回归测试
- [ ] Task 4.1: 扩展 `AuthSmokeTest`：增加 3 个用例
  - 用例 X：注册后立刻 `new AuthService()` + `GetPendingUsers()` 验证可见
  - 用例 Y：注册 → 模拟 2 个 AuthService 实例 → 第二个实例能否读到
  - 用例 Z：注册 → 修改 `users.json` 模拟"另一进程写盘" → 重新 new 读 → 应可见
- [ ] Task 4.2: 跑 `AuthSmokeTest` 全套，确认 27+ 用例全过
- [ ] Task 4.3: 跑 `dotnet run --project src/DiagPending/DiagPending.csproj` 验证 WPF 同一份 Core.dll 行为正确

## 阶段 5：交付与文档
- [ ] Task 5.1: 把根因 + 修复写入 spec.md 的 "修复记录" 章节
- [ ] Task 5.2: 通知用户测试并附诊断日志位置

# 任务依赖
- [Task 2.x] 依赖 [Task 1.x]（先调查后定位）
- [Task 3.x] 依赖 [Task 2.2]（先定位后修复）
- [Task 4.x] 依赖 [Task 3.x]（修复后回归）
- [Task 5.x] 依赖 [Task 4.x]
