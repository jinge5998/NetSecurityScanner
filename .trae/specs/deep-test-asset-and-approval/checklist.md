# Checklist

## 测试基础设施
- [x] `DeepAssetApprovalTest` 项目创建，引用 NetSecurityScanner.Core
- [x] `ResetAllData` 帮助类：清理 users.json / session.json / audit_log.json / assets
- [x] `Header / Step / StepSync / Mark / WriteReportAsync` 输出美化器
- [x] 测试报告输出到 `test-report/deep-test-report.md`

## 场景 1 - 注册 (5/5)
- [x] 1.a 正常注册成功且字段正确（Status=Pending、Permissions=[]、IsAdmin=false）
- [x] 1.b 重名注册返回 false
- [x] 1.c 弱密码注册失败
- [x] 1.d/1.d.1 同密码不同用户的 Salt / Hash 不一致
- [x] 1.e 注册后数据写入 `users.json`

## 场景 2 - 审批 (8/8)
- [x] 2.a admin 自动创建（IsAdmin=true、所有 10 项权限）
- [x] 2.b admin 登录 + `GetPendingUsers` 可见 4 个
- [x] 2.c 单个 `ApproveUserAsync` 后状态 Active
- [x] 2.d `BatchApproveAsync` 多人同时激活
- [x] 2.e `RejectUserAsync` 后状态 Disabled
- [x] 2.f.1/2.f.2/2.f.3 非 admin 调用审批方法抛 `UnauthorizedAccessException`
- [x] 2.g admin 自改权限被拒
- [x] 2.h 每次写操作生成审计条目

## 场景 3 - 资产登记 (10/10)
- [x] 3.a 无 `Asset:Add` 用户被拒
- [x] 3.b/3.b.1 有权限用户 `AddAssetAsync` 成功并可见
- [x] 3.c `UpdateAssetAsync` 权限校验生效
- [x] 3.d.1/3.d.2/3.d.3 `DeleteAssetAsync` 权限校验生效，删除后 List 不见
- [x] 3.e/3.e.1 `ImportFromScanResultsAsync` 权限校验生效
- [x] 3.f `Asset:Export` 权限位识别

## 场景 4 - 权限模板 (6/6)
- [x] 4.a `Templates.All.Count == 3`
- [x] 4.b Viewer 仅含 `Asset:View`
- [x] 4.c Operator 含 4 项，不含 Delete
- [x] 4.d AssetManager 含 8 项，不含 `User:View` / `User:Manage`
- [x] 4.e/4.e.1 套用模板后审计记录 APPROVE + SET_PERMS，用户权限数 = 8

## 场景 5 - 审计日志 (4/4)
- [x] 5.a 7 种动作全部被记录
- [x] 5.b `ClearAuditLogAsync` 后仅剩 CLEAR_AUDIT 自身
- [x] 5.c 记录的 `At` 是合法 DateTime、`Actor` 非空、`Action` 合法
- [x] 5.d 失败注册可选项

## 场景 6 - 边界与异常 (4/4)
- [x] 6.a 5 次错误密码后账户被锁 60 秒
- [x] 6.b Disabled 用户登录被拒
- [x] 6.c 登出后可重新登录
- [x] 6.e `AdminResetPasswordAsync` 后必须用新密码

## 场景 7 - 数据隔离 (3/3)
- [x] 7.a alice / bob 各自的 `ListAssetsAsync` 互不可见
- [x] 7.b 物理文件位于 `assets/alice/` 和 `assets/bob/` 不同目录
- [x] 7.c service 实例加载各自目录，互不串数据

## 场景 8 - WPF 实际可交互性 (6/6)
- [x] 8.a WPF 可执行文件存在
- [x] 8.b 关键 XAML 文件齐全
- [x] 8.c UserApprovalWindow.xaml.cs 含 BatchApproveAsync/ApproveUserAsync 调用
- [x] 8.d MainWindow.xaml.cs 含 `_pendingTimer` 定时器
- [x] 8.e WPF 进程环境检查
- [x] 8.f 生成 `test-artifacts/WpfInteractionProbe.ps1` 探针脚本

## 编译与报告
- [x] 解决方案 0 error 编译通过
- [x] **52 / 52 全部测试用例通过**
- [x] 输出 `test-report/deep-test-report.md` 报告
- [x] 报告含每阶段 ✅/❌ 列表与统计
