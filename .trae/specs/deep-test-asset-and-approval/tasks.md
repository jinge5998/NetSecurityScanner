# Tasks

- [x] Task 1: 测试基础设施 - 隔离临时目录
  - [x] SubTask 1.1: `ResetAllData()` 清理 users.json/session.json/audit_log.json/assets
  - [x] SubTask 1.2: `Header/Step/StepSync/Mark/WriteReportAsync` 美化输出与报告
  - [x] SubTask 1.3: `DeepAssetApprovalTest.csproj` 引用 Core 库

- [x] Task 2: 场景 1 - 注册流程深度测试 (5 用例)
  - [x] SubTask 2.1: 1.a 正常注册字段正确
  - [x] SubTask 2.2: 1.b 重名注册失败
  - [x] SubTask 2.3: 1.c 弱密码注册失败
  - [x] SubTask 2.4: 1.d/1.d.1 密码哈希独立性
  - [x] SubTask 2.5: 1.e 数据持久化

- [x] Task 3: 场景 2 - 审批流程深度测试 (8 用例)
  - [x] SubTask 3.1: 2.a EnsureDefaultAdmin
  - [x] SubTask 3.2: 2.b GetPendingUsers
  - [x] SubTask 3.3: 2.c 单个 Approve
  - [x] SubTask 3.4: 2.d 批量 Approve
  - [x] SubTask 3.5: 2.e Reject
  - [x] SubTask 3.6: 2.f 非 admin 拒绝
  - [x] SubTask 3.7: 2.g admin 自改权限被拒
  - [x] SubTask 3.8: 2.h 审计验证

- [x] Task 4: 场景 3 - 资产登记流程深度测试 (10 用例)
  - [x] SubTask 4.1: 3.a 无 Asset:Add 被拒
  - [x] SubTask 4.2: 3.b/3.b.1 有权限可加可见
  - [x] SubTask 4.3: 3.c UpdateAssetAsync 校验
  - [x] SubTask 4.4: 3.d.1/3.d.2/3.d.3 Delete 校验 + 列表更新
  - [x] SubTask 4.5: 3.e/3.e.1 Import 校验
  - [x] SubTask 4.6: 3.f Asset:Export 权限位

- [x] Task 5: 场景 4 - 权限模板与权限编辑深度测试 (6 用例)
  - [x] SubTask 5.1: 4.a 模板数 3
  - [x] SubTask 5.2: 4.b Viewer
  - [x] SubTask 5.3: 4.c Operator
  - [x] SubTask 5.4: 4.d AssetManager
  - [x] SubTask 5.5: 4.e/4.e.1 套用模板 + 审计

- [x] Task 6: 场景 5 - 审计日志深度测试 (4 用例)
  - [x] SubTask 6.1: 5.a 7 种动作
  - [x] SubTask 6.2: 5.b ClearAuditLogAsync
  - [x] SubTask 6.3: 5.c 字段合法性
  - [x] SubTask 6.4: 5.d 失败注册审计

- [x] Task 7: 场景 6 - 边界与异常深度测试 (4 用例)
  - [x] SubTask 7.1: 6.a 5 次密码错误锁 60s
  - [x] SubTask 7.2: 6.b Disabled 登录被拒
  - [x] SubTask 7.3: 6.c 登出后再登
  - [x] SubTask 7.4: 6.e AdminResetPassword 后用新密码

- [x] Task 8: 场景 7 - 数据隔离深度测试 (3 用例)
  - [x] SubTask 8.1: 7.a 互不可见
  - [x] SubTask 8.2: 7.b 物理目录隔离
  - [x] SubTask 8.3: 7.c service 实例隔离

- [x] Task 9: 场景 8 - WPF 实际可交互性校验 (6 用例)
  - [x] SubTask 9.1: 8.a 可执行文件存在
  - [x] SubTask 9.2: 8.b 关键 XAML 齐全
  - [x] SubTask 9.3: 8.c UserApprovalWindow.xaml.cs 含 BatchApprove 调用
  - [x] SubTask 9.4: 8.d MainWindow 含待审用户定时器
  - [x] SubTask 9.5: 8.e WPF 进程检查
  - [x] SubTask 9.6: 8.f 生成 WpfInteractionProbe.ps1

- [x] Task 10: 编译 + 跑全套测试 + 输出报告
  - [x] SubTask 10.1: `dotnet build -c Release` 0 error
  - [x] SubTask 10.2: `dotnet run` 52/52 全部通过
  - [x] SubTask 10.3: 输出 `test-report/deep-test-report.md`

# Task Dependencies
- Task 2、3、4、5、6、7、8 依赖 Task 1
- Task 9 依赖 Task 2-8
- Task 10 依赖所有上述 Task
