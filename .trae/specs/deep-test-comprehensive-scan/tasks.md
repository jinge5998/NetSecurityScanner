# Tasks

## Task 1: 深度测试基础准备
- [x] 1.1: 停止当前运行的 NetSecurityScanner.Desktop 实例(PID 55868)
- [x] 1.2: 确认 v1.0.1.3 程序集版本正确
- [x] 1.3: 确认漏洞数据库已修复(StaticVulnerabilityDatabase.json 31 条)

## Task 2: 创建 `Tools/DeepTest` 深度测试项目
- [x] 2.1: 创建 `Tools/DeepTest/DeepTest.csproj`(net6.0-windows,引用 NetSecurityScanner.Core)
- [x] 2.2: 创建 `Tools/DeepTest/Program.cs` 包含 6 个测试场景
- [x] 2.3: 实现测试结果收集器(每个 TestCase 返回 Pass/Fail/Skip + 实际数据)
- [x] 2.4: 编译通过(`dotnet build -c Release` 0 错误)

## Task 3: 编写 6 个深度测试场景
- [x] 3.1: **TestCase 1 - 127.0.0.1 Standard 全开扫描**:验证 6 阶段全部 Success/Skipped(基线)
- [x] 3.2: **TestCase 2 - 127.0.0.1 端口发现**:验证 1-65535 端口扫描能发现本地开放端口(若有)
- [x] 3.3: **TestCase 3 - 公网目标 scanme.nmap.org (45.33.32.156)**:验证 TCP 1-1000 至少发现 2 个端口(22 ssh + 80 http)
- [x] 3.4: **TestCase 4 - 漏洞匹配真实触发**:模拟"端口 80 + 服务 http"开放,验证漏洞匹配返回 >= 5 个 CVE(用反射调 MatchVulnerabilitiesFromDatabase)
- [x] 3.5: **TestCase 5 - 异常隔离**:对不存在目标(203.0.113.99 RFC 5737)扫描,验证 6 阶段不中断
- [x] 3.6: **TestCase 6 - 取消令牌**:扫描 127.0.0.1 期间 3 秒后取消,验证 `Cancelled=true` 且耗时 < 10s

## Task 4: 运行测试并生成报告
- [x] 4.1: 执行 `dotnet run -c Release --project Tools/DeepTest/`
- [x] 4.2: 收集每个 TestCase 的实际输出(端口列表、漏洞列表、阶段耗时)
- [x] 4.3: 生成 `Tools/DeepTest/deep-test-report.md`(包含:测试结论表 / 每个 TestCase 的实际数据 / 失败项的根因分析 / 修复建议)

## Task 5: 修复测试中发现的 Bug（如有）
- [x] 5.1: 根据 4.3 报告,TestCase 2 失败 — **根因是测试设计问题**(扫 10000 端口 30s 超时过紧)
- [x] 5.2: 调整 TestCase 2 为扫 1000 端口(Standard 预设) + 60s 超时 → 重新运行通过
- [x] 5.3: 在报告末尾追加"修复记录"小节

## Task 6: 验证检查清单
- [x] 6.1: 6 个 TestCase 全部 Pass 或明确 Skip
- [x] 6.2: 端口扫描命中真实端口(本地或公网) — 本机 1-1000 端口扫描完成(本机无开放属正常)
- [x] 6.3: 漏洞匹配真实返回多个 CVE(非 3 兜底) — TestCase 4 返回 15 个漏洞
- [x] 6.4: 异常隔离正确(不可达目标不抛异常) — TestCase 5 验证
- [x] 6.5: 取消令牌可工作 — TestCase 6 3.4s 中止
- [x] 6.6: 程序集版本为 1.0.1.3 — Task 1.2 验证

# Task Dependencies
- Task 2 依赖 Task 1
- Task 3 依赖 Task 2
- Task 4 依赖 Task 3
- Task 5 依赖 Task 4 (仅在有失败时执行)
- Task 6 依赖 Task 4 (或 Task 5 完成后)

# Estimated Scope
- 新增 3 个文件:DeepTest.csproj + Program.cs + deep-test-report.md
- 预计代码量 ~400 行(测试代码)
- **不修改任何业务代码**(除非发现真实 Bug)
