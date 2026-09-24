# Tasks - AI 风险评估重新设计 v2

## 任务概述
删除现有 AI 风险评估的所有 UI 实现（菜单入口、TabItem、独立窗口），并在 MainWindow TabControl 中重新设计一个现代 SOC 风格的风险评分仪表盘。仅保留核心评分展示功能，复用现有 `AIRiskAssessmentService` 算法。

## 任务列表

- [x] Task 1: 删除 MainWindow.xaml 中的旧 AI 风险评估 UI 入口
  - [x] Task 1.1: 删除菜单项"分析 → AI风险评估"（MainWindow.xaml 行 99-100）
  - [x] Task 1.2: 删除 TabItem "AI风险评估" 完整内容（MainWindow.xaml 行 806-1635）
  - [x] Task 1.3: 验证 MainWindow.xaml 顶部 `xmlns:lvc` 命名空间引用是否仍被其他 Tab 使用，若不再使用则删除

- [x] Task 2: 删除 MainWindow.xaml.cs 中的旧 AI 风险评估方法
  - [x] Task 2.1: 删除 `RefreshAiAnalysis_Click`（行 609 起）
  - [x] Task 2.2: 删除 `StartAiRiskAssessmentAsync`（行 636 起）
  - [x] Task 2.3: 删除 `UpdateAiAnalysisStatus`（行 765 起）
  - [x] Task 2.4: 删除 `UpdateAiRiskAssessment`（行 1337 起）
  - [x] Task 2.5: 删除 `UpdateGeneratePortBatFromAiButton`（行 1588 起）和调用点（行 539、1548）
  - [x] Task 2.6: 删除 `GeneratePortBatFromAi_Click`（行 1614 起）
  - [x] Task 2.7: 删除 `AIRiskAssessment_Click`（行 4684 起）
  - [x] Task 2.8: 清理扫描完成后自动触发 AI 风险评估的旧调用（行 1025-1039、1265-1282），保留触发意图但改为调用新的方法名

- [x] Task 3: 删除独立窗口文件
  - [x] Task 3.1: 删除 `NetSecurityScanner/src/NetSecurityScanner.Desktop/Views/Views/AIRiskAssessmentWindow.xaml`
  - [x] Task 3.2: 删除 `NetSecurityScanner/src/NetSecurityScanner.Desktop/Views/Views/AIRiskAssessmentWindow.xaml.cs`
  - [x] Task 3.3: 删除 `NetSecurityScanner/src/NetSecurityScanner.Desktop/Views/Views/AIRiskAssessmentWindow.xaml.backup`
  - [x] Task 3.4: 删除 `NetSecurityScanner/src/NetSecurityScanner.Desktop/Views/Views/AIRiskAssessmentWindow.xaml.cs.backup`
  - [x] Task 3.5: 删除 `NetSecurityScanner/src/NetSecurityScanner/Views/AIRiskAssessmentWindow.xaml`
  - [x] Task 3.6: 删除 `NetSecurityScanner/src/NetSecurityScanner/Views/AIRiskAssessmentWindow.xaml.cs`
  - [x] Task 3.7: 删除 `NetSecurityScanner/src/NetSecurityScanner/Views/AIRiskAssessmentWindow.xaml.backup`
  - [x] Task 3.8: 删除 `NetSecurityScanner/src/NetSecurityScanner/Views/AIRiskAssessmentWindow.xaml.cs.backup`

- [x] Task 4: 在 MainWindow.xaml 中新增现代 SOC 风险"AI风险评估" TabItem
  - [x] Task 4.1: 在原 TabItem 位置（行 806）插入新的"AI风险评估" TabItem 结构骨架
  - [x] Task 4.2: 实现评估状态条（含 AI 图标、状态文字、进度条、重新分析按钮）
  - [x] Task 4.3: 实现主评分卡片（综合风险评分 + 等级标签 + 目标 IP + 时间戳）
  - [x] Task 4.4: 实现四宫格指标卡片（开放端口数、漏洞总数、高危漏洞数、CVE 关联数）
  - [x] Task 4.5: 实现风险分布横向条形图（严重/高危/中危/低危四行）
  - [x] Task 4.6: 实现空状态提示卡片
  - [x] Task 4.7: 在 Window.Resources 中添加必要的样式资源（颜色画刷、按钮样式）

- [x] Task 5: 在 MainWindow.xaml.cs 中实现新仪表盘交互逻辑
  - [x] Task 5.1: 添加新方法 `RefreshAiRiskDashboard_Click` 处理"重新分析"按钮点击
  - [x] Task 5.2: 添加新方法 `RunAiRiskAssessmentAsync` 调用 `AIRiskAssessmentService.AssessRiskV5Async`
  - [x] Task 5.3: 添加新方法 `UpdateAiRiskDashboard(AIRiskAssessmentReportV5 report)` 更新所有仪表盘控件
  - [x] Task 5.4: 添加新方法 `UpdateAiRiskDashboardStatus(string status, int progress, bool isRunning)` 更新状态条
  - [x] Task 5.5: 添加新方法 `ShowAiRiskEmptyState()` 显示空状态提示
  - [x] Task 5.6: 修改扫描完成钩子（原行 1025、1265 附近）调用新的 `RunAiRiskAssessmentAsync`
  - [x] Task 5.7: 在 MainWindow 构造函数或 Loaded 事件中初始化仪表盘为空状态

- [x] Task 6: 编译验证与修复
  - [x] Task 6.1: 编译 NetSecurityScanner.Desktop 项目，修复所有编译错误
  - [x] Task 6.2: 检查是否有遗漏的引用（如 `using LiveChartsCore` 在 MainWindow.xaml.cs 中是否仍需要）
  - [x] Task 6.3: 检查 .csproj 文件是否需要移除对已删除文件的引用
  - [x] Task 6.4: 运行应用验证 Tab 切换、空状态、重新分析按钮功能正常

## 任务依赖
- Task 1、Task 2、Task 3 可以并行进行（删除工作）
- Task 4 依赖于 Task 1 完成（位置腾出）
- Task 5 依赖于 Task 2 和 Task 4 完成
- Task 6 依赖于 Task 1-5 全部完成

## 技术栈
- .NET 6.0 WPF
- C# 8.0+
- XAML（仅原生 WPF 控件，不引入新图表库）
- 复用 `NetSecurityScanner.Core.Services.AIRiskAssessmentService`
- 复用 `NetSecurityScanner.Core.Models.AIRiskAssessmentModelsV5`
