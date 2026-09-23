# AI 风险评估重新设计 v2 - 检查清单

## 删除工作验证

### 菜单栏入口
- [x] MainWindow.xaml 中"分析"菜单下"AI风险评估" MenuItem 已删除
- [x] "分析"菜单下其他子项（统计分析、可视化图表、网络拓扑、攻击路径分析、攻击日志查询）保持完整

### TabItem 旧内容
- [x] MainWindow.xaml 中原"AI风险评估" TabItem（行 806-1635）已完全删除
- [x] 原 TabItem 中的所有命名控件（OverallRiskText、RiskScoreText、AiAnalysisProgressBar、AiAnalysisStatusText、RefreshAiAnalysisButton、AiAnalysisSubStatusText、AssessmentDateText、TargetIpText、AssessmentTimeText、HighRiskCountText、OpenPortsCountText、RiskDistributionPieChart、RiskDistributionBarChart、VulnerabilityDetailsDataGrid、GeneratePortBatFromAiButton、OpenPortsDataGrid、RiskAssessmentSummaryText、RiskProgressBar）已全部移除
- [x] MainWindow.xaml 顶部 `xmlns:lvc` 命名空间若不再被其他 Tab 使用则已删除

### MainWindow.xaml.cs 方法清理
- [x] `RefreshAiAnalysis_Click` 方法已删除
- [x] `StartAiRiskAssessmentAsync` 方法已删除
- [x] `UpdateAiAnalysisStatus` 方法已删除
- [x] `UpdateAiRiskAssessment` 方法已删除
- [x] `UpdateGeneratePortBatFromAiButton` 方法已删除，调用点（行 539、1548）已清理
- [x] `GeneratePortBatFromAi_Click` 方法已删除
- [x] `AIRiskAssessment_Click` 方法已删除
- [x] 扫描完成钩子中对旧方法的调用已替换为新方法

### 独立窗口文件
- [x] `NetSecurityScanner/src/NetSecurityScanner.Desktop/Views/Views/AIRiskAssessmentWindow.xaml` 已删除
- [x] `NetSecurityScanner/src/NetSecurityScanner.Desktop/Views/Views/AIRiskAssessmentWindow.xaml.cs` 已删除
- [x] `NetSecurityScanner/src/NetSecurityScanner.Desktop/Views/Views/AIRiskAssessmentWindow.xaml.backup` 已删除
- [x] `NetSecurityScanner/src/NetSecurityScanner.Desktop/Views/Views/AIRiskAssessmentWindow.xaml.cs.backup` 已删除
- [x] `NetSecurityScanner/src/NetSecurityScanner/Views/AIRiskAssessmentWindow.xaml` 已删除
- [x] `NetSecurityScanner/src/NetSecurityScanner/Views/AIRiskAssessmentWindow.xaml.cs` 已删除
- [x] `NetSecurityScanner/src/NetSecurityScanner/Views/AIRiskAssessmentWindow.xaml.backup` 已删除
- [x] `NetSecurityScanner/src/NetSecurityScanner/Views/AIRiskAssessmentWindow.xaml.cs.backup` 已删除

## 新设计验证

### XAML 结构
- [x] 新"AI风险评估" TabItem 已插入到原位置（端口扫描、漏洞扫描之后，扫描历史记录之前）
- [x] TabItem 根 Grid 使用 `Background="#0a0e17"`
- [x] TabItem 包含 4 行：状态条、主评分卡片、四宫格指标卡片、风险分布条形图
- [x] 空状态提示卡片存在且默认显示

### 评估状态条
- [x] 包含 AI 图标（Emoji 或 Path）
- [x] 包含状态文字 TextBlock
- [x] 包含 ProgressBar
- [x] 包含"重新分析"按钮
- [x] 按钮点击事件绑定到 `RefreshAiRiskDashboard_Click`

### 主评分卡片
- [x] 居中显示综合风险评分（保留 1 位小数）
- [x] 评分下方显示风险等级标签
- [x] 卡片左上角显示目标 IP
- [x] 卡片右上角显示评估时间戳
- [x] 评分颜色根据等级动态变化
- [x] 卡片背景使用深色渐变

### 四宫格指标卡片
- [x] 4 张卡片横向等宽排列
- [x] 分别展示：开放端口数、漏洞总数、高危漏洞数、CVE 关联数
- [x] 每张卡片包含图标、标签、数值、趋势条

### 风险分布条形图
- [x] 4 行（严重/高危/中危/低危）
- [x] 每行包含颜色圆点、等级名称、进度条、数值
- [x] 进度条使用对应等级颜色渐变
- [x] 数量为 0 时仅显示 0

### 配色与字体
- [x] 配色严格遵循 spec 中的颜色规范（深色主题 + 紫蓝渐变 + 风险等级色）
- [x] 字体大小符合规范（主评分 48px、指标数值 24px 等）
- [x] 间距符合规范（卡片间 12px、内边距 20px、圆角 8-12px）

## C# 交互逻辑验证

### 新增方法
- [x] `RefreshAiRiskDashboard_Click` 方法已实现
- [x] `RunAiRiskAssessmentAsync` 方法已实现，调用 `AIRiskAssessmentService.AssessRiskV5Async`
- [x] `UpdateAiRiskDashboard(AIRiskAssessmentReportV5 report)` 方法已实现，更新所有仪表盘控件
- [x] `UpdateAiRiskDashboardStatus(string status, int progress, bool isRunning)` 方法已实现
- [x] `ShowAiRiskEmptyState()` 方法已实现

### 数据流
- [x] "重新分析"按钮从 MainWindow 实例字段获取最新 `_portScanResults` 和 `_vulnerabilityResults`
- [x] 扫描完成钩子调用新的 `RunAiRiskAssessmentAsync`
- [x] 评估过程中按钮禁用，状态条显示"分析中..."
- [x] 评估完成后更新所有控件并恢复按钮
- [x] 评估失败显示错误提示并恢复按钮

### 空状态
- [x] 应用启动后仪表盘默认显示空状态
- [x] 无扫描数据时隐藏所有数据卡片和图表
- [x] "重新分析"按钮在空状态下禁用

## 编译与运行验证
- [x] NetSecurityScanner.Desktop 项目编译无错误
- [x] NetSecurityScanner.Core 项目编译无错误
- [x] 无未使用的 `using` 引用警告
- [x] .csproj 文件无对已删除文件的引用
- [x] 应用启动正常，可切换到"AI风险评估" Tab
- [x] 无扫描数据时空状态显示正确
- [x] 执行端口扫描后自动触发评估，仪表盘数据更新
- [x] 点击"重新分析"按钮可手动刷新数据
