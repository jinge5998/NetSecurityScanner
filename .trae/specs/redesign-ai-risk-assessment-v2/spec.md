# AI 风险评估重新设计 Spec (v2)

## Why
当前 AI 风险评估界面在 MainWindow TabItem（行 806-1635）和独立窗口 `AIRiskAssessmentWindow` 中存在双份实现，视觉臃肿、信息密度低、配色杂乱，用户反馈"界面太丑"。同时菜单栏"分析 → AI风险评估"打开的独立窗口与 TabItem 功能重复，需要清理冗余并重新设计为单一、简洁、专业的现代化 SOC 风险评分仪表盘。

## What Changes
- **BREAKING** 删除 MainWindow 顶部菜单"分析 → AI风险评估"入口（MainWindow.xaml 行 99-100）
- **BREAKING** 删除 MainWindow TabControl 中现有的"AI风险评估" TabItem（MainWindow.xaml 行 806-1635）及其所有相关控件
- **BREAKING** 删除独立窗口文件 `Views/Views/AIRiskAssessmentWindow.xaml(.cs)` 及其 `.backup` 备份
- **BREAKING** 删除 NetSecurityScanner 旧版同名窗口文件 `NetSecurityScanner/Views/AIRiskAssessmentWindow.xaml(.cs)` 及其 `.backup` 备份
- 删除 MainWindow.xaml.cs 中所有原 AI 风险评估相关的事件处理方法（`AIRiskAssessment_Click`、`RefreshAiAnalysis_Click`、`StartAiRiskAssessmentAsync`、`UpdateAiAnalysisStatus`、`UpdateAiRiskAssessment`、`UpdateGeneratePortBatFromAiButton`、`GeneratePortBatFromAi_Click`），并清理对它们的调用点
- 在 MainWindow TabControl 中新增一个全新的"AI风险评估" TabItem，采用现代 SOC 风格的风险评分仪表盘
- 复用现有的 `AIRiskAssessmentService` 和 `AIRiskAssessmentModelsV5` 数据模型，不改动算法逻辑
- 保留扫描完成后自动触发 AI 风险评估的钩子（重构调用方式）

## Impact
- Affected specs:
  - `ai-risk-assessment-ui-optimization`（旧版 UI 优化，本 spec 取代之）
  - `add-comprehensive-scan`（综合扫描流程中引用 AI 风险评估）
- Affected code:
  - `NetSecurityScanner/src/NetSecurityScanner.Desktop/MainWindow.xaml`（菜单项删除 + TabItem 重写）
  - `NetSecurityScanner/src/NetSecurityScanner.Desktop/MainWindow.xaml.cs`（删除 7 个旧方法 + 新增 Tab 内交互逻辑）
  - `NetSecurityScanner/src/NetSecurityScanner.Desktop/Views/Views/AIRiskAssessmentWindow.xaml(.cs)` 及 `.backup`（删除）
  - `NetSecurityScanner/src/NetSecurityScanner/Views/AIRiskAssessmentWindow.xaml(.cs)` 及 `.backup`（删除）
  - `NetSecurityScanner/src/NetSecurityScanner.Core/Services/AIRiskAssessmentService.cs`（保留，仅复用）
  - `NetSecurityScanner/src/NetSecurityScanner.Core/Models/AIRiskAssessmentModelsV5.cs`（保留，仅复用）

## ADDED Requirements

### Requirement: 现代 SOC 风格风险评分仪表盘
系统 SHALL 在 MainWindow TabControl 中提供一个全新的"AI风险评估" TabItem，采用现代安全运营中心（SOC）风格设计，专注于风险评分核心数据的清晰呈现。

#### Scenario: 仪表盘顶部主评分卡片
- **WHEN** 用户切换到"AI风险评估" TabItem
- **THEN** 顶部展示一张大尺寸主评分卡片，居中显示综合风险评分（0.0 - 10.0，保留一位小数）
- **AND** 评分下方显示风险等级文字标签（"无风险" / "低风险" / "中风险" / "高风险" / "严重风险"）
- **AND** 评分数字颜色根据等级动态变化（无风险 #22c55e / 低风险 #84cc16 / 中风险 #eab308 / 高风险 #f97316 / 严重风险 #ef4444）
- **AND** 卡片背景使用深色渐变（#0f172a → #1e293b），圆角 12px，带柔和阴影
- **AND** 卡片左上角显示评估目标 IP，右上角显示评估时间戳

#### Scenario: 关键指标四宫格卡片
- **WHEN** 仪表盘渲染完成
- **THEN** 主评分卡片下方展示 4 张统计子卡片，横向等宽排列
- **AND** 四张卡片分别展示：开放端口数、漏洞总数、高危漏洞数、CVE 关联数
- **AND** 每张卡片包含：图标（Emoji）、指标标签（小字号灰色）、数值（大字号白色加粗）、趋势条（细横向进度条）
- **AND** 卡片背景为半透明深色（#1a2234），圆角 8px，悬停时轻微亮起

#### Scenario: 风险分布条形图
- **WHEN** 仪表盘渲染完成
- **THEN** 四宫格下方展示一个横向条形图，显示四个风险等级（严重/高危/中危/低危）的数量分布
- **AND** 每个等级一行，包含：左侧颜色圆点 + 等级名称、中间横向进度条（宽度按占比）、右侧数值
- **AND** 进度条使用对应等级颜色的渐变填充
- **AND** 当某等级数量为 0 时，进度条不显示，仅显示数值 0

#### Scenario: 评估状态条
- **WHEN** 仪表盘顶部
- **THEN** 主评分卡片上方显示一个细长状态条
- **AND** 包含 AI 图标、当前状态文字（"就绪" / "分析中..." / "分析完成" / "分析失败"）、进度百分比
- **AND** 状态条右侧包含"重新分析"按钮（深色背景 + 紫蓝渐变边框）
- **AND** 分析进行中按钮禁用，进度条流动显示

#### Scenario: 空数据状态
- **WHEN** 没有扫描结果时切换到"AI风险评估"Tab
- **THEN** 仪表盘中央显示空状态提示卡片
- **AND** 包含图标、提示文字"暂无扫描数据，请先执行端口扫描或漏洞扫描"
- **AND** 隐藏所有数据卡片和图表
- **AND** "重新分析"按钮禁用

### Requirement: 数据源与刷新机制
系统 SHALL 复用现有 `AIRiskAssessmentService` 进行风险评估，并提供从 MainWindow 获取最新扫描数据的刷新机制。

#### Scenario: 重新分析按钮触发
- **WHEN** 用户点击"重新分析"按钮
- **THEN** 从 MainWindow 当前实例获取最新的 `_portScanResults` 和 `_vulnerabilityResults`
- **AND** 调用 `AIRiskAssessmentService.AssessRiskAsync` 异步执行评估
- **AND** 评估过程中更新状态条为"分析中..."并禁用按钮
- **AND** 评估完成后更新所有仪表盘组件并恢复按钮
- **AND** 评估失败时显示错误提示并恢复按钮

#### Scenario: 扫描完成后自动触发
- **WHEN** 端口扫描或漏洞扫描完成且有扫描结果
- **THEN** 自动触发 AI 风险评估（不阻塞 UI 线程）
- **AND** 评估完成后自动更新仪表盘数据
- **AND** 用户在 Tab 未激活时不会被打断，下次切换到 Tab 时立即看到最新结果

### Requirement: 现代 SOC 视觉规范
系统 SHALL 遵循现代安全运营中心的视觉规范。

#### Scenario: 配色方案
- **WHEN** 渲染仪表盘
- **THEN** 使用深色主题：
  - 主背景: `#0a0e17`
  - 卡片背景: `#1a2234`（主）/ `#111827`（次）
  - 边框: `#1f2937`
  - 主文字: `#f1f5f9`
  - 次文字: `#94a3b8`
  - 弱文字: `#64748b`
- **AND** 强调色使用紫蓝渐变 `#6366f1` → `#8b5cf6`
- **AND** 风险等级色：
  - 严重: `#ef4444`
  - 高危: `#f97316`
  - 中危: `#eab308`
  - 低危: `#22c55e`
  - 无风险: `#22c55e`

#### Scenario: 字体规范
- **WHEN** 渲染文本
- **THEN** 主评分数字: 48px Bold
- **AND** 风险等级标签: 16px SemiBold
- **AND** 卡片指标数值: 24px Bold
- **AND** 卡片指标标签: 11px SemiBold
- **AND** 状态文字: 13px Medium
- **AND** 提示文字: 12px Regular

#### Scenario: 间距与圆角规范
- **WHEN** 布局卡片
- **THEN** 卡片之间间距 12px
- **AND** 卡片内边距 20px
- **AND** TabItem 整体外边距 15px
- **AND** 卡片圆角 8-12px
- **AND** 按钮 圆角 6px

## MODIFIED Requirements

### Requirement: MainWindow 菜单结构
MainWindow 顶部菜单"分析"下移除"AI风险评估"子项，保留其他分析功能（统计分析、可视化图表、网络拓扑、攻击路径分析、攻击日志查询）。

### Requirement: MainWindow TabControl 结构
MainWindow TabControl 中的"AI风险评估" TabItem 重新设计为 SOC 风格仪表盘，原 TabItem 中的所有控件（包括 PieChart、CartesianChart、DataGrid、GeneratePortBatFromAiButton 等）全部移除，新 TabItem 不再包含复杂图表组件，仅使用原生 WPF 控件（Border、TextBlock、ProgressBar、Grid、StackPanel）实现。

## REMOVED Requirements

### Requirement: 独立 AI 风险评估窗口
**Reason**: 与 MainWindow TabItem 功能重复，造成代码冗余和维护负担。用户选择在 TabItem 中集中展示。
**Migration**: 删除独立窗口文件 `AIRiskAssessmentWindow.xaml(.cs)`，所有逻辑迁移到 MainWindow.xaml.cs 中。

### Requirement: 旧 TabItem 中的复杂图表
**Reason**: 用户反馈"界面太丑"，PieChart、CartesianChart 等图表组件视觉杂乱且数据展示不清晰。新设计使用原生 WPF 控件实现简洁的条形图和进度条。
**Migration**: 移除 LiveChartsCore 在 TabItem 中的使用，仪表盘仅使用 Border/ProgressBar 等原生控件。独立窗口中如仍需要可保留 LiveChartsCore 引用。

### Requirement: 旧 TabItem 中的 DataGrid 详情
**Reason**: 用户功能范围选择仅保留"风险评分仪表盘"，不再包含风险项详细列表和导出功能。
**Migration**: 移除 `VulnerabilityDetailsDataGrid`、`OpenPortsDataGrid`、`GeneratePortBatFromAiButton`、`RiskAssessmentSummaryText` 等控件及相关方法。

### Requirement: 旧 TabItem 中的报告导出和端口脚本生成
**Reason**: 用户未选择该功能范围。
**Migration**: 移除 `GeneratePortBatFromAi_Click`、`UpdateGeneratePortBatFromAiButton` 方法及相关调用。
