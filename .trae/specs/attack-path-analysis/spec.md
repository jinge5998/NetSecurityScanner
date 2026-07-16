# 攻击路径分析功能规范

## Why
当前"分析"菜单栏中的"攻击路径分析"功能仅显示占位提示，需要实现完整的攻击路径分析功能，帮助用户可视化潜在的攻击路径，评估安全风险，并提供针对性的防御建议。

## What Changes
- 创建AttackPathAnalysisWindow.xaml和AttackPathAnalysisWindow.xaml.cs
- 实现攻击路径可视化界面，包含路径图、风险评分、攻击步骤等
- 集成现有RiskAssessmentService中的GenerateAttackPaths方法
- 添加交互式攻击路径展示，支持点击查看详细信息
- 提供防御建议和风险缓解措施

## Impact
- Affected specs: 新增攻击路径分析能力
- Affected code: 
  - MainWindow.xaml.cs - ViewAttackPaths_Click方法
  - RiskAssessmentService.cs - 已有攻击路径生成逻辑
  - TargetRiskProfile.cs - AttackPath模型
  - 新增AttackPathAnalysisWindow.xaml/cs

## ADDED Requirements
### Requirement: 攻击路径分析窗口
系统 SHALL 提供攻击路径分析窗口，展示从扫描结果中生成的攻击路径。

#### Scenario: 打开攻击路径分析窗口
- **WHEN** 用户点击"分析"菜单中的"攻击路径分析"
- **THEN** 显示攻击路径分析窗口，包含路径列表、可视化图表和详细信息

#### Scenario: 显示攻击路径列表
- **WHEN** 攻击路径分析窗口加载
- **THEN** 显示所有检测到的攻击路径，包括名称、风险评分、复杂度、成功概率

#### Scenario: 查看攻击路径详情
- **WHEN** 用户点击某个攻击路径
- **THEN** 显示该路径的详细信息，包括攻击步骤、潜在影响、防御建议

#### Scenario: 可视化攻击路径图
- **WHEN** 用户选择攻击路径
- **THEN** 显示图形化的攻击路径流程图，展示每个攻击步骤

## MODIFIED Requirements
### Requirement: 菜单栏点击事件
MainWindow.xaml.cs中的ViewAttackPaths_Click方法 SHALL 打开AttackPathAnalysisWindow窗口，而非显示占位提示。

## REMOVED Requirements
**Reason**: 功能正在开发中的占位提示
**Migration**: 用完整的攻击路径分析窗口替换
