# 摄像头安全扫描 v4 Spec

## Why
现有摄像头扫描已支持 4 套预设、智能推荐、模板、持续监控、cron、告警、基线、黑白名单、CSV/JSON 导出，但**缺少**：
- 直观的扫描统计图表（用户对扫描概况感知弱）
- 摄像头分组/标签管理（IP 多时缺乏组织）
- 右键菜单与详情弹窗（操作效率低）
- 弱口令字典自定义（出厂字典无法应对特殊场景）
- 历史趋势分析（无法看出摄像头安全态势变化）

## What Changes
- 新增扫描统计图表（顶部 RiskDashboard）
- 新增摄像头分组/标签管理（CameraTag 模型 + 标签管理窗口）
- 新增 DataGrid 右键菜单 + 详情弹窗
- 新增弱口令字典编辑器
- 新增历史趋势图窗口

## Impact
- Affected specs: enhance-camera-scan-and-plugin-v2
- Affected code:
  - NetSecurityScanner.Core/Models/CameraTag.cs（新）
  - NetSecurityScanner.Core/Services/CameraTagService.cs（新）
  - NetSecurityScanner.Core/Services/CameraWeakPasswordDictService.cs（新）
  - NetSecurityScanner.Core/Services/CameraTrendService.cs（新）
  - NetSecurityScanner.Core/Services/CameraScanStatisticsService.cs（新）
  - NetSecurityScanner.Desktop/Views/Views/CameraSecurityScannerWindow.xaml(.cs)（大幅增强）
  - NetSecurityScanner.Desktop/Views/Views/CameraDetailWindow.xaml(.cs)（新）
  - NetSecurityScanner.Desktop/Views/Views/CameraTagManageWindow.xaml(.cs)（新）
  - NetSecurityScanner.Desktop/Views/Views/CameraWeakPasswordEditorWindow.xaml(.cs)（新）
  - NetSecurityScanner.Desktop/Views/Views/CameraTrendWindow.xaml(.cs)（新）

## ADDED Requirements

### Requirement: 扫描统计图表
顶部 RiskDashboard 实时显示：严重/高/中/低/信息漏洞计数卡片、Top 5 厂商分布、Top 5 漏洞类型分布、在线率仪表盘。
#### Scenario: 扫描完成后
- **WHEN** 扫描完成
- **THEN** 顶部 Dashboard 自动更新所有统计数据

### Requirement: 摄像头分组/标签
支持给摄像头打标签（多对多），扫描时可按标签过滤，结果按标签分组显示。
#### Scenario: 创建标签
- **WHEN** 用户在标签管理窗口创建"前台""机房"两个标签，给 3 个 IP 打上"前台"
- **THEN** 扫描窗口可按"前台"过滤，结果按"前台"分组

### Requirement: 右键菜单+详情弹窗
DataGrid 支持右键菜单：查看详情、复制IP、复制CVE、过滤同厂商、跳转CVE详情。
#### Scenario: 右键点击结果
- **WHEN** 用户在 DataGrid 行上右键
- **THEN** 弹出 5 项菜单，点击"查看详情"打开详情窗口

### Requirement: 弱口令字典编辑器
可视化编辑器：列表展示当前字典、增删改、导入/导出 txt。
#### Scenario: 添加自定义口令
- **WHEN** 用户添加 5 个自定义口令
- **THEN** 字典保存到 data/camera_weak_passwords.json，下次扫描时优先使用

### Requirement: 历史趋势图
独立窗口显示：摄像头总数/在线数/漏洞总数随日期变化曲线，支持选择多个历史会话对比。
#### Scenario: 查看趋势
- **WHEN** 用户打开趋势窗口
- **THEN** 显示最近 30 天每日摄像头总数折线图
