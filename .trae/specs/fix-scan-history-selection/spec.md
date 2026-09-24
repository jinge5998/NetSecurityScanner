# 扫描历史记录勾选/选择功能完善 Spec

## Why
扫描历史记录窗口的第一列目前显示为 CheckBox 方框，用户无法正常点击勾选。需要将第一列改为序号列（#），点击序号可选中/取消选中行，支持多选后批量生成报告。

## What Changes
- **第一列从 CheckBox 改为序号列 (#)**：显示 1, 2, 3... 序号，点击可切换选中状态
- **选中状态视觉反馈**：未选中=白色背景+深灰数字；选中=橙色背景(#FFC107)+白色数字
- **自动排序**：按扫描时间降序排列，最新扫描排在最上面
- **多种选择方式**：点击序号、右键行、双击行、全选/反选按钮
- **多选批量操作**：选中多条记录后可批量生成报告或删除

## Impact
- Affected specs: 无直接依赖
- Affected code:
  - `ScanHistoryWindow.xaml` - DataGrid 第一列定义
  - `ScanHistoryWindow.xaml.cs` - ApplyFilters 排序逻辑、选择事件处理
  - `ScanHistoryItem.cs` - SelectableScanHistory 模型 + 转换器

## ADDED Requirements

### Requirement: 序号列显示与选中功能
系统 SHALL 在扫描历史记录 DataGrid 的第一列显示序号（#），用户点击序号区域可切换该行的选中状态。

#### Scenario: 点击序号切换选中状态
- **WHEN** 用户左键单击第一列的序号区域
- **THEN** 该行的选中状态被切换（选中↔未选中），序号单元格背景变为橙色(#FFC107)、文字变白色

#### Scenario: 序号自动编号
- **WHEN** 扫描历史记录加载完成
- **THEN** 第一列显示连续序号 1, 2, 3 ... N，最新扫描的记录排在最上面（序号为1）

#### Scenario: 多选支持
- **WHEN** 用户依次点击多个序号
- **THEN** 每个被点击的行独立切换选中状态，底部"已选"计数实时更新

### Requirement: 选择状态的视觉反馈
系统 SHALL 为选中和未选中状态提供清晰的视觉区分。

#### Scenario: 未选中状态
- **WHEN** 行未被选中
- **THEN** 序号单元格显示白色背景 + 深灰色(#505050) 数字

#### Scenario: 已选中状态
- **WHEN** 行已被选中
- **THEN** 序号单元格显示橙色(#FFC107)背景 + 白色数字，整行显示浅黄色高亮边框

### Requirement: 多种选择交互方式
系统 SHALL 提供多种方式让用户选择扫描记录。

#### Scenario: 右键点击选择
- **WHEN** 用户右键点击某一行
- **THEN** 该行切换选中状态，不弹出右键菜单

#### Scenario: 双击选择
- **WHEN** 用户双击某一行（非CheckBox区域）
- **THEN** 该行切换选中状态

#### Scenario: 全选/反选/取消选择
- **WHEN** 用户点击底部"全选"按钮
- **THEN** 所有当前筛选结果中的行都被选中
- **WHEN** 用户点击"反选"按钮
- **THEN** 所有行的选中状态取反
- **WHEN** 用户点击"取消选择"按钮
- **THEN** 所有行取消选中

#### Scenario: 快捷键支持
- **WHEN** 用户按下 Ctrl+A
- **THEN** 全选所有行
- **WHEN** 用户按下 Esc
- **THEN** 取消所有选择

### Requirement: 选择状态与报告生成联动
系统 SHALL 根据选择状态启用/禁用相关操作按钮。

#### Scenario: 有选中项时启用按钮
- **WHEN** 至少有一行被选中
- **THEN** "批量生成报告"和"批量删除"按钮变为可用状态，底部显示已选数量

#### Scenario: 无选中项时禁用按钮
- **WHEN** 没有任何行被选中
- **THEN** "批量生成报告"和"批量删除"按钮变为禁用状态，已选数量显示为0

## MODIFIED Requirements

### Requirement: 数据加载与排序
修改 `ApplyFilters()` 方法，确保：
1. 始终按 `ScanTime` 降序排列（最新的在最上面）
2. 为每条记录分配正确的 `RowNumber`（从1开始递增）
3. 筛选条件变化时保留已有项的选中状态
