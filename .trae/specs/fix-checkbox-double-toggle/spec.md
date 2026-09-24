# 修复扫描历史记录勾选无法工作 Spec

## Why
扫描历史记录窗口的 CheckBox 勾选无法正常工作，用户点击 CheckBox 后状态不变。根本原因是双重切换 bug：TwoWay 绑定已经更新了 IsSelected，CheckBox_Click 又手动取反，导致状态被还原。

## What Changes
- **修复 CheckBox_Click 双重切换**：移除手动 `item.IsSelected = !item.IsSelected`，仅保留 `UpdateSelectionStatus()` 调用
- **同步修复 SelectAllButton/InvertSelectButton/ClearSelectButton**：这些方法直接修改 IsSelected 后需要刷新 DataGrid 显示

## Impact
- Affected specs: fix-scan-history-selection, fix-checkbox-selection-deep
- Affected code:
  - `ScanHistoryWindow.xaml.cs` - CheckBox_Click 事件处理器（双重切换 bug）
  - `ScanHistoryWindow.xaml.cs` - 全选/反选/取消选择按钮（UI 不刷新）

## ADDED Requirements

### Requirement: CheckBox 勾选正常工作
系统 SHALL 确保用户点击 CheckBox 时，勾选状态正确切换，不被双重切换 bug 阻止。

#### Scenario: 点击 CheckBox 勾选记录
- **WHEN** 用户点击某行的 CheckBox
- **THEN** 该行 IsSelected 变为 true，CheckBox 显示勾选状态，底部计数更新

#### Scenario: 点击 CheckBox 取消勾选
- **WHEN** 用户再次点击已勾选行的 CheckBox
- **THEN** 该行 IsSelected 变为 false，CheckBox 显示未勾选状态，底部计数更新

### Requirement: 全选/反选/取消选择按钮正常刷新 UI
系统 SHALL 确保全选、反选、取消选择按钮操作后，DataGrid 中 CheckBox 的显示状态同步更新。

#### Scenario: 点击全选按钮
- **WHEN** 用户点击"全选"按钮
- **THEN** 所有行的 CheckBox 显示勾选状态，底部计数更新

#### Scenario: 点击取消选择按钮
- **WHEN** 用户点击"取消选择"按钮
- **THEN** 所有行的 CheckBox 显示未勾选状态，底部计数更新

## MODIFIED Requirements

### Requirement: CheckBox_Click 事件处理
修改 `CheckBox_Click` 方法，不再手动切换 IsSelected（TwoWay 绑定已自动完成），仅调用 `UpdateSelectionStatus()` 更新底部计数和按钮状态。
