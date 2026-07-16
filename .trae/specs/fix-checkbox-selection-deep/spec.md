# 深度修复勾选框无法工作 Spec

## Why
用户反馈扫描历史窗口的勾选框（CheckBox）仍然无法正常工作，点击 CheckBox 无法勾选/取消勾选记录。之前的修复只处理了双击和右键事件排除 CheckBox，但没有解决 CheckBox 本身的点击问题。

## What Changes
- **根本原因分析**：WPF ListView+GridView 中，CheckBox 点击事件被 ListViewItem 拦截或事件冒泡导致 ListView 选择行为覆盖了 CheckBox 的勾选行为
- **修复方案**：
  1. 为 CheckBox 添加 `Click` 事件处理器，手动切换 `IsSelected` 并阻止事件冒泡
  2. 设置 `Focusable="False"` 防止焦点问题
  3. 添加 `HorizontalAlignment="Center"` 和足够的点击区域
  4. 确保 `UpdateSourceTrigger=PropertyChanged` 正确触发绑定更新

## Impact
- Affected specs: fix-scan-history-selection
- Affected code:
  - `ScanHistoryWindow.xaml` - CheckBox 模板定义
  - `ScanHistoryWindow.xaml.cs` - CheckBox 点击事件处理器

## ADDED Requirements

### Requirement: CheckBox 点击勾选功能
系统 SHALL 提供可点击的 CheckBox 列，允许用户勾选/取消勾选扫描历史记录。

#### Scenario: 点击 CheckBox 勾选记录
- **WHEN** 用户点击某行的 CheckBox
- **THEN** 该行的 `IsSelected` 属性切换为 true，UI 显示勾选状态

#### Scenario: 点击 CheckBox 取消勾选
- **WHEN** 用户再次点击已勾选行的 CheckBox
- **THEN** 该行的 `IsSelected` 属性切换为 false，UI 显示未勾选状态

#### Scenario: CheckBox 点击不影响其他行
- **WHEN** 用户点击某行的 CheckBox
- **THEN** 其他行的勾选状态不受影响

### Requirement: CheckBox 点击事件独立处理
系统 SHALL 确保 CheckBox 的点击事件独立处理，不被 ListViewItem 或 ListView 的选择行为干扰。

#### Scenario: CheckBox 点击不触发 ListView 选择
- **WHEN** 用户点击 CheckBox
- **THEN** ListView 的 SelectedItem 不改变（除非该行本身就是被选中的）

#### Scenario: CheckBox 点击不触发双击事件
- **WHEN** 用户双击 CheckBox
- **THEN** 只切换勾选状态，不打开详情弹窗
