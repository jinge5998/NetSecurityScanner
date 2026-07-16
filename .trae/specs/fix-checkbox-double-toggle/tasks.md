# Tasks

- [x] Task 1: 修复 CheckBox_Click 双重切换 bug
  - [x] 移除 `item.IsSelected = !item.IsSelected` 手动切换逻辑
  - [x] 保留 `UpdateSelectionStatus()` 调用
  - [x] 保留 `e.Handled = true` 阻止事件冒泡

- [x] Task 2: 修复全选/反选/取消选择按钮 UI 不刷新问题
  - [x] SelectAllButton_Click 修改 IsSelected 后刷新 DataGrid 显示
  - [x] InvertSelectButton_Click 修改 IsSelected 后刷新 DataGrid 显示
  - [x] ClearSelectButton_Click 修改 IsSelected 后刷新 DataGrid 显示

- [x] Task 3: 编译验证
  - [x] 确保代码编译无错误

# Task Dependencies
- [Task 2] depends on [Task 1]
- [Task 3] depends on [Task 1], [Task 2]
