# Tasks

- [x] Task 1: 确认 XAML 序号列定义正确
  - [x] 确认第一列为 DataGridTemplateColumn，Header 为 "#"
  - [x] 确认使用 TextBlock 绑定 RowNumber 属性
  - [x] 确认使用 BoolToBgConverter 和 BoolToFgConverter 转换器
  - [x] 确认 Border 上绑定 MouseLeftButtonDown="SelectCell_MouseLeftButtonDown" 事件

- [x] Task 2: 确认转换器类完整（ScanHistoryItem.cs）
  - [x] 确认 BoolToBgConverter 存在且逻辑正确（选中=橙色，未选中=白色）
  - [x] 确认 BoolToFgConverter 存在且逻辑正确（选中=白色，未选中=深灰）
  - [x] 确认 SelectableScanHistory.RowNumber 属性存在并触发 PropertyChanged

- [x] Task 3: 确认事件处理逻辑正确（ScanHistoryWindow.xaml.cs）
  - [x] 确认 SelectCell_MouseLeftButtonDown 方法存在，通过 DataContext 获取 SelectableScanHistory 并切换 IsSelected
  - [x] 确认 HistoryDataGrid_MouseLeftButtonUp 方法作为备用点击检测
  - [x] 确认 HistoryDataGrid_MouseRightButtonUp 右键切换选中
  - [x] 确认 HistoryDataGrid_MouseDoubleClick 双击切换选中
  - [x] 确认 UpdateSelectionStatus 方法更新底部计数和按钮状态

- [x] Task 4: 确认 ApplyFilters 排序与编号逻辑
  - [x] 确认使用 OrderByDescending(h => h.ScanTime) 降序排列
  - [x] 确认为每条记录分配递增的 RowNumber（从1开始）
  - [x] 确认筛选变化时保留已有项的选中状态

- [x] Task 5: 清理缓存、重新编译并验证
  - [x] 关闭正在运行的程序进程
  - [x] 删除 obj/Release 和 bin/Release 缓存目录
  - [x] 执行 dotnet build Release 编译
  - [x] 启动程序验证序号列显示和点击选中功能

# Task Dependencies
- [Task 5] depends on [Task 1], [Task 2], [Task 3], [Task 4]
