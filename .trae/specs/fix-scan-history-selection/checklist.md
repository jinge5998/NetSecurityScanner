# Checklist

- [x] XAML 第一列定义为序号列（Header="#"），使用 TextBlock 显示 RowNumber
- [x] BoolToBgConverter 转换器存在：选中返回橙色(#FFC107)，未选中返回白色
- [x] BoolToFgConverter 转换器存在：选中返回白色，未选中返回深灰(#505050)
- [x] SelectableScanHistory.RowNumber 属性存在并正确实现 INotifyPropertyChanged
- [x] SelectCell_MouseLeftButtonDown 事件处理器存在且逻辑正确（切换 IsSelected）
- [x] ApplyFilters 使用 OrderByDescending 按时间降序排列
- [x] ApplyFilters 为每条记录分配递增 RowNumber（从1开始）
- [x] 程序编译成功（0 错误）
- [ ] 运行程序后第一列显示序号数字（1,2,3...）而非 CheckBox 方框
- [ ] 点击序号可切换该行选中状态（橙色高亮）
- [ ] 右键点击行可切换选中状态
- [ ] 双击行可切换选中状态
- [ ] 底部"已选"计数随选择变化实时更新
- [ ] 有选中项时"批量生成报告"按钮可用
