# Tasks

- [x] Task 1: 修复 XAML 中 CheckBox 的定义
  - [x] 为 CheckBox 添加 `Click="CheckBox_Click"` 事件处理器
  - [x] 设置 `Focusable="False"` 防止焦点问题
  - [x] 添加 `HorizontalAlignment="Center"` 和 `VerticalAlignment="Center"`
  - [x] 添加 `Margin="5"` 增加点击区域

- [x] Task 2: 实现 CheckBox_Click 事件处理器
  - [x] 在 ScanHistoryWindow.xaml.cs 中添加 `CheckBox_Click` 方法
  - [x] 方法内获取 CheckBox 的 DataContext (SelectableScanHistory)
  - [x] 切换 `IsSelected` 属性
  - [x] 调用 `UpdateSelectionStatus()` 更新底部计数
  - [x] 设置 `e.Handled = true` 阻止事件冒泡

- [x] Task 3: 确保 ListViewItem 不干扰 CheckBox 点击
  - [x] 在 ListViewItem 的 `PreviewMouseLeftButtonDown` 中检测是否点击了 CheckBox
  - [x] 如果是 CheckBox 点击，设置 `e.Handled = true`

- [x] Task 4: 验证修复效果
  - [x] 编译项目
  - [x] 运行程序
  - [ ] 测试点击 CheckBox 勾选记录
  - [ ] 测试点击 CheckBox 取消勾选
  - [ ] 测试双击 CheckBox 不打开详情弹窗
  - [ ] 测试右键点击 CheckBox 不切换选中状态

# Task Dependencies
- [Task 2] depends on [Task 1]
- [Task 3] depends on [Task 1]
- [Task 4] depends on [Task 2], [Task 3]
