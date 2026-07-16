# 攻击日志查询功能任务列表

- [x] Task 1: 创建攻击日志数据模型
  - [x] SubTask 1.1: 创建AttackLogEntry类，包含所有必要字段
  - [x] SubTask 1.2: 创建AttackLogStatistics类，包含统计数据字段
  - [x] SubTask 1.3: 创建AttackLogFilter类，包含筛选条件字段

- [x] Task 2: 实现攻击日志解析服务
  - [x] SubTask 2.1: 创建AttackLogService服务类
  - [x] SubTask 2.2: 实现IIS日志解析方法
  - [x] SubTask 2.3: 实现Nginx/Apache日志解析方法
  - [x] SubTask 2.4: 实现防火墙日志解析方法
  - [x] SubTask 2.5: 实现Windows事件日志解析方法
  - [x] SubTask 2.6: 实现攻击类型识别逻辑（正则匹配）
  - [x] SubTask 2.7: 实现风险等级评估逻辑

- [x] Task 3: 创建攻击日志查询窗口UI
  - [x] SubTask 3.1: 创建AttackLogWindow.xaml
  - [x] SubTask 3.2: 设计顶部工具栏（刷新、导出、筛选按钮）
  - [x] SubTask 3.3: 设计筛选区域（时间范围、攻击类型、风险等级、IP搜索）
  - [x] SubTask 3.4: 设计主内容区（左侧攻击日志表格，右侧统计面板）
  - [x] SubTask 3.5: 设计底部状态栏（显示记录数、筛选状态）
  - [x] SubTask 3.6: 设计统计面板（攻击类型图表、Top IP列表）

- [x] Task 4: 实现攻击日志查询窗口业务逻辑
  - [x] SubTask 4.1: 创建AttackLogWindow.xaml.cs
  - [x] SubTask 4.2: 实现日志加载和显示逻辑
  - [x] SubTask 4.3: 实现筛选逻辑
  - [x] SubTask 4.4: 实现导出功能（CSV、Excel）
  - [x] SubTask 4.5: 实现攻击详情窗口
  - [x] SubTask 4.6: 实现统计面板更新逻辑

- [x] Task 5: 连接主菜单点击事件
  - [x] SubTask 5.1: 修改MainWindow.xaml添加"攻击日志"菜单项
  - [x] SubTask 5.2: 修改MainWindow.xaml.cs添加点击事件处理
  - [x] SubTask 5.3: 编译测试

- [x] Task 6: 优化和测试
  - [x] SubTask 6.1: 测试日志解析功能
  - [x] SubTask 6.2: 测试筛选功能
  - [x] SubTask 6.3: 测试导出功能
  - [x] SubTask 6.4: 编译无错误
  - [x] SubTask 6.5: 运行测试

# Task Dependencies
- [Task 3] depends on [Task 1, Task 2]
- [Task 4] depends on [Task 1, Task 2, Task 3]
- [Task 5] depends on [Task 3, Task 4]
- [Task 6] depends on [Task 5]
