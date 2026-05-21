# 攻击路径分析功能任务列表

- [ ] Task 1: 创建AttackPathAnalysisWindow.xaml界面文件
  - [ ] SubTask 1.1: 设计主窗口布局，包含左侧路径列表和右侧详情面板
  - [ ] SubTask 1.2: 添加攻击路径列表控件，显示路径名称、风险评分、成功概率
  - [ ] SubTask 1.3: 添加攻击步骤可视化区域，展示流程图样式
  - [ ] SubTask 1.4: 添加防御建议和详细信息面板
  - [ ] SubTask 1.5: 添加风险等级颜色标识和统计信息

- [ ] Task 2: 创建AttackPathAnalysisWindow.xaml.cs代码文件
  - [ ] SubTask 2.1: 实现窗口初始化和数据加载逻辑
  - [ ] SubTask 2.2: 实现攻击路径选择事件处理
  - [ ] SubTask 2.3: 实现攻击步骤动态渲染逻辑
  - [ ] SubTask 2.4: 实现防御建议生成逻辑
  - [ ] SubTask 2.5: 实现数据导出功能

- [ ] Task 3: 更新MainWindow.xaml.cs
  - [ ] SubTask 3.1: 修改ViewAttackPaths_Click方法，打开AttackPathAnalysisWindow窗口

- [ ] Task 4: 编译测试和功能验证
  - [ ] SubTask 4.1: 编译项目，确保无错误
  - [ ] SubTask 4.2: 运行程序，测试攻击路径分析功能

# 任务依赖关系
- [Task 2] depends on [Task 1]
- [Task 3] depends on [Task 2]
- [Task 4] depends on [Task 3]
