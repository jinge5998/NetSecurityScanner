# Tasks

- [x] Task 1: 修改 MainWindow PluginManager_Click 入口，打开 PluginManagerWindow
  - [x] 替换 MessageBox 为 new PluginManagerWindow().ShowDialog()

- [x] Task 2: 重写 PluginManagerWindow.xaml.cs 为纯代码构建 UI
  - [x] 简化 PluginManagerWindow.xaml 为空 Window
  - [x] 用代码构建完整 UI：标题栏、工具栏、左右分栏（列表+详情）、底部按钮
  - [x] 添加键盘快捷键（Enter 刷新、Esc 关闭）
  - [x] 添加窗口 Loaded 事件异步加载插件

- [x] Task 3: 实现插件列表展示
  - [x] DataGrid 展示插件名称、版本、作者、类别、状态（带颜色标识）
  - [x] 状态列用颜色标签显示
  - [x] 选中行时右侧显示详情

- [x] Task 4: 实现插件详情面板
  - [x] 显示插件基本信息（名称、ID、版本、作者、描述）
  - [x] 显示支持的扫描类型
  - [x] 显示配置参数列表
  - [x] 显示扫描统计（扫描次数、发现漏洞数、最后扫描时间）

- [x] Task 5: 实现插件配置对话框
  - [x] 根据 ConfigParameters 动态生成表单控件
  - [x] 支持 String/Integer/Boolean/Password/FilePath/Enum 等类型
  - [x] 保存配置并持久化

- [x] Task 6: 实现启用/禁用和卸载功能
  - [x] 启用/禁用按钮切换插件状态
  - [x] 卸载按钮（非内置插件）带确认对话框

- [x] Task 7: 实现安装和插件市场入口
  - [x] 安装按钮打开文件选择器选择 DLL
  - [x] 插件市场按钮打开 PluginMarketWindow

- [x] Task 8: 编译测试验证
  - [x] dotnet build 无错误
  - [x] 运行程序验证功能

# Task Dependencies
- [Task 2] depends on [Task 1]
- [Task 3] depends on [Task 2]
- [Task 4] depends on [Task 3]
- [Task 5] depends on [Task 4]
- [Task 6] depends on [Task 4]
- [Task 7] depends on [Task 2]
- [Task 8] depends on [Task 5, Task 6, Task 7]
