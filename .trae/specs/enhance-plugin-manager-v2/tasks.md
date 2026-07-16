# Tasks

- [x] Task 1: 解决 PluginStatus 命名冲突
  - [x] 将 IVulnerabilityScannerPlugin.cs 中的 PluginStatus 类重命名为 PluginRuntimeStatus
  - [x] 更新 WeakPasswordPlugin.cs 中 GetStatus() 返回类型为 PluginRuntimeStatus
  - [x] 更新 PluginManagerWindow.xaml.cs 中所有 PluginStatus 引用为 PluginRuntimeStatus
  - [x] 确认 Models.PluginStatus 枚举不受影响

- [x] Task 2: 新增 3 个内置演示插件
  - [x] 创建 DefaultPlugins/PortServicePlugin.cs（端口服务识别插件，PluginId=builtin.portservice）
  - [x] 创建 DefaultPlugins/SslTlsPlugin.cs（SSL/TLS 检测插件，PluginId=builtin.ssltls）
  - [x] 创建 DefaultPlugins/WebVulnPlugin.cs（Web 漏洞扫描插件，PluginId=builtin.webvuln）
  - [x] 在 PluginManager.LoadBuiltInPlugins() 中注册新插件

- [x] Task 3: 插件启用/禁用状态持久化
  - [x] 修改 PluginConfig 类添加 IsEnabled 属性（已有，确认可用）
  - [x] 修改 PluginManagerWindow 初始化时从 PluginConfig 读取 IsEnabled 状态
  - [x] 修改 EnableDisableButton_Click 保存状态到 PluginConfig 并持久化
  - [x] 修改 RefreshPluginList 使用持久化的 IsEnabled 状态

- [x] Task 4: PluginManagerWindow 添加搜索与筛选
  - [x] 在工具栏添加搜索 TextBox（带 Placeholder 提示）
  - [x] 在工具栏添加类别筛选 ComboBox（全部 + 各扫描类型）
  - [x] 实现 SearchTextBox_TextChanged 实时过滤
  - [x] 实现 CategoryFilter_SelectionChanged 类别筛选
  - [x] 添加"全部"选项重置筛选

- [x] Task 5: PluginManagerWindow 添加检查更新按钮
  - [x] 在工具栏添加"🔄 检查更新"按钮
  - [x] 实现 CheckUpdates_Click 异步调用 PluginMarketService.CheckForUpdatesAsync
  - [x] 显示检查结果（有更新数量 / 全部最新）

- [x] Task 6: 插件配置输入验证
  - [x] 在 ConfigureButton_Click 的保存逻辑中添加 IsRequired 非空校验
  - [x] 添加 Integer/Float 类型数值格式校验
  - [x] 校验失败时高亮错误字段并显示提示，阻止保存

- [x] Task 7: 插件运行日志查看
  - [x] 在插件详情面板添加"📋 查看日志"按钮
  - [x] 实现 ViewLogButton_Click 弹出日志窗口
  - [x] 日志窗口展示插件运行记录（扫描时间、目标、结果摘要）

- [x] Task 8: PluginMarketWindow 改为代码构建 UI
  - [x] 简化 PluginMarketWindow.xaml 为空 Window
  - [x] 在 PluginMarketWindow.xaml.cs 中用代码构建完整 UI（标题栏、搜索筛选栏、插件卡片列表、加载指示器）
  - [x] 保留所有现有功能（搜索、筛选、排序、安装、详情、检查更新、我的插件）

- [x] Task 9: 编译测试验证
  - [x] dotnet build 无错误
  - [x] 运行程序验证所有功能

# Task Dependencies
- [Task 2] depends on [Task 1]
- [Task 3] depends on [Task 1]
- [Task 4] depends on [Task 1]
- [Task 5] depends on [Task 1]
- [Task 6] depends on [Task 1]
- [Task 7] depends on [Task 1]
- [Task 8] has no dependency (can parallel with Task 2-7)
- [Task 9] depends on [Task 2, Task 3, Task 4, Task 5, Task 6, Task 7, Task 8]
