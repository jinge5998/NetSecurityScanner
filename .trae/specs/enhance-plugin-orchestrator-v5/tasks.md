# v5 Tasks

- [ ] v5-T1: 新建 PluginOrchestrator 单例
  - [ ] v5-T1.1: `Services/PluginOrchestrator.cs` 单例类（Lazy<PluginOrchestrator>）
  - [ ] v5-T1.2: 构造函数持有 PluginManager + PluginSandboxService + PluginExecutionLogService
  - [ ] v5-T1.3: `InitializeAsync()` 启动时一次性 LoadAllPlugins
  - [ ] v5-T1.4: `ScanTargetAsync(ip, ports, selectedPluginIds?, ct)` 单目标
  - [ ] v5-T1.5: `DeepScanAsync(ScanHistoryItem)` 深挖
  - [ ] v5-T1.6: `TryRunAsync(PluginMarketPlugin)` 试运行
  - [ ] v5-T1.7: `ScanBatchAsync(targets, progress?)` 批量
  - [ ] v5-T1.8: 所有方法都走沙箱 + 写日志

- [ ] v5-T2: 新建 PluginQuickInvokeWindow
  - [ ] v5-T2.1: `Views/PluginQuickInvokeWindow.xaml` 布局：目标 IP + 端口 + 插件多选 + 进度条 + 按钮
  - [ ] v5-T2.2: `Views/PluginQuickInvokeWindow.xaml.cs` 加载所有可用插件到 CheckBox 列表
  - [ ] v5-T2.3: 解析端口输入（逗号分隔 + 范围 1-1024 + 单端口）
  - [ ] v5-T2.4: 执行按钮：禁用输入、显示进度、调 PluginOrchestrator.ScanTargetAsync
  - [ ] v5-T2.5: 完成后弹窗显示漏洞数 + 详细列表 + 可选保存

- [ ] v5-T3: 主窗口接入
  - [ ] v5-T3.1: `MainWindow.xaml` 顶部工具栏新增"🔌 插件扫描"按钮
  - [ ] v5-T3.2: `MainWindow.xaml.cs` 新增 `PluginScanButton_Click` 打开 PluginQuickInvokeWindow
  - [ ] v5-T3.3: 替换 `:1510` 处的 `new PluginManager()` 为 `PluginOrchestrator.Instance.ScanTargetAsync`
  - [ ] v5-T3.4: 启动时（如构造时）调 `PluginOrchestrator.Instance.InitializeAsync()` 预热

- [ ] v5-T4: 扫描结果深挖入口
  - [ ] v5-T4.1: `MainWindow.xaml.cs` 综合扫描结果 DataGrid 右键菜单加"🔌 用插件深挖"
  - [ ] v5-T4.2: `CameraSecurityScannerWindow.xaml.cs` 摄像头结果 DataGrid 右键菜单加"🔌 用插件深挖"
  - [ ] v5-T4.3: `ScanHistoryWindow.xaml.cs` 历史 DataGrid 右键菜单加"🔌 用插件深挖"
  - [ ] v5-T4.4: 深挖实现：弹窗确认 → PluginOrchestrator.DeepScanAsync → 弹窗结果

- [ ] v5-T5: 商店试运行 + 日志重跑
  - [ ] v5-T5.1: `PluginMarketWindow.xaml` 操作列加"▶ 试运行"按钮（"安装"前）
  - [ ] v5-T5.2: `PluginMarketWindow.xaml.cs` 实现 TryRunButton_Click → PluginOrchestrator.TryRunAsync
  - [ ] v5-T5.3: 模拟结果展示在窗口内（新增 ResultsPanel）
  - [ ] v5-T5.4: `PluginExecutionLogWindow.xaml` 顶部加"▶ 重新执行选中"按钮
  - [ ] v5-T5.5: `PluginExecutionLogWindow.xaml.cs` 实现 ReRunButton_Click → PluginOrchestrator.ScanTargetAsync(target, [port], [pluginId])

- [ ] v5-T6: 编译验证
  - [ ] v5-T6.1: 编译 0 错误
  - [ ] v5-T6.2: 启动后主窗口显示"🔌 插件扫描"按钮
  - [ ] v5-T6.3: 打开 PluginQuickInvokeWindow 显示所有插件可勾选
  - [ ] v5-T6.4: 扫描结果 DataGrid 右键菜单含"🔌 用插件深挖"
  - [ ] v5-T6.5: 商店窗口"▶ 试运行"按钮可见可点
  - [ ] v5-T6.6: 日志窗口"▶ 重新执行选中"按钮可见
  - [ ] v5-T6.7: 综合扫描后日志文件仍正常生成（不破坏 v4 流程）

# v5 Task Dependencies
- v5-T1 是其他所有任务的前置（必须先有调度器）
- v5-T2 依赖 v5-T1
- v5-T3 依赖 v5-T1, v5-T2
- v5-T4 依赖 v5-T1
- v5-T5 依赖 v5-T1
- v5-T6 依赖所有任务
