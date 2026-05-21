# 插件管理功能完善 V2 Spec

## Why
当前插件管理器虽已基本可用，但存在以下核心问题：仅有一个内置插件导致界面空旷、启用/禁用状态不持久化（重启后丢失）、无搜索过滤功能、无插件更新检测入口、PluginStatus 类型名冲突（Models.PluginStatus 枚举 vs Plugins.PluginStatus 类）、插件配置缺少必填校验、PluginMarketWindow 仍使用 XAML 可能出现初始化异常。需要进一步完善使插件管理功能达到生产可用水平。

## What Changes
- 新增 3 个内置演示插件（端口服务识别、SSL/TLS 检测、Web 漏洞扫描），使界面内容丰富
- 插件启用/禁用状态持久化到 plugin_configs.json，重启后保留
- PluginManagerWindow 添加搜索框和类别筛选功能
- PluginManagerWindow 添加"检查更新"按钮，集成 PluginMarketService
- 解决 PluginStatus 命名冲突：将 Plugins.PluginStatus 重命名为 PluginRuntimeStatus
- 插件配置对话框添加必填字段校验和输入验证
- PluginMarketWindow 改为代码构建 UI（与 PluginManagerWindow 保持一致，避免 XAML 初始化异常）
- 插件详情面板添加"查看日志"按钮，展示插件运行日志

## Impact
- Affected code: PluginManagerWindow.xaml.cs、PluginMarketWindow.xaml + .xaml.cs、PluginManager.cs、IVulnerabilityScannerPlugin.cs、WeakPasswordPlugin.cs
- Affected models: Plugin.cs（PluginStatus 枚举不受影响）、PluginConfig 类
- 新增文件: DefaultPlugins/PortServicePlugin.cs、DefaultPlugins/SslTlsPlugin.cs、DefaultPlugins/WebVulnPlugin.cs
- **BREAKING**: Plugins.PluginStatus 类重命名为 PluginRuntimeStatus，所有引用需更新

## ADDED Requirements

### Requirement: 内置演示插件扩展
系统 SHALL 提供至少 4 个内置插件（含现有弱密码检测），新增端口服务识别、SSL/TLS 检测、Web 漏洞扫描 3 个内置插件。

#### Scenario: 用户打开插件管理器
- **WHEN** 用户打开插件管理器
- **THEN** 列表中显示至少 4 个内置插件，每个插件有不同的配置参数和扫描类型

### Requirement: 插件启用/禁用状态持久化
系统 SHALL 将插件的启用/禁用状态持久化到 plugin_configs.json 文件中，窗口重启后状态保持。

#### Scenario: 用户禁用插件后重启
- **WHEN** 用户禁用某插件并关闭窗口后重新打开
- **THEN** 该插件仍显示为禁用状态

### Requirement: 插件搜索与筛选
系统 SHALL 在插件管理器工具栏提供搜索框和类别筛选下拉框，支持按名称/作者搜索和按扫描类型筛选。

#### Scenario: 用户搜索插件
- **WHEN** 用户在搜索框输入关键词
- **THEN** 插件列表实时过滤，仅显示匹配的插件

#### Scenario: 用户按类别筛选
- **WHEN** 用户选择某个扫描类型筛选
- **THEN** 列表仅显示支持该类型的插件

### Requirement: 插件更新检测
系统 SHALL 在插件管理器工具栏提供"检查更新"按钮，点击后调用 PluginMarketService 检查已安装插件是否有可用更新。

#### Scenario: 用户检查更新
- **WHEN** 用户点击"检查更新"按钮
- **THEN** 系统异步检查更新并显示结果（有更新/全部最新）

### Requirement: 插件配置输入验证
系统 SHALL 在插件配置对话框中对标记为 IsRequired 的参数进行非空校验，对 Integer/Float 类型进行数值格式校验。

#### Scenario: 用户保存配置但必填项为空
- **WHEN** 用户未填写必填参数就点击保存
- **THEN** 显示验证错误提示，阻止保存

### Requirement: 插件运行日志查看
系统 SHALL 在插件详情面板提供"查看日志"按钮，点击后弹出窗口展示该插件的运行日志记录。

#### Scenario: 用户查看插件日志
- **WHEN** 用户选中某插件并点击"查看日志"
- **THEN** 弹出日志窗口显示该插件的历史运行记录

## MODIFIED Requirements

### Requirement: PluginStatus 命名冲突解决
将 Plugins 命名空间中的 PluginStatus 类重命名为 PluginRuntimeStatus，避免与 Models.PluginStatus 枚举冲突。所有引用该类的代码（IVulnerabilityScannerPlugin.GetStatus()、WeakPasswordPlugin.GetStatus()、PluginManagerWindow 中的状态读取）需同步更新。

### Requirement: PluginMarketWindow 代码构建 UI
将 PluginMarketWindow 从 XAML 构建改为代码构建 UI（与 PluginManagerWindow 保持一致的实现方式），避免 XAML InitializeComponent 可能出现的空引用异常。

## REMOVED Requirements
无移除的需求。
