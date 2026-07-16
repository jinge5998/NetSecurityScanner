# 插件管理功能完善 Spec

## Why
当前"工具"菜单中的"插件管理"点击后仅显示"插件管理功能开发中..."的提示框，但项目已有完整的插件后端架构（PluginManager、PluginMarketService、IVulnerabilityScannerPlugin 接口等）和两个窗口（PluginManagerWindow、PluginMarketWindow）。需要将菜单入口与现有窗口连接，并完善插件管理窗口的功能，使其成为一个可用的插件管理界面。

## What Changes
- 修改 MainWindow 中的 `PluginManager_Click` 事件，打开 PluginManagerWindow 而非显示提示框
- 重写 PluginManagerWindow 为纯代码构建 UI（避免 XAML InitializeComponent 空引用异常，与 AttackLogWindow 保持一致）
- 完善插件管理窗口功能：插件列表展示、详情查看、配置编辑、启用/禁用切换、安装/卸载、插件市场入口
- 添加更多内置演示插件数据，使界面内容更丰富
- 添加插件配置对话框（替代原来的 MessageBox 提示）

## Impact
- Affected code: MainWindow.xaml.cs（PluginManager_Click 方法）、PluginManagerWindow.xaml + .xaml.cs
- Affected services: PluginManager.cs、PluginMarketService.cs（无需修改，仅调用）
- 依赖: IVulnerabilityScannerPlugin、PluginConfig、PluginInfo 等现有模型

## ADDED Requirements

### Requirement: 插件管理窗口入口
系统 SHALL 在用户点击"工具→插件管理"时打开 PluginManagerWindow 窗口，而非显示"开发中"提示。

#### Scenario: 用户点击插件管理菜单
- **WHEN** 用户点击"工具→插件管理"
- **THEN** 打开 PluginManagerWindow 窗口，显示已安装的插件列表

### Requirement: 插件列表展示
系统 SHALL 在左侧面板以 DataGrid 形式展示所有已加载插件，包含名称、版本、作者、类别、状态列。

#### Scenario: 加载插件列表
- **WHEN** 窗口打开并加载完成
- **THEN** 显示所有内置插件和外部插件，状态列用颜色区分（绿色=正常、黄色=未初始化、红色=错误）

### Requirement: 插件详情查看
系统 SHALL 在右侧面板展示选中插件的详细信息，包括名称、ID、版本、作者、描述、支持类型、配置参数、扫描统计。

#### Scenario: 用户选择插件
- **WHEN** 用户在列表中点击某个插件
- **THEN** 右侧面板显示该插件的完整信息，包括扫描次数和发现漏洞数

### Requirement: 插件配置编辑
系统 SHALL 提供配置对话框，允许用户编辑插件的配置参数（根据 ConfigParameters 动态生成表单）。

#### Scenario: 用户点击配置按钮
- **WHEN** 用户点击"配置"按钮
- **THEN** 弹出配置对话框，根据插件的 ConfigParameters 动态生成输入控件
- **AND** 用户修改后点击保存，配置被持久化

### Requirement: 启用/禁用插件
系统 SHALL 允许用户切换插件的启用/禁用状态，禁用的插件不参与扫描。

#### Scenario: 用户切换插件状态
- **WHEN** 用户点击"启用/禁用"按钮
- **THEN** 插件状态切换，列表中状态列更新

### Requirement: 安装外部插件
系统 SHALL 允许用户从本地 DLL 文件安装插件。

#### Scenario: 用户安装插件
- **WHEN** 用户点击"安装插件"并选择 DLL 文件
- **THEN** 插件被加载并出现在列表中

### Requirement: 卸载插件
系统 SHALL 允许用户卸载非内置插件，卸载前需确认。

#### Scenario: 用户卸载插件
- **WHEN** 用户选择非内置插件并点击"卸载"
- **THEN** 弹出确认对话框，确认后插件被移除

### Requirement: 插件市场入口
系统 SHALL 在工具栏提供"插件市场"按钮，点击后打开 PluginMarketWindow。

#### Scenario: 用户打开插件市场
- **WHEN** 用户点击"插件市场"按钮
- **THEN** 打开 PluginMarketWindow 窗口

### Requirement: 键盘快捷键
系统 SHALL 支持 Enter 键刷新列表、Esc 键关闭窗口。

#### Scenario: 用户按快捷键
- **WHEN** 用户按 Enter 键
- **THEN** 刷新插件列表
- **WHEN** 用户按 Esc 键
- **THEN** 关闭窗口
