# 插件管理器功能完善 V3 Spec

## Why
当前插件管理器虽然UI功能丰富，但核心问题严重：插件系统与扫描流程完全脱节（插件从未被实际调用）、启用/禁用机制不生效、插件目录路径不一致导致市场安装的插件无法加载、两套插件模型不统一、卸载不删除DLL文件、内置插件扫描逻辑为静态模拟。需要修复这些致命/严重问题，使插件系统真正可用。

## What Changes
- 将 PluginManager 集成到扫描流程，使插件在端口扫描后自动执行
- 修复启用/禁用机制，在 ScanWithAllPluginsAsync 中过滤已禁用插件
- 统一插件目录路径（PluginMarketService 使用与 PluginManager 相同的目录）
- 建立两套插件模型的映射关系
- 修复卸载功能，删除 DLL 文件
- 增强内置插件扫描逻辑（使用真实网络检测）
- 插件扫描结果写入扫描历史记录
- 插件运行时状态追踪（更新扫描次数、漏洞数、最后扫描时间）

## Impact
- Affected code:
  - `NetSecurityScanner.Core/Plugins/PluginManager.cs` — 核心逻辑修改
  - `NetSecurityScanner.Core/Services/VulnerabilityDetectionService.cs` — 集成插件扫描
  - `NetSecurityScanner.Core/Services/PluginMarketService.cs` — 统一目录路径
  - `NetSecurityScanner.Core/Plugins/DefaultPlugins/*.cs` — 增强扫描逻辑
  - `NetSecurityScanner.Desktop/MainWindow.xaml.cs` — 综合扫描中调用插件

## ADDED Requirements

### Requirement: 插件系统与扫描流程集成
系统 SHALL 在综合扫描流程中自动调用适用的已启用插件进行扫描。

#### Scenario: 综合扫描时自动调用插件
- **WHEN** 用户执行综合扫描并完成端口扫描
- **THEN** 系统对每个开放端口查找适用的已启用插件，并自动执行插件扫描
- **AND** 插件扫描结果合并到综合扫描结果中

#### Scenario: 插件扫描结果展示
- **WHEN** 插件扫描完成
- **THEN** 扫描结果包含插件名称、发现的漏洞、风险等级
- **AND** 结果写入扫描历史记录

### Requirement: 启用/禁用机制生效
系统 SHALL 确保禁用的插件不会被调用。

#### Scenario: 禁用插件不参与扫描
- **WHEN** 插件被禁用
- **THEN** GetApplicablePluginsAsync 和 ScanWithAllPluginsAsync 不返回/不调用该插件

### Requirement: 统一插件目录
系统 SHALL 确保插件市场安装的插件能被 PluginManager 正确加载。

#### Scenario: 市场安装的插件可被加载
- **WHEN** 从插件市场安装插件
- **THEN** 插件 DLL 文件保存到 PluginManager 的 Plugins 目录
- **AND** 重启应用后 PluginManager 能加载该插件

### Requirement: 卸载插件删除DLL
系统 SHALL 在卸载外部插件时删除其 DLL 文件。

#### Scenario: 卸载外部插件
- **WHEN** 用户卸载一个外部插件（非内置）
- **THEN** 系统从内存卸载插件、删除配置、删除 DLL 文件

### Requirement: 插件运行时状态追踪
系统 SHALL 在插件扫描完成后更新运行时状态统计。

#### Scenario: 扫描完成后更新统计
- **WHEN** 插件完成一次扫描
- **THEN** 更新 ScanCount（+1）、VulnerabilityFound（+发现数）、LastScanTime（当前时间）

## MODIFIED Requirements

### Requirement: 内置插件扫描逻辑增强
内置插件 SHALL 执行真实的网络检测而非返回硬编码结果。

- **PortServicePlugin**: 通过 TCP 连接获取 Banner 信息识别服务
- **SslTlsPlugin**: 使用 SslStream 进行 TLS 握手分析
- **WeakPasswordPlugin**: 检测服务是否允许密码认证（TCP连接探测）
- **WebVulnPlugin**: 使用 HttpClient 发送探测请求检测常见漏洞

## REMOVED Requirements
无
