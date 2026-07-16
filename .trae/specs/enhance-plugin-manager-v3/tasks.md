# Tasks

- [ ] Task 1: 修复 PluginManager 核心逻辑
  - [ ] SubTask 1.1: 在 PluginManager 中添加 EnablePluginAsync/DisablePluginAsync 公共方法
  - [ ] SubTask 1.2: 在 GetApplicablePluginsAsync 中过滤已禁用插件
  - [ ] SubTask 1.3: 在 ScanWithAllPluginsAsync 中过滤已禁用插件并更新运行时状态统计
  - [ ] SubTask 1.4: 修复 UninstallPluginAsync 删除 DLL 文件
  - [ ] SubTask 1.5: 添加 ScanWithPluginsForTargetAsync 方法，接收目标IP和开放端口列表，自动匹配并执行适用插件

- [ ] Task 2: 统一插件目录路径
  - [ ] SubTask 2.1: 修改 PluginMarketService 使用与 PluginManager 相同的 Plugins 目录（AppDomain.CurrentDomain.BaseDirectory + "Plugins"）
  - [ ] SubTask 2.2: 建立 Plugin（市场模型）和 IVulnerabilityScannerPlugin（运行时模型）的映射方法

- [ ] Task 3: 将 PluginManager 集成到综合扫描流程
  - [ ] SubTask 3.1: 修改 MainWindow.xaml.cs 的 ExecuteComprehensiveScanAsync 方法，在端口扫描完成后调用 PluginManager.ScanWithPluginsForTargetAsync
  - [ ] SubTask 3.2: 将插件扫描结果合并到综合扫描结果中，写入扫描历史记录

- [ ] Task 4: 增强 PortServicePlugin 扫描逻辑
  - [ ] SubTask 4.1: 实现 Banner 抓取逻辑 — 通过 TcpClient 连接目标端口，读取返回的 Banner 信息
  - [ ] SubTask 4.2: 根据 Banner 识别服务类型和版本
  - [ ] SubTask 4.3: 扫描完成后更新 PluginRuntimeStatus 统计

- [ ] Task 5: 增强 SslTlsPlugin 扫描逻辑
  - [ ] SubTask 5.1: 使用 SslStream 连接目标端口进行 TLS 握手
  - [ ] SubTask 5.2: 检测 TLS 协议版本、证书信息、过期时间
  - [ ] SubTask 5.3: 检测弱密码套件
  - [ ] SubTask 5.4: 扫描完成后更新 PluginRuntimeStatus 统计

- [ ] Task 6: 增强 WeakPasswordPlugin 扫描逻辑
  - [ ] SubTask 6.1: 通过 TcpClient 探测目标端口是否开放并允许密码认证
  - [ ] SubTask 6.2: 检测常见默认凭据风险（空密码、默认用户名等）
  - [ ] SubTask 6.3: 扫描完成后更新 PluginRuntimeStatus 统计

- [ ] Task 7: 增强 WebVulnPlugin 扫描逻辑
  - [ ] SubTask 7.1: 使用 HttpClient 发送探测请求检测常见 Web 漏洞（目录遍历、信息泄露等）
  - [ ] SubTask 7.2: 检测 HTTP 响应头安全性（缺失安全头）
  - [ ] SubTask 7.3: 扫描完成后更新 PluginRuntimeStatus 统计

- [ ] Task 8: 编译验证
  - [ ] SubTask 8.1: 编译主程序项目，确保无编译错误
  - [ ] SubTask 8.2: 运行程序验证综合扫描流程中插件扫描正常执行

# Task Dependencies
- [Task 2] depends on nothing (可并行)
- [Task 1] depends on nothing (可并行)
- [Task 3] depends on [Task 1]
- [Task 4] depends on [Task 1] (需要更新运行时状态的基础设施)
- [Task 5] depends on [Task 1]
- [Task 6] depends on [Task 1]
- [Task 7] depends on [Task 1]
- [Task 8] depends on [Task 1, Task 2, Task 3, Task 4, Task 5, Task 6, Task 7]
