# Tasks

- [x] Task 1: 设计并实现扫描模式配置模型
  - [x] SubTask 1.1: 在 Core 项目新增 `ScanProfile` 枚举（Quick/Standard/Deep/Custom）
  - [x] SubTask 1.2: 定义 `ScanProfileConfig` 类，包含 PortRange、TcpConcurrency、UdpConcurrency、TimeoutMs、RetryCount、EnablePingProbe、EnableServiceDetection
  - [x] SubTask 1.3: 为四种预设模式填充默认参数（均衡型配置）
  - [x] SubTask 1.4: 实现配置持久化，保存用户最后一次自定义参数

- [x] Task 2: 扩展 Rust 扫描服务请求协议
  - [x] SubTask 2.1: 在 `IpcRequest` / `ScanRequest` 结构体中增加 `tcp_concurrency`、`udp_concurrency`、`timeout_ms`、`retry_count`、`enable_ping_probe` 字段
  - [x] SubTask 2.2: 在 `scanner.rs` 中读取并应用这些参数
  - [x] SubTask 2.3: 实现 Ping 探测功能（使用 tokio 的 ICMP ping 或调用系统 ping）
  - [x] SubTask 2.4: 实现重试机制：对开放端口进行二次确认
  - [x] SubTask 2.5: 重新编译并部署 `rust-scanner-service.exe`

- [x] Task 3: 完善专家模式 UI
  - [x] SubTask 3.1: 在 `ExpertModeWindow.xaml` 添加扫描模式下拉框（ComboBox）
  - [x] SubTask 3.2: 添加"推荐模式"按钮和推荐结果文本显示
  - [x] SubTask 3.3: 添加可展开/折叠的"高级参数"面板，包含 TCP/UDP 并发、超时、重试、Ping 探测开关
  - [x] SubTask 3.4: 实现模式切换时自动填充/锁定高级参数（自定义模式解锁）
  - [x] SubTask 3.5: 加载并保存用户自定义参数设置

- [x] Task 4: 实现智能推荐引擎
  - [x] SubTask 4.1: 根据目标数量调整推荐：1-5 个目标推荐标准/激进，>100 个目标推荐降低并发
  - [x] SubTask 4.2: 根据首次探测 RTT 调整推荐：RTT > 200ms 推荐增加超时
  - [x] SubTask 4.3: 读取历史扫描结果，优先推荐历史上开放的端口范围
  - [x] SubTask 4.4: 读取 Rust 服务当前负载，负载高时降低并发
  - [x] SubTask 4.5: 在 UI 中显示推荐理由

- [x] Task 5: 更新 C# 扫描请求发送逻辑
  - [x] SubTask 5.1: 在 `RustScannerClient.ScanPortsAsync` 中把新的高级参数序列化到请求 JSON
  - [x] SubTask 5.2: 在 `PortScanner`（C# 内置扫描器）中应用同样的高级参数
  - [x] SubTask 5.3: 在 `ExpertModeWindow.xaml.cs` 中把 UI 参数转换为扫描配置

- [x] Task 6: 集成验证
  - [x] SubTask 6.1: 验证四种预设模式都能正常启动并完成扫描
  - [x] SubTask 6.2: 验证自定义参数（TCP 并发 200、超时 150ms）能正确下发到 Rust 服务
  - [x] SubTask 6.3: 验证智能推荐在不同目标数量/延迟场景下给出合理建议
  - [x] SubTask 6.4: 验证 C# 内置扫描器也应用新的高级参数
  - [x] SubTask 6.5: 验证用户自定义参数重启后仍保留

# Task Dependencies
- Task 2 依赖于 Task 1（协议需要先定义参数）
- Task 3 依赖于 Task 1 和 Task 2
- Task 4 依赖于 Task 1
- Task 5 依赖于 Task 1 和 Task 2
- Task 6 依赖于 Task 2、Task 3、Task 4、Task 5
