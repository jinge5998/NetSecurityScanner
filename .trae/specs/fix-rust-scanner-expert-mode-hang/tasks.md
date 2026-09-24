# Tasks

- [x] Task 1: 修复 Rust 扫描服务无响应根因
  - [x] SubTask 1.1: 在 `scanner.rs` 的扫描入口、progress/result/complete 发送处添加诊断日志
  - [x] SubTask 1.2: 检查并修复 `scan_target_ports_with_progress` 中 channel 发送可能阻塞的问题（使用 `try_send` 或独立任务转发）
  - [x] SubTask 1.3: 检查 `grab_banner_tcp`/`grab_banner_udp` 在无响应服务上的超时与并发控制，避免单端口卡住拖垮整个扫描
  - [x] SubTask 1.4: 重新编译 `rust-scanner-service.exe` 并部署到 `bin/Debug/net6.0-windows/`

- [x] Task 2: 增强 C# 客户端心跳超时与回退逻辑
  - [x] SubTask 2.1: 在 `RustScannerClient.ScanPortsAsync` 中实现 15 秒无消息心跳超时检测
  - [x] SubTask 2.2: 超时后主动关闭连接、停止 Rust 服务，并抛出可识别的 `RustScannerTimeoutException`
  - [x] SubTask 2.3: 修复 `ExecuteRustScanAsync` 异常时状态未重置的问题（清空结果集合、停止服务、重置计数器）
  - [x] SubTask 2.4: 确保 `ExecuteExpertScanAsync` 捕获 Rust 异常后调用 `ExecuteNativeScanAsync` 完成回退
  - [x] SubTask 2.5: 修复 `StartServiceAsync` 中重定向 Rust 标准输出/错误但不读取，导致子进程日志缓冲区满而阻塞的问题

- [x] Task 3: 集成验证
  - [x] SubTask 3.1: 使用 `ExpertIntegrationTest` 验证 Rust 服务对 23 个已知端口的检测仍保持 100% 召回/精确率
  - [x] SubTask 3.2: 在桌面应用中验证专家模式扫描 4 个自定义端口（关闭服务检测）能在 5 秒内完成
  - [x] SubTask 3.3: 在桌面应用中验证专家模式扫描 1000 个常用端口（开启服务检测）能持续返回进度并最终完成或正确回退
  - [x] SubTask 3.4: 验证 Rust 可执行文件缺失时自动使用 C# 扫描器

# Task Dependencies
- Task 2 依赖于 Task 1（需要先确认 Rust 端响应机制正常）
- Task 3 依赖于 Task 1 和 Task 2
