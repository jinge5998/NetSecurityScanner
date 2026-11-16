# Tasks

- [x] Task 1: 修复 C# 端 JSON 序列化字段命名 - 在 `RustScannerClient.ScanPortsAsync` 中使用 snake_case 序列化 `RustScanRequest`
  - [x] SubTask 1.1: 添加自定义 `SnakeCaseNamingPolicy` (兼容 .NET 6, 因为 `JsonNamingPolicy.SnakeCaseLower` 仅在 .NET 8+ 可用), 并在 `JsonSerializer.Serialize` 时使用
  - [x] SubTask 1.2: 编译验证 `dotnet build` 通过, 0 错误

- [x] Task 2: 修复 Rust 端错误处理 - 改 `serde_json::from_slice(...).context(...)?` 为发送 `IpcResponse::Error` 后继续
  - [x] SubTask 2.1: 在 `handle_client_connection` 和 `handle_tcp_client` 中, 用 `match` 块处理 JSON 解析错误, 失败时调用 `send_error_response` 发送错误响应后 return Ok
  - [x] SubTask 2.2: 编译验证 `cargo build --release` 通过
  - [x] SubTask 2.3: 复制新 Rust 可执行文件到 `bin/Debug/net6.0-windows/`

- [x] Task 3: 移除诊断日志 (Rust 端)
  - [x] SubTask 3.1: 移除 `info!("✅ 读取到 {} 字节请求 (read 返回 {})", ...)` 和 `info!("✅ TCP 读取到 {} 字节请求 (read 返回 {})", ...)`
  - [x] SubTask 3.2: 重新编译并复制到 bin 目录

- [x] Task 4: 移除诊断日志 (C# 端)
  - [x] SubTask 4.1: 移除 `RustScannerClient` 中的 `⏳ 开始接收Rust响应...`、`📥 ReadLine #N`、`⚠️ ReadLineAsync 返回 null` 等 OnLog 诊断消息
  - [x] SubTask 4.2: 移除 `readLineCount`、`readStart` 等临时变量
  - [x] SubTask 4.3: 重新编译 `dotnet build`

- [x] Task 5: 端到端验证
  - [x] SubTask 5.1: TestClient 用 snake_case 序列化, 扫描 2 目标 × 8 端口
  - [x] SubTask 5.2: 验证: 总耗时 1023ms, Progress 2 条, Result 5 条 (含 127.0.0.1:445 smb, 127.0.0.1:135, 192.168.101.1:80 http), Complete 收到
  - [x] SubTask 5.3: 主程序启动成功 (PID 34452)
  - [x] SubTask 5.4: 清理测试脚本 (TestClient/, diag_*.py, cs_*.py, final_test.py 等) - 保留 TestClient 作为回归测试

# Task Dependencies

- [Task 2] 依赖 [Task 1] 完成 (先修复 C# 端才能看到 Rust 错误)
- [Task 3] 依赖 [Task 2] 完成
- [Task 4] 依赖 [Task 1] 完成
- [Task 5] 依赖 [Task 1] [Task 2] [Task 3] [Task 4] 全部完成
