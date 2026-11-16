# Checklist

- [x] C# 端 `RustScannerClient.ScanPortsAsync` 使用自定义 `SnakeCaseNamingPolicy` 序列化
- [x] C# 端 `dotnet build NetSecurityScanner.Desktop.csproj` 0 错误
- [x] Rust 端 `handle_client_connection` 用 `match` 处理 JSON 解析错误, 发送 `IpcResponse::Error` 响应
- [x] Rust 端 `handle_tcp_client` 用 `match` 处理 JSON 解析错误, 发送 `IpcResponse::Error` 响应
- [x] Rust 端 `cargo build --release` 通过编译
- [x] 新的 `rust-scanner-service.exe` 已复制到 `bin/Debug/net6.0-windows/`
- [x] Rust 端 `✅ 读取到 X 字节请求` 诊断日志已移除
- [x] C# 端 `⏳ 开始接收Rust响应...` 诊断日志已移除
- [x] C# 端 `📥 ReadLine #N` 诊断日志已移除
- [x] C# 端 `⚠️ ReadLineAsync 返回 null` 诊断日志已移除
- [x] C# 端 `readLineCount` 临时变量已移除
- [x] C# 端 `readStart` 临时变量已移除
- [x] TestClient 扫描 2 目标 × 8 端口, 总耗时 1023ms (实际扫描, 不是 0.00s)
- [x] 扫描结果包含 5 个开放端口 (127.0.0.1:445 smb, 127.0.0.1:135, 192.168.101.1:80 http 等)
- [x] 收到 Complete 消息
- [x] 主程序启动成功 (PID 34452)
- [x] JSON 字段名已验证为 snake_case: `request_id`, `message_type`, `tcp_timeout_ms`, `udp_timeout_ms`, `detect_service`, `include_closed`
- [x] 测试脚本 (diag_*.py, cs_*.py, final_test.py 等) 已清理, 保留 TestClient 作为回归测试
