# 修复 Rust 扫描服务连接与序列化问题 Spec

## Why

专家模式扫描每次都是"255 目标 0 开放端口 0.00s 完成"——根本原因有两层:
1. **JSON 字段命名不匹配**: C# 端 `RustScanRequest` 用 `System.Text.Json` 默认 camelCase 序列化(如 `tcpTimeoutMs`),Rust 端 `IpcMessage` 用 serde 默认 snake_case 期望(如 `tcp_timeout_ms`),导致反序列化失败
2. **错误处理不当**: Rust 端 `serde_json::from_slice(...).context("解析请求失败")?` 在失败时**通过 `?` 立即返回 Err,导致 `stream` 被 drop,客户端 ReadAsync 立即返回 0 (EOF)**,客户端误以为扫描完成

这两个问题导致 Rust 扫描服务**从未真正执行过一次扫描**。之前所有"成功"日志(Rust 启动、连接、发送请求)都是误报。

## What Changes

### 修复 #1: JSON 字段命名一致 (C# 端)

在 `RustScannerClient.ScanPortsAsync` 中,改用 `JsonNamingPolicy.SnakeCaseLower` 序列化 `RustScanRequest`:
- `RequestId` → `request_id`
- `MessageType` → `message_type`
- `TcpTimeoutMs` → `tcp_timeout_ms`
- `UdpTimeoutMs` → `udp_timeout_ms`
- `DetectService` → `detect_service`
- `IncludeClosed` → `include_closed`

(其他字段 `targets`, `ports`, `protocol`, `concurrency` 已经是小写,无需变动)

### 修复 #2: Rust 端优雅错误处理 (服务端)

修改 `rust-scanner-service/src/ipc.rs` 中的 `handle_client_connection` 和 `handle_tcp_client`:
- **不再使用 `?` 直接返回错误**(会关闭 stream)
- 改用 `match` 处理反序列化错误,发送 `IpcResponse::Error` 响应给客户端
- 仅在底层 IO 错误时返回 `Err`

### 修复 #3: 移除诊断日志 (清理)

移除之前为定位问题添加的调试日志(`✅ 读取到 X 字节请求`、`⏳ 开始接收Rust响应...` 等),保留有用的运行信息。

### 修复 #4: C# 端 ReadLineAsync 诊断日志 (清理)

清理 `RustScannerClient` 中为定位问题添加的 `readLineCount`、`readStart` 等临时变量和诊断日志。

### 修复 #5: 验证修复

添加 TestClient 集成测试,验证:
- camelCase 请求能被正确处理
- 收到 Complete 消息
- 扫描结果正确返回

## Impact

- **Affected specs**: 专家模式扫描、Rust 扫描服务集成
- **Affected code**:
  - `src/NetSecurityScanner.Core/Services/RustScannerClient.cs` (序列化方式)
  - `src/rust-scanner-service/src/ipc.rs` (错误处理)
  - `src/rust-scanner-service/src/main.rs` (日志级别恢复)

## ADDED Requirements

### Requirement: Rust 扫描服务 JSON 协议兼容

The system SHALL ensure C# 客户端序列化的 JSON 请求能被 Rust 服务端正确反序列化。

#### Scenario: 标准扫描请求
- **WHEN** C# 客户端发送 `RustScanRequest` 序列化后的 JSON
- **THEN** Rust 服务端应能反序列化成功并开始扫描
- **AND** C# 客户端应能接收 Progress、Result、Complete 消息
- **AND** 实际扫描耗时与目标/端口数成正比(不应 < 1 秒完成 255×1000 端口)

### Requirement: Rust 服务端优雅错误响应

The system SHALL ensure Rust 服务端在反序列化失败时发送 Error 响应而非直接关闭 stream。

#### Scenario: 收到无效 JSON
- **WHEN** 客户端发送格式错误的 JSON(例如缺少必填字段)
- **THEN** Rust 服务端应发送 `{"type":"Error","code":400,"message":"..."}` 响应
- **AND** 保持连接,允许客户端发送新请求
- **AND** 客户端应能正确解析 Error 消息

### Requirement: 移除诊断日志

The system SHALL remove the diagnostic logs added during debugging (`✅ 读取到 X 字节请求`, `⏳ 开始接收Rust响应...`, `📥 ReadLine #N`, `⚠️ ReadLineAsync 返回 null`).

#### Scenario: 正常扫描过程
- **WHEN** 专家模式扫描正常进行
- **THEN** 日志应简洁清晰
- **AND** 关键事件(启动、连接、扫描进度、完成)仍应有日志

## MODIFIED Requirements

### Requirement: Rust 扫描协议字段命名

**原状态**: C# 用 camelCase, Rust 用 snake_case, **不兼容**

**新状态**: C# 端使用 `JsonNamingPolicy.SnakeCaseLower` 序列化,所有字段名都使用 snake_case, 与 Rust 端 `IpcMessage` 完全一致。

### Requirement: Rust 错误处理流

**原状态**: 任何错误都通过 `?` 提前返回,关闭 stream, 客户端 EOF

**新状态**:
- JSON 解析错误 → 发送 `IpcResponse::Error`, 保持连接
- 底层 IO 错误 → 返回 `Err`, 关闭 stream
- 扫描过程中的内部错误 → 发送 Error 响应, 仍完成整个请求

## REMOVED Requirements

### Requirement: 临时诊断日志

**Reason**: 诊断日志用于定位问题,修复后已无价值,会污染正常运行的日志输出。

**Migration**: 已添加的 `readLineCount`、`readStart`、各类 `OnLog` 诊断消息全部移除,仅保留运行信息(`🚀 Rust扫描服务已启动`、`✅ 已连接到Rust扫描服务`、`✅ Rust扫描完成` 等)。
