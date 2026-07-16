# 修复专家模式 Rust 扫描卡住无法返回结果

## Why
当前专家模式扫描虽然能成功启动 Rust 扫描服务、建立命名管道连接并 flush 扫描请求，但请求发送后 Rust 端不再返回任何 progress/result/complete 响应，导致 UI 长时间卡住且最终无法完成扫描。需要通过诊断与修复让 Rust 扫描器在专家模式下可靠工作，并在异常时自动回退到内置 C# 扫描器。

## What Changes
- 修复 Rust 扫描服务在收到扫描请求后无响应的根因（命名管道异步 IO / progress 通道阻塞 / 服务检测死锁等）
- 在 Rust 端增加扫描生命周期关键节点的诊断日志
- 在 C# 客户端增加心跳超时后的主动断开与自动回退逻辑
- 修复 C# 端 `ExecuteRustScanAsync` 异常时重置状态并正确回退到 `ExecuteNativeScanAsync`
- 验证小批量端口、大批量端口、开启/关闭服务检测等场景均能正常完成

## Impact
- 受影响能力：专家模式端口扫描、Rust 高性能扫描服务
- 受影响代码：
  - `NetSecurityScanner/src/rust-scanner-service/src/scanner.rs`
  - `NetSecurityScanner/src/rust-scanner-service/src/ipc.rs`
  - `NetSecurityScanner/src/NetSecurityScanner.Core/Services/RustScannerClient.cs`
  - `NetSecurityScanner/src/NetSecurityScanner.Desktop/Views/Views/ExpertModeWindow.xaml.cs`

## ADDED Requirements

### Requirement: Rust 扫描请求响应可观测
The system SHALL 在 Rust 扫描服务处理扫描请求的各关键阶段（请求解析、任务分发、progress 发送、结果发送、complete 发送）输出结构化日志，便于定位卡住位置。

#### Scenario: 专家模式扫描 1000 端口
- **WHEN** 用户在专家模式启动 1000 端口 TCP 扫描
- **THEN** Rust 服务日志或 C# 日志中应出现请求接收、扫描开始、progress/result/complete 等阶段信息

### Requirement: Rust 扫描卡住时自动回退
The system SHALL 在 Rust 扫描未在合理时间内返回任何响应时，主动关闭连接并自动切换到内置 C# 扫描器完成扫描。

#### Scenario: Rust 服务无响应
- **GIVEN** Rust 扫描服务已连接但 15 秒内未收到任何 progress/result/complete 消息
- **WHEN** 心跳超时触发
- **THEN** C# 客户端应断开连接、停止 Rust 进程，并调用 `ExecuteNativeScanAsync` 继续扫描

## MODIFIED Requirements

### Requirement: 专家模式扫描完成
The system SHALL 保证专家模式下使用 Rust 扫描器时，扫描能够正常启动、接收进度、返回结果并标记完成。

#### Scenario: 小批量端口扫描
- **WHEN** 用户扫描 4 个自定义端口（如 11434,80,443,22）且关闭服务检测
- **THEN** 扫描应在 5 秒内完成并显示开放端口结果

#### Scenario: 大批量端口扫描
- **WHEN** 用户扫描 1000 个常用端口且开启服务检测
- **THEN** 扫描应持续返回进度条更新，并在合理时间内完成或正确回退

#### Scenario: Rust 扫描器不可用
- **GIVEN** Rust 可执行文件不存在或服务无法启动
- **WHEN** 用户点击开始扫描
- **THEN** 系统应自动使用内置 C# 扫描器完成扫描
