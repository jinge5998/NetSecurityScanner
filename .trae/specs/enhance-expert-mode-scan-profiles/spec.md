# 专家模式扫描模式推荐与高级参数完善

## Why
当前专家模式仅提供基础的并发、超时和服务检测开关，用户在不同场景下难以快速选择最优扫描策略。本项目需要一套"预设模式 + 智能推荐 + 手动微调"的扫描配置体系，帮助用户在精度与速度之间快速找到平衡，并暴露更多高级参数满足专业需求。

## What Changes
- 专家模式 UI 增加**扫描模式**下拉框：快速、标准、深度、自定义
- 新增**智能推荐引擎**，根据目标数量、网络延迟、历史扫描结果、Rust 服务当前负载推荐最佳模式与参数
- 展开/折叠的**高级参数面板**，暴露 TCP/UDP 并发数、超时时间、重试次数、扫描前 Ping 探测
- Rust 扫描服务支持通过扫描请求接收并应用上述动态参数
- 保存用户最后一次使用的高级参数配置

## Impact
- 受影响能力：专家模式端口扫描、扫描参数配置
- 受影响代码：
  - `NetSecurityScanner/src/NetSecurityScanner.Desktop/Views/Views/ExpertModeWindow.xaml`
  - `NetSecurityScanner/src/NetSecurityScanner.Desktop/Views/Views/ExpertModeWindow.xaml.cs`
  - `NetSecurityScanner/src/NetSecurityScanner.Core/Services/RustScannerClient.cs`
  - `NetSecurityScanner/src/NetSecurityScanner.Core/Services/PortScanner.cs`
  - `NetSecurityScanner/src/rust-scanner-service/src/scanner.rs`
  - `NetSecurityScanner/src/rust-scanner-service/src/ipc.rs`

## ADDED Requirements

### Requirement: 预设扫描模式
The system SHALL 在专家模式提供快速、标准、深度、自定义四种预设扫描模式，每种模式对应明确的端口范围、超时、并发配置。

#### Scenario: 用户选择快速模式
- **WHEN** 用户在专家模式选择"快速扫描"
- **THEN** 系统使用 Top 100 端口、超时 100ms、TCP 并发 100、UDP 并发 50

#### Scenario: 用户选择标准模式
- **WHEN** 用户在专家模式选择"标准扫描"
- **THEN** 系统使用 Top 1000 端口、超时 300ms、TCP 并发 50、UDP 并发 20

#### Scenario: 用户选择深度模式
- **WHEN** 用户在专家模式选择"深度扫描"
- **THEN** 系统使用 1-65535 全端口、超时 500ms、TCP 并发 30、UDP 并发 10

#### Scenario: 用户选择自定义模式
- **WHEN** 用户在专家模式选择"自定义扫描"
- **THEN** 系统保留用户手动设置的目标、端口、并发、超时等参数

### Requirement: 智能推荐引擎
The system SHALL 根据目标数量、网络延迟、历史扫描结果、Rust 服务当前负载向用户推荐最合适的扫描模式。

#### Scenario: 少量本地目标
- **GIVEN** 用户输入 1-5 个本地目标（如 127.0.0.1）
- **WHEN** 点击开始扫描
- **THEN** 系统推荐"标准扫描"或"自定义扫描（激进参数）"

#### Scenario: 大量远程目标
- **GIVEN** 用户输入超过 100 个目标
- **WHEN** 点击开始扫描
- **THEN** 系统推荐降低并发和超时，或分批扫描

#### Scenario: 网络延迟高
- **GIVEN** 首次探测目标平均 RTT > 200ms
- **WHEN** 系统计算推荐参数
- **THEN** 推荐增加超时时间，避免漏掉慢响应端口

### Requirement: 高级参数面板
The system SHALL 在专家模式提供可展开的高级参数面板，允许用户手动调整 TCP/UDP 并发数、超时时间、重试次数、是否启用扫描前 Ping 探测。

#### Scenario: 用户调整并发数
- **WHEN** 用户将 TCP 并发数从 50 改为 200
- **THEN** 系统校验 1-1000 范围，扫描时使用新值

#### Scenario: 用户启用 Ping 探测
- **WHEN** 用户勾选"扫描前 Ping 探测"
- **THEN** 扫描前先发送 ICMP Echo，仅对存活目标执行端口扫描

## MODIFIED Requirements

### Requirement: 专家模式扫描完成
The system SHALL 保证无论用户选择哪种扫描模式或高级参数，专家模式扫描都能正常启动、接收进度、返回结果并标记完成。

#### Scenario: 自定义参数扫描
- **WHEN** 用户选择自定义模式并设置 TCP 并发 200、超时 150ms
- **THEN** 扫描应正常启动，Rust 服务应用这些参数，并返回结果
