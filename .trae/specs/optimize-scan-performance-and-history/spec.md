# 优化扫描速度与精度，并自动保存扫描历史记录

## Why
当前专家模式扫描已完成基础功能，但用户反馈扫描速度不够快、精度不够高。同时，扫描结果目前不会自动保存到历史记录中，也无法导出，影响后续审计和分析。本 spec 旨在通过参数调优、算法改进和结果持久化，全面提升专家模式的实用性。

## What Changes
- 优化四种预设扫描模式的参数，提升速度与精度的平衡
- 在 Rust 扫描服务中实现更高效的端口扫描算法（如 SYN 半开扫描可选、自适应超时）
- 增加扫描结果自动保存到历史记录的功能
- 支持从历史记录导出扫描结果为 CSV/JSON
- 在历史记录视图中显示专家模式扫描记录

## Impact
- 受影响能力：专家模式扫描、扫描历史记录、结果导出
- 受影响代码：
  - `NetSecurityScanner/src/rust-scanner-service/src/scanner.rs`
  - `NetSecurityScanner/src/NetSecurityScanner.Core/Services/PortScanner.cs`
  - `NetSecurityScanner/src/NetSecurityScanner.Core/Services/ScanHistoryService.cs`（已有或新建）
  - `NetSecurityScanner/src/NetSecurityScanner.Core/Models/ScanHistoryItem.cs`
  - `NetSecurityScanner/src/NetSecurityScanner.Desktop/Views/Views/ExpertModeWindow.xaml.cs`
  - `NetSecurityScanner/src/NetSecurityScanner.Desktop/Views/Views/ScanHistoryWindow.xaml*`（如有）

## ADDED Requirements

### Requirement: 扫描速度与精度优化
The system SHALL 提供更高效的扫描策略，减少漏报并提升扫描速度。

#### Scenario: 快速模式优化
- **WHEN** 用户选择快速模式扫描本地网络
- **THEN** 系统在 3 秒内完成 Top 100 端口扫描，漏报率低于 5%

#### Scenario: 标准模式优化
- **WHEN** 用户选择标准模式扫描单个目标
- **THEN** 系统在 10 秒内完成 Top 1000 端口扫描，漏报率低于 3%

#### Scenario: 自适应超时
- **GIVEN** 网络延迟不稳定
- **WHEN** 系统检测到大量端口超时
- **THEN** 自动增加超时时间并降低并发，避免漏报

### Requirement: 扫描结果自动保存历史记录
The system SHALL 在专家模式扫描完成后，自动将结果保存到扫描历史记录中。

#### Scenario: 扫描完成自动保存
- **WHEN** 专家模式扫描正常完成
- **THEN** 系统自动创建历史记录条目，包含目标、端口、结果、时间戳

#### Scenario: 历史记录可查看
- **GIVEN** 用户打开扫描历史窗口
- **WHEN** 历史列表加载
- **THEN** 专家模式扫描记录显示在列表中

### Requirement: 扫描结果导出
The system SHALL 支持将扫描结果导出为 CSV 或 JSON 文件。

#### Scenario: 导出当前结果
- **WHEN** 用户在专家模式扫描完成后点击导出
- **THEN** 弹出保存对话框，支持选择 CSV 或 JSON 格式

#### Scenario: 导出历史记录
- **GIVEN** 用户在历史记录中选中一条记录
- **WHEN** 用户点击导出
- **THEN** 该记录对应的扫描结果导出为所选格式

## MODIFIED Requirements

### Requirement: 专家模式扫描完成
The system SHALL 保证优化后的扫描算法不影响扫描稳定性，异常时仍正确回退到 C# 扫描器。
