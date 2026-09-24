# 修复扫描历史记录查看报错 Spec

## Why
扫描历史记录中各种扫描类型（综合扫描、端口扫描、漏洞扫描、Agent安全扫描）点击查看时存在报错、数据显示不完整或程序卡死的问题。根因包括：综合扫描产生重复历史记录且 ScanId 不匹配导致找不到独立JSON文件、Agent安全扫描完全不保存历史记录、反序列化缺少选项导致潜在数据丢失、RiskAssessment 可能为 null 等。

## What Changes
- 修复 `SaveScanResultAsync` 自动创建重复 ScanHistoryItem 的问题，当 ScanId 已存在时更新而非添加
- 综合扫描 `UpdateScanHistoryAsync` 恢复携带 PortScanResults/VulnerabilityResults 作为回退数据源
- `GetScanResultByIdAsync` 反序列化添加统一的 JsonSerializerOptions，反序列化后 null 防护
- `ShowCompleteScanResultWindow` 添加 RiskAssessment null 防护和 ScanDuration 显示
- Agent安全扫描完成后保存历史记录到 JsonDatabaseService
- 端口扫描和漏洞扫描的 CompleteScanResult 补充 ScanDuration 字段
- 扫描历史 DataGrid 设为 IsReadOnly=True 防止误编辑

## Impact
- Affected code:
  - NetSecurityScanner.Core/Services/JsonDatabaseService.cs — SaveScanResultAsync 去重、GetScanResultByIdAsync 添加选项和 null 防护
  - NetSecurityScanner.Desktop/MainWindow.xaml.cs — 综合扫描保存逻辑、ShowCompleteScanResultWindow 显示修复
  - NetSecurityScanner.Desktop/Views/Views/AgentSecurityScannerWindow.xaml.cs — 添加历史记录保存
  - NetSecurityScanner.Desktop/MainWindow.xaml — DataGrid IsReadOnly

## ADDED Requirements

### Requirement: Agent安全扫描保存历史记录
系统 SHALL 在 Agent 安全扫描完成后将扫描结果保存到 JsonDatabaseService，使其在扫描历史记录中可见。

#### Scenario: Agent安全扫描完成
- **WHEN** Agent 安全扫描完成并产生结果
- **THEN** 系统将 AgentScanResult 转换为 CompleteScanResult 并保存
- **AND** 扫描历史记录列表中显示该记录
- **AND** 双击该记录可查看详细扫描结果

### Requirement: 统一 JsonSerializerOptions
系统 SHALL 在所有 JSON 序列化和反序列化操作中使用统一的 JsonSerializerOptions。

#### Scenario: 反序列化 CompleteScanResult
- **WHEN** 从 JSON 文件加载 CompleteScanResult
- **THEN** 使用与序列化相同的 JsonSerializerOptions（IncludeFields=true）
- **AND** 对 RiskAssessment、PortScanResults、VulnerabilityResults 进行 null 防护

## MODIFIED Requirements

### Requirement: SaveScanResultAsync 去重
SaveScanResultAsync SHALL 在 scan_history.json 中检测到相同 ScanId 的记录时更新而非添加新记录。

#### Scenario: 综合扫描保存结果
- **WHEN** 综合扫描完成调用 SaveScanResultAsync
- **THEN** 如果 scan_history.json 中已存在相同 ScanId 的记录，更新该记录
- **AND** 如果不存在，添加新记录
- **AND** 不产生重复的历史记录

### Requirement: 综合扫描历史记录携带完整数据
综合扫描完成时 UpdateScanHistoryAsync 创建的 ScanHistoryItem SHALL 包含 PortScanResults 和 VulnerabilityResults 作为回退数据源。

#### Scenario: 独立JSON文件丢失时回退显示
- **WHEN** 综合扫描的独立 JSON 文件丢失或损坏
- **THEN** 从 scan_history.json 中的 ScanHistoryItem 获取 PortScanResults 和 VulnerabilityResults
- **AND** 正常显示端口和漏洞数据

### Requirement: ShowCompleteScanResultWindow 显示完整信息
ShowCompleteScanResultWindow SHALL 显示扫描耗时并对 RiskAssessment 进行 null 防护。

#### Scenario: RiskAssessment 为 null
- **WHEN** 旧版本保存的 CompleteScanResult 中 RiskAssessment 为 null
- **THEN** 不抛出 NullReferenceException
- **AND** 跳过风险评估部分的显示

#### Scenario: 显示扫描耗时
- **WHEN** CompleteScanResult 的 ScanDuration 大于 0
- **THEN** 在基本信息区域显示扫描耗时

## REMOVED Requirements
无
