# Tasks

- [x] Task 1: 修复 JsonDatabaseService.SaveScanResultAsync 去重逻辑
  - [x] 1.1: 添加静态 _jsonOptions 字段统一序列化/反序列化选项
  - [x] 1.2: SaveScanResultAsync 中检测 ScanId 是否已存在，存在则更新而非添加
  - [x] 1.3: GetScanResultByIdAsync 使用 _jsonOptions 反序列化，添加 null 防护
  - [x] 1.4: 所有序列化调用统一使用 _jsonOptions

- [x] Task 2: 修复综合扫描保存逻辑
  - [x] 2.1: UpdateScanHistoryAsync 恢复携带 PortScanResults 和 VulnerabilityResults
  - [x] 2.2: CompleteScanResult 补充 ScanDuration 字段设置
  - [x] 2.3: ShowCompleteScanResultWindow 添加 RiskAssessment null 防护和 ScanDuration 显示

- [x] Task 3: 修复端口扫描和漏洞扫描的 CompleteScanResult
  - [x] 3.1: 端口扫描保存时补充 ScanDuration
  - [x] 3.2: 漏洞扫描保存时补充 ScanDuration

- [x] Task 4: Agent安全扫描保存历史记录
  - [x] 4.1: AgentSecurityScannerWindow 扫描完成后将结果转换为 CompleteScanResult 并保存
  - [x] 4.2: 实现 AgentScanResult 到 VulnerabilityResult 列表的映射方法

- [x] Task 5: 修复 DataGrid 可编辑问题
  - [x] 5.1: ScanHistoryDataGrid 设置 IsReadOnly="True"
  - [x] 5.2: CheckBox 列单独设置 IsReadOnly="False"

- [x] Task 6: 编译验证
  - [x] 6.1: dotnet build 确认 0 错误

# Task Dependencies
- Task 2 depends on Task 1 (去重逻辑需要先修复，否则综合扫描仍会产生重复记录)
- Task 3 depends on Task 1 (使用统一的 _jsonOptions)
- Task 4 独立
- Task 5 独立
- Task 6 depends on Task 1, 2, 3, 4, 5
