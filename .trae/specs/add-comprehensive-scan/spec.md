# 综合扫描功能完善 Spec

## Why
当前"开始综合扫描"菜单项功能不完整，仅简单调用端口扫描。需要实现完整的综合扫描流程：弹出IP输入对话框 → 自动执行TCP+UDP端口扫描 → 基于开放端口执行漏洞扫描 → 结果存储到扫描历史记录 → 支持从历史记录生成报告。

## What Changes
- 完善 ComprehensiveScanDialog 对话框，增加IP地址格式验证和扫描模式选择
- 重写 ExecuteComprehensiveScanAsync 核心流程，确保TCP/UDP端口扫描+漏洞扫描完整执行
- 修复 ScanHistoryItem 模型，确保 PortScanResults/VulnerabilityResults/Duration 字段可正确序列化
- 修复 JsonDatabaseService 中 SaveScanHistoryAsync/UpdateScanHistoryAsync 方法
- 扫描完成后自动更新端口扫描Tab、漏洞扫描Tab、AI风险评估Tab
- 扫描结果自动保存到历史记录，支持从历史记录查看和生成报告

## Impact
- Affected code: MainWindow.xaml.cs, ComprehensiveScanDialog.xaml/cs, JsonDatabaseService.cs, ScanHistoryItem
- Affected UI: 扫描菜单 → 开始综合扫描, 端口扫描Tab, 漏洞扫描Tab, AI风险评估Tab, 扫描历史记录Tab

## ADDED Requirements

### Requirement: 综合扫描输入对话框
系统 SHALL 在点击"开始综合扫描"时弹出配置对话框，包含：
- 目标IP地址/域名输入框（必填，支持IPv4/IPv6/域名格式）
- 端口范围输入框（默认1-1000，支持范围和逗号分隔格式）
- TCP协议扫描复选框（默认勾选）
- UDP协议扫描复选框（默认勾选）
- 漏洞扫描复选框（默认勾选，基于开放端口执行）
- 保存到历史记录复选框（默认勾选）
- 输入验证：IP地址/域名不能为空、至少选择一种扫描协议

#### Scenario: 用户输入有效IP并开始扫描
- **WHEN** 用户输入IP 192.168.1.1，端口范围1-1000，勾选TCP+UDP+漏洞扫描
- **THEN** 对话框关闭，开始执行综合扫描流程

#### Scenario: 用户未输入IP地址
- **WHEN** 用户点击开始扫描但IP地址为空
- **THEN** 显示警告"请输入目标IP地址"，对话框不关闭

### Requirement: 综合扫描执行流程
系统 SHALL 按以下顺序执行综合扫描：
1. TCP端口扫描（如勾选）- 使用 PortScanner.ScanTcpPortsAsync
2. UDP端口扫描（如勾选）- 使用 PortScanner.ScanUdpPortsAsync
3. 服务版本识别（自动，随端口扫描执行）
4. 漏洞扫描（如勾选且有开放端口）- 使用 VulnerabilityScanner.ScanVulnerabilitiesAsync
5. 风险等级计算
6. 保存结果到历史记录
7. 更新所有UI面板

#### Scenario: TCP+UDP+漏洞扫描全流程
- **WHEN** 用户勾选TCP+UDP+漏洞扫描
- **THEN** 系统依次执行TCP扫描→UDP扫描→漏洞扫描，实时更新进度

#### Scenario: 无开放端口时跳过漏洞扫描
- **WHEN** 端口扫描完成后未发现任何开放端口
- **THEN** 跳过漏洞扫描步骤，风险等级为"无风险"

### Requirement: 扫描结果存储到历史记录
系统 SHALL 将综合扫描结果保存到JSON数据库：
- 扫描开始时创建"扫描中"状态的历史记录
- 扫描完成后更新为最终结果（包含端口列表、漏洞列表、风险等级、耗时）
- ScanHistoryItem 包含 PortScanResults、VulnerabilityResults、Duration 字段
- 保存后自动刷新历史记录Tab显示

#### Scenario: 扫描结果保存成功
- **WHEN** 综合扫描完成且勾选"保存到历史记录"
- **THEN** 扫描结果写入JSON文件，历史记录Tab显示新记录

### Requirement: 扫描结果UI更新
系统 SHALL 在扫描完成后更新所有相关UI：
- 端口扫描Tab：显示所有端口扫描结果
- 漏洞扫描Tab：显示所有发现的漏洞
- AI风险评估Tab：自动执行风险评估并更新图表和建议
- 状态栏：显示扫描耗时、开放端口数、漏洞数、风险等级

#### Scenario: 扫描完成后UI更新
- **WHEN** 综合扫描完成
- **THEN** 端口扫描Tab显示端口列表，漏洞扫描Tab显示漏洞列表，AI风险评估Tab显示评估结果

## MODIFIED Requirements

### Requirement: StartScan_Click 事件处理
原实现：直接调用 StartPortScan_Click
新实现：弹出 ComprehensiveScanDialog 对话框，根据用户配置执行综合扫描

### Requirement: ScanHistoryItem 数据模型
原模型：仅包含 ScanId/TargetIp/ScanType/ScanTime/OpenPortsCount/VulnerabilitiesCount/RiskLevel/IsSelected
新模型：增加 PortScanResults（端口扫描结果列表）、VulnerabilityResults（漏洞扫描结果列表）、Duration（扫描耗时秒数）

## REMOVED Requirements
无
