# 综合扫描深度回归测试 Spec

## Why
v1.0.1.3 修复了漏洞数据库 JSON 反序列化大小写不匹配的 Bug（3 CVE → 31 CVE,5 匹配 → 49 匹配）。本次深度测试旨在**端到端验证**综合扫描在真实目标上的端口发现与漏洞匹配能力,确认:
1. 6 阶段编排可完整执行且不中断
2. 端口扫描对真实目标能命中
3. 漏洞匹配能真实触发（31 CVE 库可用）
4. 5 个结果 Tab 数据填充正确
5. 导出/对比/Markdown 复制可用

## What Changes
- **不修改任何业务代码** — 纯测试/验证任务
- 新增 `Tools/DeepTest` 深度测试控制台项目
  - 包含 6 个测试场景（TestCase 1-6）
  - 每个场景验证一个独立的综合扫描能力
- 输出 `Tools/DeepTest/deep-test-report.md` 报告
- 必要时,**只修复**在测试中发现的实际 Bug

## Impact
- Affected specs: `enhance-comprehensive-scan`（v1.0.1.3 实现）
- Affected code: 仅诊断/测试代码,不动 `ComprehensiveScanService.cs` 业务逻辑
- 真实目标选择:
  - `127.0.0.1` (本地,验证基线)
  - `scanme.nmap.org` (Nmap 官方测试机,公网 80/22 开放)
  - `testphp.vulnweb.com` (Acunetix 故意存在漏洞的 Web 目标)

## ADDED Requirements

### Requirement: 6 阶段编排完整执行
综合扫描 SHALL 完整执行 6 个阶段且不中断。

#### Scenario: 127.0.0.1 + Standard 预设
- **WHEN** 用户对 127.0.0.1 启动 Standard 扫描(全开)
- **THEN** 7 个阶段 (HostDiscovery / TcpPortScan / UdpPortScan / ServiceDetection / VulnerabilityScan / PluginScan / RiskAssessment) 全部 `Success` 或 `Skipped`,无 `Failed`
- **AND** 整体执行时间 < 120s

### Requirement: 端口扫描真实命中
端口扫描 SHALL 能发现真实目标的开放端口。

#### Scenario: scanme.nmap.org TCP 扫描
- **WHEN** 对 `45.33.32.156` (scanme.nmap.org) 启动 TCP 扫描 1-1000
- **THEN** 至少发现 2 个开放端口(已知 22, 80)
- **AND** 端口 22 识别为 `ssh`,端口 80 识别为 `http`

### Requirement: 漏洞匹配真实触发
漏洞匹配 SHALL 真实从 31 CVE 库中匹配,非仅返回 3 兜底 CVE。

#### Scenario: 80 端口 Web 服务
- **WHEN** 端口 80 + 服务 `http` 出现在开放端口列表
- **THEN** `MatchVulnerabilitiesFromDatabase` 返回 >= 5 个漏洞(基于 31 CVE 库)
- **AND** 至少包含 1 个 `CVE-2023-xxx` 漏洞(证明新数据库加载)

### Requirement: 6 阶段异常隔离
任一阶段异常 SHALL 不阻断后续阶段。

#### Scenario: 不可达目标
- **WHEN** 对不存在/不可达的目标(如 `203.0.113.99`)启动全开扫描
- **THEN** `HostDiscovery` 阶段 `Success` 且 `HostAlive=false`
- **AND** 后续 6 个阶段仍执行(标记 `Skipped` 或部分 `Success`)
- **AND** 最终生成 `ComprehensiveScanResult` 对象(非抛异常)

### Requirement: 结果 5 Tab 数据完整
`ComprehensiveScanResultWindow` SHALL 在 5 个 Tab 上均有数据。

#### Scenario: 真实扫描后结果窗口
- **WHEN** 综合扫描完成
- **THEN** 概览 Tab 显示 目标/扫描类型/耗时/HostAlive/风险等级
- **AND** 端口 Tab 至少 1 行(本地/远程均无开放端口时显示"无数据"占位)
- **AND** 漏洞 Tab 显示从数据库匹配的真实漏洞
- **AND** 服务/插件 Tab 按数据填充

### Requirement: 导出/对比/Markdown 复制可用
3 个结果操作 SHALL 全部可用。

#### Scenario: 导出 + 复制
- **WHEN** 扫描完成后点击"导出 JSON"
- **THEN** 文件写入 `Documents/NetSecurityScanner/Exports/综合扫描_{ip}_{timestamp}.json` 且 JSON 有效
- **WHEN** 点击"复制为 Markdown"
- **THEN** `Clipboard` 包含目标/端口数/漏洞数/风险等级的中文 Markdown 文本

## MODIFIED Requirements
无（纯测试任务,不修改任何功能需求）

## REMOVED Requirements
无
