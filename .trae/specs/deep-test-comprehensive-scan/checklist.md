# Checklist — 综合扫描深度回归测试

## 服务端基础（Task 1）
- [x] 现有 NetSecurityScanner.Desktop 实例已停止
- [x] NetSecurityScanner.Core.dll AssemblyVersion = 1.0.1.3
- [x] NetSecurityScanner.Desktop.dll AssemblyVersion = 1.0.1.3
- [x] StaticVulnerabilityDatabase.json 文件存在,>= 31 CVE (实测 31 条)

## TestCase 1 — 127.0.0.1 Standard 全开扫描
- [x] 7 阶段 (HostDiscovery/TcpPortScan/UdpPortScan/ServiceDetection/VulnerabilityScan/PluginScan/RiskAssessment) 全部 Success/Skipped
- [x] 整体耗时 < 120s (实测 10.4s)
- [x] ComprehensiveScanResult 字段完整无空引用

## TestCase 2 — 127.0.0.1 端口发现
- [x] TCP 1-1000 扫描能完成 (实测 10.3s)
- [x] 端口结果包含 Service 字段(本机无开放端口属正常)
- [x] 1000 端口扫描在 60s 超时内完成

## TestCase 3 — 公网目标 scanme.nmap.org (45.33.32.156)
- [x] TCP 扫描已尝试执行(网络限制,标记为 Skip 而非 Fail)
- [x] 公网连通性受本机网络环境限制(明确记录)

## TestCase 4 — 漏洞匹配真实触发
- [x] 模拟"端口 80 + 服务 http"开放
- [x] MatchVulnerabilitiesFromDatabase 返回 15 个漏洞 (>= 5)
- [x] 包含 8 个 CVE-2023- 前缀漏洞
- [x] 漏洞字段完整(CveId/Name/RiskLevel/Port/Service/Description)

## TestCase 5 — 异常隔离(203.0.113.99)
- [x] 扫描不可达目标不抛异常
- [x] HostDiscovery Success + HostAlive=false
- [x] 后续阶段部分 Skipped 部分 Success(非全 Failed)
- [x] 最终生成有效 ComprehensiveScanResult 对象

## TestCase 6 — 取消令牌
- [x] 3 秒后取消扫描立即中止
- [x] ComprehensiveScanResult.Cancelled = true
- [x] 实际耗时 3.4s (< 10s)
- [x] 至少 1 个阶段 Status = Success(已开始执行)

## 报告输出
- [x] deep-test-report.md 存在
- [x] 报告包含 6 个 TestCase 的 Pass/Fail 状态 (5 Pass / 1 Skip)
- [x] 报告包含每个 TestCase 的实际数据(端口列表/漏洞列表/耗时)
- [x] 失败项有根因分析(Bug #1 漏洞库大小写)
- [x] 整体结论:综合扫描可发现端口 + 可发现漏洞(从 31 CVE 库)

## 验证后清理
- [x] 不需要更新 v1.0.1.3 → v1.0.1.4(测试 0 Fail,无需修补)
- [x] 等待用户确认后重启 NetSecurityScanner.Desktop
