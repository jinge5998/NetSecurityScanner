# Tasks

- [ ] Task 1: 重新组织章节生成顺序与编号
  - [ ] SubTask 1.1: 在 `HistoryWordReportGenerator.cs` 中将 `GenerateScanScopeSection` 方法的 `chapterTitle` 文字从 "1.5 扫描范围与限制" 改为 "第二章 扫描范围与方法"。
  - [ ] SubTask 1.2: 在 `GenerateScanScopeSection` 方法中将子章节标题 `S.1 扫描对象 / S.2 扫描范围外 / S.3 已知限制 / S.4 使用声明` 改为 `2.1 扫描对象 / 2.2 扫描范围外 / 2.3 已知限制 / 2.4 使用声明`。
  - [ ] SubTask 1.3: 在 `GenerateFromHistoryRecordToPath` 和 `GenerateFromMultipleRecordsToPath` 中调整章节调用顺序为：封面 → 目录 → 执行摘要 → 扫描范围与方法 → 端口扫描结果 → 漏洞详情分析 → 风险评估 → 修复建议 → 威胁情报分析 → 合规参考 → 结论与建议 → 附录A → 附录B。
  - [ ] SubTask 1.4: 在 `GeneratePortScanSection` 中将章节标题从 "二、端口扫描结果" 改为 "第三章 端口扫描结果"，子章节从 2.x 重新编号为 3.x。
  - [ ] SubTask 1.5: 在 `GenerateVulnerabilitySection` 中将章节标题从 "三、漏洞详情分析" 改为 "第四章 漏洞详情分析"，子章节从 3.x 重新编号为 4.x。
  - [ ] SubTask 1.6: 在 `GenerateRiskAssessment` 中将章节标题从 "四、风险评估" 改为 "第五章 风险评估"，子章节从 4.x 重新编号为 5.x。
  - [ ] SubTask 1.7: 在 `GenerateRemediationSection` 中将章节标题从 "五、修复建议" 改为 "第六章 修复建议"，子章节从 5.x 重新编号为 6.x。
  - [ ] SubTask 1.8: 在 `GenerateThreatIntelligenceSection` 中将章节标题从 "六、威胁情报分析" 改为 "第七章 威胁情报分析"，子章节从 6.x 重新编号为 7.x。
  - [ ] SubTask 1.9: 在 `GenerateComplianceSection` 中将章节标题从 "七、合规参考" 改为 "第八章 合规参考"，子章节从 7.x 重新编号为 8.x。
  - [ ] SubTask 1.10: 在 `GenerateConclusionSection` 中将章节标题从 "八、结论与建议" 改为 "第九章 结论与建议"，子章节从 8.x 重新编号为 9.x。
  - [ ] SubTask 1.11: 在 `GenerateScanScopeSection` 中移除"所有开放端口详情"表格与"高危端口列表"表格（已迁移到第三章）。

- [ ] Task 2: 修复条件子章节编号不稳定问题
  - [ ] SubTask 2.1: 在 `GeneratePortScanSection` 中将"2.3 高危端口安全警示"标题改为"3.3 高危端口安全警示"，并确保其始终存在标题+内容（无高危端口时显示占位说明）。
  - [ ] SubTask 2.2: 在 `GeneratePortScanSection` 中将"2.3/2.4 所有端口详情"逻辑改为统一编号"3.4 所有端口详情"，无论是否存在高危端口都使用相同编号。
  - [ ] SubTask 2.3: 在 `GeneratePortScanSection` 中将"2.5 服务分布统计"改为"3.5 服务分布统计"，并在无服务数据时显示占位说明。
  - [ ] SubTask 2.4: 在 `GenerateRemediationSection` 中将"5.3 高危漏洞专项修复方案"改为"6.3 高危漏洞专项修复方案"，并确保其始终存在标题+内容（无高危漏洞时显示占位说明）。
  - [ ] SubTask 2.5: 在 `GenerateVulnerabilitySection` 中将"3.1~3.5"改为"4.1~4.5"，并对 4.2 受影响服务分布、4.3 漏洞类型分类统计、4.5 漏洞详细信息 在无数据时显示占位说明。
  - [ ] SubTask 2.6: 在 `GenerateRiskAssessment` 中将"4.1~4.4"改为"5.1~5.4"，并对 5.2 风险等级矩阵、5.3 风险分布图表 在无漏洞时显示占位说明。

- [ ] Task 3: 重构目录生成方法
  - [ ] SubTask 3.1: 重写 `GenerateTableOfContents` 方法的 `entries` 数组，按新章节顺序与编号输出目录。
  - [ ] SubTask 3.2: 目录条目 SHALL 包含：第一章 执行摘要（1.1~1.4）、第二章 扫描范围与方法（2.1~2.4）、第三章 端口扫描结果（3.1~3.5）、第四章 漏洞详情分析（4.1~4.5）、第五章 风险评估（5.1~5.4）、第六章 修复建议（6.1~6.4）、第七章 威胁情报分析（7.1~7.4）、第八章 合规参考（8.1~8.4）、第九章 结论与建议（9.1~9.5）、附录A、附录B。
  - [ ] SubTask 3.3: 在 `GenerateTableOfContents` 末尾的"免责声明"之后增加一行说明："注：报告章节编号与正文严格对应。如某个子章节无对应数据，将显示占位说明。"

- [ ] Task 4: 新增附录B 报告使用与法律声明
  - [ ] SubTask 4.1: 在 `HistoryWordReportGenerator.cs` 中新增私有静态方法 `GenerateAppendixB(DocX doc)`，输出"附录B 报告使用与法律声明"章节。
  - [ ] SubTask 4.2: 附录B SHALL 包含子章节：B.1 报告使用范围、B.2 数据来源说明、B.3 修复建议限制、B.4 责任限制、B.5 保密声明、B.6 版本与修订记录。
  - [ ] SubTask 4.3: 在 `GenerateFromHistoryRecordToPath` 和 `GenerateFromMultipleRecordsToPath` 中，在 `GenerateCveAppendix` 之后调用 `GenerateAppendixB`。
  - [ ] SubTask 4.4: B.6 版本与修订记录 SHALL 包含：报告生成工具（NetSecurityScanner + 版本号）、报告生成时间、风险评估方法（基于CVSS v3.1 + OWASP）、数据来源说明、报告模板版本、修订说明。

- [ ] Task 5: 增强执行摘要章节
  - [ ] SubTask 5.1: 在 `GenerateExecutiveSummary` 中将章节标题从"一、执行摘要"改为"第一章 执行摘要"，子章节从 1.1~1.4 保持不变。
  - [ ] SubTask 5.2: 在 `GenerateExecutiveSummary` 末尾新增"1.5 扫描结论概览"小节，无论是否有漏洞都给出整体定性的安全态势总结（不少于 80 个中文字符）。

- [ ] Task 6: 深度完善各章节内容（v2 增强）
  - [ ] SubTask 6.1: 在封面 `GenerateCoverPage` 中新增"报告编号""扫描工程师""审核签发"等元数据区块
  - [ ] SubTask 6.2: 在目录 `GenerateTableOfContents` 的"免责声明"前增加"本报告使用说明"导言段落（≥120字）
  - [ ] SubTask 6.3: 在 1.1 核心统计数据 `GenerateExecutiveSummary` 的统计表后增加"扫描结果快读"结论段
  - [ ] SubTask 6.4: 强化 1.5 扫描结论概览，使其至少包含"总体态势 + 漏洞态势 + 端口态势 + 风险处置优先级 + 总体建议"5个维度，篇幅≥200字
  - [ ] SubTask 6.5: 在 2.1 扫描对象 `GenerateScanScopeSection` 中增加"扫描策略说明"段
  - [ ] SubTask 6.6: 在 3.1 扫描方法说明 `GeneratePortScanSection` 中增加"扫描流程图"文字描述
  - [ ] SubTask 6.7: 强化 3.3 高危端口安全警示，每个高危端口增加"风险描述 + 攻击场景 + 修复方向"3项
  - [ ] SubTask 6.8: 强化 4.5 漏洞详细信息 `AddVulnerabilityDetailBlock`，每条漏洞固定包含【漏洞概述、CVSS评分、影响范围、检测方法、修复建议】5个字段
  - [ ] SubTask 6.9: 在 5.1 风险评估项目 `GenerateRiskAssessment` 中增加"评估方法论"说明段
  - [ ] SubTask 6.10: 重构 5.4 安全建议概述为"立即行动 / 短期 / 中期 / 长期"4个时间维度
  - [ ] SubTask 6.11: 强化 6.3 高危漏洞专项修复方案，每个漏洞增加"风险描述 + 修复步骤 + 验证方法"3项
  - [ ] SubTask 6.12: 在 7.1 活跃威胁向量 `BuildThreatVectors` 调用前增加"威胁演化趋势"补充说明段
  - [ ] SubTask 6.13: 在 8.4 合规总结中增加"合规建设路线图"分阶段说明（3阶段）
  - [ ] SubTask 6.14: 在 9.1 总体安全评级中增加"评分维度权重"说明表
  - [ ] SubTask 6.15: 固定 9.3 核心结论 `BuildCoreConclusions` 输出 4-6 条结论
  - [ ] SubTask 6.16: 重构 9.4 长期安全建议为 P1/P2/P3 三档，每档至少 5 条具体可执行建议
  - [ ] SubTask 6.17: 完善 9.5 报告文档信息，确保包含 6 项元数据（工具版本/扫描引擎/生成时间/评估方法/数据来源/模板版本）
  - [ ] SubTask 6.18: 完善附录 B.1~B.6 六大子章节，每节至少 4-6 条要点

- [ ] Task 7: 编译与运行验证
  - [ ] SubTask 7.1: 停止运行中的 `NetSecurityScanner.Desktop.exe` 进程（如有）
  - [ ] SubTask 7.2: 执行 `dotnet build` 验证无编译错误
  - [ ] SubTask 7.3: 启动应用程序，生成测试用的历史扫描记录 Word 报告
  - [ ] SubTask 7.4: 验证报告章节顺序、编号与目录一致，所有子章节均有内容（包括占位说明）

# Task Dependencies
- Task 2 depends on Task 1
- Task 3 depends on Task 1, Task 2
- Task 4 depends on Task 1
- Task 5 depends on Task 1
- Task 6 depends on Task 1, Task 2, Task 3, Task 4, Task 5
- Task 7 depends on Task 6
