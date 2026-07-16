# 专家级 PDF 安全扫描报告生成 Spec

## Why
当前 PDF 报告生成存在根本性缺陷：`GenerateRealPdfReport()` 接收的是 HTML 源码字符串（而非 Markdown），逐行纯文本渲染，**没有表格、没有封面、没有页眉页脚、没有专业排版**。生成的文件要么是损坏的空 PDF，要么是 HTML 源码原样打印在页面上，完全无法交付使用。需要基于 iTextSharp 的 PdfPTable/PdfPCell 等专业 API 重新设计一套可交付的专家级安全扫描报告。

## What Changes
- **重写 `GenerateRealPdfReport()` 方法**：从"逐行文本渲染"改为"结构化数据驱动的专业排版"
- **新增 `GenerateProfessionalPdfReport()` 重载方法**：直接接收结构化数据（List\<PortScanResult\> + List\<VulnerabilityResult\> + List\<RiskAssessmentItem\> + targetIp），绕过中间字符串
- **修改两个调用入口**（ExportReport_Click 和 GenerateReportFromHistory_Click）：PDF 格式走新的专业报告生成路径
- **移除旧的降级到 HTML 逻辑**：PDF 生成失败时给出明确错误提示，不再输出伪 .pdf 文件
- **BREAKING**: 不再依赖 `ReportGenerator.GenerateReport()` 返回的中间字符串来生成 PDF

## Impact
- Affected code: MainWindow.xaml.cs（2处入口 + 1个核心方法）
- 新增代码: 全新 ~400 行的专业 PDF 生成方法
- 不影响: 其他格式导出（TXT/CSV/HTML/Word）保持不变
- 数据源: 复用已有的 VulnerabilityResult、PortScanResult、RiskAssessmentItem、CompleteScanResult 模型

## ADDED Requirements

### Requirement: 专业 PDF 报告封面页
系统 SHALL 在 PDF 第一页生成包含以下信息的封面：
- **标题区域**：大号粗体 "网络安全漏洞扫描评估报告"
- **副标题**："Professional Security Assessment Report"
- **扫描目标信息框**：目标 IP / 主机名、扫描时间范围、报告编号（GUID 后8位）
- **安全评级徽章**：根据总体风险等级显示彩色圆角矩形标签（严重=红、高=橙、中=黄、低=绿、信息=蓝）
- **底部元信息**：报告版本 v1.0、生成日期时间、"机密 — 仅限内部使用" 标注
- **装饰元素**：顶部深色横条、底部浅灰分隔线

#### Scenario: 封面页正确渲染
- **WHEN** 用户选择 PDF 格式导出报告
- **THEN** PDF 第1页为专业封面，含标题、目标信息、风险等级标签、日期和保密标注

### Requirement: 目录页
系统 SHALL 在封面之后生成目录页（TOC），列出各章节及对应页码：
1. 执行摘要
2. 扫描配置与范围
3. 端口扫描结果
4. 漏洞详情列表
5. 风险评估结果
6. 修复建议与优先级
7. 附录：合规参考映射

#### Scenario: 目录页自动生成
- **WHEN** PDF 包含多个章节
- **THEN** 自动生成带页码的目录页

### Requirement: 执行摘要章节
系统 SHALL 在第3页生成执行摘要，包含：
- **统计卡片式布局**（使用 PdfPCell 背景色区分）：
  - 总体风险评分（0-100 数字 + 进度条样式）
  - 开放端口数 / 总扫描端口数
  - 发现漏洞总数（按等级分列：严重 N 个 / 高 N 个 / 中 N 个 / 低 N 个）
  - 扫描耗时
- **关键发现 Top 5 列表**：按风险等级排序的前5个高危漏洞（名称 + 端口 + 风险等级）
- **服务分布摘要**：按服务类型统计开放端口数量（HTTP: N, SSH: N, MySQL: N 等）

#### Scenario: 执行摘要数据准确
- **WHEN** 有端口扫描结果和漏洞结果数据
- **THEN** 统计数字与实际数据一致，Top 5 漏洞按 RiskLevel 正确排序

### Requirement: 端口扫描结果表格
系统 SHALL 使用 iTextSharp PdfPTable 渲染专业的端口扫描结果表：
- **表头行**：深蓝色背景 (#2C3E50)、白色文字、加粗
- **列定义**：端口号 | 协议 | 服务名称 | 版本 | 状态 | 响应时间
- **数据行**：斑马纹背景（白色/浅灰交替）
- **状态着色**：开放=绿色文字、关闭=灰色、过滤=黄色
- **只显示 Status 为"开放"的端口**（关闭端口放入附录或省略）
- **每页自动重复表头**：跨页时表头重复显示
- **表格宽度自适应页面**：WidthPercentage = 100%

#### Scenario: 端口表格正确渲染
- **WHEN** 有开放的端口扫描结果
- **THEN** 表格中每个端口一行，含完整字段，状态颜色编码正确

### Requirement: 漏洞详情主表格
系统 SHALL 使用 iTextSharp PdfPTable 渲染漏洞详情作为报告核心内容：
- **表头**：序号 | CVE编号 | 漏洞名称 | 风险等级 | 端口 | 服务 | CVSS评分
- **每个漏洞追加详情子段落**（表格下方或嵌套单元格）：
  - 描述（Description）— 普通文本段落
  - 检测方法（DetectionMethod）
  - 解决方案（Solution）— 可多行文本
  - 参考链接（References）— 如有则显示
- **风险等级颜色编码**：
  - 严重 = 红色背景 (#FFEBEE) + 红色边框 (#F44336) + 红色文字
  - 高 = 浅橙色背景 (#FFF3E0) + 橙色边框 (#FF9800)
  - 中 = 浅黄色背景 (#FFFFE0) + 金色边框 (#FFC107)
  - 低 = 浅绿色背景 (#E8F5E9) + 绿色边框 (#4CAF50)
  - 信息 = 浅蓝色背景 (#E3F2FD) + 蓝色边框 (#2196F3)
- **按风险等级分组**：严重 → 高 → 中 → 低 → 信息 排列
- **分页处理**：每页最多 15 条漏洞，自动换页并重复表头

#### Scenario: 漏洞表格完整展示所有字段
- **WHEN** 导出包含多种风险等级的漏洞数据
- **THEN** 所有漏洞均以正确的颜色编码和完整字段展示，按等级分组排列

### Requirement: 风险评估结果展示
系统 SHALL 展示风险评估数据：
- **风险评估汇总表**：评估项目 | 风险值 | 状态（3列 PdfPTable）
- **风险分布可视化**：用水平进度条样式的 PdfPCell 模拟条形图（严重 XX% [████░░]）
- **安全建议列表**：如有 SecurityAdvice 则以有序列表形式展示

#### Scenario: 风险评估数据展示
- **WHEN** 有 RiskAssessmentItem 数据
- **THEN** 以表格形式展示各项评估结果和安全建议

### Requirement: 修复建议与优先级矩阵
系统 SHALL 生成修复建议章节：
- **P1-P4 优先级矩阵表**：优先级 | 建议修复时限 | 涉及漏洞数 | 关键操作
- **前5个高危漏洞详细修复建议**：每个漏洞一条建议（含具体命令/配置步骤）
- **通用安全加固建议**：至少 5 条行业最佳实践建议

#### Scenario: 修复建议实用
- **WHEN** 用户查看修复建议章节
- **THEN** 建议具体可操作，包含优先级分类和时间框架参考

### Requirement: 页眉页脚
系统 SHALL 为每页添加统一的页眉和页脚：
- **页眉**：左侧 "网络安全漏洞扫描报告"，右侧 "NetSecurityScanner v1.0"，底部 0.5pt 灰色分隔线
- **页脚**：左侧 "机密 — 内部文档", 右侧 "第 X 页 / 共 Y 页"
- **首页无页眉**（封面页不显示页眉）
- **目录页无页脚页码**

#### Scenario: 页码正确
- **WHEN** PDF 多于 1 页
- **THEN** 每页页脚显示正确的当前页码和总页数

### Requirement: 中文字体支持
系统 SHALL 支持中文内容的正确渲染：
- **字体回退链**：msyh.ttc(微软雅黑) → simhei.ttf(黑体) → simsun.ttc(宋体) → simsun.ttf → Helvetica
- **字体嵌入**：BaseFont.EMBEDDED 确保在没有该字体的机器上也能正常显示
- **字号合理**：正文 9-10pt，标题 16-20pt，小字注 8pt

#### Scenario: 中文正确显示
- **WHEN** 漏洞描述、解决方案等字段包含中文
- **THEN** PDF 中中文清晰可读，无乱码、无方块替代字符

### Requirement: 异常处理
系统 SHALL 在 PDF 生成失败时给出明确的错误提示：
- **字体加载全部失败** → 弹出 MessageBox 提示"PDF 字体加载失败，请确认系统中安装了微软雅黑或宋体字体"
- **iTextSharp 运行时异常** → 弹出 MessageBox 显示具体异常消息
- **数据为空** → 弹出提示"当前无扫描结果数据，请先执行扫描后再导出报告"
- **不再降级到 HTML**：失败就是失败，不给用户一个假 .pdf 文件

## MODIFIED Requirements

### Requirement: GenerateRealPdfReport 方法重写
将现有的 `GenerateRealPdfReport(string markdownContent)` 方法完全替换为 `GenerateProfessionalPdfReport(...)` 重载方法组：

```csharp
// 新的主方法 - 直接接收结构化数据
private string GenerateProfessionalPdfReport(
    List<PortScanResult> portScanResults,
    List<VulnerabilityResult> vulnerabilityResults,
    List<RiskAssessmentItem> riskAssessmentItems,
    string targetIp)

// 兼容旧调用的包装方法 - 从 markdown 内容提取数据后调用主方法（仅用于向后兼容）
private string GenerateRealPdfReport(string markdownContent)
```

### Requirement: ExportReport_Click PDF 分支修改
MainWindow.xaml.cs 两处 ExportReport_Click 入口中，PDF 分支改为：
```
旧: report = ReportGenerator.GenerateReport(...) → GenerateRealPdfReport(report)
新: GenerateProfessionalPdfReport(_portScanResults, _vulnerabilityResults, _riskAssessmentItems, targetIp)
```

## REMOVED Requirements
- 移除 `GenerateRealPdfReport(string)` 中的 HTML 降级逻辑（不再输出 .html 伪装文件）
- 移除临时文件 .tmp 方案（直接写入最终路径，失败时删除残留文件）
