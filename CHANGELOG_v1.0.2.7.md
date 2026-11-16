# 更新日志 v1.0.2.7

发布日期：2026-11-15

## 概述

本版本集中修复专家模式报告生成功能的 3 个实质缺陷（其中 2 个为"按钮承诺了但根本没做到"的假功能），
并补齐报告字段、修复 HTML 注入面。

## 修复明细

### 1. PDF 导出为假功能 → 接通真实引擎（核心修复）

「导出PDF」按钮此前通过反射查找 `NetSecurityScanner.Services.ReportEngine` 类——
**该类在全代码库中根本不存在**，反射必然失败走 catch 回退，把 HTML 报告改名为
`.html` 后提示"PDF引擎不可用"。按钮承诺 PDF、实际交付 HTML。

现直接调用 Core 层成熟的 iTextSharp 报告引擎 `HistoryReportGenerator`
（含封面页/目录/分节/风险徽章/中文字体回退链，此前该引擎编写完成后一直无调用者）：

- 新增 `BuildCompleteScanRecordsFromResults()`：把实时结果按目标分组整理为
  `CompleteScanResult` 列表（与扫描历史入库的构造方式一致）
- 单目标走 `GenerateFromHistoryRecordToPath`，多目标走 `GenerateFromMultipleRecordsToPath`
- PDF 生成放入 `Task.Run` 后台线程，避免 iTextSharp 排版 + 中文字体加载卡顿 UI

### 2. DOCX 导出丢失全部表格 → 补 `InsertTable`

Xceed DocX 的 `AddTable` 只创建表对象，**必须调用 `InsertTable` 才会写入文档**。
此前端口表与漏洞表创建并填充后均未插入——导出的 DOCX 只有标题与概览文字，
两张数据表全部丢失。已补齐两处 `doc.InsertTable(...)`。

同时增强 DOCX 内容：
- 漏洞表从 5 列扩为 **7 列**，新增「修复方案」「参考链接」（此前模型字段齐全但报告未输出）
- 标题显式指定「微软雅黑」字体，中文渲染跨环境一致（此前依赖 Word 客户端字体回退）

### 3. HTML 报告注入面修复 + 补修复方案列

- **安全修复**：此前报告标题、目标 IP、服务版本（可能来自目标返回的 Banner）、
  漏洞描述等全部**未经 HTML 转义**直接拼入报告页面。恶意目标返回含 `<script>`
  的 Banner 即可注入查看者的浏览器（存储型 XSS 面）。现统一走
  `ScanReportExporter.HtmlEscape`（与 Core 版报告同一转义约定）。
- 漏洞表新增「修复方案」列（换行转 `<br/>` 展示多步骤修复建议）。

### 4. 「按目标导出」DOCX 死按钮修复

格式选择对话框提供了 DOCX 选项，但 switch 缺少 `case "docx"`——点击后无任何响应。
已补上，与既有 `ExportWithFormatSelection` 的 docx 分支一致复用 DOCX 导出。

## 质量验证

| 门禁 | 结果 |
|---|---|
| 全解决方案 `dotnet build` | 0 错误（既有 43 条警告与本轮无关） |
| NetSecurityScanner.Core.Tests | **248/248 通过** |
| 发布产物核对 | exe / Core.dll = 1.0.2.7，rust 引擎 + 46 条漏洞库就位 |
| 启动冒烟 | `OnStartup completed successfully`，无异常 |

## 建议实测项

1. 专家模式扫描后点「导出PDF」→ 应得到真实 PDF（封面/目录/分节），不再是 HTML 改名
2. 导出 DOCX → 用 Word 打开，端口表与漏洞表（含修复方案/参考链接列）应出现
3. 含特殊字符（如 Banner 中带 `<` `>`）的目标 → HTML 报告应正确转义显示

## 遗留技术债（后续版本）

- 报告实现收敛：现存 3 套 CSV 列结构、3 套 HTML、2 套 DOCX 分散于 6 处
  （MainWindow 版 HTML 质量最高但同样未转义），建议 UI 层统一只调 Core
- `MainWindow.GeneratePdfReport` / `GenerateProfessionalPdfReport` 死代码清理
- `src\NetSecurityScanner` 旧项目副本归档（易误改旧文件）

## 交付物

| 文件/目录 | 说明 |
|---|---|
| `NetSecurityScanner/publish-v1.0.2.7/` | 主程序发布产物（含 rust-scanner-service.exe、46 条漏洞库） |
