# 更新日志 v1.0.2.8

发布日期：2026-11-15

## 概述

本版本完善「扫描历史记录中生成报告」功能：主窗口历史页与独立历史窗口的格式对话框
补上 PDF 选项（接通此前闲置的专业 iTextSharp 引擎），并修复两处 HTML 报告的注入面
与"前 10 个漏洞"截断问题。

## 修复明细

### 1. 扫描历史报告格式对话框补 PDF（主修复）

格式对话框的提示文案一直写着"**PDF格式支持专业排版、图表和彩色展示，推荐使用**"，
但选项列表里根本没有 PDF——文案与选项自相矛盾。而 Core 层的专业 PDF 生成器
（`HistoryReportGenerator`，iTextSharp，含封面页/目录/饼图/页眉页脚）早已就绪，
`MainWindow.GeneratePdfReport` 分发方法也已写好，却因对话框缺少选项而成为死代码。

现补齐三处接线，PDF 真正可用：

| 接入点 | 修改 |
|---|---|
| `MainWindow.ShowReportFormatDialog` | formatItems 新增「📄 PDF文件 (.pdf)」，置为推荐首选 |
| `MainWindow.ShowSaveFileDialog` | 新增 `case ReportFormat.Pdf` 分支 |
| `MainWindow.ExportReportWithDialog` | 分发处新增 `GeneratePdfReport` 调用（启用原死代码） |
| `ScanHistoryWindow` | 格式对话框 / 保存对话框 / 分发 switch 同步补齐（`GenerateFromHistoryRecordToPath`） |

覆盖的入口：
- 主窗口扫描历史页「生成报告」按钮（`GenerateReportFromHistory_Click`，支持勾选多条聚合出一份报告）
- 文件菜单「导出报告」（当前扫描结果）
- 独立扫描历史窗口的「生成报告」按钮

### 2. HTML 报告注入面修复（安全）

`MainWindow.GenerateHtmlReport`（约 640 行富样式报告）此前**全文件零转义**：
服务名/版本（可能来自目标返回的 Banner）、漏洞名称/描述/修复方案/检测方法、
目标 IP 等全部直接拼入 HTML。恶意目标返回含 `<script>` 的 Banner 即可注入查看报告者的浏览器。

已修复的插值点（统一 `WebUtility.HtmlEncode`）：
- 端口表整行（服务名/版本/状态）
- 漏洞概览表整行 + 详情卡片头/描述/基本信息/检测方法/修复方案逐行
- 5 处 `targetIp` 插值（封面/页脚/结论段）
- **参考链接 href 注入点**（最危险）：此前 `<a href='{v.References}'>` 双重未转义，
  可注入属性与协议。现仅当 References 为 http(s) 绝对地址且不含引号/尖括号/空格时
  才生成链接（并加 `rel="noopener noreferrer"`），否则降级为纯文本

`ScanHistoryWindow.GenerateHtmlReportAsync`（丐版 HTML）同步修复 4 处插值。

### 3. "前 10 个漏洞"截断修复（正确性）

`MainWindow.GenerateHtmlReport` 中 3.1 漏洞概览表全量列出，但 3.2 详情卡片
`Take(10)` 硬编码截断且标题硬编码"前10个"——概览与详情数量自相矛盾，
且第 11 个及以后的漏洞看不到修复方案。改为全量输出，标题动态生成"（共 N 个）"。

## 质量验证

| 门禁 | 结果 |
|---|---|
| 全解决方案 `dotnet build` | 0 错误 |
| NetSecurityScanner.Core.Tests | **248/248 通过** |
| 发布产物核对 | exe / Core.dll = 1.0.2.8，rust 引擎 + 46 条漏洞库就位 |
| 启动冒烟 | `OnStartup completed successfully`，无异常 |

## 建议实测项

1. 主窗口扫描历史页勾选若干记录 → 生成报告 → 选 PDF → 应得到带封面/目录/饼图的真实 PDF
2. 生成 HTML → 检查漏洞详情不再只有 10 个，且数量标注正确
3. 独立历史窗口（ScanHistoryWindow）→ 生成报告 → PDF 选项可用

## 遗留技术债（后续版本）

- 三处窗口（MainWindow / ScanHistoryWindow / 专家模式）的格式对话框与保存对话框
  建议抽取为共享控件，消除第三次复制（本轮已让两处对齐，未合并）
- 专家模式「扫描历史」Tab 双击详情预览（纯文本、端口截 50/漏洞截 30）暂无文件导出，
  可复用本轮 PDF 链路补齐
- `GenerateProfessionalPdfReport` 等剩余死代码清理

## 交付物

| 文件/目录 | 说明 |
|---|---|
| `NetSecurityScanner/publish-v1.0.2.8/` | 主程序发布产物（含 rust-scanner-service.exe、46 条漏洞库） |
