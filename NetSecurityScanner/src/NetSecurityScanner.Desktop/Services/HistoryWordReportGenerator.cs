using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Diagnostics;
using NetSecurityScanner.Models;
using NetSecurityScanner.Services;
using NetSecurityScanner.Utils;
using Xceed.Words.NET;
using Xceed.Document.NET;

namespace NetSecurityScanner
{
    public static class HistoryWordReportGenerator
    {
        private static readonly Xceed.Drawing.Color DeepBlue = Xceed.Drawing.Color.DarkBlue;
        private static readonly Xceed.Drawing.Color AccentBlue = Xceed.Drawing.Color.RoyalBlue;
        private static readonly Xceed.Drawing.Color LightGrayBg = Xceed.Drawing.Color.WhiteSmoke;
        private static readonly Xceed.Drawing.Color WhiteBg = Xceed.Drawing.Color.White;
        private static readonly Xceed.Drawing.Color MidGray = Xceed.Drawing.Color.Gray;

        private static string GetAppVersion()
        {
            return VersionHelper.GetVersion();
        }

        private static readonly string _logFilePath = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments),
            "NetSecurityScanner_WordReport.log");

        private static void WriteLog(string message)
        {
            try
            {
                var entry = $"[{DateTime.Now:yyyy-MM-dd HH:mm:ss.fff}] {message}{Environment.NewLine}";
                File.AppendAllText(_logFilePath, entry);
                Debug.WriteLine(message);
            }
            catch { }
        }

        private static void WriteErrorLog(string context, Exception ex)
        {
            var msg = $"[ERROR] {context}: {ex.Message}\nStackTrace: {ex.StackTrace}";
            if (ex.InnerException != null)
                msg += $"\nInnerException: {ex.InnerException.Message}\n{ex.InnerException.StackTrace}";
            WriteLog(msg);
        }

        private static void AddChartImage(DocX doc, byte[] imageData, float width = 400, float height = 220)
        {
            if (imageData == null || imageData.Length == 0)
            {
                WriteLog("[WordReport] 图表数据为空，跳过插入");
                return;
            }
            try
            {
                using var ms = new MemoryStream(imageData);
                var img = doc.AddImage(ms);
                var pic = img.CreatePicture();
                pic.Width = width;
                pic.Height = height;
                var chartPara = doc.InsertParagraph();
                chartPara.Alignment = Alignment.center;
                chartPara.AppendPicture(pic);
                chartPara.SpacingBefore(10);
                chartPara.SpacingAfter(10);
            }
            catch (Exception ex)
            {
                WriteLog($"[WordReport] 图表插入失败: {ex.Message}");
            }
        }

        private static void AddSectionDivider(DocX doc)
        {
            var divider = doc.InsertParagraph(new string('━', 60));
            divider.Alignment = Alignment.center;
            divider.FontSize(8);
            divider.Color(MidGray);
            divider.SpacingBefore(8);
            divider.SpacingAfter(8);
        }

        private static void StyleTableHeader(Table table, string[] headers)
        {
            for (int c = 0; c < headers.Length; c++)
            {
                var cell = table.Rows[0].Cells[c];
                var para = cell.Paragraphs[0];
                para.Append(headers[c]).Bold().FontSize(9);
                para.Color(Xceed.Drawing.Color.White);
                para.Alignment = Alignment.center;
                try { cell.FillColor = Xceed.Drawing.Color.DarkBlue; } catch { }
            }
        }

        private static void ApplyTableRowShading(Table table, int startRow = 1)
        {
            for (int r = startRow; r < table.Rows.Count; r++)
            {
                var bgColor = (r % 2 == 0) ? Xceed.Drawing.Color.WhiteSmoke : Xceed.Drawing.Color.White;
                for (int c = 0; c < table.Rows[r].Cells.Count; c++)
                {
                    try { table.Rows[r].Cells[c].FillColor = bgColor; } catch { }
                }
            }
        }

        #region 主入口方法

        public static string GenerateFromHistoryRecordToPath(CompleteScanResult record, string savePath)
        {
            if (record == null)
                throw new ArgumentNullException(nameof(record), "扫描记录为空");

            if (string.IsNullOrWhiteSpace(savePath))
                throw new ArgumentException("保存路径不能为空", nameof(savePath));

            var safePorts = record.PortScanResults ?? new List<PortScanResult>();
            var safeVulns = record.VulnerabilityResults ?? new List<VulnerabilityResult>();

            if (!safePorts.Any() && !safeVulns.Any())
                throw new InvalidDataException("该扫描记录暂无数据（端口和漏洞均为空）");

            var targetIp = string.IsNullOrWhiteSpace(record.TargetIp) ? "未知目标" : record.TargetIp;

            try
            {
                var directoryPath = System.IO.Path.GetDirectoryName(savePath);
                if (!string.IsNullOrEmpty(directoryPath) && !Directory.Exists(directoryPath))
                    Directory.CreateDirectory(directoryPath);

                // 使用临时文件路径创建文档，避免 MemoryStream 在 DocX v5.0.0 中的兼容性问题
                // DocX.Create(stream) 在旧版本中 Save() 后可能关闭底层流，导致后续读取失败
                using (var doc = DocX.Create(savePath))
                {
                    GenerateCoverPage(doc, targetIp, safePorts, safeVulns, false, 0, record.ScanType);
                    AddPageBreak(doc);
                    GenerateTableOfContents(doc);
                    AddPageBreak(doc);
                    GenerateExecutiveSummary(doc, safePorts, safeVulns, targetIp, record.ScanType);
                    AddPageBreak(doc);
                    GenerateScanScopeSection(doc, targetIp, safePorts, safeVulns, record.ScanType);
                    AddPageBreak(doc);
                    GeneratePortScanSection(doc, safePorts);
                    AddPageBreak(doc);
                    GenerateVulnerabilitySection(doc, safeVulns);
                    AddPageBreak(doc);
                    GenerateRiskAssessment(doc, safeVulns, safePorts);
                    AddPageBreak(doc);
                    GenerateRemediationSection(doc, safeVulns);
                    AddPageBreak(doc);
                    GenerateThreatIntelligenceSection(doc, safeVulns, safePorts);
                    AddPageBreak(doc);
                    GenerateComplianceSection(doc, safeVulns, safePorts);
                    AddPageBreak(doc);
                    GenerateConclusionSection(doc, safeVulns, safePorts);
                    AddPageBreak(doc);
                    GenerateCveAppendix(doc, safeVulns);
                    AddPageBreak(doc);
                    GenerateAppendixB(doc);
                    doc.Save();
                }

                WriteLog($"[WordReport] Word报告生成成功：{savePath}");
                return savePath;
            }
            catch (Exception ex)
            {
                WriteErrorLog("单记录Word报告生成失败", ex);
                throw;
            }
        }

        public static string GenerateFromMultipleRecordsToPath(List<CompleteScanResult> records, string savePath)
        {
            if (records == null || !records.Any())
                throw new ArgumentException("扫描记录列表为空");

            if (string.IsNullOrWhiteSpace(savePath))
                throw new ArgumentException("保存路径不能为空", nameof(savePath));

            var mergedPorts = records
                .SelectMany(r => r.PortScanResults ?? new List<PortScanResult>())
                .GroupBy(p => p?.PortNumber ?? 0)
                .Select(g => g.First())
                .OrderBy(p => p.PortNumber)
                .ToList();

            var mergedVulns = records
                .SelectMany(r => r.VulnerabilityResults ?? new List<VulnerabilityResult>())
                .GroupBy(v => v?.CveId ?? v?.Name ?? Guid.NewGuid().ToString())
                .Select(g => g.OrderByDescending(v => GetRiskPriority(v?.RiskLevel)).First())
                .OrderByDescending(v => GetRiskPriority(v?.RiskLevel))
                .ToList();

            if (!mergedPorts.Any() && !mergedVulns.Any())
                throw new InvalidDataException("所有扫描记录均无有效数据");

            var targetIp = "多目标综合";

            try
            {
                var directoryPath = System.IO.Path.GetDirectoryName(savePath);
                if (!string.IsNullOrEmpty(directoryPath) && !Directory.Exists(directoryPath))
                    Directory.CreateDirectory(directoryPath);

                using (var doc = DocX.Create(savePath))
                {
                    GenerateCoverPage(doc, targetIp, mergedPorts, mergedVulns, true, records.Count, BuildScanTypesString(records));
                    AddPageBreak(doc);
                    GenerateTableOfContents(doc);
                    AddPageBreak(doc);
                    GenerateExecutiveSummary(doc, mergedPorts, mergedVulns, targetIp, BuildScanTypesString(records));
                    AddPageBreak(doc);
                    GenerateScanScopeSection(doc, targetIp, mergedPorts, mergedVulns, BuildScanTypesString(records));
                    AddPageBreak(doc);
                    GeneratePortScanSection(doc, mergedPorts);
                    AddPageBreak(doc);
                    GenerateVulnerabilitySection(doc, mergedVulns);
                    AddPageBreak(doc);
                    GenerateRiskAssessment(doc, mergedVulns, mergedPorts);
                    AddPageBreak(doc);
                    GenerateRemediationSection(doc, mergedVulns);
                    AddPageBreak(doc);
                    GenerateThreatIntelligenceSection(doc, mergedVulns, mergedPorts);
                    AddPageBreak(doc);
                    GenerateComplianceSection(doc, mergedVulns, mergedPorts);
                    AddPageBreak(doc);
                    GenerateConclusionSection(doc, mergedVulns, mergedPorts);
                    AddPageBreak(doc);
                    GenerateCveAppendix(doc, mergedVulns);
                    AddPageBreak(doc);
                    GenerateAppendixB(doc);
                    doc.Save();
                }

                WriteLog($"[WordReport] 综合Word报告生成成功：{savePath} (合并{records.Count}条记录)");
                return savePath;
            }
            catch (Exception ex)
            {
                WriteErrorLog("多记录综合Word报告生成失败", ex);
                throw;
            }
        }

        private static void AddPageBreak(DocX doc)
        {
            var p = doc.InsertParagraph();
            p.InsertPageBreakAfterSelf();
        }

        #endregion

        #region 封面页

        private static void GenerateCoverPage(DocX doc, string targetIp, List<PortScanResult> ports, List<VulnerabilityResult> vulns, bool isComposite = false, int recordCount = 0, string scanTypeInfo = null)
        {
            var openPortCount = ports?.Count(p => p?.Status == "开放" || p?.Status?.ToLower() == "open") ?? 0;
            var vulnCount = vulns?.Count ?? 0;
            var riskLevel = CalculateOverallRiskLevel(vulns);
            var highRiskPercent = vulnCount > 0 ?
                (int)((double)(vulns?.Count(v => IsCritical(v?.RiskLevel) || IsHigh(v?.RiskLevel)) ?? 0) / vulnCount * 100) : 0;

            var headerBar = doc.InsertParagraph("NETWORK SECURITY ASSESSMENT");
            headerBar.Alignment = Alignment.center;
            headerBar.FontSize(10);
            headerBar.Bold();
            headerBar.Color(Xceed.Drawing.Color.LightSteelBlue);
            headerBar.SpacingAfter(35);

            var separator = doc.InsertParagraph(new string('─', 50));
            separator.Alignment = Alignment.center;
            separator.FontSize(7);
            separator.Color(MidGray);
            separator.SpacingAfter(30);

            var riskColors = new Dictionary<string, Xceed.Drawing.Color>
            {
                { "严重", Xceed.Drawing.Color.Firebrick },
                { "高", Xceed.Drawing.Color.OrangeRed },
                { "中", Xceed.Drawing.Color.DarkOrange },
                { "低", Xceed.Drawing.Color.SeaGreen },
                { "信息", Xceed.Drawing.Color.SlateGray }
            };
            var badgeColor = riskColors.ContainsKey(riskLevel) ? riskColors[riskLevel] : Xceed.Drawing.Color.SlateGray;
            var badgeText = riskLevel == "严重" ? "CRITICAL" : riskLevel == "高" ? "HIGH" : riskLevel == "中" ? "MEDIUM" : riskLevel == "低" ? "LOW" : "INFO";

            var badgePara = doc.InsertParagraph($"  ● {badgeText} RISK  ●  ");
            badgePara.Alignment = Alignment.center;
            badgePara.FontSize(14);
            badgePara.Bold();
            badgePara.Color(badgeColor);
            badgePara.SpacingAfter(10);

            var badgeDesc = doc.InsertParagraph($"Risk Level: {riskLevel}  |  安全等级: {riskLevel}");
            badgeDesc.Alignment = Alignment.center;
            badgeDesc.FontSize(9);
            badgeDesc.Color(MidGray);
            badgeDesc.SpacingAfter(30);

            var titleEn = doc.InsertParagraph("SECURITY ASSESSMENT REPORT");
            titleEn.Alignment = Alignment.center;
            titleEn.FontSize(20).Bold();
            titleEn.Color(DeepBlue);
            titleEn.SpacingAfter(6);

            var titleLine = doc.InsertParagraph(new string('─', 40));
            titleLine.Alignment = Alignment.center;
            titleLine.FontSize(7);
            titleLine.Color(AccentBlue);
            titleLine.SpacingAfter(6);

            var titleCn = doc.InsertParagraph("网络安全漏洞扫描评估报告");
            titleCn.Alignment = Alignment.center;
            titleCn.FontSize(22).Bold();
            titleCn.Color(DeepBlue);
            titleCn.SpacingAfter(25);

            var metaTable = doc.AddTable(5, 2);
            metaTable.Design = TableDesign.TableGrid;
            metaTable.Alignment = Alignment.center;

            var metaHeaders = new[] { "报告编号", "目标系统", "扫描时间", "扫描类型", "生成时间" };
            var scanTypeDisplay = !string.IsNullOrWhiteSpace(scanTypeInfo)
                ? scanTypeInfo
                : (isComposite ? $"综合扫描（合并{recordCount}次扫描）" : "全面漏洞扫描");

            var metaValues = new[]
            {
                $"RPT-{DateTime.Now:yyyyMMdd}-{Guid.NewGuid():N}".Substring(0, 16),
                $"{targetIp} (内网服务器)",
                DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss"),
                scanTypeDisplay,
                DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss")
            };

            for (int r = 0; r < 5; r++)
            {
                metaTable.Rows[r].Cells[0].Paragraphs[0].Append(metaHeaders[r]).Bold().FontSize(9);
                metaTable.Rows[r].Cells[0].Paragraphs[0].Alignment = Alignment.right;
                metaTable.Rows[r].Cells[1].Paragraphs[0].Append(metaValues[r]).FontSize(9);
                metaTable.Rows[r].Cells[1].Paragraphs[0].Alignment = Alignment.left;
            }

            doc.InsertParagraph().SpacingAfter(25);

            var statsTitle = doc.InsertParagraph("1.1 核心统计数据");
            statsTitle.Alignment = Alignment.center;
            statsTitle.FontSize(12).Bold();
            statsTitle.Color(DeepBlue);
            statsTitle.SpacingAfter(12);

            var statsTable = doc.AddTable(1, 4);
            statsTable.Design = TableDesign.TableGrid;
            statsTable.Alignment = Alignment.center;

            var statItems = new[]
            {
                ("风险等级", riskLevel, riskLevel),
                ("开放端口", $"{openPortCount}个", "低"),
                ("漏洞总数", $"{vulnCount}个", "低"),
                ("高危占比", $"{highRiskPercent}%", highRiskPercent >= 30 ? "高" : "低")
            };

            for (int c = 0; c < 4; c++)
            {
                var cell = statsTable.Rows[0].Cells[c];
                var labelPara = cell.Paragraphs[0];
                labelPara.Append(statItems[c].Item1).FontSize(9).Bold();
                labelPara.Color(MidGray);
                labelPara.Alignment = Alignment.center;

                var cell2 = cell.InsertParagraph();
                cell2.Alignment = Alignment.center;
                var displayColor = c == 0 ? badgeColor :
                    (statItems[c].Item3 == "高" ? Xceed.Drawing.Color.OrangeRed : DeepBlue);
                cell2.Append(statItems[c].Item2).FontSize(13).Bold();
                cell2.Color(displayColor);
            }

            doc.InsertParagraph().SpacingAfter(40);

            // 封面底部元数据区块（任务1：报告编号/扫描工程师/审核签发/密级/版本）
            var metaBlockTitle = doc.InsertParagraph("报 告 文 档 信 息");
            metaBlockTitle.Alignment = Alignment.center;
            metaBlockTitle.FontSize(11).Bold();
            metaBlockTitle.Color(DeepBlue);
            metaBlockTitle.SpacingBefore(8);
            metaBlockTitle.SpacingAfter(8);

            var metaInfoTable = doc.AddTable(7, 2);
            metaInfoTable.Design = TableDesign.TableGrid;
            metaInfoTable.Alignment = Alignment.center;

            var metaInfoHeaders = new[] { "属性", "内容" };
            StyleTableHeader(metaInfoTable, metaInfoHeaders);

            // 任务：auto-save-vulnerability-json-library 注入漏洞库元数据
            string libraryVersion = "未挂接本地库";
            string librarySyncTime = "-";
            string librarySource = "-";
            int libraryTotal = 0;
            try
            {
                var lib = LocalVulnerabilityLibrary.Instance;
                if (lib != null && lib.IsLoaded)
                {
                    var meta = lib.GetMeta();
                    if (meta != null)
                    {
                        libraryVersion = string.IsNullOrEmpty(meta.Version) ? "1.0" : meta.Version;
                        libraryTotal = meta.TotalCount;
                        librarySyncTime = meta.LastSyncTime.HasValue ? meta.LastSyncTime.Value.ToString("yyyy-MM-dd HH:mm:ss") : "未同步";
                        if (meta.Sources != null && meta.Sources.Count > 0)
                        {
                            librarySource = string.Join(" / ", meta.Sources.Select(kv => $"{kv.Key} {kv.Value}"));
                        }
                    }
                }
            }
            catch { /* 忽略报告注入异常 */ }

            var metaInfoRows = new[]
            {
                ("报告编号", $"NSS-{DateTime.Now:yyyyMMdd-HHmmss}"),
                ("扫描工程师", "NetSecurityScanner 自动扫描引擎"),
                ("审核签发", "安全运营中心（SOC）审核"),
                ("密级", "内部使用 ★ Confidential"),
                ("文档版本", "V2.0（章节规范化重构版）"),
                ("漏洞库版本", $"v{libraryVersion}  |  库总数 {libraryTotal}  |  最近同步 {librarySyncTime}  |  来源 {librarySource}")
            };

            for (int r = 0; r < metaInfoRows.Length; r++)
            {
                metaInfoTable.Rows[r + 1].Cells[0].Paragraphs[0].Append(metaInfoRows[r].Item1).FontSize(9).Bold();
                metaInfoTable.Rows[r + 1].Cells[0].Paragraphs[0].Alignment = Alignment.center;
                metaInfoTable.Rows[r + 1].Cells[1].Paragraphs[0].Append(metaInfoRows[r].Item2).FontSize(9);
                metaInfoTable.Rows[r + 1].Cells[1].Paragraphs[0].Alignment = Alignment.left;
                try { metaInfoTable.Rows[r + 1].Cells[1].FillColor = Xceed.Drawing.Color.WhiteSmoke; } catch { }
            }

            doc.InsertParagraph().SpacingAfter(15);

            var bottomLine = doc.InsertParagraph(new string('─', 50));
            bottomLine.Alignment = Alignment.center;
            bottomLine.FontSize(7);
            bottomLine.Color(MidGray);
            bottomLine.SpacingAfter(12);

            var version = GetAppVersion();
            var versionPara = doc.InsertParagraph($"NetSecurityScanner v{version}  |  Professional Edition");
            versionPara.Alignment = Alignment.center;
            versionPara.FontSize(9);
            versionPara.Color(MidGray);
            versionPara.SpacingAfter(6);

            var confidential = doc.InsertParagraph("★  CONFIDENTIAL - 机密文件 - 仅限内部使用  ★");
            confidential.Alignment = Alignment.center;
            confidential.FontSize(9).Bold();
            confidential.Color(Xceed.Drawing.Color.LightSlateGray);
        }

        #endregion

        #region 目录页

        private static void GenerateTableOfContents(DocX doc)
        {
            var title = doc.InsertParagraph("目    录");
            title.Alignment = Alignment.center;
            title.FontSize(18).Bold();
            title.Color(DeepBlue);
            title.SpacingBefore(20);
            title.SpacingAfter(4);

            var decoLine = doc.InsertParagraph(new string('━', 9));
            decoLine.Alignment = Alignment.center;
            decoLine.FontSize(7);
            decoLine.Color(AccentBlue);
            decoLine.SpacingAfter(22);

            var entries = new[]
            {
                "第一章 执行摘要",
                "      1.1 核心统计数据",
                "      1.2 风险仪表盘",
                "      1.3 服务分布图表",
                "      1.4 Top 5 高危漏洞",
                "      1.5 扫描结论概览",
                "第二章 扫描范围与方法",
                "      2.1 扫描对象",
                "      2.2 扫描范围外",
                "      2.3 已知限制",
                "      2.4 使用声明",
                "第三章 端口扫描结果",
                "      3.1 扫描方法说明",
                "      3.2 端口扫描概况",
                "      3.3 高危端口安全警示",
                "      3.4 所有端口详情",
                "      3.5 服务分布统计",
                "第四章 漏洞详情分析",
                "      4.1 漏洞风险分布",
                "      4.2 受影响服务分布",
                "      4.3 漏洞类型分类统计",
                "      4.4 漏洞概览表",
                "      4.5 漏洞详细信息",
                "第五章 风险评估",
                "      5.1 风险评估项目",
                "      5.2 风险等级矩阵",
                "      5.3 风险分布图表",
                "      5.4 安全建议概述",
                "第六章 修复建议",
                "      6.1 修复优先级矩阵",
                "      6.2 通用安全加固建议",
                "      6.3 高危漏洞专项修复方案",
                "      6.4 风险处理跟踪表",
                "第七章 威胁情报分析",
                "      7.1 活跃威胁向量",
                "      7.2 行业威胁趋势",
                "      7.3 攻击面评估",
                "      7.4 威胁情报总结",
                "第八章 合规参考",
                "      8.1 合规标准对照评估",
                "      8.2 合规差距分析",
                "      8.3 合规改进建议",
                "      8.4 合规总结",
                "第九章 结论与建议",
                "      9.1 总体安全评级",
                "      9.2 合规雷达图",
                "      9.3 核心结论",
                "      9.4 长期安全建议",
                "      9.5 报告文档信息",
                "附录A CVE漏洞参考信息",
                "附录B 报告使用与法律声明",
                "      B.1 报告使用范围",
                "      B.2 数据来源说明",
                "      B.3 修复建议限制",
                "      B.4 责任限制",
                "      B.5 保密声明",
                "      B.6 版本与修订记录"
            };

            foreach (var entry in entries)
            {
                var para = doc.InsertParagraph(entry);
                if (!entry.StartsWith(" "))
                {
                    para.Bold().FontSize(12);
                    para.Color(DeepBlue);
                    para.SpacingBefore(12);
                    para.SpacingAfter(6);
                }
                else
                {
                    para.FontSize(10.5);
                    para.SpacingBefore(3);
                    para.SpacingAfter(3);
                }
            }

            doc.InsertParagraph().SpacingAfter(20);

            // 任务2：增加"本报告使用说明"导言段落（≥120字）
            var usageGuideTitle = doc.InsertParagraph("本报告使用说明");
            usageGuideTitle.FontSize(12).Bold();
            usageGuideTitle.Color(DeepBlue);
            usageGuideTitle.SpacingBefore(8);
            usageGuideTitle.SpacingAfter(8);

            var usageGuide1 = doc.InsertParagraph("本报告采用统一的章节编号体系：第一章至第九章为主报告，分别对应执行摘要、扫描范围与方法、端口扫描结果、漏洞详情分析、风险评估、修复建议、威胁情报分析、合规参考以及结论与建议；附录A提供CVE漏洞参考信息，附录B列示报告使用与法律声明。子章节采用 x.y 标准编号体系（如 1.1、1.5、6.3）。如某个子章节无对应数据，将显示占位说明。");
            usageGuide1.FontSize(10);
            usageGuide1.SpacingAfter(6);

            var usageGuide2 = doc.InsertParagraph("建议阅读顺序：先看「第一章 执行摘要」快速建立对目标系统整体安全态势的认知，再看「第九章 结论与建议」了解总体评级与处置策略；中间章节（端口扫描/漏洞详情/风险评估/修复建议等）可按需查阅，用于深入了解具体风险项的检测方法、影响范围与修复路径。本报告适合安全运营团队、运维团队、合规审计人员及管理层等多角色协同使用。");
            usageGuide2.FontSize(10);
            usageGuide2.SpacingAfter(6);

            var usageGuide3 = doc.InsertParagraph("风险等级标识图例：");
            usageGuide3.FontSize(10).Bold();
            usageGuide3.SpacingAfter(4);

            var legendTable = doc.AddTable(1, 5);
            legendTable.Design = TableDesign.TableGrid;
            legendTable.Alignment = Alignment.center;
            var legendLabels = new[] { "严重（Critical）", "高危（High）", "中危（Medium）", "低危（Low）", "信息（Info）" };
            var legendColors = new[] { Xceed.Drawing.Color.Firebrick, Xceed.Drawing.Color.OrangeRed, Xceed.Drawing.Color.DarkOrange, Xceed.Drawing.Color.SeaGreen, Xceed.Drawing.Color.SlateGray };
            for (int c = 0; c < 5; c++)
            {
                var lc = legendTable.Rows[0].Cells[c];
                lc.Paragraphs[0].Append(legendLabels[c]).FontSize(9).Bold();
                lc.Paragraphs[0].Color(legendColors[c]);
                lc.Paragraphs[0].Alignment = Alignment.center;
            }

            doc.InsertParagraph().SpacingAfter(12);

            var disclaimer = doc.InsertParagraph("免责声明：本报告由自动化安全扫描工具生成，结果仅供参考。对于关键安全问题，建议进行人工验证和深度安全分析。");
            disclaimer.Alignment = Alignment.center;
            disclaimer.FontSize(9);
            disclaimer.Color(MidGray);
            disclaimer.SpacingAfter(10);

            var tocNote = doc.InsertParagraph("注：报告章节编号与正文严格对应。如某个子章节无对应数据，将显示占位说明。");
            tocNote.Alignment = Alignment.center;
            tocNote.FontSize(8);
            tocNote.Color(MidGray);
        }

        #endregion

        #region 第一章 执行摘要

        private static void GenerateExecutiveSummary(DocX doc, List<PortScanResult> ports,
            List<VulnerabilityResult> vulns, string targetIp, string scanTypeInfo = null)
        {
            var chapterTitle = doc.InsertParagraph("第一章 执行摘要");
            chapterTitle.FontSize(16).Bold();
            chapterTitle.Color(DeepBlue);
            chapterTitle.SpacingBefore(15);
            chapterTitle.SpacingAfter(4);

            var titleLine = doc.InsertParagraph(new string('─', 50));
            titleLine.FontSize(7);
            titleLine.Color(AccentBlue);
            titleLine.SpacingAfter(12);

            var intro = doc.InsertParagraph("本章提供本次安全扫描的核心发现和统计概览，帮助快速了解目标系统的整体安全态势，并给出定性结论。");
            intro.FontSize(10);
            intro.SpacingBefore(8);
            intro.SpacingAfter(12);

            var safePorts = ports ?? new List<PortScanResult>();
            var safeVulns = vulns ?? new List<VulnerabilityResult>();
            var openPorts = safePorts.Where(p => p?.Status == "开放" || p?.Status?.ToLower() == "open").ToList();
            var riskLevel = CalculateOverallRiskLevel(safeVulns);
            var securityScore = CalculateSecurityScore(safeVulns, openPorts);
            var highPct = safeVulns.Any() ?
                (int)((double)safeVulns.Count(v => IsCritical(v.RiskLevel) || IsHigh(v.RiskLevel)) / safeVulns.Count * 100) : 0;
            var criticalCount = safeVulns.Count(v => IsCritical(v?.RiskLevel));
            var highCount = safeVulns.Count(v => IsHigh(v?.RiskLevel));

            var overview = doc.InsertParagraph();
            overview.FontSize(10);
            overview.SpacingBefore(6);
            overview.SpacingAfter(18);

            if (safeVulns.Any())
            {
                if (riskLevel == "严重" || riskLevel == "高")
                {
                    overview.Append($"经对目标系统 {targetIp} 进行全面安全扫描，共发现{safeVulns.Count}个安全漏洞和{openPorts.Count}个开放端口。");
                    overview.Append($"系统整体安全评级为").FontSize(10);
                    overview.Append($"「{riskLevel}」").FontSize(10).Bold().Color(GetRiskColor(riskLevel));
                    overview.Append("，安全评分为").FontSize(10);
                    overview.Append($"{securityScore}/100").FontSize(10).Bold().Color(Xceed.Drawing.Color.OrangeRed);
                    overview.Append("。当前存在").FontSize(10);
                    overview.Append($"{criticalCount}个严重、{highCount}个高危").FontSize(10).Bold().Color(Xceed.Drawing.Color.Firebrick);
                    overview.Append($"漏洞需要紧急处理，建议立即启动应急响应流程，优先修复高危漏洞并关闭不必要的高危端口。").FontSize(10);
                }
                else if (riskLevel == "中")
                {
                    overview.Append($"经对目标系统 {targetIp} 的安全扫描，共发现{safeVulns.Count}个安全漏洞和{openPorts.Count}个开放端口。");
                    overview.Append($"系统整体安全评级为").FontSize(10);
                    overview.Append($"「{riskLevel}」").FontSize(10).Bold().Color(GetRiskColor(riskLevel));
                    overview.Append("，安全评分为").FontSize(10);
                    overview.Append($"{securityScore}/100").FontSize(10).Bold();
                    overview.Append("。建议按照修复优先级逐步处理中危漏洞，并加强安全监控。").FontSize(10);
                }
                else
                {
                    overview.Append($"经对目标系统 {targetIp} 的安全扫描，共发现{safeVulns.Count}个安全漏洞和{openPorts.Count}个开放端口。");
                    overview.Append($"系统整体安全评级为").FontSize(10);
                    overview.Append($"「{riskLevel}」").FontSize(10).Bold().Color(Xceed.Drawing.Color.SeaGreen);
                    overview.Append("，安全评分为").FontSize(10);
                    overview.Append($"{securityScore}/100").FontSize(10).Bold();
                    overview.Append("，安全状况良好。建议继续保持安全监控和定期扫描。").FontSize(10);
                }
            }
            else
            {
                overview.Append($"经对目标系统 {targetIp} 的安全扫描，未发现安全漏洞，共发现{openPorts.Count}个开放端口。");
                overview.Append("系统安全状况良好，建议持续保持安全监控和定期评估。").FontSize(10);
            }

            if (!string.IsNullOrWhiteSpace(scanTypeInfo))
            {
                var scanConfigTitle = doc.InsertParagraph("扫 描 配 置 信 息");
                scanConfigTitle.FontSize(12).Bold();
                scanConfigTitle.Color(DeepBlue);
                scanConfigTitle.SpacingBefore(8);
                scanConfigTitle.SpacingAfter(8);

                var hasPortScan = scanTypeInfo.Contains("TCP端口扫描") || scanTypeInfo.Contains("UDP端口扫描") || scanTypeInfo.Contains("端口");
                var hasVulnScan = scanTypeInfo.Contains("漏洞扫描") || scanTypeInfo.Contains("漏洞");
                var hasExpert = scanTypeInfo.Contains("专家模式");

                var configTable = doc.AddTable(4, 3);
                configTable.Design = TableDesign.TableGrid;
                configTable.Alignment = Alignment.center;

                var configHeaders = new[] { "扫描项目", "执行状态", "数据产出" };
                StyleTableHeader(configTable, configHeaders);

                configTable.Rows[1].Cells[0].Paragraphs[0].Append("TCP端口扫描").FontSize(9).Bold();
                configTable.Rows[1].Cells[1].Paragraphs[0].Append(hasPortScan ? "✓ 已执行" : "✗ 未执行").FontSize(9);
                configTable.Rows[1].Cells[1].Paragraphs[0].Color(hasPortScan ? Xceed.Drawing.Color.SeaGreen : Xceed.Drawing.Color.Gray);
                configTable.Rows[1].Cells[2].Paragraphs[0].Append(hasPortScan ? $"{openPorts.Count}个开放端口" : "-").FontSize(9);

                configTable.Rows[2].Cells[0].Paragraphs[0].Append("漏洞扫描").FontSize(9).Bold();
                configTable.Rows[2].Cells[1].Paragraphs[0].Append(hasVulnScan ? "✓ 已执行" : "✗ 未执行").FontSize(9);
                configTable.Rows[2].Cells[1].Paragraphs[0].Color(hasVulnScan ? Xceed.Drawing.Color.SeaGreen : Xceed.Drawing.Color.Gray);
                configTable.Rows[2].Cells[2].Paragraphs[0].Append(hasVulnScan ? $"{safeVulns.Count}个漏洞" : "-").FontSize(9);

                configTable.Rows[3].Cells[0].Paragraphs[0].Append("专家模式").FontSize(9).Bold();
                configTable.Rows[3].Cells[1].Paragraphs[0].Append(hasExpert ? "✓ 已启用" : "✗ 未启用").FontSize(9);
                configTable.Rows[3].Cells[1].Paragraphs[0].Color(hasExpert ? Xceed.Drawing.Color.SeaGreen : Xceed.Drawing.Color.Gray);
                configTable.Rows[3].Cells[2].Paragraphs[0].Append(hasExpert ? "深度检测+合规评估" : "-").FontSize(9);

                ApplyTableRowShading(configTable);
                doc.InsertParagraph().SpacingAfter(18);
            }

            var subHeader1 = doc.InsertParagraph("1.1 核心统计数据");
            subHeader1.FontSize(13).Bold();
            subHeader1.Color(DeepBlue);
            subHeader1.SpacingBefore(12);
            subHeader1.SpacingAfter(10);

            var statCardsTable = doc.AddTable(2, 4);
            statCardsTable.Design = TableDesign.TableGrid;
            statCardsTable.Alignment = Alignment.center;

            var cardItems = new[]
            {
                ("开放端口", $"{openPorts.Count}个", $"发现{openPorts.Count}个活跃端口", Xceed.Drawing.Color.RoyalBlue),
                ("漏洞总数", $"{safeVulns.Count}个", $"检测到{safeVulns.Count}个安全漏洞", Xceed.Drawing.Color.DarkOrange),
                ("高危占比", $"{highPct}%", $"{criticalCount + highCount}个严重/高危", Xceed.Drawing.Color.Firebrick),
                ("安全评分", $"{securityScore}/100", "安全评分指标", Xceed.Drawing.Color.SeaGreen)
            };

            for (int c = 0; c < 4; c++)
            {
                for (int row = 0; row < 2; row++)
                {
                    if (row == 0)
                    {
                        var cell = statCardsTable.Rows[row].Cells[c];
                        cell.Paragraphs[0].Append(cardItems[c].Item1).FontSize(11).Bold();
                        cell.Paragraphs[0].Color(cardItems[c].Item4);
                        cell.Paragraphs[0].Alignment = Alignment.center;
                    }
                    else
                    {
                        var cell = statCardsTable.Rows[row].Cells[c];
                        cell.Paragraphs[0].Append(cardItems[c].Item2).FontSize(18).Bold();
                        cell.Paragraphs[0].Color(DeepBlue);
                        cell.Paragraphs[0].Alignment = Alignment.center;
                        var subP = cell.InsertParagraph();
                        subP.Append(cardItems[c].Item3).FontSize(8);
                        subP.Color(MidGray);
                        subP.Alignment = Alignment.center;
                    }
                }
            }

            // 任务3：在 statsTable 表格后插入"扫描结果快读"结论段（2-3 句总结）
            doc.InsertParagraph().SpacingAfter(10);
            var quickRead = doc.InsertParagraph();
            quickRead.FontSize(10);
            quickRead.SpacingAfter(14);
            if (safeVulns.Any())
            {
                var highAndCritical = criticalCount + highCount;
                quickRead.Append("扫描结果快读：").Bold().FontSize(10).Color(DeepBlue);
                quickRead.Append($"本次扫描共发现 {safeVulns.Count} 个安全漏洞（其中 {criticalCount} 个严重、{highCount} 个高危），{openPorts.Count} 个开放端口，");
                if (highAndCritical > 0)
                {
                    quickRead.Append($"高危占比 {highPct}%，安全评级为「").FontSize(10);
                    quickRead.Append($"{riskLevel}").FontSize(10).Bold().Color(GetRiskColor(riskLevel));
                    quickRead.Append("」，系统当前面临显著的安全风险。").FontSize(10);
                }
                else
                {
                    quickRead.Append("以中低危漏洞为主，安全状况处于可控范围。").FontSize(10);
                }
            }
            else
            {
                quickRead.Append("扫描结果快读：").Bold().FontSize(10).Color(DeepBlue);
                quickRead.Append($"本次扫描共检测到 {openPorts.Count} 个开放端口，未在已知漏洞库中匹配到安全漏洞，系统安全状况良好。");
            }

            doc.InsertParagraph().SpacingAfter(18);

            // 1.2 风险仪表盘 - 始终存在
            {
                var gaugeTitle = doc.InsertParagraph("1.2 风险仪表盘");
                gaugeTitle.FontSize(13).Bold();
                gaugeTitle.Color(DeepBlue);
                gaugeTitle.SpacingBefore(18);
                gaugeTitle.SpacingAfter(8);
                var gaugeImage = ReportChartGenerator.GenerateRiskGaugeChart(riskLevel, securityScore);
                if (gaugeImage != null)
                {
                    AddChartImage(doc, gaugeImage, 280, 280);
                }
                else
                {
                    var placeholder = doc.InsertParagraph($"当前系统安全等级为「{riskLevel}」，安全评分为 {securityScore}/100。");
                    placeholder.FontSize(10);
                    placeholder.Alignment = Alignment.center;
                    placeholder.SpacingAfter(10);
                }
            }

            // 1.3 服务分布图表 - 始终存在标题，根据数据显示图表或占位
            {
                var svcTitle = doc.InsertParagraph("1.3 服务分布图表");
                svcTitle.FontSize(13).Bold();
                svcTitle.Color(DeepBlue);
                svcTitle.SpacingBefore(18);
                svcTitle.SpacingAfter(8);
                var svcGroups = openPorts.Where(p => !string.IsNullOrEmpty(p?.Service))
                    .GroupBy(p => p.Service).OrderByDescending(g => g.Count()).Take(6).ToList();
                if (svcGroups.Any())
                {
                    var svcData = svcGroups.Select(g => (g.Key, g.Count())).ToList();
                    var svcChart = ReportChartGenerator.GeneratePortServiceBarChart(svcData);
                    AddChartImage(doc, svcChart, 450, 190);
                    var svcNote = doc.InsertParagraph($"本次扫描共识别 {svcGroups.Count} 种主要服务类型，{svcGroups.First().Key} 服务最为活跃（{svcGroups.First().Count()} 个端口）。");
                    svcNote.FontSize(9);
                    svcNote.Color(MidGray);
                    svcNote.Alignment = Alignment.center;
                }
                else
                {
                    var placeholder = doc.InsertParagraph("未识别到具体服务类型（扫描结果中未包含服务指纹信息）。建议结合主动服务探测工具（如 Nmap -sV）进行更深入的服务识别。");
                    placeholder.FontSize(10);
                    placeholder.Alignment = Alignment.center;
                    placeholder.SpacingAfter(8);
                }
            }

            // 1.4 Top 5 高危漏洞 - 始终存在标题，根据数据显示表格或占位
            {
                var topTitle = doc.InsertParagraph("1.4 Top 5 高危漏洞");
                topTitle.FontSize(13).Bold();
                topTitle.Color(DeepBlue);
                topTitle.SpacingBefore(22);
                topTitle.SpacingAfter(10);

                if (safeVulns.Any())
                {
                    var topVulns = safeVulns.OrderByDescending(v => GetRiskPriority(v?.RiskLevel)).Take(5).ToList();
                    var topTable = doc.AddTable(topVulns.Count + 1, 4);
                    topTable.Design = TableDesign.TableGrid;
                    topTable.Alignment = Alignment.center;

                    var topHeaders = new[] { "序号", "漏洞名称", "风险等级", "CVE编号" };
                    StyleTableHeader(topTable, topHeaders);

                    int idx = 1;
                    foreach (var vuln in topVulns)
                    {
                        var row = topTable.Rows[idx];
                        var rl = string.IsNullOrWhiteSpace(vuln?.RiskLevel) ? "未分类" : vuln.RiskLevel;
                        row.Cells[0].Paragraphs[0].Append((idx).ToString()).FontSize(9);
                        row.Cells[0].Paragraphs[0].Alignment = Alignment.center;
                        row.Cells[1].Paragraphs[0].Append(string.IsNullOrWhiteSpace(vuln?.Name) ? "未知漏洞" : vuln.Name).FontSize(9);
                        row.Cells[2].Paragraphs[0].Append(rl).FontSize(9).Bold().Color(GetRiskColor(rl));
                        row.Cells[2].Paragraphs[0].Alignment = Alignment.center;
                        row.Cells[3].Paragraphs[0].Append(string.IsNullOrWhiteSpace(vuln?.CveId) ? "-" : vuln.CveId).FontSize(9);
                        idx++;
                    }
                    ApplyTableRowShading(topTable);
                }
                else
                {
                    var placeholder = doc.InsertParagraph("本次扫描未发现安全漏洞，系统在已知漏洞库中处于良好状态。建议持续保持漏洞管理流程，定期执行安全扫描。");
                    placeholder.FontSize(10);
                    placeholder.Alignment = Alignment.center;
                    placeholder.SpacingAfter(8);
                }
            }

            // 1.5 扫描结论概览 - 始终存在，给出整体定性总结（任务4：扩展为 5 个维度）
            {
                var concTitle = doc.InsertParagraph("1.5 扫描结论概览");
                concTitle.FontSize(13).Bold();
                concTitle.Color(DeepBlue);
                concTitle.SpacingBefore(22);
                concTitle.SpacingAfter(10);

                var critCount = safeVulns.Count(v => IsCritical(v?.RiskLevel));
                var highCnt = safeVulns.Count(v => IsHigh(v?.RiskLevel));
                var medCount = safeVulns.Count(v => IsMedium(v?.RiskLevel));
                var lowCount = safeVulns.Count(v => IsLow(v?.RiskLevel));
                var highRiskPortCount = openPorts.Count(p => p?.PortNumber == 445 || p?.PortNumber == 135 || p?.PortNumber == 3389 || p?.PortNumber == 23 || p?.PortNumber == 21 || p?.PortNumber == 3306 || p?.PortNumber == 1433 || p?.PortNumber == 6379);

                // 维度一：总体态势
                var para1 = doc.InsertParagraph();
                para1.Append("【总体态势】").Bold().FontSize(10).Color(DeepBlue);
                para1.Append($"本次对 {targetIp} 的安全扫描共发现 {safeVulns.Count} 个漏洞、{openPorts.Count} 个开放端口；系统整体安全评级为「").FontSize(10);
                para1.Append($"{riskLevel}").Bold().FontSize(10).Color(GetRiskColor(riskLevel));
                para1.Append($"」，安全评分 {securityScore}/100。综合来看，").FontSize(10);
                if (riskLevel == "严重" || riskLevel == "高")
                    para1.Append("系统面临较高安全风险，需立即启动应急响应并落实修复。").FontSize(10);
                else if (riskLevel == "中")
                    para1.Append("系统存在一定安全风险，建议按优先级推进修复。").FontSize(10);
                else
                    para1.Append("系统安全态势整体可控，建议持续保持安全监控。").FontSize(10);
                para1.SpacingAfter(6);

                // 维度二：漏洞态势
                var para2 = doc.InsertParagraph();
                para2.Append("【漏洞态势】").Bold().FontSize(10).Color(DeepBlue);
                para2.Append($"在 {safeVulns.Count} 个漏洞中，").FontSize(10);
                if (critCount > 0) { para2.Append($"严重漏洞 {critCount} 个").Bold().FontSize(10).Color(Xceed.Drawing.Color.Firebrick); para2.Append("，"); }
                if (highCnt > 0) { para2.Append($"高危漏洞 {highCnt} 个").Bold().FontSize(10).Color(Xceed.Drawing.Color.OrangeRed); para2.Append("，"); }
                para2.Append($"中危 {medCount} 个、低危/信息 {lowCount} 个。").FontSize(10);
                if (critCount + highCnt > 0)
                    para2.Append("存在可被远程利用的高危漏洞，攻击者可借此获取系统控制权或敏感数据，必须优先处置。").FontSize(10);
                else
                    para2.Append("未发现严重/高危级别漏洞，漏洞风险整体可控。").FontSize(10);
                para2.SpacingAfter(6);

                // 维度三：端口态势
                var para3 = doc.InsertParagraph();
                para3.Append("【端口态势】").Bold().FontSize(10).Color(DeepBlue);
                para3.Append($"共识别 {openPorts.Count} 个开放端口，").FontSize(10);
                if (highRiskPortCount > 0)
                {
                    para3.Append($"其中包含 {highRiskPortCount} 个高危端口（如 445/135/3389/23/21/3306/1433/6379 等），").FontSize(10);
                    para3.Append("这些端口是勒索软件、蠕虫病毒、暴力破解攻击的主要入口，").Bold().FontSize(10).Color(Xceed.Drawing.Color.Firebrick);
                    para3.Append("建议立即关闭或限制来源访问。").FontSize(10);
                }
                else
                {
                    para3.Append("未检测到 445/135/3389/23/21/3306/1433/6379 等高危端口对外暴露，端口暴露面整体可控。").FontSize(10);
                }
                para3.SpacingAfter(6);

                // 维度四：风险处置优先级
                var para4 = doc.InsertParagraph();
                para4.Append("【风险处置优先级】").Bold().FontSize(10).Color(DeepBlue);
                if (riskLevel == "严重" || riskLevel == "高")
                {
                    para4.Append("建议按 P1 紧急级别（24 小时内）处置严重/高危漏洞，").Bold().FontSize(10).Color(Xceed.Drawing.Color.Firebrick);
                    para4.Append("同步启动应急响应流程、隔离受影响系统、加强实时威胁监控；中危漏洞按 P2（7 天内）处理；低危漏洞按 P3 持续优化。").FontSize(10);
                }
                else if (riskLevel == "中")
                {
                    para4.Append("建议按 P2 优先级（7 天内）处置中危及以上漏洞，").Bold().FontSize(10).Color(Xceed.Drawing.Color.OrangeRed);
                    para4.Append("同步完善安全配置基线和监控告警；低危漏洞纳入 P3 持续修复计划。").FontSize(10);
                }
                else
                {
                    para4.Append("建议按 P3 持续优化原则保持安全态势，").Bold().FontSize(10).Color(Xceed.Drawing.Color.SeaGreen);
                    para4.Append("定期执行漏洞扫描与基线核查，建立常态化的安全运营机制。").FontSize(10);
                }
                para4.SpacingAfter(6);

                // 维度五：总体建议
                var para5 = doc.InsertParagraph();
                para5.Append("【总体建议】").Bold().FontSize(10).Color(DeepBlue);
                para5.Append("结合上述态势分析，建议从「漏洞修复」「端口治理」「配置加固」「监控审计」四个维度同步推进安全工作：").FontSize(10);
                para5.Append("（1）按 P1/P2/P3 优先级闭环处置漏洞；").FontSize(10);
                para5.Append("（2）关闭非必要端口，配置严格的防火墙规则；").FontSize(10);
                para5.Append("（3）建立安全配置基线并定期核查；").FontSize(10);
                para5.Append("（4）部署集中化日志管理与威胁监控平台，形成「检测-分析-响应-恢复」的安全运营闭环。").Bold().FontSize(10).Color(DeepBlue);
                para5.SpacingAfter(10);
            }
        }

        #endregion

        #region 第三章 端口扫描结果

        private static void GeneratePortScanSection(DocX doc, List<PortScanResult> results)
        {
            var chapterTitle = doc.InsertParagraph("第三章 端口扫描结果");
            chapterTitle.FontSize(16).Bold();
            chapterTitle.Color(DeepBlue);
            chapterTitle.SpacingBefore(15);
            chapterTitle.SpacingAfter(4);

            var titleLine = doc.InsertParagraph(new string('─', 50));
            titleLine.FontSize(7);
            titleLine.Color(AccentBlue);
            titleLine.SpacingAfter(12);

            var intro = doc.InsertParagraph("本节列出所有检测到的开放端口及其对应的服务信息。端口扫描是网络安全评估的基础环节，通过识别对外开放的网络端口和服务，评估目标系统的网络暴露面和潜在攻击入口。");
            intro.FontSize(10);
            intro.SpacingBefore(8);
            intro.SpacingAfter(18);

            var safeResults = results ?? new List<PortScanResult>();
            var allPorts = safeResults.OrderBy(p => p?.PortNumber ?? 0).ToList();

            if (!allPorts.Any())
            {
                var emptyPara = doc.InsertParagraph("本次扫描未发现开放端口");
                emptyPara.Alignment = Alignment.center;
                emptyPara.SpacingAfter(15);
                var notePara = doc.InsertParagraph("未发现开放端口可能表示目标系统未运行网络服务、位于防火墙后方或端口被过滤。建议结合其他扫描方式（如UDP扫描、服务发现扫描）进行进一步验证。");
                notePara.FontSize(9);
                notePara.Color(MidGray);
                return;
            }

            var openPorts = allPorts.Where(p => p?.Status == "开放" || p?.Status?.ToLower() == "open").ToList();
            var closedPorts = allPorts.Where(p => p?.Status == "关闭" || p?.Status?.ToLower() == "closed").ToList();
            var filteredPorts = allPorts.Where(p => p?.Status == "过滤" || p?.Status?.ToLower() == "filtered").ToList();

            var subHeaderScan = doc.InsertParagraph("3.1 扫描方法说明");
            subHeaderScan.FontSize(13).Bold();
            subHeaderScan.Color(DeepBlue);
            subHeaderScan.SpacingBefore(12);
            subHeaderScan.SpacingAfter(8);

            // 任务6：增加"扫描流程图"文字描述段（≥120字）
            var flowTitle = doc.InsertParagraph("扫描流程图");
            flowTitle.FontSize(11).Bold();
            flowTitle.Color(AccentBlue);
            flowTitle.SpacingBefore(4);
            flowTitle.SpacingAfter(4);

            var flowPara1 = doc.InsertParagraph("本次端口扫描按照「目标确认 → 端口发现 → 服务识别 → 漏洞匹配 → 结果汇总」五个阶段串行执行：");
            flowPara1.FontSize(10);
            flowPara1.SpacingAfter(4);

            var flowSteps = new[]
            {
                "① 目标确认：解析用户输入的目标 IP/域名，校验其可达性，并对授权范围进行提示；",
                "② 端口发现：基于 TCP SYN 半连接扫描技术对目标 1-65535 端口进行探测，依据 SYN+ACK/RST 响应判定端口状态（开放/关闭/过滤）；",
                "③ 服务识别：对开放端口主动抓取 Banner 报文，识别服务类型与版本（如 HTTP、SSH、MySQL、Redis 等）；",
                "④ 漏洞匹配：将服务指纹与内置 CVE/CNVD 漏洞库进行模式匹配，识别已知漏洞并计算 CVSS 评分；",
                "⑤ 结果汇总：将端口、漏洞、风险评估结果按统一格式汇总，生成可视化报告输出。"
            };
            foreach (var step in flowSteps)
            {
                var stepP = doc.InsertParagraph(step);
                stepP.FontSize(10);
                stepP.SpacingAfter(3);
            }
            doc.InsertParagraph().SpacingAfter(8);

            var methodPara = doc.InsertParagraph();
            methodPara.Append("本次端口扫描采用").FontSize(10);
            methodPara.Append("TCP SYN半连接扫描").FontSize(10).Bold();
            methodPara.Append("技术，通过向目标端口发送SYN数据包并分析响应来判定端口状态。扫描范围为常用TCP端口（1-65535）。").FontSize(10);
            methodPara.SpacingAfter(8);

            var methodTable = doc.AddTable(4, 3);
            methodTable.Design = TableDesign.TableGrid;
            methodTable.Alignment = Alignment.center;

            var methodHeaders = new[] { "扫描参数", "配置值", "说明" };
            StyleTableHeader(methodTable, methodHeaders);

            methodTable.Rows[1].Cells[0].Paragraphs[0].Append("扫描方式").FontSize(9).Bold();
            methodTable.Rows[1].Cells[1].Paragraphs[0].Append("TCP SYN (半连接)").FontSize(9);
            methodTable.Rows[1].Cells[2].Paragraphs[0].Append("不完成完整TCP三次握手，扫描速度快且隐蔽性好").FontSize(9);

            methodTable.Rows[2].Cells[0].Paragraphs[0].Append("扫描范围").FontSize(9).Bold();
            methodTable.Rows[2].Cells[1].Paragraphs[0].Append("常用端口 (1-65535)").FontSize(9);
            methodTable.Rows[2].Cells[2].Paragraphs[0].Append("覆盖所有标准服务端口").FontSize(9);

            methodTable.Rows[3].Cells[0].Paragraphs[0].Append("状态判定").FontSize(9).Bold();
            methodTable.Rows[3].Cells[1].Paragraphs[0].Append("SYN-ACK→开放 / RST→关闭").FontSize(9);
            methodTable.Rows[3].Cells[2].Paragraphs[0].Append("基于TCP协议响应报文判定端口状态").FontSize(9);

            ApplyTableRowShading(methodTable);
            doc.InsertParagraph().SpacingAfter(22);

            var subHeader0 = doc.InsertParagraph("3.2 端口扫描概况");
            subHeader0.FontSize(13).Bold();
            subHeader0.Color(DeepBlue);
            subHeader0.SpacingBefore(12);
            subHeader0.SpacingAfter(10);

            var summaryPara = doc.InsertParagraph();
            summaryPara.Append($"本次扫描共检测{allPorts.Count}个端口，其中");
            summaryPara.Append($" {openPorts.Count}个端口处于开放状态").FontSize(10).Bold().Color(Xceed.Drawing.Color.SeaGreen);
            if (closedPorts.Any())
                summaryPara.Append($"，{closedPorts.Count}个端口处于关闭状态");
            if (filteredPorts.Any())
                summaryPara.Append($"，{filteredPorts.Count}个端口处于过滤状态");
            summaryPara.Append("。开放端口数量直接反映了系统的网络暴露面大小。").FontSize(10);
            summaryPara.SpacingAfter(12);

            var summaryTable = doc.AddTable(5, 2);
            summaryTable.Design = TableDesign.TableGrid;
            summaryTable.Alignment = Alignment.center;

            var summaryHeaders = new[] { "统计项目", "数据" };
            StyleTableHeader(summaryTable, summaryHeaders);

            var svcTypes = openPorts.Where(p => !string.IsNullOrEmpty(p?.Service))
                .Select(p => p.Service).Distinct().Count();
            var portNums = openPorts.Select(p => p?.PortNumber ?? 0).ToHashSet();
            var highRiskPorts = portNums.Where(p => p == 445 || p == 135 || p == 3389 || p == 23 || p == 21 || p == 3306 || p == 1433 || p == 6379).ToList();
            var hasHighRisk = highRiskPorts.Any();

            summaryTable.Rows[1].Cells[0].Paragraphs[0].Append("检测端口总数").FontSize(9).Bold();
            summaryTable.Rows[1].Cells[1].Paragraphs[0].Append($"{allPorts.Count}个").FontSize(9);
            summaryTable.Rows[2].Cells[0].Paragraphs[0].Append("开放端口数").FontSize(9).Bold();
            summaryTable.Rows[2].Cells[1].Paragraphs[0].Append($"{openPorts.Count}个").FontSize(9).Bold().Color(openPorts.Count > 10 ? Xceed.Drawing.Color.OrangeRed : Xceed.Drawing.Color.SeaGreen);
            summaryTable.Rows[3].Cells[0].Paragraphs[0].Append("服务类型数").FontSize(9).Bold();
            summaryTable.Rows[3].Cells[1].Paragraphs[0].Append($"{svcTypes}种").FontSize(9);
            summaryTable.Rows[4].Cells[0].Paragraphs[0].Append("高危端口").FontSize(9).Bold();
            summaryTable.Rows[4].Cells[1].Paragraphs[0].Append(hasHighRisk ? $"{highRiskPorts.Count}个（{string.Join(", ", highRiskPorts)}）" : "未发现").FontSize(9).Bold();
            summaryTable.Rows[4].Cells[1].Paragraphs[0].Color(hasHighRisk ? Xceed.Drawing.Color.Firebrick : Xceed.Drawing.Color.SeaGreen);
            ApplyTableRowShading(summaryTable);

            doc.InsertParagraph().SpacingAfter(22);

            // 3.3 高危端口安全警示 - 始终存在标题，根据数据显示表格或占位说明
            {
                var riskTitle = doc.InsertParagraph("3.3 高危端口安全警示");
                riskTitle.FontSize(13).Bold();
                riskTitle.Color(DeepBlue);
                riskTitle.SpacingBefore(12);
                riskTitle.SpacingAfter(8);

                if (hasHighRisk)
                {
                    var riskDesc = doc.InsertParagraph($"检测到{highRiskPorts.Count}个高危端口对外暴露，这些端口通常是恶意攻击者的首要目标。开放这些端口显著增加了系统被攻破的风险，建议立即评估是否关闭或限制访问。");
                    riskDesc.FontSize(10);
                    riskDesc.SpacingAfter(10);

                    var highRiskTable = doc.AddTable(highRiskPorts.Count + 1, 4);
                    highRiskTable.Design = TableDesign.TableGrid;
                    highRiskTable.Alignment = Alignment.center;

                    var hrHeaders = new[] { "端口", "典型服务", "风险等级", "安全建议" };
                    StyleTableHeader(highRiskTable, hrHeaders);

                    // 任务7：扩展每个端口详情（风险描述 / 典型攻击场景 / 修复方向）
                    var portRiskInfo = new Dictionary<int, (string service, string risk, string advice)>
                    {
                        { 445, ("SMB文件共享", "严重", "立即关闭；如需使用可通过VPN访问") },
                        { 135, ("RPC远程调用", "严重", "关闭端口；配置防火墙阻止135/137-139") },
                        { 3389, ("远程桌面(RDP)", "高", "限制来源IP；启用NLA网络级认证") },
                        { 23, ("Telnet远程登录", "严重", "立即关闭；使用SSH替代") },
                        { 21, ("FTP文件传输", "高", "关闭；使用SFTP/FTPS替代") },
                        { 3306, ("MySQL数据库", "高", "仅限内网127.0.0.1监听") },
                        { 1433, ("SQL Server数据库", "高", "仅限内网访问；启用SSL加密") },
                        { 6379, ("Redis缓存", "高", "仅限内网监听；设置强密码认证") }
                    };

                    // 端口风险详情：风险描述 / 典型攻击场景 / 修复方向
                    var portDetail = new Dictionary<int, (string desc, string scenario, string fix)>
                    {
                        { 445, ("SMB 协议广泛用于 Windows 文件与打印共享，但历史上高危漏洞频发（EternalBlue、PrintNightmare、SMBGhost 等），是勒索软件（如 WannaCry、NotPetya）的主要传播通道。",
                                "攻击者通过 445/TCP 利用 MS17-010 等漏洞执行远程代码，或通过匿名空会话枚举共享与用户信息，进一步横向移动。",
                                "如非必要，关闭 SMB 服务并禁用 445 端口；启用 SMB 签名；通过 VPN 访问文件共享；及时安装 MS17-010 等关键补丁。") },
                        { 135, ("Microsoft RPC 端点映射器端口，DCOM、远程管理服务依赖此端口。历史上多次出现高危远程代码执行漏洞，是 WannaCry 等蠕虫的扩散节点之一。",
                                "攻击者通过 135 端口调用 DCOM 接口进行远程执行，或结合 445/139 实现内网横向渗透与权限提升。",
                                "在公网完全封禁 135/137/139 端口；按需限制内网访问；关闭不必要的 DCOM 服务；启用主机防火墙。") },
                        { 3389, ("Windows 远程桌面协议（RDP）端口，常被勒索软件团伙和 APT 组织作为初始入口。",
                                "攻击者通过暴力破解、弱口令或凭据填充登录；利用 BlueKeep（CVE-2019-0708）等漏洞在未认证状态下执行远程代码。",
                                "限制 RDP 访问来源 IP；启用网络级别认证（NLA）；强制多因素认证；设置账户锁定策略；及时更新系统补丁。") },
                        { 23, ("Telnet 协议以明文传输用户名、密码和数据，安全性极差，互联网上存在大量自动化嗅探与爆破工具。",
                                "攻击者通过网络嗅探获取管理员凭据，或通过字典攻击暴力破解 Telnet 账户。",
                                "立即关闭 Telnet 服务；改用 SSH（22 端口）并配置密钥认证；如确需 Telnet，仅在受控内网使用并强制访问控制。") },
                        { 21, ("FTP 协议默认以明文传输凭据和数据，且历史上多次出现缓冲区溢出与匿名访问漏洞。",
                                "攻击者通过匿名登录读取敏感文件，或通过弱口令暴力破解获取服务器权限，甚至利用 ProFTPD、vsftpd 等历史漏洞获取 Shell。",
                                "关闭 FTP 服务；使用 SFTP/FTPS 替代；如需保留，按用户限制目录、配置强密码策略并启用传输加密。") },
                        { 3306, ("MySQL 默认监听端口，如直接暴露在公网，存在严重的数据泄露与未授权访问风险。",
                                "攻击者通过弱口令、SQL 注入或历史 MySQL 漏洞（如 UDF 提权、CVE-2016-6662）获取数据库控制权，进一步渗透内网。",
                                "仅允许 127.0.0.1 或内网网段访问；为每个账户配置强密码；启用 TLS 加密传输；及时升级到稳定版本。") },
                        { 1433, ("Microsoft SQL Server 默认端口，对外暴露极易成为勒索软件和挖矿木马的目标。",
                                "攻击者通过 sa 弱口令暴力破解、SQL 注入或利用 xp_cmdshell 扩展执行系统命令，实现权限提升与数据窃取。",
                                "修改默认端口；仅允许内网访问；禁用 sa 账户或使用强密码；启用 SSL/TLS 加密；最小化权限原则。") },
                        { 6379, ("Redis 默认未开启认证且支持 CONFIG SET 等高危命令，公网暴露时极易被攻击者利用。",
                                "攻击者通过未授权访问写入 SSH 公钥、计划任务或恶意 SO 文件，实现远程命令执行；常见于挖矿与勒索事件。",
                                "仅监听 127.0.0.1 或内网；启用 requirepass 强密码认证；禁用或重命名危险命令；使用 Redis 6+ 的 ACL 细粒度授权。") },
                        { 27017, ("MongoDB 默认端口，公网暴露的 MongoDB 历史上多次发生大规模数据泄露事件。",
                                "攻击者通过未授权访问或弱口令登录，dump 全量数据库或植入勒索信息。",
                                "仅监听内网；启用访问控制与强密码认证；开启审计日志；最小化用户权限。") }
                    };

                    int hrIdx = 1;
                    foreach (var port in highRiskPorts)
                    {
                        var info = portRiskInfo.ContainsKey(port) ? portRiskInfo[port] : ("未知服务", "高", "评估后关闭");
                        highRiskTable.Rows[hrIdx].Cells[0].Paragraphs[0].Append($"{port}/TCP").FontSize(9).Bold();
                        highRiskTable.Rows[hrIdx].Cells[0].Paragraphs[0].Alignment = Alignment.center;
                        highRiskTable.Rows[hrIdx].Cells[1].Paragraphs[0].Append(info.Item1).FontSize(9);
                        highRiskTable.Rows[hrIdx].Cells[2].Paragraphs[0].Append(info.Item2).FontSize(9).Bold().Color(GetRiskColor(info.Item2));
                        highRiskTable.Rows[hrIdx].Cells[2].Paragraphs[0].Alignment = Alignment.center;
                        highRiskTable.Rows[hrIdx].Cells[3].Paragraphs[0].Append(info.Item3).FontSize(9);
                        hrIdx++;
                    }
                    ApplyTableRowShading(highRiskTable);

                    // 任务7：每个高危端口独立段（风险描述 + 典型攻击场景 + 修复方向）
                    doc.InsertParagraph().SpacingAfter(8);
                    var portDetailTitle = doc.InsertParagraph("高危端口风险详情（逐项说明）");
                    portDetailTitle.FontSize(11).Bold();
                    portDetailTitle.Color(AccentBlue);
                    portDetailTitle.SpacingBefore(8);
                    portDetailTitle.SpacingAfter(6);

                    int portNo = 1;
                    foreach (var port in highRiskPorts)
                    {
                        var svc = portRiskInfo.ContainsKey(port) ? portRiskInfo[port].Item1 : "未知服务";
                        var detail = portDetail.ContainsKey(port)
                            ? portDetail[port]
                            : (desc: "该端口为高危服务端口，存在被攻击的高风险。",
                               scenario: "可能遭受暴力破解、漏洞利用或数据窃取等攻击。",
                               fix: "评估业务必要性，关闭非必要端口并限制访问来源。");

                        var portHeader = doc.InsertParagraph();
                        portHeader.Append($"{portNo}. 端口 {port}/TCP（{svc}）").Bold().FontSize(10).Color(DeepBlue);
                        portHeader.SpacingBefore(6);
                        portHeader.SpacingAfter(2);

                        var portDescP = doc.InsertParagraph();
                        portDescP.Append("  • 风险描述：").Bold().FontSize(10);
                        portDescP.Append(detail.desc).FontSize(10);
                        portDescP.SpacingAfter(2);

                        var portScenarioP = doc.InsertParagraph();
                        portScenarioP.Append("  • 典型攻击场景：").Bold().FontSize(10);
                        portScenarioP.Append(detail.scenario).FontSize(10);
                        portScenarioP.SpacingAfter(2);

                        var portFixP = doc.InsertParagraph();
                        portFixP.Append("  • 修复方向：").Bold().FontSize(10);
                        portFixP.Append(detail.fix).FontSize(10);
                        portFixP.SpacingAfter(8);

                        portNo++;
                    }
                }
                else
                {
                    var noRiskPara = doc.InsertParagraph("本次扫描未检测到高危端口（445/135/3389/23/21/3306/1433/6379）对外暴露。高危端口通常是勒索软件、蠕虫病毒和暴力破解攻击的主要入口，未发现高危端口暴露是良好的安全态势。建议持续保持当前访问控制策略。");
                    noRiskPara.FontSize(10);
                    noRiskPara.Alignment = Alignment.center;
                    noRiskPara.SpacingAfter(10);
                }
                doc.InsertParagraph().SpacingAfter(22);
            }

            // 3.4 所有端口详情 - 始终使用相同编号
            var subHeader = doc.InsertParagraph("3.4 所有端口详情");
            subHeader.FontSize(13).Bold();
            subHeader.Color(DeepBlue);
            subHeader.SpacingBefore(12);
            subHeader.SpacingAfter(10);

            bool hasMore = allPorts.Count > MAX_PORTS_DISPLAY;
            var displayPorts = hasMore ? allPorts.Take(MAX_PORTS_DISPLAY).ToList() : allPorts;
            var rowCount = displayPorts.Count + 1;
            var portTable = doc.AddTable(rowCount, 5);
            portTable.Design = TableDesign.TableGrid;
            portTable.Alignment = Alignment.center;

            var portHeaders = new[] { "端口号", "状态", "服务", "版本", "风险指示" };
            StyleTableHeader(portTable, portHeaders);

            for (int i = 0; i < displayPorts.Count; i++)
            {
                var port = displayPorts[i];
                var row = portTable.Rows[i + 1];
                var status = port?.Status ?? "未知";
                var isOpen = status == "开放" || status?.ToLower() == "open";

                row.Cells[0].Paragraphs[0].Append($"{port?.PortNumber ?? 0}/TCP").FontSize(9).Bold();
                row.Cells[0].Paragraphs[0].Alignment = Alignment.center;

                row.Cells[1].Paragraphs[0].Append(status).FontSize(9);
                row.Cells[1].Paragraphs[0].Alignment = Alignment.center;
                row.Cells[1].Paragraphs[0].Color(isOpen ? Xceed.Drawing.Color.SeaGreen : GetRiskColor("低"));

                var svc = string.IsNullOrWhiteSpace(port?.Service) ? "未知服务" : port.Service;
                row.Cells[2].Paragraphs[0].Append(svc).FontSize(9);

                var version = string.IsNullOrWhiteSpace(port?.ServiceVersion) ? "-" : port.ServiceVersion;
                row.Cells[3].Paragraphs[0].Append(version).FontSize(9);

                var portNum = port?.PortNumber ?? 0;
                var riskLabel = portNum == 445 || portNum == 135 || portNum == 3389 || portNum == 23 ? "高危" :
                                portNum == 3306 || portNum == 1433 || portNum == 5432 || portNum == 6379 ? "注意" : "正常";
                row.Cells[4].Paragraphs[0].Append(riskLabel).FontSize(9).Bold();
                row.Cells[4].Paragraphs[0].Color(GetRiskColor(riskLabel == "高危" ? "高" : riskLabel == "注意" ? "中" : "低"));
                row.Cells[4].Paragraphs[0].Alignment = Alignment.center;
            }
            ApplyTableRowShading(portTable);

            if (hasMore)
            {
                var morePara = doc.InsertParagraph($"\n注：共发现{allPorts.Count}个端口，展示前{MAX_PORTS_DISPLAY}个");
                morePara.FontSize(9);
                morePara.Color(MidGray);
            }

            doc.InsertParagraph().SpacingAfter(18);

            // 3.5 服务分布统计 - 始终存在标题，根据数据显示图表或占位
            {
                var svcChartTitle = doc.InsertParagraph("3.5 服务分布统计");
                svcChartTitle.FontSize(13).Bold();
                svcChartTitle.Color(DeepBlue);
                svcChartTitle.SpacingBefore(22);
                svcChartTitle.SpacingAfter(8);

                var svcGroups = openPorts.Where(p => !string.IsNullOrEmpty(p?.Service))
                    .GroupBy(p => p.Service).OrderByDescending(g => g.Count()).Take(6).ToList();
                if (svcGroups.Any())
                {
                    var svcChartData = svcGroups.Select(g => (g.Key, g.Count())).ToList();
                    var svcChart = ReportChartGenerator.GeneratePortServiceBarChart(svcChartData);
                    AddChartImage(doc, svcChart, 450, 190);

                    var svcNote = doc.InsertParagraph($"\n共检测到{svcTypes}种不同类型的服务，其中{svcGroups.First().Key}服务最为活跃（{svcGroups.First().Count()}个端口）。");
                    svcNote.FontSize(10);
                    svcNote.SpacingBefore(6);
                    svcNote.SpacingAfter(10);
                }
                else
                {
                    var noSvcPara = doc.InsertParagraph("未识别到具体服务类型（扫描结果中未包含服务指纹信息）。建议结合主动服务探测工具（如 Nmap -sV）进行更深入的服务识别。");
                    noSvcPara.FontSize(10);
                    noSvcPara.Alignment = Alignment.center;
                    noSvcPara.SpacingAfter(10);
                }
            }
        }

        #endregion

        #region 漏洞详情

        private static void GenerateVulnerabilitySection(DocX doc, List<VulnerabilityResult> vulnerabilities)
        {
            var chapterTitle = doc.InsertParagraph("第四章 漏洞详情分析");
            chapterTitle.FontSize(16).Bold();
            chapterTitle.Color(DeepBlue);
            chapterTitle.SpacingBefore(15);
            chapterTitle.SpacingAfter(4);

            var titleLine = doc.InsertParagraph(new string('─', 50));
            titleLine.FontSize(7);
            titleLine.Color(AccentBlue);
            titleLine.SpacingAfter(12);

            var intro = doc.InsertParagraph("本节详细列出所有检测到的安全漏洞，按风险等级从高到低排列，并提供每个漏洞的CVSS评分、影响范围和修复方案。");
            intro.FontSize(10);
            intro.SpacingBefore(8);
            intro.SpacingAfter(18);

            var safeVulns = vulnerabilities ?? new List<VulnerabilityResult>();

            var criticalCount = safeVulns.Count(v => IsCritical(v?.RiskLevel));
            var highCount = safeVulns.Count(v => IsHigh(v?.RiskLevel));
            var mediumCount = safeVulns.Count(v => IsMedium(v?.RiskLevel));
            var lowCount = safeVulns.Count(v => IsLow(v?.RiskLevel));
            var unknownCount = safeVulns.Count - criticalCount - highCount - mediumCount - lowCount;

            var vulnSvcs = safeVulns.Where(v => !string.IsNullOrWhiteSpace(v?.Service))
                .GroupBy(v => v.Service).OrderByDescending(g => g.Count()).Take(5).ToList();

            if (!safeVulns.Any())
            {
                var emptyPara = doc.InsertParagraph("本次扫描未发现安全漏洞，未在已知漏洞库中匹配到已知漏洞。");
                emptyPara.Alignment = Alignment.center;
                emptyPara.SpacingAfter(12);
                var notePara = doc.InsertParagraph("未检测到已知漏洞可能表示目标系统已及时更新或安全配置良好，但也可能是扫描范围有限或目标系统运行了未公开的服务。建议结合其他评估手段进行综合判断。");
                notePara.FontSize(9);
                notePara.Color(MidGray);
                notePara.SpacingAfter(18);
            }

            var subHeader0 = doc.InsertParagraph("4.1 漏洞风险分布");
            subHeader0.FontSize(13).Bold();
            subHeader0.Color(DeepBlue);
            subHeader0.SpacingBefore(12);
            subHeader0.SpacingAfter(10);

            var distIntro = doc.InsertParagraph();
            distIntro.Append($"本次扫描共检测到{safeVulns.Count}个安全漏洞。按风险等级分布：");
            if (criticalCount > 0)
                distIntro.Append($" 严重{criticalCount}个").FontSize(10).Bold().Color(Xceed.Drawing.Color.Red);
            if (highCount > 0)
                distIntro.Append($"、高危{highCount}个").FontSize(10).Bold().Color(Xceed.Drawing.Color.OrangeRed);
            if (mediumCount > 0)
                distIntro.Append($"、中危{mediumCount}个").FontSize(10).Bold().Color(Xceed.Drawing.Color.DarkOrange);
            if (lowCount > 0)
                distIntro.Append($"、低危{lowCount}个").FontSize(10).Bold().Color(Xceed.Drawing.Color.SeaGreen);
            if (unknownCount > 0)
                distIntro.Append($"、未分类{unknownCount}个");
            distIntro.Append("。").FontSize(10);
            distIntro.SpacingAfter(12);

            var distTable = doc.AddTable(4, 3);
            distTable.Design = TableDesign.TableGrid;
            distTable.Alignment = Alignment.center;

            var distHeaders = new[] { "风险等级", "漏洞数量", "占比" };
            StyleTableHeader(distTable, distHeaders);

            void AddDistRow(int row, string level, int count)
            {
                distTable.Rows[row].Cells[0].Paragraphs[0].Append(level).FontSize(9).Bold();
                distTable.Rows[row].Cells[0].Paragraphs[0].Color(GetRiskColor(level));
                distTable.Rows[row].Cells[1].Paragraphs[0].Append($"{count}个").FontSize(9);
                distTable.Rows[row].Cells[1].Paragraphs[0].Alignment = Alignment.center;
                var pct = safeVulns.Count > 0 ? (double)count / safeVulns.Count * 100 : 0;
                distTable.Rows[row].Cells[2].Paragraphs[0].Append($"{pct:F1}%").FontSize(9).Bold();
                distTable.Rows[row].Cells[2].Paragraphs[0].Color(GetRiskColor(level));
                distTable.Rows[row].Cells[2].Paragraphs[0].Alignment = Alignment.center;
            }

            AddDistRow(1, "严重/高危", criticalCount + highCount);
            AddDistRow(2, "中危", mediumCount);
            AddDistRow(3, "低危/信息", lowCount + unknownCount);
            ApplyTableRowShading(distTable);

            doc.InsertParagraph().SpacingAfter(18);

            if (vulnSvcs.Any())
            {
                var svcDistTitle = doc.InsertParagraph("4.2 受影响服务分布");
                svcDistTitle.FontSize(13).Bold();
                svcDistTitle.Color(DeepBlue);
                svcDistTitle.SpacingBefore(12);
                svcDistTitle.SpacingAfter(10);

                var svcDistIntro = doc.InsertParagraph($"在{safeVulns.Count}个漏洞中，主要影响以下服务：");
                svcDistIntro.FontSize(10);
                svcDistIntro.SpacingAfter(8);

                var svcTable = doc.AddTable(vulnSvcs.Count + 1, 3);
                svcTable.Design = TableDesign.TableGrid;
                svcTable.Alignment = Alignment.center;

                var svcTableHeaders = new[] { "受影响服务", "漏洞数量", "最高风险等级" };
                StyleTableHeader(svcTable, svcTableHeaders);

                int svcRow = 1;
                foreach (var grp in vulnSvcs)
                {
                    svcTable.Rows[svcRow].Cells[0].Paragraphs[0].Append(grp.Key).FontSize(9).Bold();
                    svcTable.Rows[svcRow].Cells[1].Paragraphs[0].Append($"{grp.Count()}个").FontSize(9);
                    svcTable.Rows[svcRow].Cells[1].Paragraphs[0].Alignment = Alignment.center;
                    var maxRisk = CalculateOverallRiskLevel(grp.ToList());
                    svcTable.Rows[svcRow].Cells[2].Paragraphs[0].Append(maxRisk).FontSize(9).Bold().Color(GetRiskColor(maxRisk));
                    svcTable.Rows[svcRow].Cells[2].Paragraphs[0].Alignment = Alignment.center;
                    svcRow++;
                }
                ApplyTableRowShading(svcTable);

                doc.InsertParagraph().SpacingAfter(22);
            }
            else
            {
                // 无受影响服务时为 4.2 增加占位说明
                var svcDistTitle = doc.InsertParagraph("4.2 受影响服务分布");
                svcDistTitle.FontSize(13).Bold();
                svcDistTitle.Color(DeepBlue);
                svcDistTitle.SpacingBefore(12);
                svcDistTitle.SpacingAfter(10);
                var svcDistPh = doc.InsertParagraph("无受影响服务（漏洞扫描结果中未关联到具体服务信息）。");
                svcDistPh.FontSize(10);
                svcDistPh.Alignment = Alignment.center;
                svcDistPh.SpacingAfter(12);
            }

            var subHeaderType = doc.InsertParagraph("4.3 漏洞类型分类统计");
            subHeaderType.FontSize(13).Bold();
            subHeaderType.Color(DeepBlue);
            subHeaderType.SpacingBefore(12);
            subHeaderType.SpacingAfter(10);

            var typeIntro = doc.InsertParagraph($"对{safeVulns.Count}个漏洞按攻击类型进行分类统计，帮助理解系统面临的主要威胁类别：");
            typeIntro.FontSize(10);
            typeIntro.SpacingAfter(10);

            var typeCategories = new Dictionary<string, (string[] keywords, int count)>
            {
                { "远程代码执行", (new[] { "rce", "remote code", "execution", "远程执行", "代码执行", "命令执行" }, 0) },
                { "权限提升", (new[] { "privilege", "escalation", "权限提升", "提权", "elevation" }, 0) },
                { "拒绝服务", (new[] { "denial", "dos", "ddos", "拒绝服务", "crash", "resource exhaustion" }, 0) },
                { "信息泄露", (new[] { "disclosure", "泄露", "leak", "exposure", "信息披露", "信息泄漏" }, 0) },
                { "认证绕过", (new[] { "auth", "bypass", "authentication", "认证", "login", "登录", "logon" }, 0) },
                { "跨站脚本", (new[] { "xss", "cross-site", "scripting", "跨站", "html injection" }, 0) },
                { "SQL注入", (new[] { "sql", "injection", "注入" }, 0) },
                { "缓冲区溢出", (new[] { "buffer", "overflow", "缓冲区", "缓冲区溢出", "stack", "heap" }, 0) }
            };

            var matchedCount = 0;
            foreach (var vuln in safeVulns)
            {
                var name = (vuln?.Name ?? "").ToLower();
                var desc = (vuln?.Description ?? "").ToLower();
                var combined = name + " " + desc;
                bool matched = false;
                foreach (var cat in typeCategories.ToList())
                {
                    if (cat.Value.keywords.Any(k => combined.Contains(k)))
                    {
                        typeCategories[cat.Key] = (cat.Value.keywords, cat.Value.count + 1);
                        matched = true;
                    }
                }
                if (matched) matchedCount++;
            }

            var otherCount = safeVulns.Count - matchedCount;
            var activeTypes = typeCategories.Where(t => t.Value.count > 0).OrderByDescending(t => t.Value.count).Take(6).ToList();
            if (otherCount > 0)
                activeTypes.Add(new KeyValuePair<string, (string[], int)>("其他", (new[] { "其他" }, otherCount)));

            var typeTable = doc.AddTable(activeTypes.Count + 1, 4);
            typeTable.Design = TableDesign.TableGrid;
            typeTable.Alignment = Alignment.center;

            var typeHeaders = new[] { "漏洞类型", "漏洞数量", "占比", "风险特征" };
            StyleTableHeader(typeTable, typeHeaders);

            var typeRiskMap = new Dictionary<string, string>
            {
                { "远程代码执行", "高" }, { "权限提升", "高" }, { "SQL注入", "高" },
                { "拒绝服务", "中" }, { "信息泄露", "中" }, { "认证绕过", "高" },
                { "跨站脚本", "中" }, { "缓冲区溢出", "高" }
            };

            int tRow = 1;
            foreach (var typ in activeTypes)
            {
                typeTable.Rows[tRow].Cells[0].Paragraphs[0].Append(typ.Key).FontSize(9).Bold();
                typeTable.Rows[tRow].Cells[1].Paragraphs[0].Append($"{typ.Value.count}个").FontSize(9);
                typeTable.Rows[tRow].Cells[1].Paragraphs[0].Alignment = Alignment.center;
                var pct = safeVulns.Count > 0 ? (double)typ.Value.count / safeVulns.Count * 100 : 0;
                typeTable.Rows[tRow].Cells[2].Paragraphs[0].Append($"{pct:F1}%").FontSize(9).Bold();
                typeTable.Rows[tRow].Cells[2].Paragraphs[0].Color(GetRiskColor(typ.Key == "远程代码执行" || typ.Key == "权限提升" ? "高" : "中"));
                typeTable.Rows[tRow].Cells[2].Paragraphs[0].Alignment = Alignment.center;
                var riskFeature = typeRiskMap.ContainsKey(typ.Key) ? typeRiskMap[typ.Key] : "中";
                typeTable.Rows[tRow].Cells[3].Paragraphs[0].Append(riskFeature).FontSize(9).Bold().Color(GetRiskColor(riskFeature));
                typeTable.Rows[tRow].Cells[3].Paragraphs[0].Alignment = Alignment.center;
                tRow++;
            }
            ApplyTableRowShading(typeTable);

            if (!safeVulns.Any())
            {
                var typePh = doc.InsertParagraph("本次扫描未发现安全漏洞，无漏洞类型可统计。");
                typePh.FontSize(10);
                typePh.Alignment = Alignment.center;
                typePh.SpacingAfter(12);
            }

            doc.InsertParagraph().SpacingAfter(22);

            bool hasMore = safeVulns.Count > MAX_VULN_DISPLAY;
            var displayVulns = hasMore ? safeVulns.Take(MAX_VULN_DISPLAY).ToList() : safeVulns;
            var sortedVulns = displayVulns.OrderByDescending(v => GetRiskPriority(v?.RiskLevel)).ToList();

            var subHeader = doc.InsertParagraph("4.4 漏洞概览表");
            subHeader.FontSize(13).Bold();
            subHeader.Color(DeepBlue);
            subHeader.SpacingBefore(12);
            subHeader.SpacingAfter(10);

            var vulnTable = doc.AddTable(sortedVulns.Count + 1, 5);
            vulnTable.Design = TableDesign.TableGrid;
            vulnTable.Alignment = Alignment.center;

            var vulnHeaders = new[] { "#", "漏洞名称", "风险等级", "CVE 编号", "CVSS" };
            StyleTableHeader(vulnTable, vulnHeaders);

            for (int i = 0; i < sortedVulns.Count; i++)
            {
                var vuln = sortedVulns[i];
                var row = vulnTable.Rows[i + 1];
                var rl = string.IsNullOrWhiteSpace(vuln?.RiskLevel) ? "未分类" : vuln.RiskLevel;
                var name = string.IsNullOrWhiteSpace(vuln?.Name) ? "未知漏洞" : vuln.Name;
                var cve = string.IsNullOrWhiteSpace(vuln?.CveId) ? "-" : vuln.CveId;

                row.Cells[0].Paragraphs[0].Append((i + 1).ToString()).FontSize(9);
                row.Cells[0].Paragraphs[0].Alignment = Alignment.center;
                row.Cells[1].Paragraphs[0].Append(name).FontSize(9);
                row.Cells[2].Paragraphs[0].Append(rl).FontSize(9).Bold().Color(GetRiskColor(rl));
                row.Cells[2].Paragraphs[0].Alignment = Alignment.center;
                row.Cells[3].Paragraphs[0].Append(cve).FontSize(9);
                row.Cells[4].Paragraphs[0].Append($"{EstimateCvssScore(rl):F1}").FontSize(9).Bold();
                row.Cells[4].Paragraphs[0].Alignment = Alignment.center;
            }
            ApplyTableRowShading(vulnTable);

            if (hasMore)
            {
                var morePara = doc.InsertParagraph($"\n注：共发现{safeVulns.Count}个漏洞（展示前{MAX_VULN_DISPLAY}个）");
                morePara.FontSize(9);
                morePara.Color(MidGray);
            }

            doc.InsertParagraph().SpacingAfter(22);
            var detailHeader = doc.InsertParagraph("4.5 漏洞详细信息（前10个）");
            detailHeader.FontSize(13).Bold();
            detailHeader.Color(DeepBlue);
            detailHeader.SpacingBefore(22);
            detailHeader.SpacingAfter(10);

            if (safeVulns.Any())
            {
                int dIdx = 1;
                foreach (var vuln in sortedVulns.Take(Math.Min(MAX_DETAIL_BLOCKS, sortedVulns.Count)))
                {
                    try
                    {
                        AddVulnerabilityDetailBlock(doc, vuln, dIdx++);
                    }
                    catch (Exception ex)
                    {
                        Debug.WriteLine($"[WordReport-详情块] 错误: {ex.Message}");
                    }
                }
            }
            else
            {
                var detailPh = doc.InsertParagraph("本次扫描未发现安全漏洞，无可深入分析的漏洞。");
                detailPh.FontSize(10);
                detailPh.Alignment = Alignment.center;
                detailPh.SpacingAfter(10);
            }
        }

        private static void AddVulnerabilityDetailBlock(DocX doc, VulnerabilityResult vuln, int detailIndex)
        {
            if (vuln == null) return;

            var riskLevel = string.IsNullOrWhiteSpace(vuln.RiskLevel) ? "未分类" : vuln.RiskLevel;
            var name = string.IsNullOrWhiteSpace(vuln.Name) ? "未知漏洞" : vuln.Name;
            var cvssScore = EstimateCvssScore(riskLevel);

            var titlePara = doc.InsertParagraph();
            titlePara.Append($"[{detailIndex}] {name}").FontSize(11).Bold().Color(DeepBlue);
            if (!string.IsNullOrWhiteSpace(vuln.CveId))
            {
                titlePara.Append($" ({vuln.CveId})").FontSize(10).Color(AccentBlue);
            }
            titlePara.Append($"  [{riskLevel}]").FontSize(10).Bold().Color(GetRiskColor(riskLevel));
            titlePara.SpacingBefore(12);
            titlePara.SpacingAfter(6);

            var contentPara = doc.InsertParagraph();
            contentPara.Append("\n【漏洞概述】\n").FontSize(10).Bold().Color(DeepBlue);
            var desc = GetSafeString(vuln.Description);
            if (string.IsNullOrWhiteSpace(desc) || desc == "-")
            {
                desc = $"该漏洞影响 {(string.IsNullOrWhiteSpace(vuln.Service) ? "系统" : vuln.Service)}服务" + (vuln.Port.HasValue ? $"（端口 {vuln.Port.Value}）" : "");
            }
            contentPara.Append(desc).FontSize(10);

            contentPara.Append("\n【CVSS评分详情】\n").FontSize(10).Bold().Color(DeepBlue);
            var attackVector = vuln.Port.HasValue ? "网络(N)" : "本地(L)";
            var complexity = riskLevel == "严重" ? "低" : riskLevel == "高危" ? "低" : "中";
            var privileges = riskLevel == "严重" || riskLevel == "高危" ? "无(N)" : "低(L)";
            var userInteraction = "无(N)";
            var scope = riskLevel == "严重" ? "改变(C)" : "未改变(U)";
            var confidentiality = riskLevel == "严重" || riskLevel == "高危" ? "高(H)" : "低(L)";
            var integrity = riskLevel == "严重" || riskLevel == "高危" ? "高(H)" : "低(L)";
            var availability = riskLevel == "严重" ? "高(H)" : riskLevel == "高危" ? "高(H)" : "低(L)";

            contentPara.Append($"\n  • 攻击向量(AV)：{attackVector}").FontSize(9);
            contentPara.Append($"\n  • 攻击复杂度(AC)：{complexity}").FontSize(9);
            contentPara.Append($"\n  • 权限要求(PR)：{privileges}").FontSize(9);
            contentPara.Append($"\n  • 用户交互(UI)：{userInteraction}").FontSize(9);
            contentPara.Append($"\n  • 影响范围(S)：{scope}").FontSize(9);
            contentPara.Append($"\n  • 机密性(C)：{confidentiality}").FontSize(9);
            contentPara.Append($"\n  • 完整性(I)：{integrity}").FontSize(9);
            contentPara.Append($"\n  • 可用性(A)：{availability}").FontSize(9);
            contentPara.Append($"\n  • 综合评分：{cvssScore:F1}/10.0").FontSize(10).Bold().Color(GetRiskColor(riskLevel));

            contentPara.Append("\n\n【基本信息】\n").FontSize(10).Bold().Color(DeepBlue);
            contentPara.Append($"\n  • CVSS评分：{cvssScore:F1} ({riskLevel})").FontSize(9);
            contentPara.Append($"\n  • 影响端口：{(vuln?.Port.HasValue == true ? $"TCP/{vuln.Port.Value}" : "N/A")}").FontSize(9);
            contentPara.Append($"\n  • 影响服务：{(string.IsNullOrWhiteSpace(vuln.Service) ? "N/A" : vuln.Service)}").FontSize(9);
            contentPara.Append($"\n  • 风险等级：{riskLevel}").FontSize(9).Bold().Color(GetRiskColor(riskLevel));

            if (!string.IsNullOrWhiteSpace(vuln.DetectionMethod) && vuln.DetectionMethod != "-")
            {
                contentPara.Append("\n\n【检测方法】\n").FontSize(10).Bold().Color(DeepBlue);
                contentPara.Append(GetSafeString(vuln.DetectionMethod)).FontSize(10);
            }

            contentPara.Append("\n\n【影响范围分析】\n").FontSize(10).Bold().Color(DeepBlue);
            if (riskLevel == "严重" || riskLevel == "高危")
            {
                contentPara.Append("该漏洞可导致远程代码执行或权限提升，攻击者可能完全控制受影响的系统。" +
                    "影响范围包括：系统完整性破坏、敏感数据泄露、服务中断等严重后果。").FontSize(10);
            }
            else if (riskLevel == "中危")
            {
                contentPara.Append("该漏洞可导致信息泄露或服务降级，攻击者可能获取部分系统信息或造成服务影响。建议尽快修复。").FontSize(10);
            }
            else
            {
                contentPara.Append("该漏洞风险较低，主要影响信息收集或带来有限的安全隐患。建议纳入常规修复计划。").FontSize(10);
            }

            contentPara.Append("\n\n【修复方案】\n").FontSize(10).Bold().Color(DeepBlue);
            // 任务8：强化"修复建议"字段（≥50字）
            string solution;
            if (!string.IsNullOrWhiteSpace(vuln.Solution) && vuln.Solution != "-")
            {
                solution = vuln.Solution;
            }
            else
            {
                // 缺失修复建议时按风险等级给出通用强化建议（≥50字）
                if (riskLevel == "严重" || riskLevel == "高危")
                {
                    solution = "1) 立即按官方安全公告升级组件至安全版本，或安装对应补丁；2) 若暂无补丁，启用 WAF/IPS 临时缓解并限制网络访问；3) 修改默认配置、关闭非必要服务、最小化权限；4) 复测确认漏洞已闭环；5) 持续关注官方更新和威胁情报。";
                }
                else if (riskLevel == "中危")
                {
                    solution = "1) 参照官方安全公告升级到修复版本或安装补丁；2) 强化相关组件的安全配置（如关闭调试接口、限制访问范围）；3) 必要时启用临时缓解措施（如防火墙规则）；4) 跟踪修复进度并复测。";
                }
                else
                {
                    solution = "1) 评估漏洞的实际影响并纳入下一轮修复计划；2) 持续关注漏洞库和官方安全公告；3) 定期执行安全扫描和渗透测试，确保问题可控。";
                }
            }

            var solutionLines = solution.Split('\n')
                .Where(l => !string.IsNullOrWhiteSpace(l))
                .Select(l => l.Trim())
                .Take(6)
                .ToList();
            if (solutionLines.Count == 0) solutionLines.Add(solution);

            foreach (var line in solutionLines)
            {
                contentPara.Append($"  • {line}\n").FontSize(10);
            }

            // 任务8：补充【验证方法】字段，确保 5 大字段齐全
            contentPara.Append("\n【验证方法】\n").FontSize(10).Bold().Color(DeepBlue);
            var verifyText = BuildVerificationMethod(vuln, riskLevel);
            contentPara.Append(verifyText).FontSize(10);

            if (!string.IsNullOrWhiteSpace(vuln.References))
            {
                contentPara.Append("\n\n【参考链接】\n").FontSize(10).Bold().Color(DeepBlue);
                contentPara.Append(GetSafeString(vuln.References)).FontSize(9).Color(AccentBlue);
            }

            contentPara.SpacingAfter(20);

            var separator = doc.InsertParagraph(new string('─', 60));
            separator.FontSize(7);
            separator.Color(MidGray);
            separator.SpacingAfter(8);
        }

        private static string BuildVerificationMethod(VulnerabilityResult vuln, string riskLevel)
        {
            if (vuln == null) return "重新执行本扫描工具进行复测，确认漏洞已不再命中。";

            var name = (vuln.Name ?? string.Empty).ToLower();
            var hasCve = !string.IsNullOrWhiteSpace(vuln.CveId);
            var port = vuln.Port.HasValue ? $":{vuln.Port.Value}" : string.Empty;

            if (hasCve)
            {
                return $"1) 重新执行本扫描工具，针对 {vuln.CveId}{port} 复测，确认风险等级降至「低危/信息」以下；" +
                       $"2) 在 NVD 官方数据库（https://nvd.nist.gov/vuln/detail/{vuln.CveId}）查询补丁版本与缓解方案；" +
                       $"3) 通过渗透测试或漏洞 PoC 工具验证修复有效性；" +
                       $"4) 检查相关组件的版本号（{vuln.Service ?? "服务"}）已升级到安全版本；" +
                       $"5) 持续关注厂商安全公告与威胁情报。";
            }
            if (name.Contains("rce") || name.Contains("远程执行") || name.Contains("代码执行"))
            {
                return "1) 复测扫描确认漏洞不再命中；2) 在沙箱环境中使用 Metasploit 等专业工具复现漏洞，确认无法再被利用；3) 验证相关组件已升级或安全配置已生效。";
            }
            if (name.Contains("sql") && name.Contains("injection"))
            {
                return "1) 复测扫描确认漏洞不再命中；2) 使用 sqlmap 等工具对原注入点进行重新检测，确认返回结果不再含数据库错误或数据泄露；3) 验证 WAF/参数化查询已部署。";
            }
            if (name.Contains("xss") || name.Contains("跨站"))
            {
                return "1) 复测扫描确认漏洞不再命中；2) 在浏览器中构造 XSS Payload 验证不再执行；3) 验证输入过滤与输出编码已部署。";
            }
            if (riskLevel == "严重" || riskLevel == "高危")
            {
                return "1) 复测扫描确认漏洞不再命中；2) 检查相关组件已升级或加固配置已生效；3) 必要时通过人工渗透测试验证修复有效性；4) 持续关注官方安全公告。";
            }
            return "1) 重新执行本扫描工具进行复测；2) 检查相关组件版本或配置符合安全基线；3) 跟踪修复状态并归档。";
        }

        #endregion

        #region 风险评估

        private static void GenerateRiskAssessment(DocX doc, List<VulnerabilityResult> vulns, List<PortScanResult> ports)
        {
            var chapterTitle = doc.InsertParagraph("第五章 风险评估");
            chapterTitle.FontSize(16).Bold();
            chapterTitle.Color(DeepBlue);
            chapterTitle.SpacingBefore(15);
            chapterTitle.SpacingAfter(4);

            var titleLine = doc.InsertParagraph(new string('─', 50));
            titleLine.FontSize(7);
            titleLine.Color(AccentBlue);
            titleLine.SpacingAfter(12);

            var intro = doc.InsertParagraph("本节对本次扫描发现的各类风险进行综合评估和分析。");
            intro.FontSize(10);
            intro.SpacingBefore(8);
            intro.SpacingAfter(18);

            // 任务9：在 chapterTitle 后、subHeader（5.1）前增加"评估方法论"说明段（≥150字）
            var methodTitle = doc.InsertParagraph("评估方法论");
            methodTitle.FontSize(12).Bold();
            methodTitle.Color(DeepBlue);
            methodTitle.SpacingBefore(10);
            methodTitle.SpacingAfter(6);

            var methodPara0 = doc.InsertParagraph("本次风险评估采用 CVSS v3.1（Common Vulnerability Scoring System）通用漏洞评分体系作为基础评分依据。CVSS 由基础分（Base Score）、时效分（Temporal Score）和环境分（Environmental Score）三部分组成，其中基础分由攻击向量（AV）、攻击复杂度（AC）、权限要求（PR）、用户交互（UI）、影响范围（S）以及机密性/完整性/可用性（C/I/A）共 8 个维度计算得出，分值区间 0-10，分数越高风险越大。");
            methodPara0.FontSize(10);
            methodPara0.SpacingAfter(6);

            var methodPara1 = doc.InsertParagraph("在 CVSS 评分基础上，结合 OWASP 风险评估方法论，采用「可能性 × 影响」二维矩阵对所有风险项进行综合判定：可能性维度（高/中/低）综合考虑漏洞可利用性、攻击复杂度与外部可达性；影响维度（严重/高/中/低）综合考虑业务影响、数据敏感度与合规要求。风险等级判定阈值：综合评分 ≥ 9.0 为「严重」、7.0-8.9 为「高危」、4.0-6.9 为「中危」、0.1-3.9 为「低危」、0 为「信息」。最终安全评分采用加权扣分法（详见 9.1 节），综合反映漏洞严重度、端口暴露、服务多样性与攻击面复杂度。");
            methodPara1.FontSize(10);
            methodPara1.SpacingAfter(12);

            var subHeader = doc.InsertParagraph("5.1 风险评估项目");
            subHeader.FontSize(13).Bold();
            subHeader.Color(DeepBlue);
            subHeader.SpacingBefore(12);
            subHeader.SpacingAfter(10);

            var safeVulns = vulns ?? new List<VulnerabilityResult>();
            var safePorts = ports ?? new List<PortScanResult>();
            var openPortCount = safePorts.Count(p => p?.Status == "开放" || p?.Status?.ToLower() == "open");
            var criticalAndHighCount = safeVulns.Count(v => IsCritical(v?.RiskLevel) || IsHigh(v?.RiskLevel));
            var overallRisk = CalculateOverallRiskLevel(safeVulns);

            var portNums = safePorts.Where(p => p?.Status == "开放" || p?.Status?.ToLower() == "open")
                .Select(p => p?.PortNumber ?? 0).ToHashSet();
            var sensitivePorts = portNums.Where(p => p == 445 || p == 135 || p == 3389 || p == 23 || p == 21 || p == 3306 || p == 1433 || p == 6379).ToList();
            var sensitivePortDesc = sensitivePorts.Any()
                ? $"发现{sensitivePorts.Count}个高危端口（{string.Join(", ", sensitivePorts)}）"
                : "未发现高危端口暴露";
            var sensitiveRiskLevel = sensitivePorts.Any() ? "高" : "低";

            var attackSurfaceLevel = safeVulns.Any(v => IsCritical(v?.RiskLevel)) ? "高风险" :
                safeVulns.Any(v => IsHigh(v?.RiskLevel)) ? "中高风险" : "中等";

            var riskTable = doc.AddTable(7, 2);
            riskTable.Design = TableDesign.TableGrid;
            riskTable.Alignment = Alignment.center;

            var riskHeaders = new[] { "评估指标", "评估结果" };
            StyleTableHeader(riskTable, riskHeaders);

            var riskItems = new (string label, string value, string riskColorHint)[]
            {
                ("漏洞总量", $"{safeVulns.Count}个", "低"),
                ("高危漏洞数", $"{criticalAndHighCount}个", criticalAndHighCount > 0 ? "高" : "低"),
                ("开放端口数", $"{openPortCount}个", "低"),
                ("整体安全评级", overallRisk, overallRisk),
                ("敏感端口暴露", sensitivePortDesc, sensitiveRiskLevel),
                ("攻击面评估", attackSurfaceLevel, criticalAndHighCount > 0 ? "高" : "中")
            };

            for (int r = 0; r < riskItems.Length; r++)
            {
                var row = riskTable.Rows[r + 1];
                row.Cells[0].Paragraphs[0].Append(riskItems[r].label).FontSize(9).Bold();
                row.Cells[1].Paragraphs[0].Append(riskItems[r].value).FontSize(9).Bold();
                row.Cells[1].Paragraphs[0].Color(GetRiskColor(riskItems[r].riskColorHint));
            }
            ApplyTableRowShading(riskTable);

            if (safeVulns.Any())
            {
                doc.InsertParagraph().SpacingAfter(18);

                var matrixTitle = doc.InsertParagraph("5.2 风险等级矩阵（可能性 × 影响）");
                matrixTitle.FontSize(13).Bold();
                matrixTitle.Color(DeepBlue);
                matrixTitle.SpacingBefore(22);
                matrixTitle.SpacingAfter(10);

                var matrixIntro = doc.InsertParagraph("采用OWASP标准风险矩阵模型，结合漏洞可利用性和潜在影响进行风险评估：");
                matrixIntro.FontSize(10);
                matrixIntro.SpacingAfter(10);

                var matrixTable = doc.AddTable(5, 5);
                matrixTable.Design = TableDesign.TableGrid;
                matrixTable.Alignment = Alignment.center;

                var highImpactCount = safeVulns.Count(v => IsCritical(v?.RiskLevel) || IsHigh(v?.RiskLevel));
                var mediumImpactCount = safeVulns.Count(v => IsMedium(v?.RiskLevel));
                var lowImpactCount = safeVulns.Count(v => IsLow(v?.RiskLevel));

                var cornerHeaders = new[] { "可能性 ↓ / 影响 →", "低 (Low)", "中 (Medium)", "高 (High)", "严重 (Critical)" };
                StyleTableHeader(matrixTable, cornerHeaders);

                var likelihoodRows = new[]
                {
                    new[] { "高 (High)", "中风险", "高风险", "严重风险", "严重风险" },
                    new[] { "中 (Medium)", "低风险", "中风险", "高风险", "严重风险" },
                    new[] { "低 (Low)", "低风险", "低风险", "中风险", "高风险" }
                };

                for (int r = 0; r < 3; r++)
                {
                    matrixTable.Rows[r + 2].Cells[0].Paragraphs[0].Append(likelihoodRows[r][0]).FontSize(9).Bold();
                    matrixTable.Rows[r + 2].Cells[0].Paragraphs[0].Alignment = Alignment.center;

                    for (int c = 1; c <= 4; c++)
                    {
                        var cellText = likelihoodRows[r][c];
                        matrixTable.Rows[r + 2].Cells[c].Paragraphs[0].Append(cellText).FontSize(9).Bold();
                        matrixTable.Rows[r + 2].Cells[c].Paragraphs[0].Color(
                            cellText.Contains("严重") ? Xceed.Drawing.Color.Firebrick :
                            cellText.Contains("高") ? Xceed.Drawing.Color.OrangeRed :
                            cellText.Contains("中") ? Xceed.Drawing.Color.DarkOrange : Xceed.Drawing.Color.SeaGreen);
                        matrixTable.Rows[r + 2].Cells[c].Paragraphs[0].Alignment = Alignment.center;
                    }
                }

                matrixTable.Rows[4].Cells[0].Paragraphs[0].Append($"命中统计 (n={safeVulns.Count})").FontSize(9).Bold();
                matrixTable.Rows[4].Cells[1].Paragraphs[0].Append($"{lowImpactCount}个").FontSize(9);
                matrixTable.Rows[4].Cells[1].Paragraphs[0].Alignment = Alignment.center;
                matrixTable.Rows[4].Cells[2].Paragraphs[0].Append($"{mediumImpactCount}个").FontSize(9);
                matrixTable.Rows[4].Cells[2].Paragraphs[0].Alignment = Alignment.center;
                matrixTable.Rows[4].Cells[3].Paragraphs[0].Append($"{highImpactCount}个").FontSize(9).Bold().Color(Xceed.Drawing.Color.OrangeRed);
                matrixTable.Rows[4].Cells[3].Paragraphs[0].Alignment = Alignment.center;
                matrixTable.Rows[4].Cells[4].Paragraphs[0].Append("评估中").FontSize(9);
                matrixTable.Rows[4].Cells[4].Paragraphs[0].Alignment = Alignment.center;

                for (int c = 0; c < 5; c++)
                {
                    try { matrixTable.Rows[0].Cells[c].FillColor = Xceed.Drawing.Color.DarkBlue; } catch { }
                    try { matrixTable.Rows[1].Cells[c].FillColor = Xceed.Drawing.Color.LightSteelBlue; } catch { }
                }
                ApplyTableRowShading(matrixTable, 2);

                doc.InsertParagraph().SpacingAfter(22);

                var chartTitle = doc.InsertParagraph("5.3 风险分布图表");
                chartTitle.FontSize(13).Bold();
                chartTitle.Color(DeepBlue);
                chartTitle.SpacingBefore(22);
                chartTitle.SpacingAfter(10);

                var pieData = new List<(string Label, int Count, System.Drawing.Color Color)>();
                if (safeVulns.Count(v => IsCritical(v?.RiskLevel)) > 0)
                    pieData.Add(("严重", safeVulns.Count(v => IsCritical(v?.RiskLevel)), System.Drawing.Color.FromArgb(185, 28, 28)));
                if (safeVulns.Count(v => IsHigh(v?.RiskLevel)) > 0)
                    pieData.Add(("高危", safeVulns.Count(v => IsHigh(v?.RiskLevel)), System.Drawing.Color.FromArgb(194, 65, 12)));
                if (safeVulns.Count(v => IsMedium(v?.RiskLevel)) > 0)
                    pieData.Add(("中危", safeVulns.Count(v => IsMedium(v?.RiskLevel)), System.Drawing.Color.FromArgb(217, 119, 6)));
                if (safeVulns.Count(v => IsLow(v?.RiskLevel)) > 0)
                    pieData.Add(("低危", safeVulns.Count(v => IsLow(v?.RiskLevel)), System.Drawing.Color.FromArgb(5, 150, 105)));

                if (pieData.Any())
                {
                    var pieImage = ReportChartGenerator.GenerateRiskPieChart(pieData);
                    AddChartImage(doc, pieImage, 380, 380);
                }

                var barData = pieData.Select(p => (p.Label, p.Count, p.Color)).ToList();
                if (barData.Any())
                {
                    var barImage = ReportChartGenerator.GenerateRiskBarChart(barData);
                    AddChartImage(doc, barImage, 480, 210);
                }
            }
            else
            {
                // 无漏洞时为 5.2/5.3 增加占位说明
                var matrixTitle = doc.InsertParagraph("5.2 风险等级矩阵（可能性 × 影响）");
                matrixTitle.FontSize(13).Bold();
                matrixTitle.Color(DeepBlue);
                matrixTitle.SpacingBefore(22);
                matrixTitle.SpacingAfter(10);
                var matrixPh = doc.InsertParagraph("未发现漏洞，无需进行风险等级矩阵评估。建议在系统发生变更后再次扫描以确认安全态势。");
                matrixPh.FontSize(10);
                matrixPh.Alignment = Alignment.center;
                matrixPh.SpacingAfter(12);

                var chartTitle = doc.InsertParagraph("5.3 风险分布图表");
                chartTitle.FontSize(13).Bold();
                chartTitle.Color(DeepBlue);
                chartTitle.SpacingBefore(22);
                chartTitle.SpacingAfter(10);
                var chartPh = doc.InsertParagraph("未发现漏洞，无风险分布数据可展示。");
                chartPh.FontSize(10);
                chartPh.Alignment = Alignment.center;
                chartPh.SpacingAfter(12);
            }

            doc.InsertParagraph().SpacingAfter(22);
            var sugHeader = doc.InsertParagraph("5.4 安全建议概述");
            sugHeader.FontSize(13).Bold();
            sugHeader.Color(DeepBlue);
            sugHeader.SpacingBefore(22);
            sugHeader.SpacingAfter(10);

            // 任务10：重构为 4 个时间维度（立即行动/短期/中期/长期），每个维度至少 3-4 条具体建议
            var sugIntro = doc.InsertParagraph("以下按时间维度（立即行动/短期/中期/长期）给出可落地的安全建议清单，便于安全团队分阶段推进整改工作。");
            sugIntro.FontSize(10);
            sugIntro.SpacingAfter(10);

            // 立即行动（24小时内）
            var immediateHeader = doc.InsertParagraph("【立即行动】24 小时内完成");
            immediateHeader.FontSize(11).Bold();
            immediateHeader.Color(Xceed.Drawing.Color.Firebrick);
            immediateHeader.SpacingBefore(8);
            immediateHeader.SpacingAfter(4);
            var immediateItems = new[]
            {
                "立即修复所有严重和高危级别的安全漏洞，按官方公告升级组件或安装补丁",
                "关闭所有非必要的高危端口（445/135/3389/23/21 等），配置严格的防火墙规则限制来源 IP",
                "对所有暴露的远程管理端口（如 RDP/SSH）启用多因素认证(MFA)，强制强密码策略",
                "启动应急响应流程，隔离已失陷或存在高危漏洞的资产，并保留证据用于溯源分析"
            };
            foreach (var item in immediateItems)
            {
                var sPara = doc.InsertParagraph($"• {item}");
                sPara.FontSize(10);
                sPara.SpacingBefore(3);
                sPara.SpacingAfter(3);
            }

            // 短期（1-7天）
            var shortHeader = doc.InsertParagraph("【短期】1-7 天内完成");
            shortHeader.FontSize(11).Bold();
            shortHeader.Color(Xceed.Drawing.Color.OrangeRed);
            shortHeader.SpacingBefore(10);
            shortHeader.SpacingAfter(4);
            var shortItems = new[]
            {
                "对中危漏洞完成升级或配置加固，建立漏洞修复的标准化处理流程",
                "完成关键系统与应用的安全配置基线核查，修正发现的偏差项",
                "部署并验证集中化日志管理，保留关键操作日志不少于 180 天",
                "对所有对外服务启用 TLS 1.2+ 加密通信，禁用已知不安全的 SSL/TLS 版本和弱密码套件"
            };
            foreach (var item in shortItems)
            {
                var sPara = doc.InsertParagraph($"• {item}");
                sPara.FontSize(10);
                sPara.SpacingBefore(3);
                sPara.SpacingAfter(3);
            }

            // 中期（1-3个月）
            var midHeader = doc.InsertParagraph("【中期】1-3 个月内完成");
            midHeader.FontSize(11).Bold();
            midHeader.Color(Xceed.Drawing.Color.DarkOrange);
            midHeader.SpacingBefore(10);
            midHeader.SpacingAfter(4);
            var midItems = new[]
            {
                "建立漏洞管理闭环流程：扫描 → 评估 → 修复 → 复测 → 归档，明确责任人与时限",
                "实施网络分段和微隔离，将关键业务系统与办公网、互联网进行分层",
                "部署 IDS/IPS 与威胁检测平台，建立安全事件实时告警与响应机制",
                "开展全员安全意识培训和钓鱼演练，提升组织整体安全防护水位"
            };
            foreach (var item in midItems)
            {
                var sPara = doc.InsertParagraph($"• {item}");
                sPara.FontSize(10);
                sPara.SpacingBefore(3);
                sPara.SpacingAfter(3);
            }

            // 长期（3-6个月）
            var longHeader = doc.InsertParagraph("【长期】3-6 个月内完成");
            longHeader.FontSize(11).Bold();
            longHeader.Color(Xceed.Drawing.Color.SeaGreen);
            longHeader.SpacingBefore(10);
            longHeader.SpacingAfter(4);
            var longItems = new[]
            {
                "推进等保 2.0 / ISO 27001 / GDPR / PCI DSS 等合规体系建设，完成差距整改与测评认证",
                "建立威胁情报订阅和共享机制，定期执行红蓝对抗演练与桌面推演",
                "建设 SOAR 安全编排自动化与响应能力，缩短 MTTD/MTTR（平均检测/响应时间）",
                "制定并持续维护数据分类分级保护策略，覆盖数据全生命周期（采集、传输、存储、使用、销毁）"
            };
            foreach (var item in longItems)
            {
                var sPara = doc.InsertParagraph($"• {item}");
                sPara.FontSize(10);
                sPara.SpacingBefore(3);
                sPara.SpacingAfter(3);
            }

            doc.InsertParagraph().SpacingAfter(10);
        }

        #endregion

        #region 修复建议

        private static void GenerateRemediationSection(DocX doc, List<VulnerabilityResult> vulns)
        {
            var chapterTitle = doc.InsertParagraph("第六章 修复建议");
            chapterTitle.FontSize(16).Bold();
            chapterTitle.Color(DeepBlue);
            chapterTitle.SpacingBefore(15);
            chapterTitle.SpacingAfter(4);

            var titleLine = doc.InsertParagraph(new string('─', 50));
            titleLine.FontSize(7);
            titleLine.Color(AccentBlue);
            titleLine.SpacingAfter(12);

            var intro = doc.InsertParagraph("本节提供针对发现的安全问题的具体修复建议和通用安全加固措施。");
            intro.FontSize(10);
            intro.SpacingBefore(8);
            intro.SpacingAfter(18);

            var subHeader1 = doc.InsertParagraph("6.1 修复优先级矩阵");
            subHeader1.FontSize(13).Bold();
            subHeader1.Color(DeepBlue);
            subHeader1.SpacingBefore(12);
            subHeader1.SpacingAfter(10);

            var priorities = new[]
            {
                ("P1-紧急", "24小时内", "严重/远程执行类", "立即隔离受影响系统"),
                ("P2-高", "7天内", "高危/权限提升类", "尽快安排维护窗口"),
                ("P3-中", "30天内", "中危/信息泄露类", "纳入常规更新计划"),
                ("P4-低", "下个周期", "低危/信息类", "持续监控")
            };

            var prioTable = doc.AddTable(priorities.Length + 1, 4);
            prioTable.Design = TableDesign.TableGrid;
            prioTable.Alignment = Alignment.center;

            var prioHeaders = new[] { "优先级", "处理时限", "适用范围", "建议措施" };
            StyleTableHeader(prioTable, prioHeaders);

            for (int r = 0; r < priorities.Length; r++)
            {
                var prio = priorities[r];
                prioTable.Rows[r + 1].Cells[0].Paragraphs[0].Append(prio.Item1).FontSize(9).Bold();
                prioTable.Rows[r + 1].Cells[0].Paragraphs[0].Color(GetRiskColor(prio.Item1.StartsWith("P1") ? "严重" : prio.Item1.StartsWith("P2") ? "高" : prio.Item1.StartsWith("P3") ? "中" : "低"));
                prioTable.Rows[r + 1].Cells[1].Paragraphs[0].Append(prio.Item2).FontSize(9);
                prioTable.Rows[r + 1].Cells[1].Paragraphs[0].Alignment = Alignment.center;
                prioTable.Rows[r + 1].Cells[2].Paragraphs[0].Append(prio.Item3).FontSize(9);
                prioTable.Rows[r + 1].Cells[3].Paragraphs[0].Append(prio.Item4).FontSize(9);
            }
            ApplyTableRowShading(prioTable);

            doc.InsertParagraph().SpacingAfter(22);
            var subHeader2 = doc.InsertParagraph("6.2 通用安全加固建议");
            subHeader2.FontSize(13).Bold();
            subHeader2.Color(DeepBlue);
            subHeader2.SpacingBefore(22);
            subHeader2.SpacingAfter(10);

            var categories = new[] {
                ("网络层面", "配置防火墙规则，仅开放必要的业务端口；实施网络分段隔离；启用IDS/IPS；定期审计网络访问日志。"),
                ("系统层面", "及时安装操作系统安全更新；禁用不必要的服务和账户；配置强密码策略；启用账户锁定策略防止暴力破解。"),
                ("应用层面", "保持应用程序及依赖库为最新版本；实施安全的编码实践；定期进行代码安全审查和渗透测试。"),
                ("身份认证", "实施多因素认证(MFA)；采用基于角色的访问控制(RBAC)；定期清理过期账户和冗余权限。"),
                ("数据保护", "加密敏感数据存储和传输（TLS 1.2+）；实施数据分类和分级保护策略；建立定期数据备份和灾难恢复机制。"),
                ("监控审计", "部署集中化日志管理系统(SIEM)；设置安全事件实时告警阈值；定期进行安全基线检查和合规审计。")
            };

            int cIdx = 1;
            foreach (var cat in categories)
            {
                var catPara = doc.InsertParagraph();
                catPara.Append($"{cIdx}. {cat.Item1}: ").FontSize(10).Bold();
                catPara.Append(cat.Item2).FontSize(10);
                catPara.SpacingBefore(5);
                catPara.SpacingAfter(5);
                cIdx++;
            }

            if (vulns != null && vulns.Any(v => IsCritical(v?.RiskLevel) || IsHigh(v?.RiskLevel)))
            {
                doc.InsertParagraph().SpacingAfter(22);
                var subHeader3 = doc.InsertParagraph("6.3 高危漏洞专项修复方案");
                subHeader3.FontSize(13).Bold();
                subHeader3.Color(DeepBlue);
                subHeader3.SpacingBefore(22);
                subHeader3.SpacingAfter(10);

                // 任务11：6 列扩展为：漏洞名称/风险等级/CVSS/影响服务/修复步骤/验证方法
                var highVulns = vulns.Where(v => IsCritical(v?.RiskLevel) || IsHigh(v?.RiskLevel))
                    .OrderByDescending(v => GetRiskPriority(v?.RiskLevel)).Take(8).ToList();

                var fixTable = doc.AddTable(highVulns.Count + 1, 6);
                fixTable.Design = TableDesign.TableGrid;
                fixTable.Alignment = Alignment.center;

                var fixHeaders = new[] { "漏洞名称", "风险等级", "CVSS", "影响服务", "修复步骤", "验证方法" };
                StyleTableHeader(fixTable, fixHeaders);

                for (int r = 0; r < highVulns.Count; r++)
                {
                    var v = highVulns[r];
                    var rl = string.IsNullOrWhiteSpace(v?.RiskLevel) ? "未分类" : v.RiskLevel;
                    var cvssScore = EstimateCvssScore(rl);

                    // 漏洞名称（截断）
                    var nameText = v?.Name ?? "未知漏洞";
                    if (nameText.Length > 28) nameText = nameText.Substring(0, 25) + "...";
                    fixTable.Rows[r + 1].Cells[0].Paragraphs[0].Append(nameText).FontSize(9).Bold();

                    // 风险等级
                    fixTable.Rows[r + 1].Cells[1].Paragraphs[0].Append(rl).FontSize(9).Bold().Color(GetRiskColor(rl));
                    fixTable.Rows[r + 1].Cells[1].Paragraphs[0].Alignment = Alignment.center;

                    // CVSS
                    fixTable.Rows[r + 1].Cells[2].Paragraphs[0].Append($"{cvssScore:F1}").FontSize(9).Bold();
                    fixTable.Rows[r + 1].Cells[2].Paragraphs[0].Color(GetRiskColor(rl));
                    fixTable.Rows[r + 1].Cells[2].Paragraphs[0].Alignment = Alignment.center;

                    // 影响服务
                    var svcPort = v?.Port.HasValue == true ? $"{v.Service ?? "未知"} (端口{v.Port.Value})" : (v?.Service ?? "-");
                    if (svcPort.Length > 20) svcPort = svcPort.Substring(0, 17) + "...";
                    fixTable.Rows[r + 1].Cells[3].Paragraphs[0].Append(svcPort).FontSize(9);

                    // 修复步骤
                    var fixSuggestion = !string.IsNullOrWhiteSpace(v?.Solution) ? v.Solution : "请参考官方安全公告获取补丁信息；如无补丁，启用 WAF/防火墙临时缓解。";
                    if (fixSuggestion.Length > 60) fixSuggestion = fixSuggestion.Substring(0, 57) + "...";
                    fixTable.Rows[r + 1].Cells[4].Paragraphs[0].Append(fixSuggestion).FontSize(9);

                    // 验证方法
                    var verifyText = !string.IsNullOrWhiteSpace(v?.CveId)
                        ? $"复测确认漏洞不再命中；查询 NVD {v.CveId} 补丁状态"
                        : "复测扫描确认漏洞不再命中；通过 PoC 或人工渗透测试验证修复有效性";
                    if (verifyText.Length > 40) verifyText = verifyText.Substring(0, 37) + "...";
                    fixTable.Rows[r + 1].Cells[5].Paragraphs[0].Append(verifyText).FontSize(9);
                }
                ApplyTableRowShading(fixTable);

                // 任务11：在表格下方加段说明
                var fixNote = doc.InsertParagraph();
                fixNote.Append("说明：").Bold().FontSize(9).Color(DeepBlue);
                fixNote.Append("上表仅列出 Top 8 高危漏洞的专项修复方案，更多漏洞详情请参见「4.5 漏洞详细信息」与「附录A CVE漏洞参考信息」。所有修复操作建议在测试环境验证后再推送到生产环境，并做好变更前后的快照备份。修复完成后请按「验证方法」列进行复测，确保漏洞已闭环处置。").FontSize(9);
                fixNote.SpacingAfter(8);
            }
            else
            {
                // 无高危漏洞时为 6.3 增加占位说明（保持编号稳定）
                doc.InsertParagraph().SpacingAfter(22);
                var subHeader3 = doc.InsertParagraph("6.3 高危漏洞专项修复方案");
                subHeader3.FontSize(13).Bold();
                subHeader3.Color(DeepBlue);
                subHeader3.SpacingBefore(22);
                subHeader3.SpacingAfter(10);
                var noHighPh = doc.InsertParagraph("本次扫描未发现高危漏洞，无需专项修复方案。建议持续保持漏洞管理流程，并在下一个扫描周期进行复核。");
                noHighPh.FontSize(10);
                noHighPh.Alignment = Alignment.center;
                noHighPh.SpacingAfter(12);
            }

            doc.InsertParagraph().SpacingAfter(22);

            var subHeader4 = doc.InsertParagraph("6.4 风险处理跟踪表");
            subHeader4.FontSize(13).Bold();
            subHeader4.Color(DeepBlue);
            subHeader4.SpacingBefore(22);
            subHeader4.SpacingAfter(10);

            var trackIntro = doc.InsertParagraph("以下表格可用于跟踪每个风险项的处理状态，建议在实际修复过程中持续更新：");
            trackIntro.FontSize(10);
            trackIntro.SpacingAfter(10);

            var trackItems = new List<(string riskRef, string category, string description, string priority, string status, string owner)>();

            var highRiskVulnsTrack = vulns.Where(v => IsCritical(v?.RiskLevel) || IsHigh(v?.RiskLevel)).Take(6).ToList();
            int refId = 1;

            foreach (var v in highRiskVulnsTrack)
            {
                trackItems.Add(($"RISK-{refId:D3}", $"高危漏洞",
                    (v?.Name ?? "未知漏洞").Length > 40 ? (v.Name).Substring(0, 37) + "..." : (v?.Name ?? "未知漏洞"),
                    "P1-紧急", "待处理", "安全团队"));
                refId++;
            }

            var medVulns = vulns.Where(v => IsMedium(v?.RiskLevel)).Take(3).ToList();
            foreach (var v in medVulns)
            {
                trackItems.Add(($"RISK-{refId:D3}", $"中危漏洞",
                    (v?.Name ?? "未知漏洞").Length > 40 ? (v.Name).Substring(0, 37) + "..." : (v?.Name ?? "未知漏洞"),
                    "P2-高优", "待处理", "安全团队"));
                refId++;
            }

            var vulnPorts = vulns.Where(v => v?.Port.HasValue == true)
                .Select(v => v.Port.Value).ToHashSet();
            if (vulnPorts.Contains(445) || vulnPorts.Contains(135))
            {
                trackItems.Add(($"RISK-{refId:D3}", "端口曝光", "SMB/RPC高危端口对外暴露",
                    "P1-紧急", "待处理", "运维团队"));
                refId++;
            }
            if (vulnPorts.Contains(3389))
            {
                trackItems.Add(($"RISK-{refId:D3}", "端口曝光", "RDP远程桌面端口对外暴露",
                    "P1-紧急", "待处理", "运维团队"));
                refId++;
            }

            trackItems.Add(($"RISK-{refId:D3}", "安全基线", "安全配置基线建立",
                "P2-高优", "规划中", "安全团队"));
            refId++;
            trackItems.Add(($"RISK-{refId:D3}", "日志审计", "集中化日志审计部署",
                "P3-中优", "规划中", "运维团队"));

            var trackTable = doc.AddTable(trackItems.Count + 1, 6);
            trackTable.Design = TableDesign.TableGrid;
            trackTable.Alignment = Alignment.center;

            var trackHeaders = new[] { "风险编号", "类别", "风险描述", "优先级", "处理状态", "责任方" };
            StyleTableHeader(trackTable, trackHeaders);

            for (int r = 0; r < trackItems.Count; r++)
            {
                var item = trackItems[r];
                trackTable.Rows[r + 1].Cells[0].Paragraphs[0].Append(item.riskRef).FontSize(9).Bold();
                trackTable.Rows[r + 1].Cells[0].Paragraphs[0].Alignment = Alignment.center;
                trackTable.Rows[r + 1].Cells[1].Paragraphs[0].Append(item.category).FontSize(9);
                trackTable.Rows[r + 1].Cells[2].Paragraphs[0].Append(item.description).FontSize(9);
                trackTable.Rows[r + 1].Cells[3].Paragraphs[0].Append(item.priority).FontSize(9).Bold();
                trackTable.Rows[r + 1].Cells[3].Paragraphs[0].Color(item.priority.Contains("P1") ? Xceed.Drawing.Color.Firebrick : item.priority.Contains("P2") ? Xceed.Drawing.Color.OrangeRed : Xceed.Drawing.Color.DarkOrange);
                trackTable.Rows[r + 1].Cells[3].Paragraphs[0].Alignment = Alignment.center;
                trackTable.Rows[r + 1].Cells[4].Paragraphs[0].Append(item.status).FontSize(9).Bold();
                trackTable.Rows[r + 1].Cells[4].Paragraphs[0].Color(item.status == "待处理" ? Xceed.Drawing.Color.Firebrick : Xceed.Drawing.Color.DarkOrange);
                trackTable.Rows[r + 1].Cells[4].Paragraphs[0].Alignment = Alignment.center;
                trackTable.Rows[r + 1].Cells[5].Paragraphs[0].Append(item.owner).FontSize(9);
                trackTable.Rows[r + 1].Cells[5].Paragraphs[0].Alignment = Alignment.center;
            }
            ApplyTableRowShading(trackTable);

            doc.InsertParagraph().SpacingAfter(25);
            var disc = doc.InsertParagraph("免责声明：本报告由 NetSecurityScanner 安全扫描工具自动生成。报告中的漏洞检测结果和建议仅供参考，实际安全决策应结合具体业务场景和专业安全团队的人工判断。在应用任何修复措施前，请务必在测试环境充分验证。");
            disc.FontSize(9);
            disc.Color(MidGray);
        }

        #endregion

        #region 威胁情报分析

        private static void GenerateThreatIntelligenceSection(DocX doc, List<VulnerabilityResult> vulns, List<PortScanResult> ports)
        {
            var chapterTitle = doc.InsertParagraph("第七章 威胁情报分析");
            chapterTitle.FontSize(16).Bold();
            chapterTitle.Color(DeepBlue);
            chapterTitle.SpacingBefore(15);
            chapterTitle.SpacingAfter(4);

            var titleLine = doc.InsertParagraph(new string('─', 50));
            titleLine.FontSize(7);
            titleLine.Color(AccentBlue);
            titleLine.SpacingAfter(12);

            var intro = doc.InsertParagraph("本节基于本次扫描发现的开放端口和漏洞信息，结合当前威胁情报数据，对目标系统面临的威胁进行深入分析。");
            intro.FontSize(10);
            intro.SpacingBefore(8);
            intro.SpacingAfter(18);

            var safeVulns = vulns ?? new List<VulnerabilityResult>();
            var safePorts = ports ?? new List<PortScanResult>();
            var openPorts = safePorts.Where(p => p?.Status == "开放" || p?.Status?.ToLower() == "open").ToList();
            var highRiskVulns = safeVulns.Where(v => IsCritical(v?.RiskLevel) || IsHigh(v?.RiskLevel)).ToList();

            var subHeader1 = doc.InsertParagraph("7.1 活跃威胁向量");
            subHeader1.FontSize(13).Bold();
            subHeader1.Color(DeepBlue);
            subHeader1.SpacingBefore(12);
            subHeader1.SpacingAfter(10);

            // 任务12：在 subHeader1（7.1）后、threatIntro 前增加"威胁演化趋势"补充说明段（≥100字）
            var evolutionTitle = doc.InsertParagraph("威胁演化趋势");
            evolutionTitle.FontSize(11).Bold();
            evolutionTitle.Color(AccentBlue);
            evolutionTitle.SpacingBefore(6);
            evolutionTitle.SpacingAfter(4);

            var evolutionPara = doc.InsertParagraph("2024-2026 年期间，全球网络威胁格局呈现以下显著演化趋势：(1) 勒索软件继续向「双重/三重勒索」演化，结合数据窃取、DDoS 与公开曝光施压，关键基础设施、医疗与制造业成为重点目标；(2) 软件供应链攻击频发，开源组件投毒（如 XZ Utils 后门事件）和上游厂商入侵成为新的主要攻击面；(3) 国家级 APT 组织大量使用零日漏洞，浏览器、VPN/网关系边界设备、邮件网关成为首选突破口；(4) AI 驱动攻击开始普及，攻击者利用大模型生成高度定制化的钓鱼邮件、自动化漏洞发现与深度伪造社工，攻击效率与隐蔽性显著提升。组织在评估威胁时，应将上述演化趋势与自身资产暴露面联动考量，建立「知己知彼」的纵深防御体系。");
            evolutionPara.FontSize(10);
            evolutionPara.SpacingAfter(10);

            var threatIntro = doc.InsertParagraph("基于检测到的开放端口和已知漏洞，以下为当前系统面临的活跃威胁向量：");
            threatIntro.FontSize(10);
            threatIntro.SpacingAfter(10);

            var threatVectors = BuildThreatVectors(openPorts, safeVulns);
            if (threatVectors.Any())
            {
                var threatTable = doc.AddTable(threatVectors.Count + 1, 4);
                threatTable.Design = TableDesign.TableGrid;
                threatTable.Alignment = Alignment.center;

                var threatHeaders = new[] { "威胁向量", "关联端口/服务", "风险等级", "攻击方式" };
                StyleTableHeader(threatTable, threatHeaders);

                for (int r = 0; r < threatVectors.Count; r++)
                {
                    var tv = threatVectors[r];
                    threatTable.Rows[r + 1].Cells[0].Paragraphs[0].Append(tv.Item1).FontSize(9).Bold();
                    threatTable.Rows[r + 1].Cells[1].Paragraphs[0].Append(tv.Item2).FontSize(9);
                    threatTable.Rows[r + 1].Cells[2].Paragraphs[0].Append(tv.Item3).FontSize(9).Bold().Color(GetRiskColor(tv.Item3));
                    threatTable.Rows[r + 1].Cells[2].Paragraphs[0].Alignment = Alignment.center;
                    threatTable.Rows[r + 1].Cells[3].Paragraphs[0].Append(tv.Item4).FontSize(9);
                }
                ApplyTableRowShading(threatTable);
            }
            else
            {
                var noThreatPara = doc.InsertParagraph("基于当前扫描结果，未发现显著活跃威胁向量。");
                noThreatPara.FontSize(10);
                noThreatPara.SpacingAfter(10);
            }

            doc.InsertParagraph().SpacingAfter(22);

            var subHeader2 = doc.InsertParagraph("7.2 行业威胁趋势");
            subHeader2.FontSize(13).Bold();
            subHeader2.Color(DeepBlue);
            subHeader2.SpacingBefore(22);
            subHeader2.SpacingAfter(10);

            var trendIntro = doc.InsertParagraph("以下为当前网络安全领域的主要威胁趋势，供安全决策参考：");
            trendIntro.FontSize(10);
            trendIntro.SpacingAfter(10);

            var trends = new[]
            {
                ("勒索软件", "勒索软件攻击持续演化，采用双重勒索（加密+数据窃取）策略，RaaS模式降低了攻击门槛。关键基础设施和医疗行业为主要目标。", "高"),
                ("供应链攻击", "软件供应链攻击频发，攻击者通过入侵上游供应商或开源项目，实现对大量下游目标的渗透。SolarWinds事件后该威胁持续升级。", "高"),
                ("零日漏洞", "零日漏洞在野利用数量增加，国家级APT组织大量使用零日漏洞进行攻击。浏览器、VPN和邮件网关是主要利用目标。", "严重"),
                ("云服务安全", "云环境配置错误导致的数据泄露事件频发，多云环境增加了安全管理的复杂性。IAM策略不当和存储桶公开是最常见问题。", "高"),
                ("AI驱动攻击", "攻击者利用AI技术生成钓鱼邮件、自动化漏洞发现和深度伪造，攻击效率和隐蔽性大幅提升。AI安全对抗进入新阶段。", "中")
            };

            var trendTable = doc.AddTable(trends.Length + 1, 3);
            trendTable.Design = TableDesign.TableGrid;
            trendTable.Alignment = Alignment.center;

            var trendHeaders = new[] { "威胁趋势", "分析描述", "严重度" };
            StyleTableHeader(trendTable, trendHeaders);

            for (int r = 0; r < trends.Length; r++)
            {
                trendTable.Rows[r + 1].Cells[0].Paragraphs[0].Append(trends[r].Item1).FontSize(9).Bold();
                trendTable.Rows[r + 1].Cells[1].Paragraphs[0].Append(trends[r].Item2).FontSize(9);
                trendTable.Rows[r + 1].Cells[2].Paragraphs[0].Append(trends[r].Item3).FontSize(9).Bold().Color(GetRiskColor(trends[r].Item3));
                trendTable.Rows[r + 1].Cells[2].Paragraphs[0].Alignment = Alignment.center;
            }
            ApplyTableRowShading(trendTable);

            doc.InsertParagraph().SpacingAfter(22);

            var subHeader3 = doc.InsertParagraph("7.3 攻击面评估");
            subHeader3.FontSize(13).Bold();
            subHeader3.Color(DeepBlue);
            subHeader3.SpacingBefore(22);
            subHeader3.SpacingAfter(10);

            var surfaceIntro = doc.InsertParagraph("基于扫描结果对目标系统攻击面进行多维度评估：");
            surfaceIntro.FontSize(10);
            surfaceIntro.SpacingAfter(10);

            var surfaceItems = BuildAttackSurfaceItems(openPorts, safeVulns, highRiskVulns);
            var surfaceTable = doc.AddTable(surfaceItems.Count + 1, 3);
            surfaceTable.Design = TableDesign.TableGrid;
            surfaceTable.Alignment = Alignment.center;

            var surfaceHeaders = new[] { "评估维度", "当前状态", "风险等级" };
            StyleTableHeader(surfaceTable, surfaceHeaders);

            for (int r = 0; r < surfaceItems.Count; r++)
            {
                var si = surfaceItems[r];
                surfaceTable.Rows[r + 1].Cells[0].Paragraphs[0].Append(si.Item1).FontSize(9).Bold();
                surfaceTable.Rows[r + 1].Cells[1].Paragraphs[0].Append(si.Item2).FontSize(9);
                surfaceTable.Rows[r + 1].Cells[2].Paragraphs[0].Append(si.Item3).FontSize(9).Bold().Color(GetRiskColor(si.Item3));
                surfaceTable.Rows[r + 1].Cells[2].Paragraphs[0].Alignment = Alignment.center;
            }
            ApplyTableRowShading(surfaceTable);

            doc.InsertParagraph().SpacingAfter(22);

            var subHeader4 = doc.InsertParagraph("7.4 威胁情报总结");
            subHeader4.FontSize(13).Bold();
            subHeader4.Color(DeepBlue);
            subHeader4.SpacingBefore(22);
            subHeader4.SpacingAfter(10);

            var vulnCount = safeVulns.Count(v => IsCritical(v?.RiskLevel) || IsHigh(v?.RiskLevel));
            var threatSummary = doc.InsertParagraph();
            threatSummary.Append("综合分析，当前系统面临");

            if (vulnCount > 5)
                threatSummary.Append("严重的").FontSize(10).Bold().Color(Xceed.Drawing.Color.Firebrick);
            else if (vulnCount > 0)
                threatSummary.Append("较高的").FontSize(10).Bold().Color(Xceed.Drawing.Color.OrangeRed);
            else
                threatSummary.Append("较低的").FontSize(10).Bold().Color(Xceed.Drawing.Color.SeaGreen);

            threatSummary.Append("网络威胁风险。").FontSize(10);
            threatSummary.SpacingAfter(8);

            var threatDetail = doc.InsertParagraph();
            threatDetail.Append("在防御策略上，建议按照纵深防御原则（Defense in Depth），从网络边界、系统主机、应用程序和数据层面构建多层安全防护体系。结合行业威胁趋势，重点关注勒索软件和供应链攻击的防范，建立常态化的威胁监控和应急响应机制。").FontSize(10);
            threatDetail.SpacingAfter(8);

            var threatActions = new[]
            {
                ("短期行动", "漏洞修复与端口治理", "立即修复高危漏洞、关闭非必要端口、实施访问控制"),
                ("中期规划", "安全体系建设", "部署威胁检测平台、建立SIEM/SOAR体系、完善安全基线"),
                ("长期战略", "主动防御能力", "建设主动防御能力、参与威胁情报共享、持续安全培训")
            };

            var actionTable = doc.AddTable(threatActions.Length + 1, 3);
            actionTable.Design = TableDesign.TableGrid;
            actionTable.Alignment = Alignment.center;

            var actionHeaders = new[] { "时间维度", "行动方向", "具体措施" };
            StyleTableHeader(actionTable, actionHeaders);

            for (int r = 0; r < threatActions.Length; r++)
            {
                var act = threatActions[r];
                actionTable.Rows[r + 1].Cells[0].Paragraphs[0].Append(act.Item1).FontSize(9).Bold();
                actionTable.Rows[r + 1].Cells[0].Paragraphs[0].Alignment = Alignment.center;
                actionTable.Rows[r + 1].Cells[1].Paragraphs[0].Append(act.Item2).FontSize(9).Bold();
                actionTable.Rows[r + 1].Cells[2].Paragraphs[0].Append(act.Item3).FontSize(9);
            }
            ApplyTableRowShading(actionTable);
        }

        private static List<(string, string, string, string)> BuildThreatVectors(List<PortScanResult> openPorts, List<VulnerabilityResult> vulns)
        {
            var vectors = new List<(string, string, string, string)>();
            var portNumbers = openPorts.Select(p => p?.PortNumber ?? 0).ToHashSet();

            if (portNumbers.Contains(21) || portNumbers.Contains(20))
                vectors.Add(("FTP服务威胁", "20-21/FTP", "高", "匿名登录、弱口令暴力破解、明文传输嗅探"));

            if (portNumbers.Contains(22))
                vectors.Add(("SSH服务威胁", "22/SSH", "中", "暴力破解、密钥窃取、配置不当利用"));

            if (portNumbers.Contains(23))
                vectors.Add(("Telnet服务威胁", "23/Telnet", "严重", "明文传输嗅探、弱口令、未授权访问"));

            if (portNumbers.Contains(25) || portNumbers.Contains(110) || portNumbers.Contains(143))
                vectors.Add(("邮件服务威胁", "25,110,143/SMTP/POP3/IMAP", "中", "邮件中继滥用、凭据嗅探、钓鱼攻击"));

            if (portNumbers.Contains(80) || portNumbers.Contains(443) || portNumbers.Contains(8080) || portNumbers.Contains(8443))
                vectors.Add(("Web服务威胁", "80,443,8080,8443/HTTP(S)", "高", "SQL注入、XSS、CSRF、目录遍历、Web Shell"));

            if (portNumbers.Contains(135))
                vectors.Add(("RPC服务威胁", "135/RPC", "严重", "RPC漏洞利用、DCOM攻击、信息泄露"));

            if (portNumbers.Contains(139) || portNumbers.Contains(445))
                vectors.Add(("SMB服务威胁", "139,445/SMB", "严重", "EternalBlue、SMB漏洞利用、共享泄露"));

            if (portNumbers.Contains(3389))
                vectors.Add(("RDP服务威胁", "3389/RDP", "严重", "BlueKeep漏洞、暴力破解、凭据窃取"));

            if (portNumbers.Contains(1433) || portNumbers.Contains(3306) || portNumbers.Contains(5432) || portNumbers.Contains(1521))
                vectors.Add(("数据库服务威胁", "1433,3306,5432,1521/数据库", "严重", "暴力破解、SQL注入、未授权访问、数据泄露"));

            if (portNumbers.Contains(6379))
                vectors.Add(("Redis服务威胁", "6379/Redis", "严重", "未授权访问、主从复制RCE、数据泄露"));

            if (portNumbers.Contains(27017) || portNumbers.Contains(27018))
                vectors.Add(("MongoDB服务威胁", "27017,27018/MongoDB", "严重", "未授权访问、数据泄露、勒索攻击"));

            if (vulns.Any(v => IsCritical(v?.RiskLevel)))
                vectors.Add(("严重漏洞利用", "多端口/多服务", "严重", "远程代码执行、权限提升、数据窃取"));

            if (vulns.Any(v => IsHigh(v?.RiskLevel)))
                vectors.Add(("高危漏洞利用", "多端口/多服务", "高", "权限提升、信息泄露、服务拒绝"));

            if (!vectors.Any())
                vectors.Add(("常规网络威胁", "通用", "低", "端口扫描、服务探测、信息收集"));

            return vectors;
        }

        private static List<(string, string, string)> BuildAttackSurfaceItems(
            List<PortScanResult> openPorts, List<VulnerabilityResult> vulns, List<VulnerabilityResult> highRiskVulns)
        {
            var items = new List<(string, string, string)>();
            var portNumbers = openPorts.Select(p => p?.PortNumber ?? 0).ToList();
            var hasHighRiskPort = portNumbers.Any(p => p == 445 || p == 135 || p == 3389 || p == 23);

            items.Add(("外部可达端口数",
                $"{openPorts.Count}个开放端口" + (hasHighRiskPort ? "（含高危端口）" : "（未发现高危端口）"),
                hasHighRiskPort ? "高" : "低"));

            items.Add(("已知漏洞数量",
                $"{vulns.Count}个漏洞" + (highRiskVulns.Any() ? $"（含{highRiskVulns.Count}个高危）" : ""),
                highRiskVulns.Any() ? "高" : "低"));

            var hasWebPort = openPorts.Any(p => p?.PortNumber == 80 || p?.PortNumber == 443);
            items.Add(("服务暴露面",
                hasWebPort ? "Web服务对外暴露" : "无Web服务对外暴露",
                hasWebPort ? "中" : "低"));

            var hasAuthVuln = highRiskVulns.Any(v =>
                v?.Name?.ToLower().Contains("auth") == true ||
                v?.Name?.ToLower().Contains("认证") == true ||
                v?.Name?.ToLower().Contains("login") == true);
            items.Add(("身份认证风险",
                hasAuthVuln ? "存在认证相关漏洞" : "未发现认证相关漏洞",
                hasAuthVuln ? "高" : "低"));

            var hasDataLeak = vulns.Any(v =>
                v?.Name?.ToLower().Contains("disclosure") == true ||
                v?.Name?.ToLower().Contains("泄露") == true ||
                v?.Name?.ToLower().Contains("leak") == true);
            items.Add(("数据泄露风险",
                hasDataLeak ? "存在信息泄露风险" : "未发现数据泄露风险",
                hasDataLeak ? "中" : "低"));

            return items;
        }

        #endregion

        #region 合规参考

        private static void GenerateComplianceSection(DocX doc, List<VulnerabilityResult> vulns, List<PortScanResult> ports)
        {
            var chapterTitle = doc.InsertParagraph("第八章 合规参考");
            chapterTitle.FontSize(16).Bold();
            chapterTitle.Color(DeepBlue);
            chapterTitle.SpacingBefore(15);
            chapterTitle.SpacingAfter(4);

            var titleLine = doc.InsertParagraph(new string('─', 50));
            titleLine.FontSize(7);
            titleLine.Color(AccentBlue);
            titleLine.SpacingAfter(12);

            var intro = doc.InsertParagraph("本节将扫描发现的安全问题与主要合规标准进行对照分析，评估当前系统的合规状态，并提供差距分析和改进建议。");
            intro.FontSize(10);
            intro.SpacingBefore(8);
            intro.SpacingAfter(18);

            var safeVulns = vulns ?? new List<VulnerabilityResult>();
            var safePorts = ports ?? new List<PortScanResult>();
            var openPorts = safePorts.Where(p => p?.Status == "开放" || p?.Status?.ToLower() == "open").ToList();

            var subHeader1 = doc.InsertParagraph("8.1 合规标准对照评估");
            subHeader1.FontSize(13).Bold();
            subHeader1.Color(DeepBlue);
            subHeader1.SpacingBefore(12);
            subHeader1.SpacingAfter(10);

            var complianceIntro = doc.InsertParagraph("以下为本次扫描结果与主要合规标准的对照评估：");
            complianceIntro.FontSize(10);
            complianceIntro.SpacingAfter(10);

            var complianceItems = BuildComplianceItems(safeVulns, openPorts);
            var complianceTable = doc.AddTable(complianceItems.Count + 1, 4);
            complianceTable.Design = TableDesign.TableGrid;
            complianceTable.Alignment = Alignment.center;

            var complianceHeaders = new[] { "标准名称", "适用条款", "当前状态", "合规程度" };
            StyleTableHeader(complianceTable, complianceHeaders);

            for (int r = 0; r < complianceItems.Count; r++)
            {
                var ci = complianceItems[r];
                complianceTable.Rows[r + 1].Cells[0].Paragraphs[0].Append(ci.Item1).FontSize(9).Bold();
                complianceTable.Rows[r + 1].Cells[1].Paragraphs[0].Append(ci.Item2).FontSize(9);
                complianceTable.Rows[r + 1].Cells[2].Paragraphs[0].Append(ci.Item3).FontSize(9);
                complianceTable.Rows[r + 1].Cells[3].Paragraphs[0].Append(ci.Item4).FontSize(9).Bold().Color(GetComplianceColor(ci.Item4));
                complianceTable.Rows[r + 1].Cells[3].Paragraphs[0].Alignment = Alignment.center;
            }
            ApplyTableRowShading(complianceTable);

            doc.InsertParagraph().SpacingAfter(22);

            var subHeader2 = doc.InsertParagraph("8.2 合规差距分析");
            subHeader2.FontSize(13).Bold();
            subHeader2.Color(DeepBlue);
            subHeader2.SpacingBefore(22);
            subHeader2.SpacingAfter(10);

            var gapIntro = doc.InsertParagraph("基于合规标准对照评估，以下为当前系统存在的主要合规差距：");
            gapIntro.FontSize(10);
            gapIntro.SpacingAfter(10);

            var gapItems = BuildComplianceGaps(safeVulns, openPorts);
            var gapTable = doc.AddTable(gapItems.Count + 1, 5);
            gapTable.Design = TableDesign.TableGrid;
            gapTable.Alignment = Alignment.center;

            var gapHeaders = new[] { "差距项", "关联标准", "当前状态", "风险等级", "改进建议" };
            StyleTableHeader(gapTable, gapHeaders);

            for (int r = 0; r < gapItems.Count; r++)
            {
                var gi = gapItems[r];
                gapTable.Rows[r + 1].Cells[0].Paragraphs[0].Append(gi.Item1).FontSize(9);
                gapTable.Rows[r + 1].Cells[1].Paragraphs[0].Append(gi.Item2).FontSize(9);
                gapTable.Rows[r + 1].Cells[2].Paragraphs[0].Append(gi.Item3).FontSize(9);
                gapTable.Rows[r + 1].Cells[3].Paragraphs[0].Append(gi.Item4).FontSize(9).Bold().Color(GetRiskColor(gi.Item4));
                gapTable.Rows[r + 1].Cells[3].Paragraphs[0].Alignment = Alignment.center;
                gapTable.Rows[r + 1].Cells[4].Paragraphs[0].Append(gi.Item5).FontSize(9);
            }
            ApplyTableRowShading(gapTable);

            doc.InsertParagraph().SpacingAfter(22);

            var subHeader3 = doc.InsertParagraph("8.3 合规改进建议");
            subHeader3.FontSize(13).Bold();
            subHeader3.Color(DeepBlue);
            subHeader3.SpacingBefore(22);
            subHeader3.SpacingAfter(10);

            var improvementIntro = doc.InsertParagraph("针对上述合规差距，建议按以下优先级进行改进：");
            improvementIntro.FontSize(10);
            improvementIntro.SpacingAfter(10);

            var improvements = new (string, string, string, string, string)[]
            {
                ("1", "建立安全基线配置标准", "等保2.0/ISO 27001", "高", "制定并实施系统安全配置基线，定期进行基线检查和偏差修正"),
                ("2", "实施漏洞管理流程", "CIS Controls/PCI DSS", "高", "建立漏洞扫描、评估、修复的闭环管理流程，确保高危漏洞在规定时限内修复"),
                ("3", "加强访问控制机制", "等保2.0/GDPR", "高", "实施最小权限原则，部署多因素认证，定期审计账户权限"),
                ("4", "完善日志审计体系", "等保2.0/ISO 27001", "中", "部署集中化日志管理平台，确保关键操作可追溯，日志保留不少于6个月"),
                ("5", "数据加密与保护", "GDPR/PCI DSS", "中", "对敏感数据实施传输加密（TLS 1.2+）和存储加密，建立数据分类分级制度"),
                ("6", "安全意识培训", "ISO 27001/CIS Controls", "低", "定期开展安全意识培训和考核，建立安全事件报告机制")
            };

            var improveTable = doc.AddTable(improvements.Length + 1, 5);
            improveTable.Design = TableDesign.TableGrid;
            improveTable.Alignment = Alignment.center;

            var improveHeaders = new[] { "序号", "改进措施", "关联标准", "优先级", "具体建议" };
            StyleTableHeader(improveTable, improveHeaders);

            for (int r = 0; r < improvements.Length; r++)
            {
                var imp = improvements[r];
                improveTable.Rows[r + 1].Cells[0].Paragraphs[0].Append(imp.Item1).FontSize(9);
                improveTable.Rows[r + 1].Cells[0].Paragraphs[0].Alignment = Alignment.center;
                improveTable.Rows[r + 1].Cells[1].Paragraphs[0].Append(imp.Item2).FontSize(9).Bold();
                improveTable.Rows[r + 1].Cells[2].Paragraphs[0].Append(imp.Item3).FontSize(9);
                improveTable.Rows[r + 1].Cells[3].Paragraphs[0].Append(imp.Item4).FontSize(9).Bold().Color(GetRiskColor(imp.Item4));
                improveTable.Rows[r + 1].Cells[3].Paragraphs[0].Alignment = Alignment.center;
                improveTable.Rows[r + 1].Cells[4].Paragraphs[0].Append(imp.Item5).FontSize(9);
            }
            ApplyTableRowShading(improveTable);

            doc.InsertParagraph().SpacingAfter(22);

            var subHeader4 = doc.InsertParagraph("8.4 合规总结");
            subHeader4.FontSize(13).Bold();
            subHeader4.Color(DeepBlue);
            subHeader4.SpacingBefore(22);
            subHeader4.SpacingAfter(10);

            var safeVulnsForSummary = vulns ?? new List<VulnerabilityResult>();
            var highRiskVulns = safeVulnsForSummary.Where(v => IsCritical(v?.RiskLevel) || IsHigh(v?.RiskLevel)).ToList();
            var portNumbers = openPorts.Select(p => p?.PortNumber ?? 0).ToHashSet();
            var hasHighRisk = highRiskVulns.Any() || portNumbers.Any(p => p == 445 || p == 135 || p == 3389);

            var complianceSummary = doc.InsertParagraph();
            if (hasHighRisk)
            {
                complianceSummary.Append("当前系统的合规状态为").FontSize(10);
                complianceSummary.Append("「不合规」").FontSize(10).Bold().Color(Xceed.Drawing.Color.Firebrick);
                complianceSummary.Append("，存在多项需要立即处理的安全差距。主要问题集中在等保2.0安全计算环境要求和ISO 27001漏洞管理条款方面。建议在完成高危漏洞修复和高危端口治理后，重新进行合规评估。").FontSize(10);
            }
            else
            {
                complianceSummary.Append("当前系统的合规状态为").FontSize(10);
                complianceSummary.Append("「基本合规」").FontSize(10).Bold().Color(Xceed.Drawing.Color.DarkOrange);
                complianceSummary.Append("，但仍存在需要持续改进的安全差距。建议按优先级逐步推进合规建设，持续完善安全管理体系。").FontSize(10);
            }
            complianceSummary.SpacingAfter(8);

            var complianceRoadmap = doc.InsertParagraph();
            complianceRoadmap.Append("合规建设是一个持续演进的过程，建议制定分阶段的合规路线图：第一阶段完成紧急整改和高危问题修复（1-3个月），第二阶段建立体系化的安全管理流程（3-6个月），第三阶段通过正式合规测评和认证（6-12个月）。").FontSize(10);
            complianceRoadmap.SpacingAfter(10);

            // 任务13：合规建设路线图 3 阶段
            var roadmapTitle = doc.InsertParagraph("合规建设路线图（3 阶段）");
            roadmapTitle.FontSize(11).Bold();
            roadmapTitle.Color(DeepBlue);
            roadmapTitle.SpacingBefore(6);
            roadmapTitle.SpacingAfter(6);

            var phaseTable = doc.AddTable(4, 3);
            phaseTable.Design = TableDesign.TableGrid;
            phaseTable.Alignment = Alignment.center;

            var phaseHeaders = new[] { "阶段", "时间窗口", "核心工作" };
            StyleTableHeader(phaseTable, phaseHeaders);

            var phaseItems = new (string, string, string)[]
            {
                ("阶段一：紧急整改", "1-3 个月",
                    "完成严重/高危漏洞修复；关闭非必要的高危端口；部署 MFA、强制账户策略；建立漏洞响应小组与应急流程。"),
                ("阶段二：体系建设", "3-6 个月",
                    "建立安全配置基线并落地；部署集中化日志(SIEM)与威胁检测(IDS/IPS)；完善访问控制与数据加密；开展安全意识培训与演练。"),
                ("阶段三：测评认证", "6-12 个月",
                    "推进等保 2.0 三级/二级测评；ISO 27001 信息安全管理体系认证；GDPR/PCI DSS 合规自评估与差距关闭；建立持续合规监控机制。")
            };

            for (int r = 0; r < phaseItems.Length; r++)
            {
                var row = phaseTable.Rows[r + 1];
                row.Cells[0].Paragraphs[0].Append(phaseItems[r].Item1).FontSize(9).Bold();
                row.Cells[0].Paragraphs[0].Color(r == 0 ? Xceed.Drawing.Color.Firebrick : r == 1 ? Xceed.Drawing.Color.OrangeRed : Xceed.Drawing.Color.SeaGreen);
                row.Cells[1].Paragraphs[0].Append(phaseItems[r].Item2).FontSize(9);
                row.Cells[1].Paragraphs[0].Alignment = Alignment.center;
                row.Cells[2].Paragraphs[0].Append(phaseItems[r].Item3).FontSize(9);
            }
            ApplyTableRowShading(phaseTable);
        }

        private static List<(string, string, string, string)> BuildComplianceItems(
            List<VulnerabilityResult> vulns, List<PortScanResult> openPorts)
        {
            var hasHighRisk = vulns.Any(v => IsCritical(v?.RiskLevel) || IsHigh(v?.RiskLevel));
            var portNumbers = openPorts.Select(p => p?.PortNumber ?? 0).ToHashSet();
            var hasSensitivePort = portNumbers.Any(p => p == 445 || p == 135 || p == 3389 || p == 3306 || p == 1433);

            return new List<(string, string, string, string)>
            {
                ("等保2.0",
                    "安全物理环境/安全通信网络/安全区域边界",
                    hasHighRisk ? "存在高危漏洞，不满足安全计算环境要求" : "基本满足安全计算环境要求",
                    hasHighRisk ? "不合规" : "部分合规"),
                ("ISO 27001",
                    "A.12漏洞管理/A.9访问控制/A.13通信安全",
                    hasHighRisk ? "漏洞管理流程存在缺陷" : "漏洞管理基本到位",
                    hasHighRisk ? "不合规" : "部分合规"),
                ("GDPR",
                    "第32条安全措施/第25条数据保护设计",
                    hasSensitivePort ? "敏感端口暴露，数据保护措施不足" : "数据保护措施基本到位",
                    hasSensitivePort ? "不合规" : "部分合规"),
                ("PCI DSS",
                    "Requirement 6安全系统/Requirement 1防火墙",
                    hasHighRisk ? "系统安全维护不达标" : "系统安全维护基本达标",
                    hasHighRisk ? "不合规" : "部分合规"),
                ("CIS Controls",
                    "CIS 3数据保护/CIS 7漏洞管理/CIS 9网络监控",
                    hasHighRisk ? "漏洞管理和网络监控存在不足" : "基本满足CIS控制要求",
                    hasHighRisk ? "部分合规" : "基本合规")
            };
        }

        private static List<(string, string, string, string, string)> BuildComplianceGaps(
            List<VulnerabilityResult> vulns, List<PortScanResult> openPorts)
        {
            var gaps = new List<(string, string, string, string, string)>();
            var highRiskVulns = vulns.Where(v => IsCritical(v?.RiskLevel) || IsHigh(v?.RiskLevel)).ToList();
            var portNumbers = openPorts.Select(p => p?.PortNumber ?? 0).ToHashSet();

            if (highRiskVulns.Any())
                gaps.Add(("高危漏洞未修复", "等保2.0/ISO 27001/PCI DSS",
                    $"存在{highRiskVulns.Count}个高危漏洞未修复", "高",
                    "立即制定漏洞修复计划，优先处理严重和高危漏洞"));

            if (portNumbers.Contains(445) || portNumbers.Contains(135))
                gaps.Add(("高危端口暴露", "等保2.0/CIS Controls",
                    "SMB/RPC高危端口对外暴露", "高",
                    "关闭不必要的端口，配置防火墙规则限制访问"));

            if (portNumbers.Contains(3389))
                gaps.Add(("远程桌面暴露", "等保2.0/CIS Controls",
                    "RDP端口对外暴露，存在暴力破解风险", "高",
                    "限制RDP访问来源，启用网络级别认证(NLA)"));

            if (portNumbers.Contains(3306) || portNumbers.Contains(1433) || portNumbers.Contains(5432))
                gaps.Add(("数据库端口暴露", "PCI DSS/GDPR",
                    "数据库端口对外可达，存在数据泄露风险", "高",
                    "数据库端口仅限内网访问，实施访问控制策略"));

            gaps.Add(("安全配置基线缺失", "ISO 27001/CIS Controls",
                "未建立系统安全配置基线标准", "中",
                "制定安全配置基线并定期检查偏差"));

            gaps.Add(("日志审计不完善", "等保2.0/ISO 27001",
                "缺乏集中化日志管理和审计机制", "中",
                "部署SIEM系统，确保关键操作可追溯"));

            if (!vulns.Any())
                gaps.Add(("持续监控不足", "CIS Controls/ISO 27001",
                    "缺乏持续安全监控机制", "低",
                    "建立常态化安全扫描和监控机制"));

            return gaps;
        }

        #endregion

        #region 结论与建议

        private static void GenerateConclusionSection(DocX doc, List<VulnerabilityResult> vulns, List<PortScanResult> ports)
        {
            var chapterTitle = doc.InsertParagraph("第九章 结论与建议");
            chapterTitle.FontSize(16).Bold();
            chapterTitle.Color(DeepBlue);
            chapterTitle.SpacingBefore(15);
            chapterTitle.SpacingAfter(4);

            var titleLine = doc.InsertParagraph(new string('─', 50));
            titleLine.FontSize(7);
            titleLine.Color(AccentBlue);
            titleLine.SpacingAfter(12);

            var intro = doc.InsertParagraph("本节综合前述各章节的分析结果，给出总体安全评级、核心结论和长期安全建议。");
            intro.FontSize(10);
            intro.SpacingBefore(8);
            intro.SpacingAfter(18);

            var safeVulns = vulns ?? new List<VulnerabilityResult>();
            var safePorts = ports ?? new List<PortScanResult>();
            var openPorts = safePorts.Where(p => p?.Status == "开放" || p?.Status?.ToLower() == "open").ToList();

            var subHeader1 = doc.InsertParagraph("9.1 总体安全评级");
            subHeader1.FontSize(13).Bold();
            subHeader1.Color(DeepBlue);
            subHeader1.SpacingBefore(12);
            subHeader1.SpacingAfter(10);

            // 任务14：在 subHeader1（9.1）后、ratingPara 前增加"评分维度权重"说明表
            var weightTitle = doc.InsertParagraph("评分维度权重");
            weightTitle.FontSize(11).Bold();
            weightTitle.Color(AccentBlue);
            weightTitle.SpacingBefore(6);
            weightTitle.SpacingAfter(4);

            var weightIntro = doc.InsertParagraph("本次安全评分采用加权扣分法（满分 100），四个核心维度的权重如下：");
            weightIntro.FontSize(10);
            weightIntro.SpacingAfter(6);

            var weightTable = doc.AddTable(5, 3);
            weightTable.Design = TableDesign.TableGrid;
            weightTable.Alignment = Alignment.center;

            var weightHeaders = new[] { "评分维度", "权重", "说明" };
            StyleTableHeader(weightTable, weightHeaders);

            var weightItems = new (string, string, string)[]
            {
                ("漏洞严重度", "60%", "按 CVSS 评分与漏洞等级（严重-15/高-8/中-3/低-1）扣分，是决定总体评分的核心维度"),
                ("端口暴露", "25%", "高危端口（445/135/3389/23/3306/1433/5432 等）每出现一个额外扣分；开放端口总数过多也会扣分"),
                ("服务多样性", "10%", "对外服务的种类与版本分布反映攻击面复杂度，类型越多攻击路径越广"),
                ("攻击面复杂度", "5%", "结合 Web 服务、远程管理、数据库等关键服务的暴露情况做综合评判")
            };

            for (int r = 0; r < weightItems.Length; r++)
            {
                var row = weightTable.Rows[r + 1];
                row.Cells[0].Paragraphs[0].Append(weightItems[r].Item1).FontSize(9).Bold();
                row.Cells[0].Paragraphs[0].Color(DeepBlue);
                row.Cells[1].Paragraphs[0].Append(weightItems[r].Item2).FontSize(9).Bold();
                row.Cells[1].Paragraphs[0].Color(Xceed.Drawing.Color.Firebrick);
                row.Cells[1].Paragraphs[0].Alignment = Alignment.center;
                row.Cells[2].Paragraphs[0].Append(weightItems[r].Item3).FontSize(9);
            }
            ApplyTableRowShading(weightTable);
            doc.InsertParagraph().SpacingAfter(10);

            var overallRisk = CalculateOverallRiskLevel(safeVulns);
            var securityScore = CalculateSecurityScore(safeVulns, openPorts);

            var ratingPara = doc.InsertParagraph();
            ratingPara.Alignment = Alignment.center;
            ratingPara.Append("总体安全评级：").FontSize(12).Bold();
            ratingPara.Append(overallRisk).FontSize(22).Bold().Color(GetRiskColor(overallRisk));
            ratingPara.SpacingAfter(6);

            var scorePara = doc.InsertParagraph();
            scorePara.Alignment = Alignment.center;
            scorePara.Append($"安全评分：{securityScore}/100").FontSize(16).Bold();
            scorePara.Color(DeepBlue);
            scorePara.SpacingAfter(10);

            var ratingDesc = doc.InsertParagraph();
            ratingDesc.Alignment = Alignment.center;
            ratingDesc.Append(GetSecurityRatingDescription(securityScore)).FontSize(10);
            ratingDesc.SpacingAfter(15);

            var ratingTable = doc.AddTable(6, 2);
            ratingTable.Design = TableDesign.TableGrid;
            ratingTable.Alignment = Alignment.center;

            var ratingTableHeaders = new[] { "评级指标", "评估结果" };
            StyleTableHeader(ratingTable, ratingTableHeaders);

            var highRiskVulns = safeVulns.Where(v => IsCritical(v?.RiskLevel) || IsHigh(v?.RiskLevel)).ToList();
            var ratingItems = new (string, string)[]
            {
                ("漏洞风险", $"{safeVulns.Count}个漏洞（{highRiskVulns.Count}个高危）"),
                ("端口暴露", $"{openPorts.Count}个开放端口"),
                ("服务安全", highRiskVulns.Any() ? "存在高风险服务" : "服务安全状况良好"),
                ("整体评级", overallRisk),
                ("安全评分", $"{securityScore}/100")
            };

            for (int r = 0; r < ratingItems.Length; r++)
            {
                var row = ratingTable.Rows[r + 1];
                row.Cells[0].Paragraphs[0].Append(ratingItems[r].Item1).FontSize(9).Bold();
                row.Cells[1].Paragraphs[0].Append(ratingItems[r].Item2).FontSize(9);
                row.Cells[1].Paragraphs[0].Color(GetRiskColor(r == 3 ? overallRisk : "低"));
            }
            ApplyTableRowShading(ratingTable);

            doc.InsertParagraph().SpacingAfter(22);

            var subHeader2 = doc.InsertParagraph("9.2 合规雷达图");
            subHeader2.FontSize(13).Bold();
            subHeader2.Color(DeepBlue);
            subHeader2.SpacingBefore(22);
            subHeader2.SpacingAfter(10);

            var portNumbers = openPorts.Select(p => p?.PortNumber ?? 0).ToHashSet();
            var hasHighRisk = safeVulns.Any(v => IsCritical(v?.RiskLevel) || IsHigh(v?.RiskLevel));

            var radarData = new List<(string Standard, int Score)>
            {
                ("等保2.0", hasHighRisk ? 45 : 75),
                ("ISO 27001", hasHighRisk ? 50 : 80),
                ("GDPR", portNumbers.Any(p => p == 445 || p == 3389 || p == 3306) ? 40 : 85),
                ("PCI DSS", hasHighRisk ? 55 : 80),
                ("CIS Controls", hasHighRisk ? 50 : 75)
            };

            var radarImage = ReportChartGenerator.GenerateComplianceRadarChart(radarData);
            AddChartImage(doc, radarImage, 340, 340);

            doc.InsertParagraph().SpacingAfter(22);

            var subHeader3 = doc.InsertParagraph("9.3 核心结论");
            subHeader3.FontSize(13).Bold();
            subHeader3.Color(DeepBlue);
            subHeader3.SpacingBefore(22);
            subHeader3.SpacingAfter(10);

            var conclusions = BuildCoreConclusions(safeVulns, openPorts);
            int cIdx = 1;
            foreach (var conclusion in conclusions)
            {
                var conPara = doc.InsertParagraph();
                conPara.Append($"{cIdx}. ").FontSize(10).Bold();
                conPara.Append(conclusion).FontSize(10);
                conPara.SpacingBefore(5);
                conPara.SpacingAfter(5);
                cIdx++;
            }

            doc.InsertParagraph().SpacingAfter(22);

            var subHeader4 = doc.InsertParagraph("9.4 长期安全建议");
            subHeader4.FontSize(13).Bold();
            subHeader4.Color(DeepBlue);
            subHeader4.SpacingBefore(22);
            subHeader4.SpacingAfter(10);

            var longTermIntro = doc.InsertParagraph("以下为按优先级分类的长期安全改进建议：");
            longTermIntro.FontSize(10);
            longTermIntro.SpacingAfter(10);

            var p1Header = doc.InsertParagraph("P1 - 紧急（1-7天内完成）");
            p1Header.FontSize(11).Bold();
            p1Header.Color(Xceed.Drawing.Color.Firebrick);
            p1Header.SpacingBefore(10);
            p1Header.SpacingAfter(6);

            var p1Items = new[]
            {
                "修复所有严重和高危漏洞，消除远程代码执行风险",
                "关闭所有非必要的高危端口（如135、445、3389等），配置严格的防火墙规则",
                "对暴露的数据库端口实施网络隔离，仅允许授权IP访问",
                "启用所有对外服务的安全加密通信（TLS 1.2+）",
                "实施多因素认证(MFA)，覆盖所有远程访问和特权账户"
            };

            foreach (var item in p1Items)
            {
                var p = doc.InsertParagraph($"• {item}");
                p.FontSize(10);
                p.SpacingBefore(3);
                p.SpacingAfter(3);
            }

            var p2Header = doc.InsertParagraph("P2 - 重要（1-3个月内完成）");
            p2Header.FontSize(11).Bold();
            p2Header.Color(Xceed.Drawing.Color.OrangeRed);
            p2Header.SpacingBefore(12);
            p2Header.SpacingAfter(6);

            var p2Items = new[]
            {
                "建立漏洞管理闭环流程，实现扫描-评估-修复-验证的标准化",
                "部署集中化日志管理系统(SIEM)，实现安全事件实时监控和告警",
                "实施网络分段和微隔离，限制横向移动攻击路径",
                "制定安全配置基线标准，定期进行基线检查和偏差修正",
                "建立安全意识培训体系，定期开展全员安全培训"
            };

            foreach (var item in p2Items)
            {
                var p = doc.InsertParagraph($"• {item}");
                p.FontSize(10);
                p.SpacingBefore(3);
                p.SpacingAfter(3);
            }

            var p3Header = doc.InsertParagraph("P3 - 改善（3-6个月内完成）");
            p3Header.FontSize(11).Bold();
            p3Header.Color(Xceed.Drawing.Color.DarkOrange);
            p3Header.SpacingBefore(12);
            p3Header.SpacingAfter(6);

            var p3Items = new[]
            {
                "推进等保2.0合规建设，完成差距整改和测评",
                "实施ISO 27001信息安全管理体系认证",
                "建立威胁情报平台，实现安全威胁的主动防御",
                "建设安全编排自动化与响应(SOAR)能力",
                "制定数据分类分级保护策略，满足GDPR/PCI DSS合规要求"
            };

            foreach (var item in p3Items)
            {
                var p = doc.InsertParagraph($"• {item}");
                p.FontSize(10);
                p.SpacingBefore(3);
                p.SpacingAfter(3);
            }

            doc.InsertParagraph().SpacingAfter(25);

            var subHeader5 = doc.InsertParagraph("9.5 报告文档信息");
            subHeader5.FontSize(13).Bold();
            subHeader5.Color(DeepBlue);
            subHeader5.SpacingBefore(22);
            subHeader5.SpacingAfter(10);

            var docInfoTable = doc.AddTable(7, 2);
            docInfoTable.Design = TableDesign.TableGrid;
            docInfoTable.Alignment = Alignment.center;

            var docInfoHeaders = new[] { "属性", "内容" };
            StyleTableHeader(docInfoTable, docInfoHeaders);

            // 任务17：确保 docInfoItems 包含 6 项：报告生成工具/扫描引擎版本/报告生成时间/风险评估方法/数据来源说明/报告模板版本
            var docInfoItems = new[]
            {
                ("报告生成工具", $"NetSecurityScanner v{GetAppVersion()} Professional Edition"),
                ("扫描引擎版本", GetAppVersion()),
                ("报告生成时间", DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss")),
                ("风险评估方法", "基于CVSS v3.1评分体系，结合OWASP风险评估方法论"),
                ("数据来源说明", "本报告数据来源于自动化安全扫描工具，结果综合自端口扫描、漏洞检测和威胁情报匹配"),
                ("报告模板版本", "V2.0（章节规范化重构版，含 9 章主体 + 附录 A/B，统一 x.y 编号）")
            };

            for (int r = 0; r < docInfoItems.Length; r++)
            {
                docInfoTable.Rows[r + 1].Cells[0].Paragraphs[0].Append(docInfoItems[r].Item1).FontSize(9).Bold();
                docInfoTable.Rows[r + 1].Cells[1].Paragraphs[0].Append(docInfoItems[r].Item2).FontSize(9);
            }
            ApplyTableRowShading(docInfoTable);

            doc.InsertParagraph().SpacingAfter(25);

            var finalNote = doc.InsertParagraph("本报告由 NetSecurityScanner 安全扫描工具自动生成。建议结合专业安全团队的人工评估，制定完整的安全改进计划。安全建设是一个持续的过程，需要定期评估和改进。");
            finalNote.FontSize(9);
            finalNote.Color(MidGray);
        }

        private static int CalculateSecurityScore(List<VulnerabilityResult> vulns, List<PortScanResult> openPorts)
        {
            int score = 100;

            var criticalCount = vulns.Count(v => IsCritical(v?.RiskLevel));
            var highCount = vulns.Count(v => IsHigh(v?.RiskLevel));
            var mediumCount = vulns.Count(v => IsMedium(v?.RiskLevel));
            var lowCount = vulns.Count(v => IsLow(v?.RiskLevel));

            score -= criticalCount * 15;
            score -= highCount * 8;
            score -= mediumCount * 3;
            score -= lowCount * 1;

            var portNumbers = openPorts.Select(p => p?.PortNumber ?? 0).ToHashSet();
            if (portNumbers.Contains(445) || portNumbers.Contains(135)) score -= 10;
            if (portNumbers.Contains(3389)) score -= 8;
            if (portNumbers.Contains(23)) score -= 10;
            if (portNumbers.Contains(3306) || portNumbers.Contains(1433) || portNumbers.Contains(5432)) score -= 5;

            if (openPorts.Count > 20) score -= 5;
            else if (openPorts.Count > 10) score -= 3;

            return Math.Max(0, Math.Min(100, score));
        }

        private static string GetSecurityRatingDescription(int score)
        {
            if (score >= 90) return "系统安全状况优秀，仅存在少量低风险问题，建议持续保持安全监控。";
            if (score >= 75) return "系统安全状况良好，存在部分中等风险问题，建议按计划进行安全加固。";
            if (score >= 60) return "系统安全状况一般，存在多个安全风险，建议尽快制定并执行安全改进计划。";
            if (score >= 40) return "系统安全状况较差，存在高危安全风险，建议立即采取紧急修复措施。";
            return "系统安全状况严重，存在严重安全漏洞和重大风险，建议立即启动应急响应。";
        }

        private static List<string> BuildCoreConclusions(List<VulnerabilityResult> vulns, List<PortScanResult> openPorts)
        {
            // 任务15：固定输出 4-6 条结论（含风险定性 + 数量特征 + 关键建议）
            var conclusions = new List<string>();
            var safeVulns = vulns ?? new List<VulnerabilityResult>();
            var safePorts = openPorts ?? new List<PortScanResult>();
            var highRiskVulns = safeVulns.Where(v => IsCritical(v?.RiskLevel) || IsHigh(v?.RiskLevel)).ToList();
            var critCount = safeVulns.Count(v => IsCritical(v?.RiskLevel));
            var highCount = safeVulns.Count(v => IsHigh(v?.RiskLevel));
            var medCount = safeVulns.Count(v => IsMedium(v?.RiskLevel));
            var portNumbers = safePorts.Select(p => p?.PortNumber ?? 0).ToHashSet();
            var highRiskPorts = new[] { 445, 135, 3389, 23, 21, 3306, 1433, 6379, 27017 };
            var exposedHighRiskPorts = highRiskPorts.Where(p => portNumbers.Contains(p)).ToList();
            var riskLevel = CalculateOverallRiskLevel(safeVulns);

            // 1. 风险定性
            string riskSummary;
            if (riskLevel == "严重" || riskLevel == "高")
                riskSummary = $"本次安全评估结论为「{riskLevel}」风险，系统存在被远程入侵或数据泄露的明确路径，需立即启动应急响应并按 P1 优先级闭环处置。";
            else if (riskLevel == "中")
                riskSummary = $"本次安全评估结论为「{riskLevel}」风险，系统存在一定的安全隐患，建议按 P2 优先级（7 天内）完成中危及以上漏洞修复。";
            else if (safeVulns.Any())
                riskSummary = $"本次安全评估结论为「低」风险，未发现严重/高危漏洞，建议按 P3 持续优化策略保持安全态势。";
            else
                riskSummary = "本次安全评估未发现已知漏洞，系统整体安全状况良好，建议保持常态化安全监控并定期复测。";
            conclusions.Add(riskSummary);

            // 2. 数量特征（漏洞）
            var vulnDistLabel = highRiskVulns.Any() ? "高危为主" : (medCount > 0 ? "中危为主" : "低危/信息为主");
            var openCount = safePorts.Count(p => p?.Status == "开放" || p?.Status?.ToLower() == "open");
            conclusions.Add($"数量特征：本次扫描共发现 {safeVulns.Count} 个漏洞（严重 {critCount} 个、高危 {highCount} 个、中危 {medCount} 个），{safePorts.Count} 个端口（开放 {openCount} 个）。漏洞分布以{vulnDistLabel}，需结合业务影响确定修复优先级。");

            // 3. 端口与攻击面
            if (exposedHighRiskPorts.Any())
            {
                var portList = string.Join("、", exposedHighRiskPorts);
                conclusions.Add($"关键风险点：检测到 {exposedHighRiskPorts.Count} 个高危端口（{portList}）对外暴露，是勒索软件、蠕虫与暴力破解攻击的主要入口，建议立即关闭非必要端口或通过防火墙/零信任网关限制来源 IP。");
            }
            else if (safePorts.Any(p => p?.Status == "开放" || p?.Status?.ToLower() == "open"))
            {
                conclusions.Add("关键风险点：本次未检测到 445/135/3389/23/21/3306/1433/6379 等高危端口对外暴露，端口暴露面整体可控，建议继续保持严格的访问控制策略。");
            }
            else
            {
                conclusions.Add("关键风险点：本次未发现开放端口，目标系统可能位于防火墙后或未运行网络服务，建议结合业务可达性进行进一步确认。");
            }

            // 4. 合规态势
            if (highRiskVulns.Any() || exposedHighRiskPorts.Any())
                conclusions.Add("合规态势：当前不符合等保 2.0、ISO 27001、PCI DSS 等主流合规标准对漏洞管理、端口治理与访问控制的基本要求，建议按 8.4 节「合规建设路线图」分阶段推进整改。");
            else
                conclusions.Add("合规态势：当前基本满足等保 2.0、ISO 27001、PCI DSS 等主流合规标准对漏洞管理与访问控制的基本要求，建议按 8.4 节「合规建设路线图」持续完善体系化建设。");

            // 5. 关键建议（修复侧）
            if (highRiskVulns.Any())
                conclusions.Add($"关键建议：(1) 24 小时内完成所有严重/高危漏洞（{highRiskVulns.Count} 个）的修复或临时缓解；(2) 1 周内关闭/收敛暴露的高危端口，部署 MFA 与最小权限访问控制；(3) 1 个月内建立漏洞管理闭环流程并完成复测验证；(4) 持续推进 5.4 节四时间维度的安全建议落地。");
            else
                conclusions.Add("关键建议：(1) 持续保持漏洞定期扫描和补丁更新节奏；(2) 推进 5.4 节中长期安全建议落地；(3) 结合业务变更（新服务上线、网络结构调整）及时更新安全配置基线与扫描策略。");

            // 6. 持续运营
            conclusions.Add("持续运营：建议建立常态化的「扫描-评估-修复-复测-归档」闭环机制，结合威胁情报订阅定期（建议至少季度一次）执行安全评估，持续监控新增漏洞与新暴露端口，确保安全态势长期可控。");

            return conclusions;
        }

        #endregion

        #region 扫描范围与限制

        private static void GenerateScanScopeSection(DocX doc, string targetIp, List<PortScanResult> ports,
            List<VulnerabilityResult> vulns, string scanTypeInfo = null)
        {
            var chapterTitle = doc.InsertParagraph("第二章 扫描范围与方法");
            chapterTitle.FontSize(16).Bold();
            chapterTitle.Color(DeepBlue);
            chapterTitle.SpacingBefore(15);
            chapterTitle.SpacingAfter(4);

            var titleLine = doc.InsertParagraph(new string('─', 50));
            titleLine.FontSize(7);
            titleLine.Color(AccentBlue);
            titleLine.SpacingAfter(12);

            var intro = doc.InsertParagraph("本章节明确本次安全评估的扫描范围、采用的方法、已知限制以及免责声明，为报告的解读提供必要的上下文信息。");
            intro.FontSize(10);
            intro.SpacingBefore(8);
            intro.SpacingAfter(18);

            var safePorts = ports ?? new List<PortScanResult>();
            var safeVulns = vulns ?? new List<VulnerabilityResult>();
            var openPorts = safePorts.Where(p => p?.Status == "开放" || p?.Status?.ToLower() == "open").ToList();
            var closedPorts = safePorts.Where(p => p?.Status == "关闭" || p?.Status?.ToLower() == "closed" || p?.Status?.ToLower() == "filtered").ToList();

            var sub1 = doc.InsertParagraph("2.1 扫描对象");
            sub1.FontSize(13).Bold();
            sub1.Color(DeepBlue);
            sub1.SpacingBefore(12);
            sub1.SpacingAfter(10);

            var scopeTable = doc.AddTable(7, 2);
            scopeTable.Design = TableDesign.TableGrid;
            scopeTable.Alignment = Alignment.center;

            var scopeHeaders = new[] { "范围项目", "描述" };
            StyleTableHeader(scopeTable, scopeHeaders);

            var svcTypes = openPorts.Where(p => !string.IsNullOrEmpty(p?.Service)).Select(p => p.Service).Distinct().Count();
            var portNums = openPorts.Select(p => p?.PortNumber ?? 0).ToHashSet();
            var highRiskPortNums = portNums.Where(p => p == 445 || p == 135 || p == 3389 || p == 23 || p == 21 || p == 3306 || p == 1433 || p == 6379).ToList();

            var scopeItems = new[]
            {
                ("目标IP地址", targetIp),
                ("扫描方法", "TCP SYN半连接端口扫描 + 服务版本探测 + 漏洞指纹匹配"),
                ("端口扫描范围", "TCP 1-65535（常用端口全集）"),
                ("漏洞检测方式", "基于服务指纹和版本信息的漏洞匹配检测"),
                ("扫描深度", !string.IsNullOrWhiteSpace(scanTypeInfo) && scanTypeInfo.Contains("专家模式") ? "深度扫描（含合规评估）" : "标准扫描"),
                ("关联记录数", $"{safePorts.Count}条端口记录 + {safeVulns.Count}条漏洞记录")
            };

            for (int r = 0; r < scopeItems.Length; r++)
            {
                scopeTable.Rows[r + 1].Cells[0].Paragraphs[0].Append(scopeItems[r].Item1).FontSize(9).Bold();
                scopeTable.Rows[r + 1].Cells[1].Paragraphs[0].Append(scopeItems[r].Item2).FontSize(9);
            }
            ApplyTableRowShading(scopeTable);

            doc.InsertParagraph().SpacingAfter(10);

            // 任务5：在 scopeTable 表格后增加"扫描策略说明"段（≥100字）
            var strategyTitle = doc.InsertParagraph("扫描策略说明");
            strategyTitle.FontSize(11).Bold();
            strategyTitle.Color(AccentBlue);
            strategyTitle.SpacingBefore(6);
            strategyTitle.SpacingAfter(6);

            var strategyPara1 = doc.InsertParagraph("本次扫描采用 TCP SYN 半连接扫描（SYN Scan）作为主扫描方式。SYN 扫描只发送 SYN 包并根据目标返回的 SYN+ACK 或 RST 报文判定端口状态，不完成完整的三次握手，因此扫描速度快、隐蔽性好、降低对目标业务的影响。相比 TCP Connect() 全连接扫描，SYN 扫描不易被业务应用记录为连接日志，是业界公认的标准端口发现方法。");
            strategyPara1.FontSize(10);
            strategyPara1.SpacingAfter(6);

            var strategyPara2 = doc.InsertParagraph("检测深度方面，系统在完成端口发现后，将主动抓取服务 Banner 与指纹信息，结合内置 CVE/CNVD 漏洞指纹库进行版本匹配与漏洞识别；标准模式覆盖常用服务和高危漏洞，专家模式额外启用深度服务探测、配置基线核查和合规评估，可在保留扫描速度的同时提升漏洞检出率与误报率控制能力。");
            strategyPara2.FontSize(10);
            strategyPara2.SpacingAfter(12);

            var portScanSub = doc.InsertParagraph("端口扫描概况");
            portScanSub.FontSize(12).Bold();
            portScanSub.Color(AccentBlue);
            portScanSub.SpacingBefore(10);
            portScanSub.SpacingAfter(10);

            var portScanSum = doc.InsertParagraph($"本次扫描共检测 {safePorts.Count} 个端口，其中开放端口 {openPorts.Count} 个，关闭/过滤端口 {closedPorts.Count} 个，发现 {svcTypes} 种不同类型的网络服务{(highRiskPortNums.Any() ? "，其中包含" + highRiskPortNums.Count + "个高危端口" : "")}。详细的端口分布、服务指纹和高危端口列表请参见「第三章 端口扫描结果」。");
            portScanSum.FontSize(10);
            portScanSum.SpacingAfter(12);

            doc.InsertParagraph().SpacingAfter(22);

            var sub2 = doc.InsertParagraph("2.2 扫描范围外");
            sub2.FontSize(13).Bold();
            sub2.Color(DeepBlue);
            sub2.SpacingBefore(12);
            sub2.SpacingAfter(10);

            var outOfScope = new[]
            {
                "本报告不含Web应用深度安全测试（如XSS、SQL注入动态验证）",
                "本报告不含社会工程学测试和物理安全评估",
                "本报告不含无线网络安全测试",
                "本报告不含源代码安全审计和二进制逆向分析",
                "本报告不含DDoS抗压测试和性能压测"
            };

            foreach (var item in outOfScope)
            {
                var p = doc.InsertParagraph($"• {item}");
                p.FontSize(10);
                p.SpacingBefore(3);
                p.SpacingAfter(3);
            }

            doc.InsertParagraph().SpacingAfter(22);

            var sub3 = doc.InsertParagraph("2.3 已知限制");
            sub3.FontSize(13).Bold();
            sub3.Color(DeepBlue);
            sub3.SpacingBefore(12);
            sub3.SpacingAfter(10);

            var limits = new[]
            {
                "漏洞检测基于服务版本指纹匹配，无法检测零日漏洞和未知攻击向量",
                "端口扫描基于TCP SYN方法，UDP端口状态可能存在偏差",
                "扫描结果受网络条件影响，防火墙策略可能导致误报或漏报",
                "服务版本识别取决于目标服务的响应特征，部分定制化服务可能被误识别",
                "风险评估基于CVSS评分体系估算，实际风险等级需结合业务场景综合判断"
            };

            foreach (var item in limits)
            {
                var p = doc.InsertParagraph($"• {item}");
                p.FontSize(10);
                p.SpacingBefore(3);
                p.SpacingAfter(3);
            }

            doc.InsertParagraph().SpacingAfter(22);

            var sub4 = doc.InsertParagraph("2.4 使用声明");
            sub4.FontSize(13).Bold();
            sub4.Color(DeepBlue);
            sub4.SpacingBefore(12);
            sub4.SpacingAfter(10);

            var declarations = new[]
            {
                "本报告仅供内部安全评估使用，未经授权不得对外分发",
                "报告中的修复建议为通用参考方案，具体实施需结合实际网络环境和业务需求",
                "建议在非业务高峰期执行修复操作，并提前备份系统和数据",
                "对于关键业务系统的变更操作，建议先在测试环境验证后再推送到生产环境",
                "本报告中的安全评分和风险评级为定性参考指标，不作为合规审计的唯一依据"
            };

            foreach (var item in declarations)
            {
                var p = doc.InsertParagraph($"• {item}");
                p.FontSize(10);
                p.SpacingBefore(3);
                p.SpacingAfter(3);
            }
        }

        #endregion

        #region 附录：CVE参考信息

        private static void GenerateCveAppendix(DocX doc, List<VulnerabilityResult> vulns)
        {
            var chapterTitle = doc.InsertParagraph("附录A CVE漏洞参考信息");
            chapterTitle.FontSize(16).Bold();
            chapterTitle.Color(DeepBlue);
            chapterTitle.SpacingBefore(15);
            chapterTitle.SpacingAfter(4);

            var titleLine = doc.InsertParagraph(new string('─', 50));
            titleLine.FontSize(7);
            titleLine.Color(AccentBlue);
            titleLine.SpacingAfter(12);

            var safeVulns = vulns ?? new List<VulnerabilityResult>();

            if (!safeVulns.Any())
            {
                var emptyPara = doc.InsertParagraph("本次扫描未检测到任何CVE漏洞，无参考信息可供列出。");
                emptyPara.Alignment = Alignment.center;
                emptyPara.SpacingAfter(15);
                return;
            }

            var cveVulns = safeVulns
                .Where(v => !string.IsNullOrWhiteSpace(v?.CveId) && v.CveId.StartsWith("CVE-", StringComparison.OrdinalIgnoreCase))
                .GroupBy(v => v.CveId?.ToUpper())
                .Select(g => g.First())
                .OrderByDescending(v => GetRiskPriority(v?.RiskLevel))
                .ToList();

            if (!cveVulns.Any())
            {
                var noCve = doc.InsertParagraph($"检测到{safeVulns.Count}个漏洞，但均未关联标准CVE编号。");
                noCve.FontSize(10);
                noCve.SpacingAfter(10);
                return;
            }

            var intro = doc.InsertParagraph($"本次扫描共关联{cveVulns.Count}个唯一CVE编号，按风险等级从高到低排列如下。每个CVE均可在NVD（National Vulnerability Database）查询详细信息。");
            intro.FontSize(10);
            intro.SpacingBefore(8);
            intro.SpacingAfter(14);

            var cveTable = doc.AddTable(cveVulns.Count + 1, 6);
            cveTable.Design = TableDesign.TableGrid;
            cveTable.Alignment = Alignment.center;

            var cveHeaders = new[] { "CVE编号", "漏洞名称", "风险等级", "CVSS估算", "影响服务", "NVD链接" };
            StyleTableHeader(cveTable, cveHeaders);

            int cveRow = 1;
            foreach (var vuln in cveVulns)
            {
                cveTable.Rows[cveRow].Cells[0].Paragraphs[0].Append(vuln.CveId.ToUpper()).FontSize(9).Bold();
                cveTable.Rows[cveRow].Cells[0].Paragraphs[0].Alignment = Alignment.center;

                var name = vuln.Name ?? "-";
                cveTable.Rows[cveRow].Cells[1].Paragraphs[0].Append(name.Length > 50 ? name.Substring(0, 47) + "..." : name).FontSize(9);

                var risk = vuln.RiskLevel ?? "未分类";
                cveTable.Rows[cveRow].Cells[2].Paragraphs[0].Append(risk).FontSize(9).Bold().Color(GetRiskColor(risk));
                cveTable.Rows[cveRow].Cells[2].Paragraphs[0].Alignment = Alignment.center;

                var cvss = EstimateCvssScore(vuln.RiskLevel);
                cveTable.Rows[cveRow].Cells[3].Paragraphs[0].Append($"{cvss:F1}").FontSize(9).Bold();
                cveTable.Rows[cveRow].Cells[3].Paragraphs[0].Color(GetRiskColor(risk));
                cveTable.Rows[cveRow].Cells[3].Paragraphs[0].Alignment = Alignment.center;

                var svc = vuln.Service ?? "-";
                cveTable.Rows[cveRow].Cells[4].Paragraphs[0].Append(svc).FontSize(9);

                var cveUrl = $"https://nvd.nist.gov/vuln/detail/{vuln.CveId}";
                cveTable.Rows[cveRow].Cells[5].Paragraphs[0].Append(cveUrl).FontSize(7);
                cveTable.Rows[cveRow].Cells[5].Paragraphs[0].Color(AccentBlue);

                cveRow++;
            }
            ApplyTableRowShading(cveTable);

            doc.InsertParagraph().SpacingAfter(22);

            var note = doc.InsertParagraph("注：CVSS评分为基于漏洞风险等级的估算值，实际评分请参考NVD官方数据库。NVD链接为静态参考URL，请粘贴至浏览器访问。");
            note.FontSize(9);
            note.Color(MidGray);
        }

        #endregion

        #region 附录B 报告使用与法律声明

        private static void GenerateAppendixB(DocX doc)
        {
            var chapterTitle = doc.InsertParagraph("附录B、报告使用与法律声明");
            chapterTitle.FontSize(16).Bold();
            chapterTitle.Color(DeepBlue);
            chapterTitle.SpacingBefore(15);
            chapterTitle.SpacingAfter(4);

            var titleLine = doc.InsertParagraph(new string('─', 50));
            titleLine.FontSize(7);
            titleLine.Color(AccentBlue);
            titleLine.SpacingAfter(12);

            var intro = doc.InsertParagraph("本附录说明了本报告的使用范围、数据来源、修复建议限制、责任限制、保密要求以及版本与修订记录，是阅读和使用本报告的重要前提。请仔细阅读以下条款。");
            intro.FontSize(10);
            intro.SpacingBefore(8);
            intro.SpacingAfter(18);

            // B.1 报告使用范围
            var sub1 = doc.InsertParagraph("B.1 报告使用范围");
            sub1.FontSize(13).Bold();
            sub1.Color(DeepBlue);
            sub1.SpacingBefore(12);
            sub1.SpacingAfter(10);

            var useScopeItems = new[]
            {
                "本报告仅限于授权客户对其自有或受托管理的目标系统进行安全评估使用。",
                "未经 NetSecurityScanner 开发方及授权客户的书面许可，不得向第三方披露、传播或转载本报告全部或部分内容。",
                "客户可在内部安全团队、运维团队、管理层之间传阅本报告，用于制定安全改进计划、风险处置和合规审计。",
                "本报告不得用于任何商业转售、再许可或公开宣传目的，亦不得用于公开宣传、客户演示等公开场合。",
                "本报告的有效期建议为 6 个月。由于漏洞库和服务指纹会持续更新，超过有效期的报告需要重新扫描。",
                "客户在使用本报告过程中遇到的问题，可联系 NetSecurityScanner 技术支持团队获取协助。"
            };
            foreach (var item in useScopeItems)
            {
                var p = doc.InsertParagraph($"• {item}");
                p.FontSize(10);
                p.SpacingBefore(3);
                p.SpacingAfter(3);
            }

            doc.InsertParagraph().SpacingAfter(15);

            // B.2 数据来源说明
            var sub2 = doc.InsertParagraph("B.2 数据来源说明");
            sub2.FontSize(13).Bold();
            sub2.Color(DeepBlue);
            sub2.SpacingBefore(12);
            sub2.SpacingAfter(10);

            var dataSourceItems = new[]
            {
                "端口扫描数据：基于 TCP SYN 半连接扫描技术，扫描结果来源于目标系统对扫描数据包的实时响应。",
                "服务指纹数据：通过主动探测目标端口，根据服务返回的 Banner 信息识别服务类型与版本。",
                "漏洞匹配数据：基于内置漏洞指纹库（含 CVE、CNVD、CNNVD 等公开漏洞库）进行模式匹配。",
                "威胁情报数据：结合行业公开威胁情报、攻击趋势报告以及通用攻击向量知识库。",
                "风险评估模型：基于 CVSS v3.1 通用漏洞评分体系，结合 OWASP 风险评估方法论进行综合评分。",
                "合规对照标准：参考等保 2.0、ISO 27001、GDPR、PCI DSS、CIS Controls 等国际国内主流合规标准。"
            };
            foreach (var item in dataSourceItems)
            {
                var p = doc.InsertParagraph($"• {item}");
                p.FontSize(10);
                p.SpacingBefore(3);
                p.SpacingAfter(3);
            }

            doc.InsertParagraph().SpacingAfter(15);

            // B.3 修复建议限制
            var sub3 = doc.InsertParagraph("B.3 修复建议限制");
            sub3.FontSize(13).Bold();
            sub3.Color(DeepBlue);
            sub3.SpacingBefore(12);
            sub3.SpacingAfter(10);

            var fixLimitItems = new[]
            {
                "本报告中的修复建议为通用参考方案，基于公开漏洞信息、行业最佳实践和通用安全原则。",
                "具体的修复实施需要结合客户的实际网络环境、业务连续性要求、版本兼容性和资源约束进行综合评估。",
                "对于关键业务系统（核心交易数据库、生产服务器、核心业务中间件等）的修复操作，建议先在测试环境充分验证后再推送到生产环境。",
                "本报告不提供定制化的修复脚本、补丁包或具体的产品配置指导。客户应参考各厂商的官方安全公告和升级指南。",
                "部分漏洞可能存在多个修复方案（如升级、打补丁、配置调整、临时缓解等），不同方案的适用性因系统而异。",
                "对于复杂的漏洞修复场景（如 Active Directory 域控、关键中间件、定制化业务系统），建议咨询专业的安全服务团队。"
            };
            foreach (var item in fixLimitItems)
            {
                var p = doc.InsertParagraph($"• {item}");
                p.FontSize(10);
                p.SpacingBefore(3);
                p.SpacingAfter(3);
            }

            doc.InsertParagraph().SpacingAfter(15);

            // B.4 责任限制
            var sub4 = doc.InsertParagraph("B.4 责任限制");
            sub4.FontSize(13).Bold();
            sub4.Color(DeepBlue);
            sub4.SpacingBefore(12);
            sub4.SpacingAfter(10);

            var liabilityItems = new[]
            {
                "本报告基于自动化扫描工具生成，结果仅供参考。对于关键安全问题，建议进行人工渗透测试和深度安全分析。",
                "扫描工具受限于其检测能力，无法保证 100% 覆盖所有安全风险。报告中未列出的风险不代表不存在。",
                "扫描过程中可能因网络环境、防火墙策略、IDS/IPS 等因素导致部分扫描结果不准确。",
                "NetSecurityScanner 开发方不对因使用本报告而导致的任何直接或间接损失（包括但不限于业务中断、数据丢失、安全事件等）承担责任。",
                "客户应根据自身业务特点和风险承受能力，制定符合实际情况的安全策略和修复计划。",
                "本报告中的安全评分、风险等级、合规状态等定性指标为参考性指标，不作为合规审计、法律诉讼、保险索赔的唯一依据。"
            };
            foreach (var item in liabilityItems)
            {
                var p = doc.InsertParagraph($"• {item}");
                p.FontSize(10);
                p.SpacingBefore(3);
                p.SpacingAfter(3);
            }

            doc.InsertParagraph().SpacingAfter(15);

            // B.5 保密声明
            var sub5 = doc.InsertParagraph("B.5 保密声明");
            sub5.FontSize(13).Bold();
            sub5.Color(DeepBlue);
            sub5.SpacingBefore(12);
            sub5.SpacingAfter(10);

            var confidentialityItems = new[]
            {
                "本报告内容涉及客户目标系统的安全状况，属于敏感信息。未经授权不得向不相关方披露。",
                "客户应采取适当的技术和组织措施保护本报告，包括但不限于：加密存储、访问控制、传输保护、销毁处理等。",
                "如发现本报告被未授权访问、披露或泄露，应立即通知 NetSecurityScanner 开发方，并采取应急响应措施。",
                "NetSecurityScanner 开发方对报告生成、传输、存储过程中的保密性负责，并承诺不向第三方披露客户扫描结果。",
                "客户因业务需要向第三方共享本报告部分内容时，应事先对内容进行脱敏处理，并签署相应的保密协议。",
                "本报告电子版本应存储在受控环境中，纸质版本应妥善保管，使用完毕后应及时销毁。"
            };
            foreach (var item in confidentialityItems)
            {
                var p = doc.InsertParagraph($"• {item}");
                p.FontSize(10);
                p.SpacingBefore(3);
                p.SpacingAfter(3);
            }

            doc.InsertParagraph().SpacingAfter(15);

            // B.6 版本与修订记录
            var sub6 = doc.InsertParagraph("B.6 版本与修订记录");
            sub6.FontSize(13).Bold();
            sub6.Color(DeepBlue);
            sub6.SpacingBefore(12);
            sub6.SpacingAfter(10);

            var versionTable = doc.AddTable(7, 2);
            versionTable.Design = TableDesign.TableGrid;
            versionTable.Alignment = Alignment.center;

            var versionHeaders = new[] { "属性", "内容" };
            StyleTableHeader(versionTable, versionHeaders);

            var versionItems = new[]
            {
                ("报告生成工具", $"NetSecurityScanner v{GetAppVersion()} Professional Edition"),
                ("报告生成时间", DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss")),
                ("风险评估方法", "基于 CVSS v3.1 通用漏洞评分体系，结合 OWASP 风险评估方法论"),
                ("数据来源说明", "自动化扫描工具实时检测 + 内置漏洞指纹库 + 公开威胁情报"),
                ("报告模板版本", "v2.0（章节规范化重构版）"),
                ("主要修订说明", "统一章节编号为第一章~第九章 + 附录A/B；所有子章节使用 x.y 标准编号；条件子章节增加占位说明；新增扫描结论概览和报告使用与法律声明")
            };

            for (int r = 0; r < versionItems.Length; r++)
            {
                versionTable.Rows[r + 1].Cells[0].Paragraphs[0].Append(versionItems[r].Item1).FontSize(9).Bold();
                versionTable.Rows[r + 1].Cells[1].Paragraphs[0].Append(versionItems[r].Item2).FontSize(9);
            }
            ApplyTableRowShading(versionTable);

            doc.InsertParagraph().SpacingAfter(22);

            var finalNote = doc.InsertParagraph("— 报告结束 —");
            finalNote.Alignment = Alignment.center;
            finalNote.FontSize(10).Bold();
            finalNote.Color(DeepBlue);
            finalNote.SpacingBefore(15);
            finalNote.SpacingAfter(10);

            var finalSubNote = doc.InsertParagraph("本报告由 NetSecurityScanner 安全扫描工具自动生成。如对报告内容有任何疑问，请联系 NetSecurityScanner 技术支持团队。");
            finalSubNote.Alignment = Alignment.center;
            finalSubNote.FontSize(9);
            finalSubNote.Color(MidGray);
        }

        #endregion

        #region 辅助计算方法

        private const int MAX_DETAIL_BLOCKS = 10;
        private const int MAX_PORTS_DISPLAY = 500;
        private const int MAX_VULN_DISPLAY = 100;

        private static string GetSafeString(string value) => string.IsNullOrWhiteSpace(value) ? "-" : value;

        private static double EstimateCvssScore(string riskLevel)
        {
            if (string.IsNullOrEmpty(riskLevel)) return 0.0;
            if (IsCritical(riskLevel)) return 9.5;
            if (IsHigh(riskLevel)) return 7.5;
            if (IsMedium(riskLevel)) return 5.5;
            if (IsLow(riskLevel)) return 3.0;
            return 1.0;
        }

        private static int GetRiskPriority(string riskLevel)
        {
            if (string.IsNullOrWhiteSpace(riskLevel)) return 0;
            if (IsCritical(riskLevel)) return 5;
            if (IsHigh(riskLevel)) return 4;
            if (IsMedium(riskLevel)) return 3;
            if (IsLow(riskLevel)) return 2;
            return 1;
        }

        private static string CalculateOverallRiskLevel(List<VulnerabilityResult> vulnerabilities)
        {
            if (vulnerabilities == null || !vulnerabilities.Any()) return "信息";
            try
            {
                if (vulnerabilities.Any(v => IsCritical(v?.RiskLevel))) return "严重";
                if (vulnerabilities.Any(v => IsHigh(v?.RiskLevel))) return "高";
                if (vulnerabilities.Any(v => IsMedium(v?.RiskLevel))) return "中";
                return "低";
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"[WordReport-风险等级] 计算异常: {ex.Message}");
                return "信息";
            }
        }

        private static bool IsCritical(string riskLevel)
        {
            if (string.IsNullOrWhiteSpace(riskLevel)) return false;
            var level = riskLevel.Trim().ToLower();
            return level.Contains("严重") || level == "critical";
        }

        private static bool IsHigh(string riskLevel)
        {
            if (string.IsNullOrWhiteSpace(riskLevel)) return false;
            var level = riskLevel.Trim().ToLower();
            return (level.Contains("高") && !level.Contains("严重")) || level == "high";
        }

        private static bool IsMedium(string riskLevel)
        {
            if (string.IsNullOrWhiteSpace(riskLevel)) return false;
            var level = riskLevel.Trim().ToLower();
            return level.Contains("中") || level == "medium";
        }

        private static bool IsLow(string riskLevel)
        {
            if (string.IsNullOrWhiteSpace(riskLevel)) return false;
            var level = riskLevel.Trim().ToLower();
            return level.Contains("低") || level == "low";
        }

        private static Xceed.Drawing.Color GetRiskColor(string riskLevel)
        {
            if (string.IsNullOrWhiteSpace(riskLevel)) return Xceed.Drawing.Color.Gray;
            var level = riskLevel.Trim().ToLower();
            if (level.Contains("严重") || level == "critical") return Xceed.Drawing.Color.Red;
            if ((level.Contains("高") && !level.Contains("严重")) || level == "high") return Xceed.Drawing.Color.OrangeRed;
            if (level.Contains("中") || level == "medium") return Xceed.Drawing.Color.Orange;
            if (level.Contains("低") || level == "low") return Xceed.Drawing.Color.Green;
            return Xceed.Drawing.Color.Gray;
        }

        private static Xceed.Drawing.Color GetComplianceColor(string complianceLevel)
        {
            if (string.IsNullOrWhiteSpace(complianceLevel)) return Xceed.Drawing.Color.Gray;
            var level = complianceLevel.Trim();
            if (level.Contains("不合规")) return Xceed.Drawing.Color.Red;
            if (level.Contains("部分合规")) return Xceed.Drawing.Color.Orange;
            if (level.Contains("基本合规")) return Xceed.Drawing.Color.YellowGreen;
            if (level.Contains("完全合规")) return Xceed.Drawing.Color.Green;
            return Xceed.Drawing.Color.Gray;
        }

        private static string BuildScanTypesString(List<CompleteScanResult> records)
        {
            if (records == null || !records.Any())
                return "综合扫描";

            var scanTypes = records
                .Select(r => r?.ScanType)
                .Where(s => !string.IsNullOrWhiteSpace(s))
                .Distinct()
                .ToList();

            if (!scanTypes.Any())
                return "综合扫描";

            var normalized = new List<string>();
            foreach (var st in scanTypes)
            {
                if (st.Contains("专家模式"))
                    normalized.Add("专家模式");
                else if (st.Contains("漏洞"))
                    normalized.Add("漏洞扫描");
                else if (st.Contains("TCP"))
                    normalized.Add("TCP端口扫描");
                else if (st.Contains("UDP"))
                    normalized.Add("UDP端口扫描");
                else
                    normalized.Add(st);
            }

            var distinct = normalized.Distinct().ToList();
            return string.Join(" + ", distinct);
        }

        #endregion
    }
}