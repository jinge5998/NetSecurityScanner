using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Diagnostics;
using NetSecurityScanner.Models;
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

                using (var ms = new MemoryStream())
                {
                    using (var doc = DocX.Create(ms))
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
                        doc.Save();
                    }
                    using (var fs = new FileStream(savePath, FileMode.Create, FileAccess.Write, FileShare.None, 4096, FileOptions.WriteThrough | FileOptions.SequentialScan))
                    {
                        ms.Position = 0;
                        ms.CopyTo(fs);
                        fs.Flush();
                    }
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

                using (var ms = new MemoryStream())
                {
                    using (var doc = DocX.Create(ms))
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
                        doc.Save();
                    }
                    using (var fs = new FileStream(savePath, FileMode.Create, FileAccess.Write, FileShare.None, 4096, FileOptions.WriteThrough | FileOptions.SequentialScan))
                    {
                        ms.Position = 0;
                        ms.CopyTo(fs);
                        fs.Flush();
                    }
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
                "一、执行摘要",
                "      1.1 核心统计数据",
                "      1.2 风险仪表盘",
                "      1.3 服务分布图表",
                "      1.4 Top 5 高危漏洞",
                "二、端口扫描结果",
                "      2.1 扫描方法说明",
                "      2.2 端口扫描概况",
                "      2.3 高危端口安全警示",
                "      2.4 所有端口详情",
                "      2.5 服务分布统计",
                "三、漏洞详情分析",
                "      3.1 漏洞风险分布",
                "      3.2 受影响服务分布",
                "      3.3 漏洞类型分类统计",
                "      3.4 漏洞概览表",
                "      3.5 漏洞详细信息",
                "四、风险评估",
                "      4.1 风险评估项目",
                "      4.2 风险等级矩阵",
                "      4.3 风险分布图表",
                "      4.4 安全建议概述",
                "五、修复建议",
                "      5.1 修复优先级矩阵",
                "      5.2 通用安全加固建议",
                "      5.3 高危漏洞专项修复方案",
                "      5.4 风险处理跟踪表",
                "六、威胁情报分析",
                "      6.1 活跃威胁向量",
                "      6.2 行业威胁趋势",
                "      6.3 攻击面评估",
                "      6.4 威胁情报总结",
                "七、合规参考",
                "      7.1 合规标准对照评估",
                "      7.2 合规差距分析",
                "      7.3 合规改进建议",
                "      7.4 合规总结",
                "八、结论与建议",
                "      8.1 总体安全评级",
                "      8.2 合规雷达图",
                "      8.3 核心结论",
                "      8.4 长期安全建议",
                "      8.5 报告文档信息",
                "1.5 扫描范围与限制",
                "      S.1 扫描对象",
                "      S.2 扫描范围外",
                "      S.3 已知限制",
                "      S.4 使用声明",
                "附录一、CVE漏洞参考信息"
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

            doc.InsertParagraph().SpacingAfter(35);

            var disclaimer = doc.InsertParagraph("免责声明：本报告由自动化安全扫描工具生成，结果仅供参考。对于关键安全问题，建议进行人工验证和深度安全分析。");
            disclaimer.Alignment = Alignment.center;
            disclaimer.FontSize(9);
            disclaimer.Color(MidGray);
        }

        #endregion

        #region 执行摘要

        private static void GenerateExecutiveSummary(DocX doc, List<PortScanResult> ports,
            List<VulnerabilityResult> vulns, string targetIp, string scanTypeInfo = null)
        {
            var chapterTitle = doc.InsertParagraph("一、执行摘要");
            chapterTitle.FontSize(16).Bold();
            chapterTitle.Color(DeepBlue);
            chapterTitle.SpacingBefore(15);
            chapterTitle.SpacingAfter(4);

            var titleLine = doc.InsertParagraph(new string('─', 50));
            titleLine.FontSize(7);
            titleLine.Color(AccentBlue);
            titleLine.SpacingAfter(12);

            var intro = doc.InsertParagraph("本节提供本次安全扫描的核心发现和统计概览，帮助快速了解目标系统的整体安全态势。");
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

            doc.InsertParagraph().SpacingAfter(18);

            var gaugeImage = ReportChartGenerator.GenerateRiskGaugeChart(riskLevel, securityScore);
            if (gaugeImage != null)
            {
                var gaugeTitle = doc.InsertParagraph("1.2 风险仪表盘");
                gaugeTitle.FontSize(13).Bold();
                gaugeTitle.Color(DeepBlue);
                gaugeTitle.SpacingBefore(18);
                gaugeTitle.SpacingAfter(8);
                AddChartImage(doc, gaugeImage, 280, 280);
            }

            var svcGroups = openPorts.Where(p => !string.IsNullOrEmpty(p?.Service))
                .GroupBy(p => p.Service).OrderByDescending(g => g.Count()).Take(6).ToList();
            if (svcGroups.Any())
            {
                var svcTitle = doc.InsertParagraph("1.3 服务分布图表");
                svcTitle.FontSize(13).Bold();
                svcTitle.Color(DeepBlue);
                svcTitle.SpacingBefore(18);
                svcTitle.SpacingAfter(8);
                var svcData = svcGroups.Select(g => (g.Key, g.Count())).ToList();
                var svcChart = ReportChartGenerator.GeneratePortServiceBarChart(svcData);
                AddChartImage(doc, svcChart, 450, 190);
            }

            if (safeVulns.Any())
            {
                var topTitle = doc.InsertParagraph("1.4 Top 5 高危漏洞");
                topTitle.FontSize(13).Bold();
                topTitle.Color(DeepBlue);
                topTitle.SpacingBefore(22);
                topTitle.SpacingAfter(10);

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
        }

        #endregion

        #region 端口扫描结果

        private static void GeneratePortScanSection(DocX doc, List<PortScanResult> results)
        {
            var chapterTitle = doc.InsertParagraph("二、端口扫描结果");
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

            var subHeaderScan = doc.InsertParagraph("2.1 扫描方法说明");
            subHeaderScan.FontSize(13).Bold();
            subHeaderScan.Color(DeepBlue);
            subHeaderScan.SpacingBefore(12);
            subHeaderScan.SpacingAfter(8);

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

            var subHeader0 = doc.InsertParagraph("2.2 端口扫描概况");
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

            if (hasHighRisk)
            {
                var riskTitle = doc.InsertParagraph("2.3 高危端口安全警示");
                riskTitle.FontSize(13).Bold();
                riskTitle.Color(Xceed.Drawing.Color.Firebrick);
                riskTitle.SpacingBefore(12);
                riskTitle.SpacingAfter(8);

                var riskDesc = doc.InsertParagraph($"检测到{highRiskPorts.Count}个高危端口对外暴露，这些端口通常是恶意攻击者的首要目标。开放这些端口显著增加了系统被攻破的风险，建议立即评估是否关闭或限制访问。");
                riskDesc.FontSize(10);
                riskDesc.SpacingAfter(10);

                var highRiskTable = doc.AddTable(highRiskPorts.Count + 1, 4);
                highRiskTable.Design = TableDesign.TableGrid;
                highRiskTable.Alignment = Alignment.center;

                var hrHeaders = new[] { "端口", "典型服务", "风险等级", "安全建议" };
                StyleTableHeader(highRiskTable, hrHeaders);

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
                doc.InsertParagraph().SpacingAfter(22);
            }

            var subHeader = doc.InsertParagraph(hasHighRisk ? "2.4 所有端口详情" : "2.3 所有端口详情");
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

            var svcGroups = openPorts.Where(p => !string.IsNullOrEmpty(p?.Service))
                .GroupBy(p => p.Service).OrderByDescending(g => g.Count()).Take(6).ToList();
            if (svcGroups.Any())
            {
                var svcChartTitle = doc.InsertParagraph("2.5 服务分布统计");
                svcChartTitle.FontSize(13).Bold();
                svcChartTitle.Color(DeepBlue);
                svcChartTitle.SpacingBefore(22);
                svcChartTitle.SpacingAfter(8);

                var svcChartData = svcGroups.Select(g => (g.Key, g.Count())).ToList();
                var svcChart = ReportChartGenerator.GeneratePortServiceBarChart(svcChartData);
                AddChartImage(doc, svcChart, 450, 190);

                var svcNote = doc.InsertParagraph($"\n共检测到{svcTypes}种不同类型的服务，其中{svcGroups.First().Key}服务最为活跃（{svcGroups.First().Count()}个端口）。");
                svcNote.FontSize(10);
                svcNote.SpacingBefore(6);
                svcNote.SpacingAfter(10);
            }
        }

        #endregion

        #region 漏洞详情

        private static void GenerateVulnerabilitySection(DocX doc, List<VulnerabilityResult> vulnerabilities)
        {
            var chapterTitle = doc.InsertParagraph("三、漏洞详情分析");
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

            if (!safeVulns.Any())
            {
                var emptyPara = doc.InsertParagraph("本次扫描未发现安全漏洞");
                emptyPara.Alignment = Alignment.center;
                emptyPara.SpacingAfter(15);
                var notePara = doc.InsertParagraph("未检测到已知漏洞可能表示目标系统已及时更新或安全配置良好，但也可能是扫描范围有限或目标系统运行了未公开的服务。建议结合其他评估手段进行综合判断。");
                notePara.FontSize(9);
                notePara.Color(MidGray);
                return;
            }

            var criticalCount = safeVulns.Count(v => IsCritical(v?.RiskLevel));
            var highCount = safeVulns.Count(v => IsHigh(v?.RiskLevel));
            var mediumCount = safeVulns.Count(v => IsMedium(v?.RiskLevel));
            var lowCount = safeVulns.Count(v => IsLow(v?.RiskLevel));
            var unknownCount = safeVulns.Count - criticalCount - highCount - mediumCount - lowCount;

            var vulnSvcs = safeVulns.Where(v => !string.IsNullOrWhiteSpace(v?.Service))
                .GroupBy(v => v.Service).OrderByDescending(g => g.Count()).Take(5).ToList();

            var subHeader0 = doc.InsertParagraph("3.1 漏洞风险分布");
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
                var svcDistTitle = doc.InsertParagraph("3.2 受影响服务分布");
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

            var subHeaderType = doc.InsertParagraph("3.3 漏洞类型分类统计");
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
            doc.InsertParagraph().SpacingAfter(22);

            bool hasMore = safeVulns.Count > MAX_VULN_DISPLAY;
            var displayVulns = hasMore ? safeVulns.Take(MAX_VULN_DISPLAY).ToList() : safeVulns;
            var sortedVulns = displayVulns.OrderByDescending(v => GetRiskPriority(v?.RiskLevel)).ToList();

            var subHeader = doc.InsertParagraph("3.4 漏洞概览表");
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
            var detailHeader = doc.InsertParagraph("3.5 漏洞详细信息（前10个）");
            detailHeader.FontSize(13).Bold();
            detailHeader.Color(DeepBlue);
            detailHeader.SpacingBefore(22);
            detailHeader.SpacingAfter(10);

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
            var solution = GetSafeString(vuln.Solution ?? "请参考官方安全公告获取补丁信息。");
            foreach (var line in solution.Split('\n')
                .Where(l => !string.IsNullOrWhiteSpace(l))
                .Select(l => l.Trim())
                .Take(5))
            {
                contentPara.Append($"  • {line}\n").FontSize(10);
            }

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

        #endregion

        #region 风险评估

        private static void GenerateRiskAssessment(DocX doc, List<VulnerabilityResult> vulns, List<PortScanResult> ports)
        {
            var chapterTitle = doc.InsertParagraph("四、风险评估");
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

            var subHeader = doc.InsertParagraph("4.1 风险评估项目");
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

                var matrixTitle = doc.InsertParagraph("4.2 风险等级矩阵（可能性 × 影响）");
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

                var chartTitle = doc.InsertParagraph("4.3 风险分布图表");
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

            doc.InsertParagraph().SpacingAfter(22);
            var sugHeader = doc.InsertParagraph("4.4 安全建议概述");
            sugHeader.FontSize(13).Bold();
            sugHeader.Color(DeepBlue);
            sugHeader.SpacingBefore(22);
            sugHeader.SpacingAfter(10);

            var suggestions = new[] {
                "立即修复所有严重和高危级别的漏洞",
                "关闭不必要的服务和端口，减少攻击面",
                "及时更新系统和应用软件至最新版本",
                "实施强密码策略和多因素认证(MFA)",
                "配置防火墙规则限制网络访问",
                "定期进行安全扫描和渗透测试"
            };

            foreach (var s in suggestions)
            {
                var sPara = doc.InsertParagraph($"• {s}");
                sPara.FontSize(10);
                sPara.SpacingBefore(4);
                sPara.SpacingAfter(4);
            }
        }

        #endregion

        #region 修复建议

        private static void GenerateRemediationSection(DocX doc, List<VulnerabilityResult> vulns)
        {
            var chapterTitle = doc.InsertParagraph("五、修复建议");
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

            var subHeader1 = doc.InsertParagraph("5.1 修复优先级矩阵");
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
            var subHeader2 = doc.InsertParagraph("5.2 通用安全加固建议");
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
                var subHeader3 = doc.InsertParagraph("5.3 高危漏洞专项修复方案");
                subHeader3.FontSize(13).Bold();
                subHeader3.Color(DeepBlue);
                subHeader3.SpacingBefore(22);
                subHeader3.SpacingAfter(10);

                var highVulns = vulns.Where(v => IsCritical(v?.RiskLevel) || IsHigh(v?.RiskLevel))
                    .OrderByDescending(v => GetRiskPriority(v?.RiskLevel)).Take(8).ToList();

                var fixTable = doc.AddTable(highVulns.Count + 1, 4);
                fixTable.Design = TableDesign.TableGrid;
                fixTable.Alignment = Alignment.center;

                var fixHeaders = new[] { "漏洞名称", "风险等级", "影响服务", "修复建议" };
                StyleTableHeader(fixTable, fixHeaders);

                for (int r = 0; r < highVulns.Count; r++)
                {
                    var v = highVulns[r];
                    var rl = string.IsNullOrWhiteSpace(v?.RiskLevel) ? "未分类" : v.RiskLevel;
                    fixTable.Rows[r + 1].Cells[0].Paragraphs[0].Append((v?.Name ?? "未知漏洞")).FontSize(9);
                    fixTable.Rows[r + 1].Cells[1].Paragraphs[0].Append(rl).FontSize(9).Bold().Color(GetRiskColor(rl));
                    fixTable.Rows[r + 1].Cells[1].Paragraphs[0].Alignment = Alignment.center;
                    var svcPort = v?.Port.HasValue == true ? $"{v.Service ?? "未知"} (端口{v.Port.Value})" : (v?.Service ?? "-");
                    fixTable.Rows[r + 1].Cells[2].Paragraphs[0].Append(svcPort).FontSize(9);
                    var fixSuggestion = !string.IsNullOrWhiteSpace(v?.Solution) ? v.Solution : "请参考官方安全公告获取补丁信息";
                    fixTable.Rows[r + 1].Cells[3].Paragraphs[0].Append(fixSuggestion.Length > 80 ? fixSuggestion.Substring(0, 77) + "..." : fixSuggestion).FontSize(9);
                }
                ApplyTableRowShading(fixTable);
            }

            doc.InsertParagraph().SpacingAfter(22);

            var subHeader4 = doc.InsertParagraph("5.4 风险处理跟踪表");
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
            var chapterTitle = doc.InsertParagraph("六、威胁情报分析");
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

            var subHeader1 = doc.InsertParagraph("6.1 活跃威胁向量");
            subHeader1.FontSize(13).Bold();
            subHeader1.Color(DeepBlue);
            subHeader1.SpacingBefore(12);
            subHeader1.SpacingAfter(10);

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

            var subHeader2 = doc.InsertParagraph("6.2 行业威胁趋势");
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

            var subHeader3 = doc.InsertParagraph("6.3 攻击面评估");
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

            var subHeader4 = doc.InsertParagraph("6.4 威胁情报总结");
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
            var chapterTitle = doc.InsertParagraph("七、合规参考");
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

            var subHeader1 = doc.InsertParagraph("7.1 合规标准对照评估");
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

            var subHeader2 = doc.InsertParagraph("7.2 合规差距分析");
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

            var subHeader3 = doc.InsertParagraph("7.3 合规改进建议");
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

            var subHeader4 = doc.InsertParagraph("7.4 合规总结");
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
            var chapterTitle = doc.InsertParagraph("八、结论与建议");
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

            var subHeader1 = doc.InsertParagraph("8.1 总体安全评级");
            subHeader1.FontSize(13).Bold();
            subHeader1.Color(DeepBlue);
            subHeader1.SpacingBefore(12);
            subHeader1.SpacingAfter(10);

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

            var subHeader2 = doc.InsertParagraph("8.2 合规雷达图");
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

            var subHeader3 = doc.InsertParagraph("8.3 核心结论");
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

            var subHeader4 = doc.InsertParagraph("8.4 长期安全建议");
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

            var subHeader5 = doc.InsertParagraph("8.5 报告文档信息");
            subHeader5.FontSize(13).Bold();
            subHeader5.Color(DeepBlue);
            subHeader5.SpacingBefore(22);
            subHeader5.SpacingAfter(10);

            var docInfoTable = doc.AddTable(6, 2);
            docInfoTable.Design = TableDesign.TableGrid;
            docInfoTable.Alignment = Alignment.center;

            var docInfoHeaders = new[] { "属性", "内容" };
            StyleTableHeader(docInfoTable, docInfoHeaders);

            var docInfoItems = new[]
            {
                ("报告生成工具", $"NetSecurityScanner v{GetAppVersion()} Professional Edition"),
                ("扫描引擎版本", GetAppVersion()),
                ("报告生成时间", DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss")),
                ("风险评估方法", "基于CVSS v3.1评分体系，结合OWASP风险评估方法论"),
                ("数据来源说明", "本报告数据来源于自动化安全扫描工具，结果综合自端口扫描、漏洞检测和威胁情报匹配")
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
            var conclusions = new List<string>();
            var highRiskVulns = vulns.Where(v => IsCritical(v?.RiskLevel) || IsHigh(v?.RiskLevel)).ToList();
            var portNumbers = openPorts.Select(p => p?.PortNumber ?? 0).ToHashSet();

            if (vulns.Any(v => IsCritical(v?.RiskLevel)))
                conclusions.Add($"本次扫描发现{vulns.Count(v => IsCritical(v.RiskLevel))}个严重漏洞，存在被远程攻击的高风险，攻击者可利用这些漏洞获取系统控制权。");

            if (highRiskVulns.Any())
                conclusions.Add($"共发现{highRiskVulns.Count}个高危漏洞，涉及多个服务端口，需优先处理以降低被攻击风险。");

            if (portNumbers.Contains(445) || portNumbers.Contains(135) || portNumbers.Contains(3389))
                conclusions.Add("系统暴露了SMB/RPC/RDP等高危端口，这些端口是勒索软件和蠕虫病毒的主要传播通道。");

            if (portNumbers.Contains(3306) || portNumbers.Contains(1433) || portNumbers.Contains(5432) || portNumbers.Contains(6379))
                conclusions.Add("数据库或缓存服务端口对外暴露，存在数据泄露和未授权访问风险。");

            if (openPorts.Count > 15)
                conclusions.Add($"开放端口数量较多（{openPorts.Count}个），攻击面较大，建议关闭不必要的端口和服务。");

            conclusions.Add("建议建立常态化安全扫描机制，定期评估系统安全状况，及时发现和修复新增安全风险。");

            if (!vulns.Any())
                conclusions.Insert(0, "本次扫描未发现安全漏洞，系统安全状况良好，建议持续保持安全监控。");

            return conclusions;
        }

        #endregion

        #region 扫描范围与限制

        private static void GenerateScanScopeSection(DocX doc, string targetIp, List<PortScanResult> ports,
            List<VulnerabilityResult> vulns, string scanTypeInfo = null)
        {
            var chapterTitle = doc.InsertParagraph("1.5 扫描范围与限制");
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

            var sub1 = doc.InsertParagraph("S.1 扫描对象");
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

            doc.InsertParagraph().SpacingAfter(18);

            var portScanSub = doc.InsertParagraph("端口扫描情况");
            portScanSub.FontSize(12).Bold();
            portScanSub.Color(AccentBlue);
            portScanSub.SpacingBefore(10);
            portScanSub.SpacingAfter(10);

            var portScanSum = doc.InsertParagraph($"本次扫描共检测 {safePorts.Count} 个端口，其中开放端口 {openPorts.Count} 个，关闭/过滤端口 {closedPorts.Count} 个，发现 {svcTypes} 种不同类型的网络服务{(highRiskPortNums.Any() ? "，其中包含" + highRiskPortNums.Count + "个高危端口" : "")}。");
            portScanSum.FontSize(10);
            portScanSum.SpacingAfter(12);

            var portScanDetailTable = doc.AddTable(4, 2);
            portScanDetailTable.Design = TableDesign.TableGrid;
            portScanDetailTable.Alignment = Alignment.center;

            var portScanDetailHeaders = new[] { "扫描项目", "结果" };
            StyleTableHeader(portScanDetailTable, portScanDetailHeaders);

            portScanDetailTable.Rows[1].Cells[0].Paragraphs[0].Append("检测端口总数").FontSize(9).Bold();
            portScanDetailTable.Rows[1].Cells[1].Paragraphs[0].Append($"{safePorts.Count}个").FontSize(9);

            portScanDetailTable.Rows[2].Cells[0].Paragraphs[0].Append("开放端口数").FontSize(9).Bold();
            portScanDetailTable.Rows[2].Cells[1].Paragraphs[0].Append($"{openPorts.Count}个").FontSize(9).Bold().Color(openPorts.Count > 10 ? Xceed.Drawing.Color.OrangeRed : Xceed.Drawing.Color.SeaGreen);

            portScanDetailTable.Rows[3].Cells[0].Paragraphs[0].Append("关闭/过滤端口").FontSize(9).Bold();
            portScanDetailTable.Rows[3].Cells[1].Paragraphs[0].Append($"{closedPorts.Count}个").FontSize(9);

            ApplyTableRowShading(portScanDetailTable);

            if (openPorts.Any())
            {
                doc.InsertParagraph().SpacingAfter(18);

                var allPortTitle = doc.InsertParagraph("所有开放端口详情");
                allPortTitle.FontSize(12).Bold();
                allPortTitle.Color(AccentBlue);
                allPortTitle.SpacingBefore(10);
                allPortTitle.SpacingAfter(10);

                var allPortTable = doc.AddTable(openPorts.Count + 1, 5);
                allPortTable.Design = TableDesign.TableGrid;
                allPortTable.Alignment = Alignment.center;

                var allPortHeaders = new[] { "序号", "端口号", "协议", "状态", "服务/版本" };
                StyleTableHeader(allPortTable, allPortHeaders);

                int allIdx = 1;
                foreach (var p in openPorts)
                {
                    var row = allPortTable.Rows[allIdx];
                    row.Cells[0].Paragraphs[0].Append($"{allIdx}").FontSize(9).Bold();
                    row.Cells[0].Paragraphs[0].Alignment = Alignment.center;

                    var portNum = p?.PortNumber ?? 0;
                    var portColor = highRiskPortNums.Contains(portNum) ? Xceed.Drawing.Color.Firebrick : Xceed.Drawing.Color.DarkBlue;
                    row.Cells[1].Paragraphs[0].Append($"{portNum}").FontSize(9).Bold().Color(portColor);
                    row.Cells[1].Paragraphs[0].Alignment = Alignment.center;

                    row.Cells[2].Paragraphs[0].Append("TCP").FontSize(9);
                    row.Cells[2].Paragraphs[0].Alignment = Alignment.center;

                    row.Cells[3].Paragraphs[0].Append(p?.Status ?? "开放").FontSize(9).Bold().Color(Xceed.Drawing.Color.SeaGreen);
                    row.Cells[3].Paragraphs[0].Alignment = Alignment.center;

                    var svcName = string.IsNullOrWhiteSpace(p?.Service) ? "未知服务" : p.Service;
                    row.Cells[4].Paragraphs[0].Append(svcName).FontSize(9);

                    allIdx++;
                }
                ApplyTableRowShading(allPortTable);
            }

            if (highRiskPortNums.Any())
            {
                doc.InsertParagraph().SpacingAfter(18);

                var highPortTitle = doc.InsertParagraph("高危端口列表");
                highPortTitle.FontSize(12).Bold();
                highPortTitle.Color(Xceed.Drawing.Color.Firebrick);
                highPortTitle.SpacingBefore(10);
                highPortTitle.SpacingAfter(10);

                var highPortTable = doc.AddTable(highRiskPortNums.Count + 1, 4);
                highPortTable.Design = TableDesign.TableGrid;
                highPortTable.Alignment = Alignment.center;

                var highPortHeaders = new[] { "端口号", "典型服务", "风险等级", "安全建议" };
                StyleTableHeader(highPortTable, highPortHeaders);

                var portServiceMap = new Dictionary<int, (string svc, string risk, string advice)>
                {
                    { 445, ("SMB/文件共享", "严重", "禁止公网暴露，配置强访问控制") },
                    { 135, ("RPC/DCE", "高", "禁用或限制访问，修补MS17-010等漏洞") },
                    { 3389, ("RDP远程桌面", "高", "启用NLA认证，限制IP范围，使用跳板机") },
                    { 23, ("Telnet", "严重", "立即关闭，改用SSH加密协议") },
                    { 21, ("FTP", "高", "改用SFTP/FTPS，或禁用匿名访问") },
                    { 3306, ("MySQL", "高", "禁止公网访问，配置防火墙白名单") },
                    { 1433, ("SQL Server", "高", "禁用sa账号，启用Windows认证") },
                    { 6379, ("Redis", "严重", "配置requirepass认证，禁止公网暴露") }
                };

                int hpIdx = 1;
                foreach (var port in highRiskPortNums.OrderBy(p => p))
                {
                    var row = highPortTable.Rows[hpIdx];
                    row.Cells[0].Paragraphs[0].Append($"{port}").FontSize(9).Bold().Color(Xceed.Drawing.Color.Firebrick);
                    row.Cells[0].Paragraphs[0].Alignment = Alignment.center;

                    if (portServiceMap.TryGetValue(port, out var info))
                    {
                        row.Cells[1].Paragraphs[0].Append(info.svc).FontSize(9);
                        row.Cells[1].Paragraphs[0].Alignment = Alignment.center;

                        row.Cells[2].Paragraphs[0].Append(info.risk).FontSize(9).Bold().Color(
                            info.risk == "严重" ? Xceed.Drawing.Color.Firebrick : Xceed.Drawing.Color.OrangeRed);
                        row.Cells[2].Paragraphs[0].Alignment = Alignment.center;

                        row.Cells[3].Paragraphs[0].Append(info.advice).FontSize(9);
                    }
                    else
                    {
                        row.Cells[1].Paragraphs[0].Append("未知服务").FontSize(9);
                        row.Cells[2].Paragraphs[0].Append("高").FontSize(9).Bold().Color(Xceed.Drawing.Color.OrangeRed);
                        row.Cells[3].Paragraphs[0].Append("建议关闭或限制访问").FontSize(9);
                    }

                    hpIdx++;
                }
                ApplyTableRowShading(highPortTable);
            }

            doc.InsertParagraph().SpacingAfter(22);

            var sub2 = doc.InsertParagraph("S.2 扫描范围外");
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

            var sub3 = doc.InsertParagraph("S.3 已知限制");
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

            var sub4 = doc.InsertParagraph("S.4 使用声明");
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
            var chapterTitle = doc.InsertParagraph("附录一、CVE漏洞参考信息");
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

