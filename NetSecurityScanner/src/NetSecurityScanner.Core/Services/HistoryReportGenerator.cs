using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Diagnostics;
using System.Runtime.InteropServices;
using iTextSharp.text;
using iTextSharp.text.pdf;
using NetSecurityScanner.Models;
using NetSecurityScanner.Utils;

namespace NetSecurityScanner.Services
{
    public static class HistoryReportGenerator
    {

        #region 字体常量定义

        private const float FONT_TITLE_MAIN = 22f;
        private const float FONT_TITLE_SECTION = 16f;
        private const float FONT_SUBTITLE = 14f;
        private const float FONT_HEADING2 = 13f;
        private const float FONT_HEADING3 = 11f;
        private const float FONT_BODY = 10f;
        private const float FONT_SMALL = 9f;
        private const float FONT_TABLE_HEADER = 10f;
        private const float FONT_TABLE_CELL = 9f;
        private const float FONT_STAT_VALUE = 16f;
        private const float FONT_RISK_BADGE = 16f;

        #endregion

        #region 颜色常量定义 - 专家级商业报告配色方案

        public static readonly BaseColor COLOR_PRIMARY = new BaseColor(26, 54, 93);
        public static readonly BaseColor COLOR_PRIMARY_LIGHT = new BaseColor(37, 99, 235);
        public static readonly BaseColor COLOR_HEADER_BG = new BaseColor(30, 41, 59);
        public static readonly BaseColor COLOR_BORDER = new BaseColor(226, 232, 240);
        public static readonly BaseColor COLOR_ZEBRA = new BaseColor(248, 250, 252);
        public static readonly BaseColor COLOR_TEXT = new BaseColor(55, 65, 81);
        public static readonly BaseColor COLOR_SECONDARY_TEXT = new BaseColor(100, 116, 139);
        public static readonly BaseColor COLOR_CONFIDENTIAL = new BaseColor(197, 48, 48);
        public static readonly BaseColor COLOR_GRAY_HINT = new BaseColor(148, 163, 184);
        public static readonly BaseColor COLOR_SEPARATOR = new BaseColor(203, 213, 225);

        public static readonly BaseColor COLOR_SUCCESS = new BaseColor(5, 150, 105);
        public static readonly BaseColor COLOR_WARNING = new BaseColor(217, 119, 6);
        public static readonly BaseColor COLOR_DANGER = new BaseColor(220, 38, 38);
        public static readonly BaseColor COLOR_CRITICAL = new BaseColor(153, 27, 27);
        public static readonly BaseColor COLOR_INFO_BG = new BaseColor(239, 246, 255);
        public static readonly BaseColor COLOR_CARD_BG = new BaseColor(250, 250, 252);

        #endregion

        #region 风险等级颜色方案字典

        public class RiskColorScheme
        {
            public BaseColor ForegroundColor { get; set; }
            public BaseColor BackgroundColor { get; set; }
            public string DisplayName { get; set; }
        }

        public static readonly Dictionary<string, RiskColorScheme> RiskColors = new Dictionary<string, RiskColorScheme>(StringComparer.OrdinalIgnoreCase)
        {
            {
                "严重", new RiskColorScheme
                {
                    ForegroundColor = new BaseColor(153, 27, 27),
                    BackgroundColor = new BaseColor(254, 226, 226),
                    DisplayName = "严重"
                }
            },
            {
                "critical", new RiskColorScheme
                {
                    ForegroundColor = new BaseColor(153, 27, 27),
                    BackgroundColor = new BaseColor(254, 226, 226),
                    DisplayName = "严重"
                }
            },
            {
                "高", new RiskColorScheme
                {
                    ForegroundColor = new BaseColor(194, 65, 12),
                    BackgroundColor = new BaseColor(254, 243, 199),
                    DisplayName = "高危"
                }
            },
            {
                "high", new RiskColorScheme
                {
                    ForegroundColor = new BaseColor(194, 65, 12),
                    BackgroundColor = new BaseColor(254, 243, 199),
                    DisplayName = "高危"
                }
            },
            {
                "中", new RiskColorScheme
                {
                    ForegroundColor = new BaseColor(217, 119, 6),
                    BackgroundColor = new BaseColor(254, 252, 232),
                    DisplayName = "中危"
                }
            },
            {
                "medium", new RiskColorScheme
                {
                    ForegroundColor = new BaseColor(217, 119, 6),
                    BackgroundColor = new BaseColor(254, 252, 232),
                    DisplayName = "中危"
                }
            },
            {
                "低", new RiskColorScheme
                {
                    ForegroundColor = new BaseColor(5, 150, 105),
                    BackgroundColor = new BaseColor(232, 245, 233),
                    DisplayName = "低危"
                }
            },
            {
                "low", new RiskColorScheme
                {
                    ForegroundColor = new BaseColor(5, 150, 105),
                    BackgroundColor = new BaseColor(232, 245, 233),
                    DisplayName = "低危"
                }
            },
            {
                "信息", new RiskColorScheme
                {
                    ForegroundColor = new BaseColor(37, 99, 235),
                    BackgroundColor = new BaseColor(239, 246, 255),
                    DisplayName = "信息"
                }
            },
            {
                "info", new RiskColorScheme
                {
                    ForegroundColor = new BaseColor(37, 99, 235),
                    BackgroundColor = new BaseColor(239, 246, 255),
                    DisplayName = "信息"
                }
            }
        };

        private static readonly RiskColorScheme DefaultRiskColor = new RiskColorScheme
        {
            ForegroundColor = new BaseColor(148, 163, 184),
            BackgroundColor = new BaseColor(248, 250, 252),
            DisplayName = "未分类"
        };

        #endregion

        #region 显示限制常量

        private const int MAX_VULNERABILITIES_PER_PAGE = 15;
        private const int MAX_DETAIL_BLOCKS = 10;
        private const int MAX_PORTS_DISPLAY = 500;
        private const int MAX_VULN_DISPLAY = 100;

        #endregion

        #region 字体集合容器

        public class FontCollection
        {
            public BaseFont BaseFont { get; set; }
            public Font TitleFont { get; set; }
            public Font SectionTitleFont { get; set; }
            public Font SubtitleFont { get; set; }
            public Font Heading2Font { get; set; }
            public Font Heading3Font { get; set; }
            public Font BodyFont { get; set; }
            public Font SmallFont { get; set; }
            public Font TableHeaderFont { get; set; }
            public Font TableCellFont { get; set; }
            public Font BoldBodyFont { get; set; }
            public Font StatValueFont { get; set; }
            public bool IsFallbackFont { get; set; } = false;
        }

        #endregion

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
            string tempPath = null;

            try
            {
                var directoryPath = Path.GetDirectoryName(savePath);
                if (!string.IsNullOrEmpty(directoryPath) && !Directory.Exists(directoryPath))
                    Directory.CreateDirectory(directoryPath);

                tempPath = Path.Combine(Path.GetTempPath(), $"report_temp_{Guid.NewGuid():N}.pdf");
                if (File.Exists(tempPath)) File.Delete(tempPath);

                using (var fs = new FileStream(tempPath, FileMode.Create, FileAccess.Write, FileShare.None))
                {
                    var doc = new Document(PageSize.A4, 55, 55, 70, 55);
                    var writer = PdfWriter.GetInstance(doc, fs);
                    writer.CloseStream = false;

                    var pageEvent = new HistoryReportPageEvent();
                    writer.PageEvent = pageEvent;

                    doc.Open();

                    var fonts = LoadChineseFonts();
                    if (fonts.BaseFont == null)
                        fonts = CreateFallbackFontCollection();

                    var reportId = record.ScanId ?? Guid.NewGuid().ToString("N").Substring(0, 8).ToUpper();
                    var scanTime = record.ScanTime.ToString("yyyy-MM-dd HH:mm:ss");
                    var reportGenerationTime = DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss");
                    var overallRiskLevel = CalculateOverallRiskLevel(safeVulns);
                    var scanDuration = record.ScanDuration > 0 ? $"{record.ScanDuration:F1} 秒" : "";

                    try { GenerateCoverPage(doc, writer, fonts, targetIp, scanTime, reportId, overallRiskLevel, safePorts, safeVulns, scanDuration, false); }
                    catch (Exception ex) { Debug.WriteLine($"[HistoryReport-ToPath] 封面页生成错误: {ex.Message}"); AddErrorPlaceholder(doc, fonts, "封面页", ex.Message); }
                    doc.NewPage();

                    try { GenerateTableOfContents(doc, writer, fonts); }
                    catch (Exception ex) { Debug.WriteLine($"[HistoryReport-ToPath] 目录页生成错误: {ex.Message}"); AddErrorPlaceholder(doc, fonts, "目录页", ex.Message); }
                    doc.NewPage();

                    try { GenerateExecutiveSummary(doc, fonts, safePorts, safeVulns, record.RiskAssessment, targetIp, reportGenerationTime); }
                    catch (Exception ex) { Debug.WriteLine($"[HistoryReport-ToPath] 执行摘要生成错误: {ex.Message}"); AddErrorPlaceholder(doc, fonts, "执行摘要", ex.Message); }
                    doc.NewPage();

                    try { GeneratePortScanResultsSection(doc, fonts, safePorts); }
                    catch (Exception ex) { Debug.WriteLine($"[HistoryReport-ToPath] 端口扫描结果生成错误: {ex.Message}"); AddErrorPlaceholder(doc, fonts, "端口扫描结果", ex.Message); }
                    doc.NewPage();

                    try { GenerateVulnerabilityDetailsSection(doc, fonts, safeVulns); }
                    catch (Exception ex) { Debug.WriteLine($"[HistoryReport-ToPath] 漏洞详情生成错误: {ex.Message}"); AddErrorPlaceholder(doc, fonts, "漏洞详情", ex.Message); }
                    doc.NewPage();

                    try { GenerateRiskAssessmentSection(doc, fonts, record.RiskAssessment, safeVulns, safePorts); }
                    catch (Exception ex) { Debug.WriteLine($"[HistoryReport-ToPath] 风险评估生成错误: {ex.Message}"); AddErrorPlaceholder(doc, fonts, "风险评估", ex.Message); }
                    doc.NewPage();

                    try { GenerateRemediationSection(doc, fonts, safeVulns); }
                    catch (Exception ex) { Debug.WriteLine($"[HistoryReport-ToPath] 修复建议生成错误: {ex.Message}"); AddErrorPlaceholder(doc, fonts, "修复建议", ex.Message); }
                    doc.NewPage();

                    try { GenerateThreatIntelligenceSection(doc, fonts, safeVulns, safePorts, targetIp); }
                    catch (Exception ex) { Debug.WriteLine($"[HistoryReport-ToPath] 威胁情报生成错误: {ex.Message}"); AddErrorPlaceholder(doc, fonts, "威胁情报", ex.Message); }
                    doc.NewPage();

                    try { GenerateComplianceSection(doc, fonts, safeVulns, safePorts); }
                    catch (Exception ex) { Debug.WriteLine($"[HistoryReport-ToPath] 合规参考生成错误: {ex.Message}"); AddErrorPlaceholder(doc, fonts, "合规参考", ex.Message); }
                    doc.NewPage();

                    try { GenerateConclusionSection(doc, fonts, safeVulns, safePorts, targetIp); }
                    catch (Exception ex) { Debug.WriteLine($"[HistoryReport-ToPath] 结论建议生成错误: {ex.Message}"); AddErrorPlaceholder(doc, fonts, "结论建议", ex.Message); }

                    doc.Close();
                    writer.Close();
                    fs.Close();
                }

                if (!ValidatePdfHeader(tempPath))
                    throw new InvalidDataException("生成的PDF文件格式验证失败，文件可能已损坏");

                File.Copy(tempPath, savePath, true);
                Debug.WriteLine($"[HistoryReport-ToPath] PDF报告生成成功：{savePath}");
                return savePath;
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"[HistoryReport-ToPath] 报告生成失败: {ex.Message}");
                throw;
            }
            finally
            {
                if (!string.IsNullOrEmpty(tempPath) && File.Exists(tempPath))
                {
                    try { File.Delete(tempPath); }
                    catch { }
                }
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

            var compositeRecord = new CompleteScanResult
            {
                ScanId = $"COMPOSITE-{Guid.NewGuid():N}".Substring(0, 20).ToUpper(),
                TargetIp = "多目标综合",
                ScanType = "综合扫描",
                ScanTime = records.Min(r => r.ScanTime),
                ScanDuration = records.Sum(r => r.ScanDuration),
                OpenPortsCount = mergedPorts.Count,
                VulnerabilitiesCount = mergedVulns.Count,
                RiskLevel = CalculateOverallRiskLevel(mergedVulns),
                PortScanResults = mergedPorts,
                VulnerabilityResults = mergedVulns,
                RiskAssessment = MergeRiskAssessments(records.Select(r => r.RiskAssessment).ToList())
            };

            return GenerateCompositeReportToPath(compositeRecord, records.Count, savePath);
        }

        private static string GenerateCompositeReportToPath(CompleteScanResult compositeRecord, int recordCount, string savePath)
        {
            var targetIp = compositeRecord.TargetIp;
            var safePorts = compositeRecord.PortScanResults ?? new List<PortScanResult>();
            var safeVulns = compositeRecord.VulnerabilityResults ?? new List<VulnerabilityResult>();
            string tempPath = null;

            try
            {
                var directoryPath = Path.GetDirectoryName(savePath);
                if (!string.IsNullOrEmpty(directoryPath) && !Directory.Exists(directoryPath))
                    Directory.CreateDirectory(directoryPath);

                tempPath = Path.Combine(Path.GetTempPath(), $"composite_temp_{Guid.NewGuid():N}.pdf");
                if (File.Exists(tempPath)) File.Delete(tempPath);

                using (var fs = new FileStream(tempPath, FileMode.Create, FileAccess.Write, FileShare.None))
                {
                    var doc = new Document(PageSize.A4, 55, 55, 70, 55);
                    var writer = PdfWriter.GetInstance(doc, fs);
                    writer.CloseStream = false;

                    var pageEvent = new HistoryReportPageEvent();
                    writer.PageEvent = pageEvent;

                    doc.Open();

                    var fonts = LoadChineseFonts();
                    if (fonts.BaseFont == null)
                        fonts = CreateFallbackFontCollection();

                    var reportId = compositeRecord.ScanId;
                    var scanTime = $"{compositeRecord.ScanTime:yyyy-MM-dd} ~ {DateTime.Now:yyyy-MM-dd}";
                    var reportGenerationTime = DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss");
                    var overallRiskLevel = compositeRecord.RiskLevel;
                    var scanDuration = $"{compositeRecord.ScanDuration:F1} 秒 (共{recordCount}次扫描)";

                    try { GenerateCoverPage(doc, writer, fonts, targetIp, scanTime, reportId, overallRiskLevel, safePorts, safeVulns, scanDuration, true); }
                    catch (Exception ex) { Debug.WriteLine($"[HistoryReport-ToPath] 综合报告封面页生成错误: {ex.Message}"); AddErrorPlaceholder(doc, fonts, "封面页", ex.Message); }
                    doc.NewPage();

                    try { GenerateTableOfContents(doc, writer, fonts); }
                    catch (Exception ex) { Debug.WriteLine($"[HistoryReport-ToPath] 综合报告目录页生成错误: {ex.Message}"); AddErrorPlaceholder(doc, fonts, "目录页", ex.Message); }
                    doc.NewPage();

                    try { GenerateExecutiveSummary(doc, fonts, safePorts, safeVulns, compositeRecord.RiskAssessment, targetIp, reportGenerationTime, recordCount); }
                    catch (Exception ex) { Debug.WriteLine($"[HistoryReport-ToPath] 综合报告执行摘要生成错误: {ex.Message}"); AddErrorPlaceholder(doc, fonts, "执行摘要", ex.Message); }
                    doc.NewPage();

                    try { GeneratePortScanResultsSection(doc, fonts, safePorts); }
                    catch (Exception ex) { Debug.WriteLine($"[HistoryReport-ToPath] 综合报告端口扫描结果生成错误: {ex.Message}"); AddErrorPlaceholder(doc, fonts, "端口扫描结果", ex.Message); }
                    doc.NewPage();

                    try { GenerateVulnerabilityDetailsSection(doc, fonts, safeVulns); }
                    catch (Exception ex) { Debug.WriteLine($"[HistoryReport-ToPath] 综合报告漏洞详情生成错误: {ex.Message}"); AddErrorPlaceholder(doc, fonts, "漏洞详情", ex.Message); }
                    doc.NewPage();

                    try { GenerateRiskAssessmentSection(doc, fonts, compositeRecord.RiskAssessment, safeVulns, safePorts); }
                    catch (Exception ex) { Debug.WriteLine($"[HistoryReport-ToPath] 综合报告风险评估生成错误: {ex.Message}"); AddErrorPlaceholder(doc, fonts, "风险评估", ex.Message); }
                    doc.NewPage();

                    try { GenerateRemediationSection(doc, fonts, safeVulns); }
                    catch (Exception ex) { Debug.WriteLine($"[HistoryReport-ToPath] 综合报告修复建议生成错误: {ex.Message}"); AddErrorPlaceholder(doc, fonts, "修复建议", ex.Message); }
                    doc.NewPage();

                    try { GenerateThreatIntelligenceSection(doc, fonts, safeVulns, safePorts, targetIp); }
                    catch (Exception ex) { Debug.WriteLine($"[HistoryReport-ToPath] 综合报告威胁情报生成错误: {ex.Message}"); AddErrorPlaceholder(doc, fonts, "威胁情报", ex.Message); }
                    doc.NewPage();

                    try { GenerateComplianceSection(doc, fonts, safeVulns, safePorts); }
                    catch (Exception ex) { Debug.WriteLine($"[HistoryReport-ToPath] 综合报告合规参考生成错误: {ex.Message}"); AddErrorPlaceholder(doc, fonts, "合规参考", ex.Message); }
                    doc.NewPage();

                    try { GenerateConclusionSection(doc, fonts, safeVulns, safePorts, targetIp); }
                    catch (Exception ex) { Debug.WriteLine($"[HistoryReport-ToPath] 综合报告结论建议生成错误: {ex.Message}"); AddErrorPlaceholder(doc, fonts, "结论建议", ex.Message); }

                    doc.Close();
                    writer.Close();
                    fs.Close();
                }

                if (!ValidatePdfHeader(tempPath))
                    throw new InvalidDataException("生成的综合PDF文件格式验证失败，文件可能已损坏");

                File.Copy(tempPath, savePath, true);
                Debug.WriteLine($"[HistoryReport-ToPath] 综合PDF报告生成成功：{savePath} (合并{recordCount}条记录)");
                return savePath;
            }
            finally
            {
                if (!string.IsNullOrEmpty(tempPath) && File.Exists(tempPath))
                {
                    try { File.Delete(tempPath); }
                    catch { }
                }
            }
        }

        public static string GenerateFromHistoryRecord(CompleteScanResult record)
        {
            if (record == null)
            {
                Debug.WriteLine("操作失败或数据为空，请查看日志获取详细信息");
                return string.Empty;
            }

            var safePorts = record.PortScanResults ?? new List<PortScanResult>();
            var safeVulns = record.VulnerabilityResults ?? new List<VulnerabilityResult>();

            if (!safePorts.Any() && !safeVulns.Any())
            {
                Debug.WriteLine("操作失败或数据为空，请查看日志获取详细信息");
                return string.Empty;
            }

            var targetIp = string.IsNullOrWhiteSpace(record.TargetIp) ? "未知目标" : record.TargetIp;

            try
            {
                var reportDir = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "Reports");
                if (!Directory.Exists(reportDir))
                    Directory.CreateDirectory(reportDir);

                var fileName = $"HistorySecurityReport_{targetIp.Replace(".", "_")}_{DateTime.Now:yyyyMMdd_HHmmss}.pdf";
                var filePath = Path.Combine(reportDir, fileName);
                var tempPath = filePath + ".tmp";

                if (File.Exists(tempPath)) File.Delete(tempPath);
                if (File.Exists(filePath)) File.Delete(filePath);

                using (var fs = new FileStream(tempPath, FileMode.Create, FileAccess.Write, FileShare.None))
                {
                    var doc = new Document(PageSize.A4, 55, 55, 70, 55);
                    var writer = PdfWriter.GetInstance(doc, fs);
                    writer.CloseStream = false;

                    var pageEvent = new HistoryReportPageEvent();
                    writer.PageEvent = pageEvent;

                    doc.Open();

                    var fonts = LoadChineseFonts();
                    if (fonts.BaseFont == null)
                    {
                        Debug.WriteLine("[HistoryReport] 警告：所有中文字体加载失败，将使用Helvetica回退字体");
                        fonts = CreateFallbackFontCollection();
                    }

                    var reportId = record.ScanId ?? Guid.NewGuid().ToString("N").Substring(0, 8).ToUpper();
                    var scanTime = record.ScanTime.ToString("yyyy-MM-dd HH:mm:ss");
                    var reportGenerationTime = DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss");
                    var overallRiskLevel = CalculateOverallRiskLevel(safeVulns);
                    var scanDuration = record.ScanDuration > 0 ? $"{record.ScanDuration:F1} 秒" : "";

                    GenerateCoverPage(doc, writer, fonts, targetIp, scanTime, reportId, overallRiskLevel,
                        safePorts, safeVulns, scanDuration, false);
                    doc.NewPage();

                    GenerateTableOfContents(doc, writer, fonts);
                    doc.NewPage();

                    GenerateExecutiveSummary(doc, fonts, safePorts, safeVulns,
                        record.RiskAssessment, targetIp, reportGenerationTime);
                    doc.NewPage();

                    GeneratePortScanResultsSection(doc, fonts, safePorts);
                    doc.NewPage();

                    GenerateVulnerabilityDetailsSection(doc, fonts, safeVulns);
                    doc.NewPage();

                    GenerateRiskAssessmentSection(doc, fonts, record.RiskAssessment, safeVulns, safePorts);
                    doc.NewPage();

                    GenerateRemediationSection(doc, fonts, safeVulns);

                    doc.Close();
                    writer.Close();
                    fs.Close();

                    File.Move(tempPath, filePath, true);
                    Debug.WriteLine($"[HistoryReport] 专业PDF报告生成成功：{filePath}");
                    return filePath;
                }
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"[HistoryReport] 报告生成失败: {ex.Message}");
                Debug.WriteLine("操作失败或数据为空，请查看日志获取详细信息");
                return string.Empty;
            }
        }

        public static string GenerateFromMultipleRecords(List<CompleteScanResult> records)
        {
            if (records == null || !records.Any())
            {
                Debug.WriteLine("操作失败或数据为空，请查看日志获取详细信息");
                return string.Empty;
            }

            try
            {
                var mergedPorts = records
                    .SelectMany(r => r.PortScanResults ?? new List<PortScanResult>())
                    .GroupBy(p => p?.PortNumber ?? 0)
                    .Select(g => g.First())
                    .OrderBy(p => p.PortNumber)
                    .ToList();

                var mergedVulns = records
                    .SelectMany(r => r.VulnerabilityResults ?? new List<VulnerabilityResult>())
                    .GroupBy(v => v?.CveId ?? v?.Name ?? Guid.NewGuid().ToString())
                    .Select(g =>
                    {
                        var best = g.OrderByDescending(v => GetRiskPriority(v?.RiskLevel)).First();
                        return best;
                    })
                    .OrderByDescending(v => GetRiskPriority(v?.RiskLevel))
                    .ToList();

                if (!mergedPorts.Any() && !mergedVulns.Any())
                {
                    Debug.WriteLine("操作失败或数据为空，请查看日志获取详细信息");
                    return string.Empty;
                }

                var compositeRecord = new CompleteScanResult
                {
                    ScanId = $"COMPOSITE-{Guid.NewGuid():N}".Substring(0, 20).ToUpper(),
                    TargetIp = "多目标综合",
                    ScanType = "综合扫描",
                    ScanTime = records.Min(r => r.ScanTime),
                    ScanDuration = records.Sum(r => r.ScanDuration),
                    OpenPortsCount = mergedPorts.Count,
                    VulnerabilitiesCount = mergedVulns.Count,
                    RiskLevel = CalculateOverallRiskLevel(mergedVulns),
                    PortScanResults = mergedPorts,
                    VulnerabilityResults = mergedVulns,
                    RiskAssessment = MergeRiskAssessments(records.Select(r => r.RiskAssessment).ToList())
                };

                return GenerateCompositeReport(compositeRecord, records.Count);
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"[HistoryReport] 多记录合并报告生成失败: {ex.Message}");
                Debug.WriteLine("操作失败或数据为空，请查看日志获取详细信息");
                return string.Empty;
            }
        }

        private static string GenerateCompositeReport(CompleteScanResult compositeRecord, int recordCount)
        {
            var targetIp = compositeRecord.TargetIp;
            var safePorts = compositeRecord.PortScanResults ?? new List<PortScanResult>();
            var safeVulns = compositeRecord.VulnerabilityResults ?? new List<VulnerabilityResult>();

            var reportDir = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "Reports");
            if (!Directory.Exists(reportDir))
                Directory.CreateDirectory(reportDir);

            var fileName = $"CompositeSecurityReport_{DateTime.Now:yyyyMMdd_HHmmss}.pdf";
            var filePath = Path.Combine(reportDir, fileName);
            var tempPath = filePath + ".tmp";

            if (File.Exists(tempPath)) File.Delete(tempPath);
            if (File.Exists(filePath)) File.Delete(filePath);

            using (var fs = new FileStream(tempPath, FileMode.Create, FileAccess.Write, FileShare.None))
            {
                var doc = new Document(PageSize.A4, 55, 55, 70, 55);
                var writer = PdfWriter.GetInstance(doc, fs);
                writer.CloseStream = false;

                var pageEvent = new HistoryReportPageEvent();
                writer.PageEvent = pageEvent;

                doc.Open();

                var fonts = LoadChineseFonts();
                if (fonts.BaseFont == null)
                {
                    fonts = CreateFallbackFontCollection();
                }

                var reportId = compositeRecord.ScanId;
                var scanTime = $"{compositeRecord.ScanTime:yyyy-MM-dd} ~ {DateTime.Now:yyyy-MM-dd}";
                var reportGenerationTime = DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss");
                var overallRiskLevel = compositeRecord.RiskLevel;
                var scanDuration = $"{compositeRecord.ScanDuration:F1} 秒 (共{recordCount}次扫描)";

                GenerateCoverPage(doc, writer, fonts, targetIp, scanTime, reportId, overallRiskLevel,
                    safePorts, safeVulns, scanDuration, true);
                doc.NewPage();

                GenerateTableOfContents(doc, writer, fonts);
                doc.NewPage();

                GenerateExecutiveSummary(doc, fonts, safePorts, safeVulns,
                    compositeRecord.RiskAssessment, targetIp, reportGenerationTime, recordCount);
                doc.NewPage();

                GeneratePortScanResultsSection(doc, fonts, safePorts);
                doc.NewPage();

                GenerateVulnerabilityDetailsSection(doc, fonts, safeVulns);
                doc.NewPage();

                GenerateRiskAssessmentSection(doc, fonts, compositeRecord.RiskAssessment, safeVulns, safePorts);
                doc.NewPage();

                GenerateRemediationSection(doc, fonts, safeVulns);

                doc.Close();
                writer.Close();
                fs.Close();

                File.Move(tempPath, filePath, true);
                Debug.WriteLine($"[HistoryReport] 综合PDF报告生成成功：{filePath} (合并{recordCount}条记录)");
                return filePath;
            }
        }

        #endregion

        #region 字体加载系统

        private static FontCollection LoadChineseFonts()
        {
            var fonts = new FontCollection();
            BaseFont bf = null;
            bool fontLoaded = false;

            if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            {
                string[] windowsFontPaths = {
                    @"C:\Windows\Fonts\msyh.ttc,0",
                    @"C:\Windows\Fonts\simhei.ttf",
                    @"C:\Windows\Fonts\simsun.ttc,0",
                    @"C:\Windows\Fonts\msyhbd.ttc,0",
                    @"C:\Windows\Fonts\simkai.ttf"
                };

                foreach (var fontPath in windowsFontPaths)
                {
                    try
                    {
                        if (File.Exists(fontPath.Split(',')[0]))
                        {
                            bf = BaseFont.CreateFont(fontPath, BaseFont.IDENTITY_H, BaseFont.EMBEDDED);
                            Debug.WriteLine($"[HistoryReport-字体] 成功加载: {fontPath}");
                            fontLoaded = true;
                            break;
                        }
                    }
                    catch (Exception ex)
                    {
                        Debug.WriteLine($"[HistoryReport-字体] 加载失败: {fontPath} - {ex.Message}");
                    }
                }
            }
            else if (RuntimeInformation.IsOSPlatform(OSPlatform.Linux))
            {
                string[] linuxFontPaths = {
                    "/usr/share/fonts/opentype/noto/NotoSansCJK-Regular.ttc",
                    "/usr/share/fonts/opentype/noto/NotoSansCJKsc-Regular.otf",
                    "/usr/share/fonts/truetype/wqy/wqy-microhei.ttc",
                    "/usr/share/fonts/truetype/wqy/wqy-zenhei.ttc",
                    "/usr/share/fonts/truetype/droid/DroidSansFallbackFull.ttf",
                    "/usr/share/fonts/truetype/liberation/LiberationSans-Regular.ttf",
                    "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf",
                    "/usr/share/fonts/opentype/noto/NotoSans-Regular.otf"
                };

                foreach (var fontPath in linuxFontPaths)
                {
                    try
                    {
                        if (File.Exists(fontPath))
                        {
                            bf = BaseFont.CreateFont(fontPath, BaseFont.IDENTITY_H, BaseFont.EMBEDDED);
                            Debug.WriteLine($"[HistoryReport-字体] 成功加载: {fontPath}");
                            fontLoaded = true;
                            break;
                        }
                    }
                    catch (Exception ex)
                    {
                        Debug.WriteLine($"[HistoryReport-字体] 加载失败: {fontPath} - {ex.Message}");
                    }
                }
            }
            else if (RuntimeInformation.IsOSPlatform(OSPlatform.OSX))
            {
                string[] macFontPaths = {
                    "/System/Library/Fonts/PingFang.ttc",
                    "/System/Library/Fonts/STHeiti Light.ttc",
                    "/Library/Fonts/Arial Unicode.ttf"
                };

                foreach (var fontPath in macFontPaths)
                {
                    try
                    {
                        if (File.Exists(fontPath))
                        {
                            bf = BaseFont.CreateFont(fontPath, BaseFont.IDENTITY_H, BaseFont.EMBEDDED);
                            Debug.WriteLine($"[HistoryReport-字体] 成功加载: {fontPath}");
                            fontLoaded = true;
                            break;
                        }
                    }
                    catch (Exception ex)
                    {
                        Debug.WriteLine($"[HistoryReport-字体] 加载失败: {fontPath} - {ex.Message}");
                    }
                }
            }

            if (!fontLoaded)
            {
                try
                {
                    bf = BaseFont.CreateFont(BaseFont.HELVETICA, BaseFont.CP1252, false);
                    Debug.WriteLine("[HistoryReport-字体] 使用Helvetica作为最终回退字体");
                    fonts.IsFallbackFont = true;
                }
                catch (Exception ex)
                {
                    Debug.WriteLine($"[HistoryReport-字体] Helvetica回退也失败: {ex.Message}");
                }
            }

            if (bf != null)
            {
                fonts.BaseFont = bf;
                fonts.TitleFont = new Font(bf, FONT_TITLE_MAIN, Font.BOLD, COLOR_PRIMARY);
                fonts.SectionTitleFont = new Font(bf, FONT_TITLE_SECTION, Font.BOLD, COLOR_PRIMARY);
                fonts.SubtitleFont = new Font(bf, FONT_SUBTITLE, Font.NORMAL, COLOR_SECONDARY_TEXT);
                fonts.Heading2Font = new Font(bf, FONT_HEADING2, Font.BOLD, new BaseColor(52, 73, 94));
                fonts.Heading3Font = new Font(bf, FONT_HEADING3, Font.BOLD, new BaseColor(85, 85, 85));
                fonts.BodyFont = new Font(bf, FONT_BODY, Font.NORMAL, COLOR_TEXT);
                fonts.SmallFont = new Font(bf, FONT_SMALL, Font.NORMAL, COLOR_GRAY_HINT);
                fonts.TableHeaderFont = new Font(bf, FONT_TABLE_HEADER, Font.BOLD, BaseColor.WHITE);
                fonts.TableCellFont = new Font(bf, FONT_TABLE_CELL, Font.NORMAL, BaseColor.DARK_GRAY);
                fonts.BoldBodyFont = new Font(bf, FONT_BODY, Font.BOLD, BaseColor.BLACK);
                fonts.StatValueFont = new Font(bf, FONT_STAT_VALUE, Font.BOLD, BaseColor.BLACK);
            }

            return fonts;
        }

        private static FontCollection CreateFallbackFontCollection()
        {
            var fonts = new FontCollection();
            fonts.IsFallbackFont = true;

            fonts.BaseFont = null;
            fonts.TitleFont = new Font(Font.FontFamily.HELVETICA, FONT_TITLE_MAIN, Font.BOLD, COLOR_PRIMARY);
            fonts.SectionTitleFont = new Font(Font.FontFamily.HELVETICA, FONT_TITLE_SECTION, Font.BOLD, COLOR_PRIMARY);
            fonts.SubtitleFont = new Font(Font.FontFamily.HELVETICA, FONT_SUBTITLE, Font.NORMAL, COLOR_SECONDARY_TEXT);
            fonts.Heading2Font = new Font(Font.FontFamily.HELVETICA, FONT_HEADING2, Font.BOLD, new BaseColor(52, 73, 94));
            fonts.Heading3Font = new Font(Font.FontFamily.HELVETICA, FONT_HEADING3, Font.BOLD, new BaseColor(85, 85, 85));
            fonts.BodyFont = new Font(Font.FontFamily.HELVETICA, FONT_BODY, Font.NORMAL, COLOR_TEXT);
            fonts.SmallFont = new Font(Font.FontFamily.HELVETICA, FONT_SMALL, Font.NORMAL, COLOR_GRAY_HINT);
            fonts.TableHeaderFont = new Font(Font.FontFamily.HELVETICA, FONT_TABLE_HEADER, Font.BOLD, BaseColor.WHITE);
            fonts.TableCellFont = new Font(Font.FontFamily.HELVETICA, FONT_TABLE_CELL, Font.NORMAL, BaseColor.DARK_GRAY);
            fonts.BoldBodyFont = new Font(Font.FontFamily.HELVETICA, FONT_BODY, Font.BOLD, BaseColor.BLACK);
            fonts.StatValueFont = new Font(Font.FontFamily.HELVETICA, FONT_STAT_VALUE, Font.BOLD, BaseColor.BLACK);

            Debug.WriteLine("[HistoryReport-字体] 已创建基于Helvetica的回退字体配置（中文可能显示异常）");
            return fonts;
        }

        #endregion

        #region 表格单元格工厂方法（核心修改：强制使用Rectangle.BOX）

        private static PdfPCell CreateCell(string text, Font font, BaseColor bgColor,
            int alignment = Element.ALIGN_LEFT, int border = Rectangle.BOX)
        {
            return new PdfPCell(new Phrase(text ?? "-", font))
            {
                BackgroundColor = bgColor,
                HorizontalAlignment = alignment,
                VerticalAlignment = Element.ALIGN_MIDDLE,
                Padding = 6,
                Border = border,
                BorderColor = COLOR_BORDER,
                BorderWidth = 0.5f
            };
        }

        private static PdfPCell CreateHeaderCell(string text, Font font)
        {
            return new PdfPCell(new Phrase(text, font))
            {
                BackgroundColor = COLOR_HEADER_BG,
                HorizontalAlignment = Element.ALIGN_CENTER,
                VerticalAlignment = Element.ALIGN_MIDDLE,
                Padding = 8,
                Border = Rectangle.BOX,
                BorderColor = COLOR_HEADER_BG,
                BorderWidth = 0.5f
            };
        }

        private static PdfPCell CreateRiskCell(string text, Font font, RiskColorScheme riskScheme)
        {
            return new PdfPCell(new Phrase(text, font))
            {
                BackgroundColor = riskScheme.BackgroundColor,
                HorizontalAlignment = Element.ALIGN_CENTER,
                VerticalAlignment = Element.ALIGN_MIDDLE,
                Padding = 6,
                Border = Rectangle.BOX,
                BorderColor = riskScheme.ForegroundColor,
                BorderWidth = 0.5f
            };
        }

        private static PdfPCell CreateEnhancedRiskCell(string text, Font font, RiskColorScheme riskScheme)
        {
            return new PdfPCell(new Phrase(text, font))
            {
                BackgroundColor = riskScheme.ForegroundColor,
                HorizontalAlignment = Element.ALIGN_CENTER,
                VerticalAlignment = Element.ALIGN_MIDDLE,
                Padding = 6,
                Border = Rectangle.BOX,
                BorderColor = riskScheme.ForegroundColor,
                BorderWidth = 1f
            };
        }

        private static BaseColor GetCvssColor(double score)
        {
            if (score >= 9.0) return new BaseColor(153, 27, 27);
            if (score >= 7.0) return new BaseColor(220, 38, 38);
            if (score >= 4.0) return new BaseColor(245, 158, 11);
            if (score > 0) return new BaseColor(5, 150, 105);
            return COLOR_GRAY_HINT;
        }

        #endregion

        #region 第1章：封面页生成 - 使用DirectContent精确绘制

        private static void GenerateCoverPage(Document doc, PdfWriter writer, FontCollection fonts, string targetIp,
            string scanTime, string reportId, string overallRiskLevel,
            List<PortScanResult> ports, List<VulnerabilityResult> vulns,
            string scanDuration, bool isComposite = false)
        {
            var cb = writer.DirectContent;
            var deepBlue = new BaseColor(26, 54, 93);

            // 1. 顶部装饰条 - 使用Rectangle填充
            cb.SetColorFill(deepBlue);
            cb.Rectangle(0, 797, 595, 45); // x, y, width, height
            cb.Fill();

            // 装饰条上的白色文字
            cb.BeginText();
            cb.SetFontAndSize(fonts.BaseFont, 10);
            cb.SetColorFill(BaseColor.WHITE);
            cb.ShowTextAligned(Element.ALIGN_CENTER, "SECURITY ASSESSMENT REPORT", 297, 810, 0);
            cb.EndText();

            // 2. 主标题区域 - 使用ColumnText精确定位
            var mainTitleText = isComposite ? "网络安全综合扫描评估报告" : "网络安全漏洞扫描评估报告";

            // 中文主标题 - 20pt粗体深蓝色居中
            cb.BeginText();
            cb.SetFontAndSize(fonts.BaseFont, 20);
            cb.SetColorFill(deepBlue);
            cb.ShowTextAligned(Element.ALIGN_CENTER, mainTitleText, 297, 700, 0);
            cb.EndText();

            // 英文副标题 - 12pt灰色居中
            cb.BeginText();
            cb.SetFontAndSize(fonts.BaseFont, 12);
            cb.SetColorFill(COLOR_SECONDARY_TEXT);
            cb.ShowTextAligned(Element.ALIGN_CENTER, "Network Security Vulnerability Assessment Report", 297, 678, 0);
            cb.EndText();

            // 3. 信息表格 - 创建PdfPTable后用table.WriteSelectedRows()绝对定位
            var infoTable = new PdfPTable(2);
            infoTable.TotalWidth = 350;
            infoTable.SetWidths(new float[] { 1.5f, 2.5f });

            var safeTargetIp = string.IsNullOrWhiteSpace(targetIp) ? "未知目标" : targetIp;
            var safeScanTime = string.IsNullOrWhiteSpace(scanTime) ? DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss") : scanTime;
            var safeReportId = string.IsNullOrWhiteSpace(reportId) ? "N/A" : reportId;

            AddInfoRow(infoTable, "报告编号:", $"RPT-{DateTime.Now:yyyyMMdd}-{safeReportId}", fonts.BoldBodyFont, fonts.BodyFont);
            AddInfoRow(infoTable, "目标系统:", $"{safeTargetIp} ({(isComposite ? "多目标综合" : "内网服务器")})", fonts.BoldBodyFont, fonts.BodyFont);
            AddInfoRow(infoTable, "扫描时间:", safeScanTime, fonts.BoldBodyFont, fonts.BodyFont);
            AddInfoRow(infoTable, "扫描类型:", isComposite ? "综合扫描" : "全面漏洞扫描", fonts.BoldBodyFont, fonts.BodyFont);

            if (!string.IsNullOrEmpty(scanDuration))
            {
                AddInfoRow(infoTable, "扫描耗时:", scanDuration, fonts.BoldBodyFont, fonts.BodyFont);
            }

            AddInfoRow(infoTable, "报告生成:", DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss"), fonts.BoldBodyFont, fonts.BodyFont);

            infoTable.WriteSelectedRows(0, -1, 122, 560, cb); // 绝对定位起始y=560

            // 4. 统计卡片区域 - 同样使用WriteSelectedRows定位
            var statsContainer = new PdfPTable(4);
            statsContainer.TotalWidth = 480;
            statsContainer.SetWidths(new float[] { 1f, 1f, 1f, 1f });

            var openPortCount = ports?.Count(p => p?.Status == "开放" || p?.Status?.ToLower() == "open") ?? 0;
            var vulnCount = vulns?.Count ?? 0;
            var safeRiskLevel = string.IsNullOrWhiteSpace(overallRiskLevel) ? "信息" : overallRiskLevel;
            var riskColorScheme = GetRiskColorScheme(safeRiskLevel);

            var highRiskVulnCount = vulns?.Count(v => IsCritical(v?.RiskLevel) || IsHigh(v?.RiskLevel)) ?? 0;
            var highRiskPercent = vulnCount > 0 ? (int)((double)highRiskVulnCount / vulnCount * 100) : 0;

            AddExpertStatCard(statsContainer, "风险等级", riskColorScheme.DisplayName, riskColorScheme.ForegroundColor, fonts);
            AddExpertStatCard(statsContainer, "开放端口", $"{openPortCount}个", new BaseColor(52, 152, 219), fonts);
            AddExpertStatCard(statsContainer, "漏洞总数", $"{vulnCount}个", new BaseColor(220, 38, 38), fonts);
            AddExpertStatCard(statsContainer, "高危占比", $"{highRiskPercent}%", new BaseColor(243, 156, 18), fonts);

            statsContainer.WriteSelectedRows(0, -1, 57, 420, cb); // 绝对定位起始y=420

            // 5. 分隔线
            DrawSeparatorLine(cb, 280, 1.0f, COLOR_SEPARATOR);

            // 6. 底部信息 - 使用cb.ShowTextAligned()
            // 版本信息
            cb.BeginText();
            cb.SetFontAndSize(fonts.BaseFont, 9);
            cb.SetColorFill(COLOR_GRAY_HINT);
            cb.ShowTextAligned(Element.ALIGN_CENTER, $"NetSecurityScanner v{VersionHelper.GetVersion()}", 297, 80, 0);
            cb.EndText();

            // 机密标识(红色)
            cb.BeginText();
            cb.SetFontAndSize(fonts.BaseFont, 9);
            cb.SetColorFill(COLOR_CONFIDENTIAL);
            cb.ShowTextAligned(Element.ALIGN_CENTER, "机密 - 仅限内部使用 - Confidential", 297, 60, 0);
            cb.EndText();
        }

        private static void AddExpertStatCard(PdfPTable table, string label, string value, BaseColor accentColor, FontCollection fonts)
        {
            var cardCell = new PdfPCell();
            cardCell.Border = Rectangle.BOX;
            cardCell.BorderColor = accentColor;
            cardCell.BorderWidth = 1.2f;
            cardCell.Padding = 10;
            cardCell.VerticalAlignment = Element.ALIGN_MIDDLE;
            cardCell.BackgroundColor = BaseColor.WHITE;

            var content = new Paragraph()
            {
                Alignment = Element.ALIGN_CENTER,
                SpacingBefore = 3,
                SpacingAfter = 3
            };

            var labelPhrase = new Phrase(label, new Font(fonts.BaseFont, 9, Font.NORMAL, COLOR_SECONDARY_TEXT));
            var valuePhrase = new Phrase($"\n{value}", new Font(fonts.BaseFont, 17, Font.BOLD, accentColor));

            content.Add(labelPhrase);
            content.Add(valuePhrase);

            cardCell.Phrase = content;
            table.AddCell(cardCell);
        }

        private static void AddInfoRow(PdfPTable table, string label, string value, Font labelFont, Font valueFont)
        {
            var labelCell = new PdfPCell(new Phrase(label, labelFont))
            {
                Border = Rectangle.BOX,
                BorderColor = COLOR_BORDER,
                BorderWidth = 0.5f,
                HorizontalAlignment = Element.ALIGN_RIGHT,
                PaddingRight = 10,
                VerticalAlignment = Element.ALIGN_MIDDLE
            };

            var valueCell = new PdfPCell(new Phrase(value, valueFont))
            {
                Border = Rectangle.BOX,
                BorderColor = COLOR_BORDER,
                BorderWidth = 0.5f,
                HorizontalAlignment = Element.ALIGN_LEFT,
                PaddingLeft = 5,
                VerticalAlignment = Element.ALIGN_MIDDLE
            };

            table.AddCell(labelCell);
            table.AddCell(valueCell);
        }

        #endregion

        #region 第2章：目录页生成 - 使用固定坐标定位+专业格式

        private static void GenerateTableOfContents(Document doc, PdfWriter writer, FontCollection fonts)
        {
            var cb = writer.DirectContent;
            var deepBlue = new BaseColor(26, 54, 93);
            var darkGray = new BaseColor(30, 41, 59);
            var separatorColor = new BaseColor(203, 213, 225);

            // 标题 - 目 录 (18pt粗体深蓝色居中)
            cb.BeginText();
            cb.SetFontAndSize(fonts.BaseFont, 18);
            cb.SetColorFill(deepBlue);
            cb.ShowTextAligned(Element.ALIGN_CENTER, "目  录", 297, 770, 0);
            cb.EndText();

            // 英文副标题 - Table of Contents (11pt灰色居中)
            cb.BeginText();
            cb.SetFontAndSize(fonts.BaseFont, 11);
            cb.SetColorFill(COLOR_SECONDARY_TEXT);
            cb.ShowTextAligned(Element.ALIGN_CENTER, "Table of Contents", 297, 750, 0);
            cb.EndText();

            // 上分隔线 - 粗线(1.5pt)
            cb.SetColorStroke(deepBlue);
            cb.SetLineWidth(1.5f);
            cb.MoveTo(80, 735);
            cb.LineTo(515, 735);
            cb.Stroke();

            // 目录项表格 - 使用PdfPTable + WriteSelectedRows绝对定位
            var tocTable = new PdfPTable(3); // 序号/章节名/页码
            tocTable.TotalWidth = 450;
            tocTable.SetWidths(new float[] { 0.8f, 3.5f, 0.7f });

            var chapterFont = new Font(fonts.BaseFont, 11, Font.NORMAL, COLOR_TEXT);
            var subChapterFont = new Font(fonts.BaseFont, 10, Font.NORMAL, COLOR_TEXT);
            var pageFont = new Font(fonts.BaseFont, 11, Font.BOLD, darkGray);
            var subPageFont = new Font(fonts.BaseFont, 10, Font.BOLD, darkGray);
            var dotColor = new BaseColor(200, 210, 220);
            var dotFont = new Font(fonts.BaseFont, 9, Font.NORMAL, dotColor);

            var tocEntries = new[]
            {
                (Title: "第一章  执行摘要", Page: "3", IsChapter: true),
                (Title: "  1.1  核心统计数据", Page: "3", IsChapter: false),
                (Title: "  1.2  Top 5 高危漏洞", Page: "4", IsChapter: false),
                (Title: "  1.3  服务分布摘要", Page: "4", IsChapter: false),

                (Title: "第二章  端口扫描结果", Page: "5", IsChapter: true),

                (Title: "第三章  漏洞详情分析", Page: "7", IsChapter: true),
                (Title: "  3.1  漏洞概览表", Page: "7", IsChapter: false),
                (Title: "  3.2  漏洞详细信息", Page: "9", IsChapter: false),

                (Title: "第四章  风险评估汇总", Page: "11", IsChapter: true),
                (Title: "  4.1  风险评估项目", Page: "11", IsChapter: false),
                (Title: "  4.2  风险分布可视化", Page: "12", IsChapter: false),
                (Title: "  4.3  安全建议概述", Page: "12", IsChapter: false),

                (Title: "第五章  修复建议与安全加固", Page: "13", IsChapter: true),
                (Title: "  5.1  修复优先级矩阵", Page: "13", IsChapter: false),
                (Title: "  5.2  高危漏洞修复建议", Page: "14", IsChapter: false),
                (Title: "  5.3  通用安全加固建议", Page: "15", IsChapter: false),

                (Title: "附录 A  术语说明", Page: "16", IsChapter: true),
                (Title: "附录 B  参考链接", Page: "16", IsChapter: true)
            };

            foreach (var entry in tocEntries)
            {
                var titleCell = new PdfPCell();
                titleCell.Border = Rectangle.NO_BORDER;
                titleCell.PaddingBottom = entry.IsChapter ? 8 : 5;
                titleCell.PaddingTop = entry.IsChapter ? 10 : 6;
                titleCell.PaddingLeft = entry.IsChapter ? 15 : 30;

                var titlePara = new Paragraph();
                var titleFont = entry.IsChapter ? chapterFont : subChapterFont;
                titlePara.Add(new Phrase(entry.Title, titleFont));

                var maxDots = entry.IsChapter ? 50 : 40;
                var dotCount = Math.Max(5, maxDots - entry.Title.Length * 2);
                var dots = new string('.', dotCount);
                titlePara.Add(new Phrase(dots, dotFont));
                titlePara.Add(new Phrase(entry.Page, entry.IsChapter ? pageFont : subPageFont));

                titleCell.Phrase = titlePara;
                tocTable.AddCell(titleCell);
            }

            tocTable.WriteSelectedRows(0, -1, 72, 700, cb); // 绝对定位起始y=700

            // 下分隔线 - 细线(0.5pt)
            cb.SetColorStroke(separatorColor);
            cb.SetLineWidth(0.5f);
            cb.MoveTo(80, 120);
            cb.LineTo(515, 120);
            cb.Stroke();

            // 免责声明 - 使用ColumnText精确定位
            var disclaimerCT = new ColumnText(cb);
            disclaimerCT.SetSimpleColumn(72, 60, 523, 110);

            var disclaimerText = "⚠️ 免责声明：本报告由自动化安全扫描工具生成，结果仅供参考。" +
                                 "对于关键安全问题，建议进行人工验证和深度分析。";

            var disclaimerPara = new Paragraph(disclaimerText,
                new Font(fonts.BaseFont, 8, Font.NORMAL, COLOR_GRAY_HINT))
            {
                Alignment = Element.ALIGN_CENTER,
                Leading = 12
            };
            disclaimerCT.AddElement(disclaimerPara);
            disclaimerCT.Go();
        }

        #endregion

        #region 第3章：执行摘要章节

        private static void GenerateExecutiveSummary(Document doc, FontCollection fonts,
            List<PortScanResult> ports, List<VulnerabilityResult> vulns,
            RiskAssessmentSummary riskAssessment, string targetIp,
            string reportGenerationTime, int compositeRecordCount = 0)
        {
            doc.Add(new Paragraph("一、执行摘要", fonts.SectionTitleFont)
            {
                SpacingBefore = 20,
                SpacingAfter = 12
            });

            var introText = "本节提供本次安全扫描的核心发现和统计概览，帮助快速了解目标系统的整体安全态势。";
            if (compositeRecordCount > 0)
            {
                introText = $"本报告综合了{compositeRecordCount}次独立扫描的结果，提供跨时间段的安全态势分析。";
            }

            var introPara = new Paragraph(introText, fonts.BodyFont)
            {
                SpacingBefore = 10,
                SpacingAfter = 15,
                IndentationLeft = 20,
                Leading = 15,
                Alignment = Element.ALIGN_JUSTIFIED
            };
            doc.Add(introPara);

            doc.Add(new Paragraph("1.1 核心统计数据", fonts.Heading2Font)
            {
                SpacingBefore = 15,
                SpacingAfter = 8
            });

            var safePorts = ports ?? new List<PortScanResult>();
            var safeVulns = vulns ?? new List<VulnerabilityResult>();

            var openPorts = safePorts.Where(p =>
                p?.Status == "开放" || p?.Status?.ToLower() == "open" ||
                p?.Status?.ToLower() == "open|filtered").ToList();
            var totalPorts = safePorts.Count;

            var statsTable = new PdfPTable(4);
            statsTable.WidthPercentage = 100;
            statsTable.SetWidths(new float[] { 1f, 1f, 1f, 1f });
            statsTable.SpacingBefore = 8;

            var overallRiskLevel = CalculateOverallRiskLevel(safeVulns);
            var riskColorScheme = GetRiskColorScheme(overallRiskLevel);

            AddStatCard(statsTable, "总体风险等级", riskColorScheme.DisplayName,
                riskColorScheme.ForegroundColor, fonts);

            AddStatCard(statsTable, "开放端口数", $"{openPorts.Count}/{totalPorts}",
                new BaseColor(52, 152, 219), fonts);

            AddStatCard(statsTable, "发现漏洞总数", $"{safeVulns.Count}",
                new BaseColor(231, 76, 60), fonts);

            var highRiskPercent = safeVulns.Any() ?
                (int)((double)(safeVulns.Count(v => IsCritical(v?.RiskLevel) || IsHigh(v?.RiskLevel))) /
                safeVulns.Count * 100) : 0;
            AddStatCard(statsTable, "高危漏洞占比", $"{highRiskPercent}%",
                new BaseColor(243, 156, 18), fonts);

            doc.Add(statsTable);

            if (!string.IsNullOrEmpty(reportGenerationTime))
            {
                doc.Add(new Paragraph($"\n报告生成时间: {reportGenerationTime}", fonts.SmallFont)
                {
                    SpacingBefore = 10,
                    IndentationLeft = 20,
                    Alignment = Element.ALIGN_RIGHT
                });
            }

            if (safeVulns.Any())
            {
                doc.Add(new Paragraph("\n1.2 Top 5 高危漏洞", fonts.Heading2Font)
                {
                    SpacingBefore = 18,
                    SpacingAfter = 8
                });

                var topVulns = safeVulns
                    .OrderByDescending(v => GetRiskPriority(v?.RiskLevel))
                    .Take(5)
                    .ToList();

                var topVulnTable = new PdfPTable(4);
                topVulnTable.WidthPercentage = 100;
                topVulnTable.SetWidths(new float[] { 0.6f, 2.8f, 1.3f, 1.2f });
                topVulnTable.SpacingBefore = 5;
                topVulnTable.HeaderRows = 1;

                AddTableHeader(topVulnTable, new[] { "#", "漏洞名称", "风险等级", "CVE编号" }, fonts);

                int index = 1;
                foreach (var vuln in topVulns)
                {
                    var isZebra = index % 2 == 0;
                    var safeName = string.IsNullOrWhiteSpace(vuln?.Name) ? "未知漏洞" : vuln.Name;
                    var safeRiskLevel = string.IsNullOrWhiteSpace(vuln?.RiskLevel) ? "未分类" : vuln.RiskLevel;
                    var safeCveId = string.IsNullOrWhiteSpace(vuln?.CveId) ? "-" : vuln.CveId;

                    AddTopVulnRow(topVulnTable, index++, safeName, safeRiskLevel, safeCveId, fonts, isZebra);
                }

                doc.Add(topVulnTable);
            }

            if (safePorts.Any())
            {
                doc.Add(new Paragraph("\n1.3 服务分布摘要", fonts.Heading2Font)
                {
                    SpacingBefore = 18,
                    SpacingAfter = 8
                });

                var serviceGroups = openPorts
                    .Where(p => !string.IsNullOrEmpty(p?.Service))
                    .GroupBy(p => p.Service)
                    .OrderByDescending(g => g.Count())
                    .Take(8)
                    .ToList();

                var serviceTable = new PdfPTable(3);
                serviceTable.WidthPercentage = 60;
                serviceTable.SetWidths(new float[] { 2f, 1f, 1.5f });
                serviceTable.SpacingBefore = 5;
                serviceTable.HeaderRows = 1;

                AddTableHeader(serviceTable, new[] { "服务名称", "实例数量", "关联端口" }, fonts);

                int svcIdx = 1;
                foreach (var grp in serviceGroups)
                {
                    var isZebra = svcIdx % 2 == 0;
                    var cellBg = isZebra ? COLOR_ZEBRA : BaseColor.WHITE;

                    var portListBuilder = new StringBuilder();
                    var portNumbers = grp.Select(p => p.PortNumber).Take(3).ToList();
                    for (int i = 0; i < portNumbers.Count; i++)
                    {
                        if (i > 0) portListBuilder.Append(", ");
                        portListBuilder.Append(portNumbers[i].ToString());
                    }

                    serviceTable.AddCell(CreateCell(grp.Key ?? "-", fonts.TableCellFont, cellBg));
                    serviceTable.AddCell(CreateCell(grp.Count().ToString(), fonts.TableCellFont, cellBg, Element.ALIGN_CENTER));
                    serviceTable.AddCell(CreateCell(portListBuilder.ToString(), fonts.TableCellFont, cellBg));
                    svcIdx++;
                }

                doc.Add(serviceTable);
            }
        }

        private static void AddStatCard(PdfPTable table, string label, string value, BaseColor accentColor, FontCollection fonts)
        {
            var outerCell = new PdfPCell();
            outerCell.Border = Rectangle.BOX;
            outerCell.BorderColor = accentColor;
            outerCell.BorderWidth = 1f;
            outerCell.Padding = 12;
            outerCell.VerticalAlignment = Element.ALIGN_MIDDLE;
            outerCell.BackgroundColor = new BaseColor(250, 250, 252);

            var innerPara = new Paragraph()
            {
                Alignment = Element.ALIGN_CENTER,
                SpacingBefore = 5,
                SpacingAfter = 5
            };
            innerPara.Add(new Phrase($"{label}\n", fonts.SmallFont));
            innerPara.Add(new Phrase(value, new Font(fonts.BaseFont, FONT_STAT_VALUE, Font.BOLD, accentColor)));

            outerCell.Phrase = innerPara;
            table.AddCell(outerCell);
        }

        private static void AddTopVulnRow(PdfPTable table, int index, string name, string riskLevel,
            string cveId, FontCollection fonts, bool isZebra)
        {
            var bg = isZebra ? COLOR_ZEBRA : BaseColor.WHITE;

            table.AddCell(CreateCell(index.ToString(), fonts.TableCellFont, bg, Element.ALIGN_CENTER));
            table.AddCell(CreateCell(name, fonts.TableCellFont, bg));

            var riskScheme = GetRiskColorScheme(riskLevel);
            var riskFont = new Font(fonts.BaseFont, 9, Font.BOLD, riskScheme.ForegroundColor);
            table.AddCell(CreateRiskCell(riskScheme.DisplayName, riskFont, riskScheme));

            table.AddCell(CreateCell(cveId ?? "-", fonts.TableCellFont, bg, Element.ALIGN_CENTER));
        }

        #endregion

        #region 第4章：端口扫描结果表

        private static void GeneratePortScanResultsSection(Document doc, FontCollection fonts, List<PortScanResult> results)
        {
            doc.Add(new Paragraph("二、端口扫描结果", fonts.SectionTitleFont)
            {
                SpacingBefore = 20,
                SpacingAfter = 12
            });

            var introPara = new Paragraph(
                "本节列出所有检测到的开放端口及其对应的服务信息。仅展示状态为开放的端口。",
                fonts.BodyFont)
            {
                SpacingBefore = 10,
                SpacingAfter = 15,
                IndentationLeft = 20,
                Leading = 15,
                Alignment = Element.ALIGN_JUSTIFIED
            };
            doc.Add(introPara);

            var safeResults = results ?? new List<PortScanResult>();

            var openPorts = safeResults
                .Where(p => p?.Status == "开放" || p?.Status?.ToLower() == "open" ||
                       p?.Status?.ToLower() == "open|filtered")
                .OrderBy(p => p.PortNumber)
                .ToList();

            if (!openPorts.Any())
            {
                doc.Add(new Paragraph("未发现开放端口。", fonts.BodyFont) { SpacingBefore = 20 });
                return;
            }

            bool hasMorePorts = openPorts.Count > MAX_PORTS_DISPLAY;
            var displayPorts = hasMorePorts ? openPorts.Take(MAX_PORTS_DISPLAY).ToList() : openPorts;

            var table = new PdfPTable(6);
            table.WidthPercentage = 100;
            table.SetWidths(new float[] { 1f, 1f, 1.8f, 2f, 1f, 1.2f });
            table.SpacingBefore = 8;
            table.HeaderRows = 1;

            AddTableHeader(table, new[]
            {
                "端口号", "协议", "服务名称", "版本", "状态", "响应时间"
            }, fonts);

            int rowIndex = 1;
            foreach (var port in displayPorts)
            {
                try
                {
                    var isZebra = rowIndex % 2 == 0;
                    var bg = isZebra ? COLOR_ZEBRA : BaseColor.WHITE;

                    var portNumber = port?.PortNumber ?? 0;
                    var service = string.IsNullOrWhiteSpace(port?.Service) ? "-" : port.Service;
                    var serviceVersion = string.IsNullOrWhiteSpace(port?.ServiceVersion) ? "-" : port.ServiceVersion;
                    var status = string.IsNullOrWhiteSpace(port?.Status) ? "未知" : port.Status;
                    var responseTime = string.IsNullOrWhiteSpace(port?.ResponseTime) ? "-" : port.ResponseTime;

                    table.AddCell(CreateCell(portNumber.ToString(), fonts.TableCellFont, bg, Element.ALIGN_CENTER));
                    table.AddCell(CreateCell("TCP", fonts.TableCellFont, bg, Element.ALIGN_CENTER));
                    table.AddCell(CreateCell(service, fonts.TableCellFont, bg));
                    table.AddCell(CreateCell(serviceVersion, fonts.SmallFont, bg));

                    var statusColor = GetPortStatusColor(status);
                    var statusFont = new Font(fonts.BaseFont, 9, Font.BOLD, statusColor);
                    table.AddCell(CreateCell(status, statusFont, bg, Element.ALIGN_CENTER));

                    table.AddCell(CreateCell(responseTime, fonts.SmallFont, bg, Element.ALIGN_CENTER));

                    rowIndex++;
                }
                catch (Exception ex)
                {
                    Debug.WriteLine($"[HistoryReport-端口表] 行添加失败 (索引{rowIndex}): {ex.Message}");
                }
            }

            doc.Add(table);

            var statsText = $"\n共计 {openPorts.Count} 个开放端口已列出";
            if (hasMorePorts)
            {
                statsText += $"（注：共发现{openPorts.Count}个开放端口，本报告展示前{MAX_PORTS_DISPLAY}个）";
            }
            statsText += "。";

            doc.Add(new Paragraph(statsText,
                new Font(fonts.BaseFont, 9, Font.NORMAL, COLOR_GRAY_HINT))
            {
                SpacingBefore = 10,
                IndentationLeft = 20
            });
        }

        private static BaseColor GetPortStatusColor(string status)
        {
            if (string.IsNullOrEmpty(status)) return new BaseColor(149, 165, 166);
            var s = status.ToLower();
            if (s.Contains("open")) return new BaseColor(39, 174, 96);
            if (s.Contains("close")) return new BaseColor(149, 165, 166);
            if (s.Contains("filter")) return new BaseColor(241, 196, 15);
            return new BaseColor(149, 165, 166);
        }

        #endregion

        #region 第5章：漏洞详情主表 - 专家级实心彩色标题栏+左侧竖线+5段式结构

        private static void GenerateVulnerabilityDetailsSection(Document doc, FontCollection fonts,
            List<VulnerabilityResult> vulnerabilities)
        {
            doc.Add(new Paragraph("三、漏洞详情分析", fonts.SectionTitleFont)
            {
                SpacingBefore = 20,
                SpacingAfter = 12
            });

            var introPara = new Paragraph(
                "本节详细列出所有检测到的安全漏洞，按风险等级从高到低排列。" +
                "每个漏洞均附带描述、检测方法和修复建议。",
                fonts.BodyFont)
            {
                SpacingBefore = 10,
                SpacingAfter = 15,
                IndentationLeft = 20,
                Leading = 15,
                Alignment = Element.ALIGN_JUSTIFIED
            };
            doc.Add(introPara);

            var safeVulnerabilities = vulnerabilities ?? new List<VulnerabilityResult>();

            if (!safeVulnerabilities.Any())
            {
                doc.Add(new Paragraph("未发现安全漏洞。", fonts.BodyFont) { SpacingBefore = 20 });
                return;
            }

            bool hasMoreVulns = safeVulnerabilities.Count > MAX_VULN_DISPLAY;
            var displayVulns = hasMoreVulns ?
                safeVulnerabilities.Take(MAX_VULN_DISPLAY).ToList() : safeVulnerabilities;

            var sortedVulns = displayVulns
                .OrderByDescending(v => GetRiskPriority(v?.RiskLevel))
                .ToList();

            var table = new PdfPTable(7);
            table.WidthPercentage = 100;
            table.SetWidths(new float[] { 0.7f, 1.4f, 2.5f, 1f, 0.8f, 1.3f, 0.8f });
            table.SpacingBefore = 8;
            table.HeaderRows = 1;

            AddTableHeader(table, new[]
            {
                "序号", "CVE编号", "漏洞名称", "风险等级", "端口", "服务", "CVSS评分"
            }, fonts);

            int index = 1;
            foreach (var vuln in sortedVulns)
            {
                try
                {
                    var isZebra = index % 2 == 0;
                    var bg = isZebra ? COLOR_ZEBRA : BaseColor.WHITE;

                    var cveId = string.IsNullOrWhiteSpace(vuln?.CveId) ? "-" : vuln.CveId;
                    var name = string.IsNullOrWhiteSpace(vuln?.Name) ? "未知漏洞" : vuln.Name;
                    var riskLevel = string.IsNullOrWhiteSpace(vuln?.RiskLevel) ? "未分类" : vuln.RiskLevel;
                    var port = vuln?.Port.HasValue == true ? vuln.Port.Value.ToString() : "-";
                    var service = string.IsNullOrWhiteSpace(vuln?.Service) ? "-" : vuln.Service;

                    table.AddCell(CreateCell(index.ToString(), fonts.TableCellFont, bg, Element.ALIGN_CENTER));
                    table.AddCell(CreateCell(cveId, fonts.TableCellFont, bg, Element.ALIGN_CENTER));
                    table.AddCell(CreateCell(name, fonts.TableCellFont, bg));

                    var riskScheme = GetRiskColorScheme(riskLevel);
                    var riskFont = new Font(fonts.BaseFont, 9, Font.BOLD, riskScheme.ForegroundColor);
                    table.AddCell(CreateEnhancedRiskCell(riskScheme.DisplayName, riskFont, riskScheme));

                    table.AddCell(CreateCell(port, fonts.TableCellFont, bg, Element.ALIGN_CENTER));
                    table.AddCell(CreateCell(service, fonts.TableCellFont, bg));

                    var cvssScore = EstimateCvssScore(riskLevel);
                    var cvssColor = GetCvssColor(cvssScore);
                    var cvssFont = new Font(fonts.BaseFont, 9, Font.BOLD, cvssColor);
                    table.AddCell(CreateCell(cvssScore.ToString("F1"), cvssFont, bg, Element.ALIGN_CENTER));

                    index++;
                }
                catch (Exception ex)
                {
                    Debug.WriteLine($"[HistoryReport-漏洞表] 行添加失败 (索引{index}): {ex.Message}");
                }
            }

            doc.Add(table);

            if (hasMoreVulns)
            {
                var noteText = $"\n注：共发现 {safeVulnerabilities.Count} 个漏洞，" +
                    $"本报告展示前 {MAX_VULN_DISPLAY} 个高危漏洞的详细信息。" +
                    "如需查看完整列表，请导出原始数据或联系管理员。";

                doc.Add(new Paragraph(noteText,
                    new Font(fonts.BaseFont, 9, Font.NORMAL, new BaseColor(255, 152, 0)))
                {
                    SpacingBefore = 15,
                    IndentationLeft = 20,
                    IndentationRight = 20
                });
            }

            doc.Add(new Paragraph("\n3.1 漏洞详细信息（前10个）", fonts.Heading2Font)
            {
                SpacingBefore = 18,
                SpacingAfter = 8
            });

            int detailIndex = 1;
            int maxDetails = Math.Min(MAX_DETAIL_BLOCKS, sortedVulns.Count);
            foreach (var vuln in sortedVulns.Take(maxDetails))
            {
                try
                {
                    AddVulnerabilityDetailBlock(doc, fonts, vuln, detailIndex++);
                }
                catch (Exception ex)
                {
                    Debug.WriteLine($"[HistoryReport-详情块] 生成失败 (索引{detailIndex}): {ex.Message}");
                }
            }
        }

        private static void AddVulnerabilityDetailBlock(Document doc, FontCollection fonts,
            VulnerabilityResult vuln, int detailIndex = 0)
        {
            if (vuln == null)
            {
                Debug.WriteLine("[HistoryReport-详情块] 警告：漏洞对象为null，跳过");
                return;
            }

            var riskLevel = string.IsNullOrWhiteSpace(vuln.RiskLevel) ? "未分类" : vuln.RiskLevel;
            var riskScheme = GetRiskColorScheme(riskLevel);

            var container = new PdfPTable(1);
            container.WidthPercentage = 100;
            container.SpacingBefore = 10;
            container.SpacingAfter = 10;

            // === 标题行（彩色背景）===
            var titleCell = new PdfPCell() {
                BackgroundColor = riskScheme.ForegroundColor, // 实心彩色！
                Border = Rectangle.BOX,
                BorderColor = riskScheme.ForegroundColor,
                Padding = 10
            };
            var titlePara = new Paragraph();
            titlePara.Leading = 16;
            
            var indexPrefix = detailIndex > 0 ? $"● [{detailIndex}] " : "● ";
            var name = string.IsNullOrWhiteSpace(vuln.Name) ? "未知漏洞" : vuln.Name;
            
            titlePara.Add(new Phrase($"{indexPrefix}{name}", 
                new Font(fonts.BaseFont, 11, Font.BOLD, BaseColor.WHITE)));
            
            if (!string.IsNullOrWhiteSpace(vuln.CveId))
                titlePara.Add(new Phrase($" ({vuln.CveId})", 
                    new Font(fonts.BaseFont, 9, Font.NORMAL, BaseColor.WHITE)));
            
            // 右侧风险徽章
            titlePara.Add(new Phrase($"  [{riskScheme.DisplayName}]", 
                new Font(fonts.BaseFont, 10, Font.BOLD, BaseColor.WHITE)));
                
            titleCell.Phrase = titlePara;
            container.AddCell(titleCell);

            // === 内容区（左侧彩色竖线）===
            var contentCell = new PdfPCell() {
                Border = Rectangle.BOX,
                BorderColor = new BaseColor(226, 232, 240),
                BorderWidthLeft = 3f, // 左侧3pt宽彩色竖线
                BorderColorLeft = riskScheme.ForegroundColor,
                Padding = 12,
                BackgroundColor = BaseColor.WHITE
            };
            
            var content = new Paragraph();
            content.Leading = 16; // 行距
            
            // 【漏洞概述】段
            content.Add(new Phrase("\n【漏洞概述】\n", 
                new Font(fonts.BaseFont, 11, Font.BOLD, new BaseColor(30, 41, 59))));
            content.Add(new Paragraph(GetSafeString(vuln.Description), fonts.BodyFont));
            
            // 【基本信息】- 内嵌小表格
            content.Add(new Phrase("\n【基本信息】\n", 
                new Font(fonts.BaseFont, 11, Font.BOLD, new BaseColor(30, 41, 59))));
            
            var infoInnerTable = new PdfPTable(2);
            infoInnerTable.WidthPercentage = 100;
            infoInnerTable.SetWidths(new float[] { 1.2f, 2.5f });
            
            var cvssScore = EstimateCvssScore(riskLevel);
            var labelFont = new Font(fonts.BaseFont, 9, Font.NORMAL, COLOR_SECONDARY_TEXT);
            var valueFont = new Font(fonts.BaseFont, 9, Font.BOLD, COLOR_TEXT);
            
            AddInfoPair(infoInnerTable, "CVSS评分:", $"{cvssScore:F1} ({riskScheme.DisplayName})", labelFont, valueFont);
            
            var portStr = vuln?.Port.HasValue == true ? $"TCP/{vuln.Port.Value}" : "N/A";
            var svcStr = string.IsNullOrWhiteSpace(vuln?.Service) ? "-" : vuln.Service;
            AddInfoPair(infoInnerTable, "影响端口:", $"{portStr} ({svcStr})", labelFont, valueFont);
            AddInfoPair(infoInnerTable, "影响服务:", GetSafeString(vuln?.Service), labelFont, valueFont);
            AddInfoPair(infoInnerTable, "风险等级:", riskScheme.DisplayName,
                new Font(fonts.BaseFont, 9, Font.BOLD, riskScheme.ForegroundColor), valueFont);
                
            content.Add(infoInnerTable);
            
            // 【检测方法】段
            if (!string.IsNullOrWhiteSpace(vuln.DetectionMethod))
            {
                content.Add(new Phrase("\n【检测方法】\n", 
                    new Font(fonts.BaseFont, 11, Font.BOLD, new BaseColor(30, 41, 59))));
                content.Add(new Paragraph(GetSafeString(vuln.DetectionMethod), fonts.BodyFont));
            }
            
            // 【修复方案】段 - 支持多方案分行
            content.Add(new Phrase("\n【修复方案】\n", 
                new Font(fonts.BaseFont, 11, Font.BOLD, new BaseColor(30, 41, 59))));
            var solution = GetSafeString(vuln.Solution ?? "请参考官方安全公告获取补丁信息");
            // 将解决方案按换行符分割为多个段落
            foreach (var line in solution.Split('\n').Where(l => !string.IsNullOrWhiteSpace(l)))
            {
                content.Add(new Paragraph($"  • {line.Trim()}", fonts.BodyFont));
            }
            
            // 【参考链接】段 - 蓝色样式
            if (!string.IsNullOrWhiteSpace(vuln.References))
            {
                content.Add(new Phrase("\n【参考链接】\n", 
                    new Font(fonts.BaseFont, 11, Font.BOLD, new BaseColor(30, 41, 59))));
                var linkFont = new Font(fonts.BaseFont, 9, Font.UNDERLINE, new BaseColor(37, 99, 235));
                content.Add(new Phrase($"  • {GetSafeString(vuln.References)}", linkFont));
            }
            
            contentCell.Phrase = content;
            container.AddCell(contentCell);
            
            doc.Add(container);
        }

        private static void AddInfoPair(PdfPTable table, string label, string value, Font labelFont, Font valueFont)
        {
            table.AddCell(new PdfPCell(new Phrase(label, labelFont)) {
                Border = Rectangle.BOX, BorderColor = new BaseColor(226, 232, 240),
                HorizontalAlignment = Element.ALIGN_LEFT, Padding = 4
            });
            table.AddCell(new PdfPCell(new Phrase(value, valueFont)) {
                Border = Rectangle.BOX, BorderColor = new BaseColor(226, 232, 240),
                HorizontalAlignment = Element.ALIGN_LEFT, Padding = 4
            });
        }

        private static double EstimateCvssScore(string riskLevel)
        {
            if (string.IsNullOrEmpty(riskLevel)) return 0.0;
            if (IsCritical(riskLevel)) return 9.5;
            if (IsHigh(riskLevel)) return 7.5;
            if (IsMedium(riskLevel)) return 5.5;
            if (IsLow(riskLevel)) return 3.0;
            return 1.0;
        }

        #endregion

        #region 第6章：风险评估展示

        private static void GenerateRiskAssessmentSection(Document doc, FontCollection fonts,
            RiskAssessmentSummary riskAssessment, List<VulnerabilityResult> vulns,
            List<PortScanResult> ports)
        {
            doc.Add(new Paragraph("四、风险评估汇总", fonts.SectionTitleFont)
            {
                SpacingBefore = 20,
                SpacingAfter = 12
            });

            var introPara = new Paragraph(
                "本节对本次扫描发现的各类风险进行综合评估和分析。",
                fonts.BodyFont)
            {
                SpacingBefore = 10,
                SpacingAfter = 15,
                IndentationLeft = 20,
                Leading = 15,
                Alignment = Element.ALIGN_JUSTIFIED
            };
            doc.Add(introPara);

            doc.Add(new Paragraph("4.1 风险评估项目", fonts.Heading2Font)
            {
                SpacingBefore = 15,
                SpacingAfter = 8
            });

            if (riskAssessment != null && !string.IsNullOrEmpty(riskAssessment.RiskLevel))
            {
                var riskItems = new[]
                {
                    new { Item = "整体风险评级", Value = riskAssessment.RiskLevel, Status = "" },
                    new { Item = "风险评分", Value = $"{riskAssessment.RiskScore}/100", Status = "" },
                    new { Item = "漏洞总量", Value = riskAssessment.TotalVulnerabilities.ToString(), Status = "" },
                    new { Item = "高风险漏洞", Value = riskAssessment.HighRiskCount.ToString(), Status = "" },
                    new { Item = "中风险漏洞", Value = riskAssessment.MediumRiskCount.ToString(), Status = "" },
                    new { Item = "低风险漏洞", Value = riskAssessment.LowRiskCount.ToString(), Status = "" }
                };

                GenerateRiskTable(doc, fonts, riskItems);
            }
            else
            {
                GenerateAutoRiskAssessment(doc, fonts, vulns, ports);
            }

            doc.Add(new Paragraph("\n4.2 风险分布", fonts.Heading2Font)
            {
                SpacingBefore = 18,
                SpacingAfter = 8
            });

            if (vulns != null && vulns.Any())
            {
                var total = vulns.Count;
                var categories = new[]
                {
                    new { Label = "严重", Count = vulns.Count(v => IsCritical(v.RiskLevel)), Color = new BaseColor(244, 67, 54) },
                    new { Label = "高危", Count = vulns.Count(v => IsHigh(v.RiskLevel)), Color = new BaseColor(255, 152, 0) },
                    new { Label = "中危", Count = vulns.Count(v => IsMedium(v.RiskLevel)), Color = new BaseColor(255, 193, 7) },
                    new { Label = "低危", Count = vulns.Count(v => IsLow(v.RiskLevel)), Color = new BaseColor(76, 175, 80) },
                    new { Label = "信息", Count = total - vulns.Count(v => IsCritical(v.RiskLevel) || IsHigh(v.RiskLevel) || IsMedium(v.RiskLevel) || IsLow(v.RiskLevel)), Color = new BaseColor(33, 150, 243) }
                };

                var validCategories = categories.Where(c => c.Count > 0).ToList();
                if (validCategories.Any())
                {
                    var chartTable = new PdfPTable(2);
                    chartTable.WidthPercentage = 90;
                    chartTable.SetWidths(new float[] { 2.5f, 2.5f });
                    chartTable.SpacingBefore = 5;

                    var pieCell = new PdfPCell();
                    pieCell.Border = Rectangle.BOX;
                    pieCell.BorderColor = COLOR_BORDER;
                    pieCell.BorderWidth = 0.5f;
                    pieCell.Padding = 10;
                    pieCell.BackgroundColor = new BaseColor(252, 252, 252);
                    pieCell.FixedHeight = 160;

                    var pieImage = GeneratePieChart(validCategories.Select(c => (c.Label, c.Count, c.Color)).ToList(), fonts);
                    if (pieImage != null)
                    {
                        pieImage.Alignment = Element.ALIGN_CENTER;
                        pieCell.AddElement(pieImage);
                    }
                    else
                    {
                        pieCell.AddElement(new Paragraph("风险分布图", new Font(fonts.BaseFont, 10, Font.BOLD, COLOR_TEXT)) { Alignment = Element.ALIGN_CENTER });
                    }
                    chartTable.AddCell(pieCell);

                    var legendCell = new PdfPCell();
                    legendCell.Border = Rectangle.BOX;
                    legendCell.BorderColor = COLOR_BORDER;
                    legendCell.BorderWidth = 0.5f;
                    legendCell.Padding = 10;
                    legendCell.BackgroundColor = new BaseColor(252, 252, 252);

                    var legendContent = new Paragraph();
                    legendContent.Add(new Phrase("漏洞风险分布\n\n", new Font(fonts.BaseFont, 11, Font.BOLD, COLOR_TEXT)));
                    foreach (var cat in validCategories)
                    {
                        var percent = (double)cat.Count / total * 100;
                        legendContent.Add(new Phrase("■ ", new Font(fonts.BaseFont, 12, Font.BOLD, cat.Color)));
                        legendContent.Add(new Phrase($"{cat.Label}: {cat.Count}个 ({percent:F1}%)\n", fonts.BodyFont));
                    }
                    legendContent.Add(new Phrase($"\n总计: {total}个漏洞", new Font(fonts.BaseFont, 10, Font.BOLD, COLOR_PRIMARY)));
                    legendCell.Phrase = legendContent;
                    chartTable.AddCell(legendCell);

                    doc.Add(chartTable);
                }

                doc.Add(new Paragraph("\n风险等级进度条：", new Font(fonts.BaseFont, 10, Font.BOLD, COLOR_TEXT))
                {
                    SpacingBefore = 12,
                    SpacingAfter = 5
                });

                foreach (var cat in categories)
                {
                    if (cat.Count <= 0) continue;

                    var percent = (double)cat.Count / total * 100;

                    var rowTable = new PdfPTable(2);
                    rowTable.WidthPercentage = 80;
                    rowTable.SetWidths(new float[] { 1f, 3f });
                    rowTable.SpacingBefore = 3;

                    var labelCell = new PdfPCell(new Phrase(
                        $"{cat.Label}: {cat.Count} ({percent:F1}%)",
                        fonts.TableCellFont))
                    {
                        Border = Rectangle.BOX,
                        BorderColor = COLOR_BORDER,
                        BorderWidth = 0.5f,
                        HorizontalAlignment = Element.ALIGN_LEFT,
                        VerticalAlignment = Element.ALIGN_MIDDLE
                    };

                    var barCell = new PdfPCell()
                    {
                        Border = Rectangle.BOX,
                        BorderColor = new BaseColor(220, 220, 220),
                        BorderWidth = 0.5f,
                        Padding = 3,
                        FixedHeight = 18
                    };

                    var barPhrase = new Paragraph();
                    var filledBlocks = Math.Max(1, (int)(percent / 5));
                    var emptyBlocks = 20 - filledBlocks;
                    barPhrase.Add(new Phrase(new string('█', filledBlocks) + new string('░', emptyBlocks),
                        new Font(fonts.BaseFont, 8, Font.NORMAL, cat.Color)));
                    barPhrase.Add(new Phrase($" {percent:F1}%", fonts.SmallFont));
                    barCell.Phrase = barPhrase;

                    rowTable.AddCell(labelCell);
                    rowTable.AddCell(barCell);
                    doc.Add(rowTable);
                }
            }

            doc.Add(new Paragraph("\n4.3 安全建议概述", fonts.Heading2Font)
            {
                SpacingBefore = 18,
                SpacingAfter = 8
            });

            var suggestions = new[]
            {
                "立即修复所有严重和高危级别的漏洞，尤其是远程代码执行类漏洞",
                "关闭不必要的服务和端口，减少攻击面",
                "及时更新系统和应用软件至最新版本",
                "实施强密码策略和多因素认证(MFA)",
                "配置防火墙规则限制网络访问",
                "定期进行安全扫描和渗透测试",
                "建立安全事件应急响应流程"
            };

            foreach (var suggestion in suggestions)
            {
                var bulletPara = new Paragraph()
                {
                    SpacingBefore = 4,
                    SpacingAfter = 4,
                    IndentationLeft = 30
                };
                bulletPara.Add(new Phrase("* ", fonts.BoldBodyFont));
                bulletPara.Add(new Phrase(suggestion, fonts.BodyFont));
                doc.Add(bulletPara);
            }
        }

        private static void GenerateRiskTable<T>(Document doc, FontCollection fonts, IEnumerable<T> riskItems)
        {
            var riskTable = new PdfPTable(3);
            riskTable.WidthPercentage = 80;
            riskTable.SetWidths(new float[] { 2.5f, 1.5f, 1.2f });
            riskTable.SpacingBefore = 5;
            riskTable.HeaderRows = 1;

            AddTableHeader(riskTable, new[] { "评估项目", "风险值", "状态" }, fonts);

            int idx = 1;
            foreach (dynamic item in riskItems)
            {
                var isZebra = idx % 2 == 0;
                var bg = isZebra ? COLOR_ZEBRA : BaseColor.WHITE;

                var itemName = item.Item?.ToString() ?? "-";
                var itemValue = item.Value?.ToString() ?? "-";

                riskTable.AddCell(CreateCell(itemName, fonts.TableCellFont, bg));
                riskTable.AddCell(CreateCell(itemValue, fonts.TableCellFont, bg, Element.ALIGN_CENTER));

                var statusText = item.Status?.ToString() ?? "-";
                var statusColor = statusText.Contains("高") ? new BaseColor(231, 76, 60) :
                                  statusText.Contains("中") ? new BaseColor(243, 156, 18) :
                                  statusText.Contains("低") ? new BaseColor(46, 204, 113) :
                                  new BaseColor(149, 165, 166);

                var statusFont = new Font(fonts.BaseFont, 9, Font.BOLD, statusColor);
                riskTable.AddCell(CreateCell(statusText, statusFont, bg, Element.ALIGN_CENTER));
                idx++;
            }

            doc.Add(riskTable);
        }

        private static void GenerateAutoRiskAssessment(Document doc, FontCollection fonts,
            List<VulnerabilityResult> vulns, List<PortScanResult> ports)
        {
            var autoItems = new[]
            {
                new { Item = "漏洞总量", Value = (vulns?.Count ?? 0).ToString(), Status = "" },
                new { Item = "高危漏洞数", Value = (vulns?.Count(v => IsCritical(v.RiskLevel) || IsHigh(v.RiskLevel)) ?? 0).ToString(), Status = "" },
                new { Item = "开放端口数", Value = (ports?.Count(p => p.Status == "开放" || p.Status.ToLower() == "open") ?? 0).ToString(), Status = "" },
                new { Item = "敏感端口暴露", Value = "待人工确认", Status = "" },
                new { Item = "整体安全评级", Value = CalculateOverallRiskLevel(vulns), Status = "" }
            };

            GenerateRiskTable(doc, fonts, autoItems);
        }

        #endregion

        #region 第7章：修复建议章节

        private static void GenerateRemediationSection(Document doc, FontCollection fonts,
            List<VulnerabilityResult> vulns)
        {
            doc.Add(new Paragraph("五、修复建议与安全加固", fonts.SectionTitleFont)
            {
                SpacingBefore = 20,
                SpacingAfter = 12
            });

            var introPara = new Paragraph(
                "本节提供针对发现的安全问题的具体修复建议和通用安全加固措施。",
                fonts.BodyFont)
            {
                SpacingBefore = 10,
                SpacingAfter = 15,
                IndentationLeft = 20,
                Leading = 15,
                Alignment = Element.ALIGN_JUSTIFIED
            };
            doc.Add(introPara);

            doc.Add(new Paragraph("5.1 修复优先级矩阵", fonts.Heading2Font)
            {
                SpacingBefore = 15,
                SpacingAfter = 8
            });

            var priorityTable = new PdfPTable(4);
            priorityTable.WidthPercentage = 90;
            priorityTable.SetWidths(new float[] { 1f, 2.2f, 2.2f, 1.8f });
            priorityTable.SpacingBefore = 5;
            priorityTable.HeaderRows = 1;

            AddTableHeader(priorityTable, new[] { "优先级", "处理时限", "适用范围", "建议措施" }, fonts);

            var priorities = new[]
            {
                new { Prio = "P1-紧急", Timeframe = "24小时内", Scope = "严重/远程执行类", Action = "立即隔离受影响系统", PrioColor = new BaseColor(231, 76, 60) },
                new { Prio = "P2-高", Timeframe = "7天内", Scope = "高危/权限提升类", Action = "尽快安排维护窗口", PrioColor = new BaseColor(243, 156, 18) },
                new { Prio = "P3-中", Timeframe = "30天内", Scope = "中危/信息泄露类", Action = "纳入常规更新计划", PrioColor = new BaseColor(241, 196, 15) },
                new { Prio = "P4-低", Timeframe = "下个周期", Scope = "低危/信息类", Action = "持续监控", PrioColor = new BaseColor(46, 204, 113) }
            };

            int prioIdx = 1;
            foreach (var priorityItem in priorities)
            {
                var isZebra = prioIdx % 2 == 0;
                var bg = isZebra ? COLOR_ZEBRA : BaseColor.WHITE;

                var prioFont = new Font(fonts.BaseFont, 9, Font.BOLD, priorityItem.PrioColor);
                priorityTable.AddCell(CreateCell(priorityItem.Prio, prioFont, bg, Element.ALIGN_CENTER));
                priorityTable.AddCell(CreateCell(priorityItem.Timeframe, fonts.TableCellFont, bg, Element.ALIGN_CENTER));
                priorityTable.AddCell(CreateCell(priorityItem.Scope, fonts.TableCellFont, bg));
                priorityTable.AddCell(CreateCell(priorityItem.Action, fonts.TableCellFont, bg));

                prioIdx++;
            }

            doc.Add(priorityTable);

            if (vulns != null && vulns.Any())
            {
                var highRiskVulns = vulns
                    .Where(v => IsCritical(v.RiskLevel) || IsHigh(v.RiskLevel))
                    .OrderByDescending(v => IsCritical(v.RiskLevel) ? 1 : 0)
                    .Take(5)
                    .ToList();

                if (highRiskVulns.Any())
                {
                    doc.Add(new Paragraph("\n5.2 高危漏洞修复建议（Top 5）", fonts.Heading2Font)
                    {
                        SpacingBefore = 18,
                        SpacingAfter = 8
                    });

                    int fixIdx = 1;
                    foreach (var vuln in highRiskVulns)
                    {
                        var fixTable = new PdfPTable(1);
                        fixTable.WidthPercentage = 100;
                        fixTable.SpacingBefore = 5;
                        fixTable.SpacingAfter = 5;

                        var vulnRiskScheme = GetRiskColorScheme(vuln.RiskLevel);
                        var fixCell = new PdfPCell();
                        fixCell.Border = Rectangle.BOX;
                        fixCell.BorderColor = vulnRiskScheme.ForegroundColor;
                        fixCell.BorderWidth = 0.5f;
                        fixCell.Padding = 10;
                        fixCell.BackgroundColor = new BaseColor(252, 252, 252);

                        var fixContent = new Paragraph();
                        fixContent.Add(new Phrase($"【{fixIdx}】{vuln.Name}",
                            new Font(fonts.BaseFont, 11, Font.BOLD, vulnRiskScheme.ForegroundColor)));

                        if (!string.IsNullOrEmpty(vuln.CveId))
                            fixContent.Add(new Phrase($" ({vuln.CveId})\n", fonts.SmallFont));
                        else
                            fixContent.Add("\n");

                        fixContent.Add(new Phrase("修复步骤: ", fonts.BoldBodyFont));

                        if (!string.IsNullOrEmpty(vuln.Solution))
                            fixContent.Add(new Phrase($"{vuln.Solution}\n", fonts.BodyFont));
                        else
                            fixContent.Add(new Phrase(
                                "1. 访问官方安全公告获取补丁信息\n" +
                                "2. 备份相关数据和配置\n" +
                                "3. 应用最新的安全补丁或升级版本\n" +
                                "4. 验证修复效果并重启相关服务\n",
                                fonts.BodyFont));

                        fixCell.Phrase = fixContent;
                        fixTable.AddCell(fixCell);
                        doc.Add(fixTable);
                        fixIdx++;
                    }
                }
            }

            doc.Add(new Paragraph("\n5.3 通用安全加固建议", fonts.Heading2Font)
            {
                SpacingBefore = 18,
                SpacingAfter = 8
            });

            var hardeningCategories = new[]
            {
                new
                {
                    Category = "网络层面",
                    Content = "配置防火墙规则，仅开放必要的业务端口；实施网络分段隔离；启用入侵检测/防御系统(IDS/IPS)；定期审计网络访问日志。"
                },
                new
                {
                    Category = "系统层面",
                    Content = "及时安装操作系统安全更新；禁用不必要的服务和账户；配置强密码策略（长度>=12位，含大小写字母、数字、特殊字符）；启用账户锁定策略防止暴力破解。"
                },
                new
                {
                    Category = "应用层面",
                    Content = "保持应用程序及依赖库为最新版本；实施安全的编码实践（输入验证、参数化查询）；定期进行代码安全审查和渗透测试；配置安全的HTTP头部（CSP、X-Frame-Options等）。"
                },
                new
                {
                    Category = "身份认证",
                    Content = "实施多因素认证(MFA)；采用基于角色的访问控制(RBAC)；定期清理过期账户和冗余权限；监控异常登录行为并及时告警。"
                },
                new
                {
                    Category = "数据保护",
                    Content = "加密敏感数据存储和传输（TLS 1.2+）；实施数据分类和分级保护策略；建立定期数据备份和灾难恢复机制；制定数据泄露应急响应预案。"
                },
                new
                {
                    Category = "监控审计",
                    Content = "部署集中化日志管理系统(SIEM)；设置安全事件实时告警阈值；定期进行安全基线检查和合规审计；保留审计日志至少180天以满足合规要求。"
                }
            };

            int tipIdx = 1;
            foreach (var category in hardeningCategories)
            {
                var tipTable = new PdfPTable(1);
                tipTable.WidthPercentage = 100;
                tipTable.SpacingBefore = 5;
                tipTable.SpacingAfter = 5;

                var tipCell = new PdfPCell();
                tipCell.Border = Rectangle.BOX;
                tipCell.BorderColor = new BaseColor(52, 152, 219);
                tipCell.BorderWidthLeft = 3;
                tipCell.BorderWidth = 0.5f;
                tipCell.PaddingLeft = 18;
                tipCell.PaddingTop = 5;
                tipCell.PaddingBottom = 5;
                tipCell.BackgroundColor = new BaseColor(248, 250, 252);

                var tipContent = new Paragraph();
                tipContent.Add(new Phrase($"{tipIdx}. {category.Category}: ", fonts.BoldBodyFont));
                tipContent.Add(new Phrase(category.Content, fonts.BodyFont));

                tipCell.Phrase = tipContent;
                tipTable.AddCell(tipCell);
                doc.Add(tipTable);
                tipIdx++;
            }

            doc.Add(new Paragraph(" ", fonts.BodyFont) { SpacingBefore = 30 });
            var disclaimer = new Paragraph(
                "免责声明：本报告由 NetSecurityScanner 安全扫描工具自动生成。" +
                "报告中的漏洞检测结果和建议仅供参考，实际安全决策应结合具体业务场景和专业安全团队的人工判断。" +
                "在应用任何修复措施前，请务必在测试环境充分验证。",
                new Font(fonts.BaseFont, 9, Font.NORMAL, COLOR_GRAY_HINT))
            {
                IndentationLeft = 20,
                IndentationRight = 20,
                Alignment = Element.ALIGN_JUSTIFIED
            };
            doc.Add(disclaimer);
        }

        #endregion

        #region 第8章：威胁情报分析

        private static void GenerateThreatIntelligenceSection(Document doc, FontCollection fonts,
            List<VulnerabilityResult> vulns, List<PortScanResult> ports, string targetIp)
        {
            doc.Add(new Paragraph("六、威胁情报分析", fonts.SectionTitleFont)
            {
                SpacingBefore = 20,
                SpacingAfter = 12
            });

            var introPara = new Paragraph(
                "本节基于当前扫描结果和已知威胁情报数据，对目标系统面临的潜在威胁进行深度分析，帮助安全团队了解攻击者可能的利用路径和当前威胁态势。",
                fonts.BodyFont)
            {
                SpacingBefore = 10,
                SpacingAfter = 15,
                IndentationLeft = 20,
                Leading = 15,
                Alignment = Element.ALIGN_JUSTIFIED
            };
            doc.Add(introPara);

            doc.Add(new Paragraph("6.1 活跃威胁向量", fonts.Heading2Font)
            {
                SpacingBefore = 15,
                SpacingAfter = 8
            });

            var openPorts = ports?.Where(p => p.Status == "开放" || p.Status?.ToLower() == "open").ToList() ?? new List<PortScanResult>();
            var highRiskVulns = vulns?.Where(v => IsCritical(v?.RiskLevel) || IsHigh(v?.RiskLevel)).ToList() ?? new List<VulnerabilityResult>();
            var medRiskVulns = vulns?.Where(v => IsMedium(v?.RiskLevel)).ToList() ?? new List<VulnerabilityResult>();

            var threatVectors = new List<string>();
            if (openPorts.Any())
                threatVectors.Add($"基于开放端口（{string.Join("、", openPorts.Select(p => p.PortNumber.ToString()).Take(10))}）的服务探测和利用");
            if (highRiskVulns.Any())
                threatVectors.Add($"已知高危漏洞（{highRiskVulns.Count}个）的批量扫描和自动化利用");
            threatVectors.Add("弱密码和默认凭据暴力破解攻击");
            if (openPorts.Any(p => p.PortNumber == 80 || p.PortNumber == 443 || p.PortNumber == 8080))
                threatVectors.Add("Web应用层攻击（SQL注入、XSS、目录遍历等）");
            threatVectors.Add("拒绝服务攻击(DoS/DDoS)风险");
            if (openPorts.Any(p => p.PortNumber == 445 || p.PortNumber == 139))
                threatVectors.Add("勒索软件通过SMB协议横向传播");
            if (openPorts.Any(p => p.PortNumber == 3389))
                threatVectors.Add("RDP远程桌面暴力破解和蓝屏漏洞利用");

            int tvIdx = 1;
            foreach (var vector in threatVectors)
            {
                var vectorTable = new PdfPTable(1);
                vectorTable.WidthPercentage = 100;
                vectorTable.SpacingBefore = 4;
                vectorTable.SpacingAfter = 4;

                var vectorCell = new PdfPCell();
                vectorCell.Border = Rectangle.BOX;
                vectorCell.BorderColor = new BaseColor(220, 38, 38);
                vectorCell.BorderWidthLeft = 3;
                vectorCell.BorderWidth = 0.5f;
                vectorCell.PaddingLeft = 14;
                vectorCell.PaddingTop = 6;
                vectorCell.PaddingBottom = 6;
                vectorCell.BackgroundColor = new BaseColor(254, 242, 242);

                var vectorContent = new Paragraph();
                vectorContent.Add(new Phrase($"⚠ {tvIdx}. ", new Font(fonts.BaseFont, 10, Font.BOLD, new BaseColor(220, 38, 38))));
                vectorContent.Add(new Phrase(vector, fonts.BodyFont));
                vectorCell.Phrase = vectorContent;
                vectorTable.AddCell(vectorCell);
                doc.Add(vectorTable);
                tvIdx++;
            }

            doc.Add(new Paragraph("\n6.2 行业威胁趋势", fonts.Heading2Font)
            {
                SpacingBefore = 18,
                SpacingAfter = 8
            });

            var trends = new[]
            {
                new { Title = "勒索软件攻击持续增长", Desc = "针对关键基础设施和大型企业的勒索软件攻击持续增长，攻击者采用双重勒索策略（加密+数据泄露），赎金要求不断攀升。", Severity = "严重" },
                new { Title = "供应链攻击日益复杂", Desc = "软件供应链攻击影响范围扩大，攻击者通过入侵可信软件供应商来分发恶意代码，SolarWinds事件后此类攻击成为主要威胁。", Severity = "高" },
                new { Title = "零日漏洞利用速度加快", Desc = "从漏洞公开到被大规模利用的时间窗口持续缩短，攻击者利用自动化工具在数小时内即可完成漏洞武器化。", Severity = "高" },
                new { Title = "云服务成为新攻击重点", Desc = "云环境配置错误、API安全漏洞和身份认证缺陷成为攻击者的主要入口，多云环境管理复杂性增加了安全风险。", Severity = "中" },
                new { Title = "AI驱动的网络攻击", Desc = "攻击者开始利用AI技术生成钓鱼邮件、自动化漏洞发现和规避检测，传统安全防御面临新的挑战。", Severity = "中" }
            };

            var trendTable = new PdfPTable(3);
            trendTable.WidthPercentage = 100;
            trendTable.SetWidths(new float[] { 2.5f, 5f, 1.2f });
            trendTable.SpacingBefore = 5;
            trendTable.HeaderRows = 1;

            AddTableHeader(trendTable, new[] { "威胁趋势", "分析描述", "严重度" }, fonts);

            int trendIdx = 1;
            foreach (var trend in trends)
            {
                var isZebra = trendIdx % 2 == 0;
                var bg = isZebra ? COLOR_ZEBRA : BaseColor.WHITE;

                trendTable.AddCell(CreateCell(trend.Title, new Font(fonts.BaseFont, 9, Font.BOLD, COLOR_TEXT), bg));
                trendTable.AddCell(CreateCell(trend.Desc, fonts.TableCellFont, bg));
                var sevColor = trend.Severity == "严重" ? new BaseColor(153, 27, 27) :
                               trend.Severity == "高" ? new BaseColor(194, 65, 12) : new BaseColor(217, 119, 6);
                trendTable.AddCell(CreateCell(trend.Severity, new Font(fonts.BaseFont, 9, Font.BOLD, sevColor), bg, Element.ALIGN_CENTER));
                trendIdx++;
            }
            doc.Add(trendTable);

            doc.Add(new Paragraph("\n6.3 攻击面评估", fonts.Heading2Font)
            {
                SpacingBefore = 18,
                SpacingAfter = 8
            });

            var attackSurfaceTable = new PdfPTable(2);
            attackSurfaceTable.WidthPercentage = 80;
            attackSurfaceTable.SetWidths(new float[] { 2.5f, 3f });
            attackSurfaceTable.SpacingBefore = 5;
            attackSurfaceTable.HeaderRows = 1;

            AddTableHeader(attackSurfaceTable, new[] { "评估维度", "当前状态" }, fonts);

            var surfaceItems = new[]
            {
                new { Dimension = "外部可达端口数", Status = $"{openPorts.Count}个开放端口" + (openPorts.Any(p => p.PortNumber == 445 || p.PortNumber == 135 || p.PortNumber == 3389) ? "（含高危端口）" : "（未发现高危端口）") },
                new { Dimension = "已知漏洞数量", Status = $"{(vulns?.Count ?? 0)}个漏洞" + (highRiskVulns.Any() ? $"（含{highRiskVulns.Count}个高危）" : "") },
                new { Dimension = "服务版本暴露", Status = openPorts.Any(p => !string.IsNullOrEmpty(p.ServiceVersion) && p.ServiceVersion != "未知版本") ? "部分服务版本信息已暴露" : "服务版本信息未暴露" },
                new { Dimension = "整体攻击面评级", Status = highRiskVulns.Count > 3 ? "大 - 需要立即缩减" : highRiskVulns.Any() ? "中等 - 建议优化" : "较小 - 保持监控" }
            };

            int surfIdx = 1;
            foreach (var item in surfaceItems)
            {
                var isZebra = surfIdx % 2 == 0;
                var bg = isZebra ? COLOR_ZEBRA : BaseColor.WHITE;
                attackSurfaceTable.AddCell(CreateCell(item.Dimension, new Font(fonts.BaseFont, 9, Font.BOLD, COLOR_TEXT), bg));
                attackSurfaceTable.AddCell(CreateCell(item.Status, fonts.TableCellFont, bg));
                surfIdx++;
            }
            doc.Add(attackSurfaceTable);
        }

        #endregion

        #region 第9章：合规参考

        private static void GenerateComplianceSection(Document doc, FontCollection fonts,
            List<VulnerabilityResult> vulns, List<PortScanResult> ports)
        {
            doc.Add(new Paragraph("七、合规参考", fonts.SectionTitleFont)
            {
                SpacingBefore = 20,
                SpacingAfter = 12
            });

            var introPara = new Paragraph(
                "本节根据当前扫描结果，对照主要信息安全合规标准和法规要求，评估目标系统的合规状态，为合规审计和整改提供参考依据。",
                fonts.BodyFont)
            {
                SpacingBefore = 10,
                SpacingAfter = 15,
                IndentationLeft = 20,
                Leading = 15,
                Alignment = Element.ALIGN_JUSTIFIED
            };
            doc.Add(introPara);

            doc.Add(new Paragraph("7.1 合规标准对照评估", fonts.Heading2Font)
            {
                SpacingBefore = 15,
                SpacingAfter = 8
            });

            var highRiskCount = vulns?.Count(v => IsCritical(v?.RiskLevel) || IsHigh(v?.RiskLevel)) ?? 0;
            var openPorts = ports?.Where(p => p.Status == "开放" || p.Status?.ToLower() == "open").ToList() ?? new List<PortScanResult>();

            var complianceItems = new[]
            {
                new
                {
                    Standard = "等保2.0",
                    FullName = "网络安全等级保护基本要求",
                    Requirement = "安全通信网络、安全区域边界、安全计算环境、安全管理中心",
                    Status = highRiskCount > 0 ? "部分符合" : "基本符合",
                    StatusColor = highRiskCount > 0 ? new BaseColor(217, 119, 6) : new BaseColor(5, 150, 105)
                },
                new
                {
                    Standard = "ISO 27001",
                    FullName = "信息安全管理体系要求",
                    Requirement = "A.12漏洞管理、A.13通信安全、A.14系统开发安全",
                    Status = highRiskCount > 3 ? "不符合" : "部分符合",
                    StatusColor = highRiskCount > 3 ? new BaseColor(220, 38, 38) : new BaseColor(217, 119, 6)
                },
                new
                {
                    Standard = "GDPR",
                    FullName = "通用数据保护条例",
                    Requirement = "第32条-数据处理者安全措施、第25条-数据保护设计",
                    Status = "需要评估",
                    StatusColor = new BaseColor(100, 116, 139)
                },
                new
                {
                    Standard = "PCI DSS",
                    FullName = "支付卡行业数据安全标准",
                    Requirement = "Req.6安全系统开发、Req.11安全测试、Req.2安全配置",
                    Status = highRiskCount > 0 ? "不符合" : "需要评估",
                    StatusColor = highRiskCount > 0 ? new BaseColor(220, 38, 38) : new BaseColor(100, 116, 139)
                },
                new
                {
                    Standard = "CIS Controls",
                    FullName = "CIS关键安全控制措施",
                    Requirement = "控制3数据保护、控制5安全配置、控制7漏洞管理",
                    Status = highRiskCount > 0 ? "部分符合" : "基本符合",
                    StatusColor = highRiskCount > 0 ? new BaseColor(217, 119, 6) : new BaseColor(5, 150, 105)
                }
            };

            var complianceTable = new PdfPTable(4);
            complianceTable.WidthPercentage = 100;
            complianceTable.SetWidths(new float[] { 1.2f, 2.5f, 2.5f, 1.2f });
            complianceTable.SpacingBefore = 5;
            complianceTable.HeaderRows = 1;

            AddTableHeader(complianceTable, new[] { "合规标准", "相关要求", "评估范围", "符合性状态" }, fonts);

            int compIdx = 1;
            foreach (var item in complianceItems)
            {
                var isZebra = compIdx % 2 == 0;
                var bg = isZebra ? COLOR_ZEBRA : BaseColor.WHITE;

                complianceTable.AddCell(CreateCell(item.Standard, new Font(fonts.BaseFont, 9, Font.BOLD, COLOR_TEXT), bg, Element.ALIGN_CENTER));
                complianceTable.AddCell(CreateCell(item.FullName, fonts.TableCellFont, bg));
                complianceTable.AddCell(CreateCell(item.Requirement, fonts.TableCellFont, bg));
                complianceTable.AddCell(CreateCell(item.Status, new Font(fonts.BaseFont, 9, Font.BOLD, item.StatusColor), bg, Element.ALIGN_CENTER));
                compIdx++;
            }
            doc.Add(complianceTable);

            doc.Add(new Paragraph("\n7.2 合规差距分析", fonts.Heading2Font)
            {
                SpacingBefore = 18,
                SpacingAfter = 8
            });

            var gapItems = new List<string>();
            if (highRiskCount > 0)
                gapItems.Add($"发现{highRiskCount}个高危漏洞，不符合等保2.0漏洞管理要求和ISO 27001 A.12漏洞管理控制");
            if (openPorts.Any(p => p.PortNumber == 445 || p.PortNumber == 135))
                gapItems.Add("SMB/RPC等高危端口对外开放，不符合等保2.0安全区域边界要求和CIS控制5安全配置");
            if (openPorts.Any(p => p.PortNumber == 3389))
                gapItems.Add("RDP远程桌面端口暴露，不符合PCI DSS Req.1网络分段要求");
            if (!gapItems.Any())
                gapItems.Add("当前扫描结果未发现明显合规差距，建议持续监控并定期进行合规审计");

            int gapIdx = 1;
            foreach (var gap in gapItems)
            {
                var gapTable = new PdfPTable(1);
                gapTable.WidthPercentage = 100;
                gapTable.SpacingBefore = 4;
                gapTable.SpacingAfter = 4;

                var gapCell = new PdfPCell();
                gapCell.Border = Rectangle.BOX;
                gapCell.BorderColor = new BaseColor(217, 119, 6);
                gapCell.BorderWidthLeft = 3;
                gapCell.BorderWidth = 0.5f;
                gapCell.PaddingLeft = 14;
                gapCell.PaddingTop = 6;
                gapCell.PaddingBottom = 6;
                gapCell.BackgroundColor = new BaseColor(254, 252, 232);

                var gapContent = new Paragraph();
                gapContent.Add(new Phrase($"{gapIdx}. ", new Font(fonts.BaseFont, 10, Font.BOLD, new BaseColor(217, 119, 6))));
                gapContent.Add(new Phrase(gap, fonts.BodyFont));
                gapCell.Phrase = gapContent;
                gapTable.AddCell(gapCell);
                doc.Add(gapTable);
                gapIdx++;
            }

            doc.Add(new Paragraph("\n7.3 合规改进建议", fonts.Heading2Font)
            {
                SpacingBefore = 18,
                SpacingAfter = 8
            });

            var improvementSuggestions = new[]
            {
                "建立漏洞管理流程，确保所有高危漏洞在72小时内完成修复，中危漏洞7天内修复",
                "实施网络分段和访问控制，将关键系统与一般业务系统隔离",
                "建立安全配置基线，定期核查系统配置是否符合安全标准",
                "部署安全信息与事件管理系统(SIEM)，实现安全事件的集中监控和告警",
                "制定年度安全评估计划，至少每季度进行一次漏洞扫描和安全评估",
                "建立数据分类分级制度，对不同级别的数据实施差异化保护措施"
            };

            var improveTable = new PdfPTable(2);
            improveTable.WidthPercentage = 90;
            improveTable.SetWidths(new float[] { 0.6f, 5f });
            improveTable.SpacingBefore = 5;

            int sugIdx = 1;
            foreach (var suggestion in improvementSuggestions)
            {
                var isZebra = sugIdx % 2 == 0;
                var bg = isZebra ? COLOR_ZEBRA : BaseColor.WHITE;
                improveTable.AddCell(CreateCell(sugIdx.ToString(), new Font(fonts.BaseFont, 9, Font.BOLD, COLOR_PRIMARY_LIGHT), bg, Element.ALIGN_CENTER));
                improveTable.AddCell(CreateCell(suggestion, fonts.TableCellFont, bg));
                sugIdx++;
            }
            doc.Add(improveTable);
        }

        #endregion

        #region 第10章：结论与建议

        private static void GenerateConclusionSection(Document doc, FontCollection fonts,
            List<VulnerabilityResult> vulns, List<PortScanResult> ports, string targetIp)
        {
            doc.Add(new Paragraph("八、结论与建议", fonts.SectionTitleFont)
            {
                SpacingBefore = 20,
                SpacingAfter = 12
            });

            var overallRisk = CalculateOverallRiskLevel(vulns);
            var highRiskCount = vulns?.Count(v => IsCritical(v?.RiskLevel) || IsHigh(v?.RiskLevel)) ?? 0;
            var medRiskCount = vulns?.Count(v => IsMedium(v?.RiskLevel)) ?? 0;
            var lowRiskCount = vulns?.Count(v => IsLow(v?.RiskLevel)) ?? 0;
            var totalVulns = vulns?.Count ?? 0;
            var openPorts = ports?.Where(p => p.Status == "开放" || p.Status?.ToLower() == "open").ToList() ?? new List<PortScanResult>();

            var riskColor = overallRisk == "严重" ? new BaseColor(153, 27, 27) :
                            overallRisk == "高" ? new BaseColor(194, 65, 12) :
                            overallRisk == "中" ? new BaseColor(217, 119, 6) : new BaseColor(5, 150, 105);

            var riskBg = overallRisk == "严重" ? new BaseColor(254, 226, 226) :
                         overallRisk == "高" ? new BaseColor(254, 243, 199) :
                         overallRisk == "中" ? new BaseColor(254, 252, 232) : new BaseColor(236, 253, 245);

            doc.Add(new Paragraph("8.1 总体安全评级", fonts.Heading2Font)
            {
                SpacingBefore = 15,
                SpacingAfter = 8
            });

            var ratingTable = new PdfPTable(1);
            ratingTable.WidthPercentage = 70;
            ratingTable.SpacingBefore = 5;
            ratingTable.SpacingAfter = 15;
            ratingTable.HorizontalAlignment = Element.ALIGN_CENTER;

            var ratingCell = new PdfPCell();
            ratingCell.Border = Rectangle.BOX;
            ratingCell.BorderColor = riskColor;
            ratingCell.BorderWidth = 2;
            ratingCell.Padding = 20;
            ratingCell.BackgroundColor = riskBg;
            ratingCell.HorizontalAlignment = Element.ALIGN_CENTER;

            var ratingContent = new Paragraph();
            ratingContent.Alignment = Element.ALIGN_CENTER;
            ratingContent.Add(new Phrase($"\n总体安全评级\n", new Font(fonts.BaseFont, 12, Font.NORMAL, COLOR_SECONDARY_TEXT)));
            ratingContent.Add(new Phrase($"{overallRisk}风险\n", new Font(fonts.BaseFont, 28, Font.BOLD, riskColor)));
            ratingContent.Add(new Phrase($"\n目标系统：{targetIp}  |  漏洞总数：{totalVulns}  |  开放端口：{openPorts.Count}\n", new Font(fonts.BaseFont, 10, Font.NORMAL, COLOR_SECONDARY_TEXT)));
            ratingCell.Phrase = ratingContent;
            ratingTable.AddCell(ratingCell);
            doc.Add(ratingTable);

            doc.Add(new Paragraph("8.2 核心结论", fonts.Heading2Font)
            {
                SpacingBefore = 15,
                SpacingAfter = 8
            });

            var conclusionText = "";
            if (highRiskCount > 0)
            {
                conclusionText = $"本次扫描针对目标系统 {targetIp} 进行了全面的网络安全评估，共发现 {totalVulns} 个安全漏洞" +
                    $"（其中高危 {highRiskCount} 个、中危 {medRiskCount} 个、低危 {lowRiskCount} 个）和 {openPorts.Count} 个开放端口。" +
                    $"发现的高危漏洞需要立即采取修复措施，建议按照本报告提供的修复优先级矩阵制定详细的修复计划。";
            }
            else if (totalVulns > 0)
            {
                conclusionText = $"本次扫描针对目标系统 {targetIp} 进行了全面的网络安全评估，共发现 {totalVulns} 个安全漏洞" +
                    $"（其中中危 {medRiskCount} 个、低危 {lowRiskCount} 个）和 {openPorts.Count} 个开放端口。" +
                    $"当前未发现高危漏洞，但建议对中低危漏洞进行持续关注和计划修复。";
            }
            else
            {
                conclusionText = $"本次扫描针对目标系统 {targetIp} 进行了全面的网络安全评估，未发现安全漏洞。" +
                    $"发现 {openPorts.Count} 个开放端口，建议持续监控并定期进行安全评估。";
            }

            var conclusionPara = new Paragraph(conclusionText, fonts.BodyFont)
            {
                SpacingBefore = 8,
                SpacingAfter = 15,
                IndentationLeft = 20,
                IndentationRight = 20,
                Leading = 16,
                Alignment = Element.ALIGN_JUSTIFIED
            };
            doc.Add(conclusionPara);

            doc.Add(new Paragraph("8.3 长期安全建议", fonts.Heading2Font)
            {
                SpacingBefore = 15,
                SpacingAfter = 8
            });

            var longTermSuggestions = new[]
            {
                new { Priority = "P1", Suggestion = "建立定期漏洞扫描机制，建议每周至少进行一次全面扫描，关键系统每日扫描", Category = "漏洞管理" },
                new { Priority = "P1", Suggestion = "实施漏洞管理全流程，确保所有漏洞从发现到修复的闭环跟踪", Category = "漏洞管理" },
                new { Priority = "P2", Suggestion = "部署入侵检测和防御系统(IDS/IPS)，实时监控网络流量和异常行为", Category = "安全监控" },
                new { Priority = "P2", Suggestion = "建立安全事件应急响应计划，明确事件分级、响应流程和责任人", Category = "应急响应" },
                new { Priority = "P2", Suggestion = "加强员工安全意识培训，定期进行钓鱼邮件测试和安全知识考核", Category = "安全意识" },
                new { Priority = "P3", Suggestion = "实施最小权限原则，定期审查和清理用户权限，关闭不必要的账户", Category = "访问控制" },
                new { Priority = "P3", Suggestion = "保持系统和应用程序的及时更新，建立补丁管理流程和测试机制", Category = "补丁管理" },
                new { Priority = "P3", Suggestion = "定期备份关键数据，验证备份数据的完整性和可恢复性", Category = "数据保护" }
            };

            var longTermTable = new PdfPTable(3);
            longTermTable.WidthPercentage = 100;
            longTermTable.SetWidths(new float[] { 0.8f, 1.2f, 4f });
            longTermTable.SpacingBefore = 5;
            longTermTable.HeaderRows = 1;

            AddTableHeader(longTermTable, new[] { "优先级", "类别", "建议措施" }, fonts);

            int ltIdx = 1;
            foreach (var item in longTermSuggestions)
            {
                var isZebra = ltIdx % 2 == 0;
                var bg = isZebra ? COLOR_ZEBRA : BaseColor.WHITE;

                var prioColor = item.Priority == "P1" ? new BaseColor(220, 38, 38) :
                                item.Priority == "P2" ? new BaseColor(217, 119, 6) : new BaseColor(5, 150, 105);
                longTermTable.AddCell(CreateCell(item.Priority, new Font(fonts.BaseFont, 9, Font.BOLD, prioColor), bg, Element.ALIGN_CENTER));
                longTermTable.AddCell(CreateCell(item.Category, new Font(fonts.BaseFont, 9, Font.BOLD, COLOR_TEXT), bg, Element.ALIGN_CENTER));
                longTermTable.AddCell(CreateCell(item.Suggestion, fonts.TableCellFont, bg));
                ltIdx++;
            }
            doc.Add(longTermTable);

            doc.Add(new Paragraph(" ", fonts.BodyFont) { SpacingBefore = 30 });

            var footerTable = new PdfPTable(1);
            footerTable.WidthPercentage = 100;
            footerTable.SpacingBefore = 10;

            var footerCell = new PdfPCell();
            footerCell.Border = Rectangle.BOX;
            footerCell.BorderColor = COLOR_PRIMARY;
            footerCell.BorderWidthTop = 2;
            footerCell.BorderWidthBottom = 0;
            footerCell.BorderWidthLeft = 0;
            footerCell.BorderWidthRight = 0;
            footerCell.PaddingTop = 10;
            footerCell.PaddingBottom = 5;
            footerCell.BackgroundColor = new BaseColor(248, 250, 252);

            var footerContent = new Paragraph();
            footerContent.Alignment = Element.ALIGN_CENTER;
            footerContent.Add(new Phrase($"NetSecurityScanner v{VersionHelper.GetVersion()} | 报告生成时间：{DateTime.Now:yyyy-MM-dd HH:mm:ss}\n",
                new Font(fonts.BaseFont, 9, Font.NORMAL, COLOR_SECONDARY_TEXT)));
            footerContent.Add(new Phrase("免责声明：本报告由自动化安全扫描工具生成，结果仅供参考。对于关键安全问题，建议进行人工验证和深度安全分析。\n",
                new Font(fonts.BaseFont, 8, Font.NORMAL, COLOR_GRAY_HINT)));
            footerContent.Add(new Phrase("网络安全扫描报告 — 仅供内部使用",
                new Font(fonts.BaseFont, 9, Font.BOLD, COLOR_CONFIDENTIAL)));

            footerCell.Phrase = footerContent;
            footerTable.AddCell(footerCell);
            doc.Add(footerTable);
        }

        #endregion

        #region 页眉页脚系统

        public class HistoryReportPageEvent : PdfPageEventHelper
        {
            private BaseFont _baseFont;
            private int _pageNumber = 0;
            private bool _isCoverPage = true;

            public override void OnOpenDocument(PdfWriter writer, Document document)
            {
                bool fontLoaded = false;

                if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
                {
                    string[] windowsFontPaths = {
                        @"C:\Windows\Fonts\msyh.ttc,0",
                        @"C:\Windows\Fonts\simhei.ttf",
                        @"C:\Windows\Fonts\simsun.ttc,0",
                        @"C:\Windows\Fonts\msyhbd.ttc,0",
                        @"C:\Windows\Fonts\simkai.ttf"
                    };

                    foreach (var fp in windowsFontPaths)
                    {
                        try
                        {
                            if (File.Exists(fp.Split(',')[0]))
                            {
                                _baseFont = BaseFont.CreateFont(fp, BaseFont.IDENTITY_H, BaseFont.EMBEDDED);
                                fontLoaded = true;
                                break;
                            }
                        }
                        catch { }
                    }
                }
                else if (RuntimeInformation.IsOSPlatform(OSPlatform.Linux))
                {
                    string[] linuxFontPaths = {
                        "/usr/share/fonts/opentype/noto/NotoSansCJK-Regular.ttc",
                        "/usr/share/fonts/opentype/noto/NotoSansCJKsc-Regular.otf",
                        "/usr/share/fonts/truetype/wqy/wqy-microhei.ttc",
                        "/usr/share/fonts/truetype/wqy/wqy-zenhei.ttc",
                        "/usr/share/fonts/truetype/droid/DroidSansFallbackFull.ttf",
                        "/usr/share/fonts/truetype/liberation/LiberationSans-Regular.ttf",
                        "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf"
                    };

                    foreach (var fp in linuxFontPaths)
                    {
                        try
                        {
                            if (File.Exists(fp))
                            {
                                _baseFont = BaseFont.CreateFont(fp, BaseFont.IDENTITY_H, BaseFont.EMBEDDED);
                                fontLoaded = true;
                                break;
                            }
                        }
                        catch { }
                    }
                }
                else if (RuntimeInformation.IsOSPlatform(OSPlatform.OSX))
                {
                    string[] macFontPaths = {
                        "/System/Library/Fonts/PingFang.ttc",
                        "/System/Library/Fonts/STHeiti Light.ttc",
                        "/Library/Fonts/Arial Unicode.ttf"
                    };

                    foreach (var fp in macFontPaths)
                    {
                        try
                        {
                            if (File.Exists(fp))
                            {
                                _baseFont = BaseFont.CreateFont(fp, BaseFont.IDENTITY_H, BaseFont.EMBEDDED);
                                fontLoaded = true;
                                break;
                            }
                        }
                        catch { }
                    }
                }

                if (!fontLoaded)
                {
                    try
                    {
                        _baseFont = BaseFont.CreateFont(BaseFont.HELVETICA, BaseFont.CP1252, false);
                    }
                    catch { }
                }
            }

            public override void OnEndPage(PdfWriter writer, Document document)
            {
                _pageNumber++;

                if (_isCoverPage)
                {
                    _isCoverPage = false;
                    return;
                }

                var font = _baseFont != null ?
                    new Font(_baseFont, 8, Font.NORMAL, COLOR_GRAY_HINT) :
                    new Font(Font.FontFamily.HELVETICA, 8, Font.NORMAL, COLOR_GRAY_HINT);

                var headerTable = new PdfPTable(2);
                headerTable.TotalWidth = document.PageSize.Width - document.LeftMargin - document.RightMargin;
                headerTable.SetWidths(new float[] { 3f, 2f });

                var leftHeaderCell = new PdfPCell(new Phrase("网络安全漏洞扫描报告", font))
                {
                    Border = Rectangle.BOX,
                    BorderColor = COLOR_BORDER,
                    BorderWidth = 0.5f,
                    HorizontalAlignment = Element.ALIGN_LEFT,
                    PaddingBottom = 5
                };

                var rightHeaderCell = new PdfPCell(new Phrase($"NetSecurityScanner v{VersionHelper.GetVersion()}", font))
                {
                    Border = Rectangle.BOX,
                    BorderColor = COLOR_BORDER,
                    BorderWidth = 0.5f,
                    HorizontalAlignment = Element.ALIGN_RIGHT,
                    PaddingBottom = 5
                };

                headerTable.AddCell(leftHeaderCell);
                headerTable.AddCell(rightHeaderCell);
                headerTable.WriteSelectedRows(0, -1,
                    document.LeftMargin, document.PageSize.Height - 20, writer.DirectContent);

                var headerLineCb = writer.DirectContent;
                headerLineCb.SetColorStroke(COLOR_SEPARATOR);
                headerLineCb.MoveTo(document.LeftMargin, document.PageSize.Height - 28);
                headerLineCb.LineTo(document.PageSize.Width - document.RightMargin, document.PageSize.Height - 28);
                headerLineCb.Stroke();

                var footerTable = new PdfPTable(2);
                footerTable.TotalWidth = document.PageSize.Width - document.LeftMargin - document.RightMargin;
                footerTable.SetWidths(new float[] { 3f, 2f });

                var leftFooterCell = new PdfPCell(new Phrase("机密 - 内部文档", font))
                {
                    Border = Rectangle.BOX,
                    BorderColor = COLOR_BORDER,
                    BorderWidth = 0.5f,
                    HorizontalAlignment = Element.ALIGN_LEFT,
                    PaddingTop = 5
                };

                var rightFooterCell = new PdfPCell(new Phrase(
                    $"第 {_pageNumber} 页 / 共 Y 页", font))
                {
                    Border = Rectangle.BOX,
                    BorderColor = COLOR_BORDER,
                    BorderWidth = 0.5f,
                    HorizontalAlignment = Element.ALIGN_RIGHT,
                    PaddingTop = 5
                };

                footerTable.AddCell(leftFooterCell);
                footerTable.AddCell(rightFooterCell);
                footerTable.WriteSelectedRows(0, -1,
                    document.LeftMargin, 28, writer.DirectContent);

                var footerLineCb = writer.DirectContent;
                footerLineCb.SetColorStroke(COLOR_SEPARATOR);
                footerLineCb.MoveTo(document.LeftMargin, 38);
                footerLineCb.LineTo(document.PageSize.Width - document.RightMargin, 38);
                footerLineCb.Stroke();
            }
        }

        #endregion

        #region 辅助工具方法 - 通用绘图API辅助函数

        private static iTextSharp.text.Image GeneratePieChart(List<(string Label, int Count, BaseColor Color)> data, FontCollection fonts)
        {
            try
            {
                var total = data.Sum(d => d.Count);
                if (total <= 0) return null;

                int imgSize = 200;
                int centerX = imgSize / 2;
                int centerY = imgSize / 2;
                int radius = 75;

                using (var bmp = new System.Drawing.Bitmap(imgSize, imgSize))
                using (var g = System.Drawing.Graphics.FromImage(bmp))
                {
                    g.SmoothingMode = System.Drawing.Drawing2D.SmoothingMode.AntiAlias;
                    g.Clear(System.Drawing.Color.White);

                    float startAngle = -90;
                    foreach (var item in data)
                    {
                        var sweepAngle = (float)item.Count / total * 360;
                        var color = System.Drawing.Color.FromArgb(item.Color.R, item.Color.G, item.Color.B);

                        using (var brush = new System.Drawing.SolidBrush(color))
                        {
                            g.FillPie(brush, centerX - radius, centerY - radius, radius * 2, radius * 2, startAngle, sweepAngle);
                        }

                        using (var pen = new System.Drawing.Pen(System.Drawing.Color.White, 2))
                        {
                            g.DrawPie(pen, centerX - radius, centerY - radius, radius * 2, radius * 2, startAngle, sweepAngle);
                        }

                        if (sweepAngle > 15)
                        {
                            var midAngle = startAngle + sweepAngle / 2;
                            var labelRadius = radius * 0.6;
                            var labelX = centerX + (float)(labelRadius * Math.Cos(midAngle * Math.PI / 180));
                            var labelY = centerY + (float)(labelRadius * Math.Sin(midAngle * Math.PI / 180));
                            var pct = (double)item.Count / total * 100;

                            var labelStr = $"{pct:F0}%";
                            var font = new System.Drawing.Font("Microsoft YaHei", 9, System.Drawing.FontStyle.Bold);
                            var size = g.MeasureString(labelStr, font);
                            g.DrawString(labelStr, font, System.Drawing.Brushes.White,
                                labelX - size.Width / 2, labelY - size.Height / 2);
                        }

                        startAngle += sweepAngle;
                    }

                    using (var innerBrush = new System.Drawing.SolidBrush(System.Drawing.Color.White))
                    {
                        g.FillEllipse(innerBrush, centerX - 25, centerY - 25, 50, 50);
                    }

                    var totalFont = new System.Drawing.Font("Microsoft YaHei", 10, System.Drawing.FontStyle.Bold);
                    var totalSize = g.MeasureString(total.ToString(), totalFont);
                    g.DrawString(total.ToString(), totalFont, System.Drawing.Brushes.DarkSlateGray,
                        centerX - totalSize.Width / 2, centerY - totalSize.Height / 2);

                    using (var ms = new MemoryStream())
                    {
                        bmp.Save(ms, System.Drawing.Imaging.ImageFormat.Png);
                        var img = iTextSharp.text.Image.GetInstance(ms.ToArray());
                        img.ScaleToFit(140f, 140f);
                        return img;
                    }
                }
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"[PieChart] 生成饼图失败: {ex.Message}");
                return null;
            }
        }

        /// <summary>
        /// 绘制分隔线 - 使用DirectContent底层绘图API
        /// </summary>
        private static void DrawSeparatorLine(PdfContentByte cb, float y, float lineWidth = 0.5f, BaseColor color = null)
        {
            color = color ?? new BaseColor(203, 213, 225);
            cb.SetColorStroke(color);
            cb.SetLineWidth(lineWidth);
            cb.MoveTo(60, y);
            cb.LineTo(535, y);
            cb.Stroke();
        }

        /// <summary>
        /// 安全获取字符串的辅助方法 - 防止null或空白字符串导致PDF渲染异常
        /// </summary>
        private static string GetSafeString(string value)
        {
            return string.IsNullOrWhiteSpace(value) ? "-" : value;
        }

        private static void AddTableHeader(PdfPTable table, string[] headers, FontCollection fonts)
        {
            foreach (var header in headers)
            {
                table.AddCell(CreateHeaderCell(header, fonts.TableHeaderFont));
            }
        }

        private static RiskColorScheme GetRiskColorScheme(string riskLevel)
        {
            if (string.IsNullOrWhiteSpace(riskLevel)) return DefaultRiskColor;

            if (RiskColors.TryGetValue(riskLevel.Trim(), out var scheme))
                return scheme;

            return DefaultRiskColor;
        }

        private static BaseColor GetRiskLevelColor(string riskLevel)
        {
            return GetRiskColorScheme(riskLevel).ForegroundColor;
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

        private static bool ValidatePdfHeader(string filePath)
        {
            try
            {
                if (string.IsNullOrEmpty(filePath) || !File.Exists(filePath))
                    return false;

                using (var fs = new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.Read))
                {
                    if (fs.Length < 5) return false;
                    var header = new byte[5];
                    fs.Read(header, 0, 5);
                    return header[0] == '%' && header[1] == 'P' && header[2] == 'D' && header[3] == 'F' && header[4] == '-';
                }
            }
            catch
            {
                return false;
            }
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
                Debug.WriteLine($"[HistoryReport-风险等级] 计算异常: {ex.Message}");
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

        private static RiskAssessmentSummary MergeRiskAssessments(List<RiskAssessmentSummary> assessments)
        {
            if (assessments == null || !assessments.Any())
                return new RiskAssessmentSummary();

            var result = new RiskAssessmentSummary
            {
                HighRiskCount = assessments.Sum(a => a.HighRiskCount),
                MediumRiskCount = assessments.Sum(a => a.MediumRiskCount),
                LowRiskCount = assessments.Sum(a => a.LowRiskCount),
                TotalVulnerabilities = assessments.Sum(a => a.TotalVulnerabilities),
                RiskScore = (int)assessments.Average(a => a.RiskScore),
                SecurityAdvice = "综合多次扫描结果的安全建议"
            };

            if (result.RiskScore >= 80) result.RiskLevel = "严重";
            else if (result.RiskScore >= 60) result.RiskLevel = "高";
            else if (result.RiskScore >= 40) result.RiskLevel = "中";
            else if (result.RiskScore >= 20) result.RiskLevel = "低";
            else result.RiskLevel = "信息";

            return result;
        }

        private static void AddErrorPlaceholder(Document doc, FontCollection fonts,
            string sectionName, string errorMessage)
        {
            try
            {
                var errorPara = new Paragraph()
                {
                    SpacingBefore = 20,
                    SpacingAfter = 20,
                    IndentationLeft = 20,
                    Alignment = Element.ALIGN_CENTER
                };

                var errorFont = fonts.BaseFont != null ?
                    new Font(fonts.BaseFont, 10, Font.NORMAL, COLOR_CONFIDENTIAL) :
                    new Font(Font.FontFamily.HELVETICA, 10, Font.NORMAL, COLOR_CONFIDENTIAL);

                errorPara.Add(new Phrase($"[该章节生成失败: {sectionName}]", errorFont));
                errorPara.Add(new Phrase("\n", fonts.BodyFont));
                errorPara.Add(new Phrase($"错误原因: {errorMessage}", fonts.SmallFont));

                doc.Add(errorPara);
                Debug.WriteLine($"[HistoryReport] 已添加错误占位符: {sectionName}");
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"[HistoryReport] 添加错误占位符也失败: {ex.Message}");
            }
        }

        #endregion
    }
}
