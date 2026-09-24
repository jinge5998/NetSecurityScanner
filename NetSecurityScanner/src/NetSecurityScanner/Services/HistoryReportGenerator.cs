using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Diagnostics;
using System.Windows;
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

        private static bool ValidatePdfFile(string filePath)
        {
            try
            {
                if (!File.Exists(filePath))
                {
                    Debug.WriteLine($"[PDF验证] 文件不存在: {filePath}");
                    return false;
                }

                var fileInfo = new FileInfo(filePath);
                if (fileInfo.Length < 10)
                {
                    Debug.WriteLine($"[PDF验证] 文件过小 ({fileInfo.Length} bytes)，可能无效");
                    return false;
                }

                using (var fs = File.OpenRead(filePath))
                using (var reader = new StreamReader(fs, System.Text.Encoding.ASCII, true, 1024))
                {
                    var header = reader.ReadLine();
                    if (string.IsNullOrEmpty(header) || !header.StartsWith("%PDF-"))
                    {
                        Debug.WriteLine($"[PDF验证] 文件头无效: {(header ?? "null").Substring(0, Math.Min(20, header?.Length ?? 0))}");
                        return false;
                    }
                }

                Debug.WriteLine($"[PDF验证] PDF文件格式有效，大小: {fileInfo.Length / 1024} KB");
                return true;
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"[PDF验证] 验证异常: {ex.Message}");
                return false;
            }
        }

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
                using (Document doc = new Document(PageSize.A4, 55, 55, 70, 55))
                using (PdfWriter writer = PdfWriter.GetInstance(doc, fs))
                {
                    writer.CloseStream = false;
                    doc.Open();

                    var fonts = LoadChineseFonts();
                    if (fonts.BaseFont == null)
                        fonts = CreateFallbackFontCollection();

                    var pageEvent = new HistoryReportPageEvent();
                    pageEvent.BaseFont = fonts.BaseFont;
                    writer.PageEvent = pageEvent;

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

                    doc.Close();
                }

                if (!ValidatePdfFile(tempPath))
                    throw new InvalidDataException("生成的PDF文件格式验证失败，文件可能已损坏");

                File.Copy(tempPath, savePath, true);
                Debug.WriteLine($"[HistoryReport-ToPath] PDF报告生成成功：{savePath}");
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
                using (Document doc = new Document(PageSize.A4, 55, 55, 70, 55))
                using (PdfWriter writer = PdfWriter.GetInstance(doc, fs))
                {
                    writer.CloseStream = false;
                    doc.Open();

                    var fonts = LoadChineseFonts();
                    if (fonts.BaseFont == null)
                        fonts = CreateFallbackFontCollection();

                    var pageEvent = new HistoryReportPageEvent();
                    pageEvent.BaseFont = fonts.BaseFont;
                    writer.PageEvent = pageEvent;

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

                    doc.Close();
                }

                if (!ValidatePdfFile(tempPath))
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
                MessageBox.Show("扫描记录为空，无法生成报告。", "数据为空", MessageBoxButton.OK, MessageBoxImage.Warning);
                return string.Empty;
            }

            var safePorts = record.PortScanResults ?? new List<PortScanResult>();
            var safeVulns = record.VulnerabilityResults ?? new List<VulnerabilityResult>();

            if (!safePorts.Any() && !safeVulns.Any())
            {
                MessageBox.Show("该扫描记录暂无数据（端口和漏洞均为空），请先执行完整的扫描操作。", "数据为空", MessageBoxButton.OK, MessageBoxImage.Warning);
                return string.Empty;
            }

            var targetIp = string.IsNullOrWhiteSpace(record.TargetIp) ? "未知目标" : record.TargetIp;
            string tempPath = null;
            string filePath = null;

            try
            {
                // 弹出保存对话框让用户选择保存位置
                var saveDialog = new Microsoft.Win32.SaveFileDialog
                {
                    Title = "保存安全评估报告",
                    Filter = "PDF文件 (*.pdf)|*.pdf",
                    DefaultExt = "pdf",
                    FileName = $"HistorySecurityReport_{targetIp.Replace(".", "_")}_{DateTime.Now:yyyyMMdd_HHmmss}.pdf"
                };

                // 设置初始目录为桌面
                var desktopPath = Environment.GetFolderPath(Environment.SpecialFolder.Desktop);
                if (Directory.Exists(desktopPath))
                {
                    saveDialog.InitialDirectory = desktopPath;
                }

                if (saveDialog.ShowDialog() != true)
                {
                    Debug.WriteLine("[HistoryReport] 用户取消了保存操作");
                    return string.Empty;
                }

                filePath = saveDialog.FileName;
                
                // 确保目录存在
                var directoryPath = Path.GetDirectoryName(filePath);
                if (!string.IsNullOrEmpty(directoryPath) && !Directory.Exists(directoryPath))
                {
                    Directory.CreateDirectory(directoryPath);
                }
                
                tempPath = Path.Combine(Path.GetTempPath(), $"report_temp_{Guid.NewGuid():N}.pdf");

                if (File.Exists(tempPath)) File.Delete(tempPath);

                using (var fs = new FileStream(tempPath, FileMode.Create, FileAccess.Write, FileShare.None))
                using (Document doc = new Document(PageSize.A4, 55, 55, 70, 55))
                using (PdfWriter writer = PdfWriter.GetInstance(doc, fs))
                {
                    writer.CloseStream = false;

                    doc.Open();

                    var fonts = LoadChineseFonts();
                    if (fonts.BaseFont == null)
                    {
                        Debug.WriteLine("[HistoryReport] 警告：所有中文字体加载失败，将使用Helvetica回退字体");
                        fonts = CreateFallbackFontCollection();
                    }

                    var pageEvent = new HistoryReportPageEvent();
                    pageEvent.BaseFont = fonts.BaseFont;
                    writer.PageEvent = pageEvent;

                    var reportId = record.ScanId ?? Guid.NewGuid().ToString("N").Substring(0, 8).ToUpper();
                    var scanTime = record.ScanTime.ToString("yyyy-MM-dd HH:mm:ss");
                    var reportGenerationTime = DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss");
                    var overallRiskLevel = CalculateOverallRiskLevel(safeVulns);
                    var scanDuration = record.ScanDuration > 0 ? $"{record.ScanDuration:F1} 秒" : "";

                    try { GenerateCoverPage(doc, writer, fonts, targetIp, scanTime, reportId, overallRiskLevel, safePorts, safeVulns, scanDuration, false); }
                    catch (Exception ex) { Debug.WriteLine($"[HistoryReport] 封面页生成错误: {ex.Message}"); AddErrorPlaceholder(doc, fonts, "封面页", ex.Message); }
                    doc.NewPage();

                    try { GenerateTableOfContents(doc, writer, fonts); }
                    catch (Exception ex) { Debug.WriteLine($"[HistoryReport] 目录页生成错误: {ex.Message}"); AddErrorPlaceholder(doc, fonts, "目录页", ex.Message); }
                    doc.NewPage();

                    try { GenerateExecutiveSummary(doc, fonts, safePorts, safeVulns, record.RiskAssessment, targetIp, reportGenerationTime); }
                    catch (Exception ex) { Debug.WriteLine($"[HistoryReport] 执行摘要生成错误: {ex.Message}"); AddErrorPlaceholder(doc, fonts, "执行摘要", ex.Message); }
                    doc.NewPage();

                    try { GeneratePortScanResultsSection(doc, fonts, safePorts); }
                    catch (Exception ex) { Debug.WriteLine($"[HistoryReport] 端口扫描结果生成错误: {ex.Message}"); AddErrorPlaceholder(doc, fonts, "端口扫描结果", ex.Message); }
                    doc.NewPage();

                    try { GenerateVulnerabilityDetailsSection(doc, fonts, safeVulns); }
                    catch (Exception ex) { Debug.WriteLine($"[HistoryReport] 漏洞详情生成错误: {ex.Message}"); AddErrorPlaceholder(doc, fonts, "漏洞详情", ex.Message); }
                    doc.NewPage();

                    try { GenerateRiskAssessmentSection(doc, fonts, record.RiskAssessment, safeVulns, safePorts); }
                    catch (Exception ex) { Debug.WriteLine($"[HistoryReport] 风险评估生成错误: {ex.Message}"); AddErrorPlaceholder(doc, fonts, "风险评估", ex.Message); }
                    doc.NewPage();

                    try { GenerateRemediationSection(doc, fonts, safeVulns); }
                    catch (Exception ex) { Debug.WriteLine($"[HistoryReport] 修复建议生成错误: {ex.Message}"); AddErrorPlaceholder(doc, fonts, "修复建议", ex.Message); }

                    doc.Close();
                }

                if (!ValidatePdfFile(tempPath))
                {
                    throw new InvalidDataException("生成的PDF文件格式验证失败，文件可能已损坏");
                }

                File.Copy(tempPath, filePath, true);
                Debug.WriteLine($"[HistoryReport] 专业PDF报告生成成功：{filePath}");
                return filePath;
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"[HistoryReport] 报告生成失败: {ex.Message}");
                MessageBox.Show($"历史记录PDF报告生成失败:\n{ex.Message}", "错误", MessageBoxButton.OK, MessageBoxImage.Error);
                return string.Empty;
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

        public static string GenerateFromMultipleRecords(List<CompleteScanResult> records)
        {
            if (records == null || !records.Any())
            {
                MessageBox.Show("扫描记录列表为空，无法生成综合报告。", "数据为空", MessageBoxButton.OK, MessageBoxImage.Warning);
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
                    MessageBox.Show("所有扫描记录均无有效数据，无法生成综合报告。", "数据为空", MessageBoxButton.OK, MessageBoxImage.Warning);
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
                MessageBox.Show($"综合PDF报告生成失败:\n{ex.Message}", "错误", MessageBoxButton.OK, MessageBoxImage.Error);
                return string.Empty;
            }
        }

        private static string GenerateCompositeReport(CompleteScanResult compositeRecord, int recordCount)
        {
            var targetIp = compositeRecord.TargetIp;
            var safePorts = compositeRecord.PortScanResults ?? new List<PortScanResult>();
            var safeVulns = compositeRecord.VulnerabilityResults ?? new List<VulnerabilityResult>();
            string tempPath = null;
            string filePath = null;

            try
            {
                var reportDir = Environment.GetFolderPath(Environment.SpecialFolder.Desktop);
                if (!Directory.Exists(reportDir))
                    Directory.CreateDirectory(reportDir);

                var fileName = $"CompositeSecurityReport_{DateTime.Now:yyyyMMdd_HHmmss}.pdf";
                filePath = Path.Combine(reportDir, fileName);
                tempPath = Path.Combine(Path.GetTempPath(), $"composite_temp_{Guid.NewGuid():N}.pdf");

                if (File.Exists(tempPath)) File.Delete(tempPath);

                using (var fs = new FileStream(tempPath, FileMode.Create, FileAccess.Write, FileShare.None))
                using (Document doc = new Document(PageSize.A4, 55, 55, 70, 55))
                using (PdfWriter writer = PdfWriter.GetInstance(doc, fs))
                {
                    writer.CloseStream = false;

                    doc.Open();

                    var fonts = LoadChineseFonts();
                    if (fonts.BaseFont == null)
                    {
                        fonts = CreateFallbackFontCollection();
                    }

                    var pageEvent = new HistoryReportPageEvent();
                    pageEvent.BaseFont = fonts.BaseFont;
                    writer.PageEvent = pageEvent;

                    var reportId = compositeRecord.ScanId;
                    var scanTime = $"{compositeRecord.ScanTime:yyyy-MM-dd} ~ {DateTime.Now:yyyy-MM-dd}";
                    var reportGenerationTime = DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss");
                    var overallRiskLevel = compositeRecord.RiskLevel;
                    var scanDuration = $"{compositeRecord.ScanDuration:F1} 秒 (共{recordCount}次扫描)";

                    try { GenerateCoverPage(doc, writer, fonts, targetIp, scanTime, reportId, overallRiskLevel, safePorts, safeVulns, scanDuration, true); }
                    catch (Exception ex) { Debug.WriteLine($"[HistoryReport] 综合报告封面页生成错误: {ex.Message}"); AddErrorPlaceholder(doc, fonts, "封面页", ex.Message); }
                    doc.NewPage();

                    try { GenerateTableOfContents(doc, writer, fonts); }
                    catch (Exception ex) { Debug.WriteLine($"[HistoryReport] 综合报告目录页生成错误: {ex.Message}"); AddErrorPlaceholder(doc, fonts, "目录页", ex.Message); }
                    doc.NewPage();

                    try { GenerateExecutiveSummary(doc, fonts, safePorts, safeVulns, compositeRecord.RiskAssessment, targetIp, reportGenerationTime, recordCount); }
                    catch (Exception ex) { Debug.WriteLine($"[HistoryReport] 综合报告执行摘要生成错误: {ex.Message}"); AddErrorPlaceholder(doc, fonts, "执行摘要", ex.Message); }
                    doc.NewPage();

                    try { GeneratePortScanResultsSection(doc, fonts, safePorts); }
                    catch (Exception ex) { Debug.WriteLine($"[HistoryReport] 综合报告端口扫描结果生成错误: {ex.Message}"); AddErrorPlaceholder(doc, fonts, "端口扫描结果", ex.Message); }
                    doc.NewPage();

                    try { GenerateVulnerabilityDetailsSection(doc, fonts, safeVulns); }
                    catch (Exception ex) { Debug.WriteLine($"[HistoryReport] 综合报告漏洞详情生成错误: {ex.Message}"); AddErrorPlaceholder(doc, fonts, "漏洞详情", ex.Message); }
                    doc.NewPage();

                    try { GenerateRiskAssessmentSection(doc, fonts, compositeRecord.RiskAssessment, safeVulns, safePorts); }
                    catch (Exception ex) { Debug.WriteLine($"[HistoryReport] 综合报告风险评估生成错误: {ex.Message}"); AddErrorPlaceholder(doc, fonts, "风险评估", ex.Message); }
                    doc.NewPage();

                    try { GenerateRemediationSection(doc, fonts, safeVulns); }
                    catch (Exception ex) { Debug.WriteLine($"[HistoryReport] 综合报告修复建议生成错误: {ex.Message}"); AddErrorPlaceholder(doc, fonts, "修复建议", ex.Message); }

                    doc.Close();
                }

                if (!ValidatePdfFile(tempPath))
                {
                    throw new InvalidDataException("生成的综合PDF文件格式验证失败，文件可能已损坏");
                }

                File.Copy(tempPath, filePath, true);
                Debug.WriteLine($"[HistoryReport] 综合PDF报告生成成功：{filePath} (合并{recordCount}条记录)");
                return filePath;
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"[HistoryReport] 综合报告生成失败: {ex.Message}");
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

        #endregion

        #region 字体加载系统

        private static FontCollection LoadChineseFonts()
        {
            var fonts = new FontCollection();
            BaseFont bf = null;

            Debug.WriteLine("[字体] 开始加载中文字体...");

            var fontCandidates = new List<(string Path, string Description)>
            {
                (@"C:\Windows\Fonts\msyh.ttc,0", "微软雅黑(TTC索引0)"),
                (@"C:\Windows\Fonts\msyh.ttf", "微软雅黑(TTF)"),
                (@"C:\Windows\Fonts\simhei.ttf", "黑体"),
                (@"C:\Windows\Fonts\simsun.ttc,0", "宋体(TTC索引0)"),
                (@"C:\Windows\Fonts\msyhl.ttc,0", "微软雅黑Light"),
                (@"C:\Windows\Fonts\simsun.ttc,1", "宋体(TTC索引1)")
            };

            foreach (var (fontPath, desc) in fontCandidates)
            {
                try
                {
                    var actualPath = fontPath.Split(',')[0];
                    if (!File.Exists(actualPath))
                    {
                        Debug.WriteLine($"[字体] 文件不存在: {desc} - {actualPath}");
                        continue;
                    }

                    bf = BaseFont.CreateFont(fontPath, BaseFont.IDENTITY_H, BaseFont.EMBEDDED);
                    Debug.WriteLine($"[字体] ✓ 成功加载: {desc} ({fontPath})");
                    break;
                }
                catch (Exception ex)
                {
                    Debug.WriteLine($"[字体] ✗ 加载失败: {desc} - {ex.Message}");
                }
            }

            if (bf == null)
            {
                Debug.WriteLine("[字体] 预定义字体全部失败，尝试扫描系统字体目录...");
                try
                {
                    var fontDir = new DirectoryInfo(@"C:\Windows\Fonts");
                    if (fontDir.Exists)
                    {
                        var chineseFontPatterns = new[] { "sim*.ttf", "msyh*", "kai*.ttf", "fang*.ttf" };
                        var foundFonts = new List<FileInfo>();

                        foreach (var pattern in chineseFontPatterns)
                        {
                            try
                            {
                                foundFonts.AddRange(fontDir.GetFiles(pattern));
                            }
                            catch { }
                        }

                        foreach (var fontFile in foundFonts.Take(10))
                        {
                            try
                            {
                                var fontPath = fontFile.FullName;
                                if (fontFile.Extension.ToLower() == ".ttc")
                                    fontPath += ",0";

                                bf = BaseFont.CreateFont(fontPath, BaseFont.IDENTITY_H, BaseFont.EMBEDDED);
                                Debug.WriteLine($"[字体] ✓ 系统目录扫描成功: {fontFile.Name}");
                                break;
                            }
                            catch (Exception ex)
                            {
                                Debug.WriteLine($"[字体] ✗ 系统字体加载失败: {fontFile.Name} - {ex.Message}");
                            }
                        }
                    }
                }
                catch (Exception ex)
                {
                    Debug.WriteLine($"[字体] ✗ 系统字体目录扫描异常: {ex.Message}");
                }
            }

            if (bf == null)
            {
                Debug.WriteLine("[字体] ⚠ 所有中文字体加载失败，使用Helvetica回退字体（中文将无法显示）");
                try
                {
                    bf = BaseFont.CreateFont(BaseFont.HELVETICA, BaseFont.CP1252, false);
                    fonts.IsFallbackFont = true;
                }
                catch (Exception ex)
                {
                    Debug.WriteLine($"[字体] ✗ Helvetica回退也失败: {ex.Message}");
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

                Debug.WriteLine($"[字体] 字体集合创建完成，回退模式: {fonts.IsFallbackFont}");
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
            var deepBlue = new BaseColor(26, 54, 93);
            var lightBlue = new BaseColor(37, 99, 235);
            var baseFont = fonts.BaseFont;
            
            doc.Add(new Paragraph(" ", fonts.BodyFont) { SpacingBefore = 40 });
            
            // 1. 顶部装饰条 - 渐变效果模拟
            var topBarTable = new PdfPTable(1);
            topBarTable.TotalWidth = 595;
            var topBarCell = new PdfPCell(new Phrase(" ", fonts.BodyFont))
            {
                BackgroundColor = deepBlue,
                MinimumHeight = 8,
                Border = Rectangle.NO_BORDER
            };
            topBarTable.AddCell(topBarCell);
            doc.Add(topBarTable);
            
            // 2. 报告标识区域
            doc.Add(new Paragraph(" ", fonts.BodyFont) { SpacingBefore = 25 });
            
            if (baseFont != null)
            {
                // 英文报告类型标识
                var reportTypePara = new Paragraph("SECURITY ASSESSMENT REPORT", 
                    new Font(baseFont, 11, Font.BOLD, lightBlue))
                {
                    Alignment = Element.ALIGN_CENTER,
                    SpacingAfter = 6
                };
                doc.Add(reportTypePara);
                
                // 中文主标题
                var mainTitleText = isComposite ? "网络安全综合扫描评估报告" : "网络安全漏洞扫描评估报告";
                var mainTitle = new Paragraph(mainTitleText, new Font(baseFont, 24, Font.BOLD, deepBlue))
                {
                    Alignment = Element.ALIGN_CENTER,
                    SpacingBefore = 8,
                    SpacingAfter = 6
                };
                doc.Add(mainTitle);
                
                // 英文副标题
                var subTitle = new Paragraph("Network Security Vulnerability Assessment Report", 
                    new Font(baseFont, 10, Font.NORMAL, COLOR_SECONDARY_TEXT))
                {
                    Alignment = Element.ALIGN_CENTER,
                    SpacingAfter = 20
                };
                doc.Add(subTitle);
            }
            
            // 3. 装饰分隔线 - 双线设计
            var decoLineTable = new PdfPTable(1);
            decoLineTable.TotalWidth = 450;
            decoLineTable.HorizontalAlignment = Element.ALIGN_CENTER;
            
            // 上粗线
            var upperLineCell = new PdfPCell(new Phrase(" ", fonts.BodyFont))
            {
                Border = Rectangle.BOX,
                BorderColor = deepBlue,
                BorderWidthTop = 2f,
                BorderWidthBottom = 0f,
                BorderWidthLeft = 0f,
                BorderWidthRight = 0f,
                FixedHeight = 3
            };
            decoLineTable.AddCell(upperLineCell);
            
            // 下细线
            var lowerLineCell = new PdfPCell(new Phrase(" ", fonts.BodyFont))
            {
                Border = Rectangle.BOX,
                BorderColor = COLOR_SEPARATOR,
                BorderWidthTop = 0.5f,
                BorderWidthBottom = 0f,
                BorderWidthLeft = 0f,
                BorderWidthRight = 0f,
                FixedHeight = 2
            };
            decoLineTable.AddCell(lowerLineCell);
            doc.Add(decoLineTable);
            
            // 4. 核心信息表格 - 专业卡片式布局
            doc.Add(new Paragraph(" ", fonts.BodyFont) { SpacingBefore = 25 });
            
            var infoContainer = new PdfPTable(1);
            infoContainer.TotalWidth = 420;
            infoContainer.HorizontalAlignment = Element.ALIGN_CENTER;
            
            var infoCell = new PdfPCell();
            infoCell.Border = Rectangle.BOX;
            infoCell.BorderColor = new BaseColor(220, 220, 230);
            infoCell.BorderWidth = 1f;
            infoCell.Padding = 18;
            infoCell.BackgroundColor = new BaseColor(250, 251, 253);
            
            var infoTable = new PdfPTable(2);
            infoTable.TotalWidth = 380;
            infoTable.SetWidths(new float[] { 1.2f, 2.8f });
            
            Font labelFont, valueFont;
            if (fonts.BaseFont != null)
            {
                labelFont = new Font(fonts.BaseFont, 10, Font.BOLD, new BaseColor(71, 85, 105));
                valueFont = new Font(fonts.BaseFont, 10, Font.NORMAL, new BaseColor(51, 65, 85));
            }
            else
            {
                labelFont = new Font(Font.FontFamily.HELVETICA, 10, Font.BOLD, new BaseColor(71, 85, 105));
                valueFont = new Font(Font.FontFamily.HELVETICA, 10, Font.NORMAL, new BaseColor(51, 65, 85));
            }
            
            var safeTargetIp = string.IsNullOrWhiteSpace(targetIp) ? "未知目标" : targetIp;
            var safeScanTime = string.IsNullOrWhiteSpace(scanTime) ? DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss") : scanTime;
            var safeReportId = string.IsNullOrWhiteSpace(reportId) ? "N/A" : reportId;
            
            AddCoverInfoRow(infoTable, "报告编号", $"RPT-{DateTime.Now:yyyyMMdd}-{safeReportId}", labelFont, valueFont);
            AddCoverInfoRow(infoTable, "目标系统", $"{safeTargetIp} ({(isComposite ? "多目标综合" : "内网服务器")})", labelFont, valueFont);
            AddCoverInfoRow(infoTable, "扫描时间", safeScanTime, labelFont, valueFont);
            AddCoverInfoRow(infoTable, "扫描类型", isComposite ? "综合扫描" : "全面漏洞扫描", labelFont, valueFont);
            if (!string.IsNullOrEmpty(scanDuration))
            {
                AddCoverInfoRow(infoTable, "扫描耗时", scanDuration, labelFont, valueFont);
            }
            AddCoverInfoRow(infoTable, "生成时间", DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss"), labelFont, valueFont);
            
            infoCell.AddElement(infoTable);
            infoContainer.AddCell(infoCell);
            doc.Add(infoContainer);
            
            // 5. 统计数据卡片区 - 4个关键指标
            doc.Add(new Paragraph(" ", fonts.BodyFont) { SpacingBefore = 28 });
            
            var statsRow = new PdfPTable(4);
            statsRow.TotalWidth = 520;
            statsRow.SetWidths(new float[] { 1f, 1f, 1f, 1f });
            statsRow.HorizontalAlignment = Element.ALIGN_CENTER;
            statsRow.SpacingBefore = 5;
            
            var openPortCount = ports?.Count(p => p?.Status == "开放" || p?.Status?.ToLower() == "open") ?? 0;
            var vulnCount = vulns?.Count ?? 0;
            var safeRiskLevel = string.IsNullOrWhiteSpace(overallRiskLevel) ? "信息" : overallRiskLevel;
            var riskColorScheme = GetRiskColorScheme(safeRiskLevel);
            var highRiskVulnCount = vulns?.Count(v => IsCritical(v?.RiskLevel) || IsHigh(v?.RiskLevel)) ?? 0;
            var highRiskPercent = vulnCount > 0 ? (int)((double)highRiskVulnCount / vulnCount * 100) : 0;
            
            AddExpertStatCard(statsRow, "风险等级", riskColorScheme.DisplayName, riskColorScheme.ForegroundColor, fonts);
            AddExpertStatCard(statsRow, "开放端口", $"{openPortCount}个", new BaseColor(52, 152, 219), fonts);
            AddExpertStatCard(statsRow, "漏洞总数", $"{vulnCount}个", new BaseColor(231, 76, 60), fonts);
            AddExpertStatCard(statsRow, "高危占比", $"{highRiskPercent}%", new BaseColor(243, 156, 18), fonts);
            
            doc.Add(statsRow);
            
            // 6. 底部区域
            doc.Add(new Paragraph(" ", fonts.BodyFont) { SpacingBefore = 45 });
            
            // 底部分隔线
            var bottomLineTable = new PdfPTable(1);
            bottomLineTable.TotalWidth = 450;
            bottomLineTable.HorizontalAlignment = Element.ALIGN_CENTER;
            var bottomLineCell = new PdfPCell(new Phrase(" ", fonts.BodyFont))
            {
                Border = Rectangle.BOX,
                BorderColor = COLOR_SEPARATOR,
                BorderWidthTop = 1f,
                BorderWidthBottom = 0f,
                BorderWidthLeft = 0f,
                BorderWidthRight = 0f,
                FixedHeight = 4
            };
            bottomLineTable.AddCell(bottomLineCell);
            doc.Add(bottomLineTable);
            
            // 版本和机密标识
            if (baseFont != null)
            {
                doc.Add(new Paragraph(" ", fonts.BodyFont) { SpacingBefore = 12 });
                
                var versionPara = new Paragraph($"NetSecurityScanner v{VersionHelper.GetVersion()} | Professional Edition", 
                    new Font(baseFont, 9, Font.NORMAL, COLOR_GRAY_HINT))
                {
                    Alignment = Element.ALIGN_CENTER,
                    SpacingAfter = 6
                };
                doc.Add(versionPara);
                
                var confidentialPara = new Paragraph("★ 机密文件 - 仅限内部使用 - Confidential ★", 
                    new Font(baseFont, 9, Font.BOLD, COLOR_CONFIDENTIAL))
                {
                    Alignment = Element.ALIGN_CENTER,
                    SpacingBefore = 4
                };
                doc.Add(confidentialPara);
            }
        }

        private static void AddCoverInfoRow(PdfPTable table, string label, string value, Font labelFont, Font valueFont)
        {
            var labelCell = new PdfPCell(new Phrase(label, labelFont))
            {
                Border = Rectangle.BOX,
                BorderColor = COLOR_BORDER,
                BorderWidth = 0.5f,
                HorizontalAlignment = Element.ALIGN_RIGHT,
                PaddingRight = 12,
                PaddingTop = 8,
                PaddingBottom = 8,
                VerticalAlignment = Element.ALIGN_MIDDLE,
                BackgroundColor = new BaseColor(248, 250, 252)
            };

            var valueCell = new PdfPCell(new Phrase(value, valueFont))
            {
                Border = Rectangle.BOX,
                BorderColor = COLOR_BORDER,
                BorderWidth = 0.5f,
                HorizontalAlignment = Element.ALIGN_LEFT,
                PaddingLeft = 8,
                PaddingTop = 8,
                PaddingBottom = 8,
                VerticalAlignment = Element.ALIGN_MIDDLE
            };

            table.AddCell(labelCell);
            table.AddCell(valueCell);
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

            if (fonts.BaseFont != null)
            {
                var labelPhrase = new Phrase(label, new Font(fonts.BaseFont, 9, Font.NORMAL, COLOR_SECONDARY_TEXT));
                var valuePhrase = new Phrase($"\n{value}", new Font(fonts.BaseFont, 17, Font.BOLD, accentColor));

                content.Add(labelPhrase);
                content.Add(valuePhrase);
            }
            else
            {
                var fallbackLabelFont = new Font(Font.FontFamily.HELVETICA, 9, Font.NORMAL, COLOR_SECONDARY_TEXT);
                var fallbackValueFont = new Font(Font.FontFamily.HELVETICA, 17, Font.BOLD, accentColor);

                content.Add(new Phrase(label, fallbackLabelFont));
                content.Add(new Phrase($"\n{value}", fallbackValueFont));
            }

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
            var deepBlue = new BaseColor(26, 54, 93);
            var darkGray = new BaseColor(30, 41, 59);
            var lightBlue = new BaseColor(37, 99, 235);
            var separatorColor = new BaseColor(203, 213, 225);
            var baseFont = fonts.BaseFont;
            
            // 1. 页面标题区域
            if (baseFont != null)
            {
                // 英文标识
                var tocIdPara = new Paragraph("TABLE OF CONTENTS", 
                    new Font(baseFont, 10, Font.BOLD, lightBlue))
                {
                    Alignment = Element.ALIGN_CENTER,
                    SpacingBefore = 15,
                    SpacingAfter = 6
                };
                doc.Add(tocIdPara);
                
                // 中文主标题
                var tocTitle = new Paragraph("目    录", new Font(baseFont, 18, Font.BOLD, deepBlue))
                {
                    Alignment = Element.ALIGN_CENTER,
                    SpacingAfter = 4
                };
                doc.Add(tocTitle);
                
                // 装饰线
                var titleDecoTable = new PdfPTable(1);
                titleDecoTable.TotalWidth = 200;
                titleDecoTable.HorizontalAlignment = Element.ALIGN_CENTER;
                var titleDecoCell = new PdfPCell(new Phrase(" ", fonts.BodyFont))
                {
                    Border = Rectangle.BOX,
                    BorderColor = deepBlue,
                    BorderWidthTop = 2.5f,
                    BorderWidthBottom = 0f,
                    BorderWidthLeft = 0f,
                    BorderWidthRight = 0f,
                    FixedHeight = 3
                };
                titleDecoTable.AddCell(titleDecoCell);
                doc.Add(titleDecoTable);
            }
            
            // 2. 目录内容表格
            doc.Add(new Paragraph(" ", fonts.BodyFont) { SpacingBefore = 20 });
            
            if (baseFont != null)
            {
                var tocContainer = new PdfPTable(1);
                tocContainer.WidthPercentage = 88;
                tocContainer.SpacingBefore = 8;
                
                var chapterFont = new Font(baseFont, 12, Font.BOLD, deepBlue);
                var subChapterFont = new Font(baseFont, 10.5f, Font.NORMAL, new BaseColor(55, 65, 81));
                var pageFont = new Font(baseFont, 11, Font.BOLD, darkGray);
                var dotColor = new BaseColor(180, 190, 200);
                var dotFont = new Font(baseFont, 8, Font.NORMAL, dotColor);

                var tocEntries = new[]
                {
                    (Title: "一、执行摘要", Page: "3", IsChapter: true),
                    (Title: "      1.1  核心统计数据", Page: "3", IsChapter: false),
                    (Title: "      1.2  Top 5 高危漏洞", Page: "4", IsChapter: false),
                    (Title: "      1.3  服务分布摘要", Page: "4", IsChapter: false),
                    (Title: "二、端口扫描结果", Page: "5", IsChapter: true),
                    (Title: "三、漏洞详情分析", Page: "7", IsChapter: true),
                    (Title: "      3.1  漏洞概览表", Page: "7", IsChapter: false),
                    (Title: "      3.2  漏洞详细信息", Page: "8", IsChapter: false),
                    (Title: "四、风险评估", Page: "11", IsChapter: true),
                    (Title: "      4.1  风险评估项目", Page: "11", IsChapter: false),
                    (Title: "      4.2  风险分布可视化", Page: "12", IsChapter: false),
                    (Title: "      4.3  安全建议概述", Page: "12", IsChapter: false),
                    (Title: "五、修复建议", Page: "13", IsChapter: true),
                    (Title: "      5.1  修复优先级矩阵", Page: "13", IsChapter: false),
                    (Title: "      5.2  高危漏洞修复建议", Page: "14", IsChapter: false),
                    (Title: "      5.3  通用安全加固建议", Page: "15", IsChapter: false)
                };

                foreach (var entry in tocEntries)
                {
                    var rowTable = new PdfPTable(1);
                    rowTable.WidthPercentage = 100;
                    
                    var entryCell = new PdfPCell();
                    entryCell.Border = entry.IsChapter ? 
                        Rectangle.BOX : Rectangle.NO_BORDER;
                    
                    if (entry.IsChapter)
                    {
                        entryCell.BorderColor = new BaseColor(235, 240, 245);
                        entryCell.BorderWidth = 0.5f;
                        entryCell.PaddingTop = 10;
                        entryCell.PaddingBottom = 8;
                        entryCell.PaddingLeft = 12;
                        entryCell.BackgroundColor = new BaseColor(248, 250, 253);
                    }
                    else
                    {
                        entryCell.PaddingTop = 5;
                        entryCell.PaddingBottom = 4;
                        entryCell.PaddingLeft = 18;
                    }

                    var contentPara = new Paragraph();
                    var titleFont = entry.IsChapter ? chapterFont : subChapterFont;
                    contentPara.Add(new Phrase(entry.Title, titleFont));

                    var maxDots = entry.IsChapter ? 50 : 42;
                    var dotCount = Math.Max(6, maxDots - entry.Title.Length * 2);
                    var dots = new string('·', dotCount);
                    contentPara.Add(new Phrase(dots, dotFont));
                    contentPara.Add(new Phrase("  " + entry.Page, pageFont));

                    entryCell.Phrase = contentPara;
                    rowTable.AddCell(entryCell);
                    tocContainer.AddCell(rowTable);
                }

                doc.Add(tocContainer);
            }
            
            // 3. 底部装饰区域
            doc.Add(new Paragraph(" ", fonts.BodyFont) { SpacingBefore = 35 });
            
            // 分隔线
            var bottomSepTable = new PdfPTable(1);
            bottomSepTable.TotalWidth = 450;
            bottomSepTable.HorizontalAlignment = Element.ALIGN_CENTER;
            var bottomSepCell = new PdfPCell(new Phrase(" ", fonts.BodyFont))
            {
                Border = Rectangle.BOX,
                BorderColor = separatorColor,
                BorderWidthTop = 0.8f,
                BorderWidthBottom = 0f,
                BorderWidthLeft = 0f,
                BorderWidthRight = 0f,
                FixedHeight = 3
            };
            bottomSepTable.AddCell(bottomSepCell);
            doc.Add(bottomSepTable);
            
            // 免责声明
            if (baseFont != null)
            {
                var disclaimerText = "免责声明：本报告由自动化安全扫描工具生成，结果仅供参考。" +
                                    "对于关键安全问题，建议进行人工验证和深度安全分析。";

                var disclaimerBox = new PdfPTable(1);
                disclaimerBox.TotalWidth = 450;
                disclaimerBox.HorizontalAlignment = Element.ALIGN_CENTER;
                var disclaimerCell = new PdfPCell(
                    new Phrase(disclaimerText,
                        new Font(baseFont, 8.5f, Font.NORMAL, COLOR_GRAY_HINT)))
                {
                    Border = Rectangle.BOX,
                    BorderColor = new BaseColor(230, 235, 240),
                    BorderWidth = 0.5f,
                    Padding = 12,
                    BackgroundColor = new BaseColor(252, 253, 255),
                    HorizontalAlignment = Element.ALIGN_CENTER
                };
                disclaimerBox.AddCell(disclaimerCell);
                
                doc.Add(new Paragraph(" ", fonts.BodyFont) { SpacingBefore = 15 });
                doc.Add(disclaimerBox);
            }
        }

        #endregion

        #region 第3章：执行摘要章节

        private static void GenerateExecutiveSummary(Document doc, FontCollection fonts,
            List<PortScanResult> ports, List<VulnerabilityResult> vulns,
            RiskAssessmentSummary riskAssessment, string targetIp,
            string reportGenerationTime, int compositeRecordCount = 0)
        {
            var deepBlue = new BaseColor(26, 54, 93);
            var headerBg = new BaseColor(30, 41, 59);

            // 章节标题 - 带装饰线
            var chapterTitleTable = new PdfPTable(1);
            chapterTitleTable.WidthPercentage = 100;
            chapterTitleTable.SpacingBefore = 15;
            
            var titleCell = new PdfPCell(
                new Paragraph("一、执行摘要", 
                    new Font(fonts.BaseFont, 16, Font.BOLD, deepBlue)))
            {
                Border = Rectangle.BOX,
                BorderColor = deepBlue,
                BorderWidthBottom = 2.5f,
                BorderWidthTop = 0f,
                BorderWidthLeft = 0f,
                BorderWidthRight = 0f,
                PaddingBottom = 10,
                PaddingLeft = 5,
                BackgroundColor = BaseColor.WHITE
            };
            chapterTitleTable.AddCell(titleCell);
            doc.Add(chapterTitleTable);

            // 引言段落
            var introText = compositeRecordCount > 0 ?
                $"本报告综合了{compositeRecordCount}次独立扫描的结果，提供跨时间段的安全态势分析。" :
                "本节提供本次安全扫描的核心发现和统计概览，帮助快速了解目标系统的整体安全态势。";

            var introBox = new PdfPTable(1);
            introBox.WidthPercentage = 98;
            var introCell = new PdfPCell(new Paragraph(introText, fonts.BodyFont) { Leading = 17 })
            {
                Border = Rectangle.BOX,
                BorderColor = new BaseColor(235, 240, 245),
                BorderWidth = 0.8f,
                Padding = 14,
                BackgroundColor = new BaseColor(250, 251, 255),
                Indent = 12
            };
            introBox.AddCell(introCell);
            doc.Add(introBox);

            // 1.1 核心统计数据子标题
            doc.Add(new Paragraph(" ", fonts.BodyFont) { SpacingBefore = 18 });
            
            var subHeaderTable = new PdfPTable(1);
            subHeaderTable.WidthPercentage = 100;
            var subHeaderCell = new PdfPCell(
                new Paragraph("1.1 核心统计数据", 
                    new Font(fonts.BaseFont, 13, Font.BOLD, new BaseColor(52, 73, 94))))
            {
                Border = Rectangle.NO_BORDER,
                PaddingLeft = 8,
                PaddingBottom = 6,
                BackgroundColor = BaseColor.WHITE
            };
            subHeaderTable.AddCell(subHeaderCell);
            doc.Add(subHeaderTable);

            var safePorts = ports ?? new List<PortScanResult>();
            var safeVulns = vulns ?? new List<VulnerabilityResult>();

            var openPorts = safePorts.Where(p =>
                p?.Status == "开放" || p?.Status?.ToLower() == "open" ||
                p?.Status?.ToLower() == "open|filtered").ToList();
            var totalPorts = safePorts.Count;

            // 统计卡片 - 4列布局
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

            // 1.2 Top 5 高危漏洞
            if (safeVulns.Any())
            {
                doc.Add(new Paragraph(" ", fonts.BodyFont) { SpacingBefore = 22 });
                
                var topVulnHeaderTable = new PdfPTable(1);
                topVulnHeaderTable.WidthPercentage = 100;
                var topVulnHeaderCell = new PdfPCell(
                    new Paragraph("1.2 Top 5 高危漏洞", 
                        new Font(fonts.BaseFont, 13, Font.BOLD, new BaseColor(52, 73, 94))))
                {
                    Border = Rectangle.NO_BORDER,
                    PaddingLeft = 8,
                    PaddingBottom = 8,
                    BackgroundColor = BaseColor.WHITE
                };
                topVulnHeaderTable.AddCell(topVulnHeaderCell);
                doc.Add(topVulnHeaderTable);

                var topVulns = safeVulns
                    .OrderByDescending(v => GetRiskPriority(v?.RiskLevel))
                    .Take(5)
                    .ToList();

                var topVulnTable = new PdfPTable(4);
                topVulnTable.WidthPercentage = 98;
                topVulnTable.SetWidths(new float[] { 1f, 2.8f, 1.3f, 1.2f });
                topVulnTable.SpacingBefore = 6;
                topVulnTable.HeaderRows = 1;

                AddTableHeader(topVulnTable, new[] { "CVE编号", "漏洞名称", "风险等级", "端口" }, fonts);

                foreach (var vuln in topVulns)
                {
                    var isZebra = topVulns.IndexOf(vuln) % 2 == 1;
                    var safeName = string.IsNullOrWhiteSpace(vuln?.Name) ? "未知漏洞" : vuln.Name;
                    var safeRiskLevel = string.IsNullOrWhiteSpace(vuln?.RiskLevel) ? "未分类" : vuln.RiskLevel;
                    var safeCveId = string.IsNullOrWhiteSpace(vuln?.CveId) ? "-" : vuln.CveId;
                    var safePort = vuln?.Port.HasValue == true ? vuln.Port.Value.ToString() : "-";

                    AddTopVulnRow(topVulnTable, safeCveId, safeName, safeRiskLevel, safePort, fonts, isZebra);
                }

                doc.Add(topVulnTable);
            }

            // 1.3 服务分布摘要
            if (safePorts.Any())
            {
                doc.Add(new Paragraph(" ", fonts.BodyFont) { SpacingBefore = 22 });
                
                var svcHeaderTable = new PdfPTable(1);
                svcHeaderTable.WidthPercentage = 100;
                var svcHeaderCell = new PdfPCell(
                    new Paragraph("1.3 服务分布摘要", 
                        new Font(fonts.BaseFont, 13, Font.BOLD, new BaseColor(52, 73, 94))))
                {
                    Border = Rectangle.NO_BORDER,
                    PaddingLeft = 8,
                    PaddingBottom = 8,
                    BackgroundColor = BaseColor.WHITE
                };
                svcHeaderTable.AddCell(svcHeaderCell);
                doc.Add(svcHeaderTable);

                var serviceGroups = openPorts
                    .Where(p => !string.IsNullOrEmpty(p?.Service))
                    .GroupBy(p => p.Service)
                    .OrderByDescending(g => g.Count())
                    .Take(8)
                    .ToList();

                var serviceTable = new PdfPTable(3);
                serviceTable.WidthPercentage = 72;
                serviceTable.SetWidths(new float[] { 2.2f, 1.2f, 1.8f });
                serviceTable.SpacingBefore = 6;
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

            // 扫描范围说明
            doc.Add(new Paragraph(" ", fonts.BodyFont) { SpacingBefore = 22 });
            
            var scopeHeaderTable = new PdfPTable(1);
            scopeHeaderTable.WidthPercentage = 98;
            var scopeHeaderCell = new PdfPCell(
                new Paragraph("扫描范围说明", 
                    new Font(fonts.BaseFont, 11, Font.BOLD, new BaseColor(85, 85, 85))))
            {
                Border = Rectangle.BOX,
                BorderColor = new BaseColor(230, 235, 240),
                BorderWidthBottom = 1.5f,
                BorderWidthTop = 0f,
                BorderWidthLeft = 0f,
                BorderWidthRight = 0f,
                PaddingBottom = 8,
                PaddingLeft = 10,
                BackgroundColor = BaseColor.WHITE
            };
            scopeHeaderTable.AddCell(scopeHeaderCell);
            doc.Add(scopeHeaderTable);

            var scopeText = $"本次扫描覆盖目标系统 {targetIp ?? "未知"}，检测了 {totalPorts} 个端口，" +
                           $"发现 {safeVulns.Count} 个潜在安全问题。" +
                           "扫描结果基于当前系统配置和网络环境，建议定期执行安全评估。";

            var scopeContentTable = new PdfPTable(1);
            scopeContentTable.WidthPercentage = 98;
            var scopeContentCell = new PdfPCell(new Paragraph(scopeText, fonts.BodyFont) { Leading = 16 })
            {
                Border = Rectangle.BOX,
                BorderColor = new BaseColor(235, 240, 245),
                BorderWidth = 0.5f,
                Padding = 12,
                BackgroundColor = new BaseColor(252, 253, 255),
                Indent = 10
            };
            scopeContentTable.AddCell(scopeContentCell);
            doc.Add(scopeContentTable);
        }

        private static void AddStatCard(PdfPTable table, string label, string value, BaseColor accentColor, FontCollection fonts)
        {
            var outerCell = new PdfPCell();
            outerCell.Border = Rectangle.BOX;
            outerCell.BorderColor = accentColor;
            outerCell.BorderWidth = 1.2f;
            outerCell.Padding = 14;
            outerCell.VerticalAlignment = Element.ALIGN_MIDDLE;
            outerCell.BackgroundColor = BaseColor.WHITE;

            var innerPara = new Paragraph()
            {
                Alignment = Element.ALIGN_CENTER,
                SpacingBefore = 5,
                SpacingAfter = 5
            };
            
            if (fonts.BaseFont != null)
            {
                innerPara.Add(new Phrase($"{label}\n", new Font(fonts.BaseFont, 9, Font.NORMAL, COLOR_SECONDARY_TEXT)));
                innerPara.Add(new Phrase(value, new Font(fonts.BaseFont, 18, Font.BOLD, accentColor)));
            }
            else
            {
                var fallbackLabelFont = new Font(Font.FontFamily.HELVETICA, 9, Font.NORMAL, COLOR_SECONDARY_TEXT);
                var fallbackValueFont = new Font(Font.FontFamily.HELVETICA, 18, Font.BOLD, accentColor);
                
                innerPara.Add(new Phrase($"{label}\n", fallbackLabelFont));
                innerPara.Add(new Phrase(value, fallbackValueFont));
            }

            outerCell.Phrase = innerPara;
            table.AddCell(outerCell);
        }

        private static void AddTopVulnRow(PdfPTable table, string cveId, string name, string riskLevel,
            string port, FontCollection fonts, bool isZebra)
        {
            var bg = isZebra ? COLOR_ZEBRA : BaseColor.WHITE;

            table.AddCell(CreateCell(cveId ?? "-", fonts.TableCellFont, bg, Element.ALIGN_CENTER));
            table.AddCell(CreateCell(name, fonts.TableCellFont, bg));

            var riskScheme = GetRiskColorScheme(riskLevel);
            var riskFont = new Font(fonts.BaseFont, 9, Font.BOLD, riskScheme.ForegroundColor);
            table.AddCell(CreateRiskCell(riskScheme.DisplayName, riskFont, riskScheme));

            table.AddCell(CreateCell(port ?? "-", fonts.TableCellFont, bg, Element.ALIGN_CENTER));
        }

        #endregion

        #region 第4章：端口扫描结果表

        private static void GeneratePortScanResultsSection(Document doc, FontCollection fonts, List<PortScanResult> results)
        {
            var deepBlue = new BaseColor(26, 54, 93);
            var headerBg = new BaseColor(30, 41, 59);

            doc.Add(new Paragraph("二、端口扫描结果", new Font(fonts.BaseFont, 16, Font.BOLD, deepBlue))
            {
                SpacingBefore = 20,
                SpacingAfter = 15
            });

            var introPara = new Paragraph(
                "本节列出所有检测到的开放端口及其对应的服务信息。端口扫描是网络安全评估的基础环节，" +
                "通过识别开放端口可以发现潜在的攻击面。",
                fonts.BodyFont)
            {
                SpacingBefore = 8,
                SpacingAfter = 18,
                IndentationLeft = 15,
                Leading = 16,
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
                var tipTable = new PdfPTable(1);
                tipTable.TotalWidth = 480;
                var tipCell = new PdfPCell(new Phrase("本次扫描未发现开放端口", fonts.BodyFont))
                {
                    BackgroundColor = new BaseColor(248, 250, 252),
                    BorderColor = new BaseColor(203, 213, 225),
                    Border = Rectangle.BOX,
                    BorderWidth = 1,
                    Padding = 20,
                    HorizontalAlignment = Element.ALIGN_CENTER,
                    VerticalAlignment = Element.ALIGN_MIDDLE
                };
                tipTable.AddCell(tipCell);
                tipTable.SpacingBefore = 20;
                doc.Add(tipTable);
                return;
            }

            bool hasMorePorts = openPorts.Count > MAX_PORTS_DISPLAY;
            var displayPorts = hasMorePorts ? openPorts.Take(MAX_PORTS_DISPLAY).ToList() : openPorts;

            var table = new PdfPTable(6);
            table.WidthPercentage = 100;
            table.SetWidths(new float[] { 1f, 1f, 1.8f, 2f, 1f, 1.2f });
            table.SpacingBefore = 5;
            table.HeaderRows = 1;

            var headerFont = new Font(fonts.BaseFont, 10, Font.BOLD, BaseColor.WHITE);
            foreach (var header in new[] { "端口号", "协议", "服务名称", "版本", "状态", "响应时间" })
            {
                var headerCell = new PdfPCell(new Phrase(header, headerFont))
                {
                    BackgroundColor = headerBg,
                    HorizontalAlignment = Element.ALIGN_CENTER,
                    VerticalAlignment = Element.ALIGN_MIDDLE,
                    Padding = 8,
                    Border = Rectangle.BOX,
                    BorderColor = headerBg,
                    BorderWidth = 0.5f
                };
                table.AddCell(headerCell);
            }

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
                SpacingBefore = 12,
                IndentationLeft = 15
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
            var deepBlue = new BaseColor(26, 54, 93);
            var headerBg = new BaseColor(30, 41, 59);

            // 章节标题 - 带装饰线
            var chapterTitleTable = new PdfPTable(1);
            chapterTitleTable.WidthPercentage = 100;
            chapterTitleTable.SpacingBefore = 15;
            
            var titleCell = new PdfPCell(
                new Paragraph("三、漏洞详情分析", 
                    new Font(fonts.BaseFont, 16, Font.BOLD, deepBlue)))
            {
                Border = Rectangle.BOX,
                BorderColor = deepBlue,
                BorderWidthBottom = 2.5f,
                BorderWidthTop = 0f,
                BorderWidthLeft = 0f,
                BorderWidthRight = 0f,
                PaddingBottom = 10,
                PaddingLeft = 5,
                BackgroundColor = BaseColor.WHITE
            };
            chapterTitleTable.AddCell(titleCell);
            doc.Add(chapterTitleTable);

            // 引言段落
            var introBox = new PdfPTable(1);
            introBox.WidthPercentage = 98;
            var introCell = new PdfPCell(new Paragraph(
                "本节详细列出所有检测到的安全漏洞，按风险等级从高到低排列。" +
                "每个漏洞均附带描述、检测方法和修复建议，帮助安全团队快速定位和修复问题。",
                fonts.BodyFont) { Leading = 17 })
            {
                Border = Rectangle.BOX,
                BorderColor = new BaseColor(235, 240, 245),
                BorderWidth = 0.8f,
                Padding = 14,
                BackgroundColor = new BaseColor(250, 251, 255),
                Indent = 12
            };
            introBox.AddCell(introCell);
            doc.Add(introBox);

            var safeVulnerabilities = vulnerabilities ?? new List<VulnerabilityResult>();

            if (!safeVulnerabilities.Any())
            {
                var tipTable = new PdfPTable(1);
                tipTable.TotalWidth = 480;
                var tipCell = new PdfPCell(new Phrase("本次扫描未发现安全漏洞", fonts.BodyFont))
                {
                    BackgroundColor = new BaseColor(248, 250, 252),
                    BorderColor = new BaseColor(203, 213, 225),
                    Border = Rectangle.BOX,
                    BorderWidth = 1,
                    Padding = 20,
                    HorizontalAlignment = Element.ALIGN_CENTER,
                    VerticalAlignment = Element.ALIGN_MIDDLE
                };
                tipTable.AddCell(tipCell);
                tipTable.SpacingBefore = 20;
                doc.Add(tipTable);
                return;
            }

            bool hasMoreVulns = safeVulnerabilities.Count > MAX_VULN_DISPLAY;
            var displayVulns = hasMoreVulns ?
                safeVulnerabilities.Take(MAX_VULN_DISPLAY).ToList() : safeVulnerabilities;

            var sortedVulns = displayVulns
                .OrderByDescending(v => GetRiskPriority(v?.RiskLevel))
                .ToList();

            // 3.1 漏洞概览表子标题
            doc.Add(new Paragraph(" ", fonts.BodyFont) { SpacingBefore = 18 });
            
            var subHeaderTable = new PdfPTable(1);
            subHeaderTable.WidthPercentage = 100;
            var subHeaderCell = new PdfPCell(
                new Paragraph("3.1 漏洞概览表", 
                    new Font(fonts.BaseFont, 13, Font.BOLD, new BaseColor(52, 73, 94))))
            {
                Border = Rectangle.NO_BORDER,
                PaddingLeft = 8,
                PaddingBottom = 8,
                BackgroundColor = BaseColor.WHITE
            };
            subHeaderTable.AddCell(subHeaderCell);
            doc.Add(subHeaderTable);

            // 漏洞概览表格
            var table = new PdfPTable(7);
            table.WidthPercentage = 100;
            table.SetWidths(new float[] { 0.6f, 1.4f, 2.7f, 1.1f, 0.8f, 1.3f, 0.9f });
            table.SpacingBefore = 6;
            table.HeaderRows = 1;

            var headerFont = new Font(fonts.BaseFont, 9, Font.BOLD, BaseColor.WHITE);
            foreach (var header in new[] { "序号", "CVE编号", "漏洞名称", "风险等级", "端口", "服务", "CVSS" })
            {
                var headerCell = new PdfPCell(new Phrase(header, headerFont))
                {
                    BackgroundColor = headerBg,
                    HorizontalAlignment = Element.ALIGN_CENTER,
                    VerticalAlignment = Element.ALIGN_MIDDLE,
                    Padding = 7,
                    Border = Rectangle.BOX,
                    BorderColor = headerBg,
                    BorderWidth = 0.5f
                };
                table.AddCell(headerCell);
            }

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
                    var riskFont = new Font(fonts.BaseFont, 9, Font.BOLD, BaseColor.WHITE);
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
                var noteBox = new PdfPTable(1);
                noteBox.WidthPercentage = 98;
                noteBox.SpacingBefore = 12;
                
                var noteText = $"\n注：共发现 {safeVulnerabilities.Count} 个漏洞，" +
                    $"本报告展示前 {MAX_VULN_DISPLAY} 个高危漏洞的详细信息。";
                    
                var noteCell = new PdfPCell(new Paragraph(noteText,
                    new Font(fonts.BaseFont, 9, Font.NORMAL, new BaseColor(255, 152, 0))))
                {
                    Border = Rectangle.BOX,
                    BorderColor = new BaseColor(255, 243, 224),
                    BorderWidth = 1f,
                    Padding = 10,
                    BackgroundColor = new BaseColor(255, 252, 245),
                    Indent = 15
                };
                noteBox.AddCell(noteCell);
                doc.Add(noteBox);
            }

            // 3.2 漏洞详细信息（前10个）
            doc.Add(new Paragraph(" ", fonts.BodyFont) { SpacingBefore = 22 });
            
            var detailHeaderTable = new PdfPTable(1);
            detailHeaderTable.WidthPercentage = 100;
            var detailHeaderCell = new PdfPCell(
                new Paragraph("3.2 漏洞详细信息（前10个）", 
                    new Font(fonts.BaseFont, 13, Font.BOLD, new BaseColor(52, 73, 94))))
            {
                Border = Rectangle.NO_BORDER,
                PaddingLeft = 8,
                PaddingBottom = 10,
                BackgroundColor = BaseColor.WHITE
            };
            detailHeaderTable.AddCell(detailHeaderCell);
            doc.Add(detailHeaderTable);

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
            container.SpacingBefore = 8;
            container.SpacingAfter = 8;

            var titleCell = new PdfPCell() {
                BackgroundColor = riskScheme.ForegroundColor,
                Border = Rectangle.BOX,
                BorderColor = riskScheme.ForegroundColor,
                Padding = 10
            };
            var titlePara = new Paragraph();
            titlePara.Leading = 16;
            
            var indexPrefix = detailIndex > 0 ? $"[{detailIndex}] " : "";
            var name = string.IsNullOrWhiteSpace(vuln.Name) ? "未知漏洞" : vuln.Name;
            
            titlePara.Add(new Phrase($"{indexPrefix}{name}", 
                new Font(fonts.BaseFont, 11, Font.BOLD, BaseColor.WHITE)));
            
            if (!string.IsNullOrWhiteSpace(vuln.CveId))
                titlePara.Add(new Phrase($" ({vuln.CveId})", 
                    new Font(fonts.BaseFont, 9, Font.NORMAL, BaseColor.WHITE)));
            
            titlePara.Add(new Phrase($"  [{riskScheme.DisplayName}]", 
                new Font(fonts.BaseFont, 10, Font.BOLD, BaseColor.WHITE)));
                
            titleCell.Phrase = titlePara;
            container.AddCell(titleCell);

            var contentCell = new PdfPCell() {
                Border = Rectangle.BOX,
                BorderColor = new BaseColor(226, 232, 240),
                BorderWidthLeft = 3f,
                BorderColorLeft = riskScheme.ForegroundColor,
                Padding = 12,
                BackgroundColor = BaseColor.WHITE
            };
            
            var content = new Paragraph();
            content.Leading = 16;
            
            content.Add(new Phrase("\n【漏洞概述】\n", 
                new Font(fonts.BaseFont, 10, Font.BOLD, new BaseColor(30, 41, 59))));
            content.Add(new Paragraph(GetSafeString(vuln.Description), fonts.BodyFont));
            
            content.Add(new Phrase("\n【基本信息】\n", 
                new Font(fonts.BaseFont, 10, Font.BOLD, new BaseColor(30, 41, 59))));
            
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
            
            if (!string.IsNullOrWhiteSpace(vuln.DetectionMethod))
            {
                content.Add(new Phrase("\n【检测方法】\n", 
                    new Font(fonts.BaseFont, 10, Font.BOLD, new BaseColor(30, 41, 59))));
                content.Add(new Paragraph(GetSafeString(vuln.DetectionMethod), fonts.BodyFont));
            }
            
            content.Add(new Phrase("\n【修复方案】\n", 
                new Font(fonts.BaseFont, 10, Font.BOLD, new BaseColor(30, 41, 59))));
            var solution = GetSafeString(vuln.Solution ?? "请参考官方安全公告获取补丁信息");
            foreach (var line in solution.Split('\n').Where(l => !string.IsNullOrWhiteSpace(l)))
            {
                content.Add(new Paragraph($"  • {line.Trim()}", fonts.BodyFont));
            }
            
            if (!string.IsNullOrWhiteSpace(vuln.References))
            {
                content.Add(new Phrase("\n【参考链接】\n", 
                    new Font(fonts.BaseFont, 10, Font.BOLD, new BaseColor(30, 41, 59))));
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
            var deepBlue = new BaseColor(26, 54, 93);
            var headerBg = new BaseColor(30, 41, 59);

            doc.Add(new Paragraph("四、风险评估", new Font(fonts.BaseFont, 16, Font.BOLD, deepBlue))
            {
                SpacingBefore = 20,
                SpacingAfter = 15
            });

            var introPara = new Paragraph(
                "本节对本次扫描发现的各类风险进行综合评估和分析，提供量化的风险指标和可视化展示，" +
                "帮助决策者快速了解系统整体安全态势。",
                fonts.BodyFont)
            {
                SpacingBefore = 8,
                SpacingAfter = 18,
                IndentationLeft = 15,
                Leading = 16,
                Alignment = Element.ALIGN_JUSTIFIED
            };
            doc.Add(introPara);

            doc.Add(new Paragraph("4.1 风险评估项目", new Font(fonts.BaseFont, 13, Font.BOLD, new BaseColor(52, 73, 94)))
            {
                SpacingBefore = 12,
                SpacingAfter = 10
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

                GenerateRiskTable(doc, fonts, riskItems, headerBg);
            }
            else
            {
                GenerateAutoRiskAssessment(doc, fonts, vulns, ports, headerBg);
            }

            doc.Add(new Paragraph("\n4.2 风险分布可视化", new Font(fonts.BaseFont, 13, Font.BOLD, new BaseColor(52, 73, 94)))
            {
                SpacingBefore = 20,
                SpacingAfter = 10
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

                foreach (var cat in categories)
                {
                    if (cat.Count <= 0) continue;

                    var percent = (double)cat.Count / total * 100;

                    var rowTable = new PdfPTable(2);
                    rowTable.WidthPercentage = 85;
                    rowTable.SetWidths(new float[] { 1.2f, 2.8f });
                    rowTable.SpacingBefore = 4;

                    var labelCell = new PdfPCell(new Phrase(
                        $"{cat.Label}: {cat.Count} 个 ({percent:F1}%)",
                        fonts.TableCellFont))
                    {
                        Border = Rectangle.BOX,
                        BorderColor = COLOR_BORDER,
                        BorderWidth = 0.5f,
                        HorizontalAlignment = Element.ALIGN_LEFT,
                        VerticalAlignment = Element.ALIGN_MIDDLE,
                        Padding = 6
                    };

                    var barCell = new PdfPCell()
                    {
                        Border = Rectangle.BOX,
                        BorderColor = new BaseColor(220, 220, 220),
                        BorderWidth = 0.5f,
                        Padding = 4,
                        FixedHeight = 20
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

            doc.Add(new Paragraph("\n4.3 安全建议概述", new Font(fonts.BaseFont, 13, Font.BOLD, new BaseColor(52, 73, 94)))
            {
                SpacingBefore = 20,
                SpacingAfter = 10
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
                    IndentationLeft = 25
                };
                bulletPara.Add(new Phrase("• ", new Font(fonts.BaseFont, 10, Font.BOLD, deepBlue)));
                bulletPara.Add(new Phrase(suggestion, fonts.BodyFont));
                doc.Add(bulletPara);
            }
        }

        private static void GenerateRiskTable<T>(Document doc, FontCollection fonts, IEnumerable<T> riskItems, BaseColor headerBg)
        {
            var riskTable = new PdfPTable(3);
            riskTable.WidthPercentage = 85;
            riskTable.SetWidths(new float[] { 2.5f, 1.5f, 1.2f });
            riskTable.SpacingBefore = 5;
            riskTable.HeaderRows = 1;

            var headerFont = new Font(fonts.BaseFont, 10, Font.BOLD, BaseColor.WHITE);
            foreach (var header in new[] { "评估项目", "风险值", "状态" })
            {
                var headerCell = new PdfPCell(new Phrase(header, headerFont))
                {
                    BackgroundColor = headerBg,
                    HorizontalAlignment = Element.ALIGN_CENTER,
                    VerticalAlignment = Element.ALIGN_MIDDLE,
                    Padding = 8,
                    Border = Rectangle.BOX,
                    BorderColor = headerBg,
                    BorderWidth = 0.5f
                };
                riskTable.AddCell(headerCell);
            }

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
            List<VulnerabilityResult> vulns, List<PortScanResult> ports, BaseColor headerBg)
        {
            var autoItems = new[]
            {
                new { Item = "漏洞总量", Value = (vulns?.Count ?? 0).ToString(), Status = "" },
                new { Item = "高危漏洞数", Value = (vulns?.Count(v => IsCritical(v.RiskLevel) || IsHigh(v.RiskLevel)) ?? 0).ToString(), Status = "" },
                new { Item = "开放端口数", Value = (ports?.Count(p => p.Status == "开放" || p.Status.ToLower() == "open") ?? 0).ToString(), Status = "" },
                new { Item = "敏感端口暴露", Value = "待人工确认", Status = "" },
                new { Item = "整体安全评级", Value = CalculateOverallRiskLevel(vulns), Status = "" }
            };

            GenerateRiskTable(doc, fonts, autoItems, headerBg);
        }

        #endregion

        #region 第7章：修复建议章节

        private static void GenerateRemediationSection(Document doc, FontCollection fonts,
            List<VulnerabilityResult> vulns)
        {
            var deepBlue = new BaseColor(26, 54, 93);
            var headerBg = new BaseColor(30, 41, 59);

            doc.Add(new Paragraph("五、修复建议", new Font(fonts.BaseFont, 16, Font.BOLD, deepBlue))
            {
                SpacingBefore = 20,
                SpacingAfter = 15
            });

            var introPara = new Paragraph(
                "本节提供针对发现的安全问题的具体修复建议和通用安全加固措施。" +
                "建议按照优先级顺序依次处理，确保关键风险得到及时控制。",
                fonts.BodyFont)
            {
                SpacingBefore = 8,
                SpacingAfter = 18,
                IndentationLeft = 15,
                Leading = 16,
                Alignment = Element.ALIGN_JUSTIFIED
            };
            doc.Add(introPara);

            doc.Add(new Paragraph("5.1 修复优先级矩阵", new Font(fonts.BaseFont, 13, Font.BOLD, new BaseColor(52, 73, 94)))
            {
                SpacingBefore = 12,
                SpacingAfter = 10
            });

            var priorityTable = new PdfPTable(4);
            priorityTable.WidthPercentage = 95;
            priorityTable.SetWidths(new float[] { 1f, 1.5f, 2f, 2f });
            priorityTable.SpacingBefore = 5;
            priorityTable.HeaderRows = 1;

            var headerFont = new Font(fonts.BaseFont, 9, Font.BOLD, BaseColor.WHITE);
            foreach (var header in new[] { "优先级", "处理时限", "适用范围", "建议措施" })
            {
                var headerCell = new PdfPCell(new Phrase(header, headerFont))
                {
                    BackgroundColor = headerBg,
                    HorizontalAlignment = Element.ALIGN_CENTER,
                    VerticalAlignment = Element.ALIGN_MIDDLE,
                    Padding = 7,
                    Border = Rectangle.BOX,
                    BorderColor = headerBg,
                    BorderWidth = 0.5f
                };
                priorityTable.AddCell(headerCell);
            }

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
                    doc.Add(new Paragraph("\n5.2 高危漏洞修复建议（Top 5）", new Font(fonts.BaseFont, 13, Font.BOLD, new BaseColor(52, 73, 94)))
                    {
                        SpacingBefore = 20,
                        SpacingAfter = 10
                    });

                    int fixIdx = 1;
                    foreach (var vuln in highRiskVulns)
                    {
                        var fixTable = new PdfPTable(1);
                        fixTable.WidthPercentage = 100;
                        fixTable.SpacingBefore = 6;
                        fixTable.SpacingAfter = 6;

                        var vulnRiskScheme = GetRiskColorScheme(vuln.RiskLevel);
                        var fixCell = new PdfPCell();
                        fixCell.Border = Rectangle.BOX;
                        fixCell.BorderColor = vulnRiskScheme.ForegroundColor;
                        fixCell.BorderWidth = 1f;
                        fixCell.Padding = 12;
                        fixCell.BackgroundColor = new BaseColor(252, 252, 252);

                        var fixContent = new Paragraph();
                        fixContent.Add(new Phrase($"【{fixIdx}】{vuln.Name}",
                            new Font(fonts.BaseFont, 11, Font.BOLD, vulnRiskScheme.ForegroundColor)));

                        if (!string.IsNullOrEmpty(vuln.CveId))
                            fixContent.Add(new Phrase($" ({vuln.CveId})\n", fonts.SmallFont));
                        else
                            fixContent.Add("\n");

                        fixContent.Add(new Phrase("修复步骤: ", new Font(fonts.BaseFont, 10, Font.BOLD, COLOR_TEXT)));

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

            doc.Add(new Paragraph("\n5.3 通用安全加固建议", new Font(fonts.BaseFont, 13, Font.BOLD, new BaseColor(52, 73, 94)))
            {
                SpacingBefore = 20,
                SpacingAfter = 10
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
                tipCell.PaddingLeft = 15;
                tipCell.PaddingTop = 8;
                tipCell.PaddingBottom = 8;
                tipCell.BackgroundColor = new BaseColor(248, 250, 252);

                var tipContent = new Paragraph();
                tipContent.Add(new Phrase($"{tipIdx}. {category.Category}: ", new Font(fonts.BaseFont, 10, Font.BOLD, deepBlue)));
                tipContent.Add(new Phrase(category.Content, fonts.BodyFont));

                tipCell.Phrase = tipContent;
                tipTable.AddCell(tipCell);
                doc.Add(tipTable);
                tipIdx++;
            }

            doc.Add(new Paragraph(" ", fonts.BodyFont) { SpacingBefore = 25 });
            
            var disclaimerText = new Paragraph(
                "免责声明：本报告由 NetSecurityScanner 安全扫描工具自动生成。" +
                "报告中的漏洞检测结果和建议仅供参考，实际安全决策应结合具体业务场景和专业安全团队的人工判断。" +
                "在应用任何修复措施前，请务必在测试环境充分验证。",
                new Font(fonts.BaseFont, 9, Font.NORMAL, COLOR_GRAY_HINT))
            {
                IndentationLeft = 15,
                IndentationRight = 15,
                Alignment = Element.ALIGN_JUSTIFIED
            };
            
            var disclaimerCell = new PdfPCell(disclaimerText)
            {
                Border = Rectangle.BOX,
                BorderColor = COLOR_SEPARATOR,
                BorderWidth = 0.5f,
                Padding = 10,
                BackgroundColor = BaseColor.WHITE
            };
            
            var disclaimerTable = new PdfPTable(1);
            disclaimerTable.TotalWidth = 480;
            disclaimerTable.AddCell(disclaimerCell);
            doc.Add(disclaimerTable);
        }

        #endregion

        #region 页眉页脚系统

        public class HistoryReportPageEvent : PdfPageEventHelper
        {
            private BaseFont _baseFont;
            private bool _isCoverPage = true;

            public BaseFont BaseFont
            {
                set { _baseFont = value; }
            }

            public override void OnEndPage(PdfWriter writer, Document document)
            {
                if (writer.PageNumber == 1)
                    return;

                var cb = writer.DirectContent;

                if (_baseFont != null)
                {
                    cb.BeginText();
                    cb.SetFontAndSize(_baseFont, 9);
                    cb.SetColorFill(new BaseColor(100, 100, 100));
                    cb.ShowTextAligned(Element.ALIGN_LEFT, "网络安全漏洞扫描报告", 55, document.PageSize.Height - 50, 0);
                    cb.EndText();

                    cb.BeginText();
                    cb.SetFontAndSize(_baseFont, 9);
                    cb.SetColorFill(new BaseColor(100, 100, 100));
                    cb.ShowTextAligned(Element.ALIGN_RIGHT, $"NetSecurityScanner v{VersionHelper.GetVersion()}", document.PageSize.Width - 55, document.PageSize.Height - 50, 0);
                    cb.EndText();

                    cb.SetColorStroke(new BaseColor(200, 200, 200));
                    cb.SetLineWidth(0.5f);
                    cb.MoveTo(55, document.PageSize.Height - 55);
                    cb.LineTo(document.PageSize.Width - 55, document.PageSize.Height - 55);
                    cb.Stroke();

                    cb.BeginText();
                    cb.SetFontAndSize(_baseFont, 8);
                    cb.SetColorFill(new BaseColor(150, 150, 150));
                    cb.ShowTextAligned(Element.ALIGN_LEFT, "机密 - 内部文档", 55, 40, 0);
                    cb.EndText();

                    cb.BeginText();
                    cb.SetFontAndSize(_baseFont, 8);
                    cb.SetColorFill(new BaseColor(150, 150, 150));
                    cb.ShowTextAligned(Element.ALIGN_RIGHT, $"第 {writer.PageNumber} 页 / 共 {writer.PageNumber} 页", document.PageSize.Width - 55, 40, 0);
                    cb.EndText();
                }
            }
        }

        #endregion

        #region 辅助工具方法 - 通用绘图API辅助函数

        /// <summary>
        /// 安全获取中文字体 - 如果BaseFont为null则返回Helvetica回退字体
        /// </summary>
        private static BaseFont GetSafeBaseFont(FontCollection fonts)
        {
            return fonts.BaseFont ?? BaseFont.CreateFont(BaseFont.HELVETICA, BaseFont.CP1252, false);
        }

        /// <summary>
        /// 安全创建带中文支持的Font对象
        /// </summary>
        private static Font CreateSafeFont(FontCollection fonts, float size, int style, BaseColor color)
        {
            var baseFont = GetSafeBaseFont(fonts);
            return new Font(baseFont, size, style, color);
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
