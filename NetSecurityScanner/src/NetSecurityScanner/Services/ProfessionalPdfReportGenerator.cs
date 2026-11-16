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
    /// <summary>
    /// 专业级PDF报告生成服务
    /// 负责生成包含封面、目录、表格、颜色编码等元素的安全扫描评估报告
    /// </summary>
    public class ProfessionalPdfReportGenerator
    {
        /// <summary>
        /// 字体集合容器
        /// </summary>
        public class FontCollection
        {
            public BaseFont BaseFont { get; set; }
            public Font TitleFont { get; set; }
            public Font Heading1Font { get; set; }
            public Font Heading2Font { get; set; }
            public Font BodyFont { get; set; }
            public Font SmallFont { get; set; }
            public Font TableHeaderFont { get; set; }
            public Font TableCellFont { get; set; }
            public Font BoldBodyFont { get; set; }

            /// <summary>
            /// 标记是否使用了回退字体（非中文字体）
            /// </summary>
            public bool IsFallbackFont { get; set; } = false;
        }

        /// <summary>
        /// 漏洞显示数量限制（超过此数量时添加分页提示）
        /// </summary>
        private const int MAX_VULNERABILITIES_DISPLAY = 100;

        /// <summary>
        /// 生成专业级安全扫描评估报告
        /// </summary>
        public static string GenerateReport(
            List<PortScanResult> portScanResults,
            List<VulnerabilityResult> vulnerabilityResults,
            List<RiskAssessmentItem> riskAssessmentItems,
            string targetIp)
        {
            // 参数校验
            if (portScanResults == null) portScanResults = new List<PortScanResult>();
            if (vulnerabilityResults == null) vulnerabilityResults = new List<VulnerabilityResult>();
            if (riskAssessmentItems == null) riskAssessmentItems = new List<RiskAssessmentItem>();

            if (!portScanResults.Any() && !vulnerabilityResults.Any())
            {
                MessageBox.Show("暂无扫描数据，请先执行端口扫描或漏洞检测操作。", "数据为空", MessageBoxButton.OK, MessageBoxImage.Warning);
                return string.Empty;
            }

            var reportDir = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "Reports");
            if (!Directory.Exists(reportDir))
                Directory.CreateDirectory(reportDir);

            var fileName = $"ProfessionalSecurityReport_{targetIp.Replace(".", "_")}_{DateTime.Now:yyyyMMdd_HHmmss}.pdf";
            var filePath = Path.Combine(reportDir, fileName);
            var tempPath = filePath + ".tmp";

            try
            {
                if (File.Exists(tempPath)) File.Delete(tempPath);
                if (File.Exists(filePath)) File.Delete(filePath);

                using (var fs = new FileStream(tempPath, FileMode.Create, FileAccess.Write, FileShare.None))
                {
                    var doc = new Document(PageSize.A4, 60, 60, 72, 60);
                    var writer = PdfWriter.GetInstance(doc, fs);
                    writer.CloseStream = false;

                    // 注册页眉页脚事件处理器
                    var pageEvent = new ProfessionalReportPageEvent();
                    writer.PageEvent = pageEvent;

                    doc.Open();

                    // 加载中文字体（支持优雅降级）
                    var fonts = LoadChineseFonts();
                    if (fonts.BaseFont == null)
                    {
                        // 字体完全加载失败时记录警告日志并使用系统默认字体
                        Debug.WriteLine("[字体加载] 警告：所有字体加载失败，将使用iTextSharp内置默认字体继续生成报告");
                        Debug.WriteLine("[字体加载] 注意：中文内容可能显示为方块或乱码");

                        // 创建基于Helvetica的基础字体配置作为最后回退方案
                        fonts = CreateFallbackFontCollection();
                    }

                    var reportId = Guid.NewGuid().ToString("N").Substring(0, 8).ToUpper();
                    var scanTime = DateTime.Now.ToString("yyyy年MM月dd日 HH:mm:ss");
                    var reportGenerationTime = DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss"); // 报告生成时间
                    var overallRiskLevel = CalculateOverallRiskLevel(vulnerabilityResults);

                    // 尝试计算扫描耗时（如果数据中有时间戳信息）
                    var scanDuration = EstimateScanDuration(portScanResults, vulnerabilityResults);

                    // ========== 第1页：封面页 ==========
                    try
                    {
                        GenerateCoverPage(doc, fonts, targetIp, scanTime, reportId, overallRiskLevel, portScanResults, vulnerabilityResults, scanDuration);
                        doc.NewPage();
                    }
                    catch (Exception ex)
                    {
                        Debug.WriteLine($"[PDF生成] 封面页生成失败: {ex.Message}");
                        AddErrorPlaceholder(doc, fonts, "封面页", ex.Message);
                        doc.NewPage();
                    }

                    // ========== 第2页：目录页 ==========
                    try
                    {
                        GenerateTableOfContents(doc, fonts);
                        doc.NewPage();
                    }
                    catch (Exception ex)
                    {
                        Debug.WriteLine($"[PDF生成] 目录页生成失败: {ex.Message}");
                        AddErrorPlaceholder(doc, fonts, "目录页", ex.Message);
                        doc.NewPage();
                    }

                    // ========== 第3页：执行摘要 ==========
                    try
                    {
                        GenerateExecutiveSummary(doc, fonts, portScanResults, vulnerabilityResults, riskAssessmentItems, targetIp, reportGenerationTime);
                        doc.NewPage();
                    }
                    catch (Exception ex)
                    {
                        Debug.WriteLine($"[PDF生成] 执行摘要生成失败: {ex.Message}");
                        AddErrorPlaceholder(doc, fonts, "执行摘要", ex.Message);
                        doc.NewPage();
                    }

                    // ========== 端口扫描结果表格 ==========
                    try
                    {
                        GeneratePortScanTableSection(doc, fonts, portScanResults);
                        doc.NewPage();
                    }
                    catch (Exception ex)
                    {
                        Debug.WriteLine($"[PDF生成] 端口扫描表格生成失败: {ex.Message}");
                        AddErrorPlaceholder(doc, fonts, "端口扫描结果", ex.Message);
                        doc.NewPage();
                    }

                    // ========== 漏洞详情表格 ==========
                    try
                    {
                        GenerateVulnerabilityDetailsSection(doc, fonts, vulnerabilityResults);
                        doc.NewPage();
                    }
                    catch (Exception ex)
                    {
                        Debug.WriteLine($"[PDF生成] 漏洞详情生成失败: {ex.Message}");
                        AddErrorPlaceholder(doc, fonts, "漏洞详情分析", ex.Message);
                        doc.NewPage();
                    }

                    // ========== 风险评估展示 ==========
                    try
                    {
                        GenerateRiskAssessmentSection(doc, fonts, riskAssessmentItems, vulnerabilityResults, portScanResults);
                        doc.NewPage();
                    }
                    catch (Exception ex)
                    {
                        Debug.WriteLine($"[PDF生成] 风险评估章节生成失败: {ex.Message}");
                        AddErrorPlaceholder(doc, fonts, "风险评估汇总", ex.Message);
                        doc.NewPage();
                    }

                    // ========== 修复建议章节 ==========
                    try
                    {
                        GenerateRemediationSection(doc, fonts, vulnerabilityResults);
                    }
                    catch (Exception ex)
                    {
                        Debug.WriteLine($"[PDF生成] 修复建议章节生成失败: {ex.Message}");
                        AddErrorPlaceholder(doc, fonts, "修复建议与安全加固", ex.Message);
                    }

                    doc.Close();
                    writer.Close();
                    fs.Close();

                    File.Move(tempPath, filePath, true);
                    Debug.WriteLine($"专业级PDF报告生成成功：{filePath}");
                    return filePath;
                }
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"[专业PDF生成] 失败: {ex.Message}");
                try { if (File.Exists(tempPath)) File.Delete(tempPath); } catch { }
                MessageBox.Show($"专业级PDF报告生成失败:\n{ex.Message}", "错误", MessageBoxButton.OK, MessageBoxImage.Error);
                return string.Empty;
            }
        }

        /// <summary>
        /// 加载中文字体（回退链：微软雅黑 -> 黑体 -> 宋体 -> Helvetica）
        /// 支持优雅降级：当所有中文字体都失败时返回null，由调用方处理
        /// </summary>
        private static FontCollection LoadChineseFonts()
        {
            var fonts = new FontCollection();
            BaseFont bf = null;

            string[] fontPaths = {
                @"C:\Windows\Fonts\msyh.ttc,0",
                @"C:\Windows\Fonts\simhei.ttf",
                @"C:\Windows\Fonts\simsun.ttc,0",
                @"C:\Windows\Fonts\simsun.ttf"
            };

            foreach (var fp in fontPaths)
            {
                try
                {
                    bf = BaseFont.CreateFont(fp, BaseFont.IDENTITY_H, BaseFont.EMBEDDED);
                    Debug.WriteLine($"[字体加载] 成功加载: {fp}");
                    break;
                }
                catch (Exception ex)
                {
                    Debug.WriteLine($"[字体加载] 失败: {fp} - {ex.Message}");
                }
            }

            // 尝试使用系统默认的Helvetica字体作为最后回退
            if (bf == null)
            {
                try
                {
                    bf = BaseFont.CreateFont(BaseFont.HELVETICA, BaseFont.CP1252, false);
                    Debug.WriteLine($"[字体加载] 使用Helvetica回退字体");
                    fonts.IsFallbackFont = true;
                }
                catch (Exception ex)
                {
                    Debug.WriteLine($"[字体加载] Helvetica回退也失败: {ex.Message}");
                }
            }

            if (bf != null)
            {
                fonts.BaseFont = bf;
                fonts.TitleFont = new Font(bf, 24, Font.BOLD, new BaseColor(44, 62, 80));
                fonts.Heading1Font = new Font(bf, 18, Font.BOLD, new BaseColor(44, 62, 80));
                fonts.Heading2Font = new Font(bf, 14, Font.BOLD, new BaseColor(52, 73, 94));
                fonts.BodyFont = new Font(bf, 10, Font.NORMAL, BaseColor.BLACK);
                fonts.SmallFont = new Font(bf, 8, Font.NORMAL, new BaseColor(128, 128, 128));
                fonts.TableHeaderFont = new Font(bf, 9, Font.BOLD, BaseColor.WHITE);
                fonts.TableCellFont = new Font(bf, 9, Font.NORMAL, BaseColor.DARK_GRAY);
                fonts.BoldBodyFont = new Font(bf, 10, Font.BOLD, BaseColor.BLACK);
            }

            return fonts;
        }

        /// <summary>
        /// 创建回退字体集合（当所有字体都加载失败时的最后方案）
        /// 使用iTextSharp内置的默认字体
        /// </summary>
        private static FontCollection CreateFallbackFontCollection()
        {
            var fonts = new FontCollection();
            fonts.IsFallbackFont = true;

            // 使用iTextSharp内置的Helvetica字体作为基础
            fonts.BaseFont = null; // 标记为无自定义字体
            fonts.TitleFont = new Font(Font.FontFamily.HELVETICA, 24, Font.BOLD, new BaseColor(44, 62, 80));
            fonts.Heading1Font = new Font(Font.FontFamily.HELVETICA, 18, Font.BOLD, new BaseColor(44, 62, 80));
            fonts.Heading2Font = new Font(Font.FontFamily.HELVETICA, 14, Font.BOLD, new BaseColor(52, 73, 94));
            fonts.BodyFont = new Font(Font.FontFamily.HELVETICA, 10, Font.NORMAL, BaseColor.BLACK);
            fonts.SmallFont = new Font(Font.FontFamily.HELVETICA, 8, Font.NORMAL, new BaseColor(128, 128, 128));
            fonts.TableHeaderFont = new Font(Font.FontFamily.HELVETICA, 9, Font.BOLD, BaseColor.WHITE);
            fonts.TableCellFont = new Font(Font.FontFamily.HELVETICA, 9, Font.NORMAL, BaseColor.DARK_GRAY);
            fonts.BoldBodyFont = new Font(Font.FontFamily.HELVETICA, 10, Font.BOLD, BaseColor.BLACK);

            Debug.WriteLine("[字体加载] 已创建基于Helvetica的回退字体配置");
            return fonts;
        }

        private static string CalculateOverallRiskLevel(List<VulnerabilityResult> vulnerabilities)
        {
            // 空值安全检查
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
                Debug.WriteLine($"[风险等级计算] 异常: {ex.Message}");
                return "信息"; // 默认返回最低风险等级
            }
        }

        /// <summary>
        /// 估算扫描耗时（基于数据中的时间戳或使用默认值）
        /// </summary>
        private static string EstimateScanDuration(List<PortScanResult> ports, List<VulnerabilityResult> vulns)
        {
            try
            {
                // 如果无法从数据中获取时间戳，返回空字符串（封面页会处理显示逻辑）
                // 这里可以扩展为从模型中提取实际扫描时间
                return string.Empty;
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"[扫描耗时计算] 异常: {ex.Message}");
                return string.Empty;
            }
        }

        /// <summary>
        /// 添加错误占位符（当某个章节生成失败时显示）
        /// </summary>
        private static void AddErrorPlaceholder(Document doc, FontCollection fonts, string sectionName, string errorMessage)
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

                var errorFont = new Font(fonts.BaseFont ?? fonts.BodyFont.BaseFont, 10, Font.NORMAL, new BaseColor(192, 57, 43));
                errorPara.Add(new Phrase($"[该章节生成失败: {sectionName}]", errorFont));
                errorPara.Add(new Phrase("\n", fonts.BodyFont));
                errorPara.Add(new Phrase($"错误原因: {errorMessage}", fonts.SmallFont));

                doc.Add(errorPara);
                Debug.WriteLine($"[PDF生成] 已添加错误占位符: {sectionName}");
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"[PDF生成] 添加错误占位符也失败: {ex.Message}");
                // 最后的保底措施：即使错误占位符添加失败也不抛出异常
            }
        }

        private static bool IsCritical(string riskLevel)
        {
            // 增强空值和空白字符串处理
            if (string.IsNullOrWhiteSpace(riskLevel)) return false;
            var level = riskLevel.Trim().ToLower();
            return level.Contains("严重") || level == "critical";
        }

        private static bool IsHigh(string riskLevel)
        {
            // 增强空值和空白字符串处理
            if (string.IsNullOrWhiteSpace(riskLevel)) return false;
            var level = riskLevel.Trim().ToLower();
            return (level.Contains("高") && !level.Contains("严重")) || level == "high";
        }

        private static bool IsMedium(string riskLevel)
        {
            // 增强空值和空白字符串处理
            if (string.IsNullOrWhiteSpace(riskLevel)) return false;
            var level = riskLevel.Trim().ToLower();
            return level.Contains("中") || level == "medium";
        }

        private static bool IsLow(string riskLevel)
        {
            // 增强空值和空白字符串处理
            if (string.IsNullOrWhiteSpace(riskLevel)) return false;
            var level = riskLevel.Trim().ToLower();
            return level.Contains("低") || level == "low";
        }

        private static BaseColor GetRiskLevelColor(string riskLevel)
        {
            // 增强空值处理
            if (string.IsNullOrWhiteSpace(riskLevel)) return new BaseColor(158, 158, 158);
            var level = riskLevel.Trim().ToLower();
            if (level.Contains("严重") || level == "critical") return new BaseColor(244, 67, 54);
            if (level.Contains("高") || level == "high") return new BaseColor(255, 152, 0);
            if (level.Contains("中") || level == "medium") return new BaseColor(255, 193, 7);
            if (level.Contains("低") || level == "low") return new BaseColor(76, 175, 80);
            if (level.Contains("信息") || level == "info") return new BaseColor(33, 150, 243);
            return new BaseColor(158, 158, 158); // 默认灰色
        }

        private static BaseColor GetRiskLevelBackgroundColor(string riskLevel)
        {
            // 增强空值处理
            if (string.IsNullOrWhiteSpace(riskLevel)) return new BaseColor(245, 245, 245);
            var level = riskLevel.Trim().ToLower();
            if (level.Contains("严重") || level == "critical") return new BaseColor(255, 235, 238);
            if (level.Contains("高") || level == "high") return new BaseColor(255, 243, 224);
            if (level.Contains("中") || level == "medium") return new BaseColor(255, 255, 224);
            if (level.Contains("低") || level == "low") return new BaseColor(232, 245, 233);
            if (level.Contains("信息") || level == "info") return new BaseColor(227, 242, 253);
            return new BaseColor(245, 245, 245); // 默认浅灰背景
        }

        /// <summary>
        /// 生成封面页
        /// </summary>
        private static void GenerateCoverPage(Document doc, FontCollection fonts, string targetIp, string scanTime, string reportId, string overallRiskLevel, List<PortScanResult> ports, List<VulnerabilityResult> vulns, string scanDuration = "")
        {
            // 顶部装饰横条
            var topBar = new Rectangle(0, PageSize.A4.Height - 80, PageSize.A4.Width, 80);
            topBar.BackgroundColor = new BaseColor(44, 62, 80);
            doc.Add(topBar);

            doc.Add(new Paragraph(" ", fonts.BodyFont) { SpacingBefore = 40 });

            // 主标题
            var mainTitle = new Paragraph("网络安全漏洞扫描评估报告", fonts.TitleFont)
            {
                Alignment = Element.ALIGN_CENTER,
                SpacingBefore = 60,
                SpacingAfter = 10
            };
            doc.Add(mainTitle);

            // 英文副标题
            var subTitle = new Paragraph("Professional Security Assessment Report", new Font(fonts.BaseFont, 14, Font.ITALIC, new BaseColor(127, 140, 141)))
            {
                Alignment = Element.ALIGN_CENTER,
                SpacingAfter = 40
            };
            doc.Add(subTitle);

            // 扫描目标信息框
            var infoTable = new PdfPTable(2);
            infoTable.WidthPercentage = 70;
            infoTable.SetWidths(new float[] { 1.2f, 2f });
            infoTable.SpacingBefore = 20;
            infoTable.SpacingAfter = 20;

            // 增强空值安全：确保所有传入参数都有默认值
            var safeTargetIp = string.IsNullOrWhiteSpace(targetIp) ? "未知目标" : targetIp;
            var safeScanTime = string.IsNullOrWhiteSpace(scanTime) ? DateTime.Now.ToString("yyyy年MM月dd日 HH:mm:ss") : scanTime;

            AddInfoRow(infoTable, "扫描目标:", safeTargetIp, fonts.BoldBodyFont, fonts.BodyFont);
            AddInfoRow(infoTable, "扫描时间:", safeScanTime, fonts.BoldBodyFont, fonts.BodyFont);
            AddInfoRow(infoTable, "报告编号:", reportId ?? "N/A", fonts.BoldBodyFont, fonts.BodyFont);

            // 安全计算开放端口数量
            var openPortCount = ports?.Count(p => p?.Status == "开放" || p?.Status?.ToLower() == "open") ?? 0;
            AddInfoRow(infoTable, "开放端口:", $"{openPortCount} 个", fonts.BoldBodyFont, fonts.BodyFont);

            // 安全计算漏洞数量
            var vulnCount = vulns?.Count ?? 0;
            AddInfoRow(infoTable, "发现漏洞:", $"{vulnCount} 个", fonts.BoldBodyFont, fonts.BodyFont);

            // 如果有扫描耗时信息，显示在信息框中
            if (!string.IsNullOrEmpty(scanDuration))
            {
                AddInfoRow(infoTable, "扫描耗时:", scanDuration, fonts.BoldBodyFont, fonts.BodyFont);
            }

            infoTable.HorizontalAlignment = Element.ALIGN_CENTER;
            doc.Add(infoTable);

            // 安全评级徽章
            var riskBadgePara = new Paragraph() { Alignment = Element.ALIGN_CENTER, SpacingBefore = 30, SpacingAfter = 20 };
            var riskBadge = new Phrase("安全评级: ", fonts.BoldBodyFont);
            var safeOverallRiskLevel = string.IsNullOrWhiteSpace(overallRiskLevel) ? "信息" : overallRiskLevel;
            var riskLabel = new Phrase($"【{safeOverallRiskLevel}】", new Font(fonts.BaseFont, 16, Font.BOLD, GetRiskLevelColor(safeOverallRiskLevel)));
            riskBadgePara.Add(riskBadge);
            riskBadgePara.Add(riskLabel);
            doc.Add(riskBadgePara);

            // 漏洞统计概览（增强空值安全）
            if (vulns != null && vulns.Any())
            {
                var statsPara = new Paragraph() { Alignment = Element.ALIGN_CENTER, SpacingBefore = 15 };

                // 使用StringBuilder构建统计文本，提升性能
                var statsBuilder = new StringBuilder();
                statsBuilder.Append($"严重: {vulns.Count(v => IsCritical(v?.RiskLevel))}");
                statsBuilder.Append($" | 高危: {vulns.Count(v => IsHigh(v?.RiskLevel))}");
                statsBuilder.Append($" | 中危: {vulns.Count(v => IsMedium(v?.RiskLevel))}");
                statsBuilder.Append($" | 低危: {vulns.Count(v => IsLow(v?.RiskLevel))}");

                statsPara.Add(new Phrase(statsBuilder.ToString(), fonts.SmallFont));
                doc.Add(statsPara);
            }

            // 底部元信息区域
            doc.Add(new Paragraph(" ", fonts.BodyFont) { SpacingBefore = 120 });

            // 分隔线（使用简单的空白段落代替）
            doc.Add(new Paragraph(" ", new Font(fonts.BaseFont, 6, Font.NORMAL, new BaseColor(200, 200, 200))) { SpacingBefore = 5, SpacingAfter = 5 });

            // 版本和日期信息
            var metaInfo = new Paragraph()
            {
                Alignment = Element.ALIGN_CENTER,
                SpacingBefore = 15
            };
            metaInfo.Add(new Phrase($"NetSecurityScanner v{VersionHelper.GetVersion()}    |    ", fonts.SmallFont));
            metaInfo.Add(new Phrase(DateTime.Now.ToString("yyyy-MM-dd"), fonts.SmallFont));
            doc.Add(metaInfo);

            // 机密标识
            var confidential = new Paragraph("机密 - 仅限内部使用", new Font(fonts.BaseFont, 9, Font.BOLD, new BaseColor(192, 57, 43)))
            {
                Alignment = Element.ALIGN_CENTER,
                SpacingBefore = 5
            };
            doc.Add(confidential);
        }

        private static void AddInfoRow(PdfPTable table, string label, string value, Font labelFont, Font valueFont)
        {
            var labelCell = new PdfPCell(new Phrase(label, labelFont))
            {
                Border = Rectangle.NO_BORDER,
                HorizontalAlignment = Element.ALIGN_RIGHT,
                PaddingRight = 10,
                VerticalAlignment = Element.ALIGN_MIDDLE
            };

            var valueCell = new PdfPCell(new Phrase(value, valueFont))
            {
                Border = Rectangle.NO_BORDER,
                HorizontalAlignment = Element.ALIGN_LEFT,
                PaddingLeft = 5,
                VerticalAlignment = Element.ALIGN_MIDDLE
            };

            table.AddCell(labelCell);
            table.AddCell(valueCell);
        }

        /// <summary>
        /// 生成目录页
        /// </summary>
        private static void GenerateTableOfContents(Document doc, FontCollection fonts)
        {
            doc.Add(new Paragraph("目  录", fonts.TitleFont)
            {
                Alignment = Element.ALIGN_CENTER,
                SpacingBefore = 20,
                SpacingAfter = 30
            });

            var tocItems = new[]
            {
                ("一、执行摘要", "3"),
                ("二、端口扫描结果", "4"),
                ("三、漏洞详情分析", "5"),
                ("四、风险评估汇总", "7"),
                ("五、修复建议与安全加固", "8")
            };

            foreach (var tocItem in tocItems)
            {
                var title = tocItem.Item1;
                var page = tocItem.Item2;

                var tocEntry = new Paragraph()
                {
                    SpacingBefore = 12,
                    SpacingAfter = 12,
                    IndentationLeft = 40
                };

                tocEntry.Add(new Phrase(title, fonts.BodyFont));

                var dots = new string('.', Math.Max(1, 60 - title.Length * 2));
                tocEntry.Add(new Phrase(dots, new Font(fonts.BaseFont, 9, Font.NORMAL, new BaseColor(180, 180, 180))));
                tocEntry.Add(new Phrase(page, fonts.BoldBodyFont));

                doc.Add(tocEntry);
            }

            doc.Add(new Paragraph(" ", fonts.BodyFont) { SpacingBefore = 40 });
            var notePara = new Paragraph("注：本报告基于自动化安全扫描工具生成，结果仅供参考。对于关键安全问题，建议进行人工验证和深度分析。", fonts.SmallFont)
            {
                Alignment = Element.ALIGN_CENTER,
                IndentationLeft = 30,
                IndentationRight = 30
            };
            doc.Add(notePara);
        }

        /// <summary>
        /// 生成执行摘要章节
        /// </summary>
        private static void GenerateExecutiveSummary(Document doc, FontCollection fonts, List<PortScanResult> ports, List<VulnerabilityResult> vulns, List<RiskAssessmentItem> risks, string targetIp, string reportGenerationTime = "")
        {
            doc.Add(new Paragraph("一、执行摘要", fonts.Heading1Font) { SpacingBefore = 20, SpacingAfter = 15 });

            doc.Add(new Paragraph("本节提供本次安全扫描的核心发现和统计概览，帮助快速了解目标系统的整体安全态势。", fonts.BodyFont)
            {
                SpacingBefore = 10,
                SpacingAfter = 15,
                IndentationLeft = 20
            });

            // 统计卡片式布局
            doc.Add(new Paragraph("1.1 核心统计数据", fonts.Heading2Font) { SpacingBefore = 15, SpacingAfter = 10 });

            // 增强空值安全：确保列表不为null
            var safePorts = ports ?? new List<PortScanResult>();
            var safeVulns = vulns ?? new List<VulnerabilityResult>();

            var openPorts = safePorts.Where(p => p?.Status == "开放" || p?.Status?.ToLower() == "open" || p?.Status?.ToLower() == "open|filtered").ToList();
            var totalPorts = safePorts.Count;

            var statsTable = new PdfPTable(4);
            statsTable.WidthPercentage = 100;
            statsTable.SetWidths(new float[] { 1f, 1f, 1f, 1f });
            statsTable.SpacingBefore = 10;

            // 安全计算各项统计数据
            var overallRiskLevel = CalculateOverallRiskLevel(safeVulns);
            AddStatCard(statsTable, "总体风险等级", overallRiskLevel, GetRiskLevelColor(overallRiskLevel), fonts);
            AddStatCard(statsTable, "开放端口数", $"{openPorts.Count}/{totalPorts}", new BaseColor(52, 152, 219), fonts);
            AddStatCard(statsTable, "发现漏洞总数", $"{safeVulns.Count}", new BaseColor(231, 76, 60), fonts);

            // 安全计算高危漏洞占比（避免除零错误）
            var highRiskPercent = safeVulns.Any() ?
                (int)((double)(safeVulns.Count(v => IsCritical(v?.RiskLevel) || IsHigh(v?.RiskLevel))) / safeVulns.Count * 100) : 0;
            AddStatCard(statsTable, "高危漏洞占比", $"{highRiskPercent}%", new BaseColor(243, 156, 18), fonts);

            doc.Add(statsTable);

            // 添加报告生成时间信息
            if (!string.IsNullOrEmpty(reportGenerationTime))
            {
                doc.Add(new Paragraph($"\n报告生成时间: {reportGenerationTime}", fonts.SmallFont)
                {
                    SpacingBefore = 10,
                    IndentationLeft = 20,
                    Alignment = Element.ALIGN_RIGHT
                });
            }

            // Top 5 高危漏洞列表（增强空值安全）
            if (safeVulns.Any())
            {
                doc.Add(new Paragraph("\n1.2 Top 5 高危漏洞", fonts.Heading2Font) { SpacingBefore = 20, SpacingAfter = 10 });

                var topVulns = safeVulns
                    .OrderByDescending(v =>
                    {
                        // 增强空值安全：处理可能为null的RiskLevel
                        var riskLevel = v?.RiskLevel ?? "";
                        if (IsCritical(riskLevel)) return 4;
                        if (IsHigh(riskLevel)) return 3;
                        if (IsMedium(riskLevel)) return 2;
                        if (IsLow(riskLevel)) return 1;
                        return 0;
                    })
                    .Take(5)
                    .ToList();

                var topVulnTable = new PdfPTable(4);
                topVulnTable.WidthPercentage = 100;
                topVulnTable.SetWidths(new float[] { 0.5f, 2.5f, 1.2f, 1f });
                topVulnTable.SpacingBefore = 5;

                AddTableHeader(topVulnTable, new[] { "#", "漏洞名称", "风险等级", "CVE编号" }, fonts);

                int index = 1;
                foreach (var vuln in topVulns)
                {
                    var isZebra = index % 2 == 0;
                    // 增强空值安全：为所有字段提供默认值
                    var safeName = string.IsNullOrWhiteSpace(vuln?.Name) ? "未知漏洞" : vuln.Name;
                    var safeRiskLevel = string.IsNullOrWhiteSpace(vuln?.RiskLevel) ? "未分类" : vuln.RiskLevel;
                    var safeCveId = string.IsNullOrWhiteSpace(vuln?.CveId) ? "-" : vuln.CveId;

                    AddTopVulnRow(topVulnTable, index++, safeName, safeRiskLevel, safeCveId, fonts, isZebra);
                }

                doc.Add(topVulnTable);
            }

            // 服务分布摘要（增强空值安全）
            if (safePorts.Any())
            {
                doc.Add(new Paragraph("\n1.3 服务分布摘要", fonts.Heading2Font) { SpacingBefore = 20, SpacingAfter = 10 });

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

                AddTableHeader(serviceTable, new[] { "服务名称", "实例数量", "关联端口" }, fonts);

                int svcIdx = 1;
                foreach (var grp in serviceGroups)
                {
                    var isZebra = svcIdx % 2 == 0;
                    var cellBg = isZebra ? new BaseColor(248, 249, 250) : BaseColor.WHITE;

                    // 使用StringBuilder构建端口列表，提升性能
                    var portListBuilder = new StringBuilder();
                    var portNumbers = grp.Select(p => p.PortNumber).Take(3).ToList();
                    for (int i = 0; i < portNumbers.Count; i++)
                    {
                        if (i > 0) portListBuilder.Append(", ");
                        portListBuilder.Append(portNumbers[i].ToString());
                    }

                    var svcNameCell = CreateStyledCell(grp.Key ?? "-", fonts.TableCellFont, cellBg, Rectangle.NO_BORDER);
                    var countCell = CreateStyledCell(grp.Count().ToString(), fonts.TableCellFont, cellBg, Rectangle.NO_BORDER);
                    var portsCell = CreateStyledCell(portListBuilder.ToString(), fonts.TableCellFont, cellBg, Rectangle.NO_BORDER);

                    serviceTable.AddCell(svcNameCell);
                    serviceTable.AddCell(countCell);
                    serviceTable.AddCell(portsCell);
                    svcIdx++;
                }

                doc.Add(serviceTable);
            }
        }

        private static void AddStatCard(PdfPTable table, string label, string value, BaseColor accentColor, FontCollection fonts)
        {
            var outerCell = new PdfPCell();
            outerCell.Border = Rectangle.BOX;
            outerCell.BorderColor = new BaseColor(220, 220, 220);
            outerCell.Padding = 8;
            outerCell.VerticalAlignment = Element.ALIGN_MIDDLE;

            var innerPara = new Paragraph()
            {
                Alignment = Element.ALIGN_CENTER
            };
            innerPara.Add(new Phrase($"{label}\n", fonts.SmallFont));
            innerPara.Add(new Phrase(value, new Font(fonts.BaseFont, 16, Font.BOLD, accentColor)));

            outerCell.Phrase = innerPara;
            table.AddCell(outerCell);
        }

        private static void AddTableHeader(PdfPTable table, string[] headers, FontCollection fonts)
        {
            var headerBg = new BaseColor(44, 62, 80);

            foreach (var header in headers)
            {
                var cell = new PdfPCell(new Phrase(header, fonts.TableHeaderFont))
                {
                    BackgroundColor = headerBg,
                    HorizontalAlignment = Element.ALIGN_CENTER,
                    VerticalAlignment = Element.ALIGN_MIDDLE,
                    Padding = 8,
                    Border = Rectangle.NO_BORDER
                };
                table.AddCell(cell);
            }
        }

        private static void AddTopVulnRow(PdfPTable table, int index, string name, string riskLevel, string cveId, FontCollection fonts, bool isZebra)
        {
            var bg = isZebra ? new BaseColor(248, 249, 250) : BaseColor.WHITE;

            table.AddCell(CreateStyledCell(index.ToString(), fonts.TableCellFont, bg, Rectangle.NO_BORDER, Element.ALIGN_CENTER));
            table.AddCell(CreateStyledCell(name, fonts.TableCellFont, bg, Rectangle.NO_BORDER));

            var riskCell = new PdfPCell(new Phrase(riskLevel, new Font(fonts.BaseFont, 9, Font.BOLD, GetRiskLevelColor(riskLevel))))
            {
                BackgroundColor = GetRiskLevelBackgroundColor(riskLevel),
                HorizontalAlignment = Element.ALIGN_CENTER,
                VerticalAlignment = Element.ALIGN_MIDDLE,
                Padding = 6,
                Border = Rectangle.NO_BORDER
            };
            table.AddCell(riskCell);

            table.AddCell(CreateStyledCell(cveId ?? "-", fonts.TableCellFont, bg, Rectangle.NO_BORDER, Element.ALIGN_CENTER));
        }

        private static PdfPCell CreateStyledCell(string text, Font font, BaseColor bgColor, int border, int alignment = Element.ALIGN_LEFT)
        {
            return new PdfPCell(new Phrase(text, font))
            {
                BackgroundColor = bgColor,
                HorizontalAlignment = alignment,
                VerticalAlignment = Element.ALIGN_MIDDLE,
                Padding = 6,
                Border = border
            };
        }

        /// <summary>
        /// 生成端口扫描结果表格章节
        /// </summary>
        private static void GeneratePortScanTableSection(Document doc, FontCollection fonts, List<PortScanResult> results)
        {
            doc.Add(new Paragraph("二、端口扫描结果", fonts.Heading1Font) { SpacingBefore = 20, SpacingAfter = 15 });
            doc.Add(new Paragraph("本节列出所有检测到的开放端口及其对应的服务信息。仅展示状态为开放的端口。", fonts.BodyFont)
            {
                SpacingBefore = 10,
                SpacingAfter = 15,
                IndentationLeft = 20
            });

            // 增强空值安全：确保列表不为null
            var safeResults = results ?? new List<PortScanResult>();

            var openPorts = safeResults
                .Where(p => p?.Status == "开放" || p?.Status?.ToLower() == "open" || p?.Status?.ToLower() == "open|filtered")
                .OrderBy(p => p.PortNumber)
                .ToList();

            if (!openPorts.Any())
            {
                doc.Add(new Paragraph("未发现开放端口。", fonts.BodyFont) { SpacingBefore = 20 });
                return;
            }

            // 大数据量处理：限制显示数量并添加提示（虽然端口数量通常不会太多，但保持一致性）
            const int MAX_PORTS_DISPLAY = 500; // 端口数量限制相对宽松
            bool hasMorePorts = openPorts.Count > MAX_PORTS_DISPLAY;
            var displayPorts = hasMorePorts ? openPorts.Take(MAX_PORTS_DISPLAY).ToList() : openPorts;

            var table = new PdfPTable(6);
            table.WidthPercentage = 100;
            table.SetWidths(new float[] { 0.8f, 0.8f, 1.5f, 1.8f, 0.9f, 1f });
            table.SpacingBefore = 10;
            table.HeaderRows = 1;

            AddTableHeader(table, new[] { "端口号", "协议", "服务名称", "版本", "状态", "响应时间" }, fonts);

            int rowIndex = 1;
            foreach (var port in displayPorts)
            {
                try
                {
                    var isZebra = rowIndex % 2 == 0;
                    var bg = isZebra ? new BaseColor(248, 249, 250) : BaseColor.WHITE;

                    // 增强空值安全：为每个字段提供默认值
                    var portNumber = port?.PortNumber ?? 0;
                    var service = string.IsNullOrWhiteSpace(port?.Service) ? "-" : port.Service;
                    var serviceVersion = string.IsNullOrWhiteSpace(port?.ServiceVersion) ? "-" : port.ServiceVersion;
                    var status = string.IsNullOrWhiteSpace(port?.Status) ? "未知" : port.Status;
                    var responseTime = string.IsNullOrWhiteSpace(port?.ResponseTime) ? "-" : port.ResponseTime;

                    table.AddCell(CreateStyledCell(portNumber.ToString(), fonts.TableCellFont, bg, Rectangle.NO_BORDER, Element.ALIGN_CENTER));
                    table.AddCell(CreateStyledCell("TCP", fonts.TableCellFont, bg, Rectangle.NO_BORDER, Element.ALIGN_CENTER));
                    table.AddCell(CreateStyledCell(service, fonts.TableCellFont, bg, Rectangle.NO_BORDER));
                    table.AddCell(CreateStyledCell(serviceVersion, fonts.SmallFont, bg, Rectangle.NO_BORDER));

                    var statusColor = GetStatusColor(status);
                    var statusCell = new PdfPCell(new Phrase(status, new Font(fonts.BaseFont, 9, Font.BOLD, statusColor)))
                    {
                        BackgroundColor = bg,
                        HorizontalAlignment = Element.ALIGN_CENTER,
                        VerticalAlignment = Element.ALIGN_MIDDLE,
                        Padding = 6,
                        Border = Rectangle.NO_BORDER
                    };
                    table.AddCell(statusCell);

                    table.AddCell(CreateStyledCell(responseTime, fonts.SmallFont, bg, Rectangle.NO_BORDER, Element.ALIGN_CENTER));
                    rowIndex++;
                }
                catch (Exception ex)
                {
                    Debug.WriteLine($"[端口表格] 添加行失败 (索引{rowIndex}): {ex.Message}");
                    // 跳过失败的行，继续处理下一行
                }
            }

            doc.Add(table);

            // 使用StringBuilder构建统计信息
            var statsBuilder = new StringBuilder();
            statsBuilder.Append($"\n共计 {openPorts.Count} 个开放端口已列出");
            if (hasMorePorts)
            {
                statsBuilder.Append($"（注：共发现{openPorts.Count}个开放端口，本报告展示前{MAX_PORTS_DISPLAY}个）");
            }
            statsBuilder.Append("。");

            doc.Add(new Paragraph(statsBuilder.ToString(), new Font(fonts.BaseFont, 9, Font.NORMAL, new BaseColor(128, 128, 128)))
            {
                SpacingBefore = 10,
                IndentationLeft = 20
            });
        }

        private static BaseColor GetStatusColor(string status)
        {
            if (string.IsNullOrEmpty(status)) return new BaseColor(158, 158, 158);
            var s = status.ToLower();
            if (s.Contains("open")) return new BaseColor(39, 174, 96);
            if (s.Contains("close")) return new BaseColor(149, 165, 166);
            if (s.Contains("filter")) return new BaseColor(241, 196, 15);
            return new BaseColor(158, 158, 158);
        }

        /// <summary>
        /// 生成漏洞详情表格章节
        /// </summary>
        private static void GenerateVulnerabilityDetailsSection(Document doc, FontCollection fonts, List<VulnerabilityResult> vulnerabilities)
        {
            doc.Add(new Paragraph("三、漏洞详情分析", fonts.Heading1Font) { SpacingBefore = 20, SpacingAfter = 15 });
            doc.Add(new Paragraph("本节详细列出所有检测到的安全漏洞，按风险等级从高到低排列。每个漏洞均附带描述、检测方法和修复建议。", fonts.BodyFont)
            {
                SpacingBefore = 10,
                SpacingAfter = 15,
                IndentationLeft = 20
            });

            // 增强空值安全：确保列表不为null
            var safeVulnerabilities = vulnerabilities ?? new List<VulnerabilityResult>();

            if (!safeVulnerabilities.Any())
            {
                doc.Add(new Paragraph("未发现安全漏洞。", fonts.BodyFont) { SpacingBefore = 20 });
                return;
            }

            // 大数据量处理：限制显示数量并添加分页提示
            bool hasMoreVulns = safeVulnerabilities.Count > MAX_VULNERABILITIES_DISPLAY;
            var displayVulns = hasMoreVulns ? safeVulnerabilities.Take(MAX_VULNERABILITIES_DISPLAY).ToList() : safeVulnerabilities;

            var sortedVulns = displayVulns
                .OrderByDescending(v =>
                {
                    // 增强空值安全
                    var riskLevel = v?.RiskLevel ?? "";
                    if (IsCritical(riskLevel)) return 5;
                    if (IsHigh(riskLevel)) return 4;
                    if (IsMedium(riskLevel)) return 3;
                    if (IsLow(riskLevel)) return 2;
                    return 1;
                })
                .ToList();

            var table = new PdfPTable(7);
            table.WidthPercentage = 100;
            table.SetWidths(new float[] { 0.5f, 1.2f, 2.2f, 0.9f, 0.7f, 1.2f, 0.7f });
            table.SpacingBefore = 10;
            table.HeaderRows = 1;

            AddTableHeader(table, new[] { "序号", "CVE编号", "漏洞名称", "风险等级", "端口", "服务", "CVSS评分" }, fonts);

            int index = 1;
            foreach (var vuln in sortedVulns)
            {
                try
                {
                    var isZebra = index % 2 == 0;
                    var bg = isZebra ? new BaseColor(248, 249, 250) : BaseColor.WHITE;

                    // 增强空值安全：为所有字段提供默认值
                    var cveId = string.IsNullOrWhiteSpace(vuln?.CveId) ? "-" : vuln.CveId;
                    var name = string.IsNullOrWhiteSpace(vuln?.Name) ? "未知漏洞" : vuln.Name;
                    var riskLevel = string.IsNullOrWhiteSpace(vuln?.RiskLevel) ? "未分类" : vuln.RiskLevel;
                    var port = vuln?.Port.HasValue == true ? vuln.Port.Value.ToString() : "-";
                    var service = string.IsNullOrWhiteSpace(vuln?.Service) ? "-" : vuln.Service;

                    table.AddCell(CreateStyledCell(index.ToString(), fonts.TableCellFont, bg, Rectangle.NO_BORDER, Element.ALIGN_CENTER));
                    table.AddCell(CreateStyledCell(cveId, fonts.TableCellFont, bg, Rectangle.NO_BORDER, Element.ALIGN_CENTER));
                    table.AddCell(CreateStyledCell(name, fonts.TableCellFont, bg, Rectangle.NO_BORDER));

                    var riskBg = GetRiskLevelBackgroundColor(riskLevel);
                    var riskBorder = GetRiskLevelColor(riskLevel);
                    var riskCell = new PdfPCell(new Phrase(riskLevel, new Font(fonts.BaseFont, 9, Font.BOLD, riskBorder)))
                    {
                        BackgroundColor = riskBg,
                        BorderColor = riskBorder,
                        BorderWidth = 0.5f,
                        HorizontalAlignment = Element.ALIGN_CENTER,
                        VerticalAlignment = Element.ALIGN_MIDDLE,
                        Padding = 6
                    };
                    table.AddCell(riskCell);

                    table.AddCell(CreateStyledCell(port, fonts.TableCellFont, bg, Rectangle.NO_BORDER, Element.ALIGN_CENTER));
                    table.AddCell(CreateStyledCell(service, fonts.TableCellFont, bg, Rectangle.NO_BORDER));

                    // 安全计算CVSS评分并格式化
                    var cvssScore = EstimateCvssScore(riskLevel).ToString("F1");
                    table.AddCell(CreateStyledCell(cvssScore, fonts.TableCellFont, bg, Rectangle.NO_BORDER, Element.ALIGN_CENTER));

                    index++;
                }
                catch (Exception ex)
                {
                    Debug.WriteLine($"[漏洞表格] 添加行失败 (索引{index}): {ex.Message}");
                    // 跳过失败的行，继续处理下一行
                }
            }

            doc.Add(table);

            // 添加大数据量提示信息
            if (hasMoreVulns)
            {
                var noteBuilder = new StringBuilder();
                noteBuilder.Append($"\n注：共发现 {safeVulnerabilities.Count} 个漏洞，");
                noteBuilder.Append($"本报告展示前 {MAX_VULNERABILITIES_DISPLAY} 个高危漏洞的详细信息。");
                noteBuilder.Append("如需查看完整列表，请导出原始数据或联系管理员。");

                doc.Add(new Paragraph(noteBuilder.ToString(), new Font(fonts.BaseFont, 9, Font.NORMAL, new BaseColor(255, 152, 0)))
                {
                    SpacingBefore = 15,
                    IndentationLeft = 20,
                    IndentationRight = 20
                });
            }

            // 添加前10个漏洞的详细信息块（限制详情块数量以避免内存问题）
            doc.Add(new Paragraph("\n3.1 漏洞详细信息（前10个）", fonts.Heading2Font) { SpacingBefore = 20, SpacingAfter = 10 });

            int detailIndex = 1;
            int maxDetailBlocks = Math.Min(10, sortedVulns.Count); // 确保不超过实际数量
            foreach (var vuln in sortedVulns.Take(maxDetailBlocks))
            {
                try
                {
                    AddVulnerabilityDetailBlock(doc, fonts, vuln, detailIndex++);
                }
                catch (Exception ex)
                {
                    Debug.WriteLine($"[漏洞详情块] 生成失败 (索引{detailIndex}): {ex.Message}");
                    // 跳过失败的详情块，继续处理下一个
                }
            }
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

        private static void AddVulnerabilityDetailBlock(Document doc, FontCollection fonts, VulnerabilityResult vuln, int detailIndex = 0)
        {
            // 增强空值安全：确保vuln不为null
            if (vuln == null)
            {
                Debug.WriteLine("[漏洞详情块] 警告：漏洞对象为null，跳过生成");
                return;
            }

            var detailTable = new PdfPTable(1);
            detailTable.WidthPercentage = 100;
            detailTable.SpacingBefore = 8;
            detailTable.SpacingAfter = 8;

            // 增强空值安全：为所有字段提供默认值
            var riskLevel = string.IsNullOrWhiteSpace(vuln.RiskLevel) ? "未分类" : vuln.RiskLevel;
            var borderColor = GetRiskLevelColor(riskLevel);

            var mainCell = new PdfPCell();
            mainCell.Border = Rectangle.BOX;
            mainCell.BorderColor = borderColor;
            mainCell.BorderWidth = 0.5f;
            mainCell.Padding = 10;
            mainCell.BackgroundColor = new BaseColor(252, 252, 252);

            // 使用StringBuilder构建内容，提升性能
            var contentBuilder = new StringBuilder();

            if (detailIndex > 0)
            {
                contentBuilder.Append($"[{detailIndex}] ");
            }

            // 增强空值安全：处理可能为空的Name字段
            var name = string.IsNullOrWhiteSpace(vuln.Name) ? "未知漏洞" : vuln.Name;
            contentBuilder.Append($"{name}");

            if (!string.IsNullOrWhiteSpace(vuln.CveId))
            {
                contentBuilder.Append($" ({vuln.CveId})");
            }
            contentBuilder.Append("\n");

            if (!string.IsNullOrWhiteSpace(vuln.Description))
            {
                contentBuilder.Append("描述: ");
                contentBuilder.Append($"{vuln.Description}\n\n");
            }

            if (!string.IsNullOrWhiteSpace(vuln.DetectionMethod))
            {
                contentBuilder.Append("检测方法: ");
                contentBuilder.Append($"{vuln.DetectionMethod}\n\n");
            }

            if (!string.IsNullOrWhiteSpace(vuln.Solution))
            {
                contentBuilder.Append("解决方案: ");
                contentBuilder.Append($"{vuln.Solution}\n\n");
            }

            if (!string.IsNullOrWhiteSpace(vuln.References))
            {
                contentBuilder.Append("参考链接: ");
                contentBuilder.Append($"{vuln.References}");
            }

            // 将StringBuilder内容转换为Paragraph
            var content = new Paragraph();
            content.Add(new Phrase(contentBuilder.ToString(), fonts.BodyFont));

            mainCell.Phrase = content;
            detailTable.AddCell(mainCell);
            doc.Add(detailTable);
        }

        /// <summary>
        /// 生成风险评估展示章节
        /// </summary>
        private static void GenerateRiskAssessmentSection(Document doc, FontCollection fonts, List<RiskAssessmentItem> riskItems, List<VulnerabilityResult> vulns, List<PortScanResult> ports)
        {
            doc.Add(new Paragraph("四、风险评估汇总", fonts.Heading1Font) { SpacingBefore = 20, SpacingAfter = 15 });
            doc.Add(new Paragraph("本节对本次扫描发现的各类风险进行综合评估和分析。", fonts.BodyFont)
            {
                SpacingBefore = 10,
                SpacingAfter = 15,
                IndentationLeft = 20
            });

            doc.Add(new Paragraph("4.1 风险评估项目", fonts.Heading2Font) { SpacingBefore = 15, SpacingAfter = 10 });

            if (riskItems != null && riskItems.Any())
            {
                var riskTable = new PdfPTable(3);
                riskTable.WidthPercentage = 80;
                riskTable.SetWidths(new float[] { 2.5f, 1.5f, 1.2f });
                riskTable.SpacingBefore = 5;

                AddTableHeader(riskTable, new[] { "评估项目", "风险值", "状态" }, fonts);

                int idx = 1;
                foreach (var item in riskItems)
                {
                    var isZebra = idx % 2 == 0;
                    var bg = isZebra ? new BaseColor(248, 249, 250) : BaseColor.WHITE;

                    riskTable.AddCell(CreateStyledCell(item.Item, fonts.TableCellFont, bg, Rectangle.NO_BORDER));
                    riskTable.AddCell(CreateStyledCell(item.Value, fonts.TableCellFont, bg, Rectangle.NO_BORDER, Element.ALIGN_CENTER));

                    var statusColor = item.Status?.Contains("高") == true ? new BaseColor(231, 76, 60) :
                                      item.Status?.Contains("中") == true ? new BaseColor(243, 156, 18) :
                                      item.Status?.Contains("低") == true ? new BaseColor(46, 204, 113) : new BaseColor(149, 165, 166);

                    var statusCell = new PdfPCell(new Phrase(item.Status ?? "-", new Font(fonts.BaseFont, 9, Font.BOLD, statusColor)))
                    {
                        BackgroundColor = bg,
                        HorizontalAlignment = Element.ALIGN_CENTER,
                        VerticalAlignment = Element.ALIGN_MIDDLE,
                        Padding = 6,
                        Border = Rectangle.NO_BORDER
                    };
                    riskTable.AddCell(statusCell);
                    idx++;
                }

                doc.Add(riskTable);
            }
            else
            {
                GenerateAutoRiskAssessment(doc, fonts, vulns, ports);
            }

            // 风险分布可视化
            doc.Add(new Paragraph("\n4.2 风险分布", fonts.Heading2Font) { SpacingBefore = 20, SpacingAfter = 10 });

            if (vulns != null && vulns.Any())
            {
                var total = vulns.Count;
                var categories = new[]
                {
                    new { Label = "严重", Count = vulns.Count(v => IsCritical(v.RiskLevel)), Color = new BaseColor(244, 67, 54) },
                    new { Label = "高危", Count = vulns.Count(v => IsHigh(v.RiskLevel)), Color = new BaseColor(255, 152, 0) },
                    new { Label = "中危", Count = vulns.Count(v => IsMedium(v.RiskLevel)), Color = new BaseColor(255, 193, 7) },
                    new { Label = "低危", Count = vulns.Count(v => IsLow(v.RiskLevel)), Color = new BaseColor(76, 175, 80) },
                    new { Label = "信息", Count = vulns.Count(v => !(IsCritical(v.RiskLevel) || IsHigh(v.RiskLevel) || IsMedium(v.RiskLevel) || IsLow(v.RiskLevel))), Color = new BaseColor(33, 150, 243) }
                };

                foreach (var cat in categories)
                {
                    if (cat.Count <= 0) continue;

                    var percent = (double)cat.Count / total * 100;

                    var rowTable = new PdfPTable(2);
                    rowTable.WidthPercentage = 80;
                    rowTable.SetWidths(new float[] { 1f, 3f });
                    rowTable.SpacingBefore = 3;

                    var labelCell = new PdfPCell(new Phrase($"{cat.Label}: {cat.Count} ({percent:F1}%)", fonts.TableCellFont))
                    {
                        Border = Rectangle.NO_BORDER,
                        HorizontalAlignment = Element.ALIGN_LEFT,
                        VerticalAlignment = Element.ALIGN_MIDDLE
                    };

                    var barCell = new PdfPCell()
                    {
                        Border = Rectangle.BOX,
                        BorderColor = new BaseColor(220, 220, 220),
                        Padding = 3,
                        FixedHeight = 18
                    };

                    var barPhrase = new Paragraph();
                    barPhrase.Add(new Phrase(new string('█', Math.Max(1, (int)(percent / 5))), new Font(fonts.BaseFont, 8, Font.NORMAL, cat.Color)));
                    barPhrase.Add(new Phrase($" {percent:F1}%", fonts.SmallFont));
                    barCell.Phrase = barPhrase;

                    rowTable.AddCell(labelCell);
                    rowTable.AddCell(barCell);
                    doc.Add(rowTable);
                }
            }

            // 安全建议概述
            doc.Add(new Paragraph("\n4.3 安全建议概述", fonts.Heading2Font) { SpacingBefore = 20, SpacingAfter = 10 });

            var suggestions = new[]
            {
                "立即修复所有严重和高危级别的漏洞，尤其是远程代码执行类漏洞",
                "关闭不必要的服务和端口，减少攻击面",
                "及时更新系统和应用软件至最新版本",
                "实施强密码策略和多因素认证",
                "配置防火墙规则限制网络访问",
                "定期进行安全扫描和渗透测试"
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

        private static void GenerateAutoRiskAssessment(Document doc, FontCollection fonts, List<VulnerabilityResult> vulns, List<PortScanResult> ports)
        {
            var autoItems = new[]
            {
                new { Item = "漏洞总量", Value = (vulns?.Count ?? 0).ToString(), Status = "" },
                new { Item = "高危漏洞数", Value = (vulns?.Count(v => IsCritical(v.RiskLevel) || IsHigh(v.RiskLevel)) ?? 0).ToString(), Status = "" },
                new { Item = "开放端口数", Value = (ports?.Count(p => p.Status == "开放" || p.Status.ToLower() == "open") ?? 0).ToString(), Status = "" },
                new { Item = "敏感端口暴露", Value = "待人工确认", Status = "" },
                new { Item = "整体安全评级", Value = CalculateOverallRiskLevel(vulns), Status = "" }
            };

            var riskTable = new PdfPTable(3);
            riskTable.WidthPercentage = 80;
            riskTable.SetWidths(new float[] { 2.5f, 1.5f, 1.2f });
            riskTable.SpacingBefore = 5;

            AddTableHeader(riskTable, new[] { "评估项目", "风险值", "状态" }, fonts);

            int idx = 1;
            foreach (var autoItem in autoItems)
            {
                var item = autoItem.Item;
                var value = autoItem.Value;

                var isZebra = idx % 2 == 0;
                var bg = isZebra ? new BaseColor(248, 249, 250) : BaseColor.WHITE;

                riskTable.AddCell(CreateStyledCell(item, fonts.TableCellFont, bg, Rectangle.NO_BORDER));
                riskTable.AddCell(CreateStyledCell(value, fonts.TableCellFont, bg, Rectangle.NO_BORDER, Element.ALIGN_CENTER));
                riskTable.AddCell(CreateStyledCell("-", fonts.TableCellFont, bg, Rectangle.NO_BORDER, Element.ALIGN_CENTER));
                idx++;
            }

            doc.Add(riskTable);
        }

        /// <summary>
        /// 生成修复建议章节
        /// </summary>
        private static void GenerateRemediationSection(Document doc, FontCollection fonts, List<VulnerabilityResult> vulns)
        {
            doc.Add(new Paragraph("五、修复建议与安全加固", fonts.Heading1Font) { SpacingBefore = 20, SpacingAfter = 15 });
            doc.Add(new Paragraph("本节提供针对发现的安全问题的具体修复建议和通用安全加固措施。", fonts.BodyFont)
            {
                SpacingBefore = 10,
                SpacingAfter = 15,
                IndentationLeft = 20
            });

            // 优先级矩阵
            doc.Add(new Paragraph("5.1 修复优先级矩阵", fonts.Heading2Font) { SpacingBefore = 15, SpacingAfter = 10 });

            var priorityTable = new PdfPTable(4);
            priorityTable.WidthPercentage = 90;
            priorityTable.SetWidths(new float[] { 0.8f, 2.5f, 2f, 1.5f });
            priorityTable.SpacingBefore = 5;

            AddTableHeader(priorityTable, new[] { "优先级", "处理时限", "适用范围", "建议措施" }, fonts);

            var priorities = new[]
            {
                new { Prio = "P1-紧急", Timeframe = "24小时内", Scope = "严重/远程执行类", Action = "立即隔离受影响系统" },
                new { Prio = "P2-高", Timeframe = "7天内", Scope = "高危/权限提升类", Action = "尽快安排维护窗口" },
                new { Prio = "P3-中", Timeframe = "30天内", Scope = "中危/信息泄露类", Action = "纳入常规更新计划" },
                new { Prio = "P4-低", Timeframe = "下个周期", Scope = "低危/信息类", Action = "持续监控" }
            };

            int prioIdx = 1;
            foreach (var priorityItem in priorities)
            {
                var prio = priorityItem.Prio;
                var time = priorityItem.Timeframe;
                var scope = priorityItem.Scope;
                var action = priorityItem.Action;

                var isZebra = prioIdx % 2 == 0;
                var bg = isZebra ? new BaseColor(248, 249, 250) : BaseColor.WHITE;

                var prioColor = prio.Contains("P1") ? new BaseColor(231, 76, 60) :
                               prio.Contains("P2") ? new BaseColor(243, 156, 18) :
                               prio.Contains("P3") ? new BaseColor(241, 196, 15) : new BaseColor(46, 204, 113);

                var prioCell = new PdfPCell(new Phrase(prio, new Font(fonts.BaseFont, 9, Font.BOLD, prioColor)))
                {
                    BackgroundColor = bg,
                    HorizontalAlignment = Element.ALIGN_CENTER,
                    VerticalAlignment = Element.ALIGN_MIDDLE,
                    Padding = 6,
                    Border = Rectangle.NO_BORDER
                };

                priorityTable.AddCell(prioCell);
                priorityTable.AddCell(CreateStyledCell(time, fonts.TableCellFont, bg, Rectangle.NO_BORDER, Element.ALIGN_CENTER));
                priorityTable.AddCell(CreateStyledCell(scope, fonts.TableCellFont, bg, Rectangle.NO_BORDER));
                priorityTable.AddCell(CreateStyledCell(action, fonts.TableCellFont, bg, Rectangle.NO_BORDER));
                prioIdx++;
            }

            doc.Add(priorityTable);

            // 高危漏洞详细修复建议
            if (vulns != null && vulns.Any())
            {
                var highRiskVulns = vulns
                    .Where(v => IsCritical(v.RiskLevel) || IsHigh(v.RiskLevel))
                    .OrderByDescending(v => IsCritical(v.RiskLevel) ? 1 : 0)
                    .Take(5)
                    .ToList();

                if (highRiskVulns.Any())
                {
                    doc.Add(new Paragraph("\n5.2 高危漏洞修复建议（Top 5）", fonts.Heading2Font) { SpacingBefore = 20, SpacingAfter = 10 });

                    int fixIdx = 1;
                    foreach (var vuln in highRiskVulns)
                    {
                        var fixTable = new PdfPTable(1);
                        fixTable.WidthPercentage = 100;
                        fixTable.SpacingBefore = 5;
                        fixTable.SpacingAfter = 5;

                        var fixCell = new PdfPCell();
                        fixCell.Border = Rectangle.BOX;
                        fixCell.BorderColor = GetRiskLevelColor(vuln.RiskLevel);
                        fixCell.BorderWidth = 0.5f;
                        fixCell.Padding = 10;
                        fixCell.BackgroundColor = new BaseColor(252, 252, 252);

                        var fixContent = new Paragraph();
                        fixContent.Add(new Phrase($"【{fixIdx}】{vuln.Name}", new Font(fonts.BaseFont, 11, Font.BOLD, GetRiskLevelColor(vuln.RiskLevel))));
                        if (!string.IsNullOrEmpty(vuln.CveId))
                            fixContent.Add(new Phrase($" ({vuln.CveId})\n", fonts.SmallFont));
                        else
                            fixContent.Add("\n");

                        fixContent.Add(new Phrase("修复步骤: ", fonts.BoldBodyFont));
                        if (!string.IsNullOrEmpty(vuln.Solution))
                            fixContent.Add(new Phrase($"{vuln.Solution}\n", fonts.BodyFont));
                        else
                            fixContent.Add(new Phrase("1. 访问官方安全公告获取补丁信息\n2. 备份相关数据和配置\n3. 应用最新的安全补丁或升级版本\n4. 验证修复效果并重启相关服务\n", fonts.BodyFont));

                        fixCell.Phrase = fixContent;
                        fixTable.AddCell(fixCell);
                        doc.Add(fixTable);
                        fixIdx++;
                    }
                }
            }

            // 通用安全加固建议
            doc.Add(new Paragraph("\n5.3 通用安全加固建议", fonts.Heading2Font) { SpacingBefore = 20, SpacingAfter = 10 });

            var hardeningTips = new[]
            {
                new { Category = "网络层面", Content = "配置防火墙规则，仅开放必要的业务端口；实施网络分段隔离；启用入侵检测/防御系统(IDS/IPS)；定期审计网络访问日志。" },
                new { Category = "系统层面", Content = "及时安装操作系统安全更新；禁用不必要的服务和账户；配置强密码策略（长度>=12位，含大小写字母、数字、特殊字符）；启用账户锁定策略防止暴力破解。" },
                new { Category = "应用层面", Content = "保持应用程序及依赖库为最新版本；实施安全的编码实践（输入验证、参数化查询）；定期进行代码安全审查和渗透测试；配置安全的HTTP头部（CSP、X-Frame-Options等）。" },
                new { Category = "身份认证", Content = "实施多因素认证(MFA)；采用基于角色的访问控制(RBAC)；定期清理过期账户和冗余权限；监控异常登录行为。" },
                new { Category = "数据保护", Content = "加密敏感数据存储和传输（TLS 1.2+）；实施数据分类和分级保护；建立数据备份和恢复机制；制定数据泄露应急响应预案。" },
                new { Category = "监控审计", Content = "部署集中化日志管理系统；设置安全事件告警阈值；定期进行安全基线检查；保留审计日志至少180天以满足合规要求。" }
            };

            int tipIdx = 1;
            foreach (var hardeningItem in hardeningTips)
            {
                var category = hardeningItem.Category;
                var content = hardeningItem.Content;

                var tipTable = new PdfPTable(1);
                tipTable.WidthPercentage = 100;
                tipTable.SpacingBefore = 5;
                tipTable.SpacingAfter = 5;

                var tipCell = new PdfPCell();
                tipCell.Border = Rectangle.BOX;
                tipCell.BorderColor = new BaseColor(52, 152, 219);
                tipCell.BorderWidthLeft = 3;
                tipCell.PaddingLeft = 15;
                tipCell.PaddingTop = 5;
                tipCell.PaddingBottom = 5;
                tipCell.BackgroundColor = new BaseColor(248, 250, 252);

                var tipContent = new Paragraph();
                tipContent.Add(new Phrase($"{tipIdx}. {category}: ", fonts.BoldBodyFont));
                tipContent.Add(new Phrase(content, fonts.BodyFont));

                tipCell.Phrase = tipContent;
                tipTable.AddCell(tipCell);
                doc.Add(tipTable);
                tipIdx++;
            }

            // 免责声明
            doc.Add(new Paragraph(" ", fonts.BodyFont) { SpacingBefore = 30 });
            var disclaimer = new Paragraph(
                "免责声明：本报告由 NetSecurityScanner 安全扫描工具自动生成。" +
                "报告中的漏洞检测结果和建议仅供参考，实际安全决策应结合具体业务场景和专业安全团队的人工判断。" +
                "在应用任何修复措施前，请务必在测试环境充分验证。",
                new Font(fonts.BaseFont, 9, Font.NORMAL, new BaseColor(128, 128, 128)))
            {
                IndentationLeft = 20,
                IndentationRight = 20,
                Alignment = Element.ALIGN_JUSTIFIED
            };
            doc.Add(disclaimer);
        }

        /// <summary>
        /// 专业报告页眉页脚事件处理器
        /// </summary>
        public class ProfessionalReportPageEvent : PdfPageEventHelper
        {
            private BaseFont _baseFont;
            private int _pageNumber = 0;
            private bool _isCoverPage = true;

            public override void OnOpenDocument(PdfWriter writer, Document document)
            {
                string[] fontPaths = {
                    @"C:\Windows\Fonts\msyh.ttc,0",
                    @"C:\Windows\Fonts\simhei.ttf",
                    @"C:\Windows\Fonts\simsun.ttc,0"
                };

                foreach (var fp in fontPaths)
                {
                    try { _baseFont = BaseFont.CreateFont(fp, BaseFont.IDENTITY_H, BaseFont.EMBEDDED); break; }
                    catch { }
                }

                if (_baseFont == null)
                {
                    try { _baseFont = BaseFont.CreateFont(BaseFont.HELVETICA, BaseFont.CP1252, false); }
                    catch { }
                }
            }

            public override void OnEndPage(PdfWriter writer, Document document)
            {
                _pageNumber++;

                // 封面页不显示页眉页脚
                if (_isCoverPage)
                {
                    _isCoverPage = false;
                    return;
                }

                var font = _baseFont != null ? new Font(_baseFont, 8, Font.NORMAL, new BaseColor(128, 128, 128)) :
                           new Font(Font.FontFamily.HELVETICA, 8, Font.NORMAL, new BaseColor(128, 128, 128));

                // 页眉
                var headerTable = new PdfPTable(2);
                headerTable.TotalWidth = document.PageSize.Width - document.LeftMargin - document.RightMargin;
                headerTable.SetWidths(new float[] { 3f, 2f });

                var leftHeaderCell = new PdfPCell(new Phrase("网络安全漏洞扫描报告", font))
                {
                    Border = Rectangle.NO_BORDER,
                    HorizontalAlignment = Element.ALIGN_LEFT,
                    PaddingBottom = 5
                };

                var rightHeaderCell = new PdfPCell(new Phrase($"NetSecurityScanner v{VersionHelper.GetVersion()}", font))
                {
                    Border = Rectangle.NO_BORDER,
                    HorizontalAlignment = Element.ALIGN_RIGHT,
                    PaddingBottom = 5
                };

                headerTable.AddCell(leftHeaderCell);
                headerTable.AddCell(rightHeaderCell);
                headerTable.WriteSelectedRows(0, -1, document.LeftMargin, document.PageSize.Height - 20, writer.DirectContent);

                // 页眉分隔线
                var headerLineCb = writer.DirectContent;
                headerLineCb.SetColorStroke(new BaseColor(200, 200, 200));
                headerLineCb.MoveTo(document.LeftMargin, document.PageSize.Height - 28);
                headerLineCb.LineTo(document.PageSize.Width - document.RightMargin, document.PageSize.Height - 28);
                headerLineCb.Stroke();

                // 页脚
                var footerTable = new PdfPTable(2);
                footerTable.TotalWidth = document.PageSize.Width - document.LeftMargin - document.RightMargin;
                footerTable.SetWidths(new float[] { 3f, 2f });

                var leftFooterCell = new PdfPCell(new Phrase("机密 - 内部文档", font))
                {
                    Border = Rectangle.NO_BORDER,
                    HorizontalAlignment = Element.ALIGN_LEFT,
                    PaddingTop = 5
                };

                var rightFooterCell = new PdfPCell(new Phrase($"第 {_pageNumber} 页 / 共 Y 页", font))
                {
                    Border = Rectangle.NO_BORDER,
                    HorizontalAlignment = Element.ALIGN_RIGHT,
                    PaddingTop = 5
                };

                footerTable.AddCell(leftFooterCell);
                footerTable.AddCell(rightFooterCell);
                footerTable.WriteSelectedRows(0, -1, document.LeftMargin, 28, writer.DirectContent);

                // 页脚分隔线
                var footerLineCb = writer.DirectContent;
                footerLineCb.SetColorStroke(new BaseColor(200, 200, 200));
                footerLineCb.MoveTo(document.LeftMargin, 38);
                footerLineCb.LineTo(document.PageSize.Width - document.RightMargin, 38);
                footerLineCb.Stroke();
            }
        }
    }
}
