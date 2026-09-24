using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using NetSecurityScanner.Models;
using NetSecurityScanner.Data;
using iTextSharp.text;
using iTextSharp.text.pdf;
using iTextParagraph = iTextSharp.text.Paragraph;
using iTextFont = iTextSharp.text.Font;

namespace NetSecurityScanner.Services
{
    public class ReportGeneratorService
    {
        private JSONDatabaseService _databaseService;
        
        public ReportGeneratorService()
        {
            _databaseService = new JSONDatabaseService();
        }
        
        public async Task<string> GenerateReportAsync(int taskId, string reportType, string format)
        {
            await Task.Delay(500);
            
            var task = _databaseService.GetScanTask(taskId);
            var results = _databaseService.GetScanResultsByTaskId(taskId);
            var vulnerabilities = results.Where(r => r.IsVulnerable).ToList();
            
            string content;
            switch (reportType)
            {
                case "Compliance":
                    content = GenerateComplianceReport(task, results, vulnerabilities, format);
                    break;
                case "Technical":
                    content = GenerateTechnicalReport(task, results, vulnerabilities, format);
                    break;
                case "Management":
                    content = GenerateManagementReport(task, results, vulnerabilities, format);
                    break;
                default:
                    content = GenerateDefaultReport(task, results, vulnerabilities, format);
                    break;
            }
            
            if (format == "PDF")
            {
                return await ExportToPdfAsync(content, taskId, reportType);
            }
            else if (format == "Word")
            {
                throw new NotSupportedException("Word 格式导出需要 Windows 平台支持。请使用 PDF 或 HTML 格式替代。");
            }
            else
            {
                return SaveReport(content, taskId, reportType, format);
            }
        }
        
        private async Task<string> ExportToPdfAsync(string markdownContent, int taskId, string reportType)
        {
            await Task.Delay(100);
            
            var reportDir = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "Reports");
            if (!Directory.Exists(reportDir))
            {
                Directory.CreateDirectory(reportDir);
            }
            
            var timestamp = DateTime.Now.ToString("yyyyMMdd_HHmmss");
            var fileName = $"Report_{taskId}_{reportType}_{timestamp}.pdf";
            var filePath = Path.Combine(reportDir, fileName);
            
            using (var fs = new FileStream(filePath, FileMode.Create, FileAccess.Write, FileShare.None))
            {
                var doc = new iTextSharp.text.Document(PageSize.A4, 50, 50, 50, 50);
                var writer = PdfWriter.GetInstance(doc, fs);
                
                doc.Open();
                
                BaseFont baseFont;
                try
                {
                    baseFont = BaseFont.CreateFont("C:\\Windows\\Fonts\\msyh.ttc,0", BaseFont.IDENTITY_H, BaseFont.EMBEDDED);
                }
                catch
                {
                    baseFont = BaseFont.CreateFont(BaseFont.HELVETICA, BaseFont.CP1252, false);
                }
                
                var titleFont = new iTextFont(baseFont, 24, iTextFont.BOLD, new BaseColor(44, 62, 80));
                var normalFont = new iTextFont(baseFont, 11, iTextFont.NORMAL, BaseColor.BLACK);
                
                var lines = markdownContent.Split(new[] { "\r\n", "\n" }, StringSplitOptions.None);
                
                foreach (var line in lines)
                {
                    var trimmedLine = line.Trim();
                    
                    if (string.IsNullOrEmpty(trimmedLine))
                    {
                        doc.Add(new iTextParagraph(" ", normalFont));
                        continue;
                    }
                    
                    if (trimmedLine.StartsWith("# "))
                    {
                        var title = trimmedLine.Substring(2);
                        var titlePara = new iTextParagraph(title, titleFont);
                        titlePara.Alignment = Element.ALIGN_CENTER;
                        titlePara.SpacingAfter = 20;
                        doc.Add(titlePara);
                    }
                    else
                    {
                        var para = new iTextParagraph(trimmedLine, normalFont);
                        para.SpacingAfter = 5;
                        doc.Add(para);
                    }
                }
                
                doc.Close();
                writer.Close();
            }
            
            return filePath;
        }
        
        private string SaveReport(string content, int taskId, string reportType, string format)
        {
            var reportDir = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "Reports");
            if (!Directory.Exists(reportDir))
            {
                Directory.CreateDirectory(reportDir);
            }
            
            var timestamp = DateTime.Now.ToString("yyyyMMdd_HHmmss");
            var extension = format == "Markdown" ? ".md" : ".txt";
            var fileName = $"Report_{taskId}_{reportType}_{timestamp}{extension}";
            var filePath = Path.Combine(reportDir, fileName);
            
            File.WriteAllText(filePath, content, Encoding.UTF8);
            
            return filePath;
        }
        
        private string GenerateTechnicalReport(ScanTask task, List<ScanResult> results, List<ScanResult> vulnerabilities, string format)
        {
            var reportContent = new StringBuilder();
            reportContent.AppendLine("# 技术漏洞分析报告");
            reportContent.AppendLine();
            reportContent.AppendLine($"- 任务名称: {task?.TaskName ?? "未知任务"}");
            reportContent.AppendLine($"- 生成时间: {DateTime.Now:yyyy-MM-dd HH:mm:ss}");
            reportContent.AppendLine();
            reportContent.AppendLine($"- 扫描目标: {task?.TargetHosts ?? "未知"}");
            reportContent.AppendLine($"- 发现漏洞: {vulnerabilities.Count} 个");
            
            return reportContent.ToString();
        }
        
        private string GenerateManagementReport(ScanTask task, List<ScanResult> results, List<ScanResult> vulnerabilities, string format)
        {
            return $"# 管理层安全评估摘要\n\n- 任务名称: {task?.TaskName ?? "未知任务"}\n- 生成时间: {DateTime.Now:yyyy-MM-dd HH:mm:ss}\n- 发现漏洞: {vulnerabilities.Count} 个\n";
        }
        
        private string GenerateComplianceReport(ScanTask task, List<ScanResult> results, List<ScanResult> vulnerabilities, string format)
        {
            return $"# 安全合规性评估报告\n\n- 任务名称: {task?.TaskName ?? "未知任务"}\n- 生成时间: {DateTime.Now:yyyy-MM-dd HH:mm:ss}\n- 发现漏洞: {vulnerabilities.Count} 个\n";
        }
        
        private string GenerateDefaultReport(ScanTask task, List<ScanResult> results, List<ScanResult> vulnerabilities, string format)
        {
            var reportContent = new StringBuilder();
            var timestamp = DateTime.Now;

            reportContent.AppendLine($"# {task?.TaskName ?? "目标系统"}综合评估报告");
            reportContent.AppendLine();
            reportContent.AppendLine($"**生成时间: {timestamp:yyyy年MM月dd日 HH:mm:ss}**");
            reportContent.AppendLine();
            reportContent.AppendLine($"- 扫描目标: {task?.TargetHosts ?? "未知"}");
            reportContent.AppendLine($"- 扫描类型: {task?.ScanType ?? "未知"}");
            reportContent.AppendLine($"- 发现漏洞: {vulnerabilities.Count} 个");
            reportContent.AppendLine($"- 总扫描结果: {results.Count} 个");
            
            return reportContent.ToString();
        }
        
        public async Task<string> GenerateVulnerabilityReportAsync(List<Vulnerability> vulnerabilities, string targetHost, string format)
        {
            await Task.Delay(300);
            
            var reportContent = new StringBuilder();
            var timestamp = DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss");
            
            reportContent.AppendLine("# 漏洞扫描报告");
            reportContent.AppendLine();
            reportContent.AppendLine($"- 目标主机: {targetHost}");
            reportContent.AppendLine($"- 生成时间: {timestamp}");
            reportContent.AppendLine($"- 发现漏洞数: {vulnerabilities.Count}");
            reportContent.AppendLine();
            
            foreach (var vuln in vulnerabilities)
            {
                reportContent.AppendLine($"## {vuln.CveId} - {vuln.Name}");
                reportContent.AppendLine($"- 严重程度: {vuln.Severity}");
                reportContent.AppendLine($"- 描述: {vuln.Description}");
                reportContent.AppendLine();
            }
            
            var content = reportContent.ToString();
            return SaveReport(content, 0, "Vulnerability", format);
        }
        
        public async Task<string> GeneratePortScanReportAsync(List<PortInfo> portScanResults, string targetHost, string format)
        {
            await Task.Delay(300);
            
            var reportContent = new StringBuilder();
            var timestamp = DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss");
            var openPorts = portScanResults.Where(p => p.Status == "开放").ToList();
            
            reportContent.AppendLine("# 端口扫描报告");
            reportContent.AppendLine();
            reportContent.AppendLine($"- 目标主机: {targetHost}");
            reportContent.AppendLine($"- 生成时间: {timestamp}");
            reportContent.AppendLine($"- 开放端口数: {openPorts.Count}");
            reportContent.AppendLine();
            
            foreach (var port in openPorts.OrderBy(p => p.PortNumber))
            {
                reportContent.AppendLine($"- 端口 {port.PortNumber}: {port.Service}");
            }
            
            var content = reportContent.ToString();
            return SaveReport(content, 0, "PortScan", format);
        }
        
        public List<ReportInfo> GetGeneratedReports()
        {
            var reports = new List<ReportInfo>();
            
            var reportDir = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "Reports");
            if (!Directory.Exists(reportDir))
            {
                return reports;
            }
            
            try
            {
                var files = Directory.GetFiles(reportDir, "*.md")
                    .Concat(Directory.GetFiles(reportDir, "*.pdf"))
                    .Concat(Directory.GetFiles(reportDir, "*.docx"));
                
                int reportId = 1;
                foreach (var file in files)
                {
                    var fileName = Path.GetFileName(file);
                    var fileInfo = new FileInfo(file);
                    
                    reports.Add(new ReportInfo
                    {
                        ReportId = reportId++,
                        ReportName = fileName,
                        ReportPath = file,
                        GeneratedAt = fileInfo.CreationTime,
                        Size = fileInfo.Length
                    });
                }
            }
            catch
            {
            }
            
            return reports.OrderByDescending(r => r.GeneratedAt).ToList();
        }
    }
    
    public class ReportInfo
    {
        public int ReportId { get; set; }
        public string ReportName { get; set; } = string.Empty;
        public string ReportPath { get; set; } = string.Empty;
        public string ReportType { get; set; } = string.Empty;
        public string Format { get; set; } = string.Empty;
        public DateTime GeneratedAt { get; set; }
        public int VulnerabilityCount { get; set; }
        public int PortCount { get; set; }
        public string Host { get; set; } = string.Empty;
        public string TaskName { get; set; } = string.Empty;
        public long Size { get; set; }
        public bool IsSelected { get; set; }
        
        public string GeneratedAtText => GeneratedAt.ToString("yyyy-MM-dd HH:mm:ss");
        public string SizeText => Size >= 1024 * 1024 ? $"{Size / (1024.0 * 1024):F2} MB" : Size >= 1024 ? $"{Size / 1024.0:F2} KB" : $"{Size} B";
        public string FileSizeText => SizeText;
    }
}