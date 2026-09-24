using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using NetSecurityScanner.Models;

namespace NetSecurityScanner.Services
{
    public enum ReportFormat
    {
        Txt,
        Csv,
        Html,
        Word,
        Pdf
    }
    
    public class ReportGenerator
    {
        public static string GenerateReport(List<PortScanResult> portScanResults, 
                                          List<VulnerabilityResult> vulnerabilityResults, 
                                          List<RiskAssessmentItem> riskAssessmentItems,
                                          string targetIp = "未知",
                                          ReportFormat format = ReportFormat.Txt)
        {
            // 参数验证，确保列表不为null
            portScanResults ??= new List<PortScanResult>();
            vulnerabilityResults ??= new List<VulnerabilityResult>();
            riskAssessmentItems ??= new List<RiskAssessmentItem>();
            
            switch (format)
            {
                case ReportFormat.Csv:
                    return GenerateCsvReport(portScanResults, vulnerabilityResults, riskAssessmentItems, targetIp);
                case ReportFormat.Html:
                    return GenerateHtmlReport(portScanResults, vulnerabilityResults, riskAssessmentItems, targetIp);
                case ReportFormat.Word:
                    return GenerateWordReport(portScanResults, vulnerabilityResults, riskAssessmentItems, targetIp);
                case ReportFormat.Pdf:
                    return GeneratePdfReport(portScanResults, vulnerabilityResults, riskAssessmentItems, targetIp);
                case ReportFormat.Txt:
                default:
                    return GenerateTxtReport(portScanResults, vulnerabilityResults, riskAssessmentItems, targetIp);
            }
        }
        
        private static string GenerateTxtReport(List<PortScanResult> portScanResults, 
                                              List<VulnerabilityResult> vulnerabilityResults, 
                                              List<RiskAssessmentItem> riskAssessmentItems,
                                              string targetIp)
        {
            var report = new StringBuilder();
            report.AppendLine("网络安全扫描报告");
            report.AppendLine("=================");
            report.AppendLine($"生成时间: {DateTime.Now}");
            report.AppendLine();

            report.AppendLine("端口扫描结果:");
            report.AppendLine("-------------");
            foreach (var result in portScanResults)
            {
                report.AppendLine($"端口 {result.PortNumber}: {result.Status} ({result.Service})");
            }
            report.AppendLine();

            report.AppendLine("漏洞扫描结果:");
            report.AppendLine("-------------");
            if (vulnerabilityResults.Any())
            {
                foreach (var vuln in vulnerabilityResults)
                {
                    report.AppendLine($"目标IP: {targetIp}");
                    report.AppendLine($"漏洞名称: {vuln.Name}");
                    report.AppendLine($"风险等级: {vuln.RiskLevel}");
                    report.AppendLine($"端口: {vuln.Port?.ToString() ?? "N/A"}");
                    report.AppendLine($"服务: {vuln.Service}");
                    report.AppendLine($"CVE编号: {vuln.CveId}");
                    report.AppendLine($"检测方法: {vuln.DetectionMethod}");
                    report.AppendLine($"描述: {vuln.Description}");
                    report.AppendLine($"解决方案: {vuln.Solution}");
                    report.AppendLine($"参考连接: {vuln.References}");
                    report.AppendLine();
                }
            }
            else
            {
                report.AppendLine("未发现漏洞");
                report.AppendLine();
            }
            report.AppendLine();

            report.AppendLine("风险评估结果:");
            report.AppendLine("-------------");
            foreach (var item in riskAssessmentItems)
            {
                report.AppendLine($"{item.Item}: {item.Value} ({item.Status})");
            }

            return report.ToString();
        }
        
        private static string GenerateCsvReport(List<PortScanResult> portScanResults, 
                                              List<VulnerabilityResult> vulnerabilityResults, 
                                              List<RiskAssessmentItem> riskAssessmentItems,
                                              string targetIp)
        {
            var report = new StringBuilder();
            
            // 报告标题和基本信息
            report.AppendLine("网络安全扫描报告");
            report.AppendLine($"生成时间,{DateTime.Now}");
            report.AppendLine();
            
            // 端口扫描结果
            report.AppendLine("端口扫描结果");
            report.AppendLine("端口号,状态,服务");
            foreach (var result in portScanResults)
            {
                report.AppendLine($"{result.PortNumber},{result.Status},{result.Service}");
            }
            report.AppendLine();
            
            // 漏洞扫描结果
            report.AppendLine("漏洞扫描结果");
            report.AppendLine("目标IP,漏洞名称,风险等级,端口,服务,CVE编号,检测方法,描述,解决方案,参考连接");
            foreach (var vuln in vulnerabilityResults)
            {
                // CSV转义：将引号替换为双引号，并用引号包围包含逗号的字段
                string ip = EscapeCsvField(targetIp);
                string name = EscapeCsvField(vuln.Name);
                string riskLevel = EscapeCsvField(vuln.RiskLevel);
                string port = vuln.Port.HasValue ? vuln.Port.Value.ToString() : "N/A";
                string service = EscapeCsvField(vuln.Service);
                string cveId = EscapeCsvField(vuln.CveId);
                string detectionMethod = EscapeCsvField(vuln.DetectionMethod);
                string description = EscapeCsvField(vuln.Description);
                string solution = EscapeCsvField(vuln.Solution);
                string references = EscapeCsvField(vuln.References);
                
                report.AppendLine($"{ip},{name},{riskLevel},{port},{service},{cveId},{detectionMethod},{description},{solution},{references}");
            }
            report.AppendLine();
            
            // 风险评估结果
            report.AppendLine("风险评估结果");
            report.AppendLine("项目,值,状态");
            foreach (var item in riskAssessmentItems)
            {
                string itemName = EscapeCsvField(item.Item);
                string value = EscapeCsvField(item.Value);
                string status = EscapeCsvField(item.Status);
                
                report.AppendLine($"{itemName},{value},{status}");
            }
            
            return report.ToString();
        }
        
        private static string GenerateHtmlReport(List<PortScanResult> portScanResults, 
                                              List<VulnerabilityResult> vulnerabilityResults, 
                                              List<RiskAssessmentItem> riskAssessmentItems,
                                              string targetIp)
        {
            var report = new StringBuilder();
            
            // HTML头部
            report.AppendLine("<!DOCTYPE html>");
            report.AppendLine("<html>");
            report.AppendLine("<head>");
            report.AppendLine("<meta charset='utf-8'>");
            report.AppendLine("<meta name='viewport' content='width=device-width, initial-scale=1.0'>");
            report.AppendLine("<title>网络安全扫描报告</title>");
            report.AppendLine("<style>");
            report.AppendLine("* {");
            report.AppendLine("    box-sizing: border-box;");
            report.AppendLine("    margin: 0;");
            report.AppendLine("    padding: 0;");
            report.AppendLine("}");
            report.AppendLine("body {");
            report.AppendLine("    font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;");
            report.AppendLine("    background-color: #f5f7fa;");
            report.AppendLine("    color: #333;");
            report.AppendLine("    line-height: 1.6;");
            report.AppendLine("    margin: 0;");
            report.AppendLine("    padding: 20px;");
            report.AppendLine("}");
            report.AppendLine(".container {");
            report.AppendLine("    max-width: 1200px;");
            report.AppendLine("    margin: 0 auto;");
            report.AppendLine("    background: white;");
            report.AppendLine("    border-radius: 8px;");
            report.AppendLine("    box-shadow: 0 2px 10px rgba(0, 0, 0, 0.1);");
            report.AppendLine("    overflow: hidden;");
            report.AppendLine("}");
            report.AppendLine(".header {");
            report.AppendLine("    background: linear-gradient(135deg, #2C3E50 0%, #3498DB 100%);");
            report.AppendLine("    color: white;");
            report.AppendLine("    padding: 30px;");
            report.AppendLine("    text-align: center;");
            report.AppendLine("}");
            report.AppendLine(".header h1 {");
            report.AppendLine("    margin: 0 0 10px 0;");
            report.AppendLine("    font-size: 2.5em;");
            report.AppendLine("    font-weight: 600;");
            report.AppendLine("}");
            report.AppendLine(".header .meta {");
            report.AppendLine("    font-size: 1.1em;");
            report.AppendLine("    opacity: 0.9;");
            report.AppendLine("}");
            report.AppendLine(".content {");
            report.AppendLine("    padding: 30px;");
            report.AppendLine("}");
            report.AppendLine(".section {");
            report.AppendLine("    margin-bottom: 30px;");
            report.AppendLine("}");
            report.AppendLine("h2 {");
            report.AppendLine("    color: #2C3E50;");
            report.AppendLine("    margin-bottom: 15px;");
            report.AppendLine("    font-size: 1.8em;");
            report.AppendLine("    border-bottom: 2px solid #3498DB;");
            report.AppendLine("    padding-bottom: 10px;");
            report.AppendLine("}");
            report.AppendLine("h3 {");
            report.AppendLine("    color: #34495E;");
            report.AppendLine("    margin: 20px 0 10px 0;");
            report.AppendLine("    font-size: 1.3em;");
            report.AppendLine("}");
            report.AppendLine(".summary {");
            report.AppendLine("    background-color: #ECF0F1;");
            report.AppendLine("    padding: 20px;");
            report.AppendLine("    border-radius: 6px;");
            report.AppendLine("    margin-bottom: 20px;");
            report.AppendLine("}");
            report.AppendLine(".summary-grid {");
            report.AppendLine("    display: grid;");
            report.AppendLine("    grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));");
            report.AppendLine("    gap: 20px;");
            report.AppendLine("    margin-top: 15px;");
            report.AppendLine("}");
            report.AppendLine(".summary-item {");
            report.AppendLine("    background: white;");
            report.AppendLine("    padding: 15px;");
            report.AppendLine("    border-radius: 6px;");
            report.AppendLine("    box-shadow: 0 1px 3px rgba(0, 0, 0, 0.1);");
            report.AppendLine("    text-align: center;");
            report.AppendLine("}");
            report.AppendLine(".summary-item .label {");
            report.AppendLine("    font-size: 0.9em;");
            report.AppendLine("    color: #7f8c8d;");
            report.AppendLine("    margin-bottom: 5px;");
            report.AppendLine("}");
            report.AppendLine(".summary-item .value {");
            report.AppendLine("    font-size: 2em;");
            report.AppendLine("    font-weight: bold;");
            report.AppendLine("    color: #3498DB;");
            report.AppendLine("}");
            report.AppendLine("table {");
            report.AppendLine("    width: 100%;");
            report.AppendLine("    border-collapse: collapse;");
            report.AppendLine("    margin: 20px 0;");
            report.AppendLine("    background: white;");
            report.AppendLine("    border-radius: 6px;");
            report.AppendLine("    overflow: hidden;");
            report.AppendLine("    box-shadow: 0 1px 3px rgba(0, 0, 0, 0.1);");
            report.AppendLine("}");
            report.AppendLine("th {");
            report.AppendLine("    background-color: #2C3E50;");
            report.AppendLine("    color: white;");
            report.AppendLine("    padding: 12px 15px;");
            report.AppendLine("    text-align: left;");
            report.AppendLine("    font-weight: 600;");
            report.AppendLine("    text-transform: uppercase;");
            report.AppendLine("    font-size: 0.9em;");
            report.AppendLine("    letter-spacing: 0.5px;");
            report.AppendLine("}");
            report.AppendLine("td {");
            report.AppendLine("    padding: 12px 15px;");
            report.AppendLine("    border-bottom: 1px solid #ecf0f1;");
            report.AppendLine("}");
            report.AppendLine("tr:last-child td {");
            report.AppendLine("    border-bottom: none;");
            report.AppendLine("}");
            report.AppendLine("tr:nth-child(even) {");
            report.AppendLine("    background-color: #f8f9fa;");
            report.AppendLine("}");
            report.AppendLine("tr:hover {");
            report.AppendLine("    background-color: #e3f2fd;");
            report.AppendLine("    transition: background-color 0.2s ease;");
            report.AppendLine("}");
            report.AppendLine(".risk-high {");
            report.AppendLine("    color: white;");
            report.AppendLine("    background-color: #e74c3c;");
            report.AppendLine("    padding: 4px 8px;");
            report.AppendLine("    border-radius: 4px;");
            report.AppendLine("    font-weight: bold;");
            report.AppendLine("    font-size: 0.9em;");
            report.AppendLine("}");
            report.AppendLine(".risk-medium {");
            report.AppendLine("    color: white;");
            report.AppendLine("    background-color: #f39c12;");
            report.AppendLine("    padding: 4px 8px;");
            report.AppendLine("    border-radius: 4px;");
            report.AppendLine("    font-weight: bold;");
            report.AppendLine("    font-size: 0.9em;");
            report.AppendLine("}");
            report.AppendLine(".risk-low {");
            report.AppendLine("    color: white;");
            report.AppendLine("    background-color: #27ae60;");
            report.AppendLine("    padding: 4px 8px;");
            report.AppendLine("    border-radius: 4px;");
            report.AppendLine("    font-weight: bold;");
            report.AppendLine("    font-size: 0.9em;");
            report.AppendLine("}");
            report.AppendLine(".risk-severe {");
            report.AppendLine("    color: white;");
            report.AppendLine("    background-color: #c0392b;");
            report.AppendLine("    padding: 4px 8px;");
            report.AppendLine("    border-radius: 4px;");
            report.AppendLine("    font-weight: bold;");
            report.AppendLine("    font-size: 0.9em;");
            report.AppendLine("}");
            report.AppendLine(".risk-safe {");
            report.AppendLine("    color: white;");
            report.AppendLine("    background-color: #2980b9;");
            report.AppendLine("    padding: 4px 8px;");
            report.AppendLine("    border-radius: 4px;");
            report.AppendLine("    font-weight: bold;");
            report.AppendLine("    font-size: 0.9em;");
            report.AppendLine("}");
            report.AppendLine(".vulnerability-item {");
            report.AppendLine("    margin-bottom: 20px;");
            report.AppendLine("    padding: 15px;");
            report.AppendLine("    border: 1px solid #ecf0f1;");
            report.AppendLine("    border-radius: 6px;");
            report.AppendLine("    background: #fafafa;");
            report.AppendLine("}");
            report.AppendLine(".vulnerability-header {");
            report.AppendLine("    display: flex;");
            report.AppendLine("    justify-content: space-between;");
            report.AppendLine("    align-items: center;");
            report.AppendLine("    margin-bottom: 10px;");
            report.AppendLine("}");
            report.AppendLine(".vulnerability-name {");
            report.AppendLine("    font-size: 1.2em;");
            report.AppendLine("    font-weight: bold;");
            report.AppendLine("    color: #2C3E50;");
            report.AppendLine("}");
            report.AppendLine(".vulnerability-description {");
            report.AppendLine("    margin-bottom: 10px;");
            report.AppendLine("    color: #555;");
            report.AppendLine("}");
            report.AppendLine(".vulnerability-solution {");
            report.AppendLine("    margin-top: 10px;");
            report.AppendLine("    padding-top: 10px;");
            report.AppendLine("    border-top: 1px dashed #ddd;");
            report.AppendLine("}");
            report.AppendLine(".solution-title {");
            report.AppendLine("    font-weight: bold;");
            report.AppendLine("    color: #27ae60;");
            report.AppendLine("    margin-bottom: 5px;");
            report.AppendLine("}");
            report.AppendLine(".footer {");
            report.AppendLine("    background-color: #2C3E50;");
            report.AppendLine("    color: white;");
            report.AppendLine("    text-align: center;");
            report.AppendLine("    padding: 20px;");
            report.AppendLine("    font-size: 0.9em;");
            report.AppendLine("    margin-top: 30px;");
            report.AppendLine("}");
            report.AppendLine("</style>");
            report.AppendLine("</head>");
            report.AppendLine("<body>");
            
            // 报告容器
            report.AppendLine("<div class='container'>");
            
            // 报告标题和基本信息
            report.AppendLine("<div class='header'>");
            report.AppendLine("<h1 style='color: #3498DB;'>网络安全扫描报告</h1>");
            report.AppendLine($"<div class='meta'>生成时间: {DateTime.Now}</div>");
            report.AppendLine("</div>");
            
            // 报告内容
            report.AppendLine("<div class='content'>");
            
            // 执行摘要
            report.AppendLine("<div class='section'>");
            report.AppendLine("<h2>执行摘要</h2>");
            report.AppendLine("<div style='background-color: #e8f4f8; padding: 20px; border-radius: 6px; border-left: 5px solid #3498DB; margin-bottom: 20px;'>");
            report.AppendLine("<p style='font-size: 1.1em; line-height: 1.8;'>");
            report.AppendLine("本次扫描针对目标系统 <strong>" + EscapeHtml(targetIp) + "</strong> 进行了全面的网络安全评估，");
            report.AppendLine("发现了 <strong>" + vulnerabilityResults.Count + "</strong> 个安全漏洞，其中包括 <strong>" + vulnerabilityResults.Count(v => v.RiskLevel == "严重风险" || v.RiskLevel == "严重") + "</strong> 个严重风险漏洞、");
            report.AppendLine("<strong>" + vulnerabilityResults.Count(v => v.RiskLevel == "高风险" || v.RiskLevel == "高") + "</strong> 个高风险漏洞、");
            report.AppendLine("<strong>" + vulnerabilityResults.Count(v => v.RiskLevel == "中风险" || v.RiskLevel == "中") + "</strong> 个中风险漏洞和");
            report.AppendLine("<strong>" + vulnerabilityResults.Count(v => v.RiskLevel == "低风险" || v.RiskLevel == "低") + "</strong> 个低风险漏洞。");
            report.AppendLine("</p>");
            report.AppendLine("<p style='font-size: 1.1em; line-height: 1.8;'>");
            report.AppendLine("扫描还发现了 <strong>" + portScanResults.Count(p => p.Status == "开放" || p.Status == "开放或过滤") + "</strong> 个开放端口，");
            report.AppendLine("这些开放端口可能成为攻击者的潜在入口点。");
            report.AppendLine("</p>");
            report.AppendLine("<p style='font-size: 1.1em; font-weight: bold; margin-top: 15px;'>");
            report.AppendLine("<span style='color: #e74c3c;'>⚠️ 关键发现：</span> 发现多个严重风险漏洞，建议立即采取修复措施。");
            report.AppendLine("</p>");
            report.AppendLine("</div>");
            report.AppendLine("</div>");
            
            // 报告摘要
            report.AppendLine("<div class='summary'>");
            report.AppendLine("<h3>扫描结果摘要</h3>");
            report.AppendLine("<table>");
            report.AppendLine("<tr>");
            report.AppendLine("<th>扫描目标</th>");
            report.AppendLine("<th>扫描时间</th>");
            report.AppendLine("<th>扫描端口总数</th>");
            report.AppendLine("<th>开放端口数</th>");
            report.AppendLine("<th>漏洞总数</th>");
            report.AppendLine("</tr>");
            report.AppendLine("<tr>");
            report.AppendLine("<td>" + EscapeHtml(targetIp) + "</td>");
            report.AppendLine("<td>" + DateTime.Now + "</td>");
            report.AppendLine("<td>" + portScanResults.Count + "</td>");
            report.AppendLine("<td>" + portScanResults.Count(p => p.Status == "开放" || p.Status == "开放或过滤") + "</td>");
            report.AppendLine("<td>" + vulnerabilityResults.Count + "</td>");
            report.AppendLine("</tr>");
            report.AppendLine("</table>");
            
            // 漏洞风险分布
            report.AppendLine("<h3>漏洞风险分布</h3>");
            report.AppendLine("<table>");
            report.AppendLine("<tr>");
            report.AppendLine("<th>严重风险漏洞</th>");
            report.AppendLine("<th>高风险漏洞</th>");
            report.AppendLine("<th>中风险漏洞</th>");
            report.AppendLine("<th>低风险漏洞</th>");
            report.AppendLine("</tr>");
            report.AppendLine("<tr>");
            report.AppendLine("<td>" + vulnerabilityResults.Count(v => v.RiskLevel == "严重风险" || v.RiskLevel == "严重") + "</td>");
            report.AppendLine("<td>" + vulnerabilityResults.Count(v => v.RiskLevel == "高风险" || v.RiskLevel == "高") + "</td>");
            report.AppendLine("<td>" + vulnerabilityResults.Count(v => v.RiskLevel == "中风险" || v.RiskLevel == "中") + "</td>");
            report.AppendLine("<td>" + vulnerabilityResults.Count(v => v.RiskLevel == "低风险" || v.RiskLevel == "低") + "</td>");
            report.AppendLine("</tr>");
            report.AppendLine("</table>");
            report.AppendLine("</div>");
            
            // 端口扫描结果
            report.AppendLine("<div class='section'>");
            report.AppendLine("<h2>端口扫描结果</h2>");
            
            // 只显示开放端口
            var openPorts = portScanResults.Where(p => p.Status == "开放" || p.Status == "开放或过滤").OrderBy(p => p.PortNumber).ToList();
            
            if (openPorts.Any())
            {
                report.AppendLine("<table>");
                report.AppendLine("<tr><th>端口号</th><th>状态</th><th>服务</th><th>服务版本</th></tr>");
                foreach (var result in openPorts)
                {
                    // 修复端口23的显示问题
                    string service = result.PortNumber == 23 ? "Telnet" : result.Service;
                    
                    report.AppendLine("<tr>");
                    report.AppendLine("<td>" + result.PortNumber + "</td>");
                    report.AppendLine("<td>" + result.Status + "</td>");
                    report.AppendLine("<td>" + service + "</td>");
                    report.AppendLine("<td>" + EscapeHtml(result.ServiceVersion ?? "未知") + "</td>");
                    report.AppendLine("</tr>");
                }
                report.AppendLine("</table>");
            }
            else
            {
                report.AppendLine("<div style='background-color: #d4edda; padding: 15px; border-radius: 6px; border-left: 5px solid #28a745;'>");
                report.AppendLine("<p>未发现开放端口</p>");
                report.AppendLine("</div>");
            }
            report.AppendLine("</div>");
            
            // 漏洞扫描结果
            report.AppendLine("<div class='section'>");
            report.AppendLine("<h2>漏洞扫描结果</h2>");
            
            if (vulnerabilityResults.Any())
            {
                report.AppendLine("<table>");
                report.AppendLine("<tr><th>目标IP</th><th>漏洞名称</th><th>风险等级</th><th>端口</th><th>服务</th><th>CVE编号</th><th>检测方法</th><th>描述</th><th>解决方案</th><th>参考连接</th></tr>");
                
                foreach (var vuln in vulnerabilityResults)
                {
                    string riskClass = GetRiskLevelClass(vuln.RiskLevel);
                    
                    report.AppendLine("<tr>");
                    // 目标IP
                    report.AppendLine("<td>" + EscapeHtml(targetIp) + "</td>");
                    report.AppendLine("<td>" + EscapeHtml(vuln.Name) + "</td>");
                    report.AppendLine("<td><span class='" + riskClass + "'>" + EscapeHtml(vuln.RiskLevel) + "</span></td>");
                    report.AppendLine("<td>" + (vuln.Port.HasValue ? vuln.Port.Value.ToString() : "N/A") + "</td>");
                    report.AppendLine("<td>" + EscapeHtml(vuln.Service) + "</td>");
                    report.AppendLine("<td>" + EscapeHtml(vuln.CveId) + "</td>");
                    report.AppendLine("<td>" + EscapeHtml(vuln.DetectionMethod) + "</td>");
                    report.AppendLine("<td>" + EscapeHtml(vuln.Description) + "</td>");
                    report.AppendLine("<td>" + EscapeHtml(vuln.Solution) + "</td>");
                    report.AppendLine("<td>" + EscapeHtml(vuln.References) + "</td>");
                    report.AppendLine("</tr>");
                }
                report.AppendLine("</table>");
            }
            else
            {
                report.AppendLine("<div style='background-color: #d4edda; padding: 15px; border-radius: 6px; border-left: 5px solid #28a745;'>");
                report.AppendLine("<p>未发现漏洞</p>");
                report.AppendLine("</div>");
            }
            
            report.AppendLine("</div>");
            
            // 风险评估结果
            report.AppendLine("<div class='section'>");
            report.AppendLine("<h2>风险评估结果</h2>");
            report.AppendLine("<table>");
            report.AppendLine("<tr><th>评估项目</th><th>风险值</th><th>评估状态</th></tr>");
            foreach (var item in riskAssessmentItems)
            {
                string statusClass = item.Status == "危险" || item.Status == "高风险" ? "risk-high" :
                                    item.Status == "警告" || item.Status == "中风险" ? "risk-medium" :
                                    item.Status == "注意" || item.Status == "低风险" ? "risk-low" : "risk-safe";
                
                report.AppendLine("<tr>");
                report.AppendLine("<td>" + EscapeHtml(item.Item) + "</td>");
                report.AppendLine("<td>" + EscapeHtml(item.Value) + "</td>");
                report.AppendLine("<td><span class='" + statusClass + "'>" + EscapeHtml(item.Status) + "</span></td>");
                report.AppendLine("</tr>");
            }
            report.AppendLine("</table>");
            report.AppendLine("</div>");
            
            // 威胁情报分析
            report.AppendLine("<div class='section'>");
            report.AppendLine("<h2>威胁情报分析</h2>");
            report.AppendLine("<div class='vulnerability-item'>");
            report.AppendLine("<h3>活跃威胁向量</h3>");
            report.AppendLine("<ul style='margin-left: 20px; line-height: 1.8;'>");
            report.AppendLine("<li>基于开放端口的服务探测和利用</li>");
            report.AppendLine("<li>已知漏洞的批量扫描和利用</li>");
            report.AppendLine("<li>弱密码和默认凭据攻击</li>");
            report.AppendLine("<li>拒绝服务攻击风险</li>");
            report.AppendLine("</ul>");
            report.AppendLine("</div>");
            
            report.AppendLine("<div class='vulnerability-item'>");
            report.AppendLine("<h3>行业威胁趋势</h3>");
            report.AppendLine("<p>当前网络安全威胁呈现以下趋势：</p>");
            report.AppendLine("<ul style='margin-left: 20px; line-height: 1.8;'>");
            report.AppendLine("<li>勒索软件攻击持续增长，针对关键基础设施</li>");
            report.AppendLine("<li>供应链攻击日益复杂，影响范围扩大</li>");
            report.AppendLine("<li>零日漏洞利用速度加快</li>");
            report.AppendLine("<li>云服务成为新的攻击重点</li>");
            report.AppendLine("</ul>");
            report.AppendLine("</div>");
            report.AppendLine("</div>");
            
            // 修复优先级建议
            report.AppendLine("<div class='section'>");
            report.AppendLine("<h2>修复优先级建议</h2>");
            report.AppendLine("<div style='background-color: #fff3cd; padding: 20px; border-radius: 6px; border-left: 5px solid #ffc107; margin-bottom: 20px;'>");
            report.AppendLine("<h3 style='color: #856404; margin-top: 0;'>修复优先级矩阵</h3>");
            report.AppendLine("<table style='width: 100%; margin: 15px 0;'>");
            report.AppendLine("<tr style='background-color: #ffeeba;'>");
            report.AppendLine("<th>优先级</th><th>风险等级</th><th>修复时限</th><th>建议措施</th></tr>");
            report.AppendLine("<tr>");
            report.AppendLine("<td style='text-align: center; font-weight: bold;'>1</td>");
            report.AppendLine("<td><span class='risk-severe'>严重风险</span></td>");
            report.AppendLine("<td>24小时内</td>");
            report.AppendLine("<td>立即修复，必要时停机维护</td></tr>");
            report.AppendLine("<tr>");
            report.AppendLine("<td style='text-align: center; font-weight: bold;'>2</td>");
            report.AppendLine("<td><span class='risk-high'>高风险</span></td>");
            report.AppendLine("<td>72小时内</td>");
            report.AppendLine("<td>优先修复，安排紧急维护</td></tr>");
            report.AppendLine("<tr>");
            report.AppendLine("<td style='text-align: center; font-weight: bold;'>3</td>");
            report.AppendLine("<td><span class='risk-medium'>中风险</span></td>");
            report.AppendLine("<td>7天内</td>");
            report.AppendLine("<td>纳入常规维护计划</td></tr>");
            report.AppendLine("<tr>");
            report.AppendLine("<td style='text-align: center; font-weight: bold;'>4</td>");
            report.AppendLine("<td><span class='risk-low'>低风险</span></td>");
            report.AppendLine("<td>30天内</td>");
            report.AppendLine("<td>计划内修复，定期复查</td></tr>");
            report.AppendLine("</table>");
            report.AppendLine("</div>");
            
            // 漏洞修复建议
            report.AppendLine("<h3>关键漏洞修复建议</h3>");
            var criticalVulns = vulnerabilityResults.Where(v => v.RiskLevel == "严重风险" || v.RiskLevel == "严重" || v.RiskLevel == "高风险" || v.RiskLevel == "高")
                                                   .Take(5); // 只显示前5个关键漏洞
            
            if (criticalVulns.Any())
            {
                report.AppendLine("<ul style='margin-left: 20px;'>");
                foreach (var vuln in criticalVulns)
                {
                    report.AppendLine("<li style='margin-bottom: 15px;'>");
                    report.AppendLine("<strong>" + EscapeHtml(vuln.Name) + "</strong> - <span class='" + GetRiskLevelClass(vuln.RiskLevel) + "'>" + vuln.RiskLevel + "</span>");
                    report.AppendLine("<ul style='margin-left: 20px; margin-top: 5px;'>");
                    report.AppendLine("<li>修复建议：" + EscapeHtml(vuln.Solution) + "</li>");
                    report.AppendLine("<li>影响范围：整个系统</li>");
                    report.AppendLine("<li>潜在威胁：远程代码执行、数据泄露</li>");
                    report.AppendLine("</ul>");
                    report.AppendLine("</li>");
                }
                report.AppendLine("</ul>");
            }
            report.AppendLine("</div>");
            
            // 合规参考
            report.AppendLine("<div class='section'>");
            report.AppendLine("<h2>合规参考</h2>");
            report.AppendLine("<div class='vulnerability-item'>");
            report.AppendLine("<h3>相关合规标准</h3>");
            report.AppendLine("<table style='width: 100%;'>");
            report.AppendLine("<tr style='background-color: #f8f9fa;'>");
            report.AppendLine("<th>合规标准</th><th>相关要求</th><th>符合性状态</th></tr>");
            report.AppendLine("<tr>");
            report.AppendLine("<td>等保2.0</td>");
            report.AppendLine("<td>网络安全等级保护基本要求</td>");
            report.AppendLine("<td><span class='risk-medium'>部分符合</span></td>");
            report.AppendLine("</tr>");
            report.AppendLine("<tr>");
            report.AppendLine("<td>ISO 27001</td>");
            report.AppendLine("<td>信息安全管理体系要求</td>");
            report.AppendLine("<td><span class='risk-medium'>部分符合</span></td>");
            report.AppendLine("</tr>");
            report.AppendLine("<tr>");
            report.AppendLine("<td>GDPR</td>");
            report.AppendLine("<td>通用数据保护条例</td>");
            report.AppendLine("<td><span class='risk-low'>需要评估</span></td>");
            report.AppendLine("</tr>");
            report.AppendLine("<tr>");
            report.AppendLine("<td>PCI DSS</td>");
            report.AppendLine("<td>支付卡行业数据安全标准</td>");
            report.AppendLine("<td><span class='risk-low'>需要评估</span></td>");
            report.AppendLine("</tr>");
            report.AppendLine("</table>");
            report.AppendLine("</div>");
            report.AppendLine("</div>");
            
            // 结论与建议
            report.AppendLine("<div class='section'>");
            report.AppendLine("<h2>结论与建议</h2>");
            report.AppendLine("<div style='background-color: #d4edda; padding: 20px; border-radius: 6px; border-left: 5px solid #28a745; margin-bottom: 20px;'>");
            report.AppendLine("<h3 style='color: #155724; margin-top: 0;'>总体安全状况</h3>");
            string overallStatus = vulnerabilityResults.Any(v => v.RiskLevel == "严重风险" || v.RiskLevel == "严重") ? "高风险" : 
                                  vulnerabilityResults.Any(v => v.RiskLevel == "高风险" || v.RiskLevel == "高") ? "中风险" : "低风险";
            string statusColor = overallStatus == "高风险" ? "#dc3545" : overallStatus == "中风险" ? "#ffc107" : "#28a745";
            
            report.AppendLine("<p style='font-size: 1.1em;'><strong>总体安全评级：</strong><span style='color: " + statusColor + "; font-weight: bold;'>" + overallStatus + "</span></p>");
            report.AppendLine("<p>本次扫描发现的漏洞需要立即采取措施修复，特别是严重和高风险漏洞。建议按照优先级矩阵制定详细的修复计划，并定期进行复查。</p>");
            report.AppendLine("</div>");
            
            report.AppendLine("<h3>长期安全建议</h3>");
            report.AppendLine("<ul style='margin-left: 20px; line-height: 1.8;'>");
            report.AppendLine("<li>建立定期漏洞扫描机制，建议每周至少进行一次全面扫描</li>");
            report.AppendLine("<li>实施漏洞管理流程，确保所有漏洞得到及时跟踪和修复</li>");
            report.AppendLine("<li>加强员工安全意识培训，提高安全防护能力</li>");
            report.AppendLine("<li>部署入侵检测和防御系统，实时监控网络流量</li>");
            report.AppendLine("<li>建立安全事件响应计划，定期进行演练</li>");
            report.AppendLine("<li>保持系统和应用程序的及时更新，修补已知漏洞</li>");
            report.AppendLine("<li>实施最小权限原则，限制用户和服务的访问权限</li>");
            report.AppendLine("<li>定期备份关键数据，确保数据可恢复性</li>");
            report.AppendLine("</ul>");
            report.AppendLine("</div>");
            
            report.AppendLine("</div>");
            
            // 页脚
            report.AppendLine("<div class='footer'>");
            report.AppendLine("<p>网络安全扫描报告 - 仅供内部使用</p>");
            report.AppendLine("<p>报告生成时间：" + DateTime.Now + "</p>");
            report.AppendLine("<p>报告版本：1.0</p>");
            report.AppendLine("</div>");
            
            // 结束容器
            report.AppendLine("</div>");
            
            // HTML尾部
            report.AppendLine("</body>");
            report.AppendLine("</html>");
            
            return report.ToString();
        }
        
        // CSV字段转义辅助方法
        private static string EscapeCsvField(string field)
        {
            if (string.IsNullOrEmpty(field))
                return "";
            
            // 如果字段包含逗号、引号或换行符，需要用引号包围
            if (field.Contains(",") || field.Contains("\"") || field.Contains("\n") || field.Contains("\r"))
            {
                // 将引号替换为双引号
                field = field.Replace("\"", "\"\"");
                // 用引号包围字段
                field = $"\"{field}\"";
            }
            
            return field;
        }
        
        // HTML转义辅助方法
        private static string EscapeHtml(string text)
        {
            if (string.IsNullOrEmpty(text))
                return "";
            
            return text.Replace("&", "&amp;")
                       .Replace("<", "&lt;")
                       .Replace(">", "&gt;")
                       .Replace("\"", "&quot;")
                       .Replace("'", "&#39;")
                       .Replace("\n", "<br>")
                       .Replace("\r", "")
                       .Replace("\t", "&nbsp;&nbsp;&nbsp;&nbsp;");
        }
        
        // 获取风险等级优先级（用于排序）
        private static int GetRiskLevelPriority(string riskLevel)
        {
            if (string.IsNullOrEmpty(riskLevel))
                return 0;
            
            riskLevel = riskLevel.Trim();
            
            return riskLevel switch
            {
                "严重风险" => 4,
                "严重" => 4,
                "高风险" => 3,
                "高" => 3,
                "中风险" => 2,
                "中" => 2,
                "低风险" => 1,
                "低" => 1,
                _ => 0
            };
        }
        
        // 获取风险等级对应的CSS类
        private static string GetRiskLevelClass(string riskLevel)
        {
            if (string.IsNullOrEmpty(riskLevel))
                return "risk-low";
            
            riskLevel = riskLevel.Trim();
            
            return riskLevel switch
            {
                "严重风险" => "risk-severe",
                "严重" => "risk-severe",
                "高风险" => "risk-high",
                "高" => "risk-high",
                "中风险" => "risk-medium",
                "中" => "risk-medium",
                "低风险" => "risk-low",
                "低" => "risk-low",
                _ => "risk-low"
            };
        }
        
        /// <summary>
        /// 生成WORD格式报告
        /// </summary>
        private static string GenerateWordReport(List<PortScanResult> portScanResults, 
                                               List<VulnerabilityResult> vulnerabilityResults, 
                                               List<RiskAssessmentItem> riskAssessmentItems,
                                               string targetIp)
        {
            // 生成HTML格式的报告，保存为.docx文件
            return GenerateHtmlReport(portScanResults, vulnerabilityResults, riskAssessmentItems, targetIp);
        }
        
        /// <summary>
        /// 生成PDF格式报告
        /// </summary>
        private static string GeneratePdfReport(List<PortScanResult> portScanResults, 
                                              List<VulnerabilityResult> vulnerabilityResults, 
                                              List<RiskAssessmentItem> riskAssessmentItems,
                                              string targetIp)
        {
            // 生成HTML格式的报告，保存为.pdf文件
            return GenerateHtmlReport(portScanResults, vulnerabilityResults, riskAssessmentItems, targetIp);
        }
    }
}