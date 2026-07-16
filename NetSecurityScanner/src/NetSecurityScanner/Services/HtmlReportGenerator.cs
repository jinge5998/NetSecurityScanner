using NetSecurityScanner.Models;
using System;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace NetSecurityScanner.Services
{
    public class HtmlReportGenerator
    {
        public async Task<string> GenerateAsync(string target, System.Collections.Generic.List<VulnerabilityResult> vulnerabilities, string outputPath)
        {
            var html = new StringBuilder();

            html.AppendLine("<!DOCTYPE html>");
            html.AppendLine("<html lang=\"zh-CN\">");
            html.AppendLine("<head>");
            html.AppendLine("    <meta charset=\"UTF-8\">");
            html.AppendLine($"    <title>网络安全扫描报告 - {target}</title>");
            html.AppendLine("    <style>");
            html.AppendLine(@"
                body { font-family: Arial, sans-serif; margin: 40px; background: #f5f5f5; }
                .header { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 40px 20px; text-align: center; }
                .container { max-width: 1200px; margin: 0 auto; padding: 20px; }
                .summary { background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); margin-bottom: 20px; }
                .stats { display: flex; justify-content: space-around; margin: 20px 0; flex-wrap: wrap; }
                .stat-box { text-align: center; padding: 30px; border-radius: 8px; min-width: 120px; margin: 5px; color: white; }
                .critical { background: #e74c3c; } .high { background: #e67e22; }
                .medium { background: #f1c40f; color: #333; } .low { background: #27ae60; }
                table { width: 100%; background: white; border-radius: 8px; overflow: hidden; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
                th { background: #3498db; color: white; padding: 15px; text-align: left; }
                td { padding: 12px 15px; border-bottom: 1px solid #eee; }
                tr:hover { background: #f8f9fa; }
                .severity { padding: 4px 12px; border-radius: 4px; font-size: 12px; font-weight: bold; }
                .cve-link { color: #3498db; text-decoration: none; }
                .footer { text-align: center; padding: 20px; color: #7f8c8d; margin-top: 40px; }
            ");
            html.AppendLine("    </style>");
            html.AppendLine("</head>");
            html.AppendLine("<body>");

            html.AppendLine("    <div class=\"header\">");
            html.AppendLine("        <h1>🛡️ 网络安全扫描报告</h1>");
            html.AppendLine($"        <p>扫描目标: {target}</p>");
            html.AppendLine("    </div>");

            html.AppendLine("    <div class=\"container\">");
            html.AppendLine("        <div class=\"summary\">");
            html.AppendLine("            <h2>📋 扫描概要</h2>");
            html.AppendLine($"            <p><strong>扫描时间:</strong> {DateTime.Now:yyyy-MM-dd HH:mm:ss}</p>");
            html.AppendLine($"            <p><strong>发现漏洞:</strong> {vulnerabilities?.Count ?? 0}个</p>");
            html.AppendLine("        </div>");

            var criticalCount = vulnerabilities?.Count(v => v.RiskLevel == "严重") ?? 0;
            var highCount = vulnerabilities?.Count(v => v.RiskLevel == "高危") ?? 0;
            var mediumCount = vulnerabilities?.Count(v => v.RiskLevel == "中危") ?? 0;
            var lowCount = vulnerabilities?.Count(v => v.RiskLevel == "低危") ?? 0;

            html.AppendLine("        <h2>📊 漏洞统计</h2>");
            html.AppendLine("        <div class=\"stats\">");
            html.AppendLine($"            <div class=\"stat-box critical\"><h3>{criticalCount}</h3><p>严重</p></div>");
            html.AppendLine($"            <div class=\"stat-box high\"><h3>{highCount}</h3><p>高危</p></div>");
            html.AppendLine($"            <div class=\"stat-box medium\"><h3>{mediumCount}</h3><p>中危</p></div>");
            html.AppendLine($"            <div class=\"stat-box low\"><h3>{lowCount}</h3><p>低危</p></div>");
            html.AppendLine("        </div>");

            html.AppendLine("        <h2>🔍 漏洞详情</h2>");
            html.AppendLine("        <table>");
            html.AppendLine("            <thead><tr><th>CVE编号</th><th>漏洞名称</th><th>风险等级</th><th>端口</th><th>解决方案</th></tr></thead>");
            html.AppendLine("            <tbody>");

            foreach (var vuln in vulnerabilities ?? new System.Collections.Generic.List<VulnerabilityResult>())
            {
                var severityClass = vuln.RiskLevel switch
                {
                    "严重" => "critical", "高危" => "high",
                    "中危" => "medium", "低危" => "low", _ => "info"
                };

                html.AppendLine("                <tr>");
                html.AppendLine($"                    <td><a href=\"https://nvd.nist.gov/vuln/detail/{vuln.CveId}\" class=\"cve-link\" target=\"_blank\">{vuln.CveId}</a></td>");
                html.AppendLine($"                    <td>{vuln.Name}</td>");
                html.AppendLine($"                    <td><span class=\"severity {severityClass}\">{vuln.RiskLevel}</span></td>");
                html.AppendLine($"                    <td>{vuln.Port}</td>");
                html.AppendLine($"                    <td>{vuln.Solution}</td>");
                html.AppendLine("                </tr>");
            }

            html.AppendLine("            </tbody>");
            html.AppendLine("        </table>");
            html.AppendLine("    </div>");
            html.AppendLine($"    <div class=\"footer\"><p>由 NetSecurityScanner 生成 | {DateTime.Now:yyyy-MM-dd HH:mm:ss}</p></div>");
            html.AppendLine("</body>");
            html.AppendLine("</html>");

            var filePath = Path.Combine(outputPath, $"扫描报告_{target}_{DateTime.Now:yyyyMMdd_HHmmss}.html");
            await File.WriteAllTextAsync(filePath, html.ToString(), Encoding.UTF8);

            return filePath;
        }
    }
}
