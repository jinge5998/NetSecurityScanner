using System;
using System.Net;
using System.Net.Mail;
using System.Text;
using System.Threading.Tasks;

namespace NetSecurityScanner.Services
{
    public class EmailNotificationService
    {
        private readonly string _smtpServer;
        private readonly int _smtpPort;
        private readonly string _username;
        private readonly string _password;
        private readonly string _fromAddress;

        public EmailNotificationService(string smtpServer, int smtpPort,
            string username, string password, string fromAddress)
        {
            _smtpServer = smtpServer;
            _smtpPort = smtpPort;
            _username = username;
            _password = password;
            _fromAddress = fromAddress;
        }

        public async Task SendScanNotificationAsync(string toAddress, string target, int vulnerabilityCount, int criticalCount)
        {
            var message = new MailMessage
            {
                From = new MailAddress(_fromAddress, "NetSecurityScanner"),
                Subject = $"🔔 安全扫描完成 - {target} - 发现 {vulnerabilityCount} 个漏洞",
                IsBodyHtml = true
            };
            message.To.Add(toAddress);

            var sb = new StringBuilder();
            sb.AppendLine("<!DOCTYPE html><html><head><style>");
            sb.AppendLine("body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }");
            sb.AppendLine(".header { background: #3498db; color: white; padding: 20px; text-align: center; }");
            sb.AppendLine(".content { padding: 20px; }");
            sb.AppendLine(".alert { padding: 15px; margin: 10px 0; border-radius: 5px; background: #fadbd8; border-left: 5px solid #e74c3c; }");
            sb.AppendLine("</style></head><body>");
            sb.AppendLine("<div class='header'><h2>🛡️ 安全扫描报告</h2>");
            sb.AppendLine($"<p>目标: {target}</p></div>");
            sb.AppendLine("<div class='content'>");

            if (criticalCount > 0)
            {
                sb.AppendLine($"<div class='alert'><h3>⚠️ 发现 {criticalCount} 个严重漏洞!</h3>");
                sb.AppendLine("<p>请立即处理这些严重安全问题。</p></div>");
            }

            sb.AppendLine($"<p><strong>扫描时间:</strong> {DateTime.Now:yyyy-MM-dd HH:mm:ss}</p>");
            sb.AppendLine($"<p><strong>总漏洞数:</strong> {vulnerabilityCount}</p>");
            sb.AppendLine("</div></body></html>");

            message.Body = sb.ToString();

            using var client = new SmtpClient(_smtpServer, _smtpPort)
            {
                EnableSsl = true,
                Credentials = new NetworkCredential(_username, _password)
            };

            await client.SendMailAsync(message);
        }
    }
}
