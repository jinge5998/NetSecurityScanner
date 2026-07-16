using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using NetSecurityScanner.Models;

namespace NetSecurityScanner.Services
{
    /// <summary>
    /// 攻击日志解析服务
    /// 负责解析各类日志文件（IIS、Nginx/Apache、防火墙等）并识别攻击类型
    /// </summary>
    public class AttackLogService
    {
        // 攻击模式匹配规则
        private static readonly Dictionary<string, Regex[]> AttackPatterns = new()
        {
            ["SQL注入"] = new[]
            {
                new Regex(@"('|%27)(\s)*(or|and|union|select|insert|update|delete|drop|alter|create)(\s)+", RegexOptions.IgnoreCase | RegexOptions.Compiled),
                new Regex(@"(--|#|/\*)", RegexOptions.IgnoreCase | RegexOptions.Compiled),
                new Regex(@"(\b)(exec|execute|xp_|sp_)(\b)", RegexOptions.IgnoreCase | RegexOptions.Compiled),
                new Regex(@"(union\s+select|select\s+.*\s+from)", RegexOptions.IgnoreCase | RegexOptions.Compiled)
            },
            ["XSS跨站脚本"] = new[]
            {
                new Regex(@"(<script|javascript:|onerror=|onload=|onclick=)", RegexOptions.IgnoreCase | RegexOptions.Compiled),
                new Regex(@"(alert|prompt|confirm)\s*\(", RegexOptions.IgnoreCase | RegexOptions.Compiled),
                new Regex(@"(<img|<iframe|<svg|<embed|<object)[^>]*on\w+=", RegexOptions.IgnoreCase | RegexOptions.Compiled)
            },
            ["暴力破解"] = new[]
            {
                new Regex(@"(failed|invalid|incorrect)\s*(password|login|auth)", RegexOptions.IgnoreCase | RegexOptions.Compiled),
                new Regex(@"(401|403)\s.*(/login|/admin|/wp-login)", RegexOptions.IgnoreCase | RegexOptions.Compiled),
                new Regex(@"(\b)(brute\s*force|dictionary\s*attack)(\b)", RegexOptions.IgnoreCase | RegexOptions.Compiled)
            },
            ["目录遍历"] = new[]
            {
                new Regex(@"(\.\./|\.\.\\|%2e%2e%2f|%2e%2e/)", RegexOptions.IgnoreCase | RegexOptions.Compiled),
                new Regex(@"/(etc/passwd|etc/shadow|windows/system32)", RegexOptions.IgnoreCase | RegexOptions.Compiled),
                new Regex(@"(file://|readfile\()", RegexOptions.IgnoreCase | RegexOptions.Compiled)
            },
            ["命令注入"] = new[]
            {
                new Regex(@"(;|\||&&|\$\(|`)(\s)*(ping|whoami|id|cat|ls|dir|net\s*user)", RegexOptions.IgnoreCase | RegexOptions.Compiled),
                new Regex(@"(\b)(system|exec|passthru|shell_exec|popen)(\s*\()", RegexOptions.IgnoreCase | RegexOptions.Compiled)
            },
            ["文件包含"] = new[]
            {
                new Regex(@"(include|require|include_once|require_once)\s*\(.*\$", RegexOptions.IgnoreCase | RegexOptions.Compiled),
                new Regex(@"(php://input|php://filter|data://|expect://)", RegexOptions.IgnoreCase | RegexOptions.Compiled)
            },
            ["DDoS攻击"] = new[]
            {
                new Regex(@"(syn\s*flood|udp\s*flood|http\s*flood)", RegexOptions.IgnoreCase | RegexOptions.Compiled),
                new Regex(@"(connection\s*limit|rate\s*limit|threshold\s*exceeded)", RegexOptions.IgnoreCase | RegexOptions.Compiled),
                new Regex(@"(too\s*many\s*connections|max\s*clients\s*reached)", RegexOptions.IgnoreCase | RegexOptions.Compiled)
            },
            ["端口扫描"] = new[]
            {
                new Regex(@"(nmap|masscan|zmap|zenmap)", RegexOptions.IgnoreCase | RegexOptions.Compiled),
                new Regex(@"(port\s*scan|syn\s*scan|connect\s*scan)", RegexOptions.IgnoreCase | RegexOptions.Compiled),
                new Regex(@"(connection\s*refused|closed\s*port)", RegexOptions.IgnoreCase | RegexOptions.Compiled)
            },
            ["CSRF攻击"] = new[]
            {
                new Regex(@"(csrf|xsrf|cross.*site.*request)", RegexOptions.IgnoreCase | RegexOptions.Compiled),
                new Regex(@"(origin|mismatch|invalid\s*token)", RegexOptions.IgnoreCase | RegexOptions.Compiled)
            },
            ["未授权访问"] = new[]
            {
                new Regex(@"(unauthorized|access\s*denied|forbidden)", RegexOptions.IgnoreCase | RegexOptions.Compiled),
                new Regex(@"(no\s*permission|not\s*authenticated|session\s*expired)", RegexOptions.IgnoreCase | RegexOptions.Compiled)
            },
            ["恶意软件上传"] = new[]
            {
                new Regex(@"(malware|trojan|virus|backdoor|webshell)", RegexOptions.IgnoreCase | RegexOptions.Compiled),
                new Regex(@"(\.(exe|bat|cmd|sh|php|jsp|asp)[^a-z])", RegexOptions.IgnoreCase | RegexOptions.Compiled)
            },
            ["DNS攻击"] = new[]
            {
                new Regex(@"(dns\s*(amplification|tunneling|cache\s*poisoning))", RegexOptions.IgnoreCase | RegexOptions.Compiled),
                new Regex(@"(zone\s*transfer|dns\s*rebinding|dns\s*hijacking)", RegexOptions.IgnoreCase | RegexOptions.Compiled)
            }
        };

        /// <summary>
        /// 解析IIS日志文件
        /// </summary>
        /// <param name="logFilePath">IIS日志文件路径</param>
        /// <returns>解析后的攻击日志条目列表</returns>
        public async Task<List<AttackLogEntry>> ParseIISLog(string logFilePath)
        {
            var entries = new List<AttackLogEntry>();

            if (!File.Exists(logFilePath))
                return entries;

            using var reader = new StreamReader(logFilePath);
            string? line;

            while ((line = await reader.ReadLineAsync()) != null)
            {
                // 跳过注释行
                if (line.StartsWith("#"))
                    continue;

                var entry = ParseIISLogLine(line);
                if (entry != null)
                {
                    entry.AttackType = IdentifyAttackType(line);
                    entry.RiskLevel = AssessRiskLevel(entry.AttackType);
                    entries.Add(entry);
                }
            }

            return entries;
        }

        /// <summary>
        /// 解析单行IIS日志
        /// </summary>
        /// <param name="line">IIS日志行</param>
        /// <returns>解析后的攻击日志条目，解析失败返回null</returns>
        private AttackLogEntry? ParseIISLogLine(string line)
        {
            try
            {
                var parts = line.Split(new[] { ' ' }, StringSplitOptions.RemoveEmptyEntries);
                if (parts.Length < 10)
                    return null;

                return new AttackLogEntry
                {
                    Timestamp = DateTime.TryParse($"{parts[0]} {parts[1]}", out var dt) ? dt : DateTime.MinValue,
                    SourceIP = parts[2],
                    TargetIP = parts[3],
                    RequestMethod = parts[4],
                    RequestURL = parts[5],
                    StatusCode = int.TryParse(parts[6], out var code) ? code : 0,
                    RawLogLine = line
                };
            }
            catch
            {
                return null;
            }
        }

        /// <summary>
        /// 解析Nginx/Apache日志文件
        /// </summary>
        /// <param name="logFilePath">Nginx/Apache日志文件路径</param>
        /// <returns>解析后的攻击日志条目列表</returns>
        public async Task<List<AttackLogEntry>> ParseWebServerLog(string logFilePath)
        {
            var entries = new List<AttackLogEntry>();

            if (!File.Exists(logFilePath))
                return entries;

            // 常见Apache/Nginx日志格式: IP - - [时间] "方法 URL 协议" 状态码 大小 "Referer" "User-Agent"
            var logPattern = new Regex(
                @"^(?<ip>\S+)\s+\S+\s+\S+\s+\[(?<time>[^\]]+)\]\s+""(?<method>\S+)\s+(?<url>\S+)\s+\S+""\s+(?<status>\d+)\s+(?<size>\S+)\s+""(?<referer>[^""]*)""\s+""(?<agent>[^""]*)""",
                RegexOptions.Compiled);

            using var reader = new StreamReader(logFilePath);
            string? line;

            while ((line = await reader.ReadLineAsync()) != null)
            {
                var match = logPattern.Match(line);
                if (!match.Success)
                    continue;

                var attackType = IdentifyAttackType(line);
                var entry = new AttackLogEntry
                {
                    Timestamp = DateTime.TryParse(match.Groups["time"].Value, out var dt) ? dt : DateTime.MinValue,
                    SourceIP = match.Groups["ip"].Value,
                    RequestMethod = match.Groups["method"].Value,
                    RequestURL = match.Groups["url"].Value,
                    StatusCode = int.TryParse(match.Groups["status"].Value, out var code) ? code : 0,
                    UserAgent = match.Groups["agent"].Value,
                    RawLogLine = line,
                    AttackType = attackType,
                    RiskLevel = AssessRiskLevel(attackType)
                };

                entries.Add(entry);
            }

            return entries;
        }

        /// <summary>
        /// 解析防火墙日志
        /// </summary>
        /// <param name="logFilePath">防火墙日志文件路径</param>
        /// <returns>解析后的攻击日志条目列表</returns>
        public async Task<List<AttackLogEntry>> ParseFirewallLog(string logFilePath)
        {
            var entries = new List<AttackLogEntry>();

            if (!File.Exists(logFilePath))
                return entries;

            // 防火墙日志格式: [时间] 协议 SRC=来源IP DST=目标IP ... DPT=端口 ...
            var fwPattern = new Regex(
                @"\[(?<time>[^\]]+)\]\s+(?<proto>\S+)\s+SRC=(?<src>\S+)\s+DST=(?<dst>\S+).*?DPT=(?<port>\d+)",
                RegexOptions.Compiled);

            using var reader = new StreamReader(logFilePath);
            string? line;

            while ((line = await reader.ReadLineAsync()) != null)
            {
                var match = fwPattern.Match(line);
                if (!match.Success)
                    continue;

                var attackType = IdentifyFirewallAttackType(line);
                var entry = new AttackLogEntry
                {
                    Timestamp = DateTime.TryParse(match.Groups["time"].Value, out var dt) ? dt : DateTime.MinValue,
                    SourceIP = match.Groups["src"].Value,
                    TargetIP = match.Groups["dst"].Value,
                    Protocol = match.Groups["proto"].Value,
                    Port = int.TryParse(match.Groups["port"].Value, out var port) ? port : 0,
                    RawLogLine = line,
                    AttackType = attackType,
                    RiskLevel = AssessRiskLevel(attackType)
                };

                entries.Add(entry);
            }

            return entries;
        }

        /// <summary>
        /// 识别攻击类型
        /// </summary>
        /// <param name="logLine">日志行内容</param>
        /// <returns>识别出的攻击类型</returns>
        public string IdentifyAttackType(string logLine)
        {
            foreach (var pattern in AttackPatterns)
            {
                foreach (var regex in pattern.Value)
                {
                    if (regex.IsMatch(logLine))
                        return pattern.Key;
                }
            }
            return "未知";
        }

        /// <summary>
        /// 识别防火墙日志中的攻击类型
        /// </summary>
        /// <param name="logLine">防火墙日志行内容</param>
        /// <returns>识别出的攻击类型</returns>
        private string IdentifyFirewallAttackType(string logLine)
        {
            if (Regex.IsMatch(logLine, @"(SYN|FLOOD|DOS|DDoS)", RegexOptions.IgnoreCase))
                return "DDoS攻击";
            if (Regex.IsMatch(logLine, @"(SCAN|PORT)", RegexOptions.IgnoreCase))
                return "端口扫描";
            if (Regex.IsMatch(logLine, @"(DROP|REJECT|DENY|BLOCK)", RegexOptions.IgnoreCase))
                return "未授权访问";
            return "未知";
        }

        /// <summary>
        /// 评估风险等级
        /// </summary>
        /// <param name="attackType">攻击类型</param>
        /// <returns>风险等级（高/中/低）</returns>
        public string AssessRiskLevel(string attackType)
        {
            return attackType switch
            {
                "SQL注入" => "高",
                "XSS跨站脚本" => "高",
                "命令注入" => "高",
                "文件包含" => "高",
                "DDoS攻击" => "高",
                "暴力破解" => "中",
                "目录遍历" => "中",
                "未授权访问" => "中",
                "恶意软件上传" => "高",
                "CSRF攻击" => "中",
                "DNS攻击" => "高",
                "端口扫描" => "低",
                _ => "低"
            };
        }

        /// <summary>
        /// 统计攻击日志
        /// </summary>
        /// <param name="entries">攻击日志条目列表</param>
        /// <returns>攻击统计信息</returns>
        public AttackLogStatistics CalculateStatistics(List<AttackLogEntry> entries)
        {
            var stats = new AttackLogStatistics
            {
                TotalAttacks = entries.Count,
                EarliestAttack = entries.Any() ? entries.Min(e => e.Timestamp) : null,
                LatestAttack = entries.Any() ? entries.Max(e => e.Timestamp) : null
            };

            // 按攻击类型统计
            stats.AttacksByType = entries
                .GroupBy(e => e.AttackType)
                .OrderByDescending(g => g.Count())
                .ToDictionary(g => g.Key, g => g.Count());

            // 按风险等级统计
            stats.AttacksByRiskLevel = entries
                .GroupBy(e => e.RiskLevel)
                .ToDictionary(g => g.Key, g => g.Count());

            // Top 10攻击来源IP
            stats.TopSourceIPs = entries
                .GroupBy(e => e.SourceIP)
                .OrderByDescending(g => g.Count())
                .Take(10)
                .ToDictionary(g => g.Key, g => g.Count());

            // Top 10被攻击目标IP
            stats.TopTargetIPs = entries
                .GroupBy(e => e.TargetIP)
                .OrderByDescending(g => g.Count())
                .Take(10)
                .ToDictionary(g => g.Key, g => g.Count());

            // 按时间分布统计（按天）
            stats.AttacksByTime = entries
                .GroupBy(e => e.Timestamp.ToString("yyyy-MM-dd"))
                .OrderBy(g => g.Key)
                .ToDictionary(g => g.Key, g => g.Count());

            return stats;
        }

        /// <summary>
        /// 根据筛选条件过滤日志
        /// </summary>
        /// <param name="entries">攻击日志条目列表</param>
        /// <param name="filter">筛选条件</param>
        /// <returns>过滤后的攻击日志条目列表</returns>
        public List<AttackLogEntry> FilterEntries(List<AttackLogEntry> entries, AttackLogFilter filter)
        {
            var filtered = entries.AsEnumerable();

            if (filter.StartDate.HasValue)
                filtered = filtered.Where(e => e.Timestamp >= filter.StartDate.Value);

            if (filter.EndDate.HasValue)
                filtered = filtered.Where(e => e.Timestamp <= filter.EndDate.Value);

            if (filter.AttackType != "全部")
                filtered = filtered.Where(e => e.AttackType == filter.AttackType);

            if (filter.RiskLevel != "全部")
                filtered = filtered.Where(e => e.RiskLevel == filter.RiskLevel);

            if (!string.IsNullOrEmpty(filter.SourceIPKeyword))
                filtered = filtered.Where(e => e.SourceIP.Contains(filter.SourceIPKeyword));

            if (!string.IsNullOrEmpty(filter.TargetIPKeyword))
                filtered = filtered.Where(e => e.TargetIP.Contains(filter.TargetIPKeyword));

            return filtered.ToList();
        }
    }
}
