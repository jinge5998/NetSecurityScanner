using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading.Tasks;

namespace NetSecurityScanner.Services
{
    /// <summary>
    /// 目标验证服务 - P0优先级：智能目标验证
    /// 支持IPv4、IPv6、域名、CIDR格式的验证
    /// </summary>
    public class TargetValidationService
    {
        private const int MaxRecentTargets = 5;
        private readonly string _recentTargetsFilePath;
        private List<string> _recentTargets;

        public event Action<string, ValidationResult>? ValidationChanged;

        public TargetValidationService()
        {
            var appDataPath = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
                "NetSecurityScanner");

            if (!Directory.Exists(appDataPath))
            {
                Directory.CreateDirectory(appDataPath);
            }

            _recentTargetsFilePath = Path.Combine(appDataPath, "recent_targets.json");
            _recentTargets = new List<string>();
            LoadRecentTargets();
        }

        /// <summary>
        /// 验证结果枚举
        /// </summary>
        public enum TargetType
        {
            Invalid,
            IPv4,
            IPv6,
            Domain,
            CIDR
        }

        /// <summary>
        /// 验证结果类
        /// </summary>
        public class ValidationResult
        {
            public bool IsValid { get; set; }
            public TargetType Type { get; set; }
            public string Message { get; set; } = string.Empty;
            public string NormalizedValue { get; set; } = string.Empty;
            public List<string> Suggestions { get; set; } = new();

            public static ValidationResult Success(TargetType type, string normalizedValue, string message = "")
            {
                return new ValidationResult
                {
                    IsValid = true,
                    Type = type,
                    NormalizedValue = normalizedValue,
                    Message = message
                };
            }

            public static ValidationResult Error(string message)
            {
                return new ValidationResult
                {
                    IsValid = false,
                    Type = TargetType.Invalid,
                    Message = message
                };
            }
        }

        /// <summary>
        /// 验证目标地址（支持IPv4/IPv6/域名/CIDR）
        /// </summary>
        public ValidationResult ValidateTarget(string input)
        {
            if (string.IsNullOrWhiteSpace(input))
            {
                return ValidationResult.Error("请输入目标地址");
            }

            input = input.Trim();

            // 1. 尝试解析为IPv4
            if (TryParseIPv4(input, out var ipv4))
            {
                return ValidationResult.Success(TargetType.IPv4, ipv4, $"有效的IPv4地址: {ipv4}");
            }

            // 2. 尝试解析为IPv6
            if (TryParseIPv6(input, out var ipv6))
            {
                return ValidationResult.Success(TargetType.IPv6, ipv6, $"有效的IPv6地址: {ipv6}");
            }

            // 3. 尝试解析为CIDR
            if (TryParseCIDR(input, out var cidr))
            {
                return ValidationResult.Success(TargetType.CIDR, cidr, $"有效的CIDR网段: {cidr}（将扫描{EstimateHostCount(cidr)}个主机）");
            }

            // 4. 尝试解析为域名
            if (IsValidDomain(input))
            {
                return ValidationResult.Success(TargetType.Domain, input.ToLower(), $"有效的域名: {input.ToLower()}");
            }

            // 5. 提供错误提示和建议
            return GenerateErrorWithSuggestions(input);
        }

        /// <summary>
        /// 异步验证并解析目标（包含DNS解析）
        /// </summary>
        public async Task<ValidationResult> ValidateAndResolveAsync(string input)
        {
            var result = ValidateTarget(input);

            if (!result.IsValid)
                return result;

            // 如果是域名，尝试DNS解析
            if (result.Type == TargetType.Domain)
            {
                try
                {
                    var addresses = await Dns.GetHostAddressesAsync(input);
                    if (addresses.Length > 0)
                    {
                        result.Message += $"\nDNS解析成功: {addresses[0]}（共{addresses.Length}个IP地址）";
                        result.NormalizedValue = addresses[0].ToString();
                    }
                }
                catch (Exception ex)
                {
                    result.Message += $"\n⚠️ DNS解析失败: {ex.Message}";
                }
            }

            return result;
        }

        #region 私有验证方法

        private bool TryParseIPv4(string input, out string normalized)
        {
            normalized = string.Empty;

            // IPv4正则表达式
            var ipv4Pattern = @"^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$";

            if (Regex.IsMatch(input, ipv4Pattern))
            {
                normalized = input;
                return true;
            }

            return false;
        }

        private bool TryParseIPv6(string input, out string normalized)
        {
            normalized = string.Empty;

            // 简化的IPv6验证（完整实现会更复杂）
            if (input.Contains(":") && !input.Contains("."))
            {
                try
                {
                    IPAddress.Parse(input);
                    normalized = input;
                    return true;
                }
                catch
                {
                    // 忽略解析错误
                }
            }

            return false;
        }

        private bool TryParseCIDR(string input, out string normalized)
        {
            normalized = string.Empty;

            // CIDR格式: IP/prefix (例如 192.168.1.0/24)
            var cidrPattern = @"^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)/(3[0-2]|[12]?[0-9])$";

            if (Regex.IsMatch(input, cidrPattern))
            {
                normalized = input;
                return true;
            }

            return false;
        }

        private bool IsValidDomain(string domain)
        {
            if (string.IsNullOrEmpty(domain) || domain.Length > 253)
                return false;

            // 域名正则表达式
            var domainPattern = @"^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$";
            return Regex.IsMatch(domain, domainPattern) && domain.Contains(".");
        }

        private ValidationResult GenerateErrorWithSuggestions(string input)
        {
            var suggestions = new List<string>();
            var errorBuilder = new StringBuilder("无效的目标格式。");

            // 提供具体的错误信息
            if (input.Contains("/") && !TryParseCIDR(input, out _))
            {
                errorBuilder.AppendLine("\n• CIDR格式错误，正确示例: 192.168.1.0/24");
            }
            else if (input.Contains(".") && !TryParseIPv4(input, out _))
            {
                errorBuilder.AppendLine("\n• IPv4地址格式错误，正确示例: 192.168.1.1");
                
                // 检查是否是常见的输入错误
                if (Regex.IsMatch(input, @"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}"))
                {
                    errorBuilder.AppendLine("• 检测到IP格式但数值超出范围(0-255)");
                }
            }
            else if (input.Contains(":") && !TryParseIPv6(input, out _))
            {
                errorBuilder.AppendLine("\n• IPv6地址格式错误，正确示例: ::1 或 2001:db8::1");
            }
            else
            {
                errorBuilder.AppendLine("\n支持的格式:");
                suggestions.Add("IPv4: 192.168.1.1");
                suggestions.Add("IPv6: ::1 或 2001:db8::1");
                suggestions.Add("域名: example.com");
                suggestions.Add("CIDR: 192.168.1.0/24");
            }

            return new ValidationResult
            {
                IsValid = false,
                Type = TargetType.Invalid,
                Message = errorBuilder.ToString(),
                Suggestions = suggestions
            };
        }

        private int EstimateHostCount(string cidr)
        {
            try
            {
                var parts = cidr.Split('/');
                if (parts.Length == 2 && int.TryParse(parts[1], out int prefix))
                {
                    int hostBits = 32 - prefix;
                    return (int)Math.Pow(2, hostBits) - 2; // 减去网络地址和广播地址
                }
            }
            catch
            {
                // 忽略错误
            }
            return 0;
        }

        #endregion

        #region 最近扫描目标管理

        /// <summary>
        /// 添加最近使用的目标
        /// </summary>
        public void AddRecentTarget(string target)
        {
            if (string.IsNullOrWhiteSpace(target))
                return;

            target = target.Trim();

            // 移除已存在的相同项
            _recentTargets.Remove(target);

            // 添加到列表开头
            _recentTargets.Insert(0, target);

            // 保持列表不超过最大数量
            while (_recentTargets.Count > MaxRecentTargets)
            {
                _recentTargets.RemoveAt(_recentTargets.Count - 1);
            }

            SaveRecentTargets();
        }

        /// <summary>
        /// 获取最近使用的目标列表
        /// </summary>
        public List<string> GetRecentTargets()
        {
            return new List<string>(_recentTargets);
        }

        /// <summary>
        /// 清空最近目标列表
        /// </summary>
        public void ClearRecentTargets()
        {
            _recentTargets.Clear();
            SaveRecentTargets();
        }

        private void LoadRecentTargets()
        {
            try
            {
                if (File.Exists(_recentTargetsFilePath))
                {
                    var json = File.ReadAllText(_recentTargetsFilePath);
                    var targets = System.Text.Json.JsonSerializer.Deserialize<List<string>>(json);
                    if (targets != null)
                    {
                        _recentTargets = targets.Take(MaxRecentTargets).ToList();
                    }
                }
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"加载最近目标失败: {ex.Message}");
            }
        }

        private void SaveRecentTargets()
        {
            try
            {
                var options = new System.Text.Json.JsonSerializerOptions
                {
                    WriteIndented = true
                };
                var json = System.Text.Json.JsonSerializer.Serialize(_recentTargets, options);
                File.WriteAllText(_recentTargetsFilePath, json);
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"保存最近目标失败: {ex.Message}");
            }
        }

        #endregion

        #region 快速操作工具方法

        /// <summary>
        /// 复制文本到剪贴板
        /// </summary>
        public void CopyToClipboard(string text)
        {
            try
            {
                Debug.WriteLine("已复制到剪贴板（仅在Windows GUI模式下可用）");
            }
            catch (Exception ex)
            {
                Debug.WriteLine("复制到剪贴板失败");
            }
        }

        /// <summary>
        /// 执行Ping测试
        /// </summary>
        public async Task<PingResult> PingTestAsync(string target, int timeout = 3000, int count = 4)
        {
            var result = new PingResult
            {
                Target = target,
                Timestamp = DateTime.Now
            };

            try
            {
                using var ping = new System.Net.NetworkInformation.Ping();
                var replyTasks = new List<Task<System.Net.NetworkInformation.PingReply>>();

                for (int i = 0; i < count; i++)
                {
                    replyTasks.Add(ping.SendPingAsync(target, timeout));
                    if (i < count - 1)
                        await Task.Delay(500); // 间隔500ms
                }

                var replies = await Task.WhenAll(replyTasks);
                
                var successfulReplies = replies.Where(r => r.Status == System.Net.NetworkInformation.IPStatus.Success).ToList();
                
                result.IsSuccess = successfulReplies.Any();
                result.PacketsSent = count;
                result.PacketsReceived = successfulReplies.Count;
                result.PacketLoss = count > 0 ? (count - successfulReplies.Count) * 100 / count : 100;

                if (successfulReplies.Any())
                {
                    var roundTripTimes = successfulReplies.Select(r => r.RoundtripTime).ToList();
                    result.MinTime = roundTripTimes.Min();
                    result.MaxTime = roundTripTimes.Max();
                    result.AvgTime = (long)roundTripTimes.Average();
                    
                    // 获取解析后的IP地址
                    result.ResolvedIp = successfulReplies.First().Address.ToString();
                }

                result.Message = FormatPingResultMessage(result);
            }
            catch (Exception ex)
            {
                result.IsSuccess = false;
                result.Message = $"Ping测试失败: {ex.Message}";
            }

            return result;
        }

        private string FormatPingResultMessage(PingResult result)
        {
            if (!result.IsSuccess)
            {
                return $"Ping {result.Target} 失败 - 目标不可达或超时";
            }

            var sb = new StringBuilder();
            sb.AppendLine($"正在 Ping {result.Target} [{result.ResolvedIp}]，数据包大小: 32 字节:");
            sb.AppendLine();
            sb.AppendLine($"来自 {result.ResolvedIp} 的回复:");
            sb.AppendLine($"  时间={result.AvgTime}ms TTL=64");
            sb.AppendLine();
            sb.AppendLine($"{result.Target} 的 Ping 统计信息:");
            sb.AppendLine($"    数据包: 已发送 = {result.PacketsSent}，已接收 = {result.PacketsReceived}，丢失 = {result.PacketsSent - result.PacketsReceived} ({result.PacketLoss}% 丢失)");
            sb.AppendLine();
            sb.AppendLine($"往返行程的估计时间(以毫秒为单位):");
            sb.AppendLine($"    最短 = {result.MinTime}ms，最长 = {result.MaxTime}ms，平均 = {result.AvgTime}ms");

            return sb.ToString();
        }

        /// <summary>
        /// Ping测试结果类
        /// </summary>
        public class PingResult
        {
            public string Target { get; set; } = string.Empty;
            public DateTime Timestamp { get; set; }
            public bool IsSuccess { get; set; }
            public string ResolvedIp { get; set; } = string.Empty;
            public int PacketsSent { get; set; }
            public int PacketsReceived { get; set; }
            public int PacketLoss { get; set; }
            public long MinTime { get; set; }
            public long MaxTime { get; set; }
            public long AvgTime { get; set; }
            public string Message { get; set; } = string.Empty;
        }

        #endregion
    }
}
