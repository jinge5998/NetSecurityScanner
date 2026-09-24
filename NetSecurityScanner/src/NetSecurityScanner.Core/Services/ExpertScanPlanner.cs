using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Text.RegularExpressions;
using NetSecurityScanner.Core.Models;
using NetSecurityScanner.Utils;

namespace NetSecurityScanner.Core.Services
{
    /// <summary>
    /// 专家模式扫描规划器：把界面配置解析为实际的目标列表与端口列表。
    ///
    /// 这些逻辑原先内嵌在 ExpertModeWindow.xaml.cs（7834 行 God Class）中，
    /// 是 private 实例方法且直接调用 AppendLog 写 UI 控件，因此无法脱离 WPF 测试，
    /// 导致专家模式长期零测试覆盖。抽取为无 UI 依赖的静态纯函数后，
    /// 日志通过可选的 <paramref name="log"/> 回调输出，调用方（窗口）传入 AppendLog 即可保持原行为。
    /// </summary>
    public static class ExpertScanPlanner
    {
        /// <summary>
        /// 单次扫描的目标数量上限，超过则截断。
        /// </summary>
        public const int MaxTargets = 65536;

        /// <summary>
        /// 正则模式下为防止结果爆炸而设置的目标数量上限。
        /// </summary>
        public const int MaxRegexTargets = 1000;

        /// <summary>
        /// 解析目标类型为"正则模式"时用于匹配的候选私网网段前缀。
        /// </summary>
        private static readonly string[] RegexProbeNetworks =
        {
            "192.168.1.", "192.168.0.", "10.0.0.", "10.0.1.", "172.16.0.", "172.16.1."
        };

        /// <summary>
        /// 敏感端口模式在 CommonPorts.GetSensitivePorts() 之外额外并入的高危端口。
        /// 两份清单各自维护容易漏，例如 Docker 2375、K8s 6443、etcd 2379 等未授权高危端口。
        /// </summary>
        private static readonly int[] ExtraSensitivePorts =
        {
            21, 22, 23, 25, 53, 110, 135, 139, 143, 443, 445, 993, 995,
            1433, 1521, 3306, 3389, 5432, 5900, 6379, 8080, 8443, 9200, 27017,
            5000, 5001, 8888, 9090
        };

        /// <summary>
        /// 按配置解析出待扫描的目标主机列表。
        /// </summary>
        /// <param name="config">扫描配置。</param>
        /// <param name="log">可选日志回调；为空时静默丢弃日志。</param>
        public static List<string> ResolveTargets(ExpertScanConfiguration config, Action<string>? log = null)
        {
            if (config == null) throw new ArgumentNullException(nameof(config));

            var targets = new List<string>();

            switch (config.TargetType)
            {
                case "Single":
                    if (!string.IsNullOrWhiteSpace(config.TargetValue))
                        targets.Add(config.TargetValue.Trim());
                    break;

                case "Range":
                    ResolveIpRange(config, targets, log);
                    break;

                case "CIDR":
                    ResolveCidr(config, targets, log);
                    break;

                case "File":
                    var lines = (config.TargetValue ?? "").Split(
                        new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries);
                    targets.AddRange(lines.Select(l => l.Trim()).Where(l => !string.IsNullOrEmpty(l)));
                    break;

                case "Regex":
                    ResolveRegex(config, targets, log);
                    break;

                default:
                    if (!string.IsNullOrWhiteSpace(config.TargetValue))
                        targets.Add(config.TargetValue.Trim());
                    break;
            }

            // 排除主机
            if (!string.IsNullOrWhiteSpace(config.ExcludeHosts))
            {
                var excluded = config.ExcludeHosts
                    .Split(new[] { ',', ' ' }, StringSplitOptions.RemoveEmptyEntries)
                    .Select(s => s.Trim())
                    .ToHashSet();
                targets.RemoveAll(t => excluded.Contains(t));
            }

            // 随机化目标顺序
            if (config.Randomize)
            {
                var rnd = new Random();
                targets = targets.OrderBy(t => rnd.Next()).ToList();
            }

            return targets;
        }

        private static void ResolveIpRange(ExpertScanConfiguration config, List<string> targets, Action<string>? log)
        {
            var parts = (config.TargetValue ?? "").Split('-');
            if (parts.Length != 2) return;

            var startText = parts[0].Trim();
            var endText = parts[1].Trim();
            if (!IPAddress.TryParse(startText, out _) || !IPAddress.TryParse(endText, out _)) return;

            long start = IPToLong(startText);
            long end = IPToLong(endText);
            if (end < start)
            {
                // 起始 > 结束，交换
                (start, end) = (end, start);
            }

            long totalIps = end - start + 1;
            if (totalIps > MaxTargets)
            {
                log?.Invoke($"⚠️ IP段范围过大({totalIps}个)，将截断到 {MaxTargets} 个");
                end = start + MaxTargets - 1;
            }

            for (long ip = start; ip <= end; ip++)
            {
                targets.Add(LongToIP(ip));
            }
        }

        private static void ResolveCidr(ExpertScanConfiguration config, List<string> targets, Action<string>? log)
        {
            var value = config.TargetValue ?? "";
            if (!value.Contains('/')) return;

            var cidrParts = value.Split('/');
            if (cidrParts.Length != 2) return;
            if (!IPAddress.TryParse(cidrParts[0], out _)) return;
            if (!int.TryParse(cidrParts[1], out int prefix)) return;

            if (prefix < 0 || prefix > 32)
            {
                log?.Invoke($"⚠️ CIDR 前缀长度 {prefix} 无效，必须在 0-32 之间");
                return;
            }

            long baseLong = IPToLong(cidrParts[0]);
            int hostBits = 32 - prefix;
            long mask = hostBits == 32 ? 0xFFFFFFFFL : (1L << hostBits) - 1;
            long network = baseLong & ~mask;
            long broadcast = network | mask;
            long totalIps = broadcast - network + 1;

            // /31 和 /32 特殊处理：
            //   /31 为点对点链路（RFC 3021），无网络地址与广播地址之分，两个地址均可用；
            //   /32 为单一主机，network == broadcast，只产出 1 个地址；
            //   /30 及以下按惯例跳过网络地址与广播地址。
            // 修复：原实现 endIp = (prefix == 32) ? network : broadcast - 1，
            // 对 /31 会得到 endIp == broadcast - 1 == network，只产出 1 个地址，
            // 与紧邻的注释「/31 只有 2 个地址」自相矛盾，实际漏扫点对点链路的对端设备。
            long startIp = (prefix >= 31) ? network : network + 1;
            long endIp = (prefix >= 31) ? broadcast : broadcast - 1;

            if (totalIps > MaxTargets)
            {
                log?.Invoke($"⚠️ CIDR 网段过大({totalIps}个)，将截断到 {MaxTargets} 个");
                endIp = startIp + MaxTargets - 1;
            }

            for (long ip = startIp; ip <= endIp; ip++)
            {
                targets.Add(LongToIP(ip));
            }
        }

        private static void ResolveRegex(ExpertScanConfiguration config, List<string> targets, Action<string>? log)
        {
            try
            {
                var regex = new Regex(config.TargetValue ?? "");

                // 常见私网网段用于正则匹配测试（比硬编码单一网段覆盖更广）
                var testIps = new List<string>();
                for (int i = 0; i < 256; i++)
                {
                    foreach (var net in RegexProbeNetworks)
                        testIps.Add($"{net}{i}");
                }

                foreach (var testIp in testIps)
                {
                    if (regex.IsMatch(testIp) && !targets.Contains(testIp))
                    {
                        targets.Add(testIp);
                        if (targets.Count >= MaxRegexTargets) break; // 防止结果爆炸
                    }
                }

                // 若正则未匹配到任何地址，回退到把正则字符串本身作为单一目标
                if (targets.Count == 0)
                {
                    log?.Invoke($"⚠️ 正则 '{config.TargetValue}' 未匹配任何地址，将按字面量作为目标");
                    targets.Add(config.TargetValue ?? "");
                }
                else
                {
                    log?.Invoke($"ℹ️ 正则匹配到 {targets.Count} 个目标");
                }
            }
            catch (Exception ex)
            {
                log?.Invoke($"⚠️ 正则表达式解析失败: {ex.Message}");
                // 解析失败时把字面量作为目标
                if (!string.IsNullOrWhiteSpace(config.TargetValue))
                    targets.Add(config.TargetValue.Trim());
            }
        }

        /// <summary>
        /// 按配置解析出待扫描的端口列表。
        /// </summary>
        /// <param name="config">扫描配置。</param>
        /// <param name="log">可选日志回调；为空时静默丢弃日志。</param>
        public static List<int> ResolvePorts(ExpertScanConfiguration config, Action<string>? log = null)
        {
            if (config == null) throw new ArgumentNullException(nameof(config));

            var ports = new List<int>();

            switch (config.PortMode)
            {
                case "Common":
                    // 原实现为 Enumerable.Range(1, 1000)（端口 1~1000 连续区间），
                    // 会漏掉所有 1000 以上的常见服务端口：8080/8443/8888/3306/3389/5432/27017 等。
                    // 目标只开放高位端口时结果为空，漏洞扫描又依赖开放端口，导致漏洞也为空。
                    // 改用 CommonPorts.GetTop1000Ports()（知名端口 1~1024 + 高频服务端口）。
                    ports = CommonPorts.GetTop1000Ports();
                    break;

                case "Sensitive":
                    // 与 CommonPorts 定义的敏感端口取并集
                    ports = ExtraSensitivePorts
                        .Union(CommonPorts.GetSensitivePorts())
                        .Distinct()
                        .OrderBy(p => p)
                        .ToList();
                    break;

                case "All":
                    ports = Enumerable.Range(1, 65535).ToList();
                    break;

                case "Custom":
                    ports = ParseCustomPorts(config.CustomPorts, log);
                    break;

                default:
                    // 未知模式回退到常用端口，避免返回空列表导致整次扫描静默无结果
                    log?.Invoke($"⚠️ 未知端口模式 '{config.PortMode}'，已回退到常用端口");
                    ports = CommonPorts.GetTop1000Ports();
                    break;
            }

            // 排除端口
            if (!string.IsNullOrWhiteSpace(config.ExcludePorts))
            {
                var excluded = config.ExcludePorts
                    .Split(new[] { ',', ' ' }, StringSplitOptions.RemoveEmptyEntries)
                    .Where(s => int.TryParse(s.Trim(), out _))
                    .Select(s => int.Parse(s.Trim()))
                    .ToHashSet();
                ports.RemoveAll(p => excluded.Contains(p));
            }

            var finalPorts = ports.Distinct().ToList();
            if (config.RandomPortOrder)
            {
                var rnd = new Random();
                finalPorts = finalPorts.OrderBy(p => rnd.Next()).ToList();
            }
            else
            {
                finalPorts = finalPorts.OrderBy(p => p).ToList();
            }

            return finalPorts;
        }

        /// <summary>
        /// 解析自定义端口串，支持逗号/空白分隔与 <c>start-end</c> 范围写法。
        /// 无效片段跳过并记日志，不抛异常。
        /// </summary>
        public static List<int> ParseCustomPorts(string? customPorts, Action<string>? log = null)
        {
            var ports = new List<int>();
            if (string.IsNullOrWhiteSpace(customPorts)) return ports;

            foreach (var part in customPorts.Split(
                         new[] { ',', ' ', '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries))
            {
                var token = part.Trim();
                if (token.Length == 0) continue;

                if (token.Contains('-'))
                {
                    var rangeParts = token.Split('-');
                    if (rangeParts.Length == 2 &&
                        int.TryParse(rangeParts[0].Trim(), out int rawStart) &&
                        int.TryParse(rangeParts[1].Trim(), out int rawEnd))
                    {
                        // 防御性处理：start > end 时交换，避免 Enumerable.Range 抛 ArgumentOutOfRangeException
                        int start = Math.Max(1, Math.Min(rawStart, rawEnd));
                        int end = Math.Min(65535, Math.Max(rawStart, rawEnd));
                        int count = end - start + 1;
                        if (count > 0)
                        {
                            ports.AddRange(Enumerable.Range(start, count));
                        }
                        else
                        {
                            log?.Invoke($"⚠️ 端口范围 '{token}' 无效，已跳过");
                        }
                    }
                    else
                    {
                        log?.Invoke($"⚠️ 端口范围 '{token}' 解析失败，已跳过");
                    }
                }
                else if (int.TryParse(token, out int p))
                {
                    if (p >= 1 && p <= 65535)
                        ports.Add(p);
                    else
                        log?.Invoke($"⚠️ 端口 '{token}' 超出 1-65535 范围，已跳过");
                }
                else
                {
                    log?.Invoke($"⚠️ 无法解析的端口值 '{token}'，已跳过");
                }
            }

            return ports;
        }

        /// <summary>
        /// 点分十进制 IPv4 转 32 位整数。
        /// </summary>
        public static long IPToLong(string ip)
        {
            var bytes = IPAddress.Parse(ip).GetAddressBytes();
            return (long)bytes[0] << 24 | (long)bytes[1] << 16 | (long)bytes[2] << 8 | bytes[3];
        }

        /// <summary>
        /// 32 位整数转点分十进制 IPv4。
        /// </summary>
        public static string LongToIP(long ipLong)
        {
            return $"{(ipLong >> 24) & 0xFF}.{(ipLong >> 16) & 0xFF}.{(ipLong >> 8) & 0xFF}.{ipLong & 0xFF}";
        }
    }
}
