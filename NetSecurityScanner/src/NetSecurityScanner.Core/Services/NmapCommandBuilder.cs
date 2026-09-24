using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using NetSecurityScanner.Core.Models;

namespace NetSecurityScanner.Core.Services
{
    /// <summary>
    /// Nmap 命令生成器：把专家模式的界面配置翻译为等效的 nmap 命令行。
    ///
    /// ⚠️ 重要语义说明：本程序自身**从不执行 nmap**。本类产出的字符串仅用于两处：
    ///   1) 界面底部的「Nmap 命令预览框」，供用户复制到终端手动执行；
    ///   2)「导出 Nmap 命令」功能，保存为 .bat / .sh / .txt。
    ///
    /// 实际扫描由 <c>ExecuteRustScanAsync</c>（Rust 引擎）或 <c>ExecuteNativeScanAsync</c>
    /// （C# 内置扫描器）执行，二者仅消费并发/超时/重试/协议/服务检测/主机发现等少量参数。
    /// 因此下列选项**只影响本命令字符串，不改变程序自身的扫描行为**：
    ///   SynScan、OsDetection、ServiceIntensity、Mtu、FragmentPackets、BadChecksum、
    ///   DecoyScan、DecoyIps、IdleScan、ZombieHost、SourceRouting、SourcePort、
    ///   SourcePortMin/Max、Verbosity、OutputJson/Html/Csv、ShowOpenOnly、NseScriptArgs。
    /// 其中 BadChecksum / FragmentPackets / DecoyScan / IdleScan / SourceRouting 依赖
    /// 原始套接字构造能力，在纯 TCP 连接扫描模型下原理上无法实现，只能由 nmap 执行。
    ///
    /// 原先该逻辑内嵌在 ExpertModeWindow.xaml.cs（7834 行 God Class）中，无法脱离 WPF 测试。
    /// 抽取为纯函数后，随机量（TTL）与时间戳通过参数注入，使命令输出可确定性断言。
    /// </summary>
    public static class NmapCommandBuilder
    {
        /// <summary>
        /// 生成等效 nmap 命令。
        /// </summary>
        /// <param name="config">扫描配置。</param>
        /// <param name="ttl">TTL 伪装值；为空时在 48-127 间随机取值（与原实现一致）。</param>
        /// <param name="timestamp">输出文件名的时间戳；为空时取当前时间。</param>
        public static string Build(ExpertScanConfiguration config, int? ttl = null, string? timestamp = null)
        {
            if (config == null) throw new ArgumentNullException(nameof(config));

            var parts = new List<string> { "nmap" };

            bool scanTcp = config.TcpScan;
            bool scanUdp = config.UdpScan;
            bool scanSyn = config.SynScan;

            // 「仅主机发现」判定：开启了 Ping 探测，且未选择任何端口扫描协议。
            // 修复：原实现先执行 if (!scanTcp && !scanUdp) scanTcp = true，
            // 再判断 (!scanTcp && !scanUdp)，该条件恒为假，导致 -sn 分支不可达；
            // 且原条件额外要求 !HostDiscovery，与「Ping扫描」模板设置的 HostDiscovery=true 相矛盾，
            // 使 📡 Ping扫描 (-sn) 模板永远生成 -sT 端口扫描命令，与模板名称承诺的行为不符。
            bool pingOnly = config.PingProbe && !scanTcp && !scanUdp && !scanSyn;

            // 无任何扫描类型且非仅主机发现 → 默认 TCP 连接扫描
            if (!pingOnly && !scanTcp && !scanUdp) scanTcp = true;

            if (pingOnly)
            {
                parts.Add("-sn");
            }
            else
            {
                // SYN 半开扫描优先于 TCP 连接扫描
                if (scanSyn) parts.Add("-sS");
                else if (scanTcp) parts.Add("-sT");
                if (scanUdp) parts.Add("-sU");
            }

            AddDetectionFlags(config, parts);
            AddHostDiscoveryFlags(config, parts, pingOnly);

            // 反向 DNS 解析
            parts.Add(config.ReverseDns ? "-R" : "-n");

            AddPortFlags(config, parts);
            AddTimingFlags(config, parts);
            AddRandomizeFlags(config, parts);
            AddEvasionFlags(config, parts, ttl);
            AddOutputFlags(config, parts, timestamp);

            if (config.ShowOpenOnly) parts.Add("--open");

            // 日志级别
            if (config.Verbosity == 0) parts.Add("-q");
            else if (config.Verbosity == 1) parts.Add("-v");
            else if (config.Verbosity >= 2) parts.Add("-vv");

            parts.Add("--stats-every 5s");

            if (config.ScriptScan && config.ServiceDetection)
                parts.Add("--traceroute");

            var targetValue = config.TargetValue?.Trim() ?? "";
            parts.Add(string.IsNullOrEmpty(targetValue) ? "<target>" : targetValue);

            return string.Join(" ", parts);
        }

        private static void AddDetectionFlags(ExpertScanConfiguration config, List<string> parts)
        {
            if (config.ServiceDetection)
            {
                parts.Add("-sV");
                // nmap 默认强度即 7，0 表示不额外探测，二者显式输出均属冗余
                if (config.ServiceIntensity > 0 && config.ServiceIntensity != 7)
                    parts.Add($"--version-intensity {config.ServiceIntensity}");
            }

            if (config.OsDetection)
            {
                parts.Add("-O");
                parts.Add("--osscan-guess"); // 积极猜测 OS
            }

            if (config.ScriptScan)
            {
                if (!string.IsNullOrWhiteSpace(config.NseScriptArgs))
                {
                    // 用户自定义 NSE 脚本参数，如: vuln, safe, auth 或 "http-vuln-cve2017-5638"
                    parts.Add($"--script {config.NseScriptArgs}");
                }
                else
                {
                    parts.Add("-sC");
                }
            }

            // 主动扫描组合标志（-A = -O + -sV + -sC + --traceroute）
            // 仅当使用默认脚本（-sC）时才合并为 -A，自定义 NSE 参数时不合并
            bool useDefaultScripts = config.ScriptScan && string.IsNullOrWhiteSpace(config.NseScriptArgs);
            if (config.ServiceDetection && config.OsDetection && useDefaultScripts)
            {
                parts.Remove("-sV");
                parts.Remove("-O");
                parts.Remove("--osscan-guess");
                parts.Remove("-sC");
                parts.Add("-A");
            }
        }

        private static void AddHostDiscoveryFlags(ExpertScanConfiguration config, List<string> parts, bool pingOnly)
        {
            if (config.PingProbe && config.HostDiscovery)
            {
                parts.Add("-PE"); // ICMP Echo
                parts.Add("-PP"); // ICMP Timestamp
            }

            // -Pn 表示跳过主机发现，与 -sn（仅主机发现）语义直接冲突，不可同时出现
            if (!config.HostDiscovery && !pingOnly) parts.Add("-Pn");
        }

        private static void AddPortFlags(ExpertScanConfiguration config, List<string> parts)
        {
            if (config.PortMode == "All")
            {
                parts.Add("-p-");
            }
            else if (config.PortMode == "Sensitive")
            {
                parts.Add("--top-ports 100");
            }
            else if (config.PortMode == "Custom" && !string.IsNullOrWhiteSpace(config.CustomPorts))
            {
                var ports = config.CustomPorts
                    .Split(new[] { ',', ';', ' ', '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries)
                    .Select(p => p.Trim())
                    .Where(p => !string.IsNullOrEmpty(p));
                var joined = string.Join(",", ports);
                // 自定义端口全部无效时不输出空参数，避免产生 "-p " 造成命令解析异常
                if (!string.IsNullOrEmpty(joined)) parts.Add($"-p {joined}");
            }
            else
            {
                parts.Add("--top-ports 1000");
            }

            if (!string.IsNullOrWhiteSpace(config.ExcludePorts))
                parts.Add($"--exclude-ports {config.ExcludePorts.Trim()}");

            if (!string.IsNullOrWhiteSpace(config.ExcludeHosts))
                parts.Add($"--exclude-hosts {config.ExcludeHosts.Trim()}");
        }

        private static void AddTimingFlags(ExpertScanConfiguration config, List<string> parts)
        {
            int timingLevel;
            if (config.StealthMode)
                timingLevel = 2; // 隐蔽模式 → -T2
            else if (config.TcpConcurrency <= 10 && config.TcpTimeout >= 3000)
                timingLevel = 1; // 极慢 → -T1
            else if (config.TcpConcurrency <= 20 && config.TcpTimeout >= 2000)
                timingLevel = 2; // 慢速 → -T2
            else if (config.TcpConcurrency <= 50 && config.TcpTimeout >= 1000)
                timingLevel = 3; // 正常 → -T3
            else if (config.TcpConcurrency <= 200 && config.TcpTimeout <= 500)
                timingLevel = 4; // 快速 → -T4
            else
                timingLevel = 5; // 疯狂 → -T5

            parts.Add($"-T{timingLevel}");

            if (config.TcpConcurrency > 0 && config.TcpConcurrency != 50)
                parts.Add($"--max-parallelism {config.TcpConcurrency}");

            if (config.TcpTimeout > 0 && config.TcpTimeout != 1000)
                parts.Add($"--max-rtt-timeout {config.TcpTimeout}ms");
            if (config.TcpTimeout >= 100)
                parts.Add($"--min-rtt-timeout {Math.Max(10, config.TcpTimeout / 5)}ms");

            if (config.RetryCount > 0 && config.RetryCount != 1)
                parts.Add($"--max-retries {config.RetryCount}");

            // 主机超时（防止卡在慢速主机上）
            if (config.TcpTimeout >= 2000)
                parts.Add($"--host-timeout {config.TcpTimeout * 3}ms");

            if (config.RateLimit && config.PacketRate > 0)
            {
                parts.Add($"--max-rate {config.PacketRate}");
                var minRate = Math.Max(1, config.PacketRate / 10);
                if (minRate < config.PacketRate)
                    parts.Add($"--min-rate {minRate}");
            }
        }

        private static void AddRandomizeFlags(ExpertScanConfiguration config, List<string> parts)
        {
            // RandomizeCheckBox 与 RandomTargetOrderCheckBox 语义重叠，任一勾选即随机化目标顺序
            if (config.Randomize || config.RandomTargetOrder)
                parts.Add("--randomize-hosts");
            if (config.RandomPortOrder)
                parts.Add("--randomize-ports");
        }

        private static void AddEvasionFlags(ExpertScanConfiguration config, List<string> parts, int? ttl)
        {
            if (config.FragmentPackets) parts.Add("-f");

            // nmap 要求 MTU >= 8，且默认值 1500 无需显式输出
            if (!string.IsNullOrWhiteSpace(config.Mtu) && config.Mtu != "1500" &&
                int.TryParse(config.Mtu, out var mtuVal) && mtuVal >= 8 && mtuVal <= 1500)
                parts.Add($"--mtu {config.Mtu}");

            if (config.DecoyScan && !string.IsNullOrWhiteSpace(config.DecoyIps))
                parts.Add($"-D {config.DecoyIps}");

            if (config.IdleScan && !string.IsNullOrWhiteSpace(config.ZombieHost))
                parts.Add($"-sI {config.ZombieHost}");

            if (!string.IsNullOrWhiteSpace(config.SourcePort) && int.TryParse(config.SourcePort, out _))
                parts.Add($"--source-port {config.SourcePort}");

            if (config.SourcePortMin > 0 || config.SourcePortMax > 0)
            {
                if (config.SourcePortMin > 0 && config.SourcePortMax > 0 && config.SourcePortMax > config.SourcePortMin)
                    parts.Add($"--source-port {config.SourcePortMin}-{config.SourcePortMax}");
                else if (config.SourcePortMin > 0)
                    parts.Add($"--source-port {config.SourcePortMin}");
            }

            if (config.BadChecksum) parts.Add("--badsum");

            // 数据长度（规避一些防火墙）
            parts.Add("--data-length 32");

            // TTL 伪装
            parts.Add($"--ttl {ttl ?? new Random().Next(48, 128)}");

            if (config.SourceRouting) parts.Add("--ip-options L");
        }

        private static void AddOutputFlags(ExpertScanConfiguration config, List<string> parts, string? timestamp)
        {
            // 先求值再拼接：插值字符串内的格式说明符会与 ?? 产生优先级冲突
            var stamp = timestamp ?? DateTime.Now.ToString("yyyyMMdd_HHmmss");
            var baseName = $"scan_{stamp}";
            string? outputDir = null;
            if (config.SaveOutput && !string.IsNullOrWhiteSpace(config.OutputDir))
                outputDir = config.OutputDir;

            string WithDir(string fileName) => outputDir != null ? Path.Combine(outputDir, fileName) : fileName;

            if (config.OutputJson)
                parts.Add($"-oJ \"{WithDir(baseName + ".json")}\"");

            // 注意分支绑定关系须与原实现一致：-oN 的 else 只挂在 OutputCsv 上，
            // 因此 HTML 与 CSV 同时勾选时两者都会输出，且仍会追加 -oN。
            if (config.OutputHtml)
            {
                // nmap 不直接支持 HTML，生成 XML 供后续转换
                parts.Add($"-oX \"{WithDir(baseName + ".xml")}\"");
            }

            if (config.OutputCsv)
            {
                // nmap 不直接支持 CSV，使用 -oG greppable 格式
                parts.Add($"-oG \"{WithDir(baseName + ".gnmap")}\"");
            }
            else if (config.SaveOutput && outputDir != null)
            {
                // 未选择 CSV 格式但启用了保存 → 追加默认文本输出（nmap 允许多格式并存）
                parts.Add($"-oN \"{WithDir(baseName + ".txt")}\"");
            }
        }
    }
}
