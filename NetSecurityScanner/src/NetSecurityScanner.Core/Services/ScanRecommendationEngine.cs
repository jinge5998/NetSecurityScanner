using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.Json;
using NetSecurityScanner.Core.Models;
using NetSecurityScanner.Services;
using NetSecurityScanner.Utils;

namespace NetSecurityScanner.Core.Services
{
    /// <summary>
    /// 智能扫描推荐上下文，聚合影响推荐决策的全部输入。
    /// </summary>
    public class ScanRecommendationContext
    {
        /// <summary>
        /// 待扫描目标数量。
        /// </summary>
        public int TargetCount { get; set; }

        /// <summary>
        /// 平均网络往返延迟（毫秒）。
        /// </summary>
        public double AverageRttMs { get; set; }

        /// <summary>
        /// 待扫描目标列表（用于历史结果匹配）。
        /// </summary>
        public List<string> Targets { get; set; } = new();

        /// <summary>
        /// Rust 扫描服务客户端；为 null 或未连接时不参与负载推荐。
        /// </summary>
        public RustScannerClient? RustClient { get; set; }
    }

    /// <summary>
    /// 扫描推荐结果。
    /// </summary>
    public class ScanRecommendationResult
    {
        /// <summary>
        /// 推荐配置。
        /// </summary>
        public ScanProfileConfig Config { get; set; } = new();

        /// <summary>
        /// 推荐理由，可包含多条，用 "；" 分隔。
        /// </summary>
        public string Reason { get; set; } = "";
    }

    /// <summary>
    /// 专家模式智能扫描推荐引擎。
    /// 综合目标数量、网络延迟、历史扫描结果和 Rust 服务负载，给出可解释的扫描参数推荐。
    /// </summary>
    public class ScanRecommendationEngine
    {
        private const double HighCpuThreshold = 70.0;
        private const double HighMemoryThreshold = 80.0;
        private const double HighLoadThreshold = 2.0;

        private static readonly JsonSerializerOptions HistoryJsonOptions = new()
        {
            PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
            PropertyNameCaseInsensitive = true
        };

        /// <summary>
        /// 基于目标数量推荐基准配置。
        /// </summary>
        /// <param name="targetCount">目标数量。</param>
        public ScanRecommendationResult RecommendByTargetCount(int targetCount)
        {
            if (targetCount <= 0)
            {
                targetCount = 1;
            }

            ScanProfileConfig config;
            string reason;

            if (targetCount <= 5)
            {
                config = ScanProfileConfigFactory.CreateCustom();
                config.TimeoutMs = 100;
                config.TcpConcurrency = 100;
                config.UdpConcurrency = 50;
                reason = "目标数量较少，使用激进参数快速扫描";
            }
            else if (targetCount <= 100)
            {
                config = ScanProfileConfigFactory.CreateStandard();
                reason = "目标数量适中，使用标准扫描";
            }
            else if (targetCount <= 500)
            {
                config = ScanProfileConfigFactory.CreateStandard();
                config.TcpConcurrency = 20;
                config.UdpConcurrency = 10;
                reason = "目标数量较多，降低并发保证稳定性";
            }
            else
            {
                // 目标极多时选择深度扫描并继续降低并发，兼顾覆盖与稳定性。
                config = ScanProfileConfigFactory.CreateDeep();
                config.TcpConcurrency = 20;
                config.UdpConcurrency = 10;
                reason = "目标数量极多，使用深度扫描并降低并发保证稳定性";
            }

            config.Normalize();
            return new ScanRecommendationResult { Config = config, Reason = reason };
        }

        /// <summary>
        /// 基于网络延迟调整超时和并发。
        /// </summary>
        /// <param name="averageRttMs">平均往返延迟（毫秒）。</param>
        /// <param name="current">当前基准配置。</param>
        public ScanRecommendationResult RecommendByLatency(double averageRttMs, ScanProfileConfig current)
        {
            if (current == null)
            {
                throw new ArgumentNullException(nameof(current));
            }

            var config = current.Clone();
            string reason = "";

            if (averageRttMs <= 50)
            {
                // 延迟较低，保持当前超时不变。
            }
            else if (averageRttMs <= 200)
            {
                config.TimeoutMs = Math.Max(config.TimeoutMs, 300);
                reason = "网络延迟较高，增加超时避免漏检";
            }
            else
            {
                config.TimeoutMs = Math.Max(config.TimeoutMs, 500);
                config.TcpConcurrency = (int)(config.TcpConcurrency * 0.7);
                config.UdpConcurrency = (int)(config.UdpConcurrency * 0.7);
                reason = "网络延迟较高，增加超时并降低并发避免漏检";
            }

            config.Normalize();
            return new ScanRecommendationResult { Config = config, Reason = reason };
        }

        /// <summary>
        /// 基于历史扫描结果推荐端口范围和 Ping 探测。
        /// </summary>
        /// <param name="targets">当前待扫描目标。</param>
        /// <param name="profileManager">扫描配置管理器，用于定位数据目录。</param>
        public ScanRecommendationResult RecommendByHistory(List<string> targets, ScanProfileManager profileManager)
        {
            if (profileManager == null)
            {
                throw new ArgumentNullException(nameof(profileManager));
            }

            var config = ScanProfileConfigFactory.CreateStandard();
            var targetSet = new HashSet<string>(targets ?? new List<string>(), StringComparer.OrdinalIgnoreCase);

            var entries = ReadHistoryEntries(targetSet);
            string reason = "";

            if (entries.Count > 0)
            {
                var responsiveEntries = entries.Where(e => e.Responsive).ToList();
                var unresponsiveEntries = entries.Where(e => !e.Responsive).ToList();

                // 提取历史开放端口并统计出现频率。
                var portFrequency = new Dictionary<int, int>();
                foreach (var entry in responsiveEntries)
                {
                    foreach (var port in entry.OpenPorts.Where(p => p > 0 && p <= 65535).Distinct())
                    {
                        portFrequency[port] = portFrequency.GetValueOrDefault(port, 0) + 1;
                    }
                }

                if (responsiveEntries.Count > 0 && portFrequency.Count > 0)
                {
                    // 高频端口：在至少 50% 的响应记录中出现。
                    var threshold = responsiveEntries.Count * 0.5;
                    var commonPorts = portFrequency
                        .Where(kv => kv.Value >= threshold)
                        .Select(kv => kv.Key)
                        .OrderBy(p => p)
                        .ToList();

                    if (commonPorts.Count > 0)
                    {
                        config.Profile = ScanProfile.Custom;
                        config.PortRange = string.Join(",", commonPorts);
                        reason = "根据历史结果优先扫描高频开放端口";
                    }
                }

                // 若大部分目标历史无响应，启用 Ping 探测。
                if (entries.Count > 0 && unresponsiveEntries.Count / (double)entries.Count > 0.5)
                {
                    config.EnablePingProbe = true;
                    reason = string.IsNullOrEmpty(reason)
                        ? "历史数据显示目标常无响应，启用 Ping 探测"
                        : reason + "；历史数据显示目标常无响应，启用 Ping 探测";
                }
            }

            config.Normalize();
            return new ScanRecommendationResult { Config = config, Reason = reason };
        }

        /// <summary>
        /// 基于 Rust 扫描服务负载调整并发。
        /// </summary>
        /// <param name="client">Rust 扫描服务客户端。</param>
        public ScanRecommendationResult RecommendByServiceLoad(RustScannerClient client)
        {
            var config = ScanProfileConfigFactory.CreateStandard();
            string reason = "";

            if (client == null || !client.IsConnected)
            {
                reason = "Rust 服务未连接，使用标准扫描";
                return new ScanRecommendationResult { Config = config, Reason = reason };
            }

            try
            {
                var status = client.GetStatus();
                if (status != null && IsHighLoad(status))
                {
                    config.TcpConcurrency = (int)(config.TcpConcurrency * 0.6);
                    config.UdpConcurrency = (int)(config.UdpConcurrency * 0.6);
                    reason = "Rust 服务负载较高，降低并发";
                }
            }
            catch (Exception)
            {
                // 获取负载失败时不做降级，避免影响正常扫描。
                reason = "Rust 服务负载获取失败，使用标准扫描";
            }

            config.Normalize();
            return new ScanRecommendationResult { Config = config, Reason = reason };
        }

        /// <summary>
        /// 综合所有上下文给出最终推荐配置。
        /// </summary>
        /// <param name="context">推荐上下文。</param>
        public ScanRecommendationResult Recommend(ScanRecommendationContext context)
        {
            if (context == null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            var profileManager = new ScanProfileManager();

            // 1. 基于目标数量得到基准配置。
            var baseline = RecommendByTargetCount(context.TargetCount);
            var config = baseline.Config;
            var reasons = new List<string> { baseline.Reason };

            // 2. 基于网络延迟调整超时和并发。
            var latencyRecommendation = RecommendByLatency(context.AverageRttMs, config);
            config = latencyRecommendation.Config;
            if (!string.IsNullOrEmpty(latencyRecommendation.Reason))
            {
                reasons.Add(latencyRecommendation.Reason);
            }

            // 3. 基于历史结果调整端口范围和 Ping 探测。
            var historyRecommendation = RecommendByHistory(context.Targets, profileManager);
            if (historyRecommendation.Config.Profile == ScanProfile.Custom)
            {
                config.Profile = ScanProfile.Custom;
                config.PortRange = historyRecommendation.Config.PortRange;
            }
            if (historyRecommendation.Config.EnablePingProbe)
            {
                config.EnablePingProbe = true;
            }
            if (!string.IsNullOrEmpty(historyRecommendation.Reason))
            {
                reasons.Add(historyRecommendation.Reason);
            }

            // 4. 基于 Rust 服务负载调整并发。
            var loadRecommendation = RecommendByServiceLoad(context.RustClient);
            if (loadRecommendation.Reason.Contains("负载较高"))
            {
                config.TcpConcurrency = (int)(config.TcpConcurrency * 0.6);
                config.UdpConcurrency = (int)(config.UdpConcurrency * 0.6);
                reasons.Add(loadRecommendation.Reason);
            }
            else if (!string.IsNullOrEmpty(loadRecommendation.Reason) && loadRecommendation.Reason.Contains("未连接"))
            {
                reasons.Add(loadRecommendation.Reason);
            }

            config.Normalize();

            return new ScanRecommendationResult
            {
                Config = config,
                Reason = string.Join("；", reasons)
            };
        }

        private static bool IsHighLoad(RustStatusResponse status)
        {
            return status.CpuPercent >= HighCpuThreshold
                || status.MemoryPercent >= HighMemoryThreshold
                || status.LoadAverage >= HighLoadThreshold;
        }

        private static List<ScanHistoryEntry> ReadHistoryEntries(HashSet<string> targetSet)
        {
            var entries = new List<ScanHistoryEntry>();

            try
            {
                var path = Path.Combine(DataPaths.DataRoot, "scan_history.json");
                if (File.Exists(path))
                {
                    var json = File.ReadAllText(path);
                    var fileEntries = JsonSerializer.Deserialize<List<ScanHistoryEntry>>(json, HistoryJsonOptions);
                    if (fileEntries != null)
                    {
                        entries.AddRange(fileEntries.Where(e => targetSet.Count == 0 || targetSet.Contains(e.Target)));
                    }
                }
            }
            catch
            {
                // 历史文件读取失败时静默回退，不影响推荐主流程。
            }

            return entries;
        }

        private class ScanHistoryEntry
        {
            public string Target { get; set; } = "";
            public List<int> OpenPorts { get; set; } = new();
            public bool Responsive { get; set; } = true;
        }
    }
}
