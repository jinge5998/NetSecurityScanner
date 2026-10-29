using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Sockets;
using System.Threading.Tasks;
using NetSecurityScanner.Core.Models;

namespace NetSecurityScanner.Core.Services
{
    /// <summary>
    /// 批量扫描编排纯逻辑：目标校验、耗时预估、失败分类。无 IO、无 UI 依赖。
    /// </summary>
    public static class BatchScanOrchestrator
    {
        public const int MaxTargets = 65536;
        public const int ConfirmThreshold = 256;

        public static TargetParseOutcome ValidateTargets(IEnumerable<string> raw)
        {
            if (raw == null) return new TargetParseOutcome { Error = "请输入目标" };

            var list = raw.ToList();
            if (list.Count == 0 || list.All(string.IsNullOrWhiteSpace))
            {
                return new TargetParseOutcome { Error = "请输入目标" };
            }

            int total = list.Count;
            var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            var targets = new List<string>();
            int invalid = 0;

            foreach (var entry in list)
            {
                var t = (entry ?? "").Trim();
                if (t.Length == 0 || t.StartsWith("#")) { invalid++; continue; }
                if (!System.Net.IPAddress.TryParse(t, out _)) { invalid++; continue; }
                if (seen.Add(t)) targets.Add(t);
            }

            if (targets.Count > MaxTargets)
            {
                return new TargetParseOutcome { Error = $"目标数量超过 {MaxTargets} 上限，请缩小扫描范围" };
            }
            if (targets.Count == 0)
            {
                return new TargetParseOutcome { Error = "未解析到有效目标" };
            }

            return new TargetParseOutcome
            {
                Targets = targets,
                Total = total,
                Deduped = total - invalid - targets.Count,
                Invalid = invalid
            };
        }

        public static TimeSpan Estimate(int targetCount, int portCount, int concurrency, double timeoutSeconds)
        {
            if (targetCount <= 0 || concurrency <= 0) return TimeSpan.FromSeconds(1);
            double seconds = (targetCount * (double)portCount * timeoutSeconds) / concurrency
                           + (targetCount * 3.0 * timeoutSeconds) / concurrency;
            return TimeSpan.FromSeconds(Math.Max(1, seconds));
        }

        public static BatchScanFailureCategory Classify(Exception? ex, bool reachedTarget, bool hasOpenPorts, bool canceled)
        {
            // 用户取消以令牌标志为准；TaskCanceledException 继承 OperationCanceledException，必须先判 Timeout 系
            if (canceled) return BatchScanFailureCategory.Canceled;
            if (ex is TimeoutException) return BatchScanFailureCategory.Timeout;
            if (ex is TaskCanceledException) return BatchScanFailureCategory.Timeout;
            if (ex is OperationCanceledException) return BatchScanFailureCategory.Canceled;
            if (ex is SocketException se)
            {
                return se.SocketErrorCode switch
                {
                    SocketError.ConnectionRefused => BatchScanFailureCategory.ConnectionRefused,
                    SocketError.HostUnreachable or SocketError.NetworkUnreachable => BatchScanFailureCategory.Unreachable,
                    SocketError.HostNotFound => BatchScanFailureCategory.DnsFailure,
                    _ => BatchScanFailureCategory.ScanException
                };
            }
            if (ex == null && reachedTarget && !hasOpenPorts) return BatchScanFailureCategory.NoOpenPort;
            if (ex == null && reachedTarget && hasOpenPorts) return BatchScanFailureCategory.None;
            return BatchScanFailureCategory.ScanException;
        }

        public static string ToDisplayText(BatchScanFailureCategory category) => category switch
        {
            BatchScanFailureCategory.Timeout => "超时",
            BatchScanFailureCategory.ConnectionRefused => "连接被拒",
            BatchScanFailureCategory.Unreachable => "主机不可达",
            BatchScanFailureCategory.DnsFailure => "域名解析失败",
            BatchScanFailureCategory.NoOpenPort => "无开放端口",
            BatchScanFailureCategory.ScanException => "扫描异常",
            BatchScanFailureCategory.Canceled => "已取消",
            _ => ""
        };
    }
}
