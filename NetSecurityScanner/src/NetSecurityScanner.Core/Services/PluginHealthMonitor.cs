using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using NetSecurityScanner.Models;
using NetSecurityScanner.Plugins;

namespace NetSecurityScanner.Services
{
    /// <summary>
    /// 插件健康监控服务（v6-T4 + v7 升级：真实 CPU 采样 + 调用链超时 + 冷却期）。
    /// 职责：
    ///   1. 周期 5 秒采样所有 LoadedPlugins（内存/CPU/连续失败/健康度）
    ///   2. BeginSample/EndSample 暴露给 PluginManager 在每次插件执行前后埋点
    ///   3. 5 分钟内连续 3 次失败 → 冷却 5 分钟后再评估 → 隔离
    ///   4. 单次内存增量 > 200 MB → 熔断 + 扣分
    ///   5. 健康度 = 100 - 失败*0.3 - 内存*0.3 - CPU*0.2 - 超时*0.2；&lt; 60 触发 OnAlert
    ///   6. v7：订阅 TraceSpan 超时，扣 10 分
    /// </summary>
    public class PluginHealthMonitor : IDisposable
    {
        private readonly PluginManager _manager;
        private readonly PluginSecurityService _security;
        private readonly ConcurrentDictionary<string, PluginHealthSnapshot> _snapshots = new();
        private readonly ConcurrentDictionary<string, SampleContext> _activeSamples = new();
        private readonly Timer _sampleTimer;
        private readonly CancellationTokenSource _cts = new();
        private readonly DateTime _processStart = DateTime.Now;
        private TimeSpan _lastCpu;
        private DateTime _lastSampleTime = DateTime.Now;
        private const long MemoryLimitBytes = 200L * 1024 * 1024; // 200 MB
        private const int FailureThreshold = 3;
        private const int FailureWindowSeconds = 300; // 5 分钟
        private const int QuarantineCooldownSeconds = 300; // v7：冷却 5 分钟
        private const int TraceTimeoutPenalty = 10; // v7：调用链超时扣分

        /// <summary>告警事件（连续失败 / 内存超限 / 健康度低 / 调用链超时）</summary>
        public event EventHandler<(string PluginId, string AlertType, string Message)>? OnAlert;

        public PluginHealthMonitor(PluginManager manager, PluginSecurityService security)
        {
            _manager = manager;
            _security = security;
            _lastCpu = Process.GetCurrentProcess().TotalProcessorTime;
            _sampleTimer = new Timer(SampleAll, null, TimeSpan.FromSeconds(5), TimeSpan.FromSeconds(5));
        }

        public PluginHealthSnapshot? GetSnapshot(string pluginId)
        {
            _snapshots.TryGetValue(pluginId, out var s);
            return s;
        }

        public List<PluginHealthSnapshot> GetAllSnapshots()
        {
            return _snapshots.Values.OrderByDescending(s => s.HealthScore).ToList();
        }

        public List<PluginHealthSnapshot> GetQuarantined()
        {
            return _snapshots.Values.Where(s => s.IsQuarantined).ToList();
        }

        public void BeginSample(string pluginId)
        {
            _activeSamples[pluginId] = new SampleContext
            {
                PluginId = pluginId,
                StartTime = DateTime.Now,
                StartMemory = GC.GetTotalMemory(false)
            };
        }

        public void EndSample(string pluginId, bool success, Exception? ex, long elapsedMs, bool timedOut = false)
        {
            var snap = GetOrCreate(pluginId);
            _activeSamples.TryRemove(pluginId, out var ctx);

            var memDelta = 0L;
            if (ctx != null)
            {
                memDelta = Math.Max(0, GC.GetTotalMemory(false) - ctx.StartMemory);
            }

            snap.TotalExecutions++;
            snap.TotalElapsedMs += elapsedMs;
            if (memDelta > snap.PeakMemoryBytes) snap.PeakMemoryBytes = memDelta;
            snap.RecentSamples.Add(new PluginExecutionSample
            {
                Timestamp = DateTime.Now,
                Success = success,
                ElapsedMs = elapsedMs,
                MemoryDeltaBytes = memDelta,
                Error = ex?.Message
            });
            if (snap.RecentSamples.Count > 50) snap.RecentSamples.RemoveAt(0);

            if (timedOut) snap.TotalTimeouts++;

            if (!success)
            {
                snap.ConsecutiveFailures++;
                snap.TotalFailures++;
                snap.LastFailureAt = DateTime.Now;
                snap.LastError = ex?.Message;

                if (snap.ConsecutiveFailures >= FailureThreshold &&
                    !snap.IsQuarantined &&
                    !IsInCooldown(snap) &&
                    IsWithinFailureWindow(snap))
                {
                    Quarantine(pluginId, $"连续 {FailureThreshold} 次失败（{FailureWindowSeconds / 60} 分钟内），进入 5 分钟冷却期");
                    snap.CooldownUntil = DateTime.Now.AddSeconds(QuarantineCooldownSeconds);
                }
            }
            else
            {
                snap.ConsecutiveFailures = 0;
                snap.CooldownUntil = null;
            }

            if (memDelta > MemoryLimitBytes)
            {
                snap.HealthScore = Math.Max(0, snap.HealthScore - 20);
                _ = _security.AppendAuditAsync(new PluginAuditEntry
                {
                    PluginId = pluginId,
                    Action = "MemoryLimitExceeded",
                    Result = "Blocked",
                    Detail = $"内存增量 {memDelta / 1024 / 1024} MB 超过 {MemoryLimitBytes / 1024 / 1024} MB 限制"
                });
                OnAlert?.Invoke(this, (pluginId, "MemoryLimitExceeded", $"插件 {pluginId} 单次内存增量 {memDelta / 1024 / 1024} MB"));
            }
            else
            {
                RecalculateScore(snap);
            }

            if (snap.HealthScore < 60)
            {
                OnAlert?.Invoke(this, (pluginId, "LowHealthScore", $"插件 {pluginId} 健康度 {snap.HealthScore}"));
            }
        }

        /// <summary>
        /// v7：外部调用（来自 TelemetryService 的 OnTraceTimeout）
        /// </summary>
        public void OnTraceTimeoutExternal(TraceSpan span)
        {
            if (string.IsNullOrEmpty(span.PluginId)) return;
            var snap = GetOrCreate(span.PluginId);
            snap.HealthScore = Math.Max(0, snap.HealthScore - TraceTimeoutPenalty);
            _ = _security.AppendAuditAsync(new PluginAuditEntry
            {
                PluginId = span.PluginId,
                Action = "TraceTimeout",
                Result = "Warning",
                Detail = $"TraceId={span.TraceId}, Span={span.Name}, 扣 {TraceTimeoutPenalty} 分"
            });
            OnAlert?.Invoke(this, (span.PluginId, "TraceTimeout", $"插件 {span.PluginId} 调用链 Span 超时 {span.ElapsedMs}ms"));
        }

        public void Quarantine(string pluginId, string reason)
        {
            var snap = GetOrCreate(pluginId);
            if (snap.IsQuarantined) return;
            snap.IsQuarantined = true;
            snap.QuarantinedAt = DateTime.Now;
            snap.CooldownUntil = DateTime.Now.AddSeconds(QuarantineCooldownSeconds);
            _ = _security.AppendAuditAsync(new PluginAuditEntry
            {
                PluginId = pluginId,
                Action = "Quarantined",
                Result = "Success",
                Detail = reason
            });
            OnAlert?.Invoke(this, (pluginId, "Quarantined", reason));
        }

        public void Unquarantine(string pluginId)
        {
            if (_snapshots.TryGetValue(pluginId, out var snap))
            {
                snap.IsQuarantined = false;
                snap.QuarantinedAt = null;
                snap.ConsecutiveFailures = 0;
                snap.CooldownUntil = null;
                _ = _security.AppendAuditAsync(new PluginAuditEntry
                {
                    PluginId = pluginId,
                    Action = "Unquarantined",
                    Result = "Success"
                });
            }
        }

        private void SampleAll(object? state)
        {
            if (_cts.IsCancellationRequested) return;
            try
            {
                // 真实 CPU 采样：基于 Process.TotalProcessorTime
                var proc = Process.GetCurrentProcess();
                var now = DateTime.Now;
                var elapsed = (now - _lastSampleTime).TotalSeconds;
                var cpuDelta = (proc.TotalProcessorTime - _lastCpu).TotalSeconds;
                _lastCpu = proc.TotalProcessorTime;
                _lastSampleTime = now;
                var cpuPercent = elapsed > 0 ? Math.Min(100, (cpuDelta / elapsed / Environment.ProcessorCount) * 100.0) : 0;

                var loadedIds = _manager.Plugins.Keys.ToHashSet(StringComparer.OrdinalIgnoreCase);
                foreach (var id in loadedIds)
                {
                    var snap = GetOrCreate(id);
                    snap.CpuUsagePercent = cpuPercent;
                    RecalculateScore(snap);
                }
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"[PluginHealthMonitor] SampleAll 异常: {ex.Message}");
            }
        }

        private static bool IsInCooldown(PluginHealthSnapshot snap)
        {
            return snap.CooldownUntil.HasValue && snap.CooldownUntil.Value > DateTime.Now;
        }

        private static bool IsWithinFailureWindow(PluginHealthSnapshot snap)
        {
            return snap.ConsecutiveFailures >= FailureThreshold;
        }

        private void RecalculateScore(PluginHealthSnapshot snap)
        {
            int score = 100;
            if (snap.TotalExecutions > 0)
            {
                double failRate = (double)snap.TotalFailures / snap.TotalExecutions;
                score -= (int)(failRate * 30); // 失败率最多扣 30（v7：从 50 调到 30，权重 30%）
            }
            if (snap.PeakMemoryBytes > MemoryLimitBytes / 2) score -= 15; // 内存权重 30%
            if (snap.CpuUsagePercent > 80) score -= 10; // CPU 权重 20%
            if (snap.CpuUsagePercent > 95) score -= 10;
            if (snap.TotalTimeouts > 0) score -= Math.Min(20, snap.TotalTimeouts * 4); // 超时权重 20%
            snap.HealthScore = Math.Max(0, Math.Min(100, score));
        }

        private PluginHealthSnapshot GetOrCreate(string pluginId)
        {
            return _snapshots.GetOrAdd(pluginId, id => new PluginHealthSnapshot
            {
                PluginId = id,
                Name = id
            });
        }

        public void Dispose()
        {
            _cts.Cancel();
            _sampleTimer.Dispose();
            _cts.Dispose();
        }

        private class SampleContext
        {
            public string PluginId { get; set; } = string.Empty;
            public DateTime StartTime { get; set; }
            public long StartMemory { get; set; }
        }
    }
}
