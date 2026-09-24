using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using NetSecurityScanner.Models;
using NetSecurityScanner.Utils;

namespace NetSecurityScanner.Services
{
    /// <summary>
    /// 插件调用链追踪服务（v7-T4）。
    /// 职责：
    ///   1. BeginTrace/BeginSpan/EndSpan API
    ///   2. 批量写入 data/plugin_traces/{yyyyMMdd}.jsonl（5 秒 flush）
    ///   3. QueryTraceAsync 反查完整调用树
    ///   4. Span 超时（>TraceTimeoutMs）触发 OnTraceTimeout
    /// </summary>
    public class PluginTelemetryService : IDisposable
    {
        private readonly PluginSecurityService _security;
        private readonly PluginHealthMonitor? _health;
        private readonly string _traceDir;
        private readonly ConcurrentDictionary<string, TraceSpan> _activeSpans = new();
        private readonly ConcurrentDictionary<string, List<TraceSpan>> _traceIndex = new();
        private readonly ConcurrentQueue<TraceSpan> _pending = new();
        private readonly SemaphoreSlim _flushLock = new(1, 1);
        private readonly Timer _flushTimer;
        private readonly Timer _timeoutTimer;
        private readonly CancellationTokenSource _cts = new();

        public event EventHandler<TraceSpan>? OnTraceTimeout;

        public PluginTelemetryService(PluginSecurityService security, PluginHealthMonitor? health = null)
        {
            _security = security;
            _health = health;
            _traceDir = Path.Combine(DataPaths.AppDataDirectory, "plugin_traces");
            Directory.CreateDirectory(_traceDir);

            _flushTimer = new Timer(_ => _ = FlushAsync().ConfigureAwait(false), null,
                TimeSpan.FromSeconds(5), TimeSpan.FromSeconds(5));
            _timeoutTimer = new Timer(CheckTimeouts, null,
                TimeSpan.FromSeconds(5), TimeSpan.FromSeconds(5));
        }

        /// <summary>开始一个 Trace，返回 TraceId 和 RootSpanId</summary>
        public (string TraceId, string RootSpanId) BeginTrace(string name, string? targetIp = null, Dictionary<string, string>? tags = null)
        {
            var traceId = Guid.NewGuid().ToString("N");
            var spanId = NewSpanId();
            var span = new TraceSpan
            {
                TraceId = traceId,
                SpanId = spanId,
                Name = name,
                TargetIp = targetIp,
                StartTime = DateTime.Now,
                Status = "Running",
                Tags = tags ?? new()
            };
            _activeSpans[spanId] = span;
            _traceIndex.GetOrAdd(traceId, _ => new List<TraceSpan>()).Add(span);
            return (traceId, spanId);
        }

        /// <summary>开始子 Span</summary>
        public string BeginSpan(string traceId, string? parentSpanId, string name, string? pluginId = null, int? port = null)
        {
            var spanId = NewSpanId();
            var span = new TraceSpan
            {
                TraceId = traceId,
                SpanId = spanId,
                ParentSpanId = parentSpanId,
                Name = name,
                PluginId = pluginId,
                Port = port,
                StartTime = DateTime.Now,
                Status = "Running"
            };
            _activeSpans[spanId] = span;
            _traceIndex.GetOrAdd(traceId, _ => new List<TraceSpan>()).Add(span);
            return spanId;
        }

        /// <summary>结束 Span</summary>
        public void EndSpan(string spanId, string status = "Ok", string? error = null, Dictionary<string, string>? tags = null)
        {
            if (!_activeSpans.TryRemove(spanId, out var span)) return;
            span.EndTime = DateTime.Now;
            span.Status = status;
            span.ErrorMessage = error;
            if (tags != null)
            {
                foreach (var kv in tags) span.Tags[kv.Key] = kv.Value;
            }
            _pending.Enqueue(span);
        }

        /// <summary>查询完整调用树</summary>
        public async Task<TraceTree?> QueryTraceAsync(string traceId)
        {
            // 先查内存索引
            if (_traceIndex.TryGetValue(traceId, out var spans))
            {
                return BuildTree(traceId, spans);
            }
            // 再回查落盘
            return await QueryTraceFromDiskAsync(traceId).ConfigureAwait(false);
        }

        public List<TraceSpan> GetRecent(int limit = 100)
        {
            return _traceIndex.Values
                .SelectMany(l => l)
                .OrderByDescending(s => s.StartTime)
                .Take(limit)
                .ToList();
        }

        private TraceTree BuildTree(string traceId, List<TraceSpan> spans)
        {
            var tree = new TraceTree { TraceId = traceId, AllSpans = spans };
            var byParent = spans.GroupBy(s => s.ParentSpanId ?? "").ToDictionary(g => g.Key, g => g.ToList());
            if (byParent.TryGetValue("", out var roots)) tree.RootSpans = roots;
            if (spans.Count > 0)
            {
                tree.StartTime = spans.Min(s => s.StartTime);
                tree.EndTime = spans.Max(s => s.EndTime == default ? s.StartTime : s.EndTime);
                tree.TotalElapsedMs = (long)(tree.EndTime - tree.StartTime).TotalMilliseconds;
            }
            return tree;
        }

        private async Task<TraceTree?> QueryTraceFromDiskAsync(string traceId)
        {
            try
            {
                var list = new List<TraceSpan>();
                foreach (var f in Directory.GetFiles(_traceDir, "*.jsonl"))
                {
                    foreach (var line in await File.ReadAllLinesAsync(f).ConfigureAwait(false))
                    {
                        if (string.IsNullOrWhiteSpace(line)) continue;
                        try
                        {
                            var s = JsonSerializer.Deserialize<TraceSpan>(line, new JsonSerializerOptions
                            {
                                PropertyNameCaseInsensitive = true
                            });
                            if (s != null && s.TraceId == traceId) list.Add(s);
                        }
                        catch { }
                    }
                }
                if (list.Count == 0) return null;
                // 回填内存索引
                _traceIndex[traceId] = list;
                return BuildTree(traceId, list);
            }
            catch
            {
                return null;
            }
        }

        private async Task FlushAsync()
        {
            if (_pending.IsEmpty) return;
            await _flushLock.WaitAsync().ConfigureAwait(false);
            try
            {
                var byDate = new Dictionary<string, List<string>>();
                while (_pending.TryDequeue(out var span))
                {
                    var date = span.StartTime.ToString("yyyyMMdd");
                    var line = JsonSerializer.Serialize(span, new JsonSerializerOptions
                    {
                        Encoder = System.Text.Encodings.Web.JavaScriptEncoder.UnsafeRelaxedJsonEscaping
                    });
                    if (!byDate.TryGetValue(date, out var list))
                    {
                        list = new List<string>();
                        byDate[date] = list;
                    }
                    list.Add(line);
                }
                foreach (var kv in byDate)
                {
                    var file = Path.Combine(_traceDir, $"{kv.Key}.jsonl");
                    await File.AppendAllLinesAsync(file, kv.Value, Encoding.UTF8).ConfigureAwait(false);
                }
            }
            catch (Exception ex)
            {
                DebugLog($"Flush 失败: {ex.Message}");
            }
            finally
            {
                _flushLock.Release();
            }
        }

        private void CheckTimeouts(object? state)
        {
            if (_cts.IsCancellationRequested) return;
            try
            {
                var timeoutMs = _security.CurrentPolicy.TraceTimeoutMs;
                var now = DateTime.Now;
                foreach (var kv in _activeSpans)
                {
                    var span = kv.Value;
                    if (span.Status != "Running") continue;
                    if ((now - span.StartTime).TotalMilliseconds > timeoutMs)
                    {
                        EndSpan(span.SpanId, "Timeout", $"Span 超过 {timeoutMs}ms 未结束");
                        _health?.OnTraceTimeoutExternal(span);
                        OnTraceTimeout?.Invoke(this, span);
                    }
                }
            }
            catch (Exception ex)
            {
                DebugLog($"CheckTimeouts 失败: {ex.Message}");
            }
        }

        private static string NewSpanId() => Guid.NewGuid().ToString("N").Substring(0, 16);

        private static void DebugLog(string msg) => System.Diagnostics.Debug.WriteLine($"[Telemetry] {msg}");

        public void Dispose()
        {
            _cts.Cancel();
            FlushAsync().GetAwaiter().GetResult();
            _flushTimer.Dispose();
            _timeoutTimer.Dispose();
            _cts.Dispose();
        }
    }
}
