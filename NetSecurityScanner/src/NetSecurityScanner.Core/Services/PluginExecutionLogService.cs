using NetSecurityScanner.Models;
using NetSecurityScanner.Utils;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;

namespace NetSecurityScanner.Services
{
    /// <summary>
    /// 插件执行日志服务（v4-T3）
    /// - 每条记录一个 JSON 文件，按天分目录
    /// - 文件名：{PluginId}_{yyyyMMddHHmmssfff}_{Guid-N}.json，避免冲突
    /// - 所有异常静默记录到 Debug.WriteLine，不抛出
    /// </summary>
    public class PluginExecutionLogService
    {
        private static readonly JsonSerializerOptions JsonOptions = new()
        {
            WriteIndented = false,
            Encoder = System.Text.Encodings.Web.JavaScriptEncoder.UnsafeRelaxedJsonEscaping
        };

        private readonly string _baseLogDir;

        public PluginExecutionLogService()
        {
            try
            {
                _baseLogDir = Path.Combine(DataPaths.DataRoot, "plugin_executions");
            }
            catch
            {
                _baseLogDir = Path.Combine(AppContext.BaseDirectory ?? ".", "data", "plugin_executions");
            }

            try
            {
                if (!string.IsNullOrEmpty(_baseLogDir) && !Directory.Exists(_baseLogDir))
                {
                    Directory.CreateDirectory(_baseLogDir);
                }
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"[PluginExecutionLogService] 初始化日志目录失败: {ex.Message}");
            }
        }

        /// <summary>
        /// 写入单条执行记录。
        /// 异常被吞掉，不向上抛出。
        /// v6：同步写审计到 PluginSecurityService（如果 Governor 已初始化）。
        /// </summary>
        public async Task LogExecutionAsync(PluginExecutionEntry entry, CancellationToken ct = default)
        {
            if (entry == null) return;
            try
            {
                if (entry.EndTime == default) entry.EndTime = DateTime.Now;
                if (entry.StartTime == default) entry.StartTime = entry.EndTime;
                if (entry.DurationMs <= 0)
                {
                    entry.DurationMs = (long)(entry.EndTime - entry.StartTime).TotalMilliseconds;
                    if (entry.DurationMs < 0) entry.DurationMs = 0;
                }

                var dayDir = Path.Combine(_baseLogDir, entry.StartTime.ToString("yyyyMMdd"));
                if (!Directory.Exists(dayDir)) Directory.CreateDirectory(dayDir);

                var safePluginId = SanitizeFileName(string.IsNullOrEmpty(entry.PluginId) ? "unknown" : entry.PluginId);
                var ts = entry.StartTime.ToString("yyyyMMddHHmmssfff");
                var guidShort = Guid.NewGuid().ToString("N").Substring(0, 8);
                var fileName = $"{safePluginId}_{ts}_{guidShort}.json";
                var filePath = Path.Combine(dayDir, fileName);

                var json = JsonSerializer.Serialize(entry, JsonOptions);
                ct.ThrowIfCancellationRequested();
                await File.WriteAllTextAsync(filePath, json, ct).ConfigureAwait(false);

                // v6：同步写审计
                try
                {
                    var governor = NetSecurityScanner.Services.PluginGovernor.Instance;
                    if (governor.IsInitialized)
                    {
                        await governor.Security.AppendAuditAsync(new NetSecurityScanner.Models.PluginAuditEntry
                        {
                            PluginId = entry.PluginId ?? string.Empty,
                            Action = "Execute",
                            Result = entry.Success ? "Success" : "Failed",
                            Detail = $"target={entry.Target}, port={entry.Port}, vulns={entry.VulnCount}, elapsed={entry.DurationMs}ms"
                        }).ConfigureAwait(false);
                    }
                }
                catch { /* 审计失败不影响主流程 */ }
            }
            catch (OperationCanceledException)
            {
                // 用户取消，不做额外处理
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"[PluginExecutionLogService] 写入日志失败: {ex.Message}");
            }
        }

        /// <summary>
        /// 读取最近 N 天的所有日志条目（按时间倒序，最多 maxEntries 条）。
        /// </summary>
        public async Task<List<PluginExecutionEntry>> GetRecentEntriesAsync(int lastDays = 7, int maxEntries = 50, CancellationToken ct = default)
        {
            var result = new List<PluginExecutionEntry>();
            if (string.IsNullOrEmpty(_baseLogDir) || !Directory.Exists(_baseLogDir)) return result;

            try
            {
                var now = DateTime.Now.Date;
                var dayDirs = Enumerable.Range(0, Math.Max(1, lastDays))
                    .Select(i => now.AddDays(-i).ToString("yyyyMMdd"))
                    .ToHashSet(StringComparer.Ordinal);

                var files = new List<string>();
                foreach (var day in dayDirs)
                {
                    var dir = Path.Combine(_baseLogDir, day);
                    if (Directory.Exists(dir))
                    {
                        try
                        {
                            files.AddRange(Directory.GetFiles(dir, "*.json"));
                        }
                        catch (Exception ex)
                        {
                            Debug.WriteLine($"[PluginExecutionLogService] 列举 {day} 目录失败: {ex.Message}");
                        }
                    }
                }

                foreach (var file in files)
                {
                    ct.ThrowIfCancellationRequested();
                    try
                    {
                        var json = await File.ReadAllTextAsync(file, ct).ConfigureAwait(false);
                        if (string.IsNullOrWhiteSpace(json)) continue;
                        var entry = JsonSerializer.Deserialize<PluginExecutionEntry>(json, JsonOptions);
                        if (entry != null) result.Add(entry);
                    }
                    catch (OperationCanceledException) { throw; }
                    catch (Exception ex)
                    {
                        Debug.WriteLine($"[PluginExecutionLogService] 读取日志失败 {file}: {ex.Message}");
                    }
                }

                result = result
                    .OrderByDescending(e => e.StartTime)
                    .Take(Math.Max(1, maxEntries))
                    .ToList();
            }
            catch (OperationCanceledException) { /* swallow */ }
            catch (Exception ex)
            {
                Debug.WriteLine($"[PluginExecutionLogService] GetRecentEntriesAsync 异常: {ex.Message}");
            }

            return await Task.FromResult(result).ConfigureAwait(false);
        }

        /// <summary>
        /// 计算最近 N 天的统计（总执行/成功/失败/超时/平均耗时/失败率 Top / 慢 Top10）。
        /// </summary>
        public async Task<PluginExecutionStatistics> GetStatisticsAsync(int lastDays = 7, CancellationToken ct = default)
        {
            var stats = new PluginExecutionStatistics();
            try
            {
                var entries = await GetRecentEntriesAsync(lastDays, maxEntries: int.MaxValue, ct: ct).ConfigureAwait(false);
                if (entries.Count == 0) return stats;

                stats.TotalExecutions = entries.Count;
                stats.SuccessCount = entries.Count(e => e.Status == PluginExecutionStatus.Success);
                stats.FailedCount = entries.Count(e => e.Status == PluginExecutionStatus.Failed);
                stats.TimeoutCount = entries.Count(e => e.Status == PluginExecutionStatus.Timeout);

                stats.AverageDurationMs = entries.Average(e => (double)Math.Max(0, e.DurationMs));

                stats.FailedByPlugin = entries
                    .Where(e => e.Status == PluginExecutionStatus.Failed || e.Status == PluginExecutionStatus.Timeout)
                    .GroupBy(e => string.IsNullOrEmpty(e.PluginName) ? e.PluginId : e.PluginName)
                    .ToDictionary(g => g.Key, g => g.Count());

                stats.Top10SlowestPlugins = entries
                    .GroupBy(e => string.IsNullOrEmpty(e.PluginName) ? e.PluginId : e.PluginName)
                    .Select(g => new { Name = g.Key, AvgMs = g.Average(x => (double)Math.Max(0, x.DurationMs)) })
                    .OrderByDescending(x => x.AvgMs)
                    .Take(10)
                    .ToDictionary(x => x.Name, x => (int)Math.Round(x.AvgMs));
            }
            catch (OperationCanceledException) { /* swallow */ }
            catch (Exception ex)
            {
                Debug.WriteLine($"[PluginExecutionLogService] GetStatisticsAsync 异常: {ex.Message}");
            }

            return stats;
        }

        /// <summary>
        /// 清空所有日志（带二次确认仍由调用方 MessageBox 处理）。
        /// </summary>
        public Task ClearAllAsync()
        {
            try
            {
                if (!string.IsNullOrEmpty(_baseLogDir) && Directory.Exists(_baseLogDir))
                {
                    Directory.Delete(_baseLogDir, recursive: true);
                    Directory.CreateDirectory(_baseLogDir);
                }
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"[PluginExecutionLogService] ClearAllAsync 失败: {ex.Message}");
            }
            return Task.CompletedTask;
        }

        private static string SanitizeFileName(string name)
        {
            if (string.IsNullOrEmpty(name)) return "unknown";
            var invalid = Path.GetInvalidFileNameChars();
            var sb = new System.Text.StringBuilder(name.Length);
            foreach (var c in name)
            {
                sb.Append(Array.IndexOf(invalid, c) >= 0 ? '_' : c);
            }
            return sb.ToString();
        }
    }
}
