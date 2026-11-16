using NetSecurityScanner.Models;
using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;

namespace NetSecurityScanner.Plugins
{
    /// <summary>
    /// 插件执行结果状态
    /// </summary>
    public enum PluginExecutionStatus
    {
        Success,
        Failed,
        Timeout,
        Cancelled
    }

    /// <summary>
    /// 沙箱化执行结果
    /// </summary>
    public class PluginExecutionResult
    {
        public PluginExecutionStatus Status { get; set; } = PluginExecutionStatus.Failed;
        public List<VulnerabilityResult> Vulnerabilities { get; set; } = new();
        public long DurationMs { get; set; }
        public string? ErrorMessage { get; set; }
        public long MemoryDeltaKb { get; set; }
    }

    /// <summary>
    /// 插件沙箱服务接口
    /// </summary>
    public interface IPluginSandboxService
    {
        /// <summary>
        /// 在沙箱中安全执行单个插件
        /// </summary>
        Task<PluginExecutionResult> ExecuteSafelyAsync(
            IVulnerabilityScannerPlugin plugin,
            string target,
            int port,
            string serviceType,
            CancellationToken externalCt = default,
            TimeSpan? timeout = null);
    }

    /// <summary>
    /// 默认插件沙箱实现：
    /// - 限制最大并发数（默认 3 个）
    /// - 每个插件单次执行 30s 超时
    /// - 捕获并隔离所有异常
    /// - 监控执行耗时与内存变化
    /// </summary>
    public class PluginSandboxService : IPluginSandboxService
    {
        private readonly SemaphoreSlim _concurrencyLimiter;
        private static readonly TimeSpan DefaultTimeout = TimeSpan.FromSeconds(30);

        public PluginSandboxService(int maxConcurrency = 3)
        {
            int n = Math.Max(1, maxConcurrency);
            _concurrencyLimiter = new SemaphoreSlim(n, n);
        }

        public async Task<PluginExecutionResult> ExecuteSafelyAsync(
            IVulnerabilityScannerPlugin plugin,
            string target,
            int port,
            string serviceType,
            CancellationToken externalCt = default,
            TimeSpan? timeout = null)
        {
            if (plugin == null)
            {
                return new PluginExecutionResult
                {
                    Status = PluginExecutionStatus.Failed,
                    ErrorMessage = "插件实例为 null"
                };
            }

            var effectiveTimeout = timeout ?? DefaultTimeout;
            var sw = System.Diagnostics.Stopwatch.StartNew();
            long startMemKb = GC.GetTotalMemory(false) / 1024L;
            long endMemKb;

            // 1. 获取并发槽位
            try
            {
                await _concurrencyLimiter.WaitAsync(externalCt);
            }
            catch (OperationCanceledException)
            {
                return new PluginExecutionResult
                {
                    Status = PluginExecutionStatus.Cancelled,
                    DurationMs = sw.ElapsedMilliseconds,
                    ErrorMessage = "等待并发槽位时被取消"
                };
            }
            catch (Exception ex)
            {
                return new PluginExecutionResult
                {
                    Status = PluginExecutionStatus.Failed,
                    DurationMs = sw.ElapsedMilliseconds,
                    ErrorMessage = $"获取并发槽位失败: {ex.Message}"
                };
            }

            _ = true; // slot acquired

            // 2. 创建 30s 超时 CTS + 链接外部 ct
            using var timeoutCts = new CancellationTokenSource(effectiveTimeout);
            using var linkedCts = CancellationTokenSource.CreateLinkedTokenSource(externalCt, timeoutCts.Token);

            try
            {
                var context = new ScanContext
                {
                    Target = target ?? string.Empty,
                    Port = port,
                    ServiceName = serviceType ?? string.Empty,
                    Timeout = (int)effectiveTimeout.TotalMilliseconds
                };

                // 3. 执行扫描（使用真实接口签名）
                var result = await plugin.ScanAsync(context, linkedCts.Token);

                sw.Stop();
                endMemKb = GC.GetTotalMemory(false) / 1024L;

                return new PluginExecutionResult
                {
                    Status = PluginExecutionStatus.Success,
                    Vulnerabilities = result ?? new List<VulnerabilityResult>(),
                    DurationMs = sw.ElapsedMilliseconds,
                    MemoryDeltaKb = Math.Max(0, endMemKb - startMemKb)
                };
            }
            catch (OperationCanceledException) when (timeoutCts.IsCancellationRequested)
            {
                sw.Stop();
                endMemKb = GC.GetTotalMemory(false) / 1024L;
                return new PluginExecutionResult
                {
                    Status = PluginExecutionStatus.Timeout,
                    DurationMs = sw.ElapsedMilliseconds,
                    MemoryDeltaKb = Math.Max(0, endMemKb - startMemKb),
                    ErrorMessage = "执行超时"
                };
            }
            catch (OperationCanceledException)
            {
                sw.Stop();
                endMemKb = GC.GetTotalMemory(false) / 1024L;
                return new PluginExecutionResult
                {
                    Status = PluginExecutionStatus.Cancelled,
                    DurationMs = sw.ElapsedMilliseconds,
                    MemoryDeltaKb = Math.Max(0, endMemKb - startMemKb),
                    ErrorMessage = "执行被取消"
                };
            }
            catch (Exception ex)
            {
                sw.Stop();
                endMemKb = GC.GetTotalMemory(false) / 1024L;
                return new PluginExecutionResult
                {
                    Status = PluginExecutionStatus.Failed,
                    DurationMs = sw.ElapsedMilliseconds,
                    MemoryDeltaKb = Math.Max(0, endMemKb - startMemKb),
                    ErrorMessage = ex.Message
                };
            }
            finally
            {
                try
                {
                    _concurrencyLimiter.Release();
                }
                catch
                {
                    // 静默忽略释放异常
                }
            }
        }
    }
}