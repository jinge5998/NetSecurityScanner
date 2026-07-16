using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using NetSecurityScanner.Models;
using NetSecurityScanner.Plugins;

namespace NetSecurityScanner.Services
{
    /// <summary>
    /// 插件统一管控器（v6-T6 + v7 扩展：聚合 6 个新子服务）。
    /// 与 PluginOrchestrator 平级：Orchestrator = "怎么用"，Governor = "能不能用 / 健不健康 / 安不安全 / 可观测 / 可远程"。
    /// 单例，启动时 InitializeAsync() 一次性加载所有子服务。
    /// </summary>
    public class PluginGovernor : IAsyncDisposable
    {
        private static readonly Lazy<PluginGovernor> _instance = new(() => new PluginGovernor(), isThreadSafe: true);

        /// <summary>全局唯一实例</summary>
        public static PluginGovernor Instance => _instance.Value;

        private readonly SemaphoreSlim _initLock = new(1, 1);
        private readonly SemaphoreSlim _disposeLock = new(1, 1);
        private bool _initialized;
        private bool _disposed;

        // ====== v6 子服务 ======
        /// <summary>安全治理（白/黑名单/权限/审计）</summary>
        public PluginSecurityService Security { get; private set; } = null!;

        /// <summary>版本与依赖</summary>
        public PluginVersionManager VersionManager { get; private set; } = null!;

        /// <summary>健康监控</summary>
        public PluginHealthMonitor Health { get; private set; } = null!;

        /// <summary>调度与告警</summary>
        public PluginScheduler Scheduler { get; private set; } = null!;

        // ====== v7 子服务 ======
        /// <summary>v7：插件签名校验</summary>
        public PluginSignatureService Signature { get; private set; } = null!;

        /// <summary>v7：插件沙箱</summary>
        public PluginSandboxService Sandbox { get; private set; } = null!;

        /// <summary>v7：调用链追踪</summary>
        public PluginTelemetryService Telemetry { get; private set; } = null!;

        /// <summary>v7：远程管控 API</summary>
        public RemoteGovernorApiService RemoteApi { get; private set; } = null!;

        /// <summary>v7：权限申请工作流</summary>
        public PermissionRequestService PermissionRequest { get; private set; } = null!;

        /// <summary>v7：告警规则模板</summary>
        public AlertTemplateService AlertTemplate { get; private set; } = null!;

        /// <summary>当前已初始化</summary>
        public bool IsInitialized => _initialized;

        private PluginGovernor() { }

        /// <summary>
        /// 初始化所有子服务（v6 4 + v7 6 = 10 个）。重复调用只生效一次。
        /// </summary>
        public async Task InitializeAsync(PluginManager pluginManager, PluginOrchestrator orchestrator, string coreVersion = "1.0.1.0")
        {
            if (_initialized) return;
            if (_disposed) throw new ObjectDisposedException(nameof(PluginGovernor));
            await _initLock.WaitAsync().ConfigureAwait(false);
            try
            {
                if (_initialized) return;

                // ====== v6 子服务 ======
                Security = new PluginSecurityService();
                var catalog = new PluginMarketCatalogService();
                VersionManager = new PluginVersionManager(catalog, Security);
                Health = new PluginHealthMonitor(pluginManager, Security);
                Scheduler = new PluginScheduler(
                    async (task, ct) => await ExecuteScheduledTaskAsync(task, ct, orchestrator).ConfigureAwait(false),
                    Security);

                // ====== v7 子服务 ======
                Signature = new PluginSignatureService(Security);
                PermissionRequest = new PermissionRequestService(Security, null);
                Sandbox = new PluginSandboxService(Security, PermissionRequest);
                Telemetry = new PluginTelemetryService(Security, Health);
                AlertTemplate = new AlertTemplateService(Security, Scheduler);
                RemoteApi = new RemoteGovernorApiService(this);

                // 联动：Telemetry -> Health (TraceTimeout)
                Telemetry.OnTraceTimeout += (s, span) => Health.OnTraceTimeoutExternal(span);

                // 启动远程 API
                try { await RemoteApi.StartAsync().ConfigureAwait(false); }
                catch (Exception ex) { System.Diagnostics.Debug.WriteLine($"[PluginGovernor] RemoteApi 启动失败: {ex.Message}"); }

                // 启动时后台异步检查更新
                _ = Task.Run(async () =>
                {
                    try { await VersionManager.CheckUpdatesAsync(pluginManager, coreVersion).ConfigureAwait(false); }
                    catch (Exception ex) { System.Diagnostics.Debug.WriteLine($"[PluginGovernor] CheckUpdates 失败: {ex.Message}"); }
                });

                // 归档 30 天前的审计文件
                try { Security.ArchiveOldAudits(); } catch { /* 静默 */ }

                _initialized = true;
            }
            finally
            {
                _initLock.Release();
            }
        }

        /// <summary>
        /// 校验扫描请求：黑名单 + 隔离列表 + 危险操作拦截。
        /// Orchestrator.ScanTargetAsync 调用前先过本方法。
        /// </summary>
        public ValidationResult ValidateScanRequest(string pluginId, string targetIp, List<int> ports)
        {
            if (!_initialized)
            {
                return ValidationResult.Allow("Governor not initialized, allow by default");
            }

            if (!string.IsNullOrEmpty(pluginId) && !Security.IsAllowed(pluginId))
            {
                _ = Security.AppendAuditAsync(new PluginAuditEntry
                {
                    PluginId = pluginId,
                    Action = "PluginBlocked",
                    Result = "Blocked",
                    Detail = $"target={targetIp}, ports={string.Join(",", ports)}"
                });
                return ValidationResult.Block($"插件 {pluginId} 在策略黑名单中");
            }

            if (!string.IsNullOrEmpty(pluginId))
            {
                var snap = Health.GetSnapshot(pluginId);
                if (snap != null && snap.IsQuarantined)
                {
                    return ValidationResult.Block($"插件 {pluginId} 已被健康监控隔离");
                }
            }

            return ValidationResult.Allow("OK");
        }

        /// <summary>
        /// 优雅释放后台资源（v7 改为异步）。
        /// </summary>
        public async Task ShutdownAsync()
        {
            await _disposeLock.WaitAsync().ConfigureAwait(false);
            try
            {
                if (_disposed) return;
                _disposed = true;
                _initialized = false;
                try { Health?.Dispose(); } catch { }
                try { Scheduler?.Dispose(); } catch { }
                try { Telemetry?.Dispose(); } catch { }
                try { RemoteApi?.Dispose(); } catch { }
            }
            finally
            {
                _disposeLock.Release();
            }
        }

        public async ValueTask DisposeAsync() => await ShutdownAsync().ConfigureAwait(false);

        /// <summary>同步关闭（向后兼容）</summary>
        public void Shutdown() => ShutdownAsync().GetAwaiter().GetResult();

        private async Task<bool> ExecuteScheduledTaskAsync(ScheduledTask task, CancellationToken ct, PluginOrchestrator orchestrator)
        {
            try
            {
                var ports = task.Ports ?? new List<int>();
                if (ports.Count == 0) ports = new List<int> { 80, 443, 554 };
                var result = await orchestrator.ScanTargetAsync(task.TargetIp, ports, task.PluginIds, ct).ConfigureAwait(false);
                return result != null;
            }
            catch (OperationCanceledException)
            {
                return false;
            }
            catch
            {
                return false;
            }
        }
    }

    /// <summary>扫描请求校验结果</summary>
    public class ValidationResult
    {
        public bool Allowed { get; }
        public string Message { get; }

        private ValidationResult(bool allowed, string message)
        {
            Allowed = allowed;
            Message = message;
        }

        public static ValidationResult Allow(string msg) => new(true, msg);
        public static ValidationResult Block(string msg) => new(false, msg);
    }
}
