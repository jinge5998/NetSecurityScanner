using NetSecurityScanner.Models;
using NetSecurityScanner.Plugins;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;

namespace NetSecurityScanner.Services
{
    /// <summary>
    /// 插件统一编排器（v5-T1）。
    /// 目标：
    /// 1. 进程内单例：避免重复加载插件 DLL / 重复初始化沙箱 / 重复构建日志服务。
    /// 2. 对外暴露稳定的"扫描入口"API（单目标 / 批量 / 深挖历史 / 试运行）。
    /// 3. 内部仍复用 PluginManager 的"沙箱 + 日志"链路。
    ///
    /// 注意：
    /// - 本类不直接调用 _sandbox / _logger，所有真实执行委托给 PluginManager。
    /// - 本类不修改 PluginManager 的任何已有方法签名，最大限度保持兼容。
    /// </summary>
    public class PluginOrchestrator : IPluginOrchestrator
    {
        private static readonly Lazy<PluginOrchestrator> _instance =
            new Lazy<PluginOrchestrator>(() => new PluginOrchestrator(), isThreadSafe: true);

        /// <summary>
        /// 全局唯一实例。
        /// </summary>
        public static PluginOrchestrator Instance => _instance.Value;

        private readonly PluginManager _manager;
        private readonly PluginSandboxService _sandbox;
        private readonly PluginExecutionLogService _logger;
        private readonly SemaphoreSlim _initLock = new SemaphoreSlim(1, 1);
        private bool _initialized = false;

        public PluginOrchestrator()
        {
            _sandbox = new PluginSandboxService(new PluginSecurityService());
            _logger = new PluginExecutionLogService();
            // PluginManager 当前版本无接受 sandbox/logger 的构造函数，沙箱与日志的注入由 PluginManager 内部自行管理。
            // 此处仍持有沙箱与日志实例，便于将来切换为注入式。
            _manager = new PluginManager();
        }

        /// <summary>
        /// 异步初始化（线程安全，可被多次调用，仅首次生效）。
        /// 内部触发 PluginManager.LoadAllPluginsAsync（已包含内置 + 外部 DLL 加载）。
        /// </summary>
        public async Task InitializeAsync(CancellationToken ct = default)
        {
            if (_initialized) return;

            await _initLock.WaitAsync(ct).ConfigureAwait(false);
            try
            {
                if (_initialized) return;

                // PluginManager.LoadAllPluginsAsync 当前签名无 ct，使用 ConfigureAwait 保持一致
                await _manager.LoadAllPluginsAsync().ConfigureAwait(false);

                _initialized = true;
            }
            finally
            {
                try { _initLock.Release(); } catch { /* 静默 */ }
            }
        }

        /// <summary>
        /// 是否已完成初始化。
        /// </summary>
        public bool IsInitialized => _initialized;

        /// <summary>
        /// 当前已加载插件数量。
        /// </summary>
        public int LoadedPluginCount
        {
            get
            {
                try
                {
                    return _manager?.Plugins?.Count ?? 0;
                }
                catch
                {
                    return 0;
                }
            }
        }

        /// <summary>
        /// 当前已加载的插件元数据（用于 UI 展示）。
        /// </summary>
        public IReadOnlyDictionary<string, IVulnerabilityScannerPlugin> LoadedPlugins
        {
            get
            {
                if (_manager?.Plugins == null) return new Dictionary<string, IVulnerabilityScannerPlugin>();
                return _manager.Plugins;
            }
        }

        /// <summary>
        /// 单目标扫描（带已启用插件 + 沙箱 + 自动日志）。
        /// v7：透传 traceId（如果调用方有现成的 Trace 上下文）。
        /// </summary>
        /// <param name="targetIp">目标 IP</param>
        /// <param name="ports">开放端口列表</param>
        /// <param name="selectedPluginIds">预留：插件过滤（PluginManager 当前未支持，后续扩展）</param>
        /// <param name="ct">取消令牌（PluginManager 当前未透传，保留给后续扩展）</param>
        /// <param name="traceId">v7：调用链 TraceId（可选，传入则透传到 PluginManager 子 Span）</param>
        public async Task<List<VulnerabilityResult>> ScanTargetAsync(
            string targetIp,
            List<int> ports,
            IEnumerable<string>? selectedPluginIds = null,
            CancellationToken ct = default,
            string? traceId = null)
        {
            if (!_initialized)
            {
                await InitializeAsync(ct).ConfigureAwait(false);
            }

            if (string.IsNullOrWhiteSpace(targetIp))
            {
                return new List<VulnerabilityResult>();
            }

            var openPorts = ports ?? new List<int>();
            if (openPorts.Count == 0)
            {
                return new List<VulnerabilityResult>();
            }

            // selectedPluginIds 当前作为预留：PluginManager.ScanWithPluginsForTargetAsync
            // 暂未实现按 ID 过滤，会扫描所有已启用插件。
            // 透传时如果需要可由 UI 层在调用前先禁用未选插件（PluginManager.DisablePluginAsync）。
            _ = selectedPluginIds;

            // v6：调用前先经 PluginGovernor 校验（黑/白名单 + 隔离列表）
            try
            {
                var governor = PluginGovernor.Instance;
                if (governor.IsInitialized)
                {
                    if (selectedPluginIds != null)
                    {
                        foreach (var pid in selectedPluginIds)
                        {
                            var v = governor.ValidateScanRequest(pid, targetIp, openPorts);
                            if (!v.Allowed) return new List<VulnerabilityResult>();
                        }
                    }
                }
            }
            catch { /* Governor 未就绪时降级放行 */ }

            // v7：如果没传 traceId，则从 Governor.Telemetry 新开一个根 Trace
            string actualTraceId = traceId ?? string.Empty;
            if (string.IsNullOrEmpty(actualTraceId))
            {
                try
                {
                    var governor = PluginGovernor.Instance;
                    if (governor.IsInitialized)
                    {
                        var (tid, _) = governor.Telemetry.BeginTrace($"orchestrator::{targetIp}", targetIp);
                        actualTraceId = tid;
                    }
                }
                catch { actualTraceId = Guid.NewGuid().ToString("N"); }
            }

            return await _manager
                .ScanWithPluginsForTargetAsync(targetIp, openPorts, null, actualTraceId)
                .ConfigureAwait(false);
        }

        /// <summary>
        /// 深挖历史目标：从 ScanHistoryItem 抽取 IP + 端口，调用 ScanTargetAsync。
        /// ScanHistoryItem 中端口来源：PortScanResults[].PortNumber。
        /// </summary>
        public async Task<List<VulnerabilityResult>> DeepScanAsync(
            ScanHistoryItem history,
            CancellationToken ct = default)
        {
            if (history == null) return new List<VulnerabilityResult>();

            List<int> ports;
            try
            {
                ports = history.PortScanResults?
                    .Where(p => p != null)
                    .Select(p => p.PortNumber)
                    .Where(p => p > 0 && p <= 65535)
                    .Distinct()
                    .ToList() ?? new List<int>();
            }
            catch
            {
                ports = new List<int>();
            }

            if (ports.Count == 0)
            {
                // 退化：使用 OpenPortsCount 占位（无法拿到具体端口，至少跑一次 80 端口）
                ports = new List<int> { 80 };
            }

            return await ScanTargetAsync(history.TargetIp, ports, null, ct).ConfigureAwait(false);
        }

        /// <summary>
        /// 试运行市场插件：不真正调用网络，仅根据市场插件元数据生成模拟结果。
        /// 用于"先看效果，再决定是否安装"的体验流。
        /// </summary>
        public List<VulnerabilityResult> TryRunAsync(PluginMarketPlugin marketPlugin)
        {
            var results = new List<VulnerabilityResult>();
            if (marketPlugin == null) return results;

            // 用 Id + Name 的哈希做种子，确保同一插件多次试运行结果稳定
            int seed = 0;
            if (!string.IsNullOrEmpty(marketPlugin.Id)) seed ^= marketPlugin.Id.GetHashCode();
            if (!string.IsNullOrEmpty(marketPlugin.Name)) seed ^= marketPlugin.Name.GetHashCode();
            if (seed == 0) seed = (int)DateTime.Now.Ticks;

            var rand = new Random(seed);
            int count = rand.Next(0, 4); // 0..3 条模拟结果
            var category = string.IsNullOrWhiteSpace(marketPlugin.Category) ? "通用" : marketPlugin.Category;

            for (int i = 0; i < count; i++)
            {
                results.Add(new VulnerabilityResult
                {
                    Id = i + 1,
                    Name = $"[试运行] {marketPlugin.Name} - 模拟结果 {i + 1}",
                    Description = $"这是 {marketPlugin.Name}（{category}）的模拟运行结果，未实际调用网络，仅供预览插件能力。",
                    CveId = $"DEMO-{marketPlugin.Id}-{i + 1}",
                    RiskLevel = i == 0 ? "高危" : "中危",
                    Port = rand.Next(20, 10000),
                    Service = category,
                    Solution = "请先安装插件后进行真实扫描",
                    Target = string.Empty,
                    PluginId = marketPlugin.Id,
                    PluginName = marketPlugin.Name
                });
            }

            return results;
        }

        /// <summary>
        /// v5-T3: 试运行 Plugin（PluginMarketService 返回的 Models.Plugin）。
        /// Plugin.Category 是 PluginCategory 枚举，会转成中文字符串用于模拟结果展示。
        /// </summary>
        public List<VulnerabilityResult> TryRunAsync(Plugin plugin)
        {
            var results = new List<VulnerabilityResult>();
            if (plugin == null) return results;

            int seed = 0;
            if (!string.IsNullOrEmpty(plugin.Id)) seed ^= plugin.Id.GetHashCode();
            if (!string.IsNullOrEmpty(plugin.Name)) seed ^= plugin.Name.GetHashCode();
            if (seed == 0) seed = (int)DateTime.Now.Ticks;

            var rand = new Random(seed);
            int count = rand.Next(0, 4);
            var category = plugin.Category.ToString();

            // 按类别做更有针对性的"模拟演示"
            for (int i = 0; i < count; i++)
            {
                string risk = i == 0 ? "高危" : "中危";
                string service = category;
                string demoNote = plugin.Description?.Length > 30
                    ? plugin.Description.Substring(0, 30) + "..."
                    : plugin.Description ?? string.Empty;

                results.Add(new VulnerabilityResult
                {
                    Id = i + 1,
                    Name = $"[试运行] {plugin.Name} - 模拟{i + 1}",
                    Description = $"这是 {plugin.Name}（{category}）的模拟结果。\n插件能力：{demoNote}\n未实际调用网络，仅用于预览。",
                    CveId = $"DEMO-{plugin.Id}-{i + 1}",
                    RiskLevel = risk,
                    Port = rand.Next(20, 10000),
                    Service = service,
                    Solution = "请先安装插件后进行真实扫描",
                    Target = string.Empty,
                    PluginId = plugin.Id,
                    PluginName = plugin.Name
                });
            }

            return results;
        }

        /// <summary>
        /// 批量扫描：依次对每个 (ip, ports) 调用 ScanTargetAsync，并汇报进度。
        /// </summary>
        public async Task<List<VulnerabilityResult>> ScanBatchAsync(
            List<(string ip, List<int> ports)> targets,
            IProgress<(int current, int total, string ip)>? progress = null,
            CancellationToken ct = default)
        {
            var all = new List<VulnerabilityResult>();
            if (targets == null || targets.Count == 0) return all;

            if (!_initialized)
            {
                await InitializeAsync(ct).ConfigureAwait(false);
            }

            for (int i = 0; i < targets.Count; i++)
            {
                ct.ThrowIfCancellationRequested();

                var (ip, ports) = targets[i];
                progress?.Report((i + 1, targets.Count, ip));

                try
                {
                    var r = await ScanTargetAsync(ip, ports, null, ct).ConfigureAwait(false);
                    all.AddRange(r);
                }
                catch (OperationCanceledException)
                {
                    throw;
                }
                catch (Exception ex)
                {
                    System.Diagnostics.Debug.WriteLine($"[PluginOrchestrator] 批量扫描 {ip} 失败: {ex.Message}");
                }
            }

            progress?.Report((targets.Count, targets.Count, string.Empty));
            return all;
        }
    }
}