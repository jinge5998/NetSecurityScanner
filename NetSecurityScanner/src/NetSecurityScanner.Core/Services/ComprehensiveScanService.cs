using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;
using NetSecurityScanner.Models;
using NetSecurityScanner.Services;

namespace NetSecurityScanner.Services;

/// <summary>
/// 综合扫描可重用服务（v1.0.1.3 引入，替代 MainWindow.ExecuteComprehensiveScanAsync 的 230 行编排）。
/// <para>按 6 阶段串行执行：主机存活探测 → TCP+UDP 端口扫描(并发) → 服务识别 → 漏洞扫描 → 插件扫描 → 风险汇总。</para>
/// <para>任一阶段异常被 try/catch 隔离，不阻断后续阶段，最终 ComprehensiveScanResult 仍返回。</para>
/// </summary>
public class ComprehensiveScanService
{
    private readonly IPortScanner _portScanner;
    private readonly IVulnerabilityScanner _vulnerabilityScanner;
    private readonly IJsonDatabaseService _jsonDatabaseService;
    private readonly IPluginOrchestrator _pluginOrchestrator;
    private readonly Action<string>? _logger;

    public ComprehensiveScanService(
        IPortScanner? portScanner = null,
        IVulnerabilityScanner? vulnerabilityScanner = null,
        IJsonDatabaseService? jsonDatabaseService = null,
        IPluginOrchestrator? pluginOrchestrator = null,
        Action<string>? logger = null)
    {
        _portScanner = portScanner ?? new PortScanner();
        _vulnerabilityScanner = vulnerabilityScanner ?? new VulnerabilityScanner();
        _jsonDatabaseService = jsonDatabaseService ?? new JsonDatabaseService();
        _pluginOrchestrator = pluginOrchestrator ?? PluginOrchestrator.Instance;
        _logger = logger;
    }

    /// <summary>
    /// 综合扫描可重用服务（v1.0.1.3 引入，替代 MainWindow.ExecuteComprehensiveScanAsync 的 230 行编排）。
    /// <para>按 6 阶段串行执行：主机存活探测 → TCP+UDP 端口扫描(并发) → 服务识别 → 漏洞扫描 → 插件扫描 → 风险汇总。</para>
    /// <para>任一阶段异常被 try/catch 隔离，不阻断后续阶段，最终 ComprehensiveScanResult 仍返回。</para>
    /// </summary>
    [Obsolete("请使用 (IPortScanner?, IVulnerabilityScanner?, IJsonDatabaseService?, IPluginOrchestrator?, Action<string>?) 构造")]
    public ComprehensiveScanService(
        PortScanner? portScanner,
        VulnerabilityScanner? vulnerabilityScanner,
        RiskAssessmentService? riskAssessmentService,
        JsonDatabaseService? jsonDatabaseService,
        PluginOrchestrator? pluginOrchestrator,
        Action<string>? logger)
        : this(portScanner, vulnerabilityScanner, jsonDatabaseService, pluginOrchestrator, logger)
    {
        // riskAssessmentService 参数保留以兼容旧调用方，实际未使用
    }

    /// <summary>
    /// 执行综合扫描（v1.0.1.3 唯一对外入口）
    /// </summary>
    public async Task<ComprehensiveScanResult> ExecuteAsync(
        ComprehensiveScanOptions options,
        IProgress<ScanPhaseProgress>? progress = null,
        CancellationToken cancellationToken = default)
    {
        if (options == null) throw new ArgumentNullException(nameof(options));
        if (string.IsNullOrWhiteSpace(options.TargetIp))
            throw new ArgumentException("TargetIp 不能为空", nameof(options));

        var overallSw = Stopwatch.StartNew();
        var scanId = $"COMPREHENSIVE_{DateTime.Now:yyyyMMdd_HHmmss}";
        var result = new ComprehensiveScanResult
        {
            ScanId = scanId,
            TargetIp = options.TargetIp,
            ScanTime = DateTime.Now,
            AllPortResults = new List<PortScanResult>(),
            VulnerabilityResults = new List<VulnerabilityResult>(),
            PluginResults = new List<VulnerabilityResult>(),
            Phases = new List<ScanPhaseExecution>()
        };

        Log($"[综合扫描 {scanId}] 开始: {options.TargetIp}, 预设={options.Preset}");

        try
        {
            // 解析端口列表
            var ports = options.Preset == ScanPreset.Custom
                ? ScanPresetRegistry.ParsePortList(options.CustomPorts)
                : ScanPresetRegistry.GetPorts(options.Preset).ToList();
            Log($"[综合扫描 {scanId}] 端口数: {ports.Count}, 协议: TCP={options.EnableTcp}, UDP={options.EnableUdp}, 漏洞={options.EnableVulnScan}, 插件={options.EnablePluginScan}");

            // 阶段 1：主机存活探测
            var hostPhase = StartPhase(result, ScanPhase.HostDiscovery, "主机存活探测");
            try
            {
                result.HostAlive = await HostDiscoveryAsync(options.TargetIp, options.HostDiscoveryTimeoutMs, cancellationToken);
                CompletePhase(hostPhase, ScanPhaseStatus.Success, outputCount: result.HostAlive ? 1 : 0);
                ReportProgress(progress, ScanPhase.HostDiscovery, "主机存活探测", 100, result.HostAlive ? "主机存活" : "主机不可达（仍继续）", 0, overallSw);
            }
            catch (Exception ex)
            {
                FailPhase(hostPhase, ex);
                result.HostAlive = false;
                ReportProgress(progress, ScanPhase.HostDiscovery, "主机存活探测", 100, $"失败: {ex.Message}", 0, overallSw);
            }

            if (cancellationToken.IsCancellationRequested)
            {
                result.Cancelled = true;
                FinalizeResult(result, overallSw, "无风险");
                if (options.SaveToHistory) await TrySaveHistoryAsync(result);
                return result;
            }

            // 阶段 2 + 3：TCP+UDP 端口扫描（并发）
            if (options.EnableTcp || options.EnableUdp)
            {
                await RunPortScansAsync(options, ports, result, progress, overallSw, cancellationToken);
            }
            else
            {
                // 用户禁用所有端口扫描
                var tcpPhase = StartPhase(result, ScanPhase.TcpPortScan, "TCP 端口扫描");
                var udpPhase = StartPhase(result, ScanPhase.UdpPortScan, "UDP 端口扫描");
                CompletePhase(tcpPhase, ScanPhaseStatus.Skipped, 0);
                CompletePhase(udpPhase, ScanPhaseStatus.Skipped, 0);
            }

            if (cancellationToken.IsCancellationRequested)
            {
                result.Cancelled = true;
                FinalizeResult(result, overallSw, "无风险");
                if (options.SaveToHistory) await TrySaveHistoryAsync(result);
                return result;
            }

            // 阶段 4：服务识别（从 PortScanner 已返回的 Service/Version 字段汇总）
            var servicePhase = StartPhase(result, ScanPhase.ServiceDetection, "服务版本识别");
            try
            {
                int serviceCount = result.AllPortResults.Count(r => !string.IsNullOrEmpty(r.Service));
                CompletePhase(servicePhase, ScanPhaseStatus.Success, outputCount: serviceCount);
                ReportProgress(progress, ScanPhase.ServiceDetection, "服务版本识别", 100, $"识别 {serviceCount} 个服务", result.AllPortResults.Count, overallSw);
            }
            catch (Exception ex)
            {
                FailPhase(servicePhase, ex);
            }

            // 阶段 5：漏洞扫描（仅当有开放端口时）
            if (options.EnableVulnScan && result.OpenPortsCount > 0)
            {
                await RunVulnerabilityScanAsync(options, result, progress, overallSw, cancellationToken);
            }
            else
            {
                var vulnPhase = StartPhase(result, ScanPhase.VulnerabilityScan, "漏洞扫描");
                var reason = !options.EnableVulnScan ? "用户禁用" : "无开放端口，跳过";
                CompletePhase(vulnPhase, ScanPhaseStatus.Skipped, 0);
                ReportProgress(progress, ScanPhase.VulnerabilityScan, "漏洞扫描", 100, reason, result.AllPortResults.Count, overallSw);
            }

            // 阶段 6：插件扫描（仅当有开放端口时）
            if (options.EnablePluginScan && result.OpenPortsCount > 0)
            {
                await RunPluginScanAsync(options, result, progress, overallSw, cancellationToken);
            }
            else
            {
                var pluginPhase = StartPhase(result, ScanPhase.PluginScan, "插件扫描");
                var reason = !options.EnablePluginScan ? "用户禁用" : "无开放端口，跳过";
                CompletePhase(pluginPhase, ScanPhaseStatus.Skipped, 0);
                ReportProgress(progress, ScanPhase.PluginScan, "插件扫描", 100, reason, result.AllPortResults.Count, overallSw);
            }

            // 阶段 7：风险汇总 + 保存
            var riskPhase = StartPhase(result, ScanPhase.RiskAssessment, "风险等级汇总");
            try
            {
                var riskLevel = CalculateRiskLevel(result.VulnerabilityResults.Concat(result.PluginResults).ToList());
                result.RiskLevel = riskLevel;
                CompletePhase(riskPhase, ScanPhaseStatus.Success, outputCount: 1);
                ReportProgress(progress, ScanPhase.RiskAssessment, "风险等级汇总", 100, $"风险等级: {riskLevel}", result.OpenPortsCount, overallSw);
            }
            catch (Exception ex)
            {
                FailPhase(riskPhase, ex);
                result.RiskLevel = "未知";
            }

            FinalizeResult(result, overallSw, result.RiskLevel);
        }
        catch (OperationCanceledException)
        {
            result.Cancelled = true;
            Log($"[综合扫描 {scanId}] 用户取消");
            FinalizeResult(result, overallSw, "无风险");
        }
        catch (Exception ex)
        {
            Log($"[综合扫描 {scanId}] 顶层异常: {ex.Message}");
            // 顶层异常记录到风险汇总阶段
            var lastPhase = result.Phases.LastOrDefault();
            if (lastPhase != null && lastPhase.Status == ScanPhaseStatus.Running)
            {
                FailPhase(lastPhase, ex);
            }
            result.RiskLevel = "未知";
            FinalizeResult(result, overallSw, "未知");
        }

        if (options.SaveToHistory)
        {
            await TrySaveHistoryAsync(result);
        }

        return result;
    }

    #region 阶段实现

    private async Task<bool> HostDiscoveryAsync(string target, int timeoutMs, CancellationToken ct)
    {
        // 阶段 1：先 ICMP ping，超时则回退到 TCP 80/443
        try
        {
            using var ping = new Ping();
            var reply = await ping.SendPingAsync(target, timeoutMs);
            if (reply.Status == IPStatus.Success) return true;
        }
        catch
        {
            // ICMP 被防火墙拦截，继续 TCP 回退
        }

        // 回退：尝试 TCP connect 80 和 443
        foreach (var port in new[] { 80, 443 })
        {
            try
            {
                using var client = new TcpClient();
                var connectTask = client.ConnectAsync(target, port);
                var timeoutTask = Task.Delay(timeoutMs, ct);
                var completed = await Task.WhenAny(connectTask, timeoutTask);
                if (completed == connectTask && client.Connected)
                {
                    client.Close();
                    return true;
                }
            }
            catch
            {
                // 继续尝试下一个端口
            }
        }

        return false;
    }

    private async Task RunPortScansAsync(
        ComprehensiveScanOptions options,
        List<int> ports,
        ComprehensiveScanResult result,
        IProgress<ScanPhaseProgress>? progress,
        Stopwatch overallSw,
        CancellationToken cancellationToken)
    {
        // 创建两个独立的 PhaseExecution 用于记录
        var tcpPhase = StartPhase(result, ScanPhase.TcpPortScan, "TCP 端口扫描");
        var udpPhase = StartPhase(result, ScanPhase.UdpPortScan, "UDP 端口扫描");

        var tcpProgress = new Progress<int>(p =>
        {
            // TCP 占总体进度的 5-35%
            int overall = 5 + p * 30 / 100;
            ReportProgress(progress, ScanPhase.TcpPortScan, "TCP 端口扫描", p, $"扫描端口 {p}%", result.AllPortResults.Count, overallSw, overallProgress: overall);
        });

        var udpProgress = new Progress<int>(p =>
        {
            // UDP 占总体进度的 35-65%
            int overall = 35 + p * 30 / 100;
            ReportProgress(progress, ScanPhase.UdpPortScan, "UDP 端口扫描", p, $"扫描端口 {p}%", result.AllPortResults.Count, overallSw, overallProgress: overall);
        });

        var tcpBag = new ConcurrentBag<PortScanResult>();
        var udpBag = new ConcurrentBag<PortScanResult>();

        var tcpTask = options.EnableTcp
            ? _portScanner.ScanTcpPortsAsync(options.TargetIp, ports, tcpProgress, cancellationToken)
            : Task.FromResult(new List<PortScanResult>());

        var udpTask = options.EnableUdp
            ? _portScanner.ScanUdpPortsAsync(options.TargetIp, ports, udpProgress, cancellationToken)
            : Task.FromResult(new List<PortScanResult>());

        try
        {
            var tcpResults = await tcpTask;
            var udpResults = await udpTask;
            foreach (var r in tcpResults) tcpBag.Add(r);
            foreach (var r in udpResults) udpBag.Add(r);

            result.AllPortResults.AddRange(tcpBag);
            result.AllPortResults.AddRange(udpBag);
            result.TcpOpenPorts = tcpBag.Count(r => r.Status == "开放");
            result.UdpOpenPorts = udpBag.Count(r => r.Status == "开放");

            if (options.EnableTcp) CompletePhase(tcpPhase, ScanPhaseStatus.Success, outputCount: tcpBag.Count);
            else { tcpPhase.Status = ScanPhaseStatus.Skipped; tcpPhase.EndTime = DateTime.Now; }
            if (options.EnableUdp) CompletePhase(udpPhase, ScanPhaseStatus.Success, outputCount: udpBag.Count);
            else { udpPhase.Status = ScanPhaseStatus.Skipped; udpPhase.EndTime = DateTime.Now; }

            Log($"[综合扫描 {result.ScanId}] 端口扫描完成: TCP 开放 {result.TcpOpenPorts} / UDP 开放 {result.UdpOpenPorts}");
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (Exception ex)
        {
            // TCP/UDP 扫描异常时，记录所有已收到的结果
            foreach (var r in tcpBag) result.AllPortResults.Add(r);
            foreach (var r in udpBag) result.AllPortResults.Add(r);
            result.TcpOpenPorts = tcpBag.Count(r => r.Status == "开放");
            result.UdpOpenPorts = udpBag.Count(r => r.Status == "开放");

            if (options.EnableTcp) FailPhase(tcpPhase, ex);
            else { tcpPhase.Status = ScanPhaseStatus.Skipped; tcpPhase.EndTime = DateTime.Now; }
            if (options.EnableUdp) FailPhase(udpPhase, ex);
            else { udpPhase.Status = ScanPhaseStatus.Skipped; udpPhase.EndTime = DateTime.Now; }
            Log($"[综合扫描 {result.ScanId}] 端口扫描异常: {ex.Message}");
        }
    }

    private async Task RunVulnerabilityScanAsync(
        ComprehensiveScanOptions options,
        ComprehensiveScanResult result,
        IProgress<ScanPhaseProgress>? progress,
        Stopwatch overallSw,
        CancellationToken cancellationToken)
    {
        var vulnPhase = StartPhase(result, ScanPhase.VulnerabilityScan, "漏洞扫描");
        try
        {
            var openPorts = result.AllPortResults
                .Where(r => r.Status == "开放")
                .Select(p => new PortInfo
                {
                    PortNumber = p.PortNumber,
                    Protocol = "tcp",
                    Service = p.Service,
                    Version = p.ServiceVersion
                })
                .ToList();

            var vulnProgress = new Progress<(string message, int percentage)>(p =>
            {
                // 漏洞扫描占总体进度的 65-80%
                int overall = 65 + p.percentage * 15 / 100;
                ReportProgress(progress, ScanPhase.VulnerabilityScan, "漏洞扫描", p.percentage, p.message, result.AllPortResults.Count, overallSw, overallProgress: overall);
            });

            var vulns = await _vulnerabilityScanner.ScanAsync(options.TargetIp, openPorts, "standard", vulnProgress, cancellationToken);
            result.VulnerabilityResults.AddRange(vulns);

            CompletePhase(vulnPhase, ScanPhaseStatus.Success, outputCount: vulns.Count);
            Log($"[综合扫描 {result.ScanId}] 漏洞扫描完成: {vulns.Count} 个漏洞");
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (Exception ex)
        {
            result.HasVulnerabilityScanError = true;
            FailPhase(vulnPhase, ex);
            Log($"[综合扫描 {result.ScanId}] 漏洞扫描异常: {ex.Message}");
        }
    }

    private async Task RunPluginScanAsync(
        ComprehensiveScanOptions options,
        ComprehensiveScanResult result,
        IProgress<ScanPhaseProgress>? progress,
        Stopwatch overallSw,
        CancellationToken cancellationToken)
    {
        var pluginPhase = StartPhase(result, ScanPhase.PluginScan, "插件扫描");
        try
        {
            var openPortNumbers = result.AllPortResults
                .Where(r => r.Status == "开放")
                .Select(r => r.PortNumber)
                .Distinct()
                .ToList();

            if (openPortNumbers.Count == 0)
            {
                CompletePhase(pluginPhase, ScanPhaseStatus.Skipped, outputCount: 0);
                return;
            }

            // 插件扫描占总体进度的 80-95%
            var pluginProgress = new Progress<string>(msg =>
            {
                ReportProgress(progress, ScanPhase.PluginScan, "插件扫描", 50, msg, result.AllPortResults.Count, overallSw, overallProgress: 87);
            });

            var pluginResults = await _pluginOrchestrator.ScanTargetAsync(options.TargetIp, openPortNumbers, null, cancellationToken);
            result.PluginResults.AddRange(pluginResults);

            CompletePhase(pluginPhase, ScanPhaseStatus.Success, outputCount: pluginResults.Count);
            Log($"[综合扫描 {result.ScanId}] 插件扫描完成: {pluginResults.Count} 个结果");
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (Exception ex)
        {
            result.HasPluginScanError = true;
            FailPhase(pluginPhase, ex);
            Log($"[综合扫描 {result.ScanId}] 插件扫描异常: {ex.Message}");
        }
    }

    #endregion

    #region 工具方法

    private ScanPhaseExecution StartPhase(ComprehensiveScanResult result, ScanPhase phase, string phaseName)
    {
        var exec = new ScanPhaseExecution
        {
            Phase = phase,
            PhaseName = phaseName,
            Status = ScanPhaseStatus.Running,
            StartTime = DateTime.Now
        };
        result.Phases.Add(exec);
        return exec;
    }

    private void CompletePhase(ScanPhaseExecution phase, ScanPhaseStatus status, int outputCount = 0)
    {
        phase.EndTime = DateTime.Now;
        phase.DurationMs = (long)(phase.EndTime - phase.StartTime).TotalMilliseconds;
        phase.Status = status;
        phase.OutputCount = outputCount;
    }

    private void FailPhase(ScanPhaseExecution phase, Exception ex)
    {
        phase.EndTime = DateTime.Now;
        phase.DurationMs = (long)(phase.EndTime - phase.StartTime).TotalMilliseconds;
        phase.Status = ScanPhaseStatus.Failed;
        phase.ErrorMessage = ex.Message;
    }

    private void ReportProgress(
        IProgress<ScanPhaseProgress>? progress,
        ScanPhase phase,
        string phaseName,
        int subProgress,
        string message,
        int discoveredPorts,
        Stopwatch overallSw,
        int overallProgress = -1)
    {
        if (progress == null) return;

        var payload = new ScanPhaseProgress
        {
            Phase = phase,
            PhaseName = phaseName,
            SubProgress = Math.Clamp(subProgress, 0, 100),
            Progress = overallProgress >= 0 ? Math.Clamp(overallProgress, 0, 100) : Math.Clamp(subProgress, 0, 100),
            CurrentItem = message,
            ElapsedMs = overallSw.ElapsedMilliseconds,
            EstimatedRemainingMs = -1,
            Message = message
        };
        try { progress.Report(payload); } catch { /* 进度回调异常不影响主流程 */ }
    }

    private string CalculateRiskLevel(List<VulnerabilityResult> all)
    {
        if (all == null || all.Count == 0) return "无风险";
        if (all.Any(v => v.RiskLevel == "严重" || v.RiskLevel == "严重风险")) return "严重风险";
        if (all.Any(v => v.RiskLevel == "高" || v.RiskLevel == "高风险")) return "高风险";
        if (all.Any(v => v.RiskLevel == "中" || v.RiskLevel == "中风险")) return "中风险";
        return "低风险";
    }

    private void FinalizeResult(ComprehensiveScanResult result, Stopwatch sw, string riskLevel)
    {
        sw.Stop();
        result.ScanDurationSeconds = sw.Elapsed.TotalSeconds;
        result.RiskLevel = riskLevel;
        result.ScanType = BuildScanType(result);
    }

    private static string BuildScanType(ComprehensiveScanResult r)
    {
        bool tcp = r.Phases.Any(p => p.Phase == ScanPhase.TcpPortScan && p.Status == ScanPhaseStatus.Success);
        bool udp = r.Phases.Any(p => p.Phase == ScanPhase.UdpPortScan && p.Status == ScanPhaseStatus.Success);
        if (tcp && udp) return "TCP+UDP综合扫描";
        if (tcp) return "TCP综合扫描";
        if (udp) return "UDP综合扫描";
        return "综合扫描";
    }

    private async Task TrySaveHistoryAsync(ComprehensiveScanResult result)
    {
        try
        {
            // 先存"扫描中"占位记录
            await _jsonDatabaseService.SaveScanHistoryAsync(new ScanHistoryItem
            {
                ScanId = result.ScanId,
                TargetIp = result.TargetIp,
                ScanType = result.ScanType,
                ScanTime = result.ScanTime,
                OpenPortsCount = 0,
                VulnerabilitiesCount = 0,
                RiskLevel = "扫描中...",
                PortScanResults = new List<PortScanResult>(),
                VulnerabilityResults = new List<VulnerabilityResult>()
            });

            // 再存完整结果到单独 JSON
            var completeResult = new CompleteScanResult
            {
                ScanId = result.ScanId,
                TargetIp = result.TargetIp,
                ScanType = result.ScanType,
                ScanTime = result.ScanTime,
                ScanDuration = result.ScanDurationSeconds,
                OpenPortsCount = result.OpenPortsCount,
                VulnerabilitiesCount = result.VulnerabilitiesCount,
                RiskLevel = result.RiskLevel,
                PortScanResults = result.AllPortResults,
                VulnerabilityResults = result.VulnerabilityResults.Concat(result.PluginResults).ToList()
            };
            await _jsonDatabaseService.SaveScanResultAsync(completeResult);

            // 最后更新历史记录
            await _jsonDatabaseService.UpdateScanHistoryAsync(result.ScanId, new ScanHistoryItem
            {
                ScanId = result.ScanId,
                TargetIp = result.TargetIp,
                ScanType = result.ScanType,
                ScanTime = result.ScanTime,
                OpenPortsCount = result.OpenPortsCount,
                VulnerabilitiesCount = result.VulnerabilitiesCount,
                RiskLevel = result.RiskLevel,
                PortScanResults = result.AllPortResults,
                VulnerabilityResults = result.VulnerabilityResults.Concat(result.PluginResults).ToList(),
                Duration = result.ScanDurationSeconds
            });
            Log($"[综合扫描 {result.ScanId}] 已保存到历史");
        }
        catch (Exception ex)
        {
            Log($"[综合扫描 {result.ScanId}] 保存历史失败: {ex.Message}");
        }
    }

    private void Log(string message)
    {
        try { _logger?.Invoke(message); } catch { }
    }

    #endregion
}