using NetSecurityScanner.Models;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;

namespace NetSecurityScanner.Services
{
    public class BatchScanManager
    {
        private readonly VulnerabilityScanner _scanner;
        private readonly ScanHistoryService _historyService;

        public event EventHandler<BatchScanProgress> ProgressChanged;
        public event EventHandler<List<VulnerabilityResult>> TargetCompleted;

        public BatchScanManager()
        {
            _scanner = new VulnerabilityScanner();
            _historyService = new ScanHistoryService();
        }

        public async Task<BatchScanResult> ScanBatchAsync(
            List<string> targets,
            ScanConfiguration config,
            CancellationToken cancellationToken = default)
        {
            var result = new BatchScanResult
            {
                TotalTargets = targets.Count,
                StartTime = DateTime.Now,
                TargetResults = new List<List<VulnerabilityResult>>(),
                FailedTargets = new List<FailedTarget>()
            };

            var semaphore = new SemaphoreSlim(config.MaxConcurrency);
            var completedCount = 0;

            var tasks = targets.Select(async (target, index) =>
            {
                await semaphore.WaitAsync(cancellationToken);

                try
                {
                    ProgressChanged?.Invoke(this, new BatchScanProgress
                    {
                        CurrentTarget = target,
                        CompletedCount = Interlocked.Increment(ref completedCount) - 1,
                        TotalCount = targets.Count,
                        Percentage = (int)((double)(completedCount - 1) / targets.Count * 100),
                        Status = $"正在扫描 {target}..."
                    });

                    var scanResult = await ScanSingleTargetAsync(target, config, cancellationToken);
                    result.TargetResults.Add(scanResult);

                    TargetCompleted?.Invoke(this, scanResult);
                }
                catch (Exception ex)
                {
                    result.FailedTargets.Add(new FailedTarget
                    {
                        Target = target,
                        Error = ex.Message
                    });
                }
                finally
                {
                    semaphore.Release();
                }
            });

            await Task.WhenAll(tasks);

            result.EndTime = DateTime.Now;
            result.Duration = result.EndTime - result.StartTime;

            return result;
        }

        private async Task<List<VulnerabilityResult>> ScanSingleTargetAsync(string target, ScanConfiguration config, CancellationToken cancellationToken)
        {
            await _scanner.InitializeAsync(cancellationToken);

            // 获取开放端口
            var openPorts = await GetOpenPortsAsync(target, config, cancellationToken);

            // 执行漏洞扫描
            var vulnerabilities = await _scanner.ScanAsync(
                target,
                openPorts,
                config.Mode.ToString(),
                null,
                cancellationToken
            );

            return vulnerabilities;
        }

        private async Task<List<PortInfo>> GetOpenPortsAsync(string target, ScanConfiguration config, CancellationToken cancellationToken)
        {
            var portInfos = new List<PortInfo>();
            var ports = config.TargetPorts != null ? config.TargetPorts.ToList() : ParsePortRange(config.PortRange);

            foreach (var port in ports)
            {
                if (await IsPortOpenAsync(target, port, config.TimeoutMs))
                {
                    portInfos.Add(new PortInfo { PortNumber = port });
                }
            }

            return portInfos;
        }

        private async Task<bool> IsPortOpenAsync(string host, int port, int timeoutMs)
        {
            try
            {
                using var client = new System.Net.Sockets.TcpClient();
                var result = client.BeginConnect(host, port, null, null);
                var success = result.AsyncWaitHandle.WaitOne(timeoutMs);
                if (success)
                {
                    client.EndConnect(result);
                    return true;
                }
            }
            catch (Exception)
            {
                // 忽略异常
            }
            await Task.CompletedTask;
            return false;
        }

        private List<int> ParsePortRange(string range)
        {
            var ports = new List<int>();
            if (string.IsNullOrEmpty(range)) return ports;

            var parts = range.Split(',');
            foreach (var part in parts)
            {
                if (part.Contains("-"))
                {
                    var bounds = part.Split('-');
                    if (bounds.Length == 2 &&
                        int.TryParse(bounds[0], out int start) &&
                        int.TryParse(bounds[1], out int end))
                    {
                        ports.AddRange(Enumerable.Range(start, end - start + 1));
                    }
                }
                else if (int.TryParse(part, out int port))
                {
                    ports.Add(port);
                }
            }
            return ports;
        }
    }

    public class BatchScanResult
    {
        public int TotalTargets { get; set; }
        public DateTime StartTime { get; set; }
        public DateTime EndTime { get; set; }
        public TimeSpan Duration { get; set; }
        public List<List<VulnerabilityResult>> TargetResults { get; set; }
        public List<FailedTarget> FailedTargets { get; set; }

        public int TotalVulnerabilities => TargetResults.Sum(r => r?.Count ?? 0);
        public int CriticalCount => TargetResults.Sum(r => r?.Count(v => v.RiskLevel == "严重") ?? 0);
        public int HighCount => TargetResults.Sum(r => r?.Count(v => v.RiskLevel == "高危") ?? 0);
        public int MediumCount => TargetResults.Sum(r => r?.Count(v => v.RiskLevel == "中危") ?? 0);
    }

    public class BatchScanProgress
    {
        public string CurrentTarget { get; set; }
        public int CompletedCount { get; set; }
        public int TotalCount { get; set; }
        public int Percentage { get; set; }
        public string Status { get; set; }
    }

    public class FailedTarget
    {
        public string Target { get; set; }
        public string Error { get; set; }
    }
}
