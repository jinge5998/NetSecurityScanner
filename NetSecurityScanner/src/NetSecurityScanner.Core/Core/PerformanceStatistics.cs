using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Text;
using System.Threading;

namespace NetSecurityScanner.Core
{
    /// <summary>
    /// 性能统计类 - 收集和分析扫描性能数据
    /// </summary>
    public class PerformanceStatistics
    {
        private Stopwatch _totalScanStopwatch;
        private Stopwatch _activeScanStopwatch;
        private int _totalPorts;
        private int _completedPorts;
        private int _successfulScans;
        private int _failedScans;
        private int _openPorts;
        private int _maxConcurrencyReached;
        private int _currentConcurrency;
        private long _peakMemoryUsage;
        private List<ScanPhaseStatistics> _phaseStatistics;
        private Dictionary<string, long> _operationTimings;
        private List<ResourceUsageSnapshot> _resourceSnapshots;
        private int _batchCount;
        private int _totalBatchTimeMs;
        private object _lock = new object();

        /// <summary>
        /// 总扫描时间
        /// </summary>
        public TimeSpan TotalScanTime => _totalScanStopwatch?.Elapsed ?? TimeSpan.Zero;

        /// <summary>
        /// 活跃扫描时间（排除等待时间）
        /// </summary>
        public TimeSpan ActiveScanTime => _activeScanStopwatch?.Elapsed ?? TimeSpan.Zero;

        /// <summary>
        /// 平均每个端口的扫描时间
        /// </summary>
        public TimeSpan AveragePortScanTime
        {
            get
            {
                if (_completedPorts == 0)
                    return TimeSpan.Zero;
                return TimeSpan.FromMilliseconds(ActiveScanTime.TotalMilliseconds / _completedPorts);
            }
        }

        /// <summary>
        /// 扫描速度（端口/秒）
        /// </summary>
        public double ScanSpeed => _completedPorts / TotalScanTime.TotalSeconds;

        /// <summary>
        /// 成功率
        /// </summary>
        public double SuccessRate
        {
            get
            {
                int totalAttempts = _successfulScans + _failedScans;
                return totalAttempts > 0 ? (double)_successfulScans / totalAttempts : 0;
            }
        }

        /// <summary>
        /// 开放端口比例
        /// </summary>
        public double OpenPortRatio => _totalPorts > 0 ? (double)_openPorts / _totalPorts : 0;

        /// <summary>
        /// 峰值内存使用量（MB）
        /// </summary>
        public long PeakMemoryUsage => _peakMemoryUsage;

        /// <summary>
        /// 达到的最大并发数
        /// </summary>
        public int MaxConcurrencyReached => _maxConcurrencyReached;

        /// <summary>
        /// 批处理平均时间（毫秒）
        /// </summary>
        public long AverageBatchTimeMs => _batchCount > 0 ? _totalBatchTimeMs / _batchCount : 0;

        /// <summary>
        /// 操作耗时统计
        /// </summary>
        public IReadOnlyDictionary<string, long> OperationTimings => _operationTimings;

        /// <summary>
        /// 资源使用快照
        /// </summary>
        public IReadOnlyList<ResourceUsageSnapshot> ResourceSnapshots => _resourceSnapshots;

        /// <summary>
        /// 扫描阶段统计
        /// </summary>
        public IReadOnlyList<ScanPhaseStatistics> PhaseStatistics => _phaseStatistics;

        public PerformanceStatistics()
        {
            _totalScanStopwatch = new Stopwatch();
            _activeScanStopwatch = new Stopwatch();
            _phaseStatistics = new List<ScanPhaseStatistics>();
            _operationTimings = new Dictionary<string, long>();
            _resourceSnapshots = new List<ResourceUsageSnapshot>();
        }

        /// <summary>
        /// 开始扫描
        /// </summary>
        public void StartScan(int totalPorts)
        {
            lock (_lock)
            {
                _totalPorts = totalPorts;
                _totalScanStopwatch.Start();
                _activeScanStopwatch.Start();
                RecordResourceSnapshot("ScanStart");
            }
        }

        /// <summary>
        /// 停止扫描
        /// </summary>
        public void StopScan()
        {
            lock (_lock)
            {
                _totalScanStopwatch.Stop();
                _activeScanStopwatch.Stop();
                RecordResourceSnapshot("ScanEnd");
                UpdatePeakMemoryUsage();
            }
        }

        /// <summary>
        /// 记录端口扫描完成
        /// </summary>
        public void RecordPortScanned(bool success, bool isOpen)
        {
            lock (_lock)
            {
                _completedPorts++;
                if (success)
                    _successfulScans++;
                else
                    _failedScans++;
                if (isOpen)
                    _openPorts++;
                UpdatePeakMemoryUsage();
            }
        }

        /// <summary>
        /// 记录并发数变化
        /// </summary>
        public void RecordConcurrencyChange(int currentConcurrency)
        {
            lock (_lock)
            {
                _currentConcurrency = currentConcurrency;
                if (currentConcurrency > _maxConcurrencyReached)
                    _maxConcurrencyReached = currentConcurrency;
            }
        }

        /// <summary>
        /// 记录批处理完成
        /// </summary>
        public void RecordBatchCompleted(int batchSize, long timeMs)
        {
            lock (_lock)
            {
                _batchCount++;
                _totalBatchTimeMs += (int)timeMs;
            }
        }

        /// <summary>
        /// 记录操作耗时
        /// </summary>
        public void RecordOperationTime(string operationName, long timeMs)
        {
            lock (_lock)
            {
                if (_operationTimings.ContainsKey(operationName))
                    _operationTimings[operationName] += timeMs;
                else
                    _operationTimings[operationName] = timeMs;
            }
        }

        /// <summary>
        /// 记录扫描阶段
        /// </summary>
        public void RecordPhase(string phaseName, int portsProcessed)
        {
            lock (_lock)
            {
                var phaseStats = new ScanPhaseStatistics
                {
                    PhaseName = phaseName,
                    Timestamp = DateTime.Now,
                    PortsProcessed = portsProcessed,
                    ElapsedTime = TotalScanTime
                };
                _phaseStatistics.Add(phaseStats);
            }
        }

        /// <summary>
        /// 记录资源使用快照
        /// </summary>
        public void RecordResourceSnapshot(string snapshotName)
        {
            lock (_lock)
            {
                var snapshot = new ResourceUsageSnapshot
                {
                    Timestamp = DateTime.Now,
                    SnapshotName = snapshotName,
                    MemoryUsageMb = GetCurrentMemoryUsageMb(),
                    CpuUsage = GetCurrentCpuUsage(),
                    CurrentConcurrency = _currentConcurrency,
                    CompletedPorts = _completedPorts,
                    TotalPorts = _totalPorts
                };
                _resourceSnapshots.Add(snapshot);
            }
        }

        /// <summary>
        /// 生成性能报告
        /// </summary>
        public string GeneratePerformanceReport()
        {
            var sb = new StringBuilder();
            sb.AppendLine("=== 扫描性能报告 ===");
            sb.AppendLine($"总扫描时间: {TotalScanTime}");
            sb.AppendLine($"活跃扫描时间: {ActiveScanTime}");
            sb.AppendLine($"平均端口扫描时间: {AveragePortScanTime}");
            sb.AppendLine($"扫描速度: {ScanSpeed:F2} 端口/秒");
            sb.AppendLine($"成功率: {SuccessRate:P2}");
            sb.AppendLine($"开放端口: {_openPorts}/{_totalPorts} ({OpenPortRatio:P2})");
            sb.AppendLine($"峰值内存使用: {_peakMemoryUsage} MB");
            sb.AppendLine($"最大并发数: {_maxConcurrencyReached}");
            sb.AppendLine($"批处理数: {_batchCount}");
            if (_batchCount > 0)
            {
                sb.AppendLine($"平均批处理时间: {AverageBatchTimeMs} ms");
            }
            sb.AppendLine();
            
            if (_operationTimings.Count > 0)
            {
                sb.AppendLine("=== 操作耗时统计 ===");
                foreach (var kvp in _operationTimings.OrderByDescending(x => x.Value))
                {
                    sb.AppendLine($"{kvp.Key}: {kvp.Value} ms");
                }
                sb.AppendLine();
            }
            
            if (_phaseStatistics.Count > 0)
            {
                sb.AppendLine("=== 扫描阶段统计 ===");
                foreach (var phase in _phaseStatistics)
                {
                    sb.AppendLine($"{phase.Timestamp:HH:mm:ss} - {phase.PhaseName}: 处理 {phase.PortsProcessed} 个端口, 耗时 {phase.ElapsedTime}");
                }
                sb.AppendLine();
            }
            
            return sb.ToString();
        }
        
        /// <summary>
        /// 生成HTML格式的详细性能报告
        /// </summary>
        public string GenerateHtmlPerformanceReport()
        {
            var sb = new StringBuilder();
            sb.AppendLine("<!DOCTYPE html>");
            sb.AppendLine("<html>");
            sb.AppendLine("<head>");
            sb.AppendLine("<title>扫描性能报告</title>");
            sb.AppendLine("<style>");
            sb.AppendLine("body { font-family: Arial, sans-serif; margin: 20px; background-color: #f5f5f5; }");
            sb.AppendLine(".container { max-width: 1200px; margin: 0 auto; background-color: white; padding: 20px; border-radius: 8px; box-shadow: 0 0 10px rgba(0,0,0,0.1); }");
            sb.AppendLine("h1 { color: #333; text-align: center; }");
            sb.AppendLine("h2 { color: #555; border-bottom: 2px solid #ddd; padding-bottom: 10px; }");
            sb.AppendLine(".stats-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap: 20px; margin: 20px 0; }");
            sb.AppendLine(".stat-card { background-color: #f9f9f9; padding: 15px; border-radius: 6px; border-left: 4px solid #4CAF50; }");
            sb.AppendLine(".stat-card h3 { margin-top: 0; color: #333; }");
            sb.AppendLine(".stat-value { font-size: 1.5em; font-weight: bold; color: #4CAF50; }");
            sb.AppendLine(".table-container { overflow-x: auto; margin: 20px 0; }");
            sb.AppendLine("table { width: 100%; border-collapse: collapse; }");
            sb.AppendLine("th, td { padding: 12px; text-align: left; border-bottom: 1px solid #ddd; }");
            sb.AppendLine("th { background-color: #f2f2f2; font-weight: bold; }");
            sb.AppendLine("tr:hover { background-color: #f5f5f5; }");
            sb.AppendLine(".footer { margin-top: 30px; text-align: center; color: #666; font-size: 0.9em; }");
            sb.AppendLine("</style>");
            sb.AppendLine("</head>");
            sb.AppendLine("<body>");
            sb.AppendLine("<div class='container'>");
            sb.AppendLine("<h1>网络安全漏洞扫描性能报告</h1>");
            
            // 基本统计信息
            sb.AppendLine("<h2>基本性能统计</h2>");
            sb.AppendLine("<div class='stats-grid'>");
            sb.AppendLine($"<div class='stat-card'><h3>总扫描时间</h3><div class='stat-value'>{TotalScanTime}</div></div>");
            sb.AppendLine($"<div class='stat-card'><h3>活跃扫描时间</h3><div class='stat-value'>{ActiveScanTime}</div></div>");
            sb.AppendLine($"<div class='stat-card'><h3>平均端口扫描时间</h3><div class='stat-value'>{AveragePortScanTime}</div></div>");
            sb.AppendLine($"<div class='stat-card'><h3>扫描速度</h3><div class='stat-value'>{ScanSpeed:F2} 端口/秒</div></div>");
            sb.AppendLine($"<div class='stat-card'><h3>成功率</h3><div class='stat-value'>{SuccessRate:P2}</div></div>");
            sb.AppendLine($"<div class='stat-card'><h3>开放端口比例</h3><div class='stat-value'>{OpenPortRatio:P2}</div></div>");
            sb.AppendLine($"<div class='stat-card'><h3>峰值内存使用</h3><div class='stat-value'>{_peakMemoryUsage} MB</div></div>");
            sb.AppendLine($"<div class='stat-card'><h3>最大并发数</h3><div class='stat-value'>{_maxConcurrencyReached}</div></div>");
            sb.AppendLine("</div>");
            
            // 批处理统计
            if (_batchCount > 0)
            {
                sb.AppendLine("<h2>批处理统计</h2>");
                sb.AppendLine("<div class='stats-grid'>");
                sb.AppendLine($"<div class='stat-card'><h3>批处理数</h3><div class='stat-value'>{_batchCount}</div></div>");
                sb.AppendLine($"<div class='stat-card'><h3>平均批处理时间</h3><div class='stat-value'>{AverageBatchTimeMs} ms</div></div>");
                sb.AppendLine("</div>");
            }
            
            // 操作耗时统计
            if (_operationTimings.Count > 0)
            {
                sb.AppendLine("<h2>操作耗时统计</h2>");
                sb.AppendLine("<div class='table-container'>");
                sb.AppendLine("<table>");
                sb.AppendLine("<tr><th>操作名称</th><th>耗时 (ms)</th></tr>");
                foreach (var kvp in _operationTimings.OrderByDescending(x => x.Value))
                {
                    sb.AppendLine($"<tr><td>{kvp.Key}</td><td>{kvp.Value}</td></tr>");
                }
                sb.AppendLine("</table>");
                sb.AppendLine("</div>");
            }
            
            // 扫描阶段统计
            if (_phaseStatistics.Count > 0)
            {
                sb.AppendLine("<h2>扫描阶段统计</h2>");
                sb.AppendLine("<div class='table-container'>");
                sb.AppendLine("<table>");
                sb.AppendLine("<tr><th>时间</th><th>阶段名称</th><th>处理端口数</th><th>耗时</th></tr>");
                foreach (var phase in _phaseStatistics)
                {
                    sb.AppendLine($"<tr><td>{phase.Timestamp:HH:mm:ss}</td><td>{phase.PhaseName}</td><td>{phase.PortsProcessed}</td><td>{phase.ElapsedTime}</td></tr>");
                }
                sb.AppendLine("</table>");
                sb.AppendLine("</div>");
            }
            
            // 资源使用快照
            if (_resourceSnapshots.Count > 0)
            {
                sb.AppendLine("<h2>资源使用快照</h2>");
                sb.AppendLine("<div class='table-container'>");
                sb.AppendLine("<table>");
                sb.AppendLine("<tr><th>时间</th><th>快照名称</th><th>内存使用 (MB)</th><th>CPU使用率 (%)</th><th>当前并发数</th><th>完成端口数</th></tr>");
                foreach (var snapshot in _resourceSnapshots)
                {
                    sb.AppendLine($"<tr><td>{snapshot.Timestamp:HH:mm:ss}</td><td>{snapshot.SnapshotName}</td><td>{snapshot.MemoryUsageMb}</td><td>{snapshot.CpuUsage:F2}</td><td>{snapshot.CurrentConcurrency}</td><td>{snapshot.CompletedPorts}/{snapshot.TotalPorts}</td></tr>");
                }
                sb.AppendLine("</table>");
                sb.AppendLine("</div>");
            }
            
            sb.AppendLine("<div class='footer'>");
            sb.AppendLine($"报告生成时间: {DateTime.Now}");
            sb.AppendLine("</div>");
            sb.AppendLine("</div>");
            sb.AppendLine("</body>");
            sb.AppendLine("</html>");
            
            return sb.ToString();
        }
        
        /// <summary>
        /// 保存性能报告到文件
        /// </summary>
        /// <param name="filePath">文件路径</param>
        /// <param name="format">报告格式 (txt/html)</param>
        public void SavePerformanceReport(string filePath, string format = "txt")
        {
            string report;
            if (format.Equals("html", StringComparison.OrdinalIgnoreCase))
            {
                report = GenerateHtmlPerformanceReport();
            }
            else
            {
                report = GeneratePerformanceReport();
            }
            
            System.IO.File.WriteAllText(filePath, report);
        }

        /// <summary>
        /// 生成详细的CSV格式报告
        /// </summary>
        public string GenerateCsvReport()
        {
            var sb = new StringBuilder();
            sb.AppendLine("Timestamp,SnapshotName,MemoryUsageMb,CpuUsage,CurrentConcurrency,CompletedPorts,TotalPorts");
            
            foreach (var snapshot in _resourceSnapshots)
            {
                sb.AppendLine($"{snapshot.Timestamp},{snapshot.SnapshotName},{snapshot.MemoryUsageMb},{snapshot.CpuUsage},{snapshot.CurrentConcurrency},{snapshot.CompletedPorts},{snapshot.TotalPorts}");
            }
            
            return sb.ToString();
        }

        /// <summary>
        /// 获取当前内存使用量（MB）
        /// </summary>
        private long GetCurrentMemoryUsageMb()
        {
            try
            {
                return Environment.WorkingSet / (1024 * 1024);
            }
            catch
            {
                return 0;
            }
        }

        /// <summary>
        /// 获取当前CPU使用率
        /// </summary>
        private double GetCurrentCpuUsage()
        {
            try
            {
                // 简化的CPU使用率估计
                // 实际项目中可以使用更复杂的方法
                return Process.GetCurrentProcess().TotalProcessorTime.TotalSeconds / (Environment.ProcessorCount * TotalScanTime.TotalSeconds) * 100;
            }
            catch
            {
                return 0;
            }
        }

        /// <summary>
        /// 更新峰值内存使用量
        /// </summary>
        private void UpdatePeakMemoryUsage()
        {
            long currentMemory = GetCurrentMemoryUsageMb();
            if (currentMemory > _peakMemoryUsage)
            {
                _peakMemoryUsage = currentMemory;
            }
        }
    }

    /// <summary>
    /// 扫描阶段统计
    /// </summary>
    public class ScanPhaseStatistics
    {
        public DateTime Timestamp { get; set; }
        public string PhaseName { get; set; }
        public int PortsProcessed { get; set; }
        public TimeSpan ElapsedTime { get; set; }
    }

    /// <summary>
    /// 资源使用快照
    /// </summary>
    public class ResourceUsageSnapshot
    {
        public DateTime Timestamp { get; set; }
        public string SnapshotName { get; set; }
        public long MemoryUsageMb { get; set; }
        public double CpuUsage { get; set; }
        public int CurrentConcurrency { get; set; }
        public int CompletedPorts { get; set; }
        public int TotalPorts { get; set; }
    }
}
