using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Threading;
using NetSecurityScanner.Core;

namespace NetSecurityScanner.Utils
{
    /// <summary>
    /// 扫描性能监控器 - 用于监控和记录扫描过程中的各项性能指标
    /// 
    /// 监控指标：
    /// 1. 扫描吞吐量（端口/秒）
    /// 2. 平均响应时间（ms）
    /// 3. 内存使用峰值（MB）
    /// 4. CPU使用率（%）
    /// 5. 网络IO统计
    /// </summary>
    public class ScanPerformanceMonitor : IDisposable
    {
        private Stopwatch _scanStopwatch;
        private long _portsScanned;
        private long _openPortsFound;
        private long _vulnerabilitiesDetected;
        private List<double> _responseTimes;
        private long _peakMemoryUsage;
        private ResourceMonitor _resourceMonitor;
        private bool _isMonitoring;
        private bool _isDisposed;
        
        // 性能计数器
        private PerformanceCounter _cpuCounter;
        private DateTime _lastCpuReadTime;
        private float _lastCpuUsage;
        
        /// <summary>
        /// 扫描开始时间
        /// </summary>
        public DateTime? StartTime { get; private set; }
        
        /// <summary>
        /// 扫描结束时间
        /// </summary>
        public DateTime? EndTime { get; private set; }
        
        /// <summary>
        /// 是否正在监控
        /// </summary>
        public bool IsMonitoring => _isMonitoring;
        
        /// <summary>
        /// 已扫描的端口数
        /// </summary>
        public long PortsScanned => _portsScanned;
        
        /// <summary>
        /// 发现的开放端口数
        /// </summary>
        public long OpenPortsFound => _openPortsFound;
        
        /// <summary>
        /// 检测到的漏洞数量
        /// </summary>
        public long VulnerabilitiesDetected => _vulnerabilitiesDetected;
        
        /// <summary>
        /// 扫描持续时间
        /// </summary>
        public TimeSpan? Duration => _scanStopwatch?.Elapsed;
        
        /// <summary>
        /// 当前扫描速度（端口/秒）
        /// </summary>
        public double CurrentThroughput => CalculateCurrentThroughput();
        
        /// <summary>
        /// 平均响应时间（毫秒）
        /// </summary>
        public double AverageResponseTimeMs => CalculateAverageResponseTime();
        
        /// <summary>
        /// 峰值内存使用（MB）
        /// </summary>
        public double PeakMemoryUsageMb => _peakMemoryUsage / (1024.0 * 1024.0);
        
        /// <summary>
        /// 当前CPU使用率（%）
        /// </summary>
        public double CpuUsagePercent => _lastCpuUsage;
        
        /// <summary>
        /// 创建扫描性能监控器
        /// </summary>
        public ScanPerformanceMonitor()
        {
            _responseTimes = new List<double>();
            _scanStopwatch = new Stopwatch();
            
            try
            {
                // 初始化CPU计数器
                _cpuCounter = new PerformanceCounter("Processor", "% Processor Time", "_Total", true);
                _lastCpuReadTime = DateTime.MinValue;
                
                // 初始化资源监控
                _resourceMonitor = new ResourceMonitor();
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"[ScanPerformanceMonitor] 初始化失败: {ex.Message}");
            }
        }
        
        /// <summary>
        /// 开始监控
        /// </summary>
        public void StartMonitoring()
        {
            if (_isMonitoring) return;
            
            _isMonitoring = true;
            StartTime = DateTime.Now;
            EndTime = null;
            _portsScanned = 0;
            _openPortsFound = 0;
            _vulnerabilitiesDetected = 0;
            _peakMemoryUsage = 0;
            _responseTimes.Clear();
            
            _scanStopwatch.Restart();
            
            try
            {
                _resourceMonitor?.StartMonitoring();
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"[ScanPerformanceMonitor] 启动资源监控失败: {ex.Message}");
            }
            
            LogPerformanceEvent("扫描开始");
        }
        
        /// <summary>
        /// 停止监控
        /// </summary>
        public void StopMonitoring()
        {
            if (!_isMonitoring) return;
            
            _isMonitoring = false;
            EndTime = DateTime.Now;
            _scanStopwatch.Stop();
            
            try
            {
                _resourceMonitor?.StopMonitoring();
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"[ScanPerformanceMonitor] 停止资源监控失败: {ex.Message}");
            }
            
            LogPerformanceEvent("扫描结束");
        }
        
        /// <summary>
        /// 记录端口扫描完成
        /// </summary>
        /// <param name="isOpen">是否为开放端口</param>
        /// <param name="responseTimeMs">响应时间（毫秒）</param>
        public void RecordPortScanned(bool isOpen, double responseTimeMs = 0)
        {
            if (!_isMonitoring) return;
            
            Interlocked.Increment(ref _portsScanned);
            
            if (isOpen)
            {
                Interlocked.Increment(ref _openPortsFound);
            }
            
            if (responseTimeMs > 0)
            {
                lock (_responseTimes)
                {
                    _responseTimes.Add(responseTimeMs);
                    // 只保留最近10000个响应时间样本，防止内存泄漏
                    if (_responseTimes.Count > 10000)
                    {
                        _responseTimes.RemoveRange(0, _responseTimes.Count - 10000);
                    }
                }
            }
            
            UpdatePeakMemory();
        }
        
        /// <summary>
        /// 记录漏洞检测完成
        /// </summary>
        public void RecordVulnerabilityDetected()
        {
            if (!_isMonitoring) return;
            
            Interlocked.Increment(ref _vulnerabilitiesDetected);
        }
        
        /// <summary>
        /// 更新内存使用峰值
        /// </summary>
        private void UpdatePeakMemory()
        {
            try
            {
                long currentMemory = Process.GetCurrentProcess().WorkingSet64;
                if (currentMemory > _peakMemoryUsage)
                {
                    Interlocked.Exchange(ref _peakMemoryUsage, currentMemory);
                }
            }
            catch (Exception)
            {
                // 忽略错误
            }
        }
        
        /// <summary>
        /// 计算当前吞吐量
        /// </summary>
        private double CalculateCurrentThroughput()
        {
            if (!_isMonitoring || !_scanStopwatch.IsRunning || _scanStopwatch.Elapsed.TotalSeconds == 0)
                return 0;
            
            return _portsScanned / _scanStopwatch.Elapsed.TotalSeconds;
        }
        
        /// <summary>
        /// 计算平均响应时间
        /// </summary>
        private double CalculateAverageResponseTime()
        {
            lock (_responseTimes)
            {
                if (_responseTimes.Count == 0) return 0;
                return _responseTimes.Average();
            }
        }
        
        /// <summary>
        /// 获取当前CPU使用率
        /// </summary>
        public void UpdateCpuUsage()
        {
            try
            {
                if (_cpuCounter != null && 
                    (DateTime.Now - _lastCpuReadTime).TotalSeconds >= 1)
                {
                    _lastCpuUsage = _cpuCounter.NextValue();
                    _lastCpuReadTime = DateTime.Now;
                }
            }
            catch (Exception)
            {
                // 忽略错误
            }
        }
        
        /// <summary>
        /// 记录性能事件日志
        /// </summary>
        private void LogPerformanceEvent(string eventName)
        {
            System.Diagnostics.Debug.WriteLine($"[ScanPerf] {eventName} @ {DateTime.Now:HH:mm:ss.fff}");
        }
        
        /// <summary>
        /// 生成性能报告
        /// </summary>
        public ScanPerformanceReport GenerateReport()
        {
            UpdateCpuUsage();
            
            var report = new ScanPerformanceReport
            {
                GeneratedAt = DateTime.Now,
                StartTime = StartTime ?? DateTime.Now,
                EndTime = EndTime ?? DateTime.Now,
                Duration = Duration ?? TimeSpan.Zero,
                TotalPortsScanned = _portsScanned,
                OpenPortsFound = _openPortsFound,
                VulnerabilitiesDetected = _vulnerabilitiesDetected,
                Throughput = CurrentThroughput,
                AverageResponseTimeMs = AverageResponseTimeMs,
                PeakMemoryUsageMb = PeakMemoryUsageMb,
                CpuUsagePercent = CpuUsagePercent
            };
            
            return report;
        }
        
        /// <summary>
        /// 获取实时性能快照
        /// </summary>
        public ScanPerformanceSnapshot GetRealtimeSnapshot()
        {
            UpdateCpuUsage();
            
            return new ScanPerformanceSnapshot
            {
                Timestamp = DateTime.Now,
                ElapsedSeconds = _scanStopwatch?.Elapsed.TotalSeconds ?? 0,
                PortsScanned = _portsScanned,
                OpenPortsFound = _openPortsFound,
                Throughput = CurrentThroughput,
                AverageResponseTimeMs = AverageResponseTimeMs,
                MemoryUsageMb = Process.GetCurrentProcess().WorkingSet64 / (1024.0 * 1024.0),
                CpuUsagePercent = CpuUsagePercent
            };
        }
        
        #region IDisposable Implementation
        
        public void Dispose()
        {
            Dispose(true);
            GC.SuppressFinalize(this);
        }
        
        protected virtual void Dispose(bool disposing)
        {
            if (!_isDisposed)
            {
                if (disposing)
                {
                    StopMonitoring();
                    
                    _scanStopwatch?.Stop();
                    _resourceMonitor?.Dispose();
                    _cpuCounter?.Dispose();
                    
                    lock (_responseTimes)
                    {
                        _responseTimes.Clear();
                    }
                }
                _isDisposed = true;
            }
        }
        
        #endregion
    }

    /// <summary>
    /// 扫描性能报告
    /// </summary>
    public class ScanPerformanceReport
    {
        public DateTime GeneratedAt { get; set; }
        public DateTime StartTime { get; set; }
        public DateTime EndTime { get; set; }
        public TimeSpan Duration { get; set; }
        public long TotalPortsScanned { get; set; }
        public long OpenPortsFound { get; set; }
        public long VulnerabilitiesDetected { get; set; }
        public double Throughput { get; set; } // ports/sec
        public double AverageResponseTimeMs { get; set; }
        public double PeakMemoryUsageMb { get; set; }
        public double CpuUsagePercent { get; set; }
        
        public override string ToString()
        {
            return $"扫描性能报告:\n" +
                   $"- 扫描时间: {StartTime:HH:mm:ss} - {EndTime:HH:mm:ss}\n" +
                   $"- 总耗时: {Duration.TotalSeconds:F2} 秒\n" +
                   $"- 扫描端口: {TotalPortsScanned}\n" +
                   $"- 开放端口: {OpenPortsFound}\n" +
                   $"- 发现漏洞: {VulnerabilitiesDetected}\n" +
                   $"- 吞吐量: {Throughput:F1} 端口/秒\n" +
                   $"- 平均响应: {AverageResponseTimeMs:F1} ms\n" +
                   $"- 峰值内存: {PeakMemoryUsageMb:F1} MB\n" +
                   $"- CPU使用率: {CpuUsagePercent:F1}%";
        }
    }

    /// <summary>
    /// 实时性能快照
    /// </summary>
    public class ScanPerformanceSnapshot
    {
        public DateTime Timestamp { get; set; }
        public double ElapsedSeconds { get; set; }
        public long PortsScanned { get; set; }
        public long OpenPortsFound { get; set; }
        public double Throughput { get; set; }
        public double AverageResponseTimeMs { get; set; }
        public double MemoryUsageMb { get; set; }
        public double CpuUsagePercent { get; set; }
        
        public override string ToString()
        {
            return $"[{Timestamp:HH:mm:ss.fff}] " +
                   $"耗时:{ElapsedSeconds:F1}s " +
                   $"端口:{PortsScanned} " +
                   $"开放:{OpenPortsFound} " +
                   $"速率:{Throughput:F0}/s " +
                   $"响应:{AverageResponseTimeMs:F0}ms " +
                   $"内存:{MemoryUsageMb:F0}MB " +
                   $"CPU:{CpuUsagePercent:F0}%";
        }
    }
}
