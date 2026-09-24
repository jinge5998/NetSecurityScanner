using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Net.NetworkInformation;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace NetSecurityScanner.Core
{
    /// <summary>
    /// 资源监控 - 实时监控系统资源使用情况
    /// </summary>
    public class ResourceMonitor : IDisposable
    {
        private bool _isMonitoring;
        private Task _monitoringTask;
        private CancellationTokenSource _cancellationTokenSource;
        private List<ResourceUsage> _resourceUsageHistory;
        private int _maxHistorySize;
        private object _lock = new object();
        private DateTime _lastNetworkUpdate;
        private long _lastBytesSent;
        private long _lastBytesReceived;

        /// <summary>
        /// 资源使用历史记录
        /// </summary>
        public IReadOnlyList<ResourceUsage> ResourceUsageHistory
        {
            get { lock (_lock) return _resourceUsageHistory.ToList(); }
        }

        /// <summary>
        /// 当前CPU使用率
        /// </summary>
        public double CurrentCpuUsage { get; private set; }

        /// <summary>
        /// 当前内存使用量（MB）
        /// </summary>
        public long CurrentMemoryUsage { get; private set; }

        /// <summary>
        /// 当前可用内存（MB）
        /// </summary>
        public long CurrentAvailableMemory { get; private set; }

        /// <summary>
        /// 当前网络发送速度（KB/s）
        /// </summary>
        public double CurrentNetworkSendSpeed { get; private set; }

        /// <summary>
        /// 当前网络接收速度（KB/s）
        /// </summary>
        public double CurrentNetworkReceiveSpeed { get; private set; }

        /// <summary>
        /// 平均CPU使用率
        /// </summary>
        public double AverageCpuUsage
        {
            get
            {
                lock (_lock)
                {
                    return _resourceUsageHistory.Count > 0 
                        ? _resourceUsageHistory.Average(r => r.CpuUsage) 
                        : 0;
                }
            }
        }

        /// <summary>
        /// 平均内存使用量（MB）
        /// </summary>
        public double AverageMemoryUsage
        {
            get
            {
                lock (_lock)
                {
                    return _resourceUsageHistory.Count > 0 
                        ? _resourceUsageHistory.Average(r => r.MemoryUsage) 
                        : 0;
                }
            }
        }

        /// <summary>
        /// 峰值CPU使用率
        /// </summary>
        public double PeakCpuUsage
        {
            get
            {
                lock (_lock)
                {
                    return _resourceUsageHistory.Count > 0 
                        ? _resourceUsageHistory.Max(r => r.CpuUsage) 
                        : 0;
                }
            }
        }

        /// <summary>
        /// 峰值内存使用量（MB）
        /// </summary>
        public long PeakMemoryUsage
        {
            get
            {
                lock (_lock)
                {
                    return _resourceUsageHistory.Count > 0 
                        ? _resourceUsageHistory.Max(r => r.MemoryUsage) 
                        : 0;
                }
            }
        }

        /// <summary>
        /// 初始化资源监控
        /// </summary>
        /// <param name="maxHistorySize">最大历史记录大小</param>
        public ResourceMonitor(int maxHistorySize = 100)
        {
            _maxHistorySize = maxHistorySize;
            _resourceUsageHistory = new List<ResourceUsage>();
            _cancellationTokenSource = new CancellationTokenSource();
            _isMonitoring = false;
            _lastNetworkUpdate = DateTime.Now;
            
            // 初始化网络计数器
            var networkInterface = NetworkInterface.GetAllNetworkInterfaces()
                .FirstOrDefault(nic => nic.OperationalStatus == OperationalStatus.Up && 
                                      nic.NetworkInterfaceType != NetworkInterfaceType.Loopback);
            if (networkInterface != null)
            {
                var stats = networkInterface.GetIPv4Statistics();
                _lastBytesSent = stats.BytesSent;
                _lastBytesReceived = stats.BytesReceived;
            }
        }

        /// <summary>
        /// 开始资源监控
        /// </summary>
        /// <param name="intervalMs">监控间隔（毫秒）</param>
        public void StartMonitoring(int intervalMs = 1000)
        {
            if (_isMonitoring)
                return;

            _isMonitoring = true;
            _cancellationTokenSource = new CancellationTokenSource();
            var token = _cancellationTokenSource.Token;

            _monitoringTask = Task.Run(async () =>
            {
                while (!token.IsCancellationRequested)
                {
                    await Task.Delay(intervalMs, token);
                    CollectResourceUsage();
                }
            }, token);
        }

        /// <summary>
        /// 停止资源监控
        /// </summary>
        public void StopMonitoring()
        {
            if (!_isMonitoring)
                return;

            _cancellationTokenSource.Cancel();
            _monitoringTask.Wait(1000);
            _isMonitoring = false;
        }

        /// <summary>
        /// 收集资源使用情况
        /// </summary>
        private void CollectResourceUsage()
        {
            try
            {
                // 收集CPU使用率
                double cpuUsage = GetCpuUsage();
                
                // 收集内存使用情况
                (long totalMemory, long availableMemory) = GetMemoryUsage();
                long memoryUsage = totalMemory - availableMemory;
                
                // 收集网络使用情况
                (double sendSpeed, double receiveSpeed) = GetNetworkSpeed();
                
                // 更新当前值
                CurrentCpuUsage = cpuUsage;
                CurrentMemoryUsage = memoryUsage;
                CurrentAvailableMemory = availableMemory;
                CurrentNetworkSendSpeed = sendSpeed;
                CurrentNetworkReceiveSpeed = receiveSpeed;
                
                // 添加到历史记录
                var usage = new ResourceUsage
                {
                    Timestamp = DateTime.Now,
                    CpuUsage = cpuUsage,
                    MemoryUsage = memoryUsage,
                    AvailableMemory = availableMemory,
                    NetworkSendSpeed = sendSpeed,
                    NetworkReceiveSpeed = receiveSpeed
                };
                
                lock (_lock)
                {
                    _resourceUsageHistory.Add(usage);
                    
                    // 限制历史记录大小
                    if (_resourceUsageHistory.Count > _maxHistorySize)
                    {
                        _resourceUsageHistory.RemoveAt(0);
                    }
                }
            }
            catch (Exception ex)
            {
                // 忽略监控错误
                Debug.WriteLine($"资源监控错误: {ex.Message}");
            }
        }

        /// <summary>
        /// 获取CPU使用率
        /// </summary>
        /// <returns>CPU使用率（百分比）</returns>
        private double GetCpuUsage()
        {
            try
            {
                var process = Process.GetCurrentProcess();
                var cpuTime = process.TotalProcessorTime;
                Thread.Sleep(100);
                var newCpuTime = process.TotalProcessorTime;
                var elapsed = (newCpuTime - cpuTime).TotalSeconds;
                var cpuUsage = (elapsed / Environment.ProcessorCount) * 100;
                return Math.Min(100, cpuUsage);
            }
            catch
            {
                return 0;
            }
        }

        /// <summary>
        /// 获取内存使用情况
        /// </summary>
        /// <returns>总内存和可用内存（MB）</returns>
        private (long, long) GetMemoryUsage()
        {
            try
            {
                // 使用Environment类获取内存信息
                // 注意：Environment类只能获取当前进程的内存使用情况
                // 这里使用降级方案，返回合理的默认值
                long availableMemory = Environment.WorkingSet / (1024 * 1024);
                // 假设总内存为16GB
                long totalMemory = 16384;
                return (totalMemory, totalMemory - availableMemory);
            }
            catch
            {
                // 降级方案
                long availableMemory = Environment.WorkingSet / (1024 * 1024);
                return (8192, 8192 - availableMemory); // 默认值
            }
        }

        /// <summary>
        /// 获取网络速度
        /// </summary>
        /// <returns>发送速度和接收速度（KB/s）</returns>
        private (double, double) GetNetworkSpeed()
        {
            try
            {
                var now = DateTime.Now;
                var elapsedSeconds = (now - _lastNetworkUpdate).TotalSeconds;
                
                if (elapsedSeconds < 0.1)
                    return (0, 0);
                
                var networkInterface = NetworkInterface.GetAllNetworkInterfaces()
                    .FirstOrDefault(nic => nic.OperationalStatus == OperationalStatus.Up && 
                                          nic.NetworkInterfaceType != NetworkInterfaceType.Loopback);
                
                if (networkInterface == null)
                    return (0, 0);
                
                var stats = networkInterface.GetIPv4Statistics();
                long bytesSent = stats.BytesSent;
                long bytesReceived = stats.BytesReceived;
                
                double sendSpeed = (bytesSent - _lastBytesSent) / (1024.0 * elapsedSeconds);
                double receiveSpeed = (bytesReceived - _lastBytesReceived) / (1024.0 * elapsedSeconds);
                
                _lastBytesSent = bytesSent;
                _lastBytesReceived = bytesReceived;
                _lastNetworkUpdate = now;
                
                return (sendSpeed, receiveSpeed);
            }
            catch
            {
                return (0, 0);
            }
        }

        /// <summary>
        /// 获取资源使用摘要
        /// </summary>
        /// <returns>资源使用摘要</returns>
        public string GetResourceUsageSummary()
        {
            var sb = new StringBuilder();
            sb.AppendLine("=== 系统资源使用摘要 ===");
            sb.AppendLine($"CPU使用率: {CurrentCpuUsage:F2}%");
            sb.AppendLine($"内存使用: {CurrentMemoryUsage} MB / {CurrentMemoryUsage + CurrentAvailableMemory} MB");
            sb.AppendLine($"可用内存: {CurrentAvailableMemory} MB");
            sb.AppendLine($"网络发送: {CurrentNetworkSendSpeed:F2} KB/s");
            sb.AppendLine($"网络接收: {CurrentNetworkReceiveSpeed:F2} KB/s");
            sb.AppendLine($"平均CPU使用率: {AverageCpuUsage:F2}%");
            sb.AppendLine($"平均内存使用: {AverageMemoryUsage:F2} MB");
            sb.AppendLine($"峰值CPU使用率: {PeakCpuUsage:F2}%");
            sb.AppendLine($"峰值内存使用: {PeakMemoryUsage} MB");
            return sb.ToString();
        }

        /// <summary>
        /// 获取资源使用趋势
        /// </summary>
        /// <param name="minutes">趋势时间范围（分钟）</param>
        /// <returns>资源使用趋势</returns>
        public string GetResourceUsageTrend(int minutes = 5)
        {
            var cutoffTime = DateTime.Now.AddMinutes(-minutes);
            var recentUsage = _resourceUsageHistory
                .Where(u => u.Timestamp >= cutoffTime)
                .ToList();
            
            if (recentUsage.Count == 0)
                return "无足够的历史数据";
            
            var sb = new StringBuilder();
            sb.AppendLine($"=== 最近 {minutes} 分钟资源使用趋势 ===");
            
            // CPU趋势
            double cpuStart = recentUsage.First().CpuUsage;
            double cpuEnd = recentUsage.Last().CpuUsage;
            double cpuChange = cpuEnd - cpuStart;
            sb.AppendLine($"CPU使用率: {cpuStart:F2}% → {cpuEnd:F2}% ({(cpuChange >= 0 ? "↑" : "↓")} {Math.Abs(cpuChange):F2}%)");
            
            // 内存趋势
            long memoryStart = recentUsage.First().MemoryUsage;
            long memoryEnd = recentUsage.Last().MemoryUsage;
            long memoryChange = memoryEnd - memoryStart;
            sb.AppendLine($"内存使用: {memoryStart} MB → {memoryEnd} MB ({(memoryChange >= 0 ? "↑" : "↓")} {Math.Abs(memoryChange)} MB)");
            
            // 网络趋势
            double sendStart = recentUsage.First().NetworkSendSpeed;
            double sendEnd = recentUsage.Last().NetworkSendSpeed;
            double receiveStart = recentUsage.First().NetworkReceiveSpeed;
            double receiveEnd = recentUsage.Last().NetworkReceiveSpeed;
            sb.AppendLine($"网络发送: {sendStart:F2} KB/s → {sendEnd:F2} KB/s");
            sb.AppendLine($"网络接收: {receiveStart:F2} KB/s → {receiveEnd:F2} KB/s");
            
            return sb.ToString();
        }

        /// <summary>
        /// 释放资源
        /// </summary>
        public void Dispose()
        {
            StopMonitoring();
            _cancellationTokenSource?.Dispose();
        }

        /// <summary>
        /// 资源使用记录
        /// </summary>
        public class ResourceUsage
        {
            /// <summary>
            /// 记录时间戳
            /// </summary>
            public DateTime Timestamp { get; set; }

            /// <summary>
            /// CPU使用率（百分比）
            /// </summary>
            public double CpuUsage { get; set; }

            /// <summary>
            /// 内存使用量（MB）
            /// </summary>
            public long MemoryUsage { get; set; }

            /// <summary>
            /// 可用内存（MB）
            /// </summary>
            public long AvailableMemory { get; set; }

            /// <summary>
            /// 网络发送速度（KB/s）
            /// </summary>
            public double NetworkSendSpeed { get; set; }

            /// <summary>
            /// 网络接收速度（KB/s）
            /// </summary>
            public double NetworkReceiveSpeed { get; set; }
        }
    }
}
