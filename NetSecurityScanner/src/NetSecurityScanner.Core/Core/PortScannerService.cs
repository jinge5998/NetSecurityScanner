using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using NetSecurityScanner.Models;
using NetSecurityScanner.Utils;

namespace NetSecurityScanner.Core
{
    /// <summary>
    /// 高性能端口扫描服务 - 优化版本（增强性能监控）
    /// 改进点：
    /// 1. 使用Socket池减少连接开销
    /// 2. 增加最大并发数
    /// 3. 智能并发控制
    /// 4. 批量扫描策略
    /// 5. 异步处理优化
    /// 6. 集成ScanPerformanceMonitor进行实时监控
    /// </summary>
    public class PortScannerService
    {
        private CancellationTokenSource? _cancellationTokenSource;
        private int _completedPorts;
        private int _totalPorts;
        private SocketPool? _socketPool;
        private DateTime _scanStartTime;
        private int _successfulScans;
        private int _failedScans;
        private PerformanceStatistics? _performanceStats;
        private ScanResultCache? _resultCache;
        private ResourceMonitor? _resourceMonitor;
        private Logger? _logger;
        
        // 新增：增强性能监控器
        private ScanPerformanceMonitor? _scanPerfMonitor;

        public event EventHandler<ScanProgressEventArgs>? ScanProgressChanged;
        public event EventHandler<PortScannedEventArgs>? PortScanned;
        
        /// <summary>
        /// 获取性能监控报告
        /// </summary>
        public ScanPerformanceReport? PerformanceReport => _scanPerfMonitor?.GenerateReport();

        /// <summary>
        /// 当前扫描速度（端口/秒）
        /// </summary>
        public double CurrentScanSpeed => CalculateScanSpeed();

        /// <summary>
        /// 预计完成时间
        /// </summary>
        public TimeSpan? EstimatedTimeRemaining => CalculateEstimatedTimeRemaining();

        public void CancelScan()
        {
            _cancellationTokenSource?.Cancel();
        }

        /// <summary>
        /// 批量端口扫描 - 使用分区并行处理
        /// </summary>
        public async Task<List<PortInfo>> ScanPortsAsync(
            string host, 
            List<int> ports, 
            ScanOptions options,
            IProgress<ScanProgressInfo> progress = null,
            CancellationToken externalCancellationToken = default)
        {
            // 创建链接的取消令牌源，支持外部取消
            _cancellationTokenSource = CancellationTokenSource.CreateLinkedTokenSource(externalCancellationToken);
            var cancellationToken = _cancellationTokenSource.Token;
            
            // 使用内存优化的结果存储
            var results = new ConcurrentBag<PortInfo>();
            
            // 智能并发控制 - 根据端口数量和系统资源动态调整
            int optimalConcurrency = CalculateOptimalConcurrency(ports.Count, options.MaxConcurrency);
            // 根据可用内存进一步调整并发数
            optimalConcurrency = AdjustConcurrencyByMemory(optimalConcurrency);
            options.MaxConcurrency = optimalConcurrency;
            
            // 初始化Socket池
            _socketPool = new SocketPool(Math.Min(optimalConcurrency, 1000));
            
            _completedPorts = 0;
            _totalPorts = ports.Count;
            _scanStartTime = DateTime.Now;
            _successfulScans = 0;
            _failedScans = 0;
            
            // 初始化性能统计
            _performanceStats = new PerformanceStatistics();
            _performanceStats.StartScan(ports.Count);
            
            // 初始化扫描结果缓存
            _resultCache = new ScanResultCache();
            
            // 初始化资源监控
            _resourceMonitor = new ResourceMonitor();
            _resourceMonitor.StartMonitoring();
            
            // 初始化日志记录器
            _logger = new Logger();
            _logger.LogScanStart(host, ports.Count, options);
            
            // 初始化增强性能监控器（新增）
            _scanPerfMonitor = new ScanPerformanceMonitor();
            _scanPerfMonitor.StartMonitoring();

            var semaphore = new SemaphoreSlim(options.MaxConcurrency, options.MaxConcurrency);

            try
            {
                // 预解析IP地址避免重复解析
                IPAddress ipAddress;
                if (!IPAddress.TryParse(host, out ipAddress))
                {
                    var addresses = await Dns.GetHostAddressesAsync(host);
                    if (addresses.Length == 0)
                        throw new ArgumentException($"无法解析主机: {host}");
                    ipAddress = addresses[0];
                }

                // 根据系统资源动态调整分批扫描阈值
                int batchScanThreshold = CalculateBatchScanThreshold();
                
                // 大端口范围时使用分批扫描策略
                if (ports.Count > batchScanThreshold)
                {
                    return await BatchScanPortsAsync(ipAddress, ports, options, progress, cancellationToken);
                }

                // 使用异步并行扫描，避免线程阻塞
                var tasks = new List<Task>();
                var maxConcurrentTasks = Math.Min(options.MaxConcurrency, 1000);
                var throttler = new SemaphoreSlim(maxConcurrentTasks, maxConcurrentTasks);
                
                // 任务调度和错误处理增强
                // 对于大端口列表，使用分批处理避免一次性创建过多任务
                int batchSize = Math.Min(1000, ports.Count);
                for (int i = 0; i < ports.Count; i += batchSize)
                {
                    if (cancellationToken.IsCancellationRequested)
                        break;
                    
                    var batchPorts = ports.Skip(i).Take(batchSize).ToList();
                    foreach (var port in batchPorts)
                    {
                        if (cancellationToken.IsCancellationRequested)
                            break;
                        
                        tasks.Add(ProcessPortAsync(port, ipAddress, options, progress, throttler, results, cancellationToken));
                    }
                    
                    // 每批任务完成后清理内存
                    if (tasks.Count >= maxConcurrentTasks * 2)
                    {
                        // 等待部分任务完成，释放内存
                        var completedTasks = await Task.WhenAny(tasks.Select(t => t.ContinueWith(_ => t)));
                        // 移除已完成的任务
                        tasks.RemoveAll(t => t.IsCompleted);
                    }
                }

                // 等待所有扫描任务完成，即使部分任务失败
                bool wasCancelled = false;
                if (tasks.Count > 0)
                {
                    try
                    {
                        await Task.WhenAll(tasks);
                    }
                    catch (OperationCanceledException)
                    {
                        // 扫描被取消，标记状态
                        wasCancelled = true;
                        Console.WriteLine("扫描已被用户取消");
                    }
                    catch (AggregateException aex)
                    {
                        // 处理AggregateException，检查是否包含取消异常
                        bool hasCancelException = aex.InnerExceptions.Any(e => e is OperationCanceledException);
                        bool hasOtherExceptions = aex.InnerExceptions.Any(e => !(e is OperationCanceledException));
                        
                        if (hasCancelException)
                        {
                            wasCancelled = true;
                            Console.WriteLine("扫描已被用户取消");
                        }
                        
                        if (hasOtherExceptions)
                        {
                            foreach (var ex in aex.InnerExceptions.Where(e => !(e is OperationCanceledException)))
                            {
                                Console.WriteLine($"扫描过程中发生错误: {ex.Message}");
                            }
                        }
                    }
                    catch (Exception ex)
                    {
                        // 记录其他异常但不抛出
                        Console.WriteLine($"扫描过程中发生错误: {ex.Message}");
                    }
                }
                
                // 处理失败的任务
                var failedTasks = tasks.Where(t => t.IsFaulted).ToList();
                if (failedTasks.Count > 0)
                {
                    Console.WriteLine($"扫描过程中有 {failedTasks.Count} 个端口扫描失败");
                    // 记录失败的异常详情
                    foreach (var failedTask in failedTasks)
                    {
                        if (failedTask.Exception != null)
                        {
                            Console.WriteLine($"  - 失败原因: {failedTask.Exception.InnerException?.Message ?? failedTask.Exception.Message}");
                        }
                    }
                }
                
                // 如果扫描被取消，抛出异常通知上层
                if (wasCancelled || cancellationToken.IsCancellationRequested)
                {
                    throw new OperationCanceledException("扫描已被用户取消");
                }
            }
            finally
            {
                // 停止性能统计
                _performanceStats?.StopScan();
                
                // 停止增强性能监控器（新增）
                if (_scanPerfMonitor != null)
                {
                    _scanPerfMonitor.StopMonitoring();
                    var perfReport = _scanPerfMonitor.GenerateReport();
                    
                    Console.WriteLine("\n=== 扫描性能报告 ===");
                    Console.WriteLine(perfReport);
                    Console.WriteLine("==================\n");
                    
                    Debug.WriteLine(perfReport.ToString());
                }
                
                // 输出性能报告
                if (_performanceStats != null)
                {
                    Console.WriteLine(_performanceStats.GeneratePerformanceReport());
                    
                    // 保存性能报告到文件
                    try
                    {
                        string reportDir = "PerformanceReports";
                        if (!System.IO.Directory.Exists(reportDir))
                        {
                            System.IO.Directory.CreateDirectory(reportDir);
                        }
                        
                        string timestamp = DateTime.Now.ToString("yyyyMMdd_HHmmss");
                        string txtReportPath = System.IO.Path.Combine(reportDir, $"performance_report_{timestamp}.txt");
                        string htmlReportPath = System.IO.Path.Combine(reportDir, $"performance_report_{timestamp}.html");
                        
                        _performanceStats.SavePerformanceReport(txtReportPath, "txt");
                        _performanceStats.SavePerformanceReport(htmlReportPath, "html");
                        
                        Console.WriteLine($"性能报告已保存到:\n- TXT格式: {txtReportPath}\n- HTML格式: {htmlReportPath}");
                    }
                    catch (Exception ex)
                    {
                        Console.WriteLine($"保存性能报告时出错: {ex.Message}");
                    }
                }
                
                // 输出Socket池统计信息
                if (_socketPool != null)
                {
                    Console.WriteLine(_socketPool.GetStatistics());
                    _socketPool.Dispose();
                }
                
                // 输出缓存统计信息
                if (_resultCache != null)
                {
                    Console.WriteLine(_resultCache.GetStatistics());
                }
                
                // 输出资源监控统计信息
                if (_resourceMonitor != null)
                {
                    _resourceMonitor.StopMonitoring();
                    Console.WriteLine(_resourceMonitor.GetResourceUsageSummary());
                    Console.WriteLine(_resourceMonitor.GetResourceUsageTrend());
                    _resourceMonitor.Dispose();
                }
                
                // 输出日志统计信息
                if (_logger != null)
                {
                    Console.WriteLine(_logger.GetLogStatistics());
                    _logger.Dispose();
                }
            }
            
            return results.OrderBy(p => p.PortNumber).ToList();
        }
        
        /// <summary>
        /// 根据可用内存调整并发数
        /// </summary>
        /// <param name="baseConcurrency">基础并发数</param>
        /// <returns>调整后的并发数</returns>
        private int AdjustConcurrencyByMemory(int baseConcurrency)
        {
            long availableMemory = GetAvailableMemoryMb();
            
            // 根据可用内存调整并发数
            if (availableMemory < 512)
            {
                // 内存严重不足，大幅减少并发数
                return Math.Max(50, baseConcurrency / 3);
            }
            else if (availableMemory < 1024)
            {
                // 内存不足，减少并发数
                return Math.Max(100, baseConcurrency / 2);
            }
            else if (availableMemory < 2048)
            {
                // 内存适中，保持并发数
                return baseConcurrency;
            }
            // 内存充足，保持或增加并发数
            return baseConcurrency;
        }
        
        /// <summary>
        /// 分批扫描大端口范围
        /// </summary>
        private async Task<List<PortInfo>> BatchScanPortsAsync(
            IPAddress ipAddress, 
            List<int> ports, 
            ScanOptions options,
            IProgress<ScanProgressInfo> progress,
            CancellationToken cancellationToken)
        {
            var allResults = new ConcurrentBag<PortInfo>();
            int initialBatchSize = CalculateOptimalBatchSize(ports.Count);
            // 根据可用内存调整初始批量大小
            initialBatchSize = AdjustBatchSizeByMemory(initialBatchSize);
            int currentBatchSize = initialBatchSize;
            int totalBatches = (int)Math.Ceiling((double)ports.Count / initialBatchSize);
            int completedBatches = 0;
            
            // 记录批量扫描开始
            _performanceStats?.RecordPhase("BatchScanStart", 0);
            
            for (int i = 0; i < ports.Count; i += currentBatchSize)
            {
                if (cancellationToken.IsCancellationRequested)
                    break;
                
                // 动态调整批量大小 - 根据前一批的处理时间和当前内存使用情况
                if (completedBatches > 0)
                {
                    currentBatchSize = AdjustBatchSize(currentBatchSize, options);
                    // 根据内存使用情况进一步调整
                    currentBatchSize = AdjustBatchSizeByMemory(currentBatchSize);
                }
                
                var batchPorts = ports.Skip(i).Take(currentBatchSize).ToList();
                var batchStartTime = DateTime.Now;
                
                // 并行处理多个批次（如果系统资源允许）
                var batchResults = await ScanBatchAsync(ipAddress, batchPorts, options, progress, cancellationToken);
                var batchTimeMs = (long)(DateTime.Now - batchStartTime).TotalMilliseconds;
                
                // 记录批处理性能统计
                _performanceStats?.RecordBatchCompleted(batchPorts.Count, batchTimeMs);
                
                // 批量添加结果，减少锁竞争
                // 只添加开放端口和错误端口，减少内存使用
                foreach (var result in batchResults)
                {
                    if (result.Status == "开放" || result.Status == "Error")
                    {
                        allResults.Add(result);
                    }
                }
                
                // 清理批次结果，释放内存
                batchResults.Clear();
                
                completedBatches++;
                
                // 更新总体进度
                var completed = Math.Min(i + currentBatchSize, ports.Count);
                var percentage = (int)((double)completed / ports.Count * 100);
                
                // 记录扫描阶段
                _performanceStats?.RecordPhase(
                    $"Batch {completedBatches}/{totalBatches}", 
                    completed
                );
                
                // 监控内存使用情况
                long availableMemory = GetAvailableMemoryMb();
                
                var progressInfo = new ScanProgressInfo
                {
                    CompletedCount = completed,
                    TotalCount = ports.Count,
                    Percentage = percentage,
                    ScanSpeed = CurrentScanSpeed,
                    EstimatedTimeRemaining = EstimatedTimeRemaining,
                    CurrentBatchSize = currentBatchSize,
                    CompletedBatches = completedBatches,
                    TotalBatches = totalBatches,
                    AvailableMemoryMb = availableMemory
                };
                
                progress?.Report(progressInfo);
                ScanProgressChanged?.Invoke(this, new ScanProgressEventArgs(progressInfo));
                
                // 定期清理内存
                if (completedBatches % 5 == 0)
                {
                    GC.Collect(2, GCCollectionMode.Optimized);
                }
            }
            
            // 记录批量扫描完成
            _performanceStats?.RecordPhase("BatchScanEnd", ports.Count);
            
            // 清理内存
            GC.Collect(2, GCCollectionMode.Optimized);
            
            return allResults.OrderBy(p => p.PortNumber).ToList();
        }
        
        /// <summary>
        /// 根据可用内存调整批量大小
        /// </summary>
        /// <param name="baseBatchSize">基础批量大小</param>
        /// <returns>调整后的批量大小</returns>
        private int AdjustBatchSizeByMemory(int baseBatchSize)
        {
            long availableMemory = GetAvailableMemoryMb();
            
            // 根据可用内存调整批量大小
            if (availableMemory < 512)
            {
                // 内存严重不足，大幅减少批量大小
                return Math.Max(500, baseBatchSize / 3);
            }
            else if (availableMemory < 1024)
            {
                // 内存不足，减少批量大小
                return Math.Max(1000, baseBatchSize / 2);
            }
            else if (availableMemory < 2048)
            {
                // 内存适中，保持批量大小
                return baseBatchSize;
            }
            // 内存充足，保持或增加批量大小
            return baseBatchSize;
        }
        
        /// <summary>
        /// 扫描单个批次
        /// </summary>
        private async Task<List<PortInfo>> ScanBatchAsync(
            IPAddress ipAddress, 
            List<int> ports, 
            ScanOptions options,
            IProgress<ScanProgressInfo> progress,
            CancellationToken cancellationToken)
        {
            var results = new ConcurrentBag<PortInfo>();
            var semaphore = new SemaphoreSlim(options.MaxConcurrency, options.MaxConcurrency);
            
            var tasks = ports.Select(async port =>
            {
                await semaphore.WaitAsync(cancellationToken);
                try
                {
                    if (cancellationToken.IsCancellationRequested)
                        return;
                    
                    var portInfo = await ScanPortOptimized(ipAddress, port, options, cancellationToken);
                    results.Add(portInfo);
                    
                    // 统计扫描结果
                    if (portInfo.Status == "开放")
                        Interlocked.Increment(ref _successfulScans);
                    else
                        Interlocked.Increment(ref _failedScans);
                    
                    // 记录性能监控数据（新增）
                    _scanPerfMonitor?.RecordPortScanned(portInfo.Status == "开放", 0);
                    
                    // 记录性能统计
                    _performanceStats?.RecordPortScanned(
                        portInfo.Status != "Error", 
                        portInfo.Status == "开放"
                    );
                    
                    // 更新进度
                    var completed = Interlocked.Increment(ref _completedPorts);
                    var percentage = (int)((double)completed / _totalPorts * 100);
                    
                    // 计算开放端口数
                    int openPorts = results.Count(p => p.Status == "开放");
                    
                    // 获取系统内存使用情况
                    long availableMemory = GetAvailableMemoryMb();
                    
                    var progressInfo = new ScanProgressInfo
                    {
                        CompletedCount = completed,
                        TotalCount = _totalPorts,
                        Percentage = percentage,
                        CurrentPort = port,
                        PortInfo = portInfo,
                        ScanSpeed = CurrentScanSpeed,
                        EstimatedTimeRemaining = EstimatedTimeRemaining,
                        SuccessfulScans = _successfulScans,
                        FailedScans = _failedScans,
                        OpenPorts = openPorts,
                        ScanMode = ports.Count > 10000 ? "Batch" : "Normal",
                        CurrentConcurrency = options.MaxConcurrency,
                        AvailableMemoryMb = availableMemory,
                        BatchInfo = ports.Count > 10000 ? "Batch scanning mode" : "Single pass mode",
                        StatusDescription = GetScanStatusDescription(completed, _totalPorts, openPorts)
                    };
                    
                    progress?.Report(progressInfo);
                    ScanProgressChanged?.Invoke(this, new ScanProgressEventArgs(progressInfo));
                    PortScanned?.Invoke(this, new PortScannedEventArgs(portInfo));
                }
                finally
                {
                    semaphore.Release();
                }
            });
            
            try
            {
                await Task.WhenAll(tasks);
            }
            catch (OperationCanceledException)
            {
                // 扫描被取消，这是正常的
                Console.WriteLine("批次扫描已被用户取消");
            }
            catch (AggregateException aex)
            {
                // 处理AggregateException，检查是否包含取消异常
                bool hasCancelException = aex.InnerExceptions.Any(e => e is OperationCanceledException);
                bool hasOtherExceptions = aex.InnerExceptions.Any(e => !(e is OperationCanceledException));
                
                if (hasCancelException)
                {
                    Console.WriteLine("批次扫描已被用户取消");
                }
                
                if (hasOtherExceptions)
                {
                    foreach (var ex in aex.InnerExceptions.Where(e => !(e is OperationCanceledException)))
                    {
                        Console.WriteLine($"批次扫描过程中发生错误: {ex.Message}");
                    }
                }
            }
            catch (Exception ex)
            {
                // 记录异常但不抛出
                Console.WriteLine($"批次扫描过程中发生错误: {ex.Message}");
            }
            
            return results.ToList();
        }
        
        /// <summary>
        /// 优化的端口扫描 - 使用Socket池减少开销
        /// </summary>
        private async Task<PortInfo> ScanPortOptimized(IPAddress ipAddress, int port, ScanOptions options, CancellationToken cancellationToken)
        {
            string host = ipAddress.ToString();
            string protocol = options.ScanType;
            
            // 检查缓存中是否已有结果
            if (_resultCache != null && _resultCache.TryGetCachedResult(host, port, protocol, out var cachedPortInfo))
            {
                // 记录缓存命中的性能统计
                _performanceStats?.RecordOperationTime("CacheHit", 0);
                return cachedPortInfo;
            }
            
            var portInfo = new PortInfo
            {
                Host = host,
                PortNumber = port,
                Protocol = protocol,
                ScanTime = DateTime.Now,
                Status = "Closed"
            };
            
            if (protocol.Equals("TCP", StringComparison.OrdinalIgnoreCase))
            {
                await ScanTcpPortOptimized(portInfo, ipAddress, port, options, cancellationToken);
            }
            else if (protocol.Equals("UDP", StringComparison.OrdinalIgnoreCase))
            {
                await ScanUdpPortOptimized(portInfo, ipAddress, port, options, cancellationToken);
            }
            
            if (portInfo.Status == "开放" && options.EnableServiceDetection)
            {
                await DetectServiceOptimized(portInfo, ipAddress, cancellationToken);
            }
            
            // 将扫描结果添加到缓存
            _resultCache?.AddToCache(host, port, protocol, portInfo);
            
            return portInfo;
        }
        
        /// <summary>
        /// 优化的TCP端口扫描 - 使用Socket池
        /// </summary>
        private async Task ScanTcpPortOptimized(PortInfo portInfo, IPAddress ipAddress, int port, ScanOptions options, CancellationToken cancellationToken)
        {
            Socket socket = null;
            int retries = 0;
            const int maxRetries = 3;
            bool isRetryableError = false;
            
            do
            {
                try
                {
                    // 从Socket池获取连接
                    socket = await _socketPool.AcquireAsync(cancellationToken);
                    
                    // 设置超时
                    int timeout = CalculateDynamicTimeout(options.Timeout);
                    
                    // 使用异步连接，优化超时处理
                    using (var cts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken))
                    {
                        cts.CancelAfter(timeout);
                        
                        try
                        {
                            await socket.ConnectAsync(new IPEndPoint(ipAddress, port), cts.Token);
                            portInfo.Status = "开放";
                            return;
                        }
                        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
                        {
                            // 连接超时
                            portInfo.Status = "Filtered";
                            return;
                        }
                        catch (SocketException ex) when (ex.SocketErrorCode == SocketError.ConnectionRefused)
                        {
                            // 连接被拒绝 - 端口关闭
                            portInfo.Status = "Closed";
                            return;
                        }
                        catch (SocketException ex) when (
                            ex.SocketErrorCode == SocketError.TimedOut ||
                            ex.SocketErrorCode == SocketError.NetworkUnreachable ||
                            ex.SocketErrorCode == SocketError.HostUnreachable ||
                            ex.SocketErrorCode == SocketError.WouldBlock ||
                            ex.SocketErrorCode == SocketError.NoBufferSpaceAvailable ||
                            ex.SocketErrorCode == SocketError.Interrupted
                        )
                        {
                            // 可重试的网络错误
                            isRetryableError = true;
                            retries++;
                            if (retries > maxRetries)
                            {
                                portInfo.Status = "Filtered";
                                return;
                            }
                            // 指数退避延迟后重试
                            await Task.Delay(100 * retries, cancellationToken);
                        }
                        catch (SocketException ex) when (
                            ex.SocketErrorCode == SocketError.AccessDenied ||
                            ex.SocketErrorCode == SocketError.AddressFamilyNotSupported ||
                            ex.SocketErrorCode == SocketError.ProtocolNotSupported
                        )
                        {
                            // 不可重试的错误
                            portInfo.Status = "Error";
                            portInfo.Service = "Permission Error";
                            return;
                        }
                        catch (Exception)
                        {
                            // 其他错误
                            portInfo.Status = "Filtered";
                            return;
                        }
                    }
                }
                catch (Exception) when (!cancellationToken.IsCancellationRequested)
                {
                    // Socket池或其他错误
                    isRetryableError = true;
                    retries++;
                    if (retries > maxRetries)
                    {
                        portInfo.Status = "Error";
                        portInfo.Service = "Connection Error";
                        return;
                    }
                    // 短暂延迟后重试
                    await Task.Delay(100 * retries, cancellationToken);
                }
                finally
                {
                    if (socket != null)
                    {
                        try
                        {
                            _socketPool.Release(socket);
                        }
                        catch
                        {
                            // Socket释放失败，忽略错误
                        }
                    }
                }
            } while (isRetryableError && retries <= maxRetries && !cancellationToken.IsCancellationRequested);
        }
        
        /// <summary>
        /// 优化的UDP端口扫描
        /// </summary>
        private async Task ScanUdpPortOptimized(PortInfo portInfo, IPAddress ipAddress, int port, ScanOptions options, CancellationToken cancellationToken)
        {
            int retries = 0;
            const int maxRetries = 2;
            bool success = false;
            
            do
            {
                using (var socket = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp))
                {
                    try
                    {
                        int timeout = CalculateDynamicTimeout(options.Timeout);
                        socket.ReceiveTimeout = timeout;
                        socket.SendTimeout = timeout;
                        
                        var endPoint = new IPEndPoint(ipAddress, port);
                        var data = new byte[] { 0x00 };
                        
                        await socket.SendToAsync(data, SocketFlags.None, endPoint);
                        
                        var buffer = new byte[1024];
                        EndPoint remoteEndPoint = new IPEndPoint(IPAddress.Any, 0);
                        
                        var receiveTask = socket.ReceiveFromAsync(new ArraySegment<byte>(buffer), SocketFlags.None, remoteEndPoint);
                        var timeoutTask = Task.Delay(timeout, cancellationToken);
                        
                        var completedTask = await Task.WhenAny(receiveTask, timeoutTask);
                        
                        if (completedTask == receiveTask && receiveTask.IsCompletedSuccessfully)
                        {
                            portInfo.Status = "开放";
                            success = true;
                            return;
                        }
                        else
                        {
                            portInfo.Status = "Open|Filtered";
                            success = true;
                            return;
                        }
                    }
                    catch (SocketException ex) when (ex.SocketErrorCode == SocketError.ConnectionReset)
                    {
                        // ICMP端口不可达 - 端口关闭
                        portInfo.Status = "Closed";
                        success = true;
                        return;
                    }
                    catch (SocketException ex) when (
                        ex.SocketErrorCode == SocketError.TimedOut ||
                        ex.SocketErrorCode == SocketError.NetworkUnreachable ||
                        ex.SocketErrorCode == SocketError.HostUnreachable ||
                        ex.SocketErrorCode == SocketError.WouldBlock ||
                        ex.SocketErrorCode == SocketError.NoBufferSpaceAvailable
                    )
                    {
                        // 可重试的网络错误
                        retries++;
                        if (retries > maxRetries)
                        {
                            portInfo.Status = "Open|Filtered";
                            return;
                        }
                        // 短暂延迟后重试
                        await Task.Delay(100 * retries, cancellationToken);
                    }
                    catch (SocketException ex) when (
                        ex.SocketErrorCode == SocketError.AccessDenied
                    )
                    {
                        // 不可重试的错误
                        portInfo.Status = "Error";
                        portInfo.Service = "Permission Error";
                        return;
                    }
                    catch (OperationCanceledException)
                    {
                        // 任务被取消
                        throw;
                    }
                    catch (Exception)
                    {
                        // 其他错误
                        portInfo.Status = "Open|Filtered";
                        return;
                    }
                }
            } while (retries <= maxRetries && !cancellationToken.IsCancellationRequested);
        }
        
        /// <summary>
        /// 处理单个端口的扫描任务
        /// </summary>
        private async Task ProcessPortAsync(
            int port,
            IPAddress ipAddress,
            ScanOptions options,
            IProgress<ScanProgressInfo> progress,
            SemaphoreSlim throttler,
            ConcurrentBag<PortInfo> results,
            CancellationToken cancellationToken)
        {
            await throttler.WaitAsync(cancellationToken);
            
            int retryCount = 0;
            const int maxRetries = 2;
            bool success = false;
            PortInfo portInfo = null;
            
            try
            {
                do
                {
                    try
                    {
                        // 扫描端口
                        portInfo = await ScanPortOptimized(ipAddress, port, options, cancellationToken);
                        results.Add(portInfo);
                        
                        // 统计扫描结果
                        if (portInfo.Status == "开放")
                            Interlocked.Increment(ref _successfulScans);
                        else
                            Interlocked.Increment(ref _failedScans);
                        
                        // 报告进度 - 使用Interlocked确保线程安全
                        var completed = Interlocked.Increment(ref _completedPorts);
                        var percentage = (int)((double)completed / _totalPorts * 100);
                        
                        var progressInfo = new ScanProgressInfo
                        {
                            CompletedCount = completed,
                            TotalCount = _totalPorts,
                            Percentage = percentage,
                            CurrentPort = port,
                            PortInfo = portInfo,
                            ScanSpeed = CurrentScanSpeed,
                            EstimatedTimeRemaining = EstimatedTimeRemaining
                        };
                        
                        progress?.Report(progressInfo);
                        ScanProgressChanged?.Invoke(this, new ScanProgressEventArgs(progressInfo));
                        PortScanned?.Invoke(this, new PortScannedEventArgs(portInfo));
                        
                        success = true;
                        break;
                    }
                    catch (OperationCanceledException)
                    {
                        // 任务被取消，直接退出，不抛出异常
                        return;
                    }
                    catch (Exception)
                    {
                        retryCount++;
                        if (retryCount > maxRetries)
                        {
                            // 达到最大重试次数，创建失败的端口信息
                            portInfo = new PortInfo
                            {
                                Host = ipAddress.ToString(),
                                PortNumber = port,
                                Protocol = options.ScanType,
                                ScanTime = DateTime.Now,
                                Status = "Error",
                                Service = "Unknown",
                                Version = "Error"
                            };
                            results.Add(portInfo);
                            Interlocked.Increment(ref _failedScans);
                            
                            // 报告进度
                            var completed = Interlocked.Increment(ref _completedPorts);
                            var percentage = (int)((double)completed / _totalPorts * 100);
                            
                            var progressInfo = new ScanProgressInfo
                            {
                                CompletedCount = completed,
                                TotalCount = _totalPorts,
                                Percentage = percentage,
                                CurrentPort = port,
                                PortInfo = portInfo,
                                ScanSpeed = CurrentScanSpeed,
                                EstimatedTimeRemaining = EstimatedTimeRemaining
                            };
                            
                            progress?.Report(progressInfo);
                            ScanProgressChanged?.Invoke(this, new ScanProgressEventArgs(progressInfo));
                            PortScanned?.Invoke(this, new PortScannedEventArgs(portInfo));
                            
                            break;
                        }
                        
                        // 短暂延迟后重试
                        await Task.Delay(50 * retryCount, cancellationToken);
                    }
                } while (retryCount <= maxRetries && !cancellationToken.IsCancellationRequested);
            }
            finally
            {
                throttler.Release();
            }
        }

        /// <summary>
        /// 优化的服务检测 - 复用连接
        /// </summary>
        private async Task DetectServiceOptimized(PortInfo portInfo, IPAddress ipAddress, CancellationToken cancellationToken)
        {
            // 基于端口的服务识别（快速路径）
            portInfo.Service = GetServiceByPort(portInfo.PortNumber);
            
            // 添加服务详情
            portInfo.ServiceDetails = GetServiceDetails(portInfo.PortNumber);
            
            // 评估风险等级
            portInfo.RiskLevel = EvaluatePortRiskLevel(portInfo.PortNumber, portInfo.Service);
            
            // 尝试获取Banner（可选，异步超时控制）
            if (portInfo.PortNumber == 80 || portInfo.PortNumber == 443 || 
                portInfo.PortNumber == 22 || portInfo.PortNumber == 21)
            {
                await TryGetBannerOptimized(portInfo, ipAddress, cancellationToken);
            }
        }
        
        /// <summary>
        /// 获取服务详情
        /// </summary>
        private string GetServiceDetails(int port)
        {
            return port switch
            {
                21 => "文件传输协议，用于文件上传和下载",
                22 => "安全外壳协议，用于安全远程登录",
                23 => "远程终端协议，用于远程登录（不安全）",
                25 => "简单邮件传输协议，用于发送邮件",
                53 => "域名系统，用于域名解析",
                80 => "超文本传输协议，用于网页访问",
                443 => "安全超文本传输协议，用于加密网页访问",
                110 => "邮局协议版本3，用于接收邮件",
                143 => "互联网消息访问协议，用于接收邮件",
                3306 => "MySQL数据库服务",
                3389 => "远程桌面协议，用于远程桌面访问",
                5432 => "PostgreSQL数据库服务",
                6379 => "Redis缓存服务",
                8080 => "HTTP代理或备用Web服务端口",
                _ => "通用网络服务"
            };
        }
        
        /// <summary>
        /// 评估端口风险等级
        /// </summary>
        private string EvaluatePortRiskLevel(int port, string service)
        {
            // 高风险端口
            var highRiskPorts = new[] { 21, 23, 25, 135, 139, 445, 1433, 1521, 3306, 3389, 5432, 5900, 6379, 8080, 27017 };
            if (highRiskPorts.Contains(port))
                return "高风险";
            
            // 中等风险端口
            var mediumRiskPorts = new[] { 22, 53, 80, 110, 143, 443 };
            if (mediumRiskPorts.Contains(port))
                return "中等风险";
            
            return "低风险";
        }
        
        /// <summary>
        /// 优化的Banner获取 - 使用Socket池
        /// </summary>
        private async Task TryGetBannerOptimized(PortInfo portInfo, IPAddress ipAddress, CancellationToken cancellationToken)
        {
            Socket socket = null;
            try
            {
                socket = await _socketPool.AcquireAsync(cancellationToken);
                socket.ReceiveTimeout = 1000;
                socket.SendTimeout = 1000;
                
                await socket.ConnectAsync(new IPEndPoint(ipAddress, portInfo.PortNumber));
                
                // 发送探测数据
                byte[] probeData = GetProbeData(portInfo.PortNumber);
                if (probeData != null)
                {
                    await socket.SendAsync(probeData, SocketFlags.None);
                    await Task.Delay(100, cancellationToken); // 短暂等待响应
                }
                
                // 接收响应
                var buffer = new byte[512];
                var receiveTask = socket.ReceiveAsync(new ArraySegment<byte>(buffer), SocketFlags.None);
                var timeoutTask = Task.Delay(1000, cancellationToken);
                
                var completedTask = await Task.WhenAny(receiveTask, timeoutTask);
                if (completedTask == receiveTask && receiveTask.IsCompletedSuccessfully)
                {
                    var bytesRead = receiveTask.Result;
                    if (bytesRead > 0)
                    {
                        var banner = Encoding.ASCII.GetString(buffer, 0, bytesRead).Trim();
                        if (!string.IsNullOrEmpty(banner))
                        {
                            portInfo.Version = ParseVersionFromBanner(banner, portInfo.Service);
                        }
                    }
                }
            }
            catch (Exception)
            {
                // 忽略错误
            }
            finally
            {
                if (socket != null)
                {
                    _socketPool.Release(socket);
                }
            }
        }
        
        /// <summary>
        /// 根据端口获取探测数据
        /// </summary>
        private byte[] GetProbeData(int port)
        {
            return port switch
            {
                21 => Encoding.ASCII.GetBytes("USER anonymous\r\n"),
                22 => null, // SSH通常主动发送banner
                25 => Encoding.ASCII.GetBytes("EHLO scanner\r\n"),
                80 => Encoding.ASCII.GetBytes("HEAD / HTTP/1.0\r\n\r\n"),
                443 => null, // HTTPS需要SSL握手
                _ => null
            };
        }
        
        /// <summary>
        /// 从Banner解析版本信息
        /// </summary>
        private string ParseVersionFromBanner(string banner, string service)
        {
            if (string.IsNullOrEmpty(banner))
                return "Unknown";
            
            // 限制长度
            if (banner.Length > 100)
                banner = banner.Substring(0, 100) + "...";
            
            // 简单的版本解析逻辑
            return banner.Replace("\r", "").Replace("\n", " ");
        }
        
        /// <summary>
        /// 计算最优并发数
        /// </summary>
        private int CalculateOptimalConcurrency(int portCount, int requestedConcurrency)
        {
            // 基础并发数
            int baseConcurrency = requestedConcurrency;
            
            // 根据端口数量调整 - 增加并发上限以提高速度
            if (portCount > 20000)
                baseConcurrency = Math.Min(1500, Environment.ProcessorCount * 40); // 进一步提高上限
            else if (portCount > 10000)
                baseConcurrency = Math.Min(1200, Environment.ProcessorCount * 35); // 提高上限
            else if (portCount > 5000)
                baseConcurrency = Math.Min(1000, Environment.ProcessorCount * 30); // 提高上限
            else if (portCount > 1000)
                baseConcurrency = Math.Min(800, Environment.ProcessorCount * 25); // 提高上限
            else
                baseConcurrency = Math.Min(500, Environment.ProcessorCount * 20); // 提高上限
            
            // 根据系统内存调整
            long availableMemory = GetAvailableMemoryMb();
            if (availableMemory < 512)
                baseConcurrency = Math.Max(150, baseConcurrency / 2); // 提高最低并发
            else if (availableMemory < 1024)
                baseConcurrency = Math.Max(250, baseConcurrency * 3 / 4); // 提高最低并发
            else if (availableMemory > 8192)
                baseConcurrency = Math.Min(baseConcurrency * 2, 2000); // 内存充足时进一步提高并发
            else if (availableMemory > 4096)
                baseConcurrency = Math.Min((int)(baseConcurrency * 1.5), 1500); // 内存充足时提高并发
            
            // 根据网络带宽估计调整
            int networkBasedConcurrency = EstimateNetworkBasedConcurrency();
            baseConcurrency = Math.Min(baseConcurrency, networkBasedConcurrency);
            
            return Math.Max(150, baseConcurrency); // 提高最低并发
        }
        
        /// <summary>
        /// 根据网络带宽估计并发数
        /// </summary>
        private int EstimateNetworkBasedConcurrency()
        {
            try
            {
                // 简单的网络带宽估计
                // 假设每个并发连接需要约10KB/s带宽
                // 保守估计网络带宽为100Mbps
                int estimatedBandwidthMbps = 100;
                int bandwidthPerConnectionKbps = 10 * 8; // 10KB/s = 80Kbps
                
                int maxConcurrency = (estimatedBandwidthMbps * 1024) / bandwidthPerConnectionKbps;
                return Math.Max(500, Math.Min(maxConcurrency, 2000));
            }
            catch
            {
                return 1000; // 默认值
            }
        }
        
        /// <summary>
        /// 获取扫描状态描述
        /// </summary>
        private string GetScanStatusDescription(int completed, int total, int openPorts)
        {
            double progressPercentage = (double)completed / total * 100;
            
            if (progressPercentage < 10)
            {
                return "开始扫描...";
            }
            else if (progressPercentage < 30)
            {
                return "扫描初期阶段...";
            }
            else if (progressPercentage < 70)
            {
                return "扫描进行中...";
            }
            else if (progressPercentage < 90)
            {
                return "扫描接近完成...";
            }
            else
            {
                return "扫描收尾阶段...";
            }
        }
        
        /// <summary>
        /// 根据系统资源计算分批扫描阈值
        /// </summary>
        private int CalculateBatchScanThreshold()
        {
            try
            {
                // 基础阈值
                int baseThreshold = 10000;
                
                // 根据系统内存调整
                long availableMemory = GetAvailableMemoryMb();
                if (availableMemory < 1024)
                {
                    // 内存不足，降低阈值以减少内存使用
                    baseThreshold = 5000;
                }
                else if (availableMemory < 2048)
                {
                    // 内存适中，使用默认阈值
                    baseThreshold = 8000;
                }
                else if (availableMemory > 8192)
                {
                    // 内存充足，提高阈值以减少分批次数
                    baseThreshold = 20000;
                }
                else if (availableMemory > 4096)
                {
                    // 内存充足，提高阈值
                    baseThreshold = 15000;
                }
                
                // 根据处理器核心数调整
                int processorCount = Environment.ProcessorCount;
                if (processorCount <= 2)
                {
                    // 处理器核心数少，降低阈值
                    baseThreshold = Math.Max(3000, baseThreshold / 2);
                }
                else if (processorCount >= 8)
                {
                    // 处理器核心数多，提高阈值
                    baseThreshold = Math.Min(25000, (int)(baseThreshold * 1.2));
                }
                
                return baseThreshold;
            }
            catch
            {
                // 计算失败时使用默认值
                return 10000;
            }
        }
        
        /// <summary>
        /// 根据端口数量和系统资源计算最佳批次大小
        /// </summary>
        private int CalculateOptimalBatchSize(int totalPorts)
        {
            try
            {
                // 基础批次大小
                int baseBatchSize = 5000;
                
                // 根据系统内存调整
                long availableMemory = GetAvailableMemoryMb();
                if (availableMemory < 1024)
                {
                    // 内存不足，减小批次大小以减少内存使用
                    baseBatchSize = 2000;
                }
                else if (availableMemory < 2048)
                {
                    // 内存适中，使用较小的批次大小
                    baseBatchSize = 3000;
                }
                else if (availableMemory > 8192)
                {
                    // 内存充足，使用较大的批次大小
                    baseBatchSize = 8000;
                }
                else if (availableMemory > 4096)
                {
                    // 内存充足，使用较大的批次大小
                    baseBatchSize = 6000;
                }
                
                // 根据处理器核心数调整
                int processorCount = Environment.ProcessorCount;
                if (processorCount <= 2)
                {
                    // 处理器核心数少，减小批次大小
                    baseBatchSize = Math.Max(1000, baseBatchSize / 2);
                }
                else if (processorCount >= 8)
                {
                    // 处理器核心数多，增大批次大小
                    baseBatchSize = Math.Min(10000, (int)(baseBatchSize * 1.5));
                }
                
                // 根据总端口数调整
                if (totalPorts > 100000)
                {
                    // 端口数量非常大，使用较大的批次大小以减少分批次数
                    baseBatchSize = Math.Min(10000, (int)(baseBatchSize * 1.2));
                }
                else if (totalPorts < 10000)
                {
                    // 端口数量较小，使用较小的批次大小
                    baseBatchSize = Math.Max(1000, baseBatchSize / 2);
                }
                
                return baseBatchSize;
            }
            catch
            {
                // 计算失败时使用默认值
                return 5000;
            }
        }
        
        /// <summary>
        /// 计算动态超时时间
        /// </summary>
        private int CalculateDynamicTimeout(int baseTimeout)
        {
            // 根据当前扫描成功率调整超时
            int totalAttempts = _successfulScans + _failedScans;
            if (totalAttempts > 10)
            {
                double successRate = (double)_successfulScans / totalAttempts;
                if (successRate > 0.8)
                    return Math.Max(100, baseTimeout / 2); // 成功率高，减少超时
                else if (successRate < 0.3)
                    return Math.Min(10000, baseTimeout * 2); // 成功率低，增加超时
            }
            return baseTimeout;
        }
        
        /// <summary>
        /// 动态调整批量大小
        /// </summary>
        /// <param name="currentBatchSize">当前批量大小</param>
        /// <param name="options">扫描选项</param>
        /// <returns>调整后的批量大小</returns>
        private int AdjustBatchSize(int currentBatchSize, ScanOptions options)
        {
            try
            {
                // 基础调整因子
                double adjustmentFactor = 1.0;
                
                // 根据系统内存调整
                long availableMemory = GetAvailableMemoryMb();
                if (availableMemory < 512)
                {
                    // 内存不足，减少批量大小
                    adjustmentFactor = 0.7;
                }
                else if (availableMemory > 4096)
                {
                    // 内存充足，增加批量大小
                    adjustmentFactor = 1.3;
                }
                
                // 根据CPU核心数调整
                int processorCount = Environment.ProcessorCount;
                if (processorCount <= 2)
                {
                    // CPU核心数少，减少批量大小
                    adjustmentFactor *= 0.8;
                }
                else if (processorCount >= 8)
                {
                    // CPU核心数多，增加批量大小
                    adjustmentFactor *= 1.2;
                }
                
                // 计算新的批量大小
                int newBatchSize = (int)(currentBatchSize * adjustmentFactor);
                
                // 限制批量大小范围
                int minBatchSize = Math.Max(500, Environment.ProcessorCount * 50);
                int maxBatchSize = Math.Min(15000, Environment.ProcessorCount * 500);
                
                return Math.Clamp(newBatchSize, minBatchSize, maxBatchSize);
            }
            catch
            {
                // 计算失败时返回当前批量大小
                return currentBatchSize;
            }
        }
        
        /// <summary>
        /// 计算当前扫描速度
        /// </summary>
        private double CalculateScanSpeed()
        {
            TimeSpan elapsed = DateTime.Now - _scanStartTime;
            if (elapsed.TotalSeconds < 1)
                return 0;
            
            return _completedPorts / elapsed.TotalSeconds;
        }
        
        /// <summary>
        /// 计算预计完成时间
        /// </summary>
        private TimeSpan? CalculateEstimatedTimeRemaining()
        {
            double speed = CurrentScanSpeed;
            if (speed <= 0)
                return null;
            
            int remainingPorts = _totalPorts - _completedPorts;
            if (remainingPorts <= 0)
                return TimeSpan.Zero;
            
            double remainingSeconds = remainingPorts / speed;
            return TimeSpan.FromSeconds(remainingSeconds);
        }
        
        /// <summary>
        /// 获取可用内存（MB）
        /// </summary>
        private long GetAvailableMemoryMb()
        {
            try
            {
                // 简单的内存检测
                return Environment.WorkingSet / (1024 * 1024);
            }
            catch
            {
                return 1024; // 默认值
            }
        }
        
        private string GetServiceByPort(int port)
        {
            // 使用静态只读字典避免重复创建
            return ServiceMap.TryGetValue(port, out var service) ? service : "Unknown";
        }
        
        // 静态服务映射表 - 只初始化一次
        private static readonly Dictionary<int, string> ServiceMap = new()
        {
            {20, "FTP-Data"},
            {21, "FTP"},
            {22, "SSH"},
            {23, "Telnet"},
            {25, "SMTP"},
            {53, "DNS"},
            {80, "HTTP"},
            {110, "POP3"},
            {143, "IMAP"},
            {443, "HTTPS"},
            {993, "IMAPS"},
            {995, "POP3S"},
            {1433, "MSSQL"},
            {1521, "Oracle"},
            {3306, "MySQL"},
            {3389, "RDP"},
            {5432, "PostgreSQL"},
            {5900, "VNC"},
            {6379, "Redis"},
            {8080, "HTTP-Proxy"},
            {27017, "MongoDB"}
        };
    }
    
    public class ScanProgressEventArgs : EventArgs
    {
        public ScanProgressInfo ProgressInfo { get; }
        
        public ScanProgressEventArgs(ScanProgressInfo progressInfo)
        {
            ProgressInfo = progressInfo;
        }
    }
    
    public class PortScannedEventArgs : EventArgs
    {
        public PortInfo PortInfo { get; }
        
        public PortScannedEventArgs(PortInfo portInfo)
        {
            PortInfo = portInfo;
        }
    }
}
