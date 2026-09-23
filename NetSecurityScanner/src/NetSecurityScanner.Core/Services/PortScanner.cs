using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using NetSecurityScanner.Models;
using NetSecurityScanner.Utils;

namespace NetSecurityScanner.Services
{
    /// <summary>
    /// 端口扫描服务
    /// </summary>
    public class PortScanner : IPortScanner, IDisposable
    {
        // 扫描配置
        private const int DefaultTimeout = 500; // 默认TCP超时时间（优化：减少超时时间提高速度）
        private const int MaxConcurrentConnections = 300; // 最大TCP并发连接数（优化：增加并发数提高速度）
        private const int SmallPortRangeTimeout = 800; // 小范围端口扫描超时时间（优化：减少超时时间提高速度）
        private const int SmallPortRangeThreshold = 20; // 小范围端口阈值
        private const int UdpTimeout = 1000; // UDP扫描超时时间（优化：减少超时时间提高速度）
        private const int UdpMaxConcurrentConnections = 150; // 最大UDP并发连接数（优化：增加并发数提高速度）
        private const int ServiceVersionTimeout = 600; // 服务版本识别超时时间（优化：减少超时时间提高速度）

        /// <summary>
        /// TCP端口扫描
        /// </summary>
        /// <param name="targetIp">目标IP地址</param>
        /// <param name="ports">要扫描的端口列表</param>
        /// <param name="progress">进度报告</param>
        /// <param name="cancellationToken">取消令牌</param>
        /// <param name="scanPolicy">扫描策略配置</param>
        /// <returns>端口扫描结果列表</returns>
        public async Task<List<PortScanResult>> ScanTcpPortsAsync(string targetIp, List<int> ports, IProgress<int> progress = null, CancellationToken cancellationToken = default, Models.ScanPolicy scanPolicy = null)
        {
            var results = new List<PortScanResult>();
            int scannedCount = 0;
            int totalPorts = ports.Count;

            // 避免除零错误
            if (totalPorts == 0)
            {
                return results;
            }

            // 使用扫描策略配置，如果没有提供则使用默认值
            int timeout = scanPolicy?.TimeoutConfig?.TcpTimeout ?? (ports.Count <= SmallPortRangeThreshold ? SmallPortRangeTimeout : DefaultTimeout);
            int maxConcurrent = scanPolicy?.RateLimitConfig?.MaxConcurrentConnections ?? Math.Min(MaxConcurrentConnections, Math.Max(20, ports.Count / 10));
            int smallPortRangeThreshold = scanPolicy?.NetworkScanConfig?.SmallPortRangeThreshold ?? SmallPortRangeThreshold;
            int smallPortRangeTimeout = scanPolicy?.TimeoutConfig?.SmallPortRangeTimeout ?? SmallPortRangeTimeout;

            // 根据端口数量动态调整超时时间
            if (ports.Count <= smallPortRangeThreshold)
            {
                timeout = smallPortRangeTimeout;
            }

            // 速率限制：仅当调用方显式开启（EnableRateLimit=true）时生效。
            // 采用「累计耗时补偿」而非固定睡眠间隔：投递第 N 个端口时，理论耗时应为 N/速率 秒，
            // 实际耗时不足才补足差额。若用固定间隔，限流等待会与扫描本身耗时叠加，
            // 导致实际速率明显低于用户设定值。
            bool enableRateLimit = scanPolicy?.RateLimitConfig?.EnableRateLimit == true;
            int portScanRate = Math.Max(1, scanPolicy?.RateLimitConfig?.PortScanRate ?? 100);
            var rateStart = DateTime.UtcNow;
            int dispatched = 0;

            // 使用线程安全的结果列表
            var threadSafeResults = new System.Collections.Concurrent.ConcurrentBag<PortScanResult>();

            // 使用信号量限制并发连接数
            using (var semaphore = new SemaphoreSlim(maxConcurrent))
            {
                var tasks = new List<Task<PortScanResult?>>();

                try
                {
                    foreach (var port in ports)
                    {
                        // 检查取消令牌
                        cancellationToken.ThrowIfCancellationRequested();

                        // 按目标速率平滑投递端口（未开启限流时为零开销）
                        if (enableRateLimit)
                        {
                            dispatched++;
                            var expectedMs = dispatched * 1000.0 / portScanRate;
                            var elapsedMs = (DateTime.UtcNow - rateStart).TotalMilliseconds;
                            if (elapsedMs < expectedMs)
                            {
                                await Task.Delay((int)(expectedMs - elapsedMs), cancellationToken);
                            }
                        }

                        // 创建循环变量的副本，避免闭包捕获问题
                        var portCopy = port;

                        var task = Task.Run(async () =>
                        {
                            PortScanResult result = null;
                            try
                            {
                                await semaphore.WaitAsync(cancellationToken);

                                // 再次检查取消令牌
                                cancellationToken.ThrowIfCancellationRequested();

                                result = await ScanTcpPortAsync(targetIp, portCopy, timeout, cancellationToken);
                                return result;
                            }
                            catch (OperationCanceledException)
                            {
                                // 取消异常，返回空结果
                                return null;
                            }
                            catch (Exception ex)
                            {
                                // 记录异常，但不中断扫描
                                Console.WriteLine($"扫描端口 {portCopy} 时发生异常: {ex.Message}");
                                result = CreatePortResult(portCopy, "未知");
                                return result;
                            }
                            finally
                            {
                                try
                                {
                                    if (result != null)
                                    {
                                        threadSafeResults.Add(result);
                                    }

                                    int currentCount = Interlocked.Increment(ref scannedCount);
                                    if (progress != null)
                                    {
                                        int progressPercentage = (int)((double)currentCount / totalPorts * 100);
                                        // 使用TryCatch包装进度报告，避免进度报告引发的异常中断扫描
                                        try
                                        {
                                            progress.Report(progressPercentage);
                                        }
                                        catch (Exception ex)
                                        {
                                            Console.WriteLine($"报告进度时发生异常: {ex.Message}");
                                        }
                                    }
                                    semaphore.Release();
                                }
                                catch (Exception)
                                {
                                    // 忽略释放信号量时的异常
                                }
                            }
                        }, cancellationToken);

                        tasks.Add(task);
                    }

                    // 等待所有任务完成，捕获所有异常
                    var scanResults = await Task.WhenAll(tasks);

                    // 过滤掉null结果
                    results.AddRange(scanResults.OfType<PortScanResult>());

                    // 不再从线程安全结果中获取，避免重复添加
                    // 去重
                    results = results.Distinct().ToList();
                }
                catch (OperationCanceledException)
                {
                    // 扫描被取消，返回已扫描的结果
                    results.AddRange(threadSafeResults);
                    throw;
                }
                catch (Exception ex)
                {
                    // 捕获所有其他异常，确保扫描不会完全失败
                    Console.WriteLine($"扫描过程中发生异常: {ex.Message}");
                    results.AddRange(threadSafeResults);
                }
            }

            // 过滤只显示开放端口
            results = results.Where(r => r.Status == "开放" || r.Status == "开放或过滤").ToList();

            // 按端口号排序结果
            results.Sort((x, y) => x.PortNumber.CompareTo(y.PortNumber));
            return results;
        }

        /// <summary>
        /// UDP端口扫描
        /// </summary>
        /// <param name="targetIp">目标IP地址</param>
        /// <param name="ports">要扫描的端口列表</param>
        /// <param name="progress">进度报告</param>
        /// <param name="cancellationToken">取消令牌</param>
        /// <param name="scanPolicy">扫描策略配置</param>
        /// <returns>端口扫描结果列表</returns>
        public async Task<List<PortScanResult>> ScanUdpPortsAsync(string targetIp, List<int> ports, IProgress<int> progress = null, CancellationToken cancellationToken = default, Models.ScanPolicy scanPolicy = null)
        {
            var results = new List<PortScanResult>();
            int scannedCount = 0;
            int totalPorts = ports.Count;

            // 避免除零错误
            if (totalPorts == 0)
            {
                return results;
            }

            // 使用扫描策略配置，如果没有提供则使用默认值
            int timeout = scanPolicy?.TimeoutConfig?.UdpTimeout ?? UdpTimeout;
            int maxConcurrent = scanPolicy?.RateLimitConfig?.UdpMaxConcurrentConnections ?? Math.Min(UdpMaxConcurrentConnections, Math.Max(10, ports.Count / 20));

            // 速率限制（与 TCP 扫描同逻辑）：仅当调用方显式开启时生效，
            // 采用累计耗时补偿，避免限流等待与扫描耗时叠加导致实际速率偏低。
            bool enableRateLimit = scanPolicy?.RateLimitConfig?.EnableRateLimit == true;
            int portScanRate = Math.Max(1, scanPolicy?.RateLimitConfig?.PortScanRate ?? 100);
            var rateStart = DateTime.UtcNow;
            int dispatched = 0;

            // 使用线程安全的结果列表
            var threadSafeResults = new System.Collections.Concurrent.ConcurrentBag<PortScanResult>();

            // 使用信号量限制并发连接数
            using (var semaphore = new SemaphoreSlim(maxConcurrent))
            {
                var tasks = new List<Task<PortScanResult?>>();

                try
                {
                    foreach (var port in ports)
                    {
                        // 检查取消令牌
                        cancellationToken.ThrowIfCancellationRequested();

                        // 按目标速率平滑投递端口（未开启限流时为零开销）
                        if (enableRateLimit)
                        {
                            dispatched++;
                            var expectedMs = dispatched * 1000.0 / portScanRate;
                            var elapsedMs = (DateTime.UtcNow - rateStart).TotalMilliseconds;
                            if (elapsedMs < expectedMs)
                            {
                                await Task.Delay((int)(expectedMs - elapsedMs), cancellationToken);
                            }
                        }

                        // 创建循环变量的副本，避免闭包捕获问题
                        var portCopy = port;

                        var task = Task.Run(async () =>
                        {
                            PortScanResult result = null;
                            try
                            {
                                await semaphore.WaitAsync(cancellationToken);

                                // 再次检查取消令牌
                                cancellationToken.ThrowIfCancellationRequested();

                                result = await ScanUdpPortAsync(targetIp, portCopy, timeout, cancellationToken);
                                return result;
                            }
                            catch (OperationCanceledException)
                            {
                                // 取消异常，返回空结果
                                return null;
                            }
                            catch (Exception ex)
                            {
                                // 记录异常，但不中断扫描
                                Console.WriteLine($"扫描UDP端口 {portCopy} 时发生异常: {ex.Message}");
                                result = CreatePortResult(portCopy, "未知");
                                return result;
                            }
                            finally
                            {
                                try
                                {
                                    if (result != null)
                                    {
                                        threadSafeResults.Add(result);
                                    }

                                    int currentCount = Interlocked.Increment(ref scannedCount);
                                    if (progress != null)
                                    {
                                        int progressPercentage = (int)((double)currentCount / totalPorts * 100);
                                        // 使用TryCatch包装进度报告，避免进度报告引发的异常中断扫描
                                        try
                                        {
                                            progress.Report(progressPercentage);
                                        }
                                        catch (Exception ex)
                                        {
                                            Console.WriteLine($"报告UDP扫描进度时发生异常: {ex.Message}");
                                        }
                                    }
                                    semaphore.Release();
                                }
                                catch (Exception)
                                {
                                    // 忽略释放信号量时的异常
                                }
                            }
                        }, cancellationToken);

                        tasks.Add(task);
                    }

                    // 等待所有任务完成，捕获所有异常
                    var scanResults = await Task.WhenAll(tasks);

                    // 过滤掉null结果
                    results.AddRange(scanResults.OfType<PortScanResult>());

                    // 从线程安全结果中获取所有结果（作为备份）
                    results.AddRange(threadSafeResults);
                    // 去重
                    results = results.Distinct().ToList();
                }
                catch (OperationCanceledException)
                {
                    // 扫描被取消，返回已扫描的结果
                    results.AddRange(threadSafeResults);
                    throw;
                }
                catch (Exception ex)
                {
                    // 捕获所有其他异常，确保扫描不会完全失败
                    Console.WriteLine($"UDP扫描过程中发生异常: {ex.Message}");
                    results.AddRange(threadSafeResults);
                }
            }

            // 过滤只显示开放端口(UDP 与 TCP 对齐)— v1.0.1.4 P0 修复
            results = results.Where(r => r.Status == "开放" || r.Status == "开放或过滤").ToList();

            // 按端口号排序结果
            results.Sort((x, y) => x.PortNumber.CompareTo(y.PortNumber));
            return results;
        }

        /// <summary>
        /// 常用端口扫描（默认TCP）
        /// </summary>
        /// <param name="targetIp">目标IP地址</param>
        /// <param name="progress">进度报告</param>
        /// <param name="cancellationToken">取消令牌</param>
        /// <param name="scanPolicy">扫描策略配置</param>
        /// <returns>端口扫描结果列表</returns>
        public async Task<List<PortScanResult>> ScanCommonPortsAsync(string targetIp, IProgress<int> progress = null, CancellationToken cancellationToken = default, Models.ScanPolicy scanPolicy = null)
        {
            var commonPorts = PortServiceMapping.GetCommonPorts();
            return await ScanTcpPortsAsync(targetIp, commonPorts, progress, cancellationToken, scanPolicy);
        }

        /// <summary>
        /// 敏感端口扫描（默认TCP）
        /// </summary>
        /// <param name="targetIp">目标IP地址</param>
        /// <param name="progress">进度报告</param>
        /// <param name="cancellationToken">取消令牌</param>
        /// <param name="scanPolicy">扫描策略配置</param>
        /// <returns>端口扫描结果列表</returns>
        public async Task<List<PortScanResult>> ScanSensitivePortsAsync(string targetIp, IProgress<int> progress = null, CancellationToken cancellationToken = default, Models.ScanPolicy scanPolicy = null)
        {
            var sensitivePorts = PortServiceMapping.GetSensitivePorts();
            return await ScanTcpPortsAsync(targetIp, sensitivePorts, progress, cancellationToken, scanPolicy);
        }

        /// <summary>
        /// 端口扫描（默认TCP）
        /// </summary>
        /// <param name="targetIp">目标IP地址</param>
        /// <param name="ports">要扫描的端口列表</param>
        /// <param name="progress">进度报告</param>
        /// <param name="cancellationToken">取消令牌</param>
        /// <param name="scanPolicy">扫描策略配置</param>
        /// <returns>端口扫描结果列表</returns>
        public async Task<List<PortScanResult>> ScanPortsAsync(string targetIp, List<int> ports, IProgress<int> progress = null, CancellationToken cancellationToken = default, Models.ScanPolicy scanPolicy = null)
        {
            return await ScanTcpPortsAsync(targetIp, ports, progress, cancellationToken, scanPolicy);
        }

        /// <summary>
        /// 按风险评分降序扫描（高风险端口优先扫描）
        /// 适合在大量端口中优先发现高价值目标
        /// </summary>
        /// <param name="targetIp">目标IP地址</param>
        /// <param name="ports">要扫描的端口列表</param>
        /// <param name="progress">进度报告</param>
        /// <param name="cancellationToken">取消令牌</param>
        /// <param name="scanPolicy">扫描策略配置</param>
        /// <returns>端口扫描结果列表（已按风险降序+端口号升序）</returns>
        public async Task<List<PortScanResult>> ScanPortsByRiskAsync(string targetIp, List<int> ports, IProgress<int> progress = null, CancellationToken cancellationToken = default, Models.ScanPolicy scanPolicy = null)
        {
            // 先执行常规扫描
            var results = await ScanTcpPortsAsync(targetIp, ports, progress, cancellationToken, scanPolicy);
            // 按风险评分降序、端口号升序排序
            return SortByRiskDesc(results);
        }

        /// <summary>
        /// 对扫描结果按风险评分降序、端口号升序排序
        /// 评分相同时按端口号排序，便于阅读
        /// </summary>
        public static List<PortScanResult> SortByRiskDesc(List<PortScanResult> results)
        {
            if (results == null) return new List<PortScanResult>();
            return results
                .OrderByDescending(r => r.RiskScore)
                .ThenBy(r => r.PortNumber)
                .ToList();
        }

        /// <summary>
        /// 对扫描结果按风险评分升序排序（低风险在前）
        /// </summary>
        public static List<PortScanResult> SortByRiskAsc(List<PortScanResult> results)
        {
            if (results == null) return new List<PortScanResult>();
            return results
                .OrderBy(r => r.RiskScore)
                .ThenBy(r => r.PortNumber)
                .ToList();
        }

        /// <summary>
        /// 对扫描结果按端口号升序排序
        /// </summary>
        public static List<PortScanResult> SortByPortAsc(List<PortScanResult> results)
        {
            if (results == null) return new List<PortScanResult>();
            return results.OrderBy(r => r.PortNumber).ToList();
        }

        /// <summary>
        /// TCP端口扫描单个端口
        /// </summary>
        /// <param name="targetIp">目标IP地址</param>
        /// <param name="port">端口号</param>
        /// <param name="timeout">超时时间（毫秒）</param>
        /// <param name="cancellationToken">取消令牌</param>
        /// <returns>端口扫描结果</returns>
        public async Task<PortScanResult> ScanTcpPortAsync(string targetIp, int port, int timeout, CancellationToken cancellationToken = default)
        {
            try
            {
                cancellationToken.ThrowIfCancellationRequested();

                using (var client = new TcpClient())
                {
                    client.ReceiveTimeout = timeout;
                    client.SendTimeout = timeout;

                    // 对特定端口（如3345）使用稍微长一点的超时时间
                    int portSpecificTimeout = port == 3345 ? timeout * 2 : timeout;

                    // 使用CancellationToken实现超时
                    using (var timeoutCancellationTokenSource = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken))
                    {
                        timeoutCancellationTokenSource.CancelAfter(portSpecificTimeout);

                        using (var registration = timeoutCancellationTokenSource.Token.Register(() => client.Dispose()))
                        {
                            var sw = System.Diagnostics.Stopwatch.StartNew();
                            try
                            {
                                await client.ConnectAsync(targetIp, port);
                                sw.Stop();

                                // 连接成功
                                var portResult = CreatePortResult(port, "开放");
                                portResult.ScanDurationMs = sw.ElapsedMilliseconds;
                                portResult.Confidence = "高"; // 完整 TCP 三次握手成功

                                // 尝试识别服务版本
                                try
                                {
                                    portResult.ServiceVersion = await IdentifyServiceVersionAsync(targetIp, port, portResult.Service, ServiceVersionTimeout, cancellationToken);
                                    // 如果拿到了 banner 信息，可信度保持"高"
                                    if (string.IsNullOrEmpty(portResult.ServiceVersion))
                                    {
                                        portResult.Confidence = "中";
                                    }
                                }
                                catch (Exception)
                                {
                                    // 服务版本识别失败，不影响端口状态
                                    portResult.ServiceVersion = "未知版本";
                                    portResult.Confidence = "中";
                                }

                                return portResult;
                            }
                            catch (OperationCanceledException)
                            {
                                // 超时或取消，端口可能开放或被过滤
                                // 启用重试：超时可能因为第一次握手包丢失，再试一次
                                var retryResult = await RetryTcpPortAsync(targetIp, port, timeout * 2, cancellationToken);
                                if (retryResult != null) return retryResult;
                                return CreatePortResult(port, "开放或过滤");
                            }
                            catch (Exception)
                            {
                                // 连接失败，端口关闭
                                // 启用重试：第一次失败可能是网络抖动
                                var retryResult = await RetryTcpPortAsync(targetIp, port, timeout, cancellationToken);
                                if (retryResult != null) return retryResult;
                                return CreatePortResult(port, "关闭");
                            }
                        }
                    }
                }
            }
            catch (OperationCanceledException)
            {
                throw; // 重新抛出取消异常
            }
            catch (Exception ex)
            {
                // 连接失败
                if (ex is SocketException socketEx)
                {
                    // 根据不同的Socket异常返回不同的结果
                    if (socketEx.SocketErrorCode == SocketError.TimedOut ||
                        socketEx.SocketErrorCode == SocketError.HostUnreachable ||
                        socketEx.SocketErrorCode == SocketError.NetworkUnreachable)
                    {
                        // 超时或网络不可达，端口可能开放或被过滤
                        var retryResult = await RetryTcpPortAsync(targetIp, port, timeout * 2, cancellationToken);
                        if (retryResult != null) return retryResult;
                        return CreatePortResult(port, "开放或过滤");
                    }
                }
                // 其他异常，端口关闭
                return CreatePortResult(port, "关闭");
            }
        }

        /// <summary>
        /// TCP 重试：用于超时/网络抖动场景，单次重试以降低误报
        /// </summary>
        private async Task<PortScanResult> RetryTcpPortAsync(string targetIp, int port, int timeout, CancellationToken cancellationToken)
        {
            try
            {
                using (var client = new TcpClient())
                {
                    client.ReceiveTimeout = timeout;
                    client.SendTimeout = timeout;
                    using (var cts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken))
                    {
                        cts.CancelAfter(timeout);
                        using (var registration = cts.Token.Register(() => client.Dispose()))
                        {
                            var sw = System.Diagnostics.Stopwatch.StartNew();
                            await client.ConnectAsync(targetIp, port);
                            sw.Stop();
                            var result = CreatePortResult(port, "开放");
                            result.ScanDurationMs = sw.ElapsedMilliseconds;
                            result.Confidence = "高"; // 重试成功，可信度高
                            try
                            {
                                result.ServiceVersion = await IdentifyServiceVersionAsync(targetIp, port, result.Service, ServiceVersionTimeout, cancellationToken);
                                if (string.IsNullOrEmpty(result.ServiceVersion)) result.Confidence = "中";
                            }
                            catch { result.Confidence = "中"; }
                            return result;
                        }
                    }
                }
            }
            catch
            {
                return null; // 重试失败由调用方决定如何处理
            }
        }

        /// <summary>
        /// 识别服务版本
        /// </summary>
        /// <param name="targetIp">目标IP地址</param>
        /// <param name="port">端口号</param>
        /// <param name="service">服务名称</param>
        /// <param name="timeout">超时时间（毫秒）</param>
        /// <param name="cancellationToken">取消令牌</param>
        /// <returns>服务版本信息</returns>
        private async Task<string> IdentifyServiceVersionAsync(string targetIp, int port, string service, int timeout, CancellationToken cancellationToken)
        {
            try
            {
                cancellationToken.ThrowIfCancellationRequested();

                using (var client = new TcpClient())
                {
                    client.ReceiveTimeout = timeout;
                    client.SendTimeout = timeout;

                    // 使用CancellationToken实现超时
                    using (var timeoutCancellationTokenSource = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken))
                    {
                        timeoutCancellationTokenSource.CancelAfter(timeout);

                        using (var registration = timeoutCancellationTokenSource.Token.Register(() => client.Dispose()))
                        {
                            try
                            {
                                await client.ConnectAsync(targetIp, port);

                                using (var stream = client.GetStream())
                                {
                                    stream.ReadTimeout = timeout;
                                    stream.WriteTimeout = timeout;

                                    // 根据服务类型发送不同的探测数据包
                                    byte[] probeData = GetProbeData(service, port);
                                    if (probeData != null && probeData.Length > 0)
                                    {
                                        try
                                        {
                                            await stream.WriteAsync(probeData, 0, probeData.Length, cancellationToken);
                                        }
                                        catch (Exception)
                                        {
                                            // 写入失败，返回空字符串
                                            return "";
                                        }
                                    }

                                    // 等待接收数据
                                    var buffer = new byte[1024];
                                    using (var readTimeoutCancellationTokenSource = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken))
                                    {
                                        readTimeoutCancellationTokenSource.CancelAfter(timeout);

                                        int bytesRead;
                                        try
                                        {
                                            bytesRead = await stream.ReadAsync(buffer, 0, buffer.Length, cancellationToken);
                                        }
                                        catch (OperationCanceledException)
                                        {
                                            // 读取超时
                                            return "";
                                        }

                                        if (bytesRead > 0)
                                        {
                                            string response = Encoding.ASCII.GetString(buffer, 0, bytesRead);
                                            return ParseServiceVersion(service, response);
                                        }
                                        else
                                        {
                                            return "";
                                        }
                                    }
                                }
                            }
                            catch (OperationCanceledException)
                            {
                                // 连接超时或取消
                                return "";
                            }
                            catch (Exception)
                            {
                                // 连接失败
                                return "";
                            }
                        }
                    }
                }
            }
            catch (OperationCanceledException)
            {
                // 取消异常，返回空字符串
            }
            catch (Exception)
            {
                // 如果版本识别失败，返回空字符串
            }

            return "";
        }

        /// <summary>
        /// 获取服务探测数据包
        /// </summary>
        /// <param name="service">服务名称</param>
        /// <param name="port">端口号</param>
        /// <returns>探测数据包</returns>
        private byte[] GetProbeData(string service, int port)
        {
            // 根据服务类型返回不同的探测数据包
            switch (service?.ToLower())
            {
                case "http":
                case "https":
                    // HTTP 探测：使用标准 HEAD 方法，携带合法的 User-Agent 和 Connection: close
                    // 兼容 IIS、Nginx、Apache、Tomcat 等
                    return Encoding.ASCII.GetBytes(
                        "HEAD / HTTP/1.1\r\n" +
                        "User-Agent: Mozilla/5.0 (compatible; NetSecurityScanner/1.0)\r\n" +
                        "Accept: */*\r\n" +
                        "Connection: close\r\n" +
                        "\r\n");
                case "ftp":
                    return Encoding.ASCII.GetBytes("QUIT\r\n");
                case "smtp":
                    return Encoding.ASCII.GetBytes("EHLO scanner.local\r\nQUIT\r\n");
                case "pop3":
                    return Encoding.ASCII.GetBytes("QUIT\r\n");
                case "imap":
                    return Encoding.ASCII.GetBytes("A001 CAPABILITY\r\n");
                case "ssh":
                    // SSH服务会主动发送版本信息，不需要发送探测数据包
                    return null;
                case "telnet":
                    return Encoding.ASCII.GetBytes("\r\n");
                case "mysql":
                    // MySQL 协议握手：客户端发送 Server Greeting 后等待服务器返回 Handshake Packet
                    // 通过发送一个非 MySQL 兼容包，让 MySQL 返回错误版本字符串
                    return new byte[] {
                        0x9F, 0x01, 0x00, 0x00, 0x01, 0x35, 0x2E, 0x37, 0x2E, 0x32,
                        0x36, 0x00, 0x00, 0x00, 0x40, 0x3F, 0x59, 0x26, 0x4B, 0x00,
                        0xFF, 0xF7, 0x21, 0x02, 0x00, 0xFF, 0x81, 0x15, 0x00, 0x00,
                        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x6D, 0x79,
                        0x73, 0x71, 0x6C, 0x5F, 0x6E, 0x61, 0x74, 0x69, 0x76, 0x65,
                        0x5F, 0x70, 0x61, 0x73, 0x73, 0x77, 0x6F, 0x72, 0x64, 0x00
                    };
                case "postgresql":
                    // PostgreSQL 启动消息：让服务器返回版本错误
                    return Encoding.ASCII.GetBytes("\x00\x03\x00\x00user\x00postgres\x00database\x00postgres\x00\x00");
                case "redis":
                    // Redis PING 命令
                    return Encoding.ASCII.GetBytes("*1\r\n$4\r\nPING\r\n");
                case "mongodb":
                    // MongoDB hello/isMaster 命令
                    return new byte[] {
                        0x3A, 0x00, 0x00, 0x00, // MessageLength (placeholder)
                        0x01, 0x00, 0x00, 0x00, // RequestID
                        0x00, 0x00, 0x00, 0x00, // ResponseTo
                        0xD4, 0x07, 0x00, 0x00, // OpCode (OP_QUERY = 2004)
                        0x00, 0x00, 0x00, 0x00, // Flags
                        0x61, 0x64, 0x6D, 0x69, 0x6E, 0x2E, 0x24, 0x63, 0x6D, 0x64,
                        0x00, 0x00, 0x00, 0x00, 0x00, // Collection: admin.$cmd
                        0x00, 0x00, 0x00, 0x00, // Skip
                        0x01, 0x00, 0x00, 0x00, // Return
                        0x17, 0x00, 0x00, 0x00, // BSON Size
                        0x10, // type: int32
                        0x69, 0x73, 0x6D, 0x61, 0x73, 0x74, 0x65, 0x72, 0x00, // ismaster
                        0x01, 0x00, 0x00, 0x00, // 1
                        0x00 // EOO
                    };
                case "mssql":
                    // SQL Server 预登录包（简化）
                    return new byte[] {
                        0x12, 0x01, 0x00, 0x2F, 0x00, 0x00, 0x00, 0x00,
                        0x00, 0x00, 0x1A, 0x00, 0x06, 0x01, 0x00, 0x20,
                        0x00, 0x01, 0x02, 0x00, 0x21, 0x00, 0x01, 0x03,
                        0x00, 0x22, 0x00, 0x04, 0x04, 0x00, 0x26, 0x00,
                        0x01
                    };
                case "rdp":
                    // RDP 协议：发送 Connection Request
                    return new byte[] {
                        0x03, 0x00, 0x00, 0x13, // TPKT Header
                        0x0E, 0xE0, 0x00, 0x00, // X.224 Data
                        0x00, 0x00, 0x00, 0x01, // Cookie
                        0x00, 0x08, 0x00, 0x00, // RDP Version
                        0x00, 0x00, 0x00, 0x00
                    };
                case "vnc":
                    // VNC 协议：服务器会主动发送 "RFB xxx"
                    return null;
                case "dns":
                case "snmp":
                case "ntp":
                    // UDP 服务，不通过 TCP probe 处理
                    return null;
                case "smb":
                case "microsoft-ds":
                    // SMB协议：发送SMB Negotiate Protocol请求（简化版）
                    // SMB2 Negotiate Request
                    return new byte[] {
                        0x00, 0x00, 0x00, 0x5B, // NetBIOS header (length will be adjusted)
                        0xFE, 0x53, 0x4D, 0x42, // SMB2 header (0xFESMB)
                        0x40, 0x00, // StructureSize
                        0x00, 0x00, // CreditCharge
                        0x00, 0x00, 0x00, 0x00, // ChannelSequence/Reserved
                        0x00, 0x00, // CreditRequest/Flags
                        0x00, 0x00, 0x00, 0x00, // NextCommand
                        0x00, 0x00, 0x00, 0x00, // MessageId
                        0x00, 0x00, 0x00, 0x00, // Reserved/TreeId
                        0x00, 0x00, 0x00, 0x00, // SessionId
                        0x00, 0x00, 0x00, 0x00, // Signature
                        0x00, 0x00, 0x00, 0x00, // Signature
                        0x00, 0x00, // Signature
                        0x00, 0x00, // Reserved
                        0x00, 0x00, 0x00, 0x00, // NextCommand
                        0x00, 0x00, // Reserved
                        0x24, 0x00, // StructureSize
                        0x02, 0x00, // DialectCount (SMB2.1)
                        0x00, 0x00, // SecurityMode
                        0x00, 0x00, // Reserved
                        0x00, 0x00, 0x00, 0x00, // Capabilities
                        0x00, 0x00, 0x00, 0x00, // ClientGuid
                        0x00, 0x00, 0x00, 0x00, // ClientGuid
                        0x00, 0x00, 0x00, 0x00, // NegotiateContextOffset
                        0x00, 0x00, // NegotiateContextCount
                        0x00, 0x00, // Reserved
                        0x02, 0x02, // Dialect: SMB 2.0.2
                        0x10, 0x02  // Dialect: SMB 2.1
                    };
                case "rpc":
                case "msrpc":
                    // RPC协议：发送简单的DCERPC绑定请求
                    return new byte[] {
                        0x05, 0x00, // Version: 5.0
                        0x0B, // Packet Type: Bind
                        0x03, // Flags: FirstFrag, LastFrag
                        0x00, 0x00, 0x00, 0x00, // Data Representation (little endian)
                        0x3C, 0x00, // Frag Length: 60
                        0x00, 0x00, // Auth Length
                        0x00, 0x00, 0x00, 0x00, // Call ID
                        0x88, 0x04, // Max Xmit Frag: 1160
                        0x88, 0x04, // Max Recv Frag: 1160
                        0x00, 0x00, 0x00, 0x00, // Assoc Group ID
                        0x01, // Context Count: 1
                        0x00, 0x00, 0x00, // Padding
                        0x00, // Context ID: 0
                        0x00, // Number of Trans Items: 0
                        0x00, 0x00, // Padding
                        0x01, 0x00, 0x00, 0x00, // Transfer Syntax UUID (NDR)
                        0x00, 0x00, 0x00, 0x00,
                        0x00, 0x00, 0x00, 0x00,
                        0x02, 0x00, 0x00, 0x00, // Version: 2.0
                        0x01, 0x00, 0x00, 0x00, // Transfer Syntax UUID (NDR)
                        0x00, 0x00, 0x00, 0x00,
                        0x00, 0x00, 0x00, 0x00
                    };
                default:
                    // 对于未知服务，尝试发送一个简单的探测
                    // 这可以帮助识别一些简单的banner-based服务
                    return Encoding.ASCII.GetBytes("\r\n");
            }
        }

        /// <summary>
        /// 获取 UDP 协议特定探测包
        /// 用于提高 UDP 端口扫描的准确度（DNS/SNMP/NTP 等协议有特征探测包）
        /// </summary>
        private byte[] GetUdpProbeData(int port)
        {
            switch (port)
            {
                case 53: // DNS - 标准查询
                    // DNS Header: ID=0x1234, Flags=0x0100 (标准查询), Questions=1
                    // Query: example.com A
                    return new byte[] {
                        0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                        0x07, 0x65, 0x78, 0x61, 0x6D, 0x70, 0x6C, 0x65, 0x03, 0x63, 0x6F, 0x6D, 0x00,
                        0x00, 0x01, 0x00, 0x01
                    };
                case 161: // SNMP - GET-REQUEST for sysDescr
                    // SNMPv1 GET-REQUEST
                    return new byte[] {
                        0x30, 0x26, 0x02, 0x01, 0x00, 0x04, 0x06, 0x70, 0x75, 0x62, 0x6C, 0x69, 0x63,
                        0xA0, 0x19, 0x02, 0x01, 0x01, 0x02, 0x01, 0x00, 0x02, 0x01, 0x00, 0x30, 0x0E,
                        0x30, 0x0C, 0x06, 0x08, 0x2B, 0x06, 0x01, 0x02, 0x01, 0x01, 0x01, 0x00,
                        0x05, 0x00
                    };
                case 123: // NTP - NTPv4 client request
                    return new byte[] {
                        0x1B, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
                    };
                case 1900: // SSDP - M-SEARCH
                    return Encoding.ASCII.GetBytes("M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: \"ssdp:discover\"\r\nMX: 1\r\nST: ssdp:all\r\n\r\n");
                case 67:
                case 68: // DHCP - DISCOVER
                    return new byte[] {
                        0x01, 0x01, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                        0x63, 0x82, 0x53, 0x63, 0x35, 0x01, 0x01, 0xFF
                    };
                case 514: // Syslog - 测试消息
                    return Encoding.ASCII.GetBytes("<14>scanner: test message\r\n");
                case 69: // TFTP - 读请求
                    return Encoding.ASCII.GetBytes("\x00\x01test.txt\x00octet\x00");
                default:
                    // 通用探测：发送一个空的 UDP 数据包
                    // 关闭的端口会回 ICMP Port Unreachable
                    return new byte[] { 0x00 };
            }
        }

        /// <summary>
        /// 解析服务版本信息
        /// </summary>
        /// <param name="service">服务名称</param>
        /// <param name="response">服务响应</param>
        /// <returns>解析后的服务版本</returns>
        private string ParseServiceVersion(string service, string response)
        {
            if (string.IsNullOrEmpty(response))
                return "";

            // 限制响应长度，防止显示问题
            string trimmedResponse = response.Length > 100 ? response.Substring(0, 100) : response;

            // 根据服务类型解析响应获取版本信息
            switch (service?.ToLower())
            {
                case "http":
                case "https":
                    // 提取HTTP服务器版本
                    int serverIndex = trimmedResponse.IndexOf("Server:", StringComparison.OrdinalIgnoreCase);
                    if (serverIndex >= 0)
                    {
                        int endOfLine = trimmedResponse.IndexOf("\r\n", serverIndex);
                        if (endOfLine > serverIndex)
                        {
                            string version = trimmedResponse.Substring(serverIndex + 7, endOfLine - serverIndex - 7).Trim();
                            return version.Length > 30 ? version.Substring(0, 30) + "..." : version;
                        }
                    }
                    // 也兼容 X-Powered-By
                    int xpbIndex = trimmedResponse.IndexOf("X-Powered-By:", StringComparison.OrdinalIgnoreCase);
                    if (xpbIndex >= 0)
                    {
                        int endOfLine = trimmedResponse.IndexOf("\r\n", xpbIndex);
                        if (endOfLine > xpbIndex)
                        {
                            string version = trimmedResponse.Substring(xpbIndex + 13, endOfLine - xpbIndex - 13).Trim();
                            return version.Length > 30 ? version.Substring(0, 30) + "..." : version;
                        }
                    }
                    break;
                case "ftp":
                    // 提取FTP服务器版本（通常在第一行）
                    if (trimmedResponse.Contains("220"))
                    {
                        string version = trimmedResponse.Substring(4).Trim();
                        return version.Length > 30 ? version.Substring(0, 30) + "..." : version;
                    }
                    break;
                case "ssh":
                    // SSH版本通常在第一行: SSH-2.0-OpenSSH_7.4
                    if (trimmedResponse.StartsWith("SSH-"))
                    {
                        int newline = trimmedResponse.IndexOfAny(new[] { '\r', '\n' });
                        string version = newline > 0 ? trimmedResponse.Substring(0, newline) : trimmedResponse;
                        version = version.Trim();
                        return version.Length > 40 ? version.Substring(0, 40) + "..." : version;
                    }
                    break;
                case "smtp":
                    // 提取SMTP服务器版本
                    if (trimmedResponse.Contains("220"))
                    {
                        int firstLine = trimmedResponse.IndexOfAny(new[] { '\r', '\n' });
                        string firstResponse = firstLine > 0 ? trimmedResponse.Substring(0, firstLine) : trimmedResponse;
                        if (firstResponse.StartsWith("220"))
                        {
                            string version = firstResponse.Substring(3).Trim();
                            return version.Length > 30 ? version.Substring(0, 30) + "..." : version;
                        }
                    }
                    break;
                case "pop3":
                    // 提取POP3服务器版本
                    if (trimmedResponse.Contains("+OK"))
                    {
                        int firstLine = trimmedResponse.IndexOfAny(new[] { '\r', '\n' });
                        string firstResponse = firstLine > 0 ? trimmedResponse.Substring(0, firstLine) : trimmedResponse;
                        if (firstResponse.StartsWith("+OK"))
                        {
                            string version = firstResponse.Substring(3).Trim();
                            return version.Length > 30 ? version.Substring(0, 30) + "..." : version;
                        }
                    }
                    break;
                case "imap":
                    // 提取IMAP服务器版本：* OK [CAPABILITY ...] IMAP4rev1 server ready
                    if (trimmedResponse.Contains("OK"))
                    {
                        int firstLine = trimmedResponse.IndexOfAny(new[] { '\r', '\n' });
                        string firstResponse = firstLine > 0 ? trimmedResponse.Substring(0, firstLine) : trimmedResponse;
                        string version = firstResponse.Replace("* OK", "").Replace("[CAPABILITY", "").Trim();
                        return version.Length > 50 ? version.Substring(0, 50) + "..." : version;
                    }
                    break;
                case "telnet":
                    // 特别处理Telnet服务，限制返回长度
                    string telnetVersion = trimmedResponse.Trim();
                    return telnetVersion.Length > 20 ? telnetVersion.Substring(0, 20) + "..." : telnetVersion;
                case "mysql":
                    // MySQL 握手包：4 字节长度 + 1 字节序号 + 4 字节协议版本 + NUL 结尾的版本字符串
                    // 例: "5.7.26-log" 或 "8.0.32"
                    // response 是字符串，0x00 在这里显示为 \0
                    try
                    {
                        // 查找第一个 NUL 字符位置（从第 5 个字符后开始）
                        int nullIdx = response.IndexOf('\0', 5);
                        if (nullIdx > 5 && nullIdx < response.Length)
                        {
                            int versionStart = nullIdx + 1;
                            // 跳过 server version 后是 NUL 终止符
                            int versionEnd = response.IndexOf('\0', versionStart);
                            if (versionEnd > versionStart && versionEnd - versionStart < 50)
                            {
                                string ver = response.Substring(versionStart, versionEnd - versionStart);
                                if (!string.IsNullOrWhiteSpace(ver))
                                    return "MySQL " + ver;
                            }
                        }
                    }
                    catch { }
                    // 兜底：从响应中提取 "X.Y.Z" 形式
                    var mysqlMatch = System.Text.RegularExpressions.Regex.Match(trimmedResponse, @"(\d+\.\d+\.\d+[^\s\x00]*)");
                    if (mysqlMatch.Success) return "MySQL " + mysqlMatch.Groups[1].Value;
                    break;
                case "postgresql":
                    // PostgreSQL 错误响应：包含 "PostgreSQL X.Y.Z" 字样
                    var pgMatch = System.Text.RegularExpressions.Regex.Match(trimmedResponse, @"PostgreSQL\s+(\d+\.\d+(?:\.\d+)?)");
                    if (pgMatch.Success) return "PostgreSQL " + pgMatch.Groups[1].Value;
                    break;
                case "redis":
                    // Redis PING 响应：+PONG\r\n 或带版本信息
                    if (trimmedResponse.StartsWith("+PONG"))
                    {
                        return "Redis (PONG received)";
                    }
                    if (trimmedResponse.StartsWith("-"))
                    {
                        // 错误信息：可能含 NOAUTH 等
                        int lineEnd = trimmedResponse.IndexOfAny(new[] { '\r', '\n' });
                        string errLine = lineEnd > 0 ? trimmedResponse.Substring(0, lineEnd) : trimmedResponse;
                        return "Redis " + errLine.Substring(1).Trim();
                    }
                    break;
                case "mongodb":
                    // MongoDB isMaster 响应（BSON 格式），提取 version 字段
                    var mongoMatch = System.Text.RegularExpressions.Regex.Match(trimmedResponse, @"version[\"":\s]+(\d+\.\d+\.\d+)");
                    if (mongoMatch.Success) return "MongoDB " + mongoMatch.Groups[1].Value;
                    if (trimmedResponse.Contains("ismaster")) return "MongoDB (BSON response)";
                    break;
                case "mssql":
                    // SQL Server 预登录响应中可提取版本
                    var mssqlMatch = System.Text.RegularExpressions.Regex.Match(trimmedResponse, @"(\d+\.\d+\.\d+\.\d+)");
                    if (mssqlMatch.Success) return "MSSQL " + mssqlMatch.Groups[1].Value;
                    break;
                case "rdp":
                    if (trimmedResponse.Contains("RDP")) return "RDP server";
                    break;
                case "vnc":
                    if (trimmedResponse.StartsWith("RFB "))
                    {
                        int newline = trimmedResponse.IndexOfAny(new[] { '\r', '\n' });
                        string version = newline > 0 ? trimmedResponse.Substring(0, newline) : trimmedResponse;
                        return version.Trim();
                    }
                    break;
            }

            // 如果没有找到特定服务的版本信息，返回截断的响应
            return trimmedResponse.Length > 30 ? trimmedResponse.Substring(0, 30) + "..." : trimmedResponse;
        }

        /// <summary>
        /// UDP端口扫描单个端口
        /// UDP扫描原理：
        /// 1. 发送UDP数据包到目标端口
        /// 2. 如果收到ICMP端口不可达消息，端口关闭
        /// 3. 如果超时未收到响应，端口可能开放或被过滤
        /// 4. 如果收到UDP响应，端口开放
        /// 增强：使用协议特定探测包（DNS/SNMP/NTP）以提高 UDP 端口检测的准确度
        /// </summary>
        public async Task<PortScanResult> ScanUdpPortAsync(string targetIp, int port, int timeout, CancellationToken cancellationToken = default)
        {
            UdpClient udpClient = null;
            try
            {
                cancellationToken.ThrowIfCancellationRequested();

                udpClient = new UdpClient(AddressFamily.InterNetwork);
                udpClient.Client.ReceiveTimeout = timeout;
                udpClient.Client.SendTimeout = timeout;

                IPAddress targetAddress = IPAddress.Parse(targetIp);
                IPEndPoint targetEndPoint = new IPEndPoint(targetAddress, port);

                // 使用协议特定探测包提高 UDP 扫描准确度
                byte[] sendData = GetUdpProbeData(port);

                try
                {
                    await udpClient.SendAsync(sendData, sendData.Length, targetEndPoint);
                }
                catch (SocketException sendEx)
                {
                    Console.WriteLine($"UDP端口 {port} 发送失败: {sendEx.Message}");
                    return CreatePortResult(port, "关闭");
                }

                var timeoutTask = Task.Delay(timeout, cancellationToken);
                var receiveTask = udpClient.ReceiveAsync();

                // 注册异常观察器，防止未观察异常被终结器抛出
                _ = receiveTask.ContinueWith(t => { var _ = t.Exception; },
                    CancellationToken.None, TaskContinuationOptions.OnlyOnFaulted, TaskScheduler.Default);

                var completedTask = await Task.WhenAny(receiveTask, timeoutTask);

                if (completedTask == timeoutTask)
                {
                    return CreatePortResult(port, "开放或过滤");
                }

                try
                {
                    var udpResult = await receiveTask;
                    // 收到 UDP 响应，认为端口开放
                    var portResult = CreatePortResult(port, "开放");
                    portResult.Confidence = "高"; // 收到 UDP 响应，可信度高
                    portResult.ScanDurationMs = (long)timeout; // 实际等待时间
                    return portResult;
                }
                catch (SocketException recvEx)
                {
                    if (recvEx.SocketErrorCode == SocketError.ConnectionReset)
                    {
                        return CreatePortResult(port, "关闭");
                    }
                    return CreatePortResult(port, "关闭");
                }
                catch (ObjectDisposedException)
                {
                    return CreatePortResult(port, "未知");
                }
            }
            catch (OperationCanceledException)
            {
                throw;
            }
            catch (FormatException)
            {
                return CreatePortResult(port, "未知");
            }
            catch (SocketException ex)
            {
                Console.WriteLine($"UDP端口 {port} Socket异常: {ex.SocketErrorCode} - {ex.Message}");

                switch (ex.SocketErrorCode)
                {
                    case SocketError.ConnectionReset:
                        return CreatePortResult(port, "关闭");
                    case SocketError.TimedOut:
                        return CreatePortResult(port, "开放或过滤");
                    case SocketError.AccessDenied:
                    case SocketError.HostUnreachable:
                    case SocketError.NetworkUnreachable:
                        return CreatePortResult(port, "关闭");
                    default:
                        return CreatePortResult(port, "关闭");
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"UDP端口 {port} 未知异常: {ex.GetType().Name} - {ex.Message}");
                return CreatePortResult(port, "未知");
            }
            finally
            {
                try
                {
                    udpClient?.Dispose();
                }
                catch
                {
                }
            }
        }

        // 重载方法，保持向后兼容
        public async Task<PortScanResult> ScanPortAsync(string targetIp, int port, CancellationToken cancellationToken = default)
        {
            return await ScanTcpPortAsync(targetIp, port, DefaultTimeout, cancellationToken);
        }

        // 重载方法，保持向后兼容
        public async Task<PortScanResult> ScanPortAsync(string targetIp, int port, int timeout, CancellationToken cancellationToken = default)
        {
            return await ScanTcpPortAsync(targetIp, port, timeout, cancellationToken);
        }

        /// <summary>
        /// 创建端口扫描结果，自动填充风险信息（风险等级、评分、类别、漏洞提示、风险描述）
        /// </summary>
        /// <param name="port">端口号</param>
        /// <param name="status">端口状态</param>
        /// <param name="confidence">可信度（可选，默认根据状态推断）</param>
        /// <returns>端口扫描结果</returns>
        private PortScanResult CreatePortResult(int port, string status, string confidence = null)
        {
            // 自动填充风险信息：基于 PortRiskScorer 评估
            var riskLevel = PortRiskScorer.GetRiskLevel(port);
            return new PortScanResult
            {
                PortNumber = port,
                Status = status,
                Service = PortServiceMapping.GetServiceName(port),
                ServiceVersion = "", // 初始化为空字符串，避免null值
                Confidence = confidence ?? InferConfidence(status),
                RiskLevel = PortRiskScorer.GetRiskLevelName(riskLevel),
                RiskScore = PortRiskScorer.GetRiskScore(port),
                ServiceCategory = PortRiskScorer.GetCategoryName(PortRiskScorer.GetCategory(port)),
                VulnHint = PortRiskScorer.GetVulnHint(port),
                RiskDescription = PortRiskScorer.GetDescription(port)
            };
        }

        /// <summary>
        /// 根据端口状态推断可信度
        /// </summary>
        private static string InferConfidence(string status)
        {
            if (status == "开放") return "中"; // 状态明确但未拿到 banner
            if (status == "开放或过滤") return "低"; // 模糊状态
            if (status == "关闭") return "高"; // 三次握手 RST/ICMP unreachable 明确
            return "中";
        }

        #region IDisposable Implementation

        private bool _disposed = false;

        protected virtual void Dispose(bool disposing)
        {
            if (!_disposed && disposing)
            {
                // 在PortScanner中目前没有需要显式释放的托管资源
                // 但如果将来添加了HttpClient或其他需要释放的资源，可以在这里处理
            }
            _disposed = true;
        }

        public void Dispose()
        {
            Dispose(true);
            GC.SuppressFinalize(this);
        }

        #endregion
    }
}