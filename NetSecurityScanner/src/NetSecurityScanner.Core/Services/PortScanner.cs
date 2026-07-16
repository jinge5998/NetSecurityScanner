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
    public class PortScanner : IDisposable
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
                            try
                            {
                                await client.ConnectAsync(targetIp, port);
                                                    
                                // 连接成功
                                var portResult = CreatePortResult(port, "开放");
                                                    
                                // 尝试识别服务版本
                                try
                                {
                                    portResult.ServiceVersion = await IdentifyServiceVersionAsync(targetIp, port, portResult.Service, ServiceVersionTimeout, cancellationToken);
                                }
                                catch (Exception)
                                {
                                    // 服务版本识别失败，不影响端口状态
                                    portResult.ServiceVersion = "未知版本";
                                }
                                                    
                                return portResult;
                            }
                            catch (OperationCanceledException)
                            {
                                // 超时或取消，端口可能开放或被过滤
                                return CreatePortResult(port, "开放或过滤");
                            }
                            catch (Exception)
                            {
                                // 连接失败，端口关闭
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
                        return CreatePortResult(port, "开放或过滤");
                    }
                }
                // 其他异常，端口关闭
                return CreatePortResult(port, "关闭");
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
                    return Encoding.ASCII.GetBytes("HEAD / HTTP/1.1\r\nHost: " + service + "\r\n\r\n");
                case "ftp":
                    return Encoding.ASCII.GetBytes("QUIT\r\n");
                case "smtp":
                    return Encoding.ASCII.GetBytes("EHLO localhost\r\nQUIT\r\n");
                case "pop3":
                    return Encoding.ASCII.GetBytes("QUIT\r\n");
                case "imap":
                    return Encoding.ASCII.GetBytes("QUIT\r\n");
                case "ssh":
                    // SSH服务会主动发送版本信息，不需要发送探测数据包
                    return null;
                case "telnet":
                    return Encoding.ASCII.GetBytes("\r\n");
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
            string trimmedResponse = response.Length > 50 ? response.Substring(0, 50) + "..." : response;
            
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
                    // SSH版本通常在第一行
                    if (trimmedResponse.StartsWith("SSH-"))
                    {
                        string version = trimmedResponse.Trim();
                        return version.Length > 30 ? version.Substring(0, 30) + "..." : version;
                    }
                    break;
                case "smtp":
                    // 提取SMTP服务器版本
                    if (trimmedResponse.Contains("220"))
                    {
                        string version = trimmedResponse.Substring(4).Trim();
                        return version.Length > 30 ? version.Substring(0, 30) + "..." : version;
                    }
                    break;
                case "pop3":
                    // 提取POP3服务器版本
                    if (trimmedResponse.Contains("+OK"))
                    {
                        string version = trimmedResponse.Substring(4).Trim();
                        return version.Length > 30 ? version.Substring(0, 30) + "..." : version;
                    }
                    break;
                case "imap":
                    // 提取IMAP服务器版本
                    if (trimmedResponse.Contains("* OK"))
                    {
                        string version = trimmedResponse.Substring(4).Trim();
                        return version.Length > 30 ? version.Substring(0, 30) + "..." : version;
                    }
                    break;
                case "telnet":
                    // 特别处理Telnet服务，限制返回长度
                    string telnetVersion = trimmedResponse.Trim();
                    return telnetVersion.Length > 20 ? telnetVersion.Substring(0, 20) + "..." : telnetVersion;
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
        /// </summary>
        /// <param name="targetIp">目标IP地址</param>
        /// <param name="port">端口号</param>
        /// <param name="timeout">超时时间（毫秒）</param>
        /// <param name="cancellationToken">取消令牌</param>
        /// <returns>端口扫描结果</returns>
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
                
                byte[] sendData = Encoding.ASCII.GetBytes("\r\n");
                
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
                    await receiveTask;
                    return CreatePortResult(port, "开放");
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
        /// 创建端口扫描结果
        /// </summary>
        /// <param name="port">端口号</param>
        /// <param name="status">端口状态</param>
        /// <returns>端口扫描结果</returns>
        private PortScanResult CreatePortResult(int port, string status)
        {
            return new PortScanResult
            {
                PortNumber = port,
                Status = status,
                Service = PortServiceMapping.GetServiceName(port),
                ServiceVersion = "" // 初始化为空字符串，避免null值
            };
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