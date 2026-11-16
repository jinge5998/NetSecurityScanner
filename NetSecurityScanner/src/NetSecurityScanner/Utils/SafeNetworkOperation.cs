using System;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;

namespace NetSecurityScanner.Utils
{
    /// <summary>
    /// 网络操作安全包装器 - 提供带重试、超时、错误处理的网络操作
    /// 
    /// 功能：
    /// 1. 自动重试（指数退避）
    /// 2. 超时控制
    /// 3. 错误分类和处理
    /// 4. 性能统计
    /// </summary>
    public static class SafeNetworkOperation
    {
        private static int _totalOperations;
        private static int _successfulOperations;
        private static int _failedOperations;
        private static int _retriedOperations;
        
        /// <summary>
        /// 总操作次数
        /// </summary>
        public static int TotalOperations => _totalOperations;
        
        /// <summary>
        /// 成功操作次数
        /// </summary>
        public static int SuccessfulOperations => _successfulOperations;
        
        /// <summary>
        /// 失败操作次数
        /// </summary>
        public static int FailedOperations => _failedOperations;
        
        /// <summary>
        /// 重试操作次数
        /// </summary>
        public static int RetriedOperations => _retriedOperations;
        
        /// <summary>
        /// 操作成功率
        /// </summary>
        public static double SuccessRate => _totalOperations > 0 ? (double)_successfulOperations / _totalOperations * 100 : 0;
        
        /// <summary>
        /// 执行安全的网络操作（带重试）
        /// </summary>
        /// <typeparam name="T">返回类型</typeparam>
        /// <param name="operation">要执行的操作</param>
        /// <param name="defaultValue">失败时的默认返回值</param>
        /// <param name="maxRetries">最大重试次数</param>
        /// <param name="baseDelayMs">基础延迟时间（毫秒）</param>
        /// <param name="cancellationToken">取消令牌</param>
        /// <returns>操作结果</returns>
        public static async Task<T> ExecuteAsync<T>(
            Func<Task<T>> operation,
            T defaultValue,
            int maxRetries = 3,
            int baseDelayMs = 1000,
            CancellationToken cancellationToken = default)
        {
            Interlocked.Increment(ref _totalOperations);
            
            Exception lastException = null;
            
            for (int i = 0; i <= maxRetries; i++)
            {
                try
                {
                    if (cancellationToken.IsCancellationRequested)
                        return defaultValue;
                    
                    var result = await operation().ConfigureAwait(false);
                    Interlocked.Increment(ref _successfulOperations);
                    return result;
                }
                catch (OperationCanceledException)
                {
                    // 取消操作，直接抛出或返回默认值
                    throw;
                }
                catch (SocketException ex) when (IsRetryableSocketError(ex))
                {
                    lastException = ex;
                    if (i < maxRetries)
                    {
                        Interlocked.Increment(ref _retriedOperations);
                        await ExponentialBackoffDelay(i, baseDelayMs, cancellationToken).ConfigureAwait(false);
                    }
                }
                catch (WebException ex) when (IsRetryableWebError(ex))
                {
                    lastException = ex;
                    if (i < maxRetries)
                    {
                        Interlocked.Increment(ref _retriedOperations);
                        await ExponentialBackoffDelay(i, baseDelayMs, cancellationToken).ConfigureAwait(false);
                    }
                }
                catch (IOException ex) when (IsRetryableIoError(ex))
                {
                    lastException = ex;
                    if (i < maxRetries)
                    {
                        Interlocked.Increment(ref _retriedOperations);
                        await ExponentialBackoffDelay(i, baseDelayMs, cancellationToken).ConfigureAwait(false);
                    }
                }
                catch (Exception ex)
                {
                    // 非可重试异常，立即失败
                    Interlocked.Increment(ref _failedOperations);
                    LogNetworkError("不可重试的异常", ex, i);
                    throw new NetworkOperationException($"网络操作失败: {ex.Message}", ex);
                }
            }
            
            Interlocked.Increment(ref _failedOperations);
            LogNetworkError("达到最大重试次数", lastException, maxRetries);
            return defaultValue;
        }
        
        /// <summary>
        /// 执行安全的无返回值网络操作（带重试）
        /// </summary>
        /// <param name="operation">要执行的操作</param>
        /// <param name="maxRetries">最大重试次数</param>
        /// <param name="baseDelayMs">基础延迟时间（毫秒）</param>
        /// <param name="cancellationToken">取消令牌</param>
        public static async Task ExecuteAsync(
            Func<Task> operation,
            int maxRetries = 3,
            int baseDelayMs = 1000,
            CancellationToken cancellationToken = default)
        {
            Interlocked.Increment(ref _totalOperations);
            
            Exception lastException = null;
            
            for (int i = 0; i <= maxRetries; i++)
            {
                try
                {
                    if (cancellationToken.IsCancellationRequested)
                        return;
                    
                    await operation().ConfigureAwait(false);
                    Interlocked.Increment(ref _successfulOperations);
                    return;
                }
                catch (OperationCanceledException)
                {
                    throw;
                }
                catch (SocketException ex) when (IsRetryableSocketError(ex))
                {
                    lastException = ex;
                    if (i < maxRetries)
                    {
                        Interlocked.Increment(ref _retriedOperations);
                        await ExponentialBackoffDelay(i, baseDelayMs, cancellationToken).ConfigureAwait(false);
                    }
                }
                catch (WebException ex) when (IsRetryableWebError(ex))
                {
                    lastException = ex;
                    if (i < maxRetries)
                    {
                        Interlocked.Increment(ref _retriedOperations);
                        await ExponentialBackoffDelay(i, baseDelayMs, cancellationToken).ConfigureAwait(false);
                    }
                }
                catch (Exception ex)
                {
                    Interlocked.Increment(ref _failedOperations);
                    throw new NetworkOperationException($"网络操作失败: {ex.Message}", ex);
                }
            }
            
            Interlocked.Increment(ref _failedOperations);
            throw new NetworkOperationException($"网络操作在{maxRetries}次重试后仍然失败: {lastException?.Message}", lastException);
        }
        
        /// <summary>
        /// 安全地连接TCP端口
        /// </summary>
        public static async Task<bool> ConnectTcpAsync(
            string host,
            int port,
            int timeoutMs = 3000,
            CancellationToken cancellationToken = default)
        {
            return await ExecuteAsync(async () =>
            {
                using (var client = new TcpClient())
                {
                    using (var cts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken))
                    {
                        cts.CancelAfter(timeoutMs);
                        
                        try
                        {
                            await client.ConnectAsync(host, port, cts.Token);
                            return client.Connected;
                        }
                        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
                        {
                            return false; // 超时
                        }
                    }
                }
            }, false, 2, 500, cancellationToken);
        }
        
        /// <summary>
        /// 安全地发送HTTP请求
        /// </summary>
        public static async Task<string> HttpGetAsync(
            string url,
            int timeoutMs = 10000,
            CancellationToken cancellationToken = default)
        {
            return await ExecuteAsync(async () =>
            {
                using (var client = new System.Net.Http.HttpClient())
                {
                    client.Timeout = TimeSpan.FromMilliseconds(timeoutMs);
                    var response = await client.GetAsync(url, cancellationToken);
                    response.EnsureSuccessStatusCode();
                    return await response.Content.ReadAsStringAsync(cancellationToken);
                }
            }, string.Empty, 2, 1000, cancellationToken);
        }
        
        /// <summary>
        /// 指数退避延迟
        /// </summary>
        private static async Task ExponentialBackoffDelay(int retryCount, int baseDelayMs, CancellationToken cancellationToken)
        {
            // 指数退避：delay = baseDelay * 2^retryCount + random jitter
            int delay = baseDelayMs * (int)Math.Pow(2, retryCount);
            delay = Math.Min(delay, 30000); // 最大30秒
            
            // 添加随机抖动（避免惊群效应）
            var random = new Random();
            int jitter = random.Next(0, delay / 4);
            delay += jitter;
            
            try
            {
                await Task.Delay(delay, cancellationToken);
            }
            catch (OperationCanceledException)
            {
                // 取消时不抛出，让上层处理
            }
        }
        
        /// <summary>
        /// 判断是否为可重试的Socket错误
        /// </summary>
        private static bool IsRetryableSocketError(SocketException ex)
        {
            switch (ex.SocketErrorCode)
            {
                case SocketError.TimedOut:
                case SocketError.NetworkUnreachable:
                case SocketError.HostUnreachable:
                case SocketError.ConnectionReset:
                case SocketError.WouldBlock:
                case SocketError.NoBufferSpaceAvailable:
                case SocketError.Interrupted:
                case SocketError.TryAgain:
                case SocketError.AddressNotAvailable:
                    return true;
                    
                default:
                    return false;
            }
        }
        
        /// <summary>
        /// 判断是否为可重试的Web错误
        /// </summary>
        private static bool IsRetryableWebError(WebException ex)
        {
            switch (ex.Status)
            {
                case WebExceptionStatus.Timeout:
                case WebExceptionStatus.NameResolutionFailure:
                case WebExceptionStatus.ConnectFailure:
                case WebExceptionStatus.ReceiveFailure:
                case WebExceptionStatus.SendFailure:
                case WebExceptionStatus.PipelineFailure:
                case WebExceptionStatus.RequestCanceled:
                case WebExceptionStatus.ConnectionClosed:
                    return true;
                    
                default:
                    return false;
            }
        }
        
        /// <summary>
        /// 判断是否为可重试的IO错误
        /// </summary>
        private static bool IsRetryableIoError(IOException ex)
        {
            // IO错误通常可以重试一次
            return !(
                ex is UnauthorizedAccessException ||
                ex is ArgumentException ||
                ex is ArgumentNullException
            );
        }
        
        /// <summary>
        /// 记录网络错误日志
        /// </summary>
        private static void LogNetworkError(string context, Exception ex, int attempt)
        {
            System.Diagnostics.Debug.WriteLine($"[SafeNetwork] {context} (尝试 {attempt + 1}): {ex?.GetType().Name}: {ex?.Message}");
        }
        
        /// <summary>
        /// 重置统计数据
        /// </summary>
        public static void ResetStatistics()
        {
            Interlocked.Exchange(ref _totalOperations, 0);
            Interlocked.Exchange(ref _successfulOperations, 0);
            Interlocked.Exchange(ref _failedOperations, 0);
            Interlocked.Exchange(ref _retriedOperations, 0);
        }
        
        /// <summary>
        /// 获取性能统计信息
        /// </summary>
        public static string GetStatistics()
        {
            return $"网络安全操作统计:\n" +
                   $"- 总操作数: {_totalOperations}\n" +
                   $"- 成功: {_successfulOperations}\n" +
                   $"- 失败: {_failedOperations}\n" +
                   $"- 重试: {_retriedOperations}\n" +
                   $"- 成功率: {SuccessRate:F1}%";
        }
    }

    /// <summary>
    /// 网络操作自定义异常
    /// </summary>
    public class NetworkOperationException : Exception
    {
        public NetworkOperationException(string message) : base(message) { }
        public NetworkOperationException(string message, Exception innerException) : base(message, innerException) { }
    }
}
