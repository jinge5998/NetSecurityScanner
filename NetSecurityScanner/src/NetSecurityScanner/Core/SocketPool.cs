using System;
using System.Collections.Concurrent;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;

namespace NetSecurityScanner.Core
{
    /// <summary>
    /// Socket连接池 - 管理和复用Socket连接
    /// 用于优化端口扫描性能，减少连接建立和销毁的开销
    /// </summary>
    public class SocketPool : IDisposable
    {
        private readonly ConcurrentBag<Socket> _socketPool;
        private readonly SemaphoreSlim _poolSemaphore;
        private readonly int _maxPoolSize;
        private bool _disposed;
        private int _socketCreatedCount;
        private int _socketReusedCount;
        private int _socketFailedCount;
        private int _peakPoolUsage;
        private readonly object _statsLock = new object();

        /// <summary>
        /// 最大池大小
        /// </summary>
        public int MaxPoolSize => _maxPoolSize;

        /// <summary>
        /// 当前池中的Socket数量
        /// </summary>
        public int CurrentPoolSize => _socketPool.Count;

        /// <summary>
        /// 创建的Socket总数
        /// </summary>
        public int SocketCreatedCount => _socketCreatedCount;

        /// <summary>
        /// 复用的Socket总数
        /// </summary>
        public int SocketReusedCount => _socketReusedCount;

        /// <summary>
        /// 失败的Socket总数
        /// </summary>
        public int SocketFailedCount => _socketFailedCount;

        /// <summary>
        /// 峰值池使用率
        /// </summary>
        public int PeakPoolUsage => _peakPoolUsage;

        /// <summary>
        /// Socket复用率
        /// </summary>
        public double ReuseRate
        {
            get
            {
                int total = _socketCreatedCount + _socketReusedCount;
                return total > 0 ? (double)_socketReusedCount / total : 0;
            }
        }

        /// <summary>
        /// 初始化Socket池
        /// </summary>
        /// <param name="maxPoolSize">最大池大小，默认值为处理器核心数 * 10</param>
        public SocketPool(int maxPoolSize = 0)
        {
            _maxPoolSize = maxPoolSize > 0 ? maxPoolSize : Environment.ProcessorCount * 20; // 增加默认最大值
            _socketPool = new ConcurrentBag<Socket>();
            _poolSemaphore = new SemaphoreSlim(_maxPoolSize);
            _disposed = false;

            // 预初始化更多Socket，减少运行时创建开销
            int preInitCount = Math.Min(Math.Max(Environment.ProcessorCount * 10, 100), _maxPoolSize); // 增加预初始化数量
            for (int i = 0; i < preInitCount; i++)
            {
                _socketPool.Add(CreateNewSocket());
            }
        }

        /// <summary>
        /// 从池中获取Socket
        /// </summary>
        /// <param name="cancellationToken">取消令牌</param>
        /// <returns>可用的Socket</returns>
        public async Task<Socket> AcquireAsync(CancellationToken cancellationToken = default)
        {
            if (_disposed)
                throw new ObjectDisposedException(nameof(SocketPool));

            await _poolSemaphore.WaitAsync(cancellationToken);

            try
            {
                // 尝试从池中获取Socket，最多尝试3次
                int attempts = 0;
                while (attempts < 3)
                {
                    if (_socketPool.TryTake(out var socket) && IsSocketValid(socket))
                    {
                        // 增加复用计数
                        Interlocked.Increment(ref _socketReusedCount);
                        return socket;
                    }
                    attempts++;
                }

                // 池为空或取出的Socket不可用，创建新的
                return CreateNewSocket();
            }
            catch
            {
                _poolSemaphore.Release();
                throw;
            }
        }

        /// <summary>
        /// 归还Socket到池
        /// </summary>
        /// <param name="socket">要归还的Socket</param>
        public void Release(Socket socket)
        {
            if (_disposed || socket == null)
                return;

            try
            {
                // 重置Socket状态
                if (socket.Connected)
                {
                    try
                    {
                        socket.Shutdown(SocketShutdown.Both);
                    }
                    catch (Exception ex)
                    {
                        System.Diagnostics.Debug.WriteLine($"[SocketPool] Socket关闭连接失败: {ex.Message}");
                    }
                    try
                    {
                        socket.Close();
                    }
                    catch (Exception ex)
                    {
                        System.Diagnostics.Debug.WriteLine($"[SocketPool] Socket关闭失败: {ex.Message}");
                    }
                }

                // 重用Socket而不是销毁重建
                // 检查Socket是否还可用
                if (IsSocketValid(socket))
                {
                    // 重置Socket选项
                    socket.NoDelay = true;
                    socket.ReceiveTimeout = 1000;
                    socket.SendTimeout = 1000;
                    socket.ReceiveBufferSize = 1024;
                    socket.SendBufferSize = 1024;
                    
                    // 归还到池
                    _socketPool.Add(socket);
                    
                    // 更新峰值池使用率
                    int currentSize = _socketPool.Count;
                    if (currentSize > _peakPoolUsage)
                    {
                        Interlocked.Exchange(ref _peakPoolUsage, currentSize);
                    }
                }
                else
                {
                    // Socket不可用，创建新的
                    socket.Dispose();
                    Interlocked.Increment(ref _socketFailedCount);
                    var newSocket = CreateNewSocket();
                    _socketPool.Add(newSocket);
                }
            }
            catch (Exception ex)
            {
                // 发生错误时创建新的Socket
                System.Diagnostics.Debug.WriteLine($"[SocketPool] 归还Socket失败: {ex.Message}");
                try
                {
                    socket.Dispose();
                }
                catch (Exception ex2)
                {
                    System.Diagnostics.Debug.WriteLine($"[SocketPool] 释放Socket资源失败: {ex2.Message}");
                }
                Interlocked.Increment(ref _socketFailedCount);
                var newSocket = CreateNewSocket();
                _socketPool.Add(newSocket);
            }
            finally
            {
                _poolSemaphore.Release();
            }
        }
        
        /// <summary>
        /// 检查Socket是否有效
        /// </summary>
        /// <param name="socket">要检查的Socket</param>
        /// <returns>Socket是否有效</returns>
        private bool IsSocketValid(Socket socket)
        {
            try
            {
                // 检查Socket是否已被处置
                if (socket == null)
                    return false;
                
                // 检查Socket状态
                return !socket.Connected; // 确保Socket未连接
            }
            catch
            {
                return false;
            }
        }

        /// <summary>
        /// 创建新的Socket
        /// </summary>
        /// <returns>新的Socket实例</returns>
        private Socket CreateNewSocket()
        {
            var socket = new Socket(
                AddressFamily.InterNetwork,
                SocketType.Stream,
                ProtocolType.Tcp
            );

            // 优化Socket设置
            socket.NoDelay = true; // 禁用Nagle算法
            socket.ReceiveTimeout = 1000;
            socket.SendTimeout = 1000;
            socket.ReceiveBufferSize = 1024;
            socket.SendBufferSize = 1024;
            
            // 增加创建计数
            Interlocked.Increment(ref _socketCreatedCount);

            return socket;
        }

        /// <summary>
        /// 清空池
        /// </summary>
        public void Clear()
        {
            while (_socketPool.TryTake(out var socket))
            {
                try
                {
                    socket.Dispose();
                }
                catch { }
            }
        }

        /// <summary>
        /// 释放资源
        /// </summary>
        public void Dispose()
        {
            Dispose(true);
            GC.SuppressFinalize(this);
        }

        /// <summary>
        /// 释放资源
        /// </summary>
        /// <param name="disposing">是否手动释放</param>
        protected virtual void Dispose(bool disposing)
        {
            if (!_disposed)
            {
                if (disposing)
                {
                    Clear();
                    _poolSemaphore.Dispose();
                }

                _disposed = true;
            }
        }

        /// <summary>
        /// 获取Socket池统计信息
        /// </summary>
        /// <returns>统计信息字符串</returns>
        public string GetStatistics()
        {
            return $"Socket池统计信息:\n"
                + $"- 最大池大小: {_maxPoolSize}\n"
                + $"- 当前池大小: {CurrentPoolSize}\n"
                + $"- 创建的Socket: {_socketCreatedCount}\n"
                + $"- 复用的Socket: {_socketReusedCount}\n"
                + $"- 失败的Socket: {_socketFailedCount}\n"
                + $"- 峰值池使用率: {_peakPoolUsage}\n"
                + $"- Socket复用率: {ReuseRate:P2}\n";
        }

        /// <summary>
        /// 析构函数
        /// </summary>
        ~SocketPool()
        {
            Dispose(false);
        }
    }
}
