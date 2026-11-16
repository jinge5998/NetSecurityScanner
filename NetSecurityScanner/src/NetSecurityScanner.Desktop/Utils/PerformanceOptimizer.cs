using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Threading;
using System.Windows.Threading;

namespace NetSecurityScanner.Utils
{
    /// <summary>
    /// UI更新节流器 - 用于限制UI更新频率，防止频繁刷新导致界面卡顿
    /// 
    /// 使用场景：
    /// - 端口扫描过程中每个端口都触发UI更新时
    /// - 漏洞检测结果批量加载到DataGrid时
    /// - 实时统计数据频繁变化时
    /// </summary>
    public class UiUpdateThrottler : IDisposable
    {
        private readonly Dispatcher _dispatcher;
        private readonly Timer _timer;
        private readonly ConcurrentQueue<Action> _pendingActions;
        private readonly object _lockObject = new object();
        private int _updateIntervalMs;
        private bool _isDisposed;

        /// <summary>
        /// 待处理的操作数量
        /// </summary>
        public int PendingCount => _pendingActions.Count;

        /// <summary>
        /// UI更新间隔（毫秒）
        /// </summary>
        public int UpdateIntervalMs
        {
            get => _updateIntervalMs;
            set
            {
                if (value > 0)
                {
                    _updateIntervalMs = value;
                    _timer.Change(value, value);
                }
            }
        }

        /// <summary>
        /// 统计信息：总处理次数
        /// </summary>
        private long _totalProcessed;
        public long TotalProcessed => _totalProcessed;

        /// <summary>
        /// 统计信息：合并的更新次数（节省的UI刷新次数）
        /// </summary>
        private long _mergedUpdates;
        public long MergedUpdates => _mergedUpdates;

        /// <summary>
        /// 创建UI更新节流器
        /// </summary>
        /// <param name="dispatcher">UI线程调度器</param>
        /// <param name="updateIntervalMs">更新间隔（毫秒），默认500ms</param>
        public UiUpdateThrottler(Dispatcher dispatcher, int updateIntervalMs = 500)
        {
            _dispatcher = dispatcher ?? throw new ArgumentNullException(nameof(dispatcher));
            _pendingActions = new ConcurrentQueue<Action>();
            _updateIntervalMs = Math.Max(50, updateIntervalMs); // 最小50ms

            // 使用Timer定期触发批量处理
            _timer = new Timer(OnTimerTick, null, _updateIntervalMs, _updateIntervalMs);
        }

        /// <summary>
        /// 提交UI更新操作（会被合并处理）
        /// </summary>
        /// <param name="action">要执行的UI更新操作</param>
        public void Enqueue(Action action)
        {
            if (_isDisposed || action == null) return;

            _pendingActions.Enqueue(action);

            // 如果队列过大，立即触发一次处理
            if (_pendingActions.Count > 1000)
            {
                ProcessPendingUpdates();
            }
        }

        /// <summary>
        /// 提交带优先级的UI更新操作（高优先级会立即执行）
        /// </summary>
        /// <param name="action">要执行的UI更新操作</param>
        /// <param name="highPriority">是否为高优先级</param>
        public void Enqueue(Action action, bool highPriority)
        {
            if (_isDisposed || action == null) return;

            if (highPriority)
            {
                // 高优先级操作直接在UI线程执行
                try
                {
                    if (_dispatcher.CheckAccess())
                    {
                        action();
                    }
                    else
                    {
                        _dispatcher.BeginInvoke(action);
                    }
                    Interlocked.Increment(ref _totalProcessed);
                }
                catch (Exception ex)
                {
                    System.Diagnostics.Debug.WriteLine($"[UiThrottler] 高优先级操作执行失败: {ex.Message}");
                }
            }
            else
            {
                Enqueue(action);
            }
        }

        /// <summary>
        /// 立即处理所有待处理的更新
        /// </summary>
        public void Flush()
        {
            ProcessPendingUpdates();
        }

        /// <summary>
        /// 定时器回调 - 批量处理待处理的UI更新
        /// </summary>
        private void OnTimerTick(object? state)
        {
            ProcessPendingUpdates();
        }

        /// <summary>
        /// 处理所有待处理的UI更新
        /// </summary>
        private void ProcessPendingUpdates()
        {
            if (_isDisposed || _pendingActions.IsEmpty) return;

            lock (_lockObject)
            {
                if (_pendingActions.IsEmpty) return;

                try
                {
                    // 在UI线程中批量执行所有待处理的操作
                    _dispatcher.BeginInvoke((Action)(() =>
                    {
                        try
                        {
                            Action currentAction;
                            int batchCount = 0;
                            const int maxBatchSize = 100; // 每批最多处理100个操作

                            while (_pendingActions.TryDequeue(out currentAction) && batchCount < maxBatchSize)
                            {
                                try
                                {
                                    currentAction?.Invoke();
                                    batchCount++;
                                }
                                catch (Exception ex)
                                {
                                    System.Diagnostics.Debug.WriteLine($"[UiThrottler] UI操作执行失败: {ex.Message}");
                                }
                            }

                            if (batchCount > 1)
                            {
                                // 记录合并的更新次数
                                Interlocked.Add(ref _mergedUpdates, batchCount - 1);
                            }

                            Interlocked.Add(ref _totalProcessed, batchCount);
                        }
                        catch (Exception ex)
                        {
                            System.Diagnostics.Debug.WriteLine($"[UiThrottler] 批量处理失败: {ex.Message}");
                        }
                    }));
                }
                catch (Exception ex)
                {
                    System.Diagnostics.Debug.WriteLine($"[UiThrottler] 调度失败: {ex.Message}");
                }
            }
        }

        /// <summary>
        /// 清空待处理的队列
        /// </summary>
        public void Clear()
        {
            while (!_pendingActions.IsEmpty)
            {
                _pendingActions.TryDequeue(out _);
            }
        }

        /// <summary>
        /// 获取性能统计信息
        /// </summary>
        public string GetStatistics()
        {
            return $"UI节流器统计:\n" +
                   $"- 更新间隔: {_updateIntervalMs}ms\n" +
                   $"- 总处理次数: {TotalProcessed}\n" +
                   $"- 合并的更新: {MergedUpdates}\n" +
                   $"- 当前队列大小: {_pendingActions.Count}\n" +
                   $"- 节省UI刷新率: {(TotalProcessed > 0 ? (double)MergedUpdates / TotalProcessed * 100 : 0):F1}%";
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
                    _timer?.Dispose();
                    Clear();
                }
                _isDisposed = true;
            }
        }

        #endregion
    }

    /// <summary>
    /// 数据加载分页器 - 用于大数据集的分页加载，减少内存占用
    /// </summary>
    public class DataPager<T> where T : class
    {
        private readonly IList<T> _allData;
        private readonly int _pageSize;
        private int _currentPage;

        /// <summary>
        /// 页面大小（每页显示数量）
        /// </summary>
        public int PageSize => _pageSize;

        /// <summary>
        /// 当前页码（从0开始）
        /// </summary>
        public int CurrentPage => _currentPage;

        /// <summary>
        /// 总页数
        /// </summary>
        public int TotalPages => (int)Math.Ceiling((double)_allData.Count / _pageSize);

        /// <summary>
        /// 总数据数量
        /// </summary>
        public int TotalCount => _allData.Count;

        /// <summary>
        /// 是否有上一页
        /// </summary>
        public bool HasPreviousPage => _currentPage > 0;

        /// <summary>
        /// 是否有下一页
        /// </summary>
        public bool HasNextPage => _currentPage < TotalPages - 1;

        /// <summary>
        /// 创建数据分页器
        /// </summary>
        /// <param name="data">完整数据集</param>
        /// <param name="pageSize">每页大小，默认100</param>
        public DataPager(IList<T> data, int pageSize = 100)
        {
            _allData = data ?? throw new ArgumentNullException(nameof(data));
            _pageSize = Math.Max(10, Math.Min(pageSize, 1000)); // 限制在10-1000之间
            _currentPage = 0;
        }

        /// <summary>
        /// 获取当前页的数据
        /// </summary>
        public List<T> GetCurrentPage()
        {
            return GetPage(_currentPage);
        }

        /// <summary>
        /// 获取指定页的数据
        /// </summary>
        /// <param name="pageIndex">页码（从0开始）</param>
        public List<T> GetPage(int pageIndex)
        {
            if (pageIndex < 0 || pageIndex >= TotalPages)
                throw new ArgumentOutOfRangeException(nameof(pageIndex));

            _currentPage = pageIndex;

            int startIndex = pageIndex * _pageSize;
            int count = Math.Min(_pageSize, _allData.Count - startIndex);

            var pageData = new List<T>(count);
            for (int i = 0; i < count; i++)
            {
                pageData.Add(_allData[startIndex + i]);
            }

            return pageData;
        }

        /// <summary>
        /// 跳转到下一页
        /// </summary>
        public List<T> NextPage()
        {
            if (!HasNextPage)
                throw new InvalidOperationException("已经是最后一页");

            return GetPage(_currentPage + 1);
        }

        /// <summary>
        /// 跳转到上一页
        /// </summary>
        public List<T> PreviousPage()
        {
            if (!HasPreviousPage)
                throw new InvalidOperationException("已经是第一页");

            return GetPage(_currentPage - 1);
        }

        /// <summary>
        /// 跳转到首页
        /// </summary>
        public List<T> FirstPage()
        {
            return GetPage(0);
        }

        /// <summary>
        /// 跳转到末页
        /// </summary>
        public List<T> LastPage()
        {
            return GetPage(TotalPages - 1);
        }

        /// <summary>
        /// 重置到第一页
        /// </summary>
        public void Reset()
        {
            _currentPage = 0;
        }
    }
}