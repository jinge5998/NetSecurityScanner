using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using NetSecurityScanner.Models;

namespace NetSecurityScanner.Core
{
    /// <summary>
    /// 扫描结果缓存 - 存储和管理扫描结果，避免重复扫描
    /// </summary>
    public class ScanResultCache
    {
        private readonly ConcurrentDictionary<string, CacheEntry> _cache;
        private readonly int _maxCacheSize;
        private readonly TimeSpan _cacheExpiration;
        private int _cacheHits;
        private int _cacheMisses;
        private int _cacheEvictions;
        private object _cleanupLock = new object();

        /// <summary>
        /// 缓存命中数
        /// </summary>
        public int CacheHits => _cacheHits;

        /// <summary>
        /// 缓存未命中数
        /// </summary>
        public int CacheMisses => _cacheMisses;

        /// <summary>
        /// 缓存驱逐数
        /// </summary>
        public int CacheEvictions => _cacheEvictions;

        /// <summary>
        /// 当前缓存大小
        /// </summary>
        public int CurrentCacheSize => _cache.Count;

        /// <summary>
        /// 缓存命中率
        /// </summary>
        public double HitRate
        {
            get
            {
                int total = _cacheHits + _cacheMisses;
                return total > 0 ? (double)_cacheHits / total : 0;
            }
        }

        /// <summary>
        /// 初始化扫描结果缓存
        /// </summary>
        /// <param name="maxCacheSize">最大缓存大小</param>
        /// <param name="cacheExpiration">缓存过期时间</param>
        public ScanResultCache(int maxCacheSize = 10000, TimeSpan? cacheExpiration = null)
        {
            _maxCacheSize = maxCacheSize > 0 ? maxCacheSize : 10000;
            _cacheExpiration = cacheExpiration ?? TimeSpan.FromHours(24);
            _cache = new ConcurrentDictionary<string, CacheEntry>();
            _cacheHits = 0;
            _cacheMisses = 0;
            _cacheEvictions = 0;
        }

        /// <summary>
        /// 生成缓存键
        /// </summary>
        /// <param name="host">主机地址</param>
        /// <param name="port">端口号</param>
        /// <param name="protocol">协议类型</param>
        /// <returns>缓存键</returns>
        private string GenerateCacheKey(string host, int port, string protocol)
        {
            return $"{host.ToLower()}:{port}:{protocol.ToUpper()}";
        }

        /// <summary>
        /// 尝试从缓存获取扫描结果
        /// </summary>
        /// <param name="host">主机地址</param>
        /// <param name="port">端口号</param>
        /// <param name="protocol">协议类型</param>
        /// <param name="result">扫描结果</param>
        /// <returns>是否从缓存获取成功</returns>
        public bool TryGetCachedResult(string host, int port, string protocol, out PortInfo result)
        {
            string key = GenerateCacheKey(host, port, protocol);
            
            if (_cache.TryGetValue(key, out var entry))
            {
                // 检查缓存是否过期
                if (DateTime.Now - entry.Timestamp < _cacheExpiration)
                {
                    Interlocked.Increment(ref _cacheHits);
                    result = entry.PortInfo;
                    return true;
                }
                else
                {
                    // 缓存过期，移除
                    _cache.TryRemove(key, out _);
                    Interlocked.Increment(ref _cacheEvictions);
                }
            }
            
            Interlocked.Increment(ref _cacheMisses);
            result = null;
            return false;
        }

        /// <summary>
        /// 添加扫描结果到缓存
        /// </summary>
        /// <param name="host">主机地址</param>
        /// <param name="port">端口号</param>
        /// <param name="protocol">协议类型</param>
        /// <param name="portInfo">扫描结果</param>
        public void AddToCache(string host, int port, string protocol, PortInfo portInfo)
        {
            // 清理过期缓存
            CleanupExpiredEntries();
            
            // 检查缓存大小
            if (_cache.Count >= _maxCacheSize)
            {
                EvictOldestEntries();
            }
            
            string key = GenerateCacheKey(host, port, protocol);
            var entry = new CacheEntry
            {
                PortInfo = portInfo,
                Timestamp = DateTime.Now
            };
            
            _cache[key] = entry;
        }

        /// <summary>
        /// 批量添加扫描结果到缓存
        /// </summary>
        /// <param name="host">主机地址</param>
        /// <param name="protocol">协议类型</param>
        /// <param name="portInfos">扫描结果列表</param>
        public void AddBatchToCache(string host, string protocol, IEnumerable<PortInfo> portInfos)
        {
            // 清理过期缓存
            CleanupExpiredEntries();
            
            // 计算需要添加的数量
            int entriesToAdd = portInfos.Count();
            int spaceNeeded = _cache.Count + entriesToAdd;
            
            // 如果需要，驱逐旧条目
            if (spaceNeeded > _maxCacheSize)
            {
                int entriesToEvict = spaceNeeded - _maxCacheSize;
                EvictOldestEntries(entriesToEvict);
            }
            
            // 批量添加
            foreach (var portInfo in portInfos)
            {
                string key = GenerateCacheKey(host, portInfo.PortNumber, protocol);
                var entry = new CacheEntry
                {
                    PortInfo = portInfo,
                    Timestamp = DateTime.Now
                };
                
                _cache[key] = entry;
            }
        }

        /// <summary>
        /// 从缓存中移除指定主机的所有扫描结果
        /// </summary>
        /// <param name="host">主机地址</param>
        public void RemoveHostResults(string host)
        {
            string hostPrefix = $"{host.ToLower()}:";
            var keysToRemove = _cache.Where(kv => kv.Key.StartsWith(hostPrefix))
                .Select(kv => kv.Key)
                .ToList();
            
            foreach (var key in keysToRemove)
            {
                if (_cache.TryRemove(key, out _))
                {
                    Interlocked.Increment(ref _cacheEvictions);
                }
            }
        }

        /// <summary>
        /// 清空缓存
        /// </summary>
        public void Clear()
        {
            _cache.Clear();
            _cacheEvictions = 0;
            _cacheHits = 0;
            _cacheMisses = 0;
        }

        /// <summary>
        /// 清理过期的缓存条目
        /// </summary>
        private void CleanupExpiredEntries()
        {
            if (Monitor.TryEnter(_cleanupLock))
            {
                try
                {
                    var now = DateTime.Now;
                    var expiredKeys = _cache.Where(kv => now - kv.Value.Timestamp >= _cacheExpiration)
                        .Select(kv => kv.Key)
                        .ToList();
                    
                    foreach (var key in expiredKeys)
                    {
                        if (_cache.TryRemove(key, out _))
                        {
                            Interlocked.Increment(ref _cacheEvictions);
                        }
                    }
                }
                finally
                {
                    Monitor.Exit(_cleanupLock);
                }
            }
        }

        /// <summary>
        /// 驱逐最旧的缓存条目
        /// </summary>
        /// <param name="count">要驱逐的条目数量</param>
        private void EvictOldestEntries(int count = 100)
        {
            var oldestKeys = _cache.OrderBy(kv => kv.Value.Timestamp)
                .Take(count)
                .Select(kv => kv.Key)
                .ToList();
            
            foreach (var key in oldestKeys)
            {
                if (_cache.TryRemove(key, out _))
                {
                    Interlocked.Increment(ref _cacheEvictions);
                }
            }
        }

        /// <summary>
        /// 获取缓存统计信息
        /// </summary>
        /// <returns>统计信息字符串</returns>
        public string GetStatistics()
        {
            return $"扫描结果缓存统计信息:\n"
                + $"- 最大缓存大小: {_maxCacheSize}\n"
                + $"- 当前缓存大小: {_cache.Count}\n"
                + $"- 缓存命中: {_cacheHits}\n"
                + $"- 缓存未命中: {_cacheMisses}\n"
                + $"- 缓存驱逐: {_cacheEvictions}\n"
                + $"- 缓存命中率: {HitRate:P2}\n"
                + $"- 缓存过期时间: {_cacheExpiration}\n";
        }

        /// <summary>
        /// 缓存条目
        /// </summary>
        private class CacheEntry
        {
            public PortInfo PortInfo { get; set; }
            public DateTime Timestamp { get; set; }
        }
    }
}
