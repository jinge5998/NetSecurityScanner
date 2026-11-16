using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.Json;
using System.Threading.Tasks;
using NetSecurityScanner.Models;

namespace NetSecurityScanner.Services
{
    /// <summary>
    /// 端口扫描数据服务
    /// 负责端口扫描结果的JSON存储和读取
    /// </summary>
    public class PortScanDataService
    {
        private readonly string _dataDirectory;
        private readonly string _portScanDirectory;
        private readonly JsonSerializerOptions _jsonOptions;

        public PortScanDataService()
        {
            // 设置数据目录路径
            string appDataPath = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
            string appDirectory = Path.Combine(appDataPath, "NetSecurityScanner");
            _dataDirectory = Path.Combine(appDirectory, "Data");
            _portScanDirectory = Path.Combine(_dataDirectory, "PortScans");

            // 确保目录存在
            Directory.CreateDirectory(_portScanDirectory);

            // 配置JSON序列化选项
            _jsonOptions = new JsonSerializerOptions
            {
                WriteIndented = true,
                PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
                PropertyNameCaseInsensitive = true
            };
        }

        /// <summary>
        /// 保存端口扫描结果到JSON文件
        /// </summary>
        /// <param name="targetIp">目标IP</param>
        /// <param name="portScanResults">端口扫描结果列表</param>
        /// <param name="totalPortsScanned">扫描的总端口数（包括所有状态）</param>
        /// <returns>扫描会话ID</returns>
        public async Task<string> SavePortScanResultsAsync(string targetIp, List<PortScanResult> portScanResults, int totalPortsScanned = 0)
        {
            try
            {
                // 如果没有提供总端口数，使用结果列表的数量
                int actualTotalPorts = totalPortsScanned > 0 ? totalPortsScanned : portScanResults.Count;
                
                var scanSession = new PortScanSession
                {
                    SessionId = Guid.NewGuid().ToString("N"),
                    TargetIp = targetIp,
                    ScanTime = DateTime.Now,
                    TotalPorts = actualTotalPorts,
                    OpenPorts = portScanResults.Count(p => p.Status == "开放"),
                    ClosedPorts = portScanResults.Count(p => p.Status == "Closed" || p.Status == "关闭" || p.Status == "关闭或过滤"),
                    FilteredPorts = portScanResults.Count(p => p.Status == "Filtered" || p.Status == "过滤" || p.Status == "开放或过滤"),
                    PortScanResults = portScanResults.Where(p => p.Status == "开放" || p.Status == "开放或过滤").ToList()
                };

                string fileName = $"portscan_{scanSession.SessionId}.json";
                string filePath = Path.Combine(_portScanDirectory, fileName);

                string json = JsonSerializer.Serialize(scanSession, _jsonOptions);
                await File.WriteAllTextAsync(filePath, json);

                // 同时保存一个最新的扫描结果文件，方便快速访问
                string latestFilePath = Path.Combine(_dataDirectory, "latest_portscan.json");
                await File.WriteAllTextAsync(latestFilePath, json);

                return scanSession.SessionId;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"保存端口扫描结果失败: {ex.Message}");
                throw;
            }
        }

        /// <summary>
        /// 根据会话ID获取端口扫描结果
        /// </summary>
        /// <param name="sessionId">扫描会话ID</param>
        /// <returns>端口扫描会话数据</returns>
        public async Task<PortScanSession?> GetPortScanResultsAsync(string sessionId)
        {
            try
            {
                string fileName = $"portscan_{sessionId}.json";
                string filePath = Path.Combine(_portScanDirectory, fileName);

                if (!File.Exists(filePath))
                {
                    return null;
                }

                string json = await File.ReadAllTextAsync(filePath);
                return JsonSerializer.Deserialize<PortScanSession>(json, _jsonOptions);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"获取端口扫描结果失败: {ex.Message}");
                return null;
            }
        }

        /// <summary>
        /// 获取最新的端口扫描结果
        /// </summary>
        /// <returns>最新的端口扫描会话数据</returns>
        public async Task<PortScanSession?> GetLatestPortScanResultsAsync()
        {
            try
            {
                string latestFilePath = Path.Combine(_dataDirectory, "latest_portscan.json");

                if (!File.Exists(latestFilePath))
                {
                    // 如果没有最新文件，尝试获取最新的扫描会话
                    return await GetMostRecentPortScanAsync();
                }

                string json = await File.ReadAllTextAsync(latestFilePath);
                return JsonSerializer.Deserialize<PortScanSession>(json, _jsonOptions);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"获取最新端口扫描结果失败: {ex.Message}");
                return null;
            }
        }

        /// <summary>
        /// 获取最近的端口扫描结果
        /// </summary>
        /// <returns>最近的端口扫描会话数据</returns>
        public async Task<PortScanSession?> GetMostRecentPortScanAsync()
        {
            try
            {
                if (!Directory.Exists(_portScanDirectory))
                {
                    return null;
                }

                var files = Directory.GetFiles(_portScanDirectory, "portscan_*.json")
                    .Select(f => new FileInfo(f))
                    .OrderByDescending(f => f.LastWriteTime)
                    .FirstOrDefault();

                if (files == null)
                {
                    return null;
                }

                string json = await File.ReadAllTextAsync(files.FullName);
                return JsonSerializer.Deserialize<PortScanSession>(json, _jsonOptions);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"获取最近端口扫描结果失败: {ex.Message}");
                return null;
            }
        }

        /// <summary>
        /// 获取所有端口扫描历史记录
        /// </summary>
        /// <returns>端口扫描会话列表</returns>
        public async Task<List<PortScanSession>> GetAllPortScanHistoryAsync()
        {
            try
            {
                if (!Directory.Exists(_portScanDirectory))
                {
                    return new List<PortScanSession>();
                }

                var files = Directory.GetFiles(_portScanDirectory, "portscan_*.json")
                    .OrderByDescending(f => File.GetLastWriteTime(f));

                var sessions = new List<PortScanSession>();
                foreach (var file in files)
                {
                    try
                    {
                        string json = await File.ReadAllTextAsync(file);
                        var session = JsonSerializer.Deserialize<PortScanSession>(json, _jsonOptions);
                        if (session != null)
                        {
                            sessions.Add(session);
                        }
                    }
                    catch (Exception ex)
                    {
                        Console.WriteLine($"读取扫描历史文件失败 {file}: {ex.Message}");
                    }
                }

                return sessions;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"获取端口扫描历史失败: {ex.Message}");
                return new List<PortScanSession>();
            }
        }

        /// <summary>
        /// 根据目标IP获取端口扫描结果
        /// </summary>
        /// <param name="targetIp">目标IP</param>
        /// <returns>端口扫描会话列表</returns>
        public async Task<List<PortScanSession>> GetPortScanResultsByTargetAsync(string targetIp)
        {
            try
            {
                var allSessions = await GetAllPortScanHistoryAsync();
                return allSessions.Where(s => s.TargetIp == targetIp).ToList();
            }
            catch (Exception ex)
            {
                Console.WriteLine($"根据目标IP获取端口扫描结果失败: {ex.Message}");
                return new List<PortScanSession>();
            }
        }

        /// <summary>
        /// 删除指定的端口扫描记录
        /// </summary>
        /// <param name="sessionId">扫描会话ID</param>
        /// <returns>是否删除成功</returns>
        public Task<bool> DeletePortScanResultsAsync(string sessionId)
        {
            try
            {
                string fileName = $"portscan_{sessionId}.json";
                string filePath = Path.Combine(_portScanDirectory, fileName);

                if (File.Exists(filePath))
                {
                    File.Delete(filePath);
                    return Task.FromResult(true);
                }

                return Task.FromResult(false);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"删除端口扫描结果失败: {ex.Message}");
                return Task.FromResult(false);
            }
        }

        /// <summary>
        /// 清理旧的端口扫描数据
        /// </summary>
        /// <param name="daysToKeep">保留天数</param>
        /// <returns>清理的记录数</returns>
        public Task<int> CleanupOldPortScanDataAsync(int daysToKeep = 30)
        {
            try
            {
                if (!Directory.Exists(_portScanDirectory))
                {
                    return Task.FromResult(0);
                }

                var cutoffDate = DateTime.Now.AddDays(-daysToKeep);
                var files = Directory.GetFiles(_portScanDirectory, "portscan_*.json")
                    .Select(f => new FileInfo(f))
                    .Where(f => f.LastWriteTime < cutoffDate);

                int deletedCount = 0;
                foreach (var file in files)
                {
                    try
                    {
                        file.Delete();
                        deletedCount++;
                    }
                    catch (Exception ex)
                    {
                        Console.WriteLine($"删除旧扫描文件失败 {file.Name}: {ex.Message}");
                    }
                }

                return Task.FromResult(deletedCount);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"清理旧端口扫描数据失败: {ex.Message}");
                return Task.FromResult(0);
            }
        }

        /// <summary>
        /// 导出端口扫描结果为JSON字符串
        /// </summary>
        /// <param name="sessionId">扫描会话ID</param>
        /// <returns>JSON字符串</returns>
        public async Task<string?> ExportPortScanResultsAsJsonAsync(string sessionId)
        {
            try
            {
                var session = await GetPortScanResultsAsync(sessionId);
                if (session == null)
                {
                    return null;
                }

                return JsonSerializer.Serialize(session, _jsonOptions);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"导出端口扫描结果失败: {ex.Message}");
                return null;
            }
        }

        /// <summary>
        /// 获取端口扫描统计信息
        /// </summary>
        /// <returns>统计信息</returns>
        public async Task<PortScanStatistics> GetPortScanStatisticsAsync()
        {
            try
            {
                var sessions = await GetAllPortScanHistoryAsync();

                return new PortScanStatistics
                {
                    TotalScans = sessions.Count,
                    TotalPortsScanned = sessions.Sum(s => s.TotalPorts),
                    TotalOpenPorts = sessions.Sum(s => s.OpenPorts),
                    AverageOpenPortsPerScan = sessions.Any() ? sessions.Average(s => s.OpenPorts) : 0,
                    LastScanTime = sessions.Any() ? sessions.Max(s => s.ScanTime) : null,
                    UniqueTargets = sessions.Select(s => s.TargetIp).Distinct().Count()
                };
            }
            catch (Exception ex)
            {
                Console.WriteLine($"获取端口扫描统计信息失败: {ex.Message}");
                return new PortScanStatistics();
            }
        }
    }

    /// <summary>
    /// 端口扫描会话数据模型
    /// </summary>
    public class PortScanSession
    {
        public string SessionId { get; set; } = string.Empty;
        public string TargetIp { get; set; } = string.Empty;
        public DateTime ScanTime { get; set; }
        public int TotalPorts { get; set; }
        public int OpenPorts { get; set; }
        public int ClosedPorts { get; set; }
        public int FilteredPorts { get; set; }
        public List<PortScanResult> PortScanResults { get; set; } = new List<PortScanResult>();
    }

    /// <summary>
    /// 端口扫描统计信息
    /// </summary>
    public class PortScanStatistics
    {
        public int TotalScans { get; set; }
        public int TotalPortsScanned { get; set; }
        public int TotalOpenPorts { get; set; }
        public double AverageOpenPortsPerScan { get; set; }
        public DateTime? LastScanTime { get; set; }
        public int UniqueTargets { get; set; }
    }
}
