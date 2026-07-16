using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Threading.Tasks;
using NetSecurityScanner.Models;

namespace NetSecurityScanner.Data
{
    /// <summary>
    /// JSON数据库服务 - 替代传统数据库
    /// 提供JSON文件的读写操作，支持批量操作和异步操作
    /// </summary>
    public class JSONDatabaseService
    {
        private readonly string _dataDirectory;
        private readonly string _scanTasksFile;
        private readonly string _scanResultsFile;
        private readonly string _vulnerabilitiesFile;
        private readonly string _statisticsFile;
        
        // 内存缓存
        private List<ScanTask> _scanTasksCache;
        private List<ScanResult> _scanResultsCache;
        private List<Vulnerability> _vulnerabilitiesCache;
        private Dictionary<string, object> _statisticsCache;
        
        // 缓存状态
        private bool _isScanTasksCached;
        private bool _isScanResultsCached;
        private bool _isVulnerabilitiesCached;
        private bool _isStatisticsCached;
        
        // JSON序列化选项
        private readonly JsonSerializerOptions _jsonOptions;
        
        public JSONDatabaseService()
        {
            // 初始化数据目录路径
            _dataDirectory = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "data");
            _scanTasksFile = Path.Combine(_dataDirectory, "scantasks.json");
            _scanResultsFile = Path.Combine(_dataDirectory, "scanresults.json");
            _vulnerabilitiesFile = Path.Combine(_dataDirectory, "vulnerabilities.json");
            _statisticsFile = Path.Combine(_dataDirectory, "statistics.json");
            
            // 确保数据目录存在
            Directory.CreateDirectory(_dataDirectory);
            
            // 初始化缓存
            _scanTasksCache = new List<ScanTask>();
            _scanResultsCache = new List<ScanResult>();
            _vulnerabilitiesCache = new List<Vulnerability>();
            _statisticsCache = new Dictionary<string, object>();
            
            // 缓存状态
            _isScanTasksCached = false;
            _isScanResultsCached = false;
            _isVulnerabilitiesCached = false;
            _isStatisticsCached = false;
            
            // JSON序列化选项
            _jsonOptions = new JsonSerializerOptions
            {
                WriteIndented = true,
                DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
                PropertyNamingPolicy = JsonNamingPolicy.CamelCase
            };
            
            // 初始化文件
            InitializeFiles();
        }
        
        /// <summary>
        /// 初始化JSON文件
        /// </summary>
        private void InitializeFiles()
        {
            // 初始化扫描任务文件
            if (!File.Exists(_scanTasksFile))
            {
                File.WriteAllText(_scanTasksFile, JsonSerializer.Serialize(new List<ScanTask>(), _jsonOptions));
            }
            
            // 初始化扫描结果文件
            if (!File.Exists(_scanResultsFile))
            {
                File.WriteAllText(_scanResultsFile, JsonSerializer.Serialize(new List<ScanResult>(), _jsonOptions));
            }
            
            // 初始化漏洞文件
            if (!File.Exists(_vulnerabilitiesFile))
            {
                File.WriteAllText(_vulnerabilitiesFile, JsonSerializer.Serialize(new List<Vulnerability>(), _jsonOptions));
            }
            
            // 初始化统计文件
            if (!File.Exists(_statisticsFile))
            {
                File.WriteAllText(_statisticsFile, JsonSerializer.Serialize(new Dictionary<string, object>(), _jsonOptions));
            }
        }
        
        // ==================== 扫描任务操作 ====================
        
        /// <summary>
        /// 添加扫描任务
        /// </summary>
        public void AddScanTask(ScanTask task)
        {
            try
            {
                // 加载缓存
                LoadScanTasksCache();
                
                // 生成任务ID
                if (task.TaskId == 0)
                {
                    task.TaskId = _scanTasksCache.Count > 0 ? _scanTasksCache.Max(t => t.TaskId) + 1 : 1;
                }
                
                // 添加到缓存
                _scanTasksCache.Add(task);
                
                // 保存到文件
                SaveScanTasks();
            }
            catch (Exception ex)
            {
                Console.WriteLine($"添加扫描任务失败: {ex.Message}");
            }
        }
        
        /// <summary>
        /// 批量添加扫描任务
        /// </summary>
        public void AddScanTasks(IEnumerable<ScanTask> tasks)
        {
            try
            {
                // 加载缓存
                LoadScanTasksCache();
                
                // 生成任务ID
                int maxId = _scanTasksCache.Count > 0 ? _scanTasksCache.Max(t => t.TaskId) : 0;
                foreach (var task in tasks)
                {
                    if (task.TaskId == 0)
                    {
                        maxId++;
                        task.TaskId = maxId;
                    }
                    _scanTasksCache.Add(task);
                }
                
                // 保存到文件
                SaveScanTasks();
            }
            catch (Exception ex)
            {
                Console.WriteLine($"批量添加扫描任务失败: {ex.Message}");
            }
        }
        
        /// <summary>
        /// 异步添加扫描任务
        /// </summary>
        public async Task AddScanTaskAsync(ScanTask task)
        {
            await Task.Run(() => AddScanTask(task));
        }
        
        /// <summary>
        /// 异步批量添加扫描任务
        /// </summary>
        public async Task AddScanTasksAsync(IEnumerable<ScanTask> tasks)
        {
            await Task.Run(() => AddScanTasks(tasks));
        }
        
        /// <summary>
        /// 获取扫描任务
        /// </summary>
        public ScanTask GetScanTask(int taskId)
        {
            try
            {
                // 加载缓存
                LoadScanTasksCache();
                
                return _scanTasksCache.FirstOrDefault(t => t.TaskId == taskId);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"获取扫描任务失败: {ex.Message}");
                return null;
            }
        }
        
        /// <summary>
        /// 获取所有扫描任务
        /// </summary>
        public List<ScanTask> GetAllScanTasks()
        {
            try
            {
                // 加载缓存
                LoadScanTasksCache();
                
                return _scanTasksCache.ToList();
            }
            catch (Exception ex)
            {
                Console.WriteLine($"获取所有扫描任务失败: {ex.Message}");
                return new List<ScanTask>();
            }
        }
        
        /// <summary>
        /// 根据条件获取扫描任务
        /// </summary>
        public List<ScanTask> GetScanTasks(Func<ScanTask, bool> predicate)
        {
            try
            {
                // 加载缓存
                LoadScanTasksCache();
                
                return _scanTasksCache.Where(predicate).ToList();
            }
            catch (Exception ex)
            {
                Console.WriteLine($"根据条件获取扫描任务失败: {ex.Message}");
                return new List<ScanTask>();
            }
        }
        
        /// <summary>
        /// 更新扫描任务
        /// </summary>
        public void UpdateScanTask(ScanTask task)
        {
            try
            {
                // 加载缓存
                LoadScanTasksCache();
                
                // 查找并更新
                var existingTask = _scanTasksCache.FirstOrDefault(t => t.TaskId == task.TaskId);
                if (existingTask != null)
                {
                    _scanTasksCache.Remove(existingTask);
                    _scanTasksCache.Add(task);
                    
                    // 保存到文件
                    SaveScanTasks();
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"更新扫描任务失败: {ex.Message}");
            }
        }
        
        /// <summary>
        /// 删除扫描任务
        /// </summary>
        public void DeleteScanTask(int taskId)
        {
            try
            {
                // 加载缓存
                LoadScanTasksCache();
                LoadScanResultsCache();
                
                // 删除任务
                var task = _scanTasksCache.FirstOrDefault(t => t.TaskId == taskId);
                if (task != null)
                {
                    _scanTasksCache.Remove(task);
                    
                    // 删除相关的扫描结果
                    _scanResultsCache.RemoveAll(r => r.TaskId == taskId);
                    
                    // 保存到文件
                    SaveScanTasks();
                    SaveScanResults();
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"删除扫描任务失败: {ex.Message}");
            }
        }
        
        // ==================== 漏洞信息操作 ====================
        
        /// <summary>
        /// 添加漏洞信息
        /// </summary>
        public void AddVulnerability(Vulnerability vulnerability)
        {
            try
            {
                // 加载缓存
                LoadVulnerabilitiesCache();
                
                // 生成漏洞ID
                if (vulnerability.VulnerabilityId == 0)
                {
                    vulnerability.VulnerabilityId = _vulnerabilitiesCache.Count > 0 ? _vulnerabilitiesCache.Max(v => v.VulnerabilityId) + 1 : 1;
                }
                
                // 添加到缓存
                _vulnerabilitiesCache.Add(vulnerability);
                
                // 保存到文件
                SaveVulnerabilities();
            }
            catch (Exception ex)
            {
                Console.WriteLine($"添加漏洞信息失败: {ex.Message}");
            }
        }
        
        /// <summary>
        /// 批量添加漏洞信息
        /// </summary>
        public void AddVulnerabilities(IEnumerable<Vulnerability> vulnerabilities)
        {
            try
            {
                // 加载缓存
                LoadVulnerabilitiesCache();
                
                // 生成漏洞ID
                int maxId = _vulnerabilitiesCache.Count > 0 ? _vulnerabilitiesCache.Max(v => v.VulnerabilityId) : 0;
                foreach (var vulnerability in vulnerabilities)
                {
                    if (vulnerability.VulnerabilityId == 0)
                    {
                        maxId++;
                        vulnerability.VulnerabilityId = maxId;
                    }
                    _vulnerabilitiesCache.Add(vulnerability);
                }
                
                // 保存到文件
                SaveVulnerabilities();
            }
            catch (Exception ex)
            {
                Console.WriteLine($"批量添加漏洞信息失败: {ex.Message}");
            }
        }
        
        /// <summary>
        /// 获取漏洞信息
        /// </summary>
        public Vulnerability GetVulnerability(int vulnerabilityId)
        {
            try
            {
                // 加载缓存
                LoadVulnerabilitiesCache();
                
                return _vulnerabilitiesCache.FirstOrDefault(v => v.VulnerabilityId == vulnerabilityId);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"获取漏洞信息失败: {ex.Message}");
                return null;
            }
        }
        
        /// <summary>
        /// 获取所有漏洞信息
        /// </summary>
        public List<Vulnerability> GetAllVulnerabilities()
        {
            try
            {
                // 加载缓存
                LoadVulnerabilitiesCache();
                
                return _vulnerabilitiesCache.ToList();
            }
            catch (Exception ex)
            {
                Console.WriteLine($"获取所有漏洞信息失败: {ex.Message}");
                return new List<Vulnerability>();
            }
        }
        
        // ==================== 扫描结果操作 ====================
        
        /// <summary>
        /// 添加扫描结果
        /// </summary>
        public void AddScanResult(ScanResult result)
        {
            try
            {
                // 加载缓存
                LoadScanResultsCache();
                
                // 生成结果ID
                if (result.ResultId == 0)
                {
                    result.ResultId = _scanResultsCache.Count > 0 ? _scanResultsCache.Max(r => r.ResultId) + 1 : 1;
                }
                
                // 添加到缓存
                _scanResultsCache.Add(result);
                
                // 保存到文件
                SaveScanResults();
            }
            catch (Exception ex)
            {
                Console.WriteLine($"添加扫描结果失败: {ex.Message}");
            }
        }
        
        /// <summary>
        /// 批量添加扫描结果
        /// </summary>
        public void AddScanResults(IEnumerable<ScanResult> results)
        {
            try
            {
                // 加载缓存
                LoadScanResultsCache();
                
                // 生成结果ID
                int maxId = _scanResultsCache.Count > 0 ? _scanResultsCache.Max(r => r.ResultId) : 0;
                foreach (var result in results)
                {
                    if (result.ResultId == 0)
                    {
                        maxId++;
                        result.ResultId = maxId;
                    }
                    _scanResultsCache.Add(result);
                }
                
                // 保存到文件
                SaveScanResults();
            }
            catch (Exception ex)
            {
                Console.WriteLine($"批量添加扫描结果失败: {ex.Message}");
            }
        }
        
        /// <summary>
        /// 异步批量添加扫描结果
        /// </summary>
        public async Task AddScanResultsAsync(IEnumerable<ScanResult> results)
        {
            await Task.Run(() => AddScanResults(results));
        }
        
        /// <summary>
        /// 批量添加扫描任务和结果
        /// </summary>
        public void AddScanTaskWithResults(ScanTask task, IEnumerable<ScanResult> results)
        {
            try
            {
                // 添加任务
                AddScanTask(task);
                
                // 添加结果
                if (results != null && results.Any())
                {
                    foreach (var result in results)
                    {
                        result.TaskId = task.TaskId;
                    }
                    AddScanResults(results);
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"批量添加任务和结果失败: {ex.Message}");
            }
        }
        
        /// <summary>
        /// 异步批量添加扫描任务和结果
        /// </summary>
        public async Task AddScanTaskWithResultsAsync(ScanTask task, IEnumerable<ScanResult> results)
        {
            await Task.Run(() => AddScanTaskWithResults(task, results));
        }
        
        /// <summary>
        /// 根据任务ID获取扫描结果
        /// </summary>
        public List<ScanResult> GetScanResultsByTaskId(int taskId)
        {
            try
            {
                // 加载缓存
                LoadScanResultsCache();
                
                return _scanResultsCache.Where(r => r.TaskId == taskId).ToList();
            }
            catch (Exception ex)
            {
                Console.WriteLine($"根据任务ID获取扫描结果失败: {ex.Message}");
                return new List<ScanResult>();
            }
        }
        
        /// <summary>
        /// 获取任务的开放端口结果
        /// </summary>
        public List<ScanResult> GetOpenPortResults(int taskId)
        {
            try
            {
                // 加载缓存
                LoadScanResultsCache();
                
                return _scanResultsCache.Where(r => r.TaskId == taskId && !string.IsNullOrEmpty(r.Service)).ToList();
            }
            catch (Exception ex)
            {
                Console.WriteLine($"获取开放端口结果失败: {ex.Message}");
                return new List<ScanResult>();
            }
        }
        
        /// <summary>
        /// 获取漏洞扫描结果
        /// </summary>
        public List<ScanResult> GetVulnerableScanResults(int taskId)
        {
            try
            {
                // 加载缓存
                LoadScanResultsCache();
                
                return _scanResultsCache.Where(r => r.TaskId == taskId && r.IsVulnerable).ToList();
            }
            catch (Exception ex)
            {
                Console.WriteLine($"获取漏洞扫描结果失败: {ex.Message}");
                return new List<ScanResult>();
            }
        }
        
        /// <summary>
        /// 统计扫描结果
        /// </summary>
        public ScanStatistics GetScanStatistics(int taskId)
        {
            try
            {
                // 加载缓存
                LoadScanResultsCache();
                LoadScanTasksCache();
                
                var results = _scanResultsCache.Where(r => r.TaskId == taskId).ToList();
                var task = _scanTasksCache.FirstOrDefault(t => t.TaskId == taskId);
                
                return new ScanStatistics
                {
                    TotalPorts = results.Count,
                    OpenPorts = results.Count(r => !string.IsNullOrEmpty(r.Service)),
                    VulnerabilitiesFound = results.Count(r => r.IsVulnerable),
                    EndTime = task?.EndTime ?? DateTime.Now
                };
            }
            catch (Exception ex)
            {
                Console.WriteLine($"统计扫描结果失败: {ex.Message}");
                return new ScanStatistics();
            }
        }
        
        /// <summary>
        /// 清理过期数据
        /// </summary>
        public void CleanupOldData(int daysToKeep = 30)
        {
            try
            {
                // 加载缓存
                LoadScanTasksCache();
                LoadScanResultsCache();
                
                var cutoffDate = DateTime.Now.AddDays(-daysToKeep);
                
                // 删除过期的扫描任务
                var oldTasks = _scanTasksCache.Where(t => t.EndTime.HasValue && t.EndTime.Value < cutoffDate).ToList();
                var oldTaskIds = oldTasks.Select(t => t.TaskId).ToList();
                
                foreach (var task in oldTasks)
                {
                    _scanTasksCache.Remove(task);
                }
                
                // 删除过期的扫描结果
                _scanResultsCache.RemoveAll(r => oldTaskIds.Contains(r.TaskId));
                
                // 保存到文件
                SaveScanTasks();
                SaveScanResults();
            }
            catch (Exception ex)
            {
                Console.WriteLine($"清理过期数据失败: {ex.Message}");
            }
        }
        
        // ==================== 缓存操作 ====================
        
        /// <summary>
        /// 加载扫描任务缓存
        /// </summary>
        private void LoadScanTasksCache()
        {
            if (!_isScanTasksCached)
            {
                try
                {
                    if (File.Exists(_scanTasksFile))
                    {
                        var json = File.ReadAllText(_scanTasksFile);
                        _scanTasksCache = JsonSerializer.Deserialize<List<ScanTask>>(json, _jsonOptions) ?? new List<ScanTask>();
                    }
                    _isScanTasksCached = true;
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"加载扫描任务缓存失败: {ex.Message}");
                    _scanTasksCache = new List<ScanTask>();
                    _isScanTasksCached = true;
                }
            }
        }
        
        /// <summary>
        /// 加载扫描结果缓存
        /// </summary>
        private void LoadScanResultsCache()
        {
            if (!_isScanResultsCached)
            {
                try
                {
                    if (File.Exists(_scanResultsFile))
                    {
                        var json = File.ReadAllText(_scanResultsFile);
                        _scanResultsCache = JsonSerializer.Deserialize<List<ScanResult>>(json, _jsonOptions) ?? new List<ScanResult>();
                    }
                    _isScanResultsCached = true;
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"加载扫描结果缓存失败: {ex.Message}");
                    _scanResultsCache = new List<ScanResult>();
                    _isScanResultsCached = true;
                }
            }
        }
        
        /// <summary>
        /// 加载漏洞缓存
        /// </summary>
        private void LoadVulnerabilitiesCache()
        {
            if (!_isVulnerabilitiesCached)
            {
                try
                {
                    if (File.Exists(_vulnerabilitiesFile))
                    {
                        var json = File.ReadAllText(_vulnerabilitiesFile);
                        _vulnerabilitiesCache = JsonSerializer.Deserialize<List<Vulnerability>>(json, _jsonOptions) ?? new List<Vulnerability>();
                    }
                    _isVulnerabilitiesCached = true;
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"加载漏洞缓存失败: {ex.Message}");
                    _vulnerabilitiesCache = new List<Vulnerability>();
                    _isVulnerabilitiesCached = true;
                }
            }
        }
        
        /// <summary>
        /// 加载统计缓存
        /// </summary>
        private void LoadStatisticsCache()
        {
            if (!_isStatisticsCached)
            {
                try
                {
                    if (File.Exists(_statisticsFile))
                    {
                        var json = File.ReadAllText(_statisticsFile);
                        _statisticsCache = JsonSerializer.Deserialize<Dictionary<string, object>>(json, _jsonOptions) ?? new Dictionary<string, object>();
                    }
                    _isStatisticsCached = true;
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"加载统计缓存失败: {ex.Message}");
                    _statisticsCache = new Dictionary<string, object>();
                    _isStatisticsCached = true;
                }
            }
        }
        
        // 文件锁定对象
        private readonly object _fileLock = new object();
        
        // ==================== 文件保存操作 ====================
        
        /// <summary>
        /// 保存扫描任务到文件
        /// </summary>
        private async Task SaveScanTasksAsync()
        {
            await SaveFileAsync(_scanTasksFile, _scanTasksCache);
        }
        
        /// <summary>
        /// 同步保存扫描任务到文件
        /// </summary>
        private void SaveScanTasks()
        {
            SaveFile(_scanTasksFile, _scanTasksCache);
        }
        
        /// <summary>
        /// 保存扫描结果到文件
        /// </summary>
        private async Task SaveScanResultsAsync()
        {
            await SaveFileAsync(_scanResultsFile, _scanResultsCache);
        }
        
        /// <summary>
        /// 同步保存扫描结果到文件
        /// </summary>
        private void SaveScanResults()
        {
            SaveFile(_scanResultsFile, _scanResultsCache);
        }
        
        /// <summary>
        /// 保存漏洞到文件
        /// </summary>
        private async Task SaveVulnerabilitiesAsync()
        {
            await SaveFileAsync(_vulnerabilitiesFile, _vulnerabilitiesCache);
        }
        
        /// <summary>
        /// 同步保存漏洞到文件
        /// </summary>
        private void SaveVulnerabilities()
        {
            SaveFile(_vulnerabilitiesFile, _vulnerabilitiesCache);
        }
        
        /// <summary>
        /// 保存统计到文件
        /// </summary>
        private async Task SaveStatisticsAsync()
        {
            await SaveFileAsync(_statisticsFile, _statisticsCache);
        }
        
        /// <summary>
        /// 同步保存统计到文件
        /// </summary>
        private void SaveStatistics()
        {
            SaveFile(_statisticsFile, _statisticsCache);
        }
        
        /// <summary>
        /// 异步保存文件
        /// </summary>
        private async Task SaveFileAsync<T>(string filePath, T data)
        {
            try
            {
                lock (_fileLock)
                {
                    var json = JsonSerializer.Serialize(data, _jsonOptions);
                    // 使用异步文件写入
                    File.WriteAllTextAsync(filePath, json).Wait();
                }
                await Task.CompletedTask;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"保存文件 {Path.GetFileName(filePath)} 失败: {ex.Message}");
            }
        }
        
        /// <summary>
        /// 同步保存文件
        /// </summary>
        private void SaveFile<T>(string filePath, T data)
        {
            try
            {
                lock (_fileLock)
                {
                    var json = JsonSerializer.Serialize(data, _jsonOptions);
                    File.WriteAllText(filePath, json);
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"保存文件 {Path.GetFileName(filePath)} 失败: {ex.Message}");
            }
        }
        
        // ==================== 辅助方法 ====================
        
        /// <summary>
        /// 清除所有缓存
        /// </summary>
        public void ClearCache()
        {
            _isScanTasksCached = false;
            _isScanResultsCached = false;
            _isVulnerabilitiesCached = false;
            _isStatisticsCached = false;
        }
        
        /// <summary>
        /// 验证数据完整性
        /// </summary>
        public bool ValidateDataIntegrity()
        {
            try
            {
                // 验证文件存在
                return File.Exists(_scanTasksFile) && 
                       File.Exists(_scanResultsFile) && 
                       File.Exists(_vulnerabilitiesFile) && 
                       File.Exists(_statisticsFile);
            }
            catch
            {
                return false;
            }
        }
        
        /// <summary>
        /// 获取所有扫描结果
        /// </summary>
        public List<ScanResult> GetAllScanResults()
        {
            try
            {
                if (!_isScanResultsCached)
                {
                    var json = File.ReadAllText(_scanResultsFile);
                    _scanResultsCache = JsonSerializer.Deserialize<List<ScanResult>>(json, _jsonOptions) ?? new List<ScanResult>();
                    _isScanResultsCached = true;
                }
                return new List<ScanResult>(_scanResultsCache);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"获取所有扫描结果失败: {ex.Message}");
                return new List<ScanResult>();
            }
        }
        
        /// <summary>
        /// 通过ID获取扫描任务
        /// </summary>
        public ScanTask GetScanTaskById(int taskId)
        {
            try
            {
                if (!_isScanTasksCached)
                {
                    var json = File.ReadAllText(_scanTasksFile);
                    _scanTasksCache = JsonSerializer.Deserialize<List<ScanTask>>(json, _jsonOptions) ?? new List<ScanTask>();
                    _isScanTasksCached = true;
                }
                return _scanTasksCache.FirstOrDefault(t => t.TaskId == taskId);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"获取扫描任务失败: {ex.Message}");
                return null;
            }
        }
        
        /// <summary>
        /// 通过任务ID获取漏洞
        /// </summary>
        public List<Vulnerability> GetVulnerabilitiesByTaskId(int taskId)
        {
            try
            {
                if (!_isVulnerabilitiesCached)
                {
                    var json = File.ReadAllText(_vulnerabilitiesFile);
                    _vulnerabilitiesCache = JsonSerializer.Deserialize<List<Vulnerability>>(json, _jsonOptions) ?? new List<Vulnerability>();
                    _isVulnerabilitiesCached = true;
                }
                return _vulnerabilitiesCache.Where(v => v.TaskId == taskId).ToList();
            }
            catch (Exception ex)
            {
                Console.WriteLine($"获取漏洞失败: {ex.Message}");
                return new List<Vulnerability>();
            }
        }
    }
}