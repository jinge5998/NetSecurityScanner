using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;
using NetSecurityScanner.Models;

namespace NetSecurityScanner.Services
{
    public class JsonDatabaseService
    {
        private readonly string _databasePath;
        private readonly string _historyDirectory;
        private readonly string _fallbackHistoryDirectory;

        public JsonDatabaseService()
        {
            // 设置数据库路径 - 优先使用用户文档目录（权限最稳定）
            string documentsPath = Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments);
            _historyDirectory = Path.Combine(documentsPath, "NetSecurityScanner", "ScanHistory");
            _databasePath = Path.Combine(documentsPath, "NetSecurityScanner", "scan_history.json");
            _fallbackHistoryDirectory = Path.Combine(Environment.CurrentDirectory, "ScanHistory");

            Console.WriteLine($"[JsonDatabaseService] 文档目录路径: {_historyDirectory}");
            Console.WriteLine($"[JsonDatabaseService] 当前工作目录: {Environment.CurrentDirectory}");
            Console.WriteLine($"[JsonDatabaseService] 程序运行目录: {AppDomain.CurrentDomain.BaseDirectory}");
            
            // 尝试创建主目录
            if (!TryCreateDirectory(_historyDirectory))
            {
                Console.WriteLine($"[JsonDatabaseService] 文档目录创建失败，切换到当前工作目录: {_fallbackHistoryDirectory}");
                _historyDirectory = _fallbackHistoryDirectory;
                _databasePath = Path.Combine(_fallbackHistoryDirectory, "scan_history.json");
                
                if (!TryCreateDirectory(_historyDirectory))
                {
                    Console.WriteLine($"[JsonDatabaseService] 当前工作目录也失败，使用临时目录");
                    string tempPath = Path.Combine(Path.GetTempPath(), "NetSecurityScanner", "ScanHistory");
                    _historyDirectory = tempPath;
                    _databasePath = Path.Combine(tempPath, "scan_history.json");
                    Directory.CreateDirectory(_historyDirectory);
                }
            }
            
            Console.WriteLine($"[JsonDatabaseService] 最终使用路径: {_historyDirectory}");
        }
        
        /// <summary>
        /// 尝试创建目录并测试写入权限
        /// </summary>
        private bool TryCreateDirectory(string path)
        {
            try
            {
                Directory.CreateDirectory(path);
                string testFile = Path.Combine(path, ".test_write");
                File.WriteAllText(testFile, "test");
                File.Delete(testFile);
                return true;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[JsonDatabaseService] 目录创建失败 {path}: {ex.Message}");
                return false;
            }
        }

        /// <summary>
        /// 保存完整扫描结果到JSON数据库
        /// </summary>
        /// <param name="scanResult">完整扫描结果</param>
        /// <returns>保存是否成功</returns>
        public async Task<bool> SaveScanResultAsync(CompleteScanResult scanResult)
        {
            try
            {
                // 确保目录存在
                Directory.CreateDirectory(_historyDirectory);
                Directory.CreateDirectory(Path.GetDirectoryName(_databasePath));

                // 保存完整结果到单独的JSON文件，使用重试机制避免文件锁定
                string resultFilePath = Path.Combine(_historyDirectory, $"{scanResult.ScanId}.json");
                string resultJson = JsonSerializer.Serialize(scanResult, new JsonSerializerOptions
                {
                    WriteIndented = true,
                    IncludeFields = true
                });

                await SafeWriteFileAsync(resultFilePath, resultJson);

                // 获取历史记录列表
                List<ScanHistoryItem> historyList = await GetScanHistoryAsync();

                // 添加新的历史记录项
                var historyItem = new ScanHistoryItem
                {
                    ScanId = scanResult.ScanId,
                    TargetIp = scanResult.TargetIp,
                    ScanType = scanResult.ScanType,
                    ScanTime = scanResult.ScanTime,
                    OpenPortsCount = scanResult.OpenPortsCount,
                    VulnerabilitiesCount = scanResult.VulnerabilitiesCount,
                    RiskLevel = scanResult.RiskLevel
                };

                historyList.Add(historyItem);

                // 保存更新后的历史记录列表
                string historyJson = JsonSerializer.Serialize(historyList, new JsonSerializerOptions
                {
                    WriteIndented = true,
                    IncludeFields = true
                });

                await SafeWriteFileAsync(_databasePath, historyJson);

                return true;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"保存扫描结果失败: {ex.Message}");
                // 不抛出异常，让程序继续运行
                return false;
            }
        }

        /// <summary>
        /// 安全地写入文件，包含重试机制和临时文件替换策略
        /// </summary>
        private async Task SafeWriteFileAsync(string filePath, string content)
        {
            int maxRetries = 3;
            int retryDelay = 200; // 毫秒

            for (int attempt = 1; attempt <= maxRetries; attempt++)
            {
                try
                {
                    // 确保目录存在
                    string? dirPath = Path.GetDirectoryName(filePath);
                    if (!string.IsNullOrEmpty(dirPath))
                    {
                        Directory.CreateDirectory(dirPath);
                    }

                    // 使用临时文件写入，然后替换原文件（原子操作）
                    string tempFilePath = filePath + ".tmp";
                    
                    using (var fileStream = new FileStream(
                        tempFilePath, 
                        FileMode.Create, 
                        FileAccess.Write, 
                        FileShare.None, 
                        bufferSize: 4096, 
                        useAsync: true))
                    {
                        byte[] contentBytes = Encoding.UTF8.GetBytes(content);
                        await fileStream.WriteAsync(contentBytes, 0, contentBytes.Length);
                        await fileStream.FlushAsync();
                    }

                    // 删除原文件（如果存在）
                    if (File.Exists(filePath))
                    {
                        try
                        {
                            File.Delete(filePath);
                        }
                        catch (IOException)
                        {
                            // 如果删除失败，等待重试
                            if (attempt < maxRetries)
                            {
                                await Task.Delay(retryDelay * attempt);
                                continue;
                            }
                            throw;
                        }
                    }

                    // 重命名临时文件为正式文件
                    File.Move(tempFilePath, filePath);
                    return;
                }
                catch (IOException) when (attempt < maxRetries)
                {
                    // 文件被锁定，等待后重试
                    await Task.Delay(retryDelay * attempt);
                }
            }

            // 所有重试都失败，使用最简方式写入
            try
            {
                await File.WriteAllTextAsync(filePath, content);
            }
            catch
            {
                // 最后的最后，静默失败
            }
        }

        /// <summary>
        /// 获取扫描历史记录列表
        /// </summary>
        /// <returns>扫描历史记录列表</returns>
        public async Task<List<ScanHistoryItem>> GetScanHistoryAsync()
        {
            return await GetScanHistoryAsync(null, null, null, null, null);
        }
        
        /// <summary>
        /// 根据条件获取扫描历史记录列表
        /// </summary>
        /// <param name="targetIp">目标IP过滤（可选）</param>
        /// <param name="scanType">扫描类型过滤（可选）</param>
        /// <param name="startDate">开始日期过滤（可选）</param>
        /// <param name="endDate">结束日期过滤（可选）</param>
        /// <param name="riskLevel">风险等级过滤（可选）</param>
        /// <returns>过滤后的扫描历史记录列表</returns>
        public async Task<List<ScanHistoryItem>> GetScanHistoryAsync(
            string targetIp = null,
            string scanType = null,
            DateTime? startDate = null,
            DateTime? endDate = null,
            string riskLevel = null)
        {
            try
            {
                if (!File.Exists(_databasePath))
                {
                    return new List<ScanHistoryItem>();
                }

                string json = await File.ReadAllTextAsync(_databasePath);
                List<ScanHistoryItem> historyList = JsonSerializer.Deserialize<List<ScanHistoryItem>>(json) ?? new List<ScanHistoryItem>();
                
                // 应用过滤条件
                var filteredList = historyList.AsEnumerable();
                
                if (!string.IsNullOrEmpty(targetIp))
                {
                    filteredList = filteredList.Where(item => item.TargetIp.Contains(targetIp, StringComparison.OrdinalIgnoreCase));
                }
                
                if (!string.IsNullOrEmpty(scanType))
                {
                    filteredList = filteredList.Where(item => item.ScanType.Contains(scanType, StringComparison.OrdinalIgnoreCase));
                }
                
                if (startDate.HasValue)
                {
                    filteredList = filteredList.Where(item => item.ScanTime >= startDate.Value);
                }
                
                if (endDate.HasValue)
                {
                    filteredList = filteredList.Where(item => item.ScanTime <= endDate.Value);
                }
                
                if (!string.IsNullOrEmpty(riskLevel))
                {
                    filteredList = filteredList.Where(item => item.RiskLevel == riskLevel);
                }
                
                // 按扫描时间降序排序
                return filteredList.OrderByDescending(item => item.ScanTime).ToList();
            }
            catch (Exception ex)
            {
                Console.WriteLine($"获取扫描历史记录失败: {ex.Message}");
                return new List<ScanHistoryItem>();
            }
        }
        
        /// <summary>
        /// 根据条件搜索扫描历史记录
        /// </summary>
        /// <param name="searchTerm">搜索关键词</param>
        /// <returns>匹配的扫描历史记录列表</returns>
        public async Task<List<ScanHistoryItem>> SearchScanHistoryAsync(string searchTerm)
        {
            try
            {
                if (!File.Exists(_databasePath))
                {
                    return new List<ScanHistoryItem>();
                }

                string json = await File.ReadAllTextAsync(_databasePath);
                List<ScanHistoryItem> historyList = JsonSerializer.Deserialize<List<ScanHistoryItem>>(json) ?? new List<ScanHistoryItem>();
                
                if (string.IsNullOrEmpty(searchTerm))
                {
                    return historyList.OrderByDescending(item => item.ScanTime).ToList();
                }
                
                // 在多个字段中搜索
                return historyList
                    .Where(item => 
                        item.TargetIp.Contains(searchTerm, StringComparison.OrdinalIgnoreCase) ||
                        item.ScanType.Contains(searchTerm, StringComparison.OrdinalIgnoreCase) ||
                        item.ScanId.Contains(searchTerm, StringComparison.OrdinalIgnoreCase) ||
                        item.RiskLevel.Contains(searchTerm, StringComparison.OrdinalIgnoreCase))
                    .OrderByDescending(item => item.ScanTime)
                    .ToList();
            }
            catch (Exception ex)
            {
                Console.WriteLine($"搜索扫描历史记录失败: {ex.Message}");
                return new List<ScanHistoryItem>();
            }
        }
        
        /// <summary>
        /// 获取扫描统计信息
        /// </summary>
        /// <returns>扫描统计信息</returns>
        public async Task<ScanStatistics> GetScanStatisticsAsync()
        {
            try
            {
                List<ScanHistoryItem> historyList = await GetScanHistoryAsync();
                
                var stats = new ScanStatistics
                {
                    TotalScans = historyList.Count,
                    HighRiskCount = historyList.Count(item => item.RiskLevel == "高风险" || item.RiskLevel == "严重风险"),
                    MediumRiskCount = historyList.Count(item => item.RiskLevel == "中风险"),
                    LowRiskCount = historyList.Count(item => item.RiskLevel == "低风险"),
                    AverageOpenPorts = historyList.Any() ? (int)Math.Round(historyList.Average(item => item.OpenPortsCount)) : 0,
                    AverageVulnerabilities = historyList.Any() ? (int)Math.Round(historyList.Average(item => item.VulnerabilitiesCount)) : 0,
                    LastScanDate = historyList.Any() ? historyList.Max(item => item.ScanTime) : null,
                    FirstScanDate = historyList.Any() ? historyList.Min(item => item.ScanTime) : null
                };
                
                return stats;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"获取扫描统计信息失败: {ex.Message}");
                return new ScanStatistics();
            }
        }
        
        /// <summary>
        /// 清空所有扫描历史记录
        /// </summary>
        /// <returns>清空是否成功</returns>
        public async Task<bool> ClearAllScanHistoryAsync()
        {
            try
            {
                // 删除所有历史记录文件
                if (Directory.Exists(_historyDirectory))
                {
                    string[] historyFiles = Directory.GetFiles(_historyDirectory, "*.json");
                    foreach (string file in historyFiles)
                    {
                        File.Delete(file);
                    }
                }
                
                // 清空主历史文件
                await File.WriteAllTextAsync(_databasePath, "[]");
                
                return true;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"清空扫描历史记录失败: {ex.Message}");
                return false;
            }
        }

        /// <summary>
        /// 根据扫描ID获取完整扫描结果
        /// </summary>
        /// <param name="scanId">扫描ID</param>
        /// <returns>完整扫描结果</returns>
        public async Task<CompleteScanResult?> GetScanResultByIdAsync(string scanId)
        {
            try
            {
                string resultFilePath = Path.Combine(_historyDirectory, $"{scanId}.json");
                if (!File.Exists(resultFilePath))
                {
                    return null;
                }

                string json = await File.ReadAllTextAsync(resultFilePath);
                return JsonSerializer.Deserialize<CompleteScanResult>(json);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"获取扫描结果失败: {ex.Message}");
                return null;
            }
        }

        public async Task<bool> SaveScanHistoryAsync(ScanHistoryItem item)
        {
            try
            {
                List<ScanHistoryItem> historyList = await GetScanHistoryAsync();
                historyList.Insert(0, item);
                
                string historyJson = JsonSerializer.Serialize(historyList, new JsonSerializerOptions
                {
                    WriteIndented = true,
                    IncludeFields = true
                });

                await File.WriteAllTextAsync(_databasePath, historyJson);
                return true;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"保存扫描历史失败: {ex.Message}");
                return false;
            }
        }

        public async Task<bool> UpdateScanHistoryAsync(string scanId, ScanHistoryItem updatedItem)
        {
            try
            {
                List<ScanHistoryItem> historyList = await GetScanHistoryAsync();
                var existingItem = historyList.FirstOrDefault(h => h.ScanId == scanId);
                if (existingItem != null)
                {
                    var index = historyList.IndexOf(existingItem);
                    historyList[index] = updatedItem;
                }
                else
                {
                    historyList.Insert(0, updatedItem);
                }

                string historyJson = JsonSerializer.Serialize(historyList, new JsonSerializerOptions
                {
                    WriteIndented = true,
                    IncludeFields = true
                });

                await File.WriteAllTextAsync(_databasePath, historyJson);
                return true;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"更新扫描历史失败: {ex.Message}");
                return false;
            }
        }

        /// <summary>
        /// 删除指定扫描记录
        /// </summary>
        /// <param name="scanId">扫描ID</param>
        /// <returns>删除是否成功</returns>
        public async Task<bool> DeleteScanResultAsync(string scanId)
        {
            try
            {
                // 删除完整结果文件
                string resultFilePath = Path.Combine(_historyDirectory, $"{scanId}.json");
                if (File.Exists(resultFilePath))
                {
                    File.Delete(resultFilePath);
                }

                // 更新历史记录列表
                List<ScanHistoryItem> historyList = await GetScanHistoryAsync();
                historyList.RemoveAll(item => item.ScanId == scanId);

                string historyJson = JsonSerializer.Serialize(historyList, new JsonSerializerOptions
                {
                    WriteIndented = true,
                    IncludeFields = true
                });

                await File.WriteAllTextAsync(_databasePath, historyJson);

                return true;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"删除扫描结果失败: {ex.Message}");
                return false;
            }
        }

        /// <summary>
        /// 获取完整扫描结果的文件路径
        /// </summary>
        /// <param name="scanId">扫描ID</param>
        /// <returns>文件路径</returns>
        public string GetScanResultFilePath(string scanId)
        {
            return Path.Combine(_historyDirectory, $"{scanId}.json");
        }
        
        /// <summary>
        /// 保存报告到文件（支持文本和二进制格式）
        /// </summary>
        /// <param name="reportContent">报告内容（文本格式）</param>
        /// <param name="extension">文件扩展名</param>
        /// <returns>保存的文件路径</returns>
        public string SaveReportToFile(string reportContent, string extension = ".txt")
        {
            try
            {
                // 参数验证
                if (string.IsNullOrEmpty(reportContent))
                {
                    throw new ArgumentException("报告内容不能为空", nameof(reportContent));
                }
                
                // 确保扩展名格式正确
                if (string.IsNullOrEmpty(extension))
                {
                    extension = ".txt";
                }
                else if (!extension.StartsWith("."))
                {
                    extension = "." + extension.TrimStart('.');
                }
                
                string fileName = $"SecurityScanReport_{DateTime.Now:yyyyMMdd_HHmmss}{extension}";
                
                // 尝试多个路径：当前工作目录 -> 文档 -> 桌面 -> 临时目录
                string[] savePaths = new[]
                {
                    Path.Combine(Environment.CurrentDirectory, "Reports"),
                    Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments), "NetSecurityScanner", "Reports"),
                    Environment.GetFolderPath(Environment.SpecialFolder.Desktop),
                    Path.Combine(Path.GetTempPath(), "NetSecurityScanner", "Reports")
                };
                
                foreach (var basePath in savePaths)
                {
                    if (string.IsNullOrEmpty(basePath)) continue;
                    
                    try
                    {
                        string filePath = Path.Combine(basePath, fileName);
                        string directoryPath = Path.GetDirectoryName(filePath);
                        
                        if (!Directory.Exists(directoryPath))
                        {
                            Directory.CreateDirectory(directoryPath);
                        }
                        
                        // 测试写入权限
                        string testFile = Path.Combine(directoryPath, ".test_write");
                        File.WriteAllText(testFile, "test");
                        File.Delete(testFile);
                        
                        // 有权限，正式写入
                        File.WriteAllText(filePath, reportContent, Encoding.UTF8);
                        Console.WriteLine($"[SaveReport] 报告已保存到: {filePath}");
                        return filePath;
                    }
                    catch (Exception ex)
                    {
                        Console.WriteLine($"[SaveReport] 路径 {basePath} 保存失败: {ex.Message}");
                        continue;
                    }
                }
                
                // 所有路径都失败
                throw new Exception("所有保存路径都不可用，请检查文件夹权限");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[SaveReport] 保存报告失败: {ex.Message}");
                throw;
            }
        }
        
        /// <summary>
        /// 保存二进制报告到文件（用于Word和PDF格式）
        /// </summary>
        /// <param name="reportData">报告二进制数据</param>
        /// <param name="extension">文件扩展名</param>
        /// <returns>保存的文件路径</returns>
        public string SaveBinaryReportToFile(byte[] reportData, string extension)
        {
            try
            {
                // 参数验证
                if (reportData == null || reportData.Length == 0)
                {
                    throw new ArgumentException("报告数据不能为空", nameof(reportData));
                }
                
                // 确保扩展名格式正确
                if (string.IsNullOrEmpty(extension))
                {
                    throw new ArgumentException("文件扩展名不能为空", nameof(extension));
                }
                else if (!extension.StartsWith("."))
                {
                    extension = "." + extension.TrimStart('.');
                }
                
                string fileName = $"SecurityScanReport_{DateTime.Now:yyyyMMdd_HHmmss}{extension}";
                
                // 尝试多个路径：当前工作目录 -> 文档 -> 桌面 -> 临时目录
                string[] savePaths = new[]
                {
                    Path.Combine(Environment.CurrentDirectory, "Reports"),
                    Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments), "NetSecurityScanner", "Reports"),
                    Environment.GetFolderPath(Environment.SpecialFolder.Desktop),
                    Path.Combine(Path.GetTempPath(), "NetSecurityScanner", "Reports")
                };
                
                foreach (var basePath in savePaths)
                {
                    if (string.IsNullOrEmpty(basePath)) continue;
                    
                    try
                    {
                        string filePath = Path.Combine(basePath, fileName);
                        string directoryPath = Path.GetDirectoryName(filePath);
                        
                        if (!Directory.Exists(directoryPath))
                        {
                            Directory.CreateDirectory(directoryPath);
                        }
                        
                        // 测试写入权限
                        string testFile = Path.Combine(directoryPath, ".test_write");
                        File.WriteAllText(testFile, "test");
                        File.Delete(testFile);
                        
                        // 有权限，正式写入
                        File.WriteAllBytes(filePath, reportData);
                        Console.WriteLine($"[SaveBinaryReport] 报告已保存到: {filePath}");
                        return filePath;
                    }
                    catch (Exception ex)
                    {
                        Console.WriteLine($"[SaveBinaryReport] 路径 {basePath} 保存失败: {ex.Message}");
                        continue;
                    }
                }
                
                // 所有路径都失败
                throw new Exception("所有保存路径都不可用，请检查文件夹权限");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[SaveBinaryReport] 保存二进制报告失败: {ex.Message}");
                throw;
            }
        }
    }

    /// <summary>
    /// 扫描历史记录项
    /// </summary>
    public class ScanHistoryItem
    {
        public string ScanId { get; set; } = Guid.NewGuid().ToString();
        public string TargetIp { get; set; } = string.Empty;
        public string ScanType { get; set; } = string.Empty;
        public DateTime ScanTime { get; set; } = DateTime.Now;
        public int OpenPortsCount { get; set; }
        public int VulnerabilitiesCount { get; set; }
        public string RiskLevel { get; set; } = string.Empty;
        public bool IsSelected { get; set; } = false;
        public List<PortScanResult> PortScanResults { get; set; } = new();
        public List<VulnerabilityResult> VulnerabilityResults { get; set; } = new();
        public double Duration { get; set; }
    }
    
    /// <summary>
    /// 扫描统计信息
    /// </summary>
    public class ScanStatistics
    {
        /// <summary>
        /// 总扫描次数
        /// </summary>
        public int TotalScans { get; set; }
        
        /// <summary>
        /// 高风险扫描次数
        /// </summary>
        public int HighRiskCount { get; set; }
        
        /// <summary>
        /// 中风险扫描次数
        /// </summary>
        public int MediumRiskCount { get; set; }
        
        /// <summary>
        /// 低风险扫描次数
        /// </summary>
        public int LowRiskCount { get; set; }
        
        /// <summary>
        /// 平均开放端口数
        /// </summary>
        public int AverageOpenPorts { get; set; }
        
        /// <summary>
        /// 平均漏洞数
        /// </summary>
        public int AverageVulnerabilities { get; set; }
        
        /// <summary>
        /// 最后一次扫描日期
        /// </summary>
        public DateTime? LastScanDate { get; set; }
        
        /// <summary>
        /// 第一次扫描日期
        /// </summary>
        public DateTime? FirstScanDate { get; set; }
    }
}