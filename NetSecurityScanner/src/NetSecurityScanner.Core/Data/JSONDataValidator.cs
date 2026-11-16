using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.Json;
using System.Threading.Tasks;
using NetSecurityScanner.Models;
using NetSecurityScanner.Core;

namespace NetSecurityScanner.Data
{
    /// <summary>
    /// JSON数据验证器 - 提供数据验证和错误恢复功能
    /// </summary>
    public class JSONDataValidator
    {
        private readonly string _dataDirectory;
        private readonly string _backupDirectory;
        private readonly Logger _logger;
        
        public JSONDataValidator()
        {
            _dataDirectory = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "data");
            _backupDirectory = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "data", "backup");
            _logger = new Logger();
            
            Directory.CreateDirectory(_backupDirectory);
        }
        
        /// <summary>
        /// 验证所有JSON数据文件
        /// </summary>
        public async Task<ValidationResult> ValidateAllDataAsync()
        {
            var result = new ValidationResult();
            
            try
            {
                _logger.Info("开始验证所有JSON数据文件");
                
                // 验证扫描任务文件
                var tasksResult = await ValidateScanTasksFileAsync();
                result.Merge(tasksResult);
                
                // 验证扫描结果文件
                var resultsResult = await ValidateScanResultsFileAsync();
                result.Merge(resultsResult);
                
                // 验证漏洞文件
                var vulnResult = await ValidateVulnerabilitiesFileAsync();
                result.Merge(vulnResult);
                
                // 验证统计文件
                var statsResult = await ValidateStatisticsFileAsync();
                result.Merge(statsResult);
                
                _logger.Info($"数据验证完成: {result.ValidFiles} 个有效文件, {result.CorruptedFiles} 个损坏文件, {result.RepairedFiles} 个已修复");
                
                return result;
            }
            catch (Exception ex)
            {
                _logger.Error($"验证数据时发生错误: {ex.Message}");
                result.AddError($"验证过程失败: {ex.Message}");
                return result;
            }
        }
        
        /// <summary>
        /// 验证扫描任务文件
        /// </summary>
        private async Task<ValidationResult> ValidateScanTasksFileAsync()
        {
            var result = new ValidationResult();
            var filePath = Path.Combine(_dataDirectory, "scantasks.json");
            
            try
            {
                if (!File.Exists(filePath))
                {
                    result.AddError("扫描任务文件不存在");
                    return result;
                }
                
                var json = await File.ReadAllTextAsync(filePath);
                var tasks = JsonSerializer.Deserialize<List<ScanTask>>(json);
                
                if (tasks == null)
                {
                    result.AddCorruptedFile(filePath);
                    // 尝试修复
                    if (await TryRepairScanTasksFileAsync(filePath))
                    {
                        result.AddRepairedFile(filePath);
                    }
                }
                else
                {
                    // 验证每个任务的数据完整性
                    int invalidCount = 0;
                    foreach (var task in tasks)
                    {
                        if (!IsValidScanTask(task))
                        {
                            invalidCount++;
                        }
                    }
                    
                    if (invalidCount > 0)
                    {
                        result.AddWarning($"扫描任务文件中有 {invalidCount} 个无效任务");
                    }
                    
                    result.AddValidFile(filePath);
                }
            }
            catch (JsonException ex)
            {
                result.AddCorruptedFile(filePath);
                _logger.Error($"扫描任务文件JSON格式错误: {ex.Message}");
                
                if (await TryRepairScanTasksFileAsync(filePath))
                {
                    result.AddRepairedFile(filePath);
                }
            }
            catch (Exception ex)
            {
                result.AddError($"验证扫描任务文件失败: {ex.Message}");
            }
            
            return result;
        }
        
        /// <summary>
        /// 验证扫描结果文件
        /// </summary>
        private async Task<ValidationResult> ValidateScanResultsFileAsync()
        {
            var result = new ValidationResult();
            var filePath = Path.Combine(_dataDirectory, "scanresults.json");
            
            try
            {
                if (!File.Exists(filePath))
                {
                    result.AddError("扫描结果文件不存在");
                    return result;
                }
                
                var json = await File.ReadAllTextAsync(filePath);
                var results = JsonSerializer.Deserialize<List<ScanResult>>(json);
                
                if (results == null)
                {
                    result.AddCorruptedFile(filePath);
                    if (await TryRepairScanResultsFileAsync(filePath))
                    {
                        result.AddRepairedFile(filePath);
                    }
                }
                else
                {
                    result.AddValidFile(filePath);
                }
            }
            catch (JsonException ex)
            {
                result.AddCorruptedFile(filePath);
                _logger.Error($"扫描结果文件JSON格式错误: {ex.Message}");
                
                if (await TryRepairScanResultsFileAsync(filePath))
                {
                    result.AddRepairedFile(filePath);
                }
            }
            catch (Exception ex)
            {
                result.AddError($"验证扫描结果文件失败: {ex.Message}");
            }
            
            return result;
        }
        
        /// <summary>
        /// 验证漏洞文件
        /// </summary>
        private async Task<ValidationResult> ValidateVulnerabilitiesFileAsync()
        {
            var result = new ValidationResult();
            var filePath = Path.Combine(_dataDirectory, "vulnerabilities.json");
            
            try
            {
                if (!File.Exists(filePath))
                {
                    result.AddError("漏洞文件不存在");
                    return result;
                }
                
                var json = await File.ReadAllTextAsync(filePath);
                var vulnerabilities = JsonSerializer.Deserialize<List<Vulnerability>>(json);
                
                if (vulnerabilities == null)
                {
                    result.AddCorruptedFile(filePath);
                    if (await TryRepairVulnerabilitiesFileAsync(filePath))
                    {
                        result.AddRepairedFile(filePath);
                    }
                }
                else
                {
                    result.AddValidFile(filePath);
                }
            }
            catch (JsonException ex)
            {
                result.AddCorruptedFile(filePath);
                _logger.Error($"漏洞文件JSON格式错误: {ex.Message}");
                
                if (await TryRepairVulnerabilitiesFileAsync(filePath))
                {
                    result.AddRepairedFile(filePath);
                }
            }
            catch (Exception ex)
            {
                result.AddError($"验证漏洞文件失败: {ex.Message}");
            }
            
            return result;
        }
        
        /// <summary>
        /// 验证统计文件
        /// </summary>
        private async Task<ValidationResult> ValidateStatisticsFileAsync()
        {
            var result = new ValidationResult();
            var filePath = Path.Combine(_dataDirectory, "statistics.json");
            
            try
            {
                if (!File.Exists(filePath))
                {
                    // 统计文件不存在不是严重错误，可以重新生成
                    result.AddWarning("统计文件不存在，将重新生成");
                    return result;
                }
                
                var json = await File.ReadAllTextAsync(filePath);
                var statistics = JsonSerializer.Deserialize<ScanStatistics>(json);
                
                if (statistics == null)
                {
                    result.AddCorruptedFile(filePath);
                    if (await TryRepairStatisticsFileAsync(filePath))
                    {
                        result.AddRepairedFile(filePath);
                    }
                }
                else
                {
                    result.AddValidFile(filePath);
                }
            }
            catch (JsonException ex)
            {
                result.AddCorruptedFile(filePath);
                _logger.Error($"统计文件JSON格式错误: {ex.Message}");
                
                if (await TryRepairStatisticsFileAsync(filePath))
                {
                    result.AddRepairedFile(filePath);
                }
            }
            catch (Exception ex)
            {
                result.AddError($"验证统计文件失败: {ex.Message}");
            }
            
            return result;
        }
        
        /// <summary>
        /// 尝试修复扫描任务文件
        /// </summary>
        private async Task<bool> TryRepairScanTasksFileAsync(string filePath)
        {
            try
            {
                _logger.Info($"尝试修复扫描任务文件: {filePath}");
                
                // 创建备份
                var backupPath = CreateBackup(filePath);
                
                // 尝试读取并修复
                var json = await File.ReadAllTextAsync(filePath);
                var repairedJson = TryRepairJson(json);
                
                if (!string.IsNullOrEmpty(repairedJson))
                {
                    // 验证修复后的JSON
                    var tasks = JsonSerializer.Deserialize<List<ScanTask>>(repairedJson);
                    if (tasks != null)
                    {
                        await File.WriteAllTextAsync(filePath, repairedJson);
                        _logger.Info($"扫描任务文件修复成功");
                        return true;
                    }
                }
                
                // 如果修复失败，创建新的空文件
                var emptyTasks = new List<ScanTask>();
                var emptyJson = JsonSerializer.Serialize(emptyTasks, new JsonSerializerOptions { WriteIndented = true });
                await File.WriteAllTextAsync(filePath, emptyJson);
                
                _logger.Warning($"扫描任务文件无法修复，已创建新的空文件");
                return true;
            }
            catch (Exception ex)
            {
                _logger.Error($"修复扫描任务文件失败: {ex.Message}");
                return false;
            }
        }
        
        /// <summary>
        /// 尝试修复扫描结果文件
        /// </summary>
        private async Task<bool> TryRepairScanResultsFileAsync(string filePath)
        {
            try
            {
                _logger.Info($"尝试修复扫描结果文件: {filePath}");
                
                var backupPath = CreateBackup(filePath);
                var json = await File.ReadAllTextAsync(filePath);
                var repairedJson = TryRepairJson(json);
                
                if (!string.IsNullOrEmpty(repairedJson))
                {
                    var results = JsonSerializer.Deserialize<List<ScanResult>>(repairedJson);
                    if (results != null)
                    {
                        await File.WriteAllTextAsync(filePath, repairedJson);
                        _logger.Info($"扫描结果文件修复成功");
                        return true;
                    }
                }
                
                var emptyResults = new List<ScanResult>();
                var emptyJson = JsonSerializer.Serialize(emptyResults, new JsonSerializerOptions { WriteIndented = true });
                await File.WriteAllTextAsync(filePath, emptyJson);
                
                _logger.Warning($"扫描结果文件无法修复，已创建新的空文件");
                return true;
            }
            catch (Exception ex)
            {
                _logger.Error($"修复扫描结果文件失败: {ex.Message}");
                return false;
            }
        }
        
        /// <summary>
        /// 尝试修复漏洞文件
        /// </summary>
        private async Task<bool> TryRepairVulnerabilitiesFileAsync(string filePath)
        {
            try
            {
                _logger.Info($"尝试修复漏洞文件: {filePath}");
                
                var backupPath = CreateBackup(filePath);
                var json = await File.ReadAllTextAsync(filePath);
                var repairedJson = TryRepairJson(json);
                
                if (!string.IsNullOrEmpty(repairedJson))
                {
                    var vulnerabilities = JsonSerializer.Deserialize<List<Vulnerability>>(repairedJson);
                    if (vulnerabilities != null)
                    {
                        await File.WriteAllTextAsync(filePath, repairedJson);
                        _logger.Info($"漏洞文件修复成功");
                        return true;
                    }
                }
                
                var emptyVulns = new List<Vulnerability>();
                var emptyJson = JsonSerializer.Serialize(emptyVulns, new JsonSerializerOptions { WriteIndented = true });
                await File.WriteAllTextAsync(filePath, emptyJson);
                
                _logger.Warning($"漏洞文件无法修复，已创建新的空文件");
                return true;
            }
            catch (Exception ex)
            {
                _logger.Error($"修复漏洞文件失败: {ex.Message}");
                return false;
            }
        }
        
        /// <summary>
        /// 尝试修复统计文件
        /// </summary>
        private async Task<bool> TryRepairStatisticsFileAsync(string filePath)
        {
            try
            {
                _logger.Info($"尝试修复统计文件: {filePath}");
                
                var backupPath = CreateBackup(filePath);
                var json = await File.ReadAllTextAsync(filePath);
                var repairedJson = TryRepairJson(json);
                
                if (!string.IsNullOrEmpty(repairedJson))
                {
                    var stats = JsonSerializer.Deserialize<ScanStatistics>(repairedJson);
                    if (stats != null)
                    {
                        await File.WriteAllTextAsync(filePath, repairedJson);
                        _logger.Info($"统计文件修复成功");
                        return true;
                    }
                }
                
                // 创建默认统计
                var defaultStats = new Dictionary<string, object>
                {
                    ["totalScans"] = 0,
                    ["totalVulnerabilities"] = 0,
                    ["lastUpdated"] = DateTime.Now
                };
                var defaultJson = JsonSerializer.Serialize(defaultStats, new JsonSerializerOptions { WriteIndented = true });
                await File.WriteAllTextAsync(filePath, defaultJson);
                
                _logger.Warning($"统计文件无法修复，已创建默认统计");
                return true;
            }
            catch (Exception ex)
            {
                _logger.Error($"修复统计文件失败: {ex.Message}");
                return false;
            }
        }
        
        /// <summary>
        /// 尝试修复JSON字符串
        /// </summary>
        private string TryRepairJson(string json)
        {
            try
            {
                // 移除BOM字符
                json = json.TrimStart('\uFEFF');
                
                // 尝试找到有效的JSON部分
                int startIndex = json.IndexOf('[');
                int endIndex = json.LastIndexOf(']');
                
                if (startIndex >= 0 && endIndex > startIndex)
                {
                    var possibleJson = json.Substring(startIndex, endIndex - startIndex + 1);
                    
                    // 验证修复后的JSON
                    try
                    {
                        JsonDocument.Parse(possibleJson);
                        return possibleJson;
                    }
                    catch
                    {
                        // 解析失败，返回空
                    }
                }
                
                // 尝试对象格式
                startIndex = json.IndexOf('{');
                endIndex = json.LastIndexOf('}');
                
                if (startIndex >= 0 && endIndex > startIndex)
                {
                    var possibleJson = json.Substring(startIndex, endIndex - startIndex + 1);
                    
                    try
                    {
                        JsonDocument.Parse(possibleJson);
                        return possibleJson;
                    }
                    catch
                    {
                        // 解析失败
                    }
                }
                
                return null;
            }
            catch
            {
                return null;
            }
        }
        
        /// <summary>
        /// 创建备份
        /// </summary>
        private string CreateBackup(string filePath)
        {
            try
            {
                var fileName = Path.GetFileName(filePath);
                var backupName = $"{fileName}.{DateTime.Now:yyyyMMddHHmmss}.bak";
                var backupPath = Path.Combine(_backupDirectory, backupName);
                
                File.Copy(filePath, backupPath, true);
                _logger.Info($"已创建备份: {backupPath}");
                
                return backupPath;
            }
            catch (Exception ex)
            {
                _logger.Error($"创建备份失败: {ex.Message}");
                return null;
            }
        }
        
        /// <summary>
        /// 验证扫描任务数据完整性
        /// </summary>
        private bool IsValidScanTask(ScanTask task)
        {
            if (task == null) return false;
            if (task.TaskId <= 0) return false;
            if (string.IsNullOrWhiteSpace(task.TaskName)) return false;
            if (string.IsNullOrWhiteSpace(task.TargetHosts)) return false;
            
            return true;
        }
        
        /// <summary>
        /// 从备份恢复数据
        /// </summary>
        public async Task<bool> RestoreFromBackupAsync(string backupFileName)
        {
            try
            {
                var backupPath = Path.Combine(_backupDirectory, backupFileName);
                if (!File.Exists(backupPath))
                {
                    _logger.Error($"备份文件不存在: {backupPath}");
                    return false;
                }
                
                // 确定目标文件
                string targetFileName;
                if (backupFileName.StartsWith("scantasks"))
                    targetFileName = "scantasks.json";
                else if (backupFileName.StartsWith("scanresults"))
                    targetFileName = "scanresults.json";
                else if (backupFileName.StartsWith("vulnerabilities"))
                    targetFileName = "vulnerabilities.json";
                else if (backupFileName.StartsWith("statistics"))
                    targetFileName = "statistics.json";
                else
                {
                    _logger.Error($"无法识别备份文件类型: {backupFileName}");
                    return false;
                }
                
                var targetPath = Path.Combine(_dataDirectory, targetFileName);
                
                // 备份当前文件
                if (File.Exists(targetPath))
                {
                    CreateBackup(targetPath);
                }
                
                // 恢复备份
                File.Copy(backupPath, targetPath, true);
                
                _logger.Info($"已从备份恢复: {targetFileName}");
                return true;
            }
            catch (Exception ex)
            {
                _logger.Error($"从备份恢复失败: {ex.Message}");
                return false;
            }
        }
        
        /// <summary>
        /// 获取可用备份列表
        /// </summary>
        public List<BackupInfo> GetAvailableBackups()
        {
            try
            {
                var backups = new List<BackupInfo>();
                
                if (!Directory.Exists(_backupDirectory))
                {
                    return backups;
                }
                
                var files = Directory.GetFiles(_backupDirectory, "*.bak");
                foreach (var file in files)
                {
                    var fileInfo = new FileInfo(file);
                    backups.Add(new BackupInfo
                    {
                        FileName = Path.GetFileName(file),
                        FilePath = file,
                        CreatedTime = fileInfo.CreationTime,
                        FileSize = fileInfo.Length
                    });
                }
                
                return backups.OrderByDescending(b => b.CreatedTime).ToList();
            }
            catch (Exception ex)
            {
                _logger.Error($"获取备份列表失败: {ex.Message}");
                return new List<BackupInfo>();
            }
        }
    }
    
    /// <summary>
    /// 验证结果
    /// </summary>
    public class ValidationResult
    {
        public int ValidFiles { get; private set; }
        public int CorruptedFiles { get; private set; }
        public int RepairedFiles { get; private set; }
        public List<string> Errors { get; private set; } = new List<string>();
        public List<string> Warnings { get; private set; } = new List<string>();
        
        public void AddValidFile(string filePath)
        {
            ValidFiles++;
        }
        
        public void AddCorruptedFile(string filePath)
        {
            CorruptedFiles++;
        }
        
        public void AddRepairedFile(string filePath)
        {
            RepairedFiles++;
        }
        
        public void AddError(string error)
        {
            Errors.Add(error);
        }
        
        public void AddWarning(string warning)
        {
            Warnings.Add(warning);
        }
        
        public void Merge(ValidationResult other)
        {
            ValidFiles += other.ValidFiles;
            CorruptedFiles += other.CorruptedFiles;
            RepairedFiles += other.RepairedFiles;
            Errors.AddRange(other.Errors);
            Warnings.AddRange(other.Warnings);
        }
        
        public bool IsValid => CorruptedFiles == 0 && Errors.Count == 0;
    }
    
    /// <summary>
    /// 备份信息
    /// </summary>
    public class BackupInfo
    {
        public string FileName { get; set; }
        public string FilePath { get; set; }
        public DateTime CreatedTime { get; set; }
        public long FileSize { get; set; }
        
        public string FormattedSize
        {
            get
            {
                if (FileSize < 1024)
                    return $"{FileSize} B";
                if (FileSize < 1024 * 1024)
                    return $"{FileSize / 1024.0:F2} KB";
                return $"{FileSize / (1024.0 * 1024):F2} MB";
            }
        }
    }
}
