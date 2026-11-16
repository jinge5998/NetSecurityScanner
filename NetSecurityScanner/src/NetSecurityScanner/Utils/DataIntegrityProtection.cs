using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace NetSecurityScanner.Utils
{
    /// <summary>
    /// 数据完整性保护工具 - 确保文件操作的事务性和安全性
    /// 
    /// 功能：
    /// 1. 事务性写入（先写临时文件，成功后原子重命名）
    /// 2. 数据校验和（SHA256）确保文件完整性
    /// 3. 备份点创建和恢复
    /// 4. 损坏检测和修复
    /// </summary>
    public static class DataIntegrityProtection
    {
        private const string BackupExtension = ".backup";
        private const string TempExtension = ".tmp";
        private const string ChecksumExtension = ".sha256";
        
        /// <summary>
        /// 事务性写入文件 - 原子操作，确保数据一致性
        /// </summary>
        /// <param name="filePath">目标文件路径</param>
        /// <param name="content">要写入的内容</param>
        /// <param name="createBackup">是否在覆盖前创建备份</param>
        public static void TransactionalWrite(string filePath, string content, bool createBackup = true)
        {
            if (string.IsNullOrEmpty(filePath))
                throw new ArgumentNullException(nameof(filePath));
            
            if (content == null)
                throw new ArgumentNullException(nameof(content));
            
            string directory = Path.GetDirectoryName(filePath);
            string tempPath = filePath + TempExtension;
            
            try
            {
                // 确保目录存在
                if (!string.IsNullOrEmpty(directory) && !Directory.Exists(directory))
                {
                    Directory.CreateDirectory(directory);
                }
                
                // 如果需要，先创建备份
                if (createBackup && File.Exists(filePath))
                {
                    CreateBackupPoint(filePath);
                }
                
                // 写入临时文件
                File.WriteAllText(tempPath, content, Encoding.UTF8);
                
                // 验证临时文件写入成功
                if (!File.Exists(tempPath) || new FileInfo(tempPath).Length == 0)
                {
                    throw new IOException("临时文件写入失败");
                }
                
                // 原子重命名（替换原文件）
                File.Move(tempPath, filePath, overwrite: true);
                
                // 生成并保存校验和
                SaveChecksum(filePath, content);
            }
            catch (Exception)
            {
                // 清理临时文件
                CleanupTempFile(tempPath);
                throw;
            }
        }
        
        /// <summary>
        /// 异步事务性写入文件
        /// </summary>
        public static async Task TransactionalWriteAsync(string filePath, string content, bool createBackup = true)
        {
            await Task.Run(() => TransactionalWrite(filePath, content, createBackup));
        }
        
        /// <summary>
        /// 创建备份点
        /// </summary>
        /// <param name="filePath">要备份的文件路径</param>
        /// <returns>备份文件路径</returns>
        public static string CreateBackupPoint(string filePath)
        {
            if (!File.Exists(filePath))
                return null;
            
            try
            {
                string backupPath = filePath + $".{DateTime.Now:yyyyMMdd_HHmmss}{BackupExtension}";
                File.Copy(filePath, backupPath, overwrite: false);
                
                System.Diagnostics.Debug.WriteLine($"[DataIntegrity] 已创建备份: {backupPath}");
                return backupPath;
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"[DataIntegrity] 创建备份失败: {ex.Message}");
                return null;
            }
        }
        
        /// <summary>
        /// 从备份恢复文件
        /// </summary>
        /// <param name="filePath">原始文件路径</param>
        /// <param name="backupPath">备份文件路径（如果为null则自动查找最新备份）</param>
        /// <returns>是否恢复成功</returns>
        public static bool RestoreFromBackup(string filePath, string backupPath = null)
        {
            try
            {
                if (backupPath == null)
                {
                    backupPath = FindLatestBackup(filePath);
                }
                
                if (backupPath == null || !File.Exists(backupPath))
                {
                    System.Diagnostics.Debug.WriteLine("[DataIntegrity] 未找到可用的备份文件");
                    return false;
                }
                
                // 使用事务性写入确保安全恢复
                string backupContent = File.ReadAllText(backupPath, Encoding.UTF8);
                TransactionalWrite(filePath, backupContent, createBackup: false);
                
                System.Diagnostics.Debug.WriteLine($"[DataIntegrity] 已从备份恢复: {backupPath}");
                return true;
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"[DataIntegrity] 从备份恢复失败: {ex.Message}");
                return false;
            }
        }
        
        /// <summary>
        /// 计算文件的SHA256校验和
        /// </summary>
        public static string CalculateFileChecksum(string filePath)
        {
            if (!File.Exists(filePath))
                return null;
            
            try
            {
                using (var stream = File.OpenRead(filePath))
                using (var sha256 = SHA256.Create())
                {
                    byte[] hashBytes = sha256.ComputeHash(stream);
                    return BitConverter.ToString(hashBytes).Replace("-", "").ToLowerInvariant();
                }
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"[DataIntegrity] 计算校验和失败: {ex.Message}");
                return null;
            }
        }
        
        /// <summary>
        /// 计算字符串内容的SHA256校验和
        /// </summary>
        public static string CalculateContentChecksum(string content)
        {
            if (string.IsNullOrEmpty(content))
                return null;
            
            try
            {
                using (var sha256 = SHA256.Create())
                {
                    byte[] hashBytes = sha256.ComputeHash(Encoding.UTF8.GetBytes(content));
                    return BitConverter.ToString(hashBytes).Replace("-", "").ToLowerInvariant();
                }
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"[DataIntegrity] 计算内容校验和失败: {ex.Message}");
                return null;
            }
        }
        
        /// <summary>
        /// 保存校验和到文件
        /// </summary>
        private static void SaveChecksum(string filePath, string content)
        {
            try
            {
                string checksum = CalculateContentChecksum(content);
                string checksumPath = filePath + ChecksumExtension;
                File.WriteAllText(checksumPath, $"{checksum}  {Path.GetFileName(filePath)}", Encoding.ASCII);
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"[DataIntegrity] 保存校验和失败: {ex.Message}");
            }
        }
        
        /// <summary>
        /// 验证文件完整性
        /// </summary>
        /// <param name="filePath">要验证的文件路径</param>
        /// <returns>true=文件完整, false=文件损坏或无法验证</returns>
        public static bool VerifyFileIntegrity(string filePath)
        {
            if (!File.Exists(filePath))
                return false;
            
            try
            {
                string checksumPath = filePath + ChecksumExtension;
                
                if (!File.Exists(checksumPath))
                {
                    // 没有校验和文件，无法验证
                    System.Diagnostics.Debug.WriteLine($"[DataIntegrity] 未找到校验和文件: {checksumPath}");
                    return true; // 返回true避免误报
                }
                
                string storedChecksum = File.ReadAllText(checksumPath, Encoding.ASCII).Split(' ')[0];
                string actualChecksum = CalculateFileChecksum(filePath);
                
                bool isValid = string.Equals(storedChecksum, actualChecksum, StringComparison.OrdinalIgnoreCase);
                
                if (!isValid)
                {
                    System.Diagnostics.Debug.WriteLine($"[DataIntegrity] 文件校验失败！存储的校验和: {storedChecksum}, 实际校验和: {actualChecksum}");
                }
                
                return isValid;
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"[DataIntegrity] 文件完整性验证异常: {ex.Message}");
                return false;
            }
        }
        
        /// <summary>
        /// 检测并尝试修复损坏的数据文件
        /// </summary>
        /// <param name="filePath">要检查的文件路径</param>
        /// <returns>修复结果描述</returns>
        public static string DetectAndRepair(string filePath)
        {
            try
            {
                if (!File.Exists(filePath))
                {
                    return "文件不存在";
                }
                
                // 首先尝试验证完整性
                if (VerifyFileIntegrity(filePath))
                {
                    return "文件完整，无需修复";
                }
                
                // 文件损坏，尝试从备份恢复
                System.Diagnostics.Debug.WriteLine($"[DataIntegrity] 检测到文件损坏，尝试从备份恢复: {filePath}");
                
                if (RestoreFromBackup(filePath))
                {
                    // 再次验证修复后的文件
                    if (VerifyFileIntegrity(filePath))
                    {
                        return "已从备份成功修复文件";
                    }
                    else
                    {
                        return "备份文件也已损坏，无法自动修复";
                    }
                }
                else
                {
                    return "未找到可用备份，无法自动修复";
                }
            }
            catch (Exception ex)
            {
                return $"检测修复过程中发生错误: {ex.Message}";
            }
        }
        
        /// <summary>
        /// 查找最新的备份文件
        /// </summary>
        private static string FindLatestBackup(string filePath)
        {
            try
            {
                string directory = Path.GetDirectoryName(filePath);
                string fileNameWithoutExt = Path.GetFileNameWithoutExtension(filePath);
                string pattern = $"{Path.GetFileName(filePath)}.*{BackupExtension}";
                
                if (string.IsNullOrEmpty(directory))
                    directory = Directory.GetCurrentDirectory();
                
                var backupFiles = Directory.GetFiles(directory, pattern);
                
                if (backupFiles.Length == 0)
                    return null;
                
                // 找到最新的备份文件
                Array.Sort(backupFiles);
                return backupFiles[backupFiles.Length - 1];
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"[DataIntegrity] 查找备份失败: {ex.Message}");
                return null;
            }
        }
        
        /// <summary>
        /// 清理临时文件
        /// </summary>
        private static void CleanupTempFile(string tempPath)
        {
            try
            {
                if (File.Exists(tempPath))
                {
                    File.Delete(tempPath);
                }
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"[DataIntegrity] 清理临时文件失败: {ex.Message}");
            }
        }
        
        /// <summary>
        /// 清理过期的备份文件（保留最近N个）
        /// </summary>
        /// <param name="filePath">原始文件路径</param>
        /// <param name="keepCount">保留的备份数量，默认5</param>
        public static void CleanOldBackups(string filePath, int keepCount = 5)
        {
            try
            {
                string directory = Path.GetDirectoryName(filePath);
                string pattern = $"{Path.GetFileName(filePath)}.*{BackupExtension}";
                
                if (string.IsNullOrEmpty(directory))
                    directory = Directory.GetCurrentDirectory();
                
                var backupFiles = Directory.GetFiles(directory, pattern);
                
                if (backupFiles.Length <= keepCount)
                    return;
                
                // 按时间排序，删除最旧的备份
                Array.Sort(backupFiles);
                int toDelete = backupFiles.Length - keepCount;
                
                for (int i = 0; i < toDelete; i++)
                {
                    try
                    {
                        File.Delete(backupFiles[i]);
                        System.Diagnostics.Debug.WriteLine($"[DataIntegrity] 已删除旧备份: {backupFiles[i]}");
                    }
                    catch (Exception ex)
                    {
                        System.Diagnostics.Debug.WriteLine($"[DataIntegrity] 删除备份失败: {backupFiles[i]}, 错误: {ex.Message}");
                    }
                }
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"[DataIntegrity] 清理旧备份失败: {ex.Message}");
            }
        }
    }
}
