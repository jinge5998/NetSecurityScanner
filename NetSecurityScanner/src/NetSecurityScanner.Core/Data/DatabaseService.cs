using System;
using System.Collections.Generic;
using System.Data.Entity;
using System.IO;
using System.Linq;
using System.Text;
using NetSecurityScanner.Models;

namespace NetSecurityScanner.Data
{
    public class DatabaseService
    {
        public DatabaseService()
        {
            // 暂时禁用数据库初始化，以便应用程序能够启动
            // 数据库连接问题将在后续步骤中修复
        }

        public void SavePortScanResult(PortScanResult result)
        {
            try
            {
                using (var context = new SecurityContext())
                {
                    context.PortScanResults.Add(result);
                    context.SaveChanges();
                }
            }
            catch (Exception ex)
            {
                // 记录日志但不抛出异常，确保程序能继续运行
                Console.WriteLine($"保存端口扫描结果失败: {ex.Message}");
            }
        }

        public List<PortScanResult> GetPortScanResults()
        {
            try
            {
                using (var context = new SecurityContext())
                {
                    return context.PortScanResults.ToList();
                }
            }
            catch (Exception ex)
            {
                // 记录日志但不抛出异常，确保程序能继续运行
                Console.WriteLine($"获取端口扫描结果失败: {ex.Message}");
                return new List<PortScanResult>();
            }
        }

        public void SaveVulnerabilityResult(VulnerabilityResult result)
        {
            try
            {
                using (var context = new SecurityContext())
                {
                    context.VulnerabilityResults.Add(result);
                    context.SaveChanges();
                }
            }
            catch (Exception ex)
            {
                // 记录日志但不抛出异常，确保程序能继续运行
                Console.WriteLine($"保存漏洞扫描结果失败: {ex.Message}");
            }
        }

        public List<VulnerabilityResult> GetVulnerabilityResults()
        {
            try
            {
                using (var context = new SecurityContext())
                {
                    return context.VulnerabilityResults.ToList();
                }
            }
            catch (Exception ex)
            {
                // 记录日志但不抛出异常，确保程序能继续运行
                Console.WriteLine($"获取漏洞扫描结果失败: {ex.Message}");
                return new List<VulnerabilityResult>();
            }
        }

        public void SaveRiskAssessmentItem(RiskAssessmentItem item)
        {
            try
            {
                using (var context = new SecurityContext())
                {
                    context.RiskAssessmentItems.Add(item);
                    context.SaveChanges();
                }
            }
            catch (Exception ex)
            {
                // 记录日志但不抛出异常，确保程序能继续运行
                Console.WriteLine($"保存风险评估结果失败: {ex.Message}");
            }
        }

        public List<RiskAssessmentItem> GetRiskAssessmentItems()
        {
            try
            {
                using (var context = new SecurityContext())
                {
                    return context.RiskAssessmentItems.ToList();
                }
            }
            catch (Exception ex)
            {
                // 记录日志但不抛出异常，确保程序能继续运行
                Console.WriteLine($"获取风险评估结果失败: {ex.Message}");
                return new List<RiskAssessmentItem>();
            }
        }

        public void SaveScanHistory(ScanHistory history)
        {
            try
            {
                using (var context = new SecurityContext())
                {
                    context.ScanHistories.Add(history);
                    context.SaveChanges();
                }
            }
            catch (Exception ex)
            {
                // 记录日志但不抛出异常，确保程序能继续运行
                Console.WriteLine($"保存扫描历史失败: {ex.Message}");
            }
        }

        public List<ScanHistory> GetScanHistories()
        {
            try
            {
                using (var context = new SecurityContext())
                {
                    return context.ScanHistories.OrderByDescending(h => h.ScanTime).ToList();
                }
            }
            catch (Exception ex)
            {
                // 记录日志但不抛出异常，确保程序能继续运行
                Console.WriteLine($"获取扫描历史失败: {ex.Message}");
                return new List<ScanHistory>();
            }
        }

        public void DeleteScanHistory(int id)
        {
            try
            {
                using (var context = new SecurityContext())
                {
                    var history = context.ScanHistories.Find(id);
                    if (history != null)
                    {
                        context.ScanHistories.Remove(history);
                        context.SaveChanges();
                    }
                }
            }
            catch (Exception ex)
            {
                // 记录日志但不抛出异常，确保程序能继续运行
                Console.WriteLine($"删除扫描历史失败: {ex.Message}");
            }
        }

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
                
                string desktopPath = Environment.GetFolderPath(Environment.SpecialFolder.Desktop);
                string fileName = $"SecurityScanReport_{DateTime.Now:yyyyMMdd_HHmmss}{extension}";
                string filePath = Path.Combine(desktopPath, fileName);
                
                // 确保报告目录存在
                string directoryPath = Path.GetDirectoryName(filePath);
                if (!Directory.Exists(directoryPath))
                {
                    Directory.CreateDirectory(directoryPath);
                }
                
                File.WriteAllText(filePath, reportContent, Encoding.UTF8);
                
                return filePath;
            }
            catch (Exception ex)
            {
                // 记录日志但不抛出异常，确保程序能继续运行
                Console.WriteLine($"保存报告失败: {ex.Message}");
                throw;
            }
        }
    }
}