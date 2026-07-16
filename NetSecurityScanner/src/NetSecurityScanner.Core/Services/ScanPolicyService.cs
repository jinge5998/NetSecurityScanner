using System;
using System.Collections.Generic;
using System.IO;
using System.Text.Json;
using NetSecurityScanner.Models;

namespace NetSecurityScanner.Services
{
    /// <summary>
    /// 扫描策略服务
    /// </summary>
    public class ScanPolicyService
    {
        private readonly string _policiesDirectory;
        private const string DefaultPolicyFileName = "default_policy.json";
        
        /// <summary>
        /// 构造函数
        /// </summary>
        public ScanPolicyService()
        {
            // 初始化策略存储目录
            string appDataPath = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
            string appFolderPath = Path.Combine(appDataPath, "NetSecurityScanner");
            _policiesDirectory = Path.Combine(appFolderPath, "policies");
            Directory.CreateDirectory(_policiesDirectory);
        }
        
        /// <summary>
        /// 获取默认扫描策略
        /// </summary>
        /// <returns>默认扫描策略</returns>
        public ScanPolicy GetDefaultPolicy()
        {
            string defaultPolicyPath = Path.Combine(_policiesDirectory, DefaultPolicyFileName);
            
            if (File.Exists(defaultPolicyPath))
            {
                try
                {
                    string json = File.ReadAllText(defaultPolicyPath);
                    return JsonSerializer.Deserialize<ScanPolicy>(json) ?? new ScanPolicy();
                }
                catch (Exception)
                {
                    // 读取失败，返回新的默认策略
                    return CreateDefaultPolicy();
                }
            }
            else
            {
                // 默认策略文件不存在，创建并保存
                var defaultPolicy = CreateDefaultPolicy();
                SavePolicy(defaultPolicy, DefaultPolicyFileName);
                return defaultPolicy;
            }
        }
        
        /// <summary>
        /// 保存策略
        /// </summary>
        /// <param name="policy">扫描策略</param>
        /// <param name="fileName">文件名</param>
        public void SavePolicy(ScanPolicy policy, string fileName)
        {
            try
            {
                string policyPath = Path.Combine(_policiesDirectory, fileName);
                var options = new JsonSerializerOptions { WriteIndented = true };
                string json = JsonSerializer.Serialize(policy, options);
                
                // 先写入临时文件，再替换原文件，确保数据完整性
                string tempPath = policyPath + ".tmp";
                File.WriteAllText(tempPath, json);
                File.Replace(tempPath, policyPath, policyPath + ".bak");
            }
            catch (Exception ex)
            {
                throw new Exception($"保存扫描策略失败: {ex.Message}", ex);
            }
        }
        
        /// <summary>
        /// 加载策略
        /// </summary>
        /// <param name="fileName">文件名</param>
        /// <returns>扫描策略</returns>
        public ScanPolicy LoadPolicy(string fileName)
        {
            try
            {
                string policyPath = Path.Combine(_policiesDirectory, fileName);
                
                if (!File.Exists(policyPath))
                {
                    throw new FileNotFoundException($"策略文件不存在: {fileName}");
                }
                
                string json = File.ReadAllText(policyPath);
                return JsonSerializer.Deserialize<ScanPolicy>(json) ?? new ScanPolicy();
            }
            catch (Exception ex)
            {
                throw new Exception($"加载扫描策略失败: {ex.Message}", ex);
            }
        }
        
        /// <summary>
        /// 获取所有可用的策略
        /// </summary>
        /// <returns>策略列表</returns>
        public List<string> GetAvailablePolicies()
        {
            try
            {
                var policies = new List<string>();
                
                if (Directory.Exists(_policiesDirectory))
                {
                    foreach (var file in Directory.GetFiles(_policiesDirectory, "*.json"))
                    {
                        policies.Add(Path.GetFileName(file));
                    }
                }
                
                return policies;
            }
            catch (Exception)
            {
                return new List<string> { DefaultPolicyFileName };
            }
        }
        
        /// <summary>
        /// 创建默认扫描策略
        /// </summary>
        /// <returns>默认扫描策略</returns>
        private ScanPolicy CreateDefaultPolicy()
        {
            return new ScanPolicy
            {
                Name = "默认策略",
                Description = "默认扫描策略，适合大多数扫描场景",
                NetworkScanConfig = new NetworkScanConfig
                {
                    EnableTcpScan = true,
                    EnableUdpScan = false,
                    Ports = new List<int> { 21, 22, 23, 25, 53, 80, 443, 1433, 3306, 3389, 5432, 6379, 8080, 8443 },
                    ScanAllPorts = false,
                    PortTimeout = 1000
                },
                WebScanConfig = new WebScanConfig
                {
                    EnableWebScan = true,
                    EnableDirectoryTraversal = true,
                    EnableSqlInjection = true,
                    EnableXss = true,
                    EnableCommandInjection = true,
                    EnableAuthBypass = true,
                    EnableFileUpload = true,
                    ScanDepth = 2
                },
                RateLimitConfig = new RateLimitConfig
                {
                    MaxConcurrentScans = Environment.ProcessorCount * 2,
                    PortScanRate = 100,
                    HttpRequestRate = 20,
                    VulnerabilityScanRate = 10
                },
                TimeoutConfig = new TimeoutConfig
                {
                    ScanTimeout = 30,
                    HttpRequestTimeout = 5,
                    DatabaseTimeout = 10,
                    RemoteServiceTimeout = 5
                }
            };
        }
        
        /// <summary>
        /// 创建快速扫描策略
        /// </summary>
        /// <returns>快速扫描策略</returns>
        public ScanPolicy CreateQuickScanPolicy()
        {
            return new ScanPolicy
            {
                Name = "快速扫描",
                Description = "快速扫描策略，只扫描常用端口和高风险漏洞",
                NetworkScanConfig = new NetworkScanConfig
                {
                    EnableTcpScan = true,
                    EnableUdpScan = false,
                    Ports = new List<int> { 80, 443, 22, 3389, 3306, 1433, 445 },
                    ScanAllPorts = false,
                    PortTimeout = 500
                },
                WebScanConfig = new WebScanConfig
                {
                    EnableWebScan = true,
                    EnableDirectoryTraversal = true,
                    EnableSqlInjection = true,
                    EnableXss = false,
                    EnableCommandInjection = true,
                    EnableAuthBypass = false,
                    EnableFileUpload = false,
                    ScanDepth = 1
                },
                RateLimitConfig = new RateLimitConfig
                {
                    MaxConcurrentScans = Environment.ProcessorCount * 4,
                    PortScanRate = 200,
                    HttpRequestRate = 40,
                    VulnerabilityScanRate = 20
                },
                TimeoutConfig = new TimeoutConfig
                {
                    ScanTimeout = 10,
                    HttpRequestTimeout = 3,
                    DatabaseTimeout = 5,
                    RemoteServiceTimeout = 3
                }
            };
        }
        
        /// <summary>
        /// 创建全面扫描策略
        /// </summary>
        /// <returns>全面扫描策略</returns>
        public ScanPolicy CreateComprehensiveScanPolicy()
        {
            return new ScanPolicy
            {
                Name = "全面扫描",
                Description = "全面扫描策略，扫描所有端口和详细漏洞",
                NetworkScanConfig = new NetworkScanConfig
                {
                    EnableTcpScan = true,
                    EnableUdpScan = true,
                    Ports = new List<int>(), // 空列表表示扫描所有端口
                    ScanAllPorts = true,
                    PortTimeout = 2000
                },
                WebScanConfig = new WebScanConfig
                {
                    EnableWebScan = true,
                    EnableDirectoryTraversal = true,
                    EnableSqlInjection = true,
                    EnableXss = true,
                    EnableCommandInjection = true,
                    EnableAuthBypass = true,
                    EnableFileUpload = true,
                    ScanDepth = 3
                },
                RateLimitConfig = new RateLimitConfig
                {
                    MaxConcurrentScans = Environment.ProcessorCount,
                    PortScanRate = 50,
                    HttpRequestRate = 10,
                    VulnerabilityScanRate = 5
                },
                TimeoutConfig = new TimeoutConfig
                {
                    ScanTimeout = 60,
                    HttpRequestTimeout = 10,
                    DatabaseTimeout = 20,
                    RemoteServiceTimeout = 10
                }
            };
        }
    }
}