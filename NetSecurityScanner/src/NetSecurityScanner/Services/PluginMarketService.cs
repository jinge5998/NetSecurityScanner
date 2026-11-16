using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Net.Http;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Threading;
using System.Threading.Tasks;
using NetSecurityScanner.Models;

namespace NetSecurityScanner.Services
{
    /// <summary>
    /// 插件市场服务
    /// </summary>
    public class PluginMarketService
    {
        private readonly HttpClient _httpClient;
        private readonly string _pluginsDirectory;
        private readonly string _metadataFile;
        private List<Plugin> _installedPlugins;
        private readonly LoggingService _loggingService;
        
        // 模拟插件市场API端点
        private const string MarketApiBaseUrl = "https://api.netsecurityscanner.com/plugins";
        
        public PluginMarketService(LoggingService loggingService = null)
        {
            _httpClient = new HttpClient
            {
                Timeout = TimeSpan.FromSeconds(30)
            };
            
            _pluginsDirectory = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                "NetSecurityScanner",
                "Plugins"
            );
            
            _metadataFile = Path.Combine(_pluginsDirectory, "installed_plugins.json");
            _loggingService = loggingService;
            _installedPlugins = new List<Plugin>();
            
            EnsurePluginsDirectoryExists();
            LoadInstalledPlugins();
        }
        
        /// <summary>
        /// 获取插件列表（从市场）
        /// </summary>
        public async Task<PluginMarketResponse> GetPluginsAsync(PluginSearchCriteria criteria, CancellationToken cancellationToken = default)
        {
            try
            {
                // 模拟从API获取数据
                // 实际项目中应该调用真实的插件市场API
                var allPlugins = await GetMockPluginsAsync(cancellationToken);
                
                // 应用搜索过滤
                var filteredPlugins = FilterPlugins(allPlugins, criteria);
                
                // 应用排序
                filteredPlugins = SortPlugins(filteredPlugins, criteria.SortOrder);
                
                // 分页
                var totalCount = filteredPlugins.Count;
                var totalPages = (int)Math.Ceiling(totalCount / (double)criteria.PageSize);
                var pagedPlugins = filteredPlugins
                    .Skip((criteria.Page - 1) * criteria.PageSize)
                    .Take(criteria.PageSize)
                    .ToList();
                
                // 标记已安装和可更新的插件
                MarkInstalledPlugins(pagedPlugins);
                
                return new PluginMarketResponse
                {
                    Plugins = pagedPlugins,
                    TotalCount = totalCount,
                    CurrentPage = criteria.Page,
                    TotalPages = totalPages
                };
            }
            catch (Exception ex)
            {
                LogError("获取插件列表失败", ex);
                throw;
            }
        }
        
        /// <summary>
        /// 获取已安装的插件列表
        /// </summary>
        public List<Plugin> GetInstalledPlugins()
        {
            return _installedPlugins.ToList();
        }
        
        /// <summary>
        /// 安装插件
        /// </summary>
        public async Task<bool> InstallPluginAsync(Plugin plugin, IProgress<double> progress, CancellationToken cancellationToken = default)
        {
            try
            {
                LogInfo($"开始安装插件: {plugin.Name} v{plugin.Version}");
                
                plugin.Status = PluginStatus.Installing;
                
                // 创建插件目录
                var pluginDir = Path.Combine(_pluginsDirectory, plugin.Id);
                Directory.CreateDirectory(pluginDir);
                
                // 模拟下载插件文件
                var downloadPath = Path.Combine(pluginDir, $"{plugin.Id}.zip");
                await DownloadPluginAsync(plugin, downloadPath, progress, cancellationToken);
                
                // 解压插件
                await ExtractPluginAsync(downloadPath, pluginDir, cancellationToken);
                
                // 删除压缩包
                File.Delete(downloadPath);
                
                // 更新插件信息
                plugin.IsInstalled = true;
                plugin.InstallDate = DateTime.Now;
                plugin.LocalPath = pluginDir;
                plugin.Status = PluginStatus.Installed;
                
                // 添加到已安装列表
                var existingPlugin = _installedPlugins.FirstOrDefault(p => p.Id == plugin.Id);
                if (existingPlugin != null)
                {
                    _installedPlugins.Remove(existingPlugin);
                }
                _installedPlugins.Add(plugin);
                
                // 保存元数据
                SaveInstalledPlugins();
                
                LogInfo($"插件安装成功: {plugin.Name}");
                return true;
            }
            catch (Exception ex)
            {
                plugin.Status = PluginStatus.Error;
                LogError($"安装插件失败: {plugin.Name}", ex);
                return false;
            }
        }
        
        /// <summary>
        /// 更新插件
        /// </summary>
        public async Task<bool> UpdatePluginAsync(Plugin plugin, IProgress<double> progress, CancellationToken cancellationToken = default)
        {
            try
            {
                LogInfo($"开始更新插件: {plugin.Name} 到 v{plugin.Version}");
                
                plugin.Status = PluginStatus.Updating;
                
                // 先卸载旧版本
                var pluginDir = Path.Combine(_pluginsDirectory, plugin.Id);
                if (Directory.Exists(pluginDir))
                {
                    Directory.Delete(pluginDir, true);
                }
                
                // 重新安装
                return await InstallPluginAsync(plugin, progress, cancellationToken);
            }
            catch (Exception ex)
            {
                plugin.Status = PluginStatus.Error;
                LogError($"更新插件失败: {plugin.Name}", ex);
                return false;
            }
        }
        
        /// <summary>
        /// 卸载插件
        /// </summary>
        public async Task<bool> UninstallPluginAsync(Plugin plugin, CancellationToken cancellationToken = default)
        {
            try
            {
                LogInfo($"开始卸载插件: {plugin.Name}");
                
                plugin.Status = PluginStatus.Uninstalling;
                
                var pluginDir = Path.Combine(_pluginsDirectory, plugin.Id);
                if (Directory.Exists(pluginDir))
                {
                    await Task.Run(() => Directory.Delete(pluginDir, true), cancellationToken);
                }
                
                // 从已安装列表移除
                _installedPlugins.RemoveAll(p => p.Id == plugin.Id);
                
                // 保存元数据
                SaveInstalledPlugins();
                
                plugin.IsInstalled = false;
                plugin.HasUpdate = false;
                plugin.Status = PluginStatus.Available;
                plugin.LocalPath = null;
                plugin.InstallDate = null;
                
                LogInfo($"插件卸载成功: {plugin.Name}");
                return true;
            }
            catch (Exception ex)
            {
                plugin.Status = PluginStatus.Error;
                LogError($"卸载插件失败: {plugin.Name}", ex);
                return false;
            }
        }
        
        /// <summary>
        /// 检查插件更新
        /// </summary>
        public async Task<List<Plugin>> CheckForUpdatesAsync(CancellationToken cancellationToken = default)
        {
            var updates = new List<Plugin>();
            
            try
            {
                foreach (var installedPlugin in _installedPlugins)
                {
                    // 模拟从市场获取最新版本信息
                    var latestVersion = await GetLatestVersionAsync(installedPlugin.Id, cancellationToken);
                    
                    if (!string.IsNullOrEmpty(latestVersion) && 
                        IsNewerVersion(latestVersion, installedPlugin.Version))
                    {
                        installedPlugin.HasUpdate = true;
                        updates.Add(installedPlugin);
                    }
                }
                
                SaveInstalledPlugins();
            }
            catch (Exception ex)
            {
                LogError("检查插件更新失败", ex);
            }
            
            return updates;
        }
        
        /// <summary>
        /// 获取插件详情
        /// </summary>
        public async Task<Plugin> GetPluginDetailsAsync(string pluginId, CancellationToken cancellationToken = default)
        {
            // 模拟获取插件详情
            var plugins = await GetMockPluginsAsync(cancellationToken);
            return plugins.FirstOrDefault(p => p.Id == pluginId);
        }
        
        #region Private Methods
        
        private void EnsurePluginsDirectoryExists()
        {
            if (!Directory.Exists(_pluginsDirectory))
            {
                Directory.CreateDirectory(_pluginsDirectory);
            }
        }
        
        private void LoadInstalledPlugins()
        {
            try
            {
                if (File.Exists(_metadataFile))
                {
                    var json = File.ReadAllText(_metadataFile);
                    _installedPlugins = JsonSerializer.Deserialize<List<Plugin>>(json) ?? new List<Plugin>();
                }
            }
            catch (Exception ex)
            {
                LogError("加载已安装插件列表失败", ex);
                _installedPlugins = new List<Plugin>();
            }
        }
        
        private void SaveInstalledPlugins()
        {
            try
            {
                var json = JsonSerializer.Serialize(_installedPlugins, new JsonSerializerOptions
                {
                    WriteIndented = true
                });
                File.WriteAllText(_metadataFile, json);
            }
            catch (Exception ex)
            {
                LogError("保存已安装插件列表失败", ex);
            }
        }
        
        private List<Plugin> FilterPlugins(List<Plugin> plugins, PluginSearchCriteria criteria)
        {
            var filtered = plugins.AsEnumerable();
            
            // 关键词搜索
            if (!string.IsNullOrWhiteSpace(criteria.Keyword))
            {
                var keyword = criteria.Keyword.ToLower();
                filtered = filtered.Where(p => 
                    p.Name.ToLower().Contains(keyword) ||
                    p.Description.ToLower().Contains(keyword) ||
                    p.Tags.Any(t => t.ToLower().Contains(keyword)));
            }
            
            // 类别过滤
            if (criteria.Category.HasValue)
            {
                filtered = filtered.Where(p => p.Category == criteria.Category.Value);
            }
            
            return filtered.ToList();
        }
        
        private List<Plugin> SortPlugins(List<Plugin> plugins, PluginSortOrder sortOrder)
        {
            return sortOrder switch
            {
                PluginSortOrder.Popularity => plugins.OrderByDescending(p => p.DownloadCount).ToList(),
                PluginSortOrder.Newest => plugins.OrderByDescending(p => p.PublishDate).ToList(),
                PluginSortOrder.RecentlyUpdated => plugins.OrderByDescending(p => p.LastUpdateDate).ToList(),
                PluginSortOrder.HighestRated => plugins.OrderByDescending(p => p.Rating).ToList(),
                PluginSortOrder.Name => plugins.OrderBy(p => p.Name).ToList(),
                _ => plugins.OrderByDescending(p => p.DownloadCount).ToList()
            };
        }
        
        private void MarkInstalledPlugins(List<Plugin> plugins)
        {
            foreach (var plugin in plugins)
            {
                var installed = _installedPlugins.FirstOrDefault(p => p.Id == plugin.Id);
                if (installed != null)
                {
                    plugin.IsInstalled = true;
                    plugin.InstallDate = installed.InstallDate;
                    plugin.LocalPath = installed.LocalPath;
                    
                    if (installed.HasUpdate)
                    {
                        plugin.HasUpdate = true;
                        plugin.Status = PluginStatus.UpdateAvailable;
                    }
                    else
                    {
                        plugin.Status = PluginStatus.Installed;
                    }
                }
            }
        }
        
        private async Task DownloadPluginAsync(Plugin plugin, string downloadPath, IProgress<double> progress, CancellationToken cancellationToken)
        {
            // 模拟下载过程
            var totalBytes = plugin.Size > 0 ? plugin.Size : 1024 * 1024; // 默认1MB
            var downloadedBytes = 0L;
            var buffer = new byte[8192];
            
            // 创建模拟文件内容
            using (var fs = new FileStream(downloadPath, FileMode.Create))
            {
                while (downloadedBytes < totalBytes)
                {
                    cancellationToken.ThrowIfCancellationRequested();
                    
                    var toWrite = (int)Math.Min(buffer.Length, totalBytes - downloadedBytes);
                    await fs.WriteAsync(buffer, 0, toWrite, cancellationToken);
                    downloadedBytes += toWrite;
                    
                    var percentComplete = (double)downloadedBytes / totalBytes * 100;
                    progress?.Report(percentComplete);
                    
                    // 模拟网络延迟
                    await Task.Delay(10, cancellationToken);
                }
            }
            
            progress?.Report(100);
        }
        
        private async Task ExtractPluginAsync(string zipPath, string extractPath, CancellationToken cancellationToken)
        {
            await Task.Run(() =>
            {
                // 创建模拟的插件文件
                var manifestPath = Path.Combine(extractPath, "manifest.json");
                var manifest = new
                {
                    id = Path.GetFileNameWithoutExtension(zipPath),
                    version = "1.0.0",
                    main = "plugin.dll"
                };
                File.WriteAllText(manifestPath, JsonSerializer.Serialize(manifest));
                
                // 创建模拟的DLL文件
                var dllPath = Path.Combine(extractPath, "plugin.dll");
                File.WriteAllText(dllPath, "// Mock plugin file");
                
            }, cancellationToken);
        }
        
        private async Task<string> GetLatestVersionAsync(string pluginId, CancellationToken cancellationToken)
        {
            // 模拟从API获取最新版本
            await Task.Delay(100, cancellationToken);
            
            // 随机返回一个更新的版本
            var random = new Random();
            if (random.Next(0, 10) < 3) // 30%概率有更新
            {
                return $"1.{random.Next(1, 10)}.{random.Next(0, 10)}";
            }
            
            return null;
        }
        
        private bool IsNewerVersion(string newVersion, string currentVersion)
        {
            try
            {
                var newVer = Version.Parse(newVersion);
                var currentVer = Version.Parse(currentVersion);
                return newVer > currentVer;
            }
            catch
            {
                return false;
            }
        }
        
        private void LogInfo(string message)
        {
            _loggingService?.Info(message);
            System.Diagnostics.Debug.WriteLine($"[PluginMarket] {message}");
        }
        
        private void LogError(string message, Exception ex = null)
        {
            _loggingService?.Error(message, ex);
            System.Diagnostics.Debug.WriteLine($"[PluginMarket] ERROR: {message}");
            if (ex != null)
            {
                System.Diagnostics.Debug.WriteLine($"[PluginMarket] Exception: {ex.Message}");
            }
        }
        
        #endregion
        
        #region Mock Data
        
        private async Task<List<Plugin>> GetMockPluginsAsync(CancellationToken cancellationToken)
        {
            await Task.Delay(100, cancellationToken); // 模拟网络延迟
            
            return new List<Plugin>
            {
                new Plugin
                {
                    Id = "sql-injection-detector",
                    Name = "SQL注入检测器",
                    Description = "高级SQL注入漏洞检测插件，支持多种数据库类型的注入检测，包括盲注、时间注入等高级技术。",
                    Version = "2.1.0",
                    Author = "安全研究团队",
                    Category = PluginCategory.VulnerabilityDetection,
                    Tags = new List<string> { "SQL注入", "Web安全", "数据库" },
                    DownloadCount = 15420,
                    Rating = 4.8,
                    RatingCount = 328,
                    PublishDate = new DateTime(2024, 1, 15),
                    LastUpdateDate = new DateTime(2025, 1, 10),
                    MinAppVersion = "1.0.0",
                    Size = 2 * 1024 * 1024 // 2MB
                },
                new Plugin
                {
                    Id = "xss-scanner",
                    Name = "XSS漏洞扫描器",
                    Description = "全面的跨站脚本攻击(XSS)检测插件，支持反射型、存储型和DOM型XSS检测。",
                    Version = "1.5.2",
                    Author = "Web安全实验室",
                    Category = PluginCategory.VulnerabilityDetection,
                    Tags = new List<string> { "XSS", "Web安全", "前端安全" },
                    DownloadCount = 12890,
                    Rating = 4.6,
                    RatingCount = 256,
                    PublishDate = new DateTime(2024, 3, 20),
                    LastUpdateDate = new DateTime(2024, 12, 5),
                    MinAppVersion = "1.0.0",
                    Size = 1 * 1024 * 1024 // 1MB
                },
                new Plugin
                {
                    Id = "port-service-identifier",
                    Name = "端口服务识别器",
                    Description = "智能识别开放端口上运行的服务类型和版本，支持超过5000种常见服务指纹。",
                    Version = "3.0.1",
                    Author = "网络扫描专家",
                    Category = PluginCategory.PortScanning,
                    Tags = new List<string> { "端口扫描", "服务识别", "指纹识别" },
                    DownloadCount = 22150,
                    Rating = 4.9,
                    RatingCount = 512,
                    PublishDate = new DateTime(2023, 8, 10),
                    LastUpdateDate = new DateTime(2025, 1, 15),
                    MinAppVersion = "1.0.0",
                    Size = 5 * 1024 * 1024 // 5MB
                },
                new Plugin
                {
                    Id = "pdf-report-generator",
                    Name = "PDF报告生成器",
                    Description = "生成专业的PDF格式安全扫描报告，包含图表、风险评级和修复建议。",
                    Version = "1.8.0",
                    Author = "报告工具开发组",
                    Category = PluginCategory.Reporting,
                    Tags = new List<string> { "PDF", "报告", "文档" },
                    DownloadCount = 9870,
                    Rating = 4.5,
                    RatingCount = 189,
                    PublishDate = new DateTime(2024, 5, 1),
                    LastUpdateDate = new DateTime(2024, 11, 20),
                    MinAppVersion = "1.0.0",
                    Size = 3 * 1024 * 1024 // 3MB
                },
                new Plugin
                {
                    Id = "vulnerability-trend-analyzer",
                    Name = "漏洞趋势分析器",
                    Description = "分析历史扫描数据，生成漏洞趋势图表和预测，帮助了解安全态势变化。",
                    Version = "1.2.3",
                    Author = "数据分析团队",
                    Category = PluginCategory.DataAnalysis,
                    Tags = new List<string> { "数据分析", "趋势", "图表" },
                    DownloadCount = 6540,
                    Rating = 4.7,
                    RatingCount = 145,
                    PublishDate = new DateTime(2024, 6, 15),
                    LastUpdateDate = new DateTime(2024, 12, 28),
                    MinAppVersion = "1.0.0",
                    Size = 2 * 1024 * 1024 // 2MB
                },
                new Plugin
                {
                    Id = "dark-theme",
                    Name = "深色主题",
                    Description = "为应用程序提供深色模式界面，减少眼部疲劳，适合夜间使用。",
                    Version = "1.0.5",
                    Author = "UI设计团队",
                    Category = PluginCategory.UIExtension,
                    Tags = new List<string> { "主题", "UI", "深色模式" },
                    DownloadCount = 18500,
                    Rating = 4.4,
                    RatingCount = 420,
                    PublishDate = new DateTime(2024, 2, 1),
                    LastUpdateDate = new DateTime(2024, 10, 15),
                    MinAppVersion = "1.0.0",
                    Size = 500 * 1024 // 500KB
                },
                new Plugin
                {
                    Id = "nmap-integration",
                    Name = "Nmap集成插件",
                    Description = "集成Nmap扫描引擎，提供更强大的端口扫描和主机发现功能。",
                    Version = "2.0.0",
                    Author = "集成开发组",
                    Category = PluginCategory.Integration,
                    Tags = new List<string> { "Nmap", "集成", "端口扫描" },
                    DownloadCount = 11200,
                    Rating = 4.6,
                    RatingCount = 278,
                    PublishDate = new DateTime(2024, 4, 10),
                    LastUpdateDate = new DateTime(2025, 1, 5),
                    MinAppVersion = "1.0.0",
                    Size = 4 * 1024 * 1024 // 4MB
                },
                new Plugin
                {
                    Id = "ssl-tls-checker",
                    Name = "SSL/TLS检测器",
                    Description = "全面检测SSL/TLS配置安全性，包括证书验证、协议版本和密码套件分析。",
                    Version = "1.3.1",
                    Author = "加密安全专家",
                    Category = PluginCategory.VulnerabilityDetection,
                    Tags = new List<string> { "SSL", "TLS", "证书", "加密" },
                    DownloadCount = 14300,
                    Rating = 4.8,
                    RatingCount = 312,
                    PublishDate = new DateTime(2024, 7, 20),
                    LastUpdateDate = new DateTime(2024, 12, 10),
                    MinAppVersion = "1.0.0",
                    Size = 2 * 1024 * 1024 // 2MB
                },
                new Plugin
                {
                    Id = "api-security-scanner",
                    Name = "API安全扫描器",
                    Description = "专门针对RESTful API和GraphQL API的安全扫描，检测未授权访问、注入等漏洞。",
                    Version = "1.1.0",
                    Author = "API安全团队",
                    Category = PluginCategory.VulnerabilityDetection,
                    Tags = new List<string> { "API", "REST", "GraphQL", "Web安全" },
                    DownloadCount = 8900,
                    Rating = 4.5,
                    RatingCount = 198,
                    PublishDate = new DateTime(2024, 9, 1),
                    LastUpdateDate = new DateTime(2024, 12, 20),
                    MinAppVersion = "1.0.0",
                    Size = 3 * 1024 * 1024 // 3MB
                },
                new Plugin
                {
                    Id = "network-topology-mapper",
                    Name = "网络拓扑映射器",
                    Description = "自动发现网络拓扑结构并生成可视化网络图，帮助理解网络架构。",
                    Version = "1.0.8",
                    Author = "网络工具开发组",
                    Category = PluginCategory.DataAnalysis,
                    Tags = new List<string> { "网络拓扑", "可视化", "发现" },
                    DownloadCount = 7200,
                    Rating = 4.3,
                    RatingCount = 156,
                    PublishDate = new DateTime(2024, 8, 5),
                    LastUpdateDate = new DateTime(2024, 11, 30),
                    MinAppVersion = "1.0.0",
                    Size = 4 * 1024 * 1024 // 4MB
                }
            };
        }
        
        #endregion
    }
}
