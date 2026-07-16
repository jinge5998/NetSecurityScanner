using System;
using System.IO;
using System.Text.Json;
using System.Threading.Tasks;

namespace NetSecurityScanner.Services
{
    /// <summary>
    /// 应用程序设置服务
    /// </summary>
    public class SettingsService
    {
        private readonly string _settingsFilePath;
        private AppSettings _currentSettings;
        private readonly object _lockObject = new object();
        
        public SettingsService()
        {
            // 设置文件存储在用户应用数据目录
            var appDataPath = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
                "NetSecurityScanner");
            
            if (!Directory.Exists(appDataPath))
            {
                Directory.CreateDirectory(appDataPath);
            }
            
            _settingsFilePath = Path.Combine(appDataPath, "settings.json");
            _currentSettings = new AppSettings();
        }
        
        /// <summary>
        /// 加载设置
        /// </summary>
        public AppSettings LoadSettings()
        {
            try
            {
                if (File.Exists(_settingsFilePath))
                {
                    var json = File.ReadAllText(_settingsFilePath);
                    var settings = JsonSerializer.Deserialize<AppSettings>(json);
                    if (settings != null)
                    {
                        lock (_lockObject)
                        {
                            _currentSettings = settings;
                        }
                        return settings;
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"加载设置失败: {ex.Message}");
            }
            
            // 如果加载失败，返回默认设置
            return GetDefaultSettings();
        }
        
        /// <summary>
        /// 异步加载设置
        /// </summary>
        public async Task<AppSettings> LoadSettingsAsync()
        {
            try
            {
                if (File.Exists(_settingsFilePath))
                {
                    var json = await File.ReadAllTextAsync(_settingsFilePath);
                    var settings = JsonSerializer.Deserialize<AppSettings>(json);
                    if (settings != null)
                    {
                        lock (_lockObject)
                        {
                            _currentSettings = settings;
                        }
                        return settings;
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"加载设置失败: {ex.Message}");
            }
            
            return GetDefaultSettings();
        }
        
        /// <summary>
        /// 保存设置
        /// </summary>
        public bool SaveSettings(AppSettings settings)
        {
            try
            {
                var options = new JsonSerializerOptions
                {
                    WriteIndented = true,
                    PropertyNamingPolicy = JsonNamingPolicy.CamelCase
                };
                
                var json = JsonSerializer.Serialize(settings, options);
                File.WriteAllText(_settingsFilePath, json);
                
                lock (_lockObject)
                {
                    _currentSettings = settings;
                }
                
                return true;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"保存设置失败: {ex.Message}");
                return false;
            }
        }
        
        /// <summary>
        /// 异步保存设置
        /// </summary>
        public async Task<bool> SaveSettingsAsync(AppSettings settings)
        {
            try
            {
                var options = new JsonSerializerOptions
                {
                    WriteIndented = true,
                    PropertyNamingPolicy = JsonNamingPolicy.CamelCase
                };
                
                var json = JsonSerializer.Serialize(settings, options);
                await File.WriteAllTextAsync(_settingsFilePath, json);
                
                lock (_lockObject)
                {
                    _currentSettings = settings;
                }
                
                return true;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"保存设置失败: {ex.Message}");
                return false;
            }
        }
        
        /// <summary>
        /// 获取当前设置
        /// </summary>
        public AppSettings GetCurrentSettings()
        {
            lock (_lockObject)
            {
                return _currentSettings;
            }
        }
        
        /// <summary>
        /// 获取默认设置
        /// </summary>
        public AppSettings GetDefaultSettings()
        {
            return new AppSettings
            {
                // 扫描设置 - 200线程高并发
                MaxConcurrency = 200,
                ConnectionTimeout = 2000,
                DefaultScanSpeed = "快速",
                
                // 功能开关
                EnableAutoUpdate = true,
                EnableAuditLog = true,
                EnableProxy = false,
                
                // 代理设置
                ProxyServer = "",
                ProxyPort = 8080,
                ProxyUsername = "",
                ProxyPassword = "",
                
                // 报告设置
                DefaultReportFormat = "Markdown",
                AutoSaveReports = true,
                ReportsDirectory = Path.Combine(
                    Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments),
                    "NetSecurityScanner", "Reports"),
                
                // 数据库设置
                DatabasePath = Path.Combine(
                    Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
                    "NetSecurityScanner", "scanner.db"),
                
                // 通知设置
                EnableNotifications = true,
                ShowTrayIcon = true,
                MinimizeToTray = false,
                
                // 安全设置
                RequirePasswordOnStartup = false,
                AutoLockTimeout = 30,
                
                // 界面设置
                Theme = "Light",
                Language = "zh-CN",
                FontSize = 12,
                
                // 最后更新时间
                LastUpdateCheck = DateTime.MinValue,
                SettingsVersion = "1.0"
            };
        }
        
        /// <summary>
        /// 重置为默认设置
        /// </summary>
        public bool ResetToDefaults()
        {
            var defaultSettings = GetDefaultSettings();
            return SaveSettings(defaultSettings);
        }
        
        /// <summary>
        /// 更新单个设置项
        /// </summary>
        public bool UpdateSetting<T>(string propertyName, T value)
        {
            try
            {
                lock (_lockObject)
                {
                    var property = typeof(AppSettings).GetProperty(propertyName);
                    if (property != null && property.CanWrite)
                    {
                        property.SetValue(_currentSettings, value);
                        return SaveSettings(_currentSettings);
                    }
                }
                return false;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"更新设置项失败: {ex.Message}");
                return false;
            }
        }
        
        /// <summary>
        /// 导出设置到文件
        /// </summary>
        public bool ExportSettings(string filePath)
        {
            try
            {
                var options = new JsonSerializerOptions
                {
                    WriteIndented = true,
                    PropertyNamingPolicy = JsonNamingPolicy.CamelCase
                };
                
                lock (_lockObject)
                {
                    var json = JsonSerializer.Serialize(_currentSettings, options);
                    File.WriteAllText(filePath, json);
                }
                
                return true;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"导出设置失败: {ex.Message}");
                return false;
            }
        }
        
        /// <summary>
        /// 从文件导入设置
        /// </summary>
        public bool ImportSettings(string filePath)
        {
            try
            {
                if (File.Exists(filePath))
                {
                    var json = File.ReadAllText(filePath);
                    var settings = JsonSerializer.Deserialize<AppSettings>(json);
                    if (settings != null)
                    {
                        return SaveSettings(settings);
                    }
                }
                return false;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"导入设置失败: {ex.Message}");
                return false;
            }
        }
        
        /// <summary>
        /// 检查设置文件是否存在
        /// </summary>
        public bool SettingsFileExists()
        {
            return File.Exists(_settingsFilePath);
        }
        
        /// <summary>
        /// 获取设置文件路径
        /// </summary>
        public string GetSettingsFilePath()
        {
            return _settingsFilePath;
        }
    }
    
    /// <summary>
    /// 应用程序设置模型
    /// </summary>
    public class AppSettings
    {
        // 扫描设置
        public int MaxConcurrency { get; set; }
        public int ConnectionTimeout { get; set; }
        public string DefaultScanSpeed { get; set; } = "正常";
        
        // 功能开关
        public bool EnableAutoUpdate { get; set; }
        public bool EnableAuditLog { get; set; }
        public bool EnableProxy { get; set; }
        
        // 代理设置
        public string ProxyServer { get; set; } = "";
        public int ProxyPort { get; set; }
        public string ProxyUsername { get; set; } = "";
        public string ProxyPassword { get; set; } = "";
        
        // 报告设置
        public string DefaultReportFormat { get; set; } = "Markdown";
        public bool AutoSaveReports { get; set; }
        public string ReportsDirectory { get; set; } = "";
        
        // 数据库设置
        public string DatabasePath { get; set; } = "";
        
        // 通知设置
        public bool EnableNotifications { get; set; }
        public bool ShowTrayIcon { get; set; }
        public bool MinimizeToTray { get; set; }
        
        // 安全设置
        public bool RequirePasswordOnStartup { get; set; }
        public int AutoLockTimeout { get; set; }
        
        // 界面设置
        public string Theme { get; set; } = "Light";
        public string Language { get; set; } = "zh-CN";
        public int FontSize { get; set; }
        
        // 版本信息
        public DateTime LastUpdateCheck { get; set; }
        public string SettingsVersion { get; set; } = "1.0";
    }
}
