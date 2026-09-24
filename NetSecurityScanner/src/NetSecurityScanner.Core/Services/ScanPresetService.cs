using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.Json;

namespace NetSecurityScanner.Services
{
    /// <summary>
    /// 扫描配置预设管理服务 - P1优先级：扫描配置预设
    /// 提供快速/标准/深度三种预设模式，支持自定义预设
    /// </summary>
    public class ScanPresetService
    {
        private readonly string _presetsFilePath;
        private List<ScanPreset> _presets;
        private ScanPreset? _currentPreset;

        public event Action<ScanPreset>? PresetChanged;

        public ScanPresetService()
        {
            var appDataPath = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
                "NetSecurityScanner");

            if (!Directory.Exists(appDataPath))
            {
                Directory.CreateDirectory(appDataPath);
            }

            _presetsFilePath = Path.Combine(appDataPath, "scan_presets.json");
            _presets = new List<ScanPreset>();
            
            // 初始化默认预设
            InitializeDefaultPresets();
            
            // 加载用户自定义预设
            LoadCustomPresets();
        }

        /// <summary>
        /// 扫描预设模型
        /// </summary>
        public class ScanPreset
        {
            public string Id { get; set; } = Guid.NewGuid().ToString();
            public string Name { get; set; } = string.Empty;
            public string Description { get; set; } = string.Empty;
            public string Icon { get; set; } = "⚡"; // emoji图标
            
            // 端口范围配置
            public string PortRange { get; set; } = "1-1000";
            public List<int> CommonPorts { get; set; } = new();
            public bool UseCommonPortsOnly { get; set; } = false;
            
            // 性能参数
            public int MaxConcurrency { get; set; } = 100;
            public int ConnectionTimeout { get; set; } = 2000; // ms
            public int ScanSpeed { get; set; } = 2; // 1=慢速, 2=正常, 3=快速
            
            // 扫描选项
            public bool EnableServiceDetection { get; set; } = true;
            public bool EnableVersionDetection { get; set; } = true;
            public bool EnableOSDetection { get; set; } = false;
            public bool EnableVulnerabilityScan { get; set; } = false;
            
            // 高级选项
            public bool IsCustom { get; set; } = false;
            public bool IsBuiltIn { get; set; } = false;
            public DateTime CreatedAt { get; set; } = DateTime.Now;
            public DateTime? ModifiedAt { get; set; }
            
            // 预计时间和资源使用
            public string EstimatedTime { get; set; } = "~5分钟";
            public string ResourceUsage { get; set; } = "中等";
        }

        /// <summary>
        /// 获取所有可用预设（包括内置和自定义）
        /// </summary>
        public List<ScanPreset> GetAllPresets()
        {
            return new List<ScanPreset>(_presets);
        }

        /// <summary>
        /// 获取内置预设
        /// </summary>
        public List<ScanPreset> GetBuiltInPresets()
        {
            return _presets.Where(p => p.IsBuiltIn).ToList();
        }

        /// <summary>
        /// 获取自定义预设
        /// </summary>
        public List<ScanPreset> GetCustomPresets()
        {
            return _presets.Where(p => p.IsCustom).ToList();
        }

        /// <summary>
        /// 根据ID获取预设
        /// </summary>
        public ScanPreset? GetPresetById(string id)
        {
            return _presets.FirstOrDefault(p => p.Id == id);
        }

        /// <summary>
        /// 根据名称获取预设
        /// </summary>
        public ScanPreset? GetPresetByName(string name)
        {
            return _presets.FirstOrDefault(p => p.Name.Equals(name, StringComparison.OrdinalIgnoreCase));
        }

        /// <summary>
        /// 设置当前使用的预设
        /// </summary>
        public bool SetCurrentPreset(string presetId)
        {
            var preset = GetPresetById(presetId);
            if (preset != null)
            {
                _currentPreset = preset;
                PresetChanged?.Invoke(preset);
                return true;
            }
            return false;
        }

        /// <summary>
        /// 获取当前预设
        /// </summary>
        public ScanPreset? GetCurrentPreset()
        {
            return _currentPreset ?? GetPresetByName("标准扫描");
        }

        /// <summary>
        /// 创建自定义预设
        /// </summary>
        public ScanPreset CreateCustomPreset(ScanPreset preset)
        {
            preset.Id = Guid.NewGuid().ToString();
            preset.IsCustom = true;
            preset.IsBuiltIn = false;
            preset.CreatedAt = DateTime.Now;
            
            _presets.Add(preset);
            SavePresets();
            
            return preset;
        }

        /// <summary>
        /// 更新自定义预设
        /// </summary>
        public bool UpdateCustomPreset(ScanPreset updatedPreset)
        {
            if (!updatedPreset.IsCustom || updatedPreset.IsBuiltIn)
                return false;

            var existing = _presets.FirstOrDefault(p => p.Id == updatedPreset.Id);
            if (existing != null)
            {
                existing.Name = updatedPreset.Name;
                existing.Description = updatedPreset.Description;
                existing.PortRange = updatedPreset.PortRange;
                existing.CommonPorts = updatedPreset.CommonPorts;
                existing.UseCommonPortsOnly = updatedPreset.UseCommonPortsOnly;
                existing.MaxConcurrency = updatedPreset.MaxConcurrency;
                existing.ConnectionTimeout = updatedPreset.ConnectionTimeout;
                existing.ScanSpeed = updatedPreset.ScanSpeed;
                existing.EnableServiceDetection = updatedPreset.EnableServiceDetection;
                existing.EnableVersionDetection = updatedPreset.EnableVersionDetection;
                existing.EnableOSDetection = updatedPreset.EnableOSDetection;
                existing.EnableVulnerabilityScan = updatedPreset.EnableVulnerabilityScan;
                existing.ModifiedAt = DateTime.Now;
                
                SavePresets();
                return true;
            }
            return false;
        }

        /// <summary>
        /// 删除自定义预设
        /// </summary>
        public bool DeleteCustomPreset(string presetId)
        {
            var preset = _presets.FirstOrDefault(p => p.Id == presetId && p.IsCustom && !p.IsBuiltIn);
            if (preset != null)
            {
                _presets.Remove(preset);
                SavePresets();
                return true;
            }
            return false;
        }

        /// <summary>
        /// 导出预设到文件
        /// </summary>
        public bool ExportPresets(string filePath)
        {
            try
            {
                var options = new JsonSerializerOptions
                {
                    WriteIndented = true,
                    PropertyNamingPolicy = JsonNamingPolicy.CamelCase
                };
                var json = JsonSerializer.Serialize(_presets.Where(p => p.IsCustom), options);
                File.WriteAllText(filePath, json);
                return true;
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"导出预设失败: {ex.Message}");
                return false;
            }
        }

        /// <summary>
        /// 从文件导入预设
        /// </summary>
        public bool ImportPresets(string filePath)
        {
            try
            {
                if (!File.Exists(filePath))
                    return false;

                var json = File.ReadAllText(filePath);
                var importedPresets = JsonSerializer.Deserialize<List<ScanPreset>>(json);
                
                if (importedPresets != null)
                {
                    foreach (var preset in importedPresets)
                    {
                        preset.Id = Guid.NewGuid().ToString(); // 分配新的ID避免冲突
                        preset.IsCustom = true;
                        preset.IsBuiltIn = false;
                        preset.CreatedAt = DateTime.Now;
                        _presets.Add(preset);
                    }
                    
                    SavePresets();
                    return true;
                }
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"导入预设失败: {ex.Message}");
            }
            return false;
        }

        #region 私有方法

        /// <summary>
        /// 初始化默认的内置预设
        /// </summary>
        private void InitializeDefaultPresets()
        {
            _presets.AddRange(new[]
            {
                new ScanPreset
                {
                    Id = "preset-quick",
                    Name = "快速扫描",
                    Description = "仅扫描最常用的20个端口，适合快速检查",
                    Icon = "⚡",
                    PortRange = "1-1024",
                    CommonPorts = new List<int> 
                    { 
                        21, 22, 23, 25, 53, 80, 110, 111, 135, 139,
                        143, 443, 445, 993, 995, 1433, 3306, 3389, 5432, 8080
                    },
                    UseCommonPortsOnly = true,
                    MaxConcurrency = 150,
                    ConnectionTimeout = 1500,
                    ScanSpeed = 3, // 快速
                    EnableServiceDetection = true,
                    EnableVersionDetection = false,
                    EnableOSDetection = false,
                    EnableVulnerabilityScan = false,
                    IsBuiltIn = true,
                    EstimatedTime = "~30秒",
                    ResourceUsage = "低"
                },
                new ScanPreset
                {
                    Id = "preset-standard",
                    Name = "标准扫描",
                    Description = "扫描常用端口(1-1000)，平衡速度和完整性",
                    Icon = "🔍",
                    PortRange = "1-1000",
                    CommonPorts = new List<int>(),
                    UseCommonPortsOnly = false,
                    MaxConcurrency = 100,
                    ConnectionTimeout = 2000,
                    ScanSpeed = 2, // 正常
                    EnableServiceDetection = true,
                    EnableVersionDetection = true,
                    EnableOSDetection = false,
                    EnableVulnerabilityScan = false,
                    IsBuiltIn = true,
                    EstimatedTime = "~5分钟",
                    ResourceUsage = "中等"
                },
                new ScanPreset
                {
                    Id = "preset-deep",
                    Name = "深度扫描",
                    Description = "全端口扫描(1-65535) + 服务版本检测 + OS识别 + 漏洞扫描",
                    Icon = "🎯",
                    PortRange = "1-65535",
                    CommonPorts = new List<int>(),
                    UseCommonPortsOnly = false,
                    MaxConcurrency = 50,
                    ConnectionTimeout = 3000,
                    ScanSpeed = 1, // 慢速但更准确
                    EnableServiceDetection = true,
                    EnableVersionDetection = true,
                    EnableOSDetection = true,
                    EnableVulnerabilityScan = true,
                    IsBuiltIn = true,
                    EstimatedTime = "~30分钟",
                    ResourceUsage = "高"
                }
            });

            // 默认选择标准扫描
            _currentPreset = _presets.FirstOrDefault(p => p.Id == "preset-standard");
        }

        /// <summary>
        /// 加载用户自定义预设
        /// </summary>
        private void LoadCustomPresets()
        {
            try
            {
                if (File.Exists(_presetsFilePath))
                {
                    var json = File.ReadAllText(_presetsFilePath);
                    var customPresets = JsonSerializer.Deserialize<List<ScanPreset>>(json);
                    
                    if (customPresets != null)
                    {
                        foreach (var preset in customPresets)
                        {
                            // 确保不与内置预设冲突
                            if (!_presets.Any(p => p.Id == preset.Id))
                            {
                                _presets.Add(preset);
                            }
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"加载自定义预设失败: {ex.Message}");
            }
        }

        /// <summary>
        /// 保存自定义预设
        /// </summary>
        private void SavePresets()
        {
            try
            {
                var customPresets = _presets.Where(p => p.IsCustom).ToList();
                var options = new JsonSerializerOptions
                {
                    WriteIndented = true,
                    PropertyNamingPolicy = JsonNamingPolicy.CamelCase
                };
                var json = JsonSerializer.Serialize(customPresets, options);
                File.WriteAllText(_presetsFilePath, json);
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"保存预设失败: {ex.Message}");
            }
        }

        #endregion

        #region 辅助方法

        /// <summary>
        /// 解析端口范围为端口号列表
        /// </summary>
        public static List<int> ParsePortRangeToPorts(ScanPreset preset)
        {
            var ports = new List<int>();

            if (preset.UseCommonPortsOnly && preset.CommonPorts.Any())
            {
                return new List<int>(preset.CommonPorts);
            }

            // 解析端口范围字符串 (例如: "1-1000" 或 "22,80,443")
            var rangeParts = preset.PortRange.Split(',');
            foreach (var part in rangeParts)
            {
                var trimmedPart = part.Trim();
                if (trimmedPart.Contains("-"))
                {
                    var startEnd = trimmedPart.Split('-');
                    if (startEnd.Length == 2 &&
                        int.TryParse(startEnd[0].Trim(), out int start) &&
                        int.TryParse(startEnd[1].Trim(), out int end))
                    {
                        for (int i = Math.Max(1, start); i <= Math.Min(65535, end); i++)
                        {
                            ports.Add(i);
                        }
                    }
                }
                else if (int.TryParse(trimmedPart, out int port))
                {
                    if (port >= 1 && port <= 65535)
                    {
                        ports.Add(port);
                    }
                }
            }

            return ports.Distinct().OrderBy(p => p).ToList();
        }

        /// <summary>
        /// 获取扫描速度描述
        /// </summary>
        public static string GetScanSpeedDescription(int speedLevel)
        {
            return speedLevel switch
            {
                1 => "慢速（更精确）",
                2 => "正常",
                3 => "快速（可能遗漏）",
                _ => "未知"
            };
        }

        #endregion
    }
}
