using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.Json;
using System.Threading.Tasks;

namespace NetSecurityScanner.Services
{
    /// <summary>
    /// 资产管理服务
    /// </summary>
    public class AssetManagementService
    {
        private readonly string _assetsFilePath;
        private List<Asset> _assets;
        private List<AssetChangeLog> _changeLogs;

        public AssetManagementService()
        {
            _assetsFilePath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "assets.json");
            _assets = new List<Asset>();
            _changeLogs = new List<AssetChangeLog>();
            LoadAssets();
        }

        /// <summary>
        /// 获取所有资产
        /// </summary>
        public List<Asset> GetAllAssets()
        {
            return _assets.OrderBy(a => a.IPAddress).ToList();
        }

        /// <summary>
        /// 根据ID获取资产
        /// </summary>
        public Asset? GetAssetById(string id)
        {
            return _assets.FirstOrDefault(a => a.Id == id);
        }

        /// <summary>
        /// 添加资产
        /// </summary>
        public async Task<bool> AddAssetAsync(Asset asset)
        {
            if (_assets.Any(a => a.IPAddress == asset.IPAddress))
            {
                return false;
            }

            asset.Id = Guid.NewGuid().ToString();
            asset.CreatedAt = DateTime.Now;
            asset.LastModified = DateTime.Now;
            _assets.Add(asset);

            // 记录变更日志
            await AddChangeLogAsync(new AssetChangeLog
            {
                AssetId = asset.Id,
                ChangeType = ChangeType.Create,
                FieldName = "Asset",
                NewValue = $"添加资产: {asset.Name} ({asset.IPAddress})",
                ChangedBy = "System",
                ChangedAt = DateTime.Now
            });

            SaveAssets();
            return true;
        }

        /// <summary>
        /// 更新资产
        /// </summary>
        public async Task<bool> UpdateAssetAsync(Asset asset)
        {
            var existingAsset = _assets.FirstOrDefault(a => a.Id == asset.Id);
            if (existingAsset == null)
            {
                return false;
            }

            // 记录变更
            var changes = GetChanges(existingAsset, asset);
            foreach (var change in changes)
            {
                await AddChangeLogAsync(new AssetChangeLog
                {
                    AssetId = asset.Id,
                    ChangeType = ChangeType.Update,
                    FieldName = change.FieldName,
                    OldValue = change.OldValue,
                    NewValue = change.NewValue,
                    ChangedBy = "System",
                    ChangedAt = DateTime.Now
                });
            }

            // 更新资产
            existingAsset.Name = asset.Name;
            existingAsset.IPAddress = asset.IPAddress;
            existingAsset.MacAddress = asset.MacAddress;
            existingAsset.AssetType = asset.AssetType;
            existingAsset.OperatingSystem = asset.OperatingSystem;
            existingAsset.Owner = asset.Owner;
            existingAsset.Department = asset.Department;
            existingAsset.Location = asset.Location;
            existingAsset.Status = asset.Status;
            existingAsset.Description = asset.Description;
            existingAsset.Tags = asset.Tags;
            existingAsset.LastModified = DateTime.Now;

            SaveAssets();
            return true;
        }

        /// <summary>
        /// 删除资产
        /// </summary>
        public async Task<bool> DeleteAssetAsync(string id)
        {
            var asset = _assets.FirstOrDefault(a => a.Id == id);
            if (asset == null)
            {
                return false;
            }

            _assets.Remove(asset);

            await AddChangeLogAsync(new AssetChangeLog
            {
                AssetId = id,
                ChangeType = ChangeType.Delete,
                FieldName = "Asset",
                OldValue = $"删除资产: {asset.Name} ({asset.IPAddress})",
                ChangedBy = "System",
                ChangedAt = DateTime.Now
            });

            SaveAssets();
            return true;
        }

        /// <summary>
        /// 搜索资产
        /// </summary>
        public List<Asset> SearchAssets(string keyword)
        {
            if (string.IsNullOrWhiteSpace(keyword))
            {
                return GetAllAssets();
            }

            keyword = keyword.ToLower();
            return _assets.Where(a =>
                a.Name.ToLower().Contains(keyword) ||
                a.IPAddress.Contains(keyword) ||
                (a.MacAddress?.ToLower().Contains(keyword) ?? false) ||
                a.AssetType.ToLower().Contains(keyword) ||
                (a.Owner?.ToLower().Contains(keyword) ?? false) ||
                (a.Department?.ToLower().Contains(keyword) ?? false) ||
                (a.Tags?.Any(t => t.ToLower().Contains(keyword)) ?? false)
            ).ToList();
        }

        /// <summary>
        /// 按类型筛选资产
        /// </summary>
        public List<Asset> GetAssetsByType(AssetType type)
        {
            return _assets.Where(a => a.AssetType == type.ToString()).ToList();
        }

        /// <summary>
        /// 获取资产统计
        /// </summary>
        public AssetStatistics GetStatistics()
        {
            return new AssetStatistics
            {
                TotalAssets = _assets.Count,
                OnlineAssets = _assets.Count(a => a.Status == AssetStatus.Online),
                OfflineAssets = _assets.Count(a => a.Status == AssetStatus.Offline),
                MaintenanceAssets = _assets.Count(a => a.Status == AssetStatus.Maintenance),
                AssetTypeDistribution = _assets.GroupBy(a => a.AssetType)
                    .ToDictionary(g => g.Key, g => g.Count()),
                DepartmentDistribution = _assets.Where(a => !string.IsNullOrEmpty(a.Department))
                    .GroupBy(a => a.Department!)
                    .ToDictionary(g => g.Key, g => g.Count()),
                RecentChanges = _changeLogs.OrderByDescending(c => c.ChangedAt).Take(10).ToList()
            };
        }

        /// <summary>
        /// 获取变更日志
        /// </summary>
        public List<AssetChangeLog> GetChangeLogs(string? assetId = null)
        {
            if (string.IsNullOrEmpty(assetId))
            {
                return _changeLogs.OrderByDescending(c => c.ChangedAt).ToList();
            }
            return _changeLogs.Where(c => c.AssetId == assetId).OrderByDescending(c => c.ChangedAt).ToList();
        }

        /// <summary>
        /// 导入扫描结果为资产
        /// </summary>
        public async Task<int> ImportFromScanResultsAsync(List<NetworkDevice> devices)
        {
            int importedCount = 0;

            foreach (var device in devices)
            {
                if (!_assets.Any(a => a.IPAddress == device.IPAddress))
                {
                    var asset = new Asset
                    {
                        Name = device.Hostname,
                        IPAddress = device.IPAddress,
                        MacAddress = device.MacAddress,
                        AssetType = device.DeviceType.ToString(),
                        OperatingSystem = device.OperatingSystem,
                        Status = device.Status == DeviceStatus.Online ? AssetStatus.Online : AssetStatus.Offline,
                        Description = $"自动导入自网络扫描 - 开放端口: {string.Join(", ", device.OpenPorts)}",
                        CreatedAt = DateTime.Now,
                        LastModified = DateTime.Now
                    };

                    if (await AddAssetAsync(asset))
                    {
                        importedCount++;
                    }
                }
            }

            return importedCount;
        }

        /// <summary>
        /// 添加变更日志
        /// </summary>
        private async Task AddChangeLogAsync(AssetChangeLog log)
        {
            log.Id = Guid.NewGuid().ToString();
            _changeLogs.Add(log);
            await Task.CompletedTask;
        }

        /// <summary>
        /// 获取变更列表
        /// </summary>
        private List<ChangeDetail> GetChanges(Asset oldAsset, Asset newAsset)
        {
            var changes = new List<ChangeDetail>();

            if (oldAsset.Name != newAsset.Name)
                changes.Add(new ChangeDetail { FieldName = "名称", OldValue = oldAsset.Name, NewValue = newAsset.Name });

            if (oldAsset.IPAddress != newAsset.IPAddress)
                changes.Add(new ChangeDetail { FieldName = "IP地址", OldValue = oldAsset.IPAddress, NewValue = newAsset.IPAddress });

            if (oldAsset.MacAddress != newAsset.MacAddress)
                changes.Add(new ChangeDetail { FieldName = "MAC地址", OldValue = oldAsset.MacAddress, NewValue = newAsset.MacAddress });

            if (oldAsset.AssetType != newAsset.AssetType)
                changes.Add(new ChangeDetail { FieldName = "资产类型", OldValue = oldAsset.AssetType, NewValue = newAsset.AssetType });

            if (oldAsset.Status != newAsset.Status)
                changes.Add(new ChangeDetail { FieldName = "状态", OldValue = oldAsset.Status.ToString(), NewValue = newAsset.Status.ToString() });

            if (oldAsset.Owner != newAsset.Owner)
                changes.Add(new ChangeDetail { FieldName = "负责人", OldValue = oldAsset.Owner, NewValue = newAsset.Owner });

            if (oldAsset.Department != newAsset.Department)
                changes.Add(new ChangeDetail { FieldName = "部门", OldValue = oldAsset.Department, NewValue = newAsset.Department });

            return changes;
        }

        /// <summary>
        /// 加载资产
        /// </summary>
        private void LoadAssets()
        {
            try
            {
                if (File.Exists(_assetsFilePath))
                {
                    var json = File.ReadAllText(_assetsFilePath);
                    var data = JsonSerializer.Deserialize<AssetData>(json);
                    if (data != null)
                    {
                        _assets = data.Assets ?? new List<Asset>();
                        _changeLogs = data.ChangeLogs ?? new List<AssetChangeLog>();
                    }
                }
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"[AssetManagementService] 加载资产失败: {ex.Message}");
            }
        }

        /// <summary>
        /// 保存资产
        /// </summary>
        private void SaveAssets()
        {
            try
            {
                var data = new AssetData
                {
                    Assets = _assets,
                    ChangeLogs = _changeLogs
                };
                var json = JsonSerializer.Serialize(data, new JsonSerializerOptions { WriteIndented = true });
                File.WriteAllText(_assetsFilePath, json);
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"[AssetManagementService] 保存资产失败: {ex.Message}");
            }
        }
    }

    /// <summary>
    /// 资产
    /// </summary>
    public class Asset
    {
        public string Id { get; set; } = "";
        public string Name { get; set; } = "";
        public string IPAddress { get; set; } = "";
        public string? MacAddress { get; set; }
        public string AssetType { get; set; } = "";
        public string? OperatingSystem { get; set; }
        public string? Owner { get; set; }
        public string? Department { get; set; }
        public string? Location { get; set; }
        public AssetStatus Status { get; set; } = AssetStatus.Online;
        public string? Description { get; set; }
        public List<string> Tags { get; set; } = new();
        public DateTime CreatedAt { get; set; }
        public DateTime LastModified { get; set; }
    }

    /// <summary>
    /// 资产类型
    /// </summary>
    public enum AssetType
    {
        Server,
        Workstation,
        NetworkDevice,
        SecurityDevice,
        Database,
        Application,
        Other
    }

    /// <summary>
    /// 资产状态
    /// </summary>
    public enum AssetStatus
    {
        Online,
        Offline,
        Maintenance,
        Retired
    }

    /// <summary>
    /// 资产变更日志
    /// </summary>
    public class AssetChangeLog
    {
        public string Id { get; set; } = "";
        public string AssetId { get; set; } = "";
        public ChangeType ChangeType { get; set; }
        public string FieldName { get; set; } = "";
        public string? OldValue { get; set; }
        public string? NewValue { get; set; }
        public string ChangedBy { get; set; } = "";
        public DateTime ChangedAt { get; set; }
    }

    /// <summary>
    /// 变更类型
    /// </summary>
    public enum ChangeType
    {
        Create,
        Update,
        Delete
    }

    /// <summary>
    /// 资产统计
    /// </summary>
    public class AssetStatistics
    {
        public int TotalAssets { get; set; }
        public int OnlineAssets { get; set; }
        public int OfflineAssets { get; set; }
        public int MaintenanceAssets { get; set; }
        public Dictionary<string, int> AssetTypeDistribution { get; set; } = new();
        public Dictionary<string, int> DepartmentDistribution { get; set; } = new();
        public List<AssetChangeLog> RecentChanges { get; set; } = new();
    }

    /// <summary>
    /// 资产数据
    /// </summary>
    public class AssetData
    {
        public List<Asset> Assets { get; set; } = new();
        public List<AssetChangeLog> ChangeLogs { get; set; } = new();
    }

    /// <summary>
    /// 变更详情
    /// </summary>
    public class ChangeDetail
    {
        public string FieldName { get; set; } = "";
        public string? OldValue { get; set; }
        public string? NewValue { get; set; }
    }
}
