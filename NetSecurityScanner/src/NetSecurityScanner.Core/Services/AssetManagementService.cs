using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.Json;
using System.Threading.Tasks;
using NetSecurityScanner.Models;

namespace NetSecurityScanner.Services
{
    /// <summary>
    /// 资产管理服务（v1.0.1.2：写操作需 operatorName + 服务层权限校验）
    /// </summary>
    public class AssetManagementService
    {
        private readonly string _assetsFilePath;
        private List<Asset> _assets;
        private List<AssetChangeLog> _changeLogs;

        /// <summary>
        /// JSON 加载失败标记(防止损坏文件被空 list 覆盖)— v1.0.1.4 P0 修复
        /// </summary>
        private bool _loadFailed;

        /// <summary>
        /// 最后一次加载错误信息(供 UI 展示)
        /// </summary>
        public string? LastLoadError { get; private set; }

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
        /// 添加资产（需 Asset:Add 或管理员）
        /// </summary>
        public async Task<bool> AddAssetAsync(Asset asset, string operatorName)
        {
            var user = ResolveOperator(operatorName, Permission.AssetAdd);
            if (_assets.Any(a => a.IPAddress == asset.IPAddress))
            {
                return false;
            }

            asset.Id = Guid.NewGuid().ToString();
            asset.CreatedAt = DateTime.Now;
            asset.LastModified = DateTime.Now;
            asset.CreatedBy = user.Username;
            asset.LastModifiedBy = user.Username;
            _assets.Add(asset);

            // 记录变更日志
            await AddChangeLogAsync(new AssetChangeLog
            {
                AssetId = asset.Id,
                ChangeType = ChangeType.Create,
                FieldName = "Asset",
                NewValue = $"添加资产: {asset.Name} ({asset.IPAddress})",
                ChangedBy = user.Username,
                ChangedAt = DateTime.Now
            });

            SaveAssets();
            return true;
        }

        /// <summary>
        /// 更新资产（需 Asset:Edit 或管理员）
        /// </summary>
        public async Task<bool> UpdateAssetAsync(Asset asset, string operatorName)
        {
            var user = ResolveOperator(operatorName, Permission.AssetEdit);
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
                    ChangedBy = user.Username,
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
            existingAsset.LastModifiedBy = user.Username;

            SaveAssets();
            return true;
        }

        /// <summary>
        /// 删除资产（需 Asset:Delete 或管理员）
        /// </summary>
        public async Task<bool> DeleteAssetAsync(string id, string operatorName)
        {
            var user = ResolveOperator(operatorName, Permission.AssetDelete);
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
                ChangedBy = user.Username,
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
        /// 按状态筛选资产
        /// </summary>
        public List<Asset> GetAssetsByStatus(AssetStatus status)
        {
            return _assets.Where(a => a.Status == status).ToList();
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
        /// 获取所有变更日志（v1.0.1.2：变更日志窗口使用）
        /// </summary>
        public List<AssetChangeLog> GetAllChangeLogs()
        {
            return _changeLogs.OrderByDescending(c => c.ChangedAt).ToList();
        }

        /// <summary>
        /// 导入扫描结果为资产（需 Asset:Import 或管理员）
        /// </summary>
        public async Task<int> ImportFromScanResultsAsync(List<NetworkDevice> devices, string operatorName)
        {
            var user = ResolveOperator(operatorName, Permission.AssetImport);
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

                    if (await AddAssetAsync(asset, user.Username))
                    {
                        importedCount++;
                    }
                }
            }

            return importedCount;
        }

        /// <summary>
        /// 解析操作人：校验 operatorName 有效、对应会话存在、并具备所需权限。
        /// 任何不满足条件都会抛 UnauthorizedAccessException，由 UI 捕获提示。
        /// </summary>
        private User ResolveOperator(string operatorName, string requiredPermission)
        {
            if (string.IsNullOrWhiteSpace(operatorName))
            {
                throw new UnauthorizedAccessException("请先登录后再操作资产。");
            }

            var current = SessionContext.Instance.Current;
            if (current == null)
            {
                throw new UnauthorizedAccessException("会话已失效，请重新登录。");
            }

            if (!string.Equals(current.Username, operatorName, StringComparison.OrdinalIgnoreCase))
            {
                throw new UnauthorizedAccessException("操作人与当前登录账号不一致，请重新登录。");
            }

            if (current.IsAdmin)
            {
                return current;
            }

            if (string.IsNullOrEmpty(requiredPermission) ||
                current.Permissions == null ||
                !current.Permissions.Contains(requiredPermission))
            {
                throw new UnauthorizedAccessException($"需要 {requiredPermission} 权限。");
            }

            return current;
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
        /// 加载资产(损坏保护)— v1.0.1.4 P0 修复
        /// 失败时备份原文件,标记 _loadFailed=true,SaveAssets 会拒绝覆盖
        /// </summary>
        private void LoadAssets()
        {
            try
            {
                if (File.Exists(_assetsFilePath))
                {
                    var json = File.ReadAllText(_assetsFilePath);
                    var options = new JsonSerializerOptions { PropertyNameCaseInsensitive = true };
                    var data = JsonSerializer.Deserialize<AssetData>(json, options);
                    if (data != null)
                    {
                        _assets = data.Assets ?? new List<Asset>();
                        _changeLogs = data.ChangeLogs ?? new List<AssetChangeLog>();
                    }
                }
            }
            catch (Exception ex)
            {
                // 备份损坏文件
                try
                {
                    var backupPath = _assetsFilePath + ".corrupt-" + DateTime.Now.ToString("yyyyMMdd_HHmmss_fff") + ".bak";
                    if (File.Exists(_assetsFilePath))
                    {
                        File.Copy(_assetsFilePath, backupPath, overwrite: true);
                        LastLoadError = $"资产文件加载失败,已备份到 {backupPath}。错误: {ex.Message}";
                    }
                    else
                    {
                        LastLoadError = $"资产文件加载失败: {ex.Message}";
                    }
                }
                catch
                {
                    LastLoadError = $"资产文件加载失败,且备份失败: {ex.Message}";
                }

                _loadFailed = true;
                System.Diagnostics.Debug.WriteLine($"[AssetManagementService] 加载资产失败: {ex.Message}");
            }
        }

        /// <summary>
        /// 保存资产(损坏保护)— v1.0.1.4 P0 修复
        /// _loadFailed=true 时拒绝写文件,避免空 list 覆盖损坏原文件
        /// </summary>
        private void SaveAssets()
        {
            if (_loadFailed)
            {
                System.Diagnostics.Debug.WriteLine($"[AssetManagementService] 拒绝保存:JSON 加载失败,原文件已备份,需人工介入恢复");
                return;
            }

            try
            {
                var data = new AssetData
                {
                    Assets = _assets,
                    ChangeLogs = _changeLogs
                };
                var options = new JsonSerializerOptions { WriteIndented = true };
                var json = JsonSerializer.Serialize(data, options);
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
        public string? CreatedBy { get; set; }
        public string? LastModifiedBy { get; set; }
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
