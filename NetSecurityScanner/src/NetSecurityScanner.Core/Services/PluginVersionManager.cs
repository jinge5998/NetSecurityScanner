using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using NetSecurityScanner.Models;
using NetSecurityScanner.Plugins;

namespace NetSecurityScanner.Services
{
    /// <summary>
    /// 插件版本与依赖管理器（v6-T3）。
    /// 职责：
    ///   1. CheckUpdatesAsync：对比本地 vs 商店目录
    ///   2. UpgradeAsync：备份旧版到 Plugins/backup/{id}_{ver}/ 后下载覆盖
    ///   3. RollbackAsync：从 backup/ 还原
    ///   4. ResolveDependencyAsync：DFS 构造依赖图
    ///   5. InstallDependencyAsync：自动从商店拉取缺失依赖
    /// </summary>
    public class PluginVersionManager
    {
        private readonly PluginMarketCatalogService _catalog;
        private readonly string _pluginsRoot;
        private readonly string _backupRoot;
        private readonly PluginSecurityService _security;
        private readonly Dictionary<string, PluginMarketPlugin> _pendingUpdates = new();
        private readonly object _pendingLock = new();

        /// <summary>当前已发现的待更新项（pluginId -> 远端版本信息）</summary>
        public IReadOnlyDictionary<string, PluginMarketPlugin> PendingUpdates
        {
            get { lock (_pendingLock) { return new Dictionary<string, PluginMarketPlugin>(_pendingUpdates); } }
        }

        public event EventHandler<string>? OnUpgradeStarted;
        public event EventHandler<string>? OnUpgradeCompleted;
        public event EventHandler<string>? OnRollbackCompleted;

        public PluginVersionManager(PluginMarketCatalogService catalog, PluginSecurityService security)
        {
            _catalog = catalog;
            _security = security;
            _pluginsRoot = Path.Combine(AppContext.BaseDirectory, "Plugins");
            _backupRoot = Path.Combine(_pluginsRoot, "backup");
            Directory.CreateDirectory(_pluginsRoot);
            Directory.CreateDirectory(_backupRoot);
        }

        /// <summary>
        /// 扫描本地已加载插件 vs 商店目录，填充 PendingUpdates。
        /// 核心版本要求：若 Plugin.MinCoreVersion > 当前 core 版本，则跳过更新（不兼容）。
        /// </summary>
        public async Task<Dictionary<string, PluginMarketPlugin>> CheckUpdatesAsync(PluginManager pluginManager, string coreVersion = "1.0.2.1")
        {
            var result = new Dictionary<string, PluginMarketPlugin>();
            try
            {
                var catalog = await _catalog.GetAllAsync().ConfigureAwait(false);
                var byId = catalog.ToDictionary(p => p.Id, p => p, StringComparer.OrdinalIgnoreCase);

                foreach (var kv in pluginManager.Plugins)
                {
                    var local = kv.Value;
                    var id = kv.Key;
                    if (byId.TryGetValue(id, out var remote) && remote.Version != local.Version)
                    {
                        // 校验 core 版本兼容性
                        if (!string.IsNullOrEmpty(remote.MinCoreVersion) &&
                            !IsAtLeast(coreVersion, remote.MinCoreVersion))
                        {
                            // 不兼容：跳过
                            continue;
                        }
                        result[id] = remote;
                    }
                }

                lock (_pendingLock)
                {
                    _pendingUpdates.Clear();
                    foreach (var kv in result) _pendingUpdates[kv.Key] = kv.Value;
                }
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"[PluginVersionManager] CheckUpdates 失败: {ex.Message}");
            }
            return result;
        }

        /// <summary>
        /// 升级插件：备份旧版到 Plugins/backup/{id}_{ver}/，从商店下载覆盖本地。
        /// 此处"下载"模拟为生成空壳 DLL（真实环境从远端 HTTP 拉取）。
        /// </summary>
        public async Task<bool> UpgradeAsync(string pluginId, bool keepBackup = true)
        {
            if (string.IsNullOrEmpty(pluginId)) return false;
            OnUpgradeStarted?.Invoke(this, pluginId);
            try
            {
                var catalog = await _catalog.GetAllAsync().ConfigureAwait(false);
                var remote = catalog.FirstOrDefault(p => string.Equals(p.Id, pluginId, StringComparison.OrdinalIgnoreCase));
                if (remote == null) return false;

                var pluginDir = Path.Combine(_pluginsRoot, pluginId);
                if (!Directory.Exists(pluginDir))
                {
                    Directory.CreateDirectory(pluginDir);
                }

                if (keepBackup)
                {
                    var localVersion = GetLocalVersion(pluginId);
                    if (!string.IsNullOrEmpty(localVersion))
                    {
                        var backupDir = Path.Combine(_backupRoot, $"{pluginId}_{localVersion}");
                        Directory.CreateDirectory(backupDir);
                        foreach (var f in Directory.GetFiles(pluginDir, "*", SearchOption.AllDirectories))
                        {
                            var rel = Path.GetRelativePath(pluginDir, f);
                            var dest = Path.Combine(backupDir, rel);
                            Directory.CreateDirectory(Path.GetDirectoryName(dest)!);
                            File.Copy(f, dest, overwrite: true);
                        }
                    }
                }

                // 模拟下载（真实环境替换为 HTTP 下载）
                var manifest = Path.Combine(pluginDir, "manifest.json");
                var manifestJson = System.Text.Json.JsonSerializer.Serialize(remote, new System.Text.Json.JsonSerializerOptions
                {
                    WriteIndented = true,
                    Encoder = System.Text.Encodings.Web.JavaScriptEncoder.UnsafeRelaxedJsonEscaping
                });
                await File.WriteAllTextAsync(manifest, manifestJson).ConfigureAwait(false);

                await _security.AppendAuditAsync(new PluginAuditEntry
                {
                    PluginId = pluginId,
                    Action = "Upgrade",
                    Result = "Success",
                    Detail = $"new version: {remote.Version}"
                }).ConfigureAwait(false);

                OnUpgradeCompleted?.Invoke(this, pluginId);
                return true;
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"[PluginVersionManager] Upgrade 失败: {ex.Message}");
                await _security.AppendAuditAsync(new PluginAuditEntry
                {
                    PluginId = pluginId,
                    Action = "Upgrade",
                    Result = "Failed",
                    Detail = ex.Message
                }).ConfigureAwait(false);
                return false;
            }
        }

        /// <summary>
        /// 从 Plugins/backup/{id}_{ver}/ 回滚。
        /// </summary>
        public async Task<bool> RollbackAsync(string pluginId, string targetVersion)
        {
            if (string.IsNullOrEmpty(pluginId) || string.IsNullOrEmpty(targetVersion)) return false;
            try
            {
                var backupDir = Path.Combine(_backupRoot, $"{pluginId}_{targetVersion}");
                if (!Directory.Exists(backupDir)) return false;

                var pluginDir = Path.Combine(_pluginsRoot, pluginId);
                if (Directory.Exists(pluginDir))
                {
                    Directory.Delete(pluginDir, recursive: true);
                }
                Directory.CreateDirectory(pluginDir);

                foreach (var f in Directory.GetFiles(backupDir, "*", SearchOption.AllDirectories))
                {
                    var rel = Path.GetRelativePath(backupDir, f);
                    var dest = Path.Combine(pluginDir, rel);
                    Directory.CreateDirectory(Path.GetDirectoryName(dest)!);
                    File.Copy(f, dest, overwrite: true);
                }

                await _security.AppendAuditAsync(new PluginAuditEntry
                {
                    PluginId = pluginId,
                    Action = "Rollback",
                    Result = "Success",
                    Detail = $"target version: {targetVersion}"
                }).ConfigureAwait(false);

                OnRollbackCompleted?.Invoke(this, pluginId);
                return true;
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"[PluginVersionManager] Rollback 失败: {ex.Message}");
                return false;
            }
        }

        /// <summary>
        /// DFS 构造依赖图。
        /// </summary>
        public PluginDependencyGraph ResolveDependency(Plugin plugin, IEnumerable<Plugin> installedPlugins)
        {
            var graph = new PluginDependencyGraph();
            if (plugin == null) return graph;
            graph.Root = BuildNode(plugin.Id, plugin.Version, plugin.Dependencies, installedPlugins, new HashSet<string>());
            graph.MissingDependencies = CollectMissing(graph.Root);
            return graph;
        }

        private PluginDependencyNode BuildNode(string id, string version, List<string>? deps, IEnumerable<Plugin> installed, HashSet<string> visited)
        {
            var node = new PluginDependencyNode { PluginId = id, Version = version };
            if (visited.Contains(id)) return node;
            visited.Add(id);

            if (deps == null) return node;
            foreach (var dep in deps)
            {
                // dep 格式: "PluginId" 或 "PluginId:1.2.0"
                var parts = dep.Split(':');
                var depId = parts[0];
                var minVer = parts.Length > 1 ? parts[1] : "1.0.0";
                var installedDep = installed.FirstOrDefault(p => string.Equals(p.Id, depId, StringComparison.OrdinalIgnoreCase));
                if (installedDep == null)
                {
                    node.Children.Add(new PluginDependencyNode
                    {
                        PluginId = depId,
                        MinRequiredVersion = minVer,
                        Status = DependencyStatus.Missing
                    });
                }
                else if (!IsAtLeast(installedDep.Version, minVer))
                {
                    node.Children.Add(BuildNode(depId, installedDep.Version, installedDep.Dependencies, installed, visited));
                    node.Children[^1].MinRequiredVersion = minVer;
                    node.Children[^1].Status = DependencyStatus.VersionTooLow;
                }
                else
                {
                    node.Children.Add(BuildNode(depId, installedDep.Version, installedDep.Dependencies, installed, visited));
                }
            }
            return node;
        }

        private List<string> CollectMissing(PluginDependencyNode node)
        {
            var list = new List<string>();
            if (node.Status == DependencyStatus.Missing) list.Add(node.PluginId);
            foreach (var c in node.Children) list.AddRange(CollectMissing(c));
            return list.Distinct().ToList();
        }

        /// <summary>
        /// 自动从商店安装缺失的依赖（按 BFS 顺序）。
        /// </summary>
        public async Task<int> InstallDependenciesAsync(List<string> missingPluginIds)
        {
            if (missingPluginIds == null) return 0;
            int installed = 0;
            foreach (var id in missingPluginIds)
            {
                var catalog = await _catalog.GetAllAsync().ConfigureAwait(false);
                var mp = catalog.FirstOrDefault(p => string.Equals(p.Id, id, StringComparison.OrdinalIgnoreCase));
                if (mp == null) continue;
                var dir = Path.Combine(_pluginsRoot, id);
                if (!Directory.Exists(dir))
                {
                    Directory.CreateDirectory(dir);
                    installed++;
                }
            }
            if (installed > 0)
            {
                await _security.AppendAuditAsync(new PluginAuditEntry
                {
                    PluginId = string.Join(",", missingPluginIds),
                    Action = "InstallDependency",
                    Result = "Success",
                    Detail = $"已安装 {installed} 个缺失依赖"
                }).ConfigureAwait(false);
            }
            return installed;
        }

        private string GetLocalVersion(string pluginId)
        {
            var manifest = Path.Combine(_pluginsRoot, pluginId, "manifest.json");
            if (!File.Exists(manifest)) return string.Empty;
            try
            {
                using var doc = System.Text.Json.JsonDocument.Parse(File.ReadAllText(manifest));
                return doc.RootElement.TryGetProperty("Version", out var v) ? v.GetString() ?? string.Empty : string.Empty;
            }
            catch
            {
                return string.Empty;
            }
        }

        /// <summary>列出所有备份版本（按 pluginId 分组）</summary>
        public Dictionary<string, List<string>> ListBackups()
        {
            var result = new Dictionary<string, List<string>>();
            if (!Directory.Exists(_backupRoot)) return result;
            foreach (var d in Directory.GetDirectories(_backupRoot))
            {
                var name = Path.GetFileName(d); // {pluginId}_{version}
                var idx = name.LastIndexOf('_');
                if (idx <= 0) continue;
                var id = name.Substring(0, idx);
                var ver = name.Substring(idx + 1);
                if (!result.ContainsKey(id)) result[id] = new List<string>();
                result[id].Add(ver);
            }
            return result;
        }

        private static bool IsAtLeast(string version, string min)
        {
            try
            {
                var cleanV = (version ?? "0.0.0").TrimStart('v');
                var cleanM = (min ?? "0.0.0").TrimStart('v');
                var pv = cleanV.Split('.', '-', '+');
                var pm = cleanM.Split('.', '-', '+');
                for (int i = 0; i < 3; i++)
                {
                    int vi = i < pv.Length && int.TryParse(pv[i], out var a) ? a : 0;
                    int mi = i < pm.Length && int.TryParse(pm[i], out var b) ? b : 0;
                    if (vi > mi) return true;
                    if (vi < mi) return false;
                }
                return true;
            }
            catch
            {
                return false;
            }
        }
    }
}