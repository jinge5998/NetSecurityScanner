using NetSecurityScanner.Models;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;

namespace NetSecurityScanner.Plugins
{
    /// <summary>
    /// 插件管理器
    /// </summary>
    public class PluginManager
    {
        private readonly Dictionary<string, IVulnerabilityScannerPlugin> _plugins;
        private readonly Dictionary<string, PluginConfig> _pluginConfigs;
        private readonly string _pluginsDirectory;
        private readonly string _configFilePath;

        public PluginManager()
        {
            _plugins = new Dictionary<string, IVulnerabilityScannerPlugin>();
            _pluginConfigs = new Dictionary<string, PluginConfig>();
            _pluginsDirectory = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "Plugins");
            _configFilePath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "plugin_configs.json");

            // 确保插件目录存在
            if (!Directory.Exists(_pluginsDirectory))
            {
                Directory.CreateDirectory(_pluginsDirectory);
            }

            LoadPluginConfigs();
        }

        /// <summary>
        /// 获取所有已加载的插件
        /// </summary>
        public IReadOnlyDictionary<string, IVulnerabilityScannerPlugin> Plugins => _plugins;

        /// <summary>
        /// 加载所有插件
        /// </summary>
        public async Task LoadAllPluginsAsync()
        {
            // 加载内置插件
            LoadBuiltInPlugins();

            // 加载外部插件DLL
            await LoadExternalPluginsAsync();
        }

        /// <summary>
        /// 加载内置插件
        /// </summary>
        private void LoadBuiltInPlugins()
        {
            // 注册内置插件
            var builtInPlugins = new List<IVulnerabilityScannerPlugin>
            {
                new DefaultPlugins.WeakPasswordPlugin(),
                new DefaultPlugins.PortServicePlugin(),
                new DefaultPlugins.SslTlsPlugin(),
                new DefaultPlugins.WebVulnPlugin()
            };

            foreach (var plugin in builtInPlugins)
            {
                RegisterPlugin(plugin);
            }
        }

        /// <summary>
        /// 加载外部插件
        /// </summary>
        private async Task LoadExternalPluginsAsync()
        {
            if (!Directory.Exists(_pluginsDirectory))
                return;

            var pluginFiles = Directory.GetFiles(_pluginsDirectory, "*.dll");

            foreach (var file in pluginFiles)
            {
                try
                {
                    await LoadPluginFromAssemblyAsync(file);
                }
                catch (Exception ex)
                {
                    System.Diagnostics.Debug.WriteLine($"加载插件失败 {file}: {ex.Message}");
                }
            }
        }

        /// <summary>
        /// 从程序集加载插件
        /// </summary>
        private async Task LoadPluginFromAssemblyAsync(string assemblyPath)
        {
            var assembly = Assembly.LoadFrom(assemblyPath);
            var pluginTypes = assembly.GetTypes()
                .Where(t => typeof(IVulnerabilityScannerPlugin).IsAssignableFrom(t) && !t.IsInterface && !t.IsAbstract);

            foreach (var type in pluginTypes)
            {
                try
                {
                    var plugin = (IVulnerabilityScannerPlugin)Activator.CreateInstance(type);
                    
                    // 加载插件配置
                    if (_pluginConfigs.TryGetValue(plugin.PluginId, out var config))
                    {
                        await plugin.InitializeAsync(config.Parameters);
                    }
                    
                    RegisterPlugin(plugin);
                }
                catch (Exception ex)
                {
                    System.Diagnostics.Debug.WriteLine($"创建插件实例失败 {type.Name}: {ex.Message}");
                }
            }
        }

        /// <summary>
        /// 注册插件
        /// </summary>
        public void RegisterPlugin(IVulnerabilityScannerPlugin plugin)
        {
            if (!_plugins.ContainsKey(plugin.PluginId))
            {
                _plugins[plugin.PluginId] = plugin;
            }
        }

        /// <summary>
        /// 卸载插件
        /// </summary>
        public async Task<bool> UnloadPluginAsync(string pluginId)
        {
            if (_plugins.TryGetValue(pluginId, out var plugin))
            {
                await plugin.UnloadAsync();
                _plugins.Remove(pluginId);
                return true;
            }
            return false;
        }

        /// <summary>
        /// 获取适用于目标的插件
        /// </summary>
        public async Task EnablePluginAsync(string pluginId)
        {
            if (_pluginConfigs.TryGetValue(pluginId, out var config))
            {
                config.IsEnabled = true;
                await SaveConfigsAsync();
            }
        }

        public async Task DisablePluginAsync(string pluginId)
        {
            if (_pluginConfigs.TryGetValue(pluginId, out var config))
            {
                config.IsEnabled = false;
                await SaveConfigsAsync();
            }
        }

        public async Task<List<IVulnerabilityScannerPlugin>> GetApplicablePluginsAsync(string target, int port, string serviceType)
        {
            var applicablePlugins = new List<IVulnerabilityScannerPlugin>();

            foreach (var plugin in _plugins.Values)
            {
                try
                {
                    if (await plugin.CanScanAsync(target, port))
                    {
                        applicablePlugins.Add(plugin);
                    }
                }
                catch (Exception ex)
                {
                    System.Diagnostics.Debug.WriteLine($"[PluginManager] 检查插件适用性失败: {ex.Message}");
                }
            }

            applicablePlugins = applicablePlugins.Where(p =>
            {
                if (_pluginConfigs.TryGetValue(p.PluginId, out var config))
                    return config.IsEnabled;
                return true;
            }).ToList();

            return applicablePlugins;
        }

        /// <summary>
        /// 使用指定插件执行扫描
        /// </summary>
        public async Task<List<VulnerabilityResult>> ScanWithPluginAsync(
            string pluginId, 
            ScanContext context, 
            CancellationToken cancellationToken = default)
        {
            if (_plugins.TryGetValue(pluginId, out var plugin))
            {
                return await plugin.ScanAsync(context, cancellationToken);
            }

            return new List<VulnerabilityResult>();
        }

        /// <summary>
        /// 使用所有适用插件执行扫描
        /// </summary>
        public async Task<List<VulnerabilityResult>> ScanWithAllPluginsAsync(
            ScanContext context,
            IProgress<string>? progress = null,
            CancellationToken cancellationToken = default)
        {
            var allResults = new List<VulnerabilityResult>();
            var applicablePlugins = await GetApplicablePluginsAsync(context.Target, context.Port, context.ServiceName);

            foreach (var plugin in applicablePlugins)
            {
                try
                {
                    progress?.Report($"正在使用插件 {plugin.Name} 扫描...");
                    
                    var results = await plugin.ScanAsync(context, cancellationToken);

                    var status = plugin.GetStatus();
                    status.ScanCount++;
                    status.VulnerabilityFound += results.Count;
                    status.LastScanTime = DateTime.Now;

                    allResults.AddRange(results);
                }
                catch (Exception ex)
                {
                    progress?.Report($"插件 {plugin.Name} 扫描失败: {ex.Message}");
                }
            }

            return allResults;
        }

        /// <summary>
        /// 更新插件配置
        /// </summary>
        public async Task<bool> UpdatePluginConfigAsync(string pluginId, Dictionary<string, object> config)
        {
            if (_plugins.TryGetValue(pluginId, out var plugin))
            {
                var success = await plugin.InitializeAsync(config);
                if (success)
                {
                    _pluginConfigs[pluginId] = new PluginConfig
                    {
                        PluginId = pluginId,
                        Parameters = config,
                        LastUpdated = DateTime.Now
                    };
                    SavePluginConfigs();
                }
                return success;
            }
            return false;
        }

        /// <summary>
        /// 获取插件配置
        /// </summary>
        public Dictionary<string, object>? GetPluginConfig(string pluginId)
        {
            if (_pluginConfigs.TryGetValue(pluginId, out var config))
            {
                return config.Parameters;
            }
            return null;
        }

        /// <summary>
        /// 加载插件配置
        /// </summary>
        private void LoadPluginConfigs()
        {
            try
            {
                if (File.Exists(_configFilePath))
                {
                    var json = File.ReadAllText(_configFilePath);
                    var configs = JsonSerializer.Deserialize<List<PluginConfig>>(json);
                    if (configs != null)
                    {
                        foreach (var config in configs)
                        {
                            _pluginConfigs[config.PluginId] = config;
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"[PluginManager] 加载插件配置失败: {ex.Message}");
            }
        }

        /// <summary>
        /// 保存插件配置
        /// </summary>
        private void SavePluginConfigs()
        {
            try
            {
                var json = JsonSerializer.Serialize(_pluginConfigs.Values.ToList(), new JsonSerializerOptions
                {
                    WriteIndented = true
                });
                File.WriteAllText(_configFilePath, json);
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"[PluginManager] 保存插件配置失败: {ex.Message}");
            }
        }

        private async Task SaveConfigsAsync()
        {
            try
            {
                var configsPath = Path.Combine(_pluginsDirectory, "plugin_configs.json");
                var json = JsonSerializer.Serialize(_pluginConfigs, new JsonSerializerOptions { WriteIndented = true });
                await File.WriteAllTextAsync(configsPath, json);
            }
            catch { }
        }

        /// <summary>
        /// 安装插件
        /// </summary>
        public async Task<bool> InstallPluginAsync(string pluginFilePath)
        {
            try
            {
                var fileName = Path.GetFileName(pluginFilePath);
                var destPath = Path.Combine(_pluginsDirectory, fileName);
                
                File.Copy(pluginFilePath, destPath, true);
                await LoadPluginFromAssemblyAsync(destPath);
                
                return true;
            }
            catch
            {
                return false;
            }
        }

        /// <summary>
        /// 卸载插件
        /// </summary>
        public async Task<bool> UninstallPluginAsync(string pluginId)
        {
            var plugin = _plugins.TryGetValue(pluginId, out var p) ? p : null;

            var success = await UnloadPluginAsync(pluginId);
            
            if (_pluginConfigs.ContainsKey(pluginId))
            {
                _pluginConfigs.Remove(pluginId);
                SavePluginConfigs();
            }

            if (plugin != null && !plugin.PluginId.StartsWith("builtin."))
            {
                var pluginAssembly = plugin.GetType().Assembly;
                string? dllPath = pluginAssembly.Location;
                if (!string.IsNullOrEmpty(dllPath) && dllPath.StartsWith(_pluginsDirectory))
                {
                    try
                    {
                        File.Delete(dllPath);
                    }
                    catch { }
                }
            }

            return success;
        }

        public async Task<List<VulnerabilityResult>> ScanWithPluginsForTargetAsync(string targetIp, List<int> openPorts, Dictionary<string, string>? pluginConfigs = null, string? traceId = null)
        {
            var allResults = new List<VulnerabilityResult>();

            // v7：Telemetry - 启动根 Span（如果传入了 traceId 则复用，否则新开）
            string rootSpanId;
            string actualTraceId;
            try
            {
                var governor = NetSecurityScanner.Services.PluginGovernor.Instance;
                if (governor.IsInitialized)
                {
                    if (!string.IsNullOrEmpty(traceId))
                    {
                        // 透传：从 Orchestrator 传下来的 TraceId
                        actualTraceId = traceId;
                        rootSpanId = governor.Telemetry.BeginSpan(actualTraceId, null, "ScanWithPlugins", null, null);
                    }
                    else
                    {
                        (actualTraceId, rootSpanId) = governor.Telemetry.BeginTrace($"scan::{targetIp}", targetIp);
                    }
                }
                else
                {
                    actualTraceId = traceId ?? Guid.NewGuid().ToString("N");
                    rootSpanId = string.Empty;
                }
            }
            catch { actualTraceId = traceId ?? Guid.NewGuid().ToString("N"); rootSpanId = string.Empty; }

            try
            {
                var enabledPlugins = _plugins.Values.Where(p =>
                {
                    if (_pluginConfigs.TryGetValue(p.PluginId, out var config))
                        return config.IsEnabled;
                    return true;
                }).ToList();

                foreach (var plugin in enabledPlugins)
                {
                    var applicablePorts = new List<int>();

                    foreach (var port in openPorts)
                    {
                        try
                        {
                            if (await plugin.CanScanAsync(targetIp, port))
                            {
                                applicablePorts.Add(port);
                            }
                        }
                        catch { }
                    }

                    if (!applicablePorts.Any()) continue;

                    foreach (var port in applicablePorts)
                    {
                        // v7：Telemetry - 为每个 (plugin, port) 创建子 Span
                        string pluginSpanId = string.Empty;
                        try
                        {
                            var governor = NetSecurityScanner.Services.PluginGovernor.Instance;
                            if (governor.IsInitialized && !string.IsNullOrEmpty(rootSpanId))
                            {
                                pluginSpanId = governor.Telemetry.BeginSpan(actualTraceId, rootSpanId, $"plugin::{plugin.PluginId}", plugin.PluginId, port);
                            }
                        }
                        catch { }

                        // v6：埋点 HealthMonitor
                        var sw = System.Diagnostics.Stopwatch.StartNew();
                        bool pluginSuccess = true;
                        Exception? pluginException = null;
                        bool timedOut = false;
                        int vulnCount = 0;

                        try
                        {
                            try
                            {
                                var governor = NetSecurityScanner.Services.PluginGovernor.Instance;
                                if (governor.IsInitialized)
                                {
                                    governor.Health.BeginSample(plugin.PluginId);
                                }
                            }
                            catch { }

                            var pluginConfigObj = pluginConfigs?.ToDictionary(kvp => kvp.Key, kvp => (object)kvp.Value) ?? new Dictionary<string, object>();

                            var context = new ScanContext
                            {
                                Target = targetIp,
                                Port = port,
                                Timeout = 10000,
                                PluginConfig = pluginConfigObj
                            };

                            var results = await plugin.ScanAsync(context);

                            var status = plugin.GetStatus();
                            status.ScanCount++;
                            status.VulnerabilityFound += results.Count;
                            status.LastScanTime = DateTime.Now;
                            vulnCount = results.Count;

                            foreach (var result in results)
                            {
                                result.PluginId = plugin.PluginId;
                                result.PluginName = plugin.Name;
                                // 写 TraceId 便于反查
                                try
                                {
                                    var governor = NetSecurityScanner.Services.PluginGovernor.Instance;
                                    if (governor.IsInitialized && !string.IsNullOrEmpty(actualTraceId))
                                    {
                                        var tag = $"traceId={actualTraceId}";
                                        result.Description = string.IsNullOrEmpty(result.Description)
                                            ? tag
                                            : $"{result.Description} | {tag}";
                                    }
                                }
                                catch { }
                            }

                            allResults.AddRange(results);

                            // v7：Telemetry - 结束子 Span（成功）
                            try
                            {
                                var governor = NetSecurityScanner.Services.PluginGovernor.Instance;
                                if (governor.IsInitialized && !string.IsNullOrEmpty(pluginSpanId))
                                {
                                    governor.Telemetry.EndSpan(pluginSpanId, "Ok", null, new Dictionary<string, string>
                                    {
                                        { "vulns", vulnCount.ToString() },
                                        { "elapsedMs", sw.ElapsedMilliseconds.ToString() }
                                    });
                                }
                            }
                            catch { }
                        }
                        catch (OperationCanceledException)
                        {
                            pluginSuccess = false;
                            timedOut = true;
                            pluginException = new TimeoutException("插件执行超时");

                            // v7：Telemetry - 结束子 Span（Timeout）
                            try
                            {
                                var governor = NetSecurityScanner.Services.PluginGovernor.Instance;
                                if (governor.IsInitialized && !string.IsNullOrEmpty(pluginSpanId))
                                {
                                    governor.Telemetry.EndSpan(pluginSpanId, "Timeout", "插件执行超时");
                                }
                            }
                            catch { }
                        }
                        catch (Exception ex)
                        {
                            pluginSuccess = false;
                            pluginException = ex;

                            // v7：Telemetry - 结束子 Span（Error）
                            try
                            {
                                var governor = NetSecurityScanner.Services.PluginGovernor.Instance;
                                if (governor.IsInitialized && !string.IsNullOrEmpty(pluginSpanId))
                                {
                                    governor.Telemetry.EndSpan(pluginSpanId, "Error", ex.Message);
                                }
                            }
                            catch { }
                        }
                        finally
                        {
                            sw.Stop();
                            try
                            {
                                var governor = NetSecurityScanner.Services.PluginGovernor.Instance;
                                if (governor.IsInitialized)
                                {
                                    governor.Health.EndSample(plugin.PluginId, pluginSuccess, pluginException, sw.ElapsedMilliseconds, timedOut);
                                }
                            }
                            catch { }
                        }
                    }
                }
            }
            finally
            {
                // v7：Telemetry - 关闭根 Span
                try
                {
                    var governor = NetSecurityScanner.Services.PluginGovernor.Instance;
                    if (governor.IsInitialized && !string.IsNullOrEmpty(rootSpanId))
                    {
                        governor.Telemetry.EndSpan(rootSpanId, "Ok", null, new Dictionary<string, string>
                        {
                            { "totalVulns", allResults.Count.ToString() }
                        });
                    }
                }
                catch { }
            }

            return allResults;
        }
    }

    /// <summary>
    /// 插件配置
    /// </summary>
    public class PluginConfig
    {
        public string PluginId { get; set; } = string.Empty;
        public Dictionary<string, object> Parameters { get; set; } = new();
        public DateTime LastUpdated { get; set; }
        public bool IsEnabled { get; set; } = true;
    }
}
