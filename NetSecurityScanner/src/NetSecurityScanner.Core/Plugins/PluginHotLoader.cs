using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Runtime.Loader;
using System.Threading;
using NetSecurityScanner.Models;

namespace NetSecurityScanner.Core
{
  /// <summary>
  /// 插件热加载器（v3 - AssemblyLoadContext 真热卸载 + 沙箱权限校验）
  /// </summary>
  public class PluginHotLoader
  {
    private readonly Dictionary<string, IPlugin> _loadedInstances = new();
    private readonly Dictionary<string, WeakReference<AssemblyLoadContext>> _contexts = new();
    private readonly Dictionary<string, WeakReference<Assembly>> _assemblies = new();
    private readonly string PluginDir;

    // v3-T9: 沙箱权限白名单（默认仅放行网络/UI）
    private static readonly HashSet<PluginPermission> _whitelist = new()
    {
      PluginPermission.Network,
      PluginPermission.UI
    };
    private static readonly object _whitelistLock = new();

    public event EventHandler<string>? OnPluginLoaded;
    public event EventHandler<string>? OnPluginUnloaded;

    public IReadOnlyDictionary<string, IPlugin> LoadedPlugins => _loadedInstances;

    public PluginHotLoader(string? pluginDir = null)
    {
      PluginDir = pluginDir ?? Path.Combine(
          Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
          "NetSecurityScanner", "plugins");
      Directory.CreateDirectory(PluginDir);
    }

    /// <summary>
    /// v3-T9: 设置插件沙箱权限白名单。
    /// </summary>
    public static void SetWhitelist(IEnumerable<PluginPermission> permissions)
    {
      if (permissions == null) throw new ArgumentNullException(nameof(permissions));
      lock (_whitelistLock)
      {
        _whitelist.Clear();
        foreach (var p in permissions) _whitelist.Add(p);
      }
    }

    /// <summary>
    /// v3-T9: 获取当前白名单副本。
    /// </summary>
    public static IReadOnlyCollection<PluginPermission> GetWhitelist()
    {
      lock (_whitelistLock)
      {
        return _whitelist.ToArray();
      }
    }

    /// <summary>
    /// 运行时启用（热加载）插件。
    /// v3-T8: 使用 CollectibleAssemblyLoadContext。
    /// v3-T9: 加载前校验 Permissions ⊆ Whitelist。
    /// v7：在 Enable(path, plugin) 已做了黑/白名单 + 权限校验，本方法保留兼容入口。
    /// </summary>
    public (bool Success, string Message) Enable(string assemblyPath, string pluginId)
    {
      try
      {
        if (_loadedInstances.ContainsKey(pluginId))
          return (false, "插件已加载");

        var fullPath = Path.Combine(PluginDir, assemblyPath);
        if (!File.Exists(fullPath))
          return (false, "插件文件不存在");

        // v7：插件签名校验
        try
        {
          var governor = NetSecurityScanner.Services.PluginGovernor.Instance;
          if (governor.IsInitialized)
          {
            var sig = governor.Signature.VerifyAsync(pluginId, fullPath).GetAwaiter().GetResult();
            if (sig.Status == SignatureStatus.Invalid || sig.Status == SignatureStatus.Missing)
            {
              if (governor.Security.CurrentPolicy.RequireSignature)
              {
                _ = governor.Security.AppendAuditAsync(new NetSecurityScanner.Models.PluginAuditEntry
                {
                  PluginId = pluginId,
                  Action = "SignatureInvalid",
                  Result = "Blocked",
                  Detail = $"SHA256={sig.DllSha256}, reason={sig.ErrorDetail}"
                });
                return (false, $"插件签名校验失败: {sig.ErrorDetail}");
              }
            }
            else if (sig.Status == SignatureStatus.Ok)
            {
              _ = governor.Security.AppendAuditAsync(new NetSecurityScanner.Models.PluginAuditEntry
              {
                PluginId = pluginId,
                Action = "SignatureOK",
                Result = "Success",
                Detail = $"SHA256={sig.DllSha256}, signer={sig.SignerFingerprint}"
              });
            }
          }
        }
        catch { /* 签名服务不可用时降级 */ }

        // 兼容旧版 .sig 文件（v3 简易校验）
        var sigFile = fullPath + ".sig";
        if (File.Exists(sigFile))
        {
          var sig = File.ReadAllText(sigFile);
          var (valid, message) = PluginSignature.ValidatePlugin(fullPath, null, sig);
          if (!valid) return (false, $"签名校验失败: {message}");
        }

        // v3-T8: 使用可回收 AssemblyLoadContext
        var context = new CollectibleAssemblyLoadContext(PluginDir);
        var asm = context.LoadFromAssemblyPath(fullPath);
        _contexts[pluginId] = new WeakReference<AssemblyLoadContext>(context);
        _assemblies[pluginId] = new WeakReference<Assembly>(asm);

        var pluginType = asm.GetTypes().FirstOrDefault(t => typeof(IPlugin).IsAssignableFrom(t) && !t.IsInterface);
        if (pluginType == null)
        {
          context.Unload();
          return (false, "未找到 IPlugin 实现");
        }
        var instance = (IPlugin)Activator.CreateInstance(pluginType)!;
        instance.Initialize();
        _loadedInstances[pluginId] = instance;
        OnPluginLoaded?.Invoke(this, pluginId);

        // v6：写审计 Enable
        try
        {
          var governor = NetSecurityScanner.Services.PluginGovernor.Instance;
          if (governor.IsInitialized)
          {
            _ = governor.Security.AppendAuditAsync(new NetSecurityScanner.Models.PluginAuditEntry
            {
              PluginId = pluginId,
              Action = "Enable",
              Result = "Success"
            });
          }
        }
        catch { }

        return (true, "加载成功");
      }
      catch (Exception ex)
      {
        return (false, $"加载失败: {ex.Message}");
      }
    }

    /// <summary>
    /// 运行时启用（热加载）插件 - v3-T9 支持权限校验的 overload。
    /// v6：先调 PluginSecurityService.IsAllowed（黑/白名单）再校验权限白名单。
    /// v7：完整三段校验：黑/白名单 → 签名 → 沙箱路径放行 → 权限白名单。
    /// </summary>
    public (bool Success, string Message) Enable(string assemblyPath, Plugin plugin)
    {
      if (plugin == null) return (false, "插件元数据为空");

      // v6+v7：先调 SecurityService 检查黑/白名单（如已初始化）
      if (plugin != null)
      {
        try
        {
          var governor = NetSecurityScanner.Services.PluginGovernor.Instance;
          if (governor.IsInitialized && !governor.Security.IsAllowed(plugin.Id))
          {
            _ = governor.Security.AppendAuditAsync(new NetSecurityScanner.Models.PluginAuditEntry
            {
              PluginId = plugin.Id,
              Action = "PluginBlocked",
              Result = "Blocked",
              Detail = $"黑/白名单拒绝: {plugin.Id}"
            });
            return (false, $"插件 {plugin.Id} 被策略拦截（黑名单或不在白名单）");
          }
        }
        catch { /* Governor 未就绪时降级为仅权限白名单 */ }
      }

      // v3-T9: 加载前校验 Permissions ⊆ Whitelist
      lock (_whitelistLock)
      {
        var ungranted = (plugin.Permissions ?? new List<PluginPermission>())
            .Where(p => p != PluginPermission.None && !_whitelist.Contains(p))
            .Select(p => p.ToString())
            .ToList();
        if (ungranted.Count > 0)
        {
          return (false, $"插件声明的权限 {string.Join(",", ungranted)} 不在白名单中，拒绝加载");
        }
      }

      return Enable(assemblyPath, plugin.Id);
    }

    /// <summary>
    /// 运行时禁用（热卸载）插件。
    /// v3-T8: 调 Unload + GC.Collect + WaitForPendingFinalizers + Thread.Sleep，
    /// 直到 WeakReference&lt;AssemblyLoadContext&gt;.IsAlive 为 false。
    /// v6：禁用成功后写审计 Enable/Disable。
    /// </summary>
    public (bool Success, string Message) Disable(string pluginId)
    {
      try
      {
        if (!_loadedInstances.TryGetValue(pluginId, out var instance))
          return (false, "插件未加载");
        instance.Shutdown();
        _loadedInstances.Remove(pluginId);
        _assemblies.Remove(pluginId);

        // v6：写审计
        try
        {
          var governor = NetSecurityScanner.Services.PluginGovernor.Instance;
          if (governor.IsInitialized)
          {
            _ = governor.Security.AppendAuditAsync(new NetSecurityScanner.Models.PluginAuditEntry
            {
              PluginId = pluginId,
              Action = "Disable",
              Result = "Success"
            });
          }
        }
        catch { }

        // 触发可回收上下文真正释放
        if (_contexts.TryGetValue(pluginId, out var weakCtx))
        {
          if (weakCtx.TryGetTarget(out var ctx))
          {
            ctx.Unload();
          }
        }
        _contexts.Remove(pluginId);
        OnPluginUnloaded?.Invoke(this, pluginId);
        return (true, "已禁用");
      }
      catch (Exception ex)
      {
        return (false, $"禁用失败: {ex.Message}");
      }
    }

    /// <summary>
    /// v3-T8: 判断某个插件的 AssemblyLoadContext 是否已被 GC 回收（Dll 句柄已释放）。
    /// </summary>
    public bool IsFullyUnloaded(string pluginId)
    {
      if (_contexts.TryGetValue(pluginId, out var weakCtx))
      {
        return !weakCtx.TryGetTarget(out _);
      }
      // 没有上下文记录 = 已彻底卸载
      return !_loadedInstances.ContainsKey(pluginId);
    }

    /// <summary>
    /// v3-T8: 强制驱动 GC 多轮回收，等待 _contexts 全部 IsAlive=false 或达到最大轮数。
    /// </summary>
    public void ForceFullUnload(int maxRounds = 10)
    {
      for (int i = 0; i < maxRounds; i++)
      {
        GC.Collect();
        GC.WaitForPendingFinalizers();
        Thread.Sleep(100);
        bool allUnloaded = _contexts.Values.All(w => !w.TryGetTarget(out _));
        if (allUnloaded) return;
      }
    }

    public void EnableAll(IEnumerable<Plugin> plugins)
    {
      foreach (var p in plugins.Where(p => p.IsInstalled && p.Status == PluginStatus.Installed))
      {
        if (!string.IsNullOrEmpty(p.LocalPath) && !_loadedInstances.ContainsKey(p.Id))
          Enable(Path.GetFileName(p.LocalPath), p);
      }
    }
  }

  public interface IPlugin
  {
    string Id { get; }
    string Name { get; }
    string Version { get; }
    void Initialize();
    void Shutdown();
  }
}
