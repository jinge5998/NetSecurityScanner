using System;
using System.Reflection;
using System.Runtime.Loader;

namespace NetSecurityScanner.Core
{
  /// <summary>
  /// 可回收的 AssemblyLoadContext（v3）。
  /// 继承 AssemblyLoadContext 并设置 IsCollectible = true，允许在运行时 Unload，
  /// 从而真正释放插件 DLL 的文件句柄。
  /// </summary>
  public class CollectibleAssemblyLoadContext : AssemblyLoadContext
  {
    private readonly string _pluginDir;

    public CollectibleAssemblyLoadContext(string pluginDir) : base(isCollectible: true)
    {
      _pluginDir = pluginDir;
    }

    /// <summary>
    /// 解析依赖：优先在插件目录查找，再回退到默认上下文。
    /// </summary>
    protected override Assembly? Load(AssemblyName assemblyName)
    {
      // 优先尝试在插件目录加载同名 DLL（隔离插件自有依赖）
      var depPath = System.IO.Path.Combine(_pluginDir, $"{assemblyName.Name}.dll");
      if (System.IO.File.Exists(depPath))
      {
        return LoadFromAssemblyPath(depPath);
      }
      // 回退到默认加载上下文（共享主程序已加载的程序集）
      return Default.LoadFromAssemblyName(assemblyName);
    }
  }
}
