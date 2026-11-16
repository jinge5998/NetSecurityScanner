namespace NetSecurityScanner.Models
{
  /// <summary>
  /// 插件沙箱权限声明（v3-T9）。
  /// 插件必须在元数据中声明它所需的权限，主程序加载前与白名单比对，
  /// 未在白名单内的权限将被拒绝加载。
  /// </summary>
  public enum PluginPermission
  {
    /// <summary>
    /// 无需任何权限
    /// </summary>
    None = 0,

    /// <summary>
    /// 网络访问（HTTP/TCP/UDP 等）
    /// </summary>
    Network = 1,

    /// <summary>
    /// 文件系统读写
    /// </summary>
    FileSystem = 2,

    /// <summary>
    /// 启动子进程 / 执行命令
    /// </summary>
    Process = 3,

    /// <summary>
    /// UI 渲染 / 窗口 / 控件
    /// </summary>
    UI = 4
  }
}
