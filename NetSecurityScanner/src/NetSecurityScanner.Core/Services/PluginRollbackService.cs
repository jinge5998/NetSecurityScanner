using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.Json;
using NetSecurityScanner.Models;

namespace NetSecurityScanner.Core
{
  /// <summary>
  /// 插件版本回滚服务（v3-T12）。
  /// 直接读写 PluginMarketServiceV2 持久化的 installed.json：
  ///   %LOCALAPPDATA%\NetSecurityScanner\data\plugin_market\installed.json
  /// 回滚时把当前 Version 改回 VersionHistory 倒数第二条的 Version，
  /// 并把当前 installed.json 备份到 installed.json.bak。
  /// </summary>
  public class PluginRollbackService
  {
    private readonly string DataDir;
    private readonly string InstalledFile;
    private readonly string BackupFile;

    public PluginRollbackService()
    {
      DataDir = Path.Combine(
          Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
          "NetSecurityScanner", "data", "plugin_market");
      InstalledFile = Path.Combine(DataDir, "installed.json");
      BackupFile = Path.Combine(DataDir, "installed.json.bak");
    }

    /// <summary>
    /// 回滚指定插件到 VersionHistory 倒数第二条版本。
    /// </summary>
    /// <returns>成功返回 true，失败（插件不存在 / 历史不足）返回 false</returns>
    public bool Rollback(string pluginId)
    {
      if (string.IsNullOrEmpty(pluginId)) return false;
      try
      {
        Directory.CreateDirectory(DataDir);

        if (!File.Exists(InstalledFile))
          return false;

        // 加载已安装列表
        var json = File.ReadAllText(InstalledFile);
        var installed = JsonSerializer.Deserialize<List<Plugin>>(json) ?? new List<Plugin>();
        var plugin = installed.FirstOrDefault(p => p.Id == pluginId);
        if (plugin == null) return false;

        // VersionHistory 至少需要 2 条：当前 + 上一版本
        if (plugin.VersionHistory == null || plugin.VersionHistory.Count < 2)
          return false;

        var previous = plugin.VersionHistory[^2]; // 倒数第二条

        // 先备份原文件
        BackupInstalled();

        // 写回：把 Version 改为上一版本，并把当前版本压入历史
        plugin.Version = previous.Version;
        plugin.LastUpdated = DateTime.Now;

        var newJson = JsonSerializer.Serialize(installed, new JsonSerializerOptions { WriteIndented = true });
        File.WriteAllText(InstalledFile, newJson);
        return true;
      }
      catch
      {
        return false;
      }
    }

    /// <summary>
    /// 判断某个插件是否可以回滚（VersionHistory.Count >= 2）。
    /// </summary>
    public bool CanRollback(string pluginId)
    {
      try
      {
        if (string.IsNullOrEmpty(pluginId) || !File.Exists(InstalledFile)) return false;
        var json = File.ReadAllText(InstalledFile);
        var installed = JsonSerializer.Deserialize<List<Plugin>>(json) ?? new List<Plugin>();
        var plugin = installed.FirstOrDefault(p => p.Id == pluginId);
        return plugin?.VersionHistory != null && plugin.VersionHistory.Count >= 2;
      }
      catch
      {
        return false;
      }
    }

    /// <summary>
    /// 备份 installed.json -> installed.json.bak。
    /// 若已存在备份则覆盖。
    /// </summary>
    private void BackupInstalled()
    {
      if (!File.Exists(InstalledFile)) return;
      File.Copy(InstalledFile, BackupFile, overwrite: true);
    }

    /// <summary>
    /// 从 installed.json.bak 恢复上一次备份。
    /// </summary>
    public bool RestoreFromBackup()
    {
      try
      {
        if (!File.Exists(BackupFile)) return false;
        File.Copy(BackupFile, InstalledFile, overwrite: true);
        return true;
      }
      catch
      {
        return false;
      }
    }
  }
}
