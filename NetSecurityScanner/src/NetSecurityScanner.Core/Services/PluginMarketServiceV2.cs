using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.Json;
using NetSecurityScanner.Models;

namespace NetSecurityScanner.Core
{
  /// <summary>
  /// 插件市场增强服务（v2）
  /// </summary>
  public class PluginMarketServiceV2
  {
    private readonly string DataDir = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
        "NetSecurityScanner", "data", "plugin_market");
    private readonly string ReviewsFile;
    private readonly string PluginsFile;
    private List<PluginReview> _reviews = new();
    private List<Plugin> _installed = new();

    public PluginMarketServiceV2()
    {
      Directory.CreateDirectory(DataDir);
      ReviewsFile = Path.Combine(DataDir, "reviews.json");
      PluginsFile = Path.Combine(DataDir, "installed.json");
      Load();
    }

    public IReadOnlyList<Plugin> InstalledPlugins => _installed;

    public void AddReview(PluginReview review)
    {
      _reviews.Add(review);
      Save();
    }

    public List<PluginReview> GetReviews(string pluginId) =>
        _reviews.Where(r => r.PluginId == pluginId).ToList();

    public void RegisterInstalled(Plugin plugin)
    {
      var existing = _installed.FirstOrDefault(p => p.Id == plugin.Id);
      if (existing != null) _installed.Remove(existing);
      _installed.Add(plugin);
      Save();
    }

    /// <summary>
    /// 模拟从服务器拉取市场列表（含评分/版本历史）
    /// </summary>
    public List<Plugin> FetchMarket()
    {
      // 真实环境应调用 HTTP API
      return new List<Plugin>
      {
        new Plugin
        {
          Id = "ssh-audit-pro",
          Name = "SSH 审计增强",
          Version = "2.0.0",
          Author = "NetSec Team",
          Description = "更全面的 SSH 协议安全审计",
          Category = PluginCategory.VulnerabilityDetection,
          Rating = 4.6, RatingCount = 128,
          DownloadCount = 4521,
          MinCoreVersion = "1.0.0",
          VersionHistory = new List<PluginVersionHistory>
          {
            new() { Version = "2.0.0", ReleaseDate = DateTime.Now.AddDays(-7), ChangeLog = "支持 SSH v2.0" },
            new() { Version = "1.5.0", ReleaseDate = DateTime.Now.AddDays(-90), ChangeLog = "修复 CVE 识别" }
          },
          Reviews = _reviews.Where(r => r.PluginId == "ssh-audit-pro").ToList()
        },
        new Plugin
        {
          Id = "report-html",
          Name = "HTML 报告生成",
          Version = "1.2.0",
          Author = "CoolScanner",
          Description = "生成美观的 HTML 报告",
          Category = PluginCategory.Reporting,
          Rating = 4.2, RatingCount = 56,
          DownloadCount = 1893,
          MinCoreVersion = "1.0.0"
        }
      };
    }

    /// <summary>
    /// 一键升级所有可升级的插件
    /// </summary>
    public List<string> UpgradeAll(IEnumerable<Plugin> marketPlugins)
    {
      var upgraded = new List<string>();
      foreach (var m in marketPlugins)
      {
        var local = _installed.FirstOrDefault(p => p.Id == m.Id);
        if (local == null) continue;
        if (SemVer.Compare(m.Version, local.Version) > 0)
        {
          local.Version = m.Version;
          local.LastUpdated = DateTime.Now;
          upgraded.Add(m.Id);
        }
      }
      Save();
      return upgraded;
    }

    private void Save()
    {
      try
      {
        File.WriteAllText(ReviewsFile, JsonSerializer.Serialize(_reviews));
        File.WriteAllText(PluginsFile, JsonSerializer.Serialize(_installed));
      }
      catch { }
    }

    private void Load()
    {
      try
      {
        if (File.Exists(ReviewsFile))
          _reviews = JsonSerializer.Deserialize<List<PluginReview>>(File.ReadAllText(ReviewsFile)) ?? new();
        if (File.Exists(PluginsFile))
          _installed = JsonSerializer.Deserialize<List<Plugin>>(File.ReadAllText(PluginsFile)) ?? new();
      }
      catch { }
    }
  }
}
