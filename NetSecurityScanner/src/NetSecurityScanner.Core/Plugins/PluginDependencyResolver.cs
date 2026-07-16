using System;
using System.Collections.Generic;
using System.Linq;
using NetSecurityScanner.Models;

namespace NetSecurityScanner.Core
{
  /// <summary>
  /// SemVer 版本比较器（v2）
  /// </summary>
  public static class SemVer
  {
    public static int Compare(string a, string b)
    {
      var pa = Parse(a);
      var pb = Parse(b);
      for (int i = 0; i < 3; i++)
      {
        if (pa[i] != pb[i]) return pa[i].CompareTo(pb[i]);
      }
      return 0;
    }

    public static bool IsAtLeast(string version, string min)
    {
      try { return Compare(version, min) >= 0; }
      catch { return false; }
    }

    public static int[] Parse(string v)
    {
      var clean = v?.TrimStart('v') ?? "0.0.0";
      var parts = clean.Split('.', '-', '+');
      return new[]
      {
        int.Parse(parts.Length > 0 ? parts[0] : "0"),
        int.Parse(parts.Length > 1 ? parts[1] : "0"),
        int.Parse(parts.Length > 2 ? parts[2] : "0")
      };
    }
  }

  /// <summary>
  /// 插件依赖解析器（v3 - 含循环检测）
  /// </summary>
  public class PluginDependencyResolver
  {
    public class DependencyIssue
    {
      public string PluginId { get; set; } = string.Empty;
      public string MissingDependency { get; set; } = string.Empty;
      public string Reason { get; set; } = string.Empty;
      public bool IsCore { get; set; }
    }

    public List<DependencyIssue> Resolve(Plugin plugin, IEnumerable<Plugin> installedPlugins, string coreVersion)
    {
      var issues = new List<DependencyIssue>();

      // 检查最低核心框架版本
      if (!string.IsNullOrEmpty(plugin.MinCoreVersion) &&
          !SemVer.IsAtLeast(coreVersion, plugin.MinCoreVersion))
      {
        issues.Add(new DependencyIssue
        {
          PluginId = plugin.Id,
          MissingDependency = "core",
          Reason = $"需要核心框架 v{plugin.MinCoreVersion}，当前 v{coreVersion}",
          IsCore = true
        });
      }

      // 检查依赖插件
      if (plugin.Dependencies == null) return issues;
      foreach (var dep in plugin.Dependencies)
      {
        var parts = dep.Split(':');
        var depId = parts[0];
        var minVer = parts.Length > 1 ? parts[1] : "1.0.0";
        var installed = installedPlugins.FirstOrDefault(p => p.Id == depId);
        if (installed == null)
        {
          issues.Add(new DependencyIssue
          {
            PluginId = plugin.Id,
            MissingDependency = depId,
            Reason = $"依赖插件 {depId} 未安装"
          });
        }
        else if (!SemVer.IsAtLeast(installed.Version, minVer))
        {
          issues.Add(new DependencyIssue
          {
            PluginId = plugin.Id,
            MissingDependency = depId,
            Reason = $"依赖 {depId} v{installed.Version} 低于要求 v{minVer}"
          });
        }
      }
      return issues;
    }

    /// <summary>
    /// v3-T11: 依赖循环检测。
    /// 使用 DFS 染色法（白=未访问，灰=正在访问，黑=已完成）。
    /// 当 DFS 在某节点 v 找到一条指向"灰色祖先"的边时，沿父链回溯得到环路径。
    /// 检测到环时抛 InvalidOperationException，消息格式: "检测到依赖环: A->B->C->A"。
    /// </summary>
    public static void DetectCycle(IEnumerable<Plugin> plugins)
    {
      if (plugins == null) return;
      var list = plugins as IList<Plugin> ?? plugins.ToList();
      var byId = list
          .Where(p => p != null && !string.IsNullOrEmpty(p.Id))
          .GroupBy(p => p.Id)
          .ToDictionary(g => g.Key, g => g.First());

      // 0 = white, 1 = gray (in stack), 2 = black (done)
      var color = new Dictionary<string, int>();
      var parent = new Dictionary<string, string?>();
      foreach (var id in byId.Keys) color[id] = 0;

      foreach (var id in byId.Keys)
      {
        if (color[id] == 0)
        {
          var cycle = Dfs(id, byId, color, parent);
          if (cycle != null)
          {
            throw new InvalidOperationException("检测到依赖环: " + string.Join("->", cycle));
          }
        }
      }
    }

    private static List<string>? Dfs(
        string start,
        Dictionary<string, Plugin> byId,
        Dictionary<string, int> color,
        Dictionary<string, string?> parent)
    {
      var stack = new Stack<(string node, int childIdx)>();
      color[start] = 1;
      stack.Push((start, 0));

      while (stack.Count > 0)
      {
        var (node, idx) = stack.Peek();
        var deps = byId[node].Dependencies ?? new List<string>();
        // 跳过 ":" 后的版本号
        var depIds = deps
            .Where(d => !string.IsNullOrEmpty(d))
            .Select(d => d.Split(':')[0])
            .Where(d => byId.ContainsKey(d))
            .ToList();

        if (idx >= depIds.Count)
        {
          color[node] = 2;
          stack.Pop();
          continue;
        }
        // 推进 child 索引
        stack.Pop();
        stack.Push((node, idx + 1));

        var next = depIds[idx];
        if (color[next] == 1)
        {
          // 找到环：回溯父链到 next
          var cycle = new List<string> { next };
          var cur = node;
          while (cur != next && cur != null)
          {
            cycle.Add(cur);
            cur = parent.TryGetValue(cur, out var p) ? p : null;
          }
          cycle.Add(next);
          cycle.Reverse();
          return cycle;
        }
        if (color[next] == 0)
        {
          parent[next] = node;
          color[next] = 1;
          stack.Push((next, 0));
        }
      }
      return null;
    }
  }
}
