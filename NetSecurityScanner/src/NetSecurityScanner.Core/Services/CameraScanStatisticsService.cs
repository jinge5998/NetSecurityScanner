using System;
using System.Collections.Generic;
using System.Linq;
using NetSecurityScanner.Models;

namespace NetSecurityScanner.Core
{
  /// <summary>
  /// 摄像头扫描结果聚合统计服务（v4-T1）
  /// </summary>
  public static class CameraScanStatisticsService
  {
    /// <summary>
    /// 对一批扫描结果做聚合统计：在线/离线、风险分布、厂商 TopN、漏洞类型 TopN
    /// </summary>
    public static CameraScanStatistics Compute(IList<CameraScanResult>? results)
    {
      var stat = new CameraScanStatistics();
      if (results == null) return stat;

      stat.Total = results.Count;
      stat.Online = results.Count(r => r.IsOnline);
      stat.Offline = stat.Total - stat.Online;

      // 风险分布（按漏洞严重度聚合）
      var risk = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase)
      {
        ["严重"] = 0,
        ["高"] = 0,
        ["中"] = 0,
        ["低"] = 0,
        ["信息"] = 0
      };
      foreach (var r in results)
      {
        if (r.Vulnerabilities == null) continue;
        foreach (var v in r.Vulnerabilities)
        {
          var sev = NormalizeSeverity(v.Severity);
          risk[sev] = risk.GetValueOrDefault(sev, 0) + 1;
        }
      }
      stat.RiskDistribution = risk;

      // 厂商 TopN（在线优先）
      stat.VendorTopN = results
          .Where(r => r.IsOnline && !string.IsNullOrWhiteSpace(r.Vendor))
          .GroupBy(r => r.Vendor.Trim())
          .ToDictionary(g => g.Key, g => g.Count())
          .OrderByDescending(kv => kv.Value)
          .Take(5)
          .ToDictionary(kv => kv.Key, kv => kv.Value);

      // 漏洞类型 TopN
      stat.VulnTypeTopN = results
          .Where(r => r.Vulnerabilities != null)
          .SelectMany(r => r.Vulnerabilities!)
          .Where(v => !string.IsNullOrWhiteSpace(v.VulnerabilityType))
          .GroupBy(v => v.VulnerabilityType.Trim())
          .ToDictionary(g => g.Key, g => g.Count())
          .OrderByDescending(kv => kv.Value)
          .Take(5)
          .ToDictionary(kv => kv.Key, kv => kv.Value);

      return stat;
    }

    /// <summary>
    /// 将各种写法归一为 严重/高/中/低/信息
    /// </summary>
    private static string NormalizeSeverity(string? raw)
    {
      if (string.IsNullOrWhiteSpace(raw)) return "信息";
      var s = raw.Trim();
      if (s.Contains("严重") || s.Equals("Critical", StringComparison.OrdinalIgnoreCase)) return "严重";
      if (s.Contains("高") || s.Equals("High", StringComparison.OrdinalIgnoreCase)) return "高";
      if (s.Contains("中") || s.Equals("Medium", StringComparison.OrdinalIgnoreCase) || s.Equals("Moderate", StringComparison.OrdinalIgnoreCase)) return "中";
      if (s.Contains("低") || s.Equals("Low", StringComparison.OrdinalIgnoreCase)) return "低";
      return "信息";
    }
  }
}
