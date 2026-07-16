using System;
using System.Collections.Generic;
using NetSecurityScanner.Models;

namespace NetSecurityScanner.Core
{
  /// <summary>
  /// 摄像头扫描智能推荐引擎 - 根据目标规模和场景推荐最合适的扫描预设
  /// </summary>
  public class CameraScanRecommendationEngine
  {
    public class Recommendation
    {
      public CameraScanPreset Preset { get; set; } = new();
      public string Reason { get; set; } = string.Empty;
      public int EstimatedSeconds { get; set; }
      public string Coverage { get; set; } = string.Empty;
    }

    /// <summary>
    /// 根据目标数量推荐扫描配置
    /// </summary>
    public Recommendation Recommend(int targetCount, string scenario = "default")
    {
      var presets = CameraScanPreset.GetDefaultPresets();
      var rec = new Recommendation();

      if (scenario == "monitoring" || targetCount > 500)
      {
        rec.Preset = presets[0]; // 快速扫描
        rec.Reason = $"目标数量较多（{targetCount}台），推荐快速扫描以快速摸清网络资产";
        rec.EstimatedSeconds = Math.Max(30, targetCount);
        rec.Coverage = "端口+指纹";
      }
      else if (scenario == "audit" || targetCount <= 50)
      {
        rec.Preset = presets[2]; // 深度扫描
        rec.Reason = $"目标数量较少（{targetCount}台），适合深度扫描以发现全部安全隐患";
        rec.EstimatedSeconds = targetCount * 5;
        rec.Coverage = "端口+指纹+漏洞+弱口令+全服务";
      }
      else
      {
        rec.Preset = presets[1]; // 标准扫描
        rec.Reason = $"目标规模适中（{targetCount}台），推荐标准扫描平衡效率与覆盖率";
        rec.EstimatedSeconds = targetCount * 2;
        rec.Coverage = "端口+指纹+弱口令";
      }

      return rec;
    }

    /// <summary>
    /// 根据扫描耗时反馈自适应调整下次参数
    /// </summary>
    public CameraScanPreset AdaptFromHistory(CameraScanPreset basePreset, int lastTargetCount, TimeSpan lastDuration, bool wasCancelled)
    {
      if (wasCancelled)
      {
        // 被取消 -> 降低并发、提高超时
        return new CameraScanPreset
        {
          Name = basePreset.Name + " (自适应)",
          EnableFingerprint = basePreset.EnableFingerprint,
          EnableVulnerabilityScan = basePreset.EnableVulnerabilityScan,
          EnableWeakPasswordScan = basePreset.EnableWeakPasswordScan,
          MaxConcurrency = Math.Max(5, basePreset.MaxConcurrency / 2),
          TimeoutMs = basePreset.TimeoutMs * 2,
          MaxPasswordAttempts = Math.Max(10, basePreset.MaxPasswordAttempts / 2)
        };
      }

      var secPerTarget = lastDuration.TotalSeconds / Math.Max(1, lastTargetCount);
      if (secPerTarget > 10)
      {
        // 太慢 -> 提高并发、降低超时
        return new CameraScanPreset
        {
          Name = basePreset.Name + " (提速)",
          EnableFingerprint = basePreset.EnableFingerprint,
          EnableVulnerabilityScan = basePreset.EnableVulnerabilityScan,
          EnableWeakPasswordScan = basePreset.EnableWeakPasswordScan,
          MaxConcurrency = Math.Min(100, basePreset.MaxConcurrency * 2),
          TimeoutMs = Math.Max(1000, basePreset.TimeoutMs / 2),
          MaxPasswordAttempts = basePreset.MaxPasswordAttempts
        };
      }

      return basePreset;
    }
  }
}
