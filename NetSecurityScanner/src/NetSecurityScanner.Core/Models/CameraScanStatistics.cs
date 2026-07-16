using System.Collections.Generic;

namespace NetSecurityScanner.Models
{
  /// <summary>
  /// 摄像头扫描结果聚合统计（v4-T1）
  /// </summary>
  public class CameraScanStatistics
  {
    /// <summary>扫描结果总数</summary>
    public int Total { get; set; }

    /// <summary>在线数量</summary>
    public int Online { get; set; }

    /// <summary>离线数量</summary>
    public int Offline { get; set; }

    /// <summary>风险分布：严重/高/中/低/信息 -> 数量</summary>
    public Dictionary<string, int> RiskDistribution { get; set; } = new();

    /// <summary>出现次数最多的 5 个厂商</summary>
    public Dictionary<string, int> VendorTopN { get; set; } = new();

    /// <summary>出现次数最多的 5 个漏洞类型</summary>
    public Dictionary<string, int> VulnTypeTopN { get; set; } = new();
  }
}
