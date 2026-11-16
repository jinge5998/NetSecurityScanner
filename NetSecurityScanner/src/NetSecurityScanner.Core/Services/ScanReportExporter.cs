using System;
using System.IO;
using System.Net;
using System.Text;
using NetSecurityScanner.Models;

namespace NetSecurityScanner.Core.Services
{
  /// <summary>
  /// 扫描结果导出序列化器：把 <see cref="CompleteScanResult"/> 渲染为 HTML / CSV / （JSON 由调用方决定）。
  ///
  /// 定位：US-03 的「输出格式真正生效」落于本类，是可在 Core 层直接单测的纯函数，
  /// 避免此前 HTML/CSV 代码仅存于 WPF 端只能靠手工冒烟验证的可测试性缺口。
  ///
  /// 安全约定：所有来自目标/扫描结果的文本都经 HTML 转义或 CSV RFC 4180 转义，
  /// 防止把目标返回的任意内容当作可执行脚本或注入到表格字段。
  /// </summary>
  public static class ScanReportExporter
  {
    /// <summary>HTML 转义并保留换行。</summary>
    public static string HtmlEscape(string? value) =>
        WebUtility.HtmlEncode(value ?? string.Empty)
            .Replace("\r\n", "<br/>").Replace("\n", "<br/>");

    /// <summary>生成脚本不可执行的只读 HTML 报告。</summary>
    public static string SerializeHtml(CompleteScanResult scanResult)
    {
      var sb = new StringBuilder();
      sb.AppendLine("<!DOCTYPE html>");
      sb.AppendLine("<html lang=\"zh-CN\"><head><meta charset=\"utf-8\"/>");
      sb.AppendLine("<title>专家模式扫描报告</title>");
      sb.AppendLine("<style>body{font-family:system-ui,Arial,sans-serif;margin:24px}table{border-collapse:collapse;width:100%}th,td{border:1px solid #ccc;padding:6px 8px;text-align:left;font-size:13px}th{background:#f0f0f0}</style>");
      sb.AppendLine("</head><body><h1>专家模式扫描报告</h1>");
      sb.AppendLine($"<h2>{HtmlEscape(scanResult.TargetIp)}</h2>");
      sb.AppendLine($"<p>扫描类型：{HtmlEscape(scanResult.ScanType)} ｜ 扫描时间：{scanResult.ScanTime:yyyy-MM-dd HH:mm:ss} ｜ 耗时：{scanResult.ScanDuration:F1} 秒 ｜ 风险：{HtmlEscape(scanResult.RiskLevel)}</p>");
      sb.AppendLine($"<p>开放端口：{scanResult.OpenPortsCount} ｜ 漏洞：{scanResult.VulnerabilitiesCount}</p>");

      sb.AppendLine("<h3>端口详情</h3><table><tr><th>端口</th><th>状态</th><th>服务</th><th>版本</th><th>风险</th></tr>");
      foreach (var p in scanResult.PortScanResults)
      {
        sb.AppendLine($"<tr><td>{p.PortNumber}</td><td>{HtmlEscape(p.Status)}</td><td>{HtmlEscape(p.Service)}</td><td>{HtmlEscape(p.ServiceVersion)}</td><td>{HtmlEscape(p.RiskLevel)}</td></tr>");
      }
      sb.AppendLine("</table>");

      sb.AppendLine("<h3>漏洞列表</h3><table><tr><th>名称</th><th>风险</th><th>端口/服务</th><th>描述</th><th>解决方案</th></tr>");
      foreach (var v in scanResult.VulnerabilityResults)
      {
        sb.AppendLine($"<tr><td>{HtmlEscape(v.Name)}</td><td>{HtmlEscape(v.RiskLevel)}</td><td>{(v.Port?.ToString() ?? "-")}/{HtmlEscape(v.Service)}</td><td>{HtmlEscape(v.Description)}</td><td>{HtmlEscape(v.Solution)}</td></tr>");
      }
      sb.AppendLine("</table>");

      if (scanResult.RiskAssessment != null)
      {
        sb.AppendLine($"<p>风险建议：{HtmlEscape(scanResult.RiskAssessment.SecurityAdvice)}</p>");
      }
      sb.AppendLine("</body></html>");
      return sb.ToString();
    }

    /// <summary>生成 CSV 报告（RFC 4180 兼容：含逗号/引号/换行时用双引号包裹并转义）。</summary>
    public static string SerializeCsv(CompleteScanResult scanResult)
    {
      var sb = new StringBuilder();
      sb.AppendLine("TargetIp,ScanTime,ScanDurationSeconds,RiskLevel,OpenPorts,Vulnerabilities");
      sb.AppendLine($"{CsvEscape(scanResult.TargetIp)},{scanResult.ScanTime:yyyy-MM-dd HH:mm:ss},{scanResult.ScanDuration:F1},{CsvEscape(scanResult.RiskLevel)},{scanResult.OpenPortsCount},{scanResult.VulnerabilitiesCount}");

      sb.AppendLine();
      sb.AppendLine("Port,Status,Service,ServiceVersion,Confidence");
      foreach (var p in scanResult.PortScanResults)
      {
        sb.AppendLine($"{p.PortNumber},{CsvEscape(p.Status)},{CsvEscape(p.Service)},{CsvEscape(p.ServiceVersion)},{CsvEscape(p.Confidence)}");
      }

      if (scanResult.VulnerabilityResults.Count > 0)
      {
        sb.AppendLine();
        sb.AppendLine("VulnName,RiskLevel,Port,Service,CveId,Description,Solution");
        foreach (var v in scanResult.VulnerabilityResults)
        {
          sb.AppendLine($"{CsvEscape(v.Name)},{CsvEscape(v.RiskLevel)},{(v.Port?.ToString() ?? "-")},{CsvEscape(v.Service)},{CsvEscape(v.CveId)},{CsvEscape(v.Description)},{CsvEscape(v.Solution)}");
        }
      }

      return sb.ToString();
    }

    /// <summary>RFC 4180 字段转义：含分隔符/引号/换行时包裹双引号并转义内部引号。</summary>
    public static string CsvEscape(string? value)
    {
      var s = value ?? string.Empty;
      if (s.IndexOf(',') >= 0 || s.IndexOf('"') >= 0 || s.Contains('\n') || s.Contains('\r'))
      {
        return "\"" + s.Replace("\"", "\"\"") + "\"";
      }
      return s;
    }
  }
}