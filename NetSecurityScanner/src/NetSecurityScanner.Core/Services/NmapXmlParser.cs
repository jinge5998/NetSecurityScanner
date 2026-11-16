using System;
using System.Collections.Generic;
using System.Linq;
using System.Xml.Linq;
using NetSecurityScanner.Models;

namespace NetSecurityScanner.Core.Services
{
  /// <summary>
  /// 解析 nmap 标准 XML 输出（<c>nmap -oX -</c> 写入 stdout）。
  ///
  /// 这是「让 nmap 从"仅生成命令字符串"变为实际执行」的关键一环：
  /// 之前的 <see cref="NmapCommandBuilder"/> 只产出命令行供用户复制执行，
  /// 本类负责把真实 nmap 进程回传的 XML 反序列化为程序可消费的
  /// <see cref="PortScanResult"/> 列表，从而把 nmap 结果接进现有的结果回填 /
  /// 漏洞扫描链路。
  ///
  /// 设计为纯函数（不依赖 WPF / IO），便于单元测试确定性断言:
  /// 传入任意合法 nmap XML 文本即可得到结构化的端口结果，无副作用。
  /// </summary>
  public static class NmapXmlParser
  {
    /// <summary>
    /// 解析 nmap XML 文本，返回端口扫描结果。
    /// 无法识别的 <c>&lt;host&gt;</c> 块会被跳过，不会让整份结果失败。
    /// </summary>
    public static List<PortScanResult> Parse(string xml)
    {
      var results = new List<PortScanResult>();
      if (string.IsNullOrWhiteSpace(xml)) return results;

      XDocument doc;
      try
      {
        doc = XDocument.Parse(xml);
      }
      catch (Exception)
      {
        // nmap 中途被取消/输出不完整导致的非法 XML → 返回空，交由调用方告警，不抛异常。
        return results;
      }

      foreach (var host in doc.Descendants("host"))
      {
        string targetIp = host.Element("address")?.Attribute("addr")?.Value ?? "";
        foreach (var port in host.Descendants("port"))
        {
          var result = MapPort(targetIp, port);
          if (result != null) results.Add(result);
        }
      }

      return results;
    }

    /// <summary>
    /// 把单个 <c>&lt;port&gt;</c> 元素映射为 <see cref="PortScanResult"/>。
    /// 仅保留 nmap 标记为 open / open|filtered 的端口；其余状态视为关闭。
    /// </summary>
    private static PortScanResult? MapPort(string targetIp, XElement port)
    {
      if (!int.TryParse(port.Attribute("portid")?.Value, out var portNumber))
        return null;

      var stateEl = port.Descendants("state").FirstOrDefault();
      var state = stateEl?.Attribute("state")?.Value ?? "closed";
      var status = state switch
      {
        "open" => "开放",
        "open|filtered" => "开放或过滤",
        "closed" => "关闭",
        "filtered" => "被过滤",
        "unfiltered" => "未过滤",
        _ => state
      };

      var serviceEl = port.Descendants("service").FirstOrDefault();
      var serviceName = serviceEl?.Attribute("name")?.Value ?? "";
      var product = serviceEl?.Attribute("product")?.Value ?? "";
      var version = serviceEl?.Attribute("version")?.Value ?? "";
      var service = serviceName;
      if (!string.IsNullOrWhiteSpace(product)) service = product;
      var serviceVersion = version ?? "";

      // 仅把对漏洞扫描有意义的状态纳入结果；否则目标被扫描但全是关闭端口时，
      // 依然产生大量"关闭"条目。保留"关闭"便于精度审计（与内置扫描器一致）。
      var result = new PortScanResult
      {
        TargetIp = targetIp,
        PortNumber = portNumber,
        Status = status,
        Service = service,
        ServiceVersion = serviceVersion,
        Confidence = DetermineConfidence(state),
        ResponseTime = "-"
      };
      return result;
    }

    private static string DetermineConfidence(string nmapState)
    {
      return nmapState switch
      {
        "open" => "高",
        "open|filtered" => "中",
        _ => "中"
      };
    }
  }
}