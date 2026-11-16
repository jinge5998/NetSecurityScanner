using System.Collections.Generic;
using FluentAssertions;
using NetSecurityScanner.Core.Services;
using NetSecurityScanner.Models;
using Xunit;

namespace NetSecurityScanner.Tests
{
  /// <summary>
  /// US-03：扫描报告导出序列化（HTML/CSV）的 Core 层边界单测。
  /// 逻辑已从 WPF 下沉到 <see cref="ScanReportExporter"/>，这里锁定：
  ///  1) HTML 全量转义（防注入）；
  ///  2) CSV RFC 4180 转义（含逗号/引号/换行字段）；
  ///  3) 空结果/无漏洞列表等边界不抛异常且有稳定结构。
  /// </summary>
  public class ScanReportExporterTests
  {
    private static CompleteScanResult Sample(bool withVuln = true)
    {
      var result = new CompleteScanResult
      {
        TargetIp = "192.168.1.10",
        ScanType = "tcp",
        RiskLevel = "高危",
        ScanDuration = 1.5,
        OpenPortsCount = 1,
        PortScanResults = new List<PortScanResult>
                {
                    new PortScanResult
                    {
                        PortNumber = 22,
                        Status = "open",
                        Service = "ssh",
                        ServiceVersion = "OpenSSH_8.2p1",
                        Confidence = "高"
                    }
                }
      };

      if (withVuln)
      {
        result.VulnerabilityResults = new List<VulnerabilityResult>
                {
                    new VulnerabilityResult
                    {
                        Name = "弱口令",
                        RiskLevel = "高危",
                        Port = 22,
                        Service = "ssh",
                        Description = "允许暴力破解"
                    }
                };
        result.VulnerabilitiesCount = 1;
      }

      return result;
    }

    [Fact]
    public void HtmlEscape_ShouldNeutralizeScriptAndHtmlTags()
    {
      ScanReportExporter.HtmlEscape("<script>alert(1)</script>")
          .Should().NotContain("<script>")
          .And.Contain("&lt;script&gt;");
      ScanReportExporter.HtmlEscape("a&b")
          .Should().Contain("a&amp;b");
      ScanReportExporter.HtmlEscape(null).Should().BeEmpty();
    }

    [Fact]
    public void SerializeHtml_ShouldContainEscapedTargetContent_ButNotRawScript()
    {
      // 构造一个故意把目标内容当作脚本的样本
      var s = new CompleteScanResult { TargetIp = "</h2><script>hacked()</script>" };
      var html = ScanReportExporter.SerializeHtml(s);

      html.Should().NotContain("<script>")
          .And.Contain("&lt;script&gt;");
    }

    [Fact]
    public void SerializeHtml_EmptyResult_ShouldStillEmitStableTables()
    {
      var html = ScanReportExporter.SerializeHtml(Sample(withVuln: false));
      html.Should().Contain("<h3>端口详情</h3>")
          .And.Contain("<h3>漏洞列表</h3>")
          .And.Contain("</html>");
    }

    [Fact]
    public void SerializeCsv_ShouldWrapFieldWithComma_Quote_Newline_ByRfc4180()
    {
      // 服务字段含逗号 + 引号 + 换行，应被双引号包裹且内部引号翻倍
      var s = Sample();
      s.PortScanResults[0].ServiceVersion = "ssh,\"OpenSSH\"\nv2";
      var csv = ScanReportExporter.SerializeCsv(s);

      csv.Should().Contain("\"ssh,\"\"OpenSSH\"\"\nv2\"");
    }

    [Fact]
    public void SerializeCsv_PlainField_ShouldNotBeQuoted()
    {
      var csv = ScanReportExporter.SerializeCsv(Sample());
      // 普通版本号不带逗号/引号时不应被包裹
      csv.Should().Contain("OpenSSH_8.2p1")
          .And.NotContain("\"OpenSSH_8.2p1\"");
    }

    [Fact]
    public void SerializeCsv_EmptyVulnerabilities_ShouldOmitVulnSection()
    {
      var csv = ScanReportExporter.SerializeCsv(Sample(withVuln: false));
      csv.Should().NotContain("VulnName");
    }

    [Fact]
    public void SerializeCsv_AlwaysHasHeaderAndSummary_Row()
    {
      var csv = ScanReportExporter.SerializeCsv(Sample());
      csv.Should().StartWith("TargetIp,ScanTime,ScanDurationSeconds,RiskLevel,OpenPorts,Vulnerabilities")
          .And.Contain("192.168.1.10");
    }
  }
}