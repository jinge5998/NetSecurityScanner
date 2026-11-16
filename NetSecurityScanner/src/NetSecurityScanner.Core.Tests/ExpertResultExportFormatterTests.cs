using NetSecurityScanner.Core.Services;
using NetSecurityScanner.Models;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.Json;
using Xunit;

namespace NetSecurityScanner.Tests
{
    /// <summary>
    /// 专家模式结果导出格式测试：覆盖 CSV 列结构/转义、JSON 字段与中文不转义、UTF-8 BOM 落盘。
    /// 该格式生成器同时服务于「整体导出」与结果区「当前筛选/全部」导出。
    /// </summary>
    public class ExpertResultExportFormatterTests
    {
        private static PortScanResult CreatePort(string ip = "192.168.1.10", int port = 22,
            string status = "开放", string service = "ssh", string version = "OpenSSH 8.0")
        {
            return new PortScanResult
            {
                TargetIp = ip,
                PortNumber = port,
                Status = status,
                Service = service,
                ServiceVersion = version
            };
        }

        private static VulnerabilityResult CreateVuln(int id, string target = "192.168.1.10", int? port = 22,
            string name = "弱口令", string cve = "CVE-2024-0001", string risk = "高危",
            string service = "ssh", string description = "允许空密码登录")
        {
            return new VulnerabilityResult
            {
                Id = id,
                Target = target,
                Port = port,
                Name = name,
                CveId = cve,
                RiskLevel = risk,
                Service = service,
                Description = description
            };
        }

        [Fact]
        public void BuildCsv_ShouldContainHeaderAndPortRow()
        {
            var csv = ExpertResultExportFormatter.BuildCsv(
                new[] { CreatePort() },
                Array.Empty<VulnerabilityResult>());

            var lines = csv.Split(new[] { "\r\n", "\n" }, StringSplitOptions.RemoveEmptyEntries);

            Assert.Equal("报告类型,目标IP,端口,状态,服务,版本,风险等级,CVE,描述", lines[0]);
            Assert.Equal(2, lines.Length);
            Assert.Equal(
                "端口扫描,192.168.1.10,22,开放,ssh,OpenSSH 8.0,,,",
                lines[1]);
        }

        [Fact]
        public void BuildCsv_ShouldEscapeCommaQuoteAndNewlineFields()
        {
            var vuln = CreateVuln(
                id: 1,
                service: "http,https",
                description: "包含\"引号\"\n且含换行");

            var csv = ExpertResultExportFormatter.BuildCsv(
                Array.Empty<PortScanResult>(),
                new[] { vuln });

            // 含换行的字段会把记录本身拆成多行，因此按整段文本断言，
            // 验证逗号字段被引号包裹、内部双引号双写、换行原样保留在引号内
            Assert.Contains("\"http,https\"", csv);
            Assert.Contains("\"包含\"\"引号\"\"\n且含换行\"", csv);
        }

        [Fact]
        public void BuildCsv_VulnRow_ShouldAlignToNineColumns()
        {
            var csv = ExpertResultExportFormatter.BuildCsv(
                Array.Empty<PortScanResult>(),
                new[] { CreateVuln(id: 7) });

            var lines = csv.Split(new[] { "\r\n", "\n" }, StringSplitOptions.RemoveEmptyEntries);
            var fields = lines[1].Split(',');

            Assert.Equal(9, fields.Length);
            Assert.Equal("漏洞扫描", fields[0]);
            Assert.Equal("192.168.1.10", fields[1]);
            Assert.Equal("22", fields[2]);
            Assert.Equal("", fields[3]);          // 状态列留空
            Assert.Equal("ssh", fields[4]);
            Assert.Equal("", fields[5]);          // 版本列留空
            Assert.Equal("高危", fields[6]);
            Assert.Equal("CVE-2024-0001", fields[7]);
            Assert.Equal("允许空密码登录", fields[8]);
        }

        [Fact]
        public void BuildCsv_WithEmptyInputs_ShouldReturnHeaderOnly()
        {
            var csv = ExpertResultExportFormatter.BuildCsv(null, null);
            var lines = csv.Split(new[] { "\r\n", "\n" }, StringSplitOptions.RemoveEmptyEntries);

            Assert.Single(lines);
            Assert.Equal("报告类型,目标IP,端口,状态,服务,版本,风险等级,CVE,描述", lines[0]);
        }

        [Fact]
        public void BuildJson_ShouldCarryCountsAndKeepChineseUnescaped()
        {
            var json = ExpertResultExportFormatter.BuildJson(
                new[] { CreatePort() },
                new[] { CreateVuln(1, risk: "高危"), CreateVuln(2, risk: "中危") },
                totalTargets: 3,
                totalOpenPorts: 5);

            // 中文必须原样输出（UnsafeRelaxedJsonEscaping），不能变成 \uXXXX
            Assert.Contains("高危", json);
            Assert.DoesNotContain("\\u", json);

            using var doc = JsonDocument.Parse(json);
            var root = doc.RootElement;

            Assert.Equal(3, root.GetProperty("TotalTargets").GetInt32());
            Assert.Equal(5, root.GetProperty("TotalOpenPorts").GetInt32());
            Assert.Equal(2, root.GetProperty("TotalVulnerabilities").GetInt32());
            Assert.Equal(1, root.GetProperty("PortScanResults").GetArrayLength());
            Assert.Equal(2, root.GetProperty("VulnerabilityResults").GetArrayLength());
            Assert.Equal("192.168.1.10",
                root.GetProperty("PortScanResults")[0].GetProperty("TargetIp").GetString());
            Assert.Equal("高危",
                root.GetProperty("VulnerabilityResults")[0].GetProperty("RiskLevel").GetString());
        }

        [Fact]
        public void WriteCsvFile_ShouldWriteUtf8BomAndContent()
        {
            var dir = Path.Combine(Path.GetTempPath(), "NetSecurityScannerExportTests", Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(dir);
            var file = Path.Combine(dir, "端口结果_当前筛选_20261102_200000.csv");

            try
            {
                ExpertResultExportFormatter.WriteCsvFile(
                    file,
                    new[] { CreatePort() },
                    Array.Empty<VulnerabilityResult>());

                var bytes = File.ReadAllBytes(file);

                // 真实断言 BOM 为 EF BB BF
                Assert.True(bytes.Length >= 3, "文件字节数不足以包含 BOM");
                Assert.Equal(0xEF, bytes[0]);
                Assert.Equal(0xBB, bytes[1]);
                Assert.Equal(0xBF, bytes[2]);

                var text = File.ReadAllText(file, Encoding.UTF8);
                Assert.StartsWith("报告类型,目标IP,端口,状态,服务,版本,风险等级,CVE,描述", text);
                Assert.Contains("端口扫描,192.168.1.10,22,开放,ssh,OpenSSH 8.0,,,", text);
            }
            finally
            {
                if (Directory.Exists(dir))
                    Directory.Delete(dir, recursive: true);
            }
        }

        [Fact]
        public void WriteJsonFile_ShouldWriteUtf8BomAndParsableJson()
        {
            var dir = Path.Combine(Path.GetTempPath(), "NetSecurityScannerExportTests", Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(dir);
            var file = Path.Combine(dir, "漏洞结果_全部_20261102_200000.json");

            try
            {
                ExpertResultExportFormatter.WriteJsonFile(
                    file,
                    Array.Empty<PortScanResult>(),
                    new[] { CreateVuln(1) },
                    totalTargets: 1,
                    totalOpenPorts: 0);

                var bytes = File.ReadAllBytes(file);
                Assert.Equal(0xEF, bytes[0]);
                Assert.Equal(0xBB, bytes[1]);
                Assert.Equal(0xBF, bytes[2]);

                using var doc = JsonDocument.Parse(File.ReadAllText(file, Encoding.UTF8));
                Assert.Equal(1, doc.RootElement.GetProperty("TotalVulnerabilities").GetInt32());
                Assert.Equal(1, doc.RootElement.GetProperty("VulnerabilityResults").GetArrayLength());
                Assert.Equal(0, doc.RootElement.GetProperty("PortScanResults").GetArrayLength());
            }
            finally
            {
                if (Directory.Exists(dir))
                    Directory.Delete(dir, recursive: true);
            }
        }

        [Theory]
        [InlineData(null, "")]
        [InlineData("", "")]
        [InlineData("普通文本", "普通文本")]
        [InlineData("a,b", "\"a,b\"")]
        [InlineData("a\"b", "\"a\"\"b\"")]
        [InlineData("a\nb", "\"a\nb\"")]
        public void EscapeCsvField_ShouldQuoteOnlyWhenNeeded(string input, string expected)
        {
            Assert.Equal(expected, ExpertResultExportFormatter.EscapeCsvField(input));
        }
    }
}
