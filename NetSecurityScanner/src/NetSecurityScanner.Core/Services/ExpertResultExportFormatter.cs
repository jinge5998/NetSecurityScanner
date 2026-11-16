using NetSecurityScanner.Models;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.Json;

namespace NetSecurityScanner.Core.Services
{
    /// <summary>
    /// 专家模式结果区导出的 CSV/JSON 格式生成器。
    ///
    /// 实现从 ExpertModeWindow 原有的私有导出方法抽取而来，目的是让
    /// 「整体导出（导出CSV/导出JSON）」与「按结果表导出（当前筛选 / 全部）」共用同一份格式代码，
    /// 避免出现两套格式实现后逐渐漂移。CSV 统一以 UTF-8 BOM 写盘，保证在 Excel 中中文不乱码。
    /// </summary>
    public static class ExpertResultExportFormatter
    {
        /// <summary>带 BOM 的 UTF-8 编码（与原有导出按钮保持一致）</summary>
        private static readonly UTF8Encoding Utf8WithBom = new UTF8Encoding(true);

        /// <summary>
        /// 生成 CSV 文本（单表结构，端口行与漏洞行共用 9 列）。
        /// </summary>
        public static string BuildCsv(
            IEnumerable<PortScanResult> portResults,
            IEnumerable<VulnerabilityResult> vulnResults)
        {
            var sb = new StringBuilder();
            sb.AppendLine("报告类型,目标IP,端口,状态,服务,版本,风险等级,CVE,描述");

            foreach (var r in portResults ?? Enumerable.Empty<PortScanResult>())
            {
                sb.AppendLine(
                    $"端口扫描,{EscapeCsvField(r.TargetIp)},{r.PortNumber},{EscapeCsvField(r.Status)}," +
                    $"{EscapeCsvField(r.Service)},{EscapeCsvField(r.ServiceVersion)},,,");
            }

            foreach (var v in vulnResults ?? Enumerable.Empty<VulnerabilityResult>())
            {
                // 漏洞行与表头保持 9 列对齐：状态列留空，版本列留空，风险等级/CVE/描述依次填入。
                // 抽取前该行缺少版本列，导致风险等级之后的字段整体左移一列。
                sb.AppendLine(
                    $"漏洞扫描,{EscapeCsvField(v.Target)},{v.Port ?? 0},,{EscapeCsvField(v.Service)}," +
                    $",{EscapeCsvField(v.RiskLevel)},{EscapeCsvField(v.CveId)},{EscapeCsvField(v.Description)}");
            }

            return sb.ToString();
        }

        /// <summary>
        /// 生成 JSON 文本（字段结构与原有「导出JSON」一致，中文不转义为 \uXXXX）。
        /// </summary>
        public static string BuildJson(
            IEnumerable<PortScanResult> portResults,
            IEnumerable<VulnerabilityResult> vulnResults,
            int totalTargets,
            int totalOpenPorts)
        {
            var ports = (portResults ?? Enumerable.Empty<PortScanResult>()).ToList();
            var vulns = (vulnResults ?? Enumerable.Empty<VulnerabilityResult>()).ToList();

            var report = new
            {
                ExportTime = DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss"),
                TotalTargets = totalTargets,
                TotalOpenPorts = totalOpenPorts,
                TotalVulnerabilities = vulns.Count,
                PortScanResults = ports,
                VulnerabilityResults = vulns
            };

            var options = new JsonSerializerOptions
            {
                WriteIndented = true,
                Encoder = System.Text.Encodings.Web.JavaScriptEncoder.UnsafeRelaxedJsonEscaping
            };
            return JsonSerializer.Serialize(report, options);
        }

        /// <summary>写 CSV 文件（UTF-8 BOM）。</summary>
        public static void WriteCsvFile(
            string filePath,
            IEnumerable<PortScanResult> portResults,
            IEnumerable<VulnerabilityResult> vulnResults)
        {
            File.WriteAllText(filePath, BuildCsv(portResults, vulnResults), Utf8WithBom);
        }

        /// <summary>写 JSON 文件（UTF-8 BOM）。</summary>
        public static void WriteJsonFile(
            string filePath,
            IEnumerable<PortScanResult> portResults,
            IEnumerable<VulnerabilityResult> vulnResults,
            int totalTargets,
            int totalOpenPorts)
        {
            File.WriteAllText(
                filePath,
                BuildJson(portResults, vulnResults, totalTargets, totalOpenPorts),
                Utf8WithBom);
        }

        /// <summary>
        /// CSV 字段转义：包含逗号、双引号、换行时用双引号包裹，内部双引号双写。
        /// </summary>
        public static string EscapeCsvField(string value)
        {
            if (string.IsNullOrEmpty(value)) return "";
            if (value.Contains(',') || value.Contains('"') || value.Contains('\n') || value.Contains('\r'))
            {
                return "\"" + value.Replace("\"", "\"\"") + "\"";
            }
            return value;
        }
    }
}
