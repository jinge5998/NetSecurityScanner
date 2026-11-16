using NetSecurityScanner.Models;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;

namespace NetSecurityScanner.Core.Services
{
    /// <summary>
    /// 扫描结果导出服务，支持 CSV/JSON 导出（CSV 带 UTF-8 BOM）。
    /// </summary>
    public class ScanExportService
    {
        private static readonly UTF8Encoding Utf8WithBom = new UTF8Encoding(true);

        /// <summary>
        /// 将端口扫描与漏洞扫描结果导出为 CSV（含 UTF-8 BOM）。
        /// </summary>
        public string ExportToCsv(
            IEnumerable<PortScanResult> portResults,
            IEnumerable<VulnerabilityResult> vulnResults,
            ExportOptions options = null)
        {
            options ??= new ExportOptions();
            var sb = new StringBuilder();

            // 元信息
            sb.AppendLine($"导出时间,{EscapeCsvField(DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss"))}");
            sb.AppendLine($"导出类型,{EscapeCsvField(options.Title ?? "扫描结果导出")}");
            sb.AppendLine($"总目标数,{options.TotalTargets}");
            sb.AppendLine($"开放端口数,{options.TotalOpenPorts}");
            sb.AppendLine($"漏洞数,{options.TotalVulnerabilities}");
            sb.AppendLine();

            // 端口扫描结果
            sb.AppendLine("类型,目标IP,端口,状态,服务,版本,响应时间(ms)");
            foreach (var r in portResults ?? Enumerable.Empty<PortScanResult>())
            {
                sb.AppendLine(
                    $"端口扫描,{EscapeCsvField(r.TargetIp)},{r.PortNumber},{EscapeCsvField(r.Status)}," +
                    $"{EscapeCsvField(r.Service)},{EscapeCsvField(r.ServiceVersion)},{EscapeCsvField(r.ResponseTime)}");
            }

            if ((vulnResults?.Any() ?? false) && options.IncludeVulnerabilities)
            {
                sb.AppendLine();
                sb.AppendLine("类型,目标,端口,漏洞名称,CVE编号,风险等级,服务,描述");
                foreach (var v in vulnResults)
                {
                    sb.AppendLine(
                        $"漏洞扫描,{EscapeCsvField(v.Target)},{v.Port ?? 0},{EscapeCsvField(v.Name)}," +
                        $"{EscapeCsvField(v.CveId)},{EscapeCsvField(v.RiskLevel)},{EscapeCsvField(v.Service)}," +
                        $"{EscapeCsvField(v.Description)}");
                }
            }

            return sb.ToString();
        }

        /// <summary>
        /// 将端口扫描与漏洞扫描结果导出为 JSON（含 UTF-8 BOM）。
        /// </summary>
        public string ExportToJson(
            IEnumerable<PortScanResult> portResults,
            IEnumerable<VulnerabilityResult> vulnResults,
            ExportOptions options = null)
        {
            options ??= new ExportOptions();
            var report = new
            {
                ExportTime = DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss"),
                Title = options.Title ?? "扫描结果导出",
                TotalTargets = options.TotalTargets,
                TotalOpenPorts = options.TotalOpenPorts,
                TotalVulnerabilities = options.TotalVulnerabilities,
                IncludeVulnerabilities = options.IncludeVulnerabilities,
                PortScanResults = portResults ?? Enumerable.Empty<PortScanResult>(),
                VulnerabilityResults = (options.IncludeVulnerabilities ? vulnResults : null) ?? Enumerable.Empty<VulnerabilityResult>()
            };

            var serializerOptions = new JsonSerializerOptions
            {
                WriteIndented = true,
                Encoder = System.Text.Encodings.Web.JavaScriptEncoder.UnsafeRelaxedJsonEscaping
            };
            return JsonSerializer.Serialize(report, serializerOptions);
        }

        /// <summary>
        /// 保存 CSV 到文件。
        /// </summary>
        public async Task SaveCsvToFileAsync(
            string filePath,
            IEnumerable<PortScanResult> portResults,
            IEnumerable<VulnerabilityResult> vulnResults,
            ExportOptions options = null)
        {
            var content = ExportToCsv(portResults, vulnResults, options);
            await File.WriteAllTextAsync(filePath, content, Utf8WithBom);
        }

        /// <summary>
        /// 保存 JSON 到文件。
        /// </summary>
        public async Task SaveJsonToFileAsync(
            string filePath,
            IEnumerable<PortScanResult> portResults,
            IEnumerable<VulnerabilityResult> vulnResults,
            ExportOptions options = null)
        {
            var content = ExportToJson(portResults, vulnResults, options);
            await File.WriteAllTextAsync(filePath, content, Utf8WithBom);
        }

        private static string EscapeCsvField(string value)
        {
            if (string.IsNullOrEmpty(value)) return "";
            if (value.Contains(',') || value.Contains('"') || value.Contains('\n') || value.Contains('\r'))
            {
                return "\"" + value.Replace("\"", "\"\"") + "\"";
            }
            return value;
        }
    }

    /// <summary>
    /// 导出选项。
    /// </summary>
    public class ExportOptions
    {
        public string Title { get; set; }
        public int TotalTargets { get; set; }
        public int TotalOpenPorts { get; set; }
        public int TotalVulnerabilities { get; set; }
        public bool IncludeVulnerabilities { get; set; } = true;
    }
}
