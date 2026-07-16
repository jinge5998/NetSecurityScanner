using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using NetSecurityScanner.Models;
using NetSecurityScanner.Services;

namespace NetSecurityScanner.Services
{
    public class ScanService
    {
        private PortScanner _portScanner;
        private VulnerabilityScanner _vulnerabilityScanner;

        public ScanService()
        {
            _portScanner = new PortScanner();
            _vulnerabilityScanner = new VulnerabilityScanner();
        }

        public async Task<List<PortScanResult>> PerformPortScanAsync(string targetIp, string portRange, IProgress<int> progress = null, CancellationToken cancellationToken = default)
        {
            var ports = ParsePortRange(portRange);
            if (ports == null || !ports.Any())
            {
                throw new ArgumentException("无效的端口范围");
            }

            return await _portScanner.ScanPortsAsync(targetIp, ports, progress, cancellationToken);
        }

        public async Task<List<VulnerabilityResult>> PerformVulnerabilityScanAsync(string targetIp, CancellationToken cancellationToken = default)
        {
            return await _vulnerabilityScanner.ScanAsync(targetIp, new List<PortInfo>(), "standard", null, cancellationToken);
        }

        public async Task<List<VulnerabilityResult>> PerformVulnerabilityScanAsync(string targetIp, List<PortScanResult> portResults, IProgress<int> progress = null, CancellationToken cancellationToken = default)
        {
            // 将旧的IProgress<int>转换为新的IProgress<(string stage, int progress)>
            IProgress<(string message, int percentage)> newProgress = null;
            if (progress != null)
            {
                newProgress = new Progress<(string message, int percentage)>(tuple => progress.Report(tuple.percentage));
            }

            // 转换 PortScanResult 到 PortInfo
            var portInfos = portResults.Select(p => new PortInfo { PortNumber = p.PortNumber, Service = p.Service }).ToList();

            return await _vulnerabilityScanner.ScanAsync(targetIp, portInfos, "standard", newProgress, cancellationToken);
        }

        // 添加 ParsePortRange 方法
        public List<int> ParsePortRange(string portRange)
        {
            var ports = new List<int>();

            if (portRange.Contains(','))
            {
                // 解析逗号分隔的端口列表
                string[] portParts = portRange.Split(',');
                foreach (string portPart in portParts)
                {
                    if (int.TryParse(portPart.Trim(), out int port))
                    {
                        if (port >= 1 && port <= 65535)
                        {
                            ports.Add(port);
                        }
                    }
                }
            }
            else if (portRange.Contains('-'))
            {
                // 解析范围端口
                string[] rangeParts = portRange.Split('-');
                if (rangeParts.Length == 2 && 
                    int.TryParse(rangeParts[0].Trim(), out int startPort) && 
                    int.TryParse(rangeParts[1].Trim(), out int endPort))
                {
                    if (startPort >= 1 && startPort <= 65535 && 
                        endPort >= 1 && endPort <= 65535 && 
                        startPort <= endPort)
                    {
                        for (int i = startPort; i <= endPort; i++)
                        {
                            ports.Add(i);
                        }
                    }
                }
            }
            else
            {
                // 单个端口
                if (int.TryParse(portRange, out int port))
                {
                    if (port >= 1 && port <= 65535)
                    {
                        ports.Add(port);
                    }
                }
            }

            return ports.Distinct().OrderBy(p => p).ToList();
        }
    }
}