using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using NetSecurityScanner.Models;
using NetSecurityScanner.Services;

namespace VulnDiag
{
    public class Program
    {
        public static async Task<int> Main(string[] args)
        {
            Console.WriteLine("===========================================");
            Console.WriteLine(" 漏洞数据库加载验证 (修复后)");
            Console.WriteLine("===========================================");
            Console.WriteLine();

            int exitCode = 0;
            try
            {
                var scanner = new VulnerabilityScanner();
                await scanner.InitializeAsync(CancellationToken.None);

                // 用反射获取数据库大小
                var dbField = typeof(VulnerabilityScanner).GetField("_vulnerabilityDatabase",
                    System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Instance);
                var db = (List<VulnerabilityData>)dbField.GetValue(scanner);
                Console.WriteLine($"✓ 漏洞数据库大小: {db.Count} 条");
                Console.WriteLine();

                if (db.Count <= 3)
                {
                    Console.WriteLine("❌ 数据库仍然只有 3 条,修复未生效");
                    exitCode = 1;
                }
                else
                {
                    Console.WriteLine("✅ 数据库加载修复成功!显示前 10 条:");
                    foreach (var v in db.Take(10))
                    {
                        var ports = v.AffectedPorts != null && v.AffectedPorts.Any()
                            ? string.Join(",", v.AffectedPorts) : "无";
                        Console.WriteLine($"  - {v.CveId,-18} | {v.RiskLevel,-4} | 端口=[{ports,-15}] | {v.Name}");
                    }

                    Console.WriteLine();
                    Console.WriteLine("测试数据库匹配:");
                    var matchMethod = typeof(VulnerabilityScanner).GetMethod("MatchVulnerabilitiesFromDatabase",
                        System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Instance);
                    var testCases = new (int port, string service)[]
                    {
                        (22, "ssh"), (80, "http"), (443, "https"), (445, "smb"),
                        (3389, "rdp"), (3306, "mysql"), (6379, "redis"), (8080, "http")
                    };
                    int totalMatched = 0;
                    foreach (var (port, service) in testCases)
                    {
                        var portInfo = new PortInfo { PortNumber = port, Service = service, Protocol = "tcp", Host = "192.168.1.100" };
                        var matched = (List<VulnerabilityResult>)matchMethod.Invoke(scanner, new object[] { "192.168.1.100", portInfo });
                        Console.WriteLine($"  端口 {port,4} ({service,-6}): {matched.Count} 个漏洞");
                        totalMatched += matched.Count;
                    }
                    Console.WriteLine();
                    Console.WriteLine($"✅ 总匹配: {totalMatched} 个漏洞");
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"❌ 异常: {ex.GetType().Name}: {ex.Message}");
                exitCode = 1;
            }

            Console.WriteLine();
            Console.WriteLine($"退出码: {exitCode}");
            return exitCode;
        }
    }
}
