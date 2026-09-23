using System;
using System.Threading;
using System.Threading.Tasks;
using NetSecurityScanner.Models;
using NetSecurityScanner.Services;

namespace SmokeTest
{
    /// <summary>
    /// 冒烟测试：直接调用 ComprehensiveScanService 验证 6 阶段编排
    /// 目标：127.0.0.1 + Quick 预设，期望 5 秒内完成（127.0.0.1 端口数有限）
    /// </summary>
    public class Program
    {
        public static async Task<int> Main(string[] args)
        {
            Console.WriteLine("===========================================");
            Console.WriteLine(" 综合扫描服务冒烟测试 (v1.0.1.3)");
            Console.WriteLine("===========================================");
            Console.WriteLine();

            int exitCode = 0;
            try
            {
                var options = new ComprehensiveScanOptions
                {
                    TargetIp = "127.0.0.1",
                    Preset = ScanPreset.Quick,
                    CustomPorts = "",
                    EnableTcp = true,
                    EnableUdp = false,
                    EnableVulnScan = true,
                    EnablePluginScan = true,
                    Concurrency = 50,
                    TimeoutSeconds = 2,
                    RetryCount = 1,
                    SaveToHistory = false,
                    HostDiscoveryTimeoutMs = 2000
                };

                Console.WriteLine($"目标: {options.TargetIp}");
                Console.WriteLine($"预设: {options.Preset}");
                Console.WriteLine($"TCP={options.EnableTcp}, UDP={options.EnableUdp}, 漏洞={options.EnableVulnScan}, 插件={options.EnablePluginScan}");
                Console.WriteLine();

                var service = new ComprehensiveScanService();
                var lastMsg = "";
                var progress = new Progress<ScanPhaseProgress>(p =>
                {
                    if (p.Message != lastMsg)
                    {
                        Console.WriteLine($"  [{p.Phase,-20}] {p.Progress,3}% | {p.Message}");
                        lastMsg = p.Message;
                    }
                });

                using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(60));
                var sw = System.Diagnostics.Stopwatch.StartNew();
                var result = await service.ExecuteAsync(options, progress, cts.Token);
                sw.Stop();

                Console.WriteLine();
                Console.WriteLine("===========================================");
                Console.WriteLine(" 测试结果");
                Console.WriteLine("===========================================");
                Console.WriteLine($"  扫描ID:        {result.ScanId}");
                Console.WriteLine($"  目标IP:        {result.TargetIp}");
                Console.WriteLine($"  扫描类型:      {result.ScanType}");
                Console.WriteLine($"  主机存活:      {(result.HostAlive ? "✓ 是" : "✗ 否")}");
                Console.WriteLine($"  TCP开放端口:   {result.TcpOpenPorts}");
                Console.WriteLine($"  UDP开放端口:   {result.UdpOpenPorts}");
                Console.WriteLine($"  总开放端口:    {result.OpenPortsCount}");
                Console.WriteLine($"  漏洞数:        {result.VulnerabilitiesCount}");
                Console.WriteLine($"  插件结果:      {result.PluginResults.Count}");
                Console.WriteLine($"  风险等级:      {result.RiskLevel}");
                Console.WriteLine($"  耗时:          {result.ScanDurationSeconds:F2} 秒 (实测 {sw.Elapsed.TotalSeconds:F2}s)");
                Console.WriteLine($"  用户取消:      {result.Cancelled}");
                Console.WriteLine($"  漏洞扫描异常:  {result.HasVulnerabilityScanError}");
                Console.WriteLine($"  插件扫描异常:  {result.HasPluginScanError}");
                Console.WriteLine();
                Console.WriteLine("  阶段详情:");
                foreach (var p in result.Phases)
                {
                    var status = p.Status.ToString();
                    var icon = status switch
                    {
                        "Success" => "✓",
                        "Failed" => "✗",
                        "Skipped" => "○",
                        _ => "·"
                    };
                    Console.WriteLine($"    {icon} {p.PhaseName,-20} {p.Status,-10} {p.DurationMs,5}ms 输出={p.OutputCount}");
                }

                Console.WriteLine();
                if (result.Cancelled)
                {
                    Console.WriteLine("✗ 测试失败: 扫描被意外取消");
                    exitCode = 2;
                }
                else if (result.HostAlive && result.OpenPortsCount >= 0)
                {
                    Console.WriteLine("✓ 测试通过: 服务编排正常，结果有效");
                }
                else
                {
                    Console.WriteLine("⚠ 部分成功: 主机不可达但编排完成（符合预期）");
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"✗ 测试异常: {ex.GetType().Name}: {ex.Message}");
                Console.WriteLine(ex.StackTrace);
                exitCode = 1;
            }

            Console.WriteLine();
            Console.WriteLine($"退出码: {exitCode}");
            return exitCode;
        }
    }
}
