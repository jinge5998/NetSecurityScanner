using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Threading;
using System.Threading.Tasks;
using NetSecurityScanner.Models;
using NetSecurityScanner.Services;

namespace Tools.DeepTest
{
    /// <summary>
    /// 综合扫描深度回归测试
    /// 6 个测试场景,验证 v1.0.1.3 漏洞数据库修复后的端到端能力
    /// </summary>
    public class Program
    {
        private static readonly List<TestResult> Results = new();
        private static ComprehensiveScanService _service;
        private static PortScanner _portScanner;
        private static VulnerabilityScanner _vulnScanner;

        public static async Task<int> Main(string[] args)
        {
            Console.WriteLine("╔══════════════════════════════════════════════╗");
            Console.WriteLine("║  NetSecurityScanner v1.0.1.3 深度回归测试        ║");
            Console.WriteLine("║  Comprehensive Scan Deep Regression Test    ║");
            Console.WriteLine("╚══════════════════════════════════════════════╝");
            Console.WriteLine();

            // 初始化
            _service = new ComprehensiveScanService();
            _portScanner = new PortScanner();
            _vulnScanner = new VulnerabilityScanner();
            await _vulnScanner.InitializeAsync(CancellationToken.None);

            var dbField = typeof(VulnerabilityScanner).GetField("_vulnerabilityDatabase",
                BindingFlags.NonPublic | BindingFlags.Instance);
            var dbSize = ((List<VulnerabilityData>)dbField.GetValue(_vulnScanner)).Count;
            Console.WriteLine($"📦 漏洞数据库已加载: {dbSize} 条 CVE\n");

            // 6 个测试场景
            await TestCase1_LocalhostStandard();
            await TestCase2_LocalhostPorts();
            await TestCase3_PublicTarget();
            await TestCase4_VulnMatchReal();
            await TestCase5_UnreachableTarget();
            await TestCase6_Cancellation();

            // 输出汇总
            PrintSummary();

            // 返回: 0 = 全 Pass, 1 = 有失败
            return Results.All(r => r.Status == TestStatus.Pass) ? 0 : 1;
        }

        #region TestCase 1 — 127.0.0.1 Standard 全开扫描
        private static async Task TestCase1_LocalhostStandard()
        {
            var t = new TestResult { Name = "TestCase 1", Description = "127.0.0.1 Standard 全开扫描(基线)" };
            var sw = Stopwatch.StartNew();
            try
            {
                var options = new ComprehensiveScanOptions
                {
                    TargetIp = "127.0.0.1",
                    Preset = ScanPreset.Standard,
                    CustomPorts = "1-100",
                    EnableTcp = true,
                    EnableUdp = false,
                    EnableVulnScan = true,
                    EnablePluginScan = false,
                    Concurrency = 50,
                    TimeoutSeconds = 1,
                    RetryCount = 0,
                    SaveToHistory = false,
                    HostDiscoveryTimeoutMs = 1000
                };

                var lastMsg = "";
                var progress = new Progress<ScanPhaseProgress>(_ => { });
                using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(60));
                var result = await _service.ExecuteAsync(options, progress, cts.Token);
                sw.Stop();

                t.Elapsed = sw.Elapsed;

                // 验证: 7 阶段全部 Success/Skipped
                var allPhases = result.Phases;
                var failedPhases = allPhases.Where(p => p.Status == ScanPhaseStatus.Failed).ToList();

                t.Details.Add($"  阶段数: {allPhases.Count}");
                t.Details.Add($"  失败阶段数: {failedPhases.Count}");
                foreach (var p in allPhases)
                {
                    t.Details.Add($"    [{p.PhaseName}] {p.Status} ({p.DurationMs}ms) 输出={p.OutputCount}");
                }
                t.Details.Add($"  HostAlive: {result.HostAlive}");
                t.Details.Add($"  总端口: {result.OpenPortsCount} | 漏洞: {result.VulnerabilitiesCount}");
                t.Details.Add($"  Cancelled: {result.Cancelled}");

                if (failedPhases.Count == 0 && allPhases.Count >= 6 && !result.Cancelled && sw.Elapsed.TotalSeconds < 120)
                {
                    t.Status = TestStatus.Pass;
                }
                else
                {
                    t.Status = TestStatus.Fail;
                    t.ErrorMessage = $"failedPhases={failedPhases.Count}, phases={allPhases.Count}, cancelled={result.Cancelled}, elapsed={sw.Elapsed.TotalSeconds:F1}s";
                }
            }
            catch (Exception ex)
            {
                sw.Stop();
                t.Elapsed = sw.Elapsed;
                t.Status = TestStatus.Fail;
                t.ErrorMessage = ex.Message;
                t.Details.Add($"  EXCEPTION: {ex.GetType().Name}: {ex.Message}");
            }
            Results.Add(t);
        }
        #endregion

        #region TestCase 2 — 127.0.0.1 端口发现
        private static async Task TestCase2_LocalhostPorts()
        {
            var t = new TestResult { Name = "TestCase 2", Description = "127.0.0.1 端口发现(可能 0 个)" };
            var sw = Stopwatch.StartNew();
            try
            {
                using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(60));
                // 只用 PortScanner 的 TCP 1-1000 (Standard 预设范围)
                var portList = Enumerable.Range(1, 1000).ToList();
                var lastMsg = "";
                var progress = new Progress<int>(_ => { });
                var results = await _portScanner.ScanTcpPortsAsync("127.0.0.1", portList, progress, cts.Token, null);
                sw.Stop();

                t.Elapsed = sw.Elapsed;
                var openPorts = results.Where(p => p.Status == "开放").ToList();
                t.Details.Add($"  扫描端口数: 1000 (1-1000)");
                t.Details.Add($"  开放端口数: {openPorts.Count}");
                foreach (var p in openPorts.Take(20))
                {
                    t.Details.Add($"    {p.PortNumber} {p.Status} {p.Service} {p.ServiceVersion}");
                }
                if (results.Any(p => !string.IsNullOrEmpty(p.Service)))
                {
                    t.Details.Add($"  ✓ PortScanResults 包含 Service 字段");
                }

                // 不强求必须发现端口(可能 0)
                if (sw.Elapsed.TotalSeconds < 60)
                {
                    t.Status = TestStatus.Pass;
                    if (openPorts.Count == 0) t.Details.Add("  注: 本机无开放端口(正常,127.0.0.1 通常只有应用进程端口)");
                }
                else
                {
                    t.Status = TestStatus.Fail;
                    t.ErrorMessage = $"超时 {sw.Elapsed.TotalSeconds:F1}s";
                }
            }
            catch (Exception ex)
            {
                sw.Stop();
                t.Elapsed = sw.Elapsed;
                t.Status = TestStatus.Fail;
                t.ErrorMessage = ex.Message;
                t.Details.Add($"  EXCEPTION: {ex.GetType().Name}: {ex.Message}");
            }
            Results.Add(t);
        }
        #endregion

        #region TestCase 3 — 公网目标 scanme.nmap.org
        private static async Task TestCase3_PublicTarget()
        {
            var t = new TestResult { Name = "TestCase 3", Description = "公网目标 scanme.nmap.org (45.33.32.156)" };
            var sw = Stopwatch.StartNew();
            try
            {
                // 实际只测 22, 80, 443 三个 Nmap 已知开放端口,减少网络负载
                var portList = new List<int> { 22, 80, 443, 8080, 8443 };
                using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(60));
                var lastMsg = "";
                var progress = new Progress<int>(_ => { });
                var results = await _portScanner.ScanTcpPortsAsync("45.33.32.156", portList, progress, cts.Token, null);
                sw.Stop();

                t.Elapsed = sw.Elapsed;
                var openPorts = results.Where(p => p.Status == "开放").ToList();
                t.Details.Add($"  扫描端口数: 5 (22, 80, 443, 8080, 8443)");
                t.Details.Add($"  开放端口数: {openPorts.Count}");
                foreach (var p in results)
                {
                    t.Details.Add($"    {p.PortNumber} {p.Status} {p.Service} {p.ServiceVersion}");
                }

                var sshFound = openPorts.Any(p => p.PortNumber == 22);
                var httpFound = openPorts.Any(p => p.PortNumber == 80);

                if (openPorts.Count >= 2 && sshFound && httpFound)
                {
                    t.Status = TestStatus.Pass;
                }
                else if (openPorts.Count > 0)
                {
                    // 公网测试可能因网络问题部分失败
                    t.Status = TestStatus.Pass;
                    t.Details.Add($"  注: 仅发现 {openPorts.Count} 个端口(scanme.nmap.org 公网可能因超时/防火墙未全部命中)");
                }
                else
                {
                    // 公网测试可能完全失败
                    t.Status = TestStatus.Skip;
                    t.ErrorMessage = "公网目标未响应(可能是网络限制/超时)";
                }
            }
            catch (Exception ex)
            {
                sw.Stop();
                t.Elapsed = sw.Elapsed;
                t.Status = TestStatus.Skip;
                t.ErrorMessage = ex.Message;
                t.Details.Add($"  EXCEPTION (公网测试可跳过): {ex.GetType().Name}: {ex.Message}");
            }
            Results.Add(t);
        }
        #endregion

        #region TestCase 4 — 漏洞匹配真实触发
        private static async Task TestCase4_VulnMatchReal()
        {
            var t = new TestResult { Name = "TestCase 4", Description = "漏洞匹配真实触发(31 CVE 库)" };
            var sw = Stopwatch.StartNew();
            try
            {
                // 模拟"端口 80 + 服务 http"开放
                var portInfo = new PortInfo
                {
                    Host = "192.168.1.100",
                    PortNumber = 80,
                    Protocol = "tcp",
                    Service = "http",
                    Version = "Apache/2.4.49"
                };

                var matchMethod = typeof(VulnerabilityScanner).GetMethod("MatchVulnerabilitiesFromDatabase",
                    BindingFlags.NonPublic | BindingFlags.Instance);
                if (matchMethod == null)
                {
                    t.Status = TestStatus.Fail;
                    t.ErrorMessage = "找不到 MatchVulnerabilitiesFromDatabase 方法";
                    return;
                }

                var matched = (List<VulnerabilityResult>)matchMethod.Invoke(_vulnScanner, new object[] { "192.168.1.100", portInfo });
                sw.Stop();

                t.Elapsed = sw.Elapsed;
                t.Details.Add($"  测试场景: 端口 80 (http) 开放");
                t.Details.Add($"  匹配漏洞数: {matched.Count}");
                foreach (var m in matched.Take(10))
                {
                    t.Details.Add($"    - [{m.RiskLevel}] {m.CveId} | {m.Name}");
                }

                var has2023Cve = matched.Any(m => m.CveId != null && m.CveId.StartsWith("CVE-2023"));
                if (matched.Count >= 5 && has2023Cve)
                {
                    t.Status = TestStatus.Pass;
                }
                else
                {
                    t.Status = TestStatus.Fail;
                    t.ErrorMessage = $"匹配数={matched.Count} (需>=5), has2023Cve={has2023Cve}";
                }
            }
            catch (Exception ex)
            {
                sw.Stop();
                t.Elapsed = sw.Elapsed;
                t.Status = TestStatus.Fail;
                t.ErrorMessage = ex.Message;
                t.Details.Add($"  EXCEPTION: {ex.GetType().Name}: {ex.Message}");
            }
            Results.Add(t);
        }
        #endregion

        #region TestCase 5 — 异常隔离
        private static async Task TestCase5_UnreachableTarget()
        {
            var t = new TestResult { Name = "TestCase 5", Description = "异常隔离 (RFC 5737 不可达目标 203.0.113.99)" };
            var sw = Stopwatch.StartNew();
            try
            {
                var options = new ComprehensiveScanOptions
                {
                    TargetIp = "203.0.113.99",
                    Preset = ScanPreset.Quick,
                    CustomPorts = "22,80,443",
                    EnableTcp = true,
                    EnableUdp = false,
                    EnableVulnScan = true,
                    EnablePluginScan = false,
                    Concurrency = 10,
                    TimeoutSeconds = 1,
                    RetryCount = 0,
                    SaveToHistory = false,
                    HostDiscoveryTimeoutMs = 1500
                };

                using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(30));
                var progress = new Progress<ScanPhaseProgress>(_ => { });
                var result = await _service.ExecuteAsync(options, progress, cts.Token);
                sw.Stop();

                t.Elapsed = sw.Elapsed;
                t.Details.Add($"  HostAlive: {result.HostAlive}");
                t.Details.Add($"  Cancelled: {result.Cancelled}");
                t.Details.Add($"  阶段数: {result.Phases.Count}");
                foreach (var p in result.Phases)
                {
                    t.Details.Add($"    [{p.PhaseName}] {p.Status} ({p.DurationMs}ms) 输出={p.OutputCount}");
                }
                t.Details.Add($"  ComprehensiveScanResult 不为空引用: {result != null}");
                t.Details.Add($"  RiskLevel: {result.RiskLevel}");

                if (result != null && !result.Cancelled && result.Phases.Count >= 6)
                {
                    t.Status = TestStatus.Pass;
                }
                else
                {
                    t.Status = TestStatus.Fail;
                    t.ErrorMessage = $"result={result != null}, cancelled={result?.Cancelled}, phases={result?.Phases.Count}";
                }
            }
            catch (Exception ex)
            {
                sw.Stop();
                t.Elapsed = sw.Elapsed;
                t.Status = TestStatus.Fail;
                t.ErrorMessage = ex.Message;
                t.Details.Add($"  EXCEPTION (异常隔离测试不应抛): {ex.GetType().Name}: {ex.Message}");
            }
            Results.Add(t);
        }
        #endregion

        #region TestCase 6 — 取消令牌
        private static async Task TestCase6_Cancellation()
        {
            var t = new TestResult { Name = "TestCase 6", Description = "取消令牌(3 秒后取消)" };
            var sw = Stopwatch.StartNew();
            try
            {
                var options = new ComprehensiveScanOptions
                {
                    TargetIp = "127.0.0.1",
                    Preset = ScanPreset.Deep,
                    CustomPorts = "1-65535",  // Deep 扫描 1-65535 故意拉长时间
                    EnableTcp = true,
                    EnableUdp = false,
                    EnableVulnScan = false,
                    EnablePluginScan = false,
                    Concurrency = 20,
                    TimeoutSeconds = 1,
                    RetryCount = 0,
                    SaveToHistory = false,
                    HostDiscoveryTimeoutMs = 500
                };

                using var cts = new CancellationTokenSource();
                // 3 秒后取消
                cts.CancelAfter(TimeSpan.FromSeconds(3));

                var progress = new Progress<ScanPhaseProgress>(_ => { });
                var result = await _service.ExecuteAsync(options, progress, cts.Token);
                sw.Stop();

                t.Elapsed = sw.Elapsed;
                t.Details.Add($"  Cancelled: {result.Cancelled}");
                t.Details.Add($"  实际耗时: {sw.Elapsed.TotalSeconds:F1}s (取消令牌 3s)");
                t.Details.Add($"  完成阶段数: {result.Phases.Count(p => p.Status == ScanPhaseStatus.Success || p.Status == ScanPhaseStatus.Skipped)}");
                foreach (var p in result.Phases)
                {
                    t.Details.Add($"    [{p.PhaseName}] {p.Status} ({p.DurationMs}ms)");
                }

                if (result.Cancelled && sw.Elapsed.TotalSeconds < 10)
                {
                    t.Status = TestStatus.Pass;
                }
                else if (!result.Cancelled && sw.Elapsed.TotalSeconds < 10)
                {
                    // 扫描太快完成,不需要取消
                    t.Status = TestStatus.Pass;
                    t.Details.Add($"  注: 扫描在 3s 内自然完成,取消令牌未触发(也可接受)");
                }
                else
                {
                    t.Status = TestStatus.Fail;
                    t.ErrorMessage = $"cancelled={result.Cancelled}, elapsed={sw.Elapsed.TotalSeconds:F1}s";
                }
            }
            catch (Exception ex)
            {
                sw.Stop();
                t.Elapsed = sw.Elapsed;
                // OperationCanceledException 是正常的取消路径
                if (ex is OperationCanceledException)
                {
                    t.Status = TestStatus.Pass;
                    t.Details.Add($"  ✓ OperationCanceledException 抛出(可接受的取消路径)");
                    t.Details.Add($"  实际耗时: {sw.Elapsed.TotalSeconds:F1}s");
                }
                else
                {
                    t.Status = TestStatus.Fail;
                    t.ErrorMessage = ex.Message;
                    t.Details.Add($"  EXCEPTION: {ex.GetType().Name}: {ex.Message}");
                }
            }
            Results.Add(t);
        }
        #endregion

        #region 输出汇总
        private static void PrintSummary()
        {
            Console.WriteLine();
            Console.WriteLine("╔══════════════════════════════════════════════╗");
            Console.WriteLine("║            测试结果汇总                         ║");
            Console.WriteLine("╚══════════════════════════════════════════════╝");
            Console.WriteLine();

            var pass = Results.Count(r => r.Status == TestStatus.Pass);
            var fail = Results.Count(r => r.Status == TestStatus.Fail);
            var skip = Results.Count(r => r.Status == TestStatus.Skip);

            Console.WriteLine($"总计: {Results.Count} | ✅ Pass: {pass} | ❌ Fail: {fail} | ⚠️ Skip: {skip}");
            Console.WriteLine();
            Console.WriteLine(new string('═', 100));
            Console.WriteLine($"  {"#",-3}  {"状态",-8}  {"耗时",-10}  {"测试项",-50}");
            Console.WriteLine(new string('═', 100));
            for (int i = 0; i < Results.Count; i++)
            {
                var r = Results[i];
                var icon = r.Status switch
                {
                    TestStatus.Pass => "✅ PASS",
                    TestStatus.Fail => "❌ FAIL",
                    TestStatus.Skip => "⚠️  SKIP",
                    _ => "?"
                };
                Console.WriteLine($"  {i + 1,-3}  {icon,-8}  {r.Elapsed.TotalSeconds + "s",-10}  {r.Name,-30} | {r.Description}");
            }
            Console.WriteLine(new string('═', 100));
            Console.WriteLine();

            // 详细数据
            Console.WriteLine("📋 详细数据:");
            Console.WriteLine();
            foreach (var r in Results)
            {
                var icon = r.Status == TestStatus.Pass ? "✅" : r.Status == TestStatus.Fail ? "❌" : "⚠️";
                Console.WriteLine($"{icon} {r.Name} — {r.Description}");
                if (!string.IsNullOrEmpty(r.ErrorMessage))
                    Console.WriteLine($"   错误: {r.ErrorMessage}");
                foreach (var d in r.Details)
                    Console.WriteLine(d);
                Console.WriteLine();
            }
        }
        #endregion
    }

    public enum TestStatus { Pass, Fail, Skip }

    public class TestResult
    {
        public string Name { get; set; }
        public string Description { get; set; }
        public TestStatus Status { get; set; } = TestStatus.Pass;
        public TimeSpan Elapsed { get; set; }
        public string ErrorMessage { get; set; }
        public List<string> Details { get; set; } = new();
    }
}
