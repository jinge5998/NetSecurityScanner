using System;
using System.Collections.Generic;
using System.Linq;
using System.Reflection;
using FluentAssertions;
using NetSecurityScanner.Core.Models;
using NetSecurityScanner.Core.Services;
using Xunit;

namespace NetSecurityScanner.Tests
{
    /// <summary>
    /// 专家模式配置项「生效性」契约测试。
    ///
    /// 存在意义：程序自身从不执行 nmap，GenerateNmapCommand 的输出只用于命令预览与导出；
    /// 实际扫描由 Rust 引擎 / C# 内置扫描器执行，且只消费 ScanProfileConfig 的少量字段。
    /// 因此界面上大量可勾选的高级选项对真实扫描行为没有任何影响，而界面未作任何提示，
    /// 构成实质性的功能误导（详见 docs/专家模式功能完善度检查报告.md 第三节）。
    ///
    /// 本测试把「每个配置项到底影响什么」固化为可执行的契约：
    ///   1) 反射遍历 ExpertScanConfiguration 的全部属性，要求每个属性都被显式归类，
    ///      新增字段若未归类 → 测试失败，强制开发者当场决定它是否接线到扫描引擎；
    ///   2) 对「影响真实扫描」的字段，逐项断言其确实改变了下发给引擎的参数或解析结果；
    ///   3) 对「仅命令生成」的字段，逐项断言其确实出现在 Nmap 命令中，
    ///      并把不可实现的字段记入白名单以免被误当作待修缺陷。
    /// </summary>
    public class ExpertScanConfigEffectivenessContractTests
    {
        /// <summary>
        /// 影响真实扫描行为的字段：通过 ScanProfileConfig 下发到引擎，
        /// 或通过 ResolveTargets / ResolvePorts 改变实际扫描的目标与端口集合，
        /// 或影响扫描结果的保存与日志。
        /// </summary>
        private static readonly HashSet<string> AffectsActualScan = new()
        {
            // —— 下发到 ScanProfileConfig ——
            nameof(ExpertScanConfiguration.TcpConcurrency),
            nameof(ExpertScanConfiguration.UdpConcurrency),
            nameof(ExpertScanConfiguration.TcpTimeout),
            nameof(ExpertScanConfiguration.UdpTimeout),
            nameof(ExpertScanConfiguration.RetryCount),
            nameof(ExpertScanConfiguration.ServiceDetection),
            nameof(ExpertScanConfiguration.PingProbe),
            nameof(ExpertScanConfiguration.HostDiscovery),

            // —— 影响 ResolveTargets / ResolvePorts 的解析结果 ——
            nameof(ExpertScanConfiguration.TargetType),
            nameof(ExpertScanConfiguration.TargetValue),
            nameof(ExpertScanConfiguration.ExcludeHosts),
            nameof(ExpertScanConfiguration.Randomize),
            nameof(ExpertScanConfiguration.RandomTargetOrder),
            nameof(ExpertScanConfiguration.PortMode),
            nameof(ExpertScanConfiguration.CustomPorts),
            nameof(ExpertScanConfiguration.ExcludePorts),
            nameof(ExpertScanConfiguration.RandomPortOrder),

            // —— 决定下发给引擎的协议（tcp / udp / both）——
            nameof(ExpertScanConfiguration.TcpScan),
            nameof(ExpertScanConfiguration.UdpScan),

            // —— 影响 C# 内置扫描器（ExecuteNativeScanAsync）的发包节奏 ——
            nameof(ExpertScanConfiguration.RateLimit),
            nameof(ExpertScanConfiguration.PacketRate),
            nameof(ExpertScanConfiguration.StealthMode),

            // —— 影响结果保存与流程记录 ——
            nameof(ExpertScanConfiguration.ReverseDns),
            nameof(ExpertScanConfiguration.SaveOutput),
            nameof(ExpertScanConfiguration.OutputDir),
            nameof(ExpertScanConfiguration.StartTime),
        };

        /// <summary>
        /// 仅影响 Nmap 命令生成、对程序自身扫描行为无影响的字段。
        ///
        /// 其中标注 [nmap-only] 的项依赖原始套接字构造能力，
        /// 在纯 TCP 连接扫描模型下原理上无法由内置引擎实现，只能交由 nmap 执行；
        /// 这类字段应在界面上明确标注为「仅生成命令」，而不是试图接线。
        /// </summary>
        private static readonly HashSet<string> CommandGenerationOnly = new()
        {
            // 可实现但尚未接线到引擎的（属真实待修项）
            nameof(ExpertScanConfiguration.SynScan),          // 需原始套接字 + 管理员权限
            nameof(ExpertScanConfiguration.OsDetection),      // 需 TCP/IP 协议栈指纹
            nameof(ExpertScanConfiguration.ServiceIntensity), // 引擎侧可做探测深度分级

            // [nmap-only] 原理上无法由内置 TCP 连接扫描实现
            nameof(ExpertScanConfiguration.Mtu),
            nameof(ExpertScanConfiguration.FragmentPackets),
            nameof(ExpertScanConfiguration.BadChecksum),
            nameof(ExpertScanConfiguration.DecoyScan),
            nameof(ExpertScanConfiguration.DecoyIps),
            nameof(ExpertScanConfiguration.IdleScan),
            nameof(ExpertScanConfiguration.ZombieHost),
            nameof(ExpertScanConfiguration.SourceRouting),

            // 源端口：内置引擎使用 TcpClient，无法自由绑定源端口
            nameof(ExpertScanConfiguration.SourcePort),
            nameof(ExpertScanConfiguration.SourcePortMin),
            nameof(ExpertScanConfiguration.SourcePortMax),

            // 输出格式：自动保存仅有一条 JSON 分支，三个勾选框互不影响保存行为
            nameof(ExpertScanConfiguration.OutputJson),
            nameof(ExpertScanConfiguration.OutputHtml),
            nameof(ExpertScanConfiguration.OutputCsv),

            // 结果表过滤由独立的右键菜单完成，该配置项不参与任何过滤
            nameof(ExpertScanConfiguration.ShowOpenOnly),

            // 日志级别只作用于 nmap 命令的 -q/-v/-vv
            nameof(ExpertScanConfiguration.Verbosity),

            // 对应输入控件已从界面移除，CollectConfig 恒置为空串（见字段注释）
            nameof(ExpertScanConfiguration.NseScriptArgs),

            // NSE 脚本扫描：漏洞扫描判定中依赖它的分支不可达（见 ScanFlagUnreachableBranchTests）
            nameof(ExpertScanConfiguration.ScriptScan),
        };

        /// <summary>
        /// 既不影响扫描、也不影响命令生成的纯死配置。
        /// 保留在此是为了让「它确实无用」成为显式契约而非隐性遗漏；
        /// 一旦被接线到任一侧，应从本集合移出并归入对应分类，否则测试会失败。
        /// </summary>
        private static readonly HashSet<string> NotUsedAnywhere = new()
        {
            // 界面提供 500-10000ms 滑块可调节，但没有任何扫描逻辑或命令生成读取该值，
            // ScanProfileConfig 中亦无字段可承载 → 拖动滑块不产生任何效果。
            nameof(ExpertScanConfiguration.ServiceDetectTimeout),
        };

        private static IEnumerable<PropertyInfo> AllConfigProperties =>
            typeof(ExpertScanConfiguration).GetProperties(BindingFlags.Public | BindingFlags.Instance);

        [Fact]
        public void EveryConfigProperty_MustBeExplicitlyClassified()
        {
            // 核心守卫：新增配置字段必须当场归类，否则测试失败。
            // 这是防止「加了界面选项却忘记接线」再次发生的机制。
            var classified = AffectsActualScan
                .Union(CommandGenerationOnly)
                .Union(NotUsedAnywhere)
                .ToHashSet();

            var actual = AllConfigProperties.Select(p => p.Name).ToList();

            var unclassified = actual.Where(n => !classified.Contains(n)).ToList();
            var stale = classified.Where(n => !actual.Contains(n)).ToList();

            unclassified.Should().BeEmpty(
                "以下配置字段未归类，请确认它究竟影响真实扫描、仅影响 Nmap 命令生成，还是完全未被使用：" +
                string.Join(", ", unclassified));

            stale.Should().BeEmpty(
                "以下字段名已不存在于 ExpertScanConfiguration，请同步更新契约测试：" +
                string.Join(", ", stale));
        }

        [Fact]
        public void Classifications_MustBeMutuallyExclusive()
        {
            // 一个字段不能既「影响扫描」又「仅命令生成」，否则契约本身自相矛盾
            AffectsActualScan.Intersect(CommandGenerationOnly).Should().BeEmpty();
            AffectsActualScan.Intersect(NotUsedAnywhere).Should().BeEmpty();
            CommandGenerationOnly.Intersect(NotUsedAnywhere).Should().BeEmpty();
        }

        #region 影响真实扫描的字段必须确实改变引擎参数

        [Theory]
        [InlineData(nameof(ExpertScanConfiguration.TcpConcurrency), 50, 300)]
        [InlineData(nameof(ExpertScanConfiguration.UdpConcurrency), 20, 150)]
        [InlineData(nameof(ExpertScanConfiguration.TcpTimeout), 500, 3000)]
        [InlineData(nameof(ExpertScanConfiguration.UdpTimeout), 1000, 5000)]
        [InlineData(nameof(ExpertScanConfiguration.RetryCount), 1, 4)]
        public void ScanProfileConfigFields_ShouldActuallyReachEngine(string property, int lowValue, int highValue)
        {
            var baseline = ScanConfigMapper.ToScanProfileConfig(new ExpertScanConfiguration());
            var changed = ScanConfigMapper.ToScanProfileConfig(
                WithProperty(new ExpertScanConfiguration(), property, highValue));

            changed.Should().NotBeEquivalentTo(baseline,
                $"{property} 属于「影响真实扫描」分类，必须体现在下发给引擎的 ScanProfileConfig 中");
        }

        [Fact]
        public void ServiceDetection_ShouldReachEngine()
        {
            ScanConfigMapper.ToScanProfileConfig(new ExpertScanConfiguration { ServiceDetection = true })
                .EnableServiceDetection.Should().BeTrue();

            ScanConfigMapper.ToScanProfileConfig(new ExpertScanConfiguration { ServiceDetection = false })
                .EnableServiceDetection.Should().BeFalse();
        }

        [Fact]
        public void PingProbe_ShouldReachEngineOnlyWhenHostDiscoveryAlsoEnabled()
        {
            // 引擎的 EnablePingProbe 由 PingProbe && HostDiscovery 共同决定（见 ExecuteRustScanAsync）
            ScanConfigMapper.ToScanProfileConfig(new ExpertScanConfiguration
            {
                PingProbe = true,
                HostDiscovery = true
            }).EnablePingProbe.Should().BeTrue();

            ScanConfigMapper.ToScanProfileConfig(new ExpertScanConfiguration
            {
                PingProbe = true,
                HostDiscovery = false
            }).EnablePingProbe.Should().BeFalse();

            ScanConfigMapper.ToScanProfileConfig(new ExpertScanConfiguration
            {
                PingProbe = false,
                HostDiscovery = true
            }).EnablePingProbe.Should().BeFalse();
        }

        [Fact]
        public void ToScanProfileConfig_ShouldMapTimeoutFieldsCorrectly()
        {
            var result = ScanConfigMapper.ToScanProfileConfig(new ExpertScanConfiguration
            {
                TcpConcurrency = 120,
                UdpConcurrency = 45,
                TcpTimeout = 800,
                UdpTimeout = 2500,
                RetryCount = 3,
                ServiceDetection = true,
                PingProbe = true,
                HostDiscovery = true
            });

            result.TcpConcurrency.Should().Be(120);
            result.UdpConcurrency.Should().Be(45);
            result.TimeoutMs.Should().Be(800);
            result.UdpTimeoutMs.Should().Be(2500);
            result.RetryCount.Should().Be(3);
            result.EnableServiceDetection.Should().BeTrue();
            result.EnablePingProbe.Should().BeTrue();
        }

        [Fact]
        public void ToScanProfileConfig_ZeroUdpTimeout_ShouldSignalCallerFallback()
        {
            // UdpTimeoutMs == 0 表示「未设置」，由调用方的 udpTimeoutMs 参数兜底
            ScanConfigMapper.ToScanProfileConfig(new ExpertScanConfiguration { UdpTimeout = 0 })
                .UdpTimeoutMs.Should().Be(0);
        }

        [Fact]
        public void ExcludePorts_ShouldChangeResolvedPortSet()
        {
            var baseline = ExpertScanPlanner.ResolvePorts(new ExpertScanConfiguration
            {
                PortMode = "Custom",
                CustomPorts = "22,80,443"
            });

            var withExclusion = ExpertScanPlanner.ResolvePorts(new ExpertScanConfiguration
            {
                PortMode = "Custom",
                CustomPorts = "22,80,443",
                ExcludePorts = "80"
            });

            withExclusion.Should().NotBeEquivalentTo(baseline,
                "ExcludePorts 属于「影响真实扫描」分类，必须改变实际扫描的端口集合");
        }

        [Fact]
        public void ExcludeHosts_ShouldChangeResolvedTargetSet()
        {
            var baseline = ExpertScanPlanner.ResolveTargets(new ExpertScanConfiguration
            {
                TargetType = "File",
                TargetValue = "10.0.0.1\n10.0.0.2"
            });

            var withExclusion = ExpertScanPlanner.ResolveTargets(new ExpertScanConfiguration
            {
                TargetType = "File",
                TargetValue = "10.0.0.1\n10.0.0.2",
                ExcludeHosts = "10.0.0.2"
            });

            withExclusion.Should().NotBeEquivalentTo(baseline,
                "ExcludeHosts 属于「影响真实扫描」分类，必须改变实际扫描的目标集合");
        }

        #endregion

        #region 仅命令生成的字段必须确实出现在 Nmap 命令中

        [Fact]
        public void CommandOnlyFields_ShouldProduceDistinctNmapCommands()
        {
            // 这些字段对真实扫描无效，但必须在导出的 Nmap 命令里体现，
            // 否则用户连「复制命令自己去跑」这条退路都没有。
            var cases = new (string Property, object NonDefaultValue)[]
            {
                (nameof(ExpertScanConfiguration.SynScan), true),
                (nameof(ExpertScanConfiguration.OsDetection), true),
                (nameof(ExpertScanConfiguration.ServiceIntensity), 5),
                (nameof(ExpertScanConfiguration.Mtu), "64"),
                (nameof(ExpertScanConfiguration.FragmentPackets), true),
                (nameof(ExpertScanConfiguration.BadChecksum), true),
                (nameof(ExpertScanConfiguration.SourceRouting), true),
                (nameof(ExpertScanConfiguration.ShowOpenOnly), true),
                (nameof(ExpertScanConfiguration.ScriptScan), true),
            };

            foreach (var (property, value) in cases)
            {
                var baseline = NmapCommandBuilder.Build(new ExpertScanConfiguration(), ttl: 64, timestamp: "t");
                var changed = NmapCommandBuilder.Build(
                    WithProperty(new ExpertScanConfiguration(), property, value), ttl: 64, timestamp: "t");

                changed.Should().NotBe(baseline,
                    $"{property} 归类为「仅命令生成」，必须在 Nmap 命令中产生可见差异");
            }
        }

        [Fact]
        public void DecoyAndIdleFields_RequireCompanionValueToAppear()
        {
            // 诱饵 / 僵尸扫描需同时填写地址，否则不输出对应参数
            var decoy = NmapCommandBuilder.Build(new ExpertScanConfiguration
            {
                DecoyScan = true,
                DecoyIps = "10.0.0.9"
            }, ttl: 64, timestamp: "t");
            decoy.Should().Contain("-D 10.0.0.9");

            var idle = NmapCommandBuilder.Build(new ExpertScanConfiguration
            {
                IdleScan = true,
                ZombieHost = "10.0.0.7"
            }, ttl: 64, timestamp: "t");
            idle.Should().Contain("-sI 10.0.0.7");
        }

        [Fact]
        public void Verbosity_ShouldChangeNmapCommand()
        {
            var quiet = NmapCommandBuilder.Build(new ExpertScanConfiguration { Verbosity = 0 }, ttl: 64, timestamp: "t");
            var verbose = NmapCommandBuilder.Build(new ExpertScanConfiguration { Verbosity = 3 }, ttl: 64, timestamp: "t");

            quiet.Should().Contain(" -q ");
            verbose.Should().Contain(" -vv ");
        }

        [Fact]
        public void OutputFormatFlags_ShouldChangeNmapCommand()
        {
            var json = NmapCommandBuilder.Build(new ExpertScanConfiguration
            {
                OutputJson = true,
                OutputHtml = false,
                OutputCsv = false,
                SaveOutput = false
            }, ttl: 64, timestamp: "t");

            var csv = NmapCommandBuilder.Build(new ExpertScanConfiguration
            {
                OutputJson = false,
                OutputHtml = false,
                OutputCsv = true,
                SaveOutput = false
            }, ttl: 64, timestamp: "t");

            json.Should().Contain("-oJ");
            json.Should().NotContain("-oG");
            csv.Should().Contain("-oG");
            csv.Should().NotContain("-oJ");
        }

        #endregion

        #region 死配置必须被记录在案

        [Fact]
        public void ServiceDetectTimeout_ShouldAffectNothing()
        {
            // 本测试是「已知缺陷」的显式记录：该字段目前对扫描与命令生成均无影响。
            // 修复后应把字段移出 NotUsedAnywhere 分类，本测试会随之失败以提醒删除。
            var min = new ExpertScanConfiguration { ServiceDetectTimeout = 500 };
            var max = new ExpertScanConfiguration { ServiceDetectTimeout = 10000 };

            ScanConfigMapper.ToScanProfileConfig(min).Should()
                .BeEquivalentTo(ScanConfigMapper.ToScanProfileConfig(max));

            NmapCommandBuilder.Build(min, ttl: 64, timestamp: "t").Should()
                .Be(NmapCommandBuilder.Build(max, ttl: 64, timestamp: "t"));

            ExpertScanPlanner.ResolvePorts(min).Should().BeEquivalentTo(ExpertScanPlanner.ResolvePorts(max));
            ExpertScanPlanner.ResolveTargets(min).Should().BeEquivalentTo(ExpertScanPlanner.ResolveTargets(max));
        }

        #endregion

        private static ExpertScanConfiguration WithProperty(ExpertScanConfiguration config, string name, object value)
        {
            var prop = typeof(ExpertScanConfiguration).GetProperty(name)
                       ?? throw new ArgumentException($"ExpertScanConfiguration 上不存在属性 {name}");
            prop.SetValue(config, Convert.ChangeType(value, prop.PropertyType));
            return config;
        }
    }
}
