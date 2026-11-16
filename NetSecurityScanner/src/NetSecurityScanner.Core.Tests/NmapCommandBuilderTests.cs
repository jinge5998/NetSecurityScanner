using System;
using System.Collections.Generic;
using System.Linq;
using FluentAssertions;
using NetSecurityScanner.Core.Models;
using NetSecurityScanner.Core.Services;
using Xunit;

namespace NetSecurityScanner.Tests
{
    /// <summary>
    /// Nmap 命令生成器测试。
    ///
    /// 背景：程序自身从不执行 nmap，GenerateNmapCommand 的输出只用于「命令预览框」与「导出命令文件」。
    /// 因此有大量界面选项仅影响该字符串、不影响实际扫描行为。
    /// 本测试类的核心价值是把这份「仅命令生成」清单固化为回归保护：
    /// 新增配置项若忘记接线到扫描引擎，ExpertScanConfigEffectivenessContractTests 会立即失败。
    /// </summary>
    public class NmapCommandBuilderTests
    {
        /// <summary>
        /// 固定 TTL 与时间戳，使命令输出可确定性断言。
        /// </summary>
        private static string Build(ExpertScanConfiguration config)
            => NmapCommandBuilder.Build(config, ttl: 64, timestamp: "20260101_000000");

        [Fact]
        public void Build_ShouldStartWithNmap()
        {
            Build(new ExpertScanConfiguration()).Should().StartWith("nmap ");
        }

        [Fact]
        public void Build_ShouldEndWithTarget()
        {
            var config = new ExpertScanConfiguration { TargetValue = "192.168.1.1" };

            Build(config).Should().EndWith(" 192.168.1.1");
        }

        [Fact]
        public void Build_EmptyTarget_ShouldUsePlaceholder()
        {
            Build(new ExpertScanConfiguration { TargetValue = "  " }).Should().Contain("<target>");
        }

        #region 扫描类型

        [Fact]
        public void Build_TcpScan_ShouldUseConnectScan()
        {
            Build(new ExpertScanConfiguration { TcpScan = true, UdpScan = false, SynScan = false })
                .Should().Contain(" -sT ");
        }

        [Fact]
        public void Build_SynScan_ShouldTakePrecedenceOverTcpConnect()
        {
            var cmd = Build(new ExpertScanConfiguration { TcpScan = true, SynScan = true });

            cmd.Should().Contain(" -sS ");
            cmd.Should().NotContain("-sT");
        }

        [Fact]
        public void Build_UdpScan_ShouldAddUdpFlag()
        {
            Build(new ExpertScanConfiguration { TcpScan = true, UdpScan = true })
                .Should().Contain(" -sU ");
        }

        [Fact]
        public void Build_NoProtocolSelected_WithPingProbe_ShouldUsePingScan()
        {
            // 配置默认 PingProbe = true：未选任何协议即「只做主机发现」，应生成 -sn
            Build(new ExpertScanConfiguration { TcpScan = false, UdpScan = false, SynScan = false })
                .Should().Contain(" -sn ");
        }

        [Fact]
        public void Build_NoProtocolSelected_WithoutPingProbe_ShouldDefaultToTcpConnect()
        {
            Build(new ExpertScanConfiguration
            {
                PingProbe = false,
                TcpScan = false,
                UdpScan = false,
                SynScan = false
            }).Should().Contain(" -sT ");
        }

        #endregion

        #region 服务与系统检测

        [Fact]
        public void Build_ServiceDetection_ShouldAddVersionFlagAndIntensity()
        {
            var cmd = Build(new ExpertScanConfiguration { ServiceDetection = true, ServiceIntensity = 5 });

            cmd.Should().Contain(" -sV ");
            cmd.Should().Contain(" --version-intensity 5 ");
        }

        [Fact]
        public void Build_ServiceIntensitySeven_ShouldOmitIntensityFlag()
        {
            // nmap 的默认强度即 7，显式输出属冗余
            Build(new ExpertScanConfiguration { ServiceDetection = true, ServiceIntensity = 7 })
                .Should().NotContain("--version-intensity");
        }

        [Fact]
        public void Build_ServiceIntensityZero_ShouldOmitIntensityFlag()
        {
            Build(new ExpertScanConfiguration { ServiceDetection = true, ServiceIntensity = 0 })
                .Should().NotContain("--version-intensity");
        }

        [Fact]
        public void Build_OsDetection_ShouldAddOsFlags()
        {
            var cmd = Build(new ExpertScanConfiguration { OsDetection = true });

            cmd.Should().Contain(" -O ");
            cmd.Should().Contain(" --osscan-guess ");
        }

        [Fact]
        public void Build_ScriptScan_ShouldAddDefaultScriptFlag()
        {
            Build(new ExpertScanConfiguration { ScriptScan = true })
                .Should().Contain(" -sC ");
        }

        [Fact]
        public void Build_ScriptScanWithCustomArgs_ShouldUseScriptArgs()
        {
            var cmd = Build(new ExpertScanConfiguration
            {
                ScriptScan = true,
                NseScriptArgs = "vuln,safe"
            });

            cmd.Should().Contain(" --script vuln,safe ");
            cmd.Should().NotContain("-sC");
        }

        [Fact]
        public void Build_FullDetectionCombo_ShouldCollapseIntoAggressiveFlag()
        {
            // -A 等价于 -O + -sV + -sC + --traceroute，合并后不应再出现单独标志
            var cmd = Build(new ExpertScanConfiguration
            {
                ServiceDetection = true,
                OsDetection = true,
                ScriptScan = true,
                NseScriptArgs = ""
            });

            cmd.Should().Contain(" -A ");
            cmd.Should().NotContain(" -sV ");
            cmd.Should().NotContain(" -O ");
            cmd.Should().NotContain(" -sC ");
            cmd.Should().NotContain("--osscan-guess");
        }

        [Fact]
        public void Build_AggressiveCollapse_ShouldNotApplyWithCustomScriptArgs()
        {
            var cmd = Build(new ExpertScanConfiguration
            {
                ServiceDetection = true,
                OsDetection = true,
                ScriptScan = true,
                NseScriptArgs = "vuln"
            });

            cmd.Should().NotContain(" -A ");
            cmd.Should().Contain(" --script vuln ");
        }

        #endregion

        #region 主机发现与 DNS

        [Fact]
        public void Build_HostDiscoveryDisabled_ShouldSkipDiscovery()
        {
            Build(new ExpertScanConfiguration { HostDiscovery = false })
                .Should().Contain(" -Pn ");
        }

        [Fact]
        public void Build_PingProbeWithHostDiscovery_ShouldAddIcmpProbes()
        {
            var cmd = Build(new ExpertScanConfiguration { PingProbe = true, HostDiscovery = true });

            cmd.Should().Contain(" -PE ");
            cmd.Should().Contain(" -PP ");
        }

        [Fact]
        public void Build_PingOnlyMode_ShouldUsePingScanFlag()
        {
            // 与 ApplyTemplatePing 的设置保持一致：关闭全部端口扫描协议 + 开启主机发现，
            // 语义即「仅主机发现、不扫描端口」，应生成 -sn。
            // 原实现先执行 if (!scanTcp && !scanUdp) scanTcp = true，
            // 使 -sn 分支条件 !scanTcp && !scanUdp 恒为假，该分支不可达，
            // 导致 Ping 扫描模板实际生成 -sT 端口扫描命令。
            var cmd = Build(new ExpertScanConfiguration
            {
                PingProbe = true,
                HostDiscovery = true,
                TcpScan = false,
                UdpScan = false,
                SynScan = false
            });

            cmd.Should().Contain(" -sn ");
            cmd.Should().NotContain(" -sT ");
        }

        [Fact]
        public void Build_PingProbeDisabled_NoProtocol_ShouldStillDefaultToTcpConnect()
        {
            // 未开启主机发现且未选协议时，回退到 TCP 连接扫描，不应生成 -sn
            var cmd = Build(new ExpertScanConfiguration
            {
                PingProbe = false,
                HostDiscovery = true,
                TcpScan = false,
                UdpScan = false,
                SynScan = false
            });

            cmd.Should().NotContain(" -sn ");
            cmd.Should().Contain(" -sT ");
        }

        [Fact]
        public void Build_ReverseDns_ShouldToggleDnsFlags()
        {
            Build(new ExpertScanConfiguration { ReverseDns = true }).Should().Contain(" -R ");
            Build(new ExpertScanConfiguration { ReverseDns = false }).Should().Contain(" -n ");
        }

        #endregion

        #region 端口与目标范围

        [Theory]
        [InlineData("All", " -p- ")]
        [InlineData("Sensitive", " --top-ports 100 ")]
        [InlineData("Common", " --top-ports 1000 ")]
        public void Build_PortMode_ShouldMapToExpectedFlag(string portMode, string expected)
        {
            Build(new ExpertScanConfiguration { PortMode = portMode }).Should().Contain(expected);
        }

        [Fact]
        public void Build_CustomPortMode_ShouldInlinePortList()
        {
            var cmd = Build(new ExpertScanConfiguration
            {
                PortMode = "Custom",
                CustomPorts = "22, 80 ,443"
            });

            cmd.Should().Contain(" -p 22,80,443 ");
        }

        [Fact]
        public void Build_ExcludePortsAndHosts_ShouldBeEmitted()
        {
            var cmd = Build(new ExpertScanConfiguration
            {
                ExcludePorts = "25,135",
                ExcludeHosts = "10.0.0.5"
            });

            cmd.Should().Contain(" --exclude-ports 25,135 ");
            cmd.Should().Contain(" --exclude-hosts 10.0.0.5 ");
        }

        [Fact]
        public void Build_CidrTarget_ShouldBePassedThrough()
        {
            Build(new ExpertScanConfiguration { TargetValue = "192.168.1.0/24" })
                .Should().EndWith(" 192.168.1.0/24");
        }

        #endregion

        #region 时序与性能

        [Fact]
        public void Build_StealthMode_ShouldSelectSlowTimingTemplate()
        {
            Build(new ExpertScanConfiguration { StealthMode = true }).Should().Contain(" -T2 ");
        }

        [Fact]
        public void Build_DefaultPerformance_ShouldSelectFastTimingTemplate()
        {
            Build(new ExpertScanConfiguration
            {
                StealthMode = false,
                TcpConcurrency = 200,
                TcpTimeout = 500
            }).Should().Contain(" -T4 ");
        }

        [Fact]
        public void Build_NonDefaultConcurrency_ShouldSetMaxParallelism()
        {
            Build(new ExpertScanConfiguration { TcpConcurrency = 120 })
                .Should().Contain(" --max-parallelism 120 ");
        }

        [Fact]
        public void Build_ConcurrencyEqualsDefault_ShouldOmitMaxParallelism()
        {
            Build(new ExpertScanConfiguration { TcpConcurrency = 50 })
                .Should().NotContain("--max-parallelism");
        }

        [Fact]
        public void Build_RateLimit_ShouldEmitMaxAndMinRate()
        {
            var cmd = Build(new ExpertScanConfiguration { RateLimit = true, PacketRate = 1000 });

            cmd.Should().Contain(" --max-rate 1000 ");
            cmd.Should().Contain(" --min-rate 100 ");
        }

        [Fact]
        public void Build_RateLimitDisabled_ShouldOmitRateFlags()
        {
            var cmd = Build(new ExpertScanConfiguration { RateLimit = false, PacketRate = 1000 });

            cmd.Should().NotContain("--max-rate");
            cmd.Should().NotContain("--min-rate");
        }

        [Fact]
        public void Build_NonDefaultRetry_ShouldSetMaxRetries()
        {
            Build(new ExpertScanConfiguration { RetryCount = 3 }).Should().Contain(" --max-retries 3 ");
            Build(new ExpertScanConfiguration { RetryCount = 1 }).Should().NotContain("--max-retries");
        }

        [Fact]
        public void Build_LongTimeout_ShouldAddHostTimeoutGuard()
        {
            Build(new ExpertScanConfiguration { TcpTimeout = 3000 })
                .Should().Contain(" --host-timeout 9000ms ");
        }

        #endregion

        #region 随机化

        [Fact]
        public void Build_Randomize_ShouldEmitRandomizeHosts()
        {
            Build(new ExpertScanConfiguration { Randomize = true }).Should().Contain(" --randomize-hosts ");
        }

        [Fact]
        public void Build_RandomTargetOrderOnly_ShouldAlsoEmitRandomizeHosts()
        {
            // RandomizeCheckBox 与 RandomTargetOrderCheckBox 语义重叠，任一勾选都应生效
            Build(new ExpertScanConfiguration { Randomize = false, RandomTargetOrder = true })
                .Should().Contain(" --randomize-hosts ");
        }

        [Fact]
        public void Build_RandomPortOrder_ShouldEmitRandomizePorts()
        {
            Build(new ExpertScanConfiguration { RandomPortOrder = true }).Should().Contain(" --randomize-ports ");
        }

        #endregion

        #region 规避与欺骗（仅命令生成，实际扫描不生效）

        [Fact]
        public void Build_FragmentPackets_ShouldAddFragmentFlag()
        {
            Build(new ExpertScanConfiguration { FragmentPackets = true }).Should().Contain(" -f ");
        }

        [Fact]
        public void Build_NonDefaultMtu_ShouldBeEmitted()
        {
            Build(new ExpertScanConfiguration { Mtu = "64" }).Should().Contain(" --mtu 64 ");
        }

        [Fact]
        public void Build_DefaultMtu_ShouldBeOmitted()
        {
            Build(new ExpertScanConfiguration { Mtu = "1500" }).Should().NotContain("--mtu");
        }

        [Fact]
        public void Build_MtuBelowMinimum_ShouldBeRejected()
        {
            // nmap 要求 MTU >= 8
            Build(new ExpertScanConfiguration { Mtu = "4" }).Should().NotContain("--mtu");
        }

        [Fact]
        public void Build_DecoyScan_ShouldRequireDecoyIps()
        {
            Build(new ExpertScanConfiguration { DecoyScan = true, DecoyIps = "10.0.0.9,10.0.0.10" })
                .Should().Contain(" -D 10.0.0.9,10.0.0.10 ");

            Build(new ExpertScanConfiguration { DecoyScan = true, DecoyIps = "" })
                .Should().NotContain(" -D ");
        }

        [Fact]
        public void Build_IdleScan_ShouldRequireZombieHost()
        {
            Build(new ExpertScanConfiguration { IdleScan = true, ZombieHost = "10.0.0.7" })
                .Should().Contain(" -sI 10.0.0.7 ");

            Build(new ExpertScanConfiguration { IdleScan = true, ZombieHost = "" })
                .Should().NotContain("-sI");
        }

        [Fact]
        public void Build_BadChecksum_ShouldAddBadsumFlag()
        {
            Build(new ExpertScanConfiguration { BadChecksum = true }).Should().Contain(" --badsum ");
        }

        [Fact]
        public void Build_SourceRouting_ShouldAddIpOptions()
        {
            Build(new ExpertScanConfiguration { SourceRouting = true }).Should().Contain(" --ip-options L ");
        }

        [Fact]
        public void Build_SingleSourcePort_ShouldBeEmitted()
        {
            Build(new ExpertScanConfiguration { SourcePort = "53" }).Should().Contain(" --source-port 53 ");
        }

        [Fact]
        public void Build_NonNumericSourcePort_ShouldBeIgnored()
        {
            Build(new ExpertScanConfiguration { SourcePort = "abc" }).Should().NotContain("--source-port abc");
        }

        [Fact]
        public void Build_SourcePortRange_ShouldBeEmittedAsRange()
        {
            Build(new ExpertScanConfiguration { SourcePortMin = 1024, SourcePortMax = 2048 })
                .Should().Contain(" --source-port 1024-2048 ");
        }

        [Fact]
        public void Build_SourcePortMinOnly_ShouldBeEmittedAsSingleValue()
        {
            Build(new ExpertScanConfiguration { SourcePortMin = 1024, SourcePortMax = 0 })
                .Should().Contain(" --source-port 1024 ");
        }

        [Fact]
        public void Build_TtlShouldUseInjectedValue()
        {
            Build(new ExpertScanConfiguration()).Should().Contain(" --ttl 64 ");
        }

        #endregion

        #region 输出格式

        [Fact]
        public void Build_JsonOutput_ShouldUseJsonFlagWithTimestampedName()
        {
            Build(new ExpertScanConfiguration { OutputJson = true })
                .Should().Contain(" -oJ \"scan_20260101_000000.json\" ");
        }

        [Fact]
        public void Build_HtmlOutput_ShouldUseXmlFlagSinceNmapLacksHtml()
        {
            // nmap 不直接支持 HTML，生成 XML 供后续转换
            Build(new ExpertScanConfiguration { OutputJson = false, OutputHtml = true })
                .Should().Contain(" -oX \"scan_20260101_000000.xml\" ");
        }

        [Fact]
        public void Build_CsvOutput_ShouldUseGreppableFlagSinceNmapLacksCsv()
        {
            Build(new ExpertScanConfiguration { OutputJson = false, OutputCsv = true })
                .Should().Contain(" -oG \"scan_20260101_000000.gnmap\" ");
        }

        [Fact]
        public void Build_OutputDirSet_ShouldPrefixOutputPaths()
        {
            var cmd = Build(new ExpertScanConfiguration
            {
                OutputJson = true,
                SaveOutput = true,
                OutputDir = @"C:\reports"
            });

            cmd.Should().Contain(@"-oJ ""C:\reports\scan_20260101_000000.json""");
        }

        [Fact]
        public void Build_OutputDirSetButSaveDisabled_ShouldUseRelativePath()
        {
            var cmd = Build(new ExpertScanConfiguration
            {
                OutputJson = true,
                SaveOutput = false,
                OutputDir = @"C:\reports"
            });

            cmd.Should().Contain(" -oJ \"scan_20260101_000000.json\" ");
            cmd.Should().NotContain(@"C:\reports");
        }

        [Fact]
        public void Build_NoFormatSelectedButSaveEnabled_ShouldFallBackToNormalOutput()
        {
            var cmd = Build(new ExpertScanConfiguration
            {
                OutputJson = false,
                OutputHtml = false,
                OutputCsv = false,
                SaveOutput = true,
                OutputDir = @"C:\reports"
            });

            cmd.Should().Contain(@"-oN ""C:\reports\scan_20260101_000000.txt""");
        }

        [Fact]
        public void Build_ShowOpenOnly_ShouldAddOpenFlag()
        {
            Build(new ExpertScanConfiguration { ShowOpenOnly = true }).Should().Contain(" --open ");
        }

        #endregion

        #region 日志级别

        [Theory]
        [InlineData(0, " -q ")]
        [InlineData(1, " -v ")]
        [InlineData(2, " -vv ")]
        [InlineData(3, " -vv ")]
        public void Build_Verbosity_ShouldMapToExpectedFlag(int verbosity, string expected)
        {
            Build(new ExpertScanConfiguration { Verbosity = verbosity }).Should().Contain(expected);
        }

        #endregion

        [Fact]
        public void Build_ShouldAlwaysIncludeStatsAndDataLength()
        {
            var cmd = Build(new ExpertScanConfiguration());

            cmd.Should().Contain(" --stats-every 5s ");
            cmd.Should().Contain(" --data-length 32 ");
        }

        [Fact]
        public void Build_ShouldProduceSingleSpaceSeparatedTokens()
        {
            // 防御性：避免拼接出双空格导致用户复制命令后参数解析异常
            var cmd = Build(new ExpertScanConfiguration
            {
                TcpScan = true,
                ServiceDetection = true,
                OsDetection = true,
                RateLimit = true,
                OutputJson = true
            });

            cmd.Should().NotContain("  ");
        }
    }
}
