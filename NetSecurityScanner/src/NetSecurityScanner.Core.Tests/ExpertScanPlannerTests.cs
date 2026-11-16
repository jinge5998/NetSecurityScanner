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
    /// ResolvePorts 纯逻辑测试。
    /// 该逻辑原先内嵌在 ExpertModeWindow.xaml.cs（7834 行 God Class）中，无法脱离 WPF 测试。
    /// </summary>
    public class ExpertScanPlannerResolvePortsTests
    {
        [Fact]
        public void ResolvePorts_CommonMode_ShouldUseTop1000NotSequentialRange()
        {
            // 回归保护：原实现为 Enumerable.Range(1,1000)，会漏掉 1000 以上的高频服务端口，
            // 导致目标只开放高位端口时扫描结果为空、漏洞检测随之为空。
            var config = new ExpertScanConfiguration { PortMode = "Common" };

            var ports = ExpertScanPlanner.ResolvePorts(config);

            ports.Should().Contain(new[] { 8080, 8443, 3306, 3389, 5432, 27017 });
        }

        [Fact]
        public void ResolvePorts_SensitiveMode_ShouldIncludeContainerAndHighRiskPorts()
        {
            // Docker 2375 / K8s 6443 / etcd 2379 等未授权高危端口必须纳入敏感端口集
            var config = new ExpertScanConfiguration { PortMode = "Sensitive" };

            var ports = ExpertScanPlanner.ResolvePorts(config);

            ports.Should().Contain(new[] { 22, 445, 3389, 6379, 27017 });
        }

        [Fact]
        public void ResolvePorts_AllMode_ShouldCoverFullPortRange()
        {
            var config = new ExpertScanConfiguration { PortMode = "All" };

            var ports = ExpertScanPlanner.ResolvePorts(config);

            ports.Should().HaveCount(65535);
            ports.First().Should().Be(1);
            ports.Last().Should().Be(65535);
        }

        [Fact]
        public void ResolvePorts_CustomMode_ShouldParseMixedListAndRange()
        {
            var config = new ExpertScanConfiguration
            {
                PortMode = "Custom",
                CustomPorts = "22,80,443,8000-8005"
            };

            var ports = ExpertScanPlanner.ResolvePorts(config);

            ports.Should().BeEquivalentTo(new[] { 22, 80, 443, 8000, 8001, 8002, 8003, 8004, 8005 });
        }

        [Fact]
        public void ResolvePorts_CustomMode_ReversedRange_ShouldSwapInsteadOfThrowing()
        {
            // 防御性处理：start > end 时交换，避免 Enumerable.Range 抛 ArgumentOutOfRangeException
            var config = new ExpertScanConfiguration
            {
                PortMode = "Custom",
                CustomPorts = "9000-8998"
            };

            var act = () => ExpertScanPlanner.ResolvePorts(config);

            act.Should().NotThrow();
            act().Should().BeEquivalentTo(new[] { 8998, 8999, 9000 });
        }

        [Fact]
        public void ResolvePorts_CustomMode_OutOfRangePort_ShouldBeSkippedWithWarning()
        {
            var config = new ExpertScanConfiguration
            {
                PortMode = "Custom",
                CustomPorts = "22,0,70000,80"
            };
            var logs = new List<string>();

            var ports = ExpertScanPlanner.ResolvePorts(config, logs.Add);

            ports.Should().BeEquivalentTo(new[] { 22, 80 });
            logs.Should().Contain(l => l.Contains("70000"));
        }

        [Fact]
        public void ResolvePorts_CustomMode_UnparsableToken_ShouldBeSkippedWithWarning()
        {
            var config = new ExpertScanConfiguration
            {
                PortMode = "Custom",
                CustomPorts = "22,abc,80"
            };
            var logs = new List<string>();

            var ports = ExpertScanPlanner.ResolvePorts(config, logs.Add);

            ports.Should().BeEquivalentTo(new[] { 22, 80 });
            logs.Should().Contain(l => l.Contains("abc"));
        }

        [Fact]
        public void ResolvePorts_CustomMode_EmptyInput_ShouldReturnEmpty()
        {
            var config = new ExpertScanConfiguration { PortMode = "Custom", CustomPorts = "   " };

            ExpertScanPlanner.ResolvePorts(config).Should().BeEmpty();
        }

        [Fact]
        public void ResolvePorts_ShouldRemoveExcludedPorts()
        {
            var config = new ExpertScanConfiguration
            {
                PortMode = "Custom",
                CustomPorts = "22,80,443,3389",
                ExcludePorts = "80,3389"
            };

            var ports = ExpertScanPlanner.ResolvePorts(config);

            ports.Should().BeEquivalentTo(new[] { 22, 443 });
        }

        [Fact]
        public void ResolvePorts_ExcludePorts_UnparsableEntry_ShouldBeIgnoredSafely()
        {
            // 排除列表里的垃圾输入不应导致整条解析抛异常
            var config = new ExpertScanConfiguration
            {
                PortMode = "Custom",
                CustomPorts = "22,80",
                ExcludePorts = "abc, 22 ,,"
            };

            var ports = ExpertScanPlanner.ResolvePorts(config);

            ports.Should().BeEquivalentTo(new[] { 80 });
        }

        [Fact]
        public void ResolvePorts_ShouldReturnDistinctSortedPortsByDefault()
        {
            var config = new ExpertScanConfiguration
            {
                PortMode = "Custom",
                CustomPorts = "80,22,80,443,22"
            };

            var ports = ExpertScanPlanner.ResolvePorts(config);

            ports.Should().OnlyHaveUniqueItems();
            ports.Should().BeInAscendingOrder();
        }

        [Fact]
        public void ResolvePorts_RandomPortOrder_ShouldPreserveMembershipButAllowReordering()
        {
            var config = new ExpertScanConfiguration
            {
                PortMode = "Custom",
                CustomPorts = string.Join(",", Enumerable.Range(1, 200)),
                RandomPortOrder = true
            };

            var ports = ExpertScanPlanner.ResolvePorts(config);

            // 随机顺序不得增删端口
            ports.Should().HaveCount(200);
            ports.Should().OnlyHaveUniqueItems();
            ports.OrderBy(p => p).Should().BeEquivalentTo(Enumerable.Range(1, 200));
        }

        [Fact]
        public void ResolvePorts_UnknownPortMode_ShouldFallBackToCommon()
        {
            var config = new ExpertScanConfiguration { PortMode = "不存在的模式" };

            var ports = ExpertScanPlanner.ResolvePorts(config);

            ports.Should().BeEquivalentTo(ExpertScanPlanner.ResolvePorts(
                new ExpertScanConfiguration { PortMode = "Common" }));
        }
    }

    /// <summary>
    /// ResolveTargets 纯逻辑测试。
    /// </summary>
    public class ExpertScanPlannerResolveTargetsTests
    {
        [Fact]
        public void ResolveTargets_Single_ShouldReturnTrimmedValue()
        {
            var config = new ExpertScanConfiguration
            {
                TargetType = "Single",
                TargetValue = "  192.168.1.1  "
            };

            ExpertScanPlanner.ResolveTargets(config).Should().Equal("192.168.1.1");
        }

        [Fact]
        public void ResolveTargets_Single_Empty_ShouldReturnEmpty()
        {
            var config = new ExpertScanConfiguration { TargetType = "Single", TargetValue = "   " };

            ExpertScanPlanner.ResolveTargets(config).Should().BeEmpty();
        }

        [Fact]
        public void ResolveTargets_Range_ShouldExpandInclusiveRange()
        {
            var config = new ExpertScanConfiguration
            {
                TargetType = "Range",
                TargetValue = "192.168.1.1-192.168.1.5"
            };

            ExpertScanPlanner.ResolveTargets(config).Should().Equal(
                "192.168.1.1", "192.168.1.2", "192.168.1.3", "192.168.1.4", "192.168.1.5");
        }

        [Fact]
        public void ResolveTargets_Range_Reversed_ShouldSwapInsteadOfReturningEmpty()
        {
            var config = new ExpertScanConfiguration
            {
                TargetType = "Range",
                TargetValue = "192.168.1.5-192.168.1.3"
            };

            ExpertScanPlanner.ResolveTargets(config).Should().Equal(
                "192.168.1.3", "192.168.1.4", "192.168.1.5");
        }

        [Fact]
        public void ResolveTargets_Range_Oversize_ShouldTruncateTo65536()
        {
            var config = new ExpertScanConfiguration
            {
                TargetType = "Range",
                TargetValue = "10.0.0.0-10.10.0.0"
            };
            var logs = new List<string>();

            var targets = ExpertScanPlanner.ResolveTargets(config, logs.Add);

            targets.Should().HaveCount(65536);
            logs.Should().Contain(l => l.Contains("截断"));
        }

        [Fact]
        public void ResolveTargets_Range_InvalidFormat_ShouldReturnEmpty()
        {
            var config = new ExpertScanConfiguration
            {
                TargetType = "Range",
                TargetValue = "not-an-ip-range"
            };

            ExpertScanPlanner.ResolveTargets(config).Should().BeEmpty();
        }

        [Fact]
        public void ResolveTargets_Cidr24_ShouldExcludeNetworkAndBroadcast()
        {
            var config = new ExpertScanConfiguration
            {
                TargetType = "CIDR",
                TargetValue = "192.168.1.0/24"
            };

            var targets = ExpertScanPlanner.ResolveTargets(config);

            targets.Should().HaveCount(254);
            targets.First().Should().Be("192.168.1.1");
            targets.Last().Should().Be("192.168.1.254");
        }

        [Fact]
        public void ResolveTargets_Cidr32_ShouldReturnSingleHost()
        {
            var config = new ExpertScanConfiguration
            {
                TargetType = "CIDR",
                TargetValue = "192.168.1.7/32"
            };

            ExpertScanPlanner.ResolveTargets(config).Should().Equal("192.168.1.7");
        }

        [Fact]
        public void ResolveTargets_Cidr31_ShouldReturnBothAddresses()
        {
            // /31 点对点链路无网络地址与广播地址，两个地址都可用
            var config = new ExpertScanConfiguration
            {
                TargetType = "CIDR",
                TargetValue = "192.168.1.0/31"
            };

            ExpertScanPlanner.ResolveTargets(config).Should().Equal("192.168.1.0", "192.168.1.1");
        }

        [Fact]
        public void ResolveTargets_Cidr_InvalidPrefix_ShouldRejectWithWarning()
        {
            var config = new ExpertScanConfiguration
            {
                TargetType = "CIDR",
                TargetValue = "192.168.1.0/33"
            };
            var logs = new List<string>();

            var targets = ExpertScanPlanner.ResolveTargets(config, logs.Add);

            targets.Should().BeEmpty();
            logs.Should().Contain(l => l.Contains("33"));
        }

        [Fact]
        public void ResolveTargets_File_ShouldSplitLinesAndTrim()
        {
            var config = new ExpertScanConfiguration
            {
                TargetType = "File",
                TargetValue = "192.168.1.1\r\n  192.168.1.2  \n\n10.0.0.1\r"
            };

            ExpertScanPlanner.ResolveTargets(config).Should().Equal(
                "192.168.1.1", "192.168.1.2", "10.0.0.1");
        }

        [Fact]
        public void ResolveTargets_Regex_ShouldMatchAcrossPrivateNetworks()
        {
            var config = new ExpertScanConfiguration
            {
                TargetType = "Regex",
                TargetValue = @"^192\.168\.1\.(1|2|3)$"
            };

            ExpertScanPlanner.ResolveTargets(config).Should().BeEquivalentTo(
                new[] { "192.168.1.1", "192.168.1.2", "192.168.1.3" });
        }

        [Fact]
        public void ResolveTargets_Regex_NoMatch_ShouldFallBackToLiteral()
        {
            var config = new ExpertScanConfiguration
            {
                TargetType = "Regex",
                TargetValue = @"^999\.999\.999\.999$"
            };
            var logs = new List<string>();

            var targets = ExpertScanPlanner.ResolveTargets(config, logs.Add);

            targets.Should().Equal(@"^999\.999\.999\.999$");
            logs.Should().Contain(l => l.Contains("未匹配"));
        }

        [Fact]
        public void ResolveTargets_Regex_InvalidPattern_ShouldNotThrowAndFallBackToLiteral()
        {
            var config = new ExpertScanConfiguration
            {
                TargetType = "Regex",
                TargetValue = "([unclosed"
            };
            var logs = new List<string>();

            var act = () => ExpertScanPlanner.ResolveTargets(config, logs.Add);

            act.Should().NotThrow();
            act().Should().Equal("([unclosed");
            logs.Should().Contain(l => l.Contains("正则"));
        }

        [Fact]
        public void ResolveTargets_ShouldRemoveExcludedHosts()
        {
            var config = new ExpertScanConfiguration
            {
                TargetType = "File",
                TargetValue = "192.168.1.1\n192.168.1.2\n192.168.1.3",
                ExcludeHosts = "192.168.1.2"
            };

            ExpertScanPlanner.ResolveTargets(config).Should().Equal("192.168.1.1", "192.168.1.3");
        }

        [Fact]
        public void ResolveTargets_Randomize_ShouldPreserveMembership()
        {
            var config = new ExpertScanConfiguration
            {
                TargetType = "File",
                TargetValue = string.Join("\n", Enumerable.Range(1, 100).Select(i => $"10.0.0.{i}")),
                Randomize = true
            };

            var targets = ExpertScanPlanner.ResolveTargets(config);

            targets.Should().HaveCount(100);
            targets.Should().OnlyHaveUniqueItems();
        }

        [Fact]
        public void IpConversion_ShouldRoundTrip()
        {
            foreach (var ip in new[] { "0.0.0.0", "10.0.0.1", "192.168.1.254", "255.255.255.255" })
            {
                ExpertScanPlanner.LongToIP(ExpertScanPlanner.IPToLong(ip)).Should().Be(ip);
            }
        }
    }
}
