using System;
using System.Collections.Generic;
using System.Net.Sockets;
using System.Threading.Tasks;
using FluentAssertions;
using NetSecurityScanner.Core.Models;
using NetSecurityScanner.Core.Services;
using Xunit;

namespace NetSecurityScanner.Tests
{
    public class BatchScanOrchestratorTests
    {
        #region ValidateTargets

        [Fact]
        public void ValidateTargets_Duplicates_AreRemoved()
        {
            var raw = new List<string> { "192.168.1.1", "192.168.1.1", " 192.168.1.2 ", "192.168.1.2" };

            var outcome = BatchScanOrchestrator.ValidateTargets(raw);

            outcome.Error.Should().BeNull();
            outcome.Targets.Should().Equal("192.168.1.1", "192.168.1.2");
            outcome.Total.Should().Be(4);
            outcome.Deduped.Should().Be(2);
            outcome.Invalid.Should().Be(0);
        }

        [Fact]
        public void ValidateTargets_InvalidEntries_AreSkipped()
        {
            var raw = new List<string> { "192.168.1.1", "not-an-ip", "999.1.1.1", "" };

            var outcome = BatchScanOrchestrator.ValidateTargets(raw);

            outcome.Error.Should().BeNull();
            outcome.Targets.Should().Equal("192.168.1.1");
            outcome.Invalid.Should().Be(3);
        }

        [Fact]
        public void ValidateTargets_EmptyInput_ReturnsError()
        {
            var outcome = BatchScanOrchestrator.ValidateTargets(new List<string>());
            outcome.Error.Should().Be("请输入目标");
        }

        [Fact]
        public void ValidateTargets_AllWhitespace_ReturnsError()
        {
            var outcome = BatchScanOrchestrator.ValidateTargets(new List<string> { " ", "" });
            outcome.Error.Should().Be("请输入目标");
        }

        [Fact]
        public void ValidateTargets_ExceedsMax_ReturnsError()
        {
            var raw = new List<string>();
            for (int i = 0; i < BatchScanOrchestrator.MaxTargets + 1; i++)
            {
                raw.Add($"10.{(i >> 16) & 255}.{(i >> 8) & 255}.{i & 255}");
            }

            var outcome = BatchScanOrchestrator.ValidateTargets(raw);

            outcome.Error.Should().Contain("65536");
        }

        [Fact]
        public void ValidateTargets_CommentAndBlankLines_AreIgnored()
        {
            var raw = new List<string> { "# 内网段", "", "192.168.1.1" };

            var outcome = BatchScanOrchestrator.ValidateTargets(raw);

            outcome.Error.Should().BeNull();
            outcome.Targets.Should().Equal("192.168.1.1");
            outcome.Invalid.Should().Be(2);
        }

        #endregion

        #region Estimate

        [Fact]
        public void Estimate_MinimalInputs_ReturnsFourSeconds()
        {
            BatchScanOrchestrator.Estimate(1, 1, 1, 1.0).Should().Be(TimeSpan.FromSeconds(4));
        }

        [Fact]
        public void Estimate_HigherConcurrency_DecreasesEstimate()
        {
            var low = BatchScanOrchestrator.Estimate(100, 100, 1, 0.3);
            var high = BatchScanOrchestrator.Estimate(100, 100, 50, 0.3);
            high.Should().BeLessThan(low);
        }

        [Fact]
        public void Estimate_NeverBelowOneSecond()
        {
            BatchScanOrchestrator.Estimate(1, 0, 50, 0.1).Should().Be(TimeSpan.FromSeconds(1));
        }

        #endregion

        #region Classify

        [Fact]
        public void Classify_CanceledFlag_ReturnsCanceled()
        {
            BatchScanOrchestrator.Classify(null, true, true, canceled: true)
                .Should().Be(BatchScanFailureCategory.Canceled);
        }

        [Fact]
        public void Classify_OperationCanceled_ReturnsCanceled()
        {
            BatchScanOrchestrator.Classify(new OperationCanceledException(), true, false, canceled: false)
                .Should().Be(BatchScanFailureCategory.Canceled);
        }

        [Fact]
        public void Classify_TaskCanceledWithoutUserCancel_ReturnsTimeout()
        {
            BatchScanOrchestrator.Classify(new TaskCanceledException(), true, true, canceled: false)
                .Should().Be(BatchScanFailureCategory.Timeout);
        }

        [Fact]
        public void Classify_TimeoutException_ReturnsTimeout()
        {
            BatchScanOrchestrator.Classify(new TimeoutException(), true, true, canceled: false)
                .Should().Be(BatchScanFailureCategory.Timeout);
        }

        [Fact]
        public void Classify_ConnectionRefused_ReturnsConnectionRefused()
        {
            var ex = new SocketException((int)SocketError.ConnectionRefused);
            BatchScanOrchestrator.Classify(ex, true, true, canceled: false)
                .Should().Be(BatchScanFailureCategory.ConnectionRefused);
        }

        [Fact]
        public void Classify_HostUnreachable_ReturnsUnreachable()
        {
            var ex = new SocketException((int)SocketError.HostUnreachable);
            BatchScanOrchestrator.Classify(ex, true, true, canceled: false)
                .Should().Be(BatchScanFailureCategory.Unreachable);
        }

        [Fact]
        public void Classify_HostNotFound_ReturnsDnsFailure()
        {
            var ex = new SocketException((int)SocketError.HostNotFound);
            BatchScanOrchestrator.Classify(ex, true, true, canceled: false)
                .Should().Be(BatchScanFailureCategory.DnsFailure);
        }

        [Fact]
        public void Classify_NoOpenPorts_ReturnsNoOpenPort()
        {
            BatchScanOrchestrator.Classify(null, reachedTarget: true, hasOpenPorts: false, canceled: false)
                .Should().Be(BatchScanFailureCategory.NoOpenPort);
        }

        [Fact]
        public void Classify_SuccessWithPorts_ReturnsNone()
        {
            BatchScanOrchestrator.Classify(null, true, true, canceled: false)
                .Should().Be(BatchScanFailureCategory.None);
        }

        [Fact]
        public void Classify_UnknownException_ReturnsScanException()
        {
            BatchScanOrchestrator.Classify(new InvalidOperationException("boom"), true, true, canceled: false)
                .Should().Be(BatchScanFailureCategory.ScanException);
        }

        #endregion

        #region ToDisplayText

        [Theory]
        [InlineData(BatchScanFailureCategory.Timeout, "超时")]
        [InlineData(BatchScanFailureCategory.ConnectionRefused, "连接被拒")]
        [InlineData(BatchScanFailureCategory.Unreachable, "主机不可达")]
        [InlineData(BatchScanFailureCategory.DnsFailure, "域名解析失败")]
        [InlineData(BatchScanFailureCategory.NoOpenPort, "无开放端口")]
        [InlineData(BatchScanFailureCategory.ScanException, "扫描异常")]
        [InlineData(BatchScanFailureCategory.Canceled, "已取消")]
        [InlineData(BatchScanFailureCategory.None, "")]
        public void ToDisplayText_MapsAllValues(BatchScanFailureCategory category, string expected)
        {
            BatchScanOrchestrator.ToDisplayText(category).Should().Be(expected);
        }

        #endregion
    }
}
