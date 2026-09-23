using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using FluentAssertions;
using Moq;
using NetSecurityScanner.Models;
using NetSecurityScanner.Services;
using Xunit;

namespace NetSecurityScanner.Tests
{
  public class ComprehensiveScanServiceTests
  {
    private readonly Mock<IPortScanner> _portScannerMock;
    private readonly Mock<IVulnerabilityScanner> _vulnerabilityScannerMock;
    private readonly Mock<IJsonDatabaseService> _jsonDatabaseMock;
    private readonly Mock<IPluginOrchestrator> _pluginOrchestratorMock;
    private readonly ComprehensiveScanService _service;
    private readonly List<string> _logMessages;

    public ComprehensiveScanServiceTests()
    {
      _portScannerMock = new Mock<IPortScanner>();
      _vulnerabilityScannerMock = new Mock<IVulnerabilityScanner>();
      _jsonDatabaseMock = new Mock<IJsonDatabaseService>();
      _pluginOrchestratorMock = new Mock<IPluginOrchestrator>();
      _logMessages = new List<string>();

      // 设置 mock 默认行为
      _portScannerMock
          .Setup(s => s.ScanTcpPortsAsync(It.IsAny<string>(), It.IsAny<List<int>>(), It.IsAny<IProgress<int>>(), It.IsAny<CancellationToken>(), It.IsAny<ScanPolicy>()))
          .ReturnsAsync(new List<PortScanResult>());
      _portScannerMock
          .Setup(s => s.ScanUdpPortsAsync(It.IsAny<string>(), It.IsAny<List<int>>(), It.IsAny<IProgress<int>>(), It.IsAny<CancellationToken>(), It.IsAny<ScanPolicy>()))
          .ReturnsAsync(new List<PortScanResult>());
      _vulnerabilityScannerMock
          .Setup(s => s.ScanAsync(It.IsAny<string>(), It.IsAny<List<PortInfo>>(), It.IsAny<string>(), It.IsAny<IProgress<(string, int)>>(), It.IsAny<CancellationToken>()))
          .ReturnsAsync(new List<VulnerabilityResult>());
      _pluginOrchestratorMock
          .Setup(s => s.ScanTargetAsync(It.IsAny<string>(), It.IsAny<List<int>>(), It.IsAny<IEnumerable<string>?>(), It.IsAny<CancellationToken>(), It.IsAny<string?>()))
          .ReturnsAsync(new List<VulnerabilityResult>());
      _jsonDatabaseMock
          .Setup(s => s.SaveScanHistoryAsync(It.IsAny<ScanHistoryItem>()))
          .ReturnsAsync(true);
      _jsonDatabaseMock
          .Setup(s => s.SaveScanResultAsync(It.IsAny<CompleteScanResult>()))
          .ReturnsAsync(true);
      _jsonDatabaseMock
          .Setup(s => s.UpdateScanHistoryAsync(It.IsAny<string>(), It.IsAny<ScanHistoryItem>()))
          .ReturnsAsync(true);

      _service = new ComprehensiveScanService(
          _portScannerMock.Object,
          _vulnerabilityScannerMock.Object,
          _jsonDatabaseMock.Object,
          _pluginOrchestratorMock.Object,
          msg => _logMessages.Add(msg));
    }

    #region 参数验证测试

    [Fact]
    public async Task ExecuteAsync_NullOptions_ShouldThrowArgumentNullException()
    {
      // Act
      Func<Task> act = () => _service.ExecuteAsync(null!, null, CancellationToken.None);

      // Assert
      await act.Should().ThrowAsync<ArgumentNullException>();
    }

    [Fact]
    public async Task ExecuteAsync_EmptyTargetIp_ShouldThrowArgumentException()
    {
      // Arrange
      var options = new ComprehensiveScanOptions { TargetIp = "" };

      // Act
      Func<Task> act = () => _service.ExecuteAsync(options, null, CancellationToken.None);

      // Assert
      await act.Should().ThrowAsync<ArgumentException>();
    }

    [Fact]
    public async Task ExecuteAsync_WhitespaceTargetIp_ShouldThrowArgumentException()
    {
      // Arrange
      var options = new ComprehensiveScanOptions { TargetIp = "   " };

      // Act
      Func<Task> act = () => _service.ExecuteAsync(options, null, CancellationToken.None);

      // Assert
      await act.Should().ThrowAsync<ArgumentException>();
    }

    #endregion

    #region 正常扫描流程测试

    [Fact]
    public async Task ExecuteAsync_ValidOptions_ShouldReturnResult()
    {
      // Arrange
      _portScannerMock
          .Setup(s => s.ScanTcpPortsAsync("192.168.1.1", It.IsAny<List<int>>(), It.IsAny<IProgress<int>>(), It.IsAny<CancellationToken>(), It.IsAny<ScanPolicy>()))
          .ReturnsAsync(new List<PortScanResult>
          {
                    new PortScanResult { PortNumber = 80, Status = "开放", Service = "HTTP" }
          });

      var options = new ComprehensiveScanOptions
      {
        TargetIp = "192.168.1.1",
        EnableTcp = true,
        EnableUdp = false,
        EnableVulnScan = false,
        EnablePluginScan = false,
        Preset = ScanPreset.Quick
      };

      // Act
      var result = await _service.ExecuteAsync(options, null, CancellationToken.None);

      // Assert
      result.Should().NotBeNull();
      result.TargetIp.Should().Be("192.168.1.1");
      result.ScanId.Should().NotBeNullOrEmpty();
      result.ScanTime.Should().BeCloseTo(DateTime.Now, TimeSpan.FromSeconds(10));
    }

    [Fact]
    public async Task ExecuteAsync_ShouldLogStartAndEnd()
    {
      // Arrange
      _portScannerMock
          .Setup(s => s.ScanTcpPortsAsync("192.168.1.1", It.IsAny<List<int>>(), It.IsAny<IProgress<int>>(), It.IsAny<CancellationToken>(), It.IsAny<ScanPolicy>()))
          .ReturnsAsync(new List<PortScanResult>
          {
                    new PortScanResult { PortNumber = 80, Status = "开放", Service = "HTTP" }
          });

      var options = new ComprehensiveScanOptions
      {
        TargetIp = "192.168.1.1",
        Preset = ScanPreset.Quick
      };

      // Act
      await _service.ExecuteAsync(options, null, CancellationToken.None);

      // Assert
      _logMessages.Should().Contain(m => m.Contains("开始"));
    }

    [Fact]
    public async Task ExecuteAsync_ShouldCallPortScanner()
    {
      // Arrange
      _portScannerMock
          .Setup(s => s.ScanTcpPortsAsync("192.168.1.1", It.IsAny<List<int>>(), It.IsAny<IProgress<int>>(), It.IsAny<CancellationToken>(), It.IsAny<ScanPolicy>()))
          .ReturnsAsync(new List<PortScanResult>
          {
                    new PortScanResult { PortNumber = 80, Status = "开放", Service = "HTTP" }
          });

      var options = new ComprehensiveScanOptions
      {
        TargetIp = "192.168.1.1",
        Preset = ScanPreset.Quick,
        EnableTcp = true
      };

      // Act
      await _service.ExecuteAsync(options, null, CancellationToken.None);

      // Assert
      _portScannerMock.Verify(
          s => s.ScanTcpPortsAsync("192.168.1.1", It.IsAny<List<int>>(), It.IsAny<IProgress<int>>(), It.IsAny<CancellationToken>(), It.IsAny<ScanPolicy>()),
          Times.AtLeastOnce);
    }

    [Fact]
    public async Task ExecuteAsync_WithVulnScan_ShouldCallVulnerabilityScanner()
    {
      // Arrange
      _portScannerMock
          .Setup(s => s.ScanTcpPortsAsync("192.168.1.1", It.IsAny<List<int>>(), It.IsAny<IProgress<int>>(), It.IsAny<CancellationToken>(), It.IsAny<ScanPolicy>()))
          .ReturnsAsync(new List<PortScanResult>
          {
                    new PortScanResult { PortNumber = 80, Status = "开放", Service = "HTTP" }
          });

      var options = new ComprehensiveScanOptions
      {
        TargetIp = "192.168.1.1",
        Preset = ScanPreset.Quick,
        EnableTcp = true,
        EnableVulnScan = true
      };

      // Act
      await _service.ExecuteAsync(options, null, CancellationToken.None);

      // Assert
      _vulnerabilityScannerMock.Verify(
          s => s.ScanAsync(It.IsAny<string>(), It.IsAny<List<PortInfo>>(), It.IsAny<string>(), It.IsAny<IProgress<(string, int)>>(), It.IsAny<CancellationToken>()),
          Times.AtLeastOnce);
    }

    [Fact]
    public async Task ExecuteAsync_WithPluginScan_ShouldCallPluginOrchestrator()
    {
      // Arrange
      _portScannerMock
          .Setup(s => s.ScanTcpPortsAsync("192.168.1.1", It.IsAny<List<int>>(), It.IsAny<IProgress<int>>(), It.IsAny<CancellationToken>(), It.IsAny<ScanPolicy>()))
          .ReturnsAsync(new List<PortScanResult>
          {
                    new PortScanResult { PortNumber = 80, Status = "开放", Service = "HTTP" }
          });

      var options = new ComprehensiveScanOptions
      {
        TargetIp = "192.168.1.1",
        Preset = ScanPreset.Quick,
        EnableTcp = true,
        EnablePluginScan = true
      };

      // Act
      await _service.ExecuteAsync(options, null, CancellationToken.None);

      // Assert
      _pluginOrchestratorMock.Verify(
          s => s.ScanTargetAsync(It.IsAny<string>(), It.IsAny<List<int>>(), It.IsAny<IEnumerable<string>?>(), It.IsAny<CancellationToken>(), It.IsAny<string?>()),
          Times.AtLeastOnce);
    }

    [Fact]
    public async Task ExecuteAsync_ShouldSaveToDatabase()
    {
      // Arrange
      _portScannerMock
          .Setup(s => s.ScanTcpPortsAsync("192.168.1.1", It.IsAny<List<int>>(), It.IsAny<IProgress<int>>(), It.IsAny<CancellationToken>(), It.IsAny<ScanPolicy>()))
          .ReturnsAsync(new List<PortScanResult>
          {
                    new PortScanResult { PortNumber = 80, Status = "开放", Service = "HTTP" }
          });

      var options = new ComprehensiveScanOptions
      {
        TargetIp = "192.168.1.1",
        Preset = ScanPreset.Quick,
        EnableTcp = true
      };

      // Act
      await _service.ExecuteAsync(options, null, CancellationToken.None);

      // Assert
      _jsonDatabaseMock.Verify(
          s => s.SaveScanResultAsync(It.IsAny<CompleteScanResult>()),
          Times.AtLeastOnce);
    }

    #endregion

    #region 扫描预设测试

    [Fact]
    public async Task ExecuteAsync_QuickPreset_ShouldScan()
    {
      // Arrange
      _portScannerMock
          .Setup(s => s.ScanTcpPortsAsync("192.168.1.1", It.IsAny<List<int>>(), It.IsAny<IProgress<int>>(), It.IsAny<CancellationToken>(), It.IsAny<ScanPolicy>()))
          .ReturnsAsync(new List<PortScanResult>
          {
                    new PortScanResult { PortNumber = 80, Status = "开放", Service = "HTTP" }
          });

      var options = new ComprehensiveScanOptions
      {
        TargetIp = "192.168.1.1",
        Preset = ScanPreset.Quick,
        EnableTcp = true
      };

      // Act
      var result = await _service.ExecuteAsync(options, null, CancellationToken.None);

      // Assert
      result.Should().NotBeNull();
    }

    [Fact]
    public async Task ExecuteAsync_DeepPreset_ShouldScan()
    {
      // Arrange
      _portScannerMock
          .Setup(s => s.ScanTcpPortsAsync("192.168.1.1", It.IsAny<List<int>>(), It.IsAny<IProgress<int>>(), It.IsAny<CancellationToken>(), It.IsAny<ScanPolicy>()))
          .ReturnsAsync(new List<PortScanResult>
          {
                    new PortScanResult { PortNumber = 80, Status = "开放", Service = "HTTP" }
          });

      var options = new ComprehensiveScanOptions
      {
        TargetIp = "192.168.1.1",
        Preset = ScanPreset.Deep,
        EnableTcp = true
      };

      // Act
      var result = await _service.ExecuteAsync(options, null, CancellationToken.None);

      // Assert
      result.Should().NotBeNull();
    }

    [Fact]
    public async Task ExecuteAsync_CustomPreset_ShouldUseCustomPorts()
    {
      // Arrange
      _portScannerMock
          .Setup(s => s.ScanTcpPortsAsync("192.168.1.1", It.IsAny<List<int>>(), It.IsAny<IProgress<int>>(), It.IsAny<CancellationToken>(), It.IsAny<ScanPolicy>()))
          .ReturnsAsync(new List<PortScanResult>
          {
                    new PortScanResult { PortNumber = 80, Status = "开放", Service = "HTTP" }
          });

      var options = new ComprehensiveScanOptions
      {
        TargetIp = "192.168.1.1",
        Preset = ScanPreset.Custom,
        CustomPorts = "80,443,8080",
        EnableTcp = true
      };

      // Act
      var result = await _service.ExecuteAsync(options, null, CancellationToken.None);

      // Assert
      result.Should().NotBeNull();
    }

    #endregion

    #region 取消令牌测试

    [Fact]
    public async Task ExecuteAsync_CancellationRequested_ShouldReturnCancelledResult()
    {
      // Arrange
      var options = new ComprehensiveScanOptions
      {
        TargetIp = "192.168.1.1",
        Preset = ScanPreset.Quick
      };
      var cts = new CancellationTokenSource();
      cts.Cancel();

      // Act
      var result = await _service.ExecuteAsync(options, null, cts.Token);

      // Assert
      result.Cancelled.Should().BeTrue("取消令牌被触发时，结果应标记为已取消");
    }

    #endregion

    #region 进度报告测试

    [Fact]
    public async Task ExecuteAsync_ShouldReportProgress()
    {
      // Arrange
      _portScannerMock
          .Setup(s => s.ScanTcpPortsAsync("192.168.1.1", It.IsAny<List<int>>(), It.IsAny<IProgress<int>>(), It.IsAny<CancellationToken>(), It.IsAny<ScanPolicy>()))
          .ReturnsAsync(new List<PortScanResult>
          {
                    new PortScanResult { PortNumber = 80, Status = "开放", Service = "HTTP" }
          });

      var options = new ComprehensiveScanOptions
      {
        TargetIp = "192.168.1.1",
        Preset = ScanPreset.Quick
      };
      var progressReports = new List<ScanPhaseProgress>();
      var progress = new Progress<ScanPhaseProgress>(report => progressReports.Add(report));

      // Act
      await _service.ExecuteAsync(options, progress, CancellationToken.None);

      // Assert
      progressReports.Should().NotBeEmpty("应报告至少一个进度");
    }

    #endregion

    #region 日志记录测试

    [Fact]
    public async Task ExecuteAsync_WithNullLogger_ShouldNotThrow()
    {
      // Arrange
      var service = new ComprehensiveScanService(
          _portScannerMock.Object,
          _vulnerabilityScannerMock.Object,
          _jsonDatabaseMock.Object,
          _pluginOrchestratorMock.Object,
          null);

      _portScannerMock
          .Setup(s => s.ScanTcpPortsAsync("192.168.1.1", It.IsAny<List<int>>(), It.IsAny<IProgress<int>>(), It.IsAny<CancellationToken>(), It.IsAny<ScanPolicy>()))
          .ReturnsAsync(new List<PortScanResult>
          {
                    new PortScanResult { PortNumber = 80, Status = "开放", Service = "HTTP" }
          });

      var options = new ComprehensiveScanOptions
      {
        TargetIp = "192.168.1.1",
        Preset = ScanPreset.Quick
      };

      // Act
      Func<Task> act = () => service.ExecuteAsync(options, null, CancellationToken.None);

      // Assert
      await act.Should().NotThrowAsync("null logger 不应导致异常");
    }

    #endregion
  }
}