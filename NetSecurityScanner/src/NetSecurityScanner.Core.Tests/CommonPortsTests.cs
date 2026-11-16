using System;
using System.Collections.Generic;
using System.Linq;
using FluentAssertions;
using NetSecurityScanner.Utils;
using Xunit;

namespace NetSecurityScanner.Tests
{
  public class CommonPortsTests
  {
    #region GetTop1000Ports 测试

    [Fact]
    public void GetTop1000Ports_ShouldContainBasePorts()
    {
      // Act
      var ports = CommonPorts.GetTop1000Ports();

      // Assert
      ports.Should().Contain(new[] { 80, 443, 22, 21, 23, 25, 53, 110, 143, 3389, 3306, 5432, 6379 });
    }

    [Fact]
    public void GetTop1000Ports_ShouldContainHighFrequencyPorts()
    {
      // Act
      var ports = CommonPorts.GetTop1000Ports();

      // Assert
      ports.Should().Contain(new[] { 8080, 8443, 3000, 5000, 9090, 9200, 27017, 2375, 6379, 11211 });
    }

    [Fact]
    public void GetTop1000Ports_ShouldContainAllPortsFrom1To1024()
    {
      // Act
      var ports = CommonPorts.GetTop1000Ports();

      // Assert - 1-1024 全部包含
      for (int i = 1; i <= 1024; i++)
      {
        ports.Should().Contain(i);
      }
    }

    [Fact]
    public void GetTop1000Ports_ShouldHaveNoDuplicates()
    {
      // Act
      var ports = CommonPorts.GetTop1000Ports();

      // Assert
      ports.Should().OnlyHaveUniqueItems();
    }

    [Fact]
    public void GetTop1000Ports_ShouldBeSorted()
    {
      // Act
      var ports = CommonPorts.GetTop1000Ports();

      // Assert
      ports.Should().BeInAscendingOrder();
    }

    [Fact]
    public void GetTop1000Ports_Count_ShouldBeGreaterThan1024()
    {
      // Act
      var ports = CommonPorts.GetTop1000Ports();

      // Assert - 1-1024(1024个) + 高频端口(去重后) > 1024
      ports.Count.Should().BeGreaterThan(1024);
    }

    [Fact]
    public void GetTop1000Ports_ShouldNotContainPort0()
    {
      // Act
      var ports = CommonPorts.GetTop1000Ports();

      // Assert
      ports.Should().NotContain(0);
    }

    [Fact]
    public void GetTop1000Ports_ShouldNotContainPort65536()
    {
      // Act
      var ports = CommonPorts.GetTop1000Ports();

      // Assert
      ports.Should().NotContain(65536);
    }

    #endregion

    #region GetAllPorts 测试

    [Fact]
    public void GetAllPorts_ShouldContainAllCriticalServices()
    {
      // Act
      var ports = CommonPorts.GetAllPorts();

      // Assert
      ports.Should().Contain(new[]
      {
        21, 22, 23, 25, 53, 80, 110, 143, 443, 465, 993, 995, 587, // 基础/邮件
        1433, 3306, 5432, 6379, 27017, 9200, 11211, 9042, 5984, // 数据库
        3389, 5900, 445, // 远程访问
        8080, 8443, 8081, 8000, // Web
        2375, 2376, 6443, 2379, 2380, 10250, 10251, 10252, 10255, // 容器
        5672, 9092, 61616, // 消息队列
        123, 161, 162, 389, 636, 5060, 5061, 1812, 1813, // 其他
        8088, 9000, 9100, 3000, 4200, 5000, 8888, 9001, 9090, 9411, 9999 // 监控/开发
      });
    }

    [Fact]
    public void GetAllPorts_ShouldHaveNoDuplicates()
    {
      // Act
      var ports = CommonPorts.GetAllPorts();

      // Assert
      ports.Should().OnlyHaveUniqueItems();
    }

    [Fact]
    public void GetAllPorts_Count_ShouldBeGreaterThan50()
    {
      // Act
      var ports = CommonPorts.GetAllPorts();

      // Assert
      ports.Count.Should().BeGreaterThan(50);
    }

    #endregion

    #region GetCommonPorts 测试

    [Fact]
    public void GetCommonPorts_ShouldContainExactlyExpectedPorts()
    {
      // Arrange
      var expected = new List<int>
      {
        21, 22, 23, 25, 53, 80, 110, 143, 443, 465, 993, 995,
        1433, 3306, 3389, 5432, 6379, 27017, 8080, 8443
      };

      // Act
      var ports = CommonPorts.GetCommonPorts();

      // Assert
      ports.Should().BeEquivalentTo(expected);
    }

    [Fact]
    public void GetCommonPorts_ShouldHaveNoDuplicates()
    {
      // Act
      var ports = CommonPorts.GetCommonPorts();

      // Assert
      ports.Should().OnlyHaveUniqueItems();
    }

    [Fact]
    public void GetCommonPorts_Count_ShouldBe20()
    {
      // Act
      var ports = CommonPorts.GetCommonPorts();

      // Assert
      ports.Count.Should().Be(20);
    }

    #endregion

    #region IsSensitivePort 测试

    [Fact]
    public void IsSensitivePort_CommonSensitivePorts_ShouldReturnTrue()
    {
      // Assert
      CommonPorts.IsSensitivePort(21).Should().BeTrue();   // FTP
      CommonPorts.IsSensitivePort(22).Should().BeTrue();   // SSH
      CommonPorts.IsSensitivePort(23).Should().BeTrue();   // Telnet
      CommonPorts.IsSensitivePort(3389).Should().BeTrue(); // RDP
      CommonPorts.IsSensitivePort(445).Should().BeTrue();  // SMB
      CommonPorts.IsSensitivePort(6379).Should().BeTrue(); // Redis
      CommonPorts.IsSensitivePort(27017).Should().BeTrue(); // MongoDB
      CommonPorts.IsSensitivePort(9200).Should().BeTrue(); // Elasticsearch
      CommonPorts.IsSensitivePort(11211).Should().BeTrue(); // Memcached
      CommonPorts.IsSensitivePort(2375).Should().BeTrue(); // Docker HTTP
      CommonPorts.IsSensitivePort(2376).Should().BeTrue(); // Docker HTTPS
      CommonPorts.IsSensitivePort(6443).Should().BeTrue(); // Kubernetes API
      CommonPorts.IsSensitivePort(8080).Should().BeTrue(); // HTTP Alternate
      CommonPorts.IsSensitivePort(8443).Should().BeTrue(); // HTTPS Alternate
    }

    [Fact]
    public void IsSensitivePort_NonSensitivePorts_ShouldReturnFalse()
    {
      // Assert
      CommonPorts.IsSensitivePort(80).Should().BeFalse();  // HTTP（非敏感）
      CommonPorts.IsSensitivePort(443).Should().BeFalse(); // HTTPS（非敏感）
      CommonPorts.IsSensitivePort(53).Should().BeFalse();  // DNS
      CommonPorts.IsSensitivePort(8081).Should().BeFalse(); // 不在敏感列表
    }

    [Fact]
    public void IsSensitivePort_EdgePorts_ShouldNotThrow()
    {
      // Assert - 边界值
      CommonPorts.IsSensitivePort(0).Should().BeFalse();
      CommonPorts.IsSensitivePort(-1).Should().BeFalse();
      CommonPorts.IsSensitivePort(65535).Should().BeFalse();
      CommonPorts.IsSensitivePort(65536).Should().BeFalse();
    }

    #endregion

    #region GetSensitivePorts 测试

    [Fact]
    public void GetSensitivePorts_ShouldReturnAllSensitivePorts()
    {
      // Act
      var ports = CommonPorts.GetSensitivePorts();

      // Assert
      ports.Should().Contain(new[]
      {
        21, 22, 23, 3389, 445, 6379, 27017, 9200, 11211, 2375, 2376, 6443, 8080, 8443
      });
      ports.Count.Should().Be(14);
    }

    [Fact]
    public void GetSensitivePorts_ShouldBeIndependentCopy()
    {
      // Act
      var ports1 = CommonPorts.GetSensitivePorts();
      var ports2 = CommonPorts.GetSensitivePorts();

      // Assert - 返回的是独立副本，修改不影响
      ports1.Clear();
      ports2.Should().NotBeEmpty();
    }

    [Fact]
    public void GetSensitivePorts_ShouldHaveNoDuplicates()
    {
      // Act
      var ports = CommonPorts.GetSensitivePorts();

      // Assert
      ports.Should().OnlyHaveUniqueItems();
    }

    #endregion

    #region 交叉验证测试

    [Fact]
    public void SensitivePorts_ShouldBeSubsetOfTop1000Ports()
    {
      // Arrange
      var sensitivePorts = CommonPorts.GetSensitivePorts();
      var top1000Ports = CommonPorts.GetTop1000Ports();

      // Assert
      top1000Ports.Should().Contain(sensitivePorts);
    }

    [Fact]
    public void CommonPorts_ShouldBeSubsetOfTop1000Ports()
    {
      // Arrange
      var commonPorts = CommonPorts.GetCommonPorts();
      var top1000Ports = CommonPorts.GetTop1000Ports();

      // Assert
      top1000Ports.Should().Contain(commonPorts);
    }

    [Fact]
    public void SensitivePorts_ShouldAllAppearInAllPorts()
    {
      // Arrange
      var sensitivePorts = CommonPorts.GetSensitivePorts();
      var allPorts = CommonPorts.GetAllPorts();

      // Assert
      allPorts.Should().Contain(sensitivePorts);
    }

    #endregion
  }
}