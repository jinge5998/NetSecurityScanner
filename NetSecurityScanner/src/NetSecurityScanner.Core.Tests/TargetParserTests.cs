using System;
using System.Collections.Generic;
using FluentAssertions;
using NetSecurityScanner.Utils;
using Xunit;

namespace NetSecurityScanner.Tests
{
  public class TargetParserTests
  {
    private const Models.TargetType Single = Models.TargetType.Single;
    private const Models.TargetType Range = Models.TargetType.Range;
    private const Models.TargetType CIDR = Models.TargetType.CIDR;
    private const Models.TargetType ListFile = Models.TargetType.ListFile;

    #region 边界情况测试

    [Fact]
    public void ParseTargets_NullInput_ShouldThrowArgumentNullException()
    {
      // Arrange
      string input = null;

      // Act
      Action act = () => TargetParser.ParseTargets(input, Single);

      // Assert
      act.Should().Throw<ArgumentNullException>();
    }

    [Fact]
    public void ParseTargets_EmptyInput_ShouldThrowArgumentException()
    {
      // Arrange
      string input = "";

      // Act
      Action act = () => TargetParser.ParseTargets(input, Single);

      // Assert
      act.Should().Throw<ArgumentException>();
    }

    [Fact]
    public void ParseTargets_WhiteSpaceInput_ShouldThrowArgumentException()
    {
      // Arrange
      string input = "   ";

      // Act
      Action act = () => TargetParser.ParseTargets(input, Single);

      // Assert
      act.Should().Throw<ArgumentException>();
    }

    [Fact]
    public void ParseCidr_Prefix32_ShouldReturnSingleIp()
    {
      // Act
      var result = TargetParser.ParseTargets("192.168.1.100/32", CIDR);

      // Assert
      result.Should().HaveCount(1);
      result.Should().Contain("192.168.1.100");
    }

    [Fact]
    public void ParseCidr_Prefix31_ShouldReturnNoHosts()
    {
      // Act
      var result = TargetParser.ParseTargets("192.168.1.0/31", CIDR);

      // Assert - /31 用于点到点链路，无可用主机地址
      result.Should().BeEmpty();
    }

    [Fact]
    public void ParseCidr_Prefix0_ShouldThrowOverLimit()
    {
      // Act
      Action act = () => TargetParser.ParseTargets("0.0.0.0/0", CIDR);

      // Assert - 实际错误消息为"CIDR前缀 /0 会生成超过 65536 个目标，已被限制..."
      act.Should().Throw<ArgumentException>().WithMessage("*已被限制*");
    }

    [Fact]
    public void ParseCidr_Prefix8_ShouldThrowOverLimit()
    {
      // Act
      Action act = () => TargetParser.ParseTargets("10.0.0.0/8", CIDR);

      // Assert - /8 有 ~16M 地址，超过限制
      act.Should().Throw<ArgumentException>().WithMessage("*超过最大限制*");
    }

    [Fact]
    public void ParseCidr_InvalidPrefix_ShouldThrowArgumentException()
    {
      // Act
      Action act = () => TargetParser.ParseTargets("192.168.1.0/33", CIDR);

      // Assert
      act.Should().Throw<ArgumentException>().WithMessage("*0-32*");
    }

    [Fact]
    public void ParseCidr_NegativePrefix_ShouldThrowArgumentException()
    {
      // Act
      Action act = () => TargetParser.ParseTargets("192.168.1.0/-1", CIDR);

      // Assert
      act.Should().Throw<ArgumentException>().WithMessage("*0-32*");
    }

    [Fact]
    public void ParseCidr_InvalidFormat_ShouldThrowArgumentException()
    {
      // Act
      Action act = () => TargetParser.ParseTargets("192.168.1.0/24/extra", CIDR);

      // Assert
      act.Should().Throw<ArgumentException>().WithMessage("*CIDR*");
    }

    [Fact]
    public void ParseIpRange_SameStartEnd_ShouldReturnSingleIp()
    {
      // Act
      var result = TargetParser.ParseTargets("192.168.1.100-192.168.1.100", Range);

      // Assert
      result.Should().HaveCount(1);
      result.Should().Contain("192.168.1.100");
    }

    [Fact]
    public void ParseIpRange_ReversedOrder_ShouldSwapAndReturnCorrect()
    {
      // Act
      var result = TargetParser.ParseTargets("192.168.1.100-192.168.1.1", Range);

      // Assert - 自动交换，得到1-100共100个地址
      result.Should().HaveCount(100);
      result[0].Should().Be("192.168.1.1");
      result[^1].Should().Be("192.168.1.100");
    }

    [Fact]
    public void ParseIpRange_InvalidFormat_ShouldThrowArgumentException()
    {
      // Act
      Action act = () => TargetParser.ParseTargets("192.168.1.1 192.168.1.100", Range);

      // Assert
      act.Should().Throw<ArgumentException>().WithMessage("*IP段格式*");
    }

    [Fact]
    public void ParseIpRange_InvalidIp_ShouldThrowException()
    {
      // Act
      Action act = () => TargetParser.ParseTargets("not-an-ip-192.168.1.100", Range);

      // Assert
      act.Should().Throw<Exception>();
    }

    [Fact]
    public void ParseIpRange_TooLarge_ShouldThrowOverLimit()
    {
      // Act - 0.0.0.0 - 0.1.0.0 包含 65537 个地址，超过限制
      Action act = () => TargetParser.ParseTargets("0.0.0.0-0.1.0.0", Range);

      // Assert
      act.Should().Throw<ArgumentException>().WithMessage("*超过最大限制*");
    }

    [Fact]
    public void ValidateTarget_ValidSingleIp_ShouldReturnTrue()
    {
      // Act
      var result = TargetParser.ValidateTarget("192.168.1.1", Single);

      // Assert
      result.Should().BeTrue();
    }

    [Fact]
    public void ValidateTarget_InvalidCidr_ShouldReturnFalse()
    {
      // Act
      var result = TargetParser.ValidateTarget("192.168.1.0/33", CIDR);

      // Assert
      result.Should().BeFalse();
    }

    [Fact]
    public void ValidateTarget_InvalidRange_ShouldReturnFalse()
    {
      // Act
      var result = TargetParser.ValidateTarget("192.168.1.1--192.168.1.100", Range);

      // Assert
      result.Should().BeFalse();
    }

    [Fact]
    public void ValidateTarget_NullInput_ShouldReturnFalse()
    {
      // Act
      var result = TargetParser.ValidateTarget(null, Single);

      // Assert
      result.Should().BeFalse();
    }

    [Fact]
    public void ValidateTarget_EmptyInput_ShouldReturnFalse()
    {
      // Act
      var result = TargetParser.ValidateTarget("", Single);

      // Assert
      result.Should().BeFalse();
    }

    #endregion

    #region 正常功能测试

    [Fact]
    public void ParseSingleIp_ShouldReturnSingleItem()
    {
      // Act
      var result = TargetParser.ParseTargets("192.168.1.1", Single);

      // Assert
      result.Should().HaveCount(1);
      result.Should().Contain("192.168.1.1");
    }

    [Fact]
    public void ParseSmallRange_ShouldReturnCorrectCount()
    {
      // Act
      var result = TargetParser.ParseTargets("192.168.1.1-192.168.1.5", Range);

      // Assert
      result.Should().HaveCount(5);
      result[0].Should().Be("192.168.1.1");
      result[^1].Should().Be("192.168.1.5");
    }

    [Fact]
    public void ParseCidr_24Prefix_ShouldReturn254Hosts()
    {
      // Act
      var result = TargetParser.ParseTargets("192.168.1.0/24", CIDR);

      // Assert
      result.Should().HaveCount(254);
      result.Should().NotContain("192.168.1.0");
      result.Should().NotContain("192.168.1.255");
    }

    [Fact]
    public void ParseCidr_28Prefix_ShouldReturn14Hosts()
    {
      // Act
      var result = TargetParser.ParseTargets("192.168.1.0/28", CIDR);

      // Assert
      result.Should().HaveCount(14);
    }

    [Fact]
    public void ParseCidr_16Prefix_ShouldReturn65534Hosts()
    {
      // Act
      var result = TargetParser.ParseTargets("10.0.0.0/16", CIDR);

      // Assert
      result.Should().HaveCount(65534);
    }

    [Fact]
    public void ParseCidr_15Prefix_ShouldBeLimited()
    {
      // Act
      Action act = () => TargetParser.ParseTargets("10.0.0.0/15", CIDR);

      // Assert
      act.Should().Throw<ArgumentException>().WithMessage("*超过最大限制*");
    }

    [Fact]
    public void ValidateTarget_ValidCidr_ShouldReturnTrue()
    {
      // Act
      var result = TargetParser.ValidateTarget("10.0.0.0/24", CIDR);

      // Assert
      result.Should().BeTrue();
    }

    [Fact]
    public void ValidateTarget_ValidRange_ShouldReturnTrue()
    {
      // Act
      var result = TargetParser.ValidateTarget("10.0.0.1-10.0.0.10", Range);

      // Assert
      result.Should().BeTrue();
    }

    // 检查 MaxTargetsLimit 常量值
    [Fact]
    public void MaxTargetsLimit_ShouldBe65536()
    {
      // Assert
      TargetParser.MaxTargetsLimit.Should().Be(65536);
    }

    [Fact]
    public void MaxTargetsLimit_ShouldBeGreaterThanOrEqualTo65534()
    {
      // Assert - 必须至少能容纳 /16 的 65534 个地址
      TargetParser.MaxTargetsLimit.Should().BeGreaterOrEqualTo(65534);
    }

    #endregion
  }
}