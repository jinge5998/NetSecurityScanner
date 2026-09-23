using System;
using FluentAssertions;
using NetSecurityScanner.Models;
using NetSecurityScanner.Services;
using Xunit;

namespace NetSecurityScanner.Tests
{
  public class LicenseServiceTests
  {
    private readonly LicenseService _service;

    public LicenseServiceTests()
    {
      _service = new LicenseService();
    }

    #region 授权码格式验证测试

    [Fact]
    public void ValidateLicenseCode_NullCode_ShouldReturnFalse()
    {
      // Act
      var result = _service.ValidateLicenseCode(null!, out var licenseInfo, out var errorMessage);

      // Assert
      result.Should().BeFalse("null 授权码不应通过验证");
      errorMessage.Should().NotBeNullOrEmpty();
      licenseInfo.Should().BeNull();
    }

    [Fact]
    public void ValidateLicenseCode_EmptyCode_ShouldReturnFalse()
    {
      // Act
      var result = _service.ValidateLicenseCode("", out var licenseInfo, out var errorMessage);

      // Assert
      result.Should().BeFalse("空授权码不应通过验证");
      errorMessage.Should().NotBeNullOrEmpty();
      licenseInfo.Should().BeNull();
    }

    [Fact]
    public void ValidateLicenseCode_InvalidFormat_SingleSegment_ShouldReturnFalse()
    {
      // Act
      var result = _service.ValidateLicenseCode("ABCDEF123456", out var licenseInfo, out var errorMessage);

      // Assert
      result.Should().BeFalse("单段授权码格式无效");
      errorMessage.Should().Contain("格式无效");
    }

    [Fact]
    public void ValidateLicenseCode_InvalidFormat_FiveSegments_ShouldReturnFalse()
    {
      // Act
      var result = _service.ValidateLicenseCode("ABCD-1234-EFGH-5678-IJKL", out var licenseInfo, out var errorMessage);

      // Assert
      result.Should().BeFalse("五段授权码格式无效");
      errorMessage.Should().Contain("格式无效");
    }

    [Fact]
    public void ValidateLicenseCode_InvalidTimestamp_ShouldReturnFalse()
    {
      // Act
      var result = _service.ValidateLicenseCode("ABCDEF01-ABCDEF01-XYZ-ABCDEF01", out var licenseInfo, out var errorMessage);

      // Assert
      errorMessage.Should().Contain("时间戳");
      result.Should().BeFalse("无效时间戳不应通过验证");
    }

    [Fact]
    public void ValidateLicenseCode_InvalidTypeCode_ShouldReturnFalse()
    {
      // Act
      var result = _service.ValidateLicenseCode("ABCDEF01-20260101000000-X-ABCDEF01", out var licenseInfo, out var errorMessage);

      // Assert
      result.Should().BeFalse("无效类型码不应通过验证");
      // 如果 CodeToType 未抛出异常，则后续 HMAC 校验会失败，errorMessage 指示"校验失败"
      // 如果 CodeToType 抛出异常，则 errorMessage 指示"授权类型码无效"
      // 两种结果都合法，只验证验证失败即可
      errorMessage.Should().NotBeNullOrEmpty();
    }

    [Fact]
    public void ValidateLicenseCode_InvalidTypeCode_X_ShouldReturnFalse()
    {
      // Act
      var result = _service.ValidateLicenseCode("ABCDEF01-20260101000000-X-ABCDEF01", out var licenseInfo, out var errorMessage);

      // Assert
      result.Should().BeFalse("无效类型码 X 不应通过验证");
      // 可以是 "授权类型码无效" 或 "授权类型码" 或具体 CodeToType 异常
      errorMessage.Should().NotBeNullOrEmpty();
    }

    [Fact]
    public void ValidateLicenseCode_InvalidHMAC_ShouldReturnFalse()
    {
      // Act - 格式正确但 HMAC 校验失败
      var result = _service.ValidateLicenseCode("ABCDEF01-20260101000000-T-INVALIDHMAC", out var licenseInfo, out var errorMessage);

      // Assert
      result.Should().BeFalse("无效 HMAC 不应通过验证");
      errorMessage.Should().Contain("校验失败");
    }

    #endregion

    #region LicenseStatus 测试

    [Fact]
    public void GetLicenseStatus_ShouldReturnStatusWithMachineId()
    {
      // Act
      var status = _service.GetLicenseStatus();

      // Assert
      status.Should().NotBeNull();
      status.MachineId.Should().NotBeNullOrEmpty("应返回机器 ID");
      // LicenseInfo 可能为 null（首次运行）或非 null（已有授权文件），两种都合法
      // 关键验证：MachineId 始终存在
    }

    [Fact]
    public void IsLicensed_ShouldReturnConsistentResult()
    {
      // Act
      var result = _service.IsLicensed();
      var status = _service.GetLicenseStatus();

      // Assert
      result.Should().Be(status.IsLicensed, "IsLicensed() 应与 GetLicenseStatus().IsLicensed 一致");
    }

    [Fact]
    public void ActivateLicense_InvalidCode_ShouldReturnFalse()
    {
      // Act
      var result = _service.ActivateLicense("INVALID-LICENSE-CODE-12345");

      // Assert
      result.Should().BeFalse("无效授权码激活应返回 false");
    }

    [Fact]
    public void ActivateLicense_EmptyCode_ShouldReturnFalse()
    {
      // Act
      var result = _service.ActivateLicense("");

      // Assert
      result.Should().BeFalse("空授权码激活应返回 false");
    }

    [Fact]
    public void ActivateLicense_NullCode_ShouldReturnFalse()
    {
      // Act
      var result = _service.ActivateLicense(null!);

      // Assert
      result.Should().BeFalse("null 授权码激活应返回 false");
    }

    #endregion

    #region 机器 ID 测试

    [Fact]
    public void GetCurrentMachineId_ShouldReturnNonEmptyString()
    {
      // Act
      var machineId = _service.GetCurrentMachineId();

      // Assert
      machineId.Should().NotBeNullOrEmpty("机器 ID 不应为空");
      machineId.Length.Should().BeGreaterThanOrEqualTo(8, "机器 ID 应至少 8 个字符");
    }

    [Fact]
    public void GetCurrentMachineId_ShouldBeConsistent_OnMultipleCalls()
    {
      // Act
      var id1 = _service.GetCurrentMachineId();
      var id2 = _service.GetCurrentMachineId();

      // Assert
      id1.Should().Be(id2, "同一机器多次调用应返回相同 Machine ID");
    }

    #endregion
  }
}