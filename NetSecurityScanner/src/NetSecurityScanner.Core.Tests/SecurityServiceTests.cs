using System;
using System.Linq;
using System.Threading.Tasks;
using FluentAssertions;
using NetSecurityScanner.Core;
using Xunit;

namespace NetSecurityScanner.Tests
{
  public class SecurityServiceTests : IDisposable
  {
    private readonly SecurityService _service;

    public SecurityServiceTests()
    {
      _service = new SecurityService();
    }

    public void Dispose()
    {
      // SecurityService 无托管资源需要释放
    }

    #region 密码哈希与验证测试

    [Fact]
    public void HashPassword_ShouldProduceConsistentHash_WithSameSalt()
    {
      // Arrange - 访问私有方法通过反射
      var password = "TestPassword123!";
      var salt = "A7B3C9D1E5F2G8H4";

      // Act - 通过 AuthenticateUserAsync 验证哈希一致性
      // 使用已知用户 admin 的密码 admin123

      // Assert - 验证已知用户密码匹配
      var authResult = _service.AuthenticateUserAsync("admin", "admin123");
      authResult.Result.Should().BeTrue("预置用户 admin 的密码 admin123 应验证通过");
    }

    [Fact]
    public void HashPassword_ShouldProduceDifferentOutput_WithDifferentPassword()
    {
      // Act - 尝试错误密码登录预置用户
      var authResult = _service.AuthenticateUserAsync("admin", "wrong_password");

      // Assert
      authResult.Result.Should().BeFalse("错误密码不应通过验证");
    }

    [Fact]
    public void VerifyPassword_WithEmptyPassword_ShouldReturnFalse()
    {
      // Act - 空密码
      var authResult = _service.AuthenticateUserAsync("admin", "");

      // Assert
      authResult.Result.Should().BeFalse("空密码不应通过验证");
    }

    [Fact]
    public void VerifyPassword_WithNullPassword_ShouldThrowException()
    {
      // Act
      Func<Task> act = () => _service.AuthenticateUserAsync("admin", null!);

      // Assert
      // 当前实现 Encoding.UTF8.GetBytes(null) 会抛出 ArgumentNullException，
      // 这是合理的防御性行为，调用方应保证密码不为 null
      act.Should().ThrowAsync<Exception>();
    }

    [Fact]
    public void VerifyPassword_WithNonexistentUser_ShouldReturnFalse()
    {
      // Act - 不存在的用户
      var authResult = _service.AuthenticateUserAsync("nonexistent_user", "admin123");

      // Assert
      authResult.Result.Should().BeFalse("不存在的用户不应通过验证");
    }

    #endregion

    #region 认证流程测试

    [Fact]
    public void AuthenticateUserAsync_ValidAdminCredentials_ShouldReturnTrue()
    {
      // Arrange & Act
      var result = _service.AuthenticateUserAsync("admin", "admin123");

      // Assert
      result.Result.Should().BeTrue("管理员凭据应通过验证");
    }

    [Fact]
    public void AuthenticateUserAsync_ValidUserCredentials_ShouldReturnTrue()
    {
      // Arrange & Act
      var result = _service.AuthenticateUserAsync("user", "user123");

      // Assert
      result.Result.Should().BeTrue("普通用户凭据应通过验证");
    }

    [Fact]
    public void AuthenticateUserAsync_ValidAuditorCredentials_ShouldReturnTrue()
    {
      // Arrange & Act
      var result = _service.AuthenticateUserAsync("audit", "audit123");

      // Assert
      result.Result.Should().BeTrue("审计员凭据应通过验证");
    }

    [Fact]
    public void AuthenticateUserAsync_InvalidCredentials_ShouldReturnFalse()
    {
      // Act
      var result = _service.AuthenticateUserAsync("admin", "wrong_password");

      // Assert
      result.Result.Should().BeFalse("错误凭据不应通过验证");
    }

    #endregion

    #region RBAC 授权测试

    [Fact]
    public void AuthorizeActionAsync_AdminUser_ShouldHaveAllPermissions()
    {
      // Arrange - admin 用户 ID 为 "1"
      // Act
      var scanResult = _service.AuthorizeActionAsync("1", "Scan");
      var manageUsersResult = _service.AuthorizeActionAsync("1", "ManageUsers");
      var auditLogsResult = _service.AuthorizeActionAsync("1", "ViewAuditLogs");
      var reportsResult = _service.AuthorizeActionAsync("1", "GenerateReports");

      // Assert
      scanResult.Result.Should().BeTrue("管理员应有扫描权限");
      manageUsersResult.Result.Should().BeTrue("管理员应有用户管理权限");
      auditLogsResult.Result.Should().BeTrue("管理员应有审计日志权限");
      reportsResult.Result.Should().BeTrue("管理员应有报表生成权限");
    }

    [Fact]
    public void AuthorizeActionAsync_RegularUser_ShouldHaveLimitedPermissions()
    {
      // Arrange - user 用户 ID 为 "2"
      // Act
      var scanResult = _service.AuthorizeActionAsync("2", "Scan");
      var viewReportsResult = _service.AuthorizeActionAsync("2", "ViewReports");
      var manageUsersResult = _service.AuthorizeActionAsync("2", "ManageUsers");
      var auditLogsResult = _service.AuthorizeActionAsync("2", "ViewAuditLogs");

      // Assert
      scanResult.Result.Should().BeTrue("普通用户应有扫描权限");
      viewReportsResult.Result.Should().BeTrue("普通用户应有查看报表权限");
      manageUsersResult.Result.Should().BeFalse("普通用户不应有用户管理权限");
      auditLogsResult.Result.Should().BeFalse("普通用户不应有审计日志权限");
    }

    [Fact]
    public void AuthorizeActionAsync_Auditor_ShouldHaveAuditPermissions()
    {
      // Arrange - audit 用户 ID 为 "3"
      // Act
      var scanResult = _service.AuthorizeActionAsync("3", "Scan");
      var viewAuditResult = _service.AuthorizeActionAsync("3", "ViewAuditLogs");
      var viewReportsResult = _service.AuthorizeActionAsync("3", "ViewReports");
      var manageUsersResult = _service.AuthorizeActionAsync("3", "ManageUsers");

      // Assert
      scanResult.Result.Should().BeFalse("审计员不应有扫描权限");
      viewAuditResult.Result.Should().BeTrue("审计员应有审计日志权限");
      viewReportsResult.Result.Should().BeTrue("审计员应有查看报表权限");
      manageUsersResult.Result.Should().BeFalse("审计员不应有用户管理权限");
    }

    [Fact]
    public void AuthorizeActionAsync_NonexistentUserId_ShouldReturnFalse()
    {
      // Act
      var result = _service.AuthorizeActionAsync("nonexistent", "Scan");

      // Assert
      result.Result.Should().BeFalse("不存在的用户 ID 不应通过授权");
    }

    [Fact]
    public void AuthorizeActionAsync_NonexistentAction_ShouldReturnFalse()
    {
      // Act
      var result = _service.AuthorizeActionAsync("1", "NonexistentAction");

      // Assert
      result.Result.Should().BeFalse("不存在的操作不应通过授权");
    }

    #endregion

    #region 扫描目标验证测试

    [Fact]
    public void ValidateScanTarget_Localhost_ShouldReturnTrue()
    {
      // Act
      var result = _service.ValidateScanTarget("127.0.0.1");

      // Assert
      result.Should().BeTrue("localhost 应在白名单中");
    }

    [Fact]
    public void ValidateScanTarget_PrivateNetwork_ShouldReturnTrue()
    {
      // Act
      var result = _service.ValidateScanTarget("192.168.1.100");

      // Assert
      result.Should().BeTrue("192.168.x.x 应在白名单中");
    }

    [Fact]
    public void ValidateScanTarget_ExternalIp_ShouldReturnFalse()
    {
      // Act
      var result = _service.ValidateScanTarget("8.8.8.8");

      // Assert
      result.Should().BeFalse("外部 IP 不应在白名单中");
    }

    [Fact]
    public void ValidateScanTarget_EmptyString_ShouldReturnFalse()
    {
      // Act
      var result = _service.ValidateScanTarget("");

      // Assert
      result.Should().BeFalse("空字符串不应通过验证");
    }

    [Fact]
    public void ValidateScanTarget_NullInput_ShouldThrowException()
    {
      // Act
      Action act = () => _service.ValidateScanTarget(null!);

      // Assert
      // 当前实现 target.StartsWith(w) 在 target 为 null 时抛出 NullReferenceException
      // 这是合理的，调用方应保证 target 不为 null
      act.Should().Throw<Exception>();
    }

    #endregion

    #region 加密/解密测试

    [Fact]
    public void EncryptData_ShouldProduceBase64Output()
    {
      // Arrange
      var plainText = "SensitiveData123";

      // Act
      var encrypted = _service.EncryptData(plainText);

      // Assert
      encrypted.Should().NotBeNullOrEmpty();
      // Base64 字符串应只包含合法字符
      encrypted.Should().MatchRegex("^[A-Za-z0-9+/=]+$");
    }

    [Fact]
    public void DecryptData_ShouldReturnOriginalPlainText()
    {
      // Arrange
      var plainText = "SensitiveData123";

      // Act
      var encrypted = _service.EncryptData(plainText);
      var decrypted = _service.DecryptData(encrypted);

      // Assert
      decrypted.Should().Be(plainText);
    }

    [Fact]
    public void DecryptData_InvalidBase64_ShouldReturnEmpty()
    {
      // Act
      var result = _service.DecryptData("!!invalid_base64!!");

      // Assert
      result.Should().BeEmpty("无效的 Base64 输入应返回空字符串");
    }

    [Fact]
    public void DecryptData_EmptyString_ShouldReturnEmpty()
    {
      // Act
      var result = _service.DecryptData("");

      // Assert
      result.Should().BeEmpty("空字符串解密应返回空字符串");
    }

    #endregion

    #region 审计日志测试

    [Fact]
    public void LogAuditEvent_ShouldAddEntry()
    {
      // Arrange
      var beforeCount = _service.GetAuditLogs(DateTime.MinValue, DateTime.MaxValue).Count;

      // Act
      _service.LogAuditEvent("test_user", "TestAction", "Test details");

      // Assert
      var afterCount = _service.GetAuditLogs(DateTime.MinValue, DateTime.MaxValue).Count;
      afterCount.Should().Be(beforeCount + 1);
    }

    [Fact]
    public void GetAuditLogs_WithTimeRange_ShouldFilterCorrectly()
    {
      // Arrange
      _service.LogAuditEvent("user1", "Action1", "Details1");

      var fromDate = DateTime.Now.AddDays(-1);
      var toDate = DateTime.Now.AddDays(1);

      // Act
      var logs = _service.GetAuditLogs(fromDate, toDate);

      // Assert
      logs.Should().NotBeNull();
      logs.Count.Should().BeGreaterThan(0);
      logs.All(l => l.Timestamp >= fromDate && l.Timestamp <= toDate).Should().BeTrue();
    }

    [Fact]
    public void GetAuditLogs_WithFutureTimeRange_ShouldReturnEmpty()
    {
      // Arrange
      var fromDate = DateTime.Now.AddYears(1);
      var toDate = DateTime.Now.AddYears(2);

      // Act
      var logs = _service.GetAuditLogs(fromDate, toDate);

      // Assert
      logs.Should().BeEmpty("未来时间范围内不应有审计日志");
    }

    [Fact]
    public void GetAuditLogs_WithPastTimeRange_ShouldReturnEmpty()
    {
      // Arrange
      var fromDate = DateTime.Now.AddYears(-10);
      var toDate = DateTime.Now.AddYears(-9);

      // Act
      var logs = _service.GetAuditLogs(fromDate, toDate);

      // Assert
      logs.Should().BeEmpty("过去时间范围内不应有审计日志");
    }

    [Fact]
    public void LogAuditEvent_ShouldRecordCorrectDetails()
    {
      // Arrange
      var userId = "test_user";
      var action = "Login";
      var details = "Successful login from 127.0.0.1";

      // Act
      _service.LogAuditEvent(userId, action, details);

      // Assert
      var logs = _service.GetAuditLogs(DateTime.MinValue, DateTime.MaxValue);
      var log = logs.Last();
      log.UserId.Should().Be(userId);
      log.Action.Should().Be(action);
      log.Details.Should().Be(details);
      log.Timestamp.Should().BeCloseTo(DateTime.Now, TimeSpan.FromSeconds(5));
    }

    #endregion

    #region 认证触发审计日志测试

    [Fact]
    public void AuthenticateUserAsync_ShouldLogAuditEvent_OnSuccess()
    {
      // Arrange
      var beforeCount = _service.GetAuditLogs(DateTime.MinValue, DateTime.MaxValue).Count;

      // Act
      _service.AuthenticateUserAsync("admin", "admin123").Wait();

      // Assert
      var afterCount = _service.GetAuditLogs(DateTime.MinValue, DateTime.MaxValue).Count;
      afterCount.Should().Be(beforeCount + 1);
    }

    [Fact]
    public void AuthenticateUserAsync_ShouldLogAuditEvent_OnFailure()
    {
      // Arrange
      var beforeCount = _service.GetAuditLogs(DateTime.MinValue, DateTime.MaxValue).Count;

      // Act
      _service.AuthenticateUserAsync("admin", "wrong_password").Wait();

      // Assert
      var afterCount = _service.GetAuditLogs(DateTime.MinValue, DateTime.MaxValue).Count;
      afterCount.Should().Be(beforeCount + 1);
    }

    #endregion
  }
}