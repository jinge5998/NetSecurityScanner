using System;
using System.Collections.Generic;
using System.Linq;
using FluentAssertions;
using NetSecurityScanner.Core;
using Xunit;

namespace NetSecurityScanner.Tests
{
  public class CameraVerifierTests : IDisposable
  {
    private readonly CameraVerifier _verifier;

    public CameraVerifierTests()
    {
      _verifier = new CameraVerifier();
    }

    public void Dispose()
    {
      _verifier?.Dispose();
    }

    #region T3: 反例过滤测试

    [Fact]
    public void IsLikelyNotCamera_DLinkRouter_ReturnsTrue()
    {
      var result = CameraVerifier.IsLikelyNotCamera(
        "<html><title>D-Link</title></html>", "");
      result.Should().BeTrue("D-Link 路由器应被反例过滤");
    }

    [Fact]
    public void IsLikelyNotCamera_SynologyNAS_ReturnsTrue()
    {
      var result = CameraVerifier.IsLikelyNotCamera(
        "<html>Synology DiskStation</html>", "");
      result.Should().BeTrue("Synology NAS 应被反例过滤");
    }

    [Fact]
    public void IsLikelyNotCamera_QNAPNAS_ReturnsTrue()
    {
      var result = CameraVerifier.IsLikelyNotCamera(
        "<html>QNAP</html>", "");
      result.Should().BeTrue("QNAP NAS 应被反例过滤");
    }

    [Fact]
    public void IsLikelyNotCamera_HPPrinter_ReturnsTrue()
    {
      var result = CameraVerifier.IsLikelyNotCamera(
        "<html>HP Printer</html>", "");
      result.Should().BeTrue("HP 打印机应被反例过滤");
    }

    [Fact]
    public void IsLikelyNotCamera_MikroTikRouter_ReturnsTrue()
    {
      var result = CameraVerifier.IsLikelyNotCamera(
        "", "MikroTik RouterOS");
      result.Should().BeTrue("MikroTik 路由器应被反例过滤");
    }

    [Fact]
    public void IsLikelyNotCamera_IIS_ReturnsTrue()
    {
      var result = CameraVerifier.IsLikelyNotCamera(
        "", "Microsoft-IIS/10.0");
      result.Should().BeTrue("IIS 服务器应被反例过滤");
    }

    [Fact]
    public void IsLikelyNotCamera_OpenWrt_ReturnsTrue()
    {
      var result = CameraVerifier.IsLikelyNotCamera(
        "<html>OpenWrt</html>", "");
      result.Should().BeTrue("OpenWrt 路由器应被反例过滤");
    }

    [Fact]
    public void IsLikelyNotCamera_HikvisionPage_ReturnsFalse()
    {
      var result = CameraVerifier.IsLikelyNotCamera(
        "<html><title>Hikvision-Webs</title></html>", "");
      result.Should().BeFalse("海康威视页面不应被反例过滤");
    }

    [Fact]
    public void IsLikelyNotCamera_DahuaPage_ReturnsFalse()
    {
      var result = CameraVerifier.IsLikelyNotCamera(
        "<html>Dahua WebSDK</html>", "");
      result.Should().BeFalse("大华页面不应被反例过滤");
    }

    [Fact]
    public void IsLikelyNotCamera_EmptyInput_ReturnsFalse()
    {
      var result = CameraVerifier.IsLikelyNotCamera("", "");
      result.Should().BeFalse("空输入不应被反例过滤");
    }

    #endregion

    #region T4: 厂商端口表测试

    [Fact]
    public void VendorPorts_ContainsHikvision()
    {
      CameraVerifier.VendorPorts.Should().ContainKey("Hikvision");
      CameraVerifier.VendorPorts["Hikvision"].Should().Contain(8000, "海康默认 HTTP 端口 8000");
    }

    [Fact]
    public void VendorPorts_ContainsDahua()
    {
      CameraVerifier.VendorPorts.Should().ContainKey("Dahua");
      CameraVerifier.VendorPorts["Dahua"].Should().Contain(37777, "大华默认端口 37777");
    }

    [Fact]
    public void VendorPorts_ContainsUniview()
    {
      CameraVerifier.VendorPorts.Should().ContainKey("Uniview");
      CameraVerifier.VendorPorts["Uniview"].Should().Contain(34567, "宇视默认端口 34567");
    }

    [Fact]
    public void VendorPorts_ContainsTiandy()
    {
      CameraVerifier.VendorPorts.Should().ContainKey("Tiandy");
      CameraVerifier.VendorPorts["Tiandy"].Should().Contain(6036, "天地伟业默认端口 6036");
    }

    [Fact]
    public void VendorPorts_ContainsEZVIZ()
    {
      CameraVerifier.VendorPorts.Should().ContainKey("EZVIZ");
      CameraVerifier.VendorPorts["EZVIZ"].Should().Contain(8001, "萤石默认端口 8001");
    }

    [Fact]
    public void VendorPorts_HasAtLeast10Vendors()
    {
      CameraVerifier.VendorPorts.Count.Should().BeGreaterOrEqualTo(10, "至少 10 个厂商");
    }

    [Fact]
    public void DefaultScanPorts_ContainsCommonPorts()
    {
      CameraVerifier.DefaultScanPorts.Should().Contain(80, "HTTP 端口");
      CameraVerifier.DefaultScanPorts.Should().Contain(554, "RTSP 端口");
      CameraVerifier.DefaultScanPorts.Should().Contain(8000, "海康 HTTP 端口");
      CameraVerifier.DefaultScanPorts.Should().Contain(37777, "大华端口");
    }

    #endregion

    #region T3: 反例关键词完整性测试

    [Fact]
    public void AntiCameraKeywords_ContainsRouterKeywords()
    {
      CameraVerifier.AntiCameraKeywords.Should().Contain("D-Link");
      CameraVerifier.AntiCameraKeywords.Should().Contain("TP-LINK Router");
      CameraVerifier.AntiCameraKeywords.Should().Contain("MikroTik");
      CameraVerifier.AntiCameraKeywords.Should().Contain("OpenWrt");
      CameraVerifier.AntiCameraKeywords.Should().Contain("iStoreOS");
    }

    [Fact]
    public void AntiCameraKeywords_ContainsNASKeywords()
    {
      CameraVerifier.AntiCameraKeywords.Should().Contain("Synology");
      CameraVerifier.AntiCameraKeywords.Should().Contain("QNAP");
    }

    [Fact]
    public void AntiCameraKeywords_ContainsPrinterKeywords()
    {
      CameraVerifier.AntiCameraKeywords.Should().Contain("HP Printer");
      CameraVerifier.AntiCameraKeywords.Should().Contain("Brother Printer");
    }

    [Fact]
    public void AntiCameraKeywords_ContainsServerKeywords()
    {
      CameraVerifier.AntiCameraKeywords.Should().Contain("Windows Server");
      CameraVerifier.AntiCameraKeywords.Should().Contain("IIS");
    }

    #endregion

    #region T2: VerificationResult 模型测试

    [Fact]
    public void VerificationResult_DefaultValues_AreCorrect()
    {
      var result = new VerificationResult();
      result.Ip.Should().BeEmpty();
      result.IsCamera.Should().BeFalse();
      result.Confidence.Should().Be(0);
      result.Vendor.Should().BeEmpty();
      result.Method.Should().BeEmpty();
      result.Evidence.Should().BeEmpty();
      result.OpenPorts.Should().NotBeNull().And.BeEmpty();
    }

    #endregion

    #region 综合测试：5 真 + 5 假 识别率

    [Fact]
    public void AntiCameraFilter_FiveFalsePositives_AllFiltered()
    {
      var falsePositives = new List<(string name, string body, string server)>
      {
        ("D-Link 路由器", "<html>D-Link</html>", ""),
        ("Synology NAS", "<html>Synology DiskStation</html>", ""),
        ("HP 打印机", "<html>HP Printer Web</html>", ""),
        ("IIS 服务器", "", "Microsoft-HTTPAPI/2.0"),
        ("MikroTik 路由器", "<html>MikroTik</html>", "RouterOS"),
      };

      int filtered = 0;
      foreach (var (name, body, server) in falsePositives)
      {
        if (CameraVerifier.IsLikelyNotCamera(body, server))
          filtered++;
      }

      filtered.Should().Be(5, "5 个非摄像头应全部被反例过滤（误报率 0%）");
    }

    [Fact]
    public void AntiCameraFilter_FiveTrueCameras_NoneFiltered()
    {
      var trueCameras = new List<(string name, string body, string server)>
      {
        ("海康威视", "<html>Hikvision-Webs ISAPI</html>", "App-webs/"),
        ("大华", "<html>Dahua WebSDK DH-IPC</html>", "Dahua Http Server"),
        ("宇视", "<html>Uniview IPC</html>", "Uniview Http Server"),
        ("TP-Link Tapo", "<html>TP-LINK IPC Tapo</html>", "TP-LINK HTTPD"),
        ("AXIS", "<html>AXIS VAPIX M10</html>", "AXIS"),
      };

      int wronglyFiltered = 0;
      foreach (var (name, body, server) in trueCameras)
      {
        if (CameraVerifier.IsLikelyNotCamera(body, server))
          wronglyFiltered++;
      }

      wronglyFiltered.Should().Be(0, "5 个真实摄像头不应被反例过滤（漏报率 0%）");
    }

    #endregion
  }
}