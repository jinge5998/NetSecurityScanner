using System;
using System.Collections.Generic;
using System.Linq;
using NetSecurityScanner.Core;
using Xunit;

namespace NetSecurityScanner.Tests.Services
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
      Assert.True(result, "D-Link 路由器应被反例过滤");
    }

    [Fact]
    public void IsLikelyNotCamera_SynologyNAS_ReturnsTrue()
    {
      var result = CameraVerifier.IsLikelyNotCamera(
        "<html>Synology DiskStation</html>", "");
      Assert.True(result, "Synology NAS 应被反例过滤");
    }

    [Fact]
    public void IsLikelyNotCamera_QNAPNAS_ReturnsTrue()
    {
      var result = CameraVerifier.IsLikelyNotCamera(
        "<html>QNAP</html>", "");
      Assert.True(result, "QNAP NAS 应被反例过滤");
    }

    [Fact]
    public void IsLikelyNotCamera_HPPrinter_ReturnsTrue()
    {
      var result = CameraVerifier.IsLikelyNotCamera(
        "<html>HP Printer</html>", "");
      Assert.True(result, "HP 打印机应被反例过滤");
    }

    [Fact]
    public void IsLikelyNotCamera_MikroTikRouter_ReturnsTrue()
    {
      var result = CameraVerifier.IsLikelyNotCamera(
        "", "MikroTik RouterOS");
      Assert.True(result, "MikroTik 路由器应被反例过滤");
    }

    [Fact]
    public void IsLikelyNotCamera_IIS_ReturnsTrue()
    {
      var result = CameraVerifier.IsLikelyNotCamera(
        "", "Microsoft-IIS/10.0");
      Assert.True(result, "IIS 服务器应被反例过滤");
    }

    [Fact]
    public void IsLikelyNotCamera_OpenWrt_ReturnsTrue()
    {
      var result = CameraVerifier.IsLikelyNotCamera(
        "<html>OpenWrt</html>", "");
      Assert.True(result, "OpenWrt 路由器应被反例过滤");
    }

    [Fact]
    public void IsLikelyNotCamera_HikvisionPage_ReturnsFalse()
    {
      var result = CameraVerifier.IsLikelyNotCamera(
        "<html><title>Hikvision-Webs</title></html>", "");
      Assert.False(result, "海康威视页面不应被反例过滤");
    }

    [Fact]
    public void IsLikelyNotCamera_DahuaPage_ReturnsFalse()
    {
      var result = CameraVerifier.IsLikelyNotCamera(
        "<html>Dahua WebSDK</html>", "");
      Assert.False(result, "大华页面不应被反例过滤");
    }

    [Fact]
    public void IsLikelyNotCamera_EmptyInput_ReturnsFalse()
    {
      var result = CameraVerifier.IsLikelyNotCamera("", "");
      Assert.False(result, "空输入不应被反例过滤");
    }

    #endregion

    #region T4: 厂商端口表测试

    [Fact]
    public void VendorPorts_ContainsHikvision()
    {
      Assert.True(CameraVerifier.VendorPorts.ContainsKey("Hikvision"));
      Assert.Contains(8000, CameraVerifier.VendorPorts["Hikvision"]);
    }

    [Fact]
    public void VendorPorts_ContainsDahua()
    {
      Assert.True(CameraVerifier.VendorPorts.ContainsKey("Dahua"));
      Assert.Contains(37777, CameraVerifier.VendorPorts["Dahua"]);
    }

    [Fact]
    public void VendorPorts_ContainsUniview()
    {
      Assert.True(CameraVerifier.VendorPorts.ContainsKey("Uniview"));
      Assert.Contains(34567, CameraVerifier.VendorPorts["Uniview"]);
    }

    [Fact]
    public void VendorPorts_ContainsTiandy()
    {
      Assert.True(CameraVerifier.VendorPorts.ContainsKey("Tiandy"));
      Assert.Contains(6036, CameraVerifier.VendorPorts["Tiandy"]);
    }

    [Fact]
    public void VendorPorts_ContainsEZVIZ()
    {
      Assert.True(CameraVerifier.VendorPorts.ContainsKey("EZVIZ"));
      Assert.Contains(8001, CameraVerifier.VendorPorts["EZVIZ"]);
    }

    [Fact]
    public void VendorPorts_HasAtLeast10Vendors()
    {
      Assert.True(CameraVerifier.VendorPorts.Count >= 10, "至少 10 个厂商");
    }

    [Fact]
    public void DefaultScanPorts_ContainsCommonPorts()
    {
      Assert.Contains(80, CameraVerifier.DefaultScanPorts);
      Assert.Contains(554, CameraVerifier.DefaultScanPorts);
      Assert.Contains(8000, CameraVerifier.DefaultScanPorts);
      Assert.Contains(37777, CameraVerifier.DefaultScanPorts);
    }

    #endregion

    #region T3: 反例关键词完整性测试

    [Fact]
    public void AntiCameraKeywords_ContainsRouterKeywords()
    {
      Assert.Contains("D-Link", CameraVerifier.AntiCameraKeywords);
      Assert.Contains("TP-LINK Router", CameraVerifier.AntiCameraKeywords);
      Assert.Contains("MikroTik", CameraVerifier.AntiCameraKeywords);
      Assert.Contains("OpenWrt", CameraVerifier.AntiCameraKeywords);
      Assert.Contains("iStoreOS", CameraVerifier.AntiCameraKeywords);
    }

    [Fact]
    public void AntiCameraKeywords_ContainsNASKeywords()
    {
      Assert.Contains("Synology", CameraVerifier.AntiCameraKeywords);
      Assert.Contains("QNAP", CameraVerifier.AntiCameraKeywords);
    }

    [Fact]
    public void AntiCameraKeywords_ContainsPrinterKeywords()
    {
      Assert.Contains("HP Printer", CameraVerifier.AntiCameraKeywords);
      Assert.Contains("Brother Printer", CameraVerifier.AntiCameraKeywords);
    }

    [Fact]
    public void AntiCameraKeywords_ContainsServerKeywords()
    {
      Assert.Contains("Windows Server", CameraVerifier.AntiCameraKeywords);
      Assert.Contains("IIS", CameraVerifier.AntiCameraKeywords);
    }

    #endregion

    #region T2: VerificationResult 模型测试

    [Fact]
    public void VerificationResult_DefaultValues_AreCorrect()
    {
      var result = new VerificationResult();
      Assert.Equal(string.Empty, result.Ip);
      Assert.False(result.IsCamera);
      Assert.Equal(0, result.Confidence);
      Assert.Empty(result.OpenPorts);
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

      Assert.Equal(5, filtered);
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

      Assert.Equal(0, wronglyFiltered);
    }

    #endregion
  }
}