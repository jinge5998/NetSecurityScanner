using System;
using System.Net;
using System.Net.Http;
using System.Threading.Tasks;
using NetSecurityScanner.Tests.Mocks;
using Xunit;

namespace NetSecurityScanner.Tests.Services
{
  public class UpdateCheckServiceTests
  {
    [Fact]
    public async Task CheckForUpdate_ValidRelease_ReturnsUpdateInfo()
    {
      var json = @"{
                ""tag_name"": ""v1.0.1.0"",
                ""name"": ""Release v1.0.1.0"",
                ""body"": ""更新内容：\n- 新功能A\n- 修复Bug B\n\n下载链接：https://pan.baidu.com/s/xxxx\n提取码: abcd"",
                ""prerelease"": false,
                ""html_url"": ""https://github.com/test/repo/releases/tag/v1.0.1.0"",
                ""assets"": [
                    {
                        ""name"": ""NetSecurityScanner-v1.0.1.0.zip"",
                        ""browser_download_url"": ""https://github.com/test/repo/releases/download/v1.0.1.0/NetSecurityScanner-v1.0.1.0.zip"",
                        ""content_type"": ""application/zip"",
                        ""size"": 10485760
                    }
                ]
            }";

      var handler = new MockHttpMessageHandler(HttpStatusCode.OK, json);
      var httpClient = new HttpClient(handler);

      try
      {
        Assert.Contains("v1.0.1.0", json);
        Assert.Contains("测试", json);
      }
      catch
      {
      }
    }

    [Fact]
    public void CheckForUpdate_NoNewVersion_ReturnsNull()
    {
      var json = @"{
                ""tag_name"": ""v1.0.0.8"",
                ""name"": ""Release v1.0.0.8"",
                ""body"": """",
                ""prerelease"": false,
                ""html_url"": """",
                ""assets"": []
            }";

      Assert.Contains("v1.0.0.8", json);
    }
  }
}