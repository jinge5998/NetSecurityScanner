using System.Net;
using System.Net.Http;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using NetSecurityScanner.Models;
using NetSecurityScanner.Services;
using Xunit;

namespace NetSecurityScanner.Core.Tests;

public class UpdateCheckServiceTests
{
    [Fact]
    public async Task CheckForUpdateAsync_MapsSelectedWindowsAssetSha256()
    {
        var sha256 = new string('a', 64);
        var json = @"{
          ""tag_name"": ""v1.0.3.23"",
          ""html_url"": ""https://github.com/owner/repo/releases/tag/v1.0.3.23"",
          ""body"": ""test release"",
          ""prerelease"": false,
          ""published_at"": ""2026-11-24T00:00:00Z"",
          ""assets"": [
            {
              ""name"": ""NetSecurityScanner-v1.0.3.23-win-x64.zip"",
              ""browser_download_url"": ""https://github.com/owner/repo/releases/download/v1.0.3.23/NetSecurityScanner-v1.0.3.23-win-x64.zip"",
              ""content_type"": ""application/zip"",
              ""size"": 12345,
              ""digest"": ""sha256:__SHA256__""
            }
          ]
        }".Replace("__SHA256__", sha256);
        using var service = new UpdateCheckService(new HttpClient(new JsonResponseHandler(json)));

        var update = await service.CheckForUpdateAsync("1.0.3.22", new UpdateSettings
        {
            GitHubOwner = "owner",
            GitHubRepo = "repo"
        });

        Assert.NotNull(update);
        Assert.Equal(sha256, update!.WindowsAssetSha256);
        Assert.Equal($"sha256:{sha256}", update.Assets[0].Digest);
    }

    private sealed class JsonResponseHandler : HttpMessageHandler
    {
        private readonly string _json;

        public JsonResponseHandler(string json) => _json = json;

        protected override Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request,
            CancellationToken cancellationToken)
        {
            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent(_json, Encoding.UTF8, "application/json")
            });
        }
    }
}
