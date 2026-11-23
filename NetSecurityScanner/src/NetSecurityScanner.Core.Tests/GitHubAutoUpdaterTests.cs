using System;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using NetSecurityScanner.Services;
using Xunit;

namespace NetSecurityScanner.Core.Tests;

public sealed class GitHubAutoUpdaterTests : IDisposable
{
    private readonly string _root;
    private readonly string _appDir;
    private readonly string _updateTempDir;

    public GitHubAutoUpdaterTests()
    {
        _root = Path.Combine(Path.GetTempPath(), "NetSecurityScanner_UpdateTests_" + Guid.NewGuid().ToString("N"));
        _appDir = Path.Combine(_root, "app");
        _updateTempDir = Path.Combine(_root, "download");
        Directory.CreateDirectory(_appDir);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("invalid")]
    public async Task DownloadAndInstallAsync_RejectsMissingOrInvalidSha256BeforeDownload(string? expectedSha256)
    {
        WriteAppFile("NetSecurityScanner.Desktop.exe", "old-version");
        var handler = new ByteArrayResponseHandler(CreateZip(("NetSecurityScanner.Desktop.exe", "new-version")));
        using var updater = CreateUpdater(handler);

        var success = await updater.DownloadAndInstallAsync(
            "https://updates.test/app.zip",
            "app.zip",
            expectedSha256);

        Assert.False(success);
        Assert.Equal(0, handler.RequestCount);
        Assert.Equal("old-version", ReadAppFile("NetSecurityScanner.Desktop.exe"));
    }

    [Fact]
    public async Task DownloadAndInstallAsync_RejectsMismatchedSha256WithoutChangingInstallation()
    {
        WriteAppFile("NetSecurityScanner.Desktop.exe", "old-version");
        var handler = new ByteArrayResponseHandler(CreateZip(("NetSecurityScanner.Desktop.exe", "new-version")));
        using var updater = CreateUpdater(handler);

        var success = await updater.DownloadAndInstallAsync(
            "https://updates.test/app.zip",
            "app.zip",
            new string('0', 64));

        Assert.False(success);
        Assert.Equal(1, handler.RequestCount);
        Assert.Equal("old-version", ReadAppFile("NetSecurityScanner.Desktop.exe"));
        Assert.False(Directory.Exists(Path.Combine(_appDir, ".backup")));
    }

    [Fact]
    public async Task DownloadAndInstallAsync_BacksUpAndRollsBackAllEngineFiles()
    {
        WriteAppFile("NetSecurityScanner.Desktop.exe", "old-version");
        WriteAppFile("tools/nmap/scripts/http-title.nse", "old-nse");
        WriteAppFile("tools/nmap/nmap-services", "old-service-data");
        WriteAppFile("user-settings.json", "user-config");
        var package = CreateZip(
            ("NetSecurityScanner.Desktop.exe", "new-version"),
            ("tools/nmap/scripts/http-title.nse", "new-nse"),
            ("tools/nmap/nmap-services", "new-service-data"),
            ("user-settings.json", "package-config"));
        var handler = new ByteArrayResponseHandler(package);
        using var updater = CreateUpdater(handler);

        var success = await updater.DownloadAndInstallAsync(
            "https://updates.test/app.zip",
            "app.zip",
            Sha256(package));

        Assert.True(success);
        Assert.Equal("new-version", ReadAppFile("NetSecurityScanner.Desktop.exe"));
        Assert.Equal("new-nse", ReadAppFile("tools/nmap/scripts/http-title.nse"));
        Assert.Equal("new-service-data", ReadAppFile("tools/nmap/nmap-services"));
        Assert.Equal("user-config", ReadAppFile("user-settings.json"));

        var backupDir = Assert.Single(Directory.GetDirectories(Path.Combine(_appDir, ".backup")));
        Assert.Equal("old-version", File.ReadAllText(Path.Combine(backupDir, "NetSecurityScanner.Desktop.exe")));
        Assert.Equal("old-nse", File.ReadAllText(Path.Combine(backupDir, "tools/nmap/scripts/http-title.nse")));
        Assert.Equal("old-service-data", File.ReadAllText(Path.Combine(backupDir, "tools/nmap/nmap-services")));

        Assert.True(updater.Rollback());
        Assert.Equal("old-version", ReadAppFile("NetSecurityScanner.Desktop.exe"));
        Assert.Equal("old-nse", ReadAppFile("tools/nmap/scripts/http-title.nse"));
        Assert.Equal("old-service-data", ReadAppFile("tools/nmap/nmap-services"));
        Assert.Equal("user-config", ReadAppFile("user-settings.json"));
    }

    [Fact]
    public void GetDownloadCandidates_DoesNotIncludeUnreachableMirror()
    {
        const string original = "https://github.com/owner/repo/releases/download/v1/app.zip";
        using var updater = CreateUpdater(new ByteArrayResponseHandler(Array.Empty<byte>()));

        var candidates = updater.GetDownloadCandidates(original).ToArray();

        Assert.Equal(original, candidates[0]);
        Assert.Contains("https://gh-proxy.com/" + original, candidates);
        Assert.Contains("https://ghfast.top/" + original, candidates);
        Assert.DoesNotContain(candidates, candidate => candidate.Contains("mirror.ghproxy.com"));
    }

    private GitHubAutoUpdater CreateUpdater(HttpMessageHandler handler)
    {
        return new GitHubAutoUpdater(_appDir, _updateTempDir, new HttpClient(handler));
    }

    private void WriteAppFile(string relativePath, string content)
    {
        var path = Path.Combine(_appDir, relativePath);
        Directory.CreateDirectory(Path.GetDirectoryName(path)!);
        File.WriteAllText(path, content, Encoding.UTF8);
    }

    private string ReadAppFile(string relativePath)
    {
        return File.ReadAllText(Path.Combine(_appDir, relativePath), Encoding.UTF8);
    }

    private static byte[] CreateZip(params (string Name, string Content)[] entries)
    {
        using var stream = new MemoryStream();
        using (var archive = new ZipArchive(stream, ZipArchiveMode.Create, leaveOpen: true))
        {
            foreach (var entry in entries)
            {
                var zipEntry = archive.CreateEntry(entry.Name);
                using var writer = new StreamWriter(zipEntry.Open(), Encoding.UTF8);
                writer.Write(entry.Content);
            }
        }
        return stream.ToArray();
    }

    private static string Sha256(byte[] content)
    {
        return Convert.ToHexString(SHA256.HashData(content)).ToLowerInvariant();
    }

    public void Dispose()
    {
        if (Directory.Exists(_root))
            Directory.Delete(_root, recursive: true);
    }

    private sealed class ByteArrayResponseHandler : HttpMessageHandler
    {
        private readonly byte[] _content;
        public int RequestCount { get; private set; }

        public ByteArrayResponseHandler(byte[] content) => _content = content;

        protected override Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request,
            CancellationToken cancellationToken)
        {
            RequestCount++;
            var body = new ByteArrayContent(_content);
            body.Headers.ContentLength = _content.Length;
            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK) { Content = body });
        }
    }
}
