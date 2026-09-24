using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Net.Http.Json;
using System.Text.Json;
using System.Threading.Tasks;
using NetSecurityScanner.Models;

namespace NetSecurityScanner.Services
{
    /// <summary>
    /// GitHub 远程更新检查服务
    /// </summary>
    public class UpdateCheckService : IDisposable
    {
        private readonly HttpClient _httpClient;
        private readonly JsonSerializerOptions _jsonOptions;
        private readonly string? _githubToken;
        private bool _disposed;

        /// <summary>
        /// GitHub API 地址模板
        /// </summary>
        private const string GitHubLatestReleaseUrl = "https://api.github.com/repos/{0}/{1}/releases/latest";

        public UpdateCheckService(string? githubToken = null)
        {
            _githubToken = githubToken;
            _httpClient = new HttpClient
            {
                Timeout = TimeSpan.FromSeconds(15)
            };

            _httpClient.DefaultRequestHeaders.Add("User-Agent", "NetSecurityScanner-UpdateChecker");
            _httpClient.DefaultRequestHeaders.Add("Accept", "application/vnd.github.v3+json");

            if (!string.IsNullOrEmpty(_githubToken))
            {
                _httpClient.DefaultRequestHeaders.Authorization =
                    new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", _githubToken);
            }

            _jsonOptions = new JsonSerializerOptions
            {
                PropertyNameCaseInsensitive = true
            };
        }

        /// <summary>
        /// 检查是否有新版本可用
        /// </summary>
        /// <param name="currentVersion">当前版本号</param>
        /// <param name="settings">更新设置</param>
        /// <returns>如果有更新返回 UpdateInfo，否则返回 null</returns>
        public async Task<UpdateInfo?> CheckForUpdateAsync(string currentVersion, UpdateSettings settings)
        {
            try
            {
                if (settings == null || string.IsNullOrWhiteSpace(settings.GitHubOwner) || string.IsNullOrWhiteSpace(settings.GitHubRepo))
                {
                    Console.WriteLine("更新设置无效，跳过检查");
                    return null;
                }

                var url = string.Format(GitHubLatestReleaseUrl, settings.GitHubOwner, settings.GitHubRepo);

                var response = await _httpClient.GetAsync(url);

                if (!response.IsSuccessStatusCode)
                {
                    if (response.StatusCode == System.Net.HttpStatusCode.Forbidden)
                    {
                        var retryAfter = response.Headers.RetryAfter;
                        if (retryAfter != null)
                        {
                            Console.WriteLine($"GitHub API 频率限制，请在 {retryAfter.Delta?.TotalSeconds ?? 60} 秒后重试");
                        }
                        else
                        {
                            Console.WriteLine("GitHub API 访问被拒绝，请检查网络或配置 GitHub Token");
                        }
                    }
                    else if (response.StatusCode == System.Net.HttpStatusCode.NotFound)
                    {
                        Console.WriteLine("未找到远程更新信息");
                    }
                    else
                    {
                        Console.WriteLine($"GitHub API 请求失败: {(int)response.StatusCode} {response.ReasonPhrase}");
                    }
                    return null;
                }

                var json = await response.Content.ReadAsStringAsync();
                var releaseData = JsonSerializer.Deserialize<GitHubReleaseResponse>(json, _jsonOptions);

                if (releaseData == null || string.IsNullOrWhiteSpace(releaseData.TagName))
                {
                    Console.WriteLine("解析远程更新信息失败");
                    return null;
                }

                var latestVersion = StripVersionPrefix(releaseData.TagName);
                var parsedLatestVersion = ParseVersion(latestVersion);
                var parsedCurrentVersion = ParseVersion(currentVersion);

                if (parsedLatestVersion == null || parsedCurrentVersion == null)
                {
                    Console.WriteLine("版本号解析失败，跳过更新检查");
                    return null;
                }

                if (parsedLatestVersion <= parsedCurrentVersion)
                {
                    Console.WriteLine($"当前已是最新版本 ({currentVersion})");
                    return null;
                }

                var updateInfo = new UpdateInfo
                {
                    Version = latestVersion,
                    VersionTag = releaseData.TagName,
                    ReleaseDate = releaseData.PublishedAt,
                    ReleaseNotes = releaseData.Body ?? string.Empty,
                    HtmlUrl = releaseData.HtmlUrl ?? string.Empty,
                    IsPrerelease = releaseData.Prerelease,
                    DownloadUrl = string.Empty,
                    AssetName = string.Empty,
                    FileSize = 0
                };

                foreach (var asset in releaseData.Assets)
                {
                    updateInfo.Assets.Add(new GitHubAssetInfo
                    {
                        Name = asset.Name,
                        BrowserDownloadUrl = asset.BrowserDownloadUrl,
                        Size = asset.Size,
                        ContentType = asset.ContentType
                    });
                }

                SelectWindowsAsset(updateInfo);

                ParseBaiduDownloadInfo(updateInfo);

                Console.WriteLine($"发现新版本: {latestVersion}");
                return updateInfo;
            }
            catch (HttpRequestException ex) when (ex.InnerException is System.Net.Sockets.SocketException)
            {
                Console.WriteLine($"网络连接失败，无法检查更新: {ex.Message}");
                return null;
            }
            catch (TaskCanceledException)
            {
                Console.WriteLine("检查更新超时，请检查网络连接");
                return null;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"检查更新时发生错误: {ex.Message}");
                return null;
            }
        }

        /// <summary>
        /// 移除版本号前缀（如 v1.0.0.3 -> 1.0.0.3）
        /// </summary>
        private static string StripVersionPrefix(string version)
        {
            if (string.IsNullOrWhiteSpace(version))
                return string.Empty;

            var cleaned = version.Trim();
            if (cleaned.StartsWith("v", StringComparison.OrdinalIgnoreCase))
            {
                cleaned = cleaned.Substring(1);
            }
            return cleaned;
        }

        /// <summary>
        /// 解析版本号为 Version 对象
        /// </summary>
        private static Version? ParseVersion(string versionString)
        {
            if (string.IsNullOrWhiteSpace(versionString))
                return null;

            if (Version.TryParse(versionString, out var version))
            {
                return version;
            }

            try
            {
                var parts = versionString.Split('.');
                if (parts.Length == 0)
                    return null;

                int major = 0, minor = 0, build = 0, revision = 0;

                if (parts.Length >= 1) int.TryParse(parts[0], out major);
                if (parts.Length >= 2) int.TryParse(parts[1], out minor);
                if (parts.Length >= 3) int.TryParse(parts[2], out build);
                if (parts.Length >= 4) int.TryParse(parts[3], out revision);

                return new Version(major, minor, build, revision);
            }
            catch
            {
                return null;
            }
        }

        private static void SelectWindowsAsset(UpdateInfo updateInfo)
        {
            if (updateInfo.Assets.Count == 0)
                return;

            var preferredPatterns = new[]
            {
                "NetSecurityScanner-Desktop",
                "NetSecurityScanner-Windows",
                "NetSecurityScanner-win",
                "NetSecurityScanner",
                "publish"
            };

            foreach (var pattern in preferredPatterns)
            {
                var asset = updateInfo.Assets.FirstOrDefault(a =>
                    a.Name.EndsWith(".zip", StringComparison.OrdinalIgnoreCase) &&
                    a.Name.Contains(pattern, StringComparison.OrdinalIgnoreCase) &&
                    !a.Name.Contains("Linux", StringComparison.OrdinalIgnoreCase) &&
                    !a.Name.Contains("linux", StringComparison.OrdinalIgnoreCase));

                if (asset != null)
                {
                    updateInfo.WindowsAssetDownloadUrl = asset.BrowserDownloadUrl;
                    updateInfo.WindowsAssetSize = asset.Size;
                    updateInfo.WindowsAssetName = asset.Name;
                    return;
                }
            }

            var fallbackAsset = updateInfo.Assets.FirstOrDefault(a =>
                a.Name.EndsWith(".zip", StringComparison.OrdinalIgnoreCase) &&
                !a.Name.Contains("Linux", StringComparison.OrdinalIgnoreCase) &&
                !a.Name.Contains("linux", StringComparison.OrdinalIgnoreCase));

            if (fallbackAsset != null)
            {
                updateInfo.WindowsAssetDownloadUrl = fallbackAsset.BrowserDownloadUrl;
                updateInfo.WindowsAssetSize = fallbackAsset.Size;
                updateInfo.WindowsAssetName = fallbackAsset.Name;
            }
        }

        private static void ParseBaiduDownloadInfo(UpdateInfo updateInfo)
        {
            if (string.IsNullOrEmpty(updateInfo.ReleaseNotes))
                return;

            var urlMatch = System.Text.RegularExpressions.Regex.Match(
                updateInfo.ReleaseNotes,
                @"https://pan\.baidu\.com/s/[^\s\)]+",
                System.Text.RegularExpressions.RegexOptions.IgnoreCase);
            if (urlMatch.Success)
            {
                updateInfo.BaiduDownloadUrl = urlMatch.Value;
                updateInfo.DownloadUrl = urlMatch.Value;
            }

            var codeMatch = System.Text.RegularExpressions.Regex.Match(
                updateInfo.ReleaseNotes,
                @"提取码[：:]\s*(\w{4})",
                System.Text.RegularExpressions.RegexOptions.IgnoreCase);
            if (codeMatch.Success && codeMatch.Groups.Count > 1)
            {
                updateInfo.BaiduExtractionCode = codeMatch.Groups[1].Value;
            }
        }

        public void Dispose()
        {
            if (!_disposed)
            {
                _httpClient?.Dispose();
                _disposed = true;
            }
        }
    }

    /// <summary>
    /// GitHub Release API 响应模型
    /// </summary>
    internal class GitHubReleaseResponse
    {
        public string Url { get; set; } = string.Empty;
        public string AssetsUrl { get; set; } = string.Empty;
        public string HtmlUrl { get; set; } = string.Empty;
        public int Id { get; set; }
        public string TagName { get; set; } = string.Empty;
        public string Name { get; set; } = string.Empty;
        public string Body { get; set; } = string.Empty;
        public bool Prerelease { get; set; }
        public DateTime CreatedAt { get; set; }
        public DateTime PublishedAt { get; set; }
        public List<GitHubAsset> Assets { get; set; } = new List<GitHubAsset>();
    }

    /// <summary>
    /// GitHub Release 资源文件模型
    /// </summary>
    internal class GitHubAsset
    {
        public string Url { get; set; } = string.Empty;
        public string BrowserDownloadUrl { get; set; } = string.Empty;
        public string Name { get; set; } = string.Empty;
        public string ContentType { get; set; } = string.Empty;
        public long Size { get; set; }
    }
}