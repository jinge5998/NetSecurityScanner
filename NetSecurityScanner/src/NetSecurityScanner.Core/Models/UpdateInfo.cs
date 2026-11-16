using System;
using System.Collections.Generic;

namespace NetSecurityScanner.Models
{
    public class UpdateInfo
    {
        public string Version { get; set; } = string.Empty;

        public string VersionTag { get; set; } = string.Empty;

        public DateTime ReleaseDate { get; set; }

        public string ReleaseNotes { get; set; } = string.Empty;

        public string DownloadUrl { get; set; } = string.Empty;

        public string HtmlUrl { get; set; } = string.Empty;

        public long FileSize { get; set; }

        public string AssetName { get; set; } = string.Empty;

        public bool IsPrerelease { get; set; }

        public string BaiduDownloadUrl { get; set; } = string.Empty;

        public string BaiduExtractionCode { get; set; } = string.Empty;

        public List<GitHubAssetInfo> Assets { get; set; } = new();

        public string? WindowsAssetDownloadUrl { get; set; }

        public long WindowsAssetSize { get; set; }

        public string? WindowsAssetName { get; set; }
    }

    public class GitHubAssetInfo
    {
        public string Name { get; set; } = string.Empty;
        public string BrowserDownloadUrl { get; set; } = string.Empty;
        public long Size { get; set; }
        public string ContentType { get; set; } = string.Empty;
    }
}