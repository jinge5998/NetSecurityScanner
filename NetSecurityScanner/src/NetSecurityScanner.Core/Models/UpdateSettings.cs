using System;

namespace NetSecurityScanner.Models
{
    public class UpdateSettings
    {
        public string GitHubOwner { get; set; } = "jinge5998";

        public string GitHubRepo { get; set; } = "NetSecurityScanner";

        public bool CheckOnStartup { get; set; } = true;

        public DateTime? LastCheckTime { get; set; }

        public string SkippedVersion { get; set; } = string.Empty;

        public int NotifyIntervalHours { get; set; } = 24;

        public bool AutoUpdateEnabled { get; set; } = true;

        public bool AutoUpdateDataFiles { get; set; } = true;

        public string UpdateChannel { get; set; } = "release";

        public bool? CheckPrerelease { get; set; } = null;

        /// <summary>
        /// 下载镜像代理前缀（E2E 测试发现 github.com:443 在部分网络环境被阻断，
        /// asset 下载需要经镜像加速）。为空时仅尝试原始 URL；
        /// 配置后（如 "https://gh-proxy.com/"）会先尝试镜像、失败再回退原始 URL。
        /// 内置镜像候选始终参与回退（见 GitHubAutoUpdater.BuiltInMirrorPrefixes）。
        /// </summary>
        public string DownloadProxyPrefix { get; set; } = string.Empty;
    }
}