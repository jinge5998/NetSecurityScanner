using System;

namespace NetSecurityScanner.Models
{
    /// <summary>
    /// 更新设置模型
    /// </summary>
    public class UpdateSettings
    {
        /// <summary>
        /// GitHub 仓库所有者
        /// </summary>
        public string GitHubOwner { get; set; } = "jinge5998";

        /// <summary>
        /// GitHub 仓库名称
        /// </summary>
        public string GitHubRepo { get; set; } = "NetSecurityScanner";

        /// <summary>
        /// 是否在启动时检查更新
        /// </summary>
        public bool CheckOnStartup { get; set; } = true;

        /// <summary>
        /// 上次检查更新时间
        /// </summary>
        public DateTime? LastCheckTime { get; set; }

        /// <summary>
        /// 已跳过的版本号
        /// </summary>
        public string SkippedVersion { get; set; } = string.Empty;

        /// <summary>
        /// 通知间隔（小时）
        /// </summary>
        public int NotifyIntervalHours { get; set; } = 24;
    }
}
