using System;

namespace NetSecurityScanner.Models
{
    /// <summary>
    /// 远程更新信息模型
    /// </summary>
    public class UpdateInfo
    {
        /// <summary>
        /// 版本号（如 1.0.0.3）
        /// </summary>
        public string Version { get; set; } = string.Empty;

        /// <summary>
        /// 版本标签（如 v1.0.0.3）
        /// </summary>
        public string VersionTag { get; set; } = string.Empty;

        /// <summary>
        /// 发布日期
        /// </summary>
        public DateTime ReleaseDate { get; set; }

        /// <summary>
        /// 更新说明
        /// </summary>
        public string ReleaseNotes { get; set; } = string.Empty;

        /// <summary>
        /// 下载链接（已弃用，保留兼容）
        /// </summary>
        public string DownloadUrl { get; set; } = string.Empty;

        /// <summary>
        /// GitHub Release 页面链接
        /// </summary>
        public string HtmlUrl { get; set; } = string.Empty;

        /// <summary>
        /// 文件大小（字节）（已弃用，保留兼容）
        /// </summary>
        public long FileSize { get; set; }

        /// <summary>
        /// 资源文件名称（已弃用，保留兼容）
        /// </summary>
        public string AssetName { get; set; } = string.Empty;

        /// <summary>
        /// 是否为预发布版本
        /// </summary>
        public bool IsPrerelease { get; set; }

        /// <summary>
        /// 百度网盘下载链接
        /// </summary>
        public string BaiduDownloadUrl { get; set; } = string.Empty;

        /// <summary>
        /// 百度网盘提取码
        /// </summary>
        public string BaiduExtractionCode { get; set; } = string.Empty;
    }
}
