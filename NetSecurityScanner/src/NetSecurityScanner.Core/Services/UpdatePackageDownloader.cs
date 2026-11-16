using System;
using System.Diagnostics;

namespace NetSecurityScanner.Services
{
    public static class UpdatePackageDownloader
    {
        public const string DefaultDownloadUrl = "https://pan.baidu.com/s/17mhsewZVOwTs6c71H5Z-TA?pwd=7cw8";
        public const string DefaultExtractionCode = "7cw8";
        public const string DefaultGitHubReleaseUrl = "https://github.com/jinge5998/NetSecurityScanner/releases/latest";
        public const string FolderName = "NetSecurityScanner升级包";

        public static void OpenDownloadLink(string? url = null)
        {
            try
            {
                var downloadUrl = !string.IsNullOrEmpty(url) ? url : DefaultDownloadUrl;
                var psi = new ProcessStartInfo
                {
                    FileName = downloadUrl,
                    UseShellExecute = true
                };
                Process.Start(psi);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"打开下载链接失败: {ex.Message}");
            }
        }

        public static string GetDownloadGuideText(string? url = null, string? extractionCode = null)
        {
            var downloadUrl = !string.IsNullOrEmpty(url) ? url : DefaultDownloadUrl;
            var code = !string.IsNullOrEmpty(extractionCode) ? extractionCode : DefaultExtractionCode;
            return $@"===== 远程升级指南 =====

【推荐】GitHub 自动更新（主升级渠道）
1. 在应用内点击""检查更新"" → ""一键更新""
2. 程序将自动从 GitHub 下载并安装更新，完成后自动重启
3. 也可手动访问 GitHub Release 页面下载：
   {DefaultGitHubReleaseUrl}

【备用】百度网盘下载（辅助渠道，GitHub 无法访问时使用）
1. 打开百度网盘链接：
   {downloadUrl}

2. 输入提取码：{code}

3. 进入文件夹：{FolderName}

4. 下载最新的升级包文件

5. 关闭程序后，运行升级包中的安装程序完成升级

===== 注意事项 =====
- 升级前请备份重要数据
- 确保升级过程中网络连接稳定
- 如遇问题请联系技术支持
";
        }
    }
}
