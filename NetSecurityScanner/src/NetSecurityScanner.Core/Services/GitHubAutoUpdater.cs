using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Net.Http;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;

namespace NetSecurityScanner.Services
{
    public class AutoUpdateProgressEventArgs : EventArgs
    {
        public string Message { get; }
        public int ProgressPercent { get; }
        public bool IsError { get; }
        public string? ErrorMessage { get; }

        public AutoUpdateProgressEventArgs(string message, int progressPercent, bool isError = false, string? errorMessage = null)
        {
            Message = message;
            ProgressPercent = progressPercent;
            IsError = isError;
            ErrorMessage = errorMessage;
        }
    }

    public class GitHubAutoUpdater : IDisposable
    {
        private readonly HttpClient _httpClient;
        private readonly string _appBaseDir;
        private readonly string _updateTempDir;
        private readonly string _backupDir;
        private bool _disposed;

        public event EventHandler<AutoUpdateProgressEventArgs>? ProgressChanged;

        public GitHubAutoUpdater()
        {
            _httpClient = new HttpClient
            {
                Timeout = TimeSpan.FromMinutes(10)
            };
            _httpClient.DefaultRequestHeaders.Add("User-Agent", "NetSecurityScanner-AutoUpdater");

            _appBaseDir = AppDomain.CurrentDomain.BaseDirectory;
            _updateTempDir = Path.Combine(Path.GetTempPath(), "NetSecurityScanner_Update");
            _backupDir = Path.Combine(Path.GetTempPath(), "NetSecurityScanner_Backup");
        }

        public async Task<bool> DownloadAndInstallAsync(
            string downloadUrl,
            string assetName,
            IProgress<(string Message, int Percent)>? progress = null,
            CancellationToken cancellationToken = default)
        {
            try
            {
                ReportProgress("准备更新环境...", 0, progress);

                CleanDirectory(_updateTempDir);
                CleanDirectory(_backupDir);
                Directory.CreateDirectory(_updateTempDir);
                Directory.CreateDirectory(_backupDir);

                var zipPath = Path.Combine(_updateTempDir, assetName);

                ReportProgress("正在从 GitHub 下载更新包...", 5, progress);
                var downloadSuccess = await DownloadFileAsync(downloadUrl, zipPath, progress, cancellationToken);
                if (!downloadSuccess)
                {
                    ReportProgress("下载失败", 0, progress, isError: true, errorMessage: "无法从 GitHub 下载更新包");
                    return false;
                }

                ReportProgress("下载完成，正在验证文件...", 60, progress);
                if (!File.Exists(zipPath) || new FileInfo(zipPath).Length == 0)
                {
                    ReportProgress("文件验证失败", 0, progress, isError: true, errorMessage: "下载的文件无效");
                    return false;
                }

                ReportProgress("正在解压更新包...", 65, progress);
                var extractDir = Path.Combine(_updateTempDir, "extracted");
                Directory.CreateDirectory(extractDir);
                ZipFile.ExtractToDirectory(zipPath, extractDir, overwriteFiles: true);

                ReportProgress("正在备份当前版本...", 75, progress);
                BackupCurrentVersion();

                ReportProgress("正在应用更新...", 80, progress);
                var updateSourceDir = FindUpdateSourceDirectory(extractDir);
                if (updateSourceDir == null)
                {
                    ReportProgress("更新包结构无效", 0, progress, isError: true, errorMessage: "无法在更新包中找到应用程序文件");
                    return false;
                }

                ApplyUpdate(updateSourceDir, progress);

                ReportProgress("更新完成！正在准备重启...", 95, progress);

                ReportProgress("更新成功，即将重启应用...", 100, progress);
                return true;
            }
            catch (OperationCanceledException)
            {
                ReportProgress("更新已取消", 0, progress, isError: true, errorMessage: "用户取消了更新");
                return false;
            }
            catch (Exception ex)
            {
                ReportProgress($"更新失败: {ex.Message}", 0, progress, isError: true, errorMessage: ex.Message);
                try
                {
                    Rollback();
                    ReportProgress("已回滚到更新前版本", 0, progress);
                }
                catch (Exception rollbackEx)
                {
                    ReportProgress($"回滚失败: {rollbackEx.Message}", 0, progress, isError: true, errorMessage: rollbackEx.Message);
                }
                return false;
            }
        }

        public async Task<bool> UpdateDataFilesOnlyAsync(
            string downloadUrl,
            string assetName,
            IProgress<(string Message, int Percent)>? progress = null,
            CancellationToken cancellationToken = default)
        {
            try
            {
                ReportProgress("准备更新数据文件...", 0, progress);
                CleanDirectory(_updateTempDir);
                Directory.CreateDirectory(_updateTempDir);

                var zipPath = Path.Combine(_updateTempDir, assetName);

                ReportProgress("正在从 GitHub 下载...", 10, progress);
                var downloadSuccess = await DownloadFileAsync(downloadUrl, zipPath, progress, cancellationToken);
                if (!downloadSuccess) return false;

                ReportProgress("正在解压...", 60, progress);
                var extractDir = Path.Combine(_updateTempDir, "extracted");
                Directory.CreateDirectory(extractDir);
                ZipFile.ExtractToDirectory(zipPath, extractDir, overwriteFiles: true);

                ReportProgress("正在更新数据文件...", 70, progress);
                var updateSourceDir = FindUpdateSourceDirectory(extractDir);
                if (updateSourceDir == null) return false;

                var dataDir = Path.Combine(updateSourceDir, "Data");
                var localDataDir = Path.Combine(_appBaseDir, "Data");

                if (Directory.Exists(dataDir))
                {
                    if (!Directory.Exists(localDataDir))
                        Directory.CreateDirectory(localDataDir);

                    foreach (var file in Directory.GetFiles(dataDir, "*.json", SearchOption.AllDirectories))
                    {
                        var relativePath = file.Substring(dataDir.Length).TrimStart(Path.DirectorySeparatorChar);
                        var targetPath = Path.Combine(localDataDir, relativePath);
                        var targetDir = Path.GetDirectoryName(targetPath);
                        if (!string.IsNullOrEmpty(targetDir) && !Directory.Exists(targetDir))
                            Directory.CreateDirectory(targetDir);
                        File.Copy(file, targetPath, overwrite: true);
                    }

                    ReportProgress("数据文件更新完成", 100, progress);
                    return true;
                }

                ReportProgress("更新包中未找到 Data 目录", 0, progress, isError: true);
                return false;
            }
            catch (Exception ex)
            {
                ReportProgress($"数据文件更新失败: {ex.Message}", 0, progress, isError: true, errorMessage: ex.Message);
                return false;
            }
        }

        public void RestartApplication()
        {
            try
            {
                var exePath = Process.GetCurrentProcess().MainModule?.FileName;
                if (string.IsNullOrEmpty(exePath)) return;

                var startInfo = new ProcessStartInfo
                {
                    FileName = exePath,
                    UseShellExecute = false
                };

                Process.Start(startInfo);
                Process.GetCurrentProcess().Kill();
            }
            catch (Exception ex)
            {
                Console.WriteLine($"重启应用失败: {ex.Message}");
            }
        }

        public void ScheduleRestart(int delaySeconds = 3)
        {
            var exePath = Process.GetCurrentProcess().MainModule?.FileName;
            if (string.IsNullOrEmpty(exePath)) return;

            var script = $@"@echo off
timeout /t {delaySeconds} /nobreak >nul
start "" ""{exePath}""
del ""%~f0""
";
            var scriptPath = Path.Combine(Path.GetTempPath(), "NetSecurityScanner_Restart.bat");
            File.WriteAllText(scriptPath, script);

            Process.Start(new ProcessStartInfo
            {
                FileName = "cmd.exe",
                Arguments = $"/c \"{scriptPath}\"",
                CreateNoWindow = true,
                UseShellExecute = false
            });

            Process.GetCurrentProcess().Kill();
        }

        public bool Rollback()
        {
            try
            {
                if (!Directory.Exists(_backupDir)) return false;

                var backupFiles = Directory.GetFiles(_backupDir, "*", SearchOption.AllDirectories);
                foreach (var backupFile in backupFiles)
                {
                    var relativePath = backupFile.Substring(_backupDir.Length).TrimStart(Path.DirectorySeparatorChar);
                    var targetPath = Path.Combine(_appBaseDir, relativePath);

                    var targetDir = Path.GetDirectoryName(targetPath);
                    if (!string.IsNullOrEmpty(targetDir) && !Directory.Exists(targetDir))
                        Directory.CreateDirectory(targetDir);

                    File.Copy(backupFile, targetPath, overwrite: true);
                }

                Console.WriteLine("回滚成功");
                return true;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"回滚失败: {ex.Message}");
                return false;
            }
        }

        public void Cleanup()
        {
            try
            {
                if (Directory.Exists(_updateTempDir))
                    Directory.Delete(_updateTempDir, recursive: true);
            }
            catch { }

            try
            {
                if (Directory.Exists(_backupDir))
                    Directory.Delete(_backupDir, recursive: true);
            }
            catch { }
        }

        private async Task<bool> DownloadFileAsync(
            string url,
            string targetPath,
            IProgress<(string Message, int Percent)>? progress,
            CancellationToken cancellationToken)
        {
            const int maxRetries = 3;
            const int retryDelayMs = 2000;

            for (int attempt = 1; attempt <= maxRetries; attempt++)
            {
                try
                {
                    ReportProgress($"正在下载... (尝试 {attempt}/{maxRetries})", 5, progress);

                    using var response = await _httpClient.GetAsync(url, HttpCompletionOption.ResponseHeadersRead, cancellationToken);
                    response.EnsureSuccessStatusCode();

                    var totalBytes = response.Content.Headers.ContentLength ?? -1;
                    var bytesRead = 0L;
                    var buffer = new byte[81920];

                    await using var contentStream = await response.Content.ReadAsStreamAsync(cancellationToken);
                    await using var fileStream = new FileStream(targetPath, FileMode.Create, FileAccess.Write, FileShare.None);

                    int read;
                    while ((read = await contentStream.ReadAsync(buffer, cancellationToken)) > 0)
                    {
                        await fileStream.WriteAsync(buffer.AsMemory(0, read), cancellationToken);
                        bytesRead += read;

                        if (totalBytes > 0)
                        {
                            var percent = (int)(5 + (bytesRead * 55.0 / totalBytes));
                            ReportProgress($"正在下载... {FormatBytes(bytesRead)}/{FormatBytes(totalBytes)}", percent, progress);
                        }
                        else
                        {
                            var percent = (int)(5 + Math.Min(bytesRead / 1024.0 / 1024.0 / 50.0 * 55.0, 55.0));
                            ReportProgress($"正在下载... {FormatBytes(bytesRead)}", percent, progress);
                        }
                    }

                    if (totalBytes > 0 && bytesRead != totalBytes)
                    {
                        throw new IOException($"下载不完整：期望 {totalBytes} 字节，实际 {bytesRead} 字节");
                    }

                    return true;
                }
                catch (HttpRequestException ex) when (attempt < maxRetries)
                {
                    ReportProgress($"网络错误，{retryDelayMs / 1000} 秒后重试... ({ex.Message})", 5, progress);
                    await Task.Delay(retryDelayMs * attempt, cancellationToken);
                }
                catch (IOException ex) when (attempt < maxRetries)
                {
                    ReportProgress($"IO 错误，{retryDelayMs / 1000} 秒后重试... ({ex.Message})", 5, progress);
                    await Task.Delay(retryDelayMs * attempt, cancellationToken);
                }
            }

            Console.WriteLine($"下载失败：已重试 {maxRetries} 次仍无法完成");
            return false;
        }

        private void BackupCurrentVersion()
        {
            var criticalFiles = new[]
            {
                "NetSecurityScanner.Desktop.exe",
                "NetSecurityScanner.Core.dll",
                "NetSecurityScanner.Desktop.dll"
            };

            foreach (var file in Directory.GetFiles(_appBaseDir))
            {
                try
                {
                    var fileName = Path.GetFileName(file);
                    if (fileName.EndsWith(".dll", StringComparison.OrdinalIgnoreCase) ||
                        fileName.EndsWith(".exe", StringComparison.OrdinalIgnoreCase) ||
                        criticalFiles.Contains(fileName, StringComparer.OrdinalIgnoreCase))
                    {
                        var targetPath = Path.Combine(_backupDir, fileName);
                        File.Copy(file, targetPath, overwrite: true);
                    }
                }
                catch { }
            }

            var dataDir = Path.Combine(_appBaseDir, "Data");
            if (Directory.Exists(dataDir))
            {
                var backupDataDir = Path.Combine(_backupDir, "Data");
                Directory.CreateDirectory(backupDataDir);
                foreach (var file in Directory.GetFiles(dataDir, "*.json"))
                {
                    try
                    {
                        File.Copy(file, Path.Combine(backupDataDir, Path.GetFileName(file)), overwrite: true);
                    }
                    catch { }
                }
            }
        }

        private string? FindUpdateSourceDirectory(string extractDir)
        {
            var exeName = "NetSecurityScanner.Desktop.exe";

            if (Directory.GetFiles(extractDir, exeName).Length > 0)
                return extractDir;

            foreach (var dir in Directory.GetDirectories(extractDir))
            {
                if (Directory.GetFiles(dir, exeName).Length > 0)
                    return dir;

                foreach (var subDir in Directory.GetDirectories(dir))
                {
                    if (Directory.GetFiles(subDir, exeName).Length > 0)
                        return subDir;
                }
            }

            foreach (var dir in Directory.GetDirectories(extractDir))
            {
                if (Directory.GetFiles(dir, "*.dll").Length > 5)
                    return dir;
            }

            return null;
        }

        private void ApplyUpdate(string sourceDir, IProgress<(string Message, int Percent)>? progress)
        {
            var excludeDirs = new[] { "logs", "Logs", "backups", "Backups" };
            var excludeFiles = new[] { "appsettings.json", "user-settings.json" };

            foreach (var file in Directory.GetFiles(sourceDir, "*", SearchOption.AllDirectories))
            {
                var relativePath = file.Substring(sourceDir.Length).TrimStart(Path.DirectorySeparatorChar);
                var segments = relativePath.Split(Path.DirectorySeparatorChar);

                if (segments.Any(s => excludeDirs.Contains(s, StringComparer.OrdinalIgnoreCase)))
                    continue;

                if (excludeFiles.Contains(Path.GetFileName(file)))
                    continue;

                var targetPath = Path.Combine(_appBaseDir, relativePath);
                var targetDir = Path.GetDirectoryName(targetPath);
                if (!string.IsNullOrEmpty(targetDir) && !Directory.Exists(targetDir))
                    Directory.CreateDirectory(targetDir);

                try
                {
                    File.Copy(file, targetPath, overwrite: true);
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"无法更新文件 {relativePath}: {ex.Message}");
                }
            }
        }

        private void ReportProgress(string message, int percent, IProgress<(string, int)>? progress = null,
            bool isError = false, string? errorMessage = null)
        {
            progress?.Report((message, percent));
            ProgressChanged?.Invoke(this, new AutoUpdateProgressEventArgs(message, percent, isError, errorMessage));
        }

        private static string FormatBytes(long bytes)
        {
            string[] units = { "B", "KB", "MB", "GB" };
            var unitIndex = 0;
            double size = bytes;
            while (size >= 1024 && unitIndex < units.Length - 1)
            {
                size /= 1024;
                unitIndex++;
            }
            return $"{size:F1} {units[unitIndex]}";
        }

        private static void CleanDirectory(string path)
        {
            if (!Directory.Exists(path)) return;
            try
            {
                Directory.Delete(path, recursive: true);
            }
            catch
            {
                foreach (var file in Directory.GetFiles(path, "*", SearchOption.AllDirectories))
                {
                    try { File.Delete(file); } catch { }
                }
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
}