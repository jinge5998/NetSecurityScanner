using System;
using System.Diagnostics;
using System.IO;
using System.Text.Json;
using NetSecurityScanner.Core.Models;

namespace NetSecurityScanner.Core.Services
{
    /// <summary>
    /// 批量扫描配置持久化：%LOCALAPPDATA%\NetSecurityScanner\batch_scan_settings.json。
    /// 读写失败一律静默降级（返回默认值/跳过保存），不影响扫描主流程。
    /// </summary>
    public class BatchScanSettingsService
    {
        private static readonly string SettingsPath = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "NetSecurityScanner", "batch_scan_settings.json");

        private static readonly JsonSerializerOptions JsonOptions = new()
        {
            WriteIndented = true,
            Encoder = System.Text.Encodings.Web.JavaScriptEncoder.UnsafeRelaxedJsonEscaping
        };

        public BatchScanSettings Load()
        {
            try
            {
                if (!File.Exists(SettingsPath)) return new BatchScanSettings();
                var json = File.ReadAllText(SettingsPath);
                return JsonSerializer.Deserialize<BatchScanSettings>(json) ?? new BatchScanSettings();
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"[BatchScanSettingsService] 读取配置失败: {ex.Message}");
                return new BatchScanSettings();
            }
        }

        public void Save(BatchScanSettings settings)
        {
            try
            {
                Directory.CreateDirectory(Path.GetDirectoryName(SettingsPath)!);
                File.WriteAllText(SettingsPath, JsonSerializer.Serialize(settings, JsonOptions));
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"[BatchScanSettingsService] 保存配置失败: {ex.Message}");
            }
        }
    }
}
