using System;
using System.IO;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Threading.Tasks;
using NetSecurityScanner.Core.Models;
using NetSecurityScanner.Utils;

namespace NetSecurityScanner.Core.Services
{
    /// <summary>
    /// 负责专家模式扫描配置的持久化读写。
    /// 配置文件位于 <see cref="DataPaths.DataRoot"/> 下的 scan_profile.json。
    /// </summary>
    public class ScanProfileManager
    {
        private static readonly JsonSerializerOptions JsonOptions = new()
        {
            PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
            WriteIndented = true,
            DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
            Converters = { new JsonStringEnumConverter(JsonNamingPolicy.CamelCase) }
        };

        /// <summary>
        /// 配置文件完整路径。
        /// </summary>
        public static string ConfigFilePath => Path.Combine(DataPaths.DataRoot, "scan_profile.json");

        /// <summary>
        /// 从磁盘读取最后一次使用的扫描配置；若文件不存在则返回 Standard 默认配置。
        /// </summary>
        public ScanProfileConfig LoadConfig()
        {
            var path = ConfigFilePath;
            if (!File.Exists(path))
            {
                return ScanProfileConfigFactory.GetDefault(ScanProfile.Standard);
            }

            try
            {
                var json = File.ReadAllText(path);
                var config = JsonSerializer.Deserialize<ScanProfileConfig>(json, JsonOptions);
                if (config == null)
                {
                    return ScanProfileConfigFactory.GetDefault(ScanProfile.Standard);
                }

                config.Normalize();
                return config;
            }
            catch (Exception)
            {
                // 读取失败时回退到默认配置，避免应用无法启动。
                return ScanProfileConfigFactory.GetDefault(ScanProfile.Standard);
            }
        }

        /// <summary>
        /// 异步从磁盘读取最后一次使用的扫描配置。
        /// </summary>
        public async Task<ScanProfileConfig> LoadConfigAsync()
        {
            var path = ConfigFilePath;
            if (!File.Exists(path))
            {
                return ScanProfileConfigFactory.GetDefault(ScanProfile.Standard);
            }

            try
            {
                using var stream = File.OpenRead(path);
                var config = await JsonSerializer.DeserializeAsync<ScanProfileConfig>(stream, JsonOptions).ConfigureAwait(false);
                if (config == null)
                {
                    return ScanProfileConfigFactory.GetDefault(ScanProfile.Standard);
                }

                config.Normalize();
                return config;
            }
            catch (Exception)
            {
                return ScanProfileConfigFactory.GetDefault(ScanProfile.Standard);
            }
        }

        /// <summary>
        /// 将扫描配置保存到磁盘。
        /// </summary>
        public void SaveConfig(ScanProfileConfig config)
        {
            if (config == null)
            {
                throw new ArgumentNullException(nameof(config));
            }

            config.Normalize();

            var path = ConfigFilePath;
            var directory = Path.GetDirectoryName(path);
            if (!string.IsNullOrWhiteSpace(directory) && !Directory.Exists(directory))
            {
                Directory.CreateDirectory(directory);
            }

            var json = JsonSerializer.Serialize(config, JsonOptions);
            File.WriteAllText(path, json);
        }

        /// <summary>
        /// 异步将扫描配置保存到磁盘。
        /// </summary>
        public async Task SaveConfigAsync(ScanProfileConfig config)
        {
            if (config == null)
            {
                throw new ArgumentNullException(nameof(config));
            }

            config.Normalize();

            var path = ConfigFilePath;
            var directory = Path.GetDirectoryName(path);
            if (!string.IsNullOrWhiteSpace(directory) && !Directory.Exists(directory))
            {
                Directory.CreateDirectory(directory);
            }

            using var stream = new FileStream(path, FileMode.Create, FileAccess.Write, FileShare.None);
            await JsonSerializer.SerializeAsync(stream, config, JsonOptions).ConfigureAwait(false);
        }
    }
}
