using System;
using System.ComponentModel.DataAnnotations;
using System.Text.Json.Serialization;

namespace NetSecurityScanner.Core.Models
{
    /// <summary>
    /// 专家模式扫描配置模型，包含扫描模式、端口范围、并发、超时等高级参数。
    /// </summary>
    public class ScanProfileConfig
    {
        /// <summary>
        /// 当前扫描模式。
        /// </summary>
        [JsonConverter(typeof(JsonStringEnumConverter))]
        public ScanProfile Profile { get; set; } = ScanProfile.Standard;

        /// <summary>
        /// 端口范围，例如 "1-1000" 或 "80,443,22"。
        /// </summary>
        public string PortRange { get; set; } = "1-1000";

        /// <summary>
        /// TCP 并发数，范围 1-1000。
        /// </summary>
        [Range(1, 1000)]
        public int TcpConcurrency { get; set; } = 50;

        /// <summary>
        /// UDP 并发数，范围 1-1000。
        /// </summary>
        [Range(1, 1000)]
        public int UdpConcurrency { get; set; } = 20;

        /// <summary>
        /// 单次探测超时时间（毫秒），范围 50-5000。
        /// </summary>
        [Range(50, 5000)]
        public int TimeoutMs { get; set; } = 300;

        /// <summary>
        /// 重试次数，范围 0-5。
        /// </summary>
        [Range(0, 5)]
        public int RetryCount { get; set; } = 1;

        /// <summary>
        /// 是否启用 Ping 探测。
        /// </summary>
        public bool EnablePingProbe { get; set; } = false;

        /// <summary>
        /// 是否启用服务检测。
        /// </summary>
        public bool EnableServiceDetection { get; set; } = true;

        /// <summary>
        /// 创建当前配置的浅表副本。
        /// </summary>
        public ScanProfileConfig Clone()
        {
            return (ScanProfileConfig)MemberwiseClone();
        }

        /// <summary>
        /// 将各项参数规范化到有效范围内，避免 UI 输入或反序列化得到非法值。
        /// </summary>
        public void Normalize()
        {
            TcpConcurrency = Math.Clamp(TcpConcurrency, 1, 1000);
            UdpConcurrency = Math.Clamp(UdpConcurrency, 1, 1000);
            TimeoutMs = Math.Clamp(TimeoutMs, 50, 5000);
            RetryCount = Math.Clamp(RetryCount, 0, 5);

            if (string.IsNullOrWhiteSpace(PortRange))
            {
                PortRange = "1-1000";
            }
        }
    }

    /// <summary>
    /// 扫描配置预设工厂，提供四种扫描模式的均衡默认参数。
    /// </summary>
    public static class ScanProfileConfigFactory
    {
        /// <summary>
        /// 获取指定扫描模式的默认配置。
        /// </summary>
        public static ScanProfileConfig GetDefault(ScanProfile profile)
        {
            return profile switch
            {
                ScanProfile.Quick => CreateQuick(),
                ScanProfile.Standard => CreateStandard(),
                ScanProfile.Deep => CreateDeep(),
                ScanProfile.Custom => CreateCustom(),
                _ => CreateStandard()
            };
        }

        /// <summary>
        /// 快速扫描：Top 100 端口，超时 100ms，TCP 并发 100，UDP 并发 50。
        /// </summary>
        public static ScanProfileConfig CreateQuick()
        {
            return new ScanProfileConfig
            {
                Profile = ScanProfile.Quick,
                PortRange = "1-100",
                TimeoutMs = 100,
                TcpConcurrency = 100,
                UdpConcurrency = 50,
                RetryCount = 0,
                EnablePingProbe = false,
                EnableServiceDetection = true
            };
        }

        /// <summary>
        /// 标准扫描：Top 1000 端口，超时 300ms，TCP 并发 50，UDP 并发 20。
        /// </summary>
        public static ScanProfileConfig CreateStandard()
        {
            return new ScanProfileConfig
            {
                Profile = ScanProfile.Standard,
                PortRange = "1-1000",
                TimeoutMs = 300,
                TcpConcurrency = 50,
                UdpConcurrency = 20,
                RetryCount = 1,
                EnablePingProbe = false,
                EnableServiceDetection = true
            };
        }

        /// <summary>
        /// 深度扫描：全端口 1-65535，超时 500ms，TCP 并发 30，UDP 并发 10，启用 Ping 探测。
        /// </summary>
        public static ScanProfileConfig CreateDeep()
        {
            return new ScanProfileConfig
            {
                Profile = ScanProfile.Deep,
                PortRange = "1-65535",
                TimeoutMs = 500,
                TcpConcurrency = 30,
                UdpConcurrency = 10,
                RetryCount = 1,
                EnablePingProbe = true,
                EnableServiceDetection = true
            };
        }

        /// <summary>
        /// 自定义扫描：初始参数与 Standard 相同，允许用户后续修改。
        /// </summary>
        public static ScanProfileConfig CreateCustom()
        {
            var config = CreateStandard();
            config.Profile = ScanProfile.Custom;
            return config;
        }
    }
}
