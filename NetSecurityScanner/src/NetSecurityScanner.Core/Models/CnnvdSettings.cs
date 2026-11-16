using System.Text.Json.Serialization;

namespace NetSecurityScanner.Models
{
    /// <summary>
    /// CNNVD 国家漏洞数据库同步配置
    /// </summary>
    public class CnnvdSettings
    {
        /// <summary>
        /// 是否启用 CNNVD 自动同步
        /// </summary>
        [JsonPropertyName("enableAutoSync")]
        public bool EnableAutoSync { get; set; } = true;

        /// <summary>
        /// CNNVD 数据源地址
        /// </summary>
        [JsonPropertyName("baseUrl")]
        public string BaseUrl { get; set; } = "http://www.cnnvd.org.cn";

        /// <summary>
        /// CNNVD API 访问密钥
        /// </summary>
        [JsonPropertyName("apiKey")]
        public string ApiKey { get; set; } = string.Empty;

        /// <summary>
        /// 同步间隔（天）
        /// </summary>
        [JsonPropertyName("syncIntervalDays")]
        public int SyncIntervalDays { get; set; } = 7;

        /// <summary>
        /// 本地缓存有效期（天）
        /// </summary>
        [JsonPropertyName("cacheExpiryDays")]
        public int CacheExpiryDays { get; set; } = 7;

        /// <summary>
        /// 单次请求超时（秒）
        /// </summary>
        [JsonPropertyName("requestTimeoutSeconds")]
        public int RequestTimeoutSeconds { get; set; } = 30;

        /// <summary>
        /// 是否使用系统代理
        /// </summary>
        [JsonPropertyName("useSystemProxy")]
        public bool UseSystemProxy { get; set; } = false;
    }
}
