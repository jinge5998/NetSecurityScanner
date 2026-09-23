using System.Text.Json.Serialization;

namespace NetSecurityScanner.Models
{
    /// <summary>
    /// CNCERT/CC 国家互联网应急中心漏洞数据库同步配置
    /// </summary>
    public class CncertSettings
    {
        /// <summary>
        /// 是否启用 CNCERT 自动同步
        /// </summary>
        [JsonPropertyName("enableAutoSync")]
        public bool EnableAutoSync { get; set; } = true;

        /// <summary>
        /// CNCERT 数据源地址
        /// 主源：https://www.cert.org.cn
        /// </summary>
        [JsonPropertyName("baseUrl")]
        public string BaseUrl { get; set; } = "https://www.cert.org.cn";

        /// <summary>
        /// CNCERT 漏洞库 API 端点
        /// </summary>
        [JsonPropertyName("vulnerabilityApiUrl")]
        public string VulnerabilityApiUrl { get; set; } = "https://www.cert.org.cn/api/vulnerability";

        /// <summary>
        /// CNCERT API 访问密钥
        /// </summary>
        [JsonPropertyName("apiKey")]
        public string ApiKey { get; set; } = string.Empty;

        /// <summary>
        /// CNCERT 机构标识
        /// </summary>
        [JsonPropertyName("organizationId")]
        public string OrganizationId { get; set; } = "NetSecurityScanner";

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
        /// 是否启用备用数据源（NVD）
        /// 当 CNCERT 不可达时自动切换
        /// </summary>
        [JsonPropertyName("enableFallbackToNvd")]
        public bool EnableFallbackToNvd { get; set; } = true;

        /// <summary>
        /// 是否使用系统代理
        /// </summary>
        [JsonPropertyName("useSystemProxy")]
        public bool UseSystemProxy { get; set; } = false;

        /// <summary>
        /// 同步起始页
        /// </summary>
        [JsonPropertyName("startPage")]
        public int StartPage { get; set; } = 1;

        /// <summary>
        /// 单次请求最大数据条数
        /// </summary>
        [JsonPropertyName("pageSize")]
        public int PageSize { get; set; } = 100;

        /// <summary>
        /// 是否包含高危事件通报
        /// </summary>
        [JsonPropertyName("includeHighRiskAdvisory")]
        public bool IncludeHighRiskAdvisory { get; set; } = true;

        /// <summary>
        /// 是否包含一般漏洞预警
        /// </summary>
        [JsonPropertyName("includeVulnerabilityAlert")]
        public bool IncludeVulnerabilityAlert { get; set; } = true;
    }
}
