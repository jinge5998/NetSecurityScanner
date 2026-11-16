using System;
using System.Collections.Generic;

namespace NetSecurityScanner.Models
{
    /// <summary>
    /// 扫描策略配置
    /// </summary>
    public class ScanPolicy
    {
        /// <summary>
        /// 策略名称
        /// </summary>
        public string Name { get; set; } = "默认策略";

        /// <summary>
        /// 策略描述
        /// </summary>
        public string Description { get; set; } = "默认扫描策略";

        /// <summary>
        /// 网络层扫描配置
        /// </summary>
        public NetworkScanConfig NetworkScanConfig { get; set; } = new NetworkScanConfig();

        /// <summary>
        /// Web应用扫描配置
        /// </summary>
        public WebScanConfig WebScanConfig { get; set; } = new WebScanConfig();

        /// <summary>
        /// 速率限制配置
        /// </summary>
        public RateLimitConfig RateLimitConfig { get; set; } = new RateLimitConfig();

        /// <summary>
        /// 超时配置
        /// </summary>
        public TimeoutConfig TimeoutConfig { get; set; } = new TimeoutConfig();

        /// <summary>
        /// 服务（banner）探测配置。为 null 时表示未显式配置，
        /// PortScanner 将沿用内置默认行为（1 次探测 / 600ms），
        /// 从而对主窗口等未传入该配置的调用方零回归。
        /// 仅专家模式通过 BuildScanPolicy 显式下发。
        /// </summary>
        [System.Text.Json.Serialization.JsonIgnore]
        public ServiceDetectionConfig ServiceDetectionConfig { get; set; }
    }

    /// <summary>
    /// 网络层扫描配置
    /// </summary>
    public class NetworkScanConfig
    {
        /// <summary>
        /// 是否启用TCP端口扫描
        /// </summary>
        public bool EnableTcpScan { get; set; } = true;

        /// <summary>
        /// 是否启用UDP端口扫描
        /// </summary>
        public bool EnableUdpScan { get; set; } = false;

        /// <summary>
        /// 要扫描的端口列表
        /// </summary>
        public List<int> Ports { get; set; } = new List<int> { 21, 22, 23, 25, 53, 80, 443, 1433, 3306, 3389, 5432, 6379, 8080, 8443 };

        /// <summary>
        /// 是否扫描所有端口
        /// </summary>
        public bool ScanAllPorts { get; set; } = false;

        /// <summary>
        /// 端口扫描超时时间（毫秒）
        /// </summary>
        public int PortTimeout { get; set; } = 1000;

        /// <summary>
        /// 是否启用漏洞验证
        /// </summary>
        public bool EnableVulnerabilityVerification { get; set; } = true;

        /// <summary>
        /// 小范围端口阈值
        /// </summary>
        public int SmallPortRangeThreshold { get; set; } = 20;
    }

    /// <summary>
    /// Web应用扫描配置
    /// </summary>
    public class WebScanConfig
    {
        /// <summary>
        /// 是否启用Web应用扫描
        /// </summary>
        public bool EnableWebScan { get; set; } = true;

        /// <summary>
        /// 是否扫描目录遍历漏洞
        /// </summary>
        public bool EnableDirectoryTraversal { get; set; } = true;

        /// <summary>
        /// 是否扫描SQL注入漏洞
        /// </summary>
        public bool EnableSqlInjection { get; set; } = true;

        /// <summary>
        /// 是否扫描XSS漏洞
        /// </summary>
        public bool EnableXss { get; set; } = true;

        /// <summary>
        /// 是否扫描命令注入漏洞
        /// </summary>
        public bool EnableCommandInjection { get; set; } = true;

        /// <summary>
        /// 是否扫描认证绕过漏洞
        /// </summary>
        public bool EnableAuthBypass { get; set; } = true;

        /// <summary>
        /// 是否扫描文件上传漏洞
        /// </summary>
        public bool EnableFileUpload { get; set; } = true;

        /// <summary>
        /// Web扫描深度
        /// </summary>
        public int ScanDepth { get; set; } = 2;

        /// <summary>
        /// 是否检查开放重定向
        /// </summary>
        public bool CheckForOpenRedirects { get; set; } = true;

        /// <summary>
        /// 是否检查XSS
        /// </summary>
        public bool CheckForXss { get; set; } = true;

        /// <summary>
        /// 是否检查SQL注入
        /// </summary>
        public bool CheckForSqlInjection { get; set; } = true;

        /// <summary>
        /// 是否检查目录遍历
        /// </summary>
        public bool CheckForDirectoryTraversal { get; set; } = true;

        /// <summary>
        /// 是否检查命令注入
        /// </summary>
        public bool CheckForCommandInjection { get; set; } = true;

        /// <summary>
        /// 是否检查CSRF
        /// </summary>
        public bool CheckForCsrf { get; set; } = true;

        /// <summary>
        /// 是否检查SSRF
        /// </summary>
        public bool CheckForSsrf { get; set; } = true;

        /// <summary>
        /// 是否检查不安全的Cookie
        /// </summary>
        public bool CheckForInsecureCookies { get; set; } = true;

        /// <summary>
        /// 是否检查缺失的安全头
        /// </summary>
        public bool CheckForMissingSecurityHeaders { get; set; } = true;

        /// <summary>
        /// 是否检查XXE
        /// </summary>
        public bool CheckForXxe { get; set; } = true;

        /// <summary>
        /// 是否检查文件上传漏洞
        /// </summary>
        public bool CheckForFileUpload { get; set; } = true;
    }

    /// <summary>
    /// 速率限制配置
    /// </summary>
    public class RateLimitConfig
    {
        /// <summary>
        /// 最大并发扫描数
        /// </summary>
        public int MaxConcurrentScans { get; set; } = Environment.ProcessorCount * 2;

        /// <summary>
        /// 是否启用端口扫描速率限制。
        ///
        /// 必须显式开启才会限流：PortScanRate 有默认値(100)，若直接以它为依据限流，
        /// 会把所有未显式配置的调用方（主窗口扫描、插件等）全部压到 100 端口/秒，
        /// 属于严重的静默性能回归。因此限流与否只看这个开关。
        /// </summary>
        public bool EnableRateLimit { get; set; } = false;

        /// <summary>
        /// 端口扫描速率（端口/秒）。仅当 EnableRateLimit 为 true 时生效。
        /// </summary>
        public int PortScanRate { get; set; } = 100;

        /// <summary>
        /// HTTP请求速率（请求/秒）
        /// </summary>
        public int HttpRequestRate { get; set; } = 20;

        /// <summary>
        /// 漏洞扫描速率（漏洞/秒）
        /// </summary>
        public int VulnerabilityScanRate { get; set; } = 10;

        /// <summary>
        /// 最大并发连接数
        /// </summary>
        public int MaxConcurrentConnections { get; set; } = 300;

        /// <summary>
        /// 最大UDP并发连接数
        /// </summary>
        public int UdpMaxConcurrentConnections { get; set; } = 150;
    }

    /// <summary>
    /// 超时配置
    /// </summary>
    public class TimeoutConfig
    {
        /// <summary>
        /// 扫描超时时间（分钟）
        /// </summary>
        public int ScanTimeout { get; set; } = 30;

        /// <summary>
        /// HTTP请求超时时间（秒）
        /// </summary>
        public int HttpRequestTimeout { get; set; } = 5;

        /// <summary>
        /// 数据库连接超时时间（秒）
        /// </summary>
        public int DatabaseTimeout { get; set; } = 10;

        /// <summary>
        /// 远程服务连接超时时间（秒）
        /// </summary>
        public int RemoteServiceTimeout { get; set; } = 5;

        /// <summary>
        /// TCP超时时间
        /// </summary>
        public int TcpTimeout { get; set; } = 500;

        /// <summary>
        /// UDP超时时间
        /// </summary>
        public int UdpTimeout { get; set; } = 1000;

        /// <summary>
        /// 小范围端口超时时间
        /// </summary>
        public int SmallPortRangeTimeout { get; set; } = 800;
    }

    /// <summary>
    /// 服务（banner）探测配置，映射专家模式的「服务检测强度」与「服务识别超时」。
    ///
    /// 这是专家模式 US-01 / US-04 的引擎侧载体：
    /// <list type="bullet">
    ///   <item><see cref="DetectTimeoutMs"/>：单次 banner 探测的 socket 读/写超时（毫秒），对应 ServiceDetectTimeout 滑块。</item>
    ///   <item><see cref="Tries"/>：banner 探测尝试次数，对应 ServiceIntensity 强度分级。</item>
    /// </list>
    /// 该映射是纯函数，可脱离 WPF 单测；强度越高 → 探测越深（更多尝试 + 更宽松单次超时）。
    /// 为 null 或 <see cref="Tries"/> 为 0 时，PortScanner 保持内置默认行为（1 次 / 600ms）。
    /// </summary>
    public class ServiceDetectionConfig
    {
        /// <summary>
        /// 是否启用服务探测。
        /// </summary>
        public bool Enabled { get; set; } = true;

        /// <summary>
        /// 单次 banner 探测超时（毫秒），>= 1 才生效。
        /// </summary>
        public int DetectTimeoutMs { get; set; } = 600;

        /// <summary>
        /// banner 探测尝试次数（2 次及以上为对慢速服务的深度探测）。0 表示跳过 banner。
        /// </summary>
        public int Tries { get; set; } = 1;

        /// <summary>
        /// 依据专家模式的开关、强度与用户超时，构造引擎侧探测配置（纯函数，供单测）。
        ///
        /// 强度→探测深度映射：
        /// <code>
        ///   intensity = 0 或 enabled = false -> Tries = 0（仅端口可达性，跳过 banner）
        ///   intensity 1-3                 -> Tries = 1（浅）
        ///   intensity 4-6                 -> Tries = 2（中）
        ///   intensity 7-9                 -> Tries = 3（深）
        /// </code>
        /// 单次超时随强度线性放宽（最多约 1.5×），换取慢速服务更可能被识别。
        /// </summary>
        /// <param name="enabled">ServiceDetection 复选（总开关）。</param>
        /// <param name="intensity">ServiceIntensity 取值，钳制到 [-1, 9]。</param>
        /// <param name="detectTimeoutMs">ServiceDetectTimeout 滑块值（毫秒），&lt;=0 回退到 600。</param>
        public static ServiceDetectionConfig FromIntensity(bool enabled, int intensity, int detectTimeoutMs)
        {
            // 钳制：默认模板可能小于 0（未选择界面）或大于可用的普通尝试
            var clamped = Math.Clamp(intensity, -1, 9);
            var detectEnabled = enabled && clamped >= 1;

            var tries = detectEnabled
                ? clamped switch
                {
                    >= 1 and <= 3 => 1,
                    >= 4 and <= 6 => 2,
                    _ => 3 // 7-9 深
                }
                : 0;

            // 强度越高，单次读取超时越宽松（9 => 约 1.5×），换取识别慢速服务
            var baseTimeout = detectTimeoutMs > 0 ? detectTimeoutMs : 600;
            var scaled = (int)Math.Round(baseTimeout * (1.0 + (clamped * 0.055)));

            return new ServiceDetectionConfig
            {
                Enabled = enabled,
                DetectTimeoutMs = Math.Max(1, scaled),
                Tries = tries
            };
        }
    }
}