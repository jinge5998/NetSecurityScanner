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
        /// 端口扫描速率（端口/秒）
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
}