namespace NetSecurityScanner.Core.Models
{
    /// <summary>
    /// 专家模式扫描模式。
    /// </summary>
    public enum ScanProfile
    {
        /// <summary>
        /// 快速扫描：覆盖高频 Top 端口，耗时最短。
        /// </summary>
        Quick,

        /// <summary>
        /// 标准扫描：覆盖常见 Top 1000 端口，均衡速度与深度。
        /// </summary>
        Standard,

        /// <summary>
        /// 深度扫描：全端口扫描，启用 Ping 探测，耗时较长。
        /// </summary>
        Deep,

        /// <summary>
        /// 自定义扫描：用户可自由调整所有参数。
        /// </summary>
        Custom
    }
}
