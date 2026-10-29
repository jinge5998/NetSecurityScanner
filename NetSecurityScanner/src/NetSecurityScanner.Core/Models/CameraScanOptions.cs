namespace NetSecurityScanner.Core.Models
{
    /// <summary>
    /// 摄像头安全扫描选项。
    /// </summary>
    public class CameraScanOptions
    {
        /// <summary>
        /// 手动指定的设备品牌（如 Hikvision/Dahua）。为 null 时自动指纹识别。
        /// 指定后跳过 HTTP 指纹品牌匹配，直接用于固件探测、PoC 与弱口令字典选择。
        /// </summary>
        public string? ForcedVendor { get; set; }

        /// <summary>
        /// 是否执行漏洞 PoC 验证检测（快速模式下关闭）。
        /// </summary>
        public bool EnablePoCDetection { get; set; } = true;

        /// <summary>
        /// 是否执行弱口令爆破检测。默认关闭；开启前应获得目标网络的书面授权。
        /// </summary>
        public bool EnableWeakPasswordScan { get; set; } = false;

        /// <summary>
        /// 快速扫描：端口 + 指纹 + 固件 + RTSP 认证检测，跳过 PoC 与弱口令。
        /// </summary>
        public static CameraScanOptions CreateQuick() => new()
        {
            EnablePoCDetection = false,
            EnableWeakPasswordScan = false
        };

        /// <summary>
        /// 完整扫描：包含 PoC 检测；弱口令仍由 EnableWeakPasswordScan 单独控制。
        /// </summary>
        public static CameraScanOptions CreateFull(bool enableWeakPassword = false) => new()
        {
            EnablePoCDetection = true,
            EnableWeakPasswordScan = enableWeakPassword
        };
    }
}
