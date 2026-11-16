using System.Collections.Generic;

namespace NetSecurityScanner.Models
{
    /// <summary>
    /// 插件沙箱策略（v7）。
    /// 限制插件对文件系统 / 网络 / 进程 / 注册表的访问。
    /// </summary>
    public class SandboxPolicy
    {
        /// <summary>是否启用沙箱（默认 true）</summary>
        public bool Enabled { get; set; } = true;

        /// <summary>宽松模式：违规仅记录不阻断（仅调试用）</summary>
        public bool PermissiveMode { get; set; } = false;

        /// <summary>允许的目录白名单（绝对路径前缀匹配，区分大小写不敏感）</summary>
        public List<string> AllowedPaths { get; set; } = new();

        /// <summary>允许的网络出口域名白名单（如 "*.trusted.com"）</summary>
        public List<string> AllowedNetworkTargets { get; set; } = new();

        /// <summary>允许启动的进程名白名单（如 "mspaint", "notepad"）</summary>
        public List<string> AllowedProcessNames { get; set; } = new();

        /// <summary>允许的注册表根键白名单（如 "HKEY_CURRENT_USER\\Software\\Safe"）</summary>
        public List<string> AllowedRegistryKeys { get; set; } = new();
    }
}
