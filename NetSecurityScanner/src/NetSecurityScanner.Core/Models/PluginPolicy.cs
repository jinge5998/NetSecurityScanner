using System;
using System.Collections.Generic;

namespace NetSecurityScanner.Models
{
    /// <summary>
    /// 插件管控策略（v6 持久化到 data/PluginPolicy.json，v7 扩展）
    /// 包含：白名单、黑名单、权限矩阵、危险操作拦截规则、签名/沙箱/远程 API/SIEM 配置
    /// </summary>
    public class PluginPolicy
    {
        /// <summary>白名单（仅这些 pluginId 可加载；空数组 = 不限制）</summary>
        public List<string> Whitelist { get; set; } = new();

        /// <summary>黑名单（pluginId 出现在此列表一律拒绝）</summary>
        public List<string> Blacklist { get; set; } = new();

        /// <summary>权限矩阵：pluginId -> 允许的权限列表（空 = 全部允许）</summary>
        public Dictionary<string, List<string>> PermissionMatrix { get; set; } = new();

        /// <summary>危险操作拦截：opName -> 是否拦截（如 WriteRegistry/DeleteFile/StartProcess）</summary>
        public List<string> DangerousOpBlockList { get; set; } = new()
        {
            "WriteRegistry",
            "DeleteFile",
            "StartProcess"
        };

        /// <summary>策略最后修改时间</summary>
        public DateTime LastModified { get; set; } = DateTime.Now;

        /// <summary>最后修改人（当前登录用户）</summary>
        public string LastModifiedBy { get; set; } = "system";

        // ============== v7 扩展字段 ==============

        /// <summary>v7：是否强制要求签名校验（默认 true）</summary>
        public bool RequireSignature { get; set; } = true;

        /// <summary>v7：受信任公钥（PEM 格式，可以有多把）</summary>
        public List<string> TrustedPublicKeys { get; set; } = new();

        /// <summary>v7：沙箱策略（路径/网络/进程/注册表白名单）</summary>
        public SandboxPolicy Sandbox { get; set; } = new();

        /// <summary>v7：远程管控 API JWT 密钥（HS256；首次启动自动生成并保存）</summary>
        public string RemoteApiJwtSecret { get; set; } = string.Empty;

        /// <summary>v7：远程 API 绑定地址（默认 127.0.0.1）</summary>
        public string RemoteApiBindAddress { get; set; } = "127.0.0.1";

        /// <summary>v7：远程 API 监听端口（默认 9530）</summary>
        public int RemoteApiPort { get; set; } = 9530;

        /// <summary>v7：SIEM 上传配置</summary>
        public SiemConfig Siem { get; set; } = new();

        /// <summary>v7：调用链 Span 超时阈值（毫秒）</summary>
        public int TraceTimeoutMs { get; set; } = 30000;
    }
}
