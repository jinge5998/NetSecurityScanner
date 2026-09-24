using System;
using System.Collections.Generic;

namespace NetSecurityScanner.Models
{
    /// <summary>
    /// 插件签名记录（v7）。
    /// .sig 文件保存的格式：base64(RSA-SHA256(DLL字节))。
    /// 加载 DLL 时读取同目录 .sig 文件，并用 PluginPolicy.TrustedPublicKeys 中的公钥验签。
    /// </summary>
    public class PluginSignature
    {
        /// <summary>插件 Id（与 Plugin.Id 对应）</summary>
        public string PluginId { get; set; } = string.Empty;

        /// <summary>对应 DLL 文件路径</summary>
        public string DllPath { get; set; } = string.Empty;

        /// <summary>.sig 文件路径（与 DLL 同目录，扩展名为 .sig）</summary>
        public string SignaturePath { get; set; } = string.Empty;

        /// <summary>base64 编码的签名</summary>
        public string SignatureBase64 { get; set; } = string.Empty;

        /// <summary>签名人 / 公钥指纹（SHA-256 of public key, hex first 16 bytes）</summary>
        public string SignerFingerprint { get; set; } = string.Empty;

        /// <summary>DLL 的 SHA-256 指纹（hex 字符串）</summary>
        public string DllSha256 { get; set; } = string.Empty;

        /// <summary>签名时间</summary>
        public DateTime SignedAt { get; set; } = DateTime.Now;

        /// <summary>验签状态：None / Ok / Invalid / Missing / Disabled</summary>
        public SignatureStatus Status { get; set; } = SignatureStatus.None;

        /// <summary>验签失败原因（仅在 Status != Ok 时填充）</summary>
        public string? ErrorDetail { get; set; }
    }

    public enum SignatureStatus
    {
        None,
        Ok,
        Invalid,
        Missing,
        Disabled
    }
}
