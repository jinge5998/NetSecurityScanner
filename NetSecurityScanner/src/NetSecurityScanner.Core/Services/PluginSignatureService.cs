using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using NetSecurityScanner.Models;

namespace NetSecurityScanner.Services
{
    /// <summary>
    /// 插件签名校验服务（v7-T2）。
    /// 职责：
    ///   1. 加载 DLL 同目录 .sig 文件（base64 编码的 RSA-SHA256 签名）
    ///   2. 用 PluginPolicy.TrustedPublicKeys 中的公钥验签
    ///   3. 验签失败抛 PluginSignatureException
    ///   4. 提供 SignAsync 工具方法（开发期用）
    /// </summary>
    public class PluginSignatureService
    {
        private readonly PluginSecurityService _security;
        private readonly object _keyCacheLock = new();
        private readonly Dictionary<string, RSA> _keyCache = new();

        public PluginSignatureService(PluginSecurityService security)
        {
            _security = security;
        }

        /// <summary>
        /// 验证 DLL 签名。如 RequireSignature=false 则跳过校验（但仍写审计）。
        /// </summary>
        public async Task<PluginSignature> VerifyAsync(string pluginId, string dllPath)
        {
            var result = new PluginSignature
            {
                PluginId = pluginId,
                DllPath = dllPath,
                SignaturePath = GetSignaturePath(dllPath)
            };

            try
            {
                if (!File.Exists(dllPath))
                {
                    result.Status = SignatureStatus.Missing;
                    result.ErrorDetail = $"DLL 文件不存在: {dllPath}";
                    return result;
                }

                // 计算 DLL SHA-256
                result.DllSha256 = await ComputeSha256Async(dllPath).ConfigureAwait(false);

                var policy = _security.CurrentPolicy;
                if (!policy.RequireSignature)
                {
                    result.Status = SignatureStatus.Disabled;
                    return result;
                }

                if (!File.Exists(result.SignaturePath))
                {
                    result.Status = SignatureStatus.Missing;
                    result.ErrorDetail = ".sig 文件不存在";
                    return result;
                }

                result.SignatureBase64 = (await File.ReadAllTextAsync(result.SignaturePath).ConfigureAwait(false)).Trim();
                byte[] signature;
                try
                {
                    signature = Convert.FromBase64String(result.SignatureBase64);
                }
                catch (FormatException ex)
                {
                    result.Status = SignatureStatus.Invalid;
                    result.ErrorDetail = $"签名 base64 解码失败: {ex.Message}";
                    return result;
                }

                var dllBytes = await File.ReadAllBytesAsync(dllPath).ConfigureAwait(false);

                // 遍历白名单公钥，找到能验签通过的
                foreach (var pem in policy.TrustedPublicKeys)
                {
                    if (string.IsNullOrWhiteSpace(pem)) continue;
                    try
                    {
                        var rsa = GetOrLoadKey(pem);
                        if (rsa == null) continue;

                        if (rsa.VerifyHash(result.DllSha256.HexToBytes(), signature, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1))
                        {
                            result.Status = SignatureStatus.Ok;
                            result.SignerFingerprint = ComputeFingerprint(pem);
                            return result;
                        }
                    }
                    catch
                    {
                        // 单把公钥失败不影响其他
                    }
                }

                result.Status = SignatureStatus.Invalid;
                result.ErrorDetail = "无任何受信任公钥可验证签名";
                return result;
            }
            catch (Exception ex)
            {
                result.Status = SignatureStatus.Invalid;
                result.ErrorDetail = $"签名校验异常: {ex.Message}";
                return result;
            }
        }

        /// <summary>
        /// 生成签名（开发期/发布期用）。生产期由发布者用私钥签。
        /// </summary>
        public static async Task SignAsync(string dllPath, string privateKeyPem)
        {
            if (!File.Exists(dllPath)) throw new FileNotFoundException("DLL not found", dllPath);
            using var rsa = RSA.Create();
            rsa.ImportFromPem(privateKeyPem);
            var bytes = await File.ReadAllBytesAsync(dllPath).ConfigureAwait(false);
            var sha = SHA256.HashData(bytes);
            var sig = rsa.SignHash(sha, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            var sigPath = GetSignaturePath(dllPath);
            await File.WriteAllTextAsync(sigPath, Convert.ToBase64String(sig)).ConfigureAwait(false);
        }

        private RSA? GetOrLoadKey(string pem)
        {
            lock (_keyCacheLock)
            {
                if (_keyCache.TryGetValue(pem, out var cached)) return cached;
                try
                {
                    var rsa = RSA.Create();
                    rsa.ImportFromPem(pem);
                    _keyCache[pem] = rsa;
                    return rsa;
                }
                catch
                {
                    return null;
                }
            }
        }

        private static string GetSignaturePath(string dllPath)
        {
            return Path.ChangeExtension(dllPath, ".sig");
        }

        private static async Task<string> ComputeSha256Async(string path)
        {
            using var sha = SHA256.Create();
            await using var fs = File.OpenRead(path);
            var hash = await sha.ComputeHashAsync(fs).ConfigureAwait(false);
            return Convert.ToHexString(hash);
        }

        private static string ComputeFingerprint(string pem)
        {
            using var sha = SHA256.Create();
            var hash = sha.ComputeHash(Encoding.UTF8.GetBytes(pem));
            return Convert.ToHexString(hash, 0, 8);
        }
    }

    internal static class HexExtensions
    {
        public static byte[] HexToBytes(this string hex)
        {
            if (string.IsNullOrEmpty(hex)) return Array.Empty<byte>();
            hex = hex.Replace("-", "").Replace(" ", "");
            if (hex.Length % 2 != 0) hex = "0" + hex;
            var bytes = new byte[hex.Length / 2];
            for (int i = 0; i < bytes.Length; i++)
            {
                bytes[i] = Convert.ToByte(hex.Substring(i * 2, 2), 16);
            }
            return bytes;
        }
    }
}
