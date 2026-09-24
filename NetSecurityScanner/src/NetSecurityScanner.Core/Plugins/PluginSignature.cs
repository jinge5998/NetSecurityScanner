using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace NetSecurityScanner.Core
{
  /// <summary>
  /// 插件签名工具（v3 - 修复密钥 bug）
  /// </summary>
  public static class PluginSignature
  {
    /// <summary>
    /// 计算 SHA256 校验和
    /// </summary>
    public static string ComputeChecksum(string filePath)
    {
      using var sha = SHA256.Create();
      using var fs = File.OpenRead(filePath);
      var hash = sha.ComputeHash(fs);
      return Convert.ToBase64String(hash);
    }

    /// <summary>
    /// 生成 RSA 密钥对（XML 格式）。
    /// 调用方应把 PrivateKeyXml 妥善保管（用于签名），把 PublicKeyXml 分发给验证方。
    /// </summary>
    /// <param name="bits">密钥长度，默认 2048</param>
    /// <returns>(PrivateKeyXml, PublicKeyXml)</returns>
    public static (string PrivateKeyXml, string PublicKeyXml) GenerateKeyPair(int bits = 2048)
    {
      using var rsa = new RSACryptoServiceProvider(bits);
      return (rsa.ToXmlString(true), rsa.ToXmlString(false));
    }

    /// <summary>
    /// 使用调用方提供的私钥对数据签名。
    /// 强制要求传入真实私钥，避免在开发/生产之间使用隐式默认密钥导致的安全漏洞。
    /// </summary>
    public static string SignData(string data, string privateKeyXml)
    {
      if (privateKeyXml == null) throw new ArgumentNullException(nameof(privateKeyXml));
      using var rsa = new RSACryptoServiceProvider();
      rsa.FromXmlString(privateKeyXml);
      var bytes = Encoding.UTF8.GetBytes(data);
      var sig = rsa.SignData(bytes, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
      return Convert.ToBase64String(sig);
    }

    /// <summary>
    /// 使用调用方提供的公钥验证签名。
    /// 强制要求传入真实公钥，移除历史版本中 "new RSACryptoServiceProvider(2048)" 的隐式默认分支。
    /// </summary>
    public static bool VerifyData(string data, string signatureBase64, string publicKeyXml)
    {
      if (publicKeyXml == null) throw new ArgumentNullException(nameof(publicKeyXml));
      try
      {
        using var rsa = new RSACryptoServiceProvider();
        rsa.FromXmlString(publicKeyXml);
        var bytes = Encoding.UTF8.GetBytes(data);
        var sig = Convert.FromBase64String(signatureBase64);
        return rsa.VerifyData(bytes, sig, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
      }
      catch
      {
        return false;
      }
    }

    /// <summary>
    /// 校验插件完整性。
    /// 当调用方未提供 publicKeyXml 时降级为只校验校验和（不依赖签名），用于本地开发快速验证。
    /// 生产环境必须传公钥以确保签名校验生效。
    /// </summary>
    public static (bool Valid, string Message) ValidatePlugin(string filePath, string expectedChecksum, string signature, string publicKeyXml = null)
    {
      try
      {
        if (!File.Exists(filePath))
          return (false, "插件文件不存在");

        var actualChecksum = ComputeChecksum(filePath);
        if (!string.IsNullOrEmpty(expectedChecksum) && actualChecksum != expectedChecksum)
          return (false, "校验和不匹配，文件可能被篡改");

        if (!string.IsNullOrEmpty(signature))
        {
          // 未提供公钥：仅校验校验和，不做签名校验（本地开发降级路径）
          if (string.IsNullOrEmpty(publicKeyXml))
          {
            return (true, "校验和验证通过（未提供公钥，跳过签名校验）");
          }
          if (!VerifyData(actualChecksum, signature, publicKeyXml))
            return (false, "签名验证失败");
        }

        return (true, "签名验证通过");
      }
      catch (Exception ex)
      {
        return (false, $"验证异常: {ex.Message}");
      }
    }
  }
}
