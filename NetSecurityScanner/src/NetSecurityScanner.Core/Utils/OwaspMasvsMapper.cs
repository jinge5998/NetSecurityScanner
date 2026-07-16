using System;
using System.Collections.Generic;
using NetSecurityScanner.Models;

namespace NetSecurityScanner.Utils
{
  public enum MasvsCategory
  {
    MASVS_STORAGE,
    MASVS_CRYPTO,
    MASVS_AUTH,
    MASVS_NETWORK,
    MASVS_PLATFORM,
    MASVS_CODE,
    MASVS_RESILIENCE
  }

  public class MasvsMapping
  {
    public MasvsCategory Category { get; set; }
    public string CategoryId { get; set; } = string.Empty;
    public string Name { get; set; } = string.Empty;
    public string Description { get; set; } = string.Empty;
    public string VerificationLevel { get; set; } = "L1";
  }

  public static class OwaspMasvsMapper
  {
    private static readonly Dictionary<MasvsCategory, MasvsMapping> CategoryMap = new()
    {
      [MasvsCategory.MASVS_STORAGE] = new MasvsMapping
      {
        Category = MasvsCategory.MASVS_STORAGE,
        CategoryId = "MASVS-STORAGE",
        Name = "V2: 数据存储与隐私",
        Description = "用户数据、凭据和加密密钥的存储安全"
      },
      [MasvsCategory.MASVS_CRYPTO] = new MasvsMapping
      {
        Category = MasvsCategory.MASVS_CRYPTO,
        CategoryId = "MASVS-CRYPTO",
        Name = "V3: 密码学",
        Description = "加密算法的正确使用和密钥管理"
      },
      [MasvsCategory.MASVS_AUTH] = new MasvsMapping
      {
        Category = MasvsCategory.MASVS_AUTH,
        CategoryId = "MASVS-AUTH",
        Name = "V4: 认证与会话管理",
        Description = "用户认证、会话管理和生物识别安全"
      },
      [MasvsCategory.MASVS_NETWORK] = new MasvsMapping
      {
        Category = MasvsCategory.MASVS_NETWORK,
        CategoryId = "MASVS-NETWORK",
        Name = "V5: 网络通信",
        Description = "TLS配置、证书验证和网络安全"
      },
      [MasvsCategory.MASVS_PLATFORM] = new MasvsMapping
      {
        Category = MasvsCategory.MASVS_PLATFORM,
        CategoryId = "MASVS-PLATFORM",
        Name = "V6: 平台交互",
        Description = "WebView、IPC和权限管理安全"
      },
      [MasvsCategory.MASVS_CODE] = new MasvsMapping
      {
        Category = MasvsCategory.MASVS_CODE,
        CategoryId = "MASVS-CODE",
        Name = "V7: 代码质量与构建",
        Description = "代码混淆、调试保护和编译器安全选项"
      },
      [MasvsCategory.MASVS_RESILIENCE] = new MasvsMapping
      {
        Category = MasvsCategory.MASVS_RESILIENCE,
        CategoryId = "MASVS-RESILIENCE",
        Name = "V8: 韧性",
        Description = "反逆向、防篡改和运行时完整性保护"
      },
    };

    private static readonly Dictionary<VulnerabilityType, MasvsCategory[]> VulnToMasvsMap = new()
    {
      [VulnerabilityType.HardcodedKey] = new[] { MasvsCategory.MASVS_STORAGE, MasvsCategory.MASVS_CRYPTO },
      [VulnerabilityType.WebViewVulnerability] = new[] { MasvsCategory.MASVS_PLATFORM },
      [VulnerabilityType.InsecureStorage] = new[] { MasvsCategory.MASVS_STORAGE },
      [VulnerabilityType.PermissionIssue] = new[] { MasvsCategory.MASVS_PLATFORM },
      [VulnerabilityType.SSLCertificate] = new[] { MasvsCategory.MASVS_NETWORK },
      [VulnerabilityType.NetworkSecurity] = new[] { MasvsCategory.MASVS_NETWORK },
      [VulnerabilityType.CodeObfuscation] = new[] { MasvsCategory.MASVS_CODE, MasvsCategory.MASVS_RESILIENCE },
      [VulnerabilityType.DebugMode] = new[] { MasvsCategory.MASVS_CODE, MasvsCategory.MASVS_RESILIENCE },
      [VulnerabilityType.ThirdPartySDK] = new[] { MasvsCategory.MASVS_CODE, MasvsCategory.MASVS_STORAGE },
      [VulnerabilityType.Other] = new[] { MasvsCategory.MASVS_CODE },
    };

    private static readonly Dictionary<string, MasvsCategory[]> CveMasvsMap = new(StringComparer.OrdinalIgnoreCase)
    {
      ["CVE-2020-"] = new[] { MasvsCategory.MASVS_NETWORK, MasvsCategory.MASVS_CRYPTO },
      ["CVE-2019-"] = new[] { MasvsCategory.MASVS_NETWORK },
      ["CVE-2021-"] = new[] { MasvsCategory.MASVS_NETWORK },
      ["CVE-2022-"] = new[] { MasvsCategory.MASVS_NETWORK },
      ["CVE-2023-"] = new[] { MasvsCategory.MASVS_NETWORK },
      ["CVE-2024-"] = new[] { MasvsCategory.MASVS_NETWORK },
      ["CVE-2025-"] = new[] { MasvsCategory.MASVS_NETWORK },
    };

    public static MasvsCategory[] Map(VulnerabilityType vulnType, string? cveId = null)
    {
      if (VulnToMasvsMap.TryGetValue(vulnType, out var categories))
        return categories;

      if (!string.IsNullOrEmpty(cveId))
      {
        foreach (var kvp in CveMasvsMap)
        {
          if (cveId.StartsWith(kvp.Key, System.StringComparison.OrdinalIgnoreCase))
            return kvp.Value;
        }
      }

      return new[] { MasvsCategory.MASVS_CODE };
    }

    public static MasvsCategory[] Map(string riskLevel)
    {
      return riskLevel switch
      {
        "严重" => new[] { MasvsCategory.MASVS_CRYPTO, MasvsCategory.MASVS_NETWORK, MasvsCategory.MASVS_STORAGE },
        "高危" => new[] { MasvsCategory.MASVS_NETWORK, MasvsCategory.MASVS_STORAGE },
        "中危" => new[] { MasvsCategory.MASVS_CODE, MasvsCategory.MASVS_PLATFORM },
        "低危" => new[] { MasvsCategory.MASVS_CODE },
        _ => new[] { MasvsCategory.MASVS_CODE }
      };
    }

    public static MasvsMapping GetCategoryInfo(MasvsCategory category)
    {
      return CategoryMap.TryGetValue(category, out var info) ? info : CategoryMap[MasvsCategory.MASVS_CODE];
    }

    public static List<MasvsMapping> GetAllCategories()
    {
      return new List<MasvsMapping>(CategoryMap.Values);
    }
  }
}