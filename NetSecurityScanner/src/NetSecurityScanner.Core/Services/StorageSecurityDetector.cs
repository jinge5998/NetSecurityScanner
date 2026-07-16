using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using NetSecurityScanner.Core.Models;
using Models = NetSecurityScanner.Models;

namespace NetSecurityScanner.Services
{
  public class StorageSecurityDetector
  {
    public async Task<StorageSecurityReport> DetectAsync(IpaAnalysisResult ipa, Models.ScanMode mode, CancellationToken token)
    {
      var report = new StorageSecurityReport();
      var tasks = new List<Task>();

      tasks.Add(Task.Run(() =>
      {
        report.CoreData = DetectCoreDataSecurity(ipa);
      }, token));

      tasks.Add(Task.Run(() =>
      {
        report.UserDefaults = DetectUserDefaultsSecurity(ipa);
      }, token));

      tasks.Add(Task.Run(() =>
      {
        report.SQLite = DetectSQLiteSecurity(ipa);
      }, token));

      tasks.Add(Task.Run(() =>
      {
        report.Cache = DetectCacheSecurity(ipa);
      }, token));

      tasks.Add(Task.Run(() =>
      {
        report.FileProtection = DetectFileProtection(ipa);
      }, token));

      await Task.WhenAll(tasks).ConfigureAwait(false);

      report.OverallScore = ComputeOverallScore(report);
      report.Vulnerabilities = GenerateVulnerabilities(report);

      return report;
    }

    private static CoreDataSecurityResult DetectCoreDataSecurity(IpaAnalysisResult ipa)
    {
      var result = new CoreDataSecurityResult();

      var searchText = ipa.InfoPlistRawText ?? string.Empty;
      var symbolsText = string.Join(" ", ipa.MachOSymbols ?? new List<string>());

      result.HasCoreDataUsage = searchText.Contains("NSManagedObjectModel", StringComparison.OrdinalIgnoreCase) ||
                                 symbolsText.Contains("NSPersistentStore", StringComparison.Ordinal) ||
                                 symbolsText.Contains("NSManagedObjectContext", StringComparison.Ordinal);

      if (!result.HasCoreDataUsage)
      {
        result.Confidence = "未检测到CoreData使用";
        return result;
      }

      if (searchText.Contains("NSPersistentStoreFileProtectionKey", StringComparison.OrdinalIgnoreCase))
      {
        result.HasFileProtectionKey = true;
        if (searchText.Contains("NSFileProtectionComplete", StringComparison.OrdinalIgnoreCase))
          result.FileProtectionLevel = "NSFileProtectionComplete";
        else if (searchText.Contains("NSFileProtectionCompleteUnlessOpen", StringComparison.OrdinalIgnoreCase))
          result.FileProtectionLevel = "NSFileProtectionCompleteUnlessOpen";
        else if (searchText.Contains("NSFileProtectionCompleteUntilFirstUserAuthentication", StringComparison.OrdinalIgnoreCase))
          result.FileProtectionLevel = "NSFileProtectionCompleteUntilFirstUserAuthentication";
        else
          result.FileProtectionLevel = "已设置但级别未知";
      }

      result.UsesSqliteStore = symbolsText.Contains("NSSQLiteStoreType", StringComparison.Ordinal) ||
                                symbolsText.Contains("SQLite", StringComparison.Ordinal);
      result.UsesBinaryStore = symbolsText.Contains("NSBinaryStoreType", StringComparison.Ordinal);
      result.UsesInMemoryStore = symbolsText.Contains("NSInMemoryStoreType", StringComparison.Ordinal);

      if (result.UsesSqliteStore) result.StoreTypes.Add("SQLite");
      if (result.UsesBinaryStore) result.StoreTypes.Add("Binary");
      if (result.UsesInMemoryStore) result.StoreTypes.Add("InMemory");

      result.Detected = result.HasCoreDataUsage && !result.HasFileProtectionKey;
      result.Confidence = result.HasFileProtectionKey ? "中" : "高";

      return result;
    }

    private static UserDefaultsSecurityResult DetectUserDefaultsSecurity(IpaAnalysisResult ipa)
    {
      var result = new UserDefaultsSecurityResult();

      var searchText = ipa.InfoPlistRawText ?? string.Empty;
      var symbolsText = string.Join(" ", ipa.MachOSymbols ?? new List<string>());

      result.HasUserDefaultsUsage = symbolsText.Contains("NSUserDefaults", StringComparison.Ordinal) ||
                                     symbolsText.Contains("UserDefaults", StringComparison.Ordinal);

      if (!result.HasUserDefaultsUsage)
      {
        result.Confidence = "未检测到UserDefaults使用";
        return result;
      }

      var sensitiveKeys = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
      {
        ["password"] = "密码",
        ["token"] = "令牌",
        ["secret"] = "密钥",
        ["credential"] = "凭证",
        ["api_key"] = "API密钥",
        ["apikey"] = "API密钥",
        ["auth"] = "认证信息",
        ["session"] = "会话",
        ["private"] = "私密数据",
        ["ssn"] = "社会安全号",
        ["credit"] = "信用卡",
        ["card"] = "卡号",
        ["phone"] = "手机号",
        ["email"] = "邮箱",
        ["address"] = "地址",
        ["location"] = "位置",
        ["gps"] = "GPS",
        ["imei"] = "IMEI",
        ["idfa"] = "IDFA",
        ["idfv"] = "IDFV",
        ["device_id"] = "设备ID",
        ["deviceid"] = "设备ID",
        ["uuid"] = "UUID",
        ["fingerprint"] = "指纹",
        ["biometric"] = "生物特征",
        ["health"] = "健康数据",
        ["medical"] = "医疗数据",
        ["financial"] = "财务数据",
        ["bank"] = "银行",
        ["payment"] = "支付",
        ["encrypt"] = "加密密钥",
        ["certificate"] = "证书",
        ["private_key"] = "私钥",
        ["privatekey"] = "私钥"
      };

      var combinedText = searchText + " " + symbolsText;
      foreach (var (key, label) in sensitiveKeys)
      {
        if (combinedText.Contains(key, StringComparison.OrdinalIgnoreCase))
        {
          result.SensitiveKeys.Add($"{label}({key})");
        }
      }

      result.HasSensitiveDataInDefaults = result.SensitiveKeys.Count > 0;
      result.HasSuiteName = symbolsText.Contains("initWithSuiteName", StringComparison.Ordinal);
      result.TotalMatches = result.SensitiveKeys.Count;

      result.Detected = result.HasSensitiveDataInDefaults;
      result.Confidence = result.TotalMatches >= 5 ? "高" : result.TotalMatches >= 2 ? "中" : "低";

      return result;
    }

    private static SQLiteSecurityResult DetectSQLiteSecurity(IpaAnalysisResult ipa)
    {
      var result = new SQLiteSecurityResult();

      var searchText = ipa.InfoPlistRawText ?? string.Empty;
      var symbolsText = string.Join(" ", ipa.MachOSymbols ?? new List<string>());
      var combinedText = searchText + " " + symbolsText;

      result.HasSqliteUsage = combinedText.Contains("sqlite", StringComparison.OrdinalIgnoreCase) ||
                               combinedText.Contains("SQLite", StringComparison.Ordinal);

      if (!result.HasSqliteUsage)
      {
        result.Confidence = "未检测到SQLite使用";
        return result;
      }

      result.UsesSqlCipher = combinedText.Contains("sqlcipher", StringComparison.OrdinalIgnoreCase) ||
                              combinedText.Contains("SQLCipher", StringComparison.Ordinal) ||
                              combinedText.Contains("sqlite3_key", StringComparison.Ordinal);

      result.HasEncryptionKey = combinedText.Contains("sqlite3_key", StringComparison.Ordinal) ||
                                 combinedText.Contains("sqlite3_rekey", StringComparison.Ordinal) ||
                                 combinedText.Contains("setKey", StringComparison.Ordinal) ||
                                 combinedText.Contains("pragma key", StringComparison.OrdinalIgnoreCase);

      result.HasPlaintextDB = result.HasSqliteUsage && !result.UsesSqlCipher && !result.HasEncryptionKey;

      var dbPatterns = new[] { ".sqlite", ".db", ".sqlite3", ".s3db" };
      if (ipa.SdkFiles != null)
      {
        foreach (var file in ipa.SdkFiles)
        {
          foreach (var pattern in dbPatterns)
          {
            if (file.Contains(pattern, StringComparison.OrdinalIgnoreCase))
            {
              result.DatabaseFiles.Add(file);
              break;
            }
          }
        }
      }

      result.Detected = result.HasPlaintextDB;
      result.Confidence = result.UsesSqlCipher ? "中" : "高";

      return result;
    }

    private static CacheSecurityResult DetectCacheSecurity(IpaAnalysisResult ipa)
    {
      var result = new CacheSecurityResult();

      var searchText = ipa.InfoPlistRawText ?? string.Empty;
      var symbolsText = string.Join(" ", ipa.MachOSymbols ?? new List<string>());
      var combinedText = searchText + " " + symbolsText;

      result.HasCachesDirectoryUsage = combinedText.Contains("NSCachesDirectory", StringComparison.Ordinal) ||
                                        combinedText.Contains("cachesDirectory", StringComparison.Ordinal);
      result.HasTmpUsage = combinedText.Contains("NSTemporaryDirectory", StringComparison.Ordinal) ||
                            combinedText.Contains("temporaryDirectory", StringComparison.Ordinal);

      result.HasURLCacheWithoutLimit = combinedText.Contains("URLCache", StringComparison.Ordinal) &&
                                       !combinedText.Contains("diskCapacity", StringComparison.Ordinal) &&
                                       !combinedText.Contains("memoryCapacity", StringComparison.Ordinal);

      var sensitivePatterns = new[] { "password", "token", "secret", "key", "credential", "auth", "session" };
      foreach (var pattern in sensitivePatterns)
      {
        if (combinedText.Contains(pattern, StringComparison.OrdinalIgnoreCase) &&
            (combinedText.Contains("cache", StringComparison.OrdinalIgnoreCase) ||
             combinedText.Contains("tmp", StringComparison.OrdinalIgnoreCase) ||
             combinedText.Contains("temporary", StringComparison.OrdinalIgnoreCase)))
        {
          result.CachedSensitivePatterns.Add(pattern);
        }
      }

      result.HasSensitiveCache = result.CachedSensitivePatterns.Count > 0;
      result.Detected = result.HasSensitiveCache || result.HasURLCacheWithoutLimit;
      result.Confidence = result.HasSensitiveCache ? "高" : result.HasURLCacheWithoutLimit ? "中" : "低";

      return result;
    }

    private static FileProtectionResult DetectFileProtection(IpaAnalysisResult ipa)
    {
      var result = new FileProtectionResult();

      var searchText = ipa.InfoPlistRawText ?? string.Empty;
      var symbolsText = string.Join(" ", ipa.MachOSymbols ?? new List<string>());
      var combinedText = searchText + " " + symbolsText;

      result.HasFileProtectionEnabled = combinedText.Contains("NSFileProtection", StringComparison.Ordinal) ||
                                         combinedText.Contains("FileProtection", StringComparison.Ordinal);

      result.HasCompleteProtection = combinedText.Contains("NSFileProtectionComplete", StringComparison.Ordinal) &&
                                      !combinedText.Contains("NSFileProtectionCompleteUnlessOpen", StringComparison.Ordinal) &&
                                      !combinedText.Contains("NSFileProtectionCompleteUntilFirstUserAuthentication", StringComparison.Ordinal);
      result.HasCompleteUnlessOpen = combinedText.Contains("NSFileProtectionCompleteUnlessOpen", StringComparison.Ordinal);
      result.HasCompleteUntilFirstAuth = combinedText.Contains("NSFileProtectionCompleteUntilFirstUserAuthentication", StringComparison.Ordinal);
      result.HasNoProtection = combinedText.Contains("NSFileProtectionNone", StringComparison.Ordinal);

      if (result.HasCompleteProtection)
        result.ProtectionLevel = "NSFileProtectionComplete";
      else if (result.HasCompleteUnlessOpen)
        result.ProtectionLevel = "NSFileProtectionCompleteUnlessOpen";
      else if (result.HasCompleteUntilFirstAuth)
        result.ProtectionLevel = "NSFileProtectionCompleteUntilFirstUserAuthentication";
      else if (result.HasNoProtection)
        result.ProtectionLevel = "NSFileProtectionNone";
      else if (result.HasFileProtectionEnabled)
        result.ProtectionLevel = "已启用但级别未知";

      result.Detected = !result.HasFileProtectionEnabled || result.HasNoProtection;
      result.Confidence = result.HasCompleteProtection ? "低" :
                           result.HasFileProtectionEnabled ? "中" : "高";

      return result;
    }

    private static double ComputeOverallScore(StorageSecurityReport report)
    {
      double score = 0;
      int components = 0;

      if (report.CoreData.HasCoreDataUsage)
      {
        score += report.CoreData.HasFileProtectionKey ? 20 : 80;
        components++;
      }

      if (report.UserDefaults.HasUserDefaultsUsage)
      {
        score += report.UserDefaults.HasSensitiveDataInDefaults ? 80 : 15;
        components++;
      }

      if (report.SQLite.HasSqliteUsage)
      {
        score += report.SQLite.HasPlaintextDB ? 85 : 15;
        components++;
      }

      if (report.Cache.Detected)
      {
        score += report.Cache.HasSensitiveCache ? 75 : 30;
        components++;
      }

      if (report.FileProtection.Detected)
      {
        score += report.FileProtection.HasNoProtection ? 90 : 40;
        components++;
      }

      return components > 0 ? Math.Round(score / components, 1) : 0;
    }

    private static List<Models.AppVulnerabilityResult> GenerateVulnerabilities(StorageSecurityReport report)
    {
      var vulns = new List<Models.AppVulnerabilityResult>();

      if (report.CoreData.HasCoreDataUsage && !report.CoreData.HasFileProtectionKey)
      {
        vulns.Add(new Models.AppVulnerabilityResult
        {
          Id = "STOR-CORE-001",
          Name = "CoreData未启用文件保护",
          RiskLevel = Models.RiskLevel.High,
          VulnerabilityType = Models.VulnerabilityType.InsecureStorage,
          Location = "Info.plist / NSPersistentStore",
          CvssScore = 7.0,
          Description = $"检测到CoreData使用但未配置NSPersistentStoreFileProtectionKey，存储类型: {string.Join(", ", report.CoreData.StoreTypes)}",
          Suggestion = "在CoreData的NSPersistentStoreDescription中设置NSPersistentStoreFileProtectionKey为NSFileProtectionComplete"
        });
      }

      if (report.UserDefaults.HasSensitiveDataInDefaults)
      {
        vulns.Add(new Models.AppVulnerabilityResult
        {
          Id = "STOR-UD-001",
          Name = $"UserDefaults存储敏感数据 (匹配 {report.UserDefaults.TotalMatches} 项)",
          RiskLevel = report.UserDefaults.TotalMatches >= 5 ? Models.RiskLevel.High : Models.RiskLevel.Medium,
          VulnerabilityType = Models.VulnerabilityType.InsecureStorage,
          Location = "NSUserDefaults",
          CvssScore = report.UserDefaults.TotalMatches >= 5 ? 6.5 : 4.5,
          Description = $"检测到UserDefaults存储敏感数据: {string.Join("、", report.UserDefaults.SensitiveKeys.Take(8))}",
          Suggestion = "敏感数据应存储在Keychain中，不要使用UserDefaults。UserDefaults数据以明文plist存储，可被越狱设备轻易读取"
        });
      }

      if (report.SQLite.HasPlaintextDB)
      {
        vulns.Add(new Models.AppVulnerabilityResult
        {
          Id = "STOR-SQL-001",
          Name = "SQLite数据库未加密",
          RiskLevel = Models.RiskLevel.High,
          VulnerabilityType = Models.VulnerabilityType.InsecureStorage,
          Location = "SQLite数据库文件",
          CvssScore = 7.5,
          Description = $"检测到SQLite使用但未启用加密(SQLCipher/sqlite3_key)，数据库文件以明文存储: {string.Join(", ", report.SQLite.DatabaseFiles.Take(5))}",
          Suggestion = "使用SQLCipher或sqlite3_key启用SQLite加密，或使用CoreData的NSPersistentStoreFileProtectionKey"
        });
      }

      if (report.Cache.HasSensitiveCache)
      {
        vulns.Add(new Models.AppVulnerabilityResult
        {
          Id = "STOR-CACHE-001",
          Name = "缓存中存储敏感数据",
          RiskLevel = Models.RiskLevel.Medium,
          VulnerabilityType = Models.VulnerabilityType.InsecureStorage,
          Location = "Caches/Tmp目录",
          CvssScore = 5.0,
          Description = $"检测到缓存中可能存储敏感数据: {string.Join("、", report.Cache.CachedSensitivePatterns)}",
          Suggestion = "避免在缓存和临时目录中存储敏感数据，使用Keychain或加密的文件保护"
        });
      }

      if (report.Cache.HasURLCacheWithoutLimit)
      {
        vulns.Add(new Models.AppVulnerabilityResult
        {
          Id = "STOR-CACHE-002",
          Name = "URLCache未设置容量限制",
          RiskLevel = Models.RiskLevel.Low,
          VulnerabilityType = Models.VulnerabilityType.InsecureStorage,
          Location = "NSURLCache",
          CvssScore = 2.5,
          Description = "检测到URLCache使用但未设置diskCapacity和memoryCapacity限制",
          Suggestion = "设置URLCache.shared.diskCapacity和memoryCapacity限制缓存大小"
        });
      }

      if (report.FileProtection.HasNoProtection)
      {
        vulns.Add(new Models.AppVulnerabilityResult
        {
          Id = "STOR-FP-001",
          Name = "文件保护级别设置为None",
          RiskLevel = Models.RiskLevel.High,
          VulnerabilityType = Models.VulnerabilityType.InsecureStorage,
          Location = "NSFileProtection",
          CvssScore = 7.0,
          Description = "检测到NSFileProtectionNone，文件在任何时候都可被访问",
          Suggestion = "将文件保护级别设置为NSFileProtectionCompleteUnlessOpen或NSFileProtectionComplete"
        });
      }
      else if (!report.FileProtection.HasFileProtectionEnabled)
      {
        vulns.Add(new Models.AppVulnerabilityResult
        {
          Id = "STOR-FP-002",
          Name = "未启用文件保护机制",
          RiskLevel = Models.RiskLevel.Medium,
          VulnerabilityType = Models.VulnerabilityType.InsecureStorage,
          Location = "文件系统",
          CvssScore = 5.0,
          Description = "未检测到NSFileProtection相关配置，文件可能以不安全方式存储",
          Suggestion = "在写入敏感文件时使用NSDataWritingFileProtectionComplete或NSFileProtectionComplete"
        });
      }

      return vulns;
    }
  }
}