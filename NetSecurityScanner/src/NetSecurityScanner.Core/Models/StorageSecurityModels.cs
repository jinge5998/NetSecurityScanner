using System.Collections.Generic;
using NetSecurityScanner.Models;

namespace NetSecurityScanner.Core.Models
{
  public class StorageSecurityReport
  {
    public double OverallScore { get; set; }
    public CoreDataSecurityResult CoreData { get; set; } = new();
    public UserDefaultsSecurityResult UserDefaults { get; set; } = new();
    public SQLiteSecurityResult SQLite { get; set; } = new();
    public CacheSecurityResult Cache { get; set; } = new();
    public FileProtectionResult FileProtection { get; set; } = new();
    public List<AppVulnerabilityResult> Vulnerabilities { get; set; } = new();
  }

  public class CoreDataSecurityResult
  {
    public bool Detected { get; set; }
    public bool HasCoreDataUsage { get; set; }
    public bool HasFileProtectionKey { get; set; }
    public bool UsesSqliteStore { get; set; }
    public bool UsesBinaryStore { get; set; }
    public bool UsesInMemoryStore { get; set; }
    public List<string> StoreTypes { get; set; } = new();
    public string FileProtectionLevel { get; set; } = string.Empty;
    public string Confidence { get; set; } = "低";
  }

  public class UserDefaultsSecurityResult
  {
    public bool Detected { get; set; }
    public bool HasUserDefaultsUsage { get; set; }
    public bool HasSensitiveDataInDefaults { get; set; }
    public bool HasSuiteName { get; set; }
    public List<string> SensitiveKeys { get; set; } = new();
    public int TotalMatches { get; set; }
    public string Confidence { get; set; } = "低";
  }

  public class SQLiteSecurityResult
  {
    public bool Detected { get; set; }
    public bool HasSqliteUsage { get; set; }
    public bool UsesSqlCipher { get; set; }
    public bool HasEncryptionKey { get; set; }
    public bool HasPlaintextDB { get; set; }
    public List<string> DatabaseFiles { get; set; } = new();
    public string Confidence { get; set; } = "低";
  }

  public class CacheSecurityResult
  {
    public bool Detected { get; set; }
    public bool HasSensitiveCache { get; set; }
    public bool HasTmpUsage { get; set; }
    public bool HasCachesDirectoryUsage { get; set; }
    public bool HasURLCacheWithoutLimit { get; set; }
    public List<string> CachedSensitivePatterns { get; set; } = new();
    public string Confidence { get; set; } = "低";
  }

  public class FileProtectionResult
  {
    public bool Detected { get; set; }
    public bool HasFileProtectionEnabled { get; set; }
    public bool HasCompleteProtection { get; set; }
    public bool HasCompleteUnlessOpen { get; set; }
    public bool HasCompleteUntilFirstAuth { get; set; }
    public bool HasNoProtection { get; set; }
    public string ProtectionLevel { get; set; } = string.Empty;
    public string Confidence { get; set; } = "低";
  }
}