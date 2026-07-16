using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using NetSecurityScanner.Core.Models;
using Models = NetSecurityScanner.Models;

namespace NetSecurityScanner.Services
{
  public class PrivacyComplianceDetector
  {
    public async Task<PrivacyComplianceReport> DetectAsync(IpaAnalysisResult ipa, Models.ScanMode mode, CancellationToken token)
    {
      var report = new PrivacyComplianceReport();
      var tasks = new List<Task>();

      tasks.Add(Task.Run(() =>
      {
        report.Manifest = DetectPrivacyManifest(ipa);
      }, token));

      tasks.Add(Task.Run(() =>
      {
        report.DataCollection = DetectDataCollection(ipa);
      }, token));

      tasks.Add(Task.Run(() =>
      {
        report.TrackingSDKs = DetectTrackingSDKs(ipa);
      }, token));

      tasks.Add(Task.Run(() =>
      {
        report.GDPR = DetectGDPRCompliance(ipa);
      }, token));

      await Task.WhenAll(tasks).ConfigureAwait(false);

      report.OverallScore = ComputeOverallScore(report);
      report.Vulnerabilities = GenerateVulnerabilities(report);

      return report;
    }

    private static PrivacyManifestResult DetectPrivacyManifest(IpaAnalysisResult ipa)
    {
      var result = new PrivacyManifestResult();

      var searchText = ipa.InfoPlistRawText ?? string.Empty;
      var symbolsText = string.Join(" ", ipa.MachOSymbols ?? new List<string>());
      var combinedText = searchText + " " + symbolsText;

      result.HasPrivacyManifest = combinedText.Contains("PrivacyInfo.xcprivacy", StringComparison.OrdinalIgnoreCase) ||
                                   combinedText.Contains("PrivacyManifest", StringComparison.OrdinalIgnoreCase);
      result.HasPrivacyTrackingEnabled = combinedText.Contains("NSPrivacyTracking", StringComparison.OrdinalIgnoreCase) ||
                                          combinedText.Contains("PrivacyTracking", StringComparison.OrdinalIgnoreCase);
      result.HasPrivacyTrackingDomains = combinedText.Contains("NSPrivacyTrackingDomains", StringComparison.OrdinalIgnoreCase);

      var trackingDomainPatterns = new[] { "tracking", "analytics", "advertising", "ads", "metrics", "attribution" };
      foreach (var pattern in trackingDomainPatterns)
      {
        if (combinedText.Contains(pattern, StringComparison.OrdinalIgnoreCase))
        {
          result.TrackingDomains.Add(pattern);
        }
      }

      var requiredReasonAPIs = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
      {
        ["NSPrivacyAccessedAPICategoryFileTimestamp"] = "FileTimestamp API",
        ["NSPrivacyAccessedAPICategorySystemBootTime"] = "SystemBootTime API",
        ["NSPrivacyAccessedAPICategoryDiskSpace"] = "DiskSpace API",
        ["NSPrivacyAccessedAPICategoryActiveKeyboards"] = "ActiveKeyboards API",
        ["NSPrivacyAccessedAPICategoryUserDefaults"] = "UserDefaults API",
        ["file_timestamp"] = "FileTimestamp",
        ["system_boot_time"] = "SystemBootTime",
        ["disk_space"] = "DiskSpace",
        ["active_keyboard"] = "ActiveKeyboards",
        ["user_defaults"] = "UserDefaults"
      };

      foreach (var (pattern, label) in requiredReasonAPIs)
      {
        if (combinedText.Contains(pattern, StringComparison.OrdinalIgnoreCase))
        {
          result.RequiredReasonAPIs.Add(label);
          result.HasRequiredReasonAPI = true;
        }
      }

      result.Detected = !result.HasPrivacyManifest;
      result.Confidence = result.HasPrivacyManifest ? "低" : "高";

      return result;
    }

    private static DataCollectionResult DetectDataCollection(IpaAnalysisResult ipa)
    {
      var result = new DataCollectionResult();

      var searchText = ipa.InfoPlistRawText ?? string.Empty;
      var symbolsText = string.Join(" ", ipa.MachOSymbols ?? new List<string>());
      var combinedText = searchText + " " + symbolsText;

      var dataTypes = new Dictionary<string, (string Label, Action<bool> Setter)>(StringComparer.OrdinalIgnoreCase)
      {
        ["NSLocationWhenInUseUsageDescription"] = ("位置信息(使用时)", v => result.HasLocationCollection = v),
        ["NSLocationAlwaysAndWhenInUseUsageDescription"] = ("位置信息(始终)", v => result.HasLocationCollection = v),
        ["NSLocationAlwaysUsageDescription"] = ("位置信息(始终-旧版)", v => result.HasLocationCollection = v),
        ["NSCameraUsageDescription"] = ("相机", v => result.HasCameraCollection = v),
        ["NSMicrophoneUsageDescription"] = ("麦克风", v => result.HasMicrophoneCollection = v),
        ["NSContactsUsageDescription"] = ("通讯录", v => result.HasContactCollection = v),
        ["NSPhotoLibraryUsageDescription"] = ("相册", v => result.HasPhotoCollection = v),
        ["NSPhotoLibraryAddUsageDescription"] = ("相册(写入)", v => result.HasPhotoCollection = v),
        ["NSCalendarsUsageDescription"] = ("日历", v => result.HasCalendarCollection = v),
        ["NSHealthShareUsageDescription"] = ("健康数据(分享)", v => result.HasHealthDataCollection = v),
        ["NSHealthUpdateUsageDescription"] = ("健康数据(更新)", v => result.HasHealthDataCollection = v),
        ["NSBluetoothAlwaysUsageDescription"] = ("蓝牙(始终)", v => result.HasBluetoothCollection = v),
        ["NSBluetoothPeripheralUsageDescription"] = ("蓝牙(外设)", v => result.HasBluetoothCollection = v),
        ["NSFaceIDUsageDescription"] = ("Face ID", v => result.HasBiometricCollection = v),
        ["NSSpeechRecognitionUsageDescription"] = ("语音识别", v => { result.HasMicrophoneCollection = true; }),
        ["NSMotionUsageDescription"] = ("运动与健身", v => { }),
        ["NSRemindersUsageDescription"] = ("提醒事项", v => { }),
        ["NSAppleMusicUsageDescription"] = ("Apple Music", v => { }),
        ["NSVideoSubscriberAccountUsageDescription"] = ("视频订阅", v => { }),
        ["NFCReaderUsageDescription"] = ("NFC", v => { }),
        ["NSSiriUsageDescription"] = ("Siri", v => { }),
        ["NSHomeKitUsageDescription"] = ("HomeKit", v => { }),
        ["NSLocalNetworkUsageDescription"] = ("本地网络", v => { }),
        ["NSUserTrackingUsageDescription"] = ("用户追踪", v => { }),
        ["NSDesktopFolderUsageDescription"] = ("桌面文件夹", v => { }),
        ["NSDocumentsFolderUsageDescription"] = ("文档文件夹", v => { }),
        ["NSDownloadsFolderUsageDescription"] = ("下载文件夹", v => { }),
        ["NSNetworkVolumesUsageDescription"] = ("网络卷", v => { }),
        ["NSRemovableVolumesUsageDescription"] = ("可移动卷", v => { }),
      };

      foreach (var (pattern, (label, setter)) in dataTypes)
      {
        if (searchText.Contains(pattern, StringComparison.OrdinalIgnoreCase))
        {
          setter(true);
          result.CollectedDataTypes.Add(label);
        }
      }

      result.HasDataCollection = result.CollectedDataTypes.Count > 0;
      result.TotalDataTypes = result.CollectedDataTypes.Count;

      result.Detected = result.HasDataCollection;
      result.Confidence = result.TotalDataTypes >= 5 ? "高" : result.TotalDataTypes >= 2 ? "中" : "低";

      return result;
    }

    private static TrackingSDKResult DetectTrackingSDKs(IpaAnalysisResult ipa)
    {
      var result = new TrackingSDKResult();

      var searchText = ipa.InfoPlistRawText ?? string.Empty;
      var symbolsText = string.Join(" ", ipa.MachOSymbols ?? new List<string>());
      var combinedText = searchText + " " + symbolsText;

      var trackingSDKs = new Dictionary<string, (string Label, Action<bool> Setter)>(StringComparer.OrdinalIgnoreCase)
      {
        ["GoogleAnalytics"] = ("Google Analytics", v => result.HasGoogleAnalytics = v),
        ["GAI"] = ("Google Analytics", v => result.HasGoogleAnalytics = v),
        ["GAIDictionaryBuilder"] = ("Google Analytics", v => result.HasGoogleAnalytics = v),
        ["FBSDKCoreKit"] = ("Facebook SDK", v => result.HasFacebookSDK = v),
        ["FBSDKLoginKit"] = ("Facebook SDK", v => result.HasFacebookSDK = v),
        ["FBSDKShareKit"] = ("Facebook SDK", v => result.HasFacebookSDK = v),
        ["FBAudienceNetwork"] = ("Facebook Audience Network", v => result.HasFacebookSDK = v),
        ["FIRAnalytics"] = ("Firebase Analytics", v => result.HasFirebaseAnalytics = v),
        ["FirebaseAnalytics"] = ("Firebase Analytics", v => result.HasFirebaseAnalytics = v),
        ["FirebaseCore"] = ("Firebase", v => result.HasFirebaseAnalytics = v),
        ["Adjust"] = ("Adjust", v => result.HasAdjust = v),
        ["AdjustSdk"] = ("Adjust", v => result.HasAdjust = v),
        ["AppsFlyer"] = ("AppsFlyer", v => result.HasAppsFlyer = v),
        ["AppsFlyerLib"] = ("AppsFlyer", v => result.HasAppsFlyer = v),
        ["Mixpanel"] = ("Mixpanel", v => result.HasMixpanel = v),
        ["Amplitude"] = ("Amplitude", v => result.HasAmplitude = v),
        ["Amplitude_iOS"] = ("Amplitude", v => result.HasAmplitude = v),
        ["SEGAnalytics"] = ("Segment", v => result.HasSegment = v),
        ["Segment"] = ("Segment", v => result.HasSegment = v),
        ["Flurry"] = ("Flurry", v => { }),
        ["Crashlytics"] = ("Crashlytics", v => { }),
        ["AppLovin"] = ("AppLovin", v => { }),
        ["ironSource"] = ("ironSource", v => { }),
        ["UnityAds"] = ("Unity Ads", v => { }),
        ["AdMob"] = ("AdMob", v => { }),
        ["GoogleMobileAds"] = ("AdMob", v => { }),
        ["MoPub"] = ("MoPub", v => { }),
        ["Chartboost"] = ("Chartboost", v => { }),
        ["Vungle"] = ("Vungle", v => { }),
        ["Tapjoy"] = ("Tapjoy", v => { }),
        ["InMobi"] = ("InMobi", v => { }),
        ["Appodeal"] = ("Appodeal", v => { }),
        ["Bugly"] = ("Bugly", v => { }),
        ["Fabric"] = ("Fabric", v => { }),
        ["HockeyApp"] = ("HockeyApp", v => { }),
        ["Sentry"] = ("Sentry", v => { }),
        ["Bugsnag"] = ("Bugsnag", v => { }),
        ["Branch"] = ("Branch", v => { }),
        ["Kochava"] = ("Kochava", v => { }),
        ["Singular"] = ("Singular", v => { }),
        ["Tenjin"] = ("Tenjin", v => { }),
        ["OneSignal"] = ("OneSignal", v => { }),
        ["CleverTap"] = ("CleverTap", v => { }),
        ["Leanplum"] = ("Leanplum", v => { }),
        ["Localytics"] = ("Localytics", v => { }),
        ["Countly"] = ("Countly", v => { }),
        ["Matomo"] = ("Matomo", v => { }),
        ["Pendo"] = ("Pendo", v => { }),
        ["FullStory"] = ("FullStory", v => { }),
        ["Heap"] = ("Heap", v => { }),
        ["PostHog"] = ("PostHog", v => { }),
        ["RudderStack"] = ("RudderStack", v => { }),
        ["mParticle"] = ("mParticle", v => { }),
        ["Tealium"] = ("Tealium", v => { }),
        ["Ensighten"] = ("Ensighten", v => { }),
      };

      var detectedSDKs = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
      foreach (var (pattern, (label, setter)) in trackingSDKs)
      {
        if (combinedText.Contains(pattern, StringComparison.OrdinalIgnoreCase))
        {
          setter(true);
          detectedSDKs.Add(label);
        }
      }

      result.DetectedSDKs = detectedSDKs.ToList();
      result.TotalTrackingSDKs = result.DetectedSDKs.Count;

      result.Detected = result.TotalTrackingSDKs > 0;
      result.Confidence = result.TotalTrackingSDKs >= 5 ? "高" :
                           result.TotalTrackingSDKs >= 2 ? "中" : "低";

      return result;
    }

    private static GDPRComplianceResult DetectGDPRCompliance(IpaAnalysisResult ipa)
    {
      var result = new GDPRComplianceResult();

      var searchText = ipa.InfoPlistRawText ?? string.Empty;
      var symbolsText = string.Join(" ", ipa.MachOSymbols ?? new List<string>());
      var combinedText = searchText + " " + symbolsText;

      var consentPatterns = new[] { "consent", "gdpr", "CCPA", "privacy", "opt-in", "opt_out", "optout",
                                     "user_consent", "data_protection", "privacy_policy", "privacyPolicy",
                                     "ATTrackingManager", "requestTrackingAuthorization",
                                     "AppTrackingTransparency", "IDFA", "privacySettings" };
      foreach (var pattern in consentPatterns)
      {
        if (combinedText.Contains(pattern, StringComparison.OrdinalIgnoreCase))
        {
          result.HasConsentMechanism = true;
          result.ComplianceIndicators.Add($"同意机制({pattern})");
          break;
        }
      }

      var retentionPatterns = new[] { "retention", "data_retention", "retention_period", "retentionPolicy",
                                       "data_lifecycle", "data_expiry", "data_cleanup", "purge",
                                       "delete_data", "erase_data", "remove_data", "forget_me" };
      foreach (var pattern in retentionPatterns)
      {
        if (combinedText.Contains(pattern, StringComparison.OrdinalIgnoreCase))
        {
          result.HasDataRetentionPolicy = true;
          result.ComplianceIndicators.Add($"数据保留策略({pattern})");
          break;
        }
      }

      var deletePatterns = new[] { "delete_account", "delete_data", "delete_user", "erase", "right_to_delete",
                                    "right_to_erasure", "forget_me", "account_deletion", "data_deletion",
                                    "deleteMyData", "deleteAccount", "removeAccount", "purge_user" };
      foreach (var pattern in deletePatterns)
      {
        if (combinedText.Contains(pattern, StringComparison.OrdinalIgnoreCase))
        {
          result.HasRightToDelete = true;
          result.ComplianceIndicators.Add($"删除权({pattern})");
          break;
        }
      }

      var portabilityPatterns = new[] { "data_export", "export_data", "data_portability", "download_data",
                                         "data_download", "export_my_data", "download_my_data",
                                         "data_access", "access_request", "subject_access", "DSAR",
                                         "data_request", "personal_data", "personal_data_request" };
      foreach (var pattern in portabilityPatterns)
      {
        if (combinedText.Contains(pattern, StringComparison.OrdinalIgnoreCase))
        {
          result.HasDataPortability = true;
          result.ComplianceIndicators.Add($"数据可携带({pattern})");
          break;
        }
      }

      var dpaPatterns = new[] { "data_processing", "data_processor", "data_controller",
                                 "DPA", "DPO", "data_protection_officer", "privacy_shield",
                                 "SCC", "standard_contractual_clauses", "binding_corporate_rules" };
      foreach (var pattern in dpaPatterns)
      {
        if (combinedText.Contains(pattern, StringComparison.OrdinalIgnoreCase))
        {
          result.HasDataProcessingAgreement = true;
          result.ComplianceIndicators.Add($"数据处理协议({pattern})");
          break;
        }
      }

      var crossBorderPatterns = new[] { "cross_border", "data_transfer", "international_transfer",
                                         "EU_transfer", "third_country", "adequacy_decision",
                                         "data_localization", "data_sovereignty", "data_residency" };
      foreach (var pattern in crossBorderPatterns)
      {
        if (combinedText.Contains(pattern, StringComparison.OrdinalIgnoreCase))
        {
          result.HasCrossBorderTransfer = true;
          result.ComplianceIndicators.Add($"跨境传输({pattern})");
          break;
        }
      }

      var agePatterns = new[] { "age_verification", "age_gate", "parental_consent", "child_protection",
                                 "minor", "under_13", "under_16", "children_privacy", "COPPA",
                                 "age_restriction", "age_check", "birth_date", "date_of_birth" };
      foreach (var pattern in agePatterns)
      {
        if (combinedText.Contains(pattern, StringComparison.OrdinalIgnoreCase))
        {
          result.HasAgeVerification = true;
          result.ComplianceIndicators.Add($"年龄验证({pattern})");
          break;
        }
      }

      if (!result.HasConsentMechanism)
        result.MissingRequirements.Add("缺少用户同意机制");
      if (!result.HasDataRetentionPolicy)
        result.MissingRequirements.Add("缺少数据保留策略");
      if (!result.HasRightToDelete)
        result.MissingRequirements.Add("缺少删除权/被遗忘权");
      if (!result.HasDataPortability)
        result.MissingRequirements.Add("缺少数据可携带性");
      if (!result.HasDataProcessingAgreement)
        result.MissingRequirements.Add("缺少数据处理协议");
      if (!result.HasAgeVerification)
        result.MissingRequirements.Add("缺少年龄验证机制");

      result.ComplianceScore = result.ComplianceIndicators.Count * 15;
      if (result.ComplianceScore > 100) result.ComplianceScore = 100;

      result.Detected = result.MissingRequirements.Count > 0;
      result.Confidence = result.ComplianceScore >= 60 ? "中" : "高";

      return result;
    }

    private static double ComputeOverallScore(PrivacyComplianceReport report)
    {
      double score = 0;
      int components = 0;

      if (!report.Manifest.HasPrivacyManifest)
      {
        score += 70;
        components++;
      }

      if (report.DataCollection.HasDataCollection)
      {
        score += Math.Min(report.DataCollection.TotalDataTypes * 15, 100);
        components++;
      }

      if (report.TrackingSDKs.Detected)
      {
        score += Math.Min(report.TrackingSDKs.TotalTrackingSDKs * 20, 100);
        components++;
      }

      if (report.GDPR.MissingRequirements.Count > 0)
      {
        score += Math.Min(report.GDPR.MissingRequirements.Count * 15, 100);
        components++;
      }

      return components > 0 ? Math.Round(score / components, 1) : 0;
    }

    private static List<Models.AppVulnerabilityResult> GenerateVulnerabilities(PrivacyComplianceReport report)
    {
      var vulns = new List<Models.AppVulnerabilityResult>();

      if (!report.Manifest.HasPrivacyManifest)
      {
        vulns.Add(new Models.AppVulnerabilityResult
        {
          Id = "PRIV-MAN-001",
          Name = "缺少隐私清单(PrivacyInfo.xcprivacy)",
          RiskLevel = Models.RiskLevel.Medium,
          VulnerabilityType = Models.VulnerabilityType.Other,
          Location = "App Bundle",
          CvssScore = 4.5,
          Description = "未检测到PrivacyInfo.xcprivacy隐私清单文件。Apple要求自2024年春季起，所有App和第三方SDK必须包含隐私清单",
          Suggestion = "在Xcode中添加PrivacyInfo.xcprivacy文件，声明App和SDK使用的隐私相关API及数据收集实践"
        });
      }

      if (report.Manifest.HasRequiredReasonAPI)
      {
        vulns.Add(new Models.AppVulnerabilityResult
        {
          Id = "PRIV-API-001",
          Name = $"检测到Required Reason API使用 ({report.Manifest.RequiredReasonAPIs.Count} 项)",
          RiskLevel = Models.RiskLevel.Medium,
          VulnerabilityType = Models.VulnerabilityType.Other,
          Location = "PrivacyInfo.xcprivacy",
          CvssScore = 4.0,
          Description = $"检测到需要在隐私清单中声明的API: {string.Join("、", report.Manifest.RequiredReasonAPIs)}",
          Suggestion = "在PrivacyInfo.xcprivacy中声明这些API的使用原因，否则可能导致App审核被拒"
        });
      }

      if (report.DataCollection.HasDataCollection)
      {
        vulns.Add(new Models.AppVulnerabilityResult
        {
          Id = "PRIV-DATA-001",
          Name = $"数据收集检测 ({report.DataCollection.TotalDataTypes} 种数据类型)",
          RiskLevel = report.DataCollection.TotalDataTypes >= 5 ? Models.RiskLevel.High : Models.RiskLevel.Medium,
          VulnerabilityType = Models.VulnerabilityType.Other,
          Location = "Info.plist / 代码",
          CvssScore = report.DataCollection.TotalDataTypes >= 5 ? 6.0 : 4.0,
          Description = $"检测到App收集以下数据类型: {string.Join("、", report.DataCollection.CollectedDataTypes)}",
          Suggestion = "确保所有数据收集行为在隐私政策中明确说明，并为用户提供选择权"
        });
      }

      if (report.TrackingSDKs.Detected)
      {
        vulns.Add(new Models.AppVulnerabilityResult
        {
          Id = "PRIV-TRACK-001",
          Name = $"检测到追踪/分析SDK ({report.TrackingSDKs.TotalTrackingSDKs} 个)",
          RiskLevel = report.TrackingSDKs.TotalTrackingSDKs >= 5 ? Models.RiskLevel.High : Models.RiskLevel.Medium,
          VulnerabilityType = Models.VulnerabilityType.ThirdPartySDK,
          Location = "第三方SDK",
          CvssScore = report.TrackingSDKs.TotalTrackingSDKs >= 5 ? 6.5 : 4.0,
          Description = $"检测到以下追踪/分析SDK: {string.Join("、", report.TrackingSDKs.DetectedSDKs)}",
          Suggestion = "确保所有追踪SDK在隐私政策中声明，并在App Tracking Transparency框架中请求用户授权"
        });
      }

      if (report.GDPR.MissingRequirements.Count > 0)
      {
        vulns.Add(new Models.AppVulnerabilityResult
        {
          Id = "PRIV-GDPR-001",
          Name = $"GDPR/CCPA合规缺陷 ({report.GDPR.MissingRequirements.Count} 项缺失)",
          RiskLevel = report.GDPR.MissingRequirements.Count >= 4 ? Models.RiskLevel.High : Models.RiskLevel.Medium,
          VulnerabilityType = Models.VulnerabilityType.Other,
          Location = "合规性",
          CvssScore = report.GDPR.MissingRequirements.Count >= 4 ? 7.0 : 5.0,
          Description = $"GDPR/CCPA合规缺失项: {string.Join("、", report.GDPR.MissingRequirements)}",
          Suggestion = "实施完整的隐私合规框架，包括同意管理、数据访问权、删除权和数据可携带性"
        });
      }

      return vulns;
    }
  }
}