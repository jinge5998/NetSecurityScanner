using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using NetSecurityScanner.Core.Models;
using Models = NetSecurityScanner.Models;

namespace NetSecurityScanner.Services
{
  public class DylibInjectionDetector
  {
    public async Task<DylibInjectionReport> DetectAsync(IpaAnalysisResult ipa, Models.ScanMode mode, CancellationToken token)
    {
      var report = new DylibInjectionReport();
      var tasks = new List<Task>();

      tasks.Add(Task.Run(() =>
      {
        report.DylibLoadCommands = DetectDylibLoadCommands(ipa);
      }, token));

      tasks.Add(Task.Run(() =>
      {
        report.FrameworkHijack = DetectFrameworkHijack(ipa);
      }, token));

      tasks.Add(Task.Run(() =>
      {
        report.MobileSubstrate = DetectMobileSubstrate(ipa);
      }, token));

      await Task.WhenAll(tasks).ConfigureAwait(false);

      report.OverallScore = ComputeOverallScore(report);
      report.Vulnerabilities = GenerateVulnerabilities(report);

      return report;
    }

    private static DylibLoadResult DetectDylibLoadCommands(IpaAnalysisResult ipa)
    {
      var result = new DylibLoadResult();

      var symbolsText = string.Join(" ", ipa.MachOSymbols ?? new List<string>());
      var machOText = ipa.MachOData != null && ipa.MachOData.Length > 0
          ? System.Text.Encoding.ASCII.GetString(ipa.MachOData)
          : string.Empty;

      var combinedText = symbolsText + " " + machOText;

      if (string.IsNullOrWhiteSpace(combinedText))
      {
        result.Confidence = "无法检测";
        return result;
      }

      var dylibPatterns = new[] { ".dylib", "LC_LOAD_DYLIB", "LC_LOAD_WEAK_DYLIB", "LC_REEXPORT_DYLIB" };
      foreach (var pattern in dylibPatterns)
      {
        int count = CountOccurrences(combinedText, pattern);
        if (pattern == ".dylib")
          result.TotalDylibCommands += count;
      }

      if (ipa.NativeLibs != null)
      {
        result.LocalDylibCount = ipa.NativeLibs.Count(n => n.EndsWith(".dylib", StringComparison.OrdinalIgnoreCase));
        result.SystemDylibCount = result.TotalDylibCommands - result.LocalDylibCount;
      }

      var suspiciousDylibs = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
      {
        ["cycript"] = "Cycript动态注入工具",
        ["frida"] = "Frida动态插桩",
        ["frida-gadget"] = "Frida Gadget",
        ["substrate"] = "Cydia Substrate",
        ["substitute"] = "Substitute Hook框架",
        ["libhooker"] = "libhooker注入框架",
        ["fishhook"] = "fishhook符号替换",
        ["shadow"] = "Shadow反检测",
        ["flybird"] = "FlyBird注入",
        ["inject"] = "注入库",
        ["hook"] = "Hook库",
        ["dobby"] = "Dobby Hook框架",
        ["xhook"] = "xHook PLT Hook",
        ["bhook"] = "ByteHook",
        ["iphonehook"] = "CaptainHook"
      };

      foreach (var (pattern, label) in suspiciousDylibs)
      {
        if (combinedText.Contains(pattern, StringComparison.OrdinalIgnoreCase))
        {
          result.SuspiciousDylibs.Add($"{label}({pattern})");
        }
      }

      var rpathPatterns = new[] { "@executable_path", "@loader_path", "@rpath" };
      foreach (var pattern in rpathPatterns)
      {
        if (combinedText.Contains(pattern, StringComparison.OrdinalIgnoreCase))
        {
          result.Rpaths.Add(pattern);
        }
      }

      result.HasExternalRpath = result.Rpaths.Any(r => r == "@rpath" || r == "@executable_path");

      result.Detected = result.SuspiciousDylibs.Count > 0;
      result.Confidence = result.SuspiciousDylibs.Count >= 3 ? "高" :
                           result.SuspiciousDylibs.Count >= 1 ? "中" : "低";

      return result;
    }

    private static FrameworkHijackResult DetectFrameworkHijack(IpaAnalysisResult ipa)
    {
      var result = new FrameworkHijackResult();

      var symbolsText = string.Join(" ", ipa.MachOSymbols ?? new List<string>());
      var machOText = ipa.MachOData != null && ipa.MachOData.Length > 0
          ? System.Text.Encoding.ASCII.GetString(ipa.MachOData)
          : string.Empty;
      var combinedText = symbolsText + " " + machOText;

      result.HasWeakFramework = combinedText.Contains("LC_LOAD_WEAK_DYLIB", StringComparison.Ordinal);

      var suspiciousFrameworkPatterns = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
      {
        ["CydiaSubstrate"] = "Cydia Substrate框架",
        ["libsubstrate"] = "libsubstrate Hook",
        ["libsubstitute"] = "libsubstitute Hook",
        ["libhooker"] = "libhooker注入",
        ["AppSync"] = "AppSync Unified",
        ["xCon"] = "xCon反检测",
        ["tsProtector"] = "tsProtector P绕过",
        ["Flex"] = "Flex调试工具",
        ["IAPFree"] = "IAPFree内购破解",
        ["IAPCrazy"] = "IAPCrazy内购破解",
        ["LocalIAPStore"] = "LocalIAPStore内购模拟",
        ["SSLKillSwitch"] = "SSL Kill Switch",
        ["SSLKillSwitch2"] = "SSL Kill Switch 2",
        ["TrustMe"] = "TrustMe证书绕过",
        ["BreakThrough"] = "BreakThrough",
        ["FlyJB"] = "FlyJB越狱检测绕过",
        ["ABypass"] = "A-Bypass越狱检测绕过",
        ["Liberty"] = "Liberty Lite越狱检测绕过",
        ["Shadow"] = "Shadow越狱检测绕过",
        ["Hestia"] = "Hestia越狱检测绕过",
        ["KernBypass"] = "KernBypass内核级绕过",
        ["vnodebypass"] = "vnodebypass内核绕过"
      };

      foreach (var (pattern, label) in suspiciousFrameworkPatterns)
      {
        if (combinedText.Contains(pattern, StringComparison.OrdinalIgnoreCase))
        {
          result.SuspiciousFrameworks.Add($"{label}({pattern})");
        }
      }

      if (ipa.Frameworks != null)
      {
        var systemFrameworks = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
          "Foundation", "UIKit", "CoreGraphics", "QuartzCore", "CoreData",
          "CoreImage", "CoreLocation", "MapKit", "WebKit", "AVFoundation",
          "Security", "CFNetwork", "SystemConfiguration", "CoreTelephony",
          "StoreKit", "HealthKit", "HomeKit", "ARKit", "CoreML", "Vision",
          "NaturalLanguage", "Speech", "CoreNFC", "PushKit", "CallKit",
          "SiriKit", "Intents", "IntentsUI", "WatchKit", "ClockKit",
          "Photos", "PhotosUI", "Contacts", "ContactsUI", "EventKit",
          "EventKitUI", "MessageUI", "Messages", "Social", "Accounts",
          "NewsstandKit", "NewsKit", "GameKit", "GameController",
          "SceneKit", "SpriteKit", "Metal", "MetalKit", "MetalPerformanceShaders",
          "GLKit", "OpenGLES", "PDFKit", "PencilKit", "QuickLook",
          "QuickLookThumbnailing", "SafariServices", "AuthenticationServices",
          "IdentityLookup", "IdentityLookupUI", "Network", "NetworkExtension",
          "CoreBluetooth", "ExternalAccessory", "MultipeerConnectivity",
          "UserNotifications", "UserNotificationsUI", "NotificationCenter",
          "WatchConnectivity", "CloudKit", "FileProvider", "FileProviderUI",
          "BackgroundTasks", "ClassKit", "DeviceCheck", "CoreSpotlight",
          "CoreServices", "CoreText", "CoreMedia", "CoreAudio", "CoreVideo",
          "AudioToolbox", "VideoToolbox", "MediaPlayer", "MediaAccessibility"
        };

        foreach (var framework in ipa.Frameworks)
        {
          var frameworkName = framework.Replace(".framework", "");
          if (!systemFrameworks.Contains(frameworkName) &&
              !frameworkName.StartsWith("libswift", StringComparison.OrdinalIgnoreCase) &&
              !frameworkName.StartsWith("libobjc", StringComparison.OrdinalIgnoreCase) &&
              !frameworkName.StartsWith("libSystem", StringComparison.OrdinalIgnoreCase) &&
              !frameworkName.StartsWith("libc", StringComparison.OrdinalIgnoreCase) &&
              !frameworkName.StartsWith("libm", StringComparison.OrdinalIgnoreCase) &&
              !frameworkName.StartsWith("libz", StringComparison.OrdinalIgnoreCase) &&
              !frameworkName.StartsWith("libiconv", StringComparison.OrdinalIgnoreCase) &&
              !frameworkName.StartsWith("libxml", StringComparison.OrdinalIgnoreCase) &&
              !frameworkName.StartsWith("libsqlite", StringComparison.OrdinalIgnoreCase) &&
              !frameworkName.StartsWith("libresolv", StringComparison.OrdinalIgnoreCase))
          {
            result.HasMissingFramework = true;
            result.MissingFrameworkNames.Add(frameworkName);
          }
        }
      }

      result.Detected = result.SuspiciousFrameworks.Count > 0 || result.HasWeakFramework;
      result.Confidence = result.SuspiciousFrameworks.Count >= 2 ? "高" :
                           result.SuspiciousFrameworks.Count >= 1 ? "中" : "低";

      return result;
    }

    private static MobileSubstrateResult DetectMobileSubstrate(IpaAnalysisResult ipa)
    {
      var result = new MobileSubstrateResult();

      var symbolsText = string.Join(" ", ipa.MachOSymbols ?? new List<string>());
      var machOText = ipa.MachOData != null && ipa.MachOData.Length > 0
          ? System.Text.Encoding.ASCII.GetString(ipa.MachOData)
          : string.Empty;
      var combinedText = symbolsText + " " + machOText;

      var substratePatterns = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
      {
        ["MSHookFunction"] = "MSHookFunction",
        ["MSHookMessage"] = "MSHookMessageEx",
        ["MSFindSymbol"] = "MSFindSymbol",
        ["MSGetImageByName"] = "MSGetImageByName",
        ["CydiaSubstrate"] = "CydiaSubstrate框架",
        ["_MSHook"] = "MSHook系列",
        ["SubstrateLoader"] = "SubstrateLoader",
        ["SubstrateBootstrap"] = "SubstrateBootstrap",
        ["SubstrateSafeMode"] = "SafeMode",
        ["dlopen"] = "dlopen动态加载",
        ["dlsym"] = "dlsym符号解析",
        ["DYLD_INSERT_LIBRARIES"] = "DYLD_INSERT_LIBRARIES环境变量",
        ["com.saurik.substrate"] = "Cydia Substrate"
      };

      foreach (var (pattern, label) in substratePatterns)
      {
        if (combinedText.Contains(pattern, StringComparison.OrdinalIgnoreCase))
        {
          result.SubstrateReferences.Add($"{label}({pattern})");
        }
      }

      result.HasSubstrateHook = result.SubstrateReferences.Any(r =>
          r.Contains("MSHook", StringComparison.OrdinalIgnoreCase) ||
          r.Contains("Hook", StringComparison.OrdinalIgnoreCase));
      result.HasCydiaSubstrate = result.SubstrateReferences.Any(r =>
          r.Contains("CydiaSubstrate", StringComparison.OrdinalIgnoreCase) ||
          r.Contains("saurik", StringComparison.OrdinalIgnoreCase));
      result.HasSubstrateSafeMode = result.SubstrateReferences.Any(r =>
          r.Contains("SafeMode", StringComparison.OrdinalIgnoreCase));

      result.Detected = result.SubstrateReferences.Count > 0;
      result.Confidence = result.SubstrateReferences.Count >= 3 ? "高" :
                           result.SubstrateReferences.Count >= 1 ? "中" : "低";

      return result;
    }

    private static double ComputeOverallScore(DylibInjectionReport report)
    {
      double score = 0;
      int components = 0;

      if (report.DylibLoadCommands.SuspiciousDylibs.Count > 0)
      {
        score += Math.Min(report.DylibLoadCommands.SuspiciousDylibs.Count * 25, 100);
        components++;
      }

      if (report.FrameworkHijack.SuspiciousFrameworks.Count > 0)
      {
        score += Math.Min(report.FrameworkHijack.SuspiciousFrameworks.Count * 30, 100);
        components++;
      }

      if (report.MobileSubstrate.Detected)
      {
        score += Math.Min(report.MobileSubstrate.SubstrateReferences.Count * 25, 100);
        components++;
      }

      return components > 0 ? Math.Round(score / components, 1) : 0;
    }

    private static List<Models.AppVulnerabilityResult> GenerateVulnerabilities(DylibInjectionReport report)
    {
      var vulns = new List<Models.AppVulnerabilityResult>();

      if (report.DylibLoadCommands.SuspiciousDylibs.Count > 0)
      {
        vulns.Add(new Models.AppVulnerabilityResult
        {
          Id = "DYLIB-LOAD-001",
          Name = $"检测到可疑动态库加载 (匹配 {report.DylibLoadCommands.SuspiciousDylibs.Count} 项)",
          RiskLevel = report.DylibLoadCommands.SuspiciousDylibs.Count >= 3 ? Models.RiskLevel.High : Models.RiskLevel.Medium,
          VulnerabilityType = Models.VulnerabilityType.Other,
          Location = "Mach-O Load Commands",
          CvssScore = report.DylibLoadCommands.SuspiciousDylibs.Count >= 3 ? 7.5 : 5.5,
          Description = $"检测到可疑动态库注入: {string.Join("、", report.DylibLoadCommands.SuspiciousDylibs)}",
          Suggestion = "检查并移除可疑动态库引用，确保应用不包含注入/Hook工具库"
        });
      }

      if (report.DylibLoadCommands.HasExternalRpath)
      {
        vulns.Add(new Models.AppVulnerabilityResult
        {
          Id = "DYLIB-RPATH-001",
          Name = $"检测到外部rpath搜索路径 ({string.Join(", ", report.DylibLoadCommands.Rpaths)})",
          RiskLevel = Models.RiskLevel.Medium,
          VulnerabilityType = Models.VulnerabilityType.Other,
          Location = "Mach-O LC_RPATH",
          CvssScore = 5.0,
          Description = $"检测到@rpath或@executable_path搜索路径，可能被用于动态库劫持: {string.Join(", ", report.DylibLoadCommands.Rpaths)}",
          Suggestion = "限制rpath为应用自身目录，避免使用@executable_path加载外部库"
        });
      }

      if (report.FrameworkHijack.SuspiciousFrameworks.Count > 0)
      {
        vulns.Add(new Models.AppVulnerabilityResult
        {
          Id = "DYLIB-FWK-001",
          Name = $"检测到可疑Framework加载 (匹配 {report.FrameworkHijack.SuspiciousFrameworks.Count} 项)",
          RiskLevel = report.FrameworkHijack.SuspiciousFrameworks.Count >= 2 ? Models.RiskLevel.High : Models.RiskLevel.Medium,
          VulnerabilityType = Models.VulnerabilityType.Other,
          Location = "Mach-O / Frameworks",
          CvssScore = report.FrameworkHijack.SuspiciousFrameworks.Count >= 2 ? 7.5 : 5.0,
          Description = $"检测到可疑Framework: {string.Join("、", report.FrameworkHijack.SuspiciousFrameworks)}",
          Suggestion = "检查并移除可疑Framework，确保不包含越狱工具或Hook框架"
        });
      }

      if (report.FrameworkHijack.HasWeakFramework)
      {
        vulns.Add(new Models.AppVulnerabilityResult
        {
          Id = "DYLIB-WEAK-001",
          Name = "检测到弱引用动态库(LC_LOAD_WEAK_DYLIB)",
          RiskLevel = Models.RiskLevel.Medium,
          VulnerabilityType = Models.VulnerabilityType.Other,
          Location = "Mach-O Load Commands",
          CvssScore = 4.5,
          Description = "检测到LC_LOAD_WEAK_DYLIB命令，弱引用库可能被替换为恶意库",
          Suggestion = "避免使用弱引用动态库，改为强引用(LC_LOAD_DYLIB)并确保库路径可信"
        });
      }

      if (report.MobileSubstrate.Detected)
      {
        vulns.Add(new Models.AppVulnerabilityResult
        {
          Id = "DYLIB-SUB-001",
          Name = $"检测到MobileSubstrate/Cydia Substrate引用 (匹配 {report.MobileSubstrate.SubstrateReferences.Count} 项)",
          RiskLevel = report.MobileSubstrate.SubstrateReferences.Count >= 3 ? Models.RiskLevel.High : Models.RiskLevel.Medium,
          VulnerabilityType = Models.VulnerabilityType.Other,
          Location = "Mach-O符号表",
          CvssScore = report.MobileSubstrate.SubstrateReferences.Count >= 3 ? 8.0 : 5.5,
          Description = $"检测到Substrate Hook框架引用: {string.Join("、", report.MobileSubstrate.SubstrateReferences)}",
          Suggestion = "移除Substrate相关引用，使用标准的iOS安全机制替代Hook框架"
        });
      }

      return vulns;
    }

    private static int CountOccurrences(string text, string pattern)
    {
      if (string.IsNullOrEmpty(text) || string.IsNullOrEmpty(pattern))
        return 0;

      int count = 0;
      int index = 0;
      while ((index = text.IndexOf(pattern, index, StringComparison.Ordinal)) >= 0)
      {
        count++;
        index += pattern.Length;
      }
      return count;
    }
  }
}