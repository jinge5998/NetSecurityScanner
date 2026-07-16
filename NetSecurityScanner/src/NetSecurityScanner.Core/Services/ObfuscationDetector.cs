using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using NetSecurityScanner.Core.Models;
using Models = NetSecurityScanner.Models;

namespace NetSecurityScanner.Services
{
  public class ObfuscationDetector
  {
    public async Task<ObfuscationReport> DetectAsync(IpaAnalysisResult ipa, Models.ScanMode mode, CancellationToken token)
    {
      var report = new ObfuscationReport();
      var tasks = new List<Task>();

      tasks.Add(Task.Run(() =>
      {
        report.Strings = DetectStringObfuscation(ipa);
      }, token));

      tasks.Add(Task.Run(() =>
      {
        report.Classes = DetectClassNameObfuscation(ipa);
      }, token));

      tasks.Add(Task.Run(() =>
      {
        report.AntiDebug = DetectAntiDebug(ipa);
      }, token));

      tasks.Add(Task.Run(() =>
      {
        report.Integrity = DetectIntegrityChecks(ipa);
      }, token));

      if (mode != Models.ScanMode.Lightning)
      {
        tasks.Add(Task.Run(() =>
        {
          report.LLVM = DetectLLVMObfuscation(ipa);
        }, token));
      }

      await Task.WhenAll(tasks).ConfigureAwait(false);

      report.OverallScore = ComputeOverallScore(report);
      report.Level = DetermineLevel(report.OverallScore);
      report.Vulnerabilities = GenerateVulnerabilities(report);

      return report;
    }

    private static StringObfuscationResult DetectStringObfuscation(IpaAnalysisResult ipa)
    {
      var result = new StringObfuscationResult();

      if (ipa.MachOSymbols == null || ipa.MachOSymbols.Count == 0)
      {
        result.Confidence = "无法检测";
        return result;
      }

      result.TotalStrings = ipa.MachOSymbols.Count;
      int obfuscatedCount = 0;
      double totalEntropy = 0;

      foreach (var str in ipa.MachOSymbols)
      {
        if (string.IsNullOrEmpty(str) || str.Length < 4)
          continue;

        double entropy = CalculateShannonEntropy(str);
        double printableRatio = CalculatePrintableRatio(str);

        totalEntropy += entropy;

        if (entropy > 4.5 || printableRatio < 0.6)
        {
          obfuscatedCount++;
        }
      }

      if (result.TotalStrings > 0)
      {
        result.ShannonEntropy = Math.Round(totalEntropy / result.TotalStrings, 2);
        result.ObfuscatedStrings = obfuscatedCount;
        result.ObfuscationRate = Math.Round((double)obfuscatedCount / result.TotalStrings * 100, 1);
        result.PrintableCharRatio = Math.Round((double)ipa.MachOSymbols.Sum(s => CalculatePrintableRatio(s)) / result.TotalStrings, 2);
      }

      result.Detected = result.ObfuscationRate > 30;
      result.Confidence = result.ObfuscationRate > 60 ? "高" : result.ObfuscationRate > 30 ? "中" : "低";

      return result;
    }

    private static ClassNameObfuscationResult DetectClassNameObfuscation(IpaAnalysisResult ipa)
    {
      var result = new ClassNameObfuscationResult();

      var allNames = new List<string>();
      if (ipa.ClassNames != null) allNames.AddRange(ipa.ClassNames);
      if (ipa.MethodNames != null) allNames.AddRange(ipa.MethodNames);

      if (allNames.Count == 0)
      {
        result.Confidence = "无法检测";
        return result;
      }

      result.TotalClassNames = allNames.Count;
      int shortNameCount = 0;
      int randomNameCount = 0;

      foreach (var name in allNames)
      {
        if (string.IsNullOrEmpty(name))
          continue;

        if (name.Length <= 3)
        {
          shortNameCount++;
        }

        if (IsRandomName(name))
        {
          randomNameCount++;
        }
      }

      result.ShortNameCount = shortNameCount;
      result.RandomNameCount = randomNameCount;
      result.ShortNameRatio = result.TotalClassNames > 0
          ? Math.Round((double)(shortNameCount + randomNameCount) / result.TotalClassNames * 100, 1)
          : 0;

      result.Detected = result.ShortNameRatio > 30;
      result.Confidence = result.ShortNameRatio > 60 ? "高" : result.ShortNameRatio > 30 ? "中" : "低";

      return result;
    }

    private static AntiDebugResult DetectAntiDebug(IpaAnalysisResult ipa)
    {
      var result = new AntiDebugResult();

      var patterns = new Dictionary<string, (string Name, bool Flag)>(StringComparer.OrdinalIgnoreCase)
      {
        ["ptrace"] = ("ptrace反调试", false),
        ["PT_DENY_ATTACH"] = ("PT_DENY_ATTACH", false),
        ["sysctl"] = ("sysctl反调试", false),
        ["debugserver"] = ("debugserver检测", false),
        ["FlutterAntiDebug"] = ("Flutter反调试", false),
        ["isDebuggerAttached"] = ("调试器附加检测", false),
        ["TASK_FOR_PID"] = ("TASK_FOR_PID", false),
        ["task_for_pid"] = ("task_for_pid", false),
        ["dlopen.*debug"] = ("动态调试库加载", false),
      };

      var searchText = string.Join(" ", ipa.MachOSymbols ?? new List<string>());

      foreach (var (pattern, (name, _)) in patterns)
      {
        if (searchText.Contains(pattern, StringComparison.OrdinalIgnoreCase))
        {
          patterns[pattern] = (name, true);
          result.MatchedPatterns.Add($"{name} ({pattern})");
        }
      }

      result.HasPtraceCheck = patterns["ptrace"].Flag || patterns["PT_DENY_ATTACH"].Flag || patterns["TASK_FOR_PID"].Flag || patterns["task_for_pid"].Flag;
      result.HasSysctlCheck = patterns["sysctl"].Flag;
      result.HasDebugserverCheck = patterns["debugserver"].Flag;
      result.HasFlutterAntiDebug = patterns["FlutterAntiDebug"].Flag;
      result.TotalMatches = result.MatchedPatterns.Count;
      result.Detected = result.TotalMatches >= 2;
      result.Confidence = result.TotalMatches >= 4 ? "高" : result.TotalMatches >= 2 ? "中" : "低";

      return result;
    }

    private static IntegrityCheckResult DetectIntegrityChecks(IpaAnalysisResult ipa)
    {
      var result = new IntegrityCheckResult();

      result.HasCodeSignature = !string.IsNullOrEmpty(ipa.MainExecutable);
      result.HasEncryptedBinary = ipa.HasEncryptedBinary;

      var patterns = new[] { "crc32", "CRC32", "md5", "MD5", "sha1", "SHA1", "sha256", "SHA256", "tamper", "integrity", "checksum", "_CodeSignature", "LC_CODE_SIGNATURE" };

      var searchText = string.Join(" ", ipa.MachOSymbols ?? new List<string>());

      foreach (var pattern in patterns)
      {
        if (searchText.Contains(pattern, StringComparison.OrdinalIgnoreCase))
        {
          result.MatchedPatterns.Add(pattern);
        }
      }

      result.HasCrcCheck = result.MatchedPatterns.Any(p => p.IndexOf("crc", StringComparison.OrdinalIgnoreCase) >= 0);
      result.HasHashCheck = result.MatchedPatterns.Any(p => p.IndexOf("md5", StringComparison.OrdinalIgnoreCase) >= 0 || p.IndexOf("sha", StringComparison.OrdinalIgnoreCase) >= 0);
      result.HasTamperDetection = result.MatchedPatterns.Any(p => p.IndexOf("tamper", StringComparison.OrdinalIgnoreCase) >= 0 || p.IndexOf("integrity", StringComparison.OrdinalIgnoreCase) >= 0);

      result.Detected = result.HasCrcCheck || result.HasHashCheck || result.HasTamperDetection || result.HasEncryptedBinary;
      result.Confidence = result.HasCodeSignature && (result.HasHashCheck || result.HasEncryptedBinary) ? "中" : "低";

      return result;
    }

    private static LLVMObfuscationResult DetectLLVMObfuscation(IpaAnalysisResult ipa)
    {
      var result = new LLVMObfuscationResult();

      if (ipa.MachOData == null || ipa.MachOData.Length == 0)
      {
        result.Confidence = "无法检测";
        return result;
      }

      var searchText = System.Text.Encoding.ASCII.GetString(ipa.MachOData);
      var searchTextLower = searchText.ToLowerInvariant();

      var bogusPatterns = new[] { "while(true)", "if(false)", "for(;;)", "goto", "switch(", "case 0x", "case 0X" };
      int bogusCount = 0;
      foreach (var pattern in bogusPatterns)
      {
        int count = CountOccurrences(searchTextLower, pattern.ToLowerInvariant());
        if (count > 50)
        {
          bogusCount++;
          if (pattern.Contains("switch") || pattern.Contains("case"))
            result.HasControlFlowFlattening = true;
          else
            result.HasBogusControlFlow = true;
        }
      }

      var substitutionPatterns = new[] { "xor", "XOR", "rol", "ror", "mul", "div", "and", "or", "shl", "shr" };
      int subCount = 0;
      foreach (var pattern in substitutionPatterns)
      {
        int count = CountOccurrences(searchTextLower, pattern.ToLowerInvariant());
        if (count > 100)
          subCount++;
      }
      result.HasInstructionSubstitution = subCount >= 4;

      result.HasBogusControlFlow = result.HasBogusControlFlow || bogusCount >= 3;
      result.Detected = result.HasBogusControlFlow || result.HasControlFlowFlattening || result.HasInstructionSubstitution;
      result.Confidence = bogusCount >= 4 ? "高" : bogusCount >= 2 ? "中" : "低";

      return result;
    }

    private static double ComputeOverallScore(ObfuscationReport report)
    {
      double score = 0;
      int components = 0;

      if (report.Strings.Detected)
      {
        score += Math.Min(report.Strings.ObfuscationRate, 100);
        components++;
      }

      if (report.Classes.Detected)
      {
        score += Math.Min(report.Classes.ShortNameRatio, 100);
        components++;
      }

      if (report.AntiDebug.Detected)
      {
        score += Math.Min(report.AntiDebug.TotalMatches * 20, 100);
        components++;
      }

      if (report.Integrity.Detected)
      {
        score += 60;
        components++;
      }

      if (report.LLVM.Detected)
      {
        score += 80;
        components++;
      }

      return components > 0 ? Math.Round(score / components, 1) : 0;
    }

    private static ObfuscationLevel DetermineLevel(double score) => score switch
    {
      >= 75 => ObfuscationLevel.High,
      >= 40 => ObfuscationLevel.Medium,
      >= 10 => ObfuscationLevel.Low,
      _ => ObfuscationLevel.None
    };

    private static List<Models.AppVulnerabilityResult> GenerateVulnerabilities(ObfuscationReport report)
    {
      var vulns = new List<Models.AppVulnerabilityResult>();

      if (report.Strings.Detected)
      {
        vulns.Add(new Models.AppVulnerabilityResult
        {
          Id = "OBF-STR-001",
          Name = $"字符串混淆检测 (混淆率 {report.Strings.ObfuscationRate}%)",
          RiskLevel = report.Strings.ObfuscationRate > 60 ? Models.RiskLevel.Medium : Models.RiskLevel.Low,
          VulnerabilityType = Models.VulnerabilityType.CodeObfuscation,
          Location = "Mach-O __TEXT.__cstring",
          CvssScore = report.Strings.ObfuscationRate > 60 ? 5.0 : 2.5,
          Description = $"检测到 {report.Strings.ObfuscatedStrings}/{report.Strings.TotalStrings} 个字符串被混淆。",
          Suggestion = "字符串混淆增加了逆向分析难度，建议配合控制流混淆和完整性校验使用。"
        });
      }

      if (report.Classes.Detected)
      {
        vulns.Add(new Models.AppVulnerabilityResult
        {
          Id = "OBF-CLS-001",
          Name = $"类名/方法名混淆检测 (短名称占比 {report.Classes.ShortNameRatio}%)",
          RiskLevel = report.Classes.ShortNameRatio > 60 ? Models.RiskLevel.Medium : Models.RiskLevel.Low,
          VulnerabilityType = Models.VulnerabilityType.CodeObfuscation,
          Location = "Mach-O 符号表",
          CvssScore = report.Classes.ShortNameRatio > 60 ? 4.5 : 2.0,
          Description = $"检测到 {report.Classes.ShortNameCount + report.Classes.RandomNameCount}/{report.Classes.TotalClassNames} 个类名/方法名被混淆。",
          Suggestion = "符号混淆增加了逆向分析难度，但可能影响崩溃日志的可读性。"
        });
      }

      if (report.AntiDebug.Detected)
      {
        vulns.Add(new Models.AppVulnerabilityResult
        {
          Id = "OBF-ADB-001",
          Name = $"反调试保护检测 (匹配 {report.AntiDebug.TotalMatches} 项)",
          RiskLevel = Models.RiskLevel.Medium,
          VulnerabilityType = Models.VulnerabilityType.CodeObfuscation,
          Location = "Mach-O __TEXT段",
          CvssScore = 5.5,
          Description = $"检测到反调试机制: {string.Join("、", report.AntiDebug.MatchedPatterns)}",
          Suggestion = "反调试保护有效阻止动态分析，但需注意兼容性。"
        });
      }

      if (report.Integrity.Detected)
      {
        vulns.Add(new Models.AppVulnerabilityResult
        {
          Id = "OBF-INT-001",
          Name = "完整性校验检测",
          RiskLevel = Models.RiskLevel.Low,
          VulnerabilityType = Models.VulnerabilityType.CodeObfuscation,
          Location = "Mach-O",
          CvssScore = 3.5,
          Description = $"检测到完整性校验机制: {string.Join("、", report.Integrity.MatchedPatterns)}",
          Suggestion = "完整性校验防止应用被篡改，是有效的安全机制。"
        });
      }

      if (report.LLVM.Detected)
      {
        vulns.Add(new Models.AppVulnerabilityResult
        {
          Id = "OBF-LLVM-001",
          Name = "LLVM/O-LLVM混淆检测",
          RiskLevel = Models.RiskLevel.Medium,
          VulnerabilityType = Models.VulnerabilityType.CodeObfuscation,
          Location = "Mach-O 控制流",
          CvssScore = 6.0,
          Description = "检测到LLVM级别混淆(O-LLVM)特征，可能包含虚假控制流、控制流平坦化或指令替换。",
          Suggestion = "O-LLVM混淆是最强的代码保护手段之一，但会显著增加二进制体积和运行时开销。"
        });
      }

      return vulns;
    }

    private static double CalculateShannonEntropy(string text)
    {
      if (string.IsNullOrEmpty(text))
        return 0;

      var frequencies = new Dictionary<char, int>();
      foreach (var c in text)
      {
        if (frequencies.ContainsKey(c))
          frequencies[c]++;
        else
          frequencies[c] = 1;
      }

      double entropy = 0;
      int length = text.Length;
      foreach (var freq in frequencies.Values)
      {
        double probability = (double)freq / length;
        entropy -= probability * Math.Log(probability, 2);
      }

      return entropy;
    }

    private static double CalculatePrintableRatio(string text)
    {
      if (string.IsNullOrEmpty(text))
        return 0;

      int printable = 0;
      foreach (var c in text)
      {
        if (c >= 32 && c <= 126)
          printable++;
      }

      return (double)printable / text.Length;
    }

    private static bool IsRandomName(string name)
    {
      if (string.IsNullOrEmpty(name))
        return false;

      int upperCount = 0;
      int digitCount = 0;
      int vowelCount = 0;

      foreach (var c in name)
      {
        if (char.IsUpper(c)) upperCount++;
        if (char.IsDigit(c)) digitCount++;
        if ("aeiouAEIOU".Contains(c)) vowelCount++;
      }

      if (digitCount > name.Length * 0.4)
        return true;

      if (name.Length >= 5 && vowelCount == 0)
        return true;

      if (upperCount > name.Length * 0.6 && name.Length > 3)
        return true;

      return false;
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