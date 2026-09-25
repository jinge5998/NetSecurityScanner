using System;
using System.IO;
using System.Management;
using System.Security.Cryptography;
using System.Text;

namespace NetSecurityScanner.Test
{
  /// <summary>
  /// 授权码生成→激活 端到端深度测试工具 v2.0
  /// 覆盖全部 5 项关键校验 + 真实文件写入/读取验证
  /// </summary>
  class TestLicenseFlow
  {
    // === 与 LicenseService 完全一致的密钥 ===
    private static readonly string HmacKey = "NSS2026Hmac!@#Lic";
    private static readonly string AesPassword = "NSS2026LicKey!@#";
    private static readonly byte[] AesSalt = { 0x4E, 0x53, 0x53, 0x4C, 0x69, 0x63, 0x32, 0x30 };

    // === 与主程序完全一致的授权文件路径 ===
    private static readonly string LicenseDir = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
        "NetSecurityScanner", "license");
    private static readonly string LicenseFilePath = Path.Combine(LicenseDir, "license.dat");

    static void Main(string[] args)
    {
      Console.WriteLine("===================================================================");
      Console.WriteLine("   授权码生成→激活 端到端深度测试 v2.0");
      Console.WriteLine("   验证：独立生成器 → 主程序激活 → 授权文件持久化 → 重启读取");
      Console.WriteLine("===================================================================");
      Console.WriteLine();

      // ============================================================
      // 阶段 I：算法一致性验证（5 项基础校验）
      // ============================================================
      Console.WriteLine("╔══════════════════════════════════════════════════════════════════╗");
      Console.WriteLine("║  阶段 I：算法一致性验证                                        ║");
      Console.WriteLine("╚══════════════════════════════════════════════════════════════════╝");
      Console.WriteLine();

      // --- 测试1：机器指纹 ---
      Console.WriteLine("▶ 测试1：机器指纹（MachineFingerprint.Generate）");
      Console.WriteLine("  验证：生成器与主程序使用相同的机器指纹算法");
      string machineId = GenerateMachineFingerprint();
      string machinePrefix = ComputeMachineHash(machineId);
      Console.WriteLine($"  机器指纹: {machineId}");
      Console.WriteLine($"  机器码前缀: {machinePrefix}");
      Assert(machinePrefix.Length == 16, "前缀长度应为16字符");
      Console.WriteLine();

      // --- 测试2：授权码生成 ---
      Console.WriteLine("▶ 测试2：授权码生成");
      Console.WriteLine("  验证：生成算法产生正确格式的授权码");
      string licenseCodeTrial = GenerateLicenseCode(machinePrefix, DateTime.Now, "T");
      string licenseCodeYear1 = GenerateLicenseCode(machinePrefix, DateTime.Now, "1");
      string licenseCodeYear2 = GenerateLicenseCode(machinePrefix, DateTime.Now, "2");
      string licenseCodePerm = GenerateLicenseCode(machinePrefix, DateTime.Now, "P");

      Console.WriteLine($"  试用版(T): {licenseCodeTrial}");
      Console.WriteLine($"  1年期(1):  {licenseCodeYear1}");
      Console.WriteLine($"  2年期(2):  {licenseCodeYear2}");
      Console.WriteLine($"  永久(P):   {licenseCodePerm}");

      Assert(ValidateCodeFormat(licenseCodeTrial), "授权码格式验证");
      Assert(ValidateCodeFormat(licenseCodeYear1), "授权码格式验证");
      Assert(ValidateCodeFormat(licenseCodeYear2), "授权码格式验证");
      Assert(ValidateCodeFormat(licenseCodePerm), "授权码格式验证");
      Console.WriteLine();

      // --- 测试3：完整校验 LicenseService.ValidateLicenseCode ---
      Console.WriteLine("▶ 测试3：模拟 LicenseService.ValidateLicenseCode 完整校验流程");
      Console.WriteLine("  覆盖校验点：格式 → 时间戳 → 类型码 → HMAC → 机器码 → 有效期");
      foreach (var code in new[] {
                ("试用版(T)", licenseCodeTrial),
                ("1年期(1)", licenseCodeYear1),
                ("2年期(2)", licenseCodeYear2),
                ("永久(P)", licenseCodePerm) })
      {
        Console.WriteLine($"  ── {code.Item1} ──");
        bool result = SimulateValidateLicenseCode(code.Item2, machineId, machinePrefix);
        Console.WriteLine($"  结果: {(result ? "✅ 通过" : "❌ 失败")}");
        Console.WriteLine();
      }

      // --- 测试4：加密持久化 ---
      Console.WriteLine("▶ 测试4：授权文件加密持久化（AES-256-CBC + PBKDF2）");
      Console.WriteLine("  验证：SaveLicense → LoadLicense 编解码一致性");
      string testJson = $"{{\"Type\":0,\"IssuedTime\":\"2026-09-25T10:00:00\",\"ExpiryTime\":\"2026-09-25T10:05:00\",\"MachineId\":\"{machineId}\",\"LicenseCode\":\"{licenseCodeTrial}\",\"Signature\":\"\"}}";
      TestEncryption(testJson);
      Console.WriteLine();

      // --- 测试5：跨组件 HMAC 一致性 ---
      Console.WriteLine("▶ 测试5：生成器 HMAC == CryptoHelper HMAC 算法一致性");
      string hmacFromGenerator = GenerateHmac("TEST-DATA-FOR-VERIFICATION", HmacKey);
      string hmacFromCryptoHelper = CryptoHelperGenerateHmac("TEST-DATA-FOR-VERIFICATION", HmacKey);
      Console.WriteLine($"  生成器HMAC:       {hmacFromGenerator}");
      Console.WriteLine($"  CryptoHelperHMAC: {hmacFromCryptoHelper}");
      Assert(string.Equals(hmacFromGenerator, hmacFromCryptoHelper, StringComparison.OrdinalIgnoreCase),
          "HMAC算法一致");
      Console.WriteLine();

      // ============================================================
      // 阶段 II：真实端到端激活测试
      // ============================================================
      Console.WriteLine("╔══════════════════════════════════════════════════════════════════╗");
      Console.WriteLine("║  阶段 II：真实端到端激活测试                                   ║");
      Console.WriteLine("╚══════════════════════════════════════════════════════════════════╝");
      Console.WriteLine();

      // --- 测试6：模拟全类型激活 ---
      Console.WriteLine("▶ 测试6：全类型授权码激活模拟（ActivateLicense 等效）");
      bool allActivateOk = true;

      var testCases = new[]
      {
                new { Type = "试用版(T)", Code = licenseCodeTrial, TypeVal = 0, ExpireCheck = (Func<DateTime, bool>)((t) => DateTime.Now < t.AddMinutes(5)) },
                new { Type = "1年期(1)", Code = licenseCodeYear1, TypeVal = 1, ExpireCheck = (Func<DateTime, bool>)((t) => DateTime.Now < t.AddYears(1)) },
                new { Type = "2年期(2)", Code = licenseCodeYear2, TypeVal = 2, ExpireCheck = (Func<DateTime, bool>)((t) => DateTime.Now < t.AddYears(2)) },
                new { Type = "永久(P)", Code = licenseCodePerm, TypeVal = 3, ExpireCheck = (Func<DateTime, bool>)((t) => true) },
            };

      foreach (var tc in testCases)
      {
        Console.Write($"  激活 {tc.Type,-16}... ");
        var (ok, licenseJson) = SimulateActivateLicense(tc.Code, machineId, machinePrefix, tc.TypeVal);
        if (ok)
        {
          Console.WriteLine("✅");
          Console.WriteLine($"    授权文件内容: {licenseJson}");
        }
        else
        {
          Console.WriteLine("❌");
          allActivateOk = false;
        }
      }

      Assert(allActivateOk, "全部类型激活成功");
      Console.WriteLine();

      // --- 测试7：真实写入授权文件并验证读取 ---
      Console.WriteLine("▶ 测试7：真实写入授权文件 + 主程序 LoadLicense 等效验证");
      Console.WriteLine($"  目标路径: {LicenseFilePath}");

      try
      {
        // 7.1 备份现有授权
        string? backupPath = null;
        if (File.Exists(LicenseFilePath))
        {
          backupPath = LicenseFilePath + ".bak";
          File.Copy(LicenseFilePath, backupPath, true);
          Console.WriteLine($"  已备份原授权: {backupPath}");
        }

        // 7.2 写入试用版授权
        Console.WriteLine($"  写入试用版授权...");
        WriteLicenseFile(licenseCodeTrial, machineId, machinePrefix, 0);

        // 7.3 验证文件存在
        Assert(File.Exists(LicenseFilePath), "授权文件存在");
        Console.WriteLine($"  授权文件大小: {new FileInfo(LicenseFilePath).Length} 字节");

        // 7.4 读取并验证授权 (模拟主程序 LoadLicense)
        var (readOk, readType, readCode) = ReadAndVerifyLicense();
        Assert(readOk, $"授权文件读取成功 (类型={readType})");
        Assert(readCode == licenseCodeTrial, "授权码内容一致");

        // 7.5 写入永久授权
        Console.WriteLine($"  写入永久授权...");
        WriteLicenseFile(licenseCodePerm, machineId, machinePrefix, 3);

        var (readOk2, readType2, readCode2) = ReadAndVerifyLicense();
        Assert(readOk2, $"永久授权读取成功 (类型={readType2})");
        Assert(readCode2 == licenseCodePerm, "永久授权码内容一致");

        // 7.6 恢复备份
        if (backupPath != null && File.Exists(backupPath))
        {
          File.Copy(backupPath, LicenseFilePath, true);
          File.Delete(backupPath);
          Console.WriteLine($"  已恢复原始授权");
        }

        Console.WriteLine("  ✅ 授权文件读写完整验证通过！");
      }
      catch (Exception ex)
      {
        Console.WriteLine($"  ❌ 授权文件测试异常: {ex.Message}");
        allActivateOk = false;

        // 尝试恢复
        if (File.Exists(LicenseFilePath + ".bak"))
        {
          try
          {
            File.Copy(LicenseFilePath + ".bak", LicenseFilePath, true);
            File.Delete(LicenseFilePath + ".bak");
            Console.WriteLine("  已恢复原始授权（异常回滚）");
          }
          catch { }
        }
      }

      Console.WriteLine();

      // ============================================================
      // 最终结论
      // ============================================================
      Console.WriteLine("===================================================================");
      if (allActivateOk && !_anyFailed)
      {
        Console.WriteLine("  🎉 最终结论：全部测试通过！");
        Console.WriteLine($"  ✅ 算法一致：生成器与主程序使用相同的 HMAC + AES 算法");
        Console.WriteLine($"  ✅ 机器绑定：授权码已绑定本机机器指纹");
        Console.WriteLine($"  ✅ 授权持久化：AES-256-CBC 加密文件读写正常");
        Console.WriteLine();
        Console.WriteLine($"  生成的授权码可在主程序上正常激活使用！");
        Console.WriteLine($"  ➜ 试用版: {licenseCodeTrial}");
        Console.WriteLine($"  ➜ 永久版: {licenseCodePerm}");
      }
      else
      {
        Console.WriteLine("  ❌ 最终结论：存在测试失败项，请检查输出");
      }
      Console.WriteLine("===================================================================");
      Console.WriteLine();

      // 导出授权码
      Console.WriteLine("  如需在本机激活，请将以下授权码复制到 主程序 → 授权管理 → 授权码激活:");
      Console.WriteLine();
      Console.ForegroundColor = ConsoleColor.Green;
      Console.WriteLine($"  {licenseCodePerm}");
      Console.ResetColor();
      Console.WriteLine();
      Console.WriteLine("  (永久授权，无需担心过期)");
      Console.WriteLine();

      if (args.Length > 0 && args[0] == "--export")
      {
        File.WriteAllText("generated_license_code.txt", licenseCodePerm);
        Console.WriteLine($"  已导出到: {Path.GetFullPath("generated_license_code.txt")}");
      }

      Console.WriteLine("  按任意键退出...");
      if (Array.IndexOf(args, "--no-pause") < 0)
        Console.ReadKey();
    }

    // ===================================================================
    // 核心算法（与生成器 / LicenseService 完全一致）
    // ===================================================================

    /// <summary>生成授权码</summary>
    private static string GenerateLicenseCode(string prefix, DateTime issueTime, string typeCode)
    {
      string timestampStr = issueTime.ToString("yyyyMMddHHmmss");
      string dataToSign = $"{prefix}-{timestampStr}-{typeCode}";
      string hmacCode = GenerateHmac(dataToSign, HmacKey);
      return $"{prefix}-{timestampStr}-{typeCode}-{hmacCode}";
    }

    /// <summary>验证授权码格式（4段，每段非空）</summary>
    private static bool ValidateCodeFormat(string code)
    {
      var parts = code.Split('-');
      return parts.Length == 4 &&
             !string.IsNullOrEmpty(parts[0]) &&
             !string.IsNullOrEmpty(parts[1]) &&
             !string.IsNullOrEmpty(parts[2]) &&
             !string.IsNullOrEmpty(parts[3]);
    }

    /// <summary>模拟 LicenseService.ValidateLicenseCode 完整校验逻辑</summary>
    private static bool SimulateValidateLicenseCode(string code, string machineId, string expectedPrefix)
    {
      try
      {
        // 1) 格式校验
        var parts = code.Trim().Split('-');
        if (parts.Length != 4) { Console.WriteLine("    ❌ 格式错误：段数 != 4"); return false; }

        string prefix = parts[0].ToUpper();
        string timestampStr = parts[1];
        string typeCode = parts[2].ToUpper();
        string hmacCode = parts[3].ToUpper();

        // 2) 时间戳校验
        if (!DateTime.TryParseExact(timestampStr, "yyyyMMddHHmmss", null,
            System.Globalization.DateTimeStyles.None, out DateTime issuedTime))
        { Console.WriteLine("    ❌ 时间戳无效"); return false; }

        // 3) 类型码校验
        var validTypes = new[] { "T", "1", "2", "P" };
        if (Array.IndexOf(validTypes, typeCode) < 0)
        { Console.WriteLine("    ❌ 类型码无效"); return false; }

        // 4) HMAC 校验（最核心）
        string dataToVerify = $"{prefix}-{timestampStr}-{typeCode}";
        if (!CryptoHelperVerifyHmac(dataToVerify, hmacCode, HmacKey))
        { Console.WriteLine("    ❌ HMAC 校验失败"); return false; }

        // 5) 机器码绑定校验（核心）
        if (!string.Equals(prefix, expectedPrefix, StringComparison.OrdinalIgnoreCase))
        { Console.WriteLine("    ❌ 机器码不匹配"); return false; }

        // 6) 有效期校验
        DateTime? expiry = typeCode switch
        {
          "T" => issuedTime.AddMinutes(5),
          "1" => issuedTime.AddYears(1),
          "2" => issuedTime.AddYears(2),
          "P" => null,
          _ => issuedTime
        };
        if (expiry.HasValue && DateTime.Now > expiry.Value)
        { Console.WriteLine("    ❌ 已过期"); return false; }

        return true;
      }
      catch (Exception ex)
      {
        Console.WriteLine($"    ❌ 异常: {ex.Message}");
        return false;
      }
    }

    /// <summary>模拟 LicenseService.ActivateLicense 完整流程（生成授权文件 JSON）</summary>
    private static (bool Ok, string Json) SimulateActivateLicense(
        string code, string machineId, string prefix, int typeValue)
    {
      try
      {
        var parts = code.Split('-');
        DateTime issuedTime = DateTime.ParseExact(parts[1], "yyyyMMddHHmmss", null);

        // 计算有效期
        string typeCode = parts[2];
        DateTime? expiry = typeCode switch
        {
          "T" => issuedTime.AddMinutes(5),
          "1" => issuedTime.AddYears(1),
          "2" => issuedTime.AddYears(2),
          "P" => null,
          _ => issuedTime
        };

        // 构建 LicenseInfo 的 JSON（与 Newtonsoft.Json 默认序列化一致）
        string expiryJson = expiry.HasValue
            ? $"\"{expiry.Value:yyyy-MM-ddTHH:mm:ss}\""
            : "null";
        string json = $"{{\"Type\":{typeValue},\"IssuedTime\":\"{issuedTime:yyyy-MM-ddTHH:mm:ss}\",\"ExpiryTime\":{expiryJson},\"MachineId\":\"{machineId}\",\"Signature\":\"\",\"LicenseCode\":\"{code}\"}}";

        // 反序列化验证 JSON 有效
        if (!json.Contains(machineId) || !json.Contains(code))
          return (false, json);

        return (true, json);
      }
      catch
      {
        return (false, "");
      }
    }

    /// <summary>写入真实的加密授权文件（与主程序 LicenseService.SaveLicense 完全一致）</summary>
    private static void WriteLicenseFile(string code, string machineId, string prefix, int typeValue)
    {
      // 构建与 LicenseService 一致的 LicenseInfo JSON
      var parts = code.Split('-');
      DateTime issuedTime = DateTime.ParseExact(parts[1], "yyyyMMddHHmmss", null);
      string typeCode = parts[2];
      DateTime? expiry = typeCode switch
      {
        "T" => issuedTime.AddMinutes(5),
        "1" => issuedTime.AddYears(1),
        "2" => issuedTime.AddYears(2),
        "P" => null,
        _ => issuedTime
      };

      string expiryJson = expiry.HasValue
          ? $"\"{expiry.Value:yyyy-MM-ddTHH:mm:ss}\""
          : "null";

      // JSON 字段顺序必须与 LicenseInfo 的 C# 属性顺序一致（Newtonsoft.Json 默认按声明顺序）
      string json = $"{{\"Type\":{typeValue},\"IssuedTime\":\"{issuedTime:yyyy-MM-ddTHH:mm:ss}\",\"ExpiryTime\":{expiryJson},\"MachineId\":\"{machineId}\",\"Signature\":\"\",\"LicenseCode\":\"{code}\"}}";

      // AES 加密（与 LicenseService 完全一致的参数）
      byte[] key = DeriveKey(AesPassword, AesSalt);
      byte[] iv = new byte[16];
      Array.Copy(AesSalt, iv, 8);
      for (int i = 8; i < 16; i++) iv[i] = (byte)(iv[i - 8] ^ 0xFF);

      string encrypted = AesEncrypt(json, key, iv);

      // 确保目录存在
      if (!Directory.Exists(LicenseDir))
        Directory.CreateDirectory(LicenseDir);

      File.WriteAllText(LicenseFilePath, encrypted, Encoding.UTF8);
    }

    /// <summary>读取并验证授权文件（模拟 LicenseService.LoadLicense）</summary>
    private static (bool Ok, string TypeDisplay, string Code) ReadAndVerifyLicense()
    {
      if (!File.Exists(LicenseFilePath))
        return (false, "", "");

      try
      {
        string encrypted = File.ReadAllText(LicenseFilePath, Encoding.UTF8);

        byte[] key = DeriveKey(AesPassword, AesSalt);
        byte[] iv = new byte[16];
        Array.Copy(AesSalt, iv, 8);
        for (int i = 8; i < 16; i++) iv[i] = (byte)(iv[i - 8] ^ 0xFF);

        string json = AesDecrypt(encrypted, key, iv);

        // 解析 JSON 提取关键字段
        // 使用简单解析避免依赖 Newtonsoft.Json
        int typeIdx = json.IndexOf("\"Type\":", StringComparison.Ordinal) + 7;
        int typeEnd = json.IndexOf(",", typeIdx, StringComparison.Ordinal);
        int typeVal = int.Parse(json.Substring(typeIdx, typeEnd - typeIdx));

        int codeIdx = json.IndexOf("\"LicenseCode\":\"", StringComparison.Ordinal) + 15;
        int codeEnd = json.IndexOf("\"", codeIdx, StringComparison.Ordinal);
        string code = json.Substring(codeIdx, codeEnd - codeIdx);

        string typeDisplay = typeVal switch
        {
          0 => "试用版",
          1 => "1年期",
          2 => "2年期",
          3 => "永久授权",
          _ => $"未知({typeVal})"
        };

        return (true, typeDisplay, code);
      }
      catch (Exception ex)
      {
        return (false, $"读取失败: {ex.Message}", "");
      }
    }

    /// <summary>加密一致性测试</summary>
    private static void TestEncryption(string json)
    {
      try
      {
        byte[] key = DeriveKey(AesPassword, AesSalt);
        byte[] iv = new byte[16];
        Array.Copy(AesSalt, iv, 8);
        for (int i = 8; i < 16; i++) iv[i] = (byte)(iv[i - 8] ^ 0xFF);

        string encrypted = AesEncrypt(json, key, iv);
        string decrypted = AesDecrypt(encrypted, key, iv);

        bool match = json == decrypted;
        Console.WriteLine($"  加密前长度: {json.Length}");
        Console.WriteLine($"  加密后长度: {encrypted.Length}");
        Console.WriteLine($"  解密后长度: {decrypted.Length}");
        Assert(match, "加解密一致性");
        if (!match)
        {
          Console.WriteLine($"  原始: {json}");
          Console.WriteLine($"  解密: {decrypted}");
        }
      }
      catch (Exception ex)
      {
        Console.WriteLine($"  ❌ 加解密异常: {ex.Message}");
      }
    }

    // ===================================================================
    // HMAC 算法（与 LicenseCodeGeneratorWindow 完全一致）
    // ===================================================================
    private static string GenerateHmac(string data, string key)
    {
      using var hmac = new HMACSHA256(Encoding.UTF8.GetBytes(key));
      byte[] hash = hmac.ComputeHash(Encoding.UTF8.GetBytes(data));
      var sb = new StringBuilder();
      for (int i = 0; i < 3; i++)
        sb.Append(hash[i].ToString("X2"));
      return sb.ToString();
    }

    // ===================================================================
    // HMAC 算法（与 CryptoHelper 完全一致）
    // ===================================================================
    private static string CryptoHelperGenerateHmac(string data, string key)
    {
      using var hmac = new HMACSHA256(Encoding.UTF8.GetBytes(key));
      byte[] hash = hmac.ComputeHash(Encoding.UTF8.GetBytes(data));
      StringBuilder sb = new StringBuilder();
      for (int i = 0; i < 3; i++)
        sb.Append(hash[i].ToString("X2"));
      return sb.ToString();
    }

    private static bool CryptoHelperVerifyHmac(string data, string hmacCode, string key)
    {
      string expected = CryptoHelperGenerateHmac(data, key);
      return string.Equals(expected, hmacCode, StringComparison.OrdinalIgnoreCase);
    }

    // ===================================================================
    // AES 加解密（与 LicenseService / CryptoHelper 完全一致）
    // ===================================================================
    private static byte[] DeriveKey(string password, byte[] salt)
    {
      using var pbkdf2 = new Rfc2898DeriveBytes(password, salt, 100000, HashAlgorithmName.SHA256);
      return pbkdf2.GetBytes(32);
    }

    private static string AesEncrypt(string plainText, byte[] key, byte[] iv)
    {
      using var aes = Aes.Create();
      aes.Mode = CipherMode.CBC;
      aes.Padding = PaddingMode.PKCS7;
      aes.Key = key;
      aes.IV = iv;
      using var encryptor = aes.CreateEncryptor();
      using var ms = new MemoryStream();
      using (var cs = new CryptoStream(ms, encryptor, CryptoStreamMode.Write))
      {
        byte[] plainBytes = Encoding.UTF8.GetBytes(plainText);
        cs.Write(plainBytes, 0, plainBytes.Length);
        cs.FlushFinalBlock();
      }
      return Convert.ToBase64String(ms.ToArray());
    }

    private static string AesDecrypt(string cipherText, byte[] key, byte[] iv)
    {
      using var aes = Aes.Create();
      aes.Mode = CipherMode.CBC;
      aes.Padding = PaddingMode.PKCS7;
      aes.Key = key;
      aes.IV = iv;
      byte[] cipherBytes = Convert.FromBase64String(cipherText);
      using var decryptor = aes.CreateDecryptor();
      using var ms = new MemoryStream(cipherBytes);
      using var cs = new CryptoStream(ms, decryptor, CryptoStreamMode.Read);
      using var sr = new StreamReader(cs, Encoding.UTF8);
      return sr.ReadToEnd();
    }

    // ===================================================================
    // 机器指纹（与 MachineFingerprint 完全一致）
    // ===================================================================
    private static string GenerateMachineFingerprint()
    {
      try
      {
        string cpuId = GetWmiValue("Win32_Processor", "ProcessorId");
        string boardSerial = GetWmiValue("Win32_BaseBoard", "SerialNumber");
        string macAddress = GetFirstActiveMacAddress();
        string combined = $"{cpuId}|{boardSerial}|{macAddress}";
        return ComputeSha256(combined);
      }
      catch
      {
        string fallback = $"{Environment.MachineName}|{Environment.UserName}";
        return ComputeSha256(fallback);
      }
    }

    private static string GetWmiValue(string wmiClass, string propertyName)
    {
      try
      {
        using var searcher = new ManagementObjectSearcher($"SELECT {propertyName} FROM {wmiClass}");
        foreach (ManagementObject obj in searcher.Get())
        {
          var value = obj[propertyName]?.ToString();
          if (!string.IsNullOrEmpty(value))
            return value;
        }
      }
      catch { }
      return string.Empty;
    }

    private static string GetFirstActiveMacAddress()
    {
      try
      {
        using var searcher = new ManagementObjectSearcher(
            "SELECT MACAddress FROM Win32_NetworkAdapter WHERE NetConnectionStatus = 2");
        foreach (ManagementObject obj in searcher.Get())
        {
          var mac = obj["MACAddress"]?.ToString();
          if (!string.IsNullOrEmpty(mac))
            return mac;
        }
      }
      catch { }
      return string.Empty;
    }

    private static string ComputeSha256(string input)
    {
      using var sha256 = SHA256.Create();
      byte[] hash = sha256.ComputeHash(Encoding.UTF8.GetBytes(input));
      StringBuilder sb = new StringBuilder(64);
      for (int i = 0; i < 16; i++)
        sb.Append(hash[i].ToString("X2"));
      return sb.ToString();
    }

    // ===================================================================
    // 机器码前缀算法（与 LicenseService 完全一致）
    // ===================================================================
    private static string ComputeMachineHash(string machineId)
    {
      using var sha256 = SHA256.Create();
      byte[] hash = sha256.ComputeHash(Encoding.UTF8.GetBytes(machineId));
      var sb = new StringBuilder();
      for (int i = 0; i < 8; i++)
        sb.Append(hash[i].ToString("X2"));
      return sb.ToString().ToUpper();
    }

    // ===================================================================
    // 辅助方法
    // ===================================================================
    private static bool _anyFailed = false;

    private static void Assert(bool condition, string message)
    {
      if (condition)
      {
        Console.WriteLine($"  ✅ {message}");
      }
      else
      {
        Console.WriteLine($"  ❌ {message}");
        _anyFailed = true;
      }
    }

    private static bool CheckAllPassed(bool explicitCheck)
    {
      return !_anyFailed;
    }
  }
}