using System;
using System.IO;
using System.Management;
using System.Security.Cryptography;
using System.Text;

namespace NetSecurityScanner.Test
{
  /// <summary>
  /// 快速写入授权文件（无交互、无测试输出）
  /// 用法: dotnet run --project tools/LicenseFlowTest -- --write-permanent
  /// </summary>
  class WriteLicense
  {
    private static readonly string HmacKey = "NSS2026Hmac!@#Lic";
    private static readonly string AesPassword = "NSS2026LicKey!@#";
    private static readonly byte[] AesSalt = { 0x4E, 0x53, 0x53, 0x4C, 0x69, 0x63, 0x32, 0x30 };

    static void Main(string[] args)
    {
      if (args.Length > 0 && args[0] == "--write-permanent")
      {
        WritePermanentLicense();
      }
      else if (args.Length > 0 && args[0] == "--write-trial")
      {
        WriteTrialLicense();
      }
      else
      {
        Console.WriteLine("用法: --write-permanent | --write-trial");
      }
    }

    static void WritePermanentLicense()
    {
      string machineId = GenerateMachineFingerprint();
      string prefix = ComputeMachineHash(machineId);
      string code = GenerateLicenseCode(prefix, DateTime.Now, "P");
      WriteLicenseFile(code, machineId, prefix, 3);
      Console.WriteLine($"✅ 已写入永久授权");
      Console.WriteLine($"授权码: {code}");
    }

    static void WriteTrialLicense()
    {
      string machineId = GenerateMachineFingerprint();
      string prefix = ComputeMachineHash(machineId);
      string code = GenerateLicenseCode(prefix, DateTime.Now, "T");
      WriteLicenseFile(code, machineId, prefix, 0);
      Console.WriteLine($"✅ 已写入试用版授权（5分钟）");
      Console.WriteLine($"授权码: {code}");
    }

    static string GenerateLicenseCode(string prefix, DateTime issueTime, string typeCode)
    {
      string timestampStr = issueTime.ToString("yyyyMMddHHmmss");
      string dataToSign = $"{prefix}-{timestampStr}-{typeCode}";
      string hmacCode = GenerateHmac(dataToSign, HmacKey);
      return $"{prefix}-{timestampStr}-{typeCode}-{hmacCode}";
    }

    static string ComputeMachineHash(string machineId)
    {
      using var sha256 = SHA256.Create();
      byte[] hash = sha256.ComputeHash(Encoding.UTF8.GetBytes(machineId));
      var sb = new StringBuilder();
      for (int i = 0; i < 8; i++)
        sb.Append(hash[i].ToString("X2"));
      return sb.ToString().ToUpper();
    }

    static string GenerateHmac(string data, string key)
    {
      using var hmac = new HMACSHA256(Encoding.UTF8.GetBytes(key));
      byte[] hash = hmac.ComputeHash(Encoding.UTF8.GetBytes(data));
      var sb = new StringBuilder();
      for (int i = 0; i < 3; i++)
        sb.Append(hash[i].ToString("X2"));
      return sb.ToString();
    }

    static void WriteLicenseFile(string code, string machineId, string prefix, int typeValue)
    {
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

      string json = $"{{\"Type\":{typeValue},\"IssuedTime\":\"{issuedTime:yyyy-MM-ddTHH:mm:ss}\",\"ExpiryTime\":{expiryJson},\"MachineId\":\"{machineId}\",\"Signature\":\"\",\"LicenseCode\":\"{code}\"}}";

      byte[] key = DeriveKey(AesPassword, AesSalt);
      byte[] iv = new byte[16];
      Array.Copy(AesSalt, iv, 8);
      for (int i = 8; i < 16; i++) iv[i] = (byte)(iv[i - 8] ^ 0xFF);

      string encrypted = AesEncrypt(json, key, iv);

      string licenseDir = Path.Combine(
          Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
          "NetSecurityScanner", "license");
      string licenseFilePath = Path.Combine(licenseDir, "license.dat");

      if (!Directory.Exists(licenseDir))
        Directory.CreateDirectory(licenseDir);

      File.WriteAllText(licenseFilePath, encrypted, Encoding.UTF8);
    }

    static byte[] DeriveKey(string password, byte[] salt)
    {
      using var pbkdf2 = new Rfc2898DeriveBytes(password, salt, 100000, HashAlgorithmName.SHA256);
      return pbkdf2.GetBytes(32);
    }

    static string AesEncrypt(string plainText, byte[] key, byte[] iv)
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

    static string GenerateMachineFingerprint()
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

    static string GetWmiValue(string wmiClass, string propertyName)
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

    static string GetFirstActiveMacAddress()
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

    static string ComputeSha256(string input)
    {
      using var sha256 = SHA256.Create();
      byte[] hash = sha256.ComputeHash(Encoding.UTF8.GetBytes(input));
      StringBuilder sb = new StringBuilder(64);
      for (int i = 0; i < 16; i++)
        sb.Append(hash[i].ToString("X2"));
      return sb.ToString();
    }
  }
}