using System;
using System.IO;
using System.Management;
using System.Security.Cryptography;
using System.Text;

namespace NetSecurityScanner.Utils
{
  public static class MachineFingerprint
  {
    private static readonly string CacheFile = Path.Combine(
        AppDomain.CurrentDomain.BaseDirectory, ".machine_id");

    public static string Generate()
    {
      string cached = ReadCache();
      if (!string.IsNullOrEmpty(cached))
        return cached;

      string machineCode = GenerateFromHardware();
      WriteCache(machineCode);
      return machineCode;
    }

    private static string GenerateFromHardware()
    {
      try
      {
        string cpuId = GetWmiValue("Win32_Processor", "ProcessorId");
        string boardSerial = GetWmiValue("Win32_BaseBoard", "SerialNumber");
        string biosUuid = GetWmiValue("Win32_ComputerSystemProduct", "UUID");

        if (string.IsNullOrEmpty(biosUuid) || biosUuid == "FFFFFFFF-FFFF-FFFF-FFFF-FFFFFFFFFFFF"
            || biosUuid == "03000200-0400-0500-0006-000700080009")
        {
          biosUuid = GetWmiValue("Win32_BIOS", "SMBIOSBIOSUUID");
        }

        string combined = $"{cpuId}|{boardSerial}|{biosUuid}";
        return ComputeSha256(combined);
      }
      catch
      {
        return ComputeSha256(Environment.MachineName);
      }
    }

    private static string GetWmiValue(string wmiClass, string propertyName)
    {
      try
      {
        using var searcher = new ManagementObjectSearcher(
            $"SELECT {propertyName} FROM {wmiClass}");
        foreach (ManagementObject obj in searcher.Get())
        {
          var value = obj[propertyName]?.ToString();
          if (!string.IsNullOrEmpty(value))
            return value.Trim();
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

    private static string ReadCache()
    {
      try
      {
        if (File.Exists(CacheFile))
        {
          string cached = File.ReadAllText(CacheFile).Trim();
          if (cached.Length == 32)
            return cached;
        }
      }
      catch { }
      return null;
    }

    private static void WriteCache(string machineCode)
    {
      try
      {
        File.WriteAllText(CacheFile, machineCode);
        File.SetAttributes(CacheFile,
            FileAttributes.Hidden | FileAttributes.System | FileAttributes.NotContentIndexed);
      }
      catch { }
    }

    public static string Regenerate()
    {
      try
      {
        if (File.Exists(CacheFile))
          File.Delete(CacheFile);
      }
      catch { }
      return Generate();
    }
  }
}