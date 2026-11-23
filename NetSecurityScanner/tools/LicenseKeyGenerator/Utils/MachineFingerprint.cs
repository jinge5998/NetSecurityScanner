using System;
using System.IO;
using System.Management;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace NetSecurityScanner.Utils
{
  public static class MachineFingerprint
  {
    // 缓存文件放在程序基目录：命中缓存时完全不触发 WMI。
    // 深度测试发现：在部分 Windows 环境（如远程桌面/精简版系统）WMI 查询会挂起数十秒甚至永久阻塞，
    // 导致生成器停在读取本机指纹阶段、界面无法打开。缓存 + 超时 + 注册表回退三者共同规避该问题。
    private static readonly string CacheFile = Path.Combine(
        AppDomain.CurrentDomain.BaseDirectory, ".machine_id");
    private const int WmiTimeoutMs = 1500;

    public static string Generate()
    {
      // 1) 缓存优先（最快，且不触碰 WMI）
      string cached = ReadCache();
      if (!string.IsNullOrEmpty(cached))
        return cached;

      // 2) 尝试 WMI 硬件指纹，但带超时保护（WMI 挂起时不能拖死启动）
      string machineCode = string.Empty;
      try
      {
        machineCode = GenerateWithTimeout();
      }
      catch { }

      // 3) WMI 失败/超时 → 注册表 + 环境变量组合（不依赖 WMI）
      if (string.IsNullOrEmpty(machineCode))
        machineCode = GenerateFromRegistry();

      WriteCache(machineCode);
      return machineCode;
    }

    private static string GenerateWithTimeout()
    {
      string result = string.Empty;
      var task = Task.Run(() =>
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
          return string.Empty;
        }
      });
      if (task.Wait(TimeSpan.FromMilliseconds(WmiTimeoutMs)))
        result = task.Result;
      // 超时则不等待后台任务（该任务会自然结束在线程池，不阻塞 UI）
      return result ?? string.Empty;
    }

    private static string GenerateFromRegistry()
    {
      try
      {
        string productId = Microsoft.Win32.Registry.GetValue(
            @"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion",
            "ProductId", string.Empty)?.ToString() ?? string.Empty;
        string installDate = Microsoft.Win32.Registry.GetValue(
            @"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion",
            "InstallDate", string.Empty)?.ToString() ?? string.Empty;
        string fallback = $"{Environment.MachineName}|{Environment.UserName}|{productId}|{installDate}";
        return ComputeSha256(fallback);
      }
      catch
      {
        return ComputeSha256($"{Environment.MachineName}|{Environment.UserName}");
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
            return value.Trim();
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
