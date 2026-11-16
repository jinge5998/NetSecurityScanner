using System;
using System.Management;
using System.Security.Cryptography;
using System.Text;

namespace NetSecurityScanner.Utils
{
    public static class MachineFingerprint
    {
        public static string Generate()
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
                using var searcher = new ManagementObjectSearcher("SELECT MACAddress FROM Win32_NetworkAdapter WHERE NetConnectionStatus = 2");
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
            {
                sb.Append(hash[i].ToString("X2"));
            }
            return sb.ToString();
        }
    }
}
