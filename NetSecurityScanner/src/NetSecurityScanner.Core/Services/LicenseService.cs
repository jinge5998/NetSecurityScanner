using System;
using System.IO;
using System.Text;
using System.Globalization;
using Newtonsoft.Json;
using NetSecurityScanner.Models;
using NetSecurityScanner.Utils;

namespace NetSecurityScanner.Services
{
    public class LicenseService
    {
        private readonly string _licenseDirectory;
        private readonly string _licenseFilePath;
        private static readonly string _aesPassword = "NSS2026LicKey!@#";
        private static readonly byte[] _aesSalt = { 0x4E, 0x53, 0x53, 0x4C, 0x69, 0x63, 0x32, 0x30 };
        private static readonly string _hmacKey = "NSS2026Hmac!@#Lic";
        private const string PublicKeyXml = "<RSAKeyValue><Modulus>xLb4Z7t6d/jwQl/wby9+qVznmdB5nELC6yJxAzRZfKA6/nCcan0DV+PFFEsQTSpPvDiA124VzsPEcJwbZMnOon2NgoEUD3hQWOPq+qnOgEO9yrmV1enOVM9wdLHgkC6dq2c13tryf109LAtiHj0f58dvyuu6QkjH8b5MYG3q2FEZgnvm9cajSnY9P6DfD1OTalfkgGWTO7+CVJCWfE4IOD69t3bpC1nWgmIOoz7AVDjhg6/BO6ixHG/kkkgnpLi5noutxhYOjDZWu3umDfOODQ34EYZlgsAL4HlJwMpqBX+Iw33pbpBrn3/1lI7eQJT8e7U4HJXLefI0QMMiOu0qnQ==</Modulus><Exponent>AQAB</Exponent></RSAKeyValue>";

        public LicenseService()
        {
            _licenseDirectory = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                "NetSecurityScanner", "license");
            _licenseFilePath = Path.Combine(_licenseDirectory, "license.dat");
        }

        public LicenseStatus GetLicenseStatus()
        {
            var status = new LicenseStatus
            {
                MachineId = GetCurrentMachineId()
            };

            try
            {
                var license = LoadLicense();
                if (license != null)
                {
                    string currentMachineId = GetCurrentMachineId();
                    string expectedHash = ComputeMachineHash(currentMachineId);

                    if (!string.IsNullOrEmpty(license.MachineId) && license.MachineId != currentMachineId)
                    {
                        status.IsLicensed = false;
                        status.IsExpired = false;
                        status.StatusText = "授权码已锁定到其他机器";
                        return status;
                    }

                    status.LicenseInfo = license;
                    status.IsLicensed = !license.IsExpired;
                    status.IsExpired = license.IsExpired;
                    status.StatusText = license.IsExpired
                        ? $"授权已过期（{license.DisplayName}）"
                        : $"已授权（{license.DisplayName}）";
                }
            }
            catch
            {
                status.StatusText = "授权信息读取失败";
            }

            return status;
        }

        public bool ActivateLicense(string licenseCode)
        {
            if (!ValidateLicenseCode(licenseCode, out var licenseInfo, out var errorMessage))
                return false;

            SaveLicense(licenseInfo!);
            return true;
        }

        public bool IsLicensed()
        {
            var status = GetLicenseStatus();
            return status.IsLicensed;
        }

        public void SaveLicense(LicenseInfo license)
        {
            try
            {
                if (!Directory.Exists(_licenseDirectory))
                    Directory.CreateDirectory(_licenseDirectory);

                string json = JsonConvert.SerializeObject(license);
                byte[] key = CryptoHelper.DeriveKey(_aesPassword, _aesSalt);
                byte[] iv = new byte[16];
                Array.Copy(_aesSalt, iv, 8);
                for (int i = 8; i < 16; i++) iv[i] = (byte)(iv[i - 8] ^ 0xFF);

                string encrypted = CryptoHelper.AesEncrypt(json, key, iv);
                File.WriteAllText(_licenseFilePath, encrypted, Encoding.UTF8);
            }
            catch (Exception ex)
            {
                throw new Exception($"保存授权文件失败: {ex.Message}", ex);
            }
        }

        public LicenseInfo? LoadLicense()
        {
            if (!File.Exists(_licenseFilePath))
                return null;

            string encrypted = File.ReadAllText(_licenseFilePath, Encoding.UTF8);
            byte[] key = CryptoHelper.DeriveKey(_aesPassword, _aesSalt);
            byte[] iv = new byte[16];
            Array.Copy(_aesSalt, iv, 8);
            for (int i = 8; i < 16; i++) iv[i] = (byte)(iv[i - 8] ^ 0xFF);

            string json = CryptoHelper.AesDecrypt(encrypted, key, iv);
            return JsonConvert.DeserializeObject<LicenseInfo>(json);
        }

        public string GetCurrentMachineId()
        {
            return MachineFingerprint.Generate();
        }

        public bool ValidateLicenseCode(string code, out LicenseInfo? licenseInfo, out string errorMessage)
        {
            licenseInfo = null;
            errorMessage = string.Empty;

            try
            {
                var parts = code.Trim().Split('-');
                if (parts.Length != 4)
                {
                    errorMessage = "授权码格式无效（应为4段以-分隔）";
                    return false;
                }

                string machineIdPrefix = parts[0].ToUpper();
                string timestampStr = parts[1];
                string typeCode = parts[2].ToUpper();
                string hmacCode = parts[3].ToUpper();

                if (!DateTime.TryParseExact(timestampStr, "yyyyMMddHHmmss", null,
                    DateTimeStyles.None, out DateTime issuedTime))
                {
                    errorMessage = "授权码时间戳无效";
                    return false;
                }

                LicenseType licenseType;
                try
                {
                    licenseType = LicenseInfo.CodeToType(typeCode);
                }
                catch
                {
                    errorMessage = "授权类型码无效（应为T/1/2/P）";
                    return false;
                }

                string dataToVerify = $"{machineIdPrefix}-{timestampStr}-{typeCode}";
                if (!CryptoHelper.VerifyHmac(dataToVerify, hmacCode, _hmacKey))
                {
                    errorMessage = "授权码校验失败";
                    return false;
                }

                string currentMachineId = GetCurrentMachineId();
                if (string.IsNullOrEmpty(machineIdPrefix) || machineIdPrefix.Length < 8)
                {
                    errorMessage = "授权码无效：未绑定机器";
                    return false;
                }

                string expectedHash = ComputeMachineHash(currentMachineId);
                if (!string.Equals(machineIdPrefix, expectedHash, StringComparison.OrdinalIgnoreCase))
                {
                    errorMessage = "授权码与当前机器不匹配（一机一码）";
                    return false;
                }

                DateTime? expiryTime = licenseType switch
                {
                    LicenseType.TRIAL => issuedTime.AddMinutes(5),
                    LicenseType.YEAR1 => issuedTime.AddYears(1),
                    LicenseType.YEAR2 => issuedTime.AddYears(2),
                    LicenseType.PERMANENT => null,
                    _ => issuedTime
                };

                licenseInfo = new LicenseInfo
                {
                    Type = licenseType,
                    IssuedTime = issuedTime,
                    ExpiryTime = expiryTime,
                    MachineId = currentMachineId,
                    LicenseCode = code.Trim()
                };

                return true;
            }
            catch (Exception ex)
            {
                errorMessage = $"授权码验证异常：{ex.Message}";
                return false;
            }
        }

        private class LicenseCodeData
        {
            [JsonProperty("payload")]
            public string Payload { get; set; } = string.Empty;

            [JsonProperty("signature")]
            public string Signature { get; set; } = string.Empty;
        }

        private static string ComputeMachineHash(string machineId)
        {
            using var sha256 = System.Security.Cryptography.SHA256.Create();
            byte[] hash = sha256.ComputeHash(Encoding.UTF8.GetBytes(machineId));
            var sb = new StringBuilder();
            for (int i = 0; i < 8; i++)
            {
                sb.Append(hash[i].ToString("X2"));
            }
            return sb.ToString().ToUpper();
        }
    }
}
