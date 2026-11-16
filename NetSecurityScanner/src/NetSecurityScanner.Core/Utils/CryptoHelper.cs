using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace NetSecurityScanner.Utils
{
    public static class CryptoHelper
    {
        public static string SignData(string data, string privateKeyXml)
        {
            using var rsa = RSA.Create();
            rsa.FromXmlString(privateKeyXml);
            byte[] dataBytes = Encoding.UTF8.GetBytes(data);
            byte[] signatureBytes = rsa.SignData(dataBytes, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            return Convert.ToBase64String(signatureBytes);
        }

        public static bool VerifyData(string data, string signature, string publicKeyXml)
        {
            try
            {
                using var rsa = RSA.Create();
                rsa.FromXmlString(publicKeyXml);
                byte[] dataBytes = Encoding.UTF8.GetBytes(data);
                byte[] signatureBytes = Convert.FromBase64String(signature);
                return rsa.VerifyData(dataBytes, signatureBytes, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            }
            catch
            {
                return false;
            }
        }

        public static string AesEncrypt(string plainText, byte[] key, byte[] iv)
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

        public static string AesDecrypt(string cipherText, byte[] key, byte[] iv)
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

        public static byte[] DeriveKey(string password, byte[] salt)
        {
            using var pbkdf2 = new Rfc2898DeriveBytes(password, salt, 100000, HashAlgorithmName.SHA256);
            return pbkdf2.GetBytes(32);
        }

        public static string GenerateHmac(string data, string key)
        {
            using var hmac = new HMACSHA256(Encoding.UTF8.GetBytes(key));
            byte[] hash = hmac.ComputeHash(Encoding.UTF8.GetBytes(data));
            StringBuilder sb = new StringBuilder();
            for (int i = 0; i < 3; i++)
            {
                sb.Append(hash[i].ToString("X2"));
            }
            return sb.ToString();
        }

        public static bool VerifyHmac(string data, string hmacCode, string key)
        {
            string expected = GenerateHmac(data, key);
            return string.Equals(expected, hmacCode, StringComparison.OrdinalIgnoreCase);
        }
    }
}
