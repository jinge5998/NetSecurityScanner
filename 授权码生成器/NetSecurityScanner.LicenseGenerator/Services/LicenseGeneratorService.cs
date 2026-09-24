using System;
using System.Text;
using Newtonsoft.Json;
using NetSecurityScanner.LicenseGenerator.Models;
using NetSecurityScanner.LicenseGenerator.Utils;

namespace NetSecurityScanner.LicenseGenerator.Services
{
    public class LicenseGeneratorService
    {
        private static readonly string _aesPassword = "NSS2026LicKey!@#";
        private static readonly byte[] _aesSalt = { 0x4E, 0x53, 0x53, 0x4C, 0x69, 0x63, 0x32, 0x30 };
        private static readonly string _hmacKey = "NSS2026Hmac!@#Lic";
        private const string PrivateKeyXml = "<RSAKeyValue><Modulus>xLb4Z7t6d/jwQl/wby9+qVznmdB5nELC6yJxAzRZfKA6/nCcan0DV+PFFEsQTSpPvDiA124VzsPEcJwbZMnOon2NgoEUD3hQWOPq+qnOgEO9yrmV1enOVM9wdLHgkC6dq2c13tryf109LAtiHj0f58dvyuu6QkjH8b5MYG3q2FEZgnvm9cajSnY9P6DfD1OTalfkgGWTO7+CVJCWfE4IOD69t3bpC1nWgmIOoz7AVDjhg6/BO6ixHG/kkkgnpLi5noutxhYOjDZWu3umDfOODQ34EYZlgsAL4HlJwMpqBX+Iw33pbpBrn3/1lI7eQJT8e7U4HJXLefI0QMMiOu0qnQ==</Modulus><Exponent>AQAB</Exponent><P>+9dcN+70Pq1KaLL9scc/UQGjYNovM6X3eEaaybK6QNjEgx+MhZnAEd1lYkbXd8HEYcW0ZM9rHkxicv/KdQKbIAiR9KbylFcTXJQxDkLkzgxL2UbcCLp+hDkQEzob72wCTLebK0H8FiHaxmFstZ4l6hkh5ZhYpsGckOywjwI8xpc=</P><Q>x/aRITHLgKgTs3dcSSD2jN9X0JFXo5V9goNOZwzPz4TGWBm35Q4NQv+X3JYEB7sIzAJxOFp1qkVKNGsafJh86JvIV05y1KdcKGKpJJQHrh8RimyY37c4m3yu9WILhAGIXddcrZtFjuabrZ+9y8QXurDmK8O4BRfdIJWzzEn90us=</Q><DP>fzqkvyk8QXHglpZernK/nRgbxvFTSV9+b0gUKPPfPqWEWc4VeuVa8GuOLaEmd7zvjomIAin7rtneHsT1Ljn7zqolupihEqoPAQVo5xCKcUIrC4DN5qb5BamiYmRH+qPxYXqcrLTwOuotkW1kszhLZUH/KvPVTaGgjGLXK9hwhc8=</DP><DQ>B++gOOoKApQpHAFLt1dIkbS3fn6WNNbVAV4GuY5HnRvO52Y15zBUlGkidM27YTcqFTavmaX1b4mKdWQey/0dT/oGzHg/lHMD9FJeFiaN23o+Lvk6Y/6Yj4s2QmTewiFxcRAADJ/R9ebvHMfvN2wT6QPmTqxY3FLjIszuMtho63s=</DQ><InverseQ>ImQ713hUyPrlIwEL0VVBHkwxko9GAXr7p8QeDnEnpynnUQa7hg9arTf3PHSG9l5rVhPvIIRyZygYIvAOdE5xX0JD92P5KCjTBx3VgLE2bcc1EI+FshMjrp17giKHhzkOm+f8FP48V10EmF3DAnSWhIypyjuhkuz7c/e8VOjmvqY=</InverseQ><D>wgpSQdCW35z5Mh/8xVAuOtXfxsP0EYVxTAuvOp/63YoYZz+hqxEhqSKOFpRswhFIkbuSq+51KH3HWeVCyEqgv3vliKPWq+PcLbK06QlzHuazYjNqb5Wv58yvewyzHMY+1QJ8CxYiOiw42SdpY7absD/0MFASbKvqPrWeFUiXbUPkoLQ1h7rCRdPFXn2NNGCD37lHFQEYpZje1pCFNIyCAoOKmT0pmvzQLduhcGobXeNpaUa8iaWN5sLrodylQx31NPZdLEPzKkTCSpmPUupwYxWRZLEPkywf+Y28EG2HnSD3xwuvcAYqsnW4ETHgwZmacTMBlMo8BkiZfztyM6aEqQ==</D></RSAKeyValue>";

        public static string GenerateLicenseCode(string licenseType, string machineId)
        {
            if (string.IsNullOrWhiteSpace(machineId))
                throw new ArgumentException("机器码不能为空，必须绑定机器");

            string typeCode = licenseType switch
            {
                "TRIAL" => "T",
                "YEAR1" => "1",
                "YEAR2" => "2",
                "PERMANENT" => "P",
                _ => "T"
            };

            string machineIdHash = ComputeMachineHash(machineId);
            string timestamp = DateTime.UtcNow.ToString("yyyyMMddHHmmss");

            string dataToSign = $"{machineIdHash}-{timestamp}-{typeCode}";
            string hmacCode = CryptoHelper.GenerateHmac(dataToSign, _hmacKey);

            return $"{machineIdHash}-{timestamp}-{typeCode}-{hmacCode}";
        }

        private static string ComputeMachineHash(string machineId)
        {
            using var sha256 = System.Security.Cryptography.SHA256.Create();
            byte[] hash = sha256.ComputeHash(System.Text.Encoding.UTF8.GetBytes(machineId));
            var sb = new System.Text.StringBuilder();
            for (int i = 0; i < 8; i++)
            {
                sb.Append(hash[i].ToString("X2"));
            }
            return sb.ToString().ToUpper();
        }

        private class LicenseCodeData
        {
            [JsonProperty("payload")]
            public string Payload { get; set; } = string.Empty;

            [JsonProperty("signature")]
            public string Signature { get; set; } = string.Empty;
        }
    }
}
