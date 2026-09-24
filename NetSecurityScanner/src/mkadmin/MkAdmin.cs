using System;
using System.IO;
using System.Security.Cryptography;
using System.Text.Json;

class MkAdmin
{
    static void Main()
    {
        var pw = "123456";
        var salt = new byte[16];
        using (var rng = RandomNumberGenerator.Create()) rng.GetBytes(salt);
        var saltB64 = Convert.ToBase64String(salt);
        var hash = DeriveKey(pw, salt);
        var hashB64 = Convert.ToBase64String(hash);

        var user = new {
            Id = Guid.NewGuid().ToString(),
            Username = "admin",
            DisplayName = "管理员",
            PasswordHash = hashB64,
            Salt = saltB64,
            CreatedAt = DateTime.Now,
            LastLoginAt = (DateTime?)null,
            FailedAttempts = 0,
            LockoutUntil = (DateTime?)null
        };

        var store = new { Users = new[] { user } };
        var json = JsonSerializer.Serialize(store, new JsonSerializerOptions { WriteIndented = true });
        var path = Path.Combine(AppContext.BaseDirectory, "users.json");
        File.WriteAllText(path, json);
        Console.WriteLine("admin 账号已创建！密码: 123456");
        Console.WriteLine("路径: " + path);
    }

    static byte[] DeriveKey(string password, byte[] salt)
    {
        using var pbkdf2 = new Rfc2898DeriveBytes(password, salt, 100000, HashAlgorithmName.SHA256);
        return pbkdf2.GetBytes(32);
    }
}
