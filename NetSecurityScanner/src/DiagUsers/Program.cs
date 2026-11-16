using System;
using System.IO;
using System.Threading.Tasks;
using System.Text.Json;
using NetSecurityScanner.Models;
using NetSecurityScanner.Services;

class Diag
{
    static async Task Main()
    {
        try
        {
            var auth = new AuthService();
            await auth.EnsureDefaultAdminAsync();
            Console.WriteLine($"[1] EnsureDefaultAdmin OK");

            // 复制一份 StoreSnapshot，看注册前后的差异
            int beforeCount = auth.GetAllUsers().Count;
            Console.WriteLine($"[2] 注册前用户数 = {beforeCount}");

            var ok = await auth.RegisterSimpleAsync("diagtest1", "password123", "Diag Test 1");
            Console.WriteLine($"[3] RegisterAsync 返回 = {ok}");

            int afterCount = auth.GetAllUsers().Count;
            Console.WriteLine($"[4] 注册后内存中用户数 = {afterCount}");

            // 关键：直接看文件
            var path = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "users.json");
            Console.WriteLine($"[5] _usersFilePath = {path}");
            Console.WriteLine($"[6] 文件存在 = {File.Exists(path)}");
            var content = await File.ReadAllTextAsync(path);
            Console.WriteLine($"[7] 文件大小 = {content.Length}");
            Console.WriteLine($"[8] 文件含 diagtest1 = {content.Contains("diagtest1")}");

            // 尝试自己再写一次测试
            try
            {
                await File.WriteAllTextAsync(path, content + "\n/* DIAG TEST */");
                Console.WriteLine($"[9] 手动追加写成功");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[9] 手动追加写失败: {ex.GetType().Name}: {ex.Message}");
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[异常] {ex.GetType().Name}: {ex.Message}");
            Console.WriteLine($"[Stack] {ex.StackTrace}");
            if (ex.InnerException != null)
                Console.WriteLine($"[Inner] {ex.InnerException.Message}");
        }
    }
}
