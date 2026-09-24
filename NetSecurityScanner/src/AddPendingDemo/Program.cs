using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using NetSecurityScanner.Models;
using NetSecurityScanner.Services;

class Program
{
    static async Task Main()
    {
        // 关键：把工作目录切到 Desktop 的 bin 目录，确保读写 users.json 与 WPF 同源
        var desktopBin = Path.GetFullPath(Path.Combine(
            AppContext.BaseDirectory, "..", "..", "..", "..",
            "NetSecurityScanner.Desktop", "bin", "Release", "net6.0-windows"));
        if (Directory.Exists(desktopBin))
        {
            Environment.CurrentDirectory = desktopBin;
            Console.WriteLine($"Desktop bin: {desktopBin}");
        }
        else
        {
            Console.WriteLine($"目标目录不存在: {desktopBin}");
        }

        var auth = new AuthService();
        await auth.EnsureDefaultAdminAsync();

        // 创建几个待审用户（不同用户名、显示名，便于看清）
        var demos = new (string u, string p, string d)[]
        {
            ("alice",   "password123", "Alice Wang"),
            ("bob",     "secret456",   "Bob Lee"),
            ("charlie", "charlie789",  "Charlie Zhang"),
        };

        foreach (var (u, p, d) in demos)
        {
            var existed = auth.GetAllUsers().Any(x => string.Equals(x.Username, u, StringComparison.OrdinalIgnoreCase));
            if (existed)
            {
                Console.WriteLine($"已存在用户 [{u}]，跳过");
                continue;
            }
            var ok = await auth.RegisterSimpleAsync(u, p, d);
            Console.WriteLine($"注册 [{u}] -> {ok}");
        }

        // 列出当前 Pending 用户
        var login = await auth.LoginAsync("admin", "123456");
        if (login.IsSuccess)
        {
            var pending = auth.GetPendingUsers();
            Console.WriteLine($"\n当前待审用户: {pending.Count} 个");
            foreach (var u in pending)
                Console.WriteLine($"  - {u.Username} ({u.DisplayName}) Status={u.Status}");
            auth.Logout();
        }
        else
        {
            Console.WriteLine($"admin 登录失败: {login.Message}");
        }

        // 关键：把 AddPendingDemo/bin 下的 users.json 复制到 Desktop/bin 下
        // 因为 AuthService 写文件用的是 AppDomain.CurrentDomain.BaseDirectory
        var localUsersJson = Path.Combine(AppContext.BaseDirectory, "users.json");
        if (File.Exists(localUsersJson))
        {
            var target = Path.Combine(desktopBin, "users.json");
            File.Copy(localUsersJson, target, overwrite: true);
            Console.WriteLine($"\n✅ 已同步 users.json 到: {target}");
            File.Delete(localUsersJson);
        }
        else
        {
            Console.WriteLine($"\n⚠️ 未找到本地 users.json: {localUsersJson}");
        }
    }
}
