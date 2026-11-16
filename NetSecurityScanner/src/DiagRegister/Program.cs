using System;
using System.IO;
using System.Linq;
using NetSecurityScanner.Models;
using NetSecurityScanner.Services;
using NetSecurityScanner.Utils;

class Program
{
    static int Main()
    {
        Console.WriteLine("=== 模拟 WPF UserApprovalWindow 的数据加载流程 ===\n");
        Console.WriteLine(DataPaths.Describe());
        Console.WriteLine();

        // 1) 模拟 WPF 启动时 Admin 登录
        Console.WriteLine("--- 步骤 1：admin 登录 ---");
        var auth = new AuthService();
        var loginResult = auth.LoginAsync("admin", "123456").GetAwaiter().GetResult();
        Console.WriteLine($"  LoginAsync: IsSuccess={loginResult.IsSuccess} | User={loginResult.User?.Username} | IsAdmin={loginResult.User?.IsAdmin}");

        // 2) 模拟 UserApprovalWindow 加载
        Console.WriteLine("\n--- 步骤 2：UserApprovalWindow.LoadPendingUsers ---");
        try
        {
            var pending = auth.GetPendingUsers();
            Console.WriteLine($"  GetPendingUsers() 返回 {pending.Count} 个用户");
            foreach (var u in pending)
            {
                Console.WriteLine($"    - {u.Username} | Status={u.Status} | IsAdmin={u.IsAdmin} | CreatedAt={u.CreatedAt:HH:mm:ss}");
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"  ❌ 异常: {ex.GetType().Name}: {ex.Message}");
        }

        // 3) 模拟新用户注册
        Console.WriteLine("\n--- 步骤 3：模拟 RegisterWindow 注册新用户 test_new ---");
        auth.Logout();
        var newAuth = new AuthService();
        var regOk = newAuth.RegisterSimpleAsync("test_new_" + DateTime.Now.ToString("HHmmss"), "Password123", "测试新用户").GetAwaiter().GetResult();
        Console.WriteLine($"  RegisterAsync: {regOk}");

        // 4) 重新登录 admin
        Console.WriteLine("\n--- 步骤 4：admin 重新登录 ---");
        var adminAuth = new AuthService();
        var adminLogin = adminAuth.LoginAsync("admin", "123456").GetAwaiter().GetResult();
        Console.WriteLine($"  LoginAsync: IsSuccess={adminLogin.IsSuccess}");

        // 5) 重新加载待审列表
        Console.WriteLine("\n--- 步骤 5：再次 LoadPendingUsers ---");
        var pending2 = adminAuth.GetPendingUsers();
        Console.WriteLine($"  GetPendingUsers() 返回 {pending2.Count} 个用户");
        foreach (var u in pending2)
        {
            Console.WriteLine($"    - {u.Username} | Status={u.Status} | IsAdmin={u.IsAdmin} | CreatedAt={u.CreatedAt:HH:mm:ss}");
        }

        // 6) 验证文件落盘
        Console.WriteLine("\n--- 步骤 6：验证文件内容 ---");
        var json = File.ReadAllText(DataPaths.UsersFile);
        var store = System.Text.Json.JsonSerializer.Deserialize<UserStore>(json);
        Console.WriteLine($"  文件路径: {DataPaths.UsersFile}");
        Console.WriteLine($"  文件大小: {json.Length} 字节");
        Console.WriteLine($"  文件中用户数: {store.Users.Count}");
        foreach (var u in store.Users)
        {
            Console.WriteLine($"    - {u.Username} | Status={u.Status} | IsAdmin={u.IsAdmin}");
        }

        return 0;
    }
}
