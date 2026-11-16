using System;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using NetSecurityScanner.Models;
using NetSecurityScanner.Services;
using NetSecurityScanner.Utils;

class Program
{
    static int Main()
    {
        Console.WriteLine("=== 模拟完整 admin 登录 → 打开待审核窗口 ===\n");

        // 模拟 admin 登录
        var auth = new AuthService();
        var login = auth.LoginAsync("admin", "123456").GetAwaiter().GetResult();
        Console.WriteLine($"[1] admin 登录: IsSuccess={login.IsSuccess} | User={login.User?.Username} | IsAdmin={login.User?.IsAdmin}");

        // 检查 SessionContext
        var session = SessionContext.Instance.Current;
        Console.WriteLine($"[2] SessionContext.Current: Username={session?.Username} | IsAdmin={session?.IsAdmin} | Status={session?.Status}");

        // 模拟 UserApprovalWindow 加载
        Console.WriteLine("\n[3] 调用 _authService.GetPendingUsers()");
        try
        {
            var pending = auth.GetPendingUsers();
            Console.WriteLine($"✅ 返回 {pending.Count} 个待审用户:");
            foreach (var u in pending)
            {
                Console.WriteLine($"   - {u.Username,-25} | Status={u.Status} | IsAdmin={u.IsAdmin} | CreatedAt={u.CreatedAt:HH:mm:ss}");
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"❌ 异常: {ex.GetType().Name}: {ex.Message}");
        }

        // 模拟注册新用户后重新查询
        Console.WriteLine("\n[4] 模拟注册新用户后查询");
        var newAuth = new AuthService();
        var newName = "test_" + DateTime.Now.ToString("HHmmss");
        var regOk = newAuth.RegisterSimpleAsync(newName, "Password123", "测试").GetAwaiter().GetResult();
        Console.WriteLine($"   注册 [{newName}] 返回: {regOk}");

        // 关键：用户场景是 admin 已登录后再注册，注册按钮应该用另一个 auth 实例
        // 但 SessionContext 仍然保留 admin (因为 LoginAsync 设置了它)
        // 但 RegisterAsync 没有 Logout，所以 SessionContext 还是 admin
        Console.WriteLine($"   SessionContext.Current 仍是: {SessionContext.Instance.Current?.Username}");

        // 重新构造一个新 AuthService 来查询 (不重新登录)
        Console.WriteLine("\n[5] 重新构造 AuthService 调用 GetPendingUsers");
        var newAuth2 = new AuthService();
        try
        {
            var pending2 = newAuth2.GetPendingUsers();
            Console.WriteLine($"✅ 返回 {pending2.Count} 个待审用户:");
            foreach (var u in pending2)
            {
                Console.WriteLine($"   - {u.Username,-25} | Status={u.Status} | CreatedAt={u.CreatedAt:HH:mm:ss}");
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"❌ 异常: {ex.GetType().Name}: {ex.Message}");
        }

        return 0;
    }
}
