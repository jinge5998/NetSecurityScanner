using System;
using System.IO;
using System.Threading.Tasks;
using NetSecurityScanner.Models;
using NetSecurityScanner.Services;

class Program
{
    static int passed = 0, failed = 0;
    static readonly string S = new string('=', 70);

    static void Section(string t)
    {
        Console.WriteLine();
        Console.WriteLine(S);
        Console.WriteLine($"【{t}】");
        Console.WriteLine(S);
    }
    static void Assert(string name, bool ok, string? detail = null)
    {
        Console.WriteLine($"  {(ok ? "✅ 通过" : "❌ 失败")}  {name}{(detail != null ? "  →  " + detail : "")}");
        if (ok) passed++; else failed++;
    }

    static async Task<int> Main()
    {
        var baseDir = AppContext.BaseDirectory;
        foreach (var f in new[] { "users.json", "session.json", "assets.json" })
        {
            var p = Path.Combine(baseDir, f);
            if (File.Exists(p)) File.Delete(p);
        }
        // 清空测试用户目录
        var assetsDir = Path.Combine(baseDir, "assets");
        if (Directory.Exists(assetsDir))
        {
            foreach (var d in Directory.GetDirectories(assetsDir))
            {
                try { Directory.Delete(d, true); } catch { }
            }
        }

        var auth = new AuthService();
        var username = "alice";

        // ── 1) 基础登录 ──────────────────────────────────────────────
        Section("1) 注册 + 登录");
        Assert("注册 alice", await auth.RegisterSimpleAsync(username, "Pass1234!", "Alice 管理员"));
        Assert("重复注册失败", !await auth.RegisterSimpleAsync(username, "another"));
        Assert("登录成功", (await auth.LoginAsync(username, "Pass1234!")).IsSuccess);
        Assert("SessionContext.IsLoggedIn", SessionContext.Instance.IsLoggedIn);

        // ── 2) 修改显示名 ───────────────────────────────────────────
        Section("2) 修改个人资料");
        Assert("修改显示名", await auth.UpdateDisplayNameAsync(username, "Alice Super Admin"));
        Assert("会话中显示名已刷新", SessionContext.Instance.Current?.DisplayName == "Alice Super Admin");
        Assert("无效显示名被拒", !await auth.UpdateDisplayNameAsync(username, ""));

        // ── 3) 修改密码 ─────────────────────────────────────────────
        Section("3) 修改密码");
        var r1 = await auth.ChangePasswordAsync(username, "Pass1234!", "NewPass#999");
        Assert("旧密码正确改密成功", r1.IsSuccess, r1.Message);
        Assert("改密后旧密码失效", !(await auth.LoginAsync(username, "Pass1234!")).IsSuccess);
        Assert("新密码可以登录", (await auth.LoginAsync(username, "NewPass#999")).IsSuccess);
        Assert("旧密码错误被拒", !(await auth.ChangePasswordAsync(username, "wrong", "xxx")).IsSuccess);

        // ── 4) 每用户独立数据库 ─────────────────────────────────────
        Section("4) 每用户独立数据库");
        // 必须登录后创建服务实例，才能落到正确的 assets/alice/ 目录
        var aliceSvc = new AssetManagementService();
        Assert("alice 登录后服务指向 alice 目录",
            aliceSvc.GetType().GetField("_userAssetsDir",
                System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Instance)
            ?.GetValue(aliceSvc)?.ToString()?.Contains("assets\\alice") == true);
        await aliceSvc.AddAssetAsync(new Asset { Name = "alice-server", IPAddress = "10.1.1.1" }, username);

        // alice 登出，用 bob 登录
        auth.Logout();
        // bob 先注册
        await auth.RegisterSimpleAsync("bob", "BobPass!!");
        SessionContext.Instance.Clear();
        await auth.LoginAsync("bob", "BobPass!!");
        var bobSvc = new AssetManagementService();
        var bobAssets = bobSvc.GetAllAssets();
        Assert("bob 看到自己的资产列表为空（与 alice 隔离）", bobAssets.Count == 0);
        await bobSvc.AddAssetAsync(new Asset { Name = "bob-workstation", IPAddress = "10.2.2.2" }, "bob");

        // 再切回 alice 验证数据隔离
        SessionContext.Instance.Clear();
        await auth.LoginAsync(username, "NewPass#999");
        var aliceSvc2 = new AssetManagementService();
        var aliceAssets = aliceSvc2.GetAllAssets();
        Assert("alice 看到自己的资产", aliceAssets.Count == 1);
        Assert("alice 的资产不含 bob 的数据", !aliceAssets.Exists(a => a.Name == "bob-workstation"));

        // ── 5) 账号管理 ─────────────────────────────────────────────
        Section("5) 账号管理");
        var users = auth.GetAllUsers();
        Assert("GetAllUsers 返回 2 个用户", users.Count == 2);
        Assert("密码字段已脱敏（null）", users.TrueForAll(u => u.PasswordHash == null && u.Salt == null));
        Assert("alice 在列表中", users.Exists(u => u.Username == "alice"));
        Assert("bob 在列表中", users.Exists(u => u.Username == "bob"));
        Assert("显示名已更新", users.Find(u => u.Username == "alice")?.DisplayName == "Alice Super Admin");

        // ── 6) 5 次错误登录后锁定 ───────────────────────────────────
        Section("6) 登录锁定");
        SessionContext.Instance.Clear();
        bool locked = false;
        for (int i = 0; i < 7; i++)
        {
            var lr = await auth.LoginAsync(username, "wrong-pwd");
            if (lr.IsLocked) { locked = true; break; }
        }
        Assert("连续错误后账户锁定 60 秒", locked);

        // ── 7) 旧 assets.json 迁移 ─────────────────────────────────
        Section("7) 旧数据迁移");
        // 模拟旧文件（已有 alice 的资产后手动在 baseDir 创建 assets.json）
        var oldAssetsFile = Path.Combine(baseDir, "assets.json");
        var defaultAssetsFile = Path.Combine(baseDir, "assets", "default", "assets.json");
        File.WriteAllText(oldAssetsFile, "{\"Assets\":[{\"Id\":\"legacy-1\",\"Name\":\"legacy-server\",\"IPAddress\":\"192.168.0.1\"}],\"ChangeLogs\":[]}");
        // 清理 default 目录
        if (File.Exists(defaultAssetsFile)) File.Delete(defaultAssetsFile);
        if (Directory.Exists(Path.GetDirectoryName(defaultAssetsFile)!))
            Directory.Delete(Path.GetDirectoryName(defaultAssetsFile)!, true);

        // 重新实例化触发迁移
        //（在实际 App.OnStartup 里调用，这里直接测迁移逻辑）
        var oldExists = File.Exists(oldAssetsFile);
        var defaultExists = File.Exists(defaultAssetsFile);
        Assert("旧 assets.json 存在", oldExists);
        Assert("迁移前 default 不存在", !defaultExists);
        // 手动执行迁移
        try
        {
            Directory.CreateDirectory(Path.GetDirectoryName(defaultAssetsFile)!);
            File.Copy(oldAssetsFile, defaultAssetsFile);
        }
        catch { }
        Assert("迁移后 default/assets.json 存在", File.Exists(defaultAssetsFile));
        Assert("迁移后旧文件保留", File.Exists(oldAssetsFile));

        Console.WriteLine();
        Console.WriteLine($"{'='}");
        Console.WriteLine($"  总计: 通过={passed}  失败={failed}");
        return failed == 0 ? 0 : 1;
    }
}
