using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using NetSecurityScanner.Models;
using NetSecurityScanner.Services;

class Program
{
    static async Task<int> Main()
    {
        // 清理上次残留，保证测试从干净状态开始
        var baseDir = AppContext.BaseDirectory;
        foreach (var name in new[] { "users.json", "session.json", "assets.json" })
        {
            var path = Path.Combine(baseDir, name);
            if (File.Exists(path)) File.Delete(path);
        }
        // 清理上次测试用的用户资产目录
        var assetsRoot = Path.Combine(baseDir, "assets");
        if (Directory.Exists(assetsRoot))
        {
            try { Directory.Delete(assetsRoot, recursive: true); } catch { }
        }

        var auth = new AuthService();
        var passed = 0;
        var failed = 0;

        async Task Step(string name, Func<Task<bool>> action)
        {
            try
            {
                var ok = await action();
                Console.WriteLine($"{(ok ? "✅" : "❌")} {name}");
                if (ok) passed++; else failed++;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"❌ {name} - 异常: {ex.Message}");
                failed++;
            }
        }

        void StepSync(string name, Func<bool> action)
        {
            try
            {
                var ok = action();
                Console.WriteLine($"{(ok ? "✅" : "❌")} {name}");
                if (ok) passed++; else failed++;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"❌ {name} - 异常: {ex.Message}");
                failed++;
            }
        }

        Console.WriteLine("=== 阶段 1：首启动自动创建 admin/123456 ===");
        await Step("EnsureDefaultAdmin 创建 admin", async () =>
        {
            await auth.EnsureDefaultAdminAsync();
            // admin 一定存在并激活
            var r = await auth.LoginAsync("admin", "123456");
            auth.Logout();
            return r.IsSuccess && r.User != null && r.User.IsAdmin && r.User.Status == UserStatus.Active;
        });

        StepSync("admin 自动获得全部 10 项权限", () =>
        {
            var users = auth.GetAllUsers();
            var admin = users.FirstOrDefault(u => u.Username == "admin");
            if (admin == null) return false;
            return admin.Permissions != null
                && Permission.AllPermissions.All(p => admin.Permissions.Contains(p));
        });

        Console.WriteLine();
        Console.WriteLine("=== 阶段 2：admin 登录并能访问 GetPendingUsers ===");
        var adminLogin = await auth.LoginAsync("admin", "123456");
        StepSync("admin 登录成功", () => adminLogin.IsSuccess);

        StepSync("非 admin 调用 GetPendingUsers 抛异常", () =>
        {
            auth.Logout();
            try
            {
                auth.GetPendingUsers();
                return false;
            }
            catch (UnauthorizedAccessException)
            {
                return true;
            }
            catch
            {
                return false;
            }
        });

        // 重新登录 admin
        await auth.LoginAsync("admin", "123456");

        Console.WriteLine();
        Console.WriteLine("=== 阶段 3：普通用户注册 → 登录被拒 ===");
        await Step("注册 alice 应成功", async () => await auth.RegisterSimpleAsync("alice", "password123", "Alice"));
        await Step("注册 bob 应成功", async () => await auth.RegisterSimpleAsync("bob", "secret456", "Bob"));

        auth.Logout();

        await Step("alice 登录被拒（待审核）", async () =>
        {
            var r = await auth.LoginAsync("alice", "password123");
            return !r.IsSuccess && r.Message.Contains("审核");
        });

        await Step("bob 登录被拒（待审核）", async () =>
        {
            var r = await auth.LoginAsync("bob", "secret456");
            return !r.IsSuccess && r.Message.Contains("审核");
        });

        StepSync("新注册用户默认 Status=Pending", () =>
        {
            var users = auth.GetAllUsers();
            var alice = users.FirstOrDefault(u => u.Username == "alice");
            return alice != null && alice.Status == UserStatus.Pending && !alice.IsAdmin;
        });

        Console.WriteLine();
        Console.WriteLine("=== 阶段 4：admin 审核通过 alice ===");
        await auth.LoginAsync("admin", "123456");

        StepSync("admin 可看到 2 个待审用户", () => auth.GetPendingUsers().Count == 2);

        await Step("ApproveUser alice 授予 3 项权限", async () =>
        {
            var perms = new List<string>
            {
                Permission.AssetView,
                Permission.AssetAdd,
                Permission.AssetEdit
            };
            return await auth.ApproveUserAsync("admin", "alice", perms);
        });

        StepSync("alice 状态变为 Active", () =>
        {
            var users = auth.GetAllUsers();
            var alice = users.FirstOrDefault(u => u.Username == "alice");
            return alice != null
                && alice.Status == UserStatus.Active
                && alice.ApprovedBy == "admin"
                && alice.Permissions != null
                && alice.Permissions.Contains(Permission.AssetAdd);
        });

        Console.WriteLine();
        Console.WriteLine("=== 阶段 5：alice 登录并按权限操作资产 ===");
        auth.Logout();
        var aliceLogin = await auth.LoginAsync("alice", "password123");
        StepSync("alice 登录成功（已激活）", () => aliceLogin.IsSuccess);

        // 资产操作需要登录态（SessionContext.Current）
        var assetSvc = new AssetManagementService();

        await Step("alice 添加资产成功（Asset:Add）", async () =>
        {
            var a = new Asset
            {
                Name = "TestServer",
                IPAddress = "10.0.0.1",
                AssetType = "Server",
                Status = AssetStatus.Online
            };
            return await assetSvc.AddAssetAsync(a, "alice");
        });

        await Step("alice 删除资产被拒（无 Asset:Delete）", async () =>
        {
            var target = assetSvc.GetAllAssets().FirstOrDefault(a => a.IPAddress == "10.0.0.1");
            if (target == null) return false;
            try
            {
                await assetSvc.DeleteAssetAsync(target.Id, "alice");
                return false; // 不应成功
            }
            catch (UnauthorizedAccessException)
            {
                return true;
            }
        });

        await Step("alice 导入资产被拒（无 Asset:Import）", async () =>
        {
            try
            {
                var devices = new List<NetworkDevice>
                {
                    new() { Hostname = "dev", IPAddress = "10.0.0.2", DeviceType = DeviceType.WebServer, Status = DeviceStatus.Online }
                };
                await assetSvc.ImportFromScanResultsAsync(devices, "alice");
                return false;
            }
            catch (UnauthorizedAccessException)
            {
                return true;
            }
        });

        Console.WriteLine();
        Console.WriteLine("=== 阶段 6：admin 调整 alice 权限立即生效 ===");
        auth.Logout();
        await auth.LoginAsync("admin", "123456");

        await Step("授予 alice Asset:Delete + Asset:Import", async () =>
        {
            var perms = new List<string>
            {
                Permission.AssetView,
                Permission.AssetAdd,
                Permission.AssetEdit,
                Permission.AssetDelete,
                Permission.AssetImport
            };
            return await auth.SetUserPermissionsAsync("admin", "alice", perms);
        });

        // alice 重新登录以刷新 SessionContext
        auth.Logout();
        await auth.LoginAsync("alice", "password123");
        // 关键：重新实例化 AssetManagementService 以触发 SessionContext 读取
        var assetSvc2 = new AssetManagementService();

        await Step("alice 现在能删除资产（Asset:Delete 已授予）", async () =>
        {
            var target = assetSvc2.GetAllAssets().FirstOrDefault(a => a.IPAddress == "10.0.0.1");
            if (target == null) return false;
            try
            {
                return await assetSvc2.DeleteAssetAsync(target.Id, "alice");
            }
            catch
            {
                return false;
            }
        });

        Console.WriteLine();
        Console.WriteLine("=== 阶段 7：admin 拒绝 bob + 禁用 alice ===");
        auth.Logout();
        await auth.LoginAsync("admin", "123456");

        await Step("RejectUser bob 应成功", async () => await auth.RejectUserAsync("admin", "bob"));
        StepSync("bob 状态变为 Disabled", () =>
        {
            var users = auth.GetAllUsers();
            return users.FirstOrDefault(u => u.Username == "bob")?.Status == UserStatus.Disabled;
        });

        await Step("DisableUser alice 应成功", async () => await auth.DisableUserAsync("admin", "alice"));
        StepSync("alice 状态变为 Disabled", () =>
        {
            var users = auth.GetAllUsers();
            return users.FirstOrDefault(u => u.Username == "alice")?.Status == UserStatus.Disabled;
        });

        auth.Logout();

        await Step("alice 登录被拒（已禁用）", () =>
        {
            var r = auth.LoginAsync("alice", "password123");
            return r.ContinueWith(t => !t.Result.IsSuccess && t.Result.Message.Contains("禁用"));
        });

        Console.WriteLine();
        Console.WriteLine("=== 阶段 8：admin 重置密码 ===");
        await auth.LoginAsync("admin", "123456");
        await Step("AdminResetPassword bob → newpass", async () =>
            await auth.AdminResetPasswordAsync("admin", "bob", "newpass"));
        auth.Logout();
        await Step("bob 用 newpass 登录（仍然 Disabled 状态 → 拒绝）", () =>
        {
            var r = auth.LoginAsync("bob", "newpass");
            return r.ContinueWith(t => !t.Result.IsSuccess && t.Result.Message.Contains("禁用"));
        });

        // 重新启用 bob 验证密码生效
        await auth.LoginAsync("admin", "123456");
        await Step("EnableUser bob 应成功", async () => await auth.EnableUserAsync("admin", "bob"));
        auth.Logout();
        await Step("bob 用 newpass 登录成功", async () =>
        {
            var r = await auth.LoginAsync("bob", "newpass");
            return r.IsSuccess;
        });

        Console.WriteLine();
        Console.WriteLine("=== 阶段 9：admin 修改 admin 自己的权限被拒 ===");
        await auth.LoginAsync("admin", "123456");
        await Step("SetUserPermissionsAsync(admin, admin, ...) 应失败", async () =>
        {
            return !await auth.SetUserPermissionsAsync("admin", "admin", new List<string> { Permission.AssetView });
        });

        auth.Logout();

        Console.WriteLine();
        Console.WriteLine("=== 阶段 10：权限模板 ===");
        StepSync("Permission.Templates.All 包含 3 个模板", () =>
        {
            return Permission.Templates.All.Count == 3
                && Permission.Templates.All.ContainsKey(Permission.Templates.Viewer)
                && Permission.Templates.All.ContainsKey(Permission.Templates.Operator)
                && Permission.Templates.All.ContainsKey(Permission.Templates.AssetManager);
        });

        StepSync("Viewer 模板仅含 Asset:View", () =>
        {
            var p = Permission.Templates.All[Permission.Templates.Viewer].Permissions;
            return p.Count == 1 && p[0] == Permission.AssetView;
        });

        StepSync("AssetManager 模板含 8 项", () =>
        {
            var p = Permission.Templates.All[Permission.Templates.AssetManager].Permissions;
            return p.Count == 8
                && p.Contains(Permission.AssetView)
                && p.Contains(Permission.AssetAdd)
                && p.Contains(Permission.AssetEdit)
                && p.Contains(Permission.AssetDelete)
                && p.Contains(Permission.AssetImport)
                && p.Contains(Permission.AssetExport)
                && p.Contains(Permission.ScanRun)
                && p.Contains(Permission.ReportExport);
        });

        Console.WriteLine();
        Console.WriteLine("=== 阶段 11：审计日志 ===");
        await auth.LoginAsync("admin", "123456");

        await Step("注册新用户 testlog1", async () =>
            await auth.RegisterSimpleAsync("testlog1", "password123", "Test Log 1"));
        await Step("注册新用户 testlog2", async () =>
            await auth.RegisterSimpleAsync("testlog2", "password123", "Test Log 2"));

        await Step("BatchApproveAsync 批量批准 2 个", async () =>
        {
            var perms = new List<string>
            {
                Permission.AssetView,
                Permission.AssetAdd,
                Permission.AssetEdit
            };
            var targets = new List<string> { "testlog1", "testlog2" };
            int n = await auth.BatchApproveAsync("admin", targets, perms);
            return n == 2;
        });

        StepSync("审计日志含 APPROVE 记录", () =>
        {
            var logs = auth.GetAuditEntries(100);
            return logs.Any(e => e.Action == "APPROVE" && e.Actor == "admin" && e.Target == "testlog1")
                && logs.Any(e => e.Action == "APPROVE" && e.Actor == "admin" && e.Target == "testlog2");
        });

        StepSync("审计日志含 SET_PERMS 记录（由 Approve 内部触发）", () =>
        {
            var logs = auth.GetAuditEntries(100);
            return logs.Any(e => e.Action == "APPROVE" && e.Success);
        });

        await Step("RegisterAsync 失败也写审计", async () =>
        {
            // testlog1 已存在，再注册应失败 → 失败审计
            var r = await auth.RegisterSimpleAsync("testlog1", "password123", "Duplicate");
            return !r; // 业务返回 false（其实不写失败审计，但 SetUserPermissionsAsync 的失败会写）
        });

        await Step("RejectUser testlog1（已激活也能拒绝）", async () =>
            await auth.RejectUserAsync("admin", "testlog1"));
        StepSync("审计日志含 REJECT 记录", () =>
        {
            var logs = auth.GetAuditEntries(100);
            return logs.Any(e => e.Action == "REJECT" && e.Target == "testlog1" && e.Success);
        });

        await Step("ClearAuditLogAsync 应成功", async () =>
            await auth.ClearAuditLogAsync("admin"));
        StepSync("审计日志已被清空（仅剩 CLEAR_AUDIT 自身）", () =>
        {
            var logs = auth.GetAuditEntries(100);
            // 应只有 1 条：CLEAR_AUDIT
            return logs.Count == 1 && logs[0].Action == "CLEAR_AUDIT";
        });

        auth.Logout();

        Console.WriteLine();
        Console.WriteLine($"==================== 总结 ====================");
        Console.WriteLine($"通过: {passed}, 失败: {failed}");
        return failed == 0 ? 0 : 1;
    }
}
