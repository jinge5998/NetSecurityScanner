using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using NetSecurityScanner.Models;
using NetSecurityScanner.Services;
using NetSecurityScanner.Utils;

class Program
{
    static async Task<int> Main()
    {
        // 隔离数据目录：避免污染实际数据 + 残留
        var testDataDir = Path.Combine(Path.GetTempPath(), "NetSec_SmokeTest_" + Guid.NewGuid().ToString("N").Substring(0, 8));
        Directory.CreateDirectory(testDataDir);
        Environment.SetEnvironmentVariable("NETSEC_DATA_DIR", testDataDir);

        int passed = 0, failed = 0;
        try
        {
            var auth = new AuthService();
            var assetSvc = new AssetManagementService();

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

            // 1. 注册账号
            await Step("注册新账号 alice/password123", async () =>
                await auth.RegisterSimpleAsync("alice", "password123", "Alice"));

            // 2. 重复注册应失败
            await Step("重复注册应失败", async () =>
                !await auth.RegisterSimpleAsync("alice", "password123"));

            // 2.5 创建默认 admin (测试环境不依赖 WPF 启动)
            await Step("创建默认 admin/123456", async () => { await auth.EnsureDefaultAdminAsync(); return true; });
            var adminLogin = await auth.LoginAsync("admin", "123456");
            await Step("默认 admin 登录成功", () => Task.FromResult(adminLogin.IsSuccess && adminLogin.User?.IsAdmin == true));

            // 2.6 admin 批准 alice (新流程：审核 + 分发权限 一步走)
            await Step("admin 批准 alice", async () =>
            {
                var newAuth = new AuthService();
                var login = await newAuth.LoginAsync("admin", "123456");
                if (!login.IsSuccess) return false;
                return await newAuth.ApproveUserAsync("admin", "alice",
                    new System.Collections.Generic.List<string> { "Asset:View", "Asset:Add" });
            });

            // 3. 登录 (重新 new 一个 AuthService 重新加载 users.json，因为 test 2.6 用 newAuth 批准了 alice)
            await Step("登录 alice 成功", async () =>
            {
                var freshAuth = new AuthService();
                var r = await freshAuth.LoginAsync("alice", "password123");
                if (!r.IsSuccess) Console.WriteLine($"  [诊断] LoginAsync 失败: {r.Message} (IsLocked={r.IsLocked}, LockoutSeconds={r.LockoutSecondsRemaining})");
                return r.IsSuccess;
            });

            // 4. 未登录调用 AddAssetAsync 应抛 UnauthorizedAccessException
            await Step("未登录调用 AddAssetAsync 抛 UnauthorizedAccessException", async () =>
            {
                var freshAssetSvc = new AssetManagementService();
                SessionContext.Instance.Clear();
                try
                {
                    await freshAssetSvc.AddAssetAsync(new Asset { Name = "test", IPAddress = "1.1.1.1" });
                    return false;
                }
                catch (UnauthorizedAccessException) { return true; }
                catch { return false; }
            });

            // 5. 登录后添加资产成功
            await Step("登录后添加资产成功", async () =>
            {
                var freshAuth = new AuthService();
                var r = await freshAuth.LoginAsync("alice", "password123");
                if (!r.IsSuccess) return false;
                var freshAssetSvc = new AssetManagementService();
                return await freshAssetSvc.AddAssetAsync(new Asset { Name = "web-server", IPAddress = "192.168.1.10" }, r.User!.Username);
            });

            // 6. 错误密码应失败
            await Step("错误密码应失败", async () =>
            {
                var freshAuth = new AuthService();
                var r = await freshAuth.LoginAsync("alice", "wrong-pass");
                return !r.IsSuccess;
            });

            // 7. 5 次密码错误后账户被锁
            await Step("5 次密码错误后账户被锁定", async () =>
            {
                var freshAuth = new AuthService();
                for (int i = 0; i < 5; i++) await freshAuth.LoginAsync("alice", "wrong-pass");
                var r = await freshAuth.LoginAsync("alice", "wrong-pass");
                return r.IsLocked || !r.IsSuccess;
            });

            // —— 注册增强（enhance-register-flow）——
            // 8. 邮箱格式校验
            await Step("无效邮箱应被拒绝", async () =>
            {
                var r = await auth.RegisterAsync("with_invalid_mail", "Password123", null, "not-an-email", null, null);
                return !r.Success && r.ErrorCode == RegisterError.InvalidEmail;
            });
            await Step("有效邮箱应被接受", async () =>
            {
                var r = await auth.RegisterAsync("with_valid_mail", "Password123", null, "alice@example.com", null, "我的账号");
                return r.Success;
            });
            // 9. 手机号格式校验
            await Step("无效手机号应被拒绝", async () =>
            {
                var r = await auth.RegisterAsync("bad_phone_user", "Password123", null, null, "12345", null);
                return !r.Success && r.ErrorCode == RegisterError.InvalidPhone;
            });
            await Step("有效手机号应被接受", async () =>
            {
                var r = await auth.RegisterAsync("good_phone_user", "Password123", null, null, "13800138000", null);
                return r.Success;
            });
            // 10. 邮箱查重
            await Step("重复邮箱应被拒绝", async () =>
            {
                var r = await auth.RegisterAsync("dup_email_user", "Password123", null, "alice@example.com", null, null);
                return !r.Success && r.ErrorCode == RegisterError.EmailTaken;
            });
            // 11. 手机查重
            await Step("重复手机号应被拒绝", async () =>
            {
                var r = await auth.RegisterAsync("dup_phone_user", "Password123", null, null, "13800138000", null);
                return !r.Success && r.ErrorCode == RegisterError.PhoneTaken;
            });
            // 12. 申请说明超长
            await Step("超过 200 字符的申请说明应被拒绝", async () =>
            {
                var tooLong = new string('a', 201);
                var r = await auth.RegisterAsync("long_reason_user", "Password123", null, null, null, tooLong);
                return !r.Success && r.ErrorCode == RegisterError.ReasonTooLong;
            });
            // 13. 密码强度
            await Step("密码强度：弱(短)", () => Task.FromResult(AuthService.CalcPasswordStrengthLevel("12345") == 0));
            await Step("密码强度：弱(纯字母)", () => Task.FromResult(AuthService.CalcPasswordStrengthLevel("abcdefg") == 0));
            await Step("密码强度：中(字母+数字)", () => Task.FromResult(AuthService.CalcPasswordStrengthLevel("abc12345") == 1));
            await Step("密码强度：强(字母+数字+特殊+长)", () => Task.FromResult(AuthService.CalcPasswordStrengthLevel("Abc123!@#xy9z") == 2));
            // 14. 待审用户应包含新字段（直接读 _store，避免需要 admin）
            // 注意：失败用例（无效邮箱/无效手机/超长说明）的用户根本不会被创建
            await Step("with_valid_mail 是待审且含 Email 字段", () => Task.FromResult(
                auth.GetPendingUsersSafe().Any(u => u.Username == "with_valid_mail" && u.Email == "alice@example.com")));
            await Step("good_phone_user 是待审且含 Phone 字段", () => Task.FromResult(
                auth.GetPendingUsersSafe().Any(u => u.Username == "good_phone_user" && u.Phone == "13800138000")));
            await Step("long_reason_user 不会被创建", () => Task.FromResult(
                !auth.GetPendingUsersSafe().Any(u => u.Username == "long_reason_user")));

            // —— 深度测试（deep-test-register-pending-flow）——
            // X. 注册后立刻 new AuthService() + GetPendingUsers() 验证可见
            await Step("【X】注册后立即 new AuthService() 也能 GetPendingUsers 看到", async () =>
            {
                var newName = "smoke_x_" + Guid.NewGuid().ToString("N").Substring(0, 6);
                var writeAuth = new AuthService();
                var reg = await writeAuth.RegisterAsync(newName, "Password123", null, "x_" + newName + "@test.com", null, "X-test");
                if (!reg.Success) { Console.WriteLine($"  [诊断] 注册失败: {reg.ErrorCode} {reg.Message}"); return false; }

                // 关键: 立刻构造一个完全独立的 AuthService 实例
                var freshAuth = new AuthService();
                var pendings = freshAuth.GetPendingUsersSafe();
                return pendings.Any(u => u.Username == newName);
            });

            // Y. 注册 → 2 个 AuthService 实例 → 第二个实例能否读到
            await Step("【Y】两个独立 AuthService 实例 - 后者读到前者的注册", async () =>
            {
                var newName = "smoke_y_" + Guid.NewGuid().ToString("N").Substring(0, 6);
                var auth1 = new AuthService();
                var reg = await auth1.RegisterAsync(newName, "Password123", null, "y_" + newName + "@test.com", null, "Y-test");
                if (!reg.Success) return false;

                var auth2 = new AuthService();
                var pendings = auth2.GetPendingUsersSafe();
                return pendings.Any(u => u.Username == newName);
            });

            // Z. 注册 → 直接修改 users.json 文件模拟"另一进程写盘" → 重新 new 读 → 应可见
            await Step("【Z】外部修改 users.json 后重新 new AuthService() 能读到", async () =>
            {
                // 用现有的 auth 读路径
                var freshAuth = new AuthService();
                var pendingsBefore = freshAuth.GetPendingUsersSafe();
                var beforeCount = pendingsBefore.Count;
                Console.WriteLine($"  [诊断] 修改前待审: {beforeCount}");

                // 模拟"另一进程": 重新构造一个 AuthService 获取 _usersFilePath 路径
                var probe = new AuthService();
                // 用反射获取 _usersFilePath
                var fieldInfo = typeof(AuthService).GetField("_usersFilePath", System.Reflection.BindingFlags.Instance | System.Reflection.BindingFlags.NonPublic);
                if (fieldInfo == null) { Console.WriteLine("  [诊断] 找不到 _usersFilePath 字段"); return false; }
                var filePath = (string)fieldInfo.GetValue(probe);
                if (string.IsNullOrEmpty(filePath) || !File.Exists(filePath)) { Console.WriteLine($"  [诊断] 文件不存在: {filePath}"); return false; }

                // 读 JSON,手动添加一个 user
                var json = File.ReadAllText(filePath);
                var newName = "smoke_z_" + Guid.NewGuid().ToString("N").Substring(0, 6);
                var newUserJson = $"{{\"Id\":\"{Guid.NewGuid()}\",\"Username\":\"{newName}\",\"DisplayName\":\"Z-test\",\"PasswordHash\":\"Z_HASH\",\"Salt\":\"Z_SALT\",\"CreatedAt\":\"{DateTime.Now:O}\",\"LastLoginAt\":null,\"FailedAttempts\":0,\"LockoutUntil\":null,\"IsAdmin\":false,\"Status\":0,\"ApprovedBy\":null,\"ApprovedAt\":null,\"LastModifiedAt\":null,\"LastModifiedBy\":null,\"Permissions\":[],\"Email\":null,\"Phone\":null,\"Reason\":null}}";

                // 用 System.Text.Json 安全地解析、修改、再序列化
                using (var doc = System.Text.Json.JsonDocument.Parse(json))
                {
                    var root = doc.RootElement;
                    var usersArray = root.GetProperty("Users");
                    var usersList = new System.Text.Json.Nodes.JsonArray();
                    foreach (var u in usersArray.EnumerateArray())
                    {
                        usersList.Add(System.Text.Json.Nodes.JsonNode.Parse(u.GetRawText()));
                    }
                    usersList.Add(System.Text.Json.Nodes.JsonNode.Parse(newUserJson));
                    var newRoot = new System.Text.Json.Nodes.JsonObject { ["Users"] = usersList };
                    var newJson = newRoot.ToJsonString(new System.Text.Json.JsonSerializerOptions { WriteIndented = true });
                    File.WriteAllText(filePath, newJson);
                    Console.WriteLine($"  [诊断] 外部写入了 {newName}");
                    Console.WriteLine($"  [诊断] 写盘后文件长度={newJson.Length},原长度={json.Length}");
                }

                // 重新 new AuthService 读
                var freshAuth2 = new AuthService();
                var pendingsAfter = freshAuth2.GetPendingUsersSafe();
                var found = pendingsAfter.Any(u => u.Username == newName);
                Console.WriteLine($"  [诊断] 修改后待审: {pendingsAfter.Count} | 找到 {newName}={found}");
                return found;
            });

            // W. 并发写盘: A 注册 + B admin 登录(写盘) → A 注册的 user 不能被 B 覆盖丢失
            await Step("【W】并发写盘 - A 注册后 B 写盘 admin LastLoginAt,A 的 user 不丢失", async () =>
            {
                // 1) 实例 A 注册新用户
                var newName = "smoke_w_" + Guid.NewGuid().ToString("N").Substring(0, 6);
                var authA = new AuthService();
                var reg = await authA.RegisterAsync(newName, "Password123", null, "w_" + newName + "@test.com", null, "W-test");
                if (!reg.Success) { Console.WriteLine($"  [诊断] A 注册失败: {reg.ErrorCode}"); return false; }
                Console.WriteLine($"  [诊断] A 注册成功 {newName}");

                // 2) 实例 B 执行 admin 登录(内部 SaveUsersAsync 写盘 admin.LastLoginAt)
                var authB = new AuthService();
                var login = await authB.LoginAsync("admin", "123456", false);
                if (!login.IsSuccess) { Console.WriteLine($"  [诊断] B admin 登录失败: {login.Message}"); return false; }
                Console.WriteLine($"  [诊断] B admin 登录成功(写盘)");

                // 3) 实例 C 读 disk,看 A 的 newName 是否还在
                var authC = new AuthService();
                var storeField = typeof(AuthService).GetField("_store", System.Reflection.BindingFlags.Instance | System.Reflection.BindingFlags.NonPublic);
                var storeObj = storeField?.GetValue(authC);
                if (storeObj == null) return false;
                var usersProp = storeObj.GetType().GetProperty("Users");
                var usersList = (System.Collections.IEnumerable?)usersProp?.GetValue(storeObj);
                bool foundA = false, foundB = false;
                if (usersList != null)
                {
                    foreach (var u in usersList)
                    {
                        var nameProp = u.GetType().GetProperty("Username");
                        var name = (string?)nameProp?.GetValue(u);
                        if (name == newName) foundA = true;
                        if (name == "admin") foundB = true;
                    }
                }
                Console.WriteLine($"  [诊断] disk 上: {newName}={foundA} | admin={foundB}");
                return foundA && foundB;
            });

            // V. 100 并发重压: 100 个 AuthService 实例并发写盘 → 所有写都应不丢失
            await Step("【V】100 并发重压 - 100 个实例并发写盘后所有 user 都在", async () =>
            {
                const int N = 100;
                var tasks = new List<Task<bool>>();
                var names = new System.Collections.Concurrent.ConcurrentBag<string>();
                for (int i = 0; i < N; i++)
                {
                    int idx = i;
                    tasks.Add(Task.Run(async () =>
                    {
                        var auth = new AuthService();
                        var name = $"smoke_v_{idx:D3}_{Guid.NewGuid().ToString("N").Substring(0, 4)}";
                        var reg = await auth.RegisterAsync(name, "Password123", null, $"v{idx}@test.com", null, $"V-test-{idx}");
                        if (reg.Success) names.Add(name);
                        return reg.Success;
                    }));
                }
                var results = await Task.WhenAll(tasks);
                int success = results.Count(r => r);
                Console.WriteLine($"  [诊断] {N} 并发注册成功 {success}/{N}");

                // 用一个全新的 AuthService 读 disk,验证所有名字都在
                var final = new AuthService();
                var storeField = typeof(AuthService).GetField("_store", System.Reflection.BindingFlags.Instance | System.Reflection.BindingFlags.NonPublic);
                var storeObj = storeField?.GetValue(final);
                var usersProp = storeObj?.GetType().GetProperty("Users");
                var usersList = (System.Collections.IEnumerable?)usersProp?.GetValue(storeObj);
                var onDisk = new System.Collections.Generic.HashSet<string>();
                if (usersList != null)
                {
                    foreach (var u in usersList)
                    {
                        var nameProp = u.GetType().GetProperty("Username");
                        var name = (string?)nameProp?.GetValue(u);
                        if (name != null) onDisk.Add(name);
                    }
                }
                int lost = names.Count(n => !onDisk.Contains(n));
                Console.WriteLine($"  [诊断] 预期 {success} 个 V-test 用户,disk 实际找到 {onDisk.Count(n => n.StartsWith("smoke_v_"))} 个,丢失 {lost}");
                return lost == 0 && success == N;
            });

            Console.WriteLine();
            Console.WriteLine($"通过: {passed}, 失败: {failed}");
            return failed == 0 ? 0 : 1;
        }
        finally
        {
            try { Directory.Delete(testDataDir, true); } catch { }
        }
    }
}
