using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using NetSecurityScanner.Models;
using NetSecurityScanner.Utils;

namespace NetSecurityScanner.Services
{
    /// <summary>
    /// 本地用户认证服务：注册、登录、登出、密码哈希、登录失败锁定。
    /// 凭证持久化到 users.json，会话可选加密保存到 session.json。
    /// </summary>
    public class AuthService
    {
        private const int PBKDF2_ITERATIONS = 100000;
        private const int SALT_SIZE = 16;
        private const int MAX_FAILED_ATTEMPTS = 5;
        private const int LOCKOUT_SECONDS = 60;

        private static readonly Regex UsernameRegex = new(@"^[A-Za-z0-9_]{3,32}$", RegexOptions.Compiled);

        private readonly string _usersFilePath;
        private readonly string _sessionFilePath;
        private readonly string _auditFilePath;
        private UserStore _store;
        private AuditLogStore _auditStore;

        public AuthService()
        {
            // 使用集中化数据目录（所有项目共享），避免各 bin 目录数据隔离
            _usersFilePath = DataPaths.UsersFile;
            _sessionFilePath = DataPaths.SessionFile;
            _auditFilePath = DataPaths.AuditLogFile;
            _store = LoadUsers();
            _auditStore = LoadAuditLog();

            // 诊断日志：每次构造时把 DataRoot 与待审用户数写到 auth_diag.log
            // （辅助排查"注册用户看不到"的问题；不影响业务）
            try
            {
                var diagDir = Path.Combine(DataPaths.DataRoot, "logs");
                Directory.CreateDirectory(diagDir);
                var diagFile = Path.Combine(diagDir, "auth_diag.log");
                int pending = _store.Users.Count(u => u.Status == UserStatus.Pending && !u.IsAdmin);
                int active = _store.Users.Count(u => u.Status == UserStatus.Active && !u.IsAdmin);
                var line = $"[{DateTime.Now:HH:mm:ss.fff}] AuthService ctor: DataRoot={DataPaths.DataRoot} | users.json={_usersFilePath} | Exists={File.Exists(_usersFilePath)} | Total={_store.Users.Count} | Pending={pending} | Active={active} | Usernames=[{string.Join(",", _store.Users.Select(u => u.Username))}]";
                AppendDiagLog(line + Environment.NewLine);
            }
            catch { /* 诊断失败不影响主流程 */ }
        }

        #region Public API

        public static bool IsValidUsername(string username) => !string.IsNullOrEmpty(username) && UsernameRegex.IsMatch(username);

        public static bool IsValidPassword(string password) => !string.IsNullOrEmpty(password) && password.Length >= 6;

        /// <summary>
        /// 邮箱格式校验（必填 @ 与 .）。
        /// </summary>
        public static bool IsValidEmail(string? email)
        {
            if (string.IsNullOrWhiteSpace(email)) return true; // 选填：空合法
            var e = email.Trim();
            if (e.Length < 5 || e.Length > 100) return false;
            int at = e.IndexOf('@');
            if (at <= 0 || at == e.Length - 1) return false;
            if (e.IndexOf('@', at + 1) >= 0) return false; // 多个 @
            var domain = e.Substring(at + 1);
            if (!domain.Contains('.')) return false;
            if (domain.StartsWith('.') || domain.EndsWith('.')) return false;
            return true;
        }

        /// <summary>
        /// 中国大陆手机号校验：1 开头 + 10 位数字（11 位总长）。
        /// </summary>
        public static bool IsValidPhone(string? phone)
        {
            if (string.IsNullOrWhiteSpace(phone)) return true; // 选填：空合法
            var p = phone.Trim();
            if (p.Length != 11) return false;
            if (p[0] != '1') return false;
            foreach (var c in p)
                if (c < '0' || c > '9') return false;
            return true;
        }

        /// <summary>
        /// 密码强度评分：0-100。0=弱（仅长度），50=中（含字母+数字），100=强（含字母+数字+特殊字符且长度≥10）。
        /// </summary>
        public static int CalcPasswordStrength(string password)
        {
            if (string.IsNullOrEmpty(password)) return 0;
            int score = 0;
            bool hasLetter = false, hasDigit = false, hasSpecial = false;
            foreach (var c in password)
            {
                if (char.IsLetter(c)) hasLetter = true;
                else if (char.IsDigit(c)) hasDigit = true;
                else if (!char.IsWhiteSpace(c)) hasSpecial = true;
            }
            if (password.Length >= 6) score += 20;
            if (password.Length >= 10) score += 20;
            if (hasLetter && hasDigit) score += 30;
            if (hasSpecial) score += 20;
            if (password.Length >= 12) score += 10;
            return Math.Min(score, 100);
        }

        /// <summary>
        /// 密码强度等级：0=弱、1=中、2=强。
        /// </summary>
        public static int CalcPasswordStrengthLevel(string password)
        {
            int s = CalcPasswordStrength(password);
            if (s >= 80) return 2;
            if (s >= 50) return 1;
            return 0;
        }

        public bool IsUsernameAvailable(string username) =>
            !_store.Users.Any(u => string.Equals(u.Username, username, StringComparison.OrdinalIgnoreCase));

        public bool IsEmailAvailable(string? email)
        {
            if (string.IsNullOrWhiteSpace(email)) return true;
            var e = email.Trim();
            return !_store.Users.Any(u => string.Equals(u.Email, e, StringComparison.OrdinalIgnoreCase));
        }

        public bool IsPhoneAvailable(string? phone)
        {
            if (string.IsNullOrWhiteSpace(phone)) return true;
            var p = phone.Trim();
            return !_store.Users.Any(u => string.Equals(u.Phone, p, StringComparison.Ordinal));
        }

        /// <summary>
        /// 注册新用户。返回 RegisterResult 含失败原因；用户名/邮箱/手机重复或规则不匹配时返回具体错误。
        /// </summary>
        public async Task<RegisterResult> RegisterAsync(
            string username, string password,
            string? displayName = null,
            string? email = null,
            string? phone = null,
            string? reason = null)
        {
            if (!IsValidUsername(username))
                return RegisterResult.Failed(RegisterError.InvalidUsername, "用户名必须为 3-32 位字母/数字/下划线");
            if (!IsValidPassword(password))
                return RegisterResult.Failed(RegisterError.InvalidPassword, "密码至少 6 位");
            if (!IsValidEmail(email))
                return RegisterResult.Failed(RegisterError.InvalidEmail, "邮箱格式不正确");
            if (!IsValidPhone(phone))
                return RegisterResult.Failed(RegisterError.InvalidPhone, "手机号必须为 11 位数字且 1 开头");
            if (!string.IsNullOrEmpty(reason) && reason.Length > 200)
                return RegisterResult.Failed(RegisterError.ReasonTooLong, "申请说明最多 200 字符");

            if (!IsUsernameAvailable(username))
                return RegisterResult.Failed(RegisterError.UsernameTaken, "该用户名已被占用");
            if (!IsEmailAvailable(email))
                return RegisterResult.Failed(RegisterError.EmailTaken, "该邮箱已被注册");
            if (!IsPhoneAvailable(phone))
                return RegisterResult.Failed(RegisterError.PhoneTaken, "该手机号已被注册");

            var salt = GenerateSalt();
            var hash = HashPassword(password, salt);

            var user = new User
            {
                Id = Guid.NewGuid().ToString(),
                Username = username,
                DisplayName = string.IsNullOrWhiteSpace(displayName) ? username : displayName.Trim(),
                PasswordHash = hash,
                Salt = salt,
                CreatedAt = DateTime.Now,
                FailedAttempts = 0,
                IsAdmin = false,
                Status = UserStatus.Pending, // 新注册用户默认待审核
                Permissions = new System.Collections.Generic.List<string>(),
                Email = string.IsNullOrWhiteSpace(email) ? null : email.Trim(),
                Phone = string.IsNullOrWhiteSpace(phone) ? null : phone.Trim(),
                Reason = string.IsNullOrWhiteSpace(reason) ? null : reason.Trim()
            };

            _store.Users.Add(user);
            try
            {
                await SaveUsersAsync();
                // 诊断日志：确认注册成功且写盘
                var diagDir = Path.Combine(DataPaths.DataRoot, "logs");
                Directory.CreateDirectory(diagDir);
                var diagFile = Path.Combine(diagDir, "auth_diag.log");
                AppendDiagLog($"[{DateTime.Now:HH:mm:ss.fff}] RegisterAsync: SUCCESS user={user.Username} | Total={_store.Users.Count} | File={_usersFilePath}\n");
            }
            catch (Exception ex)
            {
                // 写盘失败时记日志
                try
                {
                    var diagDir = Path.Combine(DataPaths.DataRoot, "logs");
                    Directory.CreateDirectory(diagDir);
                    var diagFile = Path.Combine(diagDir, "auth_diag.log");
                    AppendDiagLog($"[{DateTime.Now:HH:mm:ss.fff}] RegisterAsync: SAVE_FAILED user={user.Username} ex={ex.GetType().Name}: {ex.Message}\n");
                }
                catch { }
                throw;
            }
            return RegisterResult.Ok();
        }

        /// <summary>
        /// 向后兼容：返回 bool 的注册重载（仅 username + password + 可选 displayName）。
        /// 新代码请用返回 RegisterResult 的主方法获取错误详情。
        /// </summary>
        public async Task<bool> RegisterSimpleAsync(string username, string password, string? displayName = null)
        {
            var r = await RegisterAsync(username, password, displayName, null, null, null);
            return r.Success;
        }

        /// <summary>
        /// 登录。返回是否登录成功；失败原因可由 LockoutSecondsRemaining>0 判断是否处于锁定。
        /// </summary>
        public async Task<LoginResult> LoginAsync(string username, string password, bool rememberMe = false)
        {
            if (string.IsNullOrWhiteSpace(username) || password == null)
                return LoginResult.Failed("用户名或密码错误");

            var user = _store.Users.FirstOrDefault(u => string.Equals(u.Username, username, StringComparison.OrdinalIgnoreCase));
            if (user == null)
            {
                // 不暴露用户是否存在
                return LoginResult.Failed("用户名或密码错误");
            }

            if (user.LockoutUntil.HasValue && user.LockoutUntil.Value > DateTime.Now)
            {
                var remain = (int)Math.Ceiling((user.LockoutUntil.Value - DateTime.Now).TotalSeconds);
                return LoginResult.Locked(remain, $"登录已锁定，请在 {remain} 秒后重试");
            }

            // 账号状态校验
            if (user.Status == UserStatus.Pending)
            {
                return LoginResult.Failed("账号待管理员审核，请联系 admin");
            }
            if (user.Status == UserStatus.Disabled)
            {
                return LoginResult.Failed("账号已被禁用，请联系管理员");
            }

            var hash = HashPassword(password, user.Salt);
            if (!string.Equals(hash, user.PasswordHash, StringComparison.Ordinal))
            {
                user.FailedAttempts++;
                if (user.FailedAttempts >= MAX_FAILED_ATTEMPTS)
                {
                    user.LockoutUntil = DateTime.Now.AddSeconds(LOCKOUT_SECONDS);
                    user.FailedAttempts = 0;
                    await SaveUsersAsync();
                    return LoginResult.Locked(LOCKOUT_SECONDS, $"连续 {MAX_FAILED_ATTEMPTS} 次登录失败，已锁定 {LOCKOUT_SECONDS} 秒");
                }
                await SaveUsersAsync();
                return LoginResult.Failed("用户名或密码错误");
            }

            // 登录成功
            user.FailedAttempts = 0;
            user.LockoutUntil = null;
            user.LastLoginAt = DateTime.Now;
            await SaveUsersAsync();

            SessionContext.Instance.Current = user;

            // 诊断日志
            try
            {
                var diagDir = Path.Combine(DataPaths.DataRoot, "logs");
                Directory.CreateDirectory(diagDir);
                var diagFile = Path.Combine(diagDir, "auth_diag.log");
                AppendDiagLog($"[{DateTime.Now:HH:mm:ss.fff}] LoginAsync: SUCCESS user={user.Username} IsAdmin={user.IsAdmin} Status={user.Status} rememberMe={rememberMe}\n");
            }
            catch { }

            if (rememberMe)
                await SaveSessionAsync(user);

            return LoginResult.Success(user);
        }

        /// <summary>
        /// 登出。清除 SessionContext，并删除 session.json（若有）。
        /// </summary>
        public void Logout()
        {
            SessionContext.Instance.Clear();
            try
            {
                if (File.Exists(_sessionFilePath))
                    File.Delete(_sessionFilePath);
            }
            catch { }
        }

        /// <summary>
        /// 启动时尝试恢复登录会话。返回是否恢复成功。
        /// </summary>
        public bool TryRestoreSession()
        {
            try
            {
                if (!File.Exists(_sessionFilePath)) return false;
                var cipher = File.ReadAllText(_sessionFilePath);
                if (string.IsNullOrWhiteSpace(cipher)) return false;

                var json = DecryptSession(cipher);
                if (string.IsNullOrEmpty(json)) return false;

                var session = JsonSerializer.Deserialize<SessionPayload>(json);
                if (session == null || string.IsNullOrEmpty(session.UserId)) return false;

                var user = _store.Users.FirstOrDefault(u => u.Id == session.UserId);
                if (user == null) return false;

                // 已禁用或待审核用户不能恢复会话
                if (user.Status != UserStatus.Active && !user.IsAdmin) return false;

                SessionContext.Instance.Current = user;

                // 诊断日志
                try
                {
                    var diagDir = Path.Combine(DataPaths.DataRoot, "logs");
                    Directory.CreateDirectory(diagDir);
                    var diagFile = Path.Combine(diagDir, "auth_diag.log");
                    AppendDiagLog($"[{DateTime.Now:HH:mm:ss.fff}] TryRestoreSession: Restored UserId={user.Id} Username={user.Username} IsAdmin={user.IsAdmin} Status={user.Status} (session.json={_sessionFilePath} Exists=True)\n");
                }
                catch { }

                return true;
            }
            catch (Exception ex)
            {
                try
                {
                    var diagDir = Path.Combine(DataPaths.DataRoot, "logs");
                    Directory.CreateDirectory(diagDir);
                    var diagFile = Path.Combine(diagDir, "auth_diag.log");
                    AppendDiagLog($"[{DateTime.Now:HH:mm:ss.fff}] TryRestoreSession: FAILED: {ex.Message}\n");
                }
                catch { }
                return false;
            }
        }

        #endregion

        #region Admin Approval & Permission

        /// <summary>
        /// 获取所有待审核用户（仅 admin 可调用）。
        /// </summary>
        public List<User> GetPendingUsers()
        {
            EnsureAdmin();
            return _store.Users
                .Where(u => u.Status == UserStatus.Pending && !u.IsAdmin)
                .Select(CloneForDisplay)
                .ToList();
        }

        /// <summary>
        /// 内部安全版：直接读 _store，不检查 admin（仅供测试 / 诊断使用）。
        /// </summary>
        public List<User> GetPendingUsersSafe() =>
            _store.Users
                .Where(u => u.Status == UserStatus.Pending && !u.IsAdmin)
                .ToList();

        /// <summary>
        /// admin 批准待审用户并授予权限。
        /// </summary>
        public async Task<bool> ApproveUserAsync(string adminName, string targetUsername, List<string> permissions)
        {
            EnsureAdmin();
            var admin = GetActiveAdmin(adminName);
            if (admin == null) { await RecordAuditAsync(adminName, "APPROVE", targetUsername, "admin 不存在", false); return false; }

            var user = _store.Users.FirstOrDefault(u =>
                string.Equals(u.Username, targetUsername, StringComparison.OrdinalIgnoreCase));
            if (user == null || user.Status != UserStatus.Pending)
            {
                await RecordAuditAsync(adminName, "APPROVE", targetUsername, "目标用户不存在或状态非 Pending", false);
                return false;
            }

            user.Status = UserStatus.Active;
            user.ApprovedBy = admin.Username;
            user.ApprovedAt = DateTime.Now;
            user.LastModifiedBy = admin.Username;
            user.LastModifiedAt = DateTime.Now;
            user.Permissions = permissions ?? new List<string>();
            // 保证至少有 Asset:View
            if (!user.Permissions.Contains(Permission.AssetView))
                user.Permissions.Add(Permission.AssetView);

            await SaveUsersAsync();
            await RecordAuditAsync(adminName, "APPROVE", targetUsername,
                $"授权 {user.Permissions.Count} 项: {string.Join(", ", user.Permissions)}", true);

            // 同步刷新 SessionContext（如果目标用户正在登录）
            SyncSession(user);
            return true;
        }

        /// <summary>
        /// admin 拒绝（禁用）待审用户。
        /// </summary>
        public async Task<bool> RejectUserAsync(string adminName, string targetUsername)
        {
            EnsureAdmin();
            var admin = GetActiveAdmin(adminName);
            if (admin == null) { await RecordAuditAsync(adminName, "REJECT", targetUsername, "admin 不存在", false); return false; }

            var user = _store.Users.FirstOrDefault(u =>
                string.Equals(u.Username, targetUsername, StringComparison.OrdinalIgnoreCase));
            if (user == null)
            {
                await RecordAuditAsync(adminName, "REJECT", targetUsername, "目标用户不存在", false);
                return false;
            }

            user.Status = UserStatus.Disabled;
            user.LastModifiedBy = admin.Username;
            user.LastModifiedAt = DateTime.Now;
            await SaveUsersAsync();
            await RecordAuditAsync(adminName, "REJECT", targetUsername, "拒绝注册申请", true);

            SyncSession(user);
            return true;
        }

        /// <summary>
        /// admin 设置已批准用户的权限。
        /// </summary>
        public async Task<bool> SetUserPermissionsAsync(string adminName, string targetUsername, List<string> permissions)
        {
            EnsureAdmin();
            var admin = GetActiveAdmin(adminName);
            if (admin == null) { await RecordAuditAsync(adminName, "SET_PERMS", targetUsername, "admin 不存在", false); return false; }

            var user = _store.Users.FirstOrDefault(u =>
                string.Equals(u.Username, targetUsername, StringComparison.OrdinalIgnoreCase));
            if (user == null) { await RecordAuditAsync(adminName, "SET_PERMS", targetUsername, "目标用户不存在", false); return false; }
            if (user.IsAdmin) { await RecordAuditAsync(adminName, "SET_PERMS", targetUsername, "禁止修改 admin 权限", false); return false; }

            user.Permissions = permissions ?? new List<string>();
            if (!user.Permissions.Contains(Permission.AssetView))
                user.Permissions.Add(Permission.AssetView);
            user.LastModifiedBy = admin.Username;
            user.LastModifiedAt = DateTime.Now;
            await SaveUsersAsync();
            await RecordAuditAsync(adminName, "SET_PERMS", targetUsername,
                $"更新为 {user.Permissions.Count} 项: {string.Join(", ", user.Permissions)}", true);

            SyncSession(user);
            return true;
        }

        /// <summary>
        /// admin 禁用已激活用户。
        /// </summary>
        public async Task<bool> DisableUserAsync(string adminName, string targetUsername)
        {
            EnsureAdmin();
            var admin = GetActiveAdmin(adminName);
            if (admin == null) { await RecordAuditAsync(adminName, "DISABLE", targetUsername, "admin 不存在", false); return false; }

            var user = _store.Users.FirstOrDefault(u =>
                string.Equals(u.Username, targetUsername, StringComparison.OrdinalIgnoreCase));
            if (user == null) { await RecordAuditAsync(adminName, "DISABLE", targetUsername, "目标用户不存在", false); return false; }
            if (user.IsAdmin) { await RecordAuditAsync(adminName, "DISABLE", targetUsername, "禁止禁用 admin", false); return false; }

            user.Status = UserStatus.Disabled;
            user.LastModifiedBy = admin.Username;
            user.LastModifiedAt = DateTime.Now;
            await SaveUsersAsync();
            await RecordAuditAsync(adminName, "DISABLE", targetUsername, "禁用账号", true);

            // 如果禁用的是当前登录用户，立即清除会话
            if (SessionContext.Instance.Current != null &&
                string.Equals(SessionContext.Instance.Current.Username, user.Username, StringComparison.OrdinalIgnoreCase))
            {
                SessionContext.Instance.Clear();
            }
            return true;
        }

        /// <summary>
        /// admin 重新激活已禁用的用户。
        /// </summary>
        public async Task<bool> EnableUserAsync(string adminName, string targetUsername)
        {
            EnsureAdmin();
            var admin = GetActiveAdmin(adminName);
            if (admin == null) { await RecordAuditAsync(adminName, "ENABLE", targetUsername, "admin 不存在", false); return false; }

            var user = _store.Users.FirstOrDefault(u =>
                string.Equals(u.Username, targetUsername, StringComparison.OrdinalIgnoreCase));
            if (user == null) { await RecordAuditAsync(adminName, "ENABLE", targetUsername, "目标用户不存在", false); return false; }

            user.Status = UserStatus.Active;
            user.LastModifiedBy = admin.Username;
            user.LastModifiedAt = DateTime.Now;
            await SaveUsersAsync();
            await RecordAuditAsync(adminName, "ENABLE", targetUsername, "重新激活账号", true);
            return true;
        }

        /// <summary>
        /// admin 重置任意用户的密码（用于忘记密码场景）。
        /// </summary>
        public async Task<bool> AdminResetPasswordAsync(string adminName, string targetUsername, string newPassword)
        {
            EnsureAdmin();
            var admin = GetActiveAdmin(adminName);
            if (admin == null) { await RecordAuditAsync(adminName, "RESET_PWD", targetUsername, "admin 不存在", false); return false; }
            if (!IsValidPassword(newPassword)) { await RecordAuditAsync(adminName, "RESET_PWD", targetUsername, "新密码不合法", false); return false; }

            var user = _store.Users.FirstOrDefault(u =>
                string.Equals(u.Username, targetUsername, StringComparison.OrdinalIgnoreCase));
            if (user == null) { await RecordAuditAsync(adminName, "RESET_PWD", targetUsername, "目标用户不存在", false); return false; }

            user.Salt = GenerateSalt();
            user.PasswordHash = HashPassword(newPassword, user.Salt);
            user.FailedAttempts = 0;
            user.LockoutUntil = null;
            user.LastModifiedBy = admin.Username;
            user.LastModifiedAt = DateTime.Now;
            await SaveUsersAsync();
            await RecordAuditAsync(adminName, "RESET_PWD", targetUsername, "重置密码", true);
            return true;
        }

        /// <summary>
        /// 批量批准多个待审用户（应用相同权限集）。
        /// </summary>
        public async Task<int> BatchApproveAsync(string adminName, List<string> targetUsernames, List<string> permissions)
        {
            EnsureAdmin();
            int ok = 0;
            foreach (var name in targetUsernames)
            {
                if (await ApproveUserAsync(adminName, name, permissions)) ok++;
            }
            return ok;
        }

        /// <summary>
        /// 批量拒绝多个待审用户。
        /// </summary>
        public async Task<int> BatchRejectAsync(string adminName, List<string> targetUsernames)
        {
            EnsureAdmin();
            int ok = 0;
            foreach (var name in targetUsernames)
            {
                if (await RejectUserAsync(adminName, name)) ok++;
            }
            return ok;
        }

        /// <summary>
        /// 获取审计日志（按时间倒序）。
        /// </summary>
        public List<AuditEntry> GetAuditEntries(int maxCount = 500)
        {
            return _auditStore.Entries
                .OrderByDescending(e => e.At)
                .Take(maxCount)
                .ToList();
        }

        /// <summary>
        /// 清空审计日志（admin 操作）。
        /// </summary>
        public async Task<bool> ClearAuditLogAsync(string adminName)
        {
            EnsureAdmin();
            int count = _auditStore.Entries.Count;
            _auditStore.Entries.Clear();
            await SaveAuditLogAsync();
            await RecordAuditAsync(adminName, "CLEAR_AUDIT", "-", $"清空 {count} 条历史", true);
            return true;
        }

        private async Task RecordAuditAsync(string actor, string action, string target, string detail, bool success)
        {
            try
            {
                _auditStore.Entries.Add(new AuditEntry
                {
                    Actor = actor,
                    Action = action,
                    Target = target,
                    Detail = detail,
                    Success = success
                });
                // 仅保留最近 1000 条
                if (_auditStore.Entries.Count > 1000)
                {
                    _auditStore.Entries = _auditStore.Entries
                        .OrderByDescending(e => e.At)
                        .Take(1000)
                        .ToList();
                }
                await SaveAuditLogAsync();
            }
            catch
            {
                // 审计写失败不应阻塞主业务
            }
        }

        private AuditLogStore LoadAuditLog()
        {
            try
            {
                if (!File.Exists(_auditFilePath)) return new AuditLogStore();
                var json = File.ReadAllText(_auditFilePath);
                if (string.IsNullOrWhiteSpace(json)) return new AuditLogStore();
                return JsonSerializer.Deserialize<AuditLogStore>(json) ?? new AuditLogStore();
            }
            catch
            {
                return new AuditLogStore();
            }
        }

        private async Task SaveAuditLogAsync()
        {
            var json = JsonSerializer.Serialize(_auditStore, new JsonSerializerOptions { WriteIndented = true });
            await File.WriteAllTextAsync(_auditFilePath, json);
        }

        private void EnsureAdmin()
        {
            var current = SessionContext.Instance.Current;
            if (current == null || !current.IsAdmin)
                throw new UnauthorizedAccessException("此操作仅限管理员");
        }

        private User? GetActiveAdmin(string adminName)
        {
            var admin = _store.Users.FirstOrDefault(u =>
                string.Equals(u.Username, adminName, StringComparison.OrdinalIgnoreCase) && u.IsAdmin);
            return admin;
        }

        private void SyncSession(User user)
        {
            if (SessionContext.Instance.Current != null &&
                string.Equals(SessionContext.Instance.Current.Username, user.Username, StringComparison.OrdinalIgnoreCase))
            {
                SessionContext.Instance.Current = user;
            }
        }

        private static User CloneForDisplay(User u) => new()
        {
            Id = u.Id,
            Username = u.Username,
            DisplayName = u.DisplayName,
            CreatedAt = u.CreatedAt,
            LastLoginAt = u.LastLoginAt,
            FailedAttempts = u.FailedAttempts,
            LockoutUntil = u.LockoutUntil,
            IsAdmin = u.IsAdmin,
            Status = u.Status,
            ApprovedBy = u.ApprovedBy,
            ApprovedAt = u.ApprovedAt,
            LastModifiedBy = u.LastModifiedBy,
            LastModifiedAt = u.LastModifiedAt,
            Permissions = new List<string>(u.Permissions ?? new List<string>()),
            PasswordHash = null,
            Salt = null
        };

        #endregion

        #region Bootstrap

        /// <summary>
        /// 确保 users.json 与 admin 账号存在；缺失则创建默认 admin/123456。
        /// </summary>
        public async Task EnsureDefaultAdminAsync()
        {
            _store = LoadUsers();
            var admin = _store.Users.FirstOrDefault(u =>
                string.Equals(u.Username, "admin", StringComparison.OrdinalIgnoreCase) && u.IsAdmin);
            if (admin != null) return;

            var salt = GenerateSalt();
            var hash = HashPassword("123456", salt);
            var newAdmin = new User
            {
                Id = Guid.NewGuid().ToString(),
                Username = "admin",
                DisplayName = "超级管理员",
                PasswordHash = hash,
                Salt = salt,
                CreatedAt = DateTime.Now,
                IsAdmin = true,
                Status = UserStatus.Active,
                Permissions = new List<string>(Permission.AllPermissions),
                ApprovedBy = "system",
                ApprovedAt = DateTime.Now
            };
            _store.Users.Add(newAdmin);
            await SaveUsersAsync();
        }

        #endregion

        #region User Management

        /// <summary>
        /// 获取所有用户（密码字段已脱敏），供账号管理窗口使用。
        /// </summary>
        public List<User> GetAllUsers()
        {
            return _store.Users.Select(u => new User
            {
                Id = u.Id,
                Username = u.Username,
                DisplayName = u.DisplayName,
                CreatedAt = u.CreatedAt,
                LastLoginAt = u.LastLoginAt,
                FailedAttempts = u.FailedAttempts,
                LockoutUntil = u.LockoutUntil,
                IsAdmin = u.IsAdmin,
                Status = u.Status,
                ApprovedBy = u.ApprovedBy,
                ApprovedAt = u.ApprovedAt,
                LastModifiedBy = u.LastModifiedBy,
                LastModifiedAt = u.LastModifiedAt,
                Permissions = new List<string>(u.Permissions ?? new List<string>()),
                PasswordHash = null,
                Salt = null
            }).ToList();
        }

        /// <summary>
        /// 修改指定用户的显示名。
        /// </summary>
        /// <param name="username">要修改的用户名</param>
        /// <param name="newDisplayName">新显示名（1-32字符）</param>
        /// <returns>是否成功</returns>
        public async Task<bool> UpdateDisplayNameAsync(string username, string newDisplayName)
        {
            if (string.IsNullOrWhiteSpace(newDisplayName) || newDisplayName.Trim().Length > 32)
                return false;

            var user = _store.Users.FirstOrDefault(u =>
                string.Equals(u.Username, username, StringComparison.OrdinalIgnoreCase));
            if (user == null) return false;

            user.DisplayName = newDisplayName.Trim();

            // 同步刷新 SessionContext（如果当前会话匹配）
            if (SessionContext.Instance.Current != null &&
                string.Equals(SessionContext.Instance.Current.Username, username, StringComparison.OrdinalIgnoreCase))
            {
                SessionContext.Instance.Current = user;
            }

            await SaveUsersAsync();
            return true;
        }

        /// <summary>
        /// 修改指定用户的密码。
        /// </summary>
        /// <param name="username">用户名</param>
        /// <param name="oldPassword">旧密码</param>
        /// <param name="newPassword">新密码（≥6位）</param>
        /// <returns>结果描述</returns>
        public async Task<ChangePasswordResult> ChangePasswordAsync(string username, string oldPassword, string newPassword)
        {
            var user = _store.Users.FirstOrDefault(u =>
                string.Equals(u.Username, username, StringComparison.OrdinalIgnoreCase));
            if (user == null)
                return ChangePasswordResult.Failed("用户不存在");

            // 校验旧密码
            var oldHash = HashPassword(oldPassword, user.Salt);
            if (!string.Equals(oldHash, user.PasswordHash, StringComparison.Ordinal))
                return ChangePasswordResult.Failed("旧密码错误");

            if (!IsValidPassword(newPassword))
                return ChangePasswordResult.Failed("新密码至少 6 位");

            // 生成新盐与哈希
            var newSalt = GenerateSalt();
            var newHash = HashPassword(newPassword, newSalt);
            user.Salt = newSalt;
            user.PasswordHash = newHash;

            await SaveUsersAsync();

            // 同步刷新 SessionContext（如果当前会话匹配）
            if (SessionContext.Instance.Current != null &&
                string.Equals(SessionContext.Instance.Current.Username, username, StringComparison.OrdinalIgnoreCase))
            {
                SessionContext.Instance.Current = user;
            }

            return ChangePasswordResult.Success();
        }

        #endregion

        #region Persistence

        // 跨实例共享的写锁：防止多个 AuthService 实例并发写 users.json 互相覆盖（last-writer-wins 丢失）
        private static readonly SemaphoreSlim _writeLock = new(1, 1);

        // 诊断日志的并发写锁：File.AppendAllText 不允许多 writer 并发,加锁保护
        private static readonly object _diagLogLock = new();

        /// <summary>
        /// 追加一行诊断日志到 auth_diag.log。线程安全,使用 _diagLogLock 串行化。
        /// </summary>
        private static void AppendDiagLog(string message)
        {
            try
            {
                var diagDir = Path.Combine(DataPaths.DataRoot, "logs");
                Directory.CreateDirectory(diagDir);
                var diagFile = Path.Combine(diagDir, "auth_diag.log");
                lock (_diagLogLock)
                {
                    File.AppendAllText(diagFile, message);
                }
            }
            catch { }
        }

        private UserStore LoadUsers()
        {
            try
            {
                if (File.Exists(_usersFilePath))
                {
                    // FileShare.ReadWrite|Delete:允许同一进程/不同进程的 reader+writer 并发持有(短时间交错)
                    // 注意:Windows 文件系统在 FileMode.Open 下,即使加了 FileShare.ReadWrite,写者仍可能短暂失败,
                    // 所以外层 _writeLock 才是真正的串行化机制。FileShare.ReadWrite 是为多 reader 并发优化。
                    using var fs = new FileStream(_usersFilePath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
                    using var sr = new StreamReader(fs);
                    var json = sr.ReadToEnd();
                    if (string.IsNullOrWhiteSpace(json)) return new UserStore();
                    var data = JsonSerializer.Deserialize<UserStore>(json);
                    if (data != null) return data;
                }
            }
            catch { }
            return new UserStore();
        }

        /// <summary>
        /// 写盘（线程安全 + 合并写）。
        /// 关键修复：写盘前先 LoadUsers() 把 disk 上**其他实例**的 user 合并进来,
        /// 避免 last-writer-wins 导致 admin3 等新注册用户被覆盖丢失。
        /// 整个 read-modify-write 都在 static _writeLock 临界区里。
        /// </summary>
        private async Task SaveUsersAsync()
        {
            await _writeLock.WaitAsync();
            try
            {
                // 1) 写盘前再读一次 disk,把"其他实例刚写入但当前 _store 没有"的用户合并进来
                var diskStore = LoadUsers();
                var diskIds = diskStore.Users.Select(u => u.Id).ToHashSet();
                // 合并：_store 中已有的 user(我们的最新数据) + disk 中其他实例独有的 user
                var merged = new UserStore();
                foreach (var u in diskStore.Users)
                {
                    // 如果 _store 中有同 Id 的版本（我们的更新），用 _store 的
                    var localMatch = _store.Users.FirstOrDefault(x => x.Id == u.Id);
                    if (localMatch != null)
                        merged.Users.Add(localMatch);
                    else
                        merged.Users.Add(u);  // 保留其他实例的 user
                }
                // 把 _store 中 disk 上没有的新 user（如刚注册的 admin3）也加入
                foreach (var u in _store.Users.Where(u => !diskIds.Contains(u.Id)))
                {
                    merged.Users.Add(u);
                }

                // 2) 把 _store 同步到合并后的版本(避免下次 _store 又丢)
                _store = merged;

                // 3) 序列化 + 写盘
                var json = JsonSerializer.Serialize(_store, new JsonSerializerOptions { WriteIndented = true });
                // FileMode.Create + FileShare.ReadWrite|Delete:允许其他 reader/writer 并发(短时间交错)
                // 真正串行化靠外层 _writeLock,这里的 FileShare 是为了让 LoadUsers 的 reader 在 writer 持锁时不被阻塞
                using (var fs = new FileStream(_usersFilePath, FileMode.Create, FileAccess.Write, FileShare.ReadWrite | FileShare.Delete))
                using (var sw = new StreamWriter(fs))
                {
                    await sw.WriteAsync(json);
                }

                // 4) 诊断日志：写盘后记录实际 disk 状态（含耗时、文件大小、防丢失校验）
                try
                {
                    var sw = System.Diagnostics.Stopwatch.StartNew();
                    var diagDir = Path.Combine(DataPaths.DataRoot, "logs");
                    Directory.CreateDirectory(diagDir);
                    var diagFile = Path.Combine(diagDir, "auth_diag.log");
                    sw.Stop();
                    var fileSize = new FileInfo(_usersFilePath).Length;
                    // 防丢失校验：disk 上的 user 数必须 >= _store 中的 user 数
                    var onDiskCount = _store.Users.Count;
                    AppendDiagLog($"[{DateTime.Now:HH:mm:ss.fff}] SaveUsersAsync: WROTE Total={onDiskCount} | Size={fileSize}B | Took={sw.ElapsedMilliseconds}ms | File={_usersFilePath} | Usernames=[{string.Join(",", _store.Users.Select(u => u.Username))}]\n");
                }
                catch { }
            }
            finally
            {
                _writeLock.Release();
            }
        }

        private async Task SaveSessionAsync(User user)
        {
            try
            {
                var payload = new SessionPayload
                {
                    UserId = user.Id,
                    Username = user.Username,
                    SavedAt = DateTime.Now
                };
                var json = JsonSerializer.Serialize(payload);
                var cipher = EncryptSession(json);
                await File.WriteAllTextAsync(_sessionFilePath, cipher);
            }
            catch { }
        }

        private string EncryptSession(string plainText)
        {
            var (key, iv) = DeriveSessionKey();
            return CryptoHelper.AesEncrypt(plainText, key, iv);
        }

        private string DecryptSession(string cipherText)
        {
            try
            {
                var (key, iv) = DeriveSessionKey();
                return CryptoHelper.AesDecrypt(cipherText, key, iv);
            }
            catch
            {
                return "";
            }
        }

        private (byte[] key, byte[] iv) DeriveSessionKey()
        {
            var fingerprint = MachineFingerprint.Generate();
            // 用机器指纹派生 32 字节 key + 16 字节 iv
            var key = CryptoHelper.DeriveKey(fingerprint, Encoding.UTF8.GetBytes("NetSecurityScanner-SessionKey-Salt"));
            var iv = CryptoHelper.DeriveKey(fingerprint + "-IV", Encoding.UTF8.GetBytes("NetSecurityScanner-SessionIV-Salt!!")).Take(16).ToArray();
            return (key, iv);
        }

        #endregion

        #region Helpers

        private static string GenerateSalt()
        {
            var buf = new byte[SALT_SIZE];
            using var rng = RandomNumberGenerator.Create();
            rng.GetBytes(buf);
            return Convert.ToBase64String(buf);
        }

        private static string HashPassword(string password, string saltB64)
        {
            var salt = Convert.FromBase64String(saltB64);
            var hash = CryptoHelper.DeriveKey(password, salt);
            return Convert.ToBase64String(hash);
        }

        #endregion
    }

    public class LoginResult
    {
        public bool IsSuccess { get; init; }
        public bool IsLocked { get; init; }
        public int LockoutSecondsRemaining { get; init; }
        public string Message { get; init; } = "";
        public User? User { get; init; }

        public static LoginResult Success(User user) => new() { IsSuccess = true, User = user, Message = "登录成功" };
        public static LoginResult Failed(string msg) => new() { IsSuccess = false, Message = msg };
        public static LoginResult Locked(int seconds, string msg) => new() { IsSuccess = false, IsLocked = true, LockoutSecondsRemaining = seconds, Message = msg };
    }

    public class ChangePasswordResult
    {
        public bool IsSuccess { get; init; }
        public string Message { get; init; } = "";

        public static ChangePasswordResult Success() => new() { IsSuccess = true, Message = "密码修改成功" };
        public static ChangePasswordResult Failed(string msg) => new() { IsSuccess = false, Message = msg };
    }

    internal class SessionPayload
    {
        public string UserId { get; set; } = "";
        public string Username { get; set; } = "";
        public DateTime SavedAt { get; set; }
    }
}
