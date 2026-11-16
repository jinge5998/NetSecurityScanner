using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace NetSecurityScanner.Core
{
    public class SecurityService
    {
        private List<User>? _users;
        private Dictionary<string, List<string>>? _roles;
        private List<AuditLog>? _auditLogs;

        private const int Pbkdf2Iterations = 10000;
        private const int SaltSize = 16;
        private const int HashSize = 32;

        public SecurityService()
        {
            InitializeUsers();
            InitializeRoles();
            _auditLogs = new List<AuditLog>();
        }

        public async Task<bool> AuthenticateUserAsync(string username, string password)
        {
            await Task.Delay(100);

            var user = _users.FirstOrDefault(u => u.Username == username);
            if (user == null)
            {
                LogAuditEvent(username, "Authentication", "Failed - User not found");
                return false;
            }

            if (VerifyPassword(password, user.PasswordHash, user.PasswordSalt))
            {
                LogAuditEvent(username, "Authentication", "Success");
                return true;
            }

            LogAuditEvent(username, "Authentication", "Failed - Invalid password");
            return false;
        }

        public async Task<bool> AuthorizeActionAsync(string userId, string action)
        {
            // 基于角色的访问控制 (RBAC)
            // 细粒度权限控制
            // 操作审计日志
            await Task.Delay(50); // 模拟网络延迟

            var user = _users.FirstOrDefault(u => u.UserId == userId);
            if (user == null)
            {
                LogAuditEvent(userId, "Authorization", "Failed - User not found");
                return false;
            }

            if (_roles.ContainsKey(user.Role))
            {
                var permissions = _roles[user.Role];
                var authorized = permissions.Contains(action);

                LogAuditEvent(userId, "Authorization", authorized ? "Success" : "Failed - Insufficient permissions");
                return authorized;
            }

            LogAuditEvent(userId, "Authorization", "Failed - Role not found");
            return false;
        }

        public string EncryptData(string data)
        {
            // 实现数据加密
            // 实际应用中应该使用更安全的加密算法
            return Convert.ToBase64String(System.Text.Encoding.UTF8.GetBytes(data));
        }

        public string DecryptData(string encryptedData)
        {
            // 实现数据解密
            try
            {
                return System.Text.Encoding.UTF8.GetString(Convert.FromBase64String(encryptedData));
            }
            catch
            {
                return string.Empty;
            }
        }

        public bool ValidateScanTarget(string target)
        {
            // 验证扫描目标是否在白名单中
            // 防止扫描被滥用
            var whitelist = new List<string> { "127.0.0.1", "192.168.1.", "10.0.0." };

            return whitelist.Any(w => target.StartsWith(w));
        }

        public void LogAuditEvent(string userId, string action, string details)
        {
            // 记录审计日志
            _auditLogs.Add(new AuditLog
            {
                Timestamp = DateTime.Now,
                UserId = userId,
                Action = action,
                Details = details
            });
        }

        public List<AuditLog> GetAuditLogs(DateTime fromDate, DateTime toDate)
        {
            // 获取指定时间范围内的审计日志
            return _auditLogs.Where(l => l.Timestamp >= fromDate && l.Timestamp <= toDate).ToList();
        }

        private void InitializeUsers()
        {
            string adminSalt = "A7B3C9D1E5F2G8H4";
            string userSalt = "K6L2M8N4O1P7Q3R9";
            string auditSalt = "S5T1U7V3W9X2Y8Z4";

            _users = new List<User>
            {
                new User
                {
                    UserId = "1", Username = "admin",
                    PasswordHash = HashPasswordPbkdf2("admin123", adminSalt),
                    PasswordSalt = adminSalt, Role = "Administrator"
                },
                new User
                {
                    UserId = "2", Username = "user",
                    PasswordHash = HashPasswordPbkdf2("user123", userSalt),
                    PasswordSalt = userSalt, Role = "User"
                },
                new User
                {
                    UserId = "3", Username = "audit",
                    PasswordHash = HashPasswordPbkdf2("audit123", auditSalt),
                    PasswordSalt = auditSalt, Role = "Auditor"
                }
            };
        }

        private static string HashPasswordPbkdf2(string password, string salt)
        {
            byte[] saltBytes = Encoding.UTF8.GetBytes(salt);
            using var deriveBytes = new Rfc2898DeriveBytes(password, saltBytes, Pbkdf2Iterations, HashAlgorithmName.SHA256);
            byte[] hash = deriveBytes.GetBytes(HashSize);
            return Convert.ToBase64String(hash);
        }

        private static bool VerifyPassword(string password, string storedHash, string storedSalt)
        {
            string computedHash = HashPasswordPbkdf2(password, storedSalt);
            return CryptographicOperations.FixedTimeEquals(
                Convert.FromBase64String(computedHash),
                Convert.FromBase64String(storedHash));
        }

        private void InitializeRoles()
        {
            // 初始化角色权限
            _roles = new Dictionary<string, List<string>>
            {
                {
                    "Administrator",
                    new List<string> { "Scan", "ManagePorts", "ManageUsers", "ViewAuditLogs", "GenerateReports" }
                },
                {
                    "User",
                    new List<string> { "Scan", "ViewReports" }
                },
                {
                    "Auditor",
                    new List<string> { "ViewAuditLogs", "ViewReports" }
                }
            };
        }
    }

    public class User
    {
        public string UserId { get; set; }
        public string Username { get; set; }
        public string PasswordHash { get; set; }
        public string PasswordSalt { get; set; }
        public string Role { get; set; }
    }

    public class AuditLog
    {
        public DateTime Timestamp { get; set; }
        public string UserId { get; set; }
        public string Action { get; set; }
        public string Details { get; set; }
    }
}