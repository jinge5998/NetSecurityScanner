using System;
using System.Collections.Generic;

namespace NetSecurityScanner.Models
{
    /// <summary>
    /// 用户状态
    /// </summary>
    public enum UserStatus
    {
        /// <summary>待审核</summary>
        Pending = 0,
        /// <summary>已激活</summary>
        Active = 1,
        /// <summary>已禁用</summary>
        Disabled = 2
    }

    /// <summary>
    /// 本地账号信息
    /// </summary>
    public class User
    {
        public string Id { get; set; } = "";
        public string Username { get; set; } = "";
        public string DisplayName { get; set; } = "";
        public string PasswordHash { get; set; } = "";
        public string Salt { get; set; } = "";
        public DateTime CreatedAt { get; set; }
        public DateTime? LastLoginAt { get; set; }
        public int FailedAttempts { get; set; }
        public DateTime? LockoutUntil { get; set; }

        // —— 角色与权限（add-role-permission-approval）——
        public bool IsAdmin { get; set; } = false;
        public UserStatus Status { get; set; } = UserStatus.Pending;
        public string? ApprovedBy { get; set; }
        public DateTime? ApprovedAt { get; set; }
        public DateTime? LastModifiedAt { get; set; }
        public string? LastModifiedBy { get; set; }
        public List<string> Permissions { get; set; } = new();

        // —— 注册联系信息（enhance-register-flow）——
        public string? Email { get; set; }
        public string? Phone { get; set; }
        public string? Reason { get; set; }
    }

    /// <summary>
    /// 用户存储（持久化到 users.json）
    /// </summary>
    public class UserStore
    {
        public List<User> Users { get; set; } = new();
    }
}
