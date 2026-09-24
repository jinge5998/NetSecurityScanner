using System;
using NetSecurityScanner.Models;

namespace NetSecurityScanner.Services
{
    /// <summary>
    /// 权限校验工具：admin 短路返回 true；普通用户检查 Permissions 列表。
    /// </summary>
    public static class PermissionService
    {
        public static bool HasPermission(User? user, string permission)
        {
            if (user == null) return false;
            if (user.IsAdmin) return true; // 超级管理员拥有所有权限
            return user.Permissions != null && user.Permissions.Contains(permission);
        }

        public static void EnsurePermission(User? user, string permission)
        {
            if (!HasPermission(user, permission))
            {
                throw new UnauthorizedAccessException($"权限不足：需要 {permission}");
            }
        }
    }
}
