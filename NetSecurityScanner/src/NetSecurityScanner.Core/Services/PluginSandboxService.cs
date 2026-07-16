using System;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using NetSecurityScanner.Models;

namespace NetSecurityScanner.Services
{
    /// <summary>
    /// 插件沙箱服务（v7-T3）。
    /// 职责：
    ///   1. 校验文件/网络/进程/注册表访问是否在白名单内
    ///   2. 违规抛 SandboxViolationException + 审计
    ///   3. 支持宽松模式（仅记录不阻断）
    /// 4. 与权限矩阵联动：批准后的权限自动放行
    /// </summary>
    public class PluginSandboxService
    {
        private readonly PluginSecurityService _security;
        private readonly PermissionRequestService? _permissionRequest;

        public PluginSandboxService(PluginSecurityService security, PermissionRequestService? permissionRequest = null)
        {
            _security = security;
            _permissionRequest = permissionRequest;
        }

        /// <summary>当前沙箱策略（实时跟随 Policy 变化）</summary>
        private SandboxPolicy Current => _security.CurrentPolicy.Sandbox;

        /// <summary>校验文件读取路径</summary>
        public void CheckFileAccess(string pluginId, string filePath, string operation = "Read")
        {
            if (!Current.Enabled) return;
            if (string.IsNullOrEmpty(filePath)) return;

            var allowed = IsPathAllowed(filePath);
            if (!allowed)
            {
                HandleViolation(pluginId, $"File.{operation}", filePath, $"文件越界: {filePath}");
            }
        }

        /// <summary>校验网络出口</summary>
        public void CheckNetworkAccess(string pluginId, string urlOrHost)
        {
            if (!Current.Enabled) return;
            if (string.IsNullOrEmpty(urlOrHost)) return;

            var host = ExtractHost(urlOrHost);
            if (string.IsNullOrEmpty(host)) return;

            var allowed = Current.AllowedNetworkTargets.Any(pattern => MatchDomain(host, pattern));
            if (!allowed)
            {
                HandleViolation(pluginId, "Network.Http", urlOrHost, $"网络出口未授权: {host}");
            }
        }

        /// <summary>校验进程启动</summary>
        public void CheckProcessStart(string pluginId, string processName)
        {
            if (!Current.Enabled) return;
            if (string.IsNullOrEmpty(processName)) return;

            var name = Path.GetFileNameWithoutExtension(processName).ToLowerInvariant();
            if (!Current.AllowedProcessNames.Any(p => string.Equals(p, name, StringComparison.OrdinalIgnoreCase)))
            {
                HandleViolation(pluginId, "Process.Start", processName, $"未授权进程: {name}");
            }
        }

        /// <summary>校验注册表访问</summary>
        public void CheckRegistryAccess(string pluginId, string keyPath, bool write)
        {
            if (!Current.Enabled) return;
            if (!write) return; // 读操作默认放行
            if (string.IsNullOrEmpty(keyPath)) return;

            var allowed = Current.AllowedRegistryKeys.Any(k =>
                keyPath.StartsWith(k, StringComparison.OrdinalIgnoreCase));
            if (!allowed)
            {
                HandleViolation(pluginId, "Registry.Write", keyPath, $"未授权注册表键: {keyPath}");
            }
        }

        /// <summary>同步放行新权限（PermissionRequest 批准后调用）</summary>
        public void GrantAccess(string path, string? network = null, string? process = null, string? registry = null)
        {
            var policy = _security.CurrentPolicy;
            var sandbox = policy.Sandbox;
            if (!string.IsNullOrEmpty(path) && !sandbox.AllowedPaths.Contains(path))
                sandbox.AllowedPaths.Add(path);
            if (!string.IsNullOrEmpty(network) && !sandbox.AllowedNetworkTargets.Contains(network))
                sandbox.AllowedNetworkTargets.Add(network);
            if (!string.IsNullOrEmpty(process) && !sandbox.AllowedProcessNames.Contains(process))
                sandbox.AllowedProcessNames.Add(process);
            if (!string.IsNullOrEmpty(registry) && !sandbox.AllowedRegistryKeys.Contains(registry))
                sandbox.AllowedRegistryKeys.Add(registry);
            _ = _security.SavePolicyAsync(policy, "sandbox-grant");
        }

        private bool IsPathAllowed(string path)
        {
            try
            {
                var full = Path.GetFullPath(path).Replace('\\', '/');
                foreach (var allowed in Current.AllowedPaths)
                {
                    if (string.IsNullOrEmpty(allowed)) continue;
                    var a = allowed.Replace('\\', '/').TrimEnd('/');
                    if (full.StartsWith(a, StringComparison.OrdinalIgnoreCase)) return true;
                }
            }
            catch
            {
                // 路径非法视为不通过
            }
            return false;
        }

        private void HandleViolation(string pluginId, string operation, string target, string message)
        {
            _ = _security.AppendAuditAsync(new PluginAuditEntry
            {
                PluginId = pluginId ?? "unknown",
                Action = "SandboxViolation",
                Result = "Blocked",
                Detail = $"{operation}: {target}"
            });

            if (Current.PermissiveMode)
            {
                Debug.WriteLine($"[Sandbox-Permissive] {message}");
                return;
            }

            throw new SandboxViolationException(pluginId ?? "?", operation, target, message);
        }

        private static string ExtractHost(string urlOrHost)
        {
            if (urlOrHost.StartsWith("http://", StringComparison.OrdinalIgnoreCase) ||
                urlOrHost.StartsWith("https://", StringComparison.OrdinalIgnoreCase))
            {
                try
                {
                    return new Uri(urlOrHost).Host;
                }
                catch
                {
                    return urlOrHost;
                }
            }
            return urlOrHost;
        }

        private static bool MatchDomain(string host, string pattern)
        {
            if (string.IsNullOrEmpty(pattern)) return false;
            if (pattern.StartsWith("*."))
            {
                var suffix = pattern.Substring(1);
                return host.EndsWith(suffix, StringComparison.OrdinalIgnoreCase) ||
                       string.Equals(host, pattern.Substring(2), StringComparison.OrdinalIgnoreCase);
            }
            return string.Equals(host, pattern, StringComparison.OrdinalIgnoreCase);
        }
    }
}
