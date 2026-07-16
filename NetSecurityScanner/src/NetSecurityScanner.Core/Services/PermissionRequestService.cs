using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using NetSecurityScanner.Models;
using NetSecurityScanner.Utils;

namespace NetSecurityScanner.Services
{
    /// <summary>
    /// 插件权限申请工作流服务（v7-T6）。
    /// 职责：
    ///   1. 插件运行时调用 RequestPermissionAsync 提交申请
    ///   2. 持久化到 data/permission_requests.json
    ///   3. 管理员通过 ApproveAsync / RejectAsync 处理
    ///   4. 批准后自动写入 PluginPolicy.PermissionMatrix + 通知沙箱放行
    ///   5. 拒绝后 1 小时内相同申请直接拒绝
    /// </summary>
    public class PermissionRequestService
    {
        private readonly PluginSecurityService _security;
        private readonly PluginSandboxService? _sandbox;
        private readonly string _storeFile;
        private readonly SemaphoreSlim _lock = new(1, 1);
        private List<PermissionRequest> _all = new();

        public event EventHandler<PermissionRequest>? OnRequestCreated;
        public event EventHandler<PermissionRequest>? OnRequestProcessed;

        public PermissionRequestService(PluginSecurityService security, PluginSandboxService? sandbox = null)
        {
            _security = security;
            _sandbox = sandbox;
            _storeFile = Path.Combine(DataPaths.AppDataDirectory, "permission_requests.json");
            Load();
        }

        public List<PermissionRequest> GetAll() => _all.OrderByDescending(r => r.RequestedAt).ToList();
        public List<PermissionRequest> GetPending() => _all.Where(r => r.Status == PermissionRequestStatus.Pending).ToList();

        /// <summary>插件提交权限申请</summary>
        public async Task<PermissionRequest> RequestPermissionAsync(string pluginId, string permission, string reason)
        {
            // 冷却期检查
            var cooldown = _all.FirstOrDefault(r =>
                r.PluginId == pluginId &&
                r.Permission == permission &&
                r.Status == PermissionRequestStatus.Rejected &&
                r.CooldownUntil > DateTime.Now);
            if (cooldown != null)
            {
                throw new PermissionDeniedException(pluginId, permission,
                    $"权限 {permission} 在冷却期内（{cooldown.CooldownUntil:HH:mm:ss} 前）无法重新申请");
            }

            var req = new PermissionRequest
            {
                PluginId = pluginId,
                Permission = permission,
                Reason = reason
            };

            await _lock.WaitAsync().ConfigureAwait(false);
            try
            {
                _all.Add(req);
                await SaveAsync().ConfigureAwait(false);
            }
            finally
            {
                _lock.Release();
            }

            await _security.AppendAuditAsync(new PluginAuditEntry
            {
                PluginId = pluginId,
                Action = "PermissionRequested",
                Result = "Pending",
                Detail = $"permission={permission}, reason={reason}"
            }).ConfigureAwait(false);

            OnRequestCreated?.Invoke(this, req);
            return req;
        }

        /// <summary>批准申请</summary>
        public async Task ApproveAsync(string requestId, string operatorName, string note)
        {
            var req = _all.FirstOrDefault(r => r.Id == requestId);
            if (req == null) throw new InvalidOperationException("申请不存在");
            if (req.Status != PermissionRequestStatus.Pending) throw new InvalidOperationException("申请已处理");

            req.Status = PermissionRequestStatus.Approved;
            req.ProcessedAt = DateTime.Now;
            req.ProcessedBy = operatorName;
            req.OperatorNote = note;

            // 写入权限矩阵
            var policy = _security.CurrentPolicy;
            if (!policy.PermissionMatrix.TryGetValue(req.PluginId, out var perms))
            {
                perms = new List<string>();
                policy.PermissionMatrix[req.PluginId] = perms;
            }
            if (!perms.Contains(req.Permission)) perms.Add(req.Permission);
            await _security.SavePolicyAsync(policy, operatorName).ConfigureAwait(false);

            // 沙箱放行（如果请求的是路径/网络/进程/注册表）
            if (_sandbox != null) TryApplySandboxGrant(req.Permission);

            await _lock.WaitAsync().ConfigureAwait(false);
            try { await SaveAsync().ConfigureAwait(false); }
            finally { _lock.Release(); }

            await _security.AppendAuditAsync(new PluginAuditEntry
            {
                Operator = operatorName,
                PluginId = req.PluginId,
                Action = "PermissionGranted",
                Result = "Success",
                Detail = $"permission={req.Permission}, note={note}"
            }).ConfigureAwait(false);

            OnRequestProcessed?.Invoke(this, req);
        }

        /// <summary>拒绝申请</summary>
        public async Task RejectAsync(string requestId, string operatorName, string note)
        {
            var req = _all.FirstOrDefault(r => r.Id == requestId);
            if (req == null) throw new InvalidOperationException("申请不存在");
            if (req.Status != PermissionRequestStatus.Pending) throw new InvalidOperationException("申请已处理");

            req.Status = PermissionRequestStatus.Rejected;
            req.ProcessedAt = DateTime.Now;
            req.ProcessedBy = operatorName;
            req.OperatorNote = note;
            req.CooldownUntil = DateTime.Now.AddHours(1);

            await _lock.WaitAsync().ConfigureAwait(false);
            try { await SaveAsync().ConfigureAwait(false); }
            finally { _lock.Release(); }

            await _security.AppendAuditAsync(new PluginAuditEntry
            {
                Operator = operatorName,
                PluginId = req.PluginId,
                Action = "PermissionRejected",
                Result = "Blocked",
                Detail = $"permission={req.Permission}, note={note}, cooldown={req.CooldownUntil:HH:mm:ss}"
            }).ConfigureAwait(false);

            OnRequestProcessed?.Invoke(this, req);
        }

        private void TryApplySandboxGrant(string permission)
        {
            // 约定：permission 前缀 FilePath:/Network:/Process:/Registry: 表示同时放行沙箱
            if (permission.StartsWith("FilePath:", StringComparison.OrdinalIgnoreCase))
                _sandbox?.GrantAccess(permission.Substring("FilePath:".Length), null, null, null);
            else if (permission.StartsWith("Network:", StringComparison.OrdinalIgnoreCase))
                _sandbox?.GrantAccess(string.Empty, permission.Substring("Network:".Length), null, null);
            else if (permission.StartsWith("Process:", StringComparison.OrdinalIgnoreCase))
                _sandbox?.GrantAccess(string.Empty, null, permission.Substring("Process:".Length), null);
            else if (permission.StartsWith("Registry:", StringComparison.OrdinalIgnoreCase))
                _sandbox?.GrantAccess(string.Empty, null, null, permission.Substring("Registry:".Length));
        }

        private void Load()
        {
            try
            {
                if (!File.Exists(_storeFile)) return;
                var json = File.ReadAllText(_storeFile, Encoding.UTF8);
                var list = JsonSerializer.Deserialize<List<PermissionRequest>>(json, new JsonSerializerOptions
                {
                    PropertyNameCaseInsensitive = true
                });
                if (list != null) _all = list;
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"[PermissionRequest] 加载失败: {ex.Message}");
            }
        }

        private async Task SaveAsync()
        {
            try
            {
                var json = JsonSerializer.Serialize(_all, new JsonSerializerOptions
                {
                    WriteIndented = true,
                    Encoder = System.Text.Encodings.Web.JavaScriptEncoder.UnsafeRelaxedJsonEscaping
                });
                var tmp = _storeFile + ".tmp";
                await File.WriteAllTextAsync(tmp, json, Encoding.UTF8).ConfigureAwait(false);
                if (File.Exists(_storeFile)) File.Replace(tmp, _storeFile, null);
                else File.Move(tmp, _storeFile);
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"[PermissionRequest] 保存失败: {ex.Message}");
            }
        }
    }
}
