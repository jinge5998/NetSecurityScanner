using System;
using System.Collections.Generic;
using System.IO;
using System.Net.Http;
using System.Net.Sockets;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using NetSecurityScanner.Models;
using NetSecurityScanner.Utils;

namespace NetSecurityScanner.Services
{
    /// <summary>
    /// 插件安全治理服务（v6-T2）。
    /// 职责：
    ///   1. 加载/保存 PluginPolicy.json（线程安全 + 原子写）
    ///   2. 检查白/黑名单 + 权限矩阵 + 危险操作拦截
    ///   3. 写入审计日志到 data/plugin_audit/{yyyyMMdd}.json（JSON Lines 追加）
    ///   4. 策略变更事件 OnPolicyChanged
    /// </summary>
    public class PluginSecurityService
    {
        private readonly object _policyLock = new();
        private PluginPolicy _policy = new();
        private readonly string _policyFile;
        private readonly string _auditDir;
        private readonly SemaphoreSlim _auditLock = new(1, 1);

        /// <summary>当前生效的策略（线程安全快照）</summary>
        public PluginPolicy CurrentPolicy
        {
            get { lock (_policyLock) { return ClonePolicy(_policy); } }
        }

        /// <summary>策略变更事件（管控中心保存后触发）</summary>
        public event EventHandler<PluginPolicy>? OnPolicyChanged;

        public PluginSecurityService(string? policyFile = null, string? auditDir = null)
        {
            _policyFile = policyFile ?? Path.Combine(DataPaths.AppDataDirectory, "PluginPolicy.json");
            _auditDir = auditDir ?? Path.Combine(DataPaths.AppDataDirectory, "plugin_audit");
            Directory.CreateDirectory(_auditDir);
            Directory.CreateDirectory(Path.Combine(_auditDir, "archive"));
            LoadPolicy();
        }

        /// <summary>
        /// 加载 PluginPolicy.json，不存在则从 data 目录的默认模板复制。
        /// </summary>
        public void LoadPolicy()
        {
            try
            {
                if (!File.Exists(_policyFile))
                {
                    // 从 Data 目录下的默认模板复制
                    var template = Path.Combine(AppContext.BaseDirectory, "Data", "PluginPolicy.json");
                    if (File.Exists(template))
                    {
                        File.Copy(template, _policyFile, overwrite: true);
                    }
                    else
                    {
                        SavePolicyInternal(new PluginPolicy());
                    }
                }

                var json = File.ReadAllText(_policyFile, Encoding.UTF8);
                var loaded = JsonSerializer.Deserialize<PluginPolicy>(json, new JsonSerializerOptions
                {
                    PropertyNameCaseInsensitive = true
                });
                if (loaded != null)
                {
                    lock (_policyLock) { _policy = loaded; }
                }
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"[PluginSecurityService] 加载策略失败: {ex.Message}");
                lock (_policyLock) { _policy = new PluginPolicy(); }
            }
        }

        /// <summary>
        /// 保存策略（原子写：先写 .tmp 再 File.Move 覆盖）
        /// </summary>
        public async Task SavePolicyAsync(PluginPolicy policy, string operatorName = "admin")
        {
            if (policy == null) throw new ArgumentNullException(nameof(policy));
            policy.LastModified = DateTime.Now;
            policy.LastModifiedBy = operatorName;

            var json = JsonSerializer.Serialize(policy, new JsonSerializerOptions
            {
                WriteIndented = true,
                Encoder = System.Text.Encodings.Web.JavaScriptEncoder.UnsafeRelaxedJsonEscaping
            });

            // 原子写：先临时文件再 Move
            var tmp = _policyFile + ".tmp";
            await File.WriteAllTextAsync(tmp, json, Encoding.UTF8).ConfigureAwait(false);
            if (File.Exists(_policyFile)) File.Replace(tmp, _policyFile, null);
            else File.Move(tmp, _policyFile);

            lock (_policyLock) { _policy = policy; }

            // 写审计
            await AppendAuditAsync(new PluginAuditEntry
            {
                Operator = operatorName,
                PluginId = "*",
                Action = "PolicyChange",
                Result = "Success",
                Detail = $"Whitelist={policy.Whitelist.Count}, Blacklist={policy.Blacklist.Count}, DangerousOps={policy.DangerousOpBlockList.Count}"
            }).ConfigureAwait(false);

            OnPolicyChanged?.Invoke(this, policy);
        }

        private void SavePolicyInternal(PluginPolicy policy)
        {
            var json = JsonSerializer.Serialize(policy, new JsonSerializerOptions
            {
                WriteIndented = true,
                Encoder = System.Text.Encodings.Web.JavaScriptEncoder.UnsafeRelaxedJsonEscaping
            });
            var tmp = _policyFile + ".tmp";
            File.WriteAllText(tmp, json, Encoding.UTF8);
            if (File.Exists(_policyFile)) File.Replace(tmp, _policyFile, null);
            else File.Move(tmp, _policyFile);
            lock (_policyLock) { _policy = policy; }
        }

        /// <summary>
        /// 检查 pluginId 是否被允许加载。
        /// 黑名单优先：黑名单中一律拒绝；白名单非空时仅放行白名单内。
        /// </summary>
        public bool IsAllowed(string pluginId)
        {
            if (string.IsNullOrEmpty(pluginId)) return false;
            PluginPolicy p;
            lock (_policyLock) { p = _policy; }

            if (p.Blacklist.Contains(pluginId)) return false;
            if (p.Whitelist != null && p.Whitelist.Count > 0 && !p.Whitelist.Contains(pluginId)) return false;
            return true;
        }

        /// <summary>
        /// 检查 pluginId 是否有 perm 权限（无策略 = 默认允许）。
        /// </summary>
        public bool HasPermission(string pluginId, string perm)
        {
            if (string.IsNullOrEmpty(pluginId) || string.IsNullOrEmpty(perm)) return true;
            PluginPolicy p;
            lock (_policyLock) { p = _policy; }
            if (p.PermissionMatrix == null) return true;
            if (!p.PermissionMatrix.TryGetValue(pluginId, out var perms)) return true;
            if (perms == null || perms.Count == 0) return true;
            return perms.Contains(perm);
        }

        /// <summary>
        /// 危险操作拦截：若 opName 在拦截列表中则抛 PermissionDeniedException。
        /// </summary>
        public void InterceptDangerousOp(string pluginId, string opName, string? context = null)
        {
            PluginPolicy p;
            lock (_policyLock) { p = _policy; }
            if (p.DangerousOpBlockList == null) return;
            if (p.DangerousOpBlockList.Contains(opName))
            {
                _ = AppendAuditAsync(new PluginAuditEntry
                {
                    PluginId = pluginId ?? string.Empty,
                    Action = "DangerousOpBlocked",
                    Result = "Blocked",
                    Detail = $"op={opName}, context={context}"
                });
                throw new PermissionDeniedException(pluginId ?? "?", opName, $"危险操作 {opName} 已被策略拦截");
            }
        }

        /// <summary>
        /// 追加审计日志到 data/plugin_audit/{yyyyMMdd}.json（JSON Lines 格式，每行一条）。
        /// v7：同时推送到 SIEM（如果配置了）+ 失败写 dead-letter。
        /// </summary>
        public async Task AppendAuditAsync(PluginAuditEntry entry)
        {
            if (entry == null) return;
            entry.Timestamp = entry.Timestamp == default ? DateTime.Now : entry.Timestamp;

            var file = Path.Combine(_auditDir, $"{entry.Timestamp:yyyyMMdd}.json");

            await _auditLock.WaitAsync().ConfigureAwait(false);
            try
            {
                var line = JsonSerializer.Serialize(entry, new JsonSerializerOptions
                {
                    Encoder = System.Text.Encodings.Web.JavaScriptEncoder.UnsafeRelaxedJsonEscaping
                });
                await File.AppendAllTextAsync(file, line + Environment.NewLine, Encoding.UTF8).ConfigureAwait(false);
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"[PluginSecurityService] 写审计失败: {ex.Message}");
            }
            finally
            {
                _auditLock.Release();
            }

            // v7：SIEM 双写
            await TryPushSiemAsync(entry).ConfigureAwait(false);
        }

        /// <summary>
        /// v7：导出指定日期范围的审计日志为 CSV（UTF-8 BOM）
        /// </summary>
        public async Task<int> ExportAuditCsvAsync(DateTime startDate, DateTime endDate, string outputPath)
        {
            if (endDate < startDate) (startDate, endDate) = (endDate, startDate);
            var sb = new StringBuilder();
            sb.Append('\uFEFF'); // UTF-8 BOM
            sb.AppendLine("时间,操作人,插件ID,操作,结果,详情,IP地址");

            int count = 0;
            for (var d = startDate.Date; d <= endDate.Date; d = d.AddDays(1))
            {
                var entries = GetAuditEntries(d);
                foreach (var e in entries)
                {
                    sb.Append(e.Timestamp.ToString("yyyy-MM-dd HH:mm:ss")).Append(',');
                    sb.Append(CsvEscape(e.Operator)).Append(',');
                    sb.Append(CsvEscape(e.PluginId)).Append(',');
                    sb.Append(CsvEscape(e.Action)).Append(',');
                    sb.Append(CsvEscape(e.Result)).Append(',');
                    sb.Append(CsvEscape(e.Detail)).Append(',');
                    sb.Append(CsvEscape(e.IpAddress)).AppendLine();
                    count++;
                }
            }

            var dir = Path.GetDirectoryName(outputPath);
            if (!string.IsNullOrEmpty(dir)) Directory.CreateDirectory(dir);
            await File.WriteAllTextAsync(outputPath, sb.ToString(), new UTF8Encoding(true)).ConfigureAwait(false);
            return count;
        }

        private static string CsvEscape(string? value)
        {
            if (string.IsNullOrEmpty(value)) return string.Empty;
            if (value.Contains(',') || value.Contains('"') || value.Contains('\n'))
            {
                return "\"" + value.Replace("\"", "\"\"") + "\"";
            }
            return value;
        }

        /// <summary>
        /// v7：配置 SIEM 上传
        /// </summary>
        public void ConfigureSiem(SiemConfig config)
        {
            var policy = CurrentPolicy;
            policy.Siem = config ?? new SiemConfig();
            _ = SavePolicyAsync(policy, "siem-config");
        }

        /// <summary>v7：SIEM 推送 + dead-letter</summary>
        private async Task TryPushSiemAsync(PluginAuditEntry entry)
        {
            var siem = CurrentPolicy.Siem;
            if (siem == null || !siem.Enabled || string.IsNullOrEmpty(siem.Endpoint)) return;

            try
            {
                if (siem.Protocol == SiemProtocol.HttpJson)
                {
                    using var http = new HttpClient { Timeout = TimeSpan.FromSeconds(siem.TimeoutSeconds) };
                    if (!string.IsNullOrEmpty(siem.ApiKey))
                        http.DefaultRequestHeaders.Add("Authorization", $"Bearer {siem.ApiKey}");
                    var json = JsonSerializer.Serialize(entry, new JsonSerializerOptions
                    {
                        Encoder = System.Text.Encodings.Web.JavaScriptEncoder.UnsafeRelaxedJsonEscaping
                    });
                    var content = new StringContent(json, Encoding.UTF8, "application/json");
                    var resp = await http.PostAsync(siem.Endpoint, content).ConfigureAwait(false);
                    if (!resp.IsSuccessStatusCode)
                    {
                        throw new HttpRequestException($"HTTP {resp.StatusCode}");
                    }
                }
                else if (siem.Protocol == SiemProtocol.SyslogUdp)
                {
                    using var udp = new UdpClient();
                    var msg = $"<134>{entry.Timestamp:yyyy-MM-ddTHH:mm:ssZ} netsec-scanner {entry.Action} plugin={entry.PluginId} result={entry.Result} detail={entry.Detail}";
                    var bytes = Encoding.UTF8.GetBytes(msg);
                    // Endpoint 格式：udp://host:port
                    var uri = siem.Endpoint.StartsWith("udp://", StringComparison.OrdinalIgnoreCase)
                        ? siem.Endpoint.Substring(6) : siem.Endpoint;
                    var parts = uri.Split(':');
                    if (parts.Length == 2 && int.TryParse(parts[1], out var port))
                    {
                        await udp.SendAsync(bytes, bytes.Length, parts[0], port).ConfigureAwait(false);
                    }
                }
            }
            catch (Exception ex)
            {
                // 写 dead-letter
                try
                {
                    var deadDir = Path.Combine(_auditDir, "dead_letter");
                    Directory.CreateDirectory(deadDir);
                    var deadFile = Path.Combine(deadDir, $"{DateTime.Now:yyyyMMdd}.jsonl");
                    var line = JsonSerializer.Serialize(entry, new JsonSerializerOptions
                    {
                        Encoder = System.Text.Encodings.Web.JavaScriptEncoder.UnsafeRelaxedJsonEscaping
                    });
                    await File.AppendAllTextAsync(deadFile, line + Environment.NewLine, Encoding.UTF8).ConfigureAwait(false);
                }
                catch
                {
                    System.Diagnostics.Debug.WriteLine($"[SIEM] dead-letter 失败: {ex.Message}");
                }
            }
        }

        /// <summary>
        /// 读取某日审计日志（按 JSON Lines 解析）。
        /// </summary>
        public List<PluginAuditEntry> GetAuditEntries(DateTime date)
        {
            var file = Path.Combine(_auditDir, $"{date:yyyyMMdd}.json");
            var list = new List<PluginAuditEntry>();
            if (!File.Exists(file)) return list;
            try
            {
                foreach (var line in File.ReadAllLines(file, Encoding.UTF8))
                {
                    if (string.IsNullOrWhiteSpace(line)) continue;
                    var entry = JsonSerializer.Deserialize<PluginAuditEntry>(line, new JsonSerializerOptions
                    {
                        PropertyNameCaseInsensitive = true
                    });
                    if (entry != null) list.Add(entry);
                }
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"[PluginSecurityService] 读取审计失败: {ex.Message}");
            }
            return list;
        }

        /// <summary>
        /// 归档 30 天前的审计文件到 archive/ 子目录。
        /// </summary>
        public void ArchiveOldAudits(int retentionDays = 30)
        {
            try
            {
                var archiveDir = Path.Combine(_auditDir, "archive");
                Directory.CreateDirectory(archiveDir);
                var cutoff = DateTime.Now.AddDays(-retentionDays);
                foreach (var f in Directory.GetFiles(_auditDir, "*.json"))
                {
                    var name = Path.GetFileNameWithoutExtension(f); // yyyyMMdd
                    if (name.Length == 8 && DateTime.TryParseExact(name, "yyyyMMdd", null, System.Globalization.DateTimeStyles.None, out var d))
                    {
                        if (d < cutoff)
                        {
                            var dest = Path.Combine(archiveDir, Path.GetFileName(f));
                            if (File.Exists(dest)) File.Delete(dest);
                            File.Move(f, dest);
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"[PluginSecurityService] 归档失败: {ex.Message}");
            }
        }

        private static PluginPolicy ClonePolicy(PluginPolicy p)
        {
            return new PluginPolicy
            {
                Whitelist = new List<string>(p.Whitelist ?? new()),
                Blacklist = new List<string>(p.Blacklist ?? new()),
                PermissionMatrix = new Dictionary<string, List<string>>(p.PermissionMatrix ?? new()),
                DangerousOpBlockList = new List<string>(p.DangerousOpBlockList ?? new()),
                LastModified = p.LastModified,
                LastModifiedBy = p.LastModifiedBy
            };
        }
    }
}
