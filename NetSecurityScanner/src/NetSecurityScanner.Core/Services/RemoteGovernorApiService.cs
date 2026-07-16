using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using NetSecurityScanner.Models;

namespace NetSecurityScanner.Services
{
    /// <summary>
    /// 远程管控 API 服务（v7-T5）。
    /// 使用 HttpListener + 自实现 HS256 JWT，监听 127.0.0.1:9530（默认）。
    /// 暴露 7 个 REST 接口，详见 spec.md。
    /// </summary>
    public class RemoteGovernorApiService : IDisposable
    {
        private readonly PluginGovernor _governor;
        private readonly PluginSecurityService _security;
        private HttpListener? _listener;
        private CancellationTokenSource? _cts;
        private Task? _loop;
        private int _port;
        private string _bindAddress;

        public bool IsRunning => _listener?.IsListening ?? false;
        public string BaseUrl => $"http://{_bindAddress}:{_port}";
        public int Port => _port;

        public RemoteGovernorApiService(PluginGovernor governor)
        {
            _governor = governor;
            _security = governor.Security;
        }

        /// <summary>启动 API 服务</summary>
        public Task StartAsync()
        {
            if (IsRunning) return Task.CompletedTask;

            var policy = _security.CurrentPolicy;
            _bindAddress = string.IsNullOrEmpty(policy.RemoteApiBindAddress) ? "127.0.0.1" : policy.RemoteApiBindAddress;
            _port = policy.RemoteApiPort <= 0 ? 9530 : policy.RemoteApiPort;

            // 确保 JWT 密钥
            if (string.IsNullOrEmpty(policy.RemoteApiJwtSecret))
            {
                policy.RemoteApiJwtSecret = GenerateSecret(48);
                _ = _security.SavePolicyAsync(policy, "system-init");
            }

            try
            {
                _listener = new HttpListener();
                _listener.Prefixes.Add($"http://{_bindAddress}:{_port}/api/");
                _listener.Start();
                _cts = new CancellationTokenSource();
                _loop = Task.Run(() => ListenLoop(_cts.Token));
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"[RemoteApi] 启动失败: {ex.Message}");
            }

            return Task.CompletedTask;
        }

        /// <summary>生成临时 JWT（默认 2 小时）</summary>
        public string GenerateTempJwt(string user = "admin", TimeSpan? ttl = null)
        {
            var secret = _security.CurrentPolicy.RemoteApiJwtSecret;
            if (string.IsNullOrEmpty(secret)) throw new InvalidOperationException("JWT 密钥未配置");
            var exp = DateTimeOffset.UtcNow.Add(ttl ?? TimeSpan.FromHours(2)).ToUnixTimeSeconds();
            return GenerateJwt(user, exp, secret);
        }

        private async Task ListenLoop(CancellationToken ct)
        {
            while (!ct.IsCancellationRequested && _listener?.IsListening == true)
            {
                HttpListenerContext ctx;
                try
                {
                    ctx = await _listener.GetContextAsync().ConfigureAwait(false);
                }
                catch (HttpListenerException) { break; }
                catch (ObjectDisposedException) { break; }
                catch (Exception ex)
                {
                    System.Diagnostics.Debug.WriteLine($"[RemoteApi] 接收异常: {ex.Message}");
                    continue;
                }

                _ = Task.Run(() => HandleAsync(ctx));
            }
        }

        private async Task HandleAsync(HttpListenerContext ctx)
        {
            var req = ctx.Request;
            var resp = ctx.Response;
            resp.ContentType = "application/json; charset=utf-8";

            try
            {
                var path = req.Url?.AbsolutePath?.ToLowerInvariant() ?? "/";
                var method = req.HttpMethod.ToUpperInvariant();

                // 鉴权（health 端点免鉴权）
                if (!path.EndsWith("/health"))
                {
                    if (!ValidateJwt(req, out var user))
                    {
                        _ = _security.AppendAuditAsync(new PluginAuditEntry
                        {
                            PluginId = "*",
                            Action = "RemoteApiUnauthorized",
                            Result = "Blocked",
                            Detail = $"{method} {path} from {req.RemoteEndPoint}",
                            IpAddress = req.RemoteEndPoint?.ToString()
                        });
                        await WriteJson(resp, 401, new { error = "Unauthorized" }).ConfigureAwait(false);
                        return;
                    }
                    resp.Headers["X-Authenticated-User"] = user ?? "unknown";
                }

                // 路由
                if (method == "GET" && path == "/api/v7/health")
                {
                    await WriteJson(resp, 200, new { status = "ok", timestamp = DateTime.Now }).ConfigureAwait(false);
                }
                else if (method == "GET" && path == "/api/v7/governor/status")
                {
                    await WriteStatusAsync(resp).ConfigureAwait(false);
                }
                else if (method == "GET" && path == "/api/v7/plugins")
                {
                    await WritePluginsAsync(resp).ConfigureAwait(false);
                }
                else if (method == "POST" && path == "/api/v7/security/policy")
                {
                    await UpdatePolicyAsync(req, resp).ConfigureAwait(false);
                }
                else if (method == "POST" && path.StartsWith("/api/v7/plugins/") && path.EndsWith("/quarantine"))
                {
                    var id = ExtractId(path, "/api/v7/plugins/", "/quarantine");
                    await QuarantineAsync(id, resp).ConfigureAwait(false);
                }
                else if (method == "POST" && path.StartsWith("/api/v7/plugins/") && path.EndsWith("/release"))
                {
                    var id = ExtractId(path, "/api/v7/plugins/", "/release");
                    await ReleaseAsync(id, resp).ConfigureAwait(false);
                }
                else if (method == "GET" && path.StartsWith("/api/v7/traces/"))
                {
                    var traceId = path.Substring("/api/v7/traces/".Length);
                    await GetTraceAsync(traceId, resp).ConfigureAwait(false);
                }
                else if (method == "GET" && path.StartsWith("/api/v7/alerts/recent"))
                {
                    var limit = 50;
                    var qs = req.Url?.Query;
                    if (!string.IsNullOrEmpty(qs))
                    {
                        var match = System.Text.RegularExpressions.Regex.Match(qs, @"limit=(\d+)");
                        if (match.Success && int.TryParse(match.Groups[1].Value, out var n)) limit = Math.Clamp(n, 1, 500);
                    }
                    await GetAlertsAsync(limit, resp).ConfigureAwait(false);
                }
                else
                {
                    await WriteJson(resp, 404, new { error = "Not Found", path }).ConfigureAwait(false);
                }
            }
            catch (Exception ex)
            {
                try
                {
                    await WriteJson(resp, 500, new { error = "Internal Server Error", detail = ex.Message }).ConfigureAwait(false);
                }
                catch { }
            }
            finally
            {
                try { resp.Close(); } catch { }
            }
        }

        private async Task WriteStatusAsync(HttpListenerResponse resp)
        {
            try
            {
                var healthSnaps = _governor.Health?.GetAllSnapshots() ?? new();
                var avgHealth = healthSnaps.Count == 0 ? 100 : (int)healthSnaps.Average(s => s.HealthScore);
                var pending = _governor.VersionManager?.PendingUpdates?.Count ?? 0;
                var quarantined = healthSnaps.Count(s => s.IsQuarantined);
                var tasks = _governor.Scheduler?.Tasks?.Count ?? 0;
                await WriteJson(resp, 200, new
                {
                    health = avgHealth,
                    pendingUpdates = pending,
                    quarantined = quarantined,
                    scheduledTasks = tasks,
                    uptime = (DateTime.Now - System.Diagnostics.Process.GetCurrentProcess().StartTime).TotalSeconds
                }).ConfigureAwait(false);
            }
            catch (Exception ex)
            {
                await WriteJson(resp, 500, new { error = ex.Message }).ConfigureAwait(false);
            }
        }

        private async Task WritePluginsAsync(HttpListenerResponse resp)
        {
            try
            {
                var plugins = _governor.Health?.GetAllSnapshots()?.Select(s => new
                {
                    id = s.PluginId,
                    name = s.Name,
                    healthScore = s.HealthScore,
                    isQuarantined = s.IsQuarantined,
                    totalExecutions = s.TotalExecutions,
                    totalFailures = s.TotalFailures,
                    peakMemoryBytes = s.PeakMemoryBytes
                }).ToList() ?? new();
                await WriteJson(resp, 200, new { count = plugins.Count, plugins }).ConfigureAwait(false);
            }
            catch (Exception ex)
            {
                await WriteJson(resp, 500, new { error = ex.Message }).ConfigureAwait(false);
            }
        }

        private async Task UpdatePolicyAsync(HttpListenerRequest req, HttpListenerResponse resp)
        {
            try
            {
                using var reader = new StreamReader(req.InputStream, Encoding.UTF8);
                var body = await reader.ReadToEndAsync().ConfigureAwait(false);
                var patch = JsonSerializer.Deserialize<Dictionary<string, JsonElement>>(body, new JsonSerializerOptions
                {
                    PropertyNameCaseInsensitive = true
                });
                if (patch == null)
                {
                    await WriteJson(resp, 400, new { error = "Invalid body" }).ConfigureAwait(false);
                    return;
                }

                var policy = _security.CurrentPolicy;
                // 简单支持：whitelist / blacklist / dangerousOpBlockList
                if (patch.TryGetValue("whitelist", out var wl) && wl.ValueKind == JsonValueKind.Array)
                {
                    policy.Whitelist = wl.EnumerateArray().Select(x => x.GetString() ?? "").ToList();
                }
                if (patch.TryGetValue("blacklist", out var bl) && bl.ValueKind == JsonValueKind.Array)
                {
                    policy.Blacklist = bl.EnumerateArray().Select(x => x.GetString() ?? "").ToList();
                }
                if (patch.TryGetValue("dangerousOpBlockList", out var dop) && dop.ValueKind == JsonValueKind.Array)
                {
                    policy.DangerousOpBlockList = dop.EnumerateArray().Select(x => x.GetString() ?? "").ToList();
                }
                await _security.SavePolicyAsync(policy, resp.Headers["X-Authenticated-User"] ?? "remote").ConfigureAwait(false);
                await WriteJson(resp, 200, new { ok = true }).ConfigureAwait(false);
            }
            catch (Exception ex)
            {
                await WriteJson(resp, 500, new { error = ex.Message }).ConfigureAwait(false);
            }
        }

        private async Task QuarantineAsync(string pluginId, HttpListenerResponse resp)
        {
            if (string.IsNullOrEmpty(pluginId))
            {
                await WriteJson(resp, 400, new { error = "pluginId required" }).ConfigureAwait(false);
                return;
            }
            _governor.Health?.Quarantine(pluginId, "远程API");
            await WriteJson(resp, 200, new { ok = true, pluginId, action = "quarantined" }).ConfigureAwait(false);
        }

        private async Task ReleaseAsync(string pluginId, HttpListenerResponse resp)
        {
            if (string.IsNullOrEmpty(pluginId))
            {
                await WriteJson(resp, 400, new { error = "pluginId required" }).ConfigureAwait(false);
                return;
            }
            _governor.Health?.Unquarantine(pluginId);
            await WriteJson(resp, 200, new { ok = true, pluginId, action = "released" }).ConfigureAwait(false);
        }

        private async Task GetTraceAsync(string traceId, HttpListenerResponse resp)
        {
            if (string.IsNullOrEmpty(traceId))
            {
                await WriteJson(resp, 400, new { error = "traceId required" }).ConfigureAwait(false);
                return;
            }
            try
            {
                var tree = _governor.Telemetry != null
                    ? await _governor.Telemetry.QueryTraceAsync(traceId).ConfigureAwait(false)
                    : null;
                if (tree == null)
                {
                    await WriteJson(resp, 404, new { error = "trace not found" }).ConfigureAwait(false);
                    return;
                }
                await WriteJson(resp, 200, new
                {
                    traceId = tree.TraceId,
                    totalElapsedMs = tree.TotalElapsedMs,
                    startTime = tree.StartTime,
                    endTime = tree.EndTime,
                    spans = tree.AllSpans
                }).ConfigureAwait(false);
            }
            catch (Exception ex)
            {
                await WriteJson(resp, 500, new { error = ex.Message }).ConfigureAwait(false);
            }
        }

        private async Task GetAlertsAsync(int limit, HttpListenerResponse resp)
        {
            try
            {
                var entries = _security.GetAuditEntries(DateTime.Today);
                var alerts = entries
                    .Where(e => e.Action.Contains("Blocked") || e.Action.Contains("Quarantined") ||
                                e.Action.Contains("Limit") || e.Action.Contains("SandboxViolation") ||
                                e.Action.Contains("Signature") || e.Action.Contains("Unauthorized"))
                    .OrderByDescending(e => e.Timestamp)
                    .Take(limit)
                    .ToList();
                await WriteJson(resp, 200, new { count = alerts.Count, alerts }).ConfigureAwait(false);
            }
            catch (Exception ex)
            {
                await WriteJson(resp, 500, new { error = ex.Message }).ConfigureAwait(false);
            }
        }

        private static async Task WriteJson(HttpListenerResponse resp, int status, object body)
        {
            resp.StatusCode = status;
            var json = JsonSerializer.Serialize(body, new JsonSerializerOptions
            {
                PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
                WriteIndented = false,
                Encoder = System.Text.Encodings.Web.JavaScriptEncoder.UnsafeRelaxedJsonEscaping
            });
            var bytes = Encoding.UTF8.GetBytes(json);
            resp.ContentLength64 = bytes.Length;
            await resp.OutputStream.WriteAsync(bytes, 0, bytes.Length).ConfigureAwait(false);
        }

        private static string ExtractId(string path, string prefix, string suffix)
        {
            if (!path.StartsWith(prefix)) return string.Empty;
            var mid = path.Substring(prefix.Length);
            if (mid.EndsWith(suffix)) mid = mid.Substring(0, mid.Length - suffix.Length);
            return mid;
        }

        private bool ValidateJwt(HttpListenerRequest req, out string? user)
        {
            user = null;
            var auth = req.Headers["Authorization"];
            if (string.IsNullOrEmpty(auth) || !auth.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase))
                return false;

            var token = auth.Substring("Bearer ".Length).Trim();
            var secret = _security.CurrentPolicy.RemoteApiJwtSecret;
            if (string.IsNullOrEmpty(secret)) return false;

            return VerifyJwt(token, secret, out user);
        }

        /// <summary>生成 HS256 JWT（自实现，不依赖外部库）</summary>
        public static string GenerateJwt(string user, long exp, string secret)
        {
            var header = Convert.ToBase64String(Encoding.UTF8.GetBytes("{\"alg\":\"HS256\",\"typ\":\"JWT\"}")).TrimEnd('=').Replace('+', '-').Replace('/', '_');
            var payload = Convert.ToBase64String(Encoding.UTF8.GetBytes(JsonSerializer.Serialize(new { sub = user, exp }))).TrimEnd('=').Replace('+', '-').Replace('/', '_');
            var unsigned = $"{header}.{payload}";
            using var hmac = new HMACSHA256(Encoding.UTF8.GetBytes(secret));
            var sig = hmac.ComputeHash(Encoding.UTF8.GetBytes(unsigned));
            var sigB64 = Convert.ToBase64String(sig).TrimEnd('=').Replace('+', '-').Replace('/', '_');
            return $"{unsigned}.{sigB64}";
        }

        /// <summary>验证 HS256 JWT</summary>
        public static bool VerifyJwt(string token, string secret, out string? user)
        {
            user = null;
            try
            {
                var parts = token.Split('.');
                if (parts.Length != 3) return false;
                var unsigned = $"{parts[0]}.{parts[1]}";
                using var hmac = new HMACSHA256(Encoding.UTF8.GetBytes(secret));
                var expected = hmac.ComputeHash(Encoding.UTF8.GetBytes(unsigned));
                var expectedB64 = Convert.ToBase64String(expected).TrimEnd('=').Replace('+', '-').Replace('/', '_');
                if (!string.Equals(expectedB64, parts[2], StringComparison.Ordinal)) return false;

                // 解析 payload
                var pad = parts[1].Length % 4;
                if (pad > 0) parts[1] += new string('=', 4 - pad);
                parts[1] = parts[1].Replace('-', '+').Replace('_', '/');
                var json = Encoding.UTF8.GetString(Convert.FromBase64String(parts[1]));
                using var doc = JsonDocument.Parse(json);
                if (doc.RootElement.TryGetProperty("exp", out var expEl) && expEl.TryGetInt64(out var exp))
                {
                    var now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
                    if (now > exp) return false;
                }
                if (doc.RootElement.TryGetProperty("sub", out var subEl))
                {
                    user = subEl.GetString();
                }
                return true;
            }
            catch
            {
                return false;
            }
        }

        private static string GenerateSecret(int bytes)
        {
            var buf = new byte[bytes];
            using var rng = RandomNumberGenerator.Create();
            rng.GetBytes(buf);
            return Convert.ToBase64String(buf).TrimEnd('=').Replace('+', '-').Replace('/', '_');
        }

        public void Stop()
        {
            try { _cts?.Cancel(); } catch { }
            try { _listener?.Stop(); } catch { }
            try { _listener?.Close(); } catch { }
        }

        public void Dispose() => Stop();
    }
}
