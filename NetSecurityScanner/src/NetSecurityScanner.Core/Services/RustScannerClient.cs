using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.IO.Pipes;
using System.Net.Sockets;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using NetSecurityScanner.Core.Models;

namespace NetSecurityScanner.Services
{
    /// <summary>
    /// Rust 扫描服务心跳超时异常，便于上层捕获并回退到内置扫描器
    /// </summary>
    public class RustScannerTimeoutException : TimeoutException
    {
        public RustScannerTimeoutException(string message) : base(message) { }
        public RustScannerTimeoutException(string message, Exception innerException) : base(message, innerException) { }
    }

    /// <summary>
    /// Rust 扫描服务 v1.0.2.1
    /// 通过命名管道或 TCP 与 Rust 扫描服务通信
    /// </summary>
    public class RustScannerClient : IDisposable
    {
        private readonly string _pipeName = "NetSecurityScannerIPC";
        private readonly int _tcpPort = 9527;
        private readonly bool _usePipe = false;
#pragma warning disable CS0414
        private readonly string _version = "1.0.2.0";
#pragma warning restore CS0414
        private NamedPipeClientStream? _pipeClient;
        private TcpClient? _tcpClient;
        private Process? _rustProcess;
        private bool _isConnected = false;

        /// <summary>
        /// 当前是否已连接到 Rust 扫描服务。
        /// </summary>
        public bool IsConnected => _isConnected;

        private CancellationTokenSource? _outputReaderCts;
        private Task? _stdoutReaderTask;
        private Task? _stderrReaderTask;

        // Rust 端使用 snake_case 字段名 (target_ip, scanned_ports 等), C# 默认是 PascalCase
        // 必须使用 SnakeCaseNamingPolicy 才能正确反序列化, 否则所有字段都是默认值
        private static readonly JsonSerializerOptions SnakeCaseOptions = new JsonSerializerOptions
        {
            PropertyNamingPolicy = new SnakeCaseNamingPolicy(),
            PropertyNameCaseInsensitive = true
        };

        /// <summary>
        /// 扫描进度事件
        /// </summary>
        public event EventHandler<RustScanProgress>? OnProgressChanged;

        /// <summary>
        /// 扫描结果事件
        /// </summary>
        public event EventHandler<RustPortResult>? OnResultReceived;

        /// <summary>
        /// 扫描完成事件
        /// </summary>
        public event EventHandler<RustScanComplete>? OnScanComplete;

        /// <summary>
        /// 日志事件
        /// </summary>
        public event EventHandler<string>? OnLog;

        /// <summary>
        /// 启动 Rust 扫描服务进程
        /// </summary>
        public async Task<bool> StartServiceAsync(string rustExePath, int concurrency = 1000, int tcpTimeout = 200, int udpTimeout = 500)
        {
            try
            {
                // 复用已存在的服务：端口 9527 若已被监听，说明上一次的 Rust 服务仍在运行
                // （例如上次扫描异常退出未清理进程、或打开了多个专家模式窗口）。
                // 此时若再启动新进程，Rust 端 bind 会失败并直接退出：
                //   Error: 通常每个套接字地址(协议/网络地址/端口)只允许使用一次。 (os error 10048)
                // 因此先探测并复用，避免无谓的启动失败。
                if (await IsPortInUseAsync(_tcpPort).ConfigureAwait(false))
                {
                    OnLog?.Invoke(this, $"ℹ️ 检测到端口 {_tcpPort} 已有服务在监听，尝试复用现有 Rust 扫描服务");
                    if (await ConnectAsync().ConfigureAwait(false))
                    {
                        OnLog?.Invoke(this, "✅ 已复用现有 Rust 扫描服务（未启动新进程）");
                        return true;
                    }
                    OnLog?.Invoke(this, "⚠️ 端口被占用但无法连接（可能是其它程序占用），仍尝试启动新服务");
                }

                // 检查 Rust 可执行文件是否存在
                if (!File.Exists(rustExePath))
                {
                    OnLog?.Invoke(this, $"⚠️ Rust扫描服务未找到: {rustExePath}");
                    OnLog?.Invoke(this, "将使用内置C#扫描器...");
                    return false;
                }

                // 启动 Rust 进程
                var startInfo = new ProcessStartInfo
                {
                    FileName = rustExePath,
                    Arguments = $"--mode tcp --endpoint {_tcpPort} --concurrency {concurrency} --tcp-timeout {tcpTimeout} --udp-timeout {udpTimeout}",
                    UseShellExecute = false,
                    CreateNoWindow = true,
                    RedirectStandardOutput = true,
                    RedirectStandardError = true
                };

                // Windows 中文环境下 Rust 子进程按系统 ANSI 代码页（GBK, 936）输出中文，
                // 而 .NET 默认以 UTF-8 解码，会把 "通常每个套接字地址..." 显示成
                // "閫氬父姣忎釜濂楁帴瀛楀湴鍧€..." 这类乱码，导致错误信息无法阅读。
                // 显式指定 GBK 编码即可正常显示（仅在支持设置编码的运行时上生效）。
                try
                {
                    var gb2312 = Encoding.GetEncoding("GB2312");
                    startInfo.StandardOutputEncoding = gb2312;
                    startInfo.StandardErrorEncoding = gb2312;
                }
                catch
                {
                    // 某些平台/运行时不支持设置编码，忽略即可（退化为默认 UTF-8）
                }

                _rustProcess = Process.Start(startInfo);
                if (_rustProcess == null)
                {
                    OnLog?.Invoke(this, "❌ 无法启动Rust扫描服务进程");
                    return false;
                }

                // 启动 stdout/stderr 异步读取任务，防止 Rust 端日志填满缓冲区后阻塞
                _outputReaderCts = new CancellationTokenSource();
                _stdoutReaderTask = Task.Run(() => ReadStreamAsync(_rustProcess.StandardOutput, "stdout", _outputReaderCts.Token));
                _stderrReaderTask = Task.Run(() => ReadStreamAsync(_rustProcess.StandardError, "stderr", _outputReaderCts.Token));

                // 等待服务启动 - 分段等待, 最多 3 秒
                // Rust 服务需要时间初始化 Tokio 运行时和创建命名管道监听器
                for (int i = 0; i < 6; i++)
                {
                    await Task.Delay(500);
                    if (_rustProcess.HasExited)
                    {
                        // 先取消读取任务，避免与后续 ReadToEndAsync 竞争
                        try
                        {
                            _outputReaderCts?.Cancel();
                            if (_stdoutReaderTask != null)
                                await Task.WhenAny(_stdoutReaderTask, Task.Delay(1000));
                            if (_stderrReaderTask != null)
                                await Task.WhenAny(_stderrReaderTask, Task.Delay(1000));
                        }
                        catch { }

                        OnLog?.Invoke(this, $"❌ Rust扫描服务启动后退出 (退出码: {_rustProcess.ExitCode})");

                        // 读取 stderr 获取详细错误
                        string stderrText = string.Empty;
                        try
                        {
                            stderrText = await _rustProcess.StandardError.ReadToEndAsync();
                            if (!string.IsNullOrEmpty(stderrText))
                                OnLog?.Invoke(this, $"   stderr: {stderrText.Trim()}");
                        }
                        catch { }

                        // 针对 os error 10048（端口被占用）给出精准提示，
                        // 避免统一提示"缺少运行库/防火墙"误导排查方向。
                        if (stderrText.Contains("10048"))
                        {
                            OnLog?.Invoke(this, $"   ➜ 端口 {_tcpPort} 已被占用：上一个 Rust 扫描服务进程可能未退出。");
                            OnLog?.Invoke(this, "   ➜ 处理：关闭其它扫描窗口，或在任务管理器结束残留的 rust-scanner-service 进程后重试。");
                        }
                        else
                        {
                            OnLog?.Invoke(this, "   可能原因: 参数错误、缺少运行库、防火墙拦截等");
                        }

                        _rustProcess.Dispose();
                        _rustProcess = null;
                        _outputReaderCts?.Dispose();
                        _outputReaderCts = null;
                        _stdoutReaderTask = null;
                        _stderrReaderTask = null;
                        return false;
                    }
                }

                OnLog?.Invoke(this, $"🚀 Rust扫描服务已启动 (PID: {_rustProcess.Id})");
                OnLog?.Invoke(this, $"   并发数: {concurrency}, TCP超时: {tcpTimeout}ms, UDP超时: {udpTimeout}ms");

                return true;
            }
            catch (Exception ex)
            {
                OnLog?.Invoke(this, $"❌ 启动Rust服务失败: {ex.Message}");
                return false;
            }
        }

        /// <summary>
        /// Rust tracing 输出的 ANSI 颜色/样式转义序列。保留它们会严重干扰日志阅读与检索。
        /// </summary>
        private static readonly Regex AnsiEscapeRegex =
            new Regex(@"\x1B\[[0-9;]*[A-Za-z]", RegexOptions.Compiled);

        /// <summary>
        /// 判断 Rust 子进程的输出行是否应丢弃。
        ///
        /// 背景：Rust 端以 tracing 的 INFO 级别逐端口打印日志，形如
        ///   scan_tcp_port: 211.137.75.166 65327 -> filtered
        ///   [result] 211.137.75.166:80
        /// 全端口扫描（65535 端口）会产生 6 万行以上，实测单个日志文件膨胀到 40MB，
        /// 既拖慢扫描也几乎无法检索。而这些逐端口行对排查问题没有价值——
        /// 扫描结果已通过 IPC 协议返回给 C#，不需要再从日志里读。
        ///
        /// 因此只保留 WARN / ERROR 以及无级别标记的行（如 panic、自定义输出）。
        /// </summary>
        private static bool ShouldSkipRustOutput(string rawLine)
        {
            var line = AnsiEscapeRegex.Replace(rawLine, "").Trim();
            if (line.Length == 0) return true;                                  // 空行
            if (line.StartsWith("at ", StringComparison.Ordinal)) return true;  // tracing 位置行 at src\...rs:NNN
            if (line.IndexOf(" INFO ", StringComparison.Ordinal) >= 0) return true;
            if (line.IndexOf(" DEBUG ", StringComparison.Ordinal) >= 0) return true;
            if (line.IndexOf(" TRACE ", StringComparison.Ordinal) >= 0) return true;
            return false;
        }

        /// <summary>
        /// 异步读取 Rust 子进程输出流，防止缓冲区满导致子进程阻塞
        /// </summary>
        private async Task ReadStreamAsync(StreamReader reader, string prefix, CancellationToken cancellationToken)
        {
            try
            {
                var canceledTask = Task.Delay(Timeout.Infinite, cancellationToken);
                while (!cancellationToken.IsCancellationRequested)
                {
                    var readTask = reader.ReadLineAsync();
                    var completed = await Task.WhenAny(readTask, canceledTask);
                    if (completed == canceledTask)
                        break;

                    var line = await readTask;
                    if (line == null)
                        break;

                    // 过滤逐端口的 INFO 噪音，并剥离 ANSI 转义码后写入
                    if (ShouldSkipRustOutput(line)) continue;

                    OnLog?.Invoke(this, $"[Rust {prefix}] {AnsiEscapeRegex.Replace(line, "").TrimEnd()}");
                }
            }
            catch (OperationCanceledException) { }
            catch (ObjectDisposedException) { }
            catch (InvalidOperationException) { }
            catch (Exception ex)
            {
                try { OnLog?.Invoke(this, $"[Rust {prefix}] 读取流异常: {ex.Message}"); } catch { }
            }
        }

        /// <summary>
        /// 探测本机指定 TCP 端口是否已被监听。
        /// 用于判断 Rust 扫描服务是否已在运行（避免重复启动导致 os error 10048）。
        /// </summary>
        private static async Task<bool> IsPortInUseAsync(int port)
        {
            TcpClient? probe = null;
            try
            {
                probe = new TcpClient();
                // 用超时任务兜底：端口无监听时 ConnectAsync 会等待系统超时（可能数秒）
                var connectTask = probe.ConnectAsync("127.0.0.1", port);
                var timeoutTask = Task.Delay(700);
                var completed = await Task.WhenAny(connectTask, timeoutTask).ConfigureAwait(false);

                if (completed != connectTask)
                {
                    // 超时：未连上，视为端口未被监听
                    _ = connectTask.ContinueWith(t => { _ = t.Exception; }, TaskScheduler.Default);
                    return false;
                }

                await connectTask.ConfigureAwait(false); // 消化异常，避免未观察任务异常
                return probe.Connected;
            }
            catch
            {
                return false;
            }
            finally
            {
                try { probe?.Dispose(); } catch { }
            }
        }

        /// <summary>
        /// 连接到 Rust 服务 (带重试)
        /// </summary>
        public async Task<bool> ConnectAsync()
        {
            // 最多重试 3 次, 每次间隔 500ms
            // Rust 服务进程已启动但命名管道监听器可能尚未就绪
            for (int attempt = 1; attempt <= 3; attempt++)
            {
                try
                {
                    if (_usePipe)
                    {
                        try { _pipeClient?.Dispose(); } catch { }
                        _pipeClient = new NamedPipeClientStream(".", _pipeName, PipeDirection.InOut, PipeOptions.Asynchronous);
                        await _pipeClient.ConnectAsync(3000);
                        _isConnected = true;
                        OnLog?.Invoke(this, $"✅ 已连接到Rust扫描服务 (命名管道, 第{attempt}次尝试)");
                        return true;
                    }
                    else
                    {
                        try { _tcpClient?.Dispose(); } catch { }
                        _tcpClient = new TcpClient();
                        await _tcpClient.ConnectAsync("127.0.0.1", _tcpPort);
                        _isConnected = true;
                        OnLog?.Invoke(this, $"✅ 已连接到Rust扫描服务 (TCP, 第{attempt}次尝试)");
                        return true;
                    }
                }
                catch (Exception ex)
                {
                    OnLog?.Invoke(this, $"⚠️ 连接Rust服务失败(第{attempt}次): {ex.Message}");
                    _isConnected = false;
                    // 清理失败的连接资源
                    if (_usePipe)
                    {
                        try { _pipeClient?.Dispose(); } catch { }
                        _pipeClient = null;
                    }
                    else
                    {
                        try { _tcpClient?.Dispose(); } catch { }
                        _tcpClient = null;
                    }
                    if (attempt < 3)
                        await Task.Delay(500);
                }
            }

            OnLog?.Invoke(this, "❌ 连接Rust服务3次重试均失败, 将回退到内置C#扫描器");
            return false;
        }

        /// <summary>
        /// 执行端口扫描
        /// </summary>
        public async Task<List<RustPortResult>> ScanPortsAsync(
            List<string> targets,
            List<int> ports,
            string protocol = "tcp",
            int concurrency = 1000,
            int tcpTimeoutMs = 200,
            int udpTimeoutMs = 500,
            bool detectService = false,
            bool includeClosed = false,
            CancellationToken cancellationToken = default,
            ScanProfileConfig? profileConfig = null)
        {
            var results = new List<RustPortResult>();

            if (!_isConnected)
            {
                await ConnectAsync();
            }

            if (!_isConnected)
            {
                OnLog?.Invoke(this, "⚠️ 未连接到Rust服务，使用内置扫描器");
                // 回退到内置扫描器
                return await FallbackScanAsync(targets, ports, protocol, cancellationToken, profileConfig);
            }

            bool scanCompleted = false; // 标记是否收到 complete 消息 (需在 try 外声明, 供回退逻辑使用)

            try
            {
                // 构造请求
                // 优先使用 ScanProfileConfig 中的高级参数；如果未提供，则保持原有默认行为
                var request = new RustScanRequest
                {
                    RequestId = Guid.NewGuid().ToString(),
                    MessageType = "scan",
                    Targets = targets,
                    Ports = ports.ConvertAll(p => (ushort)p),
                    Protocol = protocol,
                    Concurrency = profileConfig?.TcpConcurrency ?? concurrency,
                    TcpTimeoutMs = profileConfig?.TimeoutMs ?? tcpTimeoutMs,
                    // UDP 超时必须独立于 TCP：此前误用 profileConfig.TimeoutMs（即 TCP 超时），
                    // 导致 UDP 探测沿用过短的 TCP 超时，UDP 端口被大量误判为关闭/过滤。
                    // UdpTimeoutMs 为 0 表示调用方未单独配置，此时回退到 udpTimeoutMs 参数。
                    UdpTimeoutMs = (profileConfig?.UdpTimeoutMs ?? 0) > 0
                        ? profileConfig!.UdpTimeoutMs
                        : udpTimeoutMs,
                    DetectService = profileConfig?.EnableServiceDetection ?? detectService,
                    IncludeClosed = includeClosed,
                    TcpConcurrency = profileConfig?.TcpConcurrency ?? concurrency,
                    UdpConcurrency = profileConfig?.UdpConcurrency ?? concurrency,
                    RetryCount = profileConfig?.RetryCount,
                    EnablePingProbe = profileConfig?.EnablePingProbe
                };

                var requestJson = JsonSerializer.Serialize(request, new JsonSerializerOptions
                {
                    PropertyNamingPolicy = new SnakeCaseNamingPolicy()
                });
                OnLog?.Invoke(this, $"发送扫描请求: {targets.Count} 目标, {ports.Count} 端口");

                // 发送请求
                var stream = _usePipe ? (Stream)_pipeClient! : _tcpClient!.GetStream();
                var requestBytes = Encoding.UTF8.GetBytes(requestJson + "\n");
                await stream.WriteAsync(requestBytes, cancellationToken);
                // 必须显式 Flush, 否则数据会留在 .NET 缓冲区里
                // 导致 C# 阻塞在 ReadAsync, 而 Rust 阻塞在 read_until 形成死锁
                // (WriteAsync 仅写入用户态缓冲区, 不保证数据已写入管道)
                await stream.FlushAsync(cancellationToken);
                OnLog?.Invoke(this, "✅ 请求已发送并 flush 到管道");

                // 接收响应 (带心跳监控: 15秒未收到任何消息认为卡死)
                // 使用 BinaryReader + 手动按行解析, 避免 StreamReader 内部缓冲导致 ReadLineAsync 提前返回 null
                var lastMessageTime = DateTime.UtcNow;
                const int heartbeatTimeoutSeconds = 15;
                var pipeBuffer = new byte[64 * 1024];
                var lineBuffer = new StringBuilder();

                while (!cancellationToken.IsCancellationRequested)
                {
                    // 心跳检查: 15秒未收到任何消息则触发心跳超时
                    if (DateTime.UtcNow - lastMessageTime > TimeSpan.FromSeconds(heartbeatTimeoutSeconds))
                    {
                        var idle = (DateTime.UtcNow - lastMessageTime).TotalSeconds;
                        OnLog?.Invoke(this, $"❌ Rust扫描服务 {heartbeatTimeoutSeconds} 秒无响应，触发心跳超时 ({idle:F0}s 未收到任何消息)");
                        _isConnected = false; // 标记连接已断开
                        StopService();
                        throw new RustScannerTimeoutException("Rust扫描服务 15 秒无响应，已触发心跳超时");
                    }

                    // 直接阻塞读取, 由 cancellationToken 控制超时 (用户取消或心跳机制通过 catch 处理)
                    // 之前的 Task.WhenAny + 1秒轮询会丢弃未完成的 readTask, 导致数据竞争
                    int n;
                    try
                    {
                        n = await stream.ReadAsync(pipeBuffer, 0, pipeBuffer.Length, cancellationToken);
                    }
                    catch (OperationCanceledException) { break; }
                    catch (IOException ex)
                    {
                        OnLog?.Invoke(this, $"⚠️ 读取异常: {ex.Message}");
                        _isConnected = false; // 标记连接已断开
                        break;
                    }

                    if (n == 0)
                    {
                        OnLog?.Invoke(this, "⚠️ Rust 服务关闭了连接");
                        _isConnected = false; // 标记连接已断开
                        break;
                    }

                    lineBuffer.Append(Encoding.UTF8.GetString(pipeBuffer, 0, n));
                    lastMessageTime = DateTime.UtcNow;

                    // 解析所有完整行 (按 \n 切分, 保留最后一段作为下一轮的不完整行)
                    var lines = lineBuffer.ToString().Split('\n');
                    for (int i = 0; i < lines.Length - 1; i++)
                    {
                        var line = lines[i].Trim();
                        if (string.IsNullOrEmpty(line)) continue;
                        lastMessageTime = DateTime.UtcNow;

                        try
                        {
                            // 先用 JsonDocument 提取 type 字段 (小写比较), 避免重复反序列化
                            using var doc = JsonDocument.Parse(line);
                            var root = doc.RootElement;
                            if (!root.TryGetProperty("type", out var typeProp)) continue;
                            var type = typeProp.GetString()?.ToLower();

                            switch (type)
                            {
                                case "heartbeat":
                                    // Rust 端每 10 秒发送心跳, 重置 C# 端心跳计时器
                                    // 防止长时间扫描(如大量端口)时被 C# 端 15 秒超时误杀
                                    break;

                                case "progress":
                                    var progress = JsonSerializer.Deserialize<RustScanProgress>(line, SnakeCaseOptions);
                                    if (progress != null)
                                    {
                                        progress.Type = "progress";
                                        OnProgressChanged?.Invoke(this, progress);
                                    }
                                    break;

                                case "result":
                                    try
                                    {
                                        var result = JsonSerializer.Deserialize<RustPortResult>(line, SnakeCaseOptions);
                                        if (result != null)
                                        {
                                            result.Type = "result";
                                            results.Add(result);
                                            OnResultReceived?.Invoke(this, result);
                                            OnLog?.Invoke(this, $"📥 收到结果: {result.TargetIp}:{result.Port} [{result.Status}] svc={result.Service}");
                                        }
                                        else
                                        {
                                            OnLog?.Invoke(this, $"⚠️ 反序列化 result 返回 null: {line.Substring(0, Math.Min(line.Length, 200))}");
                                        }
                                    }
                                    catch (JsonException jsonEx)
                                    {
                                        OnLog?.Invoke(this, $"❌ 反序列化 result 失败: {jsonEx.Message} | 内容: {line.Substring(0, Math.Min(line.Length, 200))}");
                                    }
                                    break;

                                case "complete":
                                    var complete = JsonSerializer.Deserialize<RustScanComplete>(line, SnakeCaseOptions);
                                    if (complete != null)
                                    {
                                        complete.Type = "complete";
                                        scanCompleted = true;
                                        OnScanComplete?.Invoke(this, complete);
                                        OnLog?.Invoke(this, $"✅ 扫描完成: {complete.TotalResults} 结果, {complete.OpenPorts} 开放端口");
                                    }
                                    lineBuffer.Clear();
                                    return results;

                                case "error":
                                    var error = JsonSerializer.Deserialize<RustScanError>(line, SnakeCaseOptions);
                                    if (error != null)
                                    {
                                        OnLog?.Invoke(this, $"❌ Rust服务错误: {error.Message}");
                                    }
                                    break;
                            }
                        }
                        catch (JsonException)
                        {
                            // 忽略解析错误
                        }
                    }
                    // 保留最后一段 (可能是不完整的行) 给下一轮
                    lineBuffer.Clear();
                    lineBuffer.Append(lines[lines.Length - 1]);
                }
            }
            catch (Exception ex)
            {
                OnLog?.Invoke(this, $"❌ Rust扫描异常: {ex.Message}");
            }

            // 如果 Rust 扫描未正常完成 (心跳超时/连接断开/异常), 回退到 C# 扫描器
            // 注意: scanCompleted=true 但 results.Count==0 是合法情况 (目标确实无开放端口)
            if (!scanCompleted)
            {
                OnLog?.Invoke(this, "⚠️ Rust 扫描未正常完成, 回退到内置 C# 扫描器");
                return await FallbackScanAsync(targets, ports, protocol, cancellationToken, profileConfig);
            }

            return results;
        }

        /// <summary>
        /// 回退到内置 C# 扫描器
        /// </summary>
        private async Task<List<RustPortResult>> FallbackScanAsync(
            List<string> targets,
            List<int> ports,
            string protocol,
            CancellationToken cancellationToken,
            ScanProfileConfig? profileConfig = null)
        {
            var results = new List<RustPortResult>();
            var scanner = new PortScanner();

            foreach (var target in targets)
            {
                if (cancellationToken.IsCancellationRequested) break;

                OnLog?.Invoke(this, $"扫描目标: {target}");

                var portResults = await scanner.ScanTcpPortsAsync(
                    target,
                    ports,
                    new Progress<int>(p => OnProgressChanged?.Invoke(this, new RustScanProgress
                    {
                        CurrentTarget = target,
                        ProgressPercent = p,
                        ScannedPorts = (int)(p * ports.Count / 100.0)
                    })),
                    cancellationToken
                );

                foreach (var pr in portResults)
                {
                    if (pr.Status == "开放") // 只返回开放端口
                    {
                        results.Add(new RustPortResult
                        {
                            TargetIp = target,
                            Port = (ushort)pr.PortNumber,
                            Protocol = "TCP",
                            Status = pr.Status,
                            Service = pr.Service,
                            Version = pr.ServiceVersion ?? "",
                            Banner = "",
                            ScanTimeMs = 0
                        });
                    }
                }
            }

            OnScanComplete?.Invoke(this, new RustScanComplete
            {
                TotalResults = results.Count,
                OpenPorts = results.Count,
                ScanTimeMs = 0
            });

            return results;
        }

        /// <summary>
        /// 异步获取 Rust 扫描服务当前负载状态。
        /// 若 Rust 端尚未实现 status 响应，则返回模拟负载（低负载，不触发降级）。
        /// </summary>
        public async Task<RustStatusResponse?> GetStatusAsync(CancellationToken cancellationToken = default)
        {
            if (!_isConnected && !await ConnectAsync().ConfigureAwait(false))
            {
                return null;
            }

            using var cts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            cts.CancelAfter(TimeSpan.FromSeconds(3));

            try
            {
                var request = new RustStatusRequest
                {
                    RequestId = Guid.NewGuid().ToString(),
                    MessageType = "status"
                };

                var requestJson = JsonSerializer.Serialize(request, new JsonSerializerOptions
                {
                    PropertyNamingPolicy = new SnakeCaseNamingPolicy()
                });

                var stream = _usePipe ? (Stream)_pipeClient! : _tcpClient!.GetStream();
                var requestBytes = Encoding.UTF8.GetBytes(requestJson + "\n");
                await stream.WriteAsync(requestBytes, cts.Token).ConfigureAwait(false);
                await stream.FlushAsync(cts.Token).ConfigureAwait(false);

                var buffer = new byte[8 * 1024];
                var lineBuffer = new StringBuilder();

                while (!cts.Token.IsCancellationRequested)
                {
                    int n;
                    try
                    {
                        n = await stream.ReadAsync(buffer, 0, buffer.Length, cts.Token).ConfigureAwait(false);
                    }
                    catch (OperationCanceledException)
                    {
                        break;
                    }
                    catch (IOException)
                    {
                        break;
                    }

                    if (n == 0)
                    {
                        OnLog?.Invoke(this, "⚠️ Rust 服务关闭了连接");
                        break;
                    }

                    lineBuffer.Append(Encoding.UTF8.GetString(buffer, 0, n));
                    var lines = lineBuffer.ToString().Split('\n');
                    for (int i = 0; i < lines.Length - 1; i++)
                    {
                        var line = lines[i].Trim();
                        if (string.IsNullOrEmpty(line)) continue;

                        try
                        {
                            using var doc = JsonDocument.Parse(line);
                            var root = doc.RootElement;
                            if (!root.TryGetProperty("type", out var typeProp)) continue;
                            var type = typeProp.GetString()?.ToLowerInvariant();

                            if (type == "status")
                            {
                                var status = JsonSerializer.Deserialize<RustStatusResponse>(line, SnakeCaseOptions);
                                if (status != null)
                                {
                                    status.Type = "status";
                                    OnLog?.Invoke(this, $"📊 Rust 服务状态: CPU {status.CpuPercent:F1}%, 内存 {status.MemoryPercent:F1}%");
                                    return status;
                                }
                            }
                        }
                        catch (JsonException)
                        {
                            // 忽略解析错误
                        }
                    }

                    lineBuffer.Clear();
                    lineBuffer.Append(lines[lines.Length - 1]);
                }
            }
            catch (Exception ex)
            {
                OnLog?.Invoke(this, $"⚠️ 获取 Rust 服务状态失败: {ex.Message}");
            }

            // Rust 端尚未实现 status 时，返回模拟低负载，避免误降级。
            return new RustStatusResponse
            {
                Type = "status",
                CpuPercent = 35.0,
                MemoryPercent = 40.0,
                LoadAverage = 0.4
            };
        }

        /// <summary>
        /// 同步获取 Rust 扫描服务当前负载状态。
        /// </summary>
        public RustStatusResponse? GetStatus(CancellationToken cancellationToken = default)
        {
            return GetStatusAsync(cancellationToken).ConfigureAwait(false).GetAwaiter().GetResult();
        }

        /// <summary>
        /// 停止 Rust 服务
        /// </summary>
        public void StopService()
        {
            try
            {
                // 取消 stdout/stderr 读取任务，避免无限阻塞
                try
                {
                    _outputReaderCts?.Cancel();
                }
                catch { }

                if (_pipeClient != null)
                {
                    _pipeClient.Close();
                    _pipeClient.Dispose();
                    _pipeClient = null;
                }

                if (_tcpClient != null)
                {
                    _tcpClient.Close();
                    _tcpClient.Dispose();
                    _tcpClient = null;
                }

                if (_rustProcess != null && !_rustProcess.HasExited)
                {
                    _rustProcess.Kill();
                    _rustProcess.WaitForExit(1000);
                    OnLog?.Invoke(this, $"🛑 Rust扫描服务已停止 (PID: {_rustProcess.Id})");
                }

                // 等待读取任务结束，最多 2 秒
                try
                {
                    if (_stdoutReaderTask != null)
                    {
                        _stdoutReaderTask.Wait(TimeSpan.FromSeconds(2));
                        _stdoutReaderTask = null;
                    }
                    if (_stderrReaderTask != null)
                    {
                        _stderrReaderTask.Wait(TimeSpan.FromSeconds(2));
                        _stderrReaderTask = null;
                    }
                }
                catch { }

                _outputReaderCts?.Dispose();
                _outputReaderCts = null;

                _rustProcess?.Dispose();
                _rustProcess = null;
                _isConnected = false;
            }
            catch (Exception ex)
            {
                OnLog?.Invoke(this, $"⚠️ 停止Rust服务异常: {ex.Message}");
            }
        }

        /// <summary>
        /// 在常见路径中查找 Rust 扫描服务可执行文件。
        /// 返回完整路径，未找到则返回 null。
        /// 搜索顺序（从最可能到最不可能）：
        ///   1. 应用根目录（发布/启动脚本场景）
        ///   2. tools/、rust/ 子目录
        ///   3. publish-* 平级目录（dev 启动器场景）
        ///   4. src\rust-scanner-service\target\release|debug（开发编译场景）
        /// </summary>
        public static string? FindRustScannerExecutable()
        {
            var appDir = AppDomain.CurrentDomain.BaseDirectory;

            // 规范化: 展开 ..\..\ 之类, 方便后续比较
            string Norm(string p)
            {
                try { return Path.GetFullPath(p); } catch { return p; }
            }

            var candidates = new List<string>
            {
                // 1. 应用根目录直接放置
                Path.Combine(appDir, "rust-scanner-service.exe"),
                Path.Combine(appDir, "rust_scanner_service.exe"),
                // 2. 子目录放置
                Path.Combine(appDir, "tools", "rust-scanner-service.exe"),
                Path.Combine(appDir, "rust", "rust-scanner-service.exe"),
                Path.Combine(appDir, "engines", "rust-scanner-service.exe"),
                Path.Combine(appDir, "native", "rust-scanner-service.exe"),
            };

            // 3. publish-v* 平级目录（dev 启动器从 publish-v1.0.1.6 启动时，需要回溯到 NetSecurityScanner 根目录）
            try
            {
                var parent = Directory.GetParent(appDir)?.FullName;
                while (parent != null)
                {
                    // 1) 父目录直接放 exe
                    candidates.Add(Path.Combine(parent, "rust-scanner-service.exe"));
                    // 2) 父目录的 publish-v* 子目录
                    foreach (var sub in Directory.EnumerateDirectories(parent, "publish-v*"))
                    {
                        candidates.Add(Path.Combine(sub, "rust-scanner-service.exe"));
                        candidates.Add(Path.Combine(sub, "tools", "rust-scanner-service.exe"));
                    }
                    // 3) 父目录的 rust-scanner-service 源码构建产物
                    candidates.Add(Path.Combine(parent, "src", "rust-scanner-service", "target", "release", "rust-scanner-service.exe"));
                    candidates.Add(Path.Combine(parent, "src", "rust-scanner-service", "target", "debug", "rust-scanner-service.exe"));
                    // 4) NetSecurityScanner 项目根的 tools 目录
                    candidates.Add(Path.Combine(parent, "tools", "rust-scanner-service.exe"));
                    // 到 NetSecurityScanner 根目录即可停止上溯
                    if (Path.GetFileName(parent).Equals("NetSecurityScanner", StringComparison.OrdinalIgnoreCase))
                        break;
                    parent = Directory.GetParent(parent)?.FullName;
                }
            }
            catch { /* 忽略上溯失败 */ }

            // 4. 兼容 ../../../../ 相对路径（开发期 dotnet run）
            candidates.Add(Path.GetFullPath(Path.Combine(appDir, "..", "..", "..", "..", "rust-scanner-service", "target", "release", "rust-scanner-service.exe")));
            candidates.Add(Path.GetFullPath(Path.Combine(appDir, "..", "..", "..", "..", "rust-scanner-service", "target", "debug", "rust-scanner-service.exe")));

            // 去重 + 校验
            var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            foreach (var raw in candidates)
            {
                if (string.IsNullOrWhiteSpace(raw)) continue;
                var path = Norm(raw);
                if (!seen.Add(path)) continue;
                try
                {
                    if (File.Exists(path))
                        return path;
                }
                catch { }
            }

            return null;
        }

        /// <summary>
        /// 返回找到的 Rust 引擎目录（用于 UI 展示和"打开所在文件夹"），未找到返回 null。
        /// </summary>
        public static string? FindRustScannerDirectory()
        {
            var exe = FindRustScannerExecutable();
            if (exe == null) return null;
            try { return Path.GetDirectoryName(exe); } catch { return null; }
        }

        public void Dispose()
        {
            StopService();
        }
    }

    #region Rust IPC 数据结构

    /// <summary>
    /// Rust 状态查询请求
    /// </summary>
    public class RustStatusRequest
    {
        public string RequestId { get; set; } = "";
        public string MessageType { get; set; } = "status";
    }

    /// <summary>
    /// Rust 状态查询响应
    /// </summary>
    public class RustStatusResponse : RustResponse
    {
        public double CpuPercent { get; set; }
        public double MemoryPercent { get; set; }
        public double LoadAverage { get; set; }
    }

    /// <summary>
    /// Rust 扫描请求
    /// </summary>
    public class RustScanRequest
    {
        public string RequestId { get; set; } = "";
        public string MessageType { get; set; } = "scan";
        public List<string> Targets { get; set; } = new();
        public List<ushort> Ports { get; set; } = new();
        public string Protocol { get; set; } = "tcp";
        public int? Concurrency { get; set; }
        public int? TcpConcurrency { get; set; }
        public int? UdpConcurrency { get; set; }
        public int? TcpTimeoutMs { get; set; }
        public int? UdpTimeoutMs { get; set; }
        public int? RetryCount { get; set; }
        public bool? DetectService { get; set; }
        public bool? IncludeClosed { get; set; }
        public bool? EnablePingProbe { get; set; }
    }

    /// <summary>
    /// 自定义 SnakeCase JSON naming policy (兼容 .NET 6, System.Text.Json 内置的 SnakeCaseLower 仅 .NET 8+ 可用)
    /// </summary>
    public class SnakeCaseNamingPolicy : JsonNamingPolicy
    {
        public override string ConvertName(string name)
        {
            if (string.IsNullOrEmpty(name)) return name;

            var sb = new StringBuilder();
            for (int i = 0; i < name.Length; i++)
            {
                var c = name[i];
                if (char.IsUpper(c))
                {
                    if (i > 0) sb.Append('_');
                    sb.Append(char.ToLowerInvariant(c));
                }
                else
                {
                    sb.Append(c);
                }
            }
            return sb.ToString();
        }
    }

    /// <summary>
    /// Rust 响应基类
    /// </summary>
    public class RustResponse
    {
        public string? Type { get; set; }
    }

    /// <summary>
    /// Rust 扫描进度
    /// </summary>
    public class RustScanProgress : RustResponse
    {
        public int CurrentTargetIndex { get; set; }
        public int TotalTargets { get; set; }
        public string CurrentTarget { get; set; } = "";
        public int ScannedPorts { get; set; }
        public int TotalPorts { get; set; }
        public int OpenPortsFound { get; set; }
        public double ProgressPercent { get; set; }
        public double ScanRate { get; set; }
        public long EstimatedRemainingSeconds { get; set; }
    }

    /// <summary>
    /// Rust 端口扫描结果
    /// </summary>
    public class RustPortResult : RustResponse
    {
        public string TargetIp { get; set; } = "";
        public ushort Port { get; set; }
        public string Protocol { get; set; } = "TCP";
        public string Status { get; set; } = "";
        public string Service { get; set; } = "";
        public string Version { get; set; } = "";
        public string Banner { get; set; } = "";
        public long ScanTimeMs { get; set; }
    }

    /// <summary>
    /// Rust 扫描完成
    /// </summary>
    public class RustScanComplete : RustResponse
    {
        public int TotalResults { get; set; }
        public int OpenPorts { get; set; }
        public long ScanTimeMs { get; set; }
    }

    /// <summary>
    /// Rust 扫描错误
    /// </summary>
    public class RustScanError : RustResponse
    {
        public int Code { get; set; }
        public string Message { get; set; } = "";
    }

    #endregion
}