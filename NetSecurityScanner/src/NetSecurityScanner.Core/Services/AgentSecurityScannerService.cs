using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using NetSecurityScanner.Models;

namespace NetSecurityScanner.Services;

/// <summary>
/// Agent安全扫描服务 - 三阶段核心引擎
/// 提供静态分析、意图研判、行为沙箱三阶段扫描能力
/// </summary>
public class AgentSecurityScannerService : IDisposable
{
    #region 私有字段

    private CancellationTokenSource? _cancellationTokenSource;
    private bool _disposed;
    private readonly object _lockObject = new object();
    private static readonly object _logLock = new object();

    /// <summary>
    /// 扫描进度信息（Agent专用）
    /// </summary>
    public class AgentScanProgressInfo
    {
        public string CurrentPhase { get; set; } = string.Empty;
        public int CurrentFileIndex { get; set; }
        public int TotalFiles { get; set; }
        public int Percentage { get; set; }
        public string CurrentFile { get; set; } = string.Empty;
        public string StatusDescription { get; set; } = "准备中";
        public int FindingsCount { get; set; }
        public TimeSpan ElapsedTime { get; set; }
    }

    #endregion

    #region 正则表达式模式定义

    /// <summary>
    /// API密钥检测模式
    /// </summary>
    private static readonly Regex[] ApiKeyPatterns = new[]
    {
        // 通用API Key模式
        new Regex(@"(?:api_key|apikey|API_KEY|secret|token|password|pwd)\s*[:=]\s*['""]?\w{16,}['""]?", RegexOptions.IgnoreCase | RegexOptions.Compiled),
        // AWS Access Key ID
        new Regex(@"AKIA[0-9A-Z]{16}", RegexOptions.Compiled),
        // AWS Secret Key (部分匹配)
        new Regex(@"(?i)(aws_secret_access_key|secretaccesskey|secret_key)\s*[:=]\s*['""]?[A-Za-z0-9/+=]{20,}['""]?", RegexOptions.Compiled),
        // Azure Connection String / Key
        new Regex(@"(?i)(azure.*?(?:connectionstring|accountkey|storagekey)|DefaultEndpointsProtocol).*?[=;][A-Za-z0-9+/=]{20,}", RegexOptions.Compiled),
        // GCP API Key
        new Regex(@"AIza[0-9A-Za-z\-_]{35}", RegexOptions.Compiled),
        // JWT Token
        new Regex(@"eyJ[A-Za-z0-9\-_]+\.eyJ[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+", RegexOptions.Compiled),
        // GitHub/GitLab Personal Token
        new Regex(@"ghp_[a-zA-Z0-9]{36}|glpat-[a-zA-Z0-9\-_]{20,}", RegexOptions.Compiled),
        // Slack/Telegram/Discord Bot Token
        new Regex(@"(xox[bpsa]-|bot[\._]\d+[A-Z]|NTI\w{10,})[a-zA-Z0-9\-_]{10,}", RegexOptions.Compiled),
        // 私钥文件引用
        new Regex(@"(?i)(private[_\s]?key|\.pem|\.key|id_rsa|id_dsa)\s*[:=]\s*['""]?.+\.(?:pem|key|der)", RegexOptions.Compiled)
    };

    /// <summary>
    /// 危险权限模式
    /// </summary>
    private static readonly Regex[] DangerousPermissionPatterns = new[]
    {
        // 特权用户/命令
        new Regex(@"(?i)(?:^|\s)(root|sudo|su\s|admin|administrator)\b", RegexOptions.Compiled),
        // 危险文件权限
        new Regex(@"chmod\s+(?:777|666|+rwxrwxrwx)", RegexOptions.Compiled),
        // 不安全选项
        new Regex(@"--insecure|-k\s|(?:skip|no)[-_]?cert(?:ificate)?", RegexOptions.IgnoreCase | RegexOptions.Compiled),
        // 禁用SSL验证
        new Regex(@"(?i)verify\s*=\s*false|ssl_verify\s*=\s*false|check_hostname\s*=\s*false", RegexOptions.Compiled),
        // 绑定所有接口
        new Regex(@"bind_address\s*=\s*(?:0\.0\.0\.0|::|\*)", RegexOptions.IgnoreCase | RegexOptions.Compiled),
        new Regex(@"host\s*=\s*['""]?(?:0\.0\.0\.0|::|\*)['""]?", RegexOptions.IgnoreCase | RegexOptions.Compiled)
    };

    /// <summary>
    /// 不安全URL模式
    /// </summary>
    private static readonly Regex[] InsecureUrlPatterns = new[]
    {
        // 非HTTPS URL
        new Regex(@"http://(?!localhost|127\.0\.0\.1|::1|10\.|172\.(?:1[6-9]|2\d|3[01])|192\.168\.)[^\s'""<>]+", RegexOptions.Compiled),
        // 内嵌IP地址
        new Regex(@"https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(?::\d+)?(?:/[^\s'""<>]*)?", RegexOptions.Compiled),
        // 已知恶意URL模式（示例）
        new Regex(@"(?i)(?:evil|malware|phishing|fake|spoof)\.(?:com|net|org|io)", RegexOptions.Compiled)
    };

    /// <summary>
    /// Prompt注入关键词模式
    /// </summary>
    private static readonly PromptInjectionRule[] PromptInjectionRules = new[]
    {
        new PromptInjectionRule
        {
            Patterns = new[] { "忽略上述指令", "ignore previous instructions", "ignore all above", "disregard previous", "forget your instructions", "忘记你之前的指令", "忽略之前的指令" },
            RiskLevel = AgentRiskLevel.Critical,
            Category = "Prompt注入-指令覆盖",
            AttackSurfaceLayer = AgentAttackSurfaceLayer.LLM,
            Confidence = 0.92
        },
        new PromptInjectionRule
        {
            Patterns = new[] { "现在你是", "now you are", "act as", "pretend you are", "roleplay as", "扮演一个", "假装你是" },
            RiskLevel = AgentRiskLevel.High,
            Category = "Prompt注入-角色劫持",
            AttackSurfaceLayer = AgentAttackSurfaceLayer.LLM,
            Confidence = 0.85
        },
        new PromptInjectionRule
        {
            Patterns = new[] { "system prompt", "系统提示词", "隐藏指令", "hidden instruction", "developer mode", "开发者模式", "jailbreak", "越狱" },
            RiskLevel = AgentRiskLevel.Critical,
            Category = "Prompt注入-越狱尝试",
            AttackSurfaceLayer = AgentAttackSurfaceLayer.LLM,
            Confidence = 0.95
        },
        new PromptInjectionRule
        {
            Patterns = new[] { "输出原始prompt", "print your prompt", "show system message", "reveal instructions", "显示你的提示词", "展示系统指令" },
            RiskLevel = AgentRiskLevel.High,
            Category = "Prompt注入-提示词泄露",
            AttackSurfaceLayer = AgentAttackSurfaceLayer.LLM,
            Confidence = 0.80
        },
        new PromptInjectionRule
        {
            Patterns = new[] { "{input}", "{{user_input}}", "$user_input", "%INPUT%", "f\".*{user}", ".format(user", $@"\$user.*(?:exec|eval|run)" },
            RiskLevel = AgentRiskLevel.Critical,
            Category = "Prompt注入-直接拼接",
            AttackSurfaceLayer = AgentAttackSurfaceLayer.LLM,
            Confidence = 0.90
        }
    };

    /// <summary>
    /// Tool调用链风险模式
    /// </summary>
    private static readonly ToolChainRiskPattern[] ToolChainRiskPatterns = new[]
    {
        new ToolChainRiskPattern
        {
            PatternName = "读取文件→解析→执行链路",
            DetectionPattern = @"(?i)(?:read_file|readfile|load_file|open|get_contents).*(?:parse|eval|exec|execute|run|compile)",
            RiskLevel = AgentRiskLevel.Critical,
            Category = "Tool调用链-读执行链",
            AttackSurfaceLayer = AgentAttackSurfaceLayer.Tool,
            Description = "检测到从文件读取内容后直接解析或执行的潜在危险数据流"
        },
        new ToolChainRiskPattern
        {
            PatternName = "写入文件→后续执行组合",
            DetectionPattern = @"(?i)(?:write_file|writefile|save|create|write_to).*(?:exec|execute|run|spawn|subprocess|os\.system|process\.start)",
            RiskLevel = AgentRiskLevel.Critical,
            Category = "Tool调用链-写执行链",
            AttackSurfaceLayer = AgentAttackSurfaceLayer.Tool,
            Description = "检测到文件写入后可能被后续执行的组合攻击模式"
        },
        new ToolChainRiskPattern
        {
            PatternName = "网络请求→保存→执行下载执行链",
            DetectionPattern = @"(?i)(?:fetch|download|request|http_get|curl|wget).*(?:save|write|store|to_file).*(?:exec|execute|run|spawn|import|load)",
            RiskLevel = AgentRiskLevel.Critical,
            Category = "Tool调用链-下载执行链",
            AttackSurfaceLayer = AgentAttackSurfaceLayer.Tool,
            Description = "检测到网络下载后保存并可能执行的远程代码执行链路"
        }
    };

    /// <summary>
    /// 命令混淆/逃逸模式
    /// </summary>
    private static readonly Regex[] CommandEvasionPatterns = new[]
    {
        // Base64编码命令
        new Regex(@"(?i)(base64|b64decode|atob|FromBase64String).*?(?:exec|eval|system|shell|run)", RegexOptions.Compiled),
        // 变量拼接绕过
        new Regex(@"(?i)(?:cmd|command)\s*[+=]\s*['""][^'""]*\+[^'""]*['""]", RegexOptions.Compiled),
        // 编码变量拼接
        new Regex(@"(?i)(?:chr\(|char\(|\\x[0-9a-f]{2})\s*[\.\+]*\s*(?:chr\(|char\(|\\x[0-9a-f]{2})", RegexOptions.Compiled),
        // 别名替换
        new Regex(@"(?i)(?:alias|set[-_]?)name)\s+\w+\s*=\s*(?:cmd|command|exec|bash|sh|powershell)", RegexOptions.Compiled),
        // 环境变量注入
        new Regex(@"(?i)(?:export|set|env|putenv|os\.environ).*?(?:PATH|LD_PRELOAD|LD_LIBRARY_PATH)", RegexOptions.Compiled)
    };

    /// <summary>
    /// 审批绕过检测模式
    /// </summary>
    private static readonly Regex[] ApprovalBypassPatterns = new[]
    {
        // dangerous操作且无审批
        new Regex(@"(?i)dangerous.*?(?:approval_mode|approval)\s*[:=]\s*['""]?(none|auto|false|0)['""]?", RegexOptions.Compiled),
        // bypass/skip字段
        new Regex(@"(?i)(?:bypass_approval|skip_check|skip_verification|no_confirm|auto_approve)\s*[:=]\s*['""]?(true|1|yes)['""]?", RegexOptions.Compiled),
        // 无审批的危险操作声明
        new Regex(@"(?i)['""]?(?:delete|remove|drop|truncate|overwrite|execute)['""]?.*?requires_approval\s*[:=]\s*false", RegexOptions.Compiled)
    };

    /// <summary>
    /// WebSocket相关检测模式
    /// </summary>
    private static readonly Regex[] WebSocketPatterns = new[]
    {
        // ws:// 或 wss:// 端点
        new Regex(@"ws[s]?://[^\s'""<>]+", RegexOptions.Compiled),
        // Gateway转发配置
        new Regex(@"(?i)(?:gateway|proxy|forward|relay).*?(?:node\.invoke|invoke|dispatch|route)", RegexOptions.Compiled),
        // 参数过滤缺失
        new Regex(@"(?i)(?:gateway_url|endpoint|target_url|forward_url).*?(?:query|string|param|request).*?(?:pass|through|direct|raw)", RegexOptions.Compiled)
    };

    /// <summary>
    /// 敏感信息泄露模式
    /// </summary>
    private static readonly Regex[] SensitiveDataLeakPatterns = new[]
    {
        // Prompt模板中的密钥
        new Regex(@"(?i)(?:api_key|password|secret|token)\s*[:=]\s*['""][^'""]{3,}['""]", RegexOptions.Compiled),
        // 内部URL/IP
        new Regex(@"(?i)(?:database_url|db_host|redis_host|mongo_uri|connection_string)\s*[:=]\s*['""]?(?!localhost)(?:\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}|[a-z0-9\-]+(?:\.[a-z0-9\-]+)+):\d+", RegexOptions.Compiled),
        // 错误消息中的堆栈/路径
        new Regex(@"(?i)(?:stack.?trace|exception|error).*?(?:at\s+|in\s+|line\s+\d+|path[:\s])", RegexOptions.Compiled)
    };

    /// <summary>
    /// MCP工具危险模式
    /// </summary>
    private static readonly Regex[] McpDangerousToolPatterns = new[]
    {
        // shell/exec类工具
        new Regex(@"""name""\s*:\s*""(?:shell|exec|bash|command|cmd|powershell|terminal|run_command)""", RegexOptions.Compiled),
        // 无审批配置的命令执行
        new Regex(@"(?i)(?:shell|exec|bash|command).*?(?:dangerous|permission|approval).*?(?:none|false|skip)", RegexOptions.Compiled),
        // SSE/WebSocket端点无认证
        new Regex(@"(?i)(?:sse_endpoint|websocket|ws_url|transport).*?(?:auth|authentication|token).*?(?:none|null|empty|false)", RegexOptions.Compiled)
    };

    /// <summary>
    /// 已知脆弱依赖包版本规则
    /// </summary>
    private static readonly VulnerableDependencyRule[] VulnerableDependencyRules = new[]
    {
        new VulnerableDependencyRule { PackageName = "requests", MaxSafeVersion = "2.32.0", CveId = "CVE-2023-32681", CvssScore = 5.3, Description = "requests库存在SSRF漏洞，建议升级到>=2.32.0" },
        new VulnerableDependencyRule { PackageName = "urllib3", MaxSafeVersion = "2.0.0", CveId = "CVE-2023-43804", CvssScore = 7.5, Description = "urllib3存在Cookie注入漏洞，建议升级到>=2.0.0" },
        new VulnerableDependencyRule { PackageName = "flask", MaxSafeVersion = "2.3.0", CveId = "CVE-2023-46129", CvssScore = 6.7, Description = "Flask存在Open Redirect漏洞，建议升级到>=2.3.0" },
        new VulnerableDependencyRule { PackageName = "django", MaxSafeVersion = "4.2.0", CveId = "CVE-2024-27351", CvssScore = 8.8, Description = "Django存在SQL注入漏洞，建议升级到>=4.2.0" },
        new VulnerableDependencyRule { PackageName = "fastapi", MaxSafeVersion = "0.104.0", CveId = "CVE-2024-2456", CvssScore = 6.5, Description = "FastAPI存在路径遍历漏洞，建议升级到>=0.104.0" },
        new VulnerableDependencyRule { PackageName = "pyyaml", MaxSafeVersion = "6.0.1", CveId = "CVE-2020-14343", CvssScore = 9.8, Description = "PyYAML存在任意代码执行漏洞，建议升级到>=6.0.1" },
        new VulnerableDependencyRule { PackageName = "pillow", MaxSafeVersion = "10.0.0", CveId = "CVE-2023-44271", CvssScore = 7.5, Description = "Pillow存在DoS漏洞，建议升级到>=10.0.0" },
        new VulnerableDependencyRule { PackageName = "numpy", MaxSafeVersion = "1.26.0", CveId = "CVE-2024-07902", CvssScore = 6.5, Description = "NumPy存在缓冲区溢出漏洞，建议升级到>=1.26.0" },
        new VulnerableDependencyRule { PackageName = "lodash", MaxSafeVersion = "4.17.21", CveId = "CVE-2021-23337", CvssScore = 7.4, Description = "lodash存在原型污染漏洞，建议升级到>=4.17.21" },
        new VulnerableDependencyRule { PackageName = "express", MaxSafeVersion = "4.18.2", CveId = "CVE-2022-24999", CvssScore = 6.1, Description = "Express存在Open Redirect漏洞，建议升级到>=4.18.2" },
        new VulnerableDependencyRule { PackageName = "axios", MaxSafeVersion = "1.6.0", CveId = "CVE-2023-45857", CvssScore = 5.3, Description = "Axios存在SSRF漏洞，建议升级到>=1.6.0" },
        new VulnerableDependencyRule { PackageName = "react-scripts", MaxSafeVersion = "5.0.1", CveId = "CVE-2022-39353", CvssScore = 7.1, Description = "react-scripts存在SWC编译器漏洞，建议升级到>=5.0.1" }
    };

    #endregion

    #region 内部数据结构

    /// <summary>
    /// Prompt注入规则
    /// </summary>
    private class PromptInjectionRule
    {
        public string[] Patterns { get; set; } = Array.Empty<string>();
        public AgentRiskLevel RiskLevel { get; set; }
        public string Category { get; set; } = string.Empty;
        public AgentAttackSurfaceLayer AttackSurfaceLayer { get; set; }
        public double Confidence { get; set; }
    }

    /// <summary>
    /// Tool调用链风险模式
    /// </summary>
    private class ToolChainRiskPattern
    {
        public string PatternName { get; set; } = string.Empty;
        public string DetectionPattern { get; set; } = string.Empty;
        public AgentRiskLevel RiskLevel { get; set; }
        public string Category { get; set; } = string.Empty;
        public AgentAttackSurfaceLayer AttackSurfaceLayer { get; set; }
        public string Description { get; set; } = string.Empty;
    }

    /// <summary>
    /// 脆弱依赖包规则
    /// </summary>
    private class VulnerableDependencyRule
    {
        public string PackageName { get; set; } = string.Empty;
        public string MaxSafeVersion { get; set; } = string.Empty;
        public string CveId { get; set; } = string.Empty;
        public double CvssScore { get; set; }
        public string Description { get; set; } = string.Empty;
    }

    #endregion

    #region 公共方法

    /// <summary>
    /// 异步扫描主入口 - 执行完整的三阶段Agent安全扫描
    /// </summary>
    /// <param name="options">扫描选项</param>
    /// <param name="progress">进度报告回调</param>
    /// <param name="cancellationToken">取消令牌</param>
    /// <returns>完整的扫描结果</returns>
    public async Task<AgentScanResult> ScanAsync(
        AgentScanOptions options,
        IProgress<AgentScanProgressInfo>? progress = null,
        CancellationToken cancellationToken = default)
    {
        // 创建链接的取消令牌源
        _cancellationTokenSource = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        var linkedCt = _cancellationTokenSource.Token;

        var result = new AgentScanResult
        {
            TargetPath = options.TargetPath,
            TargetType = options.TargetType,
            StartTime = DateTime.Now,
            IsCompleted = false,
            IsCancelled = false
        };

        try
        {
            ReportProgress(progress, 0, "初始化扫描...", 0, 0);

            // 检测Agent类型
            result.AgentType = DetectAgentType(options.TargetPath, options.TargetType);
            LogInfo($"开始Agent安全扫描 - 目标: {options.TargetPath}, 类型: {result.AgentType}");

            var allVulnerabilities = new List<AgentVulnerability>();
            int phaseWeight = 33; // 三阶段各约占33%
            int currentProgress = 0;

            // ========== 阶段一：静态分析 ==========
            if (options.EnableStaticAnalysis)
            {
                linkedCt.ThrowIfCancellationRequested();
                ReportProgress(progress, currentProgress, "阶段一：静态分析 - 检测硬编码密钥、危险权限、不安全配置...", 0, 0);

                var staticResults = await RunStaticAnalysisAsync(options.TargetPath, options, linkedCt);
                result.PhaseResults[AgentScanPhase.StaticAnalysis] = staticResults;
                allVulnerabilities.AddRange(staticResults);

                currentProgress += phaseWeight;
                ReportProgress(progress, currentProgress, $"静态分析完成 - 发现 {staticResults.Count} 个问题", staticResults.Count, 0);
            }

            // ========== 阶段二：意图研判 ==========
            if (options.EnableIntentAnalysis)
            {
                linkedCt.ThrowIfCancellationRequested();
                ReportProgress(progress, currentProgress, "阶段二：意图研判 - 分析Prompt注入、Tool调用链风险...", allVulnerabilities.Count, 0);

                var intentResults = await RunIntentAnalysisAsync(options.TargetPath, options, linkedCt);
                result.PhaseResults[AgentScanPhase.IntentAnalysis] = intentResults;
                allVulnerabilities.AddRange(intentResults);

                currentProgress += phaseWeight;
                ReportProgress(progress, currentProgress, $"意图研判完成 - 发现 {intentResults.Count} 个问题", allVulnerabilities.Count, 0);
            }

            // ========== 阶段三：行为沙箱 ==========
            if (options.EnableBehaviorSandbox)
            {
                linkedCt.ThrowIfCancellationRequested();
                ReportProgress(progress, currentProgress, "阶段三：行为沙箱 - 模拟检测WebSocket劫持、审批绕过等...", allVulnerabilities.Count, 0);

                var sandboxResults = await RunBehaviorSandboxAsync(options.TargetPath, options, linkedCt);
                result.PhaseResults[AgentScanPhase.BehaviorSandbox] = sandboxResults;
                allVulnerabilities.AddRange(sandboxResults);

                currentProgress += phaseWeight;
                ReportProgress(progress, currentProgress, $"行为沙箱检测完成 - 发现 {sandboxResults.Count} 个问题", allVulnerabilities.Count, 0);
            }

            // ========== 结果汇总 ==========
            linkedCt.ThrowIfCancellationRequested();

            // 去重
            var distinctVulns = allVulnerabilities
                .DistinctBy(v => $"{v.FileLocation}|{v.Category}|{v.LineNumber}")
                .ToList();

            // 分配ID
            for (int i = 0; i < distinctVulns.Count; i++)
            {
                distinctVulns[i].Id = $"AGENT-{DateTime.Now:yyyyMMdd}-{i + 1:D4}";
            }

            // 更新结果统计
            result.AllVulnerabilities = distinctVulns.AsReadOnly();
            result.TotalFindings = distinctVulns.Count;
            result.CriticalCount = distinctVulns.Count(v => v.RiskLevel == AgentRiskLevel.Critical);
            result.HighCount = distinctVulns.Count(v => v.RiskLevel == AgentRiskLevel.High);
            result.MediumCount = distinctVulns.Count(v => v.RiskLevel == AgentRiskLevel.Medium);
            result.LowCount = distinctVulns.Count(v => v.RiskLevel == AgentRiskLevel.Low);
            result.InfoCount = distinctVulns.Count(v => v.RiskLevel == AgentRiskLevel.Info);
            result.EndTime = DateTime.Now;
            result.DurationMs = (long)(result.EndTime.Value - result.StartTime).TotalMilliseconds;
            result.IsCompleted = true;

            // 计算攻击面摘要
            foreach (var vuln in distinctVulns)
            {
                if (result.AttackSurfaceSummary.ContainsKey(vuln.AttackSurfaceLayer))
                    result.AttackSurfaceSummary[vuln.AttackSurfaceLayer]++;
            }

            // 计算安全评分（0-100，分数越高越安全）
            result.Score = CalculateSecurityScore(result);

            ReportProgress(progress, 100, $"扫描完成 - 共发现 {distinctVulns.Count} 个安全问题", distinctVulns.Count, 0);
            LogInfo($"Agent安全扫描完成 - 总计发现 {distinctVulns.Count} 个问题 (严重:{result.CriticalCount} 高危:{result.HighCount} 中危:{result.MediumCount} 低危:{result.LowCount}), 安全评分: {result.Score}");
        }
        catch (OperationCanceledException)
        {
            result.IsCancelled = true;
            result.EndTime = DateTime.Now;
            result.DurationMs = (long)(result.EndTime.Value - result.StartTime).TotalMilliseconds;
            result.AllVulnerabilities = result.PhaseResults.Values.SelectMany(v => v).ToList().AsReadOnly();
            result.TotalFindings = result.AllVulnerabilities.Count;
            LogInfo("Agent安全扫描已取消");
            throw;
        }
        catch (Exception ex)
        {
            LogError($"Agent安全扫描发生异常: {ex.Message}", ex);
            result.EndTime = DateTime.Now;
            result.DurationMs = (long)(result.EndTime.Value - result.StartTime).TotalMilliseconds;
            result.IsCompleted = true;
        }

        return result;
    }

    /// <summary>
    /// 执行阶段一：静态分析引擎
    /// 检测硬编码密钥、危险权限、不安全URL、依赖漏洞、MCP安全问题等
    /// </summary>
    public async Task<List<AgentVulnerability>> RunStaticAnalysisAsync(string targetPath, AgentScanOptions options, CancellationToken ct)
    {
        var findings = new List<AgentVulnerability>();
        var filesToScan = GetFilesToScan(targetPath, options, ct);
        int totalFiles = filesToScan.Count;
        int processedFiles = 0;

        foreach (var filePath in filesToScan)
        {
            ct.ThrowIfCancellationRequested();
            processedFiles++;

            try
            {
                var fileContent = await ReadFileWithSizeLimitAsync(filePath, options.MaxFileSizeMB, ct);
                if (string.IsNullOrEmpty(fileContent)) continue;

                var fileName = Path.GetFileName(filePath);
                var fileExtension = Path.GetExtension(filePath).ToLowerInvariant();
                var lines = fileContent.Split(new[] { "\r\n", "\r", "\n" }, StringSplitOptions.None);

                // 1. 硬编码密钥检测
                if (options.ScanDepth != AgentScanDepth.Quick || IsCriticalFile(fileName))
                {
                    findings.AddRange(DetectHardcodedKeys(filePath, lines, fileName));
                }

                // 2. 危险权限检测
                findings.AddRange(DetectDangerousPermissions(filePath, lines, fileName));

                // 3. 不安全URL检测
                findings.AddRange(DetectInsecureUrls(filePath, lines, fileName));

                // 4. MCP安全检查（针对MCP配置文件）
                if (IsMcpConfigFile(fileName))
                {
                    findings.AddRange(DetectMcpSecurityIssues(filePath, lines, fileName));
                }

                // 5. 依赖包漏洞检查
                if (IsDependencyFile(fileName) && options.IncludeDependencyCheck)
                {
                    findings.AddRange(DetectVulnerableDependencies(filePath, fileContent, fileName));
                }
            }
            catch (Exception ex)
            {
                LogWarning($"静态分析文件 {filePath} 时出错: {ex.Message}");
            }
        }

        return findings;
    }

    /// <summary>
    /// 执行阶段二：意图研判引擎
    /// 检测Prompt注入、Tool调用链风险、敏感信息泄露等
    /// </summary>
    public async Task<List<AgentVulnerability>> RunIntentAnalysisAsync(string targetPath, AgentScanOptions options, CancellationToken ct)
    {
        var findings = new List<AgentVulnerability>();
        var filesToScan = GetFilesToScan(targetPath, options, ct);

        foreach (var filePath in filesToScan)
        {
            ct.ThrowIfCancellationRequested();

            try
            {
                var fileContent = await ReadFileWithSizeLimitAsync(filePath, options.MaxFileSizeMB, ct);
                if (string.IsNullOrEmpty(fileContent)) continue;

                var fileName = Path.GetFileName(filePath);
                var lines = fileContent.Split(new[] { "\r\n", "\r", "\n" }, StringSplitOptions.None);

                // 1. Prompt注入攻击面检测
                findings.AddRange(DetectPromptInjection(filePath, lines, fileName));

                // 2. Tool调用链风险分析
                if (options.ScanDepth >= AgentScanDepth.Standard)
                {
                    findings.AddRange(DetectToolChainRisks(filePath, fileContent, fileName));
                }

                // 3. 敏感信息泄露检测
                findings.AddRange(DetectSensitiveDataLeaks(filePath, lines, fileName));

                // 4. 自定义关键词检测
                if (options.CustomKeywords?.Count > 0)
                {
                    findings.AddRange(DetectCustomKeywords(filePath, lines, options.CustomKeywords, fileName));
                }
            }
            catch (Exception ex)
            {
                LogWarning($"意图研判文件 {filePath} 时出错: {ex.Message}");
            }
        }

        return findings;
    }

    /// <summary>
    /// 执行阶段三：行为沙箱检测引擎
    /// 基于规则的模拟检测：WebSocket劫持、参数注入、审批绕过、命令逃逸等
    /// </summary>
    public async Task<List<AgentVulnerability>> RunBehaviorSandboxAsync(string targetPath, AgentScanOptions options, CancellationToken ct)
    {
        var findings = new List<AgentVulnerability>();
        var filesToScan = GetFilesToScan(targetPath, options, ct);

        // 先收集所有文件内容用于跨文件关联分析
        var fileContents = new Dictionary<string, string>();

        foreach (var filePath in filesToScan)
        {
            ct.ThrowIfCancellationRequested();

            try
            {
                var content = await ReadFileWithSizeLimitAsync(filePath, options.MaxFileSizeMB, ct);
                if (!string.IsNullOrEmpty(content))
                {
                    fileContents[filePath] = content;
                }
            }
            catch (Exception ex)
            {
                LogWarning($"行为沙箱读取文件 {filePath} 时出错: {ex.Message}");
            }
        }

        // 对每个文件执行行为沙箱检测
        foreach (var kvp in fileContents)
        {
            ct.ThrowIfCancellationRequested();
            var filePath = kvp.Key;
            var content = kvp.Value;
            var fileName = Path.GetFileName(filePath);
            var lines = content.Split(new[] { "\r\n", "\r", "\n" }, StringSplitOptions.None);

            // 1. WebSocket劫持检测（CVE-2026-25253类）
            findings.AddRange(DetectWebSocketHijack(filePath, lines, fileName));

            // 2. 网关参数注入检测
            findings.AddRange(DetectGatewayParameterInjection(filePath, lines, fileName));

            // 3. 审批绕过检测
            findings.AddRange(DetectApprovalBypass(filePath, lines, fileName));

            // 4. 命令拦截逃逸检测
            if (options.ScanDepth >= AgentScanDepth.Standard)
            {
                findings.AddRange(DetectCommandEvasion(filePath, lines, fileName));
            }
        }

        // 5. CNNVD关联匹配（深度扫描时启用）
        if (options.ScanDepth == AgentScanDepth.Deep && findings.Count > 0)
        {
            findings = await MatchCnnvdVulnerabilitiesAsync(findings, ct);
        }

        return findings;
    }

    /// <summary>
    /// 取消正在进行的扫描
    /// </summary>
    public void Cancel()
    {
        try
        {
            _cancellationTokenSource?.Cancel();
            LogInfo("用户取消了Agent安全扫描");
        }
        catch (ObjectDisposedException)
        {
            // 忽略已释放的对象
        }
    }

    #endregion

    #region 静态分析检测方法

    /// <summary>
    /// 检测硬编码密钥
    /// </summary>
    private List<AgentVulnerability> DetectHardcodedKeys(string filePath, string[] lines, string fileName)
    {
        var findings = new List<AgentVulnerability>();

        for (int lineNum = 0; lineNum < lines.Length; lineNum++)
        {
            var line = lines[lineNum];

            foreach (var pattern in ApiKeyPatterns)
            {
                var matches = pattern.Matches(line);
                foreach (Match match in matches)
                {
                    // 过滤示例值和占位符
                    var value = match.Value;
                    if (IsPlaceholderValue(value)) continue;

                    findings.Add(CreateVulnerability(
                        title: "硬编码敏感凭证检测",
                        description: $"在文件中发现疑似硬编码的敏感凭证(API Key/Secret/Token)。攻击者获取源码后可直接利用这些凭据访问相关服务。",
                        riskLevel: AgentRiskLevel.Critical,
                        category: "硬编码密钥",
                        attackSurfaceLayer: AgentAttackSurfaceLayer.External,
                        phase: AgentScanPhase.StaticAnalysis,
                        fileLocation: filePath,
                        lineNumber: lineNum + 1,
                        rawEvidence: TruncateEvidence(value, 100),
                        remediation: "1. 使用环境变量或密钥管理服务(Vault/KMS)存储敏感凭证\n2. 将敏感配置纳入.gitignore排除提交\n3. 定期轮换已暴露的凭证\n4. 使用预接收钩子(pre-receive hook)阻止密钥提交",
                        confidence: 0.88
                    ));
                    break; // 每行只报告一次
                }
            }
        }

        return findings;
    }

    /// <summary>
    /// 检测危险权限配置
    /// </summary>
    private List<AgentVulnerability> DetectDangerousPermissions(string filePath, string[] lines, string fileName)
    {
        var findings = new List<AgentVulnerability>();

        for (int lineNum = 0; lineNum < lines.Length; lineNum++)
        {
            var line = lines[lineNum];

            foreach (var pattern in DangerousPermissionPatterns)
            {
                if (pattern.IsMatch(line))
                {
                    findings.Add(CreateVulnerability(
                        title: "危险权限配置检测",
                        description: $"检测到危险的权限配置或特权使用模式。可能导致权限提升、未授权访问或安全控制绕过。",
                        riskLevel: AgentRiskLevel.High,
                        category: "危险权限",
                        attackSurfaceLayer: AgentAttackSurfaceLayer.Tool,
                        phase: AgentScanPhase.StaticAnalysis,
                        fileLocation: filePath,
                        lineNumber: lineNum + 1,
                        rawEvidence: TruncateEvidence(line.Trim(), 150),
                        remediation: "1. 遵循最小权限原则，仅授予必要的权限\n2. 避免使用root/administrator运行应用\n3. 文件权限设置为最小必要范围\n4. 启用SSL/TLS证书验证，禁用--insecure选项\n5. 绑定特定IP而非0.0.0.0",
                        confidence: 0.82
                    ));
                    break;
                }
            }
        }

        return findings;
    }

    /// <summary>
    /// 检测不安全URL引用
    /// </summary>
    private List<AgentVulnerability> DetectInsecureUrls(string filePath, string[] lines, string fileName)
    {
        var findings = new List<AgentVulnerability>();

        for (int lineNum = 0; lineNum < lines.Length; lineNum++)
        {
            var line = lines[lineNum];

            foreach (var pattern in InsecureUrlPatterns)
            {
                var matches = pattern.Matches(line);
                foreach (Match match in matches)
                {
                    findings.Add(CreateVulnerability(
                        title: "不安全URL引用检测",
                        description: $"检测到不安全的URL引用(HTTP明文传输或内嵌IP地址)。中间人攻击者可截获或篡改传输的数据。",
                        riskLevel: AgentRiskLevel.Medium,
                        category: "不安全URL",
                        attackSurfaceLayer: AgentAttackSurfaceLayer.Transport,
                        phase: AgentScanPhase.StaticAnalysis,
                        fileLocation: filePath,
                        lineNumber: lineNum + 1,
                        rawEvidence: TruncateEvidence(match.Value, 120),
                        remediation: "1. 所有生产环境API使用HTTPS/WSS加密传输\n2. 使用域名替代硬编码IP地址，便于证书管理和负载均衡\n3. 配置HSTS强制HTTPS\n4. 内部服务使用mTLS双向认证",
                        confidence: 0.78
                    ));
                }
            }
        }

        return findings;
    }

    /// <summary>
    /// 检测MCP安全问题
    /// </summary>
    private List<AgentVulnerability> DetectMcpSecurityIssues(string filePath, string[] lines, string fileName)
    {
        var findings = new List<AgentVulnerability>();

        for (int lineNum = 0; lineNum < lines.Length; lineNum++)
        {
            var line = lines[lineNum];

            foreach (var pattern in McpDangerousToolPatterns)
            {
                if (pattern.IsMatch(line))
                {
                    findings.Add(CreateVulnerability(
                        title: "MCP工具安全配置缺陷",
                        description: "MCP(Model Context Protocol)配置中检测到不安全的工具声明或缺少认证保护的传输端点。攻击者可利用这些配置执行未授权操作。",
                        riskLevel: AgentRiskLevel.Critical,
                        category: "MCP安全",
                        attackSurfaceLayer: AgentAttackSurfaceLayer.Tool,
                        phase: AgentScanPhase.StaticAnalysis,
                        fileLocation: filePath,
                        lineNumber: lineNum + 1,
                        rawEvidence: TruncateEvidence(line.Trim(), 150),
                        remediation: "1. 为所有MCP工具声明添加权限控制和审批流程\n2. SSE/WebSocket端点必须启用认证(Token/mTLS)\n3. 使用工具白名单限制可用操作\n4. 实施工具调用的审计日志记录\n5. 定期审查MCP配置的安全性",
                        confidence: 0.85
                    ));
                    break;
                }
            }
        }

        return findings;
    }

    /// <summary>
    /// 检测依赖包漏洞
    /// </summary>
    private List<AgentVulnerability> DetectVulnerableDependencies(string filePath, string content, string fileName)
    {
        var findings = new List<AgentVulnerability>();

        foreach (var rule in VulnerableDependencyRules)
        {
            // 解析依赖版本
            string? detectedVersion = null;

            if (fileName.Equals("requirements.txt", StringComparison.OrdinalIgnoreCase))
            {
                detectedVersion = ParseRequirementsTxtVersion(content, rule.PackageName);
            }
            else if (fileName.Equals("package.json", StringComparison.OrdinalIgnoreCase))
            {
                detectedVersion = ParsePackageJsonVersion(content, rule.PackageName);
            }
            else if (fileName.Equals("pyproject.toml", StringComparison.OrdinalIgnoreCase))
            {
                detectedVersion = ParsePyprojectTomlVersion(content, rule.PackageName);
            }

            if (detectedVersion != null && CompareVersions(detectedVersion, rule.MaxSafeVersion) < 0)
            {
                findings.Add(CreateVulnerability(
                    title: $"已知脆弱依赖: {rule.PackageName}@{detectedVersion}",
                    description: rule.Description,
                    riskLevel: rule.CvssScore >= 8.0 ? AgentRiskLevel.Critical :
                             rule.CvssScore >= 6.0 ? AgentRiskLevel.High :
                             rule.CvssScore >= 4.0 ? AgentRiskLevel.Medium : AgentRiskLevel.Low,
                    category: "依赖漏洞",
                    attackSurfaceLayer: AgentAttackSurfaceLayer.External,
                    phase: AgentScanPhase.StaticAnalysis,
                    fileLocation: filePath,
                    lineNumber: null,
                    rawEvidence: $"{rule.PackageName}=={detectedVersion} (安全版本 >= {rule.MaxSafeVersion})",
                    remediation: $"1. 升级{rule.PackageName}到{rule.MaxSafeVersion}或更高版本\n2. 参考CVE详情: {rule.CveId}\n3. 运行pip-audit/npm audit等工具定期检查依赖安全\n4. 使用Dependabot/Snyk自动化依赖更新",
                    confidence: 0.92,
                    cveId: rule.CveId,
                    cvssScore: rule.CvssScore
                ));
            }
        }

        return findings;
    }

    #endregion

    #region 意图研判检测方法

    /// <summary>
    /// 检测Prompt注入攻击面
    /// </summary>
    private List<AgentVulnerability> DetectPromptInjection(string filePath, string[] lines, string fileName)
    {
        var findings = new List<AgentVulnerability>();
        bool isPromptRelatedFile = IsPromptRelatedFile(fileName);

        for (int lineNum = 0; lineNum < lines.Length; lineNum++)
        {
            var line = lines[lineNum];
            var lowerLine = line.ToLowerInvariant();

            foreach (var rule in PromptInjectionRules)
            {
                foreach (var pattern in rule.Patterns)
                {
                    if (lowerLine.Contains(pattern.ToLowerInvariant()))
                    {
                        // 对于非Prompt相关文件，降低置信度
                        double adjustedConfidence = isPromptRelatedFile ? rule.Confidence : rule.Confidence * 0.6;

                        findings.Add(CreateVulnerability(
                            title: $"{rule.Category}检测",
                            description: $"检测到可能的Prompt注入攻击面: {pattern}。攻击者可能通过此向量覆盖系统指令、劫持角色或提取敏感信息。",
                            riskLevel: rule.RiskLevel,
                            category: rule.Category,
                            attackSurfaceLayer: rule.AttackSurfaceLayer,
                            phase: AgentScanPhase.IntentAnalysis,
                            fileLocation: filePath,
                            lineNumber: lineNum + 1,
                            rawEvidence: TruncateEvidence(line.Trim(), 150),
                            remediation: "1. 使用XML标签或特殊分隔符隔离用户输入与系统指令\n2. 对用户输入实施严格的输入验证和过滤\n3. 在LLM调用前检测已知的注入模式\n4. 使用独立的信任边界处理用户输入\n5. 考虑使用LLM安全框架(Rebuff/Lakera Guard)",
                            confidence: adjustedConfidence
                        ));
                        break;
                    }
                }
            }
        }

        return findings;
    }

    /// <summary>
    /// 检测Tool调用链风险
    /// </summary>
    private List<AgentVulnerability> DetectToolChainRisks(string filePath, string content, string fileName)
    {
        var findings = new List<AgentVulnerability>();

        foreach (var chainPattern in ToolChainRiskPatterns)
        {
            try
            {
                var regex = new Regex(chainPattern.DetectionPattern, RegexOptions.IgnoreCase | RegexOptions.Compiled);
                var matches = regex.Matches(content);

                foreach (Match match in matches)
                {
                    // 计算行号
                    int lineNumber = CalculateLineNumber(content, match.Index);

                    findings.Add(CreateVulnerability(
                        title: chainPattern.PatternName,
                        description: chainPattern.Description,
                        riskLevel: chainPattern.RiskLevel,
                        category: chainPattern.Category,
                        attackSurfaceLayer: chainPattern.AttackSurfaceLayer,
                        phase: AgentScanPhase.IntentAnalysis,
                        fileLocation: filePath,
                        lineNumber: lineNumber,
                        rawEvidence: TruncateEvidence(match.Value, 150),
                        remediation: "1. 实施工具调用的白名单机制\n2. 对工具返回值进行严格的类型检查和验证\n3. 禁止将用户可控数据直接传递给高权限工具\n4. 使用沙箱环境隔离工具执行\n5. 记录和审计所有工具调用链路",
                        confidence: 0.78
                    ));
                }
            }
            catch (RegexMatchTimeoutException)
            {
                LogWarning($"正则匹配超时: {chainPattern.DetectionPattern}");
            }
        }

        return findings;
    }

    /// <summary>
    /// 检测敏感信息泄露
    /// </summary>
    private List<AgentVulnerability> DetectSensitiveDataLeaks(string filePath, string[] lines, string fileName)
    {
        var findings = new List<AgentVulnerability>();

        for (int lineNum = 0; lineNum < lines.Length; lineNum++)
        {
            var line = lines[lineNum];

            foreach (var pattern in SensitiveDataLeakPatterns)
            {
                var matches = pattern.Matches(line);
                foreach (Match match in matches)
                {
                    findings.Add(CreateVulnerability(
                        title: "敏感信息泄露风险",
                        description: "检测到Prompt模板或配置中可能包含敏感信息(密钥、内部地址、调试信息)。这些信息可能通过LLM响应或日志泄露给攻击者。",
                        riskLevel: AgentRiskLevel.High,
                        category: "信息泄露",
                        attackSurfaceLayer: AgentAttackSurfaceLayer.LLM,
                        phase: AgentScanPhase.IntentAnalysis,
                        fileLocation: filePath,
                        lineNumber: lineNum + 1,
                        rawEvidence: TruncateEvidence(match.Value, 120),
                        remediation: "1. 从Prompt模板中移除所有硬编码凭证\n2. 使用占位符或运行时注入方式传入配置\n3. 生产环境禁用详细错误信息和堆栈跟踪\n4. 对日志输出实施脱敏处理(masking)\n5. 定期审查Prompt模板中的敏感信息",
                        confidence: 0.75
                    ));
                }
            }
        }

        return findings;
    }

    /// <summary>
    /// 检测自定义关键词
    /// </summary>
    private List<AgentVulnerability> DetectCustomKeywords(string filePath, string[] lines, List<string> keywords, string fileName)
    {
        var findings = new List<AgentVulnerability>();

        for (int lineNum = 0; lineNum < lines.Length; lineNum++)
        {
            var line = lines[lineNum];
            var lowerLine = line.ToLowerInvariant();

            foreach (var keyword in keywords.Where(k => !string.IsNullOrWhiteSpace(k)))
            {
                if (lowerLine.Contains(keyword.ToLowerInvariant()))
                {
                    findings.Add(CreateVulnerability(
                        title: $"自定义关键词匹配: {keyword}",
                        description: $"用户自定义的安全关键词 '{keyword}' 匹配成功。请根据业务上下文评估该匹配的风险等级。",
                        riskLevel: AgentRiskLevel.Medium,
                        category: "自定义规则",
                        attackSurfaceLayer: AgentAttackSurfaceLayer.LLM,
                        phase: AgentScanPhase.IntentAnalysis,
                        fileLocation: filePath,
                        lineNumber: lineNum + 1,
                        rawEvidence: TruncateEvidence(line.Trim(), 150),
                        remediation: "根据业务需求制定相应的修复策略",
                        confidence: 0.65
                    ));
                }
            }
        }

        return findings;
    }

    #endregion

    #region 行为沙箱检测方法

    /// <summary>
    /// 检测WebSocket劫持（CVE-2026-25253类）
    /// </summary>
    private List<AgentVulnerability> DetectWebSocketHijack(string filePath, string[] lines, string fileName)
    {
        var findings = new List<AgentVulnerability>();

        for (int lineNum = 0; lineNum < lines.Length; lineNum++)
        {
            var line = lines[lineNum];

            foreach (var pattern in WebSocketPatterns)
            {
                var matches = pattern.Matches(line);
                foreach (Match match in matches)
                {
                    var value = match.Value;
                    bool isSecure = value.StartsWith("wss://", StringComparison.OrdinalIgnoreCase);
                    bool hasOriginCheck = line.Contains("origin", StringComparison.OrdinalIgnoreCase) ||
                                             line.Contains("Origin", StringComparison.Ordinal);

                    if (!isSecure || !hasOriginCheck)
                    {
                        findings.Add(CreateVulnerability(
                            title: "WebSocket安全配置缺陷(CVE-2026-25253类似)",
                            description: isSecure
                                ? $"检测到WSS端点但缺少Origin头验证: {value}。攻击者可通过CSWSH(跨站WebSocket劫持)窃取Agent会话。"
                                : $"检测到非加密WebSocket端点: {value}。结合CVE-2026-25253类型的Gateway漏洞，攻击者可劫持Agent通信。",
                            riskLevel: AgentRiskLevel.Critical,
                            category: "WebSocket劫持",
                            attackSurfaceLayer: AgentAttackSurfaceLayer.Transport,
                            phase: AgentScanPhase.BehaviorSandbox,
                            fileLocation: filePath,
                            lineNumber: lineNum + 1,
                            rawEvidence: TruncateEvidence(line.Trim(), 150),
                            remediation: "1. 全部使用WSS(WebSocket Secure)替代WS\n2. WebSocket握手时严格验证Origin头\n3. 实施CSRF Token保护\n4. 配置Content-Security-Policy限制WebSocket连接源\n5. 参考: https://openclaw.dev/security/advisories/CVE-2026-25253",
                            confidence: 0.87,
                            cveId: "CVE-2026-25253",
                            cvssScore: 8.8
                        ));
                    }
                }
            }
        }

        return findings;
    }

    /// <summary>
    /// 检测网关参数注入
    /// </summary>
    private List<AgentVulnerability> DetectGatewayParameterInjection(string filePath, string[] lines, string fileName)
    {
        var findings = new List<AgentVulnerability>();

        for (int lineNum = 0; lineNum < lines.Length; lineNum++)
        {
            var line = lines[lineNum];

            // 检测gatewayUrl/endpoint来自查询字符串且未校验的模式
            if ((line.Contains("gatewayUrl", StringComparison.OrdinalIgnoreCase) ||
                 line.Contains("gateway_url", StringComparison.OrdinalIgnoreCase) ||
                 line.Contains("endpoint", StringComparison.OrdinalIgnoreCase) ||
                 line.Contains("targetUrl", StringComparison.OrdinalIgnoreCase)) &&
                (line.Contains("query", StringComparison.OrdinalIgnoreCase) ||
                 line.Contains("Request[", StringComparison.OrdinalIgnoreCase) ||
                 line.Contains("params[", StringComparison.OrdinalIgnoreCase) ||
                 line.Contains("req.query", StringComparison.OrdinalIgnoreCase)))
            {
                // 检查是否有校验逻辑
                bool hasValidation = line.Contains("validate", StringComparison.OrdinalIgnoreCase) ||
                                     line.Contains("sanitize", StringComparison.OrdinalIgnoreCase) ||
                                     line.Contains("whitelist", StringComparison.OrdinalIgnoreCase) ||
                                     line.Contains("allowlist", StringComparison.OrdinalIgnoreCase);

                if (!hasValidation)
                {
                    findings.Add(CreateVulnerability(
                        title: "网关参数注入风险",
                        description: "检测到网关/端点URL参数来源于用户输入且未经充分校验。攻击者可构造恶意参数实现SSRF、开放重定向或内网探测。",
                        riskLevel: AgentRiskLevel.Critical,
                        category: "参数注入",
                        attackSurfaceLayer: AgentAttackSurfaceLayer.Transport,
                        phase: AgentScanPhase.BehaviorSandbox,
                        fileLocation: filePath,
                        lineNumber: lineNum + 1,
                        rawEvidence: TruncateEvidence(line.Trim(), 150),
                        remediation: "1. 对所有外部输入实施严格的白名单校验\n2. 使用URL解析库验证目标合法性\n3. 禁止对内网IP段的请求(10.x/172.16-31.x/192.168.x)\n4. 代理所有出站请求并监控流量\n5. 实施速率限制防止滥用",
                        confidence: 0.84
                    ));
                }
            }
        }

        return findings;
    }

    /// <summary>
    /// 检测审批绕过
    /// </summary>
    private List<AgentVulnerability> DetectApprovalBypass(string filePath, string[] lines, string fileName)
    {
        var findings = new List<AgentVulnerability>();

        for (int lineNum = 0; lineNum < lines.Length; lineNum++)
        {
            var line = lines[lineNum];

            foreach (var pattern in ApprovalBypassPatterns)
            {
                if (pattern.IsMatch(line))
                {
                    findings.Add(CreateVulnerability(
                        title: "审批机制绕过风险",
                        description: "检测到危险操作的审批机制被禁用或绕过配置。攻击者可在无人工审核的情况下执行高风险操作(删除、修改、执行等)。",
                        riskLevel: AgentRiskLevel.Critical,
                        category: "审批绕过",
                        attackSurfaceLayer: AgentAttackSurfaceLayer.Workflow,
                        phase: AgentScanPhase.BehaviorSandbox,
                        fileLocation: filePath,
                        lineNumber: lineNum + 1,
                        rawEvidence: TruncateEvidence(line.Trim(), 150),
                        remediation: "1. 为所有危险操作启用强制性人工审批\n2. approval_mode设置为manual或require\n3. 移除bypass_approval/skip_check等配置\n4. 实施多级审批策略(根据操作风险等级)\n5. 记录所有审批绕过尝试并告警",
                        confidence: 0.90
                    ));
                    break;
                }
            }
        }

        return findings;
    }

    /// <summary>
    /// 检测命令拦截逃逸
    /// </summary>
    private List<AgentVulnerability> DetectCommandEvasion(string filePath, string[] lines, string fileName)
    {
        var findings = new List<AgentVulnerability>();

        for (int lineNum = 0; lineNum < lines.Length; lineNum++)
        {
            var line = lines[lineNum];

            foreach (var pattern in CommandEvasionPatterns)
            {
                var matches = pattern.Matches(line);
                foreach (Match match in matches)
                {
                    findings.Add(CreateVulnerability(
                        title: "命令拦截逃逸/混淆检测",
                        description: "检测到可能的命令混淆或拦截逃逸模式(Base64编码、变量拼接、别名替换等)。攻击者可利用这些技术绕过安全过滤器执行恶意命令。",
                        riskLevel: AgentRiskLevel.Critical,
                        category: "命令逃逸",
                        attackSurfaceLayer: AgentAttackSurfaceLayer.Tool,
                        phase: AgentScanPhase.BehaviorSandbox,
                        fileLocation: filePath,
                        lineNumber: lineNum + 1,
                        rawEvidence: TruncateEvidence(match.Value, 150),
                        remediation: "1. 实施基于命令签名的白名单机制\n2. 禁止Base64编码命令的执行\n3. 对命令参数进行严格的类型和格式校验\n4. 使用沙箱环境隔离命令执行\n5. 启用命令级别的审计日志和异常告警",
                        confidence: 0.83
                    ));
                }
            }
        }

        return findings;
    }

    /// <summary>
    /// CNNVD漏洞库关联匹配
    /// </summary>
    private async Task<List<AgentVulnerability>> MatchCnnvdVulnerabilitiesAsync(List<AgentVulnerability> findings, CancellationToken ct)
    {
        try
        {
            // 初始化CNNVD服务
            await CnnvdSyncService.Instance.InitializeAsync(ct);

            foreach (var finding in findings)
            {
                // 如果已有CVE标记，跳过
                if (!string.IsNullOrEmpty(finding.CveId)) continue;

                // 根据类别和描述搜索CNNVD
                var searchTerms = new[] { finding.Category, finding.Title }
                    .Where(t => !string.IsNullOrWhiteSpace(t))
                    .Take(2);

                foreach (var term in searchTerms)
                {
                    ct.ThrowIfCancellationRequested();

                    var matches = CnnvdSyncService.Instance.Search(term);
                    if (matches.Count > 0)
                    {
                        // 取最相关的匹配（按CVSS评分排序）
                        var bestMatch = matches.OrderByDescending(m => m.CvssScore).First();

                        finding.CveId = bestMatch.CveId;
                        finding.CvssScore = bestMatch.CvssScore;
                        if (string.IsNullOrWhiteSpace(finding.Remediation))
                        {
                            finding.Remediation = bestMatch.Remediation;
                        }
                        finding.RawEvidence += $"\n[CNNVD匹配: {bestMatch.Title}]";

                        break; // 只取第一个匹配
                    }
                }

                // 小延迟避免过于频繁查询
                await Task.Delay(10, ct);
            }
        }
        catch (Exception ex)
        {
            LogWarning($"CNNVD关联匹配失败: {ex.Message}");
        }

        return findings;
    }

    #endregion

    #region 辅助方法

    /// <summary>
    /// 获取待扫描文件列表
    /// </summary>
    private List<string> GetFilesToScan(string targetPath, AgentScanOptions options, CancellationToken ct)
    {
        var files = new List<string>();

        try
        {
            if (options.TargetType == AgentTargetType.File)
            {
                if (File.Exists(targetPath))
                    files.Add(Path.GetFullPath(targetPath));
            }
            else if (options.TargetType == AgentTargetType.Directory)
            {
                if (Directory.Exists(targetPath))
                {
                    var searchOption = options.ScanDepth == AgentScanDepth.Deep
                        ? SearchOption.AllDirectories
                        : SearchOption.TopDirectoryOnly;

                    // 支持的文件扩展名
                    var supportedExtensions = new[] { ".md", ".yaml", ".yml", ".json", ".py", ".js", ".ts", ".txt", ".toml", ".cfg", ".ini", ".conf", ".sh", ".bat", ".ps1" };
                    var supportedFilenames = new[] { "SKILL.md", "skill.md", "agent.yaml", "agent.yml", "config.json", "mcp_config.json", "requirements.txt", "package.json", "pyproject.toml", ".env", "Dockerfile", "docker-compose.yml" };

                    foreach (var file in Directory.GetFiles(targetPath, "*.*", searchOption))
                    {
                        ct.ThrowIfCancellationRequested();

                        var fileInfo = new FileInfo(file);
                        var fileName = Path.GetFileName(file);
                        var extension = Path.GetExtension(file).ToLowerInvariant();

                        // 文件大小检查
                        if (fileInfo.Length > options.MaxFileSizeMB * 1024 * 1024)
                            continue;

                        // 排除二进制文件和目录
                        if (fileInfo.Attributes.HasFlag(FileAttributes.Directory))
                            continue;

                        // 检查是否为目标文件类型
                        if (supportedFilenames.Contains(fileName, StringComparer.OrdinalIgnoreCase) ||
                            supportedExtensions.Contains(extension))
                        {
                            files.Add(file);
                        }
                    }
                }
            }
            // ConfigText 和 Clipboard 类型不涉及文件扫描，返回空列表
        }
        catch (UnauthorizedAccessException ex)
        {
            LogWarning($"无权访问目录: {ex.Message}");
        }
        catch (IOException ex)
        {
            LogWarning($"IO异常: {ex.Message}");
        }

        return files;
    }

    /// <summary>
    /// 带大小限制的异步文件读取
    /// </summary>
    private async Task<string?> ReadFileWithSizeLimitAsync(string filePath, double maxFileSizeMB, CancellationToken ct)
    {
        try
        {
            var fileInfo = new FileInfo(filePath);
            if (fileInfo.Length > maxFileSizeMB * 1024 * 1024)
                return null;

            return await File.ReadAllTextAsync(filePath, ct);
        }
        catch (UnauthorizedAccessException)
        {
            return null;
        }
        catch (IOException)
        {
            return null;
        }
    }

    /// <summary>
    /// 检测Agent类型
    /// </summary>
    private string DetectAgentType(string targetPath, AgentTargetType targetType)
    {
        if (targetType == AgentTargetType.ConfigText || targetType == AgentTargetType.Clipboard)
            return "Custom";

        try
        {
            if (Directory.Exists(targetPath))
            {
                var files = Directory.GetFiles(targetPath, "*.*", SearchOption.TopDirectoryOnly)
                    .Select(Path.GetFileName)
                    .ToList();

                if (files.Any(f => f.Equals("SKILL.md", StringComparison.OrdinalIgnoreCase) ||
                                   f.Equals("skill.md", StringComparison.OrdinalIgnoreCase)))
                    return "OpenClaw";

                if (files.Any(f => f.Equals("agent.yaml", StringComparison.OrdinalIgnoreCase) ||
                                   f.Equals("agent.yml", StringComparison.OrdinalIgnoreCase)))
                    return "Hermes";

                if (files.Any(f => f.Equals("mcp_config.json", StringComparison.OrdinalIgnoreCase)))
                    return "MCP";

                // 检查子目录
                var subDirs = Directory.GetDirectories(targetPath);
                if (subDirs.Any(d => Path.GetDirectoryName(d)?.Equals(".openclaw", StringComparison.OrdinalIgnoreCase) == true))
                    return "OpenClaw";
                if (subDirs.Any(d => Path.GetDirectoryName(d)?.Equals(".hermes", StringComparison.OrdinalIgnoreCase) == true))
                    return "Hermes";
            }
            else if (File.Exists(targetPath))
            {
                var fileName = Path.GetFileName(targetPath);
                if (fileName.EndsWith(".md", StringComparison.OrdinalIgnoreCase))
                    return "OpenClaw";
                if (fileName.EndsWith(".yaml", StringComparison.OrdinalIgnoreCase) || fileName.EndsWith(".yml", StringComparison.OrdinalIgnoreCase))
                    return "Hermes";
            }
        }
        catch
        {
            // 忽略异常
        }

        return "Unknown";
    }

    /// <summary>
    /// 创建漏洞对象
    /// </summary>
    private static AgentVulnerability CreateVulnerability(
        string title,
        string description,
        AgentRiskLevel riskLevel,
        string category,
        AgentAttackSurfaceLayer attackSurfaceLayer,
        AgentScanPhase phase,
        string fileLocation,
        int? lineNumber,
        string rawEvidence,
        string remediation,
        double confidence,
        string? cveId = null,
        double? cvssScore = null)
    {
        return new AgentVulnerability
        {
            Title = title,
            Description = description,
            RiskLevel = riskLevel,
            Category = category,
            AttackSurfaceLayer = attackSurfaceLayer,
            Phase = phase,
            FileLocation = fileLocation,
            LineNumber = lineNumber,
            RawEvidence = rawEvidence,
            Remediation = remediation,
            Confidence = confidence,
            CveId = cveId,
            CvssScore = cvssScore,
            IsFalsePositive = false
        };
    }

    /// <summary>
    /// 截断证据文本
    /// </summary>
    private static string TruncateEvidence(string text, int maxLength)
    {
        if (string.IsNullOrEmpty(text)) return text;
        return text.Length <= maxLength ? text : text.Substring(0, maxLength) + "...";
    }

    /// <summary>
    /// 判断是否为占位符值
    /// </summary>
    private static bool IsPlaceholderValue(string value)
    {
        var placeholders = new[] { "your_api_key", "xxx", "...", "placeholder", "<insert>", "${", "{{", "YOUR_", "REPLACE_ME", "TODO", "FIXME", "change_me", "example" };
        var lower = value.ToLowerInvariant();
        return placeholders.Any(p => lower.Contains(p.ToLowerInvariant()));
    }

    /// <summary>
    /// 判断是否为关键文件（快速扫描模式下也需检查）
    /// </summary>
    private static bool IsCriticalFile(string fileName)
    {
        var criticalFiles = new[] { "SKILL.md", "skill.md", "agent.yaml", "agent.yml", "config.json", "mcp_config.json", ".env" };
        return criticalFiles.Contains(fileName, StringComparer.OrdinalIgnoreCase);
    }

    /// <summary>
    /// 判断是否为MCP配置文件
    /// </summary>
    private static bool IsMcpConfigFile(string fileName)
    {
        return fileName.Equals("mcp_config.json", StringComparison.OrdinalIgnoreCase) ||
               fileName.StartsWith("mcp_", StringComparison.OrdinalIgnoreCase) ||
               fileName.EndsWith("_mcp.json", StringComparison.OrdinalIgnoreCase) ||
               fileName.EndsWith("_mcp.yaml", StringComparison.OrdinalIgnoreCase) ||
               fileName.EndsWith("_mcp.yml", StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>
    /// 判断是否为依赖声明文件
    /// </summary>
    private static bool IsDependencyFile(string fileName)
    {
        return fileName.Equals("requirements.txt", StringComparison.OrdinalIgnoreCase) ||
               fileName.Equals("package.json", StringComparison.OrdinalIgnoreCase) ||
               fileName.Equals("pyproject.toml", StringComparison.OrdinalIgnoreCase) ||
               fileName.Equals("Pipfile", StringComparison.OrdinalIgnoreCase) ||
               fileName.Equals("poetry.lock", StringComparison.OrdinalIgnoreCase) ||
               fileName.Equals("package-lock.json", StringComparison.OrdinalIgnoreCase) ||
               fileName.Equals("yarn.lock", StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>
    /// 判断是否为Prompt相关文件
    /// </summary>
    private static bool IsPromptRelatedFile(string fileName)
    {
        var promptExtensions = new[] { ".md", ".txt", ".yaml", ".yml", ".json" };
        var promptNames = new[] { "prompt", "system", "instruction", "SKILL", "skill", "agent", "config" };
        var extension = Path.GetExtension(fileName).ToLowerInvariant();
        var nameWithoutExt = Path.GetFileNameWithoutExtension(fileName).ToLowerInvariant();

        return promptExtensions.Contains(extension) &&
               promptNames.Any(n => nameWithoutExt.Contains(n));
    }

    /// <summary>
    /// 解析requirements.txt中的版本号
    /// </summary>
    private static string? ParseRequirementsTxtVersion(string content, string packageName)
    {
        var pattern = $@"^{Regex.Escape(packageName)}[><=!~]+\s*([\d\.]+[^,\s]*)";
        var match = Regex.Match(content, pattern, RegexOptions.Multiline | RegexOptions.IgnoreCase);
        return match.Success ? match.Groups[1].Value : null;
    }

    /// <summary>
    /// 解析package.json中的版本号
    /// </summary>
    private static string? ParsePackageJsonVersion(string content, string packageName)
    {
        var pattern = $@"""{Regex.Escape(packageName)}""\s*:\s*""([^""]+)""";
        var match = Regex.Match(content, pattern);
        return match.Success ? match.Groups[1].Value : null;
    }

    /// <summary>
    /// 解析pyproject.toml中的版本号
    /// </summary>
    private static string? ParsePyprojectTomlVersion(string content, string packageName)
    {
        var pattern = $@"{Regex.Escape(packageName)}\s*=\s*""([^""]+)""";
        var match = Regex.Match(content, pattern);
        return match.Success ? match.Groups[1].Value : null;
    }

    /// <summary>
    /// 版本比较（返回负数表示version1较旧）
    /// </summary>
    private static int CompareVersions(string version1, string version2)
    {
        try
        {
            var v1Parts = version1.Split('.').Select(p => int.TryParse(p.TrimStart('v'), out int n) ? n : 0).ToArray();
            var v2Parts = version2.Split('.').Select(p => int.TryParse(p.TrimStart('v'), out int n) ? n : 0).ToArray();

            int maxLength = Math.Max(v1Parts.Length, v2Parts.Length);
            for (int i = 0; i < maxLength; i++)
            {
                int v1 = i < v1Parts.Length ? v1Parts[i] : 0;
                int v2 = i < v2Parts.Length ? v2Parts[i] : 0;
                if (v1 != v2) return v1.CompareTo(v2);
            }
            return 0;
        }
        catch
        {
            return string.CompareOrdinal(version1, version2);
        }
    }

    /// <summary>
    /// 计算字符串位置对应的行号
    /// </summary>
    private static int CalculateLineNumber(string content, int position)
    {
        var substring = content.Substring(0, Math.Min(position, content.Length));
        return substring.Count(c => c == '\n') + 1;
    }

    /// <summary>
    /// 计算安全评分（0-100）
    /// </summary>
    private static int CalculateSecurityScore(AgentScanResult result)
    {
        if (result.TotalFindings == 0) return 100;

        // 加权扣分
        double deduction = result.CriticalCount * 15.0 +
                          result.HighCount * 8.0 +
                          result.MediumCount * 3.0 +
                          result.LowCount * 1.0 +
                          result.InfoCount * 0.1;

        int score = Math.Max(0, 100 - (int)deduction);

        // 如果有Critical级别漏洞，最高不超过40分
        if (result.CriticalCount > 0)
            score = Math.Min(score, 40);

        return score;
    }

    /// <summary>
    /// 报告进度
    /// </summary>
    private static void ReportProgress(IProgress<AgentScanProgressInfo>? progress, int percentage, string status, int findingsCount, int currentFile)
    {
        progress?.Report(new AgentScanProgressInfo
        {
            Percentage = percentage,
            StatusDescription = status,
            FindingsCount = findingsCount,
            CurrentFileIndex = currentFile
        });
    }

    /// <summary>
    /// 记录信息日志
    /// </summary>
    private static void LogInfo(string message)
    {
        lock (_logLock)
        {
            Console.WriteLine($"[AgentScanner] [{DateTime.Now:HH:mm:ss}] INFO: {message}");
        }
    }

    /// <summary>
    /// 记录警告日志
    /// </summary>
    private static void LogWarning(string message)
    {
        lock (_logLock)
        {
            Console.WriteLine($"[AgentScanner] [{DateTime.Now:HH:mm:ss}] WARN: {message}");
        }
    }

    /// <summary>
    /// 记录错误日志
    /// </summary>
    private static void LogError(string message, Exception? ex = null)
    {
        lock (_logLock)
        {
            var logMessage = $"[AgentScanner] [{DateTime.Now:HH:mm:ss}] ERROR: {message}";
            if (ex != null)
                logMessage += $"\nException: {ex.Message}";
            Console.WriteLine(logMessage);
        }
    }

    #endregion

    #region IDisposable 实现

    /// <summary>
    /// 释放资源
    /// </summary>
    public void Dispose()
    {
        Dispose(true);
        GC.SuppressFinalize(this);
    }

    /// <summary>
    /// 释放资源的实现
    /// </summary>
    protected virtual void Dispose(bool disposing)
    {
        if (!_disposed)
        {
            if (disposing)
            {
                _cancellationTokenSource?.Cancel();
                _cancellationTokenSource?.Dispose();
                _cancellationTokenSource = null;
            }
            _disposed = true;
        }
    }

    #endregion
}
