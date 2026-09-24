using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using NetSecurityScanner.Models;

namespace NetSecurityScanner.Services
{
    /// <summary>
    /// 告警规则模板服务（v7-T7）。
    /// 内置 8 个常用模板，管理员可一键启用创建 AlertRule。
    /// </summary>
    public class AlertTemplateService
    {
        private readonly PluginSecurityService _security;
        private readonly PluginScheduler _scheduler;
        private readonly List<AlertTemplate> _templates;

        public event EventHandler<AlertRule>? OnTemplateEnabled;

        public AlertTemplateService(PluginSecurityService security, PluginScheduler scheduler)
        {
            _security = security;
            _scheduler = scheduler;
            _templates = BuildTemplates();
        }

        public List<AlertTemplate> ListTemplates() => _templates.ToList();

        public AlertTemplate? GetTemplate(string id) => _templates.FirstOrDefault(t => t.Id == id);

        /// <summary>一键启用模板</summary>
        public AlertRule EnableTemplate(string templateId, string operatorName = "admin",
            Dictionary<string, object>? customThresholds = null)
        {
            var template = GetTemplate(templateId);
            if (template == null) throw new ArgumentException($"模板不存在: {templateId}");

            var isCustomized = customThresholds != null && customThresholds.Count > 0;
            var thresholds = isCustomized ? customThresholds! : template.DefaultThresholds;

            // 从阈值字典中提取关键数值
            int threshold = 3;
            int windowMin = 5;
            if (thresholds.TryGetValue("count", out var c) && c is int ci) threshold = ci;
            else if (thresholds.TryGetValue("thresholdMB", out var mb) && mb is int mbi) threshold = mbi;
            else if (thresholds.TryGetValue("thresholdSeconds", out var ts) && ts is int tsi) threshold = tsi;
            else if (thresholds.TryGetValue("thresholdMs", out var tm) && tm is int tmi) threshold = tmi;
            else if (thresholds.TryGetValue("score", out var sc) && sc is int sci) threshold = sci;
            if (thresholds.TryGetValue("windowSeconds", out var ws) && ws is int wsi) windowMin = wsi / 60;

            var rule = new AlertRule
            {
                Name = template.Name,
                Description = template.Description + (isCustomized ? " (自定义阈值)" : ""),
                Type = MapCategoryToAlertType(template.Category),
                Threshold = threshold,
                TimeWindowMinutes = windowMin,
                NotificationChannels = template.RecommendedChannels.Select(c => c.ToString()).ToList(),
                Enabled = true,
                IsCustomized = isCustomized,
                TemplateId = template.Id,
                ThresholdsJson = System.Text.Json.JsonSerializer.Serialize(thresholds),
                CreatedBy = operatorName,
                CreatedAt = DateTime.Now
            };

            _scheduler.AddOrUpdateAlertRule(rule);

            _ = _security.AppendAuditAsync(new PluginAuditEntry
            {
                Operator = operatorName,
                PluginId = "*",
                Action = "AlertTemplateEnabled",
                Result = "Success",
                Detail = $"template={template.Id}, rule={rule.Name}, customized={isCustomized}"
            });

            OnTemplateEnabled?.Invoke(this, rule);
            return rule;
        }

        private static AlertType MapCategoryToAlertType(AlertTemplateCategory cat) => cat switch
        {
            AlertTemplateCategory.ConsecutiveFailure => AlertType.ConsecutiveFailure,
            AlertTemplateCategory.Timeout => AlertType.ExecutionTimeout,
            AlertTemplateCategory.MemoryLimit => AlertType.MemoryLimitExceeded,
            AlertTemplateCategory.HealthBelowThreshold => AlertType.LowHealthScore,
            _ => AlertType.ConsecutiveFailure
        };

        private static List<AlertTemplate> BuildTemplates()
        {
            return new List<AlertTemplate>
            {
                new AlertTemplate
                {
                    Id = "tpl.consecutive_failure",
                    Name = "连续失败告警",
                    Description = "5 分钟内连续 3 次执行失败时触发",
                    Category = AlertTemplateCategory.ConsecutiveFailure,
                    Icon = "🔁",
                    DefaultThresholds = new() { ["count"] = 3, ["windowSeconds"] = 300 },
                    RecommendedChannels = new() { NotificationChannel.Log, NotificationChannel.Tray }
                },
                new AlertTemplate
                {
                    Id = "tpl.memory_limit",
                    Name = "内存超限告警",
                    Description = "单次执行内存增量超过 200 MB 时触发",
                    Category = AlertTemplateCategory.MemoryLimit,
                    Icon = "💾",
                    DefaultThresholds = new() { ["thresholdMB"] = 200 },
                    RecommendedChannels = new() { NotificationChannel.Log, NotificationChannel.Tray, NotificationChannel.Popup }
                },
                new AlertTemplate
                {
                    Id = "tpl.timeout",
                    Name = "执行超时告警",
                    Description = "单次插件执行超过 60 秒时触发",
                    Category = AlertTemplateCategory.Timeout,
                    Icon = "⏱️",
                    DefaultThresholds = new() { ["thresholdSeconds"] = 60 },
                    RecommendedChannels = new() { NotificationChannel.Log, NotificationChannel.Tray }
                },
                new AlertTemplate
                {
                    Id = "tpl.health_low",
                    Name = "健康度过低告警",
                    Description = "插件健康度评分低于 60 时触发",
                    Category = AlertTemplateCategory.HealthBelowThreshold,
                    Icon = "💔",
                    DefaultThresholds = new() { ["score"] = 60 },
                    RecommendedChannels = new() { NotificationChannel.Log, NotificationChannel.Popup }
                },
                new AlertTemplate
                {
                    Id = "tpl.signature_invalid",
                    Name = "签名校验失败告警",
                    Description = "插件 DLL 签名校验失败时触发（可能为恶意插件）",
                    Category = AlertTemplateCategory.SignatureInvalid,
                    Icon = "🔏",
                    DefaultThresholds = new() { ["count"] = 1 },
                    RecommendedChannels = new() { NotificationChannel.Log, NotificationChannel.Tray, NotificationChannel.Popup }
                },
                new AlertTemplate
                {
                    Id = "tpl.sandbox_violation",
                    Name = "沙箱违规告警",
                    Description = "插件越界访问文件/网络/进程/注册表时触发",
                    Category = AlertTemplateCategory.SandboxViolation,
                    Icon = "🚧",
                    DefaultThresholds = new() { ["count"] = 1 },
                    RecommendedChannels = new() { NotificationChannel.Log, NotificationChannel.Tray, NotificationChannel.Popup }
                },
                new AlertTemplate
                {
                    Id = "tpl.trace_timeout",
                    Name = "调用链超时告警",
                    Description = "调用链单 Span 超过 30 秒时触发",
                    Category = AlertTemplateCategory.TraceTimeout,
                    Icon = "⏳",
                    DefaultThresholds = new() { ["thresholdMs"] = 30000 },
                    RecommendedChannels = new() { NotificationChannel.Log, NotificationChannel.Tray }
                },
                new AlertTemplate
                {
                    Id = "tpl.unauthorized_remote",
                    Name = "远程 API 越权告警",
                    Description = "远程 API 无效/过期 JWT 请求时触发",
                    Category = AlertTemplateCategory.UnauthorizedRemoteApi,
                    Icon = "🔐",
                    DefaultThresholds = new() { ["count"] = 5, ["windowSeconds"] = 60 },
                    RecommendedChannels = new() { NotificationChannel.Log, NotificationChannel.Popup }
                }
            };
        }
    }
}
