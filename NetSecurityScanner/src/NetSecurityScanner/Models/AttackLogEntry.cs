using System;
using System.Collections.Generic;

namespace NetSecurityScanner.Models
{
    /// <summary>
    /// 攻击日志条目
    /// </summary>
    public class AttackLogEntry
    {
        /// <summary>
        /// 时间戳
        /// </summary>
        public DateTime Timestamp { get; set; }

        /// <summary>
        /// 源IP地址
        /// </summary>
        public string SourceIP { get; set; } = "";

        /// <summary>
        /// 目标IP地址
        /// </summary>
        public string TargetIP { get; set; } = "";

        /// <summary>
        /// 攻击类型
        /// </summary>
        public string AttackType { get; set; } = "";

        /// <summary>
        /// 风险等级
        /// </summary>
        public string RiskLevel { get; set; } = "";

        /// <summary>
        /// 请求URL
        /// </summary>
        public string RequestURL { get; set; } = "";

        /// <summary>
        /// HTTP状态码
        /// </summary>
        public int StatusCode { get; set; }

        /// <summary>
        /// 详细信息
        /// </summary>
        public string Details { get; set; } = "";

        /// <summary>
        /// HTTP请求方法
        /// </summary>
        public string RequestMethod { get; set; } = "";

        /// <summary>
        /// User-Agent
        /// </summary>
        public string UserAgent { get; set; } = "";

        /// <summary>
        /// 原始日志行
        /// </summary>
        public string RawLogLine { get; set; } = "";

        /// <summary>
        /// 端口号
        /// </summary>
        public int Port { get; set; }

        /// <summary>
        /// 协议类型
        /// </summary>
        public string Protocol { get; set; } = "";

        /// <summary>
        /// 地理位置信息
        /// </summary>
        public string GeoLocation { get; set; } = "";
    }

    /// <summary>
    /// 攻击日志类型枚举
    /// </summary>
    public enum AttackLogType
    {
        /// <summary>
        /// 未知攻击
        /// </summary>
        Unknown,

        /// <summary>
        /// SQL注入攻击
        /// </summary>
        SQLInjection,

        /// <summary>
        /// 跨站脚本攻击
        /// </summary>
        XSS,

        /// <summary>
        /// 暴力破解攻击
        /// </summary>
        BruteForce,

        /// <summary>
        /// 端口扫描
        /// </summary>
        PortScan,

        /// <summary>
        /// 分布式拒绝服务攻击
        /// </summary>
        DDoS,

        /// <summary>
        /// 目录遍历攻击
        /// </summary>
        DirectoryTraversal,

        /// <summary>
        /// 命令注入攻击
        /// </summary>
        CommandInjection,

        /// <summary>
        /// 文件包含攻击
        /// </summary>
        FileInclusion,

        /// <summary>
        /// 跨站请求伪造攻击
        /// </summary>
        CSRF,

        /// <summary>
        /// 未授权访问
        /// </summary>
        UnauthorizedAccess,

        /// <summary>
        /// 恶意软件上传
        /// </summary>
        MalwareUpload,

        /// <summary>
        /// DNS攻击
        /// </summary>
        DNSAttack
    }

    /// <summary>
    /// 攻击风险等级枚举
    /// </summary>
    public enum AttackRiskLevel
    {
        /// <summary>
        /// 低风险
        /// </summary>
        Low,

        /// <summary>
        /// 中风险
        /// </summary>
        Medium,

        /// <summary>
        /// 高风险
        /// </summary>
        High,

        /// <summary>
        /// 严重风险
        /// </summary>
        Critical
    }

    /// <summary>
    /// 攻击统计信息
    /// </summary>
    public class AttackLogStatistics
    {
        /// <summary>
        /// 总攻击次数
        /// </summary>
        public int TotalAttacks { get; set; }

        /// <summary>
        /// 按攻击类型统计
        /// </summary>
        public Dictionary<string, int> AttacksByType { get; set; } = new();

        /// <summary>
        /// 按风险等级统计
        /// </summary>
        public Dictionary<string, int> AttacksByRiskLevel { get; set; } = new();

        /// <summary>
        /// Top攻击来源IP
        /// </summary>
        public Dictionary<string, int> TopSourceIPs { get; set; } = new();

        /// <summary>
        /// Top被攻击目标IP
        /// </summary>
        public Dictionary<string, int> TopTargetIPs { get; set; } = new();

        /// <summary>
        /// 按时间分布统计
        /// </summary>
        public Dictionary<string, int> AttacksByTime { get; set; } = new();

        /// <summary>
        /// 最早攻击时间
        /// </summary>
        public DateTime? EarliestAttack { get; set; }

        /// <summary>
        /// 最新攻击时间
        /// </summary>
        public DateTime? LatestAttack { get; set; }
    }

    /// <summary>
    /// 攻击日志筛选条件
    /// </summary>
    public class AttackLogFilter
    {
        /// <summary>
        /// 开始日期
        /// </summary>
        public DateTime? StartDate { get; set; }

        /// <summary>
        /// 结束日期
        /// </summary>
        public DateTime? EndDate { get; set; }

        /// <summary>
        /// 攻击类型筛选（"全部"表示不过滤）
        /// </summary>
        public string AttackType { get; set; } = "全部";

        /// <summary>
        /// 风险等级筛选（"全部"表示不过滤）
        /// </summary>
        public string RiskLevel { get; set; } = "全部";

        /// <summary>
        /// 源IP关键词筛选
        /// </summary>
        public string SourceIPKeyword { get; set; } = "";

        /// <summary>
        /// 目标IP关键词筛选
        /// </summary>
        public string TargetIPKeyword { get; set; } = "";

        /// <summary>
        /// 日志来源筛选
        /// </summary>
        public string LogSource { get; set; } = "";
    }
}
