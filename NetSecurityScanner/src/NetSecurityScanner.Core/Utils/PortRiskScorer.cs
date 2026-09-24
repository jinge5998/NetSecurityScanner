using System.Collections.Generic;
using System.Linq;

namespace NetSecurityScanner.Utils
{
    /// <summary>
    /// 端口风险评分与分类工具
    /// 用于对开放端口进行风险评估和分类
    /// </summary>
    public static class PortRiskScorer
    {
        /// <summary>
        /// 端口风险等级（与 CompleteScanResult.RiskLevel 对齐）
        /// </summary>
        public enum RiskLevel
        {
            Info,    // 信息：80/HTTP、443/HTTPS 等公开服务
            Low,     // 低风险：通用服务
            Medium,  // 中风险：管理类、数据库类服务
            High,    // 高风险：远程代码执行、容器、未授权访问常见
            Critical // 严重：暴露到公网即高危的服务（Docker、Telnet、Redis 等）
        }

        /// <summary>
        /// 服务大类（用于分组和报告）
        /// </summary>
        public enum ServiceCategory
        {
            Unknown,
            Web,            // HTTP/HTTPS 类
            Database,       // MySQL/PostgreSQL/MongoDB 等
            RemoteAccess,   // SSH/RDP/VNC/Telnet
            FileTransfer,   // FTP/SMB/NFS
            Mail,           // SMTP/POP3/IMAP
            Directory,      // LDAP/Kerberos/DNS
            Container,      // Docker/Kubernetes/etcd
            MessageQueue,   // Kafka/RabbitMQ/ActiveMQ
            BigData,        // Hadoop/Elasticsearch/Cassandra
            Network,        // SNMP/NTP/DHCP/Router
            Monitoring,     // Prometheus/Grafana/Zabbix
            DevOps,         // Jenkins/GitLab/SonarQube
            Proxy,          // HTTP Proxy/SOCKS
            IoT             // MQTT/CoAP
        }

        /// <summary>
        /// 端口风险配置：(RiskLevel, ServiceCategory, Description, CommonVulns)
        /// </summary>
        private static readonly Dictionary<int, PortRiskInfo> _portRiskDb = new()
        {
            // === Critical Risk: 暴露到公网即高危 ===
            { 23, new(RiskLevel.Critical, ServiceCategory.RemoteAccess, "Telnet 明文协议", "弱口令 CVE-2023-48795") },
            { 2375, new(RiskLevel.Critical, ServiceCategory.Container, "Docker API 未授权", "未授权访问 CVE-2019-5736 / 容器逃逸") },
            { 2376, new(RiskLevel.Critical, ServiceCategory.Container, "Docker API TLS", "配置不当可导致容器接管") },
            { 6379, new(RiskLevel.Critical, ServiceCategory.Database, "Redis 数据库", "未授权访问 CVE-2022-0543") },
            { 11211, new(RiskLevel.Critical, ServiceCategory.Database, "Memcached", "未授权访问 / 反射放大 DDoS") },
            { 27017, new(RiskLevel.Critical, ServiceCategory.Database, "MongoDB 数据库", "未授权访问 / 配置不当") },
            { 2181, new(RiskLevel.Critical, ServiceCategory.BigData, "ZooKeeper", "未授权访问") },
            { 9200, new(RiskLevel.Critical, ServiceCategory.BigData, "Elasticsearch", "未授权访问 CVE-2015-1427") },
            { 9300, new(RiskLevel.Critical, ServiceCategory.BigData, "Elasticsearch 传输", "未授权访问") },
            { 5984, new(RiskLevel.Critical, ServiceCategory.Database, "CouchDB", "未授权访问 CVE-2017-12635") },

            // === High Risk: 远程访问和管理类 ===
            { 22, new(RiskLevel.High, ServiceCategory.RemoteAccess, "SSH", "弱口令 CVE-2023-38408") },
            { 3389, new(RiskLevel.High, ServiceCategory.RemoteAccess, "RDP", "BlueKeep CVE-2019-0708") },
            { 5900, new(RiskLevel.High, ServiceCategory.RemoteAccess, "VNC", "弱口令 / 未授权访问") },
            { 5901, new(RiskLevel.High, ServiceCategory.RemoteAccess, "VNC Alt", "弱口令") },
            { 2222, new(RiskLevel.High, ServiceCategory.RemoteAccess, "SSH 替代端口", "弱口令") },
            { 512, new(RiskLevel.High, ServiceCategory.RemoteAccess, "Rexec", "明文远程执行") },
            { 513, new(RiskLevel.High, ServiceCategory.RemoteAccess, "Rlogin", "明文远程登录") },
            { 3306, new(RiskLevel.High, ServiceCategory.Database, "MySQL", "弱口令 CVE-2012-2122") },
            { 1433, new(RiskLevel.High, ServiceCategory.Database, "MSSQL", "弱口令 / 注入") },
            { 5432, new(RiskLevel.High, ServiceCategory.Database, "PostgreSQL", "弱口令") },
            { 1521, new(RiskLevel.High, ServiceCategory.Database, "Oracle", "弱口令 / TNS 漏洞") },
            { 7001, new(RiskLevel.High, ServiceCategory.Web, "WebLogic", "反序列化 CVE-2020-14882") },
            { 4848, new(RiskLevel.High, ServiceCategory.Web, "GlassFish", "管理后台暴露") },
            { 9090, new(RiskLevel.High, ServiceCategory.Web, "Web 管理后台", "常见运维面板") },
            { 9092, new(RiskLevel.High, ServiceCategory.MessageQueue, "Kafka", "未授权访问") },
            { 5672, new(RiskLevel.High, ServiceCategory.MessageQueue, "RabbitMQ", "弱口令 / 未授权") },
            { 15672, new(RiskLevel.High, ServiceCategory.MessageQueue, "RabbitMQ 管理", "弱口令 / 未授权") },
            { 61616, new(RiskLevel.High, ServiceCategory.MessageQueue, "ActiveMQ", "反序列化 CVE-2015-5254") },
            { 6443, new(RiskLevel.High, ServiceCategory.Container, "Kubernetes API", "未授权访问 / RBAC 配置错误") },
            { 10250, new(RiskLevel.High, ServiceCategory.Container, "Kubelet", "未授权 RCE") },
            { 2379, new(RiskLevel.High, ServiceCategory.Container, "etcd", "未授权访问") },
            { 2380, new(RiskLevel.High, ServiceCategory.Container, "etcd Peer", "未授权访问") },
            { 8500, new(RiskLevel.High, ServiceCategory.DevOps, "Consul UI/API", "未授权访问") },
            { 8086, new(RiskLevel.High, ServiceCategory.BigData, "InfluxDB", "未授权访问") },
            { 9000, new(RiskLevel.High, ServiceCategory.BigData, "Hadoop/MinIO/Portainer", "管理后台") },
            { 8080, new(RiskLevel.Medium, ServiceCategory.Web, "HTTP 替代", "Web 服务") },
            { 8443, new(RiskLevel.Medium, ServiceCategory.Web, "HTTPS 替代", "Web 服务") },
            { 8161, new(RiskLevel.Medium, ServiceCategory.MessageQueue, "ActiveMQ 管理", "弱口令") },
            { 10001, new(RiskLevel.Medium, ServiceCategory.Web, "Web 管理", "常见管理后台") },

            // === Medium Risk: 邮件、目录、文件共享 ===
            { 25, new(RiskLevel.Medium, ServiceCategory.Mail, "SMTP", "开放中继") },
            { 110, new(RiskLevel.Medium, ServiceCategory.Mail, "POP3", "弱口令") },
            { 143, new(RiskLevel.Medium, ServiceCategory.Mail, "IMAP", "弱口令") },
            { 465, new(RiskLevel.Medium, ServiceCategory.Mail, "SMTPS", "弱口令") },
            { 587, new(RiskLevel.Medium, ServiceCategory.Mail, "SMTP 提交", "弱口令") },
            { 993, new(RiskLevel.Medium, ServiceCategory.Mail, "IMAPS", "弱口令") },
            { 995, new(RiskLevel.Medium, ServiceCategory.Mail, "POP3S", "弱口令") },
            { 389, new(RiskLevel.Medium, ServiceCategory.Directory, "LDAP", "匿名绑定 / 信息泄露") },
            { 636, new(RiskLevel.Medium, ServiceCategory.Directory, "LDAPS", "信息泄露") },
            { 21, new(RiskLevel.Medium, ServiceCategory.FileTransfer, "FTP", "匿名访问 / 弱口令") },
            { 20, new(RiskLevel.Medium, ServiceCategory.FileTransfer, "FTP-Data", "传输明文") },
            { 990, new(RiskLevel.Medium, ServiceCategory.FileTransfer, "FTPS", "弱口令") },
            { 445, new(RiskLevel.Medium, ServiceCategory.FileTransfer, "SMB", "永恒之蓝 CVE-2017-0144") },
            { 139, new(RiskLevel.Medium, ServiceCategory.FileTransfer, "NetBIOS", "信息泄露") },
            { 135, new(RiskLevel.Medium, ServiceCategory.FileTransfer, "RPC", "DCOM 漏洞") },
            { 2049, new(RiskLevel.Medium, ServiceCategory.FileTransfer, "NFS", "未授权挂载") },
            { 53, new(RiskLevel.Medium, ServiceCategory.Directory, "DNS", "区域传送 / 缓存投毒") },
            { 161, new(RiskLevel.Medium, ServiceCategory.Network, "SNMP", "默认 community string") },
            { 162, new(RiskLevel.Medium, ServiceCategory.Network, "SNMP Trap", "信息泄露") },
            { 123, new(RiskLevel.Low, ServiceCategory.Network, "NTP", "NTP 放大攻击") },
            { 514, new(RiskLevel.Low, ServiceCategory.Network, "Syslog", "日志泄露") },
            { 67, new(RiskLevel.Low, ServiceCategory.Network, "DHCP Server", "DHCP 欺骗") },
            { 68, new(RiskLevel.Low, ServiceCategory.Network, "DHCP Client", "信息泄露") },
            { 1900, new(RiskLevel.Low, ServiceCategory.Network, "SSDP/UPnP", "UPnP 暴露") },
            { 5000, new(RiskLevel.Low, ServiceCategory.Network, "UPnP", "UPnP 暴露") },

            // === Low Risk: 普通服务 ===
            { 80, new(RiskLevel.Low, ServiceCategory.Web, "HTTP", "Web 服务") },
            { 443, new(RiskLevel.Low, ServiceCategory.Web, "HTTPS", "Web 服务") },
            { 8000, new(RiskLevel.Low, ServiceCategory.Web, "HTTP Alt", "Web 服务") },
            { 8081, new(RiskLevel.Low, ServiceCategory.Web, "HTTP Alt", "Web 服务") },
            // 注:1433 MSSQL 已在 line 72 定义为 High (覆盖更准确)
            { 1812, new(RiskLevel.Low, ServiceCategory.Network, "RADIUS", "认证") },
            { 5060, new(RiskLevel.Low, ServiceCategory.IoT, "SIP", "VoIP") },

            // === Info: 公共/标准服务 ===
            { 1883, new(RiskLevel.Info, ServiceCategory.IoT, "MQTT", "IoT 消息") },
            { 8883, new(RiskLevel.Info, ServiceCategory.IoT, "MQTTS", "IoT 消息 TLS") },
            { 5683, new(RiskLevel.Info, ServiceCategory.IoT, "CoAP", "IoT 协议") },
            { 9042, new(RiskLevel.Info, ServiceCategory.BigData, "Cassandra", "数据库") },
            { 5601, new(RiskLevel.Info, ServiceCategory.Monitoring, "Kibana", "日志平台") },
            // 注:9090 Prometheus 已在 line 77 定义为 High (Web 管理后台),取更安全评级
            { 3000, new(RiskLevel.Info, ServiceCategory.DevOps, "Grafana/Node Exporter", "监控") },
            // 注:8080 HTTP 替代已在 line 89 定义为 Medium,取更安全评级
        };

        /// <summary>
        /// 获取端口的风险等级
        /// </summary>
        public static RiskLevel GetRiskLevel(int port)
        {
            return _portRiskDb.TryGetValue(port, out var info) ? info.Risk : RiskLevel.Low;
        }

        /// <summary>
        /// 获取端口的服务类别
        /// </summary>
        public static ServiceCategory GetCategory(int port)
        {
            return _portRiskDb.TryGetValue(port, out var info) ? info.Category : ServiceCategory.Unknown;
        }

        /// <summary>
        /// 获取端口的风险描述
        /// </summary>
        public static string GetDescription(int port)
        {
            return _portRiskDb.TryGetValue(port, out var info) ? info.Description : "";
        }

        /// <summary>
        /// 获取端口的常见漏洞提示
        /// </summary>
        public static string GetVulnHint(int port)
        {
            return _portRiskDb.TryGetValue(port, out var info) ? info.VulnHint : "";
        }

        /// <summary>
        /// 获取风险等级的数值评分（用于风险计算）
        /// </summary>
        public static int GetRiskScore(int port)
        {
            return GetRiskLevel(port) switch
            {
                RiskLevel.Critical => 30,
                RiskLevel.High => 15,
                RiskLevel.Medium => 8,
                RiskLevel.Low => 3,
                RiskLevel.Info => 1,
                _ => 1
            };
        }

        /// <summary>
        /// 获取所有严重和高危端口（用于重点扫描）
        /// </summary>
        public static List<int> GetHighRiskPorts()
        {
            return _portRiskDb
                .Where(kv => kv.Value.Risk == RiskLevel.Critical || kv.Value.Risk == RiskLevel.High)
                .Select(kv => kv.Key)
                .OrderBy(p => p)
                .ToList();
        }

        /// <summary>
        /// 按类别获取端口列表
        /// </summary>
        public static List<int> GetPortsByCategory(ServiceCategory category)
        {
            return _portRiskDb
                .Where(kv => kv.Value.Category == category)
                .Select(kv => kv.Key)
                .OrderBy(p => p)
                .ToList();
        }

        /// <summary>
        /// 获取类别中文名
        /// </summary>
        public static string GetCategoryName(ServiceCategory category)
        {
            return category switch
            {
                ServiceCategory.Web => "Web 服务",
                ServiceCategory.Database => "数据库",
                ServiceCategory.RemoteAccess => "远程访问",
                ServiceCategory.FileTransfer => "文件传输",
                ServiceCategory.Mail => "邮件服务",
                ServiceCategory.Directory => "目录服务",
                ServiceCategory.Container => "容器/编排",
                ServiceCategory.MessageQueue => "消息队列",
                ServiceCategory.BigData => "大数据",
                ServiceCategory.Network => "网络服务",
                ServiceCategory.Monitoring => "监控运维",
                ServiceCategory.DevOps => "DevOps 工具",
                ServiceCategory.Proxy => "代理服务",
                ServiceCategory.IoT => "IoT 设备",
                _ => "其他"
            };
        }

        /// <summary>
        /// 获取风险等级中文名
        /// </summary>
        public static string GetRiskLevelName(RiskLevel level)
        {
            return level switch
            {
                RiskLevel.Critical => "严重",
                RiskLevel.High => "高危",
                RiskLevel.Medium => "中危",
                RiskLevel.Low => "低危",
                RiskLevel.Info => "信息",
                _ => "未知"
            };
        }

        /// <summary>
        /// 端口风险信息
        /// </summary>
        private class PortRiskInfo
        {
            public RiskLevel Risk { get; }
            public ServiceCategory Category { get; }
            public string Description { get; }
            public string VulnHint { get; }

            public PortRiskInfo(RiskLevel risk, ServiceCategory category, string description, string vulnHint)
            {
                Risk = risk;
                Category = category;
                Description = description;
                VulnHint = vulnHint;
            }
        }
    }
}
