using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.Json;

namespace NetSecurityScanner.Utils
{
    /// <summary>
    /// 端口服务映射工具类
    /// </summary>
    public static class PortServiceMapping
    {
        private static Dictionary<int, string> _portMappings;
        private static List<int> _commonPorts;
        private static List<int> _sensitivePorts;
        private static DateTime _lastLoadTime;
        private static readonly TimeSpan _reloadInterval = TimeSpan.FromMinutes(5);
        
        /// <summary>
        /// 获取端口对应的服务名称
        /// </summary>
        public static string GetServiceName(int port)
        {
            LoadPortMappings();
            
            if (_portMappings.TryGetValue(port, out string serviceName))
            {
                return serviceName;
            }
            
            // 使用默认映射作为后备
            return GetDefaultServiceName(port);
        }
        
        /// <summary>
        /// 判断是否为常见端口
        /// </summary>
        public static bool IsCommonPort(int port)
        {
            LoadPortMappings();
            return _commonPorts.Contains(port);
        }
        
        /// <summary>
        /// 获取常见端口列表
        /// </summary>
        public static List<int> GetCommonPorts()
        {
            LoadPortMappings();
            return _commonPorts;
        }
        
        /// <summary>
        /// 获取敏感端口列表
        /// </summary>
        public static List<int> GetSensitivePorts()
        {
            LoadPortMappings();
            return _sensitivePorts;
        }
        
        /// <summary>
        /// 加载端口映射
        /// </summary>
        private static void LoadPortMappings()
        {
            // 检查是否需要重新加载
            if (_portMappings != null && DateTime.Now - _lastLoadTime < _reloadInterval)
            {
                return;
            }
            
            try
            {
                // 从本地文件加载端口映射
                string appDataPath = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
                string portMappingPath = Path.Combine(appDataPath, "NetSecurityScanner", "port_mapping.json");
                
                if (File.Exists(portMappingPath))
                {
                    string json = File.ReadAllText(portMappingPath);
                    _portMappings = JsonSerializer.Deserialize<Dictionary<int, string>>(json);
                    
                    // 从映射中提取常见端口
                    _commonPorts = _portMappings.Keys.ToList();
                    _sensitivePorts = GetDefaultSensitivePorts();
                    _lastLoadTime = DateTime.Now;
                    return;
                }
            }
            catch
            {
                // 加载失败，使用默认值
            }
            
            // 使用默认值
            _portMappings = GetDefaultPortMappings();
            _commonPorts = GetDefaultCommonPorts();
            _sensitivePorts = GetDefaultSensitivePorts();
            _lastLoadTime = DateTime.Now;
        }
        
        /// <summary>
        /// 获取默认端口映射
        /// </summary>
        private static Dictionary<int, string> GetDefaultPortMappings()
        {
            return new Dictionary<int, string>
            {
                // FTP 相关
                { 20, "FTP-Data" },
                { 21, "FTP" },
                { 990, "FTPS" },

                // SSH 相关
                { 22, "SSH" },
                { 23, "Telnet" },
                { 2222, "SSH-Alt" },

                // 邮件服务
                { 25, "SMTP" },
                { 110, "POP3" },
                { 143, "IMAP" },
                { 465, "SMTPS" },
                { 587, "SMTP-Submission" },
                { 993, "IMAPS" },
                { 995, "POP3S" },

                // Web 服务
                { 80, "HTTP" },
                { 443, "HTTPS" },
                { 8080, "HTTP-Alt" },
                { 8443, "HTTPS-Alt" },
                { 8000, "HTTP-Alt" },
                { 8081, "HTTP-Alt" },
                { 8888, "HTTP-Alt" },
                // 注:9090 已在 line 228 下方 Prometheus 定义,保持单一来源
                { 1080, "SOCKS" },
                { 3128, "HTTP-Proxy" },

                // 数据库服务
                { 3306, "MySQL" },
                { 1433, "MSSQL" },
                { 5432, "PostgreSQL" },
                { 1521, "Oracle" },
                { 27017, "MongoDB" },
                { 6379, "Redis" },
                { 27015, "MongoDB-Alt" },
                { 5984, "CouchDB" },
                { 11211, "Memcached" },
                { 9200, "Elasticsearch" },
                { 9300, "Elasticsearch-Transport" },
                { 9042, "Cassandra" },
                { 7000, "Cassandra-Inter" },
                { 7474, "Neo4j-HTTP" },
                { 7687, "Neo4j-Bolt" },

                // 远程访问
                { 3389, "RDP" },
                { 5900, "VNC" },
                { 5901, "VNC-Alt" },
                { 5902, "VNC-Alt" },
                { 5938, "TeamViewer" },

                // 网络服务
                { 53, "DNS" },
                { 67, "DHCP-Server" },
                { 68, "DHCP-Client" },
                { 123, "NTP" },
                { 161, "SNMP" },
                { 162, "SNMP-Trap" },
                { 514, "Syslog" },
                { 1900, "SSDP" },
                { 1812, "RADIUS" },
                { 5060, "SIP" },
                { 5061, "SIPS" },

                // 文件共享
                { 445, "SMB" },
                { 135, "RPC" },
                { 137, "NetBIOS-Name" },
                { 138, "NetBIOS-Datagram" },
                { 139, "NetBIOS-Session" },
                { 2049, "NFS" },
                { 873, "Rsync" },

                // 目录服务
                { 389, "LDAP" },
                { 636, "LDAPS" },
                { 88, "Kerberos" },
                { 3268, "LDAP-GC" },
                { 3269, "LDAPS-GC" },

                // 容器与编排
                { 2375, "Docker-API" },
                { 2376, "Docker-API-TLS" },
                { 2379, "etcd" },
                { 2380, "etcd-Peer" },
                { 6443, "Kubernetes-API" },
                { 10250, "Kubelet" },
                { 10251, "Kube-Scheduler" },
                { 10252, "Kube-Controller" },
                { 10255, "Kubelet-ReadOnly" },
                { 10256, "Kube-Proxy" },

                // 消息队列
                { 9092, "Kafka" },
                { 5672, "RabbitMQ" },
                { 15672, "RabbitMQ-Management" },
                { 61616, "ActiveMQ" },
                { 8161, "ActiveMQ-Web" },
                { 9876, "RocketMQ" },
                { 4226, "NATS-Client" },
                { 8222, "NATS-HTTP" },

                // 大数据与中间件
                { 2181, "ZooKeeper" },
                { 8086, "InfluxDB" },
                { 9000, "Hadoop/MinIO" },
                { 9870, "Hadoop-HDFS" },
                { 8088, "YARN" },
                { 16010, "HBase" },
                { 5601, "Kibana" },

                // 监控运维
                { 3000, "Grafana" },
                { 9090, "Prometheus" },
                { 9100, "Node-Exporter" },
                { 10050, "Zabbix-Agent" },
                { 10051, "Zabbix-Server" },
                { 19999, "Netdata" },

                // DevOps 工具
                // 注:8080 HTTP-Alt / 8443 HTTPS-Alt / 80 HTTP / 9000 Hadoop/MinIO 已分别在 line 133/134/131/220 定义
                { 8929, "GitLab-SSH" },
                { 8500, "Consul" },
                { 8600, "Consul-DNS" },
                { 8200, "Vault" },

                // 应用服务器
                { 7001, "WebLogic" },
                { 7002, "WebLogic-SSL" },
                { 4848, "GlassFish" },
                { 9990, "WildFly" },
                { 1099, "RMI/JBoss" },
                { 4444, "RMI-Alt" },
                { 8009, "AJP" },

                // IoT 协议
                { 1883, "MQTT" },
                { 8883, "MQTTS" },
                { 5683, "CoAP" },
                { 502, "Modbus" },
                { 102, "S7comm" },

                // 其他常见服务
                { 5000, "UPnP" },
                { 8008, "HTTP-Alt" },
                // 注:8009 AJP 已合并到 line 252 上方应用服务器区域,避免重复键
                { 8079, "TiDB" },
                { 9001, "MinIO-Console" },
                // 注:9001 Tor-OR 已合并到 MinIO-Console,避免重复键
                { 4000, "ICCP" },
                { 7077, "Spark" }
            };
        }
        
        /// <summary>
        /// 获取默认服务名称
        /// </summary>
        private static string GetDefaultServiceName(int port)
        {
            var defaultMappings = GetDefaultPortMappings();
            if (defaultMappings.TryGetValue(port, out string serviceName))
            {
                return serviceName;
            }
            return "未知服务";
        }
        
        /// <summary>
        /// 获取默认常见端口列表
        /// </summary>
        private static List<int> GetDefaultCommonPorts()
        {
            return new List<int>
            {
                20, 21, 22, 23, 25, 53, 67, 68, 80, 110, 123, 135, 137, 138, 139, 143, 161, 162, 389, 443, 445, 465, 587, 636, 990, 993, 995, 1433, 1521, 2049, 2222, 27017, 3306, 3389, 5432, 5900, 6379, 8000, 8080, 8081, 8443, 8086, 9200, 9300
            };
        }
        
        /// <summary>
        /// 获取默认敏感端口列表
        /// </summary>
        private static List<int> GetDefaultSensitivePorts()
        {
            return new List<int>
            {
                22, 23, 25, 110, 143, 3306, 1433, 5432, 1521, 27017, 3389, 5900, 6379
            };
        }

        /// <summary>
        /// 端口预设场景
        /// </summary>
        public enum PortPreset
        {
            WebServer,     // Web 服务器场景
            Database,      // 数据库场景
            Container,     // 容器/编排场景
            RemoteAccess,  // 远程访问场景
            MailServer,    // 邮件服务器场景
            FileShare,     // 文件共享场景
            DevOps,        // DevOps/CI 场景
            IoTDevice,     // IoT 设备场景
            Monitoring,    // 监控运维场景
            HighRisk       // 高危端口（严重+高危）
        }

        /// <summary>
        /// 端口预设场景元数据
        /// </summary>
        public class PortPresetInfo
        {
            public PortPreset Preset { get; set; }
            public string Name { get; set; } = "";
            public string Description { get; set; } = "";
            public List<int> Ports { get; set; } = new();
        }

        /// <summary>
        /// 获取所有预设场景信息
        /// </summary>
        public static List<PortPresetInfo> GetAllPresets()
        {
            return new List<PortPresetInfo>
            {
                new PortPresetInfo
                {
                    Preset = PortPreset.WebServer,
                    Name = "Web 服务器",
                    Description = "HTTP/HTTPS 及常见 Web 代理、WebLogic/Tomcat/Jenkins 等",
                    Ports = new List<int> { 80, 443, 8000, 8080, 8081, 8443, 8888, 8008, 9090, 7001, 7002, 4848, 9990, 1080, 3128, 8009 }
                },
                new PortPresetInfo
                {
                    Preset = PortPreset.Database,
                    Name = "数据库",
                    Description = "关系型/非关系型数据库及大数据存储",
                    Ports = new List<int> { 3306, 1433, 5432, 1521, 27017, 6379, 11211, 9200, 9300, 5984, 9042, 7000, 7474, 7687, 8086, 2181, 27015 }
                },
                new PortPresetInfo
                {
                    Preset = PortPreset.Container,
                    Name = "容器/编排",
                    Description = "Docker、Kubernetes、etcd 等容器化相关服务",
                    Ports = new List<int> { 2375, 2376, 2379, 2380, 6443, 10250, 10251, 10252, 10255, 10256 }
                },
                new PortPresetInfo
                {
                    Preset = PortPreset.RemoteAccess,
                    Name = "远程访问",
                    Description = "SSH、Telnet、RDP、VNC 等远程接入",
                    Ports = new List<int> { 22, 23, 2222, 3389, 5900, 5901, 5902, 5938, 512, 513 }
                },
                new PortPresetInfo
                {
                    Preset = PortPreset.MailServer,
                    Name = "邮件服务",
                    Description = "SMTP/POP3/IMAP 及其 TLS 变体",
                    Ports = new List<int> { 25, 110, 143, 465, 587, 993, 995 }
                },
                new PortPresetInfo
                {
                    Preset = PortPreset.FileShare,
                    Name = "文件共享",
                    Description = "FTP/SMB/NFS/Rsync 等文件共享协议",
                    Ports = new List<int> { 20, 21, 990, 135, 137, 138, 139, 445, 873, 2049 }
                },
                new PortPresetInfo
                {
                    Preset = PortPreset.DevOps,
                    Name = "DevOps 工具",
                    Description = "Jenkins、GitLab、Consul、Vault 等 DevOps 平台",
                    Ports = new List<int> { 8080, 8443, 8929, 8500, 8600, 8200, 9000, 10001 }
                },
                new PortPresetInfo
                {
                    Preset = PortPreset.IoTDevice,
                    Name = "IoT 设备",
                    Description = "MQTT、CoAP、Modbus、S7comm 等物联网协议",
                    Ports = new List<int> { 1883, 8883, 5683, 502, 102 }
                },
                new PortPresetInfo
                {
                    Preset = PortPreset.Monitoring,
                    Name = "监控运维",
                    Description = "Prometheus、Grafana、Zabbix、Node Exporter 等",
                    Ports = new List<int> { 3000, 9090, 9100, 10050, 10051, 19999, 5601, 8086 }
                },
                new PortPresetInfo
                {
                    Preset = PortPreset.HighRisk,
                    Name = "高危端口（重点）",
                    Description = "Critical+High 风险端口，优先发现高价值目标",
                    Ports = PortRiskScorer.GetHighRiskPorts()
                }
            };
        }

        /// <summary>
        /// 获取指定预设场景的端口列表
        /// </summary>
        public static List<int> GetPresetPorts(PortPreset preset)
        {
            return GetAllPresets().FirstOrDefault(p => p.Preset == preset)?.Ports ?? new List<int>();
        }

        /// <summary>
        /// 获取预设场景的中文名称
        /// </summary>
        public static string GetPresetName(PortPreset preset)
        {
            return GetAllPresets().FirstOrDefault(p => p.Preset == preset)?.Name ?? preset.ToString();
        }
    }
}