using System.Collections.Generic;
using System.Linq;

namespace NetSecurityScanner.Utils
{
    public static class CommonPorts
    {
        /// <summary>
        /// 1000 端口以上的高频服务端口。
        ///
        /// 这是「常用端口」模式的关键补充：仅扫描 1~1000 会漏掉所有高位常见服务端口，
        /// 而实际互联网暴露面里，Web 管理后台、数据库、中间件、容器编排几乎都在高位端口上。
        /// </summary>
        private static readonly List<int> _highFrequencyPorts = new List<int>
        {
            // 远程管理 / 运维
            1080,   // SOCKS 代理
            1099,   // Java RMI / JMX
            1521,   // Oracle
            1723,   // PPTP
            2049,   // NFS
            2082,   // cPanel
            2083,   // cPanel SSL
            2086,   // WHM
            2087,   // WHM SSL
            2222,   // SSH 备用 / DirectAdmin
            // 容器与编排
            2375,   // Docker HTTP（未授权高危）
            2376,   // Docker HTTPS
            2379,   // etcd client
            2380,   // etcd peer
            4194,   // cAdvisor
            6443,   // Kubernetes API
            10250,  // Kubelet API
            10251,  // kube-scheduler
            10252,  // kube-controller-manager
            10255,  // Kubelet read-only
            10257, 10259,
            // 数据库
            1433,   // MSSQL
            26379,  // Redis TLS
            3306,   // MySQL
            5432,   // PostgreSQL
            5984,   // CouchDB
            6379,   // Redis
            9042,   // Cassandra
            11211,  // Memcached
            15672,  // RabbitMQ 管理端
            16379,  // Redis 备用
            27017,  // MongoDB
            27018, 27019,
            28017,  // MongoDB Web 控制台
            // Web / 应用服务
            3000,   // Grafana / Node
            3128,   // Squid
            3268,   // LDAP Global Catalog
            3269,   // LDAP GC SSL
            3389,   // RDP
            4000, 4040,
            4443, 4444,
            4567,   // Sinatra
            5000,   // Flask / UPnP
            5001,
            5060,   // SIP
            5061,   // SIP TLS
            5601,   // Kibana
            5672,   // RabbitMQ
            5900,   // VNC
            6000,   // X11
            7000,   // AFS / 文件服务
            7001,   // WebLogic
            7070,   // Solr / RTSP 备用
            8000,   // HTTP 备用
            8008,   // HTTP 备用
            8009,   // Apache JServ
            8069,   // Odoo
            8080,   // HTTP 备用（最常见的高位 Web 端口）
            8081, 8082, 8088,   // Hadoop
            8090, 8098,
            8161,   // ActiveMQ 管理端
            8181,
            8222,
            8443,   // HTTPS 备用
            8500,   // Consul
            8530, 8531,
            8545,   // Ethereum JSON-RPC
            8554,   // RTSP
            8880,
            8888,   // Jupyter Notebook
            9000,   // SonarQube / PHP-FPM
            9001,
            9060, 9080,
            9090,   // Prometheus / Web 管理
            9092,   // Kafka
            9100,   // Prometheus node_exporter
            9200,   // Elasticsearch
            9300,   // Elasticsearch 集群通信
            9411,   // GitLab
            9443,
            9999,   // GlassFish
            10000,  // Webmin / 运维面板
            10050, 10051,   // Zabbix
            // 中间件 / 大数据 / 其他
            50000,  // SAP
            50070,  // Hadoop NameNode
            54321,
            61616,  // ActiveMQ
            65535
        };

        /// <summary>
        /// 「常用端口」扫描模式使用的端口集合（约 1100 个）。
        ///
        /// 重要背景：专家模式原先直接用 Enumerable.Range(1, 1000)，即端口 1~1000 的连续区间。
        /// 这既不是"常用端口"的语义，也不是 Nmap 的 Top-1000 频率排名，后果很严重：
        ///   1) 所有大于 1000 的常见服务端口（8080/8443/8888/3306/3389/5432/27017 等）都不会被扫描；
        ///   2) 目标若只开放高位端口，端口扫描结果为空；
        ///   3) 漏洞扫描以开放端口为唯一输入（openPorts.Any()），于是漏洞结果也一并为空。
        /// 实测目标 211.137.75.166 开放的 8443 就因此被漏判。
        ///
        /// 现改为：知名端口 1~1024 全量 + 1000 以上的高频服务端口。
        /// 这样在覆盖度与扫描耗时之间取得平衡——多出的约 100 个端口换来对主流服务的完整覆盖。
        /// </summary>
        public static List<int> GetTop1000Ports()
        {
            var ports = new List<int>(Enumerable.Range(1, 1024));
            ports.AddRange(_highFrequencyPorts);
            return ports.Distinct().OrderBy(p => p).ToList();
        }
        // 敏感端口列表
        private static readonly List<int> _sensitivePorts = new List<int>
        {
            21,   // FTP
            22,   // SSH
            23,   // Telnet
            3389, // RDP
            445,  // SMB
            6379, // Redis
            27017, // MongoDB
            9200, // Elasticsearch
            11211, // Memcached
            2375, // Docker HTTP
            2376, // Docker HTTPS
            6443, // Kubernetes API
            8080, // HTTP Alternate
            8443  // HTTPS Alternate
        };

        // 所有常见端口列表
        public static List<int> GetAllPorts()
        {
            return new List<int>
            {
                // 基础服务
                21,   // FTP
                22,   // SSH
                23,   // Telnet
                25,   // SMTP
                53,   // DNS
                80,   // HTTP
                443,  // HTTPS
                
                // 邮件服务
                110,  // POP3
                143,  // IMAP
                465,  // SMTPS
                993,  // IMAPS
                995,  // POP3S
                587,  // SMTP Submission
                
                // 数据库服务
                1433, // MSSQL
                3306, // MySQL
                5432, // PostgreSQL
                6379, // Redis
                27017, // MongoDB
                9200, // Elasticsearch
                11211, // Memcached
                9042, // Cassandra
                5984, // CouchDB
                
                // 远程访问
                3389, // RDP
                5900, // VNC
                445,  // SMB
                
                // Web服务
                8080, // HTTP Alternate
                8443, // HTTPS Alternate
                8081, // HTTP Alternate 2
                8000, // HTTP Alternate 3
                
                // 容器和编排
                2375, // Docker HTTP
                2376, // Docker HTTPS
                6443, // Kubernetes API
                2379, // etcd client
                2380, // etcd peer
                10250, // Kubelet API
                10251, // kube-scheduler
                10252, // kube-controller-manager
                10255, // Kubelet read-only
                
                // 消息队列
                5672, // RabbitMQ
                9092, // Kafka
                61616, // ActiveMQ
                
                // 其他服务
                123,  // NTP
                161,  // SNMP
                162,  // SNMP-Trap
                389,  // LDAP
                636,  // LDAPS
                5060, // SIP
                5061, // SIPS
                1812, // Radius Authentication
                1813, // Radius Accounting
                8088, // Hadoop
                9000, // SonarQube
                9100, // Prometheus
                3000, // Grafana
                4200, // Angular Dev Server
                5000, // Flask Dev Server
                8888, // Jupyter Notebook
                9001, // ActiveMQ Admin
                9090, // Prometheus Web
                9411, // GitLab
                9999  // GlassFish
            };
        }

        // 获取常用端口（较少的端口，适合快速扫描）
        public static List<int> GetCommonPorts()
        {
            return new List<int>
            {
                21,   // FTP
                22,   // SSH
                23,   // Telnet
                25,   // SMTP
                53,   // DNS
                80,   // HTTP
                110,  // POP3
                143,  // IMAP
                443,  // HTTPS
                465,  // SMTPS
                993,  // IMAPS
                995,  // POP3S
                1433, // MSSQL
                3306, // MySQL
                3389, // RDP
                5432, // PostgreSQL
                6379, // Redis
                27017, // MongoDB
                8080, // HTTP Alternate
                8443  // HTTPS Alternate
            };
        }

        // 判断是否为敏感端口
        public static bool IsSensitivePort(int port)
        {
            return _sensitivePorts.Contains(port);
        }

        // 获取敏感端口列表
        public static List<int> GetSensitivePorts()
        {
            return new List<int>(_sensitivePorts);
        }
    }
}