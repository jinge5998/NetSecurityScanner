using System.Collections.Generic;

namespace NetSecurityScanner.Utils
{
    public static class CommonPorts
    {
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