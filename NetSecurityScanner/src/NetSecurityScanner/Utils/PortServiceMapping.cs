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
                
                // 数据库服务
                { 3306, "MySQL" },
                { 1433, "MSSQL" },
                { 5432, "PostgreSQL" },
                { 1521, "Oracle" },
                { 27017, "MongoDB" },
                { 6379, "Redis" },
                { 27015, "MongoDB-Alt" },
                
                // 远程访问
                { 3389, "RDP" },
                { 5900, "VNC" },
                { 5901, "VNC-Alt" },
                
                // 网络服务
                { 53, "DNS" },
                { 67, "DHCP-Server" },
                { 68, "DHCP-Client" },
                { 123, "NTP" },
                { 161, "SNMP" },
                { 162, "SNMP-Trap" },
                
                // 文件共享
                { 445, "SMB" },
                { 135, "RPC" },
                { 137, "NetBIOS-Name" },
                { 138, "NetBIOS-Datagram" },
                { 139, "NetBIOS-Session" },
                
                // 其他常见服务
                { 2049, "NFS" },
                { 389, "LDAP" },
                { 636, "LDAPS" },
                { 5000, "UPnP" },
                { 8086, "InfluxDB" },
                { 9200, "Elasticsearch" },
                { 9300, "Elasticsearch-Transport" }
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
    }
}