using NetSecurityScanner.Models;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading.Tasks;

namespace NetSecurityScanner.Services
{
    /// <summary>
    /// 插件市场目录项（本地 mock 数据源）
    /// </summary>
    public class PluginMarketPlugin
    {
        public string Id { get; set; } = string.Empty;
        public string Name { get; set; } = string.Empty;
        public string Description { get; set; } = string.Empty;
        public string Version { get; set; } = "1.0.0";
        public string Author { get; set; } = string.Empty;

        /// <summary>
        /// 类别：漏洞扫描 / 弱口令 / Web安全 / 合规检查
        /// </summary>
        public string Category { get; set; } = string.Empty;

        public double Rating { get; set; }
        public int DownloadCount { get; set; }
        public string Icon { get; set; } = "🔌";
        public long SizeBytes { get; set; }

        // v6：核心版本要求（v6-T3 由 VersionManager 校验）
        public string? MinCoreVersion { get; set; }
    }

    /// <summary>
    /// 插件商店目录服务（本地 mock 12 个插件，模拟"商店"列表）。
    /// </summary>
    public class PluginMarketCatalogService
    {
        private readonly List<PluginMarketPlugin> _catalog;
        private readonly string _pluginsDirectory;

        public PluginMarketCatalogService()
        {
            _pluginsDirectory = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "Plugins");
            _catalog = BuildMockCatalog();
        }

        /// <summary>
        /// 获取全部 mock 插件
        /// </summary>
        public Task<List<PluginMarketPlugin>> GetAllAsync()
        {
            return Task.FromResult(_catalog.Select(Clone).ToList());
        }

        /// <summary>
        /// 按关键词 + 类别过滤
        /// </summary>
        public Task<List<PluginMarketPlugin>> SearchAsync(string keyword, string category)
        {
            IEnumerable<PluginMarketPlugin> q = _catalog;

            if (!string.IsNullOrWhiteSpace(category) && category != "全部")
            {
                q = q.Where(p => string.Equals(p.Category, category, StringComparison.OrdinalIgnoreCase));
            }

            if (!string.IsNullOrWhiteSpace(keyword))
            {
                var kw = keyword.Trim().ToLowerInvariant();
                q = q.Where(p =>
                    (p.Name?.ToLowerInvariant().Contains(kw) ?? false) ||
                    (p.Description?.ToLowerInvariant().Contains(kw) ?? false) ||
                    (p.Author?.ToLowerInvariant().Contains(kw) ?? false) ||
                    (p.Id?.ToLowerInvariant().Contains(kw) ?? false));
            }

            return Task.FromResult(q.Select(Clone).ToList());
        }

        /// <summary>
        /// 判断插件是否已安装（以 Plugins/{id}/ 目录存在为标志）
        /// </summary>
        public Task<bool> IsInstalledAsync(string pluginId)
        {
            if (string.IsNullOrWhiteSpace(pluginId))
                return Task.FromResult(false);

            try
            {
                var dir = Path.Combine(_pluginsDirectory, pluginId);
                return Task.FromResult(Directory.Exists(dir));
            }
            catch
            {
                return Task.FromResult(false);
            }
        }

        /// <summary>
        /// 按 ID 获取插件
        /// </summary>
        public Task<PluginMarketPlugin?> GetByIdAsync(string id)
        {
            if (string.IsNullOrWhiteSpace(id))
                return Task.FromResult<PluginMarketPlugin?>(null);

            var found = _catalog.FirstOrDefault(p =>
                string.Equals(p.Id, id, StringComparison.OrdinalIgnoreCase));
            return Task.FromResult(found == null ? null : Clone(found));
        }

        private static PluginMarketPlugin Clone(PluginMarketPlugin src)
        {
            return new PluginMarketPlugin
            {
                Id = src.Id,
                Name = src.Name,
                Description = src.Description,
                Version = src.Version,
                Author = src.Author,
                Category = src.Category,
                Rating = src.Rating,
                DownloadCount = src.DownloadCount,
                Icon = src.Icon,
                SizeBytes = src.SizeBytes
            };
        }

        private static List<PluginMarketPlugin> BuildMockCatalog()
        {
            return new List<PluginMarketPlugin>
            {
                new PluginMarketPlugin
                {
                    Id = "market.hikvision.weakpwd",
                    Name = "Hikvision 弱口令扫描",
                    Description = "针对海康威视摄像头的弱口令检测，覆盖 admin/12345、admin/12345abc 等 30+ 常见组合。",
                    Version = "1.4.0",
                    Author = "安全研究团队",
                    Category = "漏洞扫描",
                    Rating = 4.7,
                    DownloadCount = 12890,
                    Icon = "📷",
                    SizeBytes = 1_200_000
                },
                new PluginMarketPlugin
                {
                    Id = "market.onvif.enumerate",
                    Name = "ONVIF 设备枚举",
                    Description = "探测 ONVIF 协议服务，自动发现摄像头/NVR 设备并提取固件信息。",
                    Version = "1.1.2",
                    Author = "Web 安全实验室",
                    Category = "Web安全",
                    Rating = 4.4,
                    DownloadCount = 6520,
                    Icon = "🎥",
                    SizeBytes = 880_000
                },
                new PluginMarketPlugin
                {
                    Id = "market.ssl.grade",
                    Name = "SSL 评分",
                    Description = "基于 SSLLabs 评分算法对 SSL/TLS 配置进行 A-F 等级评定。",
                    Version = "2.0.0",
                    Author = "加密安全专家",
                    Category = "合规检查",
                    Rating = 4.8,
                    DownloadCount = 9100,
                    Icon = "🔐",
                    SizeBytes = 1_500_000
                },
                new PluginMarketPlugin
                {
                    Id = "market.ssh.weakpwd.deep",
                    Name = "SSH 弱口令深度",
                    Description = "50+ 默认凭据字典，支持 OpenSSH/libssh/华为/思科等 SSH 服务深度检测。",
                    Version = "1.3.0",
                    Author = "网络扫描专家",
                    Category = "弱口令",
                    Rating = 4.6,
                    DownloadCount = 11230,
                    Icon = "🔑",
                    SizeBytes = 2_100_000
                },
                new PluginMarketPlugin
                {
                    Id = "market.http.infoleak",
                    Name = "HTTP 敏感信息泄露",
                    Description = "30+ 高风险路径爆破（.git/.svn/.env/backup/web.config 等），识别信息泄露。",
                    Version = "1.2.5",
                    Author = "Web 安全实验室",
                    Category = "Web安全",
                    Rating = 4.5,
                    DownloadCount = 14500,
                    Icon = "🕵️",
                    SizeBytes = 980_000
                },
                new PluginMarketPlugin
                {
                    Id = "market.ftp.anonymous",
                    Name = "FTP 匿名访问",
                    Description = "探测 FTP 服务的匿名登录、弱口令与目录遍历漏洞。",
                    Version = "1.0.4",
                    Author = "安全研究团队",
                    Category = "漏洞扫描",
                    Rating = 4.2,
                    DownloadCount = 7800,
                    Icon = "📂",
                    SizeBytes = 720_000
                },
                new PluginMarketPlugin
                {
                    Id = "market.redis.unauth",
                    Name = "Redis 未授权访问",
                    Description = "检测无密码 Redis 服务，支持 CONFIG/INFO/SLAVEOF 等危险命令探测。",
                    Version = "1.5.1",
                    Author = "数据库安全组",
                    Category = "漏洞扫描",
                    Rating = 4.7,
                    DownloadCount = 13420,
                    Icon = "💾",
                    SizeBytes = 860_000
                },
                new PluginMarketPlugin
                {
                    Id = "market.ics.identify",
                    Name = "工控协议识别 (Modbus/S7)",
                    Description = "识别 Modbus/TCP、S7Comm、IEC-60870 等工控协议，定位工控设备。",
                    Version = "1.0.7",
                    Author = "工业安全研究组",
                    Category = "漏洞扫描",
                    Rating = 4.3,
                    DownloadCount = 3210,
                    Icon = "🏭",
                    SizeBytes = 1_350_000
                },
                new PluginMarketPlugin
                {
                    Id = "market.db.weakpwd",
                    Name = "数据库弱口令 (MySQL/PG/MSSQL)",
                    Description = "默认数据库凭据深度扫描，覆盖 MySQL/PostgreSQL/MSSQL/Oracle/MongoDB。",
                    Version = "2.1.0",
                    Author = "数据库安全组",
                    Category = "弱口令",
                    Rating = 4.8,
                    DownloadCount = 18650,
                    Icon = "🗄️",
                    SizeBytes = 1_800_000
                },
                new PluginMarketPlugin
                {
                    Id = "market.camera.firmware",
                    Name = "摄像头固件版本检测",
                    Description = "识别海康/大华/宇视/雄迈等摄像头固件版本，匹配已知 CVE 漏洞库。",
                    Version = "1.2.3",
                    Author = "IoT 安全团队",
                    Category = "合规检查",
                    Rating = 4.5,
                    DownloadCount = 5430,
                    Icon = "📹",
                    SizeBytes = 1_120_000
                },
                new PluginMarketPlugin
                {
                    Id = "market.snmp.weak",
                    Name = "SNMP 弱 community",
                    Description = "探测 public/private/弱 community 字符串，识别 SNMP 信息泄露与配置风险。",
                    Version = "1.0.6",
                    Author = "网络扫描专家",
                    Category = "弱口令",
                    Rating = 4.4,
                    DownloadCount = 6720,
                    Icon = "📡",
                    SizeBytes = 760_000
                },
                new PluginMarketPlugin
                {
                    Id = "market.router.default",
                    Name = "路由器默认凭据 (TP-Link/D-Link)",
                    Description = "TP-Link/D-Link/水星/腾达等家用路由器默认 admin/admin、admin/password 检测。",
                    Version = "1.1.0",
                    Author = "网络扫描专家",
                    Category = "弱口令",
                    Rating = 4.6,
                    DownloadCount = 9450,
                    Icon = "🌐",
                    SizeBytes = 690_000
                }
            };
        }
    }
}
