using System;
using System.IO;

namespace NetSecurityScanner.Utils
{
    /// <summary>
    /// 集中化数据目录：所有持久化文件（users.json / audit_log.json / assets/ 等）都应放在此目录下，
    /// 避免各 bin 目录相互隔离导致数据看不到。
    ///
    /// 优先级：
    /// 1. 环境变量 NETSEC_DATA_DIR（测试 / 诊断用）
    /// 2. %LOCALAPPDATA%\NetSecurityScanner\data\（Windows 推荐）
    /// 3. ~/NetSecurityScanner/data/（跨平台兜底）
    /// </summary>
    public static class DataPaths
    {
        public static string DataRoot { get; }

        /// <summary>
        /// 应用根目录（DataRoot 的父目录）。v6 引入。
        /// 例：C:\Users\xxx\AppData\Local\NetSecurityScanner\
        /// </summary>
        public static string AppDataDirectory { get; }

        public static string UsersFile => Path.Combine(DataRoot, "users.json");
        public static string SessionFile => Path.Combine(DataRoot, "session.json");
        public static string AuditLogFile => Path.Combine(DataRoot, "audit_log.json");
        public static string AssetsRoot => Path.Combine(DataRoot, "assets");

        public static string GetUserAssetsDir(string username) =>
            Path.Combine(AssetsRoot, SanitizeUsername(username));

        public static string GetUserAssetsFile(string username) =>
            Path.Combine(GetUserAssetsDir(username), "assets.json");

        static DataPaths()
        {
            // 1) 环境变量优先
            var env = Environment.GetEnvironmentVariable("NETSEC_DATA_DIR");
            if (!string.IsNullOrWhiteSpace(env))
            {
                DataRoot = env;
            }
            else
            {
                // 2) %LOCALAPPDATA%\NetSecurityScanner\data\
                var localAppData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
                if (!string.IsNullOrWhiteSpace(localAppData))
                {
                    DataRoot = Path.Combine(localAppData, "NetSecurityScanner", "data");
                }
                else
                {
                    // 3) 兜底
                    var home = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
                    DataRoot = Path.Combine(home ?? ".", "NetSecurityScanner", "data");
                }
            }

            // AppDataDirectory = DataRoot 的父目录（PluginPolicy / scheduled_tasks.json 等放在这一层）
            try
            {
                var parent = Directory.GetParent(DataRoot);
                AppDataDirectory = parent?.FullName ?? DataRoot;
            }
            catch
            {
                AppDataDirectory = DataRoot;
            }

            // 确保目录存在
            try
            {
                Directory.CreateDirectory(DataRoot);
                Directory.CreateDirectory(AssetsRoot);
                Directory.CreateDirectory(AppDataDirectory);
            }
            catch
            {
                // 权限不足时使用 bin 目录（最后的回退）
                DataRoot = Path.Combine(AppContext.BaseDirectory, "data");
                AppDataDirectory = AppContext.BaseDirectory;
                Directory.CreateDirectory(DataRoot);
                Directory.CreateDirectory(AssetsRoot);
            }
        }

        private static string SanitizeUsername(string username)
        {
            if (string.IsNullOrWhiteSpace(username)) return "_unknown";
            var safe = new System.Text.StringBuilder(username.Length);
            foreach (var c in username)
            {
                if (char.IsLetterOrDigit(c) || c == '_' || c == '-') safe.Append(c);
                else safe.Append('_');
            }
            return safe.ToString();
        }

        /// <summary>
        /// 用于诊断：在控制台打印当前数据目录。
        /// </summary>
        public static string Describe()
        {
            return $"DataRoot: {DataRoot}\n" +
                   $"UsersFile: {UsersFile}\n" +
                   $"SessionFile: {SessionFile}\n" +
                   $"AuditLogFile: {AuditLogFile}\n" +
                   $"AssetsRoot: {AssetsRoot}";
        }
    }
}
