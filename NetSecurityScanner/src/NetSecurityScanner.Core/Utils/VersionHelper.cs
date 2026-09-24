using System;
using System.Reflection;

namespace NetSecurityScanner.Utils
{
    /// <summary>
    /// 应用程序版本帮助类
    /// </summary>
    public static class VersionHelper
    {
        /// <summary>
        /// 获取当前程序集的版本号
        /// </summary>
        /// <returns>版本号字符串，格式为 Major.Minor.Build.Revision</returns>
        public static string GetVersion()
        {
            var assembly = Assembly.GetEntryAssembly() ?? Assembly.GetExecutingAssembly();
            var version = assembly.GetName().Version;
            return version != null ? $"{version.Major}.{version.Minor}.{version.Build}.{version.Revision}" : "1.0.2.1";
        }
    }
}