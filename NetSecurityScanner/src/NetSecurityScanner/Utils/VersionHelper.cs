using System.Reflection;

namespace NetSecurityScanner.Utils
{
    public static class VersionHelper
    {
        private static string? _cachedVersion;

        public static string GetVersion()
        {
            if (_cachedVersion != null) return _cachedVersion;

            var assembly = Assembly.GetExecutingAssembly();
            var version = assembly.GetName().Version;
            _cachedVersion = version != null
                ? $"{version.Major}.{version.Minor}.{version.Build}"
                : "1.0.0";

            return _cachedVersion;
        }

        public static string GetFullVersion()
        {
            var assembly = Assembly.GetExecutingAssembly();
            var version = assembly.GetName().Version;
            return version != null
                ? $"{version.Major}.{version.Minor}.{version.Build}.{version.Revision}"
                : "1.0.0.0";
        }

        public static string GetProductName()
        {
            return "NetSecurityScanner";
        }
    }
}
