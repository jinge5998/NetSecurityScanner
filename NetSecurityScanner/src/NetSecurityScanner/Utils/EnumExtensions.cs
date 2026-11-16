namespace NetSecurityScanner.Utils
{
    public static class EnumExtensions
    {
        public static string ToDisplayString(this Models.ScanMode mode)
        {
            return mode switch
            {
                Models.ScanMode.Lightning => "闪电扫描",
                Models.ScanMode.Standard => "标准扫描",
                Models.ScanMode.Deep => "深度扫描",
                Models.ScanMode.Targeted => "定向扫描",
                _ => "未知"
            };
        }
    }
}
