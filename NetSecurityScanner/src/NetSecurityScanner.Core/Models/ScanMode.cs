namespace NetSecurityScanner.Models
{
    public enum ScanMode
    {
        Lightning,  // 闪电扫描 <30秒
        Standard,   // 标准扫描 5-15分钟
        Deep,       // 深度扫描 30-60分钟
        Targeted,   // 定向扫描 自定义
        Full        // 全量扫描 APP专用
    }

    public enum TargetType
    {
        Single,     // 单个IP/域名
        Range,      // IP段 192.168.1.1-192.168.1.254
        CIDR,       // CIDR格式 192.168.1.0/24
        ListFile    // 文件列表
    }
}
