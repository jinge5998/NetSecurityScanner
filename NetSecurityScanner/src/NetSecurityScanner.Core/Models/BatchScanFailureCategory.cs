namespace NetSecurityScanner.Core.Models
{
    /// <summary>
    /// 批量扫描单目标失败/异常原因分类。
    /// </summary>
    public enum BatchScanFailureCategory
    {
        None,
        Timeout,
        ConnectionRefused,
        Unreachable,
        DnsFailure,
        NoOpenPort,
        ScanException,
        Canceled
    }
}
