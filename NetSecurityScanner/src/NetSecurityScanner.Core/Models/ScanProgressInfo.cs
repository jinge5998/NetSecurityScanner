using System;

namespace NetSecurityScanner.Models
{
    /// <summary>
    /// 扫描进度信息
    /// </summary>
    public class ScanProgressInfo
    {
        public int CompletedCount { get; set; }
        public int TotalCount { get; set; }
        public int Percentage { get; set; }
        public int CurrentPort { get; set; }
        public PortInfo? PortInfo { get; set; }
        
        /// <summary>
        /// 当前扫描速度（端口/秒）
        /// </summary>
        public double ScanSpeed { get; set; }
        
        /// <summary>
        /// 预计完成时间
        /// </summary>
        public TimeSpan? EstimatedTimeRemaining { get; set; }
        
        /// <summary>
        /// 成功扫描的端口数
        /// </summary>
        public int SuccessfulScans { get; set; }
        
        /// <summary>
        /// 失败扫描的端口数
        /// </summary>
        public int FailedScans { get; set; }
        
        /// <summary>
        /// 开放端口数
        /// </summary>
        public int OpenPorts { get; set; }
        
        /// <summary>
        /// 扫描模式
        /// </summary>
        public string ScanMode { get; set; } = "Normal";
        
        /// <summary>
        /// 当前并发数
        /// </summary>
        public int CurrentConcurrency { get; set; }
        
        /// <summary>
        /// 系统内存使用情况（MB）
        /// </summary>
        public long AvailableMemoryMb { get; set; }
        
        /// <summary>
        /// 批次信息
        /// </summary>
        public string BatchInfo { get; set; } = string.Empty;
        
        /// <summary>
        /// 扫描状态描述
        /// </summary>
        public string StatusDescription { get; set; } = "Scanning";
        
        /// <summary>
        /// 当前批量大小
        /// </summary>
        public int CurrentBatchSize { get; set; }
        
        /// <summary>
        /// 已完成的批次数
        /// </summary>
        public int CompletedBatches { get; set; }
        
        /// <summary>
        /// 总批次数
        /// </summary>
        public int TotalBatches { get; set; }
    }

    /// <summary>
    /// 漏洞扫描选项
    /// </summary>
    public class VulnScanOptions
    {
        public string ScanDepth { get; set; } = "标准";
        public string ScanPolicy { get; set; } = "标准";
        public bool EnablePocVerification { get; set; } = true;
        public bool EnableCveMatching { get; set; } = true;
        public int ScanDelay { get; set; } = 10;  // 减少延迟，提高速度
        public int MaxConcurrency { get; set; } = 200; // 200线程并发
    }

    /// <summary>
    /// 漏洞扫描进度信息
    /// </summary>
    public class VulnScanProgressInfo
    {
        public int CompletedCount { get; set; }
        public int TotalCount { get; set; }
        public int Percentage { get; set; }
        public string CurrentService { get; set; } = string.Empty;
    }
}
