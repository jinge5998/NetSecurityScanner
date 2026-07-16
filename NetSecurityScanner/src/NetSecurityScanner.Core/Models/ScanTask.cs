using System;
using System.Collections.Generic;

namespace NetSecurityScanner.Models
{
    public class ScanTask
    {
        public int TaskId { get; set; }
        public string TaskName { get; set; } = string.Empty;
        public string TargetHosts { get; set; } = string.Empty;
        public string ScanType { get; set; } = string.Empty;
        public string Status { get; set; } = string.Empty;
        public DateTime? StartTime { get; set; }
        public DateTime? EndTime { get; set; }
        public string CreatedBy { get; set; } = string.Empty;
        public string Options { get; set; } = string.Empty;
        
        // 非数据库字段，用于UI显示
        public string Duration { get; set; } = string.Empty;
    }
}