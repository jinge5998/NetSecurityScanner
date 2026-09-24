using System;

namespace NetSecurityScanner.Models
{
    public class ScheduledScan
    {
        public string Id { get; set; } = Guid.NewGuid().ToString();
        public string Name { get; set; }
        public string Description { get; set; }

        public string TargetType { get; set; }
        public string TargetValue { get; set; }

        public string ScanMode { get; set; }

        public string ScheduleType { get; set; }
        public string ScheduleTime { get; set; }

        public bool EnableEmailNotification { get; set; }
        public string NotificationEmail { get; set; }

        public bool IsEnabled { get; set; }
        public DateTime? LastRunTime { get; set; }
        public DateTime? NextRunTime { get; set; }
        public int RunCount { get; set; }

        public DateTime CreatedAt { get; set; } = DateTime.Now;
    }
}
