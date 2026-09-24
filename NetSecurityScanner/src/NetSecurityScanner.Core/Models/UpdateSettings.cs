using System;

namespace NetSecurityScanner.Models
{
    public class UpdateSettings
    {
        public string GitHubOwner { get; set; } = "jinge5998";

        public string GitHubRepo { get; set; } = "NetSecurityScanner";

        public bool CheckOnStartup { get; set; } = true;

        public DateTime? LastCheckTime { get; set; }

        public string SkippedVersion { get; set; } = string.Empty;

        public int NotifyIntervalHours { get; set; } = 24;

        public bool AutoUpdateEnabled { get; set; } = true;

        public bool AutoUpdateDataFiles { get; set; } = true;

        public string UpdateChannel { get; set; } = "release";
    }
}