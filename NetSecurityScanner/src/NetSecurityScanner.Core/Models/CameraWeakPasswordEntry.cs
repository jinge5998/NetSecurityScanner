using System.Collections.Generic;

namespace NetSecurityScanner.Core.Models
{
    public class CameraWeakPasswordEntry
    {
        public string Vendor { get; set; } = string.Empty;
        public List<string> Usernames { get; set; } = new();
        public List<string> Passwords { get; set; } = new();
    }
}