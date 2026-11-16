using System.Configuration;
using System.Data.Entity;
using NetSecurityScanner.Models;

namespace NetSecurityScanner.Data
{
    public class SecurityContext : DbContext
    {
        public SecurityContext() : base("SecurityConnection")
        {
        }

        public DbSet<PortScanResult> PortScanResults { get; set; }
        public DbSet<VulnerabilityResult> VulnerabilityResults { get; set; }
        public DbSet<RiskAssessmentItem> RiskAssessmentItems { get; set; }
        public DbSet<ScanHistory> ScanHistories { get; set; }

        protected override void OnModelCreating(DbModelBuilder modelBuilder)
        {
            // 使用SQLite数据库提供程序
            modelBuilder.Entity<PortScanResult>().ToTable("PortScanResults");
            modelBuilder.Entity<VulnerabilityResult>().ToTable("VulnerabilityResults");
            modelBuilder.Entity<RiskAssessmentItem>().ToTable("RiskAssessmentItems");
            modelBuilder.Entity<ScanHistory>().ToTable("ScanHistories");
        }
    }
}