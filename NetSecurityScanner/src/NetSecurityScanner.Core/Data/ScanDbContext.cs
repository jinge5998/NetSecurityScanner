using Microsoft.EntityFrameworkCore;
using NetSecurityScanner.Models;

namespace NetSecurityScanner.Data
{
    public class ScanDbContext : DbContext
    {
        public DbSet<ScanHistory> ScanHistories { get; set; }
        public DbSet<VulnerabilityRecord> VulnerabilityRecords { get; set; }

        protected override void OnConfiguring(DbContextOptionsBuilder options)
        {
            var dbPath = System.IO.Path.Combine(
                System.AppDomain.CurrentDomain.BaseDirectory,
                "Data",
                "ScanHistory.db"
            );
            options.UseSqlite($"Data Source={dbPath}");
        }

        protected override void OnModelCreating(ModelBuilder modelBuilder)
        {
            modelBuilder.Entity<ScanHistory>()
                .HasMany(s => s.Vulnerabilities)
                .WithOne(v => v.ScanHistory)
                .HasForeignKey(v => v.ScanId);
        }
    }
}
