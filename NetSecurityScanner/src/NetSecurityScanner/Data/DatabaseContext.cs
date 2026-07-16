using System.Data.Entity;
using NetSecurityScanner.Models;

namespace NetSecurityScanner.Data
{
    public class DatabaseContext : DbContext
    {
        public DatabaseContext() : base("NetSecurityScannerDb")
        {
            // 初始化数据库
            Database.SetInitializer(new DatabaseInitializer());
        }
        
        public DbSet<ScanTask> ScanTasks { get; set; }
        public DbSet<Vulnerability> Vulnerabilities { get; set; }
        public DbSet<ScanResult> ScanResults { get; set; }
        
        protected override void OnModelCreating(DbModelBuilder modelBuilder)
        {
            // 配置实体映射
            modelBuilder.Entity<ScanTask>()
                .HasKey(t => t.TaskId);
            
            modelBuilder.Entity<Vulnerability>()
                .HasKey(v => v.VulnerabilityId);
            
            modelBuilder.Entity<ScanResult>()
                .HasKey(r => r.ResultId)
                .HasOptional(r => r.Vulnerability)
                .WithMany()
                .HasForeignKey(r => r.VulnerabilityId);
        }
    }
    
    public class DatabaseInitializer : DropCreateDatabaseIfModelChanges<DatabaseContext>
    {
        protected override void Seed(DatabaseContext context)
        {
            // 初始化种子数据
            base.Seed(context);
        }
    }
}