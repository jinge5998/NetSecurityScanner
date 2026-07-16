using Microsoft.EntityFrameworkCore;
using NetSecurityScanner.Data;
using NetSecurityScanner.Models;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.Json;
using System.Threading.Tasks;

namespace NetSecurityScanner.Services
{
    public class ScanHistoryService
    {
        private readonly ScanDbContext _dbContext;

        public ScanHistoryService()
        {
            _dbContext = new ScanDbContext();
            _dbContext.Database.EnsureCreated();
        }

        public async Task SaveScanResultAsync(string target, List<VulnerabilityResult> vulnerabilities, ScanConfiguration config)
        {
            var history = new ScanHistory
            {
                ScanId = Guid.NewGuid().ToString(),
                StartTime = DateTime.Now,
                EndTime = DateTime.Now,
                Duration = TimeSpan.FromMinutes(5),
                ScanMode = config.Mode.ToString(),
                Target = target,
                TotalPorts = 1000,
                OpenPorts = vulnerabilities.Select(v => v.Port).Distinct().Count(),
                TotalVulnerabilities = vulnerabilities?.Count ?? 0,
                CriticalCount = vulnerabilities?.Count(v => v.RiskLevel == "严重") ?? 0,
                HighCount = vulnerabilities?.Count(v => v.RiskLevel == "高危") ?? 0,
                MediumCount = vulnerabilities?.Count(v => v.RiskLevel == "中危") ?? 0,
                LowCount = vulnerabilities?.Count(v => v.RiskLevel == "低危") ?? 0,
                InfoCount = vulnerabilities?.Count(v => v.RiskLevel == "信息") ?? 0,
                ScanStatus = "已完成",
                ScanConfiguration = JsonSerializer.Serialize(config),
                Vulnerabilities = vulnerabilities?.Select(v => new VulnerabilityRecord
                {
                    CveId = v.CveId,
                    Name = v.Name,
                    Description = v.Description,
                    RiskLevel = v.RiskLevel,
                    Target = target,
                    Port = v.Port,
                    Service = v.Service,
                    ServiceVersion = v.ServiceVersion,
                    DetectionMethod = v.DetectionMethod,
                    Solution = v.Solution,
                    References = v.References
                }).ToList() ?? new List<VulnerabilityRecord>()
            };

            _dbContext.ScanHistories.Add(history);
            await _dbContext.SaveChangesAsync();
        }

        public async Task<List<ScanHistory>> GetScanHistoryAsync(
            string target = null,
            DateTime? startDate = null,
            DateTime? endDate = null,
            string scanMode = null)
        {
            var query = _dbContext.ScanHistories.AsQueryable();

            if (!string.IsNullOrEmpty(target))
                query = query.Where(h => h.Target.Contains(target));

            if (startDate.HasValue)
                query = query.Where(h => h.StartTime >= startDate.Value);

            if (endDate.HasValue)
                query = query.Where(h => h.StartTime <= endDate.Value);

            if (!string.IsNullOrEmpty(scanMode))
                query = query.Where(h => h.ScanMode == scanMode);

            return await query
                .OrderByDescending(h => h.StartTime)
                .Include(h => h.Vulnerabilities)
                .ToListAsync();
        }

        public async Task<ScanHistory> GetScanByIdAsync(string scanId)
        {
            return await _dbContext.ScanHistories
                .Include(h => h.Vulnerabilities)
                .FirstOrDefaultAsync(h => h.ScanId == scanId);
        }

        public async Task DeleteScanAsync(string scanId)
        {
            var scan = await _dbContext.ScanHistories.FindAsync(scanId);
            if (scan != null)
            {
                _dbContext.ScanHistories.Remove(scan);
                await _dbContext.SaveChangesAsync();
            }
        }

        public async Task DeleteScanHistoryAsync(string scanId)
        {
            var history = await _dbContext.ScanHistories
                .FirstOrDefaultAsync(h => h.ScanId == scanId);

            if (history != null)
            {
                _dbContext.ScanHistories.Remove(history);
                await _dbContext.SaveChangesAsync();
            }
        }
    }
}
