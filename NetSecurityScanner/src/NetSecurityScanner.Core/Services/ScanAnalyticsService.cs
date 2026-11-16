using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using NetSecurityScanner.Models;

namespace NetSecurityScanner.Services
{
  public enum TimePeriodType
  {
    Daily,
    Weekly,
    Monthly,
    Quarterly,
    Yearly
  }

  public class TimeSeriesDataPoint
  {
    public string Label { get; set; } = string.Empty;
    public DateTime StartDate { get; set; }
    public DateTime EndDate { get; set; }
    public int ScanCount { get; set; }
    public int TotalVulnerabilities { get; set; }
    public int CriticalCount { get; set; }
    public int HighCount { get; set; }
    public int MediumCount { get; set; }
    public int LowCount { get; set; }
    public int OpenPorts { get; set; }
    public int TotalPorts { get; set; }
    public int UniqueTargets { get; set; }
    public double AverageScanDurationMs { get; set; }

    public double RiskIndex
    {
      get
      {
        return CriticalCount * 100 + HighCount * 50 + MediumCount * 20 + LowCount * 5;
      }
    }
  }

  public class PeriodStatisticsSummary
  {
    public TimePeriodType PeriodType { get; set; }
    public string PeriodDisplay { get; set; } = string.Empty;
    public int TotalScans { get; set; }
    public int TotalVulns { get; set; }
    public double AverageVulnsPerScan { get; set; }
    public int CriticalVulns { get; set; }
    public int HighVulns { get; set; }
    public int MediumVulns { get; set; }
    public int LowVulns { get; set; }
    public int TotalOpenPorts { get; set; }
    public int UniqueTargetsScanned { get; set; }
    public double AverageRiskIndex { get; set; }
    public double TrendChangePercent { get; set; }
    public string RiskLevel
    {
      get
      {
        return AverageRiskIndex switch
        {
          >= 500 => "极高风险",
          >= 300 => "高风险",
          >= 150 => "中风险",
          >= 50 => "低风险",
          _ => "安全"
        };
      }
    }
  }

  public class ScanAnalyticsService
  {
    private readonly JsonDatabaseService _databaseService;

    public ScanAnalyticsService()
    {
      _databaseService = new JsonDatabaseService();
    }

    public async Task<List<ScanHistoryItem>> GetAllScanHistoryAsync()
    {
      return await _databaseService.GetScanHistoryAsync();
    }

    public async Task<List<TimeSeriesDataPoint>> GetTimeSeriesDataAsync(TimePeriodType periodType, int periods = 12)
    {
      var history = await GetAllScanHistoryAsync();
      return GenerateTimeSeriesData(history, periodType, periods);
    }

    public List<TimeSeriesDataPoint> GenerateTimeSeriesData(List<ScanHistoryItem> history, TimePeriodType periodType, int periods)
    {
      var result = new List<TimeSeriesDataPoint>();
      DateTime now = DateTime.Now;

      for (int i = periods - 1; i >= 0; i--)
      {
        var (start, end, label) = GetPeriodRange(now, periodType, -i);
        var point = new TimeSeriesDataPoint
        {
          Label = label,
          StartDate = start,
          EndDate = end
        };

        var periodScans = history.Where(h => h.ScanTime >= start && h.ScanTime <= end).ToList();
        PopulateDataPoint(point, periodScans);
        result.Add(point);
      }

      return result;
    }

    public PeriodStatisticsSummary GetPeriodSummary(List<ScanHistoryItem> history, TimePeriodType periodType, int offset = 0)
    {
      var now = DateTime.Now;
      var (start, end, display) = GetPeriodRange(now, periodType, -offset);
      var periodScans = history.Where(h => h.ScanTime >= start && h.ScanTime <= end).ToList();
      var prevStart = start.AddTicks((start - GetPeriodRange(now, periodType, -(offset + 1)).Item2).Ticks);
      var prevScans = history.Where(h => h.ScanTime >= prevStart && h.ScanTime < start).ToList();

      var summary = new PeriodStatisticsSummary
      {
        PeriodType = periodType,
        PeriodDisplay = display,
        TotalScans = periodScans.Count,
        TotalVulns = periodScans.Sum(s => s.VulnerabilitiesCount),
        CriticalVulns = periodScans.Sum(s => CountByRiskLevel(s, "严重风险", "严重")),
        HighVulns = periodScans.Sum(s => CountByRiskLevel(s, "高风险", "高危")),
        MediumVulns = periodScans.Sum(s => CountByRiskLevel(s, "中风险", "中危")),
        LowVulns = periodScans.Sum(s => CountByRiskLevel(s, "低风险", "低危")),
        TotalOpenPorts = periodScans.Sum(s => s.OpenPortsCount),
        UniqueTargetsScanned = periodScans.Select(s => s.TargetIp).Distinct(StringComparer.OrdinalIgnoreCase).Count()
      };

      summary.AverageVulnsPerScan = summary.TotalScans > 0
          ? Math.Round((double)summary.TotalVulns / summary.TotalScans, 2)
          : 0;

      var point = new TimeSeriesDataPoint();
      PopulateDataPoint(point, periodScans);
      summary.AverageRiskIndex = summary.TotalScans > 0
          ? Math.Round(point.RiskIndex / (double)summary.TotalScans, 2)
          : 0;

      var prevPoint = new TimeSeriesDataPoint();
      PopulateDataPoint(prevPoint, prevScans);
      double prevRisk = prevScans.Count > 0 ? prevPoint.RiskIndex / (double)prevScans.Count : 0;
      summary.TrendChangePercent = prevRisk > 0
          ? Math.Round((summary.AverageRiskIndex - prevRisk) / prevRisk * 100, 1)
          : summary.AverageRiskIndex > 0 ? 100 : 0;

      return summary;
    }

    private static int CountByRiskLevel(ScanHistoryItem item, params string[] levels)
    {
      var vulns = item.VulnerabilityResults ?? new List<VulnerabilityResult>();
      var count = vulns.Count(v => levels.Contains(v.RiskLevel));
      if (count == 0 && levels.Length > 0)
      {
        if (levels.Contains("严重") && (item.RiskLevel == "严重风险" || item.RiskLevel == "严重"))
          count = item.VulnerabilitiesCount;
        else if (levels.Contains("高危") && (item.RiskLevel == "高风险" || item.RiskLevel == "高危"))
          count = item.VulnerabilitiesCount;
      }
      return count;
    }

    private static void PopulateDataPoint(TimeSeriesDataPoint point, List<ScanHistoryItem> scans)
    {
      point.ScanCount = scans.Count;
      point.TotalVulnerabilities = scans.Sum(s => s.VulnerabilitiesCount);
      point.OpenPorts = scans.Sum(s => s.OpenPortsCount);
      point.CriticalCount = scans.Sum(s =>
      {
        var vulns = s.VulnerabilityResults ?? new List<VulnerabilityResult>();
        var c = vulns.Count(v => v.RiskLevel == "严重" || v.RiskLevel == "严重风险");
        return c > 0 ? c : (s.RiskLevel == "严重风险" ? s.VulnerabilitiesCount : 0);
      });
      point.HighCount = scans.Sum(s =>
      {
        var vulns = s.VulnerabilityResults ?? new List<VulnerabilityResult>();
        var c = vulns.Count(v => v.RiskLevel == "高危" || v.RiskLevel == "高风险");
        return c > 0 ? c : (s.RiskLevel == "高风险" ? s.VulnerabilitiesCount : 0);
      });
      point.MediumCount = scans.Sum(s =>
      {
        var vulns = s.VulnerabilityResults ?? new List<VulnerabilityResult>();
        var c = vulns.Count(v => v.RiskLevel == "中危" || v.RiskLevel == "中风险");
        return c > 0 ? c : (s.RiskLevel == "中风险" ? s.VulnerabilitiesCount : 0);
      });
      point.LowCount = scans.Sum(s =>
      {
        var vulns = s.VulnerabilityResults ?? new List<VulnerabilityResult>();
        var c = vulns.Count(v => v.RiskLevel == "低危" || v.RiskLevel == "低风险");
        return c > 0 ? c : (s.RiskLevel == "低风险" ? s.VulnerabilitiesCount : 0);
      });
      point.UniqueTargets = scans.Select(s => s.TargetIp).Distinct(StringComparer.OrdinalIgnoreCase).Count();
      point.AverageScanDurationMs = scans.Count > 0 ? scans.Average(s => s.Duration) : 0;
    }

    public static (DateTime Start, DateTime End, string Label) GetPeriodRange(DateTime reference, TimePeriodType type, int offset)
    {
      return type switch
      {
        TimePeriodType.Daily => GetDailyRange(reference, offset),
        TimePeriodType.Weekly => GetWeeklyRange(reference, offset),
        TimePeriodType.Monthly => GetMonthlyRange(reference, offset),
        TimePeriodType.Quarterly => GetQuarterlyRange(reference, offset),
        TimePeriodType.Yearly => GetYearlyRange(reference, offset),
        _ => GetDailyRange(reference, offset)
      };
    }

    private static (DateTime Start, DateTime End, string Label) GetDailyRange(DateTime reference, int offset)
    {
      var date = reference.Date.AddDays(offset);
      return (date, date.AddDays(1).AddTicks(-1), date.ToString("MM-dd"));
    }

    private static (DateTime Start, DateTime End, string Label) GetWeeklyRange(DateTime reference, int offset)
    {
      int diff = (7 + (reference.DayOfWeek - DayOfWeek.Monday)) % 7;
      var weekStart = reference.Date.AddDays(-diff).AddDays(offset * 7);
      var weekEnd = weekStart.AddDays(7).AddTicks(-1);
      return (weekStart, weekEnd, $"{weekStart:MM/dd}-{weekEnd:MM/dd}");
    }

    private static (DateTime Start, DateTime End, string Label) GetMonthlyRange(DateTime reference, int offset)
    {
      var monthStart = new DateTime(reference.Year, reference.Month, 1).AddMonths(offset);
      var monthEnd = monthStart.AddMonths(1).AddTicks(-1);
      return (monthStart, monthEnd, $"{monthStart:yyyy年MM月}");
    }

    private static (DateTime Start, DateTime End, string Label) GetQuarterlyRange(DateTime reference, int offset)
    {
      int quarter = (reference.Month - 1) / 3;
      var quarterStart = new DateTime(reference.Year, quarter * 3 + 1, 1).AddMonths(offset * 3);
      var quarterEnd = quarterStart.AddMonths(3).AddTicks(-1);
      int qNum = (quarterStart.Month - 1) / 3 + 1;
      return (quarterStart, quarterEnd, $"{quarterStart:yyyy}Q{qNum}");
    }

    private static (DateTime Start, DateTime End, string Label) GetYearlyRange(DateTime reference, int offset)
    {
      var year = reference.Year + offset;
      var yearStart = new DateTime(year, 1, 1);
      var yearEnd = yearStart.AddYears(1).AddTicks(-1);
      return (yearStart, yearEnd, $"{year}年");
    }

    public List<PeriodStatisticsSummary> GetAllPeriodSummaries(List<ScanHistoryItem> history)
    {
      return new List<PeriodStatisticsSummary>
            {
                GetPeriodSummary(history, TimePeriodType.Daily, 0),
                GetPeriodSummary(history, TimePeriodType.Weekly, 0),
                GetPeriodSummary(history, TimePeriodType.Monthly, 0),
                GetPeriodSummary(history, TimePeriodType.Quarterly, 0),
                GetPeriodSummary(history, TimePeriodType.Yearly, 0)
            };
    }

    public Dictionary<string, object> GenerateMockDataIfEmpty()
    {
      var random = new Random(42);
      var mockHistory = new List<ScanHistoryItem>();
      var now = DateTime.Now;

      for (int day = 0; day < 365; day++)
      {
        int scansPerDay = random.Next(0, 5);
        for (int s = 0; s < scansPerDay; s++)
        {
          var scanTime = now.Date.AddDays(-day).AddHours(random.Next(8, 22)).AddMinutes(random.Next(0, 60));
          int vulns = random.Next(0, 15);
          int critical = random.Next(0, Math.Min(2, vulns));
          int high = random.Next(0, Math.Min(4, vulns - critical));
          int medium = random.Next(0, Math.Min(6, vulns - critical - high));
          int low = vulns - critical - high - medium;

          string riskLevel = (critical > 0 || high > 2) ? "高风险"
              : (high > 0 || medium > 3) ? "中风险"
              : (medium > 0 || low > 2) ? "低风险" : "无风险";

          mockHistory.Add(new ScanHistoryItem
          {
            ScanId = Guid.NewGuid().ToString(),
            TargetIp = $"192.168.{random.Next(0, 5)}.{random.Next(1, 255)}",
            ScanType = random.Next(0, 3) == 0 ? "综合扫描" : random.Next(0, 2) == 0 ? "端口扫描" : "漏洞扫描",
            ScanTime = scanTime,
            OpenPortsCount = random.Next(0, 30),
            VulnerabilitiesCount = vulns,
            RiskLevel = riskLevel,
            Duration = random.Next(3000, 120000),
            VulnerabilityResults = GenerateMockVulns(critical, high, medium, low)
          });
        }
      }

      return new Dictionary<string, object>
      {
        ["History"] = mockHistory.OrderByDescending(h => h.ScanTime).ToList()
      };
    }

    private static List<VulnerabilityResult> GenerateMockVulns(int critical, int high, int medium, int low)
    {
      var list = new List<VulnerabilityResult>();
      string[] names = { "SQL注入漏洞", "XSS跨站脚本", "弱口令风险", "未授权访问", "信息泄露",
                "缓冲区溢出", "CSRF跨站请求伪造", "SSL/TLS配置不当", "开放不必要端口", "默认配置漏洞" };
      string[] services = { "HTTP", "HTTPS", "SSH", "FTP", "MySQL", "Redis", "RDP", "SMB", "DNS", "Telnet" };

      var r = new Random();
      void Add(string level, int count)
      {
        for (int i = 0; i < count; i++)
        {
          list.Add(new VulnerabilityResult
          {
            Name = names[r.Next(names.Length)],
            RiskLevel = level,
            Service = services[r.Next(services.Length)],
            Description = $"模拟漏洞描述-{r.Next(10000)}"
          });
        }
      }
      Add("严重", critical);
      Add("高危", high);
      Add("中危", medium);
      Add("低危", low);
      return list;
    }
  }
}