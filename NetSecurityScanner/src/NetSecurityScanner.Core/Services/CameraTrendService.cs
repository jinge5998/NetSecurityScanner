using System;
using System.Collections.Generic;
using System.Data;
using System.IO;
using System.Linq;
using Microsoft.Data.Sqlite;
using NetSecurityScanner.Models;

namespace NetSecurityScanner.Core
{
  /// <summary>
  /// 摄像头扫描历史趋势服务（v4-T5）。
  /// 读取 %LOCALAPPDATA%\NetSecurityScanner\data\camera_scan_history.db（SQLite）。
  /// 数据库表结构由服务自行 EnsureCreated：
  ///   ScanSummary(ScanId TEXT, ScanTime TEXT, Total INTEGER, Online INTEGER, VulnTotal INTEGER, HighVuln INTEGER)
  /// </summary>
  public class CameraTrendService
  {
    private const string FileName = "camera_scan_history.db";
    private const string TableName = "ScanSummary";

    private static string GetDbPath()
    {
      var dir = Path.Combine(
          Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
          "NetSecurityScanner", "data");
      Directory.CreateDirectory(dir);
      return Path.Combine(dir, FileName);
    }

    /// <summary>底层 DB 文件路径，便于诊断</summary>
    public string DbPath => GetDbPath();

    private void EnsureSchema()
    {
      try
      {
        using var conn = new SqliteConnection($"Data Source={GetDbPath()}");
        conn.Open();
        var ddl = $@"CREATE TABLE IF NOT EXISTS {TableName} (
              ScanId TEXT PRIMARY KEY,
              ScanTime TEXT NOT NULL,
              Total INTEGER NOT NULL DEFAULT 0,
              Online INTEGER NOT NULL DEFAULT 0,
              VulnTotal INTEGER NOT NULL DEFAULT 0,
              HighVuln INTEGER NOT NULL DEFAULT 0
            );";
        using var cmd = conn.CreateCommand();
        cmd.CommandText = ddl;
        cmd.ExecuteNonQuery();
      }
      catch
      {
        // 静默
      }
    }

    /// <summary>
    /// 写入一条扫描汇总（v4-T5 配套 API，供 CameraScannerService 在扫描完成后调用）。
    /// </summary>
    public void RecordSummary(string scanId, DateTime scanTime, int total, int online, int vulnTotal, int highVuln)
    {
      try
      {
        EnsureSchema();
        using var conn = new SqliteConnection($"Data Source={GetDbPath()}");
        conn.Open();
        using var cmd = conn.CreateCommand();
        cmd.CommandText = $@"INSERT OR REPLACE INTO {TableName} (ScanId, ScanTime, Total, Online, VulnTotal, HighVuln)
                              VALUES ($id, $t, $total, $online, $vt, $hv)";
        cmd.Parameters.AddWithValue("$id", scanId ?? Guid.NewGuid().ToString());
        cmd.Parameters.AddWithValue("$t", scanTime.ToString("yyyy-MM-dd HH:mm:ss"));
        cmd.Parameters.AddWithValue("$total", total);
        cmd.Parameters.AddWithValue("$online", online);
        cmd.Parameters.AddWithValue("$vt", vulnTotal);
        cmd.Parameters.AddWithValue("$hv", highVuln);
        cmd.ExecuteNonQuery();
      }
      catch
      {
        // 静默
      }
    }

    /// <summary>
    /// 读取最近 days 天的趋势数据，按日期升序返回。
    /// 数据库文件不存在或为空时返回空列表。
    /// </summary>
    public List<CameraTrendPoint> GetTrend(int days = 30)
    {
      var result = new List<CameraTrendPoint>();
      if (days <= 0) days = 30;

      var path = GetDbPath();
      if (!File.Exists(path)) return result;

      try
      {
        EnsureSchema();
        using var conn = new SqliteConnection($"Data Source={path}");
        conn.Open();
        using var cmd = conn.CreateCommand();
        cmd.CommandText = $@"SELECT ScanTime, Total, Online, VulnTotal, HighVuln
                              FROM {TableName}
                              WHERE ScanTime >= $since
                              ORDER BY ScanTime ASC";
        var since = DateTime.Now.AddDays(-days).ToString("yyyy-MM-dd 00:00:00");
        cmd.Parameters.AddWithValue("$since", since);

        using var reader = cmd.ExecuteReader();
        // 按日期分组聚合（多次扫描合并到一天）
        var byDate = new SortedDictionary<DateTime, CameraTrendPoint>();
        while (reader.Read())
        {
          if (!DateTime.TryParse(reader.GetString(0), out var t)) continue;
          var total = reader.GetInt32(1);
          var online = reader.GetInt32(2);
          var vt = reader.GetInt32(3);
          var hv = reader.GetInt32(4);
          var date = t.Date;
          if (!byDate.TryGetValue(date, out var pt))
          {
            pt = new CameraTrendPoint { Date = date };
            byDate[date] = pt;
          }
          // 取当天最后一条记录作为当日代表
          pt.Total = total;
          pt.Online = online;
          pt.VulnTotal = vt;
          pt.HighVuln = hv;
          pt.Offline = Math.Max(0, total - online);
        }
        result = byDate.Values.ToList();
      }
      catch
      {
        // 静默：返回当前已聚合的结果
      }
      return result;
    }

    /// <summary>
    /// 列出最近 N 次扫描会话（用于多会话对比下拉）。返回 ScanId + ScanTime + 摘要。
    /// </summary>
    public List<TrendSessionInfo> ListRecentSessions(int take = 50)
    {
      var list = new List<TrendSessionInfo>();
      var path = GetDbPath();
      if (!File.Exists(path)) return list;

      try
      {
        EnsureSchema();
        using var conn = new SqliteConnection($"Data Source={path}");
        conn.Open();
        using var cmd = conn.CreateCommand();
        cmd.CommandText = $@"SELECT ScanId, ScanTime, Total, Online, VulnTotal, HighVuln
                              FROM {TableName}
                              ORDER BY ScanTime DESC
                              LIMIT $limit";
        cmd.Parameters.AddWithValue("$limit", take);
        using var reader = cmd.ExecuteReader();
        while (reader.Read())
        {
          list.Add(new TrendSessionInfo
          {
            ScanId = reader.GetString(0),
            ScanTime = DateTime.TryParse(reader.GetString(1), out var t) ? t : DateTime.MinValue,
            Total = reader.GetInt32(2),
            Online = reader.GetInt32(3),
            VulnTotal = reader.GetInt32(4),
            HighVuln = reader.GetInt32(5)
          });
        }
      }
      catch
      {
        // 静默
      }
      return list;
    }
  }

  /// <summary>趋势窗口中可选择的一次会话</summary>
  public class TrendSessionInfo
  {
    public string ScanId { get; set; } = string.Empty;
    public DateTime ScanTime { get; set; }
    public int Total { get; set; }
    public int Online { get; set; }
    public int VulnTotal { get; set; }
    public int HighVuln { get; set; }
    public string Display => $"{ScanTime:yyyy-MM-dd HH:mm}  总{Total}/在线{Online}/漏洞{VulnTotal}";
  }
}
