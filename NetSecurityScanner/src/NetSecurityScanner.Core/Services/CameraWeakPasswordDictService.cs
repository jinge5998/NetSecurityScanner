using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.Json;

namespace NetSecurityScanner.Core
{
  /// <summary>
  /// 摄像头弱口令字典服务（v4-T4）。
  /// 持久化到 %LOCALAPPDATA%\NetSecurityScanner\data\camera_weak_passwords.json
  /// 内置字典至少 50 个常见摄像头弱口令；用户可追加自定义并禁用内置。
  /// </summary>
  public class CameraWeakPasswordDictService
  {
    /// <summary>内置默认字典（50+ 常用弱口令）</summary>
    public static readonly IReadOnlyList<string> BuiltInPasswords = new List<string>
    {
      // 通用
      "admin", "12345", "123456", "1234", "123", "password", "root", "user", "test", "guest",
      "admin123", "root123", "pass", "qwerty", "abc123", "111111", "000000", "666666", "888888",
      "999999", "12345678", "123456789", "1234567890", "admin1", "1q2w3e4r", "abc",
      // 厂商默认
      "hikvision", "dahua", "default", "system", "manager", "ubnt", "supervisor",
      "hik12345", "hik123456", "dahua123", "tlJwpbo6", "5up", "vizxv", "xc3511",
      "tluafed", "7ujMko0admin", "iVMS-8700", "iVM88", "7ujMko0vizxv", "klv1234",
      "jvc", "Polycom", "tigers", "s2b", "Bcom_admin", "wbox", "20150602", "merlin",
      "fidel123", "1001chin", "netcam", "vstarcam2017", "vstarcam123", "sw2017jl",
      "aptec2009", "pass1234", "mios", "zsun1188", "x5O!d%c#z", "changeme"
    };

    private const string FileName = "camera_weak_passwords.json";
    private readonly object _lock = new();
    private readonly List<string> _custom = new();
    private bool _builtInEnabled = true;

    private class PersistShape
    {
      public List<string> CustomPasswords { get; set; } = new();
      public bool BuiltInEnabled { get; set; } = true;
    }

    public CameraWeakPasswordDictService()
    {
      Load();
    }

    private static string GetFilePath()
    {
      var dir = Path.Combine(
          Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
          "NetSecurityScanner", "data");
      Directory.CreateDirectory(dir);
      return Path.Combine(dir, FileName);
    }

    private void Load()
    {
      try
      {
        var file = GetFilePath();
        if (!File.Exists(file)) return;
        var json = File.ReadAllText(file, Encoding.UTF8);
        var data = JsonSerializer.Deserialize<PersistShape>(json);
        if (data == null) return;
        _custom.Clear();
        _custom.AddRange(data.CustomPasswords ?? new List<string>());
        _builtInEnabled = data.BuiltInEnabled;
      }
      catch
      {
        // 静默失败，使用默认空集合
      }
    }

    private void Save()
    {
      try
      {
        var data = new PersistShape
        {
          CustomPasswords = _custom.Distinct().ToList(),
          BuiltInEnabled = _builtInEnabled
        };
        var json = JsonSerializer.Serialize(data, new JsonSerializerOptions { WriteIndented = true });
        File.WriteAllText(GetFilePath(), json, new UTF8Encoding(false));
      }
      catch
      {
        // 静默
      }
    }

    /// <summary>是否启用内置字典</summary>
    public bool BuiltInEnabled
    {
      get { lock (_lock) return _builtInEnabled; }
      set { lock (_lock) { _builtInEnabled = value; Save(); } }
    }

    /// <summary>当前自定义口令数</summary>
    public int CustomCount { get { lock (_lock) return _custom.Count; } }

    /// <summary>内置字典条目数（始终为正，不受 BuiltInEnabled 影响）</summary>
    public int BuiltInCount => BuiltInPasswords.Count;

    /// <summary>合并后总条目数</summary>
    public int Count
    {
      get
      {
        lock (_lock)
        {
          var seen = new HashSet<string>(StringComparer.Ordinal);
          if (_builtInEnabled)
          {
            foreach (var p in BuiltInPasswords) seen.Add(p);
          }
          foreach (var p in _custom) seen.Add(p);
          return seen.Count;
        }
      }
    }

    /// <summary>获取合并后的全量口令（内置在前，自定义在后，去重）</summary>
    public IReadOnlyList<string> GetAll()
    {
      lock (_lock)
      {
        var result = new List<string>();
        var seen = new HashSet<string>(StringComparer.Ordinal);
        if (_builtInEnabled)
        {
          foreach (var p in BuiltInPasswords)
          {
            if (seen.Add(p)) result.Add(p);
          }
        }
        foreach (var p in _custom)
        {
          if (seen.Add(p)) result.Add(p);
        }
        return result;
      }
    }

    /// <summary>获取当前用户自定义口令（只读）</summary>
    public IReadOnlyList<string> GetCustom() { lock (_lock) return _custom.ToList(); }

    /// <summary>添加一条自定义口令（已存在则忽略）</summary>
    public bool Add(string pwd)
    {
      if (string.IsNullOrWhiteSpace(pwd)) return false;
      var trimmed = pwd.Trim();
      lock (_lock)
      {
        if (_custom.Any(p => string.Equals(p, trimmed, StringComparison.Ordinal))) return false;
        _custom.Add(trimmed);
        Save();
        return true;
      }
    }

    /// <summary>移除一条自定义口令</summary>
    public bool Remove(string pwd)
    {
      if (string.IsNullOrWhiteSpace(pwd)) return false;
      lock (_lock)
      {
        var removed = _custom.RemoveAll(p => string.Equals(p, pwd, StringComparison.Ordinal)) > 0;
        if (removed) Save();
        return removed;
      }
    }

    /// <summary>清空所有自定义口令（不影响内置字典）</summary>
    public void Clear()
    {
      lock (_lock)
      {
        if (_custom.Count == 0) return;
        _custom.Clear();
        Save();
      }
    }

    /// <summary>从 txt 导入（每行一条），返回新增条数</summary>
    public int ImportTxt(string filePath)
    {
      if (string.IsNullOrWhiteSpace(filePath) || !File.Exists(filePath)) return 0;
      int added = 0;
      try
      {
        var lines = File.ReadAllLines(filePath, Encoding.UTF8);
        lock (_lock)
        {
          foreach (var raw in lines)
          {
            if (string.IsNullOrWhiteSpace(raw)) continue;
            var p = raw.Trim();
            // 兼容 # 开头的注释
            if (p.StartsWith("#") || p.StartsWith("//")) continue;
            if (_custom.Any(x => string.Equals(x, p, StringComparison.Ordinal))) continue;
            _custom.Add(p);
            added++;
          }
          if (added > 0) Save();
        }
      }
      catch
      {
        // 静默
      }
      return added;
    }

    /// <summary>导出当前合并后的全量口令到 txt（每行一条），返回写入条数</summary>
    public int ExportTxt(string filePath)
    {
      if (string.IsNullOrWhiteSpace(filePath)) return 0;
      try
      {
        var list = GetAll();
        var sb = new StringBuilder();
        sb.AppendLine("# 摄像头弱口令字典");
        sb.AppendLine($"# 导出时间: {DateTime.Now:yyyy-MM-dd HH:mm:ss}");
        sb.AppendLine($"# 总条数: {list.Count}");
        foreach (var p in list) sb.AppendLine(p);
        File.WriteAllText(filePath, sb.ToString(), new UTF8Encoding(false));
        return list.Count;
      }
      catch
      {
        return 0;
      }
    }

    /// <summary>底层数据文件路径（手工备份用）</summary>
    public string DataFilePath => GetFilePath();
  }
}
