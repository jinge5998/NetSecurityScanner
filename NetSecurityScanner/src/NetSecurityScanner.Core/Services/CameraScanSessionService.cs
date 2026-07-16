using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.Json;
using System.Threading.Tasks;
using NetSecurityScanner.Models;

namespace NetSecurityScanner.Core
{
  /// <summary>
  /// 摄像头扫描会话服务（v2）
  /// </summary>
  public class CameraScanSessionService
  {
    private static readonly string SessionDir = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
        "NetSecurityScanner", "data", "camera_sessions");

    public async Task<string> SaveSessionAsync(CameraScanSession session)
    {
      try
      {
        Directory.CreateDirectory(SessionDir);
        var file = Path.Combine(SessionDir, $"{session.SessionId}.json");
        var json = JsonSerializer.Serialize(session, new JsonSerializerOptions { WriteIndented = true });
        await File.WriteAllTextAsync(file, json);
        return file;
      }
      catch
      {
        return string.Empty;
      }
    }

    public async Task<CameraScanSession?> LoadSessionAsync(string sessionId)
    {
      try
      {
        var file = Path.Combine(SessionDir, $"{sessionId}.json");
        if (!File.Exists(file)) return null;
        var json = await File.ReadAllTextAsync(file);
        return JsonSerializer.Deserialize<CameraScanSession>(json);
      }
      catch
      {
        return null;
      }
    }

    public List<CameraScanSession> ListSessions(int max = 50)
    {
      try
      {
        if (!Directory.Exists(SessionDir)) return new List<CameraScanSession>();
        return Directory.GetFiles(SessionDir, "*.json")
            .OrderByDescending(File.GetLastWriteTime)
            .Take(max)
            .Select(f =>
            {
              try
              {
                return JsonSerializer.Deserialize<CameraScanSession>(File.ReadAllText(f));
              }
              catch { return null; }
            })
            .Where(s => s != null)
            .Cast<CameraScanSession>()
            .ToList();
      }
      catch
      {
        return new List<CameraScanSession>();
      }
    }

    public bool DeleteSession(string sessionId)
    {
      try
      {
        var file = Path.Combine(SessionDir, $"{sessionId}.json");
        if (File.Exists(file))
        {
          File.Delete(file);
          return true;
        }
      }
      catch { }
      return false;
    }
  }
}
