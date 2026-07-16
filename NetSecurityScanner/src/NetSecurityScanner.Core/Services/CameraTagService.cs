using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.Json;
using NetSecurityScanner.Models;

namespace NetSecurityScanner.Core
{
  /// <summary>
  /// 摄像头标签管理服务（v4-T2）。持久化到 %LOCALAPPDATA%\NetSecurityScanner\data\camera_tags.json
  /// </summary>
  public class CameraTagService
  {
    private const string FileName = "camera_tags.json";
    private readonly object _lock = new();

    private class TagDataFile
    {
      public List<CameraTag> Tags { get; set; } = new();
      public List<CameraTagAssignment> Assignments { get; set; } = new();
    }

    private static string GetDataDir()
    {
      var dir = Path.Combine(
          Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
          "NetSecurityScanner", "data");
      Directory.CreateDirectory(dir);
      return dir;
    }

    private static string GetFilePath() => Path.Combine(GetDataDir(), FileName);

    private TagDataFile Load()
    {
      try
      {
        var file = GetFilePath();
        if (!File.Exists(file)) return new TagDataFile();
        var json = File.ReadAllText(file);
        return JsonSerializer.Deserialize<TagDataFile>(json) ?? new TagDataFile();
      }
      catch
      {
        return new TagDataFile();
      }
    }

    private void Save(TagDataFile data)
    {
      try
      {
        var file = GetFilePath();
        var json = JsonSerializer.Serialize(data, new JsonSerializerOptions { WriteIndented = true });
        File.WriteAllText(file, json);
      }
      catch
      {
        // 静默失败，不影响功能
      }
    }

    public List<CameraTag> GetAll()
    {
      lock (_lock)
      {
        return Load().Tags.OrderBy(t => t.Name).ToList();
      }
    }

    public void Add(CameraTag tag)
    {
      if (tag == null) return;
      if (string.IsNullOrWhiteSpace(tag.TagId)) tag.TagId = Guid.NewGuid().ToString();
      if (tag.CreatedTime == default) tag.CreatedTime = DateTime.Now;
      if (string.IsNullOrWhiteSpace(tag.Color)) tag.Color = "#3498DB";

      lock (_lock)
      {
        var data = Load();
        data.Tags.Add(tag);
        Save(data);
      }
    }

    public void Update(CameraTag tag)
    {
      if (tag == null || string.IsNullOrWhiteSpace(tag.TagId)) return;
      lock (_lock)
      {
        var data = Load();
        var idx = data.Tags.FindIndex(t => t.TagId == tag.TagId);
        if (idx >= 0)
        {
          data.Tags[idx] = tag;
          Save(data);
        }
      }
    }

    public void Remove(string tagId)
    {
      if (string.IsNullOrWhiteSpace(tagId)) return;
      lock (_lock)
      {
        var data = Load();
        data.Tags.RemoveAll(t => t.TagId == tagId);
        data.Assignments.RemoveAll(a => a.TagId == tagId);
        Save(data);
      }
    }

    public List<string> GetTagsForIp(string ip)
    {
      if (string.IsNullOrWhiteSpace(ip)) return new List<string>();
      lock (_lock)
      {
        var data = Load();
        return data.Assignments
            .Where(a => a.Ip == ip)
            .Select(a => a.TagId)
            .ToList();
      }
    }

    public IReadOnlyList<string> GetIpsForTag(string tagId)
    {
      if (string.IsNullOrWhiteSpace(tagId)) return Array.Empty<string>();
      lock (_lock)
      {
        var data = Load();
        return data.Assignments
            .Where(a => a.TagId == tagId)
            .Select(a => a.Ip)
            .Distinct()
            .ToList();
      }
    }

    public void Assign(string ip, string tagId)
    {
      if (string.IsNullOrWhiteSpace(ip) || string.IsNullOrWhiteSpace(tagId)) return;
      lock (_lock)
      {
        var data = Load();
        // 同一对 (ip, tag) 只允许一条
        if (data.Assignments.Any(a => a.Ip == ip && a.TagId == tagId)) return;
        data.Assignments.Add(new CameraTagAssignment { Ip = ip, TagId = tagId });
        Save(data);
      }
    }

    public void Unassign(string ip, string tagId)
    {
      if (string.IsNullOrWhiteSpace(ip) || string.IsNullOrWhiteSpace(tagId)) return;
      lock (_lock)
      {
        var data = Load();
        data.Assignments.RemoveAll(a => a.Ip == ip && a.TagId == tagId);
        Save(data);
      }
    }

    /// <summary>
    /// 按标签过滤 IP 列表。tagId 为 null/空 时返回原列表。
    /// </summary>
    public List<string> FilterIps(IEnumerable<string> ips, string tagId)
    {
      if (string.IsNullOrWhiteSpace(tagId))
        return ips?.ToList() ?? new List<string>();

      var assigned = new HashSet<string>(GetIpsForTag(tagId));
      return (ips ?? Enumerable.Empty<string>())
          .Where(ip => assigned.Contains(ip))
          .ToList();
    }

    /// <summary>
    /// 暴露底层 JSON 路径，方便高级用户手工备份/恢复。
    /// </summary>
    public string DataFilePath => GetFilePath();
  }
}
