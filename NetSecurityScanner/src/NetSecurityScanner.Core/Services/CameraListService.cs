using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.Json;
using NetSecurityScanner.Models;

namespace NetSecurityScanner.Core
{
  /// <summary>
  /// 摄像头 IP 白/黑名单服务（v3-T5）。
  /// 持久化：<c>%LOCALAPPDATA%\NetSecurityScanner\data\camera_lists.json</c>
  /// </summary>
  public class CameraListService
  {
    private readonly string ListFile = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
        "NetSecurityScanner", "data", "camera_lists.json");

    private CameraIpList _data = CameraIpList.Empty;

    public CameraListService()
    {
      _data = Load();
    }

    public IReadOnlyList<string> WhiteList => _data.WhiteList;
    public IReadOnlyList<string> BlackList => _data.BlackList;

    public event EventHandler? Changed;

    public void AddToWhiteList(string ip)
    {
      if (string.IsNullOrWhiteSpace(ip)) return;
      var v = ip.Trim();
      _data.WhiteList.RemoveAll(x => string.Equals(x, v, StringComparison.OrdinalIgnoreCase));
      _data.BlackList.RemoveAll(x => string.Equals(x, v, StringComparison.OrdinalIgnoreCase));
      _data.WhiteList.Add(v);
      Persist();
      Changed?.Invoke(this, EventArgs.Empty);
    }

    public void AddToBlackList(string ip)
    {
      if (string.IsNullOrWhiteSpace(ip)) return;
      var v = ip.Trim();
      _data.BlackList.RemoveAll(x => string.Equals(x, v, StringComparison.OrdinalIgnoreCase));
      _data.WhiteList.RemoveAll(x => string.Equals(x, v, StringComparison.OrdinalIgnoreCase));
      _data.BlackList.Add(v);
      Persist();
      Changed?.Invoke(this, EventArgs.Empty);
    }

    public void Remove(string ip)
    {
      if (string.IsNullOrWhiteSpace(ip)) return;
      var v = ip.Trim();
      _data.WhiteList.RemoveAll(x => string.Equals(x, v, StringComparison.OrdinalIgnoreCase));
      _data.BlackList.RemoveAll(x => string.Equals(x, v, StringComparison.OrdinalIgnoreCase));
      Persist();
      Changed?.Invoke(this, EventArgs.Empty);
    }

    public bool IsWhitelisted(string ip) =>
        !string.IsNullOrWhiteSpace(ip) &&
        _data.WhiteList.Any(x => string.Equals(x, ip.Trim(), StringComparison.OrdinalIgnoreCase));

    public bool IsBlacklisted(string ip) =>
        !string.IsNullOrWhiteSpace(ip) &&
        _data.BlackList.Any(x => string.Equals(x, ip.Trim(), StringComparison.OrdinalIgnoreCase));

    /// <summary>
    /// 给定 IP 集合，返回过滤后的子集（剔除黑名单）。
    /// </summary>
    public List<string> FilterBlackList(IEnumerable<string> ips)
    {
      if (ips == null) return new List<string>();
      return ips.Where(ip => !IsBlacklisted(ip)).ToList();
    }

    /// <summary>
    /// 同步加载的白名单提供给告警服务使用。
    /// </summary>
    public void ApplyWhitelistTo(CameraAlertService alertService)
    {
      if (alertService == null) return;
      alertService.SetWhitelist(_data.WhiteList);
    }

    private void Persist()
    {
      try
      {
        Directory.CreateDirectory(Path.GetDirectoryName(ListFile)!);
        var json = JsonSerializer.Serialize(_data, new JsonSerializerOptions { WriteIndented = true });
        File.WriteAllText(ListFile, json);
      }
      catch { }
    }

    private CameraIpList Load()
    {
      try
      {
        if (!File.Exists(ListFile)) return CameraIpList.Empty;
        var json = File.ReadAllText(ListFile);
        return JsonSerializer.Deserialize<CameraIpList>(json) ?? CameraIpList.Empty;
      }
      catch
      {
        return CameraIpList.Empty;
      }
    }
  }
}
