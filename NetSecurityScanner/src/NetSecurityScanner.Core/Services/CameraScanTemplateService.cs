using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.Json;
using NetSecurityScanner.Models;

namespace NetSecurityScanner.Core
{
  /// <summary>
  /// 摄像头扫描模板服务（v2 + v3 导入导出）
  /// </summary>
  public class CameraScanTemplateService
  {
    private readonly List<CameraScanTemplate> _templates;

    public CameraScanTemplateService()
    {
      _templates = CameraScanTemplate.GetDefaultTemplates();
    }

    public IReadOnlyList<CameraScanTemplate> Templates => _templates;

    public CameraScanTemplate? GetById(string id) =>
        _templates.FirstOrDefault(t => t.Id == id);

    public void ApplyTemplate(CameraScanOptions options, string templateId)
    {
      var t = GetById(templateId);
      if (t == null) return;
      options.CustomPorts = new List<int>(t.Ports);
    }

    /// <summary>
    /// v3-T6: 导出指定 id 的模板为 JSON 文件。
    /// </summary>
    public void Export(string id, string filePath)
    {
      if (string.IsNullOrWhiteSpace(id))
        throw new ArgumentException("模板 id 不能为空", nameof(id));
      if (string.IsNullOrWhiteSpace(filePath))
        throw new ArgumentException("导出路径不能为空", nameof(filePath));

      var t = GetById(id);
      if (t == null) throw new InvalidOperationException($"未找到 id={id} 的模板");

      var dir = Path.GetDirectoryName(filePath);
      if (!string.IsNullOrEmpty(dir)) Directory.CreateDirectory(dir);
      var json = JsonSerializer.Serialize(t, new JsonSerializerOptions { WriteIndented = true });
      File.WriteAllText(filePath, json);
    }

    /// <summary>
    /// v3-T6: 从 JSON 文件导入模板，返回新的模板实例并自动加入列表。
    /// </summary>
    public CameraScanTemplate Import(string filePath)
    {
      if (string.IsNullOrWhiteSpace(filePath))
        throw new ArgumentException("文件路径不能为空", nameof(filePath));
      if (!File.Exists(filePath))
        throw new FileNotFoundException("模板文件不存在", filePath);

      var json = File.ReadAllText(filePath);
      var t = JsonSerializer.Deserialize<CameraScanTemplate>(json);
      if (t == null) throw new InvalidDataException("模板 JSON 解析失败");
      if (string.IsNullOrWhiteSpace(t.Id))
        t.Id = $"imported_{Guid.NewGuid():N}".Substring(0, 16);

      // 替换已有或追加
      var existing = _templates.FindIndex(x => x.Id == t.Id);
      if (existing >= 0) _templates[existing] = t;
      else _templates.Add(t);
      return t;
    }
  }
}
