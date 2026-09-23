using System;
using System.Collections.Generic;
using System.IO;
using System.Text.Json;

namespace NetSecurityScanner.Core.Services
{
    public class CustomNmapTemplate
    {
        public string Id { get; set; } = Guid.NewGuid().ToString();
        public string Name { get; set; } = "";
        public string Category { get; set; } = "Custom";
        public string Description { get; set; } = "";
        public string Icon { get; set; } = "💾";
        public DateTime CreatedAt { get; set; } = DateTime.Now;
        public Dictionary<string, object> Config { get; set; } = new();
    }

    public static class CustomNmapTemplateStore
    {
        private static string FilePath => Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "NetSecurityScanner", "nmap_templates.json");

        public static List<CustomNmapTemplate> LoadAll()
        {
            try
            {
                if (!File.Exists(FilePath)) return new List<CustomNmapTemplate>();
                var json = File.ReadAllText(FilePath);
                return JsonSerializer.Deserialize<List<CustomNmapTemplate>>(json) ?? new();
            }
            catch { return new List<CustomNmapTemplate>(); }
        }

        public static bool Save(CustomNmapTemplate template)
        {
            try
            {
                var all = LoadAll();
                all.RemoveAll(t => t.Id == template.Id);
                all.Add(template);
                Directory.CreateDirectory(Path.GetDirectoryName(FilePath)!);
                var json = JsonSerializer.Serialize(all, new JsonSerializerOptions { WriteIndented = true });
                File.WriteAllText(FilePath, json);
                return true;
            }
            catch { return false; }
        }

        public static bool Delete(string id)
        {
            try
            {
                var all = LoadAll();
                var before = all.Count;
                all.RemoveAll(t => t.Id == id);
                if (all.Count == before) return false;
                var json = JsonSerializer.Serialize(all, new JsonSerializerOptions { WriteIndented = true });
                File.WriteAllText(FilePath, json);
                return true;
            }
            catch { return false; }
        }
    }
}
