using System;
using System.Collections.Generic;
using System.Linq;
using NetSecurityScanner.Core.Models;

namespace NetSecurityScanner.Core.Services
{
    public static class NmapTemplateRegistry
    {
        private static readonly Dictionary<string, NmapTemplate> _templates = new();
        private static readonly object _lock = new();

        public static IReadOnlyList<NmapTemplate> All
        {
            get
            {
                lock (_lock)
                {
                    return _templates.Values
                        .OrderBy(t => t.Category)
                        .ThenBy(t => t.Name)
                        .ToList();
                }
            }
        }

        public static void Register(NmapTemplate template)
        {
            if (template == null || string.IsNullOrEmpty(template.Id)) return;
            lock (_lock) _templates[template.Id] = template;
        }

        public static NmapTemplate? Get(string id)
        {
            lock (_lock) return _templates.TryGetValue(id, out var t) ? t : null;
        }

        public static void Clear() { lock (_lock) _templates.Clear(); }
    }
}
