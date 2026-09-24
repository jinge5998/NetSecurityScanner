using System;
using System.Linq;
using System.Reflection;

class Program
{
    static void Main()
    {
        var baseDir = @"d:\360安全浏览器下载\软件开发备份\网络安全漏洞扫描\NetSecurityScanner\src\NetSecurityScanner.Desktop\bin\Release\net6.0-windows\";
        AppDomain.CurrentDomain.AssemblyResolve += (s, e) => {
            var name = new AssemblyName(e.Name).Name + ".dll";
            var path = System.IO.Path.Combine(baseDir, name);
            if (System.IO.File.Exists(path)) return Assembly.LoadFrom(path);
            return null;
        };

        foreach (var dll in new[] { "LiveChartsCore.dll", "LiveChartsCore.SkiaSharpView.dll" })
        {
            var path = System.IO.Path.Combine(baseDir, dll);
            if (!System.IO.File.Exists(path)) { Console.WriteLine($"MISSING: {dll}"); continue; }
            var asm = Assembly.LoadFrom(path);
            Console.WriteLine($"== {dll} ==");
            // 搜索所有包含 Global/TextSettings/Hint/Style 的扩展方法
            foreach (var t in asm.GetTypes())
            {
                foreach (var m in t.GetMethods(BindingFlags.Public | BindingFlags.Static))
                {
                    if (m.Name.Contains("HasGlobal") || m.Name.Contains("TextSettings") || m.Name.Contains("HasTheme") || m.Name.Contains("HasMappers"))
                    {
                        var pars = string.Join(", ", m.GetParameters().Select(p => $"{p.ParameterType.Name} {p.Name}"));
                        Console.WriteLine($"  {t.FullName}.{m.Name}({pars})");
                    }
                }
            }
            // 列出所有 LiveChartsSettings / Theme 类
            foreach (var t in asm.GetTypes().Where(t => t.Name.Contains("Settings") || t.Name.Contains("Theme")))
            {
                Console.WriteLine($"  TYPE: {t.FullName}");
            }
        }
    }
}

