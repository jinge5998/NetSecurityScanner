using System;
using System.IO;
using System.Linq;

class Program
{
    static int Main()
    {
        var root = @"D:\360安全浏览器下载\软件开发备份\网络安全漏洞扫描\NetSecurityScanner\src";
        var exclude = new[] { "AuthService.cs", "RegisterResult.cs", "User.cs", "RegisterWindow.xaml.cs" };
        int updated = 0, scanned = 0;
        foreach (var f in Directory.EnumerateFiles(root, "*.cs", SearchOption.AllDirectories))
        {
            scanned++;
            var name = Path.GetFileName(f);
            if (exclude.Contains(name)) continue;
            if (f.Contains("\\bin\\") || f.Contains("\\obj\\")) continue;
            var text = File.ReadAllText(f);
            if (!text.Contains(".RegisterAsync(")) continue;
            var newText = text.Replace(".RegisterAsync(", ".RegisterSimpleAsync(");
            File.WriteAllText(f, newText);
            Console.WriteLine("Updated: " + f);
            updated++;
        }
        Console.WriteLine($"Scanned: {scanned}, Updated: {updated}");
        return 0;
    }
}
