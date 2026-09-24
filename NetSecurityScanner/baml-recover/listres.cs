using System;
using System.IO;
using System.Reflection;
using System.Text;
using System.Resources;
using System.Collections;

class Program {
    static int Main(string[] args) {
        var asm = Assembly.LoadFrom(args[0]);
        // 查找 BAML 资源
        foreach (var name in asm.GetManifestResourceNames()) {
            Console.WriteLine("Resource: " + name);
        }
        return 0;
    }
}
