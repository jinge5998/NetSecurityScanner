using System;
using System.IO;
using System.Reflection.Metadata;
using System.Reflection.PortableExecutable;

string pdbPath = @"d:\360安全浏览器下载\软件开发备份\网络安全漏洞扫描\NetSecurityScanner\src\NetSecurityScanner.Desktop\bin\Debug\net6.0-windows\NetSecurityScanner.Desktop.pdb";

using var stream = File.OpenRead(pdbPath);
using var reader = new MetadataReaderProvider(stream).GetMetadataReader();

Console.WriteLine("=== Source files in PDB ===");
int count = 0;
foreach (var docHandle in reader.Documents)
{
    var doc = reader.GetDocument(docHandle);
    var name = reader.GetString(doc.Name);
    Console.WriteLine(name);
    count++;
    if (count >= 10) break;
}
Console.WriteLine($"... total {reader.Documents.Count} documents");