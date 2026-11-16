using System;
using System.Diagnostics;

var exePath = @"d:\360安全浏览器下载\软件开发备份\网络安全漏洞扫描\NetSecurityScanner\publish-v1.0.1.6\NetSecurityScanner.Desktop.exe";

if (File.Exists(exePath))
{
  Console.WriteLine("[√] 找到文件: " + exePath);
  var psi = new ProcessStartInfo(exePath)
  {
    WorkingDirectory = Path.GetDirectoryName(exePath),
    UseShellExecute = true
  };
  var proc = Process.Start(psi);
  Console.WriteLine("[√] 程序已启动，进程ID: " + proc?.Id);
}
else
{
  Console.WriteLine("[×] 文件不存在，请检查路径!");
}