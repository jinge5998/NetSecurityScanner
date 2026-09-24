Set WshShell = CreateObject("WScript.Shell")
Set fso = CreateObject("Scripting.FileSystemObject")

exePath = "d:\360安全浏览器下载\软件开发备份\网络安全漏洞扫描\NetSecurityScanner\publish-v1.0.2.1\NetSecurityScanner.Desktop.exe"

If fso.FileExists(exePath) Then
    WshShell.Run Chr(34) & exePath & Chr(34), 1, False
Else
    MsgBox "未找到程序文件：" & vbCrLf & exePath, 16, "错误"
End If