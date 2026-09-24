Add-Type -AssemblyName "System.Reflection.Metadata" -ErrorAction SilentlyContinue
$dll = "d:\360安全浏览器下载\软件开发备份\网络安全漏洞扫描\NetSecurityScanner\src\NetSecurityScanner.Desktop\bin\Release\net6.0-windows\LiveChartsCore.SkiaSharpView.dll"
$asm = [System.Reflection.Assembly]::LoadFrom($dll)
$types = $asm.GetTypes() | Where-Object { $_.Name -match "TextSettings|HasGlobal" }
$types | ForEach-Object { Write-Host $_.FullName }
Write-Host "---"
$livecharts = [System.Reflection.Assembly]::LoadFrom("d:\360安全浏览器下载\软件开发备份\网络安全漏洞扫描\NetSecurityScanner\src\NetSecurityScanner.Desktop\bin\Release\net6.0-windows\LiveChartsCore.dll")
$types2 = $livecharts.GetTypes() | Where-Object { $_.Name -match "TextSettings|HasGlobal" }
$types2 | ForEach-Object { Write-Host $_.FullName }
