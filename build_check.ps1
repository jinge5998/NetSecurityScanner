Set-Location "d:\360安全浏览器下载\软件开发备份\网络安全漏洞扫描"
$out = & dotnet build "NetSecurityScanner/src/NetSecurityScanner.sln" -c Debug --nologo 2>&1
$out | Out-File -FilePath "build_output.txt" -Encoding utf8
$out | Select-Object -Last 40
