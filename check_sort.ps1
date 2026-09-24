$content = Get-Content 'd:\360安全浏览器下载\软件开发备份\网络安全漏洞扫描\NetSecurityScanner\src\NetSecurityScanner\Services\PortScanner.cs' -Raw
if ($content -match 'static.*SortByRiskDesc') {
  Write-Output 'FOUND SortByRiskDesc'
} else {
  Write-Output 'NOT FOUND - SortByRiskDesc in NetSecurityScanner.Services.PortScanner'
}
if ($content -match 'public class PortScanner') {
  Write-Output 'PortScanner class found'
}
