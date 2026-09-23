$dir = "d:\360安全浏览器下载\软件开发备份\网络安全漏洞扫描\NetSecurityScanner\publish-v1.0.1.5"
$files = Get-ChildItem -Path $dir -File
$matches = $files | Where-Object { $_.Name -match "LiveCharts|Skia|HarfBuzz|libSkia|libHarf" }
$matches | ForEach-Object { Write-Host $_.Name }
Write-Host "---"
Write-Host "Total files: $($files.Count)"
