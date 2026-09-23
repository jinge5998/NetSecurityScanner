$root = 'd:\360安全浏览器下载\软件开发备份\网络安全漏洞扫描\NetSecurityScanner\src\NetSecurityScanner.Desktop'
Write-Output "Path: $root"
$files = Get-ChildItem -Path $root -Filter '*.cs' -ErrorAction SilentlyContinue
Write-Output "Top-level files: $($files.Count)"
$files2 = Get-ChildItem -Path $root -Recurse -Filter '*.cs' -ErrorAction SilentlyContinue
Write-Output "Recursive files: $($files2.Count)"
if ($files2.Count -gt 0) {
  Write-Output "First file: $($files2[0].FullName)"
  $c = Get-Content $files2[0].FullName -Raw
  if ($c -match 'using NetSecurityScanner\.Services;') {
    Write-Output "USING Services FOUND in: $($files2[0].FullName)"
  }
}
