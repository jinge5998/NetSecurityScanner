$files = Get-ChildItem -Path 'd:\360安全浏览器下载\软件开发备份\网络安全漏洞扫描\NetSecurityScanner\src\NetSecurityScanner.Desktop' -Recurse -Filter '*.cs' -ErrorAction SilentlyContinue
foreach ($f in $files) {
  $c = Get-Content $f.FullName -Raw
  if ($c -match 'using NetSecurityScanner\.Services;') {
    Write-Output $f.FullName
  }
}
