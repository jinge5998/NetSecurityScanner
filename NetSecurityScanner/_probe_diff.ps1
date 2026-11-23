$ErrorActionPreference = 'Continue'
$master = 'D:\360安全浏览器下载\软件开发备份\网络安全漏洞扫描\nmap-master'
$local = Join-Path $PSScriptRoot 'tools\nmap'
$out = New-Object System.Collections.Generic.List[string]

$out.Add('=== nselib 差异 ===')
$md = Join-Path $master 'nselib'
$ld = Join-Path $local  'nselib'
$mFiles = @(Get-ChildItem $md -Recurse -File -ErrorAction SilentlyContinue)
$diffCount = 0
$missing = @()
foreach ($f in $mFiles) {
  $rel = $f.FullName.Substring($md.Length + 1)
  $lp = Join-Path $ld $rel
  if (-not (Test-Path $lp)) { $missing += $rel; continue }
  if ((Get-FileHash $f.FullName).Hash -ne (Get-FileHash $lp).Hash) { $diffCount++; if ($diffCount -le 25) { $out.Add('  内容不同: ' + $rel) } }
}
$out.Add("  本地缺失: $($missing.Count)")
foreach ($m in ($missing | Select-Object -First 15)) { $out.Add('    ' + $m) }
$out.Add("  内容不同总数: $diffCount / $($mFiles.Count)")

$out.Add('')
$out.Add('=== nmap.xsl 差异 ===')
$mx = Join-Path $master 'docs\nmap.xsl'
$lx = Join-Path $local  'nmap.xsl'
if ((Test-Path $mx) -and (Test-Path $lx)) {
  $out.Add("  master: $((Get-Item $mx).Length) bytes  local: $((Get-Item $lx).Length) bytes")
  $out.Add("  哈希一致: " + ((Get-FileHash $mx).Hash -eq (Get-FileHash $lx).Hash))
}
else { $out.Add("  文件缺失 master=$(Test-Path $mx) local=$(Test-Path $lx)") }

$out.Add('')
$out.Add('=== nse_main.lua 差异 ===')
$out.Add('  哈希一致: ' + ((Get-FileHash (Join-Path $master 'nse_main.lua')).Hash -eq (Get-FileHash (Join-Path $local 'nse_main.lua')).Hash))

$out.Add('')
$out.Add('=== 6 个内容不同的脚本，大小对比 ===')
foreach ($n in @('broadcast-ping.nse', 'http-title.nse', 'nbd-info.nse', 'rsa-vuln-roca.nse', 'ssh-hostkey.nse', 'ssl-enum-ciphers.nse')) {
  $mp = Join-Path (Join-Path $master 'scripts') $n
  $lp = Join-Path (Join-Path $local  'scripts') $n
  $out.Add(("  {0,-22} master={1,6}  local={2,6}" -f $n, (Get-Item $mp).Length, (Get-Item $lp).Length))
}

$out.Add('')
$out.Add('=== 本地 nselib/data 子目录文件数 ===')
$out.Add('  master: ' + @(Get-ChildItem (Join-Path $md 'data') -File -ErrorAction SilentlyContinue).Count + '   local: ' + @(Get-ChildItem (Join-Path $ld 'data') -File -ErrorAction SilentlyContinue).Count)

$out | Out-File -FilePath (Join-Path $PSScriptRoot '_probe_diff.txt') -Encoding utf8
Write-Host 'DIFF-DONE'