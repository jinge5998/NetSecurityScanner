$ErrorActionPreference = 'Stop'
$master = 'D:\360安全浏览器下载\软件开发备份\网络安全漏洞扫描\nmap-master'
$local = Join-Path $PSScriptRoot 'tools\nmap'
$backup = Join-Path $env:TEMP ('nmap-nse-backup-' + (Get-Date -Format 'yyyyMMdd_HHmmss'))
$out = New-Object System.Collections.Generic.List[string]

$targets = @(
  'nselib\http.lua',
  'nselib\iec61850mms.lua',
  'nselib\ssh2.lua',
  'nselib\tls.lua',
  'scripts\broadcast-ping.nse',
  'scripts\http-title.nse',
  'scripts\nbd-info.nse',
  'scripts\rsa-vuln-roca.nse',
  'scripts\ssh-hostkey.nse',
  'scripts\ssl-enum-ciphers.nse'
)

$out.Add("备份目录: $backup")
foreach ($rel in $targets) {
  $src = Join-Path $master $rel
  $dst = Join-Path $local  $rel
  if (-not (Test-Path $src)) { throw "源文件缺失: $src" }
  $bakDir = Join-Path $backup (Split-Path $rel -Parent)
  New-Item -ItemType Directory -Path $bakDir -Force | Out-Null
  Copy-Item $dst (Join-Path $bakDir (Split-Path $rel -Leaf)) -Force
  Copy-Item $src $dst -Force
  $same = (Get-FileHash $src).Hash -eq (Get-FileHash $dst).Hash
  $out.Add(("{0,-32} 同步完成 哈希一致={1}  大小={2}" -f $rel, $same, (Get-Item $dst).Length))
}

$out.Add('')
$out.Add('=== 同步后全量复核（应为 0 处差异） ===')
$md = Join-Path $master 'nselib'
$ld = Join-Path $local  'nselib'
$diff = 0
foreach ($f in (Get-ChildItem $md -Recurse -File)) {
  $rel = $f.FullName.Substring($md.Length + 1)
  $lp = Join-Path $ld $rel
  if (-not (Test-Path $lp) -or (Get-FileHash $f.FullName).Hash -ne (Get-FileHash $lp).Hash) { $diff++ }
}
$out.Add("nselib 差异: $diff / 186")

$ms = Join-Path $master 'scripts'
$ls = Join-Path $local  'scripts'
$diff2 = 0
foreach ($f in (Get-ChildItem $ms -Filter '*.nse' -File)) {
  $lp = Join-Path $ls $f.Name
  if (-not (Test-Path $lp) -or (Get-FileHash $f.FullName).Hash -ne (Get-FileHash $lp).Hash) { $diff2++ }
}
$out.Add("scripts 差异: $diff2 / 619")

foreach ($df in @('nmap-services', 'nmap-rpc', 'nmap-os-db', 'nmap-service-probes', 'nmap-protocols', 'nmap-mac-prefixes', 'nse_main.lua')) {
  $same = (Get-FileHash (Join-Path $master $df)).Hash -eq (Get-FileHash (Join-Path $local $df)).Hash
  $out.Add("数据文件 $df 一致=$same")
}

$out | Out-File -FilePath (Join-Path $PSScriptRoot '_sync_result.txt') -Encoding utf8
Write-Host 'SYNC-DONE'