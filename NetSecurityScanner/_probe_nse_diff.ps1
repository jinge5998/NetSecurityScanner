$ErrorActionPreference = 'Continue'
$master = 'D:\360安全浏览器下载\软件开发备份\网络安全漏洞扫描\nmap-master'
$local = Join-Path $PSScriptRoot 'tools\nmap'
$out = New-Object System.Collections.Generic.List[string]

$pairs = @(
  @('nselib\http.lua', 'nselib\http.lua'),
  @('nselib\iec61850mms.lua', 'nselib\iec61850mms.lua'),
  @('nselib\ssh2.lua', 'nselib\ssh2.lua'),
  @('nselib\tls.lua', 'nselib\tls.lua'),
  @('scripts\broadcast-ping.nse', 'scripts\broadcast-ping.nse'),
  @('scripts\http-title.nse', 'scripts\http-title.nse'),
  @('scripts\nbd-info.nse', 'scripts\nbd-info.nse'),
  @('scripts\rsa-vuln-roca.nse', 'scripts\rsa-vuln-roca.nse'),
  @('scripts\ssh-hostkey.nse', 'scripts\ssh-hostkey.nse'),
  @('scripts\ssl-enum-ciphers.nse', 'scripts\ssl-enum-ciphers.nse')
)

foreach ($pair in $pairs) {
  $rel = $pair[0]
  $mp = Join-Path $master $rel
  $lp = Join-Path $local  $rel
  $out.Add('')
  $out.Add("########## $rel ##########")
  $a = Get-Content $mp
  $b = Get-Content $lp
  $d = Compare-Object -ReferenceObject $a -DifferenceObject $b
  $out.Add("master 行数=$($a.Count)  local 行数=$($b.Count)  差异块数=$($d.Count)")
  $addedLocal = @($d | Where-Object { $_.SideIndicator -eq '=>' })
  $addedMaster = @($d | Where-Object { $_.SideIndicator -eq '<=' })
  $out.Add("仅 master 有(<=): $($addedMaster.Count) 行   仅 local 有(=>): $($addedLocal.Count) 行")
  $out.Add('--- 仅 local 有（本地独有，即 master 已删除/改写）前 12 行 ---')
  foreach ($x in ($addedLocal | Select-Object -First 12)) { $out.Add('  L> ' + $x.InputObject.Trim()) }
  $out.Add('--- 仅 master 有（master 新增/改写）前 12 行 ---')
  foreach ($x in ($addedMaster | Select-Object -First 12)) { $out.Add('  M> ' + $x.InputObject.Trim()) }
}

$out | Out-File -FilePath (Join-Path $PSScriptRoot '_nse_diff.txt') -Encoding utf8
Write-Host 'NSE-DIFF-DONE'