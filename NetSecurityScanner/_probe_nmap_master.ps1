$ErrorActionPreference = 'Continue'
$master = 'D:\360安全浏览器下载\软件开发备份\网络安全漏洞扫描\nmap-master'
$local = Join-Path $PSScriptRoot 'tools\nmap'
$lines = New-Object System.Collections.Generic.List[string]

$lines.Add("=== 路径存在性 ===")
foreach ($p in @($master, (Join-Path $master 'configure.ac'), (Join-Path $master 'CHANGELOG'), (Join-Path $master 'scripts'), (Join-Path $master 'nselib'))) {
  $lines.Add(("{0,-60} {1}" -f $p, (Test-Path $p)))
}

$lines.Add("")
$lines.Add("=== nmap-master 版本 ===")
$ca = Join-Path $master 'configure.ac'
if (Test-Path $ca) {
  $hit = Select-String -Path $ca -Pattern 'NMAP_VERSION' | Select-Object -First 4
  foreach ($h in $hit) { $lines.Add('  ' + $h.Line.Trim()) }
}
else {
  $lines.Add('  configure.ac 不存在')
}

$lines.Add("")
$lines.Add("=== CHANGELOG 前 5 行 ===")
$cl = Join-Path $master 'CHANGELOG'
if (Test-Path $cl) { foreach ($l in (Get-Content $cl -TotalCount 5)) { $lines.Add('  ' + $l) } }

$lines.Add("")
$lines.Add("=== scripts / nselib 计数对比 ===")
$ms = @(Get-ChildItem (Join-Path $master 'scripts') -Filter '*.nse' -File -ErrorAction SilentlyContinue)
$ls = @(Get-ChildItem (Join-Path $local  'scripts') -Filter '*.nse' -File -ErrorAction SilentlyContinue)
$mn = @(Get-ChildItem (Join-Path $master 'nselib') -Recurse -File -ErrorAction SilentlyContinue)
$ln = @(Get-ChildItem (Join-Path $local  'nselib') -Recurse -File -ErrorAction SilentlyContinue)
$lines.Add("  master scripts(*.nse): $($ms.Count)   local: $($ls.Count)")
$lines.Add("  master nselib(files):  $($mn.Count)   local: $($ln.Count)")

$lines.Add("")
$lines.Add("=== 本地缺失的脚本（master 有、local 无） ===")
$localNames = @{}
foreach ($f in $ls) { $localNames[$f.Name] = $true }
$missing = @()
foreach ($f in $ms) { if (-not $localNames.ContainsKey($f.Name)) { $missing += $f.Name } }
if ($missing.Count -eq 0) { $lines.Add('  无缺失') } else { $lines.Add("  缺失 $($missing.Count) 个:") ; foreach ($n in ($missing | Select-Object -First 30)) { $lines.Add('    ' + $n) } }

$lines.Add("")
$lines.Add("=== 内容不一致的脚本（同名但哈希不同） ===")
$diff = @()
foreach ($f in $ms) {
  $lp = Join-Path (Join-Path $local 'scripts') $f.Name
  if (Test-Path $lp) {
    $a = (Get-FileHash $f.FullName -Algorithm SHA256).Hash
    $b = (Get-FileHash $lp -Algorithm SHA256).Hash
    if ($a -ne $b) { $diff += $f.Name }
  }
}
$lines.Add("  不一致 $($diff.Count) 个")
foreach ($n in ($diff | Select-Object -First 20)) { $lines.Add('    ' + $n) }

$lines.Add("")
$lines.Add("=== master 是否含 nmap-payloads ===")
$pl = @(Get-ChildItem $master -Recurse -Filter 'nmap-payloads' -File -ErrorAction SilentlyContinue)
$lines.Add("  找到 $($pl.Count) 个")

$lines.Add("")
$lines.Add("=== 本地 tools\nmap 顶层文件 ===")
foreach ($f in (Get-ChildItem $local -File -ErrorAction SilentlyContinue)) {
  $lines.Add(("  {0,-30} {1,9} bytes" -f $f.Name, $f.Length))
}

$lines | Out-File -FilePath (Join-Path $PSScriptRoot '_probe_result.txt') -Encoding utf8
Write-Host "PROBE-DONE"