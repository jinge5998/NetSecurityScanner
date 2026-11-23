$ErrorActionPreference = 'Continue'
$nmap = Join-Path $PSScriptRoot 'tools\nmap\nmap.exe'
$out = New-Object System.Collections.Generic.List[string]

function Run-Case {
  param([string]$Name, [string[]]$ArgList)
  $out.Add("")
  $out.Add("===== $Name =====")
  $out.Add("CMD: nmap " + ($ArgList -join ' '))
  $psi = New-Object System.Diagnostics.ProcessStartInfo
  $psi.FileName = $nmap
  $psi.UseShellExecute = $false
  $psi.CreateNoWindow = $true
  $psi.RedirectStandardOutput = $true
  $psi.RedirectStandardError = $true
  $psi.StandardOutputEncoding = [System.Text.Encoding]::UTF8
  foreach ($a in $ArgList) { $psi.ArgumentList.Add($a) }
  $sw = [System.Diagnostics.Stopwatch]::StartNew()
  $p = [System.Diagnostics.Process]::Start($psi)
  $so = $p.StandardOutput.ReadToEndAsync()
  $se = $p.StandardError.ReadToEndAsync()
  $p.WaitForExit(180000) | Out-Null
  $sw.Stop()
  $stdout = $so.Result
  $stderr = $se.Result
  $out.Add("EXITCODE=$($p.ExitCode)  耗时=$([math]::Round($sw.Elapsed.TotalSeconds,1))s")
  $errLines = ($stderr -split "`n" | Where-Object { $_.Trim().Length -gt 0 })
  $out.Add("stderr 非空行数=$($errLines.Count)")
  foreach ($l in ($errLines | Select-Object -First 6)) { $out.Add("  E| " + $l.Trim()) }
  $portLines = ($stdout -split "`n" | Where-Object { $_ -match '^\d+/(tcp|udp)' })
  $out.Add("端口结果行数=$($portLines.Count)")
  foreach ($l in ($portLines | Select-Object -First 6)) { $out.Add("  P| " + $l.TrimEnd()) }
  $warn = ($stdout -split "`n" | Where-Object { $_ -match 'WARNING|QUITTING|Failed|failed|ERROR|error' })
  foreach ($l in ($warn | Select-Object -First 6)) { $out.Add("  W| " + $l.TrimEnd()) }
}

$base = @('-n', '-p', '445', '-T4', '--ttl', '64', '127.0.0.1')

Run-Case '1. 分片 -f + 恒定 --data-length 32（Builder 恒定注入）' (@('-sT', '-f', '--data-length', '32') + $base)
Run-Case '2. 分片 -f 但无 --data-length（对照）' (@('-sT', '-f') + $base)
Run-Case '3. SYN 扫描 -sS（非管理员）' (@('-sS', '-sV', '--data-length', '32') + $base)
Run-Case '4. OS 识别 -O --osscan-guess + -sT' (@('-sT', '-sV', '-O', '--osscan-guess', '--data-length', '32') + $base)
Run-Case '5. --mtu 16 与 -f 同时（互斥）' (@('-sT', '-f', '--mtu', '16', '--data-length', '32') + $base)
Run-Case '6. 诱饵 -D + --data-length' (@('-sT', '-D', 'RND:5', '--data-length', '32') + $base)
Run-Case '7. 畸形校验和 --badsum + -sT' (@('-sT', '--badsum', '--data-length', '32') + $base)
Run-Case '8. --ip-options L + -sT' (@('-sT', '--ip-options', 'L', '--data-length', '32') + $base)
Run-Case '9. 纯 UDP 扫描 -sU（无 payload 文件时的表现）' @('-sU', '-n', '-p', '161', '-T4', '127.0.0.1')

$out | Out-File -FilePath (Join-Path $PSScriptRoot '_nmap_option_probe.txt') -Encoding utf8
Write-Host 'OPTION-PROBE-DONE'