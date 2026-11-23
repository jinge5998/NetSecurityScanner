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
  $p.WaitForExit(120000) | Out-Null
  $sw.Stop()
  $stdout = $so.Result
  $stderr = $se.Result
  $out.Add("EXITCODE=$($p.ExitCode)  耗时=$([math]::Round($sw.Elapsed.TotalSeconds,1))s")
  $out.Add("--- stderr (前 8 行非空) ---")
  $errLines = ($stderr -split "`n" | Where-Object { $_.Trim().Length -gt 0 })
  if ($errLines.Count -eq 0) { $out.Add("(空)") } else { foreach ($l in ($errLines | Select-Object -First 8)) { $out.Add("  " + $l.Trim()) } }
  $out.Add("--- stdout 中 port 行 ---")
  $portLines = ($stdout -split "`n" | Where-Object { $_ -match '^\d+/(tcp|udp)' })
  if ($portLines.Count -eq 0) { $out.Add("(无端口结果)") } else { foreach ($l in ($portLines | Select-Object -First 12)) { $out.Add("  " + $l.TrimEnd()) } }
  $out.Add("--- stdout 中 NSE / 错误关键字 ---")
  $kw = ($stdout -split "`n" | Where-Object { $_ -match 'ERROR|LUA|script|SCRIPT|Failed|failed' })
  if ($kw.Count -eq 0) { $out.Add("(无)") } else { foreach ($l in ($kw | Select-Object -First 10)) { $out.Add("  " + $l.TrimEnd()) } }
}

Run-Case 'A. 专家模式默认：TCP 连接扫描 + 服务识别 + 默认脚本（含 --data-length 32）' @('-sT', '-sV', '-sC', '-n', '-p', '135,445,3389', '-T4', '--data-length', '32', '--ttl', '64', '127.0.0.1')
Run-Case 'B. UDP 服务识别（含 --data-length 32）' @('-sU', '-sV', '-n', '-p', '53,123,161', '-T4', '--data-length', '32', '--ttl', '64', '127.0.0.1')
Run-Case 'C. UDP 服务识别（不含 --data-length）' @('-sU', '-sV', '-n', '-p', '53,123,161', '-T4', '--ttl', '64', '127.0.0.1')
Run-Case 'D. NSE vuln 脚本集（检查是否有 Lua 运行错误）' @('-sT', '-sV', '--script', 'vuln', '-n', '-p', '135,445', '-T4', '127.0.0.1')
Run-Case 'E. NSE default 脚本集 + 445' @('-sT', '-sV', '-sC', '-n', '-p', '445', '-T4', '127.0.0.1')

$out | Out-File -FilePath (Join-Path $PSScriptRoot '_nmap_engine_probe.txt') -Encoding utf8
Write-Host 'ENGINE-PROBE-DONE'