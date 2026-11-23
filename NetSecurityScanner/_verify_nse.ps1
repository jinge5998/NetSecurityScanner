$ErrorActionPreference = 'Continue'
$nmap = Join-Path $PSScriptRoot 'tools\nmap\nmap.exe'
$out = New-Object System.Collections.Generic.List[string]

function Run-Nmap {
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
  $p = [System.Diagnostics.Process]::Start($psi)
  $so = $p.StandardOutput.ReadToEndAsync()
  $se = $p.StandardRedirectErrorAsync
  $se = $p.StandardError.ReadToEndAsync()
  $p.WaitForExit(180000) | Out-Null
  $stdout = $so.Result
  $stderr = $se.Result
  $out.Add("EXITCODE=$($p.ExitCode)")
  $err = ($stderr -split "`n" | Where-Object { $_.Trim().Length -gt 0 })
  $out.Add("stderr 非空行=$($err.Count)")
  foreach ($l in ($err | Select-Object -First 6)) { $out.Add("  E| " + $l.Trim()) }
  $bad = ($stdout -split "`n" | Where-Object { $_ -match 'ERROR|lua error|LUA ERROR|Failed to load|syntax error|attempt to' })
  $out.Add("Lua/加载错误行=$($bad.Count)")
  foreach ($l in ($bad | Select-Object -First 8)) { $out.Add("  X| " + $l.TrimEnd()) }
  return $stdout
}

$out.Add('=== 1. 重建 scripts\script.db（解析全部 619 个脚本） ===')
$dbBefore = (Get-Item (Join-Path $PSScriptRoot 'tools\nmap\scripts\script.db'))
$out.Add("执行前 script.db: $($dbBefore.Length) bytes  $($dbBefore.LastWriteTime)")
Run-Nmap 'nmap --script-updatedb' @('--script-updatedb') | Out-Null
$dbAfter = (Get-Item (Join-Path $PSScriptRoot 'tools\nmap\scripts\script.db'))
$out.Add("执行后 script.db: $($dbAfter.Length) bytes  $($dbAfter.LastWriteTime)")

$out.Add('')
$out.Add('=== 2. 逐个强制解析本次更新的 6 个脚本（--script-help 会真正加载脚本与依赖库） ===')
foreach ($s in @('broadcast-ping', 'http-title', 'nbd-info', 'rsa-vuln-roca', 'ssh-hostkey', 'ssl-enum-ciphers')) {
  $text = Run-Nmap "script-help: $s" @('--script-help', $s)
  $ok = ($text -match 'Categories') -or ($text -match '===') 
  $out.Add("  $s 加载成功=$ok")
}

$out.Add('')
$out.Add('=== 3. 真实扫描：-sC 默认脚本集（走本次更新的 http-title 等） ===')
$t = Run-Nmap 'nmap -sT -sV -sC -p 135,445,3389' @('-sT', '-sV', '-sC', '-n', '-p', '135,445,3389', '-T4', '127.0.0.1')
foreach ($l in ($t -split "`n" | Where-Object { $_ -match '^\d+/tcp|^\|' } | Select-Object -First 10)) { $out.Add("  " + $l.TrimEnd()) }

$out.Add('')
$out.Add('=== 4. 真实扫描：--script vuln 漏洞脚本集 ===')
$t2 = Run-Nmap 'nmap -sT -sV --script vuln -p 445' @('-sT', '-sV', '--script', 'vuln', '-n', '-p', '445', '-T4', '127.0.0.1')
foreach ($l in ($t2 -split "`n" | Where-Object { $_ -match '^\d+/tcp|^\|' } | Select-Object -First 10)) { $out.Add("  " + $l.TrimEnd()) }

$out.Add('')
$out.Add('=== 5. 真实扫描：--script ssl-enum-ciphers / ssh-hostkey（无对应服务，验证脚本可正常执行不报错） ===')
Run-Nmap 'nmap --script ssl-enum-ciphers,ssh-hostkey -p 443,22' @('-sT', '-n', '-p', '443,22', '--script', 'ssl-enum-ciphers,ssh-hostkey', '-T4', '127.0.0.1') | Out-Null

$out | Out-File -FilePath (Join-Path $PSScriptRoot '_nse_verify.txt') -Encoding utf8
Write-Host 'NSE-VERIFY-DONE'