$ErrorActionPreference = 'Continue'
$nmap = Join-Path $PSScriptRoot 'tools\nmap\nmap.exe'
$out = New-Object System.Collections.Generic.List[string]

function Run-Case {
  param([string]$Id, [string]$Desc, [string[]]$ArgList, [int]$TimeoutMs = 240000)

  $out.Add("")
  $out.Add("==================================================================")
  $out.Add("[$Id] $Desc")
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
  try {
    $p = [System.Diagnostics.Process]::Start($psi)
    $soTask = $p.StandardOutput.ReadToEndAsync()
    $seTask = $p.StandardError.ReadToEndAsync()
    if (-not $p.WaitForExit($TimeoutMs)) {
      try { $p.Kill() } catch {}
      $sw.Stop()
      $out.Add("RESULT: TIMEOUT (>${TimeoutMs}ms)  耗时=$([math]::Round($sw.Elapsed.TotalSeconds,1))s")
      return
    }
    $sw.Stop()
    $stdout = $soTask.Result
    $stderr = $seTask.Result
    $out.Add("EXITCODE=$($p.ExitCode)  耗时=$([math]::Round($sw.Elapsed.TotalSeconds,1))s")
  }
  catch {
    $sw.Stop()
    $out.Add("RESULT: LAUNCH-FAILED  $($_.Exception.Message)")
    return
  }

  $portLines = @($stdout -split "`n" | Where-Object { $_ -match '^\d+/(tcp|udp|sctp)' })
  $out.Add("端口结果行数=$($portLines.Count)")
  foreach ($l in ($portLines | Select-Object -First 10)) { $out.Add("  P| " + $l.TrimEnd()) }

  $nseLines = @($stdout -split "`n" | Where-Object { $_ -match '^\|' })
  $out.Add("NSE 输出行数=$($nseLines.Count)")
  foreach ($l in ($nseLines | Select-Object -First 8)) { $out.Add("  S| " + $l.TrimEnd()) }

  $errLines = @($stderr -split "`n" | Where-Object { $_.Trim().Length -gt 0 })
  $out.Add("stderr 非空行=$($errLines.Count)")
  foreach ($l in ($errLines | Select-Object -First 6)) { $out.Add("  E| " + $l.Trim()) }

  $luaErr = @($stdout + "`n" + $stderr -split "`n" | Where-Object {
      $_ -match 'LUA ERROR|lua error|Failed to load|syntax error|attempt to (index|call|compare)'
    })
  $out.Add("Lua/加载错误=$($luaErr.Count)")
  foreach ($l in ($luaErr | Select-Object -First 6)) { $out.Add("  X| " + $l.Trim()) }

  $fatal = @($stdout + "`n" + $stderr -split "`n" | Where-Object {
      $_ -match 'unrecognized option|Invalid argument|option requires|QUITTING|FATAL'
    })
  $out.Add("致命参数错误=$($fatal.Count)")
  foreach ($l in ($fatal | Select-Object -First 6)) { $out.Add("  F| " + $l.Trim()) }
}

$out.Add("nmap 引擎全选项实测  $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')")
$out.Add("nmap: $nmap")
$out.Add("管理员: " + ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator))

# ---------- A. 扫描类型 ----------
Run-Case 'A1' 'TCP 连接扫描 -sT（基础）' @('-sT', '-n', '-p', '135,445,3389', '-T4', '127.0.0.1')
Run-Case 'A2' 'SYN 半开扫描 -sS（非管理员应降级）' @('-sS', '-n', '-p', '135,445', '-T4', '127.0.0.1')
Run-Case 'A3' 'UDP 扫描 -sU + 服务识别' @('-sU', '-sV', '-n', '-p', '53,123,161,500', '-T4', '127.0.0.1')
Run-Case 'A4' 'TCP+UDP 混合' @('-sT', '-sU', '-sV', '-n', '-p', '445,161', '-T4', '127.0.0.1')
Run-Case 'A5' '仅主机发现 -sn（Ping 扫描模板）' @('-sn', '-PE', '-PP', '-n', '-T4', '127.0.0.1')

# ---------- B. 探测能力 ----------
Run-Case 'B1' '服务识别 -sV 默认强度' @('-sT', '-sV', '-n', '-p', '135,445,3389', '-T4', '127.0.0.1')
Run-Case 'B2' '服务识别强度 2 --version-intensity 2' @('-sT', '-sV', '--version-intensity', '2', '-n', '-p', '445', '-T4', '127.0.0.1')
Run-Case 'B3' '服务识别强度 9 --version-intensity 9' @('-sT', '-sV', '--version-intensity', '9', '-n', '-p', '445', '-T4', '127.0.0.1')
Run-Case 'B4' 'OS 识别 -O --osscan-guess（非管理员应降级）' @('-sT', '-O', '--osscan-guess', '-n', '-p', '135,445', '-T4', '127.0.0.1')
Run-Case 'B5' '主动组合 -A' @('-A', '-n', '-p', '135,445', '-T4', '127.0.0.1')
Run-Case 'B6' '默认脚本集 -sC' @('-sT', '-sV', '-sC', '-n', '-p', '135,445,3389', '-T4', '127.0.0.1')

# ---------- C. NSE 脚本 ----------
Run-Case 'C1' 'NSE 分类 vuln' @('-sT', '-sV', '--script', 'vuln', '-n', '-p', '445', '-T4', '127.0.0.1')
Run-Case 'C2' 'NSE 分类 safe' @('-sT', '-sV', '--script', 'safe', '-n', '-p', '135,445', '-T4', '127.0.0.1')
Run-Case 'C3' 'NSE 单脚本 http-title' @('-sT', '-sV', '--script', 'http-title', '-n', '-p', '80,8080', '-T4', '127.0.0.1')
Run-Case 'C4' 'NSE 单脚本 smb-os-discovery' @('-sT', '-sV', '--script', 'smb-os-discovery', '-n', '-p', '445', '-T4', '127.0.0.1')
Run-Case 'C5' 'NSE 脚本参数 --script-args' @('-sT', '-sV', '--script', 'smb-vuln-ms17-010', '--script-args', 'smbbasic=1', '-n', '-p', '445', '-T4', '127.0.0.1')

# ---------- D. 端口范围 ----------
Run-Case 'D1' 'Top 100 端口' @('-sT', '-n', '--top-ports', '100', '-T4', '127.0.0.1')
Run-Case 'D2' '自定义端口 + 排除端口' @('-sT', '-n', '-p', '135,139,445,3389', '--exclude-ports', '139', '-T4', '127.0.0.1')
Run-Case 'D3' '端口区间 1-1024' @('-sT', '-n', '-p', '1-1024', '-T4', '127.0.0.1')

# ---------- E. 时序 ----------
Run-Case 'E1' '隐蔽 -T2 + 限速' @('-sT', '-n', '-p', '445', '-T2', '--max-rate', '50', '-T4', '127.0.0.1')
Run-Case 'E2' '并发/超时/重试参数' @('-sT', '-n', '-p', '135,445', '-T4', '--max-parallelism', '100', '--max-rtt-timeout', '500ms', '--min-rtt-timeout', '100ms', '--max-retries', '2', '127.0.0.1')

# ---------- F. 规避/欺骗（raw socket 依赖） ----------
Run-Case 'F1' '分片 -f（非管理员应降级）' @('-sT', '-f', '-n', '-p', '445', '-T4', '127.0.0.1')
Run-Case 'F2' 'MTU --mtu 16（非管理员应降级）' @('-sT', '--mtu', '16', '-n', '-p', '445', '-T4', '127.0.0.1')
Run-Case 'F3' '诱饵 -D（非管理员应降级）' @('-sT', '-D', '192.168.1.100,192.168.1.101', '-n', '-p', '445', '-T4', '127.0.0.1')
Run-Case 'F4' '畸形校验和 --badsum（非管理员应降级）' @('-sT', '--badsum', '-n', '-p', '445', '-T4', '127.0.0.1')
Run-Case 'F5' '源端口 --source-port 53' @('-sT', '--source-port', '53', '-n', '-p', '445', '-T4', '127.0.0.1')
Run-Case 'F6' '源端口区间 --source-port 40000-40100' @('-sT', '--source-port', '40000-40100', '-n', '-p', '445', '-T4', '127.0.0.1')
Run-Case 'F7' 'IP 选项 --ip-options L（非管理员应降级）' @('-sT', '--ip-options', 'L', '-n', '-p', '445', '-T4', '127.0.0.1')

# ---------- G. 引擎恒定注入参数（NmapCommandBuilder 必带） ----------
Run-Case 'G1' '完整默认链路：-sT -sV -sC --data-length 32 --ttl 64 --stats-every 5s' @('-sT', '-sV', '-sC', '-n', '-p', '135,445,3389', '-T4', '--data-length', '32', '--ttl', '64', '--stats-every', '5s', '127.0.0.1')
Run-Case 'G2' 'XML 输出 -oX（引擎解析依赖）' @('-sT', '-sV', '-sC', '-n', '-p', '135,445,3389', '-T4', '-oX', (Join-Path $PSScriptRoot '_t_out.xml'), '127.0.0.1')
Run-Case 'G3' '仅开放端口 --open' @('-sT', '-n', '-p', '1-1000', '--open', '-T4', '127.0.0.1')
Run-Case 'G4' '随机目标顺序 --randomize-hosts' @('-sT', '-n', '-p', '445', '--randomize-hosts', '-T4', '127.0.0.1')

$out | Out-File -FilePath (Join-Path $PSScriptRoot '_nmap_full_test.txt') -Encoding utf8
Write-Host 'FULL-TEST-DONE'