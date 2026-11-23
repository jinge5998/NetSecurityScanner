# 对比不同参数下引擎扫描耗时
$ErrorActionPreference = "Stop"

function Test-Scan($name, $ports, $concurrency, $tcpTimeout, $retryCount) {
  $client = [System.Net.Sockets.TcpClient]::new()
  try {
    $client.Connect("127.0.0.1", 9527)
    $req = @{
      request_id        = "perf-$name"
      message_type      = "scan"
      targets           = @("127.0.0.1")
      ports             = $ports
      protocol          = "tcp"
      concurrency       = $concurrency
      tcp_timeout_ms    = $tcpTimeout
      udp_timeout_ms    = 5000
      detect_service    = $false
      include_closed    = $false
      retry_count       = $retryCount
      enable_ping_probe = $false
    } | ConvertTo-Json -Depth 5 -Compress

    $stream = $client.GetStream()
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($req + "`n")
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    $stream.Write($bytes, 0, $bytes.Length)
    $stream.Flush()

    $buf = New-Object byte[] 65536
    $sb = [System.Text.StringBuilder]::new()
    $deadline = (Get-Date).AddSeconds(360)
    $complete = $false
    while ((Get-Date) -lt $deadline) {
      if (-not $stream.DataAvailable) { Start-Sleep -Milliseconds 500; continue }
      $n = $stream.Read($buf, 0, $buf.Length)
      if ($n -eq 0) { break }
      for ($i = 0; $i -lt $n; $i++) { [void]$sb.Append([char]$buf[$i]) }
      if ($sb.ToString().Contains("complete")) { $complete = $true; break }
    }
    $sw.Stop()
    Write-Host ("[{0}] 端口:{1} 并发:{2} 超时:{3}ms 重试:{4} => {5:N1}秒 complete={6}" -f `
        $name, $ports.Count, $concurrency, $tcpTimeout, $retryCount, `
        $sw.Elapsed.TotalSeconds, $complete)
    # 提取引擎的 scan_time_ms
    $text = $sb.ToString()
    $m = [regex]::Match($text, '"scan_time_ms":(\d+)')
    if ($m.Success) { Write-Host "   引擎自报 scan_time_ms=$($m.Groups[1].Value)" }
  }
  catch {
    Write-Host "[$name] ERROR: $($_.Exception.Message)"
  }
  finally {
    $client.Close()
    [System.GC]::Collect()
  }
}

$ports5000 = @(1..5000)
$ports2000 = @(1..2000)

Write-Host "==== A. 默认参数(1000并发/200ms) vs 用户参数(251并发/3000ms) ===="
Test-Scan "A1-default"     $ports2000 1000 200  1 
Test-Scan "A2-user"        $ports2000 251  3000 3
Write-Host "==== B. 仅改变超时 ===="
Test-Scan "B1-251/500"     $ports2000 251  500  1
Test-Scan "B2-251/3000"    $ports2000 251  3000 1
Write-Host "done"