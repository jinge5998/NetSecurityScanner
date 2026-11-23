# 测量引擎处理较大规模端口扫描的耗时
$ErrorActionPreference = "Stop"

$portCount = 5000
$ports = @(1..$portCount)

$client = [System.Net.Sockets.TcpClient]::new()
try {
  $client.Connect("127.0.0.1", 9527)
  $req = @{
    request_id        = "probe-big-"
    message_type      = "scan"
    targets           = @("127.0.0.1")
    ports             = $ports
    protocol          = "tcp"
    concurrency       = 251
    tcp_timeout_ms    = 3000
    udp_timeout_ms    = 5000
    detect_service    = $false
    include_closed    = $false
    retry_count       = 3
    enable_ping_probe = $false
  } | ConvertTo-Json -Depth 5 -Compress

  $stream = $client.GetStream()
  $bytes = [System.Text.Encoding]::UTF8.GetBytes($req + "`n")
  $sw = [System.Diagnostics.Stopwatch]::StartNew()
  $stream.Write($bytes, 0, $bytes.Length)
  $stream.Flush()

  $buffer = New-Object byte[] 65536
  $sb = [System.Text.StringBuilder]::new()
  $deadline = (Get-Date).AddSeconds(240)
  $complete = $false
  while ((Get-Date) -lt $deadline) {
    if (-not $stream.DataAvailable) { Start-Sleep -Milliseconds 500; continue }
    $n = $stream.Read($buffer, 0, $buffer.Length)
    if ($n -eq 0) { break }
    for ($i = 0; $i -lt $n; $i++) { $sb.Append([char]$buffer[$i]) | Out-Null }
    if ($sb.ToString().Contains("complete")) { $complete = $true; break }
  }
  $sw.Stop()
  Write-Host "== 请求 ${portCount} 端口 (concurrency=251) =="
  Write-Host "耗时: $($sw.Elapsed.TotalSeconds) 秒, 收到complete: $complete"

  # 统计接收到的消息类型
  $text = $sb.ToString()
  $progressCount = ([regex]::Matches($text, '"type":"progress"')).Count
  $resultCount = ([regex]::Matches($text, '"type":"result"')).Count
  $completeCount = ([regex]::Matches($text, '"type":"complete"')).Count
  Write-Host "progress=$progressCount result=$resultCount complete=$completeCount"
  Write-Host "响应末尾300字: " + $text.Substring([Math]::Max(0, $text.Length - 300))
}
catch {
  Write-Host "ERROR: $($_.Exception.Message)"
}
finally {
  $client.Close()
}