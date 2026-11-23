# 严格验证 Rust 引擎响应 JSON 的合法性
$ErrorActionPreference = "Stop"

$client = [System.Net.Sockets.TcpClient]::new()
try {
  $client.Connect("127.0.0.1", 9527)
  $req = @{
    request_id     = "probe2-" + [guid]::NewGuid().ToString("N").Substring(0, 8)
    message_type   = "scan"
    targets        = @("127.0.0.1")
    ports          = @(22, 3389)
    protocol       = "tcp"
    concurrency    = 50
    tcp_timeout_ms = 300
    udp_timeout_ms = 500
  } | ConvertTo-Json -Depth 5 -Compress

  $stream = $client.GetStream()
  $bytes = [System.Text.Encoding]::UTF8.GetBytes($req + "`n")
  $stream.Write($bytes, 0, $bytes.Length)
  $stream.Flush()

  $buffer = New-Object byte[] 8192
  $all = [System.Collections.Generic.List[byte]]::new()
  $deadline = (Get-Date).AddSeconds(20)
  while ((Get-Date) -lt $deadline) {
    if (-not $stream.DataAvailable) { Start-Sleep -Milliseconds 200; continue }
    $n = $stream.Read($buffer, 0, $buffer.Length)
    if ($n -eq 0) { break }
    for ($i = 0; $i -lt $n; $i++) { $all.Add($buffer[$i]) }
    $s = [System.Text.Encoding]::UTF8.GetString($all.ToArray())
    if ($s.Contains("complete")) { break }
  }

  $raw = [System.Text.Encoding]::UTF8.GetString($all.ToArray())
  Write-Host "=== RAW RESPONSE ==="
  Write-Host $raw
  Write-Host "=== 逐行解析测试 ==="
  $lines = $raw -split "`n" | Where-Object { $_.Trim().Length -gt 0 }
  foreach ($line in $lines) {
    try {
      $obj = $line | ConvertFrom-Json
      Write-Host "PARSE_OK type=$($obj.type)"
    }
    catch {
      Write-Host "PARSE_FAIL: $($line.Substring(0, [Math]::Min(120, $line.Length)))  ==> $($_.Exception.Message)"
    }
  }
}
catch {
  Write-Host "ERROR: $_"
}
finally {
  $client.Close()
}
Write-Host "done"