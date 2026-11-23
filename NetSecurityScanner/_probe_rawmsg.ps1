# 专项: 抓取引擎返回消息的原始格式, 验证 complete/heartbeat 的确切 JSON 结构
$ErrorActionPreference = "Continue"
$c = [System.Net.Sockets.TcpClient]::new()
try {
  $c.Connect("127.0.0.1", 9527)
  $c.ReceiveBufferSize = 1048576
  $c.NoDelay = $true
  $stream = $c.GetStream()
  $stream.ReadTimeout = 5000

  # 一次小扫描, 快速拿到 complete
  $req = @{ request_id = "raw"; message_type = "scan"; targets = @("127.0.0.1");
    ports = (@(1..1000)); protocol = "tcp"; concurrency = 100; tcp_timeout_ms = 500;
    udp_timeout_ms = 1000; detect_service = $false; include_closed = $false;
    retry_count = 0
  } | ConvertTo-Json -Depth 5 -Compress
  $bytes = [System.Text.Encoding]::UTF8.GetBytes($req + "`n")
  $stream.Write($bytes, 0, $bytes.Length); $stream.Flush()

  Start-Sleep -Seconds 2
  $lineBuffer = ""
  $deadline = [DateTime]::Now.AddSeconds(60)
  while ([DateTime]::Now -lt $deadline) {
    if ($stream.DataAvailable) {
      $buf = New-Object byte[] 1048576
      $n = $stream.Read($buf, 0, $buf.Length)
      if ($n -gt 0) {
        $lineBuffer += [System.Text.Encoding]::UTF8.GetString($buf, 0, $n)
        $lines = $lineBuffer -split "`n"
        $lineBuffer = $lines[-1]
        for ($i = 0; $i -lt $lines.Length - 1; $i++) {
          $line = $lines[$i].Trim()
          if ($line -eq "") { continue }
          $obj = $null
          try {
            $obj = $line | ConvertFrom-Json
            $type = $obj.type
            $msgType = $obj.message_type
            $kind = if ($type) { $type } elseif ($msgType) { $msgType } else { "??" }
            Write-Host "[$kind] RAW: $line"
            if ($kind -eq "complete") {
              Write-Host "==== 收到 complete, 客户端可正常解析 ===="
              $deadline = [DateTime]::MinValue  # 结束外层循环
              break
            }
          }
          catch {
            Write-Host "[RAW-unparseable] $line"
          }
        }
        $deadline2 = $deadline
      }
    }
    else {
      Start-Sleep -Milliseconds 100
    }
  }
  Write-Host "==== 原始消息诊断完成 ===="
}
catch {
  Write-Host "FAIL: $($_.Exception.Message)"
}
finally {
  $c.Close()
}