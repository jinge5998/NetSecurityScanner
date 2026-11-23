# 专项: 观察长扫描期间引擎是否发送 heartbeat/progress, 以及 complete 到达延迟
$ErrorActionPreference = "Continue"
$c = [System.Net.Sockets.TcpClient]::new()
try {
  $c.Connect("127.0.0.1", 9527)
  $stream = $c.GetStream()

  # 扫描 8000 端口 retry=2, 预计引擎开销较大, 用于观察扫描期间的消息流
  $req = @{ request_id = "watch"; message_type = "scan"; targets = @("127.0.0.1");
    ports = (@(1..8000)); protocol = "tcp"; concurrency = 251; tcp_timeout_ms = 3000;
    udp_timeout_ms = 1000; detect_service = $false; include_closed = $false;
    retry_count = 2 
  } | ConvertTo-Json -Depth 5 -Compress
  $bytes = [System.Text.Encoding]::UTF8.GetBytes($req + "`n")
  $sw = [System.Diagnostics.Stopwatch]::StartNew()
  $stream.Write($bytes, 0, $bytes.Length); $stream.Flush()

  $buf = New-Object byte[] 65536
  $lastPrint = 0
  $msgCount = 0
  $types = @{}
  $firstComplete = $null
  $lastMsgT = $null
  while ($true) {
    if ($stream.DataAvailable) {
      $n = $stream.Read($buf, 0, $buf.Length)
      if ($n -eq 0) { Write-Host "[$($sw.Elapsed.TotalSeconds.ToString('F1'))s] 连接被对端关闭"; break }
      $str = [System.Text.Encoding]::UTF8.GetString($buf, 0, $n)
      $msgCount++
      $t = $sw.Elapsed.TotalSeconds
      $lastMsgT = $t
      if ($str -match '"type":"(\w+)"') { $ty = $Matches[1]; $types[$ty] = ($types[$ty] ?? 0) + 1 }
      if ($str.Contains('complete')) {
        if (-not $firstComplete) { $firstComplete = $t }
        Write-Host "[$($t.ToString('F1'))s] 收到 complete | 片段=$($str.Substring(0,[Math]::Min(120,$str.Length)))"
        Start-Sleep -Milliseconds 500
        # complete 后继续读 3 秒看是否还有后续消息
        $idle = 0
        while ($idle -lt 3) {
          if ($stream.DataAvailable) {
            $n2 = $stream.Read($buf, 0, $buf.Length)
            if ($n2 -gt 0) {
              $s2 = [System.Text.Encoding]::UTF8.GetString($buf, 0, $n2)
              Write-Host "  [after-complete] 又收到 $n2 字节: $($s2.Substring(0,[Math]::Min(100,$s2.Length)))"
            }
            $idle = 0
          }
          else { Start-Sleep -Milliseconds 300; $idle += 0.3 }
        }
        break
      }
    }
    else {
      $now = $sw.Elapsed.TotalSeconds
      if ([int]$now -gt $lastPrint) {
        $lastPrint = [int]$now
        $since = if ($lastMsgT) { ($now - $lastMsgT).ToString('F0') } else { 'n/a' }
        Write-Host "[$($now.ToString('F0'))s] 已等待... 上条消息距今 ${since}s (总消息${msgCount}条)"
      }
      if ($now -gt 200) { Write-Host "超时 200s 终止"; break }
      Start-Sleep -Milliseconds 200
    }
  }
  Write-Host "==== 汇总 ===="
  Write-Host "总消息数: $msgCount"
  Write-Host "类型计数: $($types | ConvertTo-Json -Compress)"
  Write-Host "firstComplete at: $(if ($firstComplete) { $firstComplete.ToString('F1') } else { '未收到' })"
  Write-Host "墙钟总用: $($sw.Elapsed.TotalSeconds.ToString('F1'))s"
}
catch {
  Write-Host "FAIL: $($_.Exception.Message)"
}
finally {
  $c.Close()
}