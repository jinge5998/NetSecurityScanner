# 专项: 验证修复后引擎在长扫描期间每 10 秒发送 heartbeat (逐行 JSON 解析, 排除渲染干扰)
$ErrorActionPreference = "Continue"
$c = [System.Net.Sockets.TcpClient]::new()
try {
  $c.Connect("127.0.0.1", 9527)
  $stream = $c.GetStream()

  # 多目标延长扫描时长, 强制跨多个 10s 心跳周期 (8 x 10000 端口, 约 2 分钟+)
  $req = @{ request_id = "hb2"; message_type = "scan";
    targets = @("127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1");
    ports = (@(1..10000)); protocol = "tcp"; concurrency = 20; tcp_timeout_ms = 1000;
    udp_timeout_ms = 1000; detect_service = $false; include_closed = $false;
    retry_count = 0
  } | ConvertTo-Json -Depth 5 -Compress
  $bytes = [System.Text.Encoding]::UTF8.GetBytes($req + "`n")
  $sw = [System.Diagnostics.Stopwatch]::StartNew()
  $stream.Write($bytes, 0, $bytes.Length); $stream.Flush()

  $buf = New-Object byte[] 1048576
  $hbCount = 0; $prCount = 0; $rsCount = 0; $done = $false
  $hbTimes = @()
  while (-not $done) {
    if ($stream.DataAvailable) {
      $n = $stream.Read($buf, 0, $buf.Length)
      if ($n -eq 0) { Write-Host "[$($sw.Elapsed.TotalSeconds.ToString('F1'))s] 连接被对端关闭"; break }
      $str = [System.Text.Encoding]::UTF8.GetString($buf, 0, $n)
      # 逐行拆解, 计数每种类型
      foreach ($line in ($str -split "`n")) {
        $l = $line.Trim()
        if ($l -eq "") { continue }
        try {
          $o = $l | ConvertFrom-Json
        }
        catch { continue }
        $ty = $o.type
        if ($ty -eq "heartbeat") { $hbCount++; $hbTimes += $sw.Elapsed.TotalSeconds.ToString('F1') }
        elseif ($ty -eq "progress") { $prCount++ }
        elseif ($ty -eq "result") { $rsCount++ }
        elseif ($ty -eq "complete") {
          Write-Host "[$($sw.Elapsed.TotalSeconds.ToString('F1'))s] 收到 complete: total_results=$($o.total_results)"
          $done = $true
        }
      }
    }
    else {
      if ($sw.Elapsed.TotalSeconds -gt 300) { Write-Host "超时 300s 终止"; break }
      Start-Sleep -Milliseconds 200
    }
  }
  Write-Host "==== 心跳验证汇总 ===="
  Write-Host "heartbeat=$hbCount progress=$prCount result=$rsCount"
  Write-Host "心跳时刻(s): $($hbTimes -join ', ')"
  Write-Host "墙钟总用: $($sw.Elapsed.TotalSeconds.ToString('F1'))s"
}
catch {
  Write-Host "FAIL: $($_.Exception.Message)"
}
finally {
  $c.Close()
}