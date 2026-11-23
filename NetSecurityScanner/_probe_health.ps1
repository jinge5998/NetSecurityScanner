# 引擎健康检查: 连接 9527, 发送轻量扫描请求, 验证响应链路
$ErrorActionPreference = "Continue"
$c = [System.Net.Sockets.TcpClient]::new()
try {
  $c.Connect("127.0.0.1", 9527)
  $stream = $c.GetStream()

  # 只扫 20 个常用端口 (1-20), 30s 内完成
  $req = @{ request_id = "health"; message_type = "scan"; targets = @("127.0.0.1");
    ports = (@(1..30)); protocol = "tcp"; concurrency = 30; tcp_timeout_ms = 500;
    udp_timeout_ms = 1000; detect_service = $true; include_closed = $false;
    retry_count = 0
  } | ConvertTo-Json -Depth 5 -Compress
  $bytes = [System.Text.Encoding]::UTF8.GetBytes($req + "`n")
  $sw = [System.Diagnostics.Stopwatch]::StartNew()
  $stream.Write($bytes, 0, $bytes.Length); $stream.Flush()
  Write-Host "请求已发送, 等待响应..."

  $buf = New-Object byte[] 1048576
  $hb = 0; $pr = 0; $rs = 0; $doneCount = 0; $errCount = 0
  $timeout = [DateTime]::Now.AddSeconds(30)
  while ([DateTime]::Now -lt $timeout) {
    if ($stream.DataAvailable) {
      $n = $stream.Read($buf, 0, $buf.Length)
      if ($n -eq 0) { Write-Host "连接被对端关闭"; break }
      $str = [System.Text.Encoding]::UTF8.GetString($buf, 0, $n)
      foreach ($line in ($str -split "`n")) {
        $l = $line.Trim()
        if ($l -eq "") { continue }
        try { $o = $l | ConvertFrom-Json } catch { Write-Host "无法解析行: $($l.Substring(0,[Math]::Min($l.Length,120)))"; continue }
        switch ($o.type) {
          "heartbeat" { $hb++ }
          "progress" { $pr++ }
          "result" { $rs++ }
          "complete" { Write-Host "[$($sw.Elapsed.TotalSeconds.ToString('F1'))s] COMPLETE: total_results=$($o.total_results) open=$($o.open_ports) scan_time=$($o.scan_time_ms)ms"; $doneCount++; $timeout = [DateTime]::MinValue }
          "error" { Write-Host "[$($sw.Elapsed.TotalSeconds.ToString('F1'))s] ERROR: $($o.message)"; $errCount++ }
        }
      }
    }
    else {
      if ($sw.Elapsed.TotalSeconds -gt 1 -and $doneCount -eq 0 -and $pr -eq 0) {
        # 静默期无消息不阻塞, 继续等
      }
      Start-Sleep -Milliseconds 100
    }
  }
  Write-Host "==== 引擎健康检查汇总 ===="
  Write-Host "heartbeat=$hb progress=$pr result=$rs complete=$doneCount error=$errCount"
  Write-Host "总耗时: $($sw.Elapsed.TotalSeconds.ToString('F1'))s"
  if ($doneCount -eq 1 -and $errCount -eq 0) { Write-Host "HEALTH: OK" } elseif ($doneCount -eq 1) { Write-Host "HEALTH: COMPLETED_WITH_ERRORS" } else { Write-Host "HEALTH: FAILED (未收到 complete)" }
}
catch {
  Write-Host "FAIL: $($_.Exception.Message)"
  Write-Host "HEALTH: FAILED"
}
finally {
  $c.Close()
}