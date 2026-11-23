# 专项: 将引擎返回的原始字节流原样写入文件, 验证真实 JSON 内容(排除终端转义干扰)
$ErrorActionPreference = "Continue"
$out = Join-Path $PSScriptRoot "_raw_dump.bin"
$c = [System.Net.Sockets.TcpClient]::new()
try {
  $c.Connect("127.0.0.1", 9527)
  $stream = $c.GetStream()

  $req = @{ request_id = "dump"; message_type = "scan"; targets = @("127.0.0.1");
    ports = (@(1..500)); protocol = "tcp"; concurrency = 100; tcp_timeout_ms = 500;
    udp_timeout_ms = 1000; detect_service = $false; include_closed = $false;
    retry_count = 0
  } | ConvertTo-Json -Depth 5 -Compress
  $bytes = [System.Text.Encoding]::UTF8.GetBytes($req + "`n")
  $stream.Write($bytes, 0, $bytes.Length); $stream.Flush()

  Start-Sleep -Seconds 2
  $total = New-Object byte[] 0
  $deadline = [DateTime]::Now.AddSeconds(30)
  while ([DateTime]::Now -lt $deadline) {
    if ($stream.DataAvailable) {
      $buf = New-Object byte[] 2097152
      $n = $stream.Read($buf, 0, $buf.Length)
      if ($n -gt 0) {
        $total += $buf[0..($n - 1)]
      }
    }
    else {
      Start-Sleep -Milliseconds 100
    }
  }
  [System.IO.File]::WriteAllBytes($out, $total)
  Write-Host "dumped $($total.Length) bytes -> $out"
}
catch {
  Write-Host "FAIL: $($_.Exception.Message)"
}
finally {
  $c.Close()
}