# 字节级验证引擎响应的 JSON 合法性
$ErrorActionPreference = "Stop"
$req = @{
  request_id     = "probe-byte-"
  message_type   = "scan"
  targets        = @("127.0.0.1")
  ports          = @(3389, 80, 443)
  protocol       = "tcp"
  concurrency    = 251
  tcp_timeout_ms = 3000
  udp_timeout_ms = 5000
  detect_service = $false
  include_closed = $false
} | ConvertTo-Json -Depth 5 -Compress

$client = [System.Net.Sockets.TcpClient]::new()
try {
  $client.Connect("127.0.0.1", 9527)
  $client.ReceiveTimeout = 30000
  $stream = $client.GetStream()
  $bytes = [System.Text.Encoding]::UTF8.GetBytes($req + "`n")
  $stream.Write($bytes, 0, $bytes.Length)
  $stream.Flush()

  $all = [System.Collections.Generic.List[byte]]::new()
  $buf = New-Object byte[] 8192
  $deadline = (Get-Date).AddSeconds(30)
  while ((Get-Date) -lt $deadline) {
    if ($stream.DataAvailable) {
      $n = $stream.Read($buf, 0, $buf.Length)
      if ($n -eq 0) { break }
      for ($i = 0; $i -lt $n; $i++) { $all.Add($buf[$i]) }
      $s = [System.Text.Encoding]::UTF8.GetString($all.ToArray())
      if ($s.Contains("complete")) { break }
    }
    else { Start-Sleep -Milliseconds 200 }
  }
  [System.IO.File]::WriteAllBytes(
    "d:\360安全浏览器下载\软件开发备份\网络安全漏洞扫描\NetSecurityScanner\_engine_bytes.bin",
    $all.ToArray())

  Write-Host "总字节数: $($all.Count)"
  # 逗号(0x2C)数量
  $commaCount = ($all.ToArray() | Where-Object { $_ -eq 0x2C }).Count
  Write-Host "ASCII逗号(0x2C)字节数: $commaCount"
  Write-Host "换行数: " + ($all.ToArray() | Where-Object { $_ -eq 0x0A }).Count

  # 严格逐行解析
  $raw = [System.Text.Encoding]::UTF8.GetString($all.ToArray())
  $lines = $raw -split "`n" | Where-Object { $_.Trim().Length -gt 0 }
  foreach ($line in $lines) {
    try {
      $doc = [System.Text.Json.JsonDocument]::Parse($line)
      Write-Host "PARSE_OK type=$($doc.RootElement.GetProperty('type').GetString()) len=$($line.Length)"
    }
    catch {
      Write-Host "PARSE_FAIL len=$($line.Length) sample=$($line.Substring(0, [Math]::Min(100, $line.Length)))"
    }
  }
}
catch {
  Write-Host "ERROR: $($_.Exception.Message)"
}
finally {
  $client.Close()
}