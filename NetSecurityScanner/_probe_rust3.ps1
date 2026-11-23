# 保存引擎真实响应到文件，用 .NET 严格解析验证每行
$ErrorActionPreference = "Stop"
$outPath = "d:\360安全浏览器下载\软件开发备份\网络安全漏洞扫描\NetSecurityScanner\_engine_raw_response.txt"

$client = [System.Net.Sockets.TcpClient]::new()
try {
  $client.Connect("127.0.0.1", 9527)
  $req = @{
    request_id     = "probe3-" + [guid]::NewGuid().ToString("N").Substring(0, 8)
    message_type   = "scan"
    targets        = @("127.0.0.1")
    ports          = @(3389)
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
  [System.IO.File]::WriteAllText($outPath, $raw, [System.Text.Encoding]::UTF8)
  Write-Host "saved to $outPath ($($all.Count) bytes)"

  # .NET 严格解析逐行
  $lines = $raw -split "`n" | Where-Object { $_.Trim().Length -gt 0 }
  for ($i = 0; $i -lt $lines.Count; $i++) {
    $line = $lines[$i].Trim()
    try {
      $doc = [System.Text.Json.JsonDocument]::Parse($line)
      $type = $doc.RootElement.GetProperty("type").GetString()
      Write-Host "[line $i] STRICT_PARSE_OK type=$type"
    }
    catch {
      Write-Host "[line $i] STRICT_PARSE_FAIL len=$($line.Length) first80=$($line.Substring(0, [Math]::Min(80, $line.Length)))"
    }
  }
}
catch {
  Write-Host "ERROR: $_"
}
finally {
  $client.Close()
}