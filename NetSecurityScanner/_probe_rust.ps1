# 探测 rust-scanner-service 响应能力
# 发送 snake_case 扫描请求并等待响应（最长 30 秒）
$ErrorActionPreference = "Stop"

$client = [System.Net.Sockets.TcpClient]::new()
try {
    $client.Connect("127.0.0.1", 9527)
    Write-Host "connected"

    $req = @{
        request_id    = "probe-" + [guid]::NewGuid().ToString("N").Substring(0,8)
        message_type  = "scan"
        targets       = @("127.0.0.1")
        ports         = @(80, 443, 3389)
        protocol      = "tcp"
        concurrency   = 100
        tcp_timeout_ms = 500
        udp_timeout_ms = 1000
        detect_service = $true
        include_closed = $false
    } | ConvertTo-Json -Depth 5 -Compress

    $stream = $client.GetStream()
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($req + "`n")
    $stream.Write($bytes, 0, $bytes.Length)
    $stream.Flush()
    Write-Host "request sent"

    $buffer = New-Object byte[] 4096
    $sb = [System.Text.StringBuilder]::new()
    $deadline = (Get-Date).AddSeconds(30)
    while ((Get-Date) -lt $deadline) {
        if (-not $stream.DataAvailable) {
            Start-Sleep -Milliseconds 200
            continue
        }
        $n = $stream.Read($buffer, 0, $buffer.Length)
        if ($n -eq 0) {
            Write-Host "EOF (stream closed)"
            break
        }
        [void]$sb.Append([System.Text.Encoding]::UTF8.GetString($buffer, 0, $n))
        $text = $sb.ToString()
        if ($text.Contains("complete") -or $text.Contains('"type":"Error"') -or $text.Contains('"type": "Error"')) {
            break
        }
    }
    Write-Host "=== received ==="
    Write-Host $sb.ToString()
} catch {
    Write-Host "ERROR: $_"
} finally {
    $client.Close()
}
Write-Host "probe done"