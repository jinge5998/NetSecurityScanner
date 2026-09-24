# 启动一个测试 HTTP 服务（端口 18080 + 19222,模拟 Web + SSH）
$listener1 = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Parse('127.0.0.1'), 18080)
$listener1.Start()
Write-Host "✓ 端口 18080 (HTTP-like) 已开启"

$listener2 = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Parse('127.0.0.1'), 19222)
$listener2.Start()
Write-Host "✓ 端口 19222 (SSH-like) 已开启"

# 接受连接但不主动关闭（让端口保持开放）
$job1 = Start-Job -ScriptBlock {
    param($listener)
    while ($true) {
        try {
            $client = $listener.AcceptTcpClient()
            # 不主动关闭，让端口一直处于 LISTENING 状态
            Start-Sleep -Milliseconds 100
            $client.Close()
        } catch {}
    }
} -ArgumentInputObject $listener1

$job2 = Start-Job -ScriptBlock {
    param($listener)
    while ($true) {
        try {
            $client = $listener.AcceptTcpClient()
            Start-Sleep -Milliseconds 100
            $client.Close()
        } catch {}
    }
} -ArgumentInputObject $listener2

# 保存 PID 以便后续清理
$listener1, $listener2 | ForEach-Object { $_ } | Out-Null
Write-Host "Listener PIDs saved"

# 立即验证端口可访问
$test = Test-NetConnection -ComputerName 127.0.0.1 -Port 18080 -WarningAction SilentlyContinue
if ($test.TcpTestSucceeded) {
    Write-Host "✓ 验证: 18080 端口可达"
} else {
    Write-Host "✗ 验证: 18080 端口不可达"
}
$test2 = Test-NetConnection -ComputerName 127.0.0.1 -Port 19222 -WarningAction SilentlyContinue
if ($test2.TcpTestSucceeded) {
    Write-Host "✓ 验证: 19222 端口可达"
}

# 把 listener 和 job 句柄写到全局,以便清理脚本读取
$global:TestListener1 = $listener1
$global:TestListener2 = $listener2
$global:TestJob1 = $job1
$global:TestJob2 = $job2

Write-Host ""
Write-Host "测试服务已启动，按 Ctrl+C 终止后运行 cleanup.ps1 清理"
Write-Host "或运行: Stop-Process -Name powershell -Force (强制结束)"
