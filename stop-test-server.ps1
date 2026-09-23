# 清理测试服务
if ($global:TestListener1) { $global:TestListener1.Stop() }
if ($global:TestListener2) { $global:TestListener2.Stop() }
if ($global:TestJob1) { Stop-Job $global:TestJob1 -ErrorAction SilentlyContinue; Remove-Job $global:TestJob1 -Force -ErrorAction SilentlyContinue }
if ($global:TestJob2) { Stop-Job $global:TestJob2 -ErrorAction SilentlyContinue; Remove-Job $global:TestJob2 -Force -ErrorAction SilentlyContinue }
Write-Host "✓ 测试服务已停止"
