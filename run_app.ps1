$ErrorActionPreference = "Continue"
$exePath = "d:\360安全浏览器下载\软件开发备份\网络安全漏洞扫描\NetSecurityScanner\src\NetSecurityScanner.Desktop\bin\Debug\net6.0-windows\NetSecurityScanner.Desktop.exe"
Write-Host "Starting application..."
Write-Host "Exe path: $exePath"
Write-Host "Exists: $(Test-Path $exePath)"
$proc = Start-Process -FilePath $exePath -PassThru -NoNewWindow
Write-Host "Process started with PID: $($proc.Id)"
Write-Host "Waiting 3 seconds..."
Start-Sleep -Seconds 3
if (-not $proc.HasExited) {
  Write-Host "Application is running successfully!"
}
else {
  Write-Host "Application exited with code: $($proc.ExitCode)"
}