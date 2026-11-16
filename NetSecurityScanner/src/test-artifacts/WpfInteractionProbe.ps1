
# WPF 交互探针（手动运行）
$ErrorActionPreference = 'Stop'
$exe = Join-Path $PSScriptRoot '..\NetSecurityScanner\src\NetSecurityScanner.Desktop\bin\Release\net6.0-windows\NetSecurityScanner.Desktop.exe'
if (-not (Test-Path $exe)) { Write-Host "❌ 未找到 WPF 可执行文件: $exe" -ForegroundColor Red; exit 1 }

Write-Host "启动 WPF 应用..." -ForegroundColor Cyan
$proc = Start-Process $exe -PassThru
Start-Sleep -Seconds 5
if ($proc.HasExited) { Write-Host "❌ 进程已退出" -ForegroundColor Red; exit 2 }
if ($proc.Responding) { Write-Host "✅ 进程响应中 (PID=$($proc.Id))" -ForegroundColor Green } else { Write-Host "❌ 进程无响应" -ForegroundColor Red }

Write-Host "截图保存中..." -ForegroundColor Cyan
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing
$screen = [System.Windows.Forms.Screen]::PrimaryScreen.Bounds
$bitmap = New-Object System.Drawing.Bitmap $screen.Width, $screen.Height
$graphics = [System.Drawing.Graphics]::FromImage($bitmap)
$graphics.CopyFromScreen($screen.Location, [System.Drawing.Point]::Empty, $screen.Size)
$out = Join-Path $PSScriptRoot 'main-window.png'
$bitmap.Save($out)
Write-Host "✅ 截图已保存: $out" -ForegroundColor Green

Write-Host "关闭 WPF..." -ForegroundColor Cyan
Stop-Process -Id $proc.Id -Force
Write-Host "✅ 完成" -ForegroundColor Green
