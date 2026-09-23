[Console]::OutputEncoding = [System.Text.Encoding]::UTF8

$ps1Dir = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $ps1Dir
$exe = Join-Path $ps1Dir 'NetSecurityScanner\publish-v1.0.1.5\NetSecurityScanner.Desktop.exe'
Write-Host "EXE: $exe"
if (-not (Test-Path $exe)) { Write-Host "EXE not found"; exit 1 }

Add-Type @"
using System;
using System.Runtime.InteropServices;
public class Win32 {
    [DllImport("user32.dll")] public static extern IntPtr FindWindow(string lpClassName, string lpWindowName);
    [DllImport("user32.dll")] public static extern bool SetForegroundWindow(IntPtr hWnd);
    [DllImport("user32.dll")] public static extern bool ShowWindow(IntPtr hWnd, int nCmdShow);
    [DllImport("user32.dll")] public static extern bool GetWindowRect(IntPtr hWnd, out RECT lpRect);
    [DllImport("user32.dll")] public static extern bool PrintWindow(IntPtr hwnd, IntPtr hdcBlt, uint nFlags);
    [DllImport("user32.dll")] public static extern bool MoveWindow(IntPtr hWnd, int X, int Y, int W, int H, bool bRepaint);
    [StructLayout(LayoutKind.Sequential)]
    public struct RECT { public int Left, Top, Right, Bottom; }
}
"@

$proc = Start-Process -FilePath $exe -PassThru
Write-Host "Launched PID: $($proc.Id)"
Start-Sleep -Seconds 5

$proc.Refresh()
$title = $proc.MainWindowTitle
Write-Host "Title: [$title]"

if ([string]::IsNullOrEmpty($title)) { $title = "网络安全扫描工具" }

$hwnd = [Win32]::FindWindow($null, $title)
if ($hwnd -eq [IntPtr]::Zero) {
    Write-Host "Window not found" -ForegroundColor Red
    exit 1
}

[Win32]::ShowWindow($hwnd, 9) | Out-Null
[Win32]::ShowWindow($hwnd, 3) | Out-Null
[Win32]::MoveWindow($hwnd, 0, 0, 1600, 900, $true) | Out-Null
[Win32]::SetForegroundWindow($hwnd) | Out-Null
Start-Sleep -Milliseconds 2000

$rect = New-Object Win32+RECT
[Win32]::GetWindowRect($hwnd, [ref]$rect) | Out-Null
$w = $rect.Right - $rect.Left
$h = $rect.Bottom - $rect.Top
Write-Host "Window: ${w}x${h}"

Add-Type -AssemblyName System.Drawing
$bmp = New-Object System.Drawing.Bitmap $w, $h
$g = [System.Drawing.Graphics]::FromImage($bmp)
$hdc = $g.GetHdc()
$ok = [Win32]::PrintWindow($hwnd, $hdc, 2)
$g.ReleaseHdc($hdc)
Write-Host "PrintWindow: $ok"

$out = Join-Path $env:TEMP ("app_main_" + (Get-Date -Format "yyyyMMdd_HHmmss") + ".png")
$bmp.Save($out, [System.Drawing.Imaging.ImageFormat]::Png)
$g.Dispose()
$bmp.Dispose()
Write-Host "Saved: $out"
