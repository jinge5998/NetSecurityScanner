[Console]::OutputEncoding = [System.Text.Encoding]::UTF8

Set-Location 'd:\360安全浏览器下载\软件开发备份\网络安全漏洞扫描\NetSecurityScanner\publish-v1.0.1.5'
$exe = '.\NetSecurityScanner.Desktop.exe'

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

# Launch
$proc = Start-Process -FilePath $exe -PassThru
Write-Host "Launched PID: $($proc.Id)"
Start-Sleep -Seconds 4

# Find by process main window title
$proc.Refresh()
$title = $proc.MainWindowTitle
Write-Host "Title: $title"

if ([string]::IsNullOrEmpty($title)) {
    # Try finding any process
    Get-Process -Id $proc.Id | Format-List Id, ProcessName, MainWindowTitle, MainWindowHandle
    $title = "网络安全扫描工具"
}

$hwnd = [Win32]::FindWindow($null, $title)
if ($hwnd -eq [IntPtr]::Zero) {
    Write-Host "Window not found, trying again" -ForegroundColor Yellow
    Start-Sleep -Seconds 2
    $hwnd = [Win32]::FindWindow($null, $title)
}

if ($hwnd -eq [IntPtr]::Zero) {
    Write-Host "Failed to find window" -ForegroundColor Red
    exit 1
}

Write-Host "HWND: $hwnd"
[Win32]::ShowWindow($hwnd, 9) | Out-Null
[Win32]::ShowWindow($hwnd, 3) | Out-Null  # SW_MAXIMIZE = 3
[Win32]::MoveWindow($hwnd, 0, 0, 1600, 900, $true) | Out-Null
[Win32]::SetForegroundWindow($hwnd) | Out-Null
Start-Sleep -Milliseconds 2000

$rect = New-Object Win32+RECT
[Win32]::GetWindowRect($hwnd, [ref]$rect) | Out-Null
$w = $rect.Right - $rect.Left
$h = $rect.Bottom - $rect.Top
Write-Host "Window: ${w}x${h} @ ($($rect.Left),$($rect.Top))"

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
