[Console]::OutputEncoding = [System.Text.Encoding]::UTF8

Add-Type @"
using System;
using System.Runtime.InteropServices;
public class Win32 {
    [DllImport("user32.dll")] public static extern IntPtr FindWindow(string lpClassName, string lpWindowName);
    [DllImport("user32.dll")] public static extern bool SetForegroundWindow(IntPtr hWnd);
    [DllImport("user32.dll")] public static extern bool ShowWindow(IntPtr hWnd, int nCmdShow);
    [DllImport("user32.dll")] public static extern bool GetWindowRect(IntPtr hWnd, out RECT lpRect);
    [DllImport("user32.dll")] public static extern bool PrintWindow(IntPtr hwnd, IntPtr hdcBlt, uint nFlags);
    [StructLayout(LayoutKind.Sequential)]
    public struct RECT { public int Left, Top, Right, Bottom; }
}
"@

$hwnd = [Win32]::FindWindow($null, "网络安全扫描工具")
if ($hwnd -eq [IntPtr]::Zero) {
    Write-Host "Window not found" -ForegroundColor Red
    exit
}
Write-Host "Window handle: $hwnd"

# Restore if minimized (SW_RESTORE = 9), then show (SW_SHOW = 5)
[Win32]::ShowWindow($hwnd, 9) | Out-Null
[Win32]::ShowWindow($hwnd, 5) | Out-Null
[Win32]::SetForegroundWindow($hwnd) | Out-Null
Start-Sleep -Milliseconds 1500

# Get window rect
$rect = New-Object Win32+RECT
[Win32]::GetWindowRect($hwnd, [ref]$rect) | Out-Null
$w = $rect.Right - $rect.Left
$h = $rect.Bottom - $rect.Top
Write-Host "Window: $w x $h @ ($($rect.Left),$($rect.Top))"

# Capture window using PrintWindow for proper rendering
Add-Type -AssemblyName System.Drawing
$bmp = New-Object System.Drawing.Bitmap $w, $h
$g = [System.Drawing.Graphics]::FromImage($bmp)
$hdc = $g.GetHdc()
$ok = [Win32]::PrintWindow($hwnd, $hdc, 2)  # PW_RENDERFULLCONTENT = 2
$g.ReleaseHdc($hdc)
Write-Host "PrintWindow: $ok"

$out = Join-Path $env:TEMP ("app_" + (Get-Date -Format "yyyyMMdd_HHmmss") + ".png")
$bmp.Save($out, [System.Drawing.Imaging.ImageFormat]::Png)
$g.Dispose()
$bmp.Dispose()
Write-Host "Saved: $out"
