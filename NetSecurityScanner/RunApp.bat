@echo off
title Starting NetSecurityScanner
cd /d "%~dp0"

rem 自动探测最新的 publish-v1.0.x 发布目录，避免版本升级后路径失效
rem 版本号提取使用 Substring(9)（跳过 "publish-v" 前缀），避免正则中单引号转义陷阱
set "PUBDIR="
for /f "usebackq delims=" %%D in (`powershell -NoProfile -ExecutionPolicy Bypass -Command "(Get-ChildItem -Directory -Filter 'publish-v1.0.*' | Where-Object { Test-Path (Join-Path $_.FullName 'NetSecurityScanner.Desktop.exe') } | Sort-Object { [version]($_.Name.Substring(9)) } -Descending | Select-Object -First 1).FullName"`) do set "PUBDIR=%%D"

if not defined PUBDIR (
    echo [ERROR] 未找到可运行的 publish-v1.0.x 发布目录
    echo 请先执行 rebuild-and-run.bat 重新发布
    pause
    exit /b 1
)

echo Starting: %PUBDIR%\NetSecurityScanner.Desktop.exe
start "" "%PUBDIR%\NetSecurityScanner.Desktop.exe"
exit /b 0