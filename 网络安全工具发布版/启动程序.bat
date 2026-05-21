@echo off
chcp 65001 >nul
color 0a
title 网络安全漏洞扫描工具

echo ============================================================
echo              网络安全漏洞扫描工具 v1.0
echo ============================================================
echo.
echo [提示] 正在启动程序...
echo [提示] 首次启动可能需要几秒钟加载...
echo.

cd /d "%~dp0"
start "" "NetSecurityScanner.exe"

echo [成功] 程序已启动，正在运行中...
echo [提示] 关闭此窗口不会影响程序运行
echo.
timeout /t 3 /nobreak >nul
exit
