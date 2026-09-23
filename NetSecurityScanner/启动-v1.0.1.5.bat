@echo off
chcp 65001 >nul
title NetSecurityScanner v1.0.1.5 启动器
color 0B

echo ============================================
echo   NetSecurityScanner v1.0.1.5 - 启动中...
echo ============================================
echo.

cd /d "%~dp0publish-v1.0.1.5-new"

if exist "NetSecurityScanner.Desktop.exe" (
    echo [√] 找到主程序文件
    echo [*] 正在启动 NetSecurityScanner.Desktop.exe ...
    echo.
    start "" "NetSecurityScanner.Desktop.exe"
    echo [√] 程序已启动！
    echo.
    echo 提示：如果窗口没有自动弹出，请查看任务栏或系统托盘
) else (
    echo [×] 错误：未找到 NetSecurityScanner.Desktop.exe
    echo.
    echo 请检查 publish-v1.0.1.5-new 目录是否存在
)

echo.
timeout /t 3 >nul
exit