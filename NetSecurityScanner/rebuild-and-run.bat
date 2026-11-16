@echo off
chcp 65001 >nul
title Rebuild + Run NetSecurityScanner
cd /d "%~dp0"

rem 统一委托给 rebuild-and-run.ps1 执行，避免两套脚本版本号/参数不一致
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0rebuild-and-run.ps1"
if errorlevel 1 (
    echo.
    echo [ERROR] 重新发布失败，请查看上方日志
    pause
    exit /b 1
)
exit /b 0