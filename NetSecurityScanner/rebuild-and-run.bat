@echo off
chcp 65001 >nul
echo ========================================
echo   Rebuild + Run v1.0.2.1
echo ========================================

cd /d "%~dp0"

set PROJ=%~dp0src\NetSecurityScanner.Desktop\NetSecurityScanner.Desktop.csproj
set OUT=%~dp0publish-v1.0.2.1

echo [1/3] Cleaning old output...
if exist "%OUT%" rmdir /s /q "%OUT%"

echo [2/3] Publishing...
echo Project: %PROJ%
echo Output: %OUT%

dotnet publish "%PROJ%" ^
    -c Release ^
    -r win-x64 ^
    --self-contained true ^
    -p:PublishSingleFile=false ^
    -p:IncludeNativeLibrariesForSelfExtract=true ^
    -p:AssemblyVersion=1.0.2.1 ^
    -p:FileVersion=1.0.2.1 ^
    -p:Version=1.0.2.1 ^
    -o "%OUT%"

if errorlevel 1 (
    echo.
    echo FAILED TO PUBLISH
    pause
    exit /b 1
)

echo.
echo [3/3] Starting program...
set EXE=%OUT%\NetSecurityScanner.Desktop.exe
if exist "%EXE%" (
    echo Starting: %EXE%
    cd /d "%OUT%"
    start "" "%EXE%"
    echo.
    echo Program started! Please check your desktop.
) else (
    echo EXE not found!
)
pause