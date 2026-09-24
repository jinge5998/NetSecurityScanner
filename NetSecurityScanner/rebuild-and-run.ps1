# Rebuild and Run v1.0.2.1
$ErrorActionPreference = "Stop"

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $scriptDir

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  Rebuild + Run v1.0.2.1" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan

$projPath = Join-Path $scriptDir "src\NetSecurityScanner.Desktop\NetSecurityScanner.Desktop.csproj"
$outDir = Join-Path $scriptDir "publish-v1.0.2.1"

Write-Host "[1/3] Cleaning old output..." -ForegroundColor Yellow
if (Test-Path $outDir) {
    Remove-Item -Path $outDir -Recurse -Force -ErrorAction SilentlyContinue
    Write-Host "  Cleaned." -ForegroundColor Gray
}

Write-Host "[2/3] Publishing..." -ForegroundColor Yellow
Write-Host "  Project: $projPath"
Write-Host "  Output:  $outDir"

& dotnet publish $projPath `
    -c Release `
    -r win-x64 `
    --self-contained true `
    -p:PublishSingleFile=false `
    -p:IncludeNativeLibrariesForSelfExtract=true `
    -p:AssemblyVersion=1.0.2.1 `
    -p:FileVersion=1.0.2.1 `
    -p:Version=1.0.2.1 `
    -o $outDir

if ($LASTEXITCODE -ne 0) {
    Write-Host "`n❌ PUBLISH FAILED!" -ForegroundColor Red
    exit 1
}

Write-Host "`n[3/3] Verifying output..." -ForegroundColor Yellow
$exe = Join-Path $outDir "NetSecurityScanner.Desktop.exe"
if (-not (Test-Path $exe)) {
    Write-Host "❌ EXE not found: $exe" -ForegroundColor Red
    exit 1
}

$fi = Get-Item $exe
Write-Host "  EXE: $exe" -ForegroundColor Green
Write-Host "  Size: $([math]::Round($fi.Length / 1MB, 2)) MB" -ForegroundColor Green
Write-Host "  Modified: $($fi.LastWriteTime)" -ForegroundColor Green

Write-Host "`n✅ Build complete! Starting application..." -ForegroundColor Green
Start-Process -FilePath $exe -WorkingDirectory $outDir
Write-Host "  Application launched successfully!" -ForegroundColor Green