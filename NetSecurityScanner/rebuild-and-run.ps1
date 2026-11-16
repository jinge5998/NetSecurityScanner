# 重新发布并运行 NetSecurityScanner.Desktop
# 版本号自动从现有 publish-v* 目录探测并自增补丁号，无需手工维护
$ErrorActionPreference = "Stop"

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $scriptDir

function Get-NextVersion {
    $latest = $null
    Get-ChildItem -Directory -Filter 'publish-v*' | ForEach-Object {
        $verText = $_.Name -replace '^publish-v', ''
        $parsed = $null
        if ([version]::TryParse($verText, [ref]$parsed)) {
            if ($null -eq $latest -or $parsed -gt $latest) { $latest = $parsed }
        }
    }
    if ($null -eq $latest) {
        return [version]'1.0.0.0'
    }
    $parts = @($latest.Major, $latest.Minor, $latest.Build, $latest.Revision)
    $parts[3] = $parts[3] + 1
    return [version]($parts -join '.')
}

$version = Get-NextVersion
$versionText = $version.ToString()

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  Rebuild + Run v$versionText" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan

$projPath = Join-Path $scriptDir "src\NetSecurityScanner.Desktop\NetSecurityScanner.Desktop.csproj"
$outDir = Join-Path $scriptDir "publish-v$versionText"

if (-not (Test-Path $projPath)) {
    Write-Host "❌ 未找到项目文件: $projPath" -ForegroundColor Red
    exit 1
}

Write-Host "[1/4] Publishing (self-contained, no clean)..." -ForegroundColor Yellow
Write-Host "  Project: $projPath"
Write-Host "  Output:  $outDir"

& dotnet publish $projPath `
    -c Release `
    -r win-x64 `
    --self-contained true `
    -p:PublishSingleFile=false `
    -p:IncludeNativeLibrariesForSelfExtract=true `
    -p:AssemblyVersion=$versionText `
    -p:FileVersion=$versionText `
    -p:Version=$versionText `
    -o $outDir

if ($LASTEXITCODE -ne 0) {
    Write-Host "`n❌ PUBLISH FAILED!" -ForegroundColor Red
    exit 1
}

Write-Host "`n[2/4] Verifying output..." -ForegroundColor Yellow
$exe = Join-Path $outDir "NetSecurityScanner.Desktop.exe"
if (-not (Test-Path $exe)) {
    Write-Host "❌ EXE not found: $exe" -ForegroundColor Red
    exit 1
}

$fi = Get-Item $exe
Write-Host "  EXE:      $exe" -ForegroundColor Green
Write-Host "  Size:     $([math]::Round($fi.Length / 1MB, 2)) MB" -ForegroundColor Green
Write-Host "  Modified: $($fi.LastWriteTime)" -ForegroundColor Green

Write-Host "`n[3/4] Bundling Rust engine..." -ForegroundColor Yellow
$engineSrc = Join-Path $scriptDir "src\rust-scanner-service\target\release\rust-scanner-service.exe"
$engineDst = Join-Path $outDir "rust-scanner-service.exe"

if (-not (Test-Path $engineSrc)) {
    Write-Host "  Engine binary not found, building with cargo..." -ForegroundColor Gray
    Push-Location (Join-Path $scriptDir "src\rust-scanner-service")
    & cargo build --release
    Pop-Location
}

if (Test-Path $engineSrc) {
    Copy-Item $engineSrc $engineDst -Force
    $ei = Get-Item $engineDst
    Write-Host "  Engine:   $engineDst ($([math]::Round($ei.Length / 1MB, 2)) MB, $($ei.LastWriteTime))" -ForegroundColor Green
}
else {
    Write-Host "  ⚠️ rust-scanner-service.exe 缺失，专家模式将降级到内置 C# 扫描器" -ForegroundColor Yellow
}

Write-Host "`n[4/4] Starting application..." -ForegroundColor Yellow
Start-Process -FilePath $exe -WorkingDirectory $outDir
Write-Host "  ✅ Application launched: $exe" -ForegroundColor Green
Write-Host "`nDone. Version: v$versionText" -ForegroundColor Cyan