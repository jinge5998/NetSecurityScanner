# NetSecurityScanner 构建 / 发布脚本（手动模式）
#
# 默认（无参数）：仅编译 dotnet build，不修改版本号、不打包、不启动。
# 打包：必须显式 -Publish 并配合 -Version x.y.z.w 手动指定版本号（不再自动自增）。
# 启动：必须显式 -Run 才启动应用。
#
# 示例：
#   .\rebuild-and-run.ps1                          # 只编译，验证代码能过
#   .\rebuild-and-run.ps1 -Publish -Version 1.0.4.0  # 手动发布 v1.0.4.0
#   .\rebuild-and-run.ps1 -Run                     # 启动最近一次发布版本
[CmdletBinding()]
param(
    [switch]$Publish,
    [string]$Version,
    [switch]$Run
)

$ErrorActionPreference = "Stop"
$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $scriptDir

$projPath = Join-Path $scriptDir "src\NetSecurityScanner.Desktop\NetSecurityScanner.Desktop.csproj"
if (-not (Test-Path $projPath)) {
    Write-Host "未找到项目文件: $projPath" -ForegroundColor Red
    exit 1
}

# ---------- 默认：仅编译 ----------
if (-not $Publish -and -not $Run) {
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host "  Build only（不打包 / 不改版本号）" -ForegroundColor Cyan
    Write-Host "========================================" -ForegroundColor Cyan
    & dotnet build $projPath -c Release -v minimal --nologo
    if ($LASTEXITCODE -ne 0) {
        Write-Host "`nBUILD FAILED" -ForegroundColor Red
        exit 1
    }
    Write-Host "`nBuild OK。如需发布请手动执行: .\rebuild-and-run.ps1 -Publish -Version x.y.z.w" -ForegroundColor Cyan
    exit 0
}

# ---------- 打包：必须手动指定版本号 ----------
$outDir = $null
$exe = $null

if ($Publish) {
    if ([string]::IsNullOrWhiteSpace($Version)) {
        Write-Host "手动模式：打包必须显式指定版本号，例如 -Version 1.0.4.0" -ForegroundColor Red
        Write-Host "脚本不再自动探测/自增版本号。" -ForegroundColor Yellow
        exit 1
    }
    $parsed = $null
    if (-not [version]::TryParse($Version, [ref]$parsed)) {
        Write-Host "版本号格式无效: $Version（应为 x.y.z.w，如 1.0.4.0）" -ForegroundColor Red
        exit 1
    }
    $versionText = $parsed.ToString()
    $outDir = Join-Path $scriptDir "publish-v$versionText"

    if (Test-Path $outDir) {
        Write-Host "目标目录已存在: $outDir" -ForegroundColor Red
        Write-Host "为避免覆盖历史发布包，请换一个版本号，或手动处理该目录后重试。" -ForegroundColor Yellow
        exit 1
    }

    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host "  Publish v$versionText（手动指定版本）" -ForegroundColor Cyan
    Write-Host "========================================" -ForegroundColor Cyan

    Write-Host "[1/4] Publishing (self-contained)..." -ForegroundColor Yellow
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
        Write-Host "`nPUBLISH FAILED" -ForegroundColor Red
        exit 1
    }

    Write-Host "`n[2/4] Verifying output..." -ForegroundColor Yellow
    $exe = Join-Path $outDir "NetSecurityScanner.Desktop.exe"
    if (-not (Test-Path $exe)) {
        Write-Host "EXE not found: $exe" -ForegroundColor Red
        exit 1
    }
    $fi = Get-Item $exe
    Write-Host "  EXE:      $exe" -ForegroundColor Green
    Write-Host "  Size:     $([math]::Round($fi.Length / 1MB, 2)) MB" -ForegroundColor Green
    Write-Host "  Modified: $($fi.LastWriteTime)" -ForegroundColor Green

    Write-Host "`n[2.5/4] Bundling nmap toolset..." -ForegroundColor Yellow
    $nmapSrc = Join-Path $scriptDir "tools\nmap"
    $nmapDst = Join-Path $outDir "tools\nmap"
    $nmapExe = Join-Path $nmapDst "nmap.exe"

    # 只排除构建期产物（安装器/源码包），数据文件全部保留
    $nmapExcludes = @('*.tar.bz2', '*.tar.gz', '*.tar.xz', '*.zip', '*setup*.exe', '*.lnk', '*.reg', 'ZENMAP_README')

    if (Test-Path (Join-Path $nmapSrc "nmap.exe")) {
        New-Item -ItemType Directory -Path $nmapDst -Force | Out-Null
        Get-ChildItem $nmapSrc -Force | Where-Object {
            $name = $_.Name
            $skip = $false
            foreach ($pat in $nmapExcludes) { if ($name -like $pat) { $skip = $true; break } }
            -not $skip
        } | ForEach-Object {
            if ($_.PSIsContainer) { Copy-Item $_.FullName $nmapDst -Recurse -Force }
            else { Copy-Item $_.FullName $nmapDst -Force }
        }
        Write-Host "  Copied nmap toolset (build artifacts excluded)" -ForegroundColor Green
    }
    else {
        Write-Host "  nmap toolset 缺失（tools\nmap\nmap.exe），nmap 引擎将不可用" -ForegroundColor Yellow
    }

    if (Test-Path $nmapExe) {
        $nmapFiles = Get-ChildItem $nmapDst -Recurse -File
        $nmapSizeMB = [math]::Round(($nmapFiles | Measure-Object Length -Sum).Sum / 1MB, 2)
        Write-Host "  nmap:     $nmapDst ($($nmapFiles.Count) files, $nmapSizeMB MB)" -ForegroundColor Green

        # 数据文件完整性校验（清单取自官方 nmap 仓库 Makefile.in 的 nmapdatadir）
        $nmapDataFiles = @(
            'nmap-services', 'nmap-rpc', 'nmap-os-db', 'nmap-service-probes',
            'nmap-protocols', 'nmap-mac-prefixes', 'nse_main.lua'
        )
        $missingData = @()
        foreach ($dataFile in $nmapDataFiles) {
            if (-not (Test-Path (Join-Path $nmapDst $dataFile))) { $missingData += $dataFile }
        }
        if (-not (Test-Path (Join-Path $nmapDst 'scripts'))) { $missingData += 'scripts/' }

        if ($missingData.Count -gt 0) {
            Write-Host "  nmap 数据文件缺失: $($missingData -join ', ')（扫描结果将不准确）" -ForegroundColor Red
        }
        else {
            Write-Host "  nmap data: $($nmapDataFiles.Count) 个数据文件 + scripts/ 全部就位" -ForegroundColor Green
        }
    }

    Write-Host "`n[2.6/4] Seeding .machine_id cache (保持跨发布版本授权不失效)..." -ForegroundColor Yellow
    # 命中 .machine_id 缓存即直接返回、不重算；播种已验证机器码避免指纹算法变化导致授权失效
    $seeded = $false
    $priorPublish = Get-ChildItem -Directory -Filter 'publish-v*' -ErrorAction SilentlyContinue |
        Where-Object { $_.FullName -ne $outDir -and (Test-Path (Join-Path $_.FullName '.machine_id')) } |
        Sort-Object LastWriteTime -Descending | Select-Object -First 1
    if ($priorPublish) {
        $srcId = (Get-Content (Join-Path $priorPublish.FullName '.machine_id') -Raw -ErrorAction SilentlyContinue).Trim()
        if ($srcId.Length -eq 32) {
            $dstFile = Join-Path $outDir '.machine_id'
            [System.IO.File]::WriteAllText($dstFile, $srcId, [System.Text.UTF8Encoding]::new($false))
            [System.IO.File]::SetAttributes($dstFile, [System.IO.FileAttributes]::Hidden -bor [System.IO.FileAttributes]::System -bor [System.IO.FileAttributes]::NotContentIndexed)
            Write-Host "  .machine_id seeded from $($priorPublish.Name): $srcId" -ForegroundColor Green
            $seeded = $true
        }
    }
    if (-not $seeded) {
        $recFile = Join-Path $env:LOCALAPPDATA 'NetSecurityScanner\licenseIssuer\issuance_records.json'
        if (Test-Path $recFile) {
            try {
                $recJson = Get-Content $recFile -Raw -ErrorAction Stop | ConvertFrom-Json
                $boundId = $recJson.Records | Where-Object { $_.MachineId -and $_.MachineId.Length -eq 32 } |
                    Select-Object -First 1 -ExpandProperty MachineId
                if ($boundId) {
                    $dstFile = Join-Path $outDir '.machine_id'
                    [System.IO.File]::WriteAllText($dstFile, $boundId, [System.Text.UTF8Encoding]::new($false))
                    [System.IO.File]::SetAttributes($dstFile, [System.IO.FileAttributes]::Hidden -bor [System.IO.FileAttributes]::System -bor [System.IO.FileAttributes]::NotContentIndexed)
                    Write-Host "  .machine_id seeded from license issuance records: $boundId" -ForegroundColor Green
                    $seeded = $true
                }
            }
            catch { Write-Host "  (issuance_records.json 解析失败: $($_.Exception.Message))" -ForegroundColor DarkGray }
        }
    }
    if (-not $seeded) {
        Write-Host "  无可用机器码缓存源，首次启动将自动生成（若与授权绑定机器码不一致需重新激活）" -ForegroundColor Yellow
    }

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
        Write-Host "  rust-scanner-service.exe 缺失，专家模式将降级到内置 C# 扫描器" -ForegroundColor Yellow
    }

    Write-Host "`nPublished: v$versionText -> $outDir" -ForegroundColor Cyan
}

# ---------- 启动：显式 -Run 才启动 ----------
if ($Run) {
    if (-not $exe) {
        # 未在本次打包，则启动最近一次手动发布的版本
        $latest = Get-ChildItem -Directory -Filter 'publish-v*' -ErrorAction SilentlyContinue |
            Sort-Object LastWriteTime -Descending | Select-Object -First 1
        if ($latest) { $exe = Join-Path $latest.FullName "NetSecurityScanner.Desktop.exe" }
    }
    if ($exe -and (Test-Path $exe)) {
        Write-Host "`n[4/4] Starting application..." -ForegroundColor Yellow
        Start-Process -FilePath $exe -WorkingDirectory (Split-Path $exe)
        Write-Host "  Application launched: $exe" -ForegroundColor Green
    }
    else {
        Write-Host "未找到可启动的发布版本，请先手动 -Publish。" -ForegroundColor Red
        exit 1
    }
}
