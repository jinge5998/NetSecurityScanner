# NetSecurityScanner.Desktop 发行版打包脚本
# 自包含模式，无需目标电脑安装 .NET 运行时
# -NoPrompt: 非交互模式，跳过最后的运行确认与暂停（便于 CI/自动化调用）

param(
    [switch]$NoPrompt
)

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  NetSecurityScanner.Desktop 打包工具" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

$projectPath = "$PSScriptRoot\src\NetSecurityScanner.Desktop\NetSecurityScanner.Desktop.csproj"

# 版本号自动探测并自增：避免硬编码旧路径，也防止误删当前正在使用的发布目录
$latestVersion = $null
Get-ChildItem -Path "$PSScriptRoot" -Directory -Filter 'publish-v*' | ForEach-Object {
    $verText = $_.Name -replace '^publish-v', ''
    $parsed = $null
    if ([version]::TryParse($verText, [ref]$parsed)) {
        if ($null -eq $latestVersion -or $parsed -gt $latestVersion) { $latestVersion = $parsed }
    }
}
if ($null -eq $latestVersion) {
    $latestVersion = [version]'1.0.0.0'
}
$parts = @($latestVersion.Major, $latestVersion.Minor, $latestVersion.Build, $latestVersion.Revision)
$parts[3] = $parts[3] + 1
$publishVersion = [version]($parts -join '.')

$outputPath = "$PSScriptRoot\publish-v$publishVersion"

# 清理旧输出
Write-Host "[1/6] 清理旧输出..." -ForegroundColor Yellow
if (Test-Path $outputPath) {
    Remove-Item -Path $outputPath -Recurse -Force -ErrorAction SilentlyContinue
    Write-Host "已删除旧输出目录" -ForegroundColor Gray
}

# 编译并打包
Write-Host "[2/6] 编译并打包 Desktop 项目..." -ForegroundColor Yellow
Write-Host "项目: $projectPath" -ForegroundColor Gray
Write-Host "输出: $outputPath" -ForegroundColor Gray
Write-Host ""

& dotnet publish "$projectPath" `
    -c Release `
    -r win-x64 `
    --self-contained true `
    -p:PublishSingleFile=false `
    -p:IncludeNativeLibrariesForSelfExtract=true `
    -p:AssemblyVersion=$publishVersion `
    -p:FileVersion=$publishVersion `
    -p:Version=$publishVersion `
    -o $outputPath

if ($LASTEXITCODE -ne 0) {
    Write-Host ""
    Write-Host "❌ 打包失败!" -ForegroundColor Red
    Write-Host ""
    if (-not $NoPrompt) { Read-Host "按 Enter 键退出" }
    exit 1
}

Write-Host ""
Write-Host "[3/6] 打包 Rust 扫描引擎..." -ForegroundColor Yellow

$engineSrc = Join-Path $PSScriptRoot "src\rust-scanner-service\target\release\rust-scanner-service.exe"
if (-not (Test-Path $engineSrc)) {
    Write-Host "未找到引擎二进制，尝试使用 cargo 构建..." -ForegroundColor Gray
    Push-Location (Join-Path $PSScriptRoot "src\rust-scanner-service")
    & cargo build --release
    Pop-Location
}

if (Test-Path $engineSrc) {
    Copy-Item $engineSrc (Join-Path $outputPath "rust-scanner-service.exe") -Force
    Write-Host "已复制 rust-scanner-service.exe 到发布目录" -ForegroundColor Gray
}
else {
    Write-Host "⚠️ 未能获取 rust-scanner-service.exe，专家模式将降级到内置 C# 扫描器" -ForegroundColor Yellow
}

Write-Host ""
Write-Host "[4/6] 验证输出文件..." -ForegroundColor Yellow

$exePath = Join-Path $outputPath "NetSecurityScanner.Desktop.exe"

if (Test-Path $exePath) {
    $fileInfo = Get-Item $exePath
    $totalFiles = (Get-ChildItem -Path $outputPath -Recurse -File).Count
    $totalSize = (Get-ChildItem -Path $outputPath -Recurse -File | Measure-Object -Property Length -Sum).Sum / 1MB

    Write-Host ""
    Write-Host "========================================" -ForegroundColor Green
    Write-Host "  ✅ 打包成功!" -ForegroundColor Green
    Write-Host "========================================" -ForegroundColor Green
    Write-Host ""
    Write-Host "📦 可执行文件:" -ForegroundColor Cyan
    Write-Host "   $exePath" -ForegroundColor White
    Write-Host ""
    Write-Host "📊 打包统计:" -ForegroundColor Cyan
    Write-Host "   文件总数: $totalFiles 个" -ForegroundColor White
    Write-Host "   总大小: $([math]::Round($totalSize, 2)) MB" -ForegroundColor White
    Write-Host "   主程序大小: $([math]::Round($fileInfo.Length / 1MB, 2)) MB" -ForegroundColor White
    Write-Host ""
    Write-Host "💡 使用说明:" -ForegroundColor Yellow
    Write-Host "   1. 复制整个 '$outputPath' 文件夹到目标电脑" -ForegroundColor Gray
    Write-Host "   2. 无需安装 .NET 运行时，已包含所有依赖" -ForegroundColor Gray
    Write-Host "   3. 直接运行 NetSecurityScanner.Desktop.exe 即可" -ForegroundColor Gray
    Write-Host ""

    $response = if ($NoPrompt) { "N" } else { Read-Host "是否立即运行程序? (Y/N)" }

    if ($response -eq "Y" -or $response -eq "y") {
        Write-Host ""
        Write-Host "正在启动程序..." -ForegroundColor Green
        Start-Process $exePath
        Write-Host "程序已启动!" -ForegroundColor Green
    }
}
else {
    Write-Host ""
    Write-Host "❌ 打包失败: 未找到输出文件!" -ForegroundColor Red
}

Write-Host ""
if (-not $NoPrompt) { Read-Host "按 Enter 键退出" }