# NetSecurityScanner.Desktop 发行版打包脚本
# 自包含模式，无需目标电脑安装 .NET 运行时

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  NetSecurityScanner.Desktop 打包工具" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

$projectPath = "$PSScriptRoot\src\NetSecurityScanner.Desktop\NetSecurityScanner.Desktop.csproj"
$outputPath = "$PSScriptRoot\publish\NetSecurityScanner-v1.0.0.2"

# 清理旧输出
Write-Host "[1/5] 清理旧输出..." -ForegroundColor Yellow
if (Test-Path $outputPath) {
    Remove-Item -Path $outputPath -Recurse -Force -ErrorAction SilentlyContinue
    Write-Host "已删除旧输出目录" -ForegroundColor Gray
}

# 编译并打包
Write-Host "[2/5] 编译并打包 Desktop 项目..." -ForegroundColor Yellow
Write-Host "项目: $projectPath" -ForegroundColor Gray
Write-Host "输出: $outputPath" -ForegroundColor Gray
Write-Host ""

& dotnet publish "$projectPath" `
    -c Release `
    -r win-x64 `
    --self-contained true `
    -p:PublishSingleFile=false `
    -p:IncludeNativeLibrariesForSelfExtract=true `
    -o $outputPath

if ($LASTEXITCODE -ne 0) {
    Write-Host ""
    Write-Host "❌ 打包失败!" -ForegroundColor Red
    Write-Host ""
    Read-Host "按 Enter 键退出"
    exit 1
}

Write-Host ""
Write-Host "[3/5] 验证输出文件..." -ForegroundColor Yellow

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

    $response = Read-Host "是否立即运行程序? (Y/N)"

    if ($response -eq "Y" -or $response -eq "y") {
        Write-Host ""
        Write-Host "正在启动程序..." -ForegroundColor Green
        Start-Process $exePath
        Write-Host "程序已启动!" -ForegroundColor Green
    }
} else {
    Write-Host ""
    Write-Host "❌ 打包失败: 未找到输出文件!" -ForegroundColor Red
}

Write-Host ""
Read-Host "按 Enter 键退出"
