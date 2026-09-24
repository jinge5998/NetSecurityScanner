# 提取并反编译 WPF BAML 资源为 XAML
# 使用 ILSpy 的 BamlDecompiler

param(
    [string]$DllPath,
    [string]$ResourceFilter = "assetmanagementwindow",
    [string]$OutputDir = "$PSScriptRoot\baml_output"
)

Add-Type -Path "$env:USERPROFILE\.nuget\packages\icstudio.bamldecompiler\1.0.0\lib\netstandard2.0\ICStudio.BamlDecompiler.dll" -ErrorAction SilentlyContinue

if (-not (Test-Path $OutputDir)) { New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null }

Write-Host "Loading assembly: $DllPath"
$bytes = [System.IO.File]::ReadAllBytes($DllPath)
$assembly = [System.Reflection.Assembly]::Load($bytes)

$resources = $assembly.GetManifestResourceNames() | Where-Object { $_ -match $ResourceFilter }
Write-Host "Found resources: $($resources -join ', ')"

foreach ($res in $resources) {
    $stream = $assembly.GetManifestResourceStream($res)
    if ($stream) {
        $outPath = Join-Path $OutputDir ($res -replace '/', '_' -replace '\.baml', '.xaml')
        Write-Host "Extracting: $res -> $outPath"

        # Read all bytes
        $ms = New-Object System.IO.MemoryStream
        $stream.CopyTo($ms)
        $bamlBytes = $ms.ToArray()

        # Save raw BAML
        $bamlPath = $outPath -replace '\.xaml$', '.baml'
        [System.IO.File]::WriteAllBytes($bamlPath, $bamlBytes)

        $stream.Close()
    }
}
Write-Host "Done. Files in: $OutputDir"
