[Console]::OutputEncoding = [System.Text.Encoding]::UTF8

$base = $args[0]
$dlls = @(
    (Join-Path $base 'LiveChartsCore.dll'),
    (Join-Path $base 'LiveChartsCore.SkiaSharpView.dll'),
    (Join-Path $base 'SkiaSharp.dll')
)

# First load SkiaSharp so LiveChartsCore can find its dependencies
foreach ($dll in $dlls) {
    if (Test-Path $dll) {
        try {
            $bytes = [System.IO.File]::ReadAllBytes($dll)
            [System.Reflection.Assembly]::Load($bytes) | Out-Null
            Write-Host "Loaded: $dll" -ForegroundColor Green
        } catch {
            Write-Host "Failed: $dll - $_" -ForegroundColor Red
        }
    }
}

Write-Host ""
Write-Host "=== Loaded assemblies (LiveChartsCore / SkiaSharp) ===" -ForegroundColor Yellow
[System.AppDomain]::CurrentDomain.GetAssemblies() | Where-Object { $_.GetName().Name -match 'LiveCharts|Skia' } | ForEach-Object {
    Write-Host "  $($_.GetName().Name) v$($_.GetName().Version)"
}

Write-Host ""
Write-Host "=== SolidColorPaint 字体相关属性 ===" -ForegroundColor Yellow
$scp = [System.Type]::GetType("LiveChartsCore.SkiaSharpView.Painting.SolidColorPaint, LiveChartsCore.SkiaSharpView", $false, $true)
if ($scp) {
    Write-Host "TYPE: $($scp.FullName)"
    Write-Host "BaseType: $($scp.BaseType.FullName)"
    Write-Host ""
    Write-Host "--- 继承链字体相关属性 ---"
    $cur = $scp
    $idx = 0
    while ($cur -ne $null) {
        Write-Host "  [$($cur.FullName)]"
        $cur.GetProperties([System.Reflection.BindingFlags]'Public,Instance,DeclaredOnly') | Where-Object { $_.Name -match 'ont|ypeface|amily' } | ForEach-Object {
            $setter = if ($_.CanWrite) { "set" } else { "get_only" }
            Write-Host "    $($_.Name) : $($_.PropertyType.Name) [$setter]"
        }
        $cur = $cur.BaseType
        $idx++
        if ($idx -gt 6) { break }
    }
} else {
    Write-Host "SolidColorPaint not found by name, searching loaded assemblies..."
    [System.AppDomain]::CurrentDomain.GetAssemblies() | ForEach-Object {
        try {
            $_.GetTypes() | Where-Object { $_.Name -eq 'SolidColorPaint' -or $_.Name -eq 'SkiaPaint' }
        } catch [System.Reflection.ReflectionTypeLoadException] {
            ,$_.Exception.Types | Where-Object { $_ -ne $null -and ($_.Name -eq 'SolidColorPaint' -or $_.Name -eq 'SkiaPaint') }
        }
    } | ForEach-Object {
        Write-Host "  Found: $($_.FullName)"
    }
}

Write-Host ""
Write-Host "=== HasGlobalSKTypeface method ===" -ForegroundColor Yellow
$liveCharts = [System.AppDomain]::CurrentDomain.GetAssemblies() | Where-Object { $_.GetName().Name -eq 'LiveChartsCore' } | Select-Object -First 1
if ($liveCharts) {
    try {
        $liveCharts.GetTypes() | Where-Object { $_.IsSealed -or $_.IsAbstract -or $_.IsClass } | ForEach-Object {
            $_.GetMethods([System.Reflection.BindingFlags]'Public,Static') | Where-Object { $_.Name -match 'Global|Typeface|Configure' } | ForEach-Object {
                $params = ($_.GetParameters() | ForEach-Object { "$($_.ParameterType.Name) $($_.Name)" }) -join ', '
                Write-Host "  $($_.DeclaringType.FullName).$($_.Name)($params)"
            }
        }
    } catch [System.Reflection.ReflectionTypeLoadException] {
        Write-Host "ReflectionTypeLoadException, using Types from exception..."
        $liveCharts.GetExportedTypes() | ForEach-Object {
            $_.GetMethods([System.Reflection.BindingFlags]'Public,Static') | Where-Object { $_.Name -match 'Global|Typeface|Configure' } | ForEach-Object {
                $params = ($_.GetParameters() | ForEach-Object { "$($_.ParameterType.Name) $($_.Name)" }) -join ', '
                Write-Host "  $($_.DeclaringType.FullName).$($_.Name)($params)"
            }
        }
    }
}
