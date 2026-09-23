[Console]::OutputEncoding = [System.Text.Encoding]::UTF8

# Load via byte array to avoid file path issues
$base = $args[0]
$dlls = @(
    (Join-Path $base 'LiveChartsCore.dll'),
    (Join-Path $base 'LiveChartsCore.SkiaSharpView.dll')
)

$asms = @()
foreach ($dll in $dlls) {
    if (Test-Path $dll) {
        $bytes = [System.IO.File]::ReadAllBytes($dll)
        $a = [System.Reflection.Assembly]::Load($bytes)
        $asms += $a
        Write-Host "Loaded: $($a.GetName().Name) v$($a.GetName().Version)" -ForegroundColor Cyan
    } else {
        Write-Host "Missing: $dll" -ForegroundColor Red
    }
}

Write-Host ""
Write-Host "=== SolidColorPaint 字体相关属性 ===" -ForegroundColor Yellow
$types = $asms | ForEach-Object { $_.GetTypes() } | Where-Object { $_.FullName -eq 'LiveChartsCore.SkiaSharpView.Painting.SolidColorPaint' }
foreach ($t in $types) {
    Write-Host "TYPE: $($t.FullName)"
    Write-Host "BaseType: $($t.BaseType.FullName)"
    Write-Host ""
    Write-Host "--- SolidColorPaint 自身属性 ---"
    $t.GetProperties([System.Reflection.BindingFlags]'Public,Instance,DeclaredOnly') | ForEach-Object {
        Write-Host "  $($_.Name) : $($_.PropertyType.Name)"
    }
    Write-Host ""
    Write-Host "--- 继承链字体相关属性 ---"
    $chain = @()
    $cur = $t
    while ($cur -ne $null) {
        $chain += $cur
        $cur = $cur.BaseType
    }
    foreach ($c in $chain) {
        Write-Host "  [$($c.FullName)]"
        $c.GetProperties([System.Reflection.BindingFlags]'Public,Instance,DeclaredOnly') | Where-Object { $_.Name -match 'ont|ypeface|amily' } | ForEach-Object {
            $setter = if ($_.CanWrite) { "set" } else { "get_only" }
            Write-Host "    $($_.Name) : $($_.PropertyType.Name) [$setter]"
        }
    }
}

Write-Host ""
Write-Host "=== Paint<TDrawingContext> 类型 ===" -ForegroundColor Yellow
$paint = $asms | ForEach-Object { $_.GetTypes() } | Where-Object { $_.Name -eq 'Paint' -or $_.Name -eq 'Paint`1' }
foreach ($p in $paint) {
    Write-Host "TYPE: $($p.FullName)"
    Write-Host "BaseType: $($p.BaseType.FullName)"
    $p.GetProperties([System.Reflection.BindingFlags]'Public,Instance,DeclaredOnly') | ForEach-Object {
        Write-Host "  $($_.Name) : $($_.PropertyType.Name)"
    }
}

Write-Host ""
Write-Host "=== LiveCharts.HasGlobalSKTypeface 扩展方法 ===" -ForegroundColor Yellow
$ext = $asms | ForEach-Object { $_.GetTypes() } | Where-Object { $_.Name -like '*Extensions*' -or $_.Name -like '*Configure*' }
foreach ($e in $ext) {
    $e.GetMethods([System.Reflection.BindingFlags]'Public,Static') | Where-Object { $_.Name -match 'Global|Font|Typeface|Configure' } | ForEach-Object {
        $params = ($_.GetParameters() | ForEach-Object { "$($_.ParameterType.Name) $($_.Name)" }) -join ', '
        Write-Host "  $($_.DeclaringType.FullName).$($_.Name)($params)"
    }
}
