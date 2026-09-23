[Console]::OutputEncoding = [System.Text.Encoding]::UTF8

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
    }
}

function Get-Type-Safe([System.Reflection.Assembly]$asm, [string]$fullName) {
    try {
        return $asm.GetType($fullName, $false, $true)
    } catch {
        return $null
    }
}

function Get-Types-Safe([System.Reflection.Assembly]$asm) {
    try {
        return ,$asm.GetTypes()
    } catch [System.Reflection.ReflectionTypeLoadException] {
        return ,$_.Exception.Types | Where-Object { $_ -ne $null }
    } catch {
        return @()
    }
}

Write-Host "=== SolidColorPaint 字体相关属性 ===" -ForegroundColor Yellow
$typesAll = $asms | ForEach-Object { Get-Types-Safe $_ } | Where-Object { $_ -ne $null }
$scp = $typesAll | Where-Object { $_.FullName -eq 'LiveChartsCore.SkiaSharpView.Painting.SolidColorPaint' }
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
        if ($idx -gt 5) { break }
    }
} else {
    Write-Host "SolidColorPaint type not found"
    $typesAll | Where-Object { $_.Name -eq 'SolidColorPaint' } | ForEach-Object {
        Write-Host "Candidate: $($_.FullName)"
    }
}

Write-Host ""
Write-Host "=== SkiaPaint 类型 ===" -ForegroundColor Yellow
$sp = $typesAll | Where-Object { $_.FullName -eq 'LiveChartsCore.SkiaSharpView.Painting.SkiaPaint' }
if ($sp) {
    Write-Host "TYPE: $($sp.FullName)"
    $sp.GetProperties([System.Reflection.BindingFlags]'Public,Instance,DeclaredOnly') | ForEach-Object {
        Write-Host "  $($_.Name) : $($_.PropertyType.Name)"
    }
} else {
    Write-Host "SkiaPaint not found"
    $typesAll | Where-Object { $_.Name -eq 'SkiaPaint' } | ForEach-Object {
        Write-Host "Candidate: $($_.FullName)"
    }
}

Write-Host ""
Write-Host "=== LiveChartsExtensions.HasGlobalSKTypeface ===" -ForegroundColor Yellow
$exts = $typesAll | Where-Object { $_.Name -like '*Extensions*' }
foreach ($e in $exts) {
    $e.GetMethods([System.Reflection.BindingFlags]'Public,Static') | Where-Object { $_.Name -match 'Global|Typeface|Configure' } | ForEach-Object {
        $params = ($_.GetParameters() | ForEach-Object { "$($_.ParameterType.Name) $($_.Name)" }) -join ', '
        Write-Host "  $($e.FullName).$($_.Name)($params)"
    }
}

Write-Host ""
Write-Host "=== Paint (Base) Type ===" -ForegroundColor Yellow
$typesAll | Where-Object { $_.FullName -match '^LiveChartsCore\.Painting\.Paint' -or $_.FullName -match '^LiveChartsCore\.Painting\.Paint`' } | ForEach-Object {
    Write-Host "TYPE: $($_.FullName)"
    Write-Host "  Base: $($_.BaseType.FullName)"
    $_.GetProperties([System.Reflection.BindingFlags]'Public,Instance,DeclaredOnly') | ForEach-Object {
        Write-Host "    $($_.Name) : $($_.PropertyType.Name)"
    }
}

Write-Host ""
Write-Host "=== Animatable / Paint 通用字体字段 ===" -ForegroundColor Yellow
$typesAll | Where-Object { $_.Name -eq 'Paint' -and $_.Namespace -eq 'LiveChartsCore.Painting' } | ForEach-Object {
    Write-Host "TYPE: $($_.FullName)"
    $_.GetFields([System.Reflection.BindingFlags]'Public,Instance,DeclaredOnly') | ForEach-Object {
        Write-Host "  field $($_.Name) : $($_.FieldType.Name)"
    }
}
