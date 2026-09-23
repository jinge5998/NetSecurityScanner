[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$procs = Get-Process | Where-Object { $_.ProcessName -like 'NetSecurityScanner*' -or $_.MainWindowTitle -like '*网络安全*' }
if ($procs) {
    $procs | Select-Object Id, ProcessName, StartTime, MainWindowTitle | Format-Table -AutoSize
} else {
    Write-Host "No process found"
}
