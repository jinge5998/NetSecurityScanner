$prev = @{}
foreach ($pid in @(40076, 37608)) {
  $proc = Get-Process -Id $pid -ErrorAction SilentlyContinue
  if ($proc) { $prev[$pid] = $proc.CPU }
}
Start-Sleep -Seconds 3
Write-Host "=== CPU 增量 (3秒内) ==="
foreach ($pid in @(40076, 37608)) {
  $proc = Get-Process -Id $pid -ErrorAction SilentlyContinue
  if ($proc) {
    $delta = $proc.CPU - $prev[$pid]
    $kb = [math]::Round($proc.WorkingSet64 / 1KB, 0)
    Write-Host ("PID {0}  CPU增={1:N2}s  内存={2}KB  启动={3}" -f $pid, $delta, $kb, $proc.StartTime)
  }
  else {
    Write-Host "PID $pid 已退出"
  }
}