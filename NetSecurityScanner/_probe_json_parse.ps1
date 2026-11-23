# 用 .NET System.Text.Json 严格模式测试引擎返回的 JSON
# 模拟 RustScannerClient 中的 JsonDocument.Parse(line) 行为
$sample = '{"type":"result""target_ip":"127.0.0.1""port":3389}'

try {
  $doc = [System.Text.Json.JsonDocument]::Parse($sample)
  Write-Host "STRICT_PARSE_OK type=$($doc.RootElement.GetProperty('type').GetString())"
}
catch {
  Write-Host "STRICT_PARSE_FAIL: $($_.Exception.Message)"
}

Write-Host "--- 对照：C# 代码依赖的 JsonDocument.Parse(line) ---"
Write-Host "RustScannerClient 中的解析代码: using var doc = JsonDocument.Parse(line);"

# 正常 JSON 对照
$normal = '{"type":"result","target_ip":"127.0.0.1","port":3389}'
try {
  $doc = [System.Text.Json.JsonDocument]::Parse($normal)
  Write-Host "NORMAL_PARSE_OK type=$($doc.RootElement.GetProperty('type').GetString())"
}
catch {
  Write-Host "NORMAL_PARSE_FAIL: $($_.Exception.Message)"
}