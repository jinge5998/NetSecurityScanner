$file = "d:\360安全浏览器下载\软件开发备份\网络安全漏洞扫描\NetSecurityScanner\src\NetSecurityScanner.Desktop\Views\Views\ExpertModeWindow.xaml.cs"
$keywords = @("Recommend","Nmap","Template","扫描模板","扫描方案","ScanProfile")

foreach ($k in $keywords) {
    Write-Host "===== KeyWord: $k ====="
    $matches = Select-String -Path $file -Pattern $k -SimpleMatch
    foreach ($m in $matches) {
        $lineNum = $m.LineNumber
        $lineText = $m.Line.Trim()
        if ($lineText.Length -gt 200) { $lineText = $lineText.Substring(0,200) + "..." }
        Write-Host ("{0,5}: {1}" -f $lineNum, $lineText)
    }
    Write-Host "Total for '$k': $($matches.Count)"
    Write-Host ""
}
