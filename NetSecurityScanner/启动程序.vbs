Set WshShell = CreateObject("WScript.Shell")
Set fso = CreateObject("Scripting.FileSystemObject")

' 以脚本所在目录为基准，自动探测最新的 publish-v1.0.x 发布目录，
' 避免版本升级后脚本里硬编码的旧路径失效。
baseDir = fso.GetParentFolderName(WScript.ScriptFullName)

bestPath = ""
bestVer = ""

Set rootFolder = fso.GetFolder(baseDir)
For Each subFolder In rootFolder.SubFolders
    name = subFolder.Name
    If LCase(Left(name, 8)) = "publish-" Then
        ver = Mid(name, 9)
        exePath = fso.BuildPath(subFolder.Path, "NetSecurityScanner.Desktop.exe")
        If fso.FileExists(exePath) Then
            If bestVer = "" Then
                bestVer = ver
                bestPath = exePath
            ElseIf VerCompare(ver, bestVer) > 0 Then
                bestVer = ver
                bestPath = exePath
            End If
        End If
    End If
Next

If bestPath <> "" Then
    WshShell.Run Chr(34) & bestPath & Chr(34), 1, False
Else
    MsgBox "未找到可运行的发布目录（publish-v1.0.x）" & vbCrLf & vbCrLf & _
           "请先执行 rebuild-and-run.bat 重新发布。", 16, "错误"
End If

' 比较两个版本号（形如 v1.0.3.2），返回 1 表示 a>b，-1 表示 a<b，0 表示相等
Function VerCompare(a, b)
    a = Mid(a, 2)
    b = Mid(b, 2)
    arrA = Split(a, ".")
    arrB = Split(b, ".")
    maxIdx = UBound(arrA)
    If UBound(arrB) > maxIdx Then maxIdx = UBound(arrB)
    For i = 0 To maxIdx
        x = 0
        y = 0
        If i <= UBound(arrA) Then x = CLng(arrA(i))
        If i <= UBound(arrB) Then y = CLng(arrB(i))
        If x > y Then
            VerCompare = 1
            Exit Function
        End If
        If x < y Then
            VerCompare = -1
            Exit Function
        End If
    Next
    VerCompare = 0
End Function