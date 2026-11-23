---
name: "wpf-release-launch"
description: "Publishes .NET WPF apps, seeds .machine_id license cache, launches detached via WMI, polls window visibility. Invoke when releasing/running NetSecurityScanner or LicenseKeyGenerator locally."
---

# WPF Release & Launch (NetSecurityScanner 专用)

端到端固化本仓库 .NET WPF 桌面端的**发布 → 授权连续 → 脱离会话启动 → 窗口稳定性验证**流程。避免每次发布都重新踩「GUI 被沙箱杀掉 / WMI 挂起导致界面打不开 / 指纹算法变化导致授权失效 / exe 与 dll 版本不一致」的坑。

## 何时触发

- 用户说「运行最新版本」「重新发布」「打包」「启动 X」。
- 需要让 WPF 窗口在工具调用结束后**继续存活**（普通 `Start-Process` 会被沙箱 Job 回收）。
- 发布后出现「一启动就退出」「界面打不开」「授权弹窗」「扫描无结果」等现象时的定位与修复。

## 仓库关键常量（先确认，别硬猜）

| 项 | 值 / 路径 |
|----|-----------|
| 仓库根 (git) | `D:\360安全浏览器下载\软件开发备份\网络安全漏洞扫描` |
| 项目子目录 | `...\网络安全漏洞扫描\NetSecurityScanner` |
| 扫描仪发布脚本 | `...\NetSecurityScanner\rebuild-and-run.ps1`（版本号自增，已内置播种 `.machine_id`） |
| 扫描仪输出 | `...\NetSecurityScanner\publish-v<ver>\`，exe = `NetSecurityScanner.Desktop.exe` |
| 生成器项目 | `...\NetSecurityScanner\tools\LicenseKeyGenerator\LicenseKeyGenerator.csproj` |
| 生成器输出 | 仓库根 `...\网络安全漏洞扫描\LicenseKeyGenerator\`，exe = `LicenseKeyGenerator.exe` |
| 授权绑定机器码 | `C3811D1E116374E80BDB2CBD414648BC`（32 位十六进制，来自 `issuance_records.json`） |
| 机器码缓存文件 | `<exe所在目录>\.machine_id`（Hidden+System+NotContentIndexed，内容必须恰好 32 字符） |
| 启动日志 | `<发布目录>\logs\boot_YYYYMMDD_HHMMSS.log` |
| 专家扫描日志 | `<发布目录>\logs\expert_scan_*.log` |
| 指纹实现（双端） | `src\NetSecurityScanner.Core\Utils\MachineFingerprint.cs`、`tools\LicenseKeyGenerator\Utils\MachineFingerprint.cs` |
| 授权校验 | `src\NetSecurityScanner.Core\Services\LicenseService.cs`（L42-45 精确比对 `MachineId`） |

---

## 阶段 1：停进程、解文件锁

发布前必须先停掉占用目标 exe 的进程，否则 `dotnet publish` 会报「file locked」。

```powershell
Get-Process -Name NetSecurityScanner.Desktop,LicenseKeyGenerator,rust-scanner-service -ErrorAction SilentlyContinue |
  ForEach-Object { try { Stop-Process -Id $_.Id -Force -ErrorAction Stop } catch {} }
Start-Sleep -Seconds 2
```

> ⚠️ 只能用 `Stop-Process -Id`，**禁止** `taskkill`（环境黑名单）。

---

## 阶段 2：发布（dotnet publish self-contained win-x64）

### 扫描仪
优先用现成脚本（已含 nmap/rust 打包 + 自动播种 `.machine_id`）：

```powershell
& "...\NetSecurityScanner\rebuild-and-run.ps1"
```

若需手工发布（或脚本失败）：

```powershell
$proj = "...\NetSecurityScanner\src\NetSecurityScanner.Desktop\NetSecurityScanner.Desktop.csproj"
$out  = "...\NetSecurityScanner\publish-v1.0.x.y"
dotnet publish $proj -c Release -r win-x64 --self-contained true `
  -p:PublishSingleFile=false -p:IncludeNativeLibrariesForSelfExtract=true `
  -p:AssemblyVersion=1.0.x.y -p:FileVersion=1.0.x.y -p:Version=1.0.x.y -o $out
```

发布后**必须核对** `NetSecurityScanner.Desktop.exe` 与 `NetSecurityScanner.Core.dll` 为**同一分钟构建、版本一致**——旧 bug 就是 exe 旧 / Core.dll 新（`ScanPortsAsync` 多了 `allowRetry` 参数）→ 运行时 `MissingMethodException` → 扫描 0 结果。

```powershell
Get-Item "$out\NetSecurityScanner.Desktop.exe","$out\NetSecurityScanner.Core.dll" |
  Select-Object Name, LastWriteTime, @{N='Ver';E={$_.VersionInfo.FileVersion}}
```

### 生成器
```powershell
$proj = "...\NetSecurityScanner\tools\LicenseKeyGenerator\LicenseKeyGenerator.csproj"
$out  = "...\网络安全漏洞扫描\LicenseKeyGenerator"
dotnet publish $proj -c Release -r win-x64 --self-contained true -p:PublishSingleFile=false -o $out
```

---

## 阶段 3：播种 `.machine_id`（授权连续性的关键）

`MachineFingerprint.Generate()` **先读缓存**：命中 `.machine_id`（且 `.Trim()` 后长度恰好 32）就直接返回，**不重算、不覆盖**。利用这一点把已授权的机器码写进新发布包，发布后授权即通过，无需重新激活。

两个来源，按优先级取：

1. **最近一个旧发布包的 `.machine_id`**（已验证可用）。
2. **`%LOCALAPPDATA%\NetSecurityScanner\licenseIssuer\issuance_records.json`** 里 `Records[].MachineId`（取第一条 32 位）。

幂等播种脚本：

```powershell
$out    = "<目标发布目录>"
$bound  = $null
# 来源1：旧发布包
$prior = Get-ChildItem (Split-Path $out) -Directory -Filter 'publish-v*' -ErrorAction SilentlyContinue |
  Where-Object { $_.FullName -ne $out -and (Test-Path (Join-Path $_.FullName '.machine_id')) } |
  Sort-Object LastWriteTime -Descending | Select-Object -First 1
if ($prior) {
  $candidate = (Get-Content (Join-Path $prior.FullName '.machine_id') -Raw).Trim()
  if ($candidate.Length -eq 32) { $bound = $candidate }
}
# 来源2：发行记录
if (-not $bound) {
  $rec = Join-Path $env:LOCALAPPDATA 'NetSecurityScanner\licenseIssuer\issuance_records.json'
  if (Test-Path $rec) {
    $j = Get-Content $rec -Raw | ConvertFrom-Json
    $bound = $j.Records | Where-Object { $_.MachineId -and $_.MachineId.Length -eq 32 } |
      Select-Object -First 1 -ExpandProperty MachineId
  }
}
if ($bound) {
  $f = Join-Path $out '.machine_id'
  [System.IO.File]::WriteAllText($f, $bound, [System.Text.UTF8Encoding]::new($false))
  [System.IO.File]::SetAttributes($f, [System.IO.FileAttributes]::Hidden -bor [System.IO.FileAttributes]::System -bor [System.IO.FileAttributes]::NotContentIndexed)
  Write-Output "seeded .machine_id = $bound"
}
```

> 用 `[System.IO.File]::WriteAllText`（UTF-8 无 BOM）而不是 `Set-Content`，避免写入多余换行/编码差异导致 `ReadCache` 的 32 长度校验失败。

---

## 阶段 4：脱离会话启动（WMI，必用）

**核心问题**：在 TRAE 沙箱里用 `Start-Process` 拉起的 GUI 进程会继承当前 Shell Job，工具调用结束时 Job 被销毁 → 进程被杀，窗口一闪而过。**必须**用 WMI `Win32_Process.Create` 脱离会话。

```powershell
$exe = "<发布目录>\<App>.exe"
$dir = Split-Path -Parent $exe
$r = Invoke-CimMethod -ClassName Win32_Process -MethodName Create `
  -Arguments @{ CommandLine = ('"' + $exe + '"'); CurrentDirectory = $dir }
# $r.ReturnValue == 0 成功，$r.ProcessId 为新 PID
```

> 需要 `dangerouslyDisableSandbox: true`（WMI 调用超出沙箱文件/网络限制）。
> `CurrentDirectory` 必须传 exe 所在目录，否则相对路径（日志、nmap、`.machine_id`）会找不到。

---

## 阶段 5：秒级轮询验证窗口稳定

启动后每秒轮询 `MainWindowHandle` + 可见性，持续 12–15 秒。**通过标准**：第 1–2 秒起 `VISIBLE` 且持续不消失、不退出、`Responding=True`。

```powershell
Add-Type @"
using System; using System.Runtime.InteropServices;
public class WVis { [DllImport("user32.dll")] public static extern bool IsWindowVisible(IntPtr h); }
"@
$pid0 = <上一步的 ProcessId>
for ($i=0; $i -lt 15; $i++) {
  Start-Sleep -Seconds 1
  $p = Get-Process -Id $pid0 -ErrorAction SilentlyContinue
  if (-not $p) { Write-Output "t+$($i+1)s EXITED"; break }
  $h = $p.MainWindowHandle
  $vis = if ($h -ne [IntPtr]::Zero) { [WVis]::IsWindowVisible($h) } else { $false }
  Write-Output ("t+$($i+1)s hwnd=$h vis=$vis title='$($p.MainWindowTitle)' resp=$($p.Responding)")
}
```

### 窗口在屏外/被遮挡 → 恢复并置顶
若 `Visible=True` 但用户看不到（常见于曾接双显示器，窗口停在负坐标）：

```powershell
Add-Type @"
using System; using System.Runtime.InteropServices;
public class WPos {
  [DllImport("user32.dll")] public static extern bool ShowWindow(IntPtr h, int n);
  [DllImport("user32.dll")] public static extern bool SetWindowPos(IntPtr h, IntPtr a, int x, int y, int cx, int cy, uint f);
  [DllImport("user32.dll")] public static extern bool SetForegroundWindow(IntPtr h);
}
"@
$h = (Get-Process -Id $pid0).MainWindowHandle
[void][WPos]::ShowWindow($h, 9)          # SW_RESTORE
[void][WPos]::SetWindowPos($h, [IntPtr]-1, 140, 90, 1060, 740, 0x0040) # HWND_TOPMOST, SWP_SHOWWINDOW
Start-Sleep -Milliseconds 300
[void][WPos]::SetForegroundWindow($h)
```

### 枚举进程所有顶层窗口（确认哪个是真界面）
`MainWindow` 可能只是自关闭的启动器。用 `EnumWindows` 过滤 `GetWindowThreadProcessId==目标PID` 且 `IsWindowVisible` 的窗口，看标题/矩形：

```powershell
# 见上文 W6 风格定义：EnumWindows + GetWindowThreadProcessId + GetWindowText + GetWindowRect
```

---

## 阶段 6：授权与功能验证

### 授权（扫描仪）
读最新 `boot_*.log`：
- ✅ 正常：`License OK` → `Creating MainWindow...` → `=== MAIN WINDOW SHOWN ===` → `OnStartup completed successfully`，无 `APP EXIT`，进程存活。
- ❌ 失效：`Not licensed -> showing LicenseDialog` → `LicenseDialog result: False` → `=== APP EXIT code=0 ===`。
  - 根因 99% 是 `.machine_id` 缺失或值 ≠ 授权绑定机器码 → 回到**阶段 3** 重新播种。
  - 绝**不要**直接改 `license.dat` 里的到期/机器码字段——那会破坏签名校验，触发「签名无效」（历史教训）。

### 扫描（专家模式，原始 bug 验证）
用户跑完专家模式扫描后查 `expert_scan_*.log`：
- ❌ 若出现 `MissingMethodException: ...ScanPortsAsync(...10 params...)` → exe 与 Core.dll 版本不一致 → 重新构建发布（阶段 2 末尾的版本核对是防线）。
- ❌ 若出现跨线程 `InvalidOperationException` → UI 线程编组问题，另查。
- ✅ 应有端口列表 + 漏洞匹配输出。

### 生成器打不开
- 查 `MachineFingerprint` 是否为旧版（同步直调 WMI、无超时无缓存）→ WMI 挂起会把 UI 冻在 `OnLoaded` → 窗口出不来。换成**缓存 + 1.5s 超时 + 注册表回退**版（与扫描仪 `Core` 同款）。
- 事件日志无 `.NET Runtime`/`Application Error` 但窗口消失 → 多半是窗口被关但进程残留或屏外，按阶段 5 恢复。

---

## Windows / 沙箱 约束速查（违反会让命令失败或行为异常）

| 约束 | 正确做法 |
|------|----------|
| PowerShell 5 不支持 `&&`/`\|\|` | 用 `;` 顺序串联；条件用 `if ($LASTEXITCODE -eq 0)` |
| 禁止 `cmd /c`、`cmd.exe` | 全部用 PowerShell 原生命令 |
| 禁止 `taskkill`、`rm`、`del` 等 | 停进程用 `Stop-Process -Id`；删文件用 `DeleteFile` 工具 |
| 禁止 `grep -r`/`cat`/`find` | 用 Grep / Read / Glob 工具 |
| PowerShell 5 不支持 `Join-String` 等高版本 cmdlet | 用 `-join` 或基础拼接 |
| PowerShell heredoc `@'...'@` 在本 shell 易解析失败 | git 多段提交用 `git commit -m "title" -m "body"` |
| git 输出可能进分页器挂起 | `$env:GIT_PAGER = "cat"` 或每条加 `--no-pager` |
| `curl` 是 `Invoke-WebRequest` 别名且参数不兼容 | 直接用 `Invoke-WebRequest -UseBasicParsing` |
| 路径含空格 | 用 `& "..."` 调用；拼接用 `Join-Path` |
| GUI 进程会随工具调用结束被杀 | 必须用阶段 4 的 WMI 脱离启动 |
| 修改 `.ps1` 后 | 用 AST 解析器校验语法（不执行）：`[System.Management.Automation.Language.Parser]::ParseFile($path,[ref]$null,[ref]$errors)`，`$errors` 为空即通过 |

---

## 故障速查表

| 现象 | 首查 | 修复 |
|------|------|------|
| 一启动就退出 | `boot_*.log` 是否 `LicenseDialog result: False` | 阶段 3 播种 `.machine_id` |
| 界面打不开 / 双击无反应 | 生成器 `MachineFingerprint` 是否旧阻塞版；`MainWindowHandle` 是否为 0 | 换缓存+超时版指纹；阶段 5 恢复窗口 |
| 扫描 0 端口/漏洞 | `expert_scan_*.log` 是否 `MissingMethodException` | 核对 exe↔Core.dll 同版本，重新发布 |
| 窗口闪一下消失 | 进程是否还活着（无崩溃日志）；是否屏外 | 阶段 5 枚举窗口 + 置顶 |
| 发布报 file locked | 旧进程未停 | 阶段 1 `Stop-Process` |
| 改授权后「签名无效」 | 是否篡改了 `license.dat` 受签名字段 | 回退，走生成器重新签发，不要手改签名载荷 |
