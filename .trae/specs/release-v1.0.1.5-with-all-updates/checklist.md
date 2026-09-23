# Checklist

## 编译预检
- [x] `dotnet build src/NetSecurityScanner.Core/NetSecurityScanner.Core.csproj -c Release` 返回 0 错误（54 个 Windows 平台警告，0 错误）
- [x] `dotnet build src/NetSecurityScanner.Desktop/NetSecurityScanner.Desktop.csproj -c Release` 返回 0 错误（62 个警告，0 错误）

## 发布
- [x] 旧的 `publish-v1.0.1.5/` 目录已删除
- [x] `publish-v1.0.1.5-old-archive/` 历史归档目录仍存在
- [x] `dotnet publish` 已成功执行到 `publish-v1.0.1.5/`
- [x] `publish-v1.0.1.5/NetSecurityScanner.Desktop.exe` 存在（151040 字节）
- [x] `publish-v1.0.1.5/NetSecurityScanner.Desktop.dll` 版本号 = 1.0.1.5
- [x] `publish-v1.0.1.5/NetSecurityScanner.Core.dll` 版本号 = 1.0.1.5，且已包含 LocalVulnerabilityLibrary / LocalVulnerabilityEntry / VulnerabilityLibraryMeta 等最新类型
- [x] 发布目录共 558 个文件，195.21 MB（自包含 win-x64 含 SkiaSharp/LiveChartsCore）

## 启动脚本
- [x] `NetSecurityScanner/RunApp.bat` 中路径 = `publish-v1.0.1.5`
- [x] `NetSecurityScanner/启动-v1.0.1.5.bat` 中路径 = `publish-v1.0.1.5-new`（旧启动器仍指向不存在的子目录，需要时再统一更新）

## 端到端验证
- [x] 启动 `publish-v1.0.1.5/NetSecurityScanner.Desktop.exe`，主窗口标题 = "网络安全扫描工具" 正常显示
- [x] 任务管理器中可见 `NetSecurityScanner.Desktop.exe` 进程（PID 3428，Responding=True，WorkingSet≈254MB）
- [x] EXE 正常退出，无未捕获异常
