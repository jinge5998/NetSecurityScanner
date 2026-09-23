# Tasks

- [x] Task 1: Core 与 Desktop 项目编译预检
  - [x] SubTask 1.1: 执行 `dotnet build src/NetSecurityScanner.Core/NetSecurityScanner.Core.csproj -c Release`，确认 0 错误
  - [x] SubTask 1.2: 执行 `dotnet build src/NetSecurityScanner.Desktop/NetSecurityScanner.Desktop.csproj -c Release`，确认 0 错误

- [x] Task 2: 清理旧的 publish-v1.0.1.5 目录
  - [x] SubTask 2.1: 确认 `NetSecurityScanner/publish-v1.0.1.5-old-archive/` 仍存在（保留为历史归档）
  - [x] SubTask 2.2: 删除 `NetSecurityScanner/publish-v1.0.1.5/`

- [x] Task 3: 重新发布 v1.0.1.5
  - [x] SubTask 3.1: 执行 `dotnet publish src/NetSecurityScanner.Desktop/NetSecurityScanner.Desktop.csproj -c Release -r win-x64 --self-contained true -p:PublishSingleFile=false -p:IncludeNativeLibrariesForSelfExtract=true -p:AssemblyVersion=1.0.1.5 -p:FileVersion=1.0.1.5 -p:Version=1.0.1.5 -o publish-v1.0.1.5`
  - [x] SubTask 3.2: 确认 `publish-v1.0.1.5/NetSecurityScanner.Desktop.exe` 已生成
  - [x] SubTask 3.3: 确认 `publish-v1.0.1.5/NetSecurityScanner.Desktop.dll` 版本号 = 1.0.1.5
  - [x] SubTask 3.4: 确认 `publish-v1.0.1.5/NetSecurityScanner.Core.dll` 已包含最新漏洞库相关类型（LocalVulnerabilityLibrary / LocalVulnerabilityEntry / VulnerabilityLibraryMeta 全部 grep 命中）

- [x] Task 4: 启动与端到端验证
  - [x] SubTask 4.1: 启动 `publish-v1.0.1.5/NetSecurityScanner.Desktop.exe`，确认主窗口正常显示
  - [x] SubTask 4.2: 通过任务管理器确认 `NetSecurityScanner.Desktop.exe` 进程已运行
  - [x] SubTask 4.3: 关闭程序，结束进程

# Task Dependencies
- Task 2 depends on Task 1
- Task 3 depends on Task 1, Task 2
- Task 4 depends on Task 3
