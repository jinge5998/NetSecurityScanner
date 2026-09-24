# 发布 v1.0.1.5 整合所有最新更新 Spec

## Why
源码中已包含本轮全部更新（AI 风险评估图表字体修复、历史 Word 报告内容深度完善、CNNVD/CNCERT 漏洞库数据连接、漏洞自动存储 JSON 库并扫描调取等），`NetSecurityScanner.Desktop.csproj` 中 AssemblyVersion/FileVersion/Version 仍为 1.0.1.5。当前 `publish-v1.0.1.5/` 目录是旧版本发布产物（缺少上述更新），而新内容已发布到 `publish-v1.0.1.6/`。本次需要清理旧的 `publish-v1.0.1.5/` 并基于当前最新源码重新发布到 `publish-v1.0.1.5/`，保持 1.0.1.5 这一正式版本号与所有最新功能一致，并执行端到端验证。

## What Changes
- **BREAKING** 删除/归档旧 `publish-v1.0.1.5/` 旧发布目录（避免新 EXE 与旧 EXE 混淆）
- 使用现有 `rebuild-and-run.ps1` 重新 `dotnet publish` 到 `publish-v1.0.1.5/`
- 编译时强制传入 `AssemblyVersion=1.0.1.5`、`FileVersion=1.0.1.5`、`Version=1.0.1.5`
- 保留 `RunApp.bat` / `启动-v1.0.1.5.bat` 与发布目录结构一致
- 启动 `publish-v1.0.1.5/NetSecurityScanner.Desktop.exe` 验证主要功能可用

## Impact
- Affected specs: 发布构建、版本号、启动脚本
- Affected code:
  - `NetSecurityScanner/src/NetSecurityScanner.Desktop/NetSecurityScanner.Desktop.csproj`（已含 1.0.1.5 版本号，无需修改）
  - `NetSecurityScanner/RunApp.bat`（已指向 `publish-v1.0.1.5`）
  - `NetSecurityScanner/rebuild-and-run.ps1` / `.bat`（已配置 1.0.1.5 输出）
  - `NetSecurityScanner/publish-v1.0.1.5/`（将被重新生成）
  - `NetSecurityScanner/publish-v1.0.1.5-old-archive/`（保留作为历史归档，不影响新版本）

## ADDED Requirements

### Requirement: 重新发布 v1.0.1.5
The system SHALL 在源码最新状态下，删除旧 `publish-v1.0.1.5/` 并重新 `dotnet publish` 生成新的 `publish-v1.0.1.5/`，版本号统一为 1.0.1.5。

#### Scenario: 完整发布流程
- **WHEN** 触发本次发布任务
- **THEN** 调用 `rebuild-and-run.ps1`（或等价 dotnet publish 命令）输出到 `publish-v1.0.1.5/`
- **AND** 生成的 `NetSecurityScanner.Desktop.exe` 大小 > 100 MB（含 SkiaSharp / LiveChartsCore / 自包含运行时）
- **AND** DLL 版本号与 EXE 版本号均为 1.0.1.5

### Requirement: 编译通过
The system SHALL 在发布前保证 `dotnet build src/NetSecurityScanner.Core` 与 `dotnet build src/NetSecurityScanner.Desktop` 均返回 0 错误。

#### Scenario: Core 与 Desktop 都成功编译
- **WHEN** 执行 `dotnet build -c Release`
- **THEN** Core 0 错误
- **AND** Desktop 0 错误

### Requirement: 启动脚本路径一致
The system SHALL 确保 `RunApp.bat` 与 `启动-v1.0.1.5.bat` 均指向 `publish-v1.0.1.5/NetSecurityScanner.Desktop.exe`。

#### Scenario: 双击 RunApp.bat 启动
- **WHEN** 用户双击 `NetSecurityScanner/RunApp.bat`
- **THEN** 启动新发布的 `publish-v1.0.1.5/NetSecurityScanner.Desktop.exe`
- **AND** 程序正常弹出主窗口

## MODIFIED Requirements
无。

## REMOVED Requirements
无。

## EXECUTION Strategy
1. **代码预检**: `dotnet build src/NetSecurityScanner.Core/NetSecurityScanner.Core.csproj -c Release`
2. **代码预检**: `dotnet build src/NetSecurityScanner.Desktop/NetSecurityScanner.Desktop.csproj -c Release`
3. **清理旧发布**: 删除 `publish-v1.0.1.5/`
4. **重新发布**: `dotnet publish` 到 `publish-v1.0.1.5/`，传 `AssemblyVersion=1.0.1.5` / `FileVersion=1.0.1.5` / `Version=1.0.1.5`
5. **结果验证**: 检查 `publish-v1.0.1.5/NetSecurityScanner.Desktop.exe` 存在、文件大小正常、版本号正确
6. **运行验证**: 启动 EXE，确认主窗口可正常显示
