# 修复 v1.0.1.5 分析菜单中 AI 风险评估残留 Spec (v2 续)

## Why
源码 [MainWindow.xaml](file:///d:/360安全浏览器下载/软件开发备份/网络安全漏洞扫描/NetSecurityScanner/src/NetSecurityScanner.Desktop/MainWindow.xaml) 已经移除"AI风险评估"菜单项和 TabItem（已 grep 验证 0 命中），并且新的发布目录 `publish-v1.0.1.5-recover/NetSecurityScanner.Desktop.dll` 也已验证不含 "AI风险评估" 字符串（DLL 字符串搜索结果：0 命中）。但旧目录 `publish-v1.0.1.5/NetSecurityScanner.Desktop.dll` 仍包含 3 处 "AI风险评估" 字符串。同时 `RunApp.bat` 仍指向不存在的 `publish-v1.0.1.5-new` 目录，导致用户实际运行的是旧 `publish-v1.0.1.5` EXE，菜单里仍然能看到 AI 风险评估。

## What Changes
- **BREAKING** 关闭所有旧 `publish-v1.0.1.5` 进程（已确认无进程运行）
- 删除/归档旧目录 `publish-v1.0.1.5/`（旧 EXE 含 AI 风险评估菜单），或将其重命名为 `_archive`
- 将 `publish-v1.0.1.5-recover/` 重命名为 `publish-v1.0.1.5/`（确保发布目录结构唯一且与版本号对齐）
- 更新 `RunApp.bat`，指向正确的发布目录 `publish-v1.0.1.5`
- 重新从干净源码（`NetSecurityScanner.Desktop/MainWindow.xaml`）publish 一遍，覆盖 `publish-v1.0.1.5/` 目录
- 启动更新后的 `publish-v1.0.1.5/NetSecurityScanner.Desktop.exe`，验证"分析"菜单中已无 "AI风险评估"

## Impact
- Affected code:
  - [MainWindow.xaml](file:///d:/360安全浏览器下载/软件开发备份/网络安全漏洞扫描/NetSecurityScanner/src/NetSecurityScanner.Desktop/MainWindow.xaml)（已正确，AI风险评估菜单和 TabItem 已删除）
  - [MainWindow.xaml.cs](file:///d:/360安全浏览器下载/软件开发备份/网络安全漏洞扫描/NetSecurityScanner/src/NetSecurityScanner.Desktop/MainWindow.xaml.cs)（已正确，AI风险评估 UI 方法已删除，仅保留 `AIRiskAssessmentService` 算法服务引用）
  - [RunApp.bat](file:///d:/360安全浏览器下载/软件开发备份/网络安全漏洞扫描/NetSecurityScanner/RunApp.bat)（需要更新启动路径）
  - `NetSecurityScanner/publish-v1.0.1.5/`（旧发布目录，需要替换为干净版本）
  - `NetSecurityScanner/publish-v1.0.1.5-recover/`（新干净发布目录，需要重命名/合并到 publish-v1.0.1.5）

## ADDED Requirements

### Requirement: 干净的发布目录
系统 SHALL 确保 `publish-v1.0.1.5/NetSecurityScanner.Desktop.dll` 是从已删除 AI风险评估菜单的源码编译的版本。

#### Scenario: 重新发布干净版本
- **WHEN** 用户报告 v1.0.1.5 上仍能看到 AI风险评估菜单
- **THEN** 从 `NetSecurityScanner.Desktop.csproj`（AssemblyVersion=1.0.1.5）重新 dotnet publish 到 `publish-v1.0.1.5/`
- **AND** 验证 `publish-v1.0.1.5/NetSecurityScanner.Desktop.dll` 中 "AI风险评估" 字符串出现次数 = 0
- **AND** 保留 `AIRiskAssessmentService` 等算法/服务内部引用（这些是后端逻辑，不是 UI）

#### Scenario: 归档旧版本
- **WHEN** 新版本发布成功
- **THEN** 备份目录（如 `publish-v1.0.1.5-recover/`）应整合到主发布目录或归档
- **AND** `RunApp.bat` 指向正确的发布目录 `publish-v1.0.1.5/NetSecurityScanner.Desktop.exe`

### Requirement: 修复启动脚本
系统 SHALL 确保 `RunApp.bat` 指向有效的发布目录。

#### Scenario: RunApp.bat 路径正确
- **WHEN** 用户双击 `RunApp.bat`
- **THEN** 启动 `publish-v1.0.1.5/NetSecurityScanner.Desktop.exe`
- **AND** 启动的 EXE 来自干净源码（无 AI风险评估菜单）

### Requirement: 验证 UI 已删除 AI风险评估
系统 SHALL 在启动后通过进程/窗口检查确认 "分析"菜单中无 "AI风险评估"。

#### Scenario: 菜单验证
- **WHEN** 程序稳定运行
- **THEN** DLL 字符串扫描确认 MenuItem 列表中无 "AI风险评估"
- **AND** TabControl 字符串扫描确认无 "AI风险评估" TabItem
- **AND** 用户能正常看到不含 AI风险评估的菜单

## REMOVED Requirements

### Requirement: AI风险评估 UI 菜单项
**Reason**: 用户已要求删除"分析"菜单下的"AI风险评估"入口。
**Migration**: AI风险评估功能保留在后台 `AIRiskAssessmentService`，仅在扫描完成后自动触发，UI 入口已删除。

### Requirement: AI风险评估 TabItem
**Reason**: 用户已要求删除主界面 TabControl 中的 "AI风险评估" TabItem。
**Migration**: 评估结果通过 `AIRiskAssessmentService` 自动执行，统计数据保留在原服务的内部模型中。

## EXECUTION Strategy
1. **源验证**: 确认 `NetSecurityScanner.Desktop/MainWindow.xaml` 中无 AI风险评估（已完成）
2. **DLL 验证**: 确认 `publish-v1.0.1.5-recover/NetSecurityScanner.Desktop.dll` 中无 AI风险评估字符串（已完成，0 命中）
3. **目录整合**: 将 `publish-v1.0.1.5-recover/` 整体移动到 `publish-v1.0.1.5/`，或重新 publish 到 `publish-v1.0.1.5/`
4. **启动脚本**: 更新 `RunApp.bat` 路径
5. **最终验证**: 启动新 EXE，确认用户能看到干净的菜单
