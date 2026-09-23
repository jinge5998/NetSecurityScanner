# Tasks

- [x] Task 1: 创建数据模型与注册表
  - [x] SubTask 1.1: 在 `NetSecurityScanner.Core/Models/` 新建 `NmapTemplate.cs`，包含 Id/Name/Icon/Description/NmapCommand/Apply 方法
  - [x] SubTask 1.2: 在 `NetSecurityScanner.Core/Services/` 新建 `NmapTemplateRegistry.cs`，内置 14 + 5 = 19 个模板
  - [x] SubTask 1.3: 在 `NetSecurityScanner.Core/Services/` 新建 `CustomNmapTemplateStore.cs`，支持 JSON 持久化

- [x] Task 2: 重构现有 14 个模板按钮为数据驱动
  - [x] SubTask 2.1: 创建统一的 `ApplyNmapTemplateButton_Click` 处理器，遍历 `NmapTemplateRegistry.All` 匹配按钮 Name
  - [x] SubTask 2.2: 修改 XAML：将 14 个分散按钮的 Click 全部指向统一处理器，Tag 或 Name 携带 Template.Id
  - [x] SubTask 2.3: 验证旧按钮的功能（点击后设置仍正确应用、通知仍弹出）

- [x] Task 3: 新增 5 个标准 nmap 模板
  - [x] SubTask 3.1: Intense Scan (-T4 -A -v)
  - [x] SubTask 3.2: Intense Scan Plus UDP (-sS -sU -T4 -A -v)
  - [x] SubTask 3.3: Regular Scan（默认行为）
  - [x] SubTask 3.4: Slow Comprehensive Scan (-sS -sU -T4 -A -v -p- -PE)
  - [x] SubTask 3.5: Quick Traceroute (-sn --traceroute)
  - [x] SubTask 3.6: 在 XAML 添加对应按钮（行 1944 之后）

- [x] Task 4: 修复 PresetStealthBtn 字段错误
  - [x] SubTask 4.1: 把 `RandomizeCheckBox.IsChecked = true` 改为 `RandomTargetOrderCheckBox.IsChecked = true`
  - [x] SubTask 4.2: 同时修复 `NmapTemplateRegistry` 中该模板的 `Apply` 方法

- [x] Task 5: 增强 GenerateNmapCommand
  - [x] SubTask 5.1: 添加 `--version-intensity N` 输出
  - [x] SubTask 5.2: 添加 `--osscan-limit`（当 OsDetect + TcpScan 时）
  - [x] SubTask 5.3: 添加 `-Pn`（当 HostDiscovery == false 时）
  - [x] SubTask 5.4: 添加 `--open`（如果 `ShowOpenOnly` 为 true，可选）
  - [x] SubTask 5.5: 添加 `--min-rate N`（当 RateLimit 启用时）
  - [x] SubTask 5.6: 添加 `--stats-every 5s`（进度输出）

- [x] Task 6: 模板预览面板
  - [x] SubTask 6.1: 在 XAML 添加"👁️ 预览 nmap 命令"按钮 + TextBox（只读，等宽字体）
  - [x] SubTask 6.2: `PreviewNmapButton_Click` 调用 `GenerateNmapCommand` 把结果显示到 TextBox
  - [x] SubTask 6.3: 复制预览按钮（带图标）

- [x] Task 7: 自定义模板保存/加载
  - [x] SubTask 7.1: XAML 添加"💾 保存为模板"按钮（带输入对话框）
  - [x] SubTask 7.2: "📂 我的模板"下拉框，列出已保存的自定义模板
  - [x] SubTask 7.3: 加载自定义模板：调用 `Apply` 方法
  - [x] SubTask 7.4: 删除自定义模板：右键菜单 → 删除

- [x] Task 8: 统一 emoji 前缀
  - [x] SubTask 8.1: 为 14 个现有模板补全一致的 emoji（确保每个 ShowTemplateApplied 调用都带 emoji）

- [x] Task 9: 编译验证 + 启动验证
  - [x] SubTask 9.1: `dotnet build` 0 错误 0 新警告
  - [x] SubTask 9.2: 启动应用 → 测试 5 个新模板按钮 + 模板预览 + 自定义模板保存/加载

# Task Dependencies
- Task 2 依赖 Task 1（注册表必须先存在）
- Task 3 依赖 Task 1
- Task 4 独立
- Task 5 独立
- Task 6 独立
- Task 7 依赖 Task 1.3（持久化层）
- Task 8 依赖 Task 2（重构后才能统一）
- Task 9 依赖所有上述

# 实施结果摘要
- 新增 3 个 Core 文件：`NmapTemplate.cs` / `NmapTemplateRegistry.cs` / `CustomNmapTemplateStore.cs`
- 修改 2 个 Desktop 文件：`ExpertModeWindow.xaml` / `ExpertModeWindow.xaml.cs`
- 删除 14 个旧 Click handler（`NmapFastBtn_Click` 等），统一为 `ApplyNmapTemplateButton_Click` + 19 个 `ApplyTemplateXxx` 方法
- 修复 1 个 bug：`PresetStealthBtn` 字段错配 `RandomizeCheckBox` → `RandomTargetOrderCheckBox`
- `GenerateNmapCommand` 新增 6 个 nmap flag：`--version-intensity` / `--osscan-limit` / `-Pn` / `--open` / `--min-rate` / `--stats-every 5s`
- 新增配置字段：`ExpertScanConfiguration.ShowOpenOnly`
- XAML 新增 5 个模板按钮 + 2 个新面板（预览 + 自定义模板）
- 编译验证：0 错误 / 0 新警告
- 启动验证：进程 PID 50196，窗口标题"网络安全扫描工具"
