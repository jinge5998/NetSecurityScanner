# Tasks

- [x] Task 1: 创建共享库项目 NetSecurityScanner.Core
  - [x] 1.1 创建 `NetSecurityScanner/NetSecurityScanner.Core/NetSecurityScanner.Core.csproj`，目标框架 net8.0
  - [x] 1.2 将 Models/、Core/、Data/、Utils/ 目录下的所有 .cs 文件移入 Core 项目（排除 Windows 特定引用）
  - [x] 1.3 将 Services/ 目录下无 UI 依赖的 .cs 文件移入 Core 项目
  - [x] 1.4 确保 Core 项目编译通过，无对 System.Windows.* 的依赖

- [x] Task 2: 重构 Windows 桌面版为壳项目 NetSecurityScanner.Desktop
  - [x] 2.1 创建 `NetSecurityScanner/NetSecurityScanner.Desktop/NetSecurityScanner.Desktop.csproj`，目标框架 net8.0-windows，UseWPF=true
  - [x] 2.2 Desktop 项目引用 Core 项目
  - [x] 2.3 将 Views/*.xaml、MainWindow.xaml/.cs、App.xaml/.cs 移入 Desktop 项目
  - [x] 2.4 确保 Desktop 版本功能完整，编译运行正常

- [x] Task 3: 创建 Avalonia Linux 版本项目 NetSecurityScanner.Linux
  - [x] 3.1 创建 `NetSecurityScanner/NetSecurityScanner.Linux/NetSecurityScanner.Linux.csproj`，目标框架 net8.0，引入 Avalonia 11.x
  - [x] 3.2 Linux 项目引用 Core 项目
  - [x] 3.3 创建 Avalonia App.axaml 入口文件和 Program.cs 启动引导
  - [x] 3.4 将 MainWindow 从 WPF XAML 迁移为 Avalonia AXAML（保持布局一致）
  - [x] 3.5 替换跨平台 NuGet 包：OxyPlot.SkiaSharp、LiveChartsCore.SkiaSharpView.AvaloniaUI、QuestPDF

- [x] Task 4: 视图文件迁移（WPF XAML → Avalonia AXAML）
  - [x] 4.1 迁移 MainWindow 主窗口（标签页 + 工具栏 + 状态栏）
  - [x] 4.2 迁移端口扫描界面 (PortScanWindow)
  - [x] 4.3 迁移漏洞详情界面 (VulnerabilityDetailWindow)
  - [x] 4.4 迁移扫描历史记录界面 (ScanHistoryWindow)
  - [x] 4.5 迁移插件管理界面 (PluginManagerWindow)
  - [x] 4.6 迁移攻击日志窗口 (AttackLogWindow)
  - [x] 4.7 迁移资产管理窗口 (AssetManagementWindow)
  - [x] 4.8 迁移网络拓扑窗口 (NetworkTopologyWindow)
  - [x] 4.9 迁移合规检查窗口 (ComplianceCheckWindow)
  - [x] 4.10 修复23个AXAML编译错误（DataGrid/Button/ProgressBar属性兼容性）

- [x] Task 5: PDF 报告生成器适配 Linux 字体
  - [x] 5.1 修改 HistoryReportGenerator.cs 的 LoadChineseFonts() 方法，添加 Linux 字体路径检测
  - [x] 5.2 修改 ProfessionalPdfReportGenerator.cs 同上
  - [x] 5.3 实现平台自动检测：Windows 用 C:\Windows\Fonts\，Linux 用 /usr/share/fonts/
  - [x] 5.4 Core 项目编译通过，字体加载逻辑已就绪

- [x] Task 6: Linux 打包脚本与分发格式
  - [x] 6.1 编写 `build-appimage.sh` — 使用 linuxdeploy 打包为 AppImage
  - [x] 6.2 编写 `build-deb.sh` — 使用 dpkg-deb 构建 deb 安装包
  - [x] 6.3 编写 `build-targz.sh` — 打包 tar.gz 归档
  - [x] 6.4 创建 .desktop 文件（Linux 桌面入口配置）
  - [x] 6.5 README-LINUX.md 用户使用说明文档

- [x] Task 7: 解决方案整合与编译验证
  - [x] 7.1 创建 NetSecurityScanner.sln 解决方案文件，包含 Core + Desktop + Linux 三个项目
  - [x] 7.2 在 Windows 上编译 Desktop 版本并运行测试 ✅ 0错误
  - [x] 7.3 Linux 版本编译通过 ✅ 0错误（修复23个AXAML属性错误后）

# Task Dependencies
- [Task 2] depends on [Task 1]
- [Task 3] depends on [Task 1]
- [Task 4] depends on [Task 3]
- [Task 5] depends on [Task 3]
- [Task 6] depends on [Task 3, Task 4, Task 5]
- [Task 7] depends on [Task 1, Task 2, Task 3, Task 4, Task 5, Task 6]

# 并行执行建议
- Task 1 独立先行
- Task 2 和 Task 3 可并行（都只依赖 Task 1）
- Task 4 和 Task 5 可并行（都只依赖 Task 3）
