# Checklist

## 项目结构重构
- [x] NetSecurityScanner.Core 共享库项目创建完成，目标框架 net8.0
- [x] Models/、Core/、Data/、Utils/ 目录文件全部移入 Core 项目
- [x] Services/ 中无 UI 依赖的文件移入 Core 项目
- [x] Core 项目编译通过（0错误），无 System.Windows.* 依赖

## Windows 桌面版 (Desktop)
- [x] NetSecurityScanner.Desktop 壳项目创建，目标框架 net6.0-windows + UseWPF
- [x] Desktop 项目正确引用 Core 项目
- [x] 所有 WPF XAML 视图文件移入 Desktop 项目（27个窗口）
- [x] Desktop 版本编译运行正常（0错误），功能完整

## Linux 版本 (Avalonia)
- [x] NetSecurityScanner.Linux 项目创建，引入 Avalonia UI 11.x
- [x] Linux 项目正确引用 Core 项目
- [x] Avalonia App.axaml 入口和 Program.cs 启动引导创建完成
- [x] NuGet 包替换完成（OxyPlot.SkiaSharp / LiveChartsCore.AvaloniaUI / QuestPDF）
- [x] MainWindow.axaml 主窗口迁移完成，布局与 WPF 版一致

## 视图文件迁移完整性
- [x] MainWindow 主窗口（标签页 + 工具栏 + 状态栏）迁移完成
- [x] 端口扫描界面 PortScanWindow 迁移完成
- [x] 漏洞详情界面 VulnerabilityDetailWindow 迁移完成
- [x] 扫描历史记录界面 ScanHistoryWindow 迁移完成
- [x] 插件管理界面 PluginManagerWindow 迁移完成
- [x] 攻击日志窗口 AttackLogWindow 迁移完成
- [x] 资产管理窗口 AssetManagementWindow 迁移完成
- [x] 网络拓扑窗口 NetworkTopologyWindow 迁移完成
- [x] 合规检查窗口 ComplianceCheckWindow 迁移完成
- [x] 23个AXAML编译错误已修复（DataGrid/Button/ProgressBar属性兼容性）

## PDF 报告 Linux 适配
- [x] HistoryReportGenerator.cs 字体加载支持 Linux 路径（/usr/share/fonts/）
- [x] ProfessionalPdfReportGenerator.cs 字体加载支持 Linux 路径
- [x] 平台自动检测逻辑实现（Windows vs Linux vs macOS 字体路径切换）
- [x] Core 项目编译通过，字体适配代码已就绪

## Linux 打包分发
- [x] build-appimage.sh 脚本编写完成（AppImage格式）
- [x] build-deb.sh 脚本编写完成（deb安装包格式）
- [x] build-targz.sh 脚本编写完成（tar.gz通用压缩包格式）
- [x] .desktop 文件创建（应用图标 + 分类 + 执行命令）
- [x] README-LINUX.md 用户使用说明文档编写完成
- [x] Packaging 目录结构完整（5个文件）

## 解决方案与最终验证
- [x] NetSecurityScanner.sln 解决方案包含 Core + Desktop + Linux 三个项目
- [x] Windows 上 dotnet build Desktop 版本成功（0错误）
- [x] Windows 上运行 Desktop 版本功能正常
- [x] Linux 上 dotnet build Linux 版本成功（0错误）
- [x] 三个项目全部编译通过 ✅
