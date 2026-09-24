# Checklist

## 源码验证
- [x] Task 1.1: 源码 MainWindow.xaml 分析菜单中无 "AI风险评估" MenuItem
- [x] Task 1.2: 源码 MainWindow.xaml TabControl 中无 "AI风险评估" TabItem
- [x] Task 1.3: 源码 MainWindow.xaml 全文件无 "AI风险评估" / "AIRiskAssessment" UI 字符串

## 进程清理
- [x] Task 2.1: 已关闭 publish-v1.0.1.5 目录下的所有进程
- [x] Task 2.2: 当前无 NetSecurityScanner.Desktop 进程残留

## 发布目录验证
- [x] Task 3.1: publish-v1.0.1.5-recover/NetSecurityScanner.Desktop.dll 中 "AI风险评估" 字符串 0 命中
- [x] Task 3.2: publish-v1.0.1.5-recover/NetSecurityScanner.Desktop.exe 已是最新编译版本（2026-08-15 16:48）

## 目录整合
- [x] Task 4.1: publish-v1.0.1.5/NetSecurityScanner.Desktop.dll 中 "AI风险评估" 字符串 0 命中
- [x] Task 4.2: 旧 publish-v1.0.1.5 目录已重命名为 publish-v1.0.1.5-old-archive

## 启动脚本修复
- [x] Task 5.1: RunApp.bat 指向 publish-v1.0.1.5（不是 publish-v1.0.1.5-new）
- [x] Task 5.2: RunApp.bat 路径有效可执行

## 运行时验证
- [x] Task 6.1: 程序从 publish-v1.0.1.5 启动 (PID 37532, 启动时间 2026-08-15 19:26:46)
- [x] Task 6.2: 程序稳定运行超过 30 秒，CPU 0.6s，内存 75MB
- [x] Task 6.3: DLL 字符串扫描确认 "AI风险评估" 0 命中（已与已删除的 -recover 目录对比）
