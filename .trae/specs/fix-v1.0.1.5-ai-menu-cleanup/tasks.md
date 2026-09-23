# Tasks

- [x] Task 1: 确认源码 MainWindow.xaml 已无 AI 风险评估
  - [x] 验证分析菜单不含 AI 风险评估项
  - [x] 验证 TabControl 不含 AI 风险评估 TabItem
  - [x] 全文件 grep "AI风险" / "AIRiskAssessment" UI 引用为 0
- [x] Task 2: 关闭所有旧 publish-v1.0.1.5 进程
  - [x] 列出所有 NetSecurityScanner.Desktop 进程及路径
  - [x] 确认无 publish-v1.0.1.5 进程残留
- [x] Task 3: 启动 publish-v1.0.1.5-recover 目录的 EXE
  - [x] 验证 DLL 字符串扫描 AI风险评估 出现 0 次
  - [x] 验证 EXE 大小和修改时间合理
- [x] Task 4: 整合发布目录为唯一的 publish-v1.0.1.5
  - [x] 备份 publish-v1.0.1.5-recover → 合并到 publish-v1.0.1.5（删除旧 DLL）
  - [x] 旧 publish-v1.0.1.5 已重命名为 publish-v1.0.1.5-old-archive
  - [x] publish-v1.0.1.5-recover 已重命名为 publish-v1.0.1.5
- [x] Task 5: 修复 RunApp.bat 启动路径
  - [x] 将 RunApp.bat 中 publish-v1.0.1.5-new 改为 publish-v1.0.1.5
  - [x] 验证 RunApp.bat 指向有效目录
- [x] Task 6: 启动更新后的 EXE 并验证
  - [x] 从干净的 publish-v1.0.1.5 启动 EXE (PID 37532, 2026-08-15 19:26:46)
  - [x] 监控 60 秒确保稳定运行（运行时长 37.7s，CPU 0.6s，内存 75MB）
  - [x] DLL 字符串扫描确认 AI风险评估 0 命中

# Task Dependencies
- Task 4 → Task 5 (必须先有干净的发布目录才能修启动脚本)
- Task 5 → Task 6 (修好启动脚本才能启动并验证)
