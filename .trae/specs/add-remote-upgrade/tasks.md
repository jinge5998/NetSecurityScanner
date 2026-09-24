# Tasks

- [x] Task 1: 创建数据模型和配置服务
  - [x] Task 1.1: 创建 UpdateInfo.cs 数据模型类
  - [x] Task 1.2: 创建 UpdateSettings.cs 配置模型类
  - [x] Task 1.3: 扩展 SettingsService 支持更新配置

- [x] Task 2: 实现版本检测核心服务
  - [x] Task 2.1: 创建 UpdateCheckService.cs 服务类
  - [x] Task 2.2: 实现 GitHub API 调用和JSON解析
  - [x] Task 2.3: 实现语义化版本比较逻辑
  - [x] Task 2.4: 实现网络异常处理和超时控制

- [x] Task 3: 实现升级包下载引导服务
  - [x] Task 3.1: 创建 UpdatePackageDownloader.cs 服务类
  - [x] Task 3.2: 实现百度网盘链接打开功能
  - [x] Task 3.3: 添加下载引导提示信息

- [x] Task 4: 创建升级提示窗口界面
  - [x] Task 4.1: 创建 UpdateDialog.xaml 窗口文件
  - [x] Task 4.2: 设计版本信息展示区域
  - [x] Task 4.3: 设计更新日志展示区域
  - [x] Task 4.4: 实现操作按钮(立即下载/稍后提醒/跳过此版本)

- [x] Task 5: 实现升级窗口逻辑
  - [x] Task 5.1: 创建 UpdateDialog.xaml.cs 代码文件
  - [x] Task 5.2: 实现按钮事件处理
  - [x] Task 5.3: 实现跳过版本记录逻辑
  - [x] Task 5.4: 实现下次提醒时间控制

- [x] Task 6: 集成到主程序
  - [x] Task 6.1: 在 MainWindow.xaml 添加"检查更新"菜单项
  - [x] Task 6.2: 在 MainWindow.xaml.cs 添加检查更新事件处理
  - [x] Task 6.3: 在 App.xaml.cs 添加启动时版本检查
  - [x] Task 6.4: 添加加载状态提示

- [x] Task 7: 创建GitHub仓库初始化脚本
  - [x] Task 7.1: 创建 init-github-repo.ps1 初始化脚本
  - [x] Task 7.2: 创建 .gitignore 文件
  - [x] Task 7.3: 创建 Release Notes 模板文件
  - [x] Task 7.4: 编写发布指南文档

- [x] Task 8: 验证和测试
  - [x] Task 8.1: 编译项目验证无错误
  - [x] Task 8.2: 运行程序测试启动时版本检查
  - [x] Task 8.3: 测试手动检查更新功能
  - [x] Task 8.4: 测试升级窗口交互(跳过/稍后/下载)
  - [x] Task 8.5: 测试配置持久化(跳过版本记录生效)

# Task Dependencies
- Task 2 depends on Task 1
- Task 4 depends on Task 2
- Task 5 depends on Task 4
- Task 6 depends on Task 5
- Task 6 depends on Task 3
- Task 8 depends on Task 6
- Task 7 is independent (can run in parallel)
