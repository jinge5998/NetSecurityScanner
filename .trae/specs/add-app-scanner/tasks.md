# Tasks

- [x] Task 1: 创建APP扫描数据模型
  - [x] Task 1.1: 创建AppScanResult.cs数据模型类
  - [x] Task 1.2: 定义扫描模式枚举(SAST/DAST/SCA)
  - [x] Task 1.3: 定义风险等级枚举和漏洞类型枚举
  - [x] Task 1.4: 创建AppVulnerabilityResult类包含所有必要字段

- [x] Task 2: 实现APP扫描核心服务
  - [x] Task 2.1: 创建AppScannerService.cs服务类
  - [x] Task 2.2: 实现APK文件解析基础功能
  - [x] Task 2.3: 实现SAST静态分析检测逻辑
  - [x] Task 2.4: 实现SCA软件成分分析功能
  - [x] Task 2.5: 添加扫描进度事件和日志事件
  - [x] Task 2.6: 支持取消扫描操作

- [x] Task 3: 创建APP扫描窗口界面
  - [x] Task 3.1: 创建AppScannerWindow.xaml窗口文件
  - [x] Task 3.2: 实现文件选择区域(支持拖拽和点击)
  - [x] Task 3.3: 实现扫描配置区域(扫描类型选择)
  - [x] Task 3.4: 实现扫描进度显示区域
  - [x] Task 3.5: 实现扫描结果表格展示
  - [x] Task 3.6: 添加结果过滤和排序功能

- [x] Task 4: 实现APP扫描窗口逻辑
  - [x] Task 4.1: 创建AppScannerWindow.xaml.cs代码文件
  - [x] Task 4.2: 实现文件选择和验证逻辑
  - [x] Task 4.3: 实现扫描执行和进度更新
  - [x] Task 4.4: 实现扫描结果展示和交互
  - [x] Task 4.5: 实现报告导出功能

- [x] Task 5: 集成到主菜单
  - [x] Task 5.1: 在MainWindow.xaml添加APP扫描菜单项
  - [x] Task 5.2: 在MainWindow.xaml.cs添加点击事件处理
  - [x] Task 5.3: 测试菜单功能和窗口打开

- [x] Task 6: 验证和测试
  - [x] Task 6.1: 编译项目验证无错误
  - [x] Task 6.2: 运行程序测试完整流程
  - [x] Task 6.3: 测试文件选择和扫描功能
  - [x] Task 6.4: 测试报告导出功能

# Task Dependencies
- Task 2 depends on Task 1
- Task 4 depends on Task 3
- Task 4 depends on Task 2
- Task 5 depends on Task 4
- Task 6 depends on Task 5
