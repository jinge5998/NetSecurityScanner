# Tasks

- [x] Task 1: 创建Agent安全扫描数据模型
  - [x] 1.1 创建 AgentAttackSurfaceLayer.cs 六层攻击面枚举
  - [x] 1.2 创建 AgentScanPhase.cs 扫描阶段枚举
  - [x] 1.3 创建 AgentVulnerability.cs 漏洞模型（含AgentRiskLevel枚举）
  - [x] 1.4 创建 AgentScanResult.cs 扫描结果模型（含AgentTargetType枚举）
  - [x] 1.5 创建 AgentScanOptions.cs 配置模型（含AgentScanDepth枚举）

- [x] Task 2: 实现CNNVD漏洞库同步服务
  - [x] 2.1 创建 CnnvdSyncService.cs 基础框架（单例+本地JSON缓存）
  - [x] 2.2 内置82条Agent CVE漏洞数据（超危12/高危21/中危47/低危2）
  - [x] 2.3 实现本地缓存读写和离线查询功能（GetAll/GetByRiskLevel/Search/GetByCveId/GetByComponent/GetStatistics）
  - [x] 2.4 实现同步和过期检查机制

- [x] Task 3: 实现三阶段扫描核心引擎
  - [x] 3.1 创建 AgentSecurityScannerService.cs 主服务框架（ScanAsync/Cancel/IDisposable）
  - [x] 3.2 实现阶段一：静态分析引擎（硬编码密钥/危险权限/不安全URL/MCP安全/依赖包漏洞/配置解析）
  - [x] 3.3 实现阶段二：意图研判引擎（Prompt注入/Tool调用链/敏感信息泄露/自定义关键词）
  - [x] 3.4 实现阶段三：行为沙箱检测引擎（WebSocket劫持/网关注入/审批绕过/命令逃逸/CNNVD关联）
  - [x] 3.5 实现六层攻击面分类映射和安全评分算法

- [x] Task 4: 创建Agent安全扫描主窗口UI
  - [x] 4.1 创建 AgentSecurityScannerWindow.xaml 窗口框架（1300x900/标题区/输入区/配置区/进度区/Tab区/状态栏）
  - [x] 4.2 实现目标输入区域（文件/目录/配置导入/文本粘贴四种模式切换）
  - [x] 4.3 实现扫描配置面板（三阶段开关/深度选择/依赖检查）
  - [x] 4.4 实现概览仪表盘Tab（六层攻击面热力图+风险统计卡片+Top10问题列表+摘要信息）
  - [x] 4.5 实现静态分析结果Tab（DataGrid+等级筛选+类型筛选+搜索+双击详情）
  - [x] 4.6 实现意图研判结果Tab（WrapPanel风险卡片布局+彩色竖条+置信度条+Expander修复建议）
  - [x] 4.7 实现行为检测结果Tab（CVE DataGrid+CVSS颜色条+选中详情面板+CVE点击复制）
  - [x] 4.8 实现修复建议Tab（优先级排序列表+复制按钮+统计栏+导出按钮）

- [x] Task 5: 实现窗口后台逻辑与交互
  - [x] 5.1 重写 AgentSecurityScannerWindow.xaml.cs 集成Core层正式模型和服务
  - [x] 5.2 实现异步扫描流程（调用AgentSecurityScannerService.ScanAsync+进度回调+取消支持+实时UI更新）
  - [x] 5.3 实现扫描控制逻辑（开始/停止/状态切换/UI禁用启用/计时器）
  - [x] 5.4 实现报告导出功能（文本格式含完整扫描摘要+三阶段结果+修复清单）+ Markdown修复清单导出
  - [x] 5.5 实现结果搜索、筛选、排序交互 + XAML Binding同步更新

- [x] Task 6: 集成到主程序菜单
  - [x] 6.1 在 MainWindow.xaml 的"扫描"菜单下添加"Agent安全扫描"菜单项（APP扫描之后）
  - [x] 6.2 在 MainWindow.xaml.cs 中添加 AgentSecurityScan_Click 事件处理方法
  - [x] 6.3 编译验证通过（0错误，dotnet build成功生成dll）

# Task Dependencies
- [Task 2] 无依赖，与Task 1 并行完成 ✅
- [Task 3] 依赖于 [Task 1] ✅ 和 [Task 2] ✅ — 已完成
- [Task 4] 依赖于 [Task 1] ✅ — 已完成（XAML Binding已同步更新为Core层模型属性名）
- [Task 5] 依赖于 [Task 3] ✅ 和 [Task 4] ✅ — 已完成（已删除局部模型类，改用Core层正式模型+真实服务调用）
- [Task 6] 依赖于 [Task 4] ✅ 和 [Task 5] ✅ — 已完成
