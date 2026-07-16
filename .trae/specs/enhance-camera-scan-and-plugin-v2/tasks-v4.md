# v4 Tasks

- [x] v4-T1: 扫描统计图表
  - [x] v4-T1.1: `Services/CameraScanStatisticsService.cs` 提供 `Compute(results)` 返回 `CameraStatistics { Total, Online, Offline, RiskDistribution: Dict<string,int>, VendorTopN: Dict, VulnTypeTopN: Dict }`
  - [x] v4-T1.2: `CameraSecurityScannerWindow.xaml` 顶部新增 RiskDashboard Grid（5 个风险等级卡片 + 厂商 Top 5 柱图 + 漏洞类型 Top 5 柱图 + 在线率仪表盘）
  - [x] v4-T1.3: 使用原生 WPF 绘制（不引入 LiveCharts），自定义 `VendorBarChart` / `VulnTypeBarChart` UserControl
  - [x] v4-T1.4: `DisplayResults` 完成后自动调 `UpdateDashboard(statistics)`

- [x] v4-T2: 摄像头分组/标签
  - [x] v4-T2.1: `Models/CameraTag.cs` { TagId, Name, Color, Description, CreatedTime }
  - [x] v4-T2.2: `Models/CameraTagAssignment.cs` { Ip, TagId }
  - [x] v4-T2.3: `Services/CameraTagService.cs` 增删改查 + 分配/取消分配 + 按标签过滤 IP，持久化到 `data/camera_tags.json`
  - [x] v4-T2.4: `Views/Views/CameraTagManageWindow.xaml(.cs)` 标签管理窗口（左侧标签列表 / 右侧该标签下的 IP 列表）
  - [x] v4-T2.5: 扫描窗口新增"按标签过滤"下拉 + "按标签分组"开关
  - [x] v4-T2.6: DataGrid 新增"标签"列，显示该 IP 的所有标签

- [x] v4-T3: 右键菜单+详情弹窗
  - [x] v4-T3.1: `Views/Views/CameraDetailWindow.xaml(.cs)` 详情窗口：左侧基本/端口/漏洞/弱口令 4 个 Tab，右侧风险评分和厂商 Logo
  - [x] v4-T3.2: DataGrid 加 `ContextMenu`：查看详情、复制IP、复制CVE、过滤同厂商、跳转CVE（NVD 链接）
  - [x] v4-T3.3: 双击行打开详情窗口

- [x] v4-T4: 弱口令字典编辑器
  - [x] v4-T4.1: `Services/CameraWeakPasswordDictService.cs` 增删改 + 导入/导出 txt + 合并内置字典
  - [x] v4-T4.2: 持久化到 `data/camera_weak_passwords.json`
  - [x] v4-T4.3: `Views/Views/CameraWeakPasswordEditorWindow.xaml(.cs)` 编辑器窗口
  - [x] v4-T4.4: 扫描窗口新增"自定义弱口令"链接按钮，点击打开编辑器
  - [x] v4-T4.5: `CameraScannerService` 集成：扫描时优先使用自定义字典（如果存在）

- [x] v4-T5: 历史趋势图
  - [x] v4-T5.1: `Services/CameraTrendService.cs` 读取 `data/camera_scan_history.db`（SQLite）按日期聚合
  - [x] v4-T5.2: `Models/CameraTrendPoint.cs` { Date, Total, Online, Offline, VulnTotal, HighVuln }
  - [x] v4-T5.3: `Views/Views/CameraTrendWindow.xaml(.cs)` 趋势窗口：3 个折线图（总数/在线数/漏洞数）+ 多会话对比下拉
  - [x] v4-T5.4: 扫描窗口新增"📈 历史趋势"按钮
  - [x] v4-T5.5: 自定义 `LineChart` UserControl 绘制折线图

# v4 Task Dependencies
- v4-T3 详情弹窗 依赖 v4-T1 统计服务（详情窗口也显示统计）
- v4-T5 趋势图 依赖 v4-T1 统计服务
- 其他任务独立

# v4 验证清单
- [x] Dashboard 5 个风险卡片在扫描完成后立即更新
- [x] 厂商 Top 5 / 漏洞 Top 5 柱图正确显示
- [x] 创建标签"前台"并分配 3 个 IP，扫描时按"前台"过滤
- [x] DataGrid 右键菜单 5 项都能正常触发
- [x] 双击行打开详情窗口，4 个 Tab 都有数据
- [x] 弱口令编辑器添加 5 个口令后保存，重新打开可见
- [x] 弱口令编辑器导入/导出 txt 正常
- [x] 趋势窗口打开后显示最近 30 天曲线
- [x] v4 所有功能编译通过（0 错误）
