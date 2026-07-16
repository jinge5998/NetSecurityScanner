# Tasks

- [ ] Task 1: 扫描结果可视化 Tab
  - [ ] SubTask 1.1: 新增 Tab 9「📈 数据可视化」，使用 Grid 布局分上下两排
  - [ ] SubTask 1.2: 端口分布饼图（TCP/UDP 协议占比 + Top 10 端口柱状图，用 WPF Canvas 自绘）
  - [ ] SubTask 1.3: 风险等级分布图（严重/高危/中危/低危/信息 5 级饼图 + 柱状图）
  - [ ] SubTask 1.4: 服务类型分布图（HTTP/SSH/FTP/MySQL 等柱状图）
  - [ ] SubTask 1.5: 「导出图片」按钮，将当前图表区域渲染为 PNG 保存

- [ ] Task 2: 扫描报告增强
  - [ ] SubTask 2.1: 导出按钮改为下拉菜单（PDF/CSV/JSON/HTML/DOCX）
  - [ ] SubTask 2.2: CSV 导出（端口结果 + 漏洞结果两个文件，UTF-8 BOM）
  - [ ] SubTask 2.3: JSON 导出（完整扫描结果序列化）
  - [ ] SubTask 2.4: HTML 导出（单文件 HTML，内联样式，表格 + 概览统计）
  - [ ] SubTask 2.5: 报告设置对话框（标题、公司名、扫描员、备注）

- [ ] Task 3: 批量目标管理
  - [ ] SubTask 3.1: 目标配置区增加「📥 导入」「📤 导出」「🔄 去重」三个按钮
  - [ ] SubTask 3.2: 从 TXT 文件导入目标（按行解析，支持 IP/CIDR/范围混合）
  - [ ] SubTask 3.3: 导出目标列表为 TXT 文件
  - [ ] SubTask 3.4: 自动去重功能，显示去重前后数量
  - [ ] SubTask 3.5: 目标分组管理（新增分组、删除分组、按分组筛选）

- [ ] Task 4: 高级参数面板完善
  - [ ] SubTask 4.1: 性能调优 Tab 重组为四个分组：并发控制 / 超时重试 / 探测选项 / 随机化设置
  - [ ] SubTask 4.2: TCP/UDP 并发滑块（1-1000，实时显示数值）
  - [ ] SubTask 4.3: 超时精细控制（TCP连接超时 / UDP等待超时 / 服务识别超时，分别设置）
  - [ ] SubTask 4.4: 重试次数滑块（0-5 次）
  - [ ] SubTask 4.5: Ping 探测开关（扫描前 ICMP 存活探测）
  - [ ] SubTask 4.6: 随机化选项（随机端口顺序 / 随机目标顺序）
  - [ ] SubTask 4.7: 源端口范围设置
  - [ ] SubTask 4.8: 参数透传到 Rust / 内置扫描器

- [ ] Task 5: 专项扫描模块
  - [ ] SubTask 5.1: 新增 Tab 10「🔧 专项工具」，分四类卡片：弱口令 / 目录扫描 / POC验证 / CMS识别
  - [ ] SubTask 5.2: 弱口令爆破模块（支持 SSH/FTP/MySQL/MSSQL，可配置用户密码字典）
  - [ ] SubTask 5.3: 目录扫描模块（Web 目录遍历，内置常见敏感路径字典）
  - [ ] SubTask 5.4: POC 验证模块（从插件库加载 POC 插件执行）
  - [ ] SubTask 5.5: CMS 识别模块（指纹匹配识别 CMS 类型和版本）

- [ ] Task 6: 验证 & 构建
  - [ ] SubTask 6.1: `dotnet build -c Debug` 0 错误
  - [ ] SubTask 6.2: 专家模式窗口可正常打开
  - [ ] SubTask 6.3: 各 Tab 切换无异常

# Task Dependencies
- Task 1, 2, 3, 4, 5 之间相互独立，可并行完成
- Task 6 依赖 Task 1-5 全部完成
