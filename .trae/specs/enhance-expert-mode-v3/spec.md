# 专家模式 v3 功能完善 Spec

## Why
专家模式 v2 已完成 Rust 引擎、历史对比、定时扫描、结果交互、导出增强、预设管理、智能推荐、目标解析、进度增强、配置恢复 10 项能力，但在数据可视化、报告多样性、目标批量管理、高级参数、专项扫描模块方面仍有提升空间。本版本聚焦这 5 大方向，使专家模式成为真正的专业级安全测试工作台。

## What Changes
- **扫描结果可视化**：新增「📈 数据可视化 Tab，包含端口分布饼图、风险等级柱状图、服务类型分布图、扫描时序图，支持导出图片
- **扫描报告增强**：支持 CSV / JSON / HTML / DOCX 多格式导出，可自定义报告标题、Logo、描述，报告模板管理
- **批量目标管理**：目标支持从 TXT/CSV/Excel 导入、导出为文件、分组管理、标签筛选、去重、存活探测
- **高级参数面板完善**：增加 TCP/UDP 并发滑块、超时/重试精细控制、Ping 探测开关、MTU/分片设置、源端口随机化、扫描顺序随机化、脚本扫描强度
- **专项扫描模块**：新增弱口令爆破（SSH/FTP/MySQL/MSSQL）、目录扫描、POC验证、CMS 识别等专项插件入口

## Impact
- Affected specs: enhance-expert-mode-v2（在 v2 基础上扩展）
- Affected code:
  - `ExpertModeWindow.xaml` / `.xaml.cs` — 主要改动目标
  - `ReportEngine.cs` — 报告生成扩展
  - `TargetManagerService.cs`（新增）— 目标批量管理
  - `PortScanner.cs / VulnerabilityScanner.cs — 高级参数透传
  - `PluginOrchestrator.cs` — 专项扫描插件调度
  - `BruteForceService.cs`（新增）— 弱口令爆破

## ADDED Requirements

### Requirement: 扫描结果可视化
系统 SHALL 在专家模式新增「📈 数据可视化」Tab，提供多种图表展示扫描结果。

#### Scenario: 端口分布饼图
- **WHEN** 用户切换到数据可视化 Tab 且有扫描结果
- **THEN** 显示端口协议分布饼图（TCP/UDP）和端口数量排名 Top 10 端口柱状图

#### Scenario: 风险等级分布图
- **WHEN** 有漏洞扫描结果时
- **THEN** 显示严重/高危/中危/低危/信息 5 级风险分布饼图和数量柱状图

#### Scenario: 服务类型分布图
- **WHEN** 有服务识别结果时
- **THEN** 显示 HTTP/SSH/FTP/MySQL 等服务类型分布柱状图

#### Scenario: 导出图表
- **WHEN** 用户点击「导出图片」
- **THEN** 将当前图表导出为 PNG 图片保存到本地

### Requirement: 扫描报告增强
系统 SHALL 支持多格式报告导出和自定义模板。

#### Scenario: 多格式导出
- **WHEN** 用户点击导出下拉菜单选择格式
- **THEN** 支持 PDF / CSV / JSON / HTML / DOCX 五种格式可选

#### Scenario: 自定义报告信息
- **WHEN** 用户点击「报告设置」
- **THEN** 可编辑报告标题、公司名称、Logo 描述、扫描人员等信息

#### Scenario: CSV 导出
- **WHEN** 选择 CSV 导出
- **THEN** 导出端口结果和漏洞结果两个 CSV 文件（带 BOM 的 UTF-8 编码）

#### Scenario: HTML 导出
- **WHEN** 选择 HTML 导出
- **THEN** 生成单文件 HTML 报告，包含图表、表格、可折叠详情

### Requirement: 批量目标管理
系统 SHALL 提供目标批量导入导出和分组管理。

#### Scenario: 从文件导入目标
- **WHEN** 用户点击「导入目标」选择 TXT/CSV 文件
- **THEN** 按行读取文件内容解析目标地址，支持 IP 支持 CIDR、范围、单 IP 混合格式

#### Scenario: 导出目标列表
- **WHEN** 用户点击「导出目标」
- **THEN** 将当前目标列表导出为 TXT 文件

#### Scenario: 目标去重
- **WHEN** 导入或粘贴目标后
- **THEN** 自动去重并显示去重前后数量对比

#### Scenario: 目标分组
- **WHEN** 用户创建目标分组
- **THEN** 可将目标分配到不同分组，支持按分组筛选

### Requirement: 高级参数面板完善
系统 SHALL 在性能调优 Tab 增加更丰富的高级扫描参数。

#### Scenario: 并发数滑块
- **WHEN** 用户调整 TCP/UDP 并发滑块
- **THEN** 实时显示当前值，范围 1-1000

#### Scenario: 超时精细控制
- **WHEN** 用户设置超时时间
- **THEN** 支持 TCP 连接超时、UDP 等待超时、服务识别超时分别设置

#### Scenario: 重试次数
- **WHEN** 用户设置重试次数
- **THEN** 端口扫描重试 0-5 次可调

#### Scenario: Ping 探测开关
- **WHEN** 用户勾选「扫描前 Ping 探测」
- **THEN** 扫描前先 ICMP Echo 探测存活，仅对存活目标扫描

#### Scenario: 随机化选项
- **WHEN** 用户勾选「随机端口顺序」或「随机目标顺序」
- **THEN** 扫描时打乱顺序，降低被检测概率

#### Scenario: 源端口设置
- **WHEN** 用户设置源端口范围
- **THEN** 扫描时使用指定源端口范围

### Requirement: 专项扫描模块
系统 SHALL 新增「🔧 专项工具」Tab，提供多种专项安全检测工具。

#### Scenario: 弱口令爆破
- **WHEN** 用户选择弱口令爆破并配置目标端口、服务类型、用户名密码字典
- **THEN** 对指定服务执行弱口令检测，返回成功的结果

#### Scenario: 目录扫描
- **WHEN** 用户输入 URL 和字典路径
- **THEN** 对 Web 目标执行目录遍历扫描，发现敏感文件和目录

#### Scenario: POC 验证
- **WHEN** 用户选择 POC 插件和目标
- **THEN** 执行选定的 POC 验证漏洞是否存在

#### Scenario: CMS 识别
- **WHEN** 用户输入目标 URL
- **THEN** 识别目标 CMS 类型和版本

## MODIFIED Requirements

### Requirement: 性能调优 Tab 重组
原「性能调优」Tab 增加高级参数面板，分为：并发控制、超时重试、探测选项、随机化设置四个分组。

### Requirement: 导出按钮
原导出按钮从单个 PDF 改为下拉菜单，支持 PDF/CSV/JSON/HTML/DOCX 多选。

## REMOVED Requirements
无
