# Agent安全扫描模块 Spec

## Why
随着AI Agent技术（OpenClaw、Hermes Agent等）的快速部署，AI智能体安全问题日益突出。据统计公网上已部署超14万个AI智能体实例，其中10%以上存在高危漏洞，600多个实例已加载恶意Skill。当前网络安全扫描工具缺少针对AI Agent的专项安全检测能力，需要新增Agent安全扫描模块，覆盖静态分析、意图研判、行为沙箱三阶段检测，集成CNNVD国家漏洞库，提供完整的Agent安全评估能力。

## What Changes
- 在主窗口"扫描"菜单栏下新增"Agent安全扫描"菜单项
- 新建AgentSecurityScannerWindow独立扫描窗口（Views/Views/AgentSecurityScannerWindow.xaml）
- 新建Agent安全扫描核心服务（Services/AgentSecurityScannerService.cs）
- 新建Agent漏洞数据模型（Models/AgentVulnerability.cs、Models/AgentScanResult.cs）
- 新建CNNVD漏洞库同步服务（Services/CnnvdSyncService.cs）
- 新建Agent安全扫描报告生成器
- 集成三阶段扫描引擎：静态分析→意图研判→行为沙箱

## Impact
- Affected specs: 无依赖其他spec
- Affected code:
  - `MainWindow.xaml` — 菜单栏增加菜单项
  - `MainWindow.xaml.cs` — 增加菜单事件处理
  - 新增 `Views/Views/AgentSecurityScannerWindow.xaml(.cs)` — 主扫描窗口
  - 新增 `Services/AgentSecurityScannerService.cs` — 核心扫描引擎
  - 新增 `Services/CnnvdSyncService.cs` — CNNVD漏洞库同步
  - 新增 `Models/AgentVulnerability.cs` — Agent漏洞模型
  - 新增 `Models/AgentScanResult.cs` — 扫描结果模型

## ADDED Requirements

### Requirement: Agent安全扫描入口
系统 SHALL 在"扫描"菜单栏下提供"Agent安全扫描"功能入口，点击后打开独立的Agent安全扫描窗口。

#### Scenario: 用户打开Agent安全扫描
- **WHEN** 用户点击"扫描"→"Agent安全扫描"
- **THEN** 系统打开AgentSecurityScannerWindow独立窗口

### Requirement: 三阶段扫描引擎
系统 SHALL 实现"静态分析→意图研判→行为沙箱"三阶段扫描策略：

#### 阶段一：静态分析
- 解析Agent配置文件（SKILL.md、agent.yaml、config.json等）
- 检测硬编码密钥、危险权限声明、不安全的URL引用
- 检测依赖包已知漏洞（供应链安全）
- 扫描MCP工具配置中的命令注入风险点
- 输出：静态风险项列表（风险等级/类型/位置/描述）

#### 阶段二：意图研判
- 对Agent的Skill描述、Prompt模板进行语义安全分析
- 检测提示词注入攻击面（越狱指令、角色劫持、上下文操纵）
- 分析Tool调用链是否存在权限提升路径
- 识别敏感信息泄露风险（系统提示词中含密钥等）
- 输出：语义风险评级+攻击场景描述

#### 阶段三：行为沙箱（模拟检测）
- 基于规则模拟Agent行为模式的安全检测
- 检测WebSocket劫持风险（CVE-2026-25253类漏洞）
- 检测网关参数注入、URL篡改等运行时攻击面
- 检测审批队列绕过、命令拦截逃逸风险
- 输出：动态行为风险列表+利用条件说明

### Requirement: CNNVD漏洞库集成
系统 SHALL 支持同步CNNVD国家人工智能安全漏洞库数据：
- 提供手动同步和自动更新两种模式
- 覆盖OpenClaw/Hermes Agent等主流平台CVE漏洞
- 漏洞分级：超危(12)、高危(21)、中危(47)、低危(2)
- 本地缓存漏洞库支持离线查询
- 扫描时自动关联已知CVE编号

### Requirement: Agent扫描目标配置
系统 SHALL 支持以下扫描目标输入方式：
- **文件/目录扫描**：选择Agent项目目录或Skill包文件
- **配置文件导入**：导入SKILL.md / agent.yml / JSON配置
- **文本粘贴**：直接粘贴Agent配置/Prompt内容进行分析
- 目标类型自动识别（OpenClaw Skill / Hermes Agent / 自定义Agent）

### Requirement: 扫描结果展示
系统 SHALL 以分页Tab方式展示三阶段扫描结果：
- **概览仪表盘**：六层攻击面覆盖图 + 风险统计 + 评分雷达图
- **静态分析结果**：DataGrid展示（文件/行号/风险类型/等级/详情）
- **意图研判结果**：风险卡片式布局（注入类型/置信度/攻击场景/修复建议）
- **行为检测结果**：漏洞明细表（CVE编号/危害等级/影响组件/利用条件）
- **修复建议面板**：按优先级排列的可操作修复建议
- 支持结果筛选（按等级/类型/阶段）、搜索、导出

### Requirement: 扫描报告导出
系统 SHALL 支持导出Agent安全扫描报告：
- HTML格式（含图表、详细漏洞信息、修复建议）
- SARIF格式（可导入GitHub安全面板）
- JSON格式（便于API集成）
- 报告包含：扫描摘要、三阶段详细结果、漏洞清单、修复建议、合规检查项

### Requirement: 六层攻击面模型
系统 SHALL 基于360智能体安全六层攻击面模型组织扫描项：
1. **LLM层**：Prompt注入、模型窃取、训练数据泄露
2. **工具层**：命令注入、SSRF、不安全工具调用
3. **记忆层**：记忆投毒、上下文污染、RAG注入
4. **流程层**：流程劫持、循环攻击、资源耗尽
5. **传输层**：中间人攻击、WebSocket劫持、会话接管
6. **外部接口层**：API滥用、回调投毒、Webhook劫持

## MODIFIED Requirements
无现有需求修改。

## REMOVED Requirements
无。
