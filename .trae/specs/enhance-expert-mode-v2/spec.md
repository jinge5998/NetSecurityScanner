# 专家模式功能完善 Spec

## Why
专家模式窗口已具备 6 个 Tab（目标配置 / 端口与服务 / 性能调优 / 高级选项 / 实时结果 / Nmap模板）和基本的扫描执行能力，但存在多处功能缺失与体验问题：扫描未走 Rust 引擎、无扫描历史对比、无定时扫描、导出格式单一、结果无法交互查看详情、预设管理不可编辑等。需补全这些能力使其真正可用于生产级安全测试。

## What Changes
- 扫描引擎切换：增加 Rust IPC 扫描模式，与主窗口 ExpertModeWindow 一致走 `_useRustScanner` 双通道
- 扫描历史与对比：新增「📊 扫描历史」Tab，列出历史扫描记录，支持两次扫描结果差异对比
- 定时扫描：新增「⏰ 定时扫描」Tab，基于 PluginScheduler 的 Cron 调度，支持单次/循环/自定义 Cron
- 结果交互增强：实时结果 DataGrid 行双击弹出详情窗口；端口结果行右键菜单增加「针对此端口深度漏洞扫描」
- 导出增强：新增 PDF 导出（沿用主窗口 ReportEngine）；导出 Nmap 命令使用 STA 线程安全复制（与 LicenseDialog 同款）
- 预设管理增强：预设保存/加载支持自定义命名、编辑、删除；Nmap 模板按钮点击后不再弹 MessageBox 而是在页面内显示应用结果
- 智能推荐集成：读取已有 ScanProfileConfig + RecommendEngine，在目标配置区显示推荐模式
- 目标解析增强：CIDR/Range 超过 256 个目标时弹出警告；支持从剪贴板粘贴目标列表
- 扫描进度增强：实时结果 Tab 在扫描进行中自动切换并滚动；增加已用时间/预计剩余时间显示
- 配置持久化：用户上次使用的配置自动恢复（包括 Tab 选项、目标类型、端口模式等）

## Impact
- Affected specs: enhance-expert-mode-scan-profiles（扫描模式配置模型已有，需复用 ScanProfileConfig）
- Affected code:
  - `ExpertModeWindow.xaml` / `.xaml.cs` — 主要改动目标
  - `PluginScheduler` — 定时扫描复用
  - `RustScannerClient` — Rust IPC 扫描
  - `PortScanner` / `VulnerabilityScanner` — 内置 C# 扫描器
  - `ScanProfileConfig` / `RecommendEngine` — 智能推荐
  - `ReportEngine` — PDF 导出

## ADDED Requirements

### Requirement: Rust IPC 扫描模式
系统 SHALL 在专家模式扫描时支持 Rust 引擎。当 `_useRustScanner=true` 时调用 `RustScannerClient.ScanPortsAsync`，否则走内置 `PortScanner`。用户可在性能调优 Tab 切换引擎。

#### Scenario: Rust 引擎可用时
- **WHEN** 用户点击开始扫描且 Rust 引擎已就绪
- **THEN** 扫描走 Rust IPC 通道，实时进度从 IPC 流式回传

#### Scenario: Rust 引擎不可用时
- **WHEN** Rust 可执行文件未找到或 IPC 连接失败
- **THEN** 自动降级到内置 C# 扫描器，日志中提示降级原因

### Requirement: 扫描历史与差异对比
系统 SHALL 提供扫描历史 Tab，展示所有历史专家扫描记录（从 JsonDatabaseService 读取）。支持选择两条记录进行差异对比，显示新增/关闭端口和新增/修复漏洞。

#### Scenario: 查看扫描历史
- **WHEN** 用户切换到「扫描历史」Tab
- **THEN** 显示按时间倒序的历史扫描列表，含目标/时间/端口数/漏洞数/风险等级

#### Scenario: 差异对比
- **WHEN** 用户选择两条扫描记录并点击「对比」
- **THEN** 弹出对比窗口，显示：新增开放端口（绿）、已关闭端口（红）、新增漏洞（红）、已修复漏洞（绿）

### Requirement: 定时扫描
系统 SHALL 在「定时扫描」Tab 中允许用户创建 Cron 调度的扫描任务。支持「仅一次 / 每天 / 每周 / 自定义 Cron」四种模式。任务通过 PluginScheduler 执行。

#### Scenario: 创建定时扫描
- **WHEN** 用户填写目标、选择 Cron 模式并点击「创建任务」
- **THEN** 任务写入 PluginScheduler，到时间自动执行扫描

### Requirement: 结果交互增强
系统 SHALL 支持在实时结果 DataGrid 中双击行查看详情，右键菜单增加「深度漏洞扫描」操作。

#### Scenario: 双击端口行
- **WHEN** 用户双击端口扫描结果中的某一行
- **THEN** 弹出详情窗口，显示完整端口信息、服务 Banner、漏洞列表

#### Scenario: 右键深度扫描
- **WHEN** 用户在端口行右键点击「深度漏洞扫描」
- **THEN** 仅针对该端口的开放服务执行深度漏洞扫描

### Requirement: 导出增强
系统 SHALL 支持 PDF 导出（复用主窗口 ReportEngine），Nmap 命令复制使用 STA 线程 + Win32 API 安全方案。

#### Scenario: 导出 PDF 报告
- **WHEN** 用户点击「导出 PDF」按钮
- **THEN** 生成与主窗口风格一致的专业 PDF 扫描报告

### Requirement: 预设管理增强
系统 SHALL 支持预设的增删改。保存预设时输入名称；加载预设时从列表选择；已保存的预设可删除。Nmap 模板按钮点击后在页面内显示应用结果（非弹窗）。

#### Scenario: 保存自定义预设
- **WHEN** 用户配置完参数后点击「保存预设」并输入名称
- **THEN** 预设以 JSON 形式保存到 `%LOCALAPPDATA%\NetSecurityScanner\expert_presets\`

#### Scenario: 删除预设
- **WHEN** 用户在预设列表中选中某项并点击删除
- **THEN** 预设被删除，文件同步删除

### Requirement: 智能推荐集成
系统 SHALL 在目标配置区显示推荐扫描模式（基于 ScanProfileConfig + RecommendEngine）。点击「推荐模式」按钮后根据目标数量和网络条件自动推荐 Quick/Standard/Deep/Custom 并显示推荐理由。

#### Scenario: 目标数较多
- **WHEN** 目标数 > 50 时点击推荐
- **THEN** 推荐降低并发、增加超时，显示理由

### Requirement: 目标解析增强
系统 SHALL 在 CIDR/Range 超过 256 个目标时弹出确认警告。支持从剪贴板快速粘贴目标列表。

#### Scenario: 大范围目标警告
- **WHEN** 用户输入 CIDR 如 192.168.0.0/16 解析出超过 256 个目标
- **THEN** 弹出警告「目标数量较多(N个)，扫描可能耗时较长，是否继续？」

#### Scenario: 粘贴目标
- **WHEN** 用户在目标输入区按 Ctrl+V 或点击「从剪贴板粘贴」按钮
- **THEN** 自动将剪贴板内容按行分割填入目标列表

### Requirement: 扫描进度增强
系统 SHALL 在实时结果 Tab 中显示已用时间、预计剩余时间。扫描开始时自动切换到实时结果 Tab。

#### Scenario: 扫描进行中
- **WHEN** 扫描正在执行
- **THEN** 底部状态栏显示「已用: XX:XX | 预计剩余: XX:XX」，ProgressBar 实时更新

### Requirement: 配置自动恢复
系统 SHALL 在窗口打开时自动恢复上次使用的配置（Tab 选项、目标类型、端口模式、高级参数等）。

#### Scenario: 重新打开专家模式
- **WHEN** 用户关闭并重新打开专家模式窗口
- **THEN** 所有配置恢复到上次关闭时的状态

## MODIFIED Requirements

### Requirement: Nmap 模板应用反馈
Nmap 模板按钮点击后不再弹 MessageBox，改为在模板区域下方显示绿色提示条「已应用: xxx 模式」，3 秒后自动消失。

### Requirement: 预设保存/加载
原 SavePresetButton/LoadPresetButton 仅支持简单序列化。现增加预设列表管理 UI：保存时弹出输入名称对话框，加载时显示下拉列表选择。
